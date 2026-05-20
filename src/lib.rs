#![allow(unsafe_op_in_unsafe_fn)]

use std::collections::{HashMap, HashSet};
use std::fmt::Write as FmtWrite;
use std::time::Duration;

use serde::{Deserialize, Serialize};

// ── Private parse structs ─────────────────────────────────────────────────────

#[derive(Deserialize)]
struct PyProject {
    project: Project,
}

#[derive(Deserialize)]
struct Project {
    dependencies: Vec<String>,
}

#[derive(Deserialize)]
struct LockFile {
    package: Vec<LockedPackage>,
}

#[derive(Deserialize)]
pub(crate) struct LockedPackage {
    pub(crate) name: String,
    pub(crate) version: String,
    dependencies: Option<Vec<LockedDep>>,
    #[serde(rename = "optional-dependencies")]
    optional_dependencies: Option<HashMap<String, Vec<LockedDep>>>,
}

#[derive(Deserialize)]
struct LockedDep {
    name: String,
    extra: Option<Vec<String>>,
    #[allow(dead_code)]
    marker: Option<String>,
}

#[derive(Serialize)]
struct BatchQuery {
    queries: Vec<OsvQuery>,
}

#[derive(Serialize)]
struct OsvQuery {
    version: String,
    package: OsvPackageQuery,
}

#[derive(Serialize)]
struct OsvPackageQuery {
    name: String,
    ecosystem: String,
}

#[derive(Deserialize)]
struct BatchVulnList {
    #[serde(default)]
    results: Vec<VulnList>,
}

#[derive(Deserialize)]
struct VulnList {
    #[serde(default)]
    vulns: Vec<VulnRef>,
}

#[derive(Deserialize)]
struct VulnRef {
    id: String,
}

#[derive(Deserialize)]
pub(crate) struct OsvVulnDetail {
    #[allow(dead_code)]
    pub(crate) id: String,
    pub(crate) summary: Option<String>,
    pub(crate) details: Option<String>,
    pub(crate) aliases: Option<Vec<String>>,
    pub(crate) severity: Option<Vec<OsvSeverity>>,
    pub(crate) affected: Option<Vec<OsvAffected>>,
    pub(crate) references: Option<Vec<OsvReference>>,
    // GHSA records store "severity": "HIGH" / "CRITICAL" etc. here
    pub(crate) database_specific: Option<serde_json::Value>,
    // If set, this vulnerability was retracted — must be skipped
    pub(crate) withdrawn: Option<String>,
}

#[derive(Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    severity_type: String,
    #[allow(dead_code)]
    score: String,
}

#[derive(Deserialize)]
struct OsvAffected {
    ranges: Option<Vec<OsvRange>>,
}

#[derive(Deserialize)]
struct OsvRange {
    events: Option<Vec<OsvEvent>>,
}

#[derive(Deserialize)]
struct OsvEvent {
    fixed: Option<String>,
    #[allow(dead_code)]
    introduced: Option<String>,
    #[serde(rename = "lastAffected")]
    last_affected: Option<String>,
}

#[derive(Deserialize)]
struct OsvReference {
    #[serde(rename = "type")]
    ref_type: String,
    url: String,
}

// ── Public data types ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CveInfo {
    pub id: String,
    pub summary: Option<String>,
    pub details: Option<String>,
    pub severity: Option<String>,
    /// Exact version where this CVE was fixed, if available.
    pub fix_version: Option<String>,
    /// When no fix version exists: the last version known to be affected.
    /// Implies upgrading beyond this version is safe.
    pub last_affected_version: Option<String>,
    pub advisory_url: Option<String>,
}

#[derive(Debug, Clone)]
pub struct VulnerabilityReport {
    pub package: String,
    pub version: String,
    /// Empty = direct dependency in pyproject.toml.
    /// Non-empty = path from root to this package.
    pub ancestors: Vec<String>,
    pub cves: Vec<CveInfo>,
}

pub struct ScanResult {
    pub total_scanned: usize,
    pub vulnerabilities: Vec<VulnerabilityReport>,
    // Internal state retained so fix_suggestions_from_scan avoids a second network call
    pub(crate) ancestors_map: HashMap<String, Vec<String>>,
    pub(crate) vuln_ids: HashMap<String, Vec<String>>,
    pub(crate) detail_map: HashMap<String, OsvVulnDetail>,
    pub(crate) lock_map: HashMap<String, LockedPackage>,
}

#[derive(Debug, Clone)]
pub struct FixSuggestion {
    pub package: String,
    pub current_version: String,
    /// Min version that fixes all fixable CVEs for this package.
    pub fix_version: Option<String>,
    /// If some CVEs have no fix but have lastAffected, upgrade beyond this version.
    pub last_affected_version: Option<String>,
    /// "PATCH", "MINOR", "MAJOR", or "NONE" when no fix exists.
    pub bump_type: String,
    pub is_direct: bool,
    /// Ancestor chain. Empty = direct dep.
    pub ancestors: Vec<String>,
    pub total_cve_count: usize,
    /// IDs of CVEs with no fix version AND no lastAffected info.
    pub unfixable_cve_ids: Vec<String>,
    /// Human-readable reason why Option A is safe (for transitive deps).
    pub option_a_reason: String,
    /// Immediate parent of the vulnerable package (for transitive deps).
    pub immediate_parent: Option<String>,
    pub immediate_parent_version: Option<String>,
    /// Tier-1 dep in pyproject.toml that transitively pulls this package.
    pub tier1_dep: Option<String>,
}

// ── Name helpers ──────────────────────────────────────────────────────────────

pub(crate) fn normalize_name(name: &str) -> String {
    name.to_lowercase().replace(['-', '_', '.'], "-")
}

fn extract_name(dep_str: &str) -> &str {
    let end = dep_str
        .find(|c: char| {
            matches!(c, '[' | '>' | '<' | '=' | '!' | '~' | ';') || c.is_ascii_whitespace()
        })
        .unwrap_or(dep_str.len());
    &dep_str[..end]
}

fn extract_extras(dep_str: &str) -> Vec<String> {
    let Some(start) = dep_str.find('[') else {
        return vec![];
    };
    let Some(rel_end) = dep_str[start..].find(']') else {
        return vec![];
    };
    dep_str[start + 1..start + rel_end]
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

// ── Version helpers ───────────────────────────────────────────────────────────

pub(crate) fn parse_ver(v: &str) -> (u64, u64, u64) {
    let mut parts = v.split('.').map(|p| {
        p.chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse::<u64>()
            .unwrap_or(0)
    });
    (
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
    )
}

pub(crate) fn max_ver<'a>(a: &'a str, b: &'a str) -> &'a str {
    if parse_ver(b) > parse_ver(a) { b } else { a }
}

pub(crate) fn bump_type_str(current: &str, fixed: &str) -> &'static str {
    let (cm, cn, _) = parse_ver(current);
    let (fm, fn_, _) = parse_ver(fixed);
    if fm > cm {
        "MAJOR"
    } else if fn_ > cn {
        "MINOR"
    } else {
        "PATCH"
    }
}

pub(crate) fn bump_reason(current: &str, fixed: &str, parent: &str, parent_ver: &str) -> String {
    match bump_type_str(current, fixed) {
        "MAJOR" => format!(
            "MAJOR bump — verify {} v{} supports this version before upgrading",
            parent, parent_ver
        ),
        "MINOR" => format!(
            "MINOR bump — {} v{} supports this version (new features, no breaking changes)",
            parent, parent_ver
        ),
        _ => format!(
            "PATCH bump — {} v{} already supports this version",
            parent, parent_ver
        ),
    }
}

// ── Dependency resolution ─────────────────────────────────────────────────────

fn get_deps<'a>(pkg: &'a LockedPackage, extras: &[String]) -> Vec<&'a LockedDep> {
    let mut deps: Vec<&LockedDep> = pkg.dependencies.as_deref().unwrap_or(&[]).iter().collect();
    if let Some(opt) = &pkg.optional_dependencies {
        for extra in extras {
            if let Some(extra_deps) = opt.get(extra.as_str()) {
                deps.extend(extra_deps);
            }
        }
    }
    deps
}

// ── Tree builder ──────────────────────────────────────────────────────────────

fn build_tree_string(
    name: &str,
    extras: &[String],
    lock_map: &HashMap<String, LockedPackage>,
    path: &mut HashSet<String>,
    depth: usize,
    out: &mut String,
) {
    let indent = "  ".repeat(depth);
    let extras_str = if extras.is_empty() {
        String::new()
    } else {
        format!("[{}]", extras.join(","))
    };

    if path.contains(name) {
        let _ = writeln!(out, "{}{}{} [*]", indent, name, extras_str);
        return;
    }

    match lock_map.get(name) {
        None => {
            let _ = writeln!(out, "{}{}{} [missing]", indent, name, extras_str);
        }
        Some(pkg) => {
            let _ = writeln!(out, "{}{} v{}{}", indent, name, pkg.version, extras_str);
            path.insert(name.to_owned());
            for dep in get_deps(pkg, extras) {
                let child_name = normalize_name(&dep.name);
                let child_extras = dep.extra.clone().unwrap_or_default();
                build_tree_string(&child_name, &child_extras, lock_map, path, depth + 1, out);
            }
            path.remove(name);
        }
    }
}

// ── Package collection ────────────────────────────────────────────────────────

fn collect_packages(
    name: &str,
    extras: &[String],
    lock_map: &HashMap<String, LockedPackage>,
    seen: &mut HashSet<String>,
    out: &mut Vec<(String, String)>,
) {
    if !seen.insert(name.to_owned()) {
        return;
    }
    if let Some(pkg) = lock_map.get(name) {
        out.push((pkg.name.clone(), pkg.version.clone()));
        for dep in get_deps(pkg, extras) {
            let child_name = normalize_name(&dep.name);
            let child_extras = dep.extra.clone().unwrap_or_default();
            collect_packages(&child_name, &child_extras, lock_map, seen, out);
        }
    }
}

// ── OSV queries ───────────────────────────────────────────────────────────────

fn osv_batch_query(
    packages: &[(String, String)],
    client: &reqwest::blocking::Client,
) -> anyhow::Result<HashMap<String, Vec<String>>> {
    let mut vuln_ids: HashMap<String, Vec<String>> = HashMap::new();

    // OSV /v1/querybatch is capped at 1000 packages per request
    for chunk in packages.chunks(1000) {
        let queries: Vec<OsvQuery> = chunk
            .iter()
            .map(|(name, version)| OsvQuery {
                version: version.clone(),
                package: OsvPackageQuery {
                    name: name.clone(),
                    ecosystem: "PyPI".to_string(),
                },
            })
            .collect();

        let resp: BatchVulnList = client
            .post("https://api.osv.dev/v1/querybatch")
            .json(&BatchQuery { queries })
            .send()?
            .error_for_status()?
            .json()?;

        for (i, result) in resp.results.into_iter().enumerate() {
            if !result.vulns.is_empty() {
                let ids: Vec<String> = result.vulns.into_iter().map(|v| v.id).collect();
                vuln_ids.insert(normalize_name(&chunk[i].0), ids);
            }
        }
    }

    Ok(vuln_ids)
}

fn fetch_vuln_detail(
    id: &str,
    client: &reqwest::blocking::Client,
) -> anyhow::Result<OsvVulnDetail> {
    client
        .get(format!("https://api.osv.dev/v1/vulns/{}", id))
        .send()?
        .error_for_status()?
        .json()
        .map_err(Into::into)
}

// ── Detail extraction ─────────────────────────────────────────────────────────

fn extract_fix_version(detail: &OsvVulnDetail) -> Option<&str> {
    detail.affected.as_deref()?.iter().find_map(|a| {
        a.ranges
            .as_deref()?
            .iter()
            .find_map(|r| r.events.as_deref()?.iter().find_map(|e| e.fixed.as_deref()))
    })
}

fn extract_last_affected(detail: &OsvVulnDetail) -> Option<&str> {
    detail.affected.as_deref()?.iter().find_map(|a| {
        a.ranges.as_deref()?.iter().find_map(|r| {
            r.events
                .as_deref()?
                .iter()
                .find_map(|e| e.last_affected.as_deref())
        })
    })
}

fn extract_advisory_url(detail: &OsvVulnDetail) -> Option<String> {
    if let Some(refs) = &detail.references
        && let Some(r) = refs.iter().find(|r| r.ref_type == "ADVISORY")
    {
        return Some(r.url.clone());
    }
    detail.aliases.as_deref()?.iter().find_map(|a| {
        a.starts_with("CVE-")
            .then(|| format!("https://nvd.nist.gov/vuln/detail/{}", a))
    })
}

pub(crate) fn extract_severity(detail: &OsvVulnDetail) -> Option<String> {
    if let Some(db) = &detail.database_specific
        && let Some(label) = db.get("severity").and_then(|v| v.as_str())
        && !label.is_empty()
        && label != "UNSPECIFIED"
    {
        let cvss_type = detail
            .severity
            .as_deref()
            .and_then(|s| s.first())
            .map(|s| format!(" ({})", s.severity_type));
        return Some(format!("{}{}", label, cvss_type.unwrap_or_default()));
    }
    detail
        .severity
        .as_deref()?
        .first()
        .map(|s| s.severity_type.clone())
}

// ── Audit collector ───────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn collect_audit(
    name: &str,
    extras: &[String],
    lock_map: &HashMap<String, LockedPackage>,
    vuln_ids: &HashMap<String, Vec<String>>,
    detail_map: &HashMap<String, OsvVulnDetail>,
    ancestors: &[String],
    path: &mut HashSet<String>,
    seen_vulns: &mut HashSet<String>,
    ancestors_out: &mut HashMap<String, Vec<String>>,
    out: &mut Vec<VulnerabilityReport>,
) {
    if path.contains(name) {
        return;
    }

    if let Some(ids) = vuln_ids.get(name)
        && seen_vulns.insert(name.to_owned())
    {
        ancestors_out.insert(name.to_owned(), ancestors.to_vec());
        let version = lock_map
            .get(name)
            .map(|p| p.version.clone())
            .unwrap_or_else(|| "?".to_owned());

        let cves: Vec<CveInfo> = ids
            .iter()
            .map(|id| {
                if let Some(detail) = detail_map.get(id.as_str()) {
                    CveInfo {
                        id: id.clone(),
                        summary: detail.summary.clone(),
                        details: detail.details.clone(),
                        severity: extract_severity(detail),
                        fix_version: extract_fix_version(detail).map(str::to_owned),
                        last_affected_version: extract_last_affected(detail).map(str::to_owned),
                        advisory_url: extract_advisory_url(detail),
                    }
                } else {
                    CveInfo {
                        id: id.clone(),
                        summary: None,
                        details: None,
                        severity: None,
                        fix_version: None,
                        last_affected_version: None,
                        advisory_url: None,
                    }
                }
            })
            .collect();

        out.push(VulnerabilityReport {
            package: name.to_owned(),
            version,
            ancestors: ancestors.to_vec(),
            cves,
        });
    }

    if let Some(pkg) = lock_map.get(name) {
        let mut new_ancestors = ancestors.to_vec();
        new_ancestors.push(name.to_owned());
        path.insert(name.to_owned());
        for dep in get_deps(pkg, extras) {
            let child_name = normalize_name(&dep.name);
            let child_extras = dep.extra.clone().unwrap_or_default();
            collect_audit(
                &child_name,
                &child_extras,
                lock_map,
                vuln_ids,
                detail_map,
                &new_ancestors,
                path,
                seen_vulns,
                ancestors_out,
                out,
            );
        }
        path.remove(name);
    }
}

// ── Fix suggestion builder ────────────────────────────────────────────────────

fn build_fix_suggestions_internal(
    ancestors_map: &HashMap<String, Vec<String>>,
    vuln_ids: &HashMap<String, Vec<String>>,
    detail_map: &HashMap<String, OsvVulnDetail>,
    lock_map: &HashMap<String, LockedPackage>,
) -> Vec<FixSuggestion> {
    let mut pkgs: Vec<&str> = ancestors_map.keys().map(String::as_str).collect();
    pkgs.sort_unstable();

    pkgs.into_iter()
        .filter_map(|name| {
            let ids = vuln_ids.get(name)?;
            let ancestors = &ancestors_map[name];
            let current_ver = lock_map
                .get(name)
                .map(|p| p.version.as_str())
                .unwrap_or("?");
            let is_direct = ancestors.is_empty();

            let mut min_safe: Option<&str> = None;
            let mut min_last_affected: Option<&str> = None;
            let mut unfixable_cve_ids: Vec<String> = vec![];

            for id in ids {
                if let Some(detail) = detail_map.get(id.as_str()) {
                    if let Some(v) = extract_fix_version(detail) {
                        min_safe = Some(min_safe.map_or(v, |cur| max_ver(cur, v)));
                    } else if let Some(la) = extract_last_affected(detail) {
                        min_last_affected =
                            Some(min_last_affected.map_or(la, |cur| max_ver(cur, la)));
                    } else {
                        unfixable_cve_ids.push(id.clone());
                    }
                }
            }

            let bump_type = min_safe
                .map(|v| bump_type_str(current_ver, v).to_owned())
                .unwrap_or_else(|| "NONE".to_owned());

            let (immediate_parent, immediate_parent_version) = if is_direct {
                (None, None)
            } else {
                let parent = ancestors.last().map(String::as_str).unwrap_or(name);
                let parent_ver = lock_map
                    .get(parent)
                    .map(|p| p.version.as_str())
                    .unwrap_or("?");
                (Some(parent.to_owned()), Some(parent_ver.to_owned()))
            };

            let tier1_dep = ancestors.first().cloned();

            let option_a_reason = if let Some(safe_ver) = min_safe {
                if is_direct {
                    String::new()
                } else {
                    let parent = immediate_parent.as_deref().unwrap_or(name);
                    let parent_ver = immediate_parent_version.as_deref().unwrap_or("?");
                    bump_reason(current_ver, safe_ver, parent, parent_ver)
                }
            } else {
                String::new()
            };

            Some(FixSuggestion {
                package: name.to_owned(),
                current_version: current_ver.to_owned(),
                fix_version: min_safe.map(str::to_owned),
                last_affected_version: min_last_affected.map(str::to_owned),
                bump_type,
                is_direct,
                ancestors: ancestors.clone(),
                total_cve_count: ids.len(),
                unfixable_cve_ids,
                option_a_reason,
                immediate_parent,
                immediate_parent_version,
                tier1_dep,
            })
        })
        .collect()
}

// ── File parsing ──────────────────────────────────────────────────────────────

fn parse_files(
    pyproject_path: &str,
    lock_path: &str,
) -> anyhow::Result<(PyProject, HashMap<String, LockedPackage>)> {
    let pyproject: PyProject = toml::from_str(&std::fs::read_to_string(pyproject_path)?)?;
    let lock: LockFile = toml::from_str(&std::fs::read_to_string(lock_path)?)?;
    let lock_map = lock
        .package
        .into_iter()
        .map(|p| (normalize_name(&p.name), p))
        .collect();
    Ok((pyproject, lock_map))
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Return the full dependency tree as a formatted string.
pub fn dependency_tree(pyproject_path: &str, lock_path: &str) -> anyhow::Result<String> {
    let (pyproject, lock_map) = parse_files(pyproject_path, lock_path)?;
    let mut out = String::new();
    let mut path = HashSet::new();
    for raw in &pyproject.project.dependencies {
        let name = normalize_name(extract_name(raw));
        let extras = extract_extras(raw);
        build_tree_string(&name, &extras, &lock_map, &mut path, 0, &mut out);
    }
    Ok(out)
}

/// Scan all packages in the dependency tree against OSV. Returns structured results.
pub fn vulnerability_scan(pyproject_path: &str, lock_path: &str) -> anyhow::Result<ScanResult> {
    let (pyproject, lock_map) = parse_files(pyproject_path, lock_path)?;

    let mut seen: HashSet<String> = HashSet::new();
    let mut packages: Vec<(String, String)> = vec![];
    for raw in &pyproject.project.dependencies {
        let name = normalize_name(extract_name(raw));
        let extras = extract_extras(raw);
        collect_packages(&name, &extras, &lock_map, &mut seen, &mut packages);
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    eprintln!("Querying OSV for {} packages...", packages.len());
    let vuln_ids = osv_batch_query(&packages, &client)?;

    let mut all_ids: Vec<&str> = vuln_ids.values().flatten().map(String::as_str).collect();
    all_ids.sort_unstable();
    all_ids.dedup();

    eprintln!("Fetching details for {} vulnerabilities...", all_ids.len());
    let mut detail_map: HashMap<String, OsvVulnDetail> = HashMap::new();
    for id in all_ids {
        match fetch_vuln_detail(id, &client) {
            Ok(detail) => {
                // Skip retracted vulnerabilities
                if detail.withdrawn.is_none() {
                    detail_map.insert(id.to_owned(), detail);
                }
            }
            Err(e) => eprintln!("Warning: failed to fetch {}: {}", id, e),
        }
    }

    let mut path = HashSet::new();
    let mut seen_vulns: HashSet<String> = HashSet::new();
    let mut ancestors_map: HashMap<String, Vec<String>> = HashMap::new();
    let mut vulnerabilities: Vec<VulnerabilityReport> = vec![];

    for raw in &pyproject.project.dependencies {
        let name = normalize_name(extract_name(raw));
        let extras = extract_extras(raw);
        collect_audit(
            &name,
            &extras,
            &lock_map,
            &vuln_ids,
            &detail_map,
            &[],
            &mut path,
            &mut seen_vulns,
            &mut ancestors_map,
            &mut vulnerabilities,
        );
    }

    Ok(ScanResult {
        total_scanned: packages.len(),
        vulnerabilities,
        ancestors_map,
        vuln_ids,
        detail_map,
        lock_map,
    })
}

/// Build fix suggestions from an already-completed scan. No additional network calls.
pub fn fix_suggestions_from_scan(result: &ScanResult) -> Vec<FixSuggestion> {
    build_fix_suggestions_internal(
        &result.ancestors_map,
        &result.vuln_ids,
        &result.detail_map,
        &result.lock_map,
    )
}

/// Convenience: run a full scan and return fix suggestions in one call.
pub fn fix_suggestions(
    pyproject_path: &str,
    lock_path: &str,
) -> anyhow::Result<Vec<FixSuggestion>> {
    let result = vulnerability_scan(pyproject_path, lock_path)?;
    Ok(fix_suggestions_from_scan(&result))
}

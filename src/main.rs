use clap::{Args, CommandFactory, Parser, Subcommand};
use py_uv_audit::{FixSuggestion, ScanResult};
use std::path::Path;

fn colorize_severity(s: &str) -> String {
    let upper = s.to_uppercase();
    let code = if upper.contains("CRITICAL") {
        "\x1b[91m"
    } else if upper.contains("HIGH") {
        "\x1b[31m"
    } else if upper.contains("MODERATE") || upper.contains("MEDIUM") {
        "\x1b[93m"
    } else {
        return s.to_owned();
    };
    format!("{}{}\x1b[0m", code, s)
}

fn bump_label(bump_type: &str) -> String {
    let (label, code) = match bump_type {
        "MAJOR" => ("MAJOR", "\x1b[91m"),
        "MINOR" => ("MINOR", "\x1b[93m"),
        _ => ("PATCH", "\x1b[32m"),
    };
    format!("{}{}\x1b[0m", code, label)
}

fn print_scan_report(result: &ScanResult) {
    println!("\n=== VULNERABILITY REPORT ===\n");

    if result.vulnerabilities.is_empty() {
        println!(
            "No vulnerabilities found across {} packages scanned.",
            result.total_scanned
        );
        return;
    }

    for vuln in &result.vulnerabilities {
        println!("VULNERABLE: {} v{}", vuln.package, vuln.version);
        if vuln.ancestors.is_empty() {
            println!("  Introduced via: [direct dependency]");
        } else {
            let chain: Vec<&str> = vuln
                .ancestors
                .iter()
                .map(String::as_str)
                .chain(std::iter::once(vuln.package.as_str()))
                .collect();
            println!("  Introduced via: {}", chain.join(" → "));
        }
        for cve in &vuln.cves {
            println!(
                "  - {}: {}",
                cve.id,
                cve.summary.as_deref().unwrap_or("(no summary)")
            );
            if let Some(sev) = &cve.severity {
                println!("    Severity: {}", colorize_severity(sev));
            }
            match &cve.fix_version {
                Some(v) => println!("    Fixed in: {}", v),
                None => match &cve.last_affected_version {
                    Some(la) => println!("    Fixed in: no fix version — last affected: {}", la),
                    None => println!("    Fixed in: no fix available"),
                },
            }
            if let Some(url) = &cve.advisory_url {
                println!("    Advisory: {}", url);
            }
        }
        println!();
    }

    println!(
        "--- {} vulnerable package(s) found ({} total scanned) ---",
        result.vulnerabilities.len(),
        result.total_scanned
    );
}

fn print_fix_suggestions_cli(suggestions: &[FixSuggestion]) {
    println!("\n=== REMEDIATION SUGGESTIONS ===\n");

    let direct: Vec<&FixSuggestion> = suggestions.iter().filter(|s| s.is_direct).collect();
    let transitive: Vec<&FixSuggestion> = suggestions.iter().filter(|s| !s.is_direct).collect();

    if !direct.is_empty() {
        println!("Direct dependencies:\n");
        for s in &direct {
            if let Some(fix_ver) = &s.fix_version {
                let bump = bump_label(&s.bump_type);
                println!(
                    "  {} {} → {}  [{}]",
                    s.package, s.current_version, fix_ver, bump
                );
                println!("    Command:         uv add \"{}>={}\"", s.package, fix_ver);
                println!("    pyproject.toml:  \"{}>={}\"", s.package, fix_ver);
                let fixable = s.total_cve_count - s.unfixable_cve_ids.len();
                if s.unfixable_cve_ids.is_empty() {
                    println!(
                        "    Fixes {} vulnerabilit{}",
                        fixable,
                        if fixable == 1 { "y" } else { "ies" }
                    );
                } else {
                    println!(
                        "    Fixes {} of {} vulnerabilities",
                        fixable, s.total_cve_count
                    );
                    for uid in &s.unfixable_cve_ids {
                        println!("    \x1b[91m⚠ {} has no fix available\x1b[0m", uid);
                    }
                }
            } else if let Some(la) = &s.last_affected_version {
                println!(
                    "  {} v{}  \x1b[93m[UPGRADE BEYOND {}]\x1b[0m",
                    s.package, s.current_version, la
                );
                println!("    Command:  uv add \"{}>{}\"", s.package, la);
            } else {
                println!(
                    "  {} v{}  \x1b[91m[NO FIX AVAILABLE]\x1b[0m",
                    s.package, s.current_version
                );
                println!(
                    "    ⚠ No fix available for {} vulnerabilit{} — consider replacing this dependency",
                    s.total_cve_count,
                    if s.total_cve_count == 1 { "y" } else { "ies" }
                );
            }
            println!();
        }
    }

    if !transitive.is_empty() {
        println!("Transitive dependencies:\n");
        for s in &transitive {
            let chain: Vec<&str> = s
                .ancestors
                .iter()
                .map(String::as_str)
                .chain(std::iter::once(s.package.as_str()))
                .collect();
            let via = chain.join(" → ");
            let tier1 = s.tier1_dep.as_deref().unwrap_or(s.package.as_str());

            if let Some(fix_ver) = &s.fix_version {
                let bump = bump_label(&s.bump_type);
                println!(
                    "  {} {} → {}  [{}]  (via: {})",
                    s.package, s.current_version, fix_ver, bump, via
                );
                println!("    Option A: uv lock --upgrade-package {}", s.package);
                println!("              {}", s.option_a_reason);
                println!(
                    "    Option B: add \"{}>={}\" to pyproject.toml",
                    s.package, fix_ver
                );
                println!("              if Option A causes a conflict, pin a version floor here");
                println!("    Option C: uv lock --upgrade-package {}", tier1);
                println!(
                    "              last resort — upgrades {} so it pulls in a compatible {}",
                    tier1, s.package
                );
            } else if let Some(la) = &s.last_affected_version {
                println!(
                    "  {} v{}  \x1b[93m[UPGRADE BEYOND {}]\x1b[0m  (via: {})",
                    s.package, s.current_version, la, via
                );
                println!("    Option A: uv lock --upgrade-package {}", s.package);
                println!(
                    "    Option B: add \"{}>{}\" to pyproject.toml",
                    s.package, la
                );
                println!("    Option C: uv lock --upgrade-package {}", tier1);
            } else {
                println!(
                    "  {} v{}  \x1b[91m[NO FIX AVAILABLE]\x1b[0m  (via: {})",
                    s.package, s.current_version, via
                );
            }

            for uid in &s.unfixable_cve_ids {
                println!(
                    "    \x1b[91m⚠ {} has no fix — consider replacing {}\x1b[0m",
                    uid, tier1
                );
            }
            println!();
        }
    }
}

#[derive(Parser)]
#[command(
    name = "py-uv-audit",
    version,
    about = "Vulnerability scanner for uv-managed Python projects",
    long_about = "Scans your pyproject.toml + uv.lock against the OSV database \
                  and reports vulnerable packages, with optional dependency tree \
                  and fix suggestions."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan the project for vulnerabilities
    Audit(AuditArgs),
}

#[derive(Args)]
struct AuditArgs {
    /// Print the full dependency tree before the report
    #[arg(long)]
    tree: bool,

    /// Print fix suggestions after the report
    #[arg(long)]
    suggest: bool,

    /// Path to pyproject.toml
    #[arg(long, default_value = "pyproject.toml")]
    pyproject: String,

    /// Path to uv.lock
    #[arg(long, default_value = "uv.lock")]
    lockfile: String,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        None => {
            Cli::command().print_help()?;
            println!();
            Ok(())
        }
        Some(Commands::Audit(args)) => run_audit(args),
    }
}

fn run_audit(args: AuditArgs) -> anyhow::Result<()> {
    check_project_files(&args.pyproject, &args.lockfile)?;

    if args.tree {
        println!("=== DEPENDENCY TREE ===\n");
        print!(
            "{}",
            py_uv_audit::dependency_tree(&args.pyproject, &args.lockfile)
                .map_err(wrap_network_error)?
        );
    }

    let result = py_uv_audit::vulnerability_scan(&args.pyproject, &args.lockfile)
        .map_err(wrap_network_error)?;
    print_scan_report(&result);

    if args.suggest && !result.vulnerabilities.is_empty() {
        let suggestions = py_uv_audit::fix_suggestions_from_scan(&result);
        print_fix_suggestions_cli(&suggestions);
    }

    Ok(())
}

fn check_project_files(pyproject: &str, lockfile: &str) -> anyhow::Result<()> {
    if !Path::new(pyproject).is_file() {
        anyhow::bail!(
            "pyproject.toml not found at {pyproject}\n\n\
             py-uv-audit must be run from the root of a uv-managed Python project,\n\
             or pointed at one explicitly:\n\n    \
             py-uv-audit audit --pyproject <PATH> --lockfile <PATH>\n\n\
             A 'uv-managed project' is any directory containing both pyproject.toml\n\
             and uv.lock (created by `uv init` or `uv lock`)."
        );
    }
    if !Path::new(lockfile).is_file() {
        anyhow::bail!(
            "uv.lock not found at {lockfile}\n\n\
             Run `uv lock` to generate it, or point py-uv-audit at an existing\n\
             one with --lockfile <PATH>."
        );
    }
    Ok(())
}

fn wrap_network_error(err: anyhow::Error) -> anyhow::Error {
    for cause in err.chain() {
        if let Some(re) = cause.downcast_ref::<reqwest::Error>()
            && (re.is_connect() || re.is_timeout())
        {
            return anyhow::anyhow!(
                "could not reach the OSV vulnerability database at api.osv.dev\n\n\
                 This is a network problem on your machine, not a bug in py-uv-audit.\n\
                 Try:\n  \
                 - Confirm you have an internet connection\n  \
                 - If behind a corporate proxy, set HTTPS_PROXY before re-running\n  \
                 - Check whether api.osv.dev is reachable from your browser\n\n\
                 Underlying error: {re}"
            );
        }
    }
    err
}

# py-uv-audit

A fast vulnerability scanner for [uv](https://github.com/astral-sh/uv)-managed Python
projects, written in Rust and distributed via PyPI as a precompiled binary.

Reads your `pyproject.toml` + `uv.lock`, queries the [OSV](https://osv.dev)
vulnerability database for every direct and transitive dependency, and prints a
colorized report with actionable fix suggestions.

## Installation

```sh
pip install py-uv-audit
# or, with uv:
uv tool install py-uv-audit
# or, for Rust users:
cargo install py-uv-audit
```

Pre-built wheels ship for Linux (x86_64, aarch64), macOS (x86_64, Apple Silicon),
and Windows (x86_64). No Rust toolchain required on your machine.

## Usage

Run from the root of a uv-managed Python project (directory with `pyproject.toml`
and `uv.lock`):

```sh
py-uv-audit                          # scan and report vulnerabilities
py-uv-audit --tree                   # print full dependency tree
py-uv-audit --suggest                # report + remediation suggestions
py-uv-audit --tree --suggest         # all of the above
py-uv-audit --pyproject ./path/to/pyproject.toml --lockfile ./path/to/uv.lock
```

### Example output

```
=== VULNERABILITY REPORT ===

VULNERABLE: requests v2.31.0
  Introduced via: [direct dependency]
  - GHSA-9wx4-h78v-vm56: requests vulnerable to .netrc credentials leak
    Severity: MODERATE (CVSS_V3)
    Fixed in: 2.32.0
    Advisory: https://github.com/advisories/GHSA-9wx4-h78v-vm56

--- 1 vulnerable package(s) found (42 total scanned) ---
```

## How it works under the hood

`py-uv-audit` is a Rust binary, but you install it through `pip`. The trick is what
[`ruff`](https://github.com/astral-sh/ruff) and `uv` itself do: GitHub Actions
compiles the Rust source for every (OS, arch) combination, wraps each binary in
a Python wheel, and publishes those wheels to PyPI. When you run `pip install
py-uv-audit`, pip picks the wheel matching your platform, extracts the binary into
your venv's `bin/`, and you can run `py-uv-audit` from the shell. There is no
Python code at runtime — Python is purely the installer.

## Development

Requires [Rust](https://rustup.rs) (≥ 1.85 for edition 2024) and optionally
[uv](https://github.com/astral-sh/uv) + [maturin](https://github.com/PyO3/maturin)
for testing the PyPI build.

```sh
# Iterate on the Rust source
cargo run -- --tree --suggest

# Build a release binary
cargo build --release
./target/release/py-uv-audit --tree

# Build a wheel locally (matches what CI produces)
uv tool install "maturin>=1.7,<2.0"
maturin build --release
ls dist/         # py_uv_audit-0.1.0-py3-none-<platform>.whl

# Install the wheel into a throwaway venv to test
uv venv /tmp/v
uv pip install --python /tmp/v dist/py_uv_audit-*.whl
/tmp/v/bin/py-uv-audit --tree
```

## Releasing

Releases are tagged commits on the default branch. GitHub Actions builds wheels
for every platform and publishes to PyPI automatically.

```sh
# Bump version in Cargo.toml (single source of truth — pyproject.toml reads it dynamically)
git commit -am "bump to 0.2.0"
git tag -a v0.2.0 -m "Release 0.2.0"
git push origin master --tags
```

## License

MIT

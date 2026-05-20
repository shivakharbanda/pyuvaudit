# py-uv-audit

Vulnerability scanner for `uv`-managed Python projects. Written in Rust; shipped
as a precompiled binary via PyPI wheels (maturin `bindings = "bin"` mode). PyPI
name is `py-uv-audit` because the bare `uv-audit` was taken.

There is **no PyO3 layer and no `import py_uv_audit` Python API** — `pip install`
is purely the distribution mechanism, same model as `ruff` and `uv`.

## Project structure

| Path | Purpose |
|------|---------|
| `Cargo.toml` | Crate metadata, dependencies, release profile |
| `src/lib.rs` | Business logic (parsing, OSV API, scan, fix suggestions) |
| `src/main.rs` | CLI entry point — argparse + ANSI formatting |
| `pyproject.toml` | PyPI packaging via maturin (reads version from Cargo.toml) |
| `.github/workflows/ci.yml` | Lint, build matrix (5 platforms), sdist, OIDC publish |

## Before editing any Rust code

**Always load the rust-expert skill first:**

```
/rust-expert
```

The skill is at `.claude/skills/rust-expert/SKILL.md`. It covers Rust 2024
edition idioms, ownership patterns, error handling with `anyhow`/`thiserror`,
and Clippy/fmt requirements.

## Building the CLI

```sh
cargo build                    # compile
cargo run -- --tree            # dependency tree
cargo run -- --suggest         # vuln report + fix suggestions
cargo run -- --tree --suggest  # all of the above
cargo run -- --pyproject /path/to/pyproject.toml --lockfile /path/to/uv.lock
```

## Building the PyPI wheel locally

```sh
uv tool install "maturin>=1.7,<2.0"
maturin build --release        # dist/py_uv_audit-*.whl
```

## Releasing

Bump `version` in `Cargo.toml` (single source of truth), commit, tag `v*`, push.
GitHub Actions builds wheels for all platforms and publishes to PyPI via OIDC
trusted publishing.

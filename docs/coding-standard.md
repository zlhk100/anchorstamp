<!--
SPDX-License-Identifier: CC-BY-4.0
Copyright © 2026 Lei Zhou
https://creativecommons.org/licenses/by/4.0/
-->

# Coding standard

Every rule has an identifier, a reason and a mechanical check.
`scripts/check.sh` runs all of them and prints one line per rule:
`PASS`, `FAIL` or `MISSING`. A checker that is not installed is
reported `MISSING`, never `PASS`. The script exits non-zero if any rule
fails. It passes before every commit.

Deviations from a rule are recorded in `DEVIATIONS.md` beside the
component, one entry per deviation, with the rule, the place and the
reason.

## Rust

| ID | Rule | Reason | Check |
|---|---|---|---|
| CS-RS-1 | New crates are clean under `clippy::pedantic`, warnings as errors, all targets. | A new crate starts without lint debt; a warning nobody reads is not a check. | `cargo clippy -p <crate> --no-deps --all-targets -- -W clippy::pedantic -D warnings` for each crate in `NEW_CRATES` in `scripts/check.sh`. |
| CS-RS-2 | Every crate root of a new crate carries `#![forbid(unsafe_code)]`. | Memory safety is the compiler's job in code that has no reason to be unsafe; `forbid` cannot be lifted further down. | `grep` for the attribute in `src/main.rs` and `src/lib.rs` of each new crate. |
| CS-RS-3 | Existing crates gain no clippy finding: per crate, the number of `clippy::pedantic` findings stays at or below the baseline. | Existing crates predate this standard. Their findings are recorded, not hidden, and may only go down. | Unique findings (lint, file, line, column) per crate, all targets, compared with `scripts/clippy-baseline.txt`. The baseline is written once by `scripts/check.sh --write-clippy-baseline` and lowered when findings are fixed. |
| CS-RS-4 | Every writable static is listed in `scripts/static-allowlist.txt` as `<symbol> <file> <reason>`. | Shared mutable state is where concurrency and signal bugs live; each instance is justified where a reviewer can see it. | Search of all `.rs` files under `crates/` for `static mut`, statics of interior-mutable types (atomics, locks, cells, lazy and once types) and `thread_local!`; each hit must be on the allowlist with a reason. |
| CS-RS-5 | `cargo deny check` passes on the workspace. | Licences, advisories and duplicate or unknown sources of dependencies are checked by a tool, not by eye. | `cargo deny check`; `MISSING` when `cargo-deny` is not installed. |

## Python (`demo/framework`)

| ID | Rule | Reason | Check |
|---|---|---|---|
| CS-PY-1 | `ruff check` is clean, with ruff at the version pinned in `demo/framework/requirements-dev.lock`. | One linter at one version, so findings are comparable across runs. | `scripts/dev-venv.sh <dir>` builds the development venv from the lock (hash-checked); `DEV_VENV=<dir> scripts/check.sh` runs its `ruff check --no-cache demo` after checking the ruff version against the pin. |
| CS-PY-2 | The framework is started as `python -I -B`. | `-I` keeps the user site, the current directory and `PYTHON*` variables off the import path; `-B` writes no bytecode into the root-owned environment. | Every shell line that starts `agent.py` with a Python interpreter passes `-I -B`. |
| CS-PY-3 | Dependencies come only from `demo/framework/requirements.lock` (the agent's environment) and `demo/framework/requirements-dev.lock` (development tools); every requirement in them carries a `--hash`; every `pip install` uses `--require-hashes`. | The interpreter runs code from every installed package; only reviewed, pinned, hashed packages enter an environment. | Every requirement in both lock files has `--hash=sha256:`; every `pip install` in a project shell script has `--require-hashes`; Python code without `requirements.lock` fails. |

## Shell (`demo/`, `scripts/`)

| ID | Rule | Reason | Check |
|---|---|---|---|
| CS-SH-1 | No shellcheck finding beyond `scripts/shellcheck-baseline.txt`, which records the findings of the scripts committed before this standard; a new script is therefore shellcheck clean. Every script sets `set -eu` (or stricter); `demo/run.sh` keeps its `set -eu`. | Scripts here run as root or produce evidence; an unset variable or an ignored failure must stop them. Existing findings are recorded, not hidden, and may only go down. | Findings of every `.sh` file under `demo/` and `scripts/`, keyed by file, code and line content (not line number), must all be in the baseline; and a `set -eu` line in every such file. The baseline is written once by `scripts/check.sh --write-shellcheck-baseline` and lowered when findings are fixed. |

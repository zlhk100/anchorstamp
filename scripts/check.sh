#!/bin/bash
# scripts/check.sh — the check target of the coding standard (docs/coding-standard.md).
#
#   scripts/check.sh                              run every rule
#   scripts/check.sh --write-clippy-baseline      record per-crate clippy
#                                                 pedantic finding counts
#   scripts/check.sh --write-shellcheck-baseline  record shellcheck findings
#                                                 of the committed scripts
#   Baselines are written once, on a clean tree, at the base commit.
#
#   DEV_VENV  the development venv built by scripts/dev-venv.sh; ruff is
#             taken from it (default target/dev-venv)
#
# Prints one line per rule: PASS, FAIL or MISSING. A checker that is not
# installed is MISSING, never PASS. Exits 1 if any rule FAILs, else 0.
# Runs as the operator and needs no privilege. CS-RS-5 (cargo-deny) reads
# the advisory database, which may need the network.
set -euo pipefail
export LC_ALL=C

cd "$(dirname "$0")/.."

# Crates added since the coding standard: full rules (CS-RS-1, CS-RS-2).
NEW_CRATES=(anchorstamp-exec)
BASELINE=scripts/clippy-baseline.txt
SC_BASELINE=scripts/shellcheck-baseline.txt
ALLOWLIST=scripts/static-allowlist.txt
SHELL_DIRS=(demo scripts)
DEV_VENV=${DEV_VENV:-target/dev-venv}
DEV_LOCK=demo/framework/requirements-dev.lock

fail=0
report() {
    printf '%-9s %-8s %s\n' "$1" "$2" "$3"
    if [ "$2" = FAIL ]; then fail=1; fi
}
have() { command -v "$1" >/dev/null 2>&1; }
is_new() {
    local c
    for c in "${NEW_CRATES[@]}"; do [ "$c" = "$1" ] && return 0; done
    return 1
}

# Unique clippy pedantic findings of one crate, all targets.
clippy_count() {
    cargo clippy -q -p "$1" --all-targets --message-format=json \
        -- -W clippy::pedantic 2>/dev/null |
        jq -r --arg p "$1" '
            select(.reason == "compiler-message")
            | select(.target.name != null)
            | select(.package_id | test("[/#]" + $p + "[@#]"))
            | .message
            | select(.level == "warning" and .code != null)
            | .code.code + " " + (.spans[0].file_name // "") + ":"
              + ((.spans[0].line_start // 0) | tostring) + ":"
              + ((.spans[0].column_start // 0) | tostring)' |
        sort -u | wc -l
}

# Workspace members by directory name, from Cargo.toml.
members() {
    sed -n '/^members = \[/,/^\]/p' Cargo.toml | sed -n 's|.*"crates/\([^"]*\)".*|\1|p'
}

# Shell files of the project.
shell_files() { find "${SHELL_DIRS[@]}" -type f -name '*.sh' | sort; }

# Shellcheck findings as "<file> TAB SC<code> TAB <line content>", sorted.
# Keyed by line content, not number, so unrelated edits do not shift them.
sc_findings() {
    local f ln code
    for f in "$@"; do
        { shellcheck -f json1 "$f" || true; } |
            jq -r '.comments[] | "\(.line) SC\(.code)"' |
            while read -r ln code; do
                printf '%s\t%s\t%s\n' "$f" "$code" \
                    "$(sed -n "${ln}p" "$f" | tr '\t' ' ' | sed 's/^ *//; s/ *$//')"
            done
    done | sort
}

clean_base() {
    git diff --quiet HEAD -- "$@" || { echo "$*: changed since HEAD" >&2; exit 1; }
}

if [ "${1:-}" = --write-shellcheck-baseline ]; then
    have shellcheck || { echo "shellcheck MISSING" >&2; exit 1; }
    have jq || { echo "jq MISSING" >&2; exit 1; }
    mapfile -t committed < <(git ls-tree -r --name-only HEAD -- "${SHELL_DIRS[@]}" |
        grep '\.sh$' | sort)
    clean_base "${committed[@]}"
    {
        echo "# shellcheck findings of the scripts committed at $(git rev-parse --short HEAD),"
        echo "# one per line: file, code, line content (tab-separated)."
        echo "# Written by scripts/check.sh --write-shellcheck-baseline."
        echo "# $(shellcheck --version | sed -n 's/^version: /shellcheck /p')"
        sc_findings "${committed[@]}"
    } >"$SC_BASELINE"
    cat "$SC_BASELINE"
    exit 0
fi

if [ "${1:-}" = --write-clippy-baseline ]; then
    have cargo-clippy || { echo "cargo-clippy MISSING" >&2; exit 1; }
    have jq || { echo "jq MISSING" >&2; exit 1; }
    clean_base crates Cargo.toml Cargo.lock
    {
        echo "# clippy pedantic findings per existing crate, all targets,"
        echo "# unique by lint and position. Written by"
        echo "# scripts/check.sh --write-clippy-baseline at $(git rev-parse --short HEAD)."
        echo "# $(cargo clippy --version)"
        for c in $(members); do
            is_new "$c" && continue
            echo "$c $(clippy_count "$c")"
        done
    } >"$BASELINE"
    cat "$BASELINE"
    exit 0
fi

# CS-RS-1  clippy pedantic, warnings as errors, new crates.
if ! have cargo-clippy; then
    report CS-RS-1 MISSING "cargo-clippy not installed"
else
    present=()
    for c in "${NEW_CRATES[@]}"; do [ -d "crates/$c" ] && present+=("$c"); done
    if [ ${#present[@]} -eq 0 ]; then
        report CS-RS-1 PASS "no new crate present yet"
    else
        bad=()
        for c in "${present[@]}"; do
            cargo clippy -q -p "$c" --no-deps --all-targets -- -W clippy::pedantic -D warnings ||
                bad+=("$c")
        done
        if [ ${#bad[@]} -eq 0 ]; then
            report CS-RS-1 PASS "${present[*]}"
        else
            report CS-RS-1 FAIL "${bad[*]}"
        fi
    fi
fi

# CS-RS-2  #![forbid(unsafe_code)] in every crate root of the new crates.
bad=()
checked=()
for c in "${NEW_CRATES[@]}"; do
    [ -d "crates/$c" ] || continue
    for root in "crates/$c/src/main.rs" "crates/$c/src/lib.rs"; do
        [ -f "$root" ] || continue
        checked+=("$root")
        grep -qE '^#!\[forbid\(unsafe_code\)\]' "$root" || bad+=("$root")
    done
done
if [ ${#bad[@]} -ne 0 ]; then
    report CS-RS-2 FAIL "${bad[*]}"
elif [ ${#checked[@]} -eq 0 ]; then
    report CS-RS-2 PASS "no new crate present yet"
else
    report CS-RS-2 PASS "${checked[*]}"
fi

# CS-RS-3  existing crates: no new clippy finding against the baseline.
if ! have cargo-clippy; then
    report CS-RS-3 MISSING "cargo-clippy not installed"
elif ! have jq; then
    report CS-RS-3 MISSING "jq not installed"
elif [ ! -f "$BASELINE" ]; then
    report CS-RS-3 FAIL "$BASELINE absent"
else
    bad=()
    for c in $(members); do
        is_new "$c" && continue
        base=$(awk -v c="$c" '$1 == c { print $2 }' "$BASELINE")
        if [ -z "$base" ]; then bad+=("$c:no-baseline"); continue; fi
        now=$(clippy_count "$c")
        [ "$now" -le "$base" ] || bad+=("$c:$base->$now")
    done
    if [ ${#bad[@]} -eq 0 ]; then
        report CS-RS-3 PASS "at or below $BASELINE"
    else
        report CS-RS-3 FAIL "${bad[*]}"
    fi
fi

# CS-RS-4  every writable static is on the allowlist with a reason.
# Writable: `static mut`, a static of an interior-mutable type, thread_local!.
found=$(grep -rnE \
    '^\s*(pub(\([^)]*\))?\s+)?static\s+(mut\s+)?[A-Za-z_][A-Za-z0-9_]*\s*:\s*[^=]*(Atomic|Mutex|RwLock|Cell|OnceLock|LazyLock|Lazy|Condvar|Once\b)|^\s*(pub(\([^)]*\))?\s+)?static\s+mut\s|thread_local!' \
    --include='*.rs' crates || true)
bad=()
n=0
while IFS= read -r line; do
    [ -n "$line" ] || continue
    n=$((n + 1))
    file=${line%%:*}
    if [[ $line =~ static[[:space:]]+(mut[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*) ]]; then
        sym=${BASH_REMATCH[2]}
    else
        sym=thread_local
    fi
    if [ ! -f "$ALLOWLIST" ] ||
        ! awk -v s="$sym" -v f="$file" \
            '!/^#/ && $1 == s && $2 == f && NF >= 3 { ok = 1 } END { exit !ok }' "$ALLOWLIST"; then
        bad+=("$sym@$file")
    fi
done <<<"$found"
if [ ${#bad[@]} -eq 0 ]; then
    report CS-RS-4 PASS "$n writable static(s), all listed"
else
    report CS-RS-4 FAIL "not listed: ${bad[*]}"
fi

# CS-RS-5  cargo-deny on the workspace.
if ! have cargo-deny; then
    report CS-RS-5 MISSING "cargo-deny not installed"
elif cargo deny check >&2; then
    report CS-RS-5 PASS "workspace"
else
    report CS-RS-5 FAIL "workspace"
fi

# CS-PY-1  ruff check clean, ruff at the version pinned in the dev lock.
ruff=$DEV_VENV/bin/ruff
pin=$(sed -n 's/^ruff==\([^ ]*\).*/\1/p' "$DEV_LOCK" 2>/dev/null || true)
pyfiles=$(find demo -type f -name '*.py' | sort)
if [ ! -x "$ruff" ]; then
    report CS-PY-1 MISSING "ruff not installed at $ruff (scripts/dev-venv.sh)"
elif [ -z "$pin" ]; then
    report CS-PY-1 FAIL "no ruff pin in $DEV_LOCK"
elif [ "$("$ruff" --version | awk '{ print $2 }')" != "$pin" ]; then
    report CS-PY-1 FAIL "$ruff is not ruff $pin"
elif [ -z "$pyfiles" ]; then
    report CS-PY-1 PASS "no Python code yet (ruff $pin)"
elif "$ruff" check --no-cache demo; then
    report CS-PY-1 PASS "demo (ruff $pin)"
else
    report CS-PY-1 FAIL "demo (ruff $pin)"
fi

# Shell lines with continuations joined and comments dropped.
joined() {
    awk '{ sub(/^[ \t]*#.*/, "") }
         /\\$/ { sub(/\\$/, ""); buf = buf $0 " "; next }
         { print FILENAME ": " buf $0; buf = "" }' "$@"
}
mapfile -t sh < <(shell_files)

# CS-PY-2  the framework is started as python -I -B.
lines=$(joined "${sh[@]}" | grep -E 'python[0-9.]*[[:space:]].*agent\.py' || true)
if [ -z "$lines" ]; then
    report CS-PY-2 PASS "no agent.py invocation yet"
elif badlines=$(grep -vE 'python[0-9.]*[[:space:]]+-I[[:space:]]+-B[[:space:]]' <<<"$lines"); then
    report CS-PY-2 FAIL "$(cut -d: -f1 <<<"$badlines" | sort -u | tr '\n' ' ')"
else
    report CS-PY-2 PASS "$(wc -l <<<"$lines") invocation(s)"
fi

# CS-PY-3  dependencies only from the lock files, every requirement hashed,
# every pip install with --require-hashes.
LOCK=demo/framework/requirements.lock
installs=$(joined "${sh[@]}" |
    grep -E '(^|[[:space:]/])pip3?[[:space:]]+install|-m[[:space:]]+pip[[:space:]]+install' || true)
problems=()
locks=()
for l in "$LOCK" "$DEV_LOCK"; do
    [ -f "$l" ] || continue
    locks+=("$l")
    unhashed=$(awk '/^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
                    { rec = rec $0 }
                    !/\\[[:space:]]*$/ { if (rec !~ /--hash=sha256:/) print rec; rec = "" }' "$l")
    [ -z "$unhashed" ] || problems+=("unhashed requirement in $l")
done
if [ -n "$pyfiles" ] && [ ! -f "$LOCK" ]; then
    problems+=("$LOCK absent")
fi
if [ -n "$installs" ] && grep -qv -- '--require-hashes' <<<"$installs"; then
    problems+=("pip install without --require-hashes")
fi
if [ ${#problems[@]} -ne 0 ]; then
    report CS-PY-3 FAIL "${problems[*]}"
else
    report CS-PY-3 PASS "hashed: ${locks[*]:-none}; $(grep -c . <<<"$installs" || true) install(s) require hashes"
fi

# CS-SH-1  no shellcheck finding beyond the baseline (scripts committed
# before the standard); new scripts therefore clean; set -eu in every script.
if ! have shellcheck; then
    report CS-SH-1 MISSING "shellcheck not installed"
elif ! have jq; then
    report CS-SH-1 MISSING "jq not installed"
elif [ ! -f "$SC_BASELINE" ]; then
    report CS-SH-1 FAIL "$SC_BASELINE absent"
else
    bad=()
    for f in "${sh[@]}"; do
        grep -qE '^set -eu' "$f" || bad+=("$f:no-set-eu")
    done
    new=$(comm -23 <(sc_findings "${sh[@]}") <(grep -v '^#' "$SC_BASELINE" | sort))
    if [ -n "$new" ]; then
        printf 'new shellcheck finding: %s\n' "$new" >&2
        mapfile -t -O "${#bad[@]}" bad < <(cut -f1,2 <<<"$new" | tr '\t' ':')
    fi
    if [ ${#bad[@]} -eq 0 ]; then
        report CS-SH-1 PASS "${#sh[@]} file(s), no finding beyond $SC_BASELINE"
    else
        report CS-SH-1 FAIL "${bad[*]}"
    fi
fi

# Kernel C: the module under observer/kernel follows the kernel's own
# conventions (coding-style.rst, checkpatch --strict, sparse), and its
# writable statics are listed like the Rust ones.
KDIR=${KDIR:-/lib/modules/$(uname -r)/build}
KMOD_DIRS=(observer/kernel/anchorstamp_exec)
KCC=${KCC:-x86_64-linux-gnu-gcc-12}
# Sources only: the build generates <module>.mod.c beside them.
mapfile -t kc < <(find "${KMOD_DIRS[@]}" -type f -name '*.c' ! -name '*.mod.c' 2>/dev/null | sort)

# CS-KC-1  checkpatch --strict clean.
checkpatch=$KDIR/scripts/checkpatch.pl
if [ ${#kc[@]} -eq 0 ]; then
    report CS-KC-1 PASS "no kernel C yet"
elif [ ! -f "$checkpatch" ]; then
    report CS-KC-1 MISSING "$checkpatch absent"
elif perl "$checkpatch" --strict --no-tree --quiet -f "${kc[@]}" >&2; then
    report CS-KC-1 PASS "${kc[*]}"
else
    report CS-KC-1 FAIL "${kc[*]}"
fi

# CS-KC-2  sparse clean: a C=2 build prints nothing from the checker.
if [ ${#kc[@]} -eq 0 ]; then
    report CS-KC-2 PASS "no kernel C yet"
elif ! have sparse; then
    report CS-KC-2 MISSING "sparse not installed"
elif ! have "$KCC"; then
    report CS-KC-2 MISSING "$KCC not installed"
else
    bad=()
    for d in "${KMOD_DIRS[@]}"; do
        out=$(make -s -C "$KDIR" M="$PWD/$d" CC="$KCC" C=2 modules 2>&1) || bad+=("$d:build")
        if grep -E ': (warning|error):' <<<"$out" >&2; then bad+=("$d"); fi
    done
    if [ ${#bad[@]} -eq 0 ]; then
        report CS-KC-2 PASS "${KMOD_DIRS[*]}"
    else
        report CS-KC-2 FAIL "${bad[*]}"
    fi
fi

# CS-KC-3  every writable file-scope static in kernel C is on the allowlist.
# Writable: a line-start `static` definition that is not const and not a
# function (no parenthesis before its `=` or `;`), or a static DEFINE_*().
bad=()
n=0
for f in "${kc[@]}"; do
    while IFS= read -r sym; do
        [ -n "$sym" ] || continue
        n=$((n + 1))
        awk -v s="$sym" -v f="$f" \
            '!/^#/ && $1 == s && $2 == f && NF >= 3 { ok = 1 } END { exit !ok }' \
            "$ALLOWLIST" || bad+=("$sym@$f")
    done < <(sed -nE \
        -e '/^static[[:space:]]+(const[[:space:]]|.*[[:space:]]const[[:space:]])/d' \
        -e 's/^static[[:space:]]+DEFINE_[A-Z0-9_]+\(([A-Za-z_][A-Za-z0-9_]*).*/\1/p' \
        -e 's/^static[[:space:]][^(=;]*[^A-Za-z0-9_]([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*(\[[^]]*\])?[[:space:]]*[=;].*/\1/p' \
        "$f")
done
if [ ${#bad[@]} -eq 0 ]; then
    report CS-KC-3 PASS "$n writable static(s), all listed"
else
    report CS-KC-3 FAIL "not listed: ${bad[*]}"
fi

exit "$fail"

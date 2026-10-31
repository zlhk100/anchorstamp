#!/bin/bash
# demo/run.sh — one proof-of-concept run, as root via sudo.
#
#   sudo demo/run.sh <scenario>
#   sudo demo/run.sh --leak-test <scenario>
#
# Scenarios: honest shadow forger pipeline subagent burst evade longpath
# tamper escalate.
#
# Before running, as the operator (not root):
#   cargo build --workspace --release
#   cargo build -p anchorstamp-observe-audit --release --features leak-test \
#       --target-dir target/leak-test           # only for --leak-test
#
# What it does, in order:
#    1  preflight P-1..P-7; record `auditctl -s` and `auditctl -l`
#    2  install the binaries into a new root-owned directory; record SHA-256
#    3  create the run directory (never reused) with sink/ and claims/
#    4  add the audit rules for this run; record their exact text
#    5  start the observer as a direct child
#    6  wait for its anchor; check it is our child and runs as nobody
#    7  run the scenario as the measured account, no terminal
#    8  kill every process of the measured account; settle 2 s
#    9  SIGTERM the observer by its pid; wait
#   10  delete the rules by exact text; compare rules and audit counters
#   11  run the report as the operator
# On any exit after step 4, steps 8, 9 and 10 run.
#
# It deletes nothing, rotates nothing, kills nothing by name, and never
# runs a binary from the workspace as root.

set -eu
umask 022
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
LC_ALL=C
export LC_ALL

AGENT=anchorstamp-agent
NOBODY=65534
STATE=/var/lib/anchorstamp
INSTALL_BASE=/usr/local/lib/anchorstamp-poc
AUDITD_CONF=/etc/audit/auditd.conf
SCENARIOS="honest shadow forger pipeline subagent burst evade longpath tamper escalate"

HERE=$(cd "$(dirname "$0")" && pwd -P)
TREE=$(cd "$HERE/.." && pwd -P)

# ---- logging: buffered until the run directory exists -----------------
EARLY=""
HLOG=""
log() {
    local line
    line="$(date -u +%Y-%m-%dT%H:%M:%SZ) $*"
    printf '%s\n' "$line"
    if [ -n "$HLOG" ]; then
        printf '%s\n' "$line" >>"$HLOG"
    else
        EARLY="$EARLY$line
"
    fi
}
die() {
    log "REFUSED: $*"
    exit 1
}
stop() {
    log "STOP: $*"
    STOPPED=1
}
STOPPED=0

# ---- arguments ---------------------------------------------------------
LEAK=0
if [ "${1:-}" = "--leak-test" ]; then
    LEAK=1
    shift
fi
[ $# -eq 1 ] || die "usage: sudo demo/run.sh [--leak-test] <scenario>"
SCENARIO=$1
case " $SCENARIOS " in
*" $SCENARIO "*) ;;
*) die "unknown scenario '$SCENARIO'; one of: $SCENARIOS" ;;
esac

# ---- 1 preflight -------------------------------------------------------
log "step 1 preflight; scenario=$SCENARIO leak_test=$LEAK"

# P-1  root, invoked through sudo by the operator who owns the build tree
[ "$(id -u)" -eq 0 ] || die "P-1 not root"
[ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ] || die "P-1 not invoked through sudo by an operator"
[ -d "$TREE/target/release" ] || die "P-1/P-5 no build tree at $TREE/target/release — build it first"
OWNER=$(stat -c %U "$TREE/target/release")
[ "$SUDO_USER" = "$OWNER" ] || die "P-1 SUDO_USER=$SUDO_USER does not own the build tree"
log "P-1 ok euid=0 SUDO_USER is the build tree's owner"

# P-2  auditd active, audit enabled (1, not 2: rules must be removable)
systemctl is-active --quiet auditd || die "P-2 auditd not active"
STATUS_BEFORE=$(auditctl -s)
printf '%s\n' "$STATUS_BEFORE" | grep -qx 'enabled 1' || die "P-2 audit not 'enabled 1'"
log "P-2 ok auditd active, enabled 1"

# P-3  state directory absent, or root:root 0755 and not a symlink
if [ -e "$STATE" ] || [ -L "$STATE" ]; then
    [ ! -L "$STATE" ] || die "P-3 $STATE is a symlink"
    [ -d "$STATE" ] || die "P-3 $STATE is not a directory"
    [ "$(stat -c '%u:%g %a' "$STATE")" = "0:0 755" ] || die "P-3 $STATE not root:root 0755"
fi
for d in "$INSTALL_BASE"; do
    if [ -e "$d" ] || [ -L "$d" ]; then
        [ ! -L "$d" ] && [ -d "$d" ] || die "P-3 $d is not a plain directory"
        [ "$(stat -c '%u:%g %a' "$d")" = "0:0 755" ] || die "P-3 $d not root:root 0755"
    fi
done
log "P-3 ok"

# P-4  the measured account: exists, not in sudo or adm, no login shell
AGENT_UID=$(id -u "$AGENT") || die "P-4 $AGENT does not exist"
AGENT_GROUPS=" $(id -nG "$AGENT") "
case "$AGENT_GROUPS" in
*" sudo "* | *" adm "* | *" wheel "* | *" root "*) die "P-4 $AGENT is in a privileged group" ;;
esac
AGENT_SHELL=$(getent passwd "$AGENT" | cut -d: -f7)
case "$AGENT_SHELL" in
/usr/sbin/nologin | /sbin/nologin | /bin/false | /usr/bin/false) ;;
*) die "P-4 $AGENT has shell $AGENT_SHELL" ;;
esac
[ "$AGENT_UID" -ne 0 ] && [ "$AGENT_UID" -ne "$NOBODY" ] || die "P-4 $AGENT uid $AGENT_UID"
log "P-4 ok $AGENT uid=$AGENT_UID groups=$(id -nG "$AGENT") shell=$AGENT_SHELL"

# P-5  release binaries built
REL=$TREE/target/release
OBS_SRC=$REL/anchorstamp-observe-audit
if [ "$LEAK" -eq 1 ]; then
    OBS_SRC=$TREE/target/leak-test/release/anchorstamp-observe-audit
fi
for f in "$OBS_SRC" "$REL/agentsim" "$REL/demo-report"; do
    [ -f "$f" ] && [ ! -L "$f" ] || die "P-5 missing $f — build it first"
done
log "P-5 ok"

# P-6  current rules captured
RULES_BEFORE=$(auditctl -l)
log "P-6 ok auditctl -l captured"

# P-7  audit.log below half of max_log_file
LOG_FILE=$(sed -n 's/^log_file *= *//p' "$AUDITD_CONF" | head -n1)
LOG_FILE=${LOG_FILE:-/var/log/audit/audit.log}
MAX_MB=$(sed -n 's/^max_log_file *= *//p' "$AUDITD_CONF" | head -n1)
case "$MAX_MB" in '' | *[!0-9]*) die "P-7 cannot read max_log_file" ;; esac
SIZE=$(stat -c %s "$LOG_FILE")
LIMIT=$((MAX_MB * 1024 * 1024 / 2))
if [ "$SIZE" -gt "$LIMIT" ]; then
    die "P-7 $LOG_FILE is $SIZE bytes, above half of max_log_file ($LIMIT). Rotate it yourself first: sudo service auditd rotate"
fi
log "P-7 ok $LOG_FILE size=$SIZE limit=$LIMIT"

# ---- 2 install ---------------------------------------------------------
ID=$(date -u +%Y%m%dT%H%M%S)-$$
KEY=as-$ID
[ -d "$INSTALL_BASE" ] || mkdir -m 0755 "$INSTALL_BASE"
INST=$INSTALL_BASE/$ID
mkdir -m 0755 "$INST"
mkdir -m 0755 "$INST/scenarios"
install -o root -g root -m 0755 "$OBS_SRC" "$INST/anchorstamp-observe-audit"
install -o root -g root -m 0755 "$REL/agentsim" "$INST/agentsim"
install -o root -g root -m 0755 "$REL/demo-report" "$INST/demo-report"
for s in $SCENARIOS; do
    install -o root -g root -m 0644 "$HERE/scenarios/$s.txt" "$INST/scenarios/$s.txt"
done
log "step 2 installed into $INST"
while IFS= read -r l; do log "  sha256 $l"; done < <(cd "$INST" && sha256sum anchorstamp-observe-audit agentsim demo-report scenarios/*.txt)

# ---- 3 run directory ---------------------------------------------------
[ -d "$STATE" ] || mkdir -m 0755 "$STATE"
RUN=$STATE/run-$ID
mkdir -m 0755 "$RUN"
mkdir -m 0755 "$RUN/sink"
mkdir -m 0755 "$RUN/claims"
chown "$AGENT:$AGENT" "$RUN/claims"
HLOG=$RUN/harness.log
printf '%s' "$EARLY" >"$HLOG"
CHECKS=$RUN/harness-checks.txt
: >"$CHECKS"
check() { printf '%s\n' "$*" >>"$CHECKS"; log "check $*"; }
printf '%s\n' "$STATUS_BEFORE" >"$RUN/audit-status-before.txt"
printf '%s\n' "$RULES_BEFORE" >"$RUN/audit-rules-before.txt"
log "step 3 run directory $RUN"
log "  core_pattern=$(cat /proc/sys/kernel/core_pattern) suid_dumpable=$(cat /proc/sys/fs/suid_dumpable) ptrace_scope=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo absent)"

# ---- 4 audit rules -----------------------------------------------------
RULE64="always,exit -F arch=b64 -S execve,execveat -F success=1 -F uid=$AGENT_UID -k $KEY"
RULE32="always,exit -F arch=b32 -S execve,execveat -F success=1 -F uid=$AGENT_UID -k $KEY"
RULES_ADDED=""
OBS=""
AGENTS_KILLED=0
OBSERVER_STOPPED=0
RULES_RESTORED=0

# steps 8, 9 and 10; each runs once
cleanup() {
    local rc=$?
    set +e
    if [ "$AGENTS_KILLED" -eq 0 ]; then step8; fi
    if [ "$OBSERVER_STOPPED" -eq 0 ]; then step9; fi
    if [ "$RULES_RESTORED" -eq 0 ]; then step10; fi
    log "exit rc=$rc stopped=$STOPPED"
    exit "$rc"
}

step8() {
    AGENTS_KILLED=1
    local r
    pkill -KILL -u anchorstamp-agent && r=0 || r=$?
    log "step 8 pkill -KILL -u anchorstamp-agent rc=$r (1 = none left)"
    sleep 2
    local left
    left=$(pgrep -u anchorstamp-agent | tr '\n' ' ')
    if [ -n "$left" ]; then stop "measured-account processes remain: $left"; fi
    check "agent processes after kill: ${left:-none}"
}

step9() {
    OBSERVER_STOPPED=1
    if [ -z "$OBS" ]; then
        log "step 9 no observer started"
        return
    fi
    if [ "$(awk '/^PPid:/{print $2}' "/proc/$OBS/status" 2>/dev/null)" = "$$" ]; then
        kill -TERM "$OBS"
    else
        log "step 9 observer $OBS already gone"
    fi
    wait "$OBS" && OBS_RC=0 || OBS_RC=$?
    log "step 9 observer exit=$OBS_RC (0 = clean stop on SIGTERM)"
    check "observer exit status: $OBS_RC"
}

step10() {
    RULES_RESTORED=1
    local r
    for rule in $RULES_ADDED; do
        case "$rule" in
        b64) auditctl -d $RULE64 && r=0 || r=$? ; log "step 10 delete: -d $RULE64 rc=$r" ;;
        b32) auditctl -d $RULE32 && r=0 || r=$? ; log "step 10 delete: -d $RULE32 rc=$r" ;;
        esac
    done
    local after status_after
    after=$(auditctl -l)
    printf '%s\n' "$after" >"$RUN/audit-rules-after.txt"
    if [ "$after" = "$RULES_BEFORE" ]; then
        check "audit rules after == before: yes"
    else
        check "audit rules after == before: NO"
        stop "audit rules differ from before the run"
    fi
    status_after=$(auditctl -s)
    printf '%s\n' "$status_after" >"$RUN/audit-status-after.txt"
    local lb la bb ba
    lb=$(printf '%s\n' "$STATUS_BEFORE" | awk '$1=="lost"{print $2}')
    la=$(printf '%s\n' "$status_after" | awk '$1=="lost"{print $2}')
    bb=$(printf '%s\n' "$STATUS_BEFORE" | awk '$1=="backlog"{print $2}')
    ba=$(printf '%s\n' "$status_after" | awk '$1=="backlog"{print $2}')
    check "audit lost before=$lb after=$la; backlog before=$bb after=$ba"
    if [ "$lb" != "$la" ] || [ "$bb" != "$ba" ]; then stop "audit lost or backlog changed during the run"; fi
}

trap cleanup EXIT
trap 'exit 130' INT TERM

auditctl -a $RULE64
RULES_ADDED="b64"
log "step 4 added: -a $RULE64"
auditctl -a $RULE32
RULES_ADDED="b64 b32"
log "step 4 added: -a $RULE32"
while IFS= read -r l; do log "  auditctl -l: $l"; done < <(auditctl -l)

# ---- 5 observer --------------------------------------------------------
OBS_ARGS=(--audit-log "$LOG_FILE" --sink "$RUN/sink" --key "$KEY")
if [ "$LEAK" -eq 1 ]; then
    mkdir -m 0700 "$RUN/leak"
    OBS_ARGS+=(--leak-key-file "$RUN/leak/key.bin")
fi
"$INST/anchorstamp-observe-audit" "${OBS_ARGS[@]}" </dev/null 2>"$RUN/observer.log" &
OBS=$!
log "step 5 observer started pid=$OBS"

# ---- 6 the drop, checked before the agent starts -----------------------
n=0
while [ "$(stat -c %s "$RUN/sink/anchor.pub" 2>/dev/null || echo 0)" != 32 ]; do
    kill -0 "$OBS" 2>/dev/null || die "step 6 observer exited before writing its anchor"
    n=$((n + 1))
    [ "$n" -lt 100 ] || die "step 6 no anchor after 10 s"
    sleep 0.1
done
ST=/proc/$OBS/status
[ "$(awk '/^PPid:/{print $2}' "$ST")" = "$$" ] || die "step 6 observer is not run.sh's child"
[ "$(awk '/^Uid:/{print $2,$3,$4,$5}' "$ST")" = "$NOBODY $NOBODY $NOBODY $NOBODY" ] || die "step 6 observer uids not all $NOBODY"
[ "$(awk '/^Gid:/{print $2,$3,$4,$5}' "$ST")" = "$NOBODY $NOBODY $NOBODY $NOBODY" ] || die "step 6 observer gids not all $NOBODY"
[ "$(awk '/^Groups:/{print $2}' "$ST")" = "" ] || die "step 6 observer has supplementary groups"
# A non-dumpable process's /proc directory is owned by root, whatever its uid.
[ "$(stat -c %u:%g "/proc/$OBS")" = "0:0" ] || die "step 6 /proc/$OBS not root-owned: observer is dumpable"
check "observer pid=$OBS $(grep -E '^(PPid|Uid|Gid|Groups):' "$ST" | tr '\t\n' '  ')"
check "observer /proc/$OBS owner $(stat -c %u:%g "/proc/$OBS") (0:0 = not dumpable)"
grep -q 'dropped uid=65534 gid=65534 groups=0 dumpable=0' "$RUN/observer.log" || die "step 6 observer did not log its drop"
ANCHOR_SHA=$(sha256sum "$RUN/sink/anchor.pub" | cut -d' ' -f1)
check "anchor sha256 at start $ANCHOR_SHA"
check "sink at start: $(stat -c '%n %U:%G %a' "$RUN/sink" "$RUN/sink/sightings.bin" "$RUN/sink/anchor.pub" | tr '\n' ';')"
log "step 6 ok"

# ---- 7 the measured account -------------------------------------------
set +e
sudo -n -u "$AGENT" -- setsid -w "$INST/agentsim" "$INST/scenarios/$SCENARIO.txt" "$RUN" \
    </dev/null >"$RUN/agent.log" 2>&1
AGENT_RC=$?
set -e
log "step 7 agentsim exit=$AGENT_RC"
check "agentsim exit status: $AGENT_RC (3 = a refusal test succeeded)"
if [ "$AGENT_RC" -eq 3 ]; then stop "a refusal test succeeded"; fi

# ---- 8, 9, 10 ----------------------------------------------------------
step8
step9
ANCHOR_SHA_END=$(sha256sum "$RUN/sink/anchor.pub" | cut -d' ' -f1)
if [ "$ANCHOR_SHA_END" = "$ANCHOR_SHA" ]; then
    check "anchor sha256 at end unchanged"
else
    check "anchor sha256 at end CHANGED $ANCHOR_SHA_END"
    stop "the anchor changed during the run"
fi
check "sink at end: $(stat -c '%n %U:%G %a' "$RUN/sink" "$RUN/sink/sightings.bin" "$RUN/sink/anchor.pub" | tr '\n' ';')"
check "sink entries: $(cd "$RUN/sink" && ls -A | tr '\n' ' ')"
step10

# ---- N-6 leak search ---------------------------------------------------
if [ "$LEAK" -eq 1 ]; then
    KEYHEX=$(od -An -v -tx1 "$RUN/leak/key.bin" | tr -d ' \n')
    KEYB64=$(base64 -w0 "$RUN/leak/key.bin")
    KEYB64NP=${KEYB64%%=*}
    found=0
    # every file of the run except the export itself, and the harness's own output so far
    while IFS= read -r -d '' f; do
        [ "$f" = "$RUN/leak/key.bin" ] && continue
        raw=$(od -An -v -tx1 "$f" | tr -d ' \n')
        case "$raw" in *"$KEYHEX"*) log "LEAK raw key bytes in $f"; found=1 ;; esac
        if grep -aqiF -e "$KEYHEX" "$f"; then log "LEAK hex key in $f"; found=1; fi
        if grep -aqF -e "$KEYB64NP" "$f"; then log "LEAK base64 key in $f"; found=1; fi
    done < <(find "$RUN" -type f -print0)
    if [ "$found" -eq 0 ]; then
        check "leak search: key absent (raw, hex lower/upper, base64) from every file of the run"
    else
        check "leak search: KEY FOUND"
        stop "the observer key appears in a run output"
    fi
fi

# ---- 11 report ---------------------------------------------------------
sudo -n -u "$SUDO_USER" -- "$INST/demo-report" "$RUN" >"$RUN/report.txt"
log "step 11 report written to $RUN/report.txt"
cat "$RUN/report.txt"
if [ "$STOPPED" -ne 0 ]; then
    log "run finished WITH A STOP — see above"
    exit 1
fi
log "run finished"

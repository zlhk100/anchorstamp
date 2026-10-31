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
#    1  preflight checks; record `auditctl -s` and `auditctl -l`
#    2  install the binaries and scenarios into a new root-owned directory,
#       each copied from a regular file through a descriptor; record SHA-256
#    3  create the run directory (never reused) with sink/ and claims/
#    4  add the audit rules for this run; record their exact text
#    5  start the observer as a direct child
#    6  wait for its anchor; check it is our child and runs as nobody
#    7  run the scenario as the measured account, no terminal, watching
#       the audit log's size; at 3/4 of max_log_file the account is killed
#    8  kill every process of the measured account by uid until none is
#       left; settle 2 s
#    9  SIGTERM the observer by its pid; wait at most 5 s, then SIGKILL
#   10  delete the rules by exact text; compare rules and audit counters
#   11  run the report as the operator
# On any exit after step 4, steps 8, 9 and 10 run, with INT, TERM and HUP
# ignored while they do.
#
# It deletes nothing, rotates nothing, kills nothing by name, and never
# runs a binary from the workspace as root.
#
# The audit rules are appended, so any rule already on the exit list
# would match first and stamp its own key; the preflight refuses unless
# no rule is loaded at all.

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

# root, invoked through sudo by the operator who owns the build tree
[ "$(id -u)" -eq 0 ] || die "not root"
[ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ] || die "not invoked through sudo by an operator"
[ -d "$TREE/target/release" ] || die "no build tree at $TREE/target/release — build it first"
OWNER=$(stat -c %U "$TREE/target/release")
[ "$SUDO_USER" = "$OWNER" ] || die "SUDO_USER=$SUDO_USER does not own the build tree"
log "preflight root: ok euid=0, SUDO_USER is the build tree's owner"

# auditd active, audit enabled (1, not 2: rules must be removable)
systemctl is-active --quiet auditd || die "auditd not active"
STATUS_BEFORE=$(auditctl -s)
printf '%s\n' "$STATUS_BEFORE" | grep -qx 'enabled 1' || die "audit not 'enabled 1'"
log "preflight audit: ok auditd active, enabled 1"

# state directory absent, or root:root 0755 and not a symlink
if [ -e "$STATE" ] || [ -L "$STATE" ]; then
    [ ! -L "$STATE" ] || die "$STATE is a symlink"
    [ -d "$STATE" ] || die "$STATE is not a directory"
    [ "$(stat -c '%u:%g %a' "$STATE")" = "0:0 755" ] || die "$STATE not root:root 0755"
fi
for d in "$INSTALL_BASE"; do
    if [ -e "$d" ] || [ -L "$d" ]; then
        [ ! -L "$d" ] && [ -d "$d" ] || die "$d is not a plain directory"
        [ "$(stat -c '%u:%g %a' "$d")" = "0:0 755" ] || die "$d not root:root 0755"
    fi
done
log "preflight directories: ok"

# the measured account: exists, not in sudo or adm, no login shell
AGENT_UID=$(id -u "$AGENT") || die "$AGENT does not exist"
AGENT_GROUPS=" $(id -nG "$AGENT") "
case "$AGENT_GROUPS" in
*" sudo "* | *" adm "* | *" wheel "* | *" root "*) die "$AGENT is in a privileged group" ;;
esac
AGENT_SHELL=$(getent passwd "$AGENT" | cut -d: -f7)
case "$AGENT_SHELL" in
/usr/sbin/nologin | /sbin/nologin | /bin/false | /usr/bin/false) ;;
*) die "$AGENT has shell $AGENT_SHELL" ;;
esac
[ "$AGENT_UID" -ne 0 ] && [ "$AGENT_UID" -ne "$NOBODY" ] || die "$AGENT uid $AGENT_UID"
log "preflight account: ok $AGENT uid=$AGENT_UID groups=$(id -nG "$AGENT") shell=$AGENT_SHELL"

# no process of the measured account, by real or effective uid
LEFT=$(pgrep -U "$AGENT_UID"; pgrep -u "$AGENT_UID") || true
[ -z "$LEFT" ] || die "processes of $AGENT exist before the run: $(printf '%s' "$LEFT" | tr '\n' ' ')"
log "preflight account processes: ok none"

# release binaries built
REL=$TREE/target/release
OBS_SRC=$REL/anchorstamp-observe-audit
if [ "$LEAK" -eq 1 ]; then
    OBS_SRC=$TREE/target/leak-test/release/anchorstamp-observe-audit
fi
for f in "$OBS_SRC" "$REL/agentsim" "$REL/demo-report"; do
    [ -f "$f" ] && [ ! -L "$f" ] || die "missing $f — build it first"
done
log "preflight binaries: ok"

# current rules captured; none may be loaded. An existing exit-list rule
# matches before ours and stamps its own key, so the observer would drop
# those records; task and exclude rules can suppress records outright.
RULES_BEFORE=$(auditctl -l)
[ "$RULES_BEFORE" = "No rules" ] || die "audit rules are loaded; this harness needs none (auditctl -l: $(printf '%s' "$RULES_BEFORE" | head -n3 | tr '\n' ';'))"
log "preflight rules: ok auditctl -l captured: No rules"

# auditd.conf: audit.log below half of max_log_file; name_format NONE
LOG_FILE=$(sed -n 's/^log_file *= *//p' "$AUDITD_CONF" | head -n1)
LOG_FILE=${LOG_FILE:-/var/log/audit/audit.log}
MAX_MB=$(sed -n 's/^max_log_file *= *//p' "$AUDITD_CONF" | head -n1)
case "$MAX_MB" in '' | *[!0-9]*) die "cannot read max_log_file" ;; esac
SIZE=$(stat -c %s "$LOG_FILE")
LIMIT=$((MAX_MB * 1024 * 1024 / 2))
WATCH_LIMIT=$((MAX_MB * 1024 * 1024 * 3 / 4))
if [ "$SIZE" -gt "$LIMIT" ]; then
    die "$LOG_FILE is $SIZE bytes, above half of max_log_file ($LIMIT). Rotate it yourself first: sudo service auditd rotate"
fi
log "preflight log size: ok $LOG_FILE size=$SIZE limit=$LIMIT; the run is stopped at $WATCH_LIMIT"
NAME_FORMAT=$(sed -n 's/^name_format *= *//p' "$AUDITD_CONF" | head -n1 | tr '[:lower:]' '[:upper:]')
[ "$NAME_FORMAT" = "NONE" ] || die "auditd.conf name_format is '${NAME_FORMAT:-unset}', not NONE: every record would gain a node= field"
log "preflight name_format: ok NONE"

# ---- 2 install ---------------------------------------------------------
ID=$(date -u +%Y%m%dT%H%M%S)-$$
KEY=as-$ID
[ -d "$INSTALL_BASE" ] || mkdir -m 0755 "$INSTALL_BASE"
INST=$INSTALL_BASE/$ID
mkdir -m 0755 "$INST"
mkdir -m 0755 "$INST/scenarios"

# Copy one file in as root. The source sits in a tree the operator owns,
# so: a regular file and not a symlink, checked just before the copy; the
# copy is read through one descriptor, which must name the same file the
# check saw.
copy_in() {
    local src=$1 dst=$2 mode=$3 fd seen held
    [ -f "$src" ] && [ ! -L "$src" ] || die "install source not a regular file: $src"
    exec {fd}<"$src" || die "install source cannot be opened: $src"
    seen=$(stat -c '%F %d:%i' -- "$src")
    held=$(stat -L -c '%F %d:%i' "/proc/self/fd/$fd")
    if [ -L "$src" ] || [ "$seen" != "$held" ]; then
        die "install source changed while being opened: $src"
    fi
    case "$held" in "regular file "* | "regular empty file "*) ;; *) die "install source not a regular file: $src" ;; esac
    cat <&"$fd" >"$dst" || die "install copy failed: $src"
    exec {fd}<&-
    chown root:root "$dst"
    chmod "$mode" "$dst"
}
copy_in "$OBS_SRC" "$INST/anchorstamp-observe-audit" 0755
copy_in "$REL/agentsim" "$INST/agentsim" 0755
copy_in "$REL/demo-report" "$INST/demo-report" 0755
for s in $SCENARIOS; do
    copy_in "$HERE/scenarios/$s.txt" "$INST/scenarios/$s.txt" 0644
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
OBS_START=""
OBS_RC=""
AGENTS_KILLED=0
AGENTS_REMAIN=0
OBSERVER_STOPPED=0
RULES_RESTORED=0

# steps 8, 9 and 10; each runs once. A second signal must not cut them
# short, so they run with INT, TERM and HUP ignored.
cleanup() {
    local rc=$?
    trap '' INT TERM HUP
    set +e
    if [ "$AGENTS_KILLED" -eq 0 ]; then step8; fi
    if [ "$OBSERVER_STOPPED" -eq 0 ]; then step9; fi
    if [ "$RULES_RESTORED" -eq 0 ]; then step10; fi
    log "exit rc=$rc stopped=$STOPPED"
    exit "$rc"
}

# "root-owned" when /proc/PID/status is owned 0:0, else "not root-owned"
# (also when it cannot be read). When a process's dumpable value is not 1
# the kernel gives the entries inside /proc/PID to root; the /proc/PID
# directory itself keeps the process's owner, so it shows nothing. A
# root-owned status rules out dumpable 1 only: it cannot tell 0 from 2.
proc_status_owner() {
    if [ "$(stat -c %u:%g "/proc/$1/status" 2>/dev/null)" = "0:0" ]; then
        echo "root-owned"
    else
        echo "not root-owned"
    fi
}

# Start time (field 22 of /proc/PID/stat, clock ticks since boot) of
# PID, or nothing. Fields are counted after the last ')', since the
# command name may hold spaces or parentheses.
start_time() {
    local s rest
    s=$(cat "/proc/$1/stat" 2>/dev/null) || return 1
    rest=${s##*) }
    set -- $rest
    [ $# -ge 20 ] || return 1
    printf '%s' "${20}"
}

# Whether $OBS is still the process run.sh started: our child (PPid) with
# the start time recorded at launch. bash reaps a background child as soon
# as it exits, so after that the pid may name another process; without
# both matches no signal is sent.
obs_is_ours() {
    [ -n "$OBS" ] && [ -n "$OBS_START" ] || return 1
    [ "$(awk '/^PPid:/{print $2}' "/proc/$OBS/status" 2>/dev/null)" = "$$" ] || return 1
    [ "$(start_time "$OBS")" = "$OBS_START" ]
}

# ours and not yet a zombie
obs_running() {
    obs_is_ours && [ "$(awk '/^State:/{print $2}' "/proc/$OBS/status" 2>/dev/null)" != Z ]
}

# Kill every process of the measured account, by real uid and by
# effective uid, until neither finds one; bounded. Never by name.
kill_agents() {
    local i left
    for i in 1 2 3 4 5 6 7 8 9 10; do
        pkill -KILL -U "$AGENT_UID" || true
        pkill -KILL -u "$AGENT_UID" || true
        left=$(pgrep -U "$AGENT_UID"; pgrep -u "$AGENT_UID") || true
        [ -n "$left" ] || return 0
        sleep 0.2
    done
    return 1
}

step8() {
    AGENTS_KILLED=1
    local r left
    kill_agents && r=0 || r=$?
    log "step 8 pkill -KILL by uid $AGENT_UID (real and effective) until none left: rc=$r (0 = none left)"
    sleep 2
    left=$( (pgrep -U "$AGENT_UID"; pgrep -u "$AGENT_UID") | sort -u | tr '\n' ' ') || true
    if [ -n "$left" ]; then
        AGENTS_REMAIN=1
        stop "measured-account processes remain: $left"
    fi
    check "agent processes after kill: ${left:-none}"
}

step9() {
    OBSERVER_STOPPED=1
    if [ -z "$OBS" ]; then
        log "step 9 no observer started"
        check "observer exit status: none (never started)"
        return
    fi
    # Each signal only after checking the pid still names our observer.
    if obs_running; then
        kill -TERM "$OBS" || true
        local n=0
        while obs_running; do
            n=$((n + 1))
            if [ "$n" -ge 50 ]; then
                if obs_is_ours; then
                    log "step 9 observer still running 5 s after SIGTERM; SIGKILL"
                    kill -KILL "$OBS" || true
                else
                    log "step 9 pid $OBS no longer names our observer; no SIGKILL sent"
                fi
                break
            fi
            sleep 0.1
        done
    else
        log "step 9 observer $OBS already exited (or the pid no longer names it); no signal sent"
    fi
    # bash keeps the status of a child it reaped early; wait returns it
    wait "$OBS" && OBS_RC=0 || OBS_RC=$?
    log "step 9 observer exit=$OBS_RC (0 = clean stop on SIGTERM)"
    check "observer exit status: $OBS_RC"
    case "$OBS_RC" in
    0) ;;
    1) stop "the observer's stream ended during the run (exit 1): the audit log rotated, shrank or failed" ;;
    *) stop "the observer exited $OBS_RC" ;;
    esac
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
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# recorded before each add: a signal between the two must not leave a
# rule nobody deletes (deleting one never added fails and is logged)
RULES_ADDED="b64"
auditctl -a $RULE64
log "step 4 added: -a $RULE64"
RULES_ADDED="b64 b32"
auditctl -a $RULE32
log "step 4 added: -a $RULE32"
while IFS= read -r l; do log "  auditctl -l: $l"; done < <(auditctl -l)

# ---- 5 observer --------------------------------------------------------
OBS_ARGS=(--audit-log "$LOG_FILE" --sink "$RUN/sink" --key "$KEY")
if [ "$LEAK" -eq 1 ]; then
    mkdir -m 0700 "$RUN/leak"
    OBS_ARGS+=(--leak-key-file "$RUN/leak/key.bin")
fi
# Launched and its pid and start time captured with INT, TERM and HUP
# ignored, so no signal can leave an observer cleanup does not know of.
# The observer installs its own SIGTERM handler, so the ignored
# disposition it inherits does not stop step 9.
trap '' INT TERM HUP
"$INST/anchorstamp-observe-audit" "${OBS_ARGS[@]}" </dev/null 2>"$RUN/observer.log" &
OBS=$!
OBS_START=$(start_time "$OBS") || OBS_START=""
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
log "step 5 observer started pid=$OBS start_time=${OBS_START:-unreadable}"

# ---- 6 the drop, checked before the agent starts -----------------------
n=0
while [ "$(stat -c %s "$RUN/sink/anchor.pub" 2>/dev/null || echo 0)" != 32 ]; do
    obs_running || die "step 6 observer exited before writing its anchor"
    n=$((n + 1))
    [ "$n" -lt 100 ] || die "step 6 no anchor after 10 s"
    sleep 0.1
done
ST=/proc/$OBS/status
[ -n "$OBS_START" ] || die "step 6 observer start time was not recorded"
obs_is_ours || die "step 6 pid $OBS is not run.sh's child with the start time recorded at launch"
check "observer pid=$OBS start_time=$OBS_START (field 22 of /proc/$OBS/stat; required before every signal)"
OBS_UIDS=$(awk '/^Uid:/{print $2,$3,$4,$5}' "$ST")
[ "$OBS_UIDS" = "$NOBODY $NOBODY $NOBODY $NOBODY" ] || die "step 6 observer uids not all $NOBODY: $OBS_UIDS"
check "observer uids (real effective saved fs): $OBS_UIDS"
OBS_GIDS=$(awk '/^Gid:/{print $2,$3,$4,$5}' "$ST")
[ "$OBS_GIDS" = "$NOBODY $NOBODY $NOBODY $NOBODY" ] || die "step 6 observer gids not all $NOBODY: $OBS_GIDS"
check "observer gids (real effective saved fs): $OBS_GIDS"
OBS_GROUPS=$(awk '/^Groups:/{$1=""; print}' "$ST" | tr -s ' ')
[ -z "${OBS_GROUPS# }" ] || die "step 6 observer has supplementary groups:$OBS_GROUPS"
check "observer supplementary groups: none"
# Not dumpable: the secondary check rules out dumpable 1; the primary
# evidence is the observer's own reading, since it exits unless it is 0.
[ "$(proc_status_owner "$OBS")" = "root-owned" ] || die "step 6 /proc/$OBS/status not root-owned: observer is dumpable 1"
check "/proc/$OBS/status owned 0:0      rules out dumpable 1 only"
grep -qx 'observe-audit: dropped uid=65534 gid=65534 groups=0 dumpable=0' "$RUN/observer.log" || die "step 6 observer did not log dumpable=0 after its drop"
check "the observer's own line \"dropped uid=65534 gid=65534 groups=0 dumpable=0\" — the primary evidence (it exits unless 0)"
SCOPE_LINE=$(grep -m1 -x 'observe-audit: ptrace_scope=[0-9]*' "$RUN/observer.log") || die "step 6 observer did not log ptrace_scope"
[ "${SCOPE_LINE##*=}" -ge 1 ] || die "step 6 observer reports ptrace_scope below 1"
check "observer checked ptrace_scope=${SCOPE_LINE##*=} (at least 1)"
ANCHOR_SHA=$(sha256sum "$RUN/sink/anchor.pub" | cut -d' ' -f1)
check "anchor sha256 at start $ANCHOR_SHA"
check "sink at start: $(stat -c '%n %U:%G %a' "$RUN/sink" "$RUN/sink/sightings.bin" "$RUN/sink/anchor.pub" | tr '\n' ';')"
log "step 6 ok"

# ---- 7 the measured account -------------------------------------------
# The account's execs grow the audit log. A rotation mid-run would end the
# observer's stream and delete the host's oldest log, so the size is
# watched and the account killed at 3/4 of max_log_file. The observer
# ending early is also a stop.
sudo -n -u "$AGENT" -- setsid -w "$INST/agentsim" "$INST/scenarios/$SCENARIO.txt" "$RUN" \
    </dev/null >"$RUN/agent.log" 2>&1 &
AGENT_PID=$!
log "step 7 agentsim started via sudo pid=$AGENT_PID"
PEAK=0
while kill -0 "$AGENT_PID" 2>/dev/null && [ "$(awk '/^State:/{print $2}' "/proc/$AGENT_PID/status" 2>/dev/null)" != Z ]; do
    NOW=$(stat -c %s "$LOG_FILE" 2>/dev/null || echo 0)
    [ "$NOW" -le "$PEAK" ] || PEAK=$NOW
    if [ "$NOW" -ge "$WATCH_LIMIT" ]; then
        stop "audit log reached $NOW bytes (3/4 of max_log_file is $WATCH_LIMIT); measured account killed"
        kill_agents || true
        break
    fi
    if ! obs_running; then
        stop "the observer ended while the measured account ran; measured account killed"
        kill_agents || true
        break
    fi
    sleep 0.2
done
wait "$AGENT_PID" && AGENT_RC=0 || AGENT_RC=$?
log "step 7 agentsim exit=$AGENT_RC; audit log peak size seen $PEAK of $WATCH_LIMIT"
check "audit log size during the run: peak $PEAK bytes, stop at $WATCH_LIMIT"
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

# Processes of the measured account still alive: nothing more runs.
if [ "$AGENTS_REMAIN" -ne 0 ]; then
    log "STOP: measured-account processes survived the kill rounds; leak search and report skipped"
    exit 1
fi

# ---- leak search (test build only) -------------------------------------
# Only files root wrote: claims/ belongs to the measured account and is
# not read. Regular files only, never through a symlink, at most
# LEAK_MAX bytes each; a file over the cap leaves the search incomplete,
# which is a stop.
LEAK_MAX=$((64 * 1024 * 1024))
if [ "$LEAK" -eq 1 ]; then
    KEYHEX=$(od -An -v -tx1 "$RUN/leak/key.bin" | tr -d ' \n')
    KEYB64=$(base64 -w0 "$RUN/leak/key.bin")
    KEYB64NP=${KEYB64%%=*}
    found=0
    unsearched=0
    # every root-written file of the run except the export itself
    while IFS= read -r -d '' f; do
        [ "$f" = "$RUN/leak/key.bin" ] && continue
        if [ ! -f "$f" ] || [ -L "$f" ]; then
            log "leak search: $f is not a regular file; not read"
            unsearched=1
            continue
        fi
        if [ "$(stat -c %s -- "$f")" -gt "$LEAK_MAX" ]; then
            log "leak search: $f is over $LEAK_MAX bytes; not searched"
            unsearched=1
            continue
        fi
        raw=$(od -An -v -tx1 "$f" | tr -d ' \n')
        case "$raw" in *"$KEYHEX"*) log "LEAK raw key bytes in $f"; found=1 ;; esac
        if grep -aqiF -e "$KEYHEX" "$f"; then log "LEAK hex key in $f"; found=1; fi
        if grep -aqF -e "$KEYB64NP" "$f"; then log "LEAK base64 key in $f"; found=1; fi
    done < <(find "$RUN" -path "$RUN/claims" -prune -o -type f -print0)
    if [ "$found" -eq 0 ] && [ "$unsearched" -ne 0 ]; then
        check "leak search: INCOMPLETE - a file could not be searched (see the log)"
        stop "the leak search could not read every file"
    elif [ "$found" -eq 0 ]; then
        check "leak search: key absent (raw, hex lower/upper, base64) from every root-written file of the run (claims/ excluded)"
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

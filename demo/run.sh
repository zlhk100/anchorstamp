#!/bin/bash
# demo/run.sh — one proof-of-concept run, as root via sudo.
#
#   sudo demo/run.sh <scenario>
#   sudo demo/run.sh --leak-test <scenario>
#
# Scenarios: honest shadow forger pipeline subagent burst evade longpath
# tamper escalate (agentsim); framework framework-live framework-netcheck
# (a real agent framework, demo/framework/agent.py, in the venv
# /opt/anchorstamp-venv; framework-netcheck is the test that the scope
# blocks the network).
#
# Before running, as the operator (not root):
#   cargo build --workspace --release
#   cargo build -p anchorstamp-observe-audit --release --features leak-test \
#       --target-dir target/leak-test           # only for --leak-test
# Before a framework scenario, once, as root: demo/framework/install-venv.sh
# For framework-live, Ollama serving qwen2.5:7b-instruct on 127.0.0.1:11434.
#
# The framework scenarios add: preflight checks of the venv (and, live, of
# Ollama); the bridge, agent.py and requirements.lock installed; the venv's
# `pip freeze --all` run as the measured account and hashed; in step 7 the
# agent in place of agentsim, inside a systemd scope that caps memory and
# tasks and allows IP traffic to 127.0.0.1 only (live: a 90 s budget, a stop at twice that,
# and an ss sample of the measured account's TCP/UDP peers each tick);
# the leak search also reads claims/agent-log.jsonl; after the report,
# that log is printed as the agent's own account.
#
# What it does, in order:
#    1  preflight checks; record `auditctl -s` and `auditctl -l`; the
#       measured account has no crontab and no at job; framework-netcheck:
#       the plan's curl run as the measured account outside any scope, the
#       control the block inside the scope is shown against (run again
#       after step 10)
#    2  install the binaries and scenarios into a new root-owned directory,
#       each copied from a regular file through a descriptor; record SHA-256
#    3  create the run directory (never reused) with sink/ and claims/
#    4  add the audit rules for this run; record their exact text
#    5  start the observer as a direct child
#    6  wait for its anchor; check it is our child and runs as nobody
#    7  run the scenario as the measured account, no terminal, watching
#       the audit log's size; at 3/4 of max_log_file the account is killed
#    8  kill every process of the measured account by uid until none is
#       left; settle 2 s; then check again for a crontab or at job (a stop
#       if one appeared); claims/ frozen: root-owned, no write bit
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
# auditd's own messages when it stops writing records, as the installed
# auditd 3.0.7 prints them (strings of /usr/sbin/auditd)
AUDITD_SUSPEND_TEXTS=(
    "Audit daemon is suspending logging due to previously mentioned write error"
    "Audit daemon is suspending logging due to low disk space."
    "Audit daemon is suspending logging due to no space left on logging partition."
    "Audit daemon is suspending logging due to logfile size."
)
SYSLOG=/var/log/syslog
SCENARIOS="honest shadow forger pipeline subagent burst evade longpath tamper escalate"
FRAMEWORK_SCENARIOS="framework framework-live framework-netcheck"
VENV=/opt/anchorstamp-venv
OLLAMA=127.0.0.1:11434
LIVE_MODEL=qwen2.5:7b-instruct
LIVE_BUDGET_S=90
LIVE_HARD_S=$((2 * LIVE_BUDGET_S))
CRON_SPOOL=/var/spool/cron/crontabs
AT_SPOOL=/var/spool/cron/atjobs
ATD=/usr/sbin/atd
CRON_ALLOW=/etc/cron.allow
CRON_DENY=/etc/cron.deny
AT_ALLOW=/etc/at.allow
AT_DENY=/etc/at.deny

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

# The measured account's scheduled jobs (crontab, at), which would run
# outside the run. Prints one line; returns 0 none, 1 some, 2 cannot tell.
# cron and at each count as not installed only when neither the command
# nor its spool exists; one without the other is an inconsistent install.
sched_check() {
    local out n cron
    if command -v crontab >/dev/null 2>&1 && [ -e "$CRON_SPOOL" ]; then
        # the spool file `crontab -l` would read, looked at directly: the
        # account is barred from crontab (cron.deny), and crontab then
        # refuses even root's `-l -u` for it
        if [ ! -d "$CRON_SPOOL" ] || [ ! -r "$CRON_SPOOL" ] || [ ! -x "$CRON_SPOOL" ]; then
            echo "$CRON_SPOOL is not a readable directory"
            return 2
        fi
        if [ -e "$CRON_SPOOL/$AGENT" ] || [ -L "$CRON_SPOOL/$AGENT" ]; then
            echo "a crontab of $AGENT exists"
            return 1
        fi
        cron="no crontab of $AGENT (spool $CRON_SPOOL/$AGENT absent)"
    elif ! command -v crontab >/dev/null 2>&1 && [ ! -e "$CRON_SPOOL" ]; then
        cron="cron not installed: no cron job can exist"
    else
        echo "crontab and $CRON_SPOOL do not agree: inconsistent cron install"
        return 2
    fi
    if command -v atq >/dev/null 2>&1; then
        out=$(atq 2>&1) || {
            echo "atq failed: $(printf '%s' "$out" | head -n1)"
            return 2
        }
        n=$(printf '%s\n' "$out" | awk -v u="$AGENT" '$NF == u' | wc -l)
        if [ "$n" -gt 0 ]; then
            echo "$n at job(s) of $AGENT"
            return 1
        fi
        echo "$cron; no at job of $AGENT"
    elif [ -e "$ATD" ] || [ -e "$AT_SPOOL" ]; then
        echo "atq absent but $ATD or $AT_SPOOL present: inconsistent at install"
        return 2
    else
        echo "$cron; at not installed (no atq, no atd, no spool): no at job can exist"
    fi
    return 0
}

# Whether user $1 is listed in file $2 (one name per line).
listed() {
    [ -f "$2" ] && awk -v u="$1" '{ sub(/^[ \t]+/, ""); sub(/[ \t]+$/, "") } $0 == u { f = 1 } END { exit !f }' "$2"
}

# Whether the measured account is barred from creating cron jobs, and at
# jobs when at is installed: when the allow file exists, by not being in
# it; otherwise by being in the deny file. Prints one line; returns 0
# barred, 1 not.
sched_barred() {
    local cron at
    if command -v crontab >/dev/null 2>&1; then
        if [ -e "$CRON_ALLOW" ]; then
            if listed "$AGENT" "$CRON_ALLOW"; then
                echo "$AGENT is in $CRON_ALLOW: it can create cron jobs"
                return 1
            fi
            cron="cron: $CRON_ALLOW exists and does not list $AGENT"
        elif listed "$AGENT" "$CRON_DENY"; then
            cron="cron: $AGENT is in $CRON_DENY"
        else
            echo "$AGENT can create cron jobs: no $CRON_ALLOW and not in $CRON_DENY (add it there)"
            return 1
        fi
    else
        cron="cron: not installed"
    fi
    if command -v at >/dev/null 2>&1 || command -v atq >/dev/null 2>&1; then
        if [ -e "$AT_ALLOW" ]; then
            if listed "$AGENT" "$AT_ALLOW"; then
                echo "$AGENT is in $AT_ALLOW: it can create at jobs"
                return 1
            fi
            at="at: $AT_ALLOW exists and does not list $AGENT"
        elif listed "$AGENT" "$AT_DENY"; then
            at="at: $AGENT is in $AT_DENY"
        else
            echo "$AGENT can create at jobs: no $AT_ALLOW and not in $AT_DENY (add it there)"
            return 1
        fi
    else
        at="at: not installed"
    fi
    echo "$cron; $at"
}

# Open $1 for reading on descriptor AFD, only if it is a regular file, not
# a symbolic link, and the opened file has exactly one link. Checked first
# so no FIFO is opened. Returns 1, with AFD empty, otherwise.
open_single() {
    AFD=""
    if [ -L "$1" ] || [ ! -f "$1" ]; then return 1; fi
    exec {AFD}<"$1" || {
        AFD=""
        return 1
    }
    case "$(stat -L -c '%F %h' "/proc/self/fd/$AFD")" in
    "regular file 1" | "regular empty file 1") return 0 ;;
    esac
    exec {AFD}<&-
    AFD=""
    return 1
}

# The entries under $RUN/claims that match the find tests given (none:
# every entry), as "<count> entries: <listing>". Each entry is listed with
# owner, mode, type and link count; the listing is cut to 64 KiB and every
# byte outside printable ASCII shown as '?'. The names are the measured
# account's. Returns 1, printing nothing, when find fails.
claims_list() {
    local n list
    n=$(find -P "$RUN/claims" "$@" -printf . | wc -c; exit "${PIPESTATUS[0]}") || return 1
    list=$(find -P "$RUN/claims" "$@" -printf 'claims/%P %u:%g %m %y links=%n;' 2>/dev/null |
        head -c 65537 | LC_ALL=C tr -c '\40-\176' '?')
    if [ "${#list}" -gt 65536 ]; then list="${list:0:65536} [listing cut at 65536 bytes]"; fi
    printf '%s entries: %s' "$n" "$list"
}

# The value of key $1 in auditd.conf, surrounding blanks removed; empty
# when the key is absent.
auditd_value() {
    sed -n "s/^$1[[:space:]]*=[[:space:]]*//p" "$AUDITD_CONF" | head -n1 | sed 's/[[:space:]]*$//'
}

# How many lines of auditd.conf set key $1.
auditd_count() {
    grep -c "^$1[[:space:]]*=" "$AUDITD_CONF" || true
}

# A free-space threshold of auditd.conf, key $1, in bytes: the value is in
# megabytes, or, ending in %, a percentage from 1 to 99 of the size ($2
# bytes) of the filesystem holding the log. Prints nothing and returns 1
# when the key is absent or its value is neither form: never a default.
auditd_space() {
    local v
    v=$(auditd_value "$1")
    case "$v" in
    [1-9]% | [1-9][0-9]%) printf '%s\n' $((${v%\%} * $2 / 100)) ;;
    '' | *[!0-9]* | ?????????????*) return 1 ;;
    *) printf '%s\n' $((10#$v * 1024 * 1024)) ;;
    esac
}

# auditd's own messages since step 1 ($AUDITD_SINCE), from $SUSPEND_SRC,
# searched for the texts with which it announces that it suspends logging.
# Prints the matching lines (at most 5, printable ASCII); returns 0 found,
# 1 none, 2 the search failed.
auditd_suspend_search() {
    local msgs size found t
    local pat=()
    for t in "${AUDITD_SUSPEND_TEXTS[@]}"; do pat+=(-e "$t"); done
    case "$SUSPEND_SRC" in
    journal)
        msgs=$(journalctl -u auditd -q --since "$AUDITD_SINCE" -o cat) || return 2
        ;;
    syslog)
        if [ -L "$SYSLOG" ] || [ ! -f "$SYSLOG" ]; then return 2; fi
        # rotated or replaced since step 1: the offset means nothing
        [ "$(stat -c %d:%i "$SYSLOG" 2>/dev/null)" = "$SYSLOG_ID" ] || return 2
        size=$(stat -c %s "$SYSLOG") || return 2
        [ "$size" -ge "$SYSLOG_OFF" ] || return 2
        msgs=$(tail -c +"$((SYSLOG_OFF + 1))" "$SYSLOG") || return 2
        ;;
    *) return 2 ;;
    esac
    found=$(printf '%s\n' "$msgs" | grep -a -F "${pat[@]}" | head -n 5 | LC_ALL=C tr -c '\12\40-\176' '?') || true
    [ -n "$found" ] || return 1
    printf '%s' "$found"
}

# The search above, logged as a check; a suspension found or a failed
# search is a stop. $1 names the point in the run.
auditd_suspend_check() {
    local out r
    out=$(auditd_suspend_search) && r=0 || r=$?
    case "$r" in
    0)
        check "auditd suspension search $1 ($SUSPEND_SRC since $AUDITD_SINCE): FOUND: $(printf '%s' "$out" | tr '\n' ';')"
        stop "auditd suspended logging during the run; audit evidence incomplete"
        ;;
    1) check "auditd suspension search $1 ($SUSPEND_SRC since $AUDITD_SINCE): none" ;;
    *)
        check "auditd suspension search $1 ($SUSPEND_SRC since $AUDITD_SINCE): the search failed"
        stop "the search for an auditd suspension failed ($1)"
        ;;
    esac
}

# The netcheck control: the plan's curl as the measured account, outside
# any scope, stdin /dev/null. Sets CTRL_RC, CTRL_CODE (the HTTP code,
# digits only) and CTRL_ERR (the last 512 bytes of its stderr, one line,
# printable ASCII). The stderr is captured through descriptor 3; the exit
# status and HTTP code follow it on the last line.
netcheck_control() {
    local all last
    all=$({
        out=$(sudo -n -u "$AGENT" -- env -i PATH=/usr/bin:/bin /usr/bin/curl -sS \
            -o /dev/null -w '%{http_code}' --max-time 3 http://1.1.1.1/ </dev/null 2>&3) && r=0 || r=$?
        printf '\n%s %s' "$r" "$out"
    } 3>&1)
    last=${all##*$'\n'}
    CTRL_RC=${last%% *}
    case "$CTRL_RC" in '' | *[!0-9]*) CTRL_RC=255 ;; esac
    CTRL_CODE=$(printf '%s' "${last#* }" | LC_ALL=C tr -cd '0-9' | head -c 3)
    CTRL_ERR=$(printf '%s' "${all%$'\n'*}" | tail -c 512 | tr '\n' ' ' | LC_ALL=C tr -cd '\40-\176')
}

# Whether auditd is writing records: a user record with text $1 sent with
# auditctl -m, then $LOG_FILE polled for that exact text (fixed string,
# read as root) every 0.2 s for up to 5 s. Returns 0 seen, 1 not seen,
# 2 auditctl -m failed.
audit_marker() {
    local i
    auditctl -m "$1" >/dev/null 2>&1 || return 2
    for i in $(seq 1 25); do
        if grep -qF -- "$1" "$LOG_FILE"; then return 0; fi
        sleep 0.2
    done
    return 1
}

# curl reads a config file from its user's home even with HOME unset; one
# there could change what the netcheck curls do. Prints the first of
# .curlrc and .config/curlrc (or a symbolic link of that name) in the
# measured account's home and returns 0; returns 1 when there is none.
curl_config_found() {
    local h f
    h=$(getent passwd "$AGENT" | cut -d: -f6)
    if [ -n "$h" ] && [ -d "$h" ]; then
        for f in "$h/.curlrc" "$h/.config/curlrc"; do
            if [ -e "$f" ] || [ -L "$f" ]; then
                printf '%s' "$f"
                return 0
            fi
        done
    fi
    return 1
}

# ---- arguments ---------------------------------------------------------
LEAK=0
if [ "${1:-}" = "--leak-test" ]; then
    LEAK=1
    shift
fi
[ $# -eq 1 ] || die "usage: sudo demo/run.sh [--leak-test] <scenario>"
SCENARIO=$1
FRAMEWORK=0
LIVE=0
case " $SCENARIOS " in
*" $SCENARIO "*) ;;
*)
    case " $FRAMEWORK_SCENARIOS " in
    *" $SCENARIO "*) FRAMEWORK=1 ;;
    *) die "unknown scenario '$SCENARIO'; one of: $SCENARIOS $FRAMEWORK_SCENARIOS" ;;
    esac
    ;;
esac
if [ "$SCENARIO" = framework-live ]; then LIVE=1; fi

# ---- 1 preflight -------------------------------------------------------
log "step 1 preflight; scenario=$SCENARIO leak_test=$LEAK"
# auditd's messages from here on are searched for a suspension
AUDITD_SINCE=$(date -u '+%Y-%m-%d %H:%M:%S UTC')

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
# the suspension texts searched for below are this auditd's own
AUDITD_BIN=$(command -v auditd) || die "auditd binary not found in $PATH"
for t in "${AUDITD_SUSPEND_TEXTS[@]}"; do
    grep -aqF -- "$t" "$AUDITD_BIN" || die "$AUDITD_BIN does not contain \"$t\": the suspension search would not match this auditd"
done
log "preflight auditd suspension texts: ok all ${#AUDITD_SUSPEND_TEXTS[@]} found in $AUDITD_BIN"
# where auditd's own messages are read: the journal, if it holds any of
# auditd's; else the syslog file from its size now, the same file
# (device and inode) at search time
SYSLOG_OFF=0
SYSLOG_ID=""
if [ -n "$(journalctl -u auditd -q -n 1 -o cat 2>/dev/null)" ]; then
    SUSPEND_SRC=journal
elif [ ! -L "$SYSLOG" ] && [ -f "$SYSLOG" ] && SYSLOG_ID=$(stat -c %d:%i "$SYSLOG") &&
    SYSLOG_OFF=$(stat -c %s "$SYSLOG"); then
    SUSPEND_SRC=syslog
else
    die "no auditd message in the journal and no $SYSLOG: a suspension of auditd's logging could not be detected"
fi
log "preflight auditd messages: read from the $SUSPEND_SRC since $AUDITD_SINCE (syslog ${SYSLOG_ID:-n/a} offset $SYSLOG_OFF)"

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

# framework-netcheck: the control. The same curl as the measured account,
# outside any scope, before the rules exist. If it cannot reach 1.1.1.1
# here, a failure inside the scope shows nothing about the scope.
NETCHECK_CTRL=0
if [ "$SCENARIO" = framework-netcheck ]; then
    if f=$(curl_config_found); then die "$f exists: a curl config of $AGENT could change the netcheck"; fi
    log "preflight netcheck curl config: ok none in the home of $AGENT ($(getent passwd "$AGENT" | cut -d: -f6))"
    netcheck_control
    CTRL1="rc=$CTRL_RC http_code=${CTRL_CODE:-none} stderr_tail=\"$CTRL_ERR\""
    log "preflight netcheck control 1: curl http://1.1.1.1/ as $AGENT outside any scope: $CTRL1"
    if [ "$CTRL_RC" -eq 0 ]; then
        NETCHECK_CTRL=1
    else
        stop "netcheck control failed outside the scope: no block can be shown (inconclusive)"
    fi
fi

# no crontab and no at job of the measured account
SCHED_BEFORE=$(sched_check) && r=0 || r=$?
[ "$r" -eq 0 ] || die "scheduled jobs: $SCHED_BEFORE"
log "preflight scheduled jobs: ok $SCHED_BEFORE"
# and it cannot create any
BARRED=$(sched_barred) || die "scheduling: $BARRED"
log "preflight scheduling barred: ok $BARRED"

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

# framework: the bridge built; the venv present, a plain directory owned
# by root, nothing under it owned by anyone else or writable by group or
# other (symbolic links excepted: their mode is not used); live: Ollama
# answers on $OLLAMA and lists the model, asked as the operator.
if [ "$FRAMEWORK" -eq 1 ]; then
    for f in "$REL/anchorstamp-exec" "$HERE/framework/agent.py" "$HERE/framework/requirements.lock"; do
        if [ ! -f "$f" ] || [ -L "$f" ]; then die "missing $f — build it first"; fi
    done
    command -v systemd-run >/dev/null || die "systemd-run not found: the framework runs inside a scope"
    CGFS=$(stat -f -c %T /sys/fs/cgroup 2>/dev/null) || CGFS=unreadable
    [ "$CGFS" = cgroup2fs ] || die "/sys/fs/cgroup is $CGFS, not cgroup2fs: MemoryMax and TasksMax need the unified cgroup v2 hierarchy"
    log "preflight cgroup: ok /sys/fs/cgroup is cgroup2fs"
    if [ -L "$VENV" ] || [ ! -d "$VENV" ]; then die "$VENV is not a directory; run demo/framework/install-venv.sh"; fi
    [ "$(stat -c '%u:%g' "$VENV")" = "0:0" ] || die "$VENV not owned by root:root"
    BAD=$(find "$VENV" \( ! -uid 0 -o ! -gid 0 \) -print -quit)
    [ -z "$BAD" ] || die "$VENV has an entry not owned by root:root: $BAD"
    BAD=$(find "$VENV" ! -type l -perm /022 -print -quit)
    [ -z "$BAD" ] || die "$VENV has an entry writable by group or other: $BAD"
    [ -x "$VENV/bin/python" ] || die "$VENV/bin/python is not executable"
    # every directory above it root's, not a link, writable by root only;
    # and no setuid or setgid entry in it
    d=$(dirname "$VENV")
    while :; do
        [ ! -L "$d" ] || die "$d (above $VENV) is a symbolic link"
        [ "$(stat -c '%u:%g' "$d")" = "0:0" ] || die "$d (above $VENV) not owned by root:root"
        [ -z "$(find "$d" -maxdepth 0 -perm /022)" ] || die "$d (above $VENV) is writable by group or other"
        [ "$d" != / ] || break
        d=$(dirname "$d")
    done
    BAD=$(find "$VENV" -perm /6000 -print -quit)
    [ -z "$BAD" ] || die "$VENV has a setuid or setgid entry: $BAD"
    log "preflight venv: ok $VENV root:root, nothing group- or other-writable, no setuid or setgid; directories above it root's and not group- or other-writable"
    if [ "$LIVE" -eq 1 ]; then
        MODELS=$(sudo -n -u "$SUDO_USER" -- curl -sS --max-time 5 "http://$OLLAMA/v1/models") ||
            die "Ollama does not answer on $OLLAMA"
        printf '%s' "$MODELS" | grep -Eq "\"id\": *\"${LIVE_MODEL//./\\.}\"" ||
            die "Ollama on $OLLAMA does not list $LIVE_MODEL"
        log "preflight ollama: ok $OLLAMA lists $LIVE_MODEL"
        ss -tuneH >/dev/null || die "ss -tuneH fails: the live run's socket sample would be empty"
        log "preflight ss: ok"
    fi
fi

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
# framework: a margin above auditd's own free-space thresholds. auditd
# acts at space_left and admin_space_left (the actions are logged); the harness
# kills the measured account first, at STOP_FREE = the larger of the two
# plus 4 GiB available, and starts only with room for the audit log to
# grow to twice max_log_file above that.
if [ "$FRAMEWORK" -eq 1 ]; then
    FS_SIZE=$(df -B1 --output=size "$LOG_FILE" | tail -n1 | tr -d ' ')
    case "$FS_SIZE" in '' | *[!0-9]*) die "cannot read the size of the filesystem under $LOG_FILE" ;; esac
    for k in space_left admin_space_left; do
        n=$(auditd_count "$k")
        case "$n" in '' | *[!0-9]*) die "cannot count $k in $AUDITD_CONF" ;; esac
        [ "$n" -le 1 ] || die "auditd.conf sets $k $n times: which one auditd uses is not checked here"
    done
    SL_RAW=$(auditd_value space_left | LC_ALL=C tr -cd '\40-\176')
    ASL_RAW=$(auditd_value admin_space_left | LC_ALL=C tr -cd '\40-\176')
    SL=$(auditd_space space_left "$FS_SIZE") || die "auditd.conf space_left '$SL_RAW' is not megabytes or a percentage from 1 to 99"
    ASL=$(auditd_space admin_space_left "$FS_SIZE") || die "auditd.conf admin_space_left '$ASL_RAW' is not megabytes or a percentage from 1 to 99"
    for a in space_left_action admin_space_left_action disk_full_action disk_error_action; do
        v=$(auditd_value "$a" | LC_ALL=C tr -cd '\40-\176')
        log "preflight auditd $a=${v:-unset}"
        if [ "$a" = admin_space_left_action ]; then ASL_ACTION=${v:-unset}; fi
    done
    STOP_FREE=$(((SL > ASL ? SL : ASL) + 4 * 1024 * 1024 * 1024))
    log "preflight auditd space_left=$SL_RAW ($SL bytes) admin_space_left=$ASL_RAW ($ASL bytes) on a filesystem of $FS_SIZE bytes; STOP_FREE=$STOP_FREE bytes (the larger plus 4 GiB)"
    FREE=$(df -B1 --output=avail "$LOG_FILE" | tail -n1 | tr -d ' ')
    case "$FREE" in '' | *[!0-9]*) die "cannot read free space under $LOG_FILE" ;; esac
    NEED=$((STOP_FREE + 2 * MAX_MB * 1024 * 1024))
    [ "$FREE" -ge "$NEED" ] || die "free space under $LOG_FILE is $FREE bytes, below STOP_FREE + 2 x max_log_file ($NEED)"
    log "preflight free space: ok $FREE bytes under $LOG_FILE, at least $NEED (STOP_FREE + 2 x max_log_file)"
fi

# The run's identifier, fixed here so the markers can carry it.
ID=$(date -u +%Y%m%dT%H%M%S)-$$
# auditd is writing records now: a suspended auditd still accepts rules
# and reports "enabled 1", but writes nothing.
MARK_PRE="anchorstamp preflight $ID"
audit_marker "$MARK_PRE" && r=0 || r=$?
case "$r" in
0) log "preflight audit marker: ok \"$MARK_PRE\" written to $LOG_FILE" ;;
2) die "auditctl -m failed: auditd is not writing records (suspended?): restart auditd" ;;
*) die "audit marker \"$MARK_PRE\" not in $LOG_FILE after 5 s: auditd is not writing records (suspended?): restart auditd" ;;
esac

# ---- 2 install ---------------------------------------------------------
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
if [ "$FRAMEWORK" -eq 1 ]; then
    copy_in "$REL/anchorstamp-exec" "$INST/anchorstamp-exec" 0755
    copy_in "$HERE/framework/agent.py" "$INST/agent.py" 0644
    copy_in "$HERE/framework/requirements.lock" "$INST/requirements.lock" 0644
fi
log "step 2 installed into $INST"
while IFS= read -r l; do log "  sha256 $l"; done < <(cd "$INST" && sha256sum anchorstamp-observe-audit agentsim demo-report scenarios/*.txt)
if [ "$FRAMEWORK" -eq 1 ]; then
    while IFS= read -r l; do log "  sha256 $l"; done < <(cd "$INST" && sha256sum anchorstamp-exec agent.py requirements.lock)
    # What the measured account's interpreter sees installed; before the
    # rules are added, so it is not part of the observed run.
    FREEZE=$(cd / && sudo -n -u "$AGENT" -- env -i PATH=/usr/bin:/bin LANG=C.UTF-8 \
        "$VENV/bin/python" -I -B -m pip freeze --all --disable-pip-version-check --no-input) ||
        die "pip freeze as $AGENT failed"
    while IFS= read -r l; do log "  pip freeze --all ($AGENT): $l"; done <<<"$FREEZE"
    log "  sha256 $(printf '%s\n' "$FREEZE" | sha256sum | cut -d' ' -f1)  pip freeze --all as $AGENT"
    LEFT=$(pgrep -U "$AGENT_UID"; pgrep -u "$AGENT_UID") || true
    [ -z "$LEFT" ] || die "processes of $AGENT remain after pip freeze: $(printf '%s' "$LEFT" | tr '\n' ' ')"
fi

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
check "scheduled jobs before the run: $SCHED_BEFORE"
check "scheduling barred for the measured account: $BARRED"
if [ "$FRAMEWORK" -eq 1 ]; then
    check "auditd takes admin_space_left_action=$ASL_ACTION at admin_space_left=$ASL_RAW ($ASL bytes available); the harness kills the measured account at $STOP_FREE bytes available"
fi
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
    # auditd still writing at the end of the run
    local mark_end="anchorstamp end $ID"
    audit_marker "$mark_end" && r=0 || r=$?
    if [ "$r" -eq 0 ]; then
        check "audit marker at the end: \"$mark_end\" written to $LOG_FILE"
    else
        check "audit marker at the end: \"$mark_end\" NOT written to $LOG_FILE (auditctl -m rc class $r)"
        stop "auditd was not writing at the end of the run; audit evidence incomplete"
    fi
    auditd_suspend_check "at step 10"
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
# The framework: an empty environment but for PATH, LANG and the two
# Hugging Face switches; the venv's interpreter isolated (-I) and writing no
# bytecode (-B); the bridge by absolute path; started in /. Live: the
# model on Ollama.
# The whole of it runs in a transient systemd scope: memory and tasks
# capped, IP traffic denied except to 127.0.0.1.
SCOPE=()
if [ "$FRAMEWORK" -eq 1 ]; then
    AGENT_NAME=agent.py
    MODEL=scripted
    if [ "$LIVE" -eq 1 ]; then MODEL="openai:http://$OLLAMA/v1#$LIVE_MODEL"; fi
    if [ "$SCENARIO" = framework-netcheck ]; then MODEL=scripted:netcheck; fi
    SCOPE_UNIT=anchorstamp-agent-$ID
    SCOPE=(systemd-run --scope --quiet --unit "$SCOPE_UNIT" -p MemoryMax=4G -p TasksMax=256 \
        -p IPAddressDeny=any -p IPAddressAllow=127.0.0.1/32 --)
    AGENT_CMD=(setsid -w env -i -C / PATH=/usr/bin:/bin LANG=C.UTF-8 HF_HUB_OFFLINE=1 HF_HUB_DISABLE_TELEMETRY=1 \
        "$VENV"/bin/python -I -B "$INST/agent.py" "$RUN" \
        --bridge "$INST/anchorstamp-exec" --model "$MODEL")
else
    AGENT_NAME=agentsim
    AGENT_CMD=(setsid -w "$INST/agentsim" "$INST/scenarios/$SCENARIO.txt" "$RUN")
fi
if [ "$FRAMEWORK" -eq 1 ]; then
    log "step 7 command: ${SCOPE[*]} sudo -n -u $AGENT -- ${AGENT_CMD[*]}"
    check "framework scope: $SCOPE_UNIT.scope (MemoryMax=4G TasksMax=256 IPAddressDeny=any IPAddressAllow=127.0.0.1/32)"
fi
AGENT_T0=$(date +%s%N)
"${SCOPE[@]}" sudo -n -u "$AGENT" -- "${AGENT_CMD[@]}" \
    </dev/null >"$RUN/agent.log" 2>&1 &
AGENT_PID=$!
log "step 7 $AGENT_NAME started via sudo pid=$AGENT_PID"
PEAK=0
SS_TICKS=0
SS_FOREIGN=0
SCOPE_SEEN=0
while kill -0 "$AGENT_PID" 2>/dev/null && [ "$(awk '/^State:/{print $2}' "/proc/$AGENT_PID/status" 2>/dev/null)" != Z ]; do
    NOW=$(stat -c %s "$LOG_FILE" 2>/dev/null || echo 0)
    [ "$NOW" -le "$PEAK" ] || PEAK=$NOW
    # live: the measured account's TCP/UDP sockets whose peer is not
    # Ollama. With two protocols ss prints a Netid column: the peer is $6.
    # No -p: process names are the measured account's to choose; a logged
    # line is cut to printable ASCII.
    if [ "$LIVE" -eq 1 ]; then
        SS_TICKS=$((SS_TICKS + 1))
        while IFS= read -r l; do
            [ -n "$l" ] || continue
            SS_FOREIGN=$((SS_FOREIGN + 1))
            log "step 7 ss: measured-account TCP/UDP peer other than $OLLAMA: $(printf '%s' "$l" | LC_ALL=C tr -cd '\11\40-\176')"
        done < <(ss -tuneH 2>/dev/null | awk -v u="uid:$AGENT_UID" -v ok="$OLLAMA" \
            '{ for (i = 7; i <= NF; i++) if ($i == u) { if ($6 != ok) print; break } }')
    fi
    if [ "$NOW" -ge "$WATCH_LIMIT" ]; then
        stop "audit log reached $NOW bytes (3/4 of max_log_file is $WATCH_LIMIT); measured account killed"
        kill_agents || true
        break
    fi
    # framework: a process of the measured account seen inside the scope
    if [ "$FRAMEWORK" -eq 1 ] && [ "$SCOPE_SEEN" -eq 0 ]; then
        for p in $(pgrep -U "$AGENT_UID"); do
            cg=$(cat "/proc/$p/cgroup" 2>/dev/null) || continue
            case "$cg" in
            *"/$SCOPE_UNIT.scope")
                SCOPE_SEEN=1
                log "step 7 pid $p of $AGENT is in its scope: $cg"
                break
                ;;
            esac
        done
    fi
    # framework: free space under the audit log at least STOP_FREE, above
    # the point where auditd itself acts
    if [ "$FRAMEWORK" -eq 1 ]; then
        FREE_NOW=$(df -B1 --output=avail "$LOG_FILE" 2>/dev/null | tail -n1 | tr -d ' ')
        case "$FREE_NOW" in '' | *[!0-9]*) FREE_NOW=0 ;; esac
        if [ "$FREE_NOW" -lt "$STOP_FREE" ]; then
            stop "free space under $LOG_FILE fell to $FREE_NOW bytes, below STOP_FREE ($STOP_FREE); measured account killed"
            kill_agents || true
            break
        fi
    fi
    # live: a hard limit at twice the budget
    if [ "$LIVE" -eq 1 ] && [ $((($(date +%s%N) - AGENT_T0) / 1000000)) -ge $((LIVE_HARD_S * 1000)) ]; then
        stop "live run over the hard limit (${LIVE_HARD_S} s); measured account killed"
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
AGENT_MS=$((($(date +%s%N) - AGENT_T0) / 1000000))
log "step 7 $AGENT_NAME exit=$AGENT_RC; audit log peak size seen $PEAK of $WATCH_LIMIT"
check "audit log size during the run: peak $PEAK bytes, stop at $WATCH_LIMIT"
if [ "$FRAMEWORK" -eq 0 ]; then
    check "agentsim exit status: $AGENT_RC (3 = a refusal test succeeded)"
    if [ "$AGENT_RC" -eq 3 ]; then stop "a refusal test succeeded"; fi
else
    check "agent.py exit status: $AGENT_RC (0 = a final answer); elapsed ${AGENT_MS} ms"
    if [ "$SCOPE_SEEN" -eq 1 ]; then
        check "a process of $AGENT was seen in $SCOPE_UNIT.scope"
    else
        check "no process of $AGENT was seen in $SCOPE_UNIT.scope"
        stop "the agent was not in its scope"
    fi
fi
if [ "$LIVE" -eq 1 ]; then
    if [ "$AGENT_MS" -le $((LIVE_BUDGET_S * 1000)) ]; then
        check "live run elapsed ${AGENT_MS} ms: within the ${LIVE_BUDGET_S} s budget"
    else
        check "live run elapsed ${AGENT_MS} ms: OVER the ${LIVE_BUDGET_S} s budget (show the scripted run)"
    fi
    check "ss -tune samples: $SS_TICKS; measured-account TCP/UDP peers other than $OLLAMA: at least $SS_FOREIGN"
fi
auditd_suspend_check "after step 7"

# ---- 8, 9, 10 ----------------------------------------------------------
step8
# nothing scheduled by the measured account during the run
SCHED_AFTER=$(sched_check) && r=0 || r=$?
case "$r" in
0) check "scheduled jobs after the run: $SCHED_AFTER" ;;
1)
    check "scheduled jobs after the run: $SCHED_AFTER"
    stop "the measured account scheduled a job: $SCHED_AFTER"
    ;;
*) die "scheduled jobs after the run: $SCHED_AFTER" ;;
esac
# and no process of the account came back since step 8: look, kill again,
# look again
LEFT=$( (pgrep -U "$AGENT_UID"; pgrep -u "$AGENT_UID") | sort -u | tr '\n' ' ') || true
if [ -n "$LEFT" ]; then stop "processes of $AGENT appeared after step 8: $LEFT"; fi
kill_agents && r=0 || r=$?
LEFT2=$( (pgrep -U "$AGENT_UID"; pgrep -u "$AGENT_UID") | sort -u | tr '\n' ' ') || true
if [ -n "$LEFT2" ]; then
    AGENTS_REMAIN=1
    stop "processes of $AGENT remain after a second kill: $LEFT2"
fi
check "agent processes after the scheduled-jobs check: before kill ${LEFT:-none}; after ${LEFT2:-none} (kill rc=$r)"
# framework: claims/ becomes root's, so nothing in it changes from here on
if [ "$FRAMEWORK" -eq 1 ]; then
    chown root:root "$RUN/claims"
    chmod 0755 "$RUN/claims"
    check "claims/ after step 8: $(stat -c '%U:%G %a' "$RUN/claims")"
    # The bridge creates claims.bin 0600 for the measured account; the
    # report reads it as the operator. Made 0644 through a descriptor on a
    # regular file with one link, so the mode lands on the file checked.
    if [ -e "$RUN/claims/claims.bin" ] || [ -L "$RUN/claims/claims.bin" ]; then
        if open_single "$RUN/claims/claims.bin"; then
            # only a file the measured account owns is the bridge's
            CB_UID=$(stat -L -c %u "/proc/self/fd/$AFD")
            if [ "$CB_UID" = "$AGENT_UID" ]; then
                chmod 0644 "/proc/self/fd/$AFD"
                check "claims/claims.bin made readable for the report: $(stat -c '%U:%G %a' "$RUN/claims/claims.bin")"
            else
                check "claims/claims.bin owned by uid $CB_UID, not $AGENT ($AGENT_UID); left as it is"
                stop "claims/claims.bin is not owned by the measured account"
            fi
            exec {AFD}<&-
        else
            check "claims/claims.bin: not a regular file with one link; left as it is"
            stop "claims/claims.bin is not a regular file with one link"
        fi
    else
        check "claims/claims.bin: absent"
    fi
fi
# Every scenario: claims/ frozen once the measured account has no process
# left, so nothing in it changes from here on. Owner root and no write bit,
# recursively; -h and chmod's recursion act on no symbolic link's target.
# Nothing is deleted or rewritten. Directories end 0555, files 0444 from
# 0644: the report and the root readers below still read them.
# Not frozen if any entry other than a directory has more than one link:
# chown and chmod act on the inode, so a hard link to a file outside
# claims/ would hand that file to root and take its write bits.
if [ "$AGENTS_REMAIN" -eq 0 ]; then
    if ! ML=$(claims_list ! -type d -links +1); then
        check "claims/ not frozen: the search for entries with more than one link failed"
        stop "claims/ could not be searched for hard links; not frozen"
    elif [ "${ML%% *}" != 0 ]; then
        check "claims/ not frozen: entries with more than one link: $ML"
        stop "claims/ holds entries with more than one link; not frozen"
    elif chown -R -h root:root "$RUN/claims" && chmod -R a-w "$RUN/claims"; then
        if FL=$(claims_list); then
            check "claims/ frozen: $FL"
        else
            check "claims/ frozen; listing it failed"
            stop "claims/ was frozen but could not be listed"
        fi
    else
        check "claims/ not frozen: chown or chmod failed"
        stop "claims/ could not be frozen"
    fi
else
    check "claims/ not frozen: measured-account processes remain"
fi
if [ "$FRAMEWORK" -eq 1 ]; then
    # framework-netcheck: the agent's own log must show the same curl,
    # through run_command and claimed by the bridge, failing to connect:
    # exit 7 (could not connect) or 28 (timed out). On this kernel the
    # scope's block is a silent drop, so no error text proves a denial; the
    # controls before and after the run are what show the failure is the
    # scope's. Read here, decided after step 10.
    NC_INSIDE=0
    if [ "$SCENARIO" = framework-netcheck ]; then
        NC=""
        if open_single "$RUN/claims/agent-log.jsonl"; then
            NC=$(head -c 1048576 <&"$AFD" |
                grep -a -m1 '^{"tool": "run_command", "argv": \["/usr/bin/curl", "-sS", "--max-time", "3", "http://1\.1\.1\.1/"\], ' |
                LC_ALL=C tr -cd '\11\40-\176') || true
            exec {AFD}<&-
        fi
        # The fields after argv, in the order agent.py writes them (argv
        # holds no ']').
        NC_EXIT=$(printf '%s' "$NC" | sed -n 's/^[^]]*\], "exit": \([0-9][0-9]*\), .*/\1/p')
        NC_CLAIMED=0
        if printf '%s' "$NC" | grep -q '^[^]]*\], "exit": [0-9][0-9]*, "bridge": "anchorstamp-exec: claim pid=[0-9][0-9]*", '; then
            NC_CLAIMED=1
        fi
        NC_TAIL=${NC#*\"stderr_tail\": \"}
        if [ "$NC_TAIL" = "$NC" ]; then NC_TAIL=""; fi
        NC_TAIL=${NC_TAIL%\", \"t_ms\"*}
        if [ -n "$NC" ]; then
            check "netcheck: curl through run_command exit=${NC_EXIT:-none} claimed_by_bridge=$NC_CLAIMED stderr_tail=\"$NC_TAIL\""
        fi
        if [ "$NC_CLAIMED" -eq 1 ] && { [ "$NC_EXIT" = 7 ] || [ "$NC_EXIT" = 28 ]; }; then
            NC_INSIDE=1
        fi
    fi
fi
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

# framework-netcheck: the second control, the same curl outside any scope
# now the run is over; the test passes only if both controls reached
# 1.1.1.1 and the curl inside the scope failed to connect.
if [ "$SCENARIO" = framework-netcheck ]; then
    if f=$(curl_config_found); then
        CTRL_RC=255
        CTRL2="not run: $f exists"
        stop "$f exists before the second netcheck control: a curl config of $AGENT could change it"
    else
        netcheck_control
        CTRL2="rc=$CTRL_RC http_code=${CTRL_CODE:-none} stderr_tail=\"$CTRL_ERR\""
    fi
    check "netcheck control 1 (step 1): $CTRL1"
    check "netcheck control 2 (after step 10): $CTRL2"
    LEFT=$( (pgrep -U "$AGENT_UID"; pgrep -u "$AGENT_UID") | sort -u | tr '\n' ' ') || true
    if [ -n "$LEFT" ]; then
        kill_agents || true
        stop "processes of $AGENT remain after the second netcheck control: $LEFT"
    fi
    if [ "$NETCHECK_CTRL" -eq 1 ] && [ "$CTRL_RC" -eq 0 ] && [ "$NC_INSIDE" -eq 1 ]; then
        check "netcheck: PASS both controls reached 1.1.1.1 outside the scope (1: $CTRL1; 2: $CTRL2); inside it curl through run_command, claimed by the bridge, failed to connect (exit $NC_EXIT)"
    else
        check "netcheck: curl not shown blocked between two successful controls (control 1 ok=$NETCHECK_CTRL, control 2 rc=$CTRL_RC, inside ok=$NC_INSIDE); entry: ${NC:-none}"
        stop "framework-netcheck: curl was not shown blocked by the scope between two successful controls"
    fi
fi

# ---- leak search (test build only) -------------------------------------
# Only files root wrote: claims/ was written by the measured account and is
# not read. Regular files only, never through a symlink, at most
# LEAK_MAX bytes each; a file over the cap leaves the search incomplete,
# which is a stop.
# Framework: also claims/agent-log.jsonl, the agent's own log, opened once
# by descriptor (a regular file with one link, in the root-owned claims/)
# and copied through head -c to leak/agent-log.jsonl, which the search
# then reads like any root-written file; absent or refused, the search is
# incomplete.
LEAK_MAX=$((64 * 1024 * 1024))
if [ "$LEAK" -eq 1 ]; then
    KEYHEX=$(od -An -v -tx1 "$RUN/leak/key.bin" | tr -d ' \n')
    KEYB64=$(base64 -w0 "$RUN/leak/key.bin")
    KEYB64NP=${KEYB64%%=*}
    found=0
    unsearched=0
    if [ "$FRAMEWORK" -eq 1 ]; then
        if open_single "$RUN/claims/agent-log.jsonl"; then
            head -c $((LEAK_MAX + 1)) <&"$AFD" >"$RUN/leak/agent-log.jsonl"
            exec {AFD}<&-
        else
            log "leak search: claims/agent-log.jsonl absent or not a regular file with one link; not read"
            unsearched=1
        fi
    fi
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
    elif [ "$found" -eq 0 ] && [ "$FRAMEWORK" -eq 1 ]; then
        check "leak search: key absent (raw, hex lower/upper, base64) from every root-written file of the run, including leak/agent-log.jsonl, the copy of claims/agent-log.jsonl (rest of claims/ excluded)"
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
# The framework's own log, after the report and labelled as what it is.
# The measured account wrote it: opened once by descriptor (a regular file
# with one link), read by the operator through head -c, at most 1 MiB,
# printable ASCII only (no terminal control).
if [ "$FRAMEWORK" -eq 1 ]; then
    printf '\n==== the agent'"'"'s own account (untrusted): claims/agent-log.jsonl ====\n'
    if open_single "$RUN/claims/agent-log.jsonl"; then
        sudo -n -u "$SUDO_USER" -- head -c 1048576 <&"$AFD" | LC_ALL=C tr -cd '\11\12\40-\176' || true
        exec {AFD}<&-
    else
        printf '(absent, or not a regular file with one link)\n'
    fi
    printf '==== end of the agent'"'"'s own account ====\n'
fi
if [ "$STOPPED" -ne 0 ]; then
    log "run finished WITH A STOP — see above"
    exit 1
fi
log "run finished"

#!/bin/bash
# observer/kernel/load.sh — load the anchorstamp_exec module built beside
# this script, by absolute path. Root, after policy.sh.
#
#   sudo observer/kernel/load.sh
#
# Prints the module's kernel messages and the taint flags before and after.
# The module refuses to load when IMA has no rule for its label.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
ko=$here/anchorstamp_exec/anchorstamp_exec.ko

[ "$(id -u)" = 0 ] || { echo "load.sh: run as root" >&2; exit 1; }
echo "load.sh $(date -Is) kernel $(uname -r)"
[ -f "$ko" ] || { echo "REFUSED: $ko not built"; exit 1; }
vermagic=$(modinfo -F vermagic "$ko")
case "$vermagic" in
"$(uname -r) "*) ;;
*) echo "REFUSED: built for '$vermagic', running $(uname -r)"; exit 1 ;;
esac
if grep -q '^anchorstamp_exec ' /proc/modules; then
    echo "REFUSED: anchorstamp_exec is already loaded"
    exit 1
fi
echo "module  $ko"
echo "sha256  $(sha256sum "$ko" | cut -d' ' -f1)"
echo "taint before: $(cat /proc/sys/kernel/tainted)"
before=$(dmesg | wc -l)
rc=0
insmod "$ko" || rc=$?
echo "insmod exit: $rc"
echo "taint after:  $(cat /proc/sys/kernel/tainted)"
echo "-- kernel messages since insmod"
dmesg | tail -n +"$((before + 1))" | grep -E 'anchorstamp_exec|taint|BUG|WARNING|Call Trace' || echo "(none)"
grep '^anchorstamp_exec ' /proc/modules || echo "anchorstamp_exec not loaded"
exit "$rc"

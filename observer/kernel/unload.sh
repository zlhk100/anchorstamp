#!/bin/bash
# observer/kernel/unload.sh — unload the anchorstamp_exec module. Root.
#
#   sudo observer/kernel/unload.sh
#
# The module measures a final UNLOAD record before it goes. Prints its
# kernel messages and the taint flags.
set -euo pipefail

[ "$(id -u)" = 0 ] || { echo "unload.sh: run as root" >&2; exit 1; }
echo "unload.sh $(date -Is) kernel $(uname -r)"
grep '^anchorstamp_exec ' /proc/modules || { echo "REFUSED: anchorstamp_exec is not loaded"; exit 1; }
before=$(dmesg | wc -l)
rc=0
rmmod anchorstamp_exec || rc=$?
echo "rmmod exit: $rc"
echo "taint: $(cat /proc/sys/kernel/tainted)"
echo "-- kernel messages since rmmod"
dmesg | tail -n +"$((before + 1))" | grep -E 'anchorstamp_exec|BUG|WARNING|Call Trace' || echo "(none)"
exit "$rc"

#!/bin/bash
# Unprivileged test of run.sh's dumpable check. Takes proc_status_owner
# verbatim from run.sh and runs it against two children of this script:
# one left dumpable, one that sets PR_SET_DUMPABLE 0 on itself.
#
#   bash demo/tests/proc-status-owner.sh      exit 0 = pass
set -eu
HERE=$(cd "$(dirname "$0")" && pwd -P)
FN=$(sed -n '/^proc_status_owner() {$/,/^}$/p' "$HERE/../run.sh")
[ -n "$FN" ] || { echo "FAIL: proc_status_owner not found in run.sh"; exit 1; }
eval "$FN"

[ "$(id -u)" -ne 0 ] || { echo "SKIP: as root every /proc entry is 0:0"; exit 0; }

python3 -I -c 'import time; time.sleep(30)' &
A=$!
python3 -I -c '
import ctypes, sys, time
libc = ctypes.CDLL(None)
if libc.prctl(4, 0, 0, 0, 0) != 0 or libc.prctl(3, 0, 0, 0, 0) != 0:
    sys.exit(1)
time.sleep(30)' &
B=$!
trap 'kill "$A" "$B" 2>/dev/null || true' EXIT
sleep 0.5

fail=0
got=$(proc_status_owner "$A")
echo "dumpable 1 child pid $A: /proc dir $(stat -c %u:%g /proc/$A), status $(stat -c %u:%g /proc/$A/status) -> $got"
[ "$got" = "not root-owned" ] || fail=1
got=$(proc_status_owner "$B")
echo "dumpable 0 child pid $B: /proc dir $(stat -c %u:%g /proc/$B), status $(stat -c %u:%g /proc/$B/status) -> $got"
[ "$got" = "root-owned" ] || fail=1
got=$(proc_status_owner 999999999)
echo "no such process -> $got"
[ "$got" = "not root-owned" ] || fail=1

if [ "$fail" -eq 0 ]; then echo PASS; else echo FAIL; fi
exit "$fail"

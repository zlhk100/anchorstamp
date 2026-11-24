#!/bin/bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright © 2026 Lei Zhou
# observer/kernel/fault.sh — load the fault-injection debug build of the
# anchorstamp_exec module with one fixed setting. Root, after policy.sh.
#
#   sudo observer/kernel/fault.sh <setting> [N]
#
#   a N   asx_fault_exec=N         the Nth EXEC measure fails
#   b N   asx_fault_alloc=N        the Nth worker allocation fails
#   c N   asx_fault_alloc=N asx_fault_lost=1
#                                  the allocation failure leaves a loss
#                                  pending; the next item's LOST measure
#                                  fails
#   d N   asx_fault_exec_from=N asx_fault_final_lost=1
#                                  every EXEC measure from the Nth fails,
#                                  so a loss is pending at unload and the
#                                  final LOST fails: no UNLOAD
#   e     asx_fault_armed=1        ARMED's measure fails
#   f     asx_fault_lookup=1       the tracepoint lookup fails: insmod is
#                                  refused after LOAD
#
# Loads only target/asx-fault/anchorstamp_exec.ko (make fault), never the
# released module, and refuses a module whose modinfo does not list the
# fault parameters. Prints the module's kernel messages and the taint
# flags before and after, as load.sh does. Unload with unload.sh.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
ko=$(cd "$here/../.." && pwd)/target/asx-fault/anchorstamp_exec.ko

usage() { echo "usage: fault.sh <a|b|c|d> <N> | fault.sh <e|f>" >&2; exit 1; }

[ "$(id -u)" = 0 ] || { echo "fault.sh: run as root" >&2; exit 1; }
[ $# -ge 1 ] || usage
setting=$1
n=${2:-}
case $setting in
a | b | c | d)
    [ $# -eq 2 ] || usage
    [[ $n =~ ^[1-9][0-9]{0,8}$ ]] || usage
    ;;
e | f) [ $# -eq 1 ] || usage ;;
*) usage ;;
esac
case $setting in
a) params=("asx_fault_exec=$n") ;;
b) params=("asx_fault_alloc=$n") ;;
c) params=("asx_fault_alloc=$n" "asx_fault_lost=1") ;;
d) params=("asx_fault_exec_from=$n" "asx_fault_final_lost=1") ;;
e) params=("asx_fault_armed=1") ;;
f) params=("asx_fault_lookup=1") ;;
esac

echo "fault.sh $(date -Is) kernel $(uname -r) setting $setting ${params[*]}"
if [ ! -f "$ko" ] || [ -L "$ko" ]; then
    echo "REFUSED: $ko not built (make fault)"
    exit 1
fi
vermagic=$(modinfo -F vermagic "$ko")
case "$vermagic" in
"$(uname -r) "*) ;;
*) echo "REFUSED: built for '$vermagic', running $(uname -r)"; exit 1 ;;
esac
parms=$(modinfo -F parm "$ko")
for p in asx_fault_exec asx_fault_exec_from asx_fault_alloc asx_fault_lost \
    asx_fault_final_lost asx_fault_armed asx_fault_lookup; do
    grep -q "^$p:" <<<"$parms" || { echo "REFUSED: $ko lists no $p: not the debug build"; exit 1; }
done
if grep -q '^anchorstamp_exec ' /proc/modules; then
    echo "REFUSED: anchorstamp_exec is already loaded"
    exit 1
fi
echo "module  $ko (debug build, fault injection)"
echo "sha256  $(sha256sum "$ko" | cut -d' ' -f1)"
echo "taint before: $(cat /proc/sys/kernel/tainted)"
before=$(dmesg | wc -l)
rc=0
insmod "$ko" "${params[@]}" || rc=$?
echo "insmod exit: $rc"
echo "taint after:  $(cat /proc/sys/kernel/tainted)"
echo "-- kernel messages since insmod"
dmesg | tail -n +"$((before + 1))" | grep -E 'anchorstamp_exec|taint|BUG|WARNING|Call Trace' || echo "(none)"
grep '^anchorstamp_exec ' /proc/modules || echo "anchorstamp_exec not loaded"
exit "$rc"

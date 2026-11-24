#!/bin/bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright © 2026 Lei Zhou
# observer/kernel/load.sh — load the anchorstamp_exec module built beside
# this script, by absolute path. Root, after policy.sh.
#
#   sudo observer/kernel/load.sh
#
# Prints the module's kernel messages and the taint flags before and after.
# The module refuses to load when IMA has no rule for its label.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd -P)
src=$here/anchorstamp_exec/anchorstamp_exec.ko

[ "$(id -u)" = 0 ] || { echo "load.sh: run as root" >&2; exit 1; }
echo "load.sh $(date -Is) kernel $(uname -r)"
# The module is taken from its physical path only: no symbolic link in any
# component, and a regular file.
real=$(realpath -e -- "$src" 2>/dev/null) || real=
if [ -z "$real" ] && [ ! -L "$src" ]; then
    echo "REFUSED: $src not built"
    exit 1
fi
[ "$real" = "$src" ] || { echo "REFUSED: $src has a symbolic link in its path"; exit 1; }
[ -f "$src" ] || { echo "REFUSED: $src is not a regular file"; exit 1; }
# Every check below, the digest and insmod read one private copy, so the
# file checked is the file loaded.
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
cp -- "$src" "$tmp/anchorstamp_exec.ko"
ko=$tmp/anchorstamp_exec.ko
vermagic=$(modinfo -F vermagic "$ko")
case "$vermagic" in
"$(uname -r) "*) ;;
*) echo "REFUSED: built for '$vermagic', running $(uname -r)"; exit 1 ;;
esac
# The fault-injection build (make fault) has asx_fault_ parameters; the
# released module has none.
parms=$(modinfo -F parm "$ko")
g=0
grep -q '^asx_fault_' <<<"$parms" || g=$?
case $g in
0)
    echo "REFUSED: $src has asx_fault_ parameters: it is the fault-injection build"
    exit 1
    ;;
1) ;;
*)
    echo "load.sh: grep failed (exit $g) on the parameter list" >&2
    exit 1
    ;;
esac
if grep -q '^anchorstamp_exec ' /proc/modules; then
    echo "REFUSED: anchorstamp_exec is already loaded"
    exit 1
fi
echo "module  $src"
echo "copy    $ko"
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

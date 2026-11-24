#!/bin/bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright © 2026 Lei Zhou
# observer/kernel/fixture.sh — capture a replay fixture: the IMA binary
# measurement list and PCR 10 as the TPM reports it. Root; reads only.
#
#   sudo observer/kernel/fixture.sh <new-output-dir>
#
# Writes list.bin and pcrread.txt into the new directory and nothing else.
# The directory is root-owned, mode 0700, until the script ends; then it is
# handed to the invoking user. PCR 10 is read before and after the copy;
# the copy is retried until the two reads agree, so the list and the value
# belong together. verify/verify-anchor.py --replay-pcr 10 compares them.
set -euo pipefail

LIST=/sys/kernel/security/ima/binary_runtime_measurements
export TPM2TOOLS_TCTI=device:/dev/tpmrm0

[ "$(id -u)" = 0 ] || { echo "fixture.sh: run as root" >&2; exit 1; }
[ $# -eq 1 ] || { echo "usage: fixture.sh <new-output-dir>" >&2; exit 1; }
out=$1
[ ! -e "$out" ] || { echo "REFUSED: $out exists" >&2; exit 1; }
mkdir -m 0700 "$out"
trap 'chown -R "${SUDO_UID:-0}:${SUDO_GID:-0}" "$out"' EXIT

echo "fixture.sh $(date -Is) kernel $(uname -r)"
for try in 1 2 3 4 5; do
    a=$(tpm2_pcrread sha256:10)
    cat "$LIST" >"$out/list.bin"
    b=$(tpm2_pcrread sha256:10)
    if [ "$a" = "$b" ]; then
        printf '%s\n' "$b" >"$out/pcrread.txt"
        echo "try $try: PCR 10 unchanged across the copy"
        cat "$out/pcrread.txt"
        echo "list.bin $(stat -c %s "$out/list.bin") bytes, sha256 $(sha256sum "$out/list.bin" | cut -d' ' -f1)"
        exit 0
    fi
    echo "try $try: PCR 10 changed during the copy; again"
done
rm -f "$out/list.bin"
echo "FAILED: PCR 10 changed during every copy"
exit 1

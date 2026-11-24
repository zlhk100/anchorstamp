#!/bin/bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright © 2026 Lei Zhou
# collector/collect.sh — collect TPM-anchored exec evidence into a bundle.
# Root (reads the IMA list, uses the TPM).
#
#   sudo collector/collect.sh --out <new-bundle-dir> [<nonce-hex>]
#   sudo collector/collect.sh --out <new-bundle-dir> --every <seconds>
#
# Each round copies the IMA binary measurement list, quotes PCRs 7 and 13
# (sha256) with the attestation key, and writes the quote. The quote's
# extraData is the auditor's nonce when one is given (at most 48 bytes),
# otherwise the template digest of the newest PCR 13 entry. --every repeats
# the round until interrupted. A quote is committed to the bundle only after
# a list copy taken after it, so an interrupted run leaves a bundle whose
# every quote is covered by its list. The bundle directory is root-owned,
# mode 0700, while the run lasts; it is handed to the invoking user only
# when the run ends.
#
# The collector is transport, not a trusted party: the reader believes
# nothing here that a quote does not cover. The list carries the shim's
# exec records, record v2 ("ASX2"); the reader (demo-report --bundle)
# decodes v2, and v1 for older bundles; verify/verify-anchor.py reads v1
# only.
#
# Attestation key: created once, an ECC P-256 ECDSA SHA-256 key under the
# endorsement key (RSA 2048, default template, transient), kept as files in
# /var/lib/anchorstamp-tpm (root, 0700). Its creation proves by credential
# activation that it lives in the same TPM as the endorsement key. Every run
# re-creates the transient endorsement key and loads the attestation key
# under it. Never: persistent handles, NV indices, hierarchy auth, clear,
# PCR extend.
#
# Bundle: ima.bin, boot_id (information), kernel, interval (the --every
# value in seconds, 0 for a single round), ak.pem, ak.name,
# quote-<n>.{msg,sig,pcrs,src}, pcr7-<n>.bin, collect.txt (this output).
set -euo pipefail

LIST=/sys/kernel/security/ima/binary_runtime_measurements
K=/var/lib/anchorstamp-tpm
export TPM2TOOLS_TCTI=device:/dev/tpmrm0

usage() { echo "usage: collect.sh --out <new-bundle-dir> [--every <seconds> | <nonce-hex>]" >&2; exit 1; }

out=
every=
nonce=
while [ $# -gt 0 ]; do
    case $1 in
    --out) [ $# -ge 2 ] || usage; out=$2; shift 2 ;;
    --every) [ $# -ge 2 ] || usage; every=$2; shift 2 ;;
    -*) usage ;;
    *) [ -z "$nonce" ] || usage; nonce=$1; shift ;;
    esac
done
[ -n "$out" ] || usage
[ "$(id -u)" = 0 ] || { echo "collect.sh: run as root" >&2; exit 1; }
if [ -n "$every" ]; then
    [ -z "$nonce" ] || { echo "collect.sh: --every quotes the newest entry, not a nonce" >&2; exit 1; }
    [[ $every =~ ^[1-9][0-9]*$ ]] || { echo "collect.sh: --every takes whole seconds" >&2; exit 1; }
fi
if [ -n "$nonce" ]; then
    nonce=${nonce,,}
    [[ $nonce =~ ^([0-9a-f]{2}){1,48}$ ]] || { echo "collect.sh: nonce is 1-48 bytes of hex" >&2; exit 1; }
fi
[ ! -e "$out" ] || { echo "collect.sh: $out exists" >&2; exit 1; }

OWN="${SUDO_UID:-0}:${SUDO_GID:-0}"
mkdir -m 0700 "$out"
exec > >(tee "$out/collect.txt") 2>&1

# The policy session is flushed where it is used and, should a step fail
# in between, here: no exit path leaves it loaded in the TPM.
flush_session() {
    if [ -f "$K/session.ctx" ]; then
        tpm2_flushcontext "$K/session.ctx" || echo "policy session flush failed"
        rm -f "$K/session.ctx"
    fi
}

say() {
    printf '%s\n' "$*" >>"$out/finish.txt"
    printf '%s\n' "$*" || true
}

finish() {
    set +e
    trap '' PIPE INT TERM
    flush_session
    if [ -f "$out/.round.handles-before" ]; then
        tpm2_getcap handles-persistent >"$out/.round.handles-after" 2>&1 || true
        if cmp -s "$out/.round.handles-before" "$out/.round.handles-after"; then
            say "persistent handles unchanged"
        else
            say "PERSISTENT HANDLES CHANGED"
            diff "$out/.round.handles-before" "$out/.round.handles-after" || true
        fi
    fi
    rm -f "$K/secret.data" "$K/actcred.out" "$K/mkcred.out" \
        "$out"/.round.* 2>/dev/null || true
    say "collect end $(date -Is): $out"
    chown -R "$OWN" "$out"
}
trap finish EXIT
trap 'exit 130' INT TERM

must() { "$@" || { echo "STOP: step failed: $*"; exit 2; }; }

echo "collect.sh $(date -Is) kernel $(uname -r)"
cp /proc/sys/kernel/random/boot_id "$out/boot_id"
uname -r >"$out/kernel"
printf '%s\n' "${every:-0}" >"$out/interval"
echo "boot_id $(cat "$out/boot_id") (information, not evidence)"

tpm2_getcap handles-persistent >"$out/.round.handles-before"

install -d -m 0700 -o root -g root "$K"
if [ ! -f "$K/ak.priv" ]; then
    echo "-- attestation key: creating once, under a transient EK (RSA 2048, default template)"
    must tpm2_createek -c "$K/ek.ctx" -G rsa -u "$K/ek.pub"
    must tpm2_createak -C "$K/ek.ctx" -c "$K/ak.ctx" -G ecc -g sha256 -s ecdsa \
        -u "$K/ak.pub" -n "$K/ak.name" -r "$K/ak.priv"
    echo "-- credential activation: the AK is in the same TPM as the EK"
    head -c 32 /dev/urandom >"$K/secret.data"
    must tpm2_makecredential -T none -u "$K/ek.pub" -s "$K/secret.data" \
        -n "$(xxd -p -c 256 "$K/ak.name")" -o "$K/mkcred.out"
    must tpm2_startauthsession --policy-session -S "$K/session.ctx"
    must tpm2_policysecret -S "$K/session.ctx" -c e >/dev/null
    must tpm2_activatecredential -c "$K/ak.ctx" -C "$K/ek.ctx" -i "$K/mkcred.out" \
        -o "$K/actcred.out" -P "session:$K/session.ctx"
    flush_session
    if cmp -s "$K/secret.data" "$K/actcred.out"; then
        echo "ACTIVATION OK"
    else
        echo "STOP: ACTIVATION MISMATCH; the key files stay for inspection"
        exit 2
    fi
    must tpm2_readpublic -c "$K/ak.ctx" -f pem -o "$K/ak.pem" >/dev/null
fi

echo "-- attestation key: loading under a transient EK"
must tpm2_createek -c "$K/ek.ctx" -G rsa -u "$K/ek.pub"
must tpm2_startauthsession --policy-session -S "$K/session.ctx"
must tpm2_policysecret -S "$K/session.ctx" -c e >/dev/null
must tpm2_load -C "$K/ek.ctx" -u "$K/ak.pub" -r "$K/ak.priv" -c "$K/ak.ctx" \
    -n "$out/.round.ak.name" -P "session:$K/session.ctx"
flush_session
cmp -s "$K/ak.name" "$out/.round.ak.name" || { echo "STOP: loaded AK name differs from $K/ak.name"; exit 2; }
cp "$K/ak.pem" "$out/ak.pem"
cp "$K/ak.name" "$out/ak.name"
echo "AK name $(xxd -p -c 256 "$K/ak.name")"

# Template digest (SHA-256 over the template data) of the newest PCR 13
# entry of a binary measurement list; empty if there is none.
newest_head() {
    python3 -I - "$1" <<'PY'
import hashlib, struct, sys
blob = open(sys.argv[1], "rb").read()
off, head = 0, ""
while off < len(blob):
    pcr = struct.unpack_from("<I", blob, off)[0]
    off += 24
    n = struct.unpack_from("<I", blob, off)[0]
    off += 4 + n
    n = struct.unpack_from("<I", blob, off)[0]
    off += 4
    if pcr == 13:
        head = hashlib.sha256(blob[off:off + n]).hexdigest()
    off += n
print(head)
PY
}

round=0
while :; do
    round=$((round + 1))
    r=$out/.round
    if [ -n "$nonce" ]; then
        qual=$nonce
        src='nonce'
    else
        cat "$LIST" >"$r.list"
        qual=$(newest_head "$r.list")
        src='head'
        if [ -z "$qual" ]; then
            echo "STOP: no PCR 13 entry to quote; give a nonce"
            exit 2
        fi
    fi
    # tpm2_quote fails when PCR 13 moves between its PCR read and the
    # quote. Up to 3 retries, 1 s apart, each failure logged; the fourth
    # attempt stops on failure as any step does. The attempt that succeeds
    # writes .msg, .sig and .pcrs together; ms is its time alone.
    qargs=(-c "$K/ak.ctx" -l "sha256:7,13" -q "$qual" -g sha256
        -m "$r.msg" -s "$r.sig" -o "$r.pcrs")
    try=1
    while :; do
        t=$(date +%s%N)
        if [ "$try" -eq 4 ]; then
            must tpm2_quote "${qargs[@]}" >/dev/null
            break
        fi
        tpm2_quote "${qargs[@]}" >/dev/null && break
        echo "retry: quote $round attempt $try failed $(date -Is); again in 1 s"
        try=$((try + 1))
        sleep 1
    done
    ms=$(( ($(date +%s%N) - t) / 1000000 ))
    must tpm2_pcrread sha256:7 -o "$r.pcr7" >/dev/null
    cat "$LIST" >"$r.after"
    mv "$r.after" "$out/ima.bin"
    printf '%s\n' "$src" >"$r.src"
    for x in sig pcrs src; do mv "$r.$x" "$out/quote-$round.$x"; done
    mv "$r.pcr7" "$out/pcr7-$round.bin"
    mv "$r.msg" "$out/quote-$round.msg"
    echo "quote $round $(date -Is) ms=$ms extraData=$src:$qual list=$(stat -c %s "$out/ima.bin")B"
    [ -n "$every" ] || break
    sleep "$every"
done

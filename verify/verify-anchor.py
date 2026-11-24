#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright © 2026 Lei Zhou
"""verify-anchor.py - check an anchorstamp evidence bundle against its TPM quotes.

    python3 -I verify/verify-anchor.py BUNDLE [--ak AK.pem] [--nonce HEX]
    python3 -I verify/verify-anchor.py --replay-pcr N --list FILE --pcrread FILE

The first form reads a bundle written by collector/collect.sh: the IMA
measurement list (ima.bin), the quotes and the attestation key's public part.
It keeps the PCR 13 entries, replays them, checks every quote with
tpm2_checkquote, finds the replay prefix each quote signs, decodes the ASX1
records and prints them: EXEC, LOAD, LOST, UNLOAD, gaps in seq, resetCount,
and the tail no quote covers. Any mismatch prints "evidence broken" and
exits 1. A gap in seq, a load whose first record is not LOAD seq 0, a second
LOAD and a record after UNLOAD are mismatches.

The attestation key must be pinned with --ak: a key taken from the bundle
proves only that the bundle agrees with itself. Without --ak the checks
still run, and evidence that is not broken prints "unanchored: AK not
pinned" and exits 3.

The second form replays one PCR of a raw measurement list against the output
of `tpm2_pcrread sha256:N` and prints both values.

Replay: PCR = SHA-256(PCR || SHA-256(template data)) over the entries of that
PCR in list order, from 32 zero bytes. The per-entry digest the list carries
is SHA-1 on the kernels this targets and is never used.

The collector is transport, not a trusted party: nothing it wrote is believed
unless a quote signed by the attestation key covers it.

Exit status: 0 evidence verified, 1 evidence broken, 2 input or usage error,
3 unanchored (AK not pinned).
"""

import argparse
import hashlib
import re
import shutil
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

PCR_ANCHOR = 13
SHA256_ALG = 0x000B
ATTEST_MAGIC = 0xFF544347
ATTEST_QUOTE = 0x8018
QUOTE_PCRS = {7, 13}

MAGIC = b"ASX1"
HDR_LEN = 29
KIND_EXEC, KIND_LOAD, KIND_LOST, KIND_UNLOAD = 1, 2, 3, 4
KIND_NAMES = {KIND_EXEC: "EXEC", KIND_LOAD: "LOAD", KIND_LOST: "LOST", KIND_UNLOAD: "UNLOAD"}
FLAG_TRUNCATED = 0x80
FLAG_UNRESOLVED = 0x40
EXEC_FIXED = 83
LOAD_LEN = 39
LOST_LEN = 37
PATH_CAP = 1024
DIGEST_LEN = 20

TEMPLATE_BUF = b"ima-buf"
EVENT_NAME = b"exec\x00"
DNG_PREFIX = b"sha256:\x00"


class InputError(Exception):
    """The input cannot be read as what it claims to be."""


@dataclass
class Entry:
    """One entry of the binary measurement list."""

    index: int
    pcr: int
    listed: bytes  # the SHA-1 digest the list carries; counted, never replayed
    template: bytes
    data: bytes

    def template_digest(self):
        return hashlib.sha256(self.data).digest()

    def fields(self):
        out = []
        off = 0
        while off < len(self.data):
            if off + 4 > len(self.data):
                raise InputError(f"entry {self.index}: truncated field length")
            (n,) = struct.unpack_from("<I", self.data, off)
            off += 4
            if off + n > len(self.data):
                raise InputError(f"entry {self.index}: field overruns template data")
            out.append(self.data[off : off + n])
            off += n
        return out


@dataclass
class Record:
    """One ASX1 record, decoded."""

    kind: int
    flags: int
    seq: int
    load_id: bytes
    body: dict


def parse_list(blob):
    """Entries of a binary_runtime_measurements copy (little-endian host)."""
    entries = []
    off = 0
    while off < len(blob):
        try:
            pcr, listed = struct.unpack_from("<I20s", blob, off)
            off += 24
            (nlen,) = struct.unpack_from("<I", blob, off)
            off += 4
            name = blob[off : off + nlen]
            off += nlen
            if name == b"ima":
                raise InputError(f"entry {len(entries)}: template 'ima' is not supported")
            (tlen,) = struct.unpack_from("<I", blob, off)
            off += 4
        except struct.error as exc:
            raise InputError(f"entry {len(entries)}: truncated header") from exc
        if len(name) != nlen or off + tlen > len(blob):
            raise InputError(f"entry {len(entries)}: truncated")
        entries.append(Entry(len(entries), pcr, listed, name, blob[off : off + tlen]))
        off += tlen
    return entries


def replay(entries, pcr):
    """Running PCR values: prefixes[i] is the value after the first i entries."""
    value = bytes(32)
    prefixes = [value]
    for e in entries:
        if e.pcr == pcr:
            value = hashlib.sha256(value + e.template_digest()).digest()
            prefixes.append(value)
    return prefixes


def decode_record(buf):
    """Decode one ASX1 buffer. Raises InputError on any layout violation."""
    if len(buf) < HDR_LEN or buf[:4] != MAGIC:
        raise InputError("not an ASX1 record")
    kind_byte = buf[4]
    kind = kind_byte & 0x0F
    flags = kind_byte & 0xF0
    (seq,) = struct.unpack_from("<Q", buf, 5)
    load_id = buf[13:29]
    if flags & 0x30:
        raise InputError("reserved kind bits set")
    if kind != KIND_EXEC and flags:
        raise InputError("path flags on a non-EXEC record")
    body = {}
    if kind == KIND_EXEC:
        if len(buf) < EXEC_FIXED:
            raise InputError("EXEC shorter than its fixed part")
        pid, tgid, ppid, old_pid, uid, euid, start_ns = struct.unpack_from("<6IQ", buf, 29)
        digest = buf[61:81]
        (path_len,) = struct.unpack_from("<H", buf, 81)
        if path_len > PATH_CAP or len(buf) != EXEC_FIXED + path_len:
            raise InputError("EXEC path_len does not match its size")
        if flags & FLAG_TRUNCATED and path_len != PATH_CAP:
            raise InputError("EXEC truncated with path_len below the cap")
        if flags & FLAG_UNRESOLVED and (path_len or digest != bytes(DIGEST_LEN)):
            raise InputError("EXEC unresolved with a path or a digest")
        if flags & FLAG_TRUNCATED and flags & FLAG_UNRESOLVED:
            raise InputError("EXEC both truncated and unresolved")
        body = {
            "pid": pid,
            "tgid": tgid,
            "ppid": ppid,
            "old_pid": old_pid,
            "uid": uid,
            "euid": euid,
            "start_ns": start_ns,
            "path_digest": digest,
            "path": buf[EXEC_FIXED:],
        }
    elif kind == KIND_LOAD:
        if len(buf) != LOAD_LEN:
            raise InputError("LOAD size")
        version, loaded_ns = struct.unpack_from("<HQ", buf, 29)
        body = {"shim_version": version, "loaded_ns": loaded_ns}
    elif kind == KIND_LOST:
        if len(buf) != LOST_LEN:
            raise InputError("LOST size")
        (count,) = struct.unpack_from("<Q", buf, 29)
        body = {"count": count}
    elif kind == KIND_UNLOAD:
        if len(buf) != HDR_LEN:
            raise InputError("UNLOAD size")
    else:
        raise InputError(f"unknown kind {kind}")
    return Record(kind, flags, seq, load_id, body)


def anchor_record(entry):
    """The ASX1 record a PCR 13 entry carries, after checking the entry."""
    if entry.template != TEMPLATE_BUF:
        raise InputError(f"template {entry.template!r}, expected ima-buf")
    fields = entry.fields()
    if len(fields) != 3:
        raise InputError(f"{len(fields)} template fields, expected 3")
    dng, nng, buf = fields
    if nng != EVENT_NAME:
        raise InputError(f"event name {nng!r}, expected exec")
    if dng != DNG_PREFIX + hashlib.sha256(buf).digest():
        raise InputError("d-ng digest is not SHA-256 of the buffer")
    return decode_record(buf)


def format_record(rec):
    head = f"{KIND_NAMES[rec.kind]:<6} load={rec.load_id.hex()[:8]} seq={rec.seq}"
    b = rec.body
    if rec.kind == KIND_EXEC:
        flags = []
        if rec.flags & FLAG_TRUNCATED:
            flags.append("truncated")
        if rec.flags & FLAG_UNRESOLVED:
            flags.append("unresolved")
        path = b["path"].decode("utf-8", "backslashreplace")
        return (
            f"{head} pid={b['pid']} tgid={b['tgid']} ppid={b['ppid']} "
            f"old_pid={b['old_pid']} uid={b['uid']} euid={b['euid']} "
            f"start_ns={b['start_ns']} digest={b['path_digest'].hex()} "
            f"path={path!r}" + (f" [{','.join(flags)}]" if flags else "")
        )
    if rec.kind == KIND_LOAD:
        return f"{head} shim_version={b['shim_version']} loaded_ns={b['loaded_ns']}"
    if rec.kind == KIND_LOST:
        return f"{head} count={b['count']}"
    return head


def sequence_findings(records):
    """Gaps and order faults in seq, per load. records: list of (index, Record)."""
    findings = []
    last = {}
    for idx, rec in records:
        key = rec.load_id
        if key not in last:
            if rec.kind != KIND_LOAD or rec.seq != 0:
                findings.append(
                    f"GAP    load={key.hex()[:8]} first record is {KIND_NAMES[rec.kind]} "
                    f"seq={rec.seq} (entry {idx}), not LOAD seq=0"
                )
        else:
            prev = last[key]
            if prev.kind == KIND_UNLOAD:
                findings.append(f"GAP    load={key.hex()[:8]} record after UNLOAD (entry {idx})")
            if rec.seq != prev.seq + 1:
                findings.append(
                    f"GAP    load={key.hex()[:8]} seq {prev.seq} -> {rec.seq} (entry {idx})"
                )
            if rec.kind == KIND_LOAD:
                findings.append(f"GAP    load={key.hex()[:8]} second LOAD (entry {idx})")
        last[key] = rec
    return findings


@dataclass
class Attest:
    """The fields of a TPMS_ATTEST quote this verifier uses."""

    extra_data: bytes
    clock: int
    reset_count: int
    restart_count: int
    safe: int
    selection: list
    pcr_digest: bytes


def parse_attest(blob):
    """Decode a TPMS_ATTEST (big-endian TPM marshalling) holding a quote."""
    try:
        magic, typ = struct.unpack_from(">IH", blob, 0)
        off = 6
        (n,) = struct.unpack_from(">H", blob, off)
        off += 2 + n
        (n,) = struct.unpack_from(">H", blob, off)
        extra = blob[off + 2 : off + 2 + n]
        off += 2 + n
        clock, reset, restart, safe = struct.unpack_from(">QIIB", blob, off)
        off += 17 + 8
        (count,) = struct.unpack_from(">I", blob, off)
        off += 4
        selection = []
        for _ in range(count):
            alg, size = struct.unpack_from(">HB", blob, off)
            off += 3
            bits = blob[off : off + size]
            off += size
            pcrs = {i * 8 + b for i, byte in enumerate(bits) for b in range(8) if byte >> b & 1}
            selection.append((alg, pcrs))
        (n,) = struct.unpack_from(">H", blob, off)
        digest = blob[off + 2 : off + 2 + n]
        off += 2 + n
    except struct.error as exc:
        raise InputError("quote message truncated") from exc
    if magic != ATTEST_MAGIC or typ != ATTEST_QUOTE:
        raise InputError("quote message is not a TPM-generated quote")
    if off != len(blob) or len(digest) != n:
        raise InputError("quote message length")
    return Attest(extra, clock, reset, restart, safe, selection, digest)


def run_checkquote(ak, msg, sig, pcrs, qual_hex):
    """tpm2_checkquote over one quote; returns (ok, output)."""
    tool = shutil.which("tpm2_checkquote")
    if tool is None:
        raise InputError("tpm2_checkquote not installed")
    res = subprocess.run(
        [tool, "-u", str(ak), "-m", str(msg), "-s", str(sig), "-f", str(pcrs),
         "-g", "sha256", "-q", qual_hex],
        capture_output=True, text=True, check=False,
    )
    return res.returncode == 0, (res.stdout + res.stderr).strip()


def quote_ids(bundle):
    ids = []
    for p in bundle.glob("quote-*.msg"):
        m = re.fullmatch(r"quote-(\d+)\.msg", p.name)
        if m:
            ids.append(m.group(1))
    return sorted(ids, key=int)


def read_text(path):
    try:
        return path.read_text().strip()
    except OSError as exc:
        raise InputError(f"{path.name}: {exc.strerror}") from exc


def read_bytes(path):
    try:
        return path.read_bytes()
    except OSError as exc:
        raise InputError(f"{path.name}: {exc.strerror}") from exc


def verify_bundle(bundle, ak=None, nonce=None, checkquote=None, out=print):
    """Verify one bundle. Returns the list of reasons the evidence is broken."""
    checkquote = checkquote or run_checkquote
    broken = []
    entries = parse_list(read_bytes(bundle / "ima.bin"))
    anchor = [e for e in entries if e.pcr == PCR_ANCHOR]
    prefixes = replay(entries, PCR_ANCHOR)
    digests = [e.template_digest() for e in anchor]

    boot_id = bundle / "boot_id"
    if boot_id.exists():
        out(f"boot_id {read_text(boot_id)} (information, not evidence)")
    out(f"list   {len(entries)} entries, {len(anchor)} on PCR {PCR_ANCHOR}")

    records = []
    for i, e in enumerate(anchor):
        try:
            rec = anchor_record(e)
        except InputError as exc:
            broken.append(f"PCR {PCR_ANCHOR} entry {e.index}: {exc}")
            out(f"BAD    entry {e.index}: {exc}")
            continue
        records.append((i, rec))

    ak_path = Path(ak) if ak else bundle / "ak.pem"
    out(f"ak     {ak_path}" + ("" if ak else " (from the bundle, not pinned by --ak)"))

    ids = quote_ids(bundle)
    if not ids:
        broken.append("no quote in the bundle")
    anchored = None
    for q in ids:
        msg = bundle / f"quote-{q}.msg"
        att = parse_attest(read_bytes(msg))
        src = read_text(bundle / f"quote-{q}.src")
        qual = att.extra_data.hex()
        line = (
            f"QUOTE  {q} resetCount={att.reset_count} restartCount={att.restart_count} "
            f"clock={att.clock} extraData={src}:{qual}"
        )
        ok, detail = checkquote(ak_path, msg, bundle / f"quote-{q}.sig",
                                bundle / f"quote-{q}.pcrs", qual)
        if not ok:
            broken.append(f"quote {q}: tpm2_checkquote failed: {detail}")
        if att.selection != [(SHA256_ALG, QUOTE_PCRS)]:
            broken.append(f"quote {q}: selection is not sha256:7,13")
        pcr7 = read_bytes(bundle / f"pcr7-{q}.bin")
        match = None
        if len(pcr7) == 32:
            for n, value in enumerate(prefixes):
                if hashlib.sha256(pcr7 + value).digest() == att.pcr_digest:
                    match = n
                    break
        if match is None:
            broken.append(f"quote {q}: no replay prefix of PCR {PCR_ANCHOR} gives the quoted digest")
            out(f"{line} checkquote={'ok' if ok else 'FAILED'} replay=NO MATCH")
            continue
        if src == "nonce":
            if nonce is not None and qual != nonce.lower():
                broken.append(f"quote {q}: extraData is not the auditor's nonce")
        elif src == "head":
            heads = [i + 1 for i, d in enumerate(digests) if d.hex() == qual]
            if not heads or heads[0] > match:
                broken.append(f"quote {q}: head is not an entry the quote covers")
        else:
            broken.append(f"quote {q}: unknown extraData source {src!r}")
        out(
            f"{line} checkquote={'ok' if ok else 'FAILED'} pcr7={pcr7.hex()} "
            f"pcr13={prefixes[match].hex()} covers {match} of {len(anchor)}"
        )
        anchored = match if anchored is None else max(anchored, match)

    for i, rec in records:
        out(("       " if anchored is not None and i < anchored else "TAIL   ") + format_record(rec))
    for finding in sequence_findings(records):
        out(finding)
        broken.append(finding.removeprefix("GAP").strip())

    lost = sum(r.body["count"] for _, r in records if r.kind == KIND_LOST)
    execs = sum(1 for _, r in records if r.kind == KIND_EXEC)
    tail = len(anchor) - (anchored or 0)
    out(f"total  EXEC {execs}, LOST count {lost}, loads {len({r.load_id for _, r in records})}")
    out(f"tail   {tail} PCR {PCR_ANCHOR} entries after the last quote: unanchored")
    out("note   record order is the order execs reached the workqueue, not exact exec order")
    return broken


def pcrread_value(text, pcr):
    m = re.search(rf"^\s*{pcr}\s*:\s*0x([0-9A-Fa-f]{{64}})\s*$", text, re.M)
    if not m:
        raise InputError(f"no sha256 PCR {pcr} value in the pcrread output")
    return bytes.fromhex(m.group(1))


def replay_fixture(list_path, pcrread_path, pcr, out=print):
    """Replay one PCR of a raw list against a tpm2_pcrread output. True if equal."""
    entries = parse_list(read_bytes(Path(list_path)))
    mine = [e for e in entries if e.pcr == pcr]
    zero = sum(1 for e in mine if e.listed == bytes(20))
    value = replay(entries, pcr)[-1]
    read = pcrread_value(read_text(Path(pcrread_path)), pcr)
    out(f"entries  {len(entries)}, {len(mine)} on PCR {pcr}")
    out(f"replay   {value.hex()}")
    out(f"pcrread  {read.hex()}")
    if zero:
        out(f"note     {zero} PCR {pcr} entries list an all-zero digest (violations)")
    out("EQUAL" if value == read else "NOT EQUAL")
    return value == read


def verdict(broken, pinned):
    """The closing line and exit status for one bundle."""
    if broken:
        return "evidence broken", 1
    if not pinned:
        return "unanchored: AK not pinned", 3
    return "evidence verified", 0


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("bundle", nargs="?", help="bundle directory written by collect.sh")
    ap.add_argument("--ak", help="attestation key public PEM to pin instead of the bundle's")
    ap.add_argument("--nonce", help="the auditor's nonce, hex, to check nonce quotes against")
    ap.add_argument("--replay-pcr", type=int, help="fixture mode: PCR to replay")
    ap.add_argument("--list", help="fixture mode: binary measurement list")
    ap.add_argument("--pcrread", help="fixture mode: tpm2_pcrread output")
    args = ap.parse_args(argv)
    try:
        if args.replay_pcr is not None:
            if not (args.list and args.pcrread) or args.bundle:
                ap.error("--replay-pcr needs --list and --pcrread and no bundle")
            return 0 if replay_fixture(args.list, args.pcrread, args.replay_pcr) else 1
        if not args.bundle:
            ap.error("a bundle directory is required")
        broken = verify_bundle(Path(args.bundle), ak=args.ak, nonce=args.nonce)
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for reason in broken:
        print(f"BROKEN {reason}")
    line, status = verdict(broken, pinned=bool(args.ak))
    print(line)
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

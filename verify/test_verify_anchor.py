#!/usr/bin/env python3
"""Offline tests of verify-anchor.py on a synthetic measurement list.

    python3 -I verify/test_verify_anchor.py

Records are packed here from the published layout, independently of the
decoder, so a decoder that drifts from the layout fails.
"""

import hashlib
import importlib.util
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True  # leave no __pycache__ beside the sources
_SPEC = importlib.util.spec_from_file_location(
    "verify_anchor", Path(__file__).resolve().parent / "verify-anchor.py"
)
va = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(va)

LOAD_A = bytes(range(16))
LOAD_B = bytes(range(16, 32))


def header(kind, seq, load_id):
    return b"ASX1" + bytes([kind]) + seq.to_bytes(8, "little") + load_id


def exec_rec(seq, path, load_id=LOAD_A, unresolved=False, pid=4242):
    kind = 1
    digest = bytes(20)
    body = b""
    if unresolved:
        kind |= 0x40
    else:
        digest = hashlib.sha256(path).digest()[:20]
        body = path
        if len(path) > 1024:
            kind |= 0x80
            body = path[:1024]
    fixed = b"".join(v.to_bytes(4, "little") for v in (pid, pid, 1, pid, 999, 999))
    return (
        header(kind, seq, load_id) + fixed + (123456789).to_bytes(8, "little")
        + digest + len(body).to_bytes(2, "little") + body
    )


def load_rec(load_id=LOAD_A):
    return header(2, 0, load_id) + (1).to_bytes(2, "little") + (5000).to_bytes(8, "little")


def lost_rec(seq, count, load_id=LOAD_A):
    return header(3, seq, load_id) + count.to_bytes(8, "little")


def unload_rec(seq, load_id=LOAD_A):
    return header(4, seq, load_id)


def field(b):
    return struct.pack("<I", len(b)) + b


def entry(pcr, template, data, listed=b"\x11" * 20):
    return (
        struct.pack("<I", pcr) + listed + struct.pack("<I", len(template)) + template
        + struct.pack("<I", len(data)) + data
    )


def buf_entry(rec, pcr=13, event=b"exec\x00", dng=None):
    dng = dng if dng is not None else b"sha256:\x00" + hashlib.sha256(rec).digest()
    return entry(pcr, b"ima-buf", field(dng) + field(event) + field(rec))


def ng_entry(name, pcr=10, listed=b"\x11" * 20):
    dng = b"sha256:\x00" + hashlib.sha256(name).digest()
    return entry(pcr, b"ima-ng", field(dng) + field(name + b"\x00"), listed)


def chain(datas):
    value = bytes(32)
    for d in datas:
        value = hashlib.sha256(value + hashlib.sha256(d).digest()).digest()
    return value


def attest(extra, pcr_digest, reset=7, pcrs=(7, 13)):
    bits = bytearray(3)
    for p in pcrs:
        bits[p // 8] |= 1 << (p % 8)
    signer = b"\x00\x0b" + bytes(32)
    return (
        struct.pack(">IH", 0xFF544347, 0x8018)
        + struct.pack(">H", len(signer)) + signer
        + struct.pack(">H", len(extra)) + extra
        + struct.pack(">QIIB", 1000, reset, 0, 1) + struct.pack(">Q", 0x0000040002000700)
        + struct.pack(">I", 1) + struct.pack(">HB", 0x000B, 3) + bytes(bits)
        + struct.pack(">H", 32) + pcr_digest
    )


LONG = b"/" + b"x" * 1500
RECORDS = [
    load_rec(),
    exec_rec(1, b"/usr/bin/true"),
    exec_rec(2, LONG),
    exec_rec(3, b"", unresolved=True),
    lost_rec(4, 3),
    exec_rec(5, b"/tmp/gone (deleted)"),
    unload_rec(6),
]


def sample_list(records=RECORDS):
    return b"".join([ng_entry(b"boot_aggregate"), *(buf_entry(r) for r in records), ng_entry(b"/etc/x")])


class Decode(unittest.TestCase):
    def test_each_kind(self):
        kinds = [va.decode_record(r).kind for r in RECORDS]
        self.assertEqual(kinds, [2, 1, 1, 1, 3, 1, 4])

    def test_exec_fields(self):
        r = va.decode_record(exec_rec(1, b"/usr/bin/true", pid=77))
        self.assertEqual((r.seq, r.load_id, r.flags), (1, LOAD_A, 0))
        b = r.body
        self.assertEqual((b["pid"], b["tgid"], b["ppid"], b["old_pid"]), (77, 77, 1, 77))
        self.assertEqual((b["uid"], b["euid"], b["start_ns"]), (999, 999, 123456789))
        self.assertEqual(b["path"], b"/usr/bin/true")
        self.assertEqual(b["path_digest"], hashlib.sha256(b"/usr/bin/true").digest()[:20])

    def test_truncated_path_digest_over_full_path(self):
        r = va.decode_record(exec_rec(2, LONG))
        self.assertEqual(r.flags, 0x80)
        self.assertEqual(len(r.body["path"]), 1024)
        self.assertEqual(r.body["path_digest"], hashlib.sha256(LONG).digest()[:20])

    def test_unresolved_path(self):
        r = va.decode_record(exec_rec(3, b"", unresolved=True))
        self.assertEqual(r.flags, 0x40)
        self.assertEqual((r.body["path"], r.body["path_digest"]), (b"", bytes(20)))

    def test_load_lost_unload(self):
        self.assertEqual(va.decode_record(load_rec()).body, {"shim_version": 1, "loaded_ns": 5000})
        self.assertEqual(va.decode_record(lost_rec(4, 3)).body, {"count": 3})
        self.assertEqual(va.decode_record(unload_rec(6)).body, {})

    def test_record_sizes(self):
        self.assertEqual(len(load_rec()), 39)
        self.assertEqual(len(lost_rec(1, 1)), 37)
        self.assertEqual(len(unload_rec(1)), 29)
        self.assertEqual(len(exec_rec(1, b"/a")), 83 + 2)

    def test_malformed(self):
        bad = [
            b"ASX2" + load_rec()[4:],
            load_rec() + b"\x00",
            exec_rec(1, b"/a")[:-1],
            header(1 | 0x10, 1, LOAD_A) + exec_rec(1, b"/a")[29:],
            header(3 | 0x80, 1, LOAD_A) + (1).to_bytes(8, "little"),
            header(9, 1, LOAD_A),
        ]
        for b in bad:
            with self.assertRaises(va.InputError):
                va.decode_record(b)


class ListAndReplay(unittest.TestCase):
    def test_parse_keeps_order_and_pcr(self):
        entries = va.parse_list(sample_list())
        self.assertEqual([e.pcr for e in entries], [10] + [13] * len(RECORDS) + [10])
        self.assertEqual([va.anchor_record(e).seq for e in entries if e.pcr == 13], list(range(7)))

    def test_replay_uses_template_data_not_listed_digest(self):
        entries = va.parse_list(sample_list())
        datas = [e.data for e in entries if e.pcr == 13]
        self.assertEqual(va.replay(entries, 13)[-1], chain(datas))
        self.assertEqual(len(va.replay(entries, 13)), len(RECORDS) + 1)

    def test_dng_mismatch(self):
        e = va.parse_list(buf_entry(load_rec(), dng=b"sha256:\x00" + bytes(32)))[0]
        with self.assertRaises(va.InputError):
            va.anchor_record(e)

    def test_foreign_template_and_event(self):
        with self.assertRaises(va.InputError):
            va.anchor_record(va.parse_list(ng_entry(b"/x", pcr=13))[0])
        with self.assertRaises(va.InputError):
            va.anchor_record(va.parse_list(buf_entry(load_rec(), event=b"other\x00"))[0])

    def test_truncated_list(self):
        with self.assertRaises(va.InputError):
            va.parse_list(sample_list()[:-3])

    def test_gaps(self):
        recs = [(0, va.decode_record(load_rec())), (1, va.decode_record(exec_rec(1, b"/a"))),
                (2, va.decode_record(exec_rec(3, b"/a"))),
                (3, va.decode_record(exec_rec(5, b"/b", load_id=LOAD_B)))]
        f = va.sequence_findings(recs)
        self.assertEqual(len(f), 2)
        self.assertIn("seq 1 -> 3", f[0])
        self.assertIn("not LOAD", f[1])

    def test_contiguous_has_no_gap(self):
        recs = [(i, va.decode_record(r)) for i, r in enumerate(RECORDS)]
        self.assertEqual(va.sequence_findings(recs), [])


class Fixture(unittest.TestCase):
    def test_replay_fixture(self):
        blob = b"".join([ng_entry(b"boot_aggregate"), ng_entry(b"/a", listed=bytes(20)),
                         buf_entry(load_rec())])
        entries = va.parse_list(blob)
        value = chain([e.data for e in entries if e.pcr == 10])
        with tempfile.TemporaryDirectory() as d:
            lst = Path(d, "list.bin")
            lst.write_bytes(blob)
            good = Path(d, "good.txt")
            good.write_text(f"  sha256:\n    10: 0x{value.hex().upper()}\n")
            bad = Path(d, "bad.txt")
            bad.write_text(f"  sha256:\n    10: 0x{bytes(32).hex()}\n")
            lines = []
            self.assertTrue(va.replay_fixture(lst, good, 10, out=lines.append))
            self.assertIn("note     1 PCR 10 entries list an all-zero digest (violations)", lines)
            self.assertFalse(va.replay_fixture(lst, bad, 10, out=lambda _: None))


PCR7 = hashlib.sha256(b"pcr7").digest()


class Bundle(unittest.TestCase):
    """Whole-bundle checks; tpm2_checkquote is replaced by a stub."""

    def make(self, d, quotes, records=RECORDS):
        blob = sample_list(records)
        Path(d, "ima.bin").write_bytes(blob)
        Path(d, "boot_id").write_text("00000000-0000-0000-0000-000000000000\n")
        entries = va.parse_list(blob)
        prefixes = va.replay(entries, 13)
        digests = [e.template_digest() for e in entries if e.pcr == 13]
        for q, (src, covers, extra) in enumerate(quotes, 1):
            if extra is None:
                extra = digests[covers - 1]
            value = prefixes[covers]
            Path(d, f"quote-{q}.msg").write_bytes(attest(extra, hashlib.sha256(PCR7 + value).digest()))
            Path(d, f"quote-{q}.src").write_text(src + "\n")
            Path(d, f"pcr7-{q}.bin").write_bytes(PCR7)
            Path(d, f"quote-{q}.sig").write_bytes(b"")
            Path(d, f"quote-{q}.pcrs").write_bytes(b"")

    def run_bundle(self, quotes, nonce=None, ok=True, records=RECORDS, extend=None):
        with tempfile.TemporaryDirectory() as d:
            self.make(d, quotes, records)
            if extend is not None:
                Path(d, "quote-1.msg").write_bytes(attest(b"\x01" * 32, extend))
            lines = []
            broken = va.verify_bundle(Path(d), nonce=nonce,
                                      checkquote=lambda *a: (ok, "stub"), out=lines.append)
            return broken, lines

    def test_verified_with_head_quote_and_tail(self):
        broken, lines = self.run_bundle([("head", 5, None)])
        self.assertEqual(broken, [])
        self.assertIn("covers 5 of 7", next(x for x in lines if x.startswith("QUOTE")))
        self.assertEqual(sum(x.startswith("TAIL") for x in lines), 2)
        self.assertIn("tail   2 PCR 13 entries after the last quote: unanchored", lines)
        self.assertIn("total  EXEC 4, LOST count 3, loads 1", lines)

    def test_nonce_quote(self):
        n = "ab" * 20
        self.assertEqual(self.run_bundle([("nonce", 7, bytes.fromhex(n))], nonce=n)[0], [])
        broken, _ = self.run_bundle([("nonce", 7, bytes.fromhex(n))], nonce="cd" * 20)
        self.assertTrue(any("auditor's nonce" in b for b in broken))

    def test_extend_outside_the_list_is_broken(self):
        broken, _ = self.run_bundle([("head", 7, None)], extend=hashlib.sha256(b"x").digest())
        self.assertTrue(any("no replay prefix" in b for b in broken))

    def test_head_beyond_what_the_quote_covers(self):
        entries = va.parse_list(sample_list())
        late = [e.template_digest() for e in entries if e.pcr == 13][6]
        broken, _ = self.run_bundle([("head", 3, late)])
        self.assertTrue(any("head is not an entry" in b for b in broken))

    def test_checkquote_failure_is_broken(self):
        broken, _ = self.run_bundle([("head", 7, None)], ok=False)
        self.assertTrue(any("tpm2_checkquote failed" in b for b in broken))

    def test_no_quote_is_broken(self):
        self.assertIn("no quote in the bundle", self.run_bundle([])[0])

    def test_bad_record_is_broken(self):
        recs = [*RECORDS[:2], b"ASX1\x09" + bytes(24)]
        broken, _ = self.run_bundle([("head", 3, None)], records=recs)
        self.assertTrue(any("unknown kind" in b for b in broken))

    def test_attest_fields(self):
        a = va.parse_attest(attest(b"\x05" * 32, bytes(32), reset=86))
        self.assertEqual((a.reset_count, a.extra_data, a.selection), (86, b"\x05" * 32, [(0x000B, {7, 13})]))
        with self.assertRaises(va.InputError):
            va.parse_attest(attest(b"", bytes(32))[:-1])


if __name__ == "__main__":
    unittest.main(verbosity=2)

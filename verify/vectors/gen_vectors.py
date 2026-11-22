#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Conformance vectors for layout 1, written as hex text.

    python3 -I verify/vectors/gen_vectors.py

Builds every vector of the index-axis conformance set over unsigned
layout-1 sighting encodings, every LINUX_EXEC vector (w01..w38) over the
kernel and software source encodings, and a few extra vectors (short ECDSA
scalars, unusable attestation keys). Writes:

    vectors-a.txt    index-axis vectors (TEST scheme)
    vectors-b.txt    LINUX_EXEC vectors and the extras
    signatures.txt   the signature cache (see below)
    vectors.sha256   SHA-256 of the three files above

Bytes are built from the specification's notation and the conventions
fixed for these vectors, not from the reader's code. Expected outcomes are
written by hand from the specification's tables; only the anchor numbers
follow from the conventions (quote clocks and counters). This script is not
a second reader: it computes no outcome.

Everything is deterministic except ECDSA signatures, which the system
`openssl` CLI makes with a random nonce. Each signature is cached in
signatures.txt, keyed by SHA-256 of the attestation it signs; a missing
entry is made once and appended. Every cached signature is checked with
`openssl dgst -verify` on every run, so a rerun reproduces every byte.

Python standard library only. Run with -I.
"""

import hashlib
import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

# Published test key, RFC 6979 A.2.5; not a secret; anchors nothing.
TEST_KEY_X = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
TEST_KEY_UX = 0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6
TEST_KEY_UY = 0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299
# The RFC's signature over "sample" with SHA-256, for a known-answer check.
RFC_SAMPLE_R = 0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716
RFC_SAMPLE_S = 0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8
# The order of the P-256 group.
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")


def sha(b):
    return hashlib.sha256(b).digest()


def u8(v):
    return struct.pack(">B", v)


def be16(v):
    return struct.pack(">H", v)


def be32(v):
    return struct.pack(">I", v)


def be64(v):
    return struct.pack(">Q", v)


def le16(v):
    return struct.pack("<H", v)


def le32(v):
    return struct.pack("<I", v)


def le64(v):
    return struct.pack("<Q", v)


AK_SPKI = SPKI_PREFIX + b"\x04" + TEST_KEY_UX.to_bytes(32, "big") + TEST_KEY_UY.to_bytes(32, "big")

# ---- conventions ---------------------------------------------------------

PATHS = {
    "D": b"/usr/bin/true",
    "X": b"/usr/bin/false",
    "Y": b"/usr/bin/yes",
    "Q": b"/usr/bin/env",
    "I": b"/usr/bin/sh",
}
DIG = {k: sha(v) for k, v in PATHS.items()}
BOOT = bytes([0xB0]) + bytes(range(1, 16))
OTHER_BOOT = b"\xbb" * 16
L = b"\x4c" * 16
L2 = b"\x4d" * 16
PCR7 = b"\x07" * 32
SIGNER = b"\x00\x0b" + b"\x5a" * 32  # qualifiedSigner: any fixed 34 bytes
LINUX_EXEC = 0x0001
TEST = 0xFFFF
OBSERVER = 0xFFFD
CLASS_EXEC = 1
CLASS_INSTANCE_START = 0xFFFD
CLASS_PARSE_REJECT = 0xFFFE

# ---- layout-1 encodings (big-endian) -------------------------------------


def subject(scheme, b):
    assert 1 <= len(b) <= 64
    return be16(scheme) + u8(len(b)) + b


def sighting(subj, cls, data, instance, index, prev, mode=1, cov_from=0, over=1):
    return (
        b"anchorstamp/sighting"
        + u8(1)
        + subj
        + be16(cls)
        + be16(len(data))
        + data
        + u8(mode)
        + be64(cov_from)
        + be16(over)
        + u8(0)
        + instance
        + be64(index)
        + prev
        + u8(0)
    )


def chain(prior):
    return sha(b"anchorstamp/chain" + b"\x00" + prior)


def joinref(scheme, b):
    return b"anchorstamp/joinref" + u8(1) + subject(scheme, b)


def claim(pid, t0, t_reap, digest, boot8):
    return joinref(LINUX_EXEC, be32(pid) + be64(t0) + be64(t_reap) + digest + boot8)


C = claim(4242, 2000, 3000, DIG["D"], BOOT[:8])

# ---- the shim's records (little-endian) ----------------------------------


def head(magic, kind, seq, load):
    return magic + u8(kind) + le64(seq) + load


def exec2(seq, load, pid, exec_ns, exe="D", req=None, start=None, uid=1001, ns=0, interp=False):
    path = PATHS[exe]
    req_d = DIG[req if req else exe]
    start = exec_ns - 10 if start is None else start
    kind = 1 | (0x20 if interp else 0)
    body = b"".join(le32(v) for v in (pid, pid, 1, pid, uid, uid))
    body += le64(start) + le64(exec_ns) + le32(0x00800001) + le64(1000 + pid)
    body += DIG[exe] + req_d + u8(ns) + le16(len(path)) + path
    return head(b"ASX2", kind, seq, load) + body


def load2(seq, load, loaded_ns):
    return head(b"ASX2", 2, seq, load) + le16(2) + le64(loaded_ns)


def armed2(seq, load, armed_ns):
    return head(b"ASX2", 5, seq, load) + le64(armed_ns)


def lost2(seq, load, count, first, last):
    return head(b"ASX2", 3, seq, load) + le64(count) + le64(first) + le64(last)


def unload2(seq, load, close_ns, unloaded_ns):
    return head(b"ASX2", 4, seq, load) + le64(close_ns) + le64(unloaded_ns)


def load1(load, loaded_ns):
    return head(b"ASX1", 2, 0, load) + le16(1) + le64(loaded_ns)


def exec1(seq, load, pid, start_ns, exe="X"):
    path = PATHS[exe]
    body = b"".join(le32(v) for v in (pid, pid, 1, pid, 1001, 1001))
    body += le64(start_ns) + DIG[exe][:20] + le16(len(path)) + path
    return head(b"ASX1", 1, seq, load) + body


def fields(*fs):
    return b"".join(le32(len(f)) + f for f in fs)


def buf_entry(record):
    """A PCR-13 ima-buf entry carrying `record`."""
    tdata = fields(b"sha256:\x00" + sha(record), b"exec\x00", record)
    return template_entry(b"ima-buf", tdata)


def template_entry(name, tdata):
    return le32(13) + b"\x5a" * 20 + le32(len(name)) + name + le32(len(tdata)) + tdata


FOREIGN = template_entry(b"ima-ng", fields(b"sha256:\x00" + b"\xab" * 32, b"foreign\x00"))


def tdata_of(entry):
    nlen = struct.unpack_from("<I", entry, 24)[0]
    off = 28 + nlen
    tlen = struct.unpack_from("<I", entry, off)[0]
    return entry[off + 4 : off + 4 + tlen]


def running(entries):
    v = [b"\x00" * 32]
    for e in entries:
        v.append(sha(v[-1] + sha(tdata_of(e))))
    return v


# ---- quotes --------------------------------------------------------------


def attest(extra, clock, pcr_digest, reset=7, restart=0, safe=1):
    return (
        be32(0xFF544347)
        + be16(0x8018)
        + be16(len(SIGNER))
        + SIGNER
        + be16(len(extra))
        + extra
        + be64(clock)
        + be32(reset)
        + be32(restart)
        + u8(safe)
        + be64(0)
        + be32(1)
        + be16(0x000B)
        + u8(3)
        + b"\x80\x20\x00"
        + be16(32)
        + pcr_digest
    )


def tpmt(r, s, rlen=32, slen=32):
    rb = r.to_bytes(32, "big")[32 - rlen :]
    sb = s.to_bytes(32, "big")[32 - slen :]
    assert int.from_bytes(rb, "big") == r and int.from_bytes(sb, "big") == s
    return be16(0x0018) + be16(0x000B) + be16(len(rb)) + rb + be16(len(sb)) + sb


def der_int(v):
    b = v.to_bytes((v.bit_length() + 8) // 8 or 1, "big")
    return b"\x02" + u8(len(b)) + b


def der_sig(r, s):
    body = der_int(r) + der_int(s)
    return b"\x30" + u8(len(body)) + body


def parse_der_sig(b):
    assert b[0] == 0x30 and b[1] == len(b) - 2
    assert b[2] == 0x02
    lr = b[3]
    r = int.from_bytes(b[4 : 4 + lr], "big")
    assert b[4 + lr] == 0x02
    ls = b[5 + lr]
    s = int.from_bytes(b[6 + lr : 6 + lr + ls], "big")
    return r, s


class Signer:
    """The openssl CLI with the published test key, and the cache."""

    def __init__(self, work, cache_path):
        self.work = work
        self.cache_path = cache_path
        self.cache = {}
        self.order = []
        self.made = 0
        if os.path.exists(cache_path):
            for line in open(cache_path, encoding="ascii"):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                key, r, s = line.split()
                self.cache[key] = (int(r, 16), int(s, 16))
                self.order.append(key)
        sec1 = (
            b"\x30\x31\x02\x01\x01\x04\x20"
            + TEST_KEY_X.to_bytes(32, "big")
            + b"\xa0\x0a\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07"
        )
        self.key_der = os.path.join(work, "key.der")
        with open(self.key_der, "wb") as f:
            f.write(sec1)
        self.key = os.path.join(work, "key.pem")
        self.pub = os.path.join(work, "pub.pem")
        run(["openssl", "ec", "-inform", "DER", "-in", self.key_der, "-out", self.key])
        run(["openssl", "ec", "-inform", "DER", "-in", self.key_der, "-pubout", "-out", self.pub])
        pub_der = os.path.join(work, "pub.der")
        run(["openssl", "ec", "-inform", "DER", "-in", self.key_der, "-pubout", "-outform", "DER", "-out", pub_der])
        with open(pub_der, "rb") as f:
            got = f.read()
        if got != AK_SPKI:
            sys.exit("STOP: the private scalar does not give the published public key")

    def verify(self, msg, r, s):
        m = os.path.join(self.work, "m.bin")
        g = os.path.join(self.work, "g.der")
        with open(m, "wb") as f:
            f.write(msg)
        with open(g, "wb") as f:
            f.write(der_sig(r, s))
        p = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", self.pub, "-signature", g, m],
            capture_output=True,
            check=False,
        )
        return p.returncode == 0 and p.stdout.strip() == b"Verified OK"

    def sign_once(self, msg):
        m = os.path.join(self.work, "m.bin")
        g = os.path.join(self.work, "g.der")
        with open(m, "wb") as f:
            f.write(msg)
        run(["openssl", "dgst", "-sha256", "-sign", self.key, "-out", g, m])
        with open(g, "rb") as f:
            return parse_der_sig(f.read())

    def sign(self, msg, short=False):
        """(r, s) over `msg`; with `short`, one whose r or s has a leading
        zero byte, found by re-signing (at most 4096 tries)."""
        key = sha(msg).hex()
        if key not in self.cache:
            for _ in range(4096 if short else 1):
                r, s = self.sign_once(msg)
                if not short or r < 1 << 248 or s < 1 << 248:
                    break
            else:
                sys.exit("STOP: no short signature in 4096 tries")
            self.cache[key] = (r, s)
            self.order.append(key)
            self.made += 1
        r, s = self.cache[key]
        if not self.verify(msg, r, s):
            sys.exit(f"STOP: cached signature for {key} does not verify")
        if short and not (r < 1 << 248 or s < 1 << 248):
            sys.exit(f"STOP: cached signature for {key} is not short")
        return r, s

    def write(self):
        with open(self.cache_path, "w", encoding="ascii") as f:
            f.write("# SHA-256(attest) r s: ECDSA P-256 SHA-256 by the openssl CLI with the\n")
            f.write("# published RFC 6979 A.2.5 test key (not a secret; anchors nothing).\n")
            for k in self.order:
                r, s = self.cache[k]
                f.write(f"{k} {r:064x} {s:064x}\n")


def run(cmd):
    p = subprocess.run(cmd, capture_output=True, check=False)
    if p.returncode != 0:
        sys.exit(f"STOP: {' '.join(cmd)}: {p.stderr.decode(errors='replace').strip()}")
    return p.stdout


# ---- vector text ---------------------------------------------------------


class Out:
    def __init__(self):
        self.lines = []

    def block(self, name, tests, body, expect):
        self.lines.append(f"vector {name}")
        self.lines.append(f"tests {tests}")
        self.lines.extend(body)
        self.lines.extend("expect " + e for e in expect)
        self.lines.append("end")
        self.lines.append("")

    def text(self, header):
        return "".join(f"# {h}\n" for h in header) + "\n" + "\n".join(self.lines)


# ---- index-axis vectors over S encodings ---------------------------------

A1 = b"\xa1" * 16
B2 = b"\xb2" * 16
TRUE = PATHS["D"]


def test_subject(instance, position, ident):
    return subject(TEST, instance + be64(position) + bytes([ident]))


def test_joinref(instance, position, ident):
    return joinref(TEST, instance + be64(position) + bytes([ident]))


def part_a():
    s0 = sighting(test_subject(A1, 0, 0x10), CLASS_EXEC, TRUE, A1, 0, b"\x00" * 32)
    s1 = sighting(test_subject(A1, 1, 0x11), CLASS_EXEC, TRUE, A1, 1, chain(s0))
    s2 = sighting(test_subject(A1, 2, 0x12), CLASS_EXEC, TRUE, A1, 2, chain(s1))
    s4 = sighting(test_subject(A1, 4, 0x14), CLASS_EXEC, TRUE, A1, 4, b"\xee" * 32)
    s2f = sighting(test_subject(A1, 2, 0x22), CLASS_EXEC, TRUE, A1, 2, chain(s1))
    start = BOOT + be64(0) + be32(0)
    c0 = sighting(subject(OBSERVER, B2), CLASS_INSTANCE_START, start, B2, 0, b"\x00" * 32)
    t1 = sighting(test_subject(B2, 1, 0x11), CLASS_EXEC, TRUE, B2, 1, chain(c0))
    t2 = sighting(test_subject(B2, 2, 0x12), CLASS_EXEC, TRUE, B2, 2, chain(t1))
    r2 = sighting(subject(OBSERVER, B2), CLASS_PARSE_REJECT, be64(1), B2, 2, chain(t1))
    t3 = sighting(test_subject(B2, 3, 0x13), CLASS_EXEC, TRUE, B2, 3, chain(r2))
    j = {
        "S1": test_joinref(A1, 1, 0x11),
        "unknown": test_joinref(A1, 1, 0x99),
        "S1 at 2": test_joinref(A1, 2, 0x11),
        "index 3": test_joinref(A1, 3, 0x13),
        "index 9": test_joinref(A1, 9, 0x19),
        "T1": test_joinref(B2, 1, 0x11),
        "B2 unknown": test_joinref(B2, 1, 0x99),
    }
    agrees = [
        "kind Agrees",
        "strength 100",
        "scheme ffff",
        "caps SelfProvAbsent,SequenceUnappraised,AnchorOperatorAsserted",
    ]

    def health(gaps=0, forks=0, touches=0):
        return f"health gaps={gaps} breaks=0 forks={forks} excluded=0 touches={touches} broken=0"

    vecs = [
        ("v01", "empty stream", "S1", [], ["kind NothingToCompare", health(), "path NothingArrived"]),
        ("v02", "corroborated", "S1", [s0, s1, s2], agrees + [health(), "path Relayed1"]),
        ("v03", "fabricated, mediated, in window", "unknown", [s0, s1, s2, s4],
         ["kind Disagrees", "detail Unobserved", health(gaps=1), "path Relayed1"]),
        ("v04", "resolves to another subject", "S1 at 2", [s0, s1, s2],
         ["kind Disagrees", "detail SubjectMismatch", health(), "path Relayed1"]),
        ("v05", "gap touches the claim", "index 3", [s0, s1, s2, s4],
         ["kind NothingToCompare", health(gaps=1, touches=1), "path Relayed1"]),
        ("v06", "gap does not touch the claim", "S1", [s0, s1, s2, s4],
         agrees + [health(gaps=1), "path Relayed1"]),
        ("v07", "claim beyond the stream's end", "index 9", [s0, s1, s2],
         ["kind NothingToCompare", health(), "path Relayed1"]),
        ("v09", "fork", "S1", [s0, s1, s2, s2f], agrees + [health(forks=1), "path Relayed1"]),
        ("v10", "Local claim", None, [s0, s1, s2], ["kind NothingToCompare", health(), "path Relayed1"]),
        ("v13", "instance start", "T1", [c0, t1, t2], agrees + [health(), "path Relayed1"]),
        ("v14", "parse reject touches", "B2 unknown", [c0, t1, r2, t3],
         ["kind NothingToCompare", health(touches=1), "path Relayed1"]),
        ("v14b", "unobserved after an instance start", "B2 unknown", [c0, t1, t2],
         ["kind Disagrees", "detail Unobserved", health(), "path Relayed1"]),
    ]
    out = Out()
    for name, tests, cl, stream, expect in vecs:
        body = ["claim " + (j[cl].hex() if cl else "local")]
        body += ["record " + r.hex() for r in stream]
        out.block(name, tests, body, expect + ["anchor none"])
    out.block("v11", "account", ["claim " + j["S1"].hex()] + ["record " + r.hex() for r in (s0, s1, s2)],
              ["unclaimed " + A1.hex() + ":0," + A1.hex() + ":2"])
    out.block("v15", "account never lists a control record",
              ["claim " + j["T1"].hex()] + ["record " + r.hex() for r in (c0, t1, t2)],
              ["unclaimed " + B2.hex() + ":2"])
    return out


# ---- LINUX_EXEC vectors --------------------------------------------------

K_CAPS = "SelfProvAbsent,BootConfigUnappraised,EkChainUnvalidated,AkPinnedLocally,BootAsserted"
KA_CAPS = K_CAPS + ",RootCanInsert"
STD = "anchor within reset=7 from=100000 to=200000 restart_from=0 restart_to=0 safe=1"


def agrees_k(also=0, extra="", anchor=STD, strength=400):
    return ["kind Agrees", f"strength {strength}", "scheme 0001", f"caps {KA_CAPS}{extra}", f"also {also}", anchor]


def disagrees_k(detail):
    return ["kind Disagrees", f"detail {detail}", "strength 400", f"caps {K_CAPS}", STD]


NTC = ["kind NothingToCompare", "anchor none"]
TAIL = agrees_k(extra=",Unanchored", anchor="anchor none", strength=100)


class K:
    """A kernel-source vector: list entries in order, quotes at prefixes."""

    def __init__(self, entries, q1=None, q0=2, boot=BOOT):
        self.entries = entries
        self.q0 = q0
        self.q1 = len(entries) if q1 is None else q1
        self.boot = boot
        self.extra_quotes = []

    def quotes(self, signer, mutate=None, short=False):
        v = running(self.entries)
        spec = [(self.q0, b"\x11" * 16, 100000, v[self.q0]), (self.q1, b"\x22" * 16, 200000, v[self.q1])]
        spec += self.extra_quotes
        out = []
        for i, (_, extra, clock, value) in enumerate(spec):
            msg = attest(extra, clock, sha(PCR7 + value))
            r, s = signer.sign(msg, short=short and i == 1)
            rlen = slen = 32
            if short and i == 1:
                rlen = 31 if r < 1 << 248 else 32
                slen = 31 if s < 1 << 248 and rlen == 32 else 32
            if mutate:
                s = mutate(s)
            out.append((msg, tpmt(r, s, rlen, slen)))
        return out

    def body(self, signer, mutate=None, ak=AK_SPKI, short=False):
        lines = ["profile K", "ak " + ak.hex(), "boot " + self.boot.hex(), "nonce " + (b"\x22" * 16).hex(),
                 "interval 0", "list " + b"".join(self.entries).hex()]
        for msg, sig in self.quotes(signer, mutate, short):
            lines.append(f"quote {msg.hex()} {sig.hex()} {PCR7.hex()}")
        return lines


def load_l(*records, loaded=1000, armed=1100):
    """Load L: LOAD, ARMED, then `records` (callables taking a seq) at seq 2..."""
    out = [buf_entry(load2(0, L, loaded)), buf_entry(armed2(1, L, armed))]
    for i, rec in enumerate(records):
        out.append(buf_entry(rec(2 + i)))
    return out


def ex(pid, exec_ns, exe="X", **kw):
    return lambda seq: exec2(seq, L, pid, exec_ns, exe, **kw)


def lost(count, first, last):
    return lambda seq: lost2(seq, L, count, first, last)


def s_stream(records, mode=1):
    """A software-source stream: instance 0x5a, START at index 0."""
    inst = b"\x5a" * 16
    start = BOOT + be64(1000) + be32(10_000_000)
    out = [sighting(subject(OBSERVER, inst), CLASS_INSTANCE_START, start, inst, 0, b"\x00" * 32, mode, 1000)]
    for i, (pid, lo, hi, exe) in enumerate(records):
        subj = subject(LINUX_EXEC, be32(pid) + be64(lo) + be64(hi) + DIG[exe])
        out.append(sighting(subj, CLASS_EXEC, PATHS[exe], inst, 1 + i, chain(out[-1]), mode, 1000))
    return out


def part_b(signer):
    out = Out()
    w1 = load_l(ex(4242, 2500, "D"), ex(99, 3500))
    w2 = load_l(ex(4242, 2500), ex(99, 3500))
    w3 = load_l(ex(7, 1500), ex(99, 3500))

    def k(name, tests, vec, expect, claim_=C, mutate=None, ak=AK_SPKI, short=False, scope=None):
        body = vec.body(signer, mutate, ak, short)
        body.append("claim " + (claim_.hex() if claim_ else "local"))
        if scope is not None:
            body.append("scope " + ",".join(str(u) for u in scope))
        out.block(name, tests, body, expect)

    def s(name, tests, recs, expect, mode=1):
        body = ["profile S", "claim " + C.hex()] + ["record " + r.hex() for r in s_stream(recs, mode)]
        out.block(name, tests, body, expect)

    # x01 first: w01's second quote then carries, padded, the cached
    # signature whose r or s is short; x01 carries it unpadded
    k("x01", "short ECDSA scalar", K(w1), agrees_k(), short=True)
    k("w01", "match", K(w1), agrees_k())
    k("w02", "wrong file", K(w2), disagrees_k("SubjectMismatch"))
    k("w03", "unobserved", K(w3), disagrees_k("Unobserved"))
    k("w04", "not reached", K(load_l(ex(7, 1500), ex(99, 2900))), NTC)
    k("w05", "before coverage", K(load_l(ex(7, 4100), loaded=4000, armed=4050)),
      ["kind NotCovered", "windows 4000-open", "anchor none"])
    k("w06", "before ARMED", K(load_l(ex(99, 3500), armed=2600)), NTC)
    k("w07", "pid outside the window", K(load_l(ex(4242, 1500, "D"), ex(99, 3500))), disagrees_k("Unobserved"))
    k("w08", "re-exec", K(load_l(ex(4242, 2400, start=2300), ex(4242, 2500, "D", start=2300), ex(99, 3500))),
      agrees_k(also=0))
    k("w09", "two matches", K(load_l(ex(4242, 2400, "D", start=2300), ex(4242, 2600, "D", start=2300))),
      agrees_k(also=1))
    k("w10", "LOST touching", K(load_l(ex(7, 1500), lost(3, 2100, 2200), ex(99, 3500))),
      NTC + ["health touches=1"])
    k("w11", "LOST not touching", K(load_l(ex(7, 1500), lost(3, 3100, 3200), ex(99, 3500))),
      disagrees_k("Unobserved"))
    w12 = [buf_entry(load2(0, L, 1000)), buf_entry(armed2(1, L, 1100)),
           buf_entry(exec2(2, L, 7, 1500, "X")), buf_entry(exec2(4, L, 99, 3500, "X"))]
    k("w12", "seq gap", K(w12), NTC + ["health gaps=1 touches=1"])
    w13 = K(w3)
    w13.extra_quotes = [(None, b"\x33" * 16, 300000, b"\xee" * 32)]
    k("w13", "replay break", w13, NTC + ["health breaks=1 broken=1"])
    k("w14", "tail", K(w1, q1=2), TAIL)
    k("w15", "tail reach only", K(w3, q1=3), NTC)
    k("w16", "bad signature", K(w1), TAIL + ["health excluded=2"], mutate=lambda s: s ^ 1)
    k("w17", "high-S", K(w1), agrees_k(), mutate=lambda s: N - s)
    w18 = w1[:3] + [FOREIGN] + w1[3:]
    k("w18", "foreign PCR-13 entry", K(w18), agrees_k() + ["health excluded=1"])
    k("w19", "other boot", K(w1, boot=OTHER_BOOT), NTC)
    k("w20", "Local claim", K(w1), NTC, claim_=None)
    k("w21", "interpreted", K(load_l(ex(4242, 2500, "I", req="D", interp=True))), agrees_k(extra=",Interpreted"))
    w22 = [buf_entry(load1(L, 1000)), buf_entry(exec1(1, L, 7, 1500)), buf_entry(exec1(2, L, 99, 3500))]
    k("w22", "v1 load", K(w22, q0=1), NTC)
    s("w23", "S match", [(4242, 2400, 2600, "D")],
      ["kind Agrees", "strength 100", "scheme 0001",
       "caps SelfProvAbsent,SequenceUnappraised,TransportOperatorAsserted,BootAsserted,PathUnverified",
       "also 0", "anchor none"])
    s("w24", "S mismatch", [(4242, 2400, 2600, "X"), (99, 3500, 3700, "X")], NTC)
    k("w25", "loss beside a mismatch", K(load_l(ex(4242, 2500), lost(1, 2450, 2450), ex(99, 3500))), NTC)
    k("w26", "private mount namespace", K(load_l(ex(4242, 2500, "D", ns=2), ex(99, 3500))), NTC)
    k("w27", "unlinked file", K(load_l(ex(4242, 2500, ns=8), ex(99, 3500))), NTC)
    k("w28", "fork outside the window", K(load_l(ex(4242, 2500, "D", start=1900), ex(99, 3500))),
      disagrees_k("Unobserved"))
    k("w29", "two processes", K(load_l(ex(4242, 2100, start=2050), ex(4242, 2800, "D", start=2700))), NTC)
    k("w30", "tail mismatch", K(w2, q1=2), NTC)
    s("w31", "Sampled source", [(99, 3500, 3700, "X")], NTC, mode=2)
    w32 = load_l(ex(4242, 2500, "D"), ex(500, 2600), ex(600, 2700, uid=0), lost(1, 4000, 4000))
    k("w32", "account scope", K(w32), ["unclaimed " + L.hex() + ":3"], scope=[1001])
    k("w33", "rename", K(load_l(ex(4242, 2500, "Y", req="D"), ex(99, 3500))), NTC)
    k("w34", "first exec before ARMED", K(load_l(ex(4242, 1500, start=900), ex(99, 3500))), NTC,
      claim_=claim(4242, 800, 3000, DIG["D"], BOOT[:8]))
    k("w35", "unstable first, stable re-exec",
      K(load_l(ex(4242, 2400, "D", start=2300, ns=8), ex(4242, 2500, "Q", start=2300), ex(99, 3500))), NTC)
    w36 = load_l(ex(99, 3500)) + [buf_entry(load2(0, L2, 3600)), buf_entry(exec2(3, L, 100, 3700, "X"))]
    k("w36", "interleaved loads", K(w36), NTC + ["health breaks=1 broken=1"])
    w37 = [buf_entry(load2(0, L, 1000)), buf_entry(armed2(1, L, 1100)), buf_entry(unload2(2, L, 3600, 3700)),
           buf_entry(load2(0, L2, 3800)), buf_entry(armed2(1, L2, 3850)), buf_entry(exec2(2, L2, 4242, 2500, "D"))]
    k("w37", "forged load after UNLOAD", K(w37), agrees_k())
    k("w38", "probe held across unload", K(load_l(ex(7, 1500), ex(99, 3500), lambda seq: unload2(seq, L, 2500, 3600))),
      NTC)

    # extras: an unusable attestation key leaves every quote excluded and
    # every record in the tail
    k("x02", "AK of the wrong length", K(w1), TAIL + ["health excluded=2"], ak=AK_SPKI[:-1])
    bad_prefix = bytearray(AK_SPKI)
    bad_prefix[5] ^= 1
    k("x03", "AK with a wrong prefix", K(w1), TAIL + ["health excluded=2"], ak=bytes(bad_prefix))
    off_curve = bytearray(AK_SPKI)
    off_curve[-1] ^= 1
    k("x04", "AK point off the curve", K(w1), TAIL + ["health excluded=2"], ak=bytes(off_curve))
    return out


def main():
    with tempfile.TemporaryDirectory(dir=HERE) as work:
        signer = Signer(work, os.path.join(HERE, "signatures.txt"))
        # the known answer: the RFC's own signature over "sample" verifies
        if not signer.verify(b"sample", RFC_SAMPLE_R, RFC_SAMPLE_S):
            sys.exit("STOP: the RFC 6979 A.2.5 known answer does not verify")
        a = part_a()
        b = part_b(signer)
        signer.write()
    header_a = [
        "Index-axis conformance vectors (TEST scheme) over unsigned layout-1 sightings.",
        "Generated by gen_vectors.py; expected outcomes written by hand.",
        "Two vectors of the signed layout (unknown key, high S) retire with it.",
    ]
    header_b = [
        "LINUX_EXEC conformance vectors, kernel (K) and software (S) sources, layout 1.",
        "Generated by gen_vectors.py; expected outcomes written by hand; anchor numbers",
        "follow from the quote conventions. AK: the published RFC 6979 A.2.5 P-256 key.",
    ]
    files = {
        "vectors-a.txt": a.text(header_a),
        "vectors-b.txt": b.text(header_b),
    }
    for name, text in files.items():
        with open(os.path.join(HERE, name), "w", encoding="ascii") as f:
            f.write(text)
    with open(os.path.join(HERE, "vectors.sha256"), "w", encoding="ascii") as f:
        for name in ("vectors-a.txt", "vectors-b.txt", "signatures.txt"):
            with open(os.path.join(HERE, name), "rb") as g:
                f.write(f"{hashlib.sha256(g.read()).hexdigest()}  {name}\n")
    print(f"signatures made this run: {signer.made}; cached: {len(signer.order)}")
    print(open(os.path.join(HERE, "vectors.sha256"), encoding="ascii").read(), end="")


if __name__ == "__main__":
    main()

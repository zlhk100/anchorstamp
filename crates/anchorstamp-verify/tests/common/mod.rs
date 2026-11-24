// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright © 2026 Lei Zhou

//! Builders for reader tests: unsigned layout-1 sighting streams, shim
//! records v1 and v2 inside IMA list entries, and `LINUX_EXEC` claims.

#![allow(dead_code)]

use anchorstamp_core::{
    CLASS_CLOCK_STEP, CLASS_COMMAND_EXECUTION, CLASS_INSTANCE_START, CLASS_PARSE_REJECT,
    CLASS_STREAM_ENDED, Coverage, CoverageMode, JOINREF_MAX_LEN, Observed, SIGHTING_MAX_LEN,
    SchemeTag, Seq, SequenceSource, SightingParts, SubjectRef, encode_joinref, encode_sighting,
};
use anchorstamp_verify::chain_digest;
use sha2::{Digest, Sha256};

pub fn sha(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

/// The digest conventions: D, X, Y, Q, I name five paths.
pub fn d() -> [u8; 32] {
    sha(b"/usr/bin/true")
}
pub fn x() -> [u8; 32] {
    sha(b"/usr/bin/false")
}
pub fn y() -> [u8; 32] {
    sha(b"/usr/bin/yes")
}
pub fn q() -> [u8; 32] {
    sha(b"/usr/bin/env")
}
pub fn i() -> [u8; 32] {
    sha(b"/usr/bin/sh")
}

/// Boot B: b0 01 .. 0f; another boot B': 16 bytes 0xbb.
pub const BOOT: [u8; 16] =
    [0xb0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
pub const OTHER_BOOT: [u8; 16] = [0xbb; 16];
pub const LOAD_L: [u8; 16] = [0x4c; 16];
pub const LOAD_L2: [u8; 16] = [0x4d; 16];

pub fn boot8(b: &[u8; 16]) -> [u8; 8] {
    b[..8].try_into().unwrap()
}

/// An encoded `LINUX_EXEC` join reference.
pub fn claim(pid: u32, t0: u64, t_reap: u64, digest: [u8; 32], boot: [u8; 8]) -> Vec<u8> {
    let mut s = [0u8; 60];
    s[0..4].copy_from_slice(&pid.to_be_bytes());
    s[4..12].copy_from_slice(&t0.to_be_bytes());
    s[12..20].copy_from_slice(&t_reap.to_be_bytes());
    s[20..52].copy_from_slice(&digest);
    s[52..60].copy_from_slice(&boot);
    let mut buf = [0u8; JOINREF_MAX_LEN];
    let n = encode_joinref(&SubjectRef::new(SchemeTag::LINUX_EXEC, &s).unwrap(), &mut buf).unwrap();
    buf[..n].to_vec()
}

/// The standard claim: pid 4242, window [2000, 3000], digest D, boot B.
pub fn c() -> Vec<u8> {
    claim(4242, 2000, 3000, d(), boot8(&BOOT))
}

// ---- profile S ---------------------------------------------------------

#[derive(Clone, Copy)]
pub enum S {
    Start { boot: [u8; 16], cov_from: u64, tol: u32 },
    Exec { pid: u32, lo: u64, hi: u64, digest: [u8; 32] },
    Reject(u64),
    Step(u64),
    Ended(u8),
}

/// An unsigned, chained stream of one instance.
pub struct SStream {
    pub instance: [u8; 16],
    pub mode: CoverageMode,
    prev: [u8; 32],
    index: u64,
    pub records: Vec<Vec<u8>>,
}

impl SStream {
    pub fn new(instance: [u8; 16]) -> SStream {
        SStream { instance, mode: CoverageMode::Mediated, prev: [0; 32], index: 0, records: Vec::new() }
    }

    pub fn push(&mut self, r: S) -> &mut SStream {
        let ctl = SubjectRef::new(SchemeTag::OBSERVER, &self.instance).unwrap();
        let (subject, class, data): (SubjectRef, u16, Vec<u8>) = match r {
            S::Start { boot, cov_from, tol } => {
                let mut d = boot.to_vec();
                d.extend_from_slice(&cov_from.to_be_bytes());
                d.extend_from_slice(&tol.to_be_bytes());
                (ctl, CLASS_INSTANCE_START, d)
            }
            S::Exec { pid, lo, hi, digest } => {
                let mut s = pid.to_be_bytes().to_vec();
                s.extend_from_slice(&lo.to_be_bytes());
                s.extend_from_slice(&hi.to_be_bytes());
                s.extend_from_slice(&digest);
                let mut d = vec![0u8];
                d.extend_from_slice(&1u32.to_be_bytes());
                d.extend_from_slice(b"/usr/bin/true");
                (SubjectRef::new(SchemeTag::LINUX_EXEC, &s).unwrap(), CLASS_COMMAND_EXECUTION, d)
            }
            S::Reject(n) => (ctl, CLASS_PARSE_REJECT, n.to_be_bytes().to_vec()),
            S::Step(n) => (ctl, CLASS_CLOCK_STEP, n.to_be_bytes().to_vec()),
            S::Ended(r) => (ctl, CLASS_STREAM_ENDED, vec![r]),
        };
        let parts = SightingParts {
            subject,
            observed: Observed { class, data: &data },
            coverage: Coverage { mode: self.mode, from: 0, over: CLASS_COMMAND_EXECUTION },
            self_prov: None,
            seq: Seq { instance: self.instance, index: self.index, prev: self.prev },
            source: SequenceSource::None,
        };
        let mut buf = [0u8; SIGHTING_MAX_LEN];
        let n = encode_sighting(&parts, &mut buf).unwrap();
        let rec = buf[..n].to_vec();
        self.prev = chain_digest(&rec);
        self.index += 1;
        self.records.push(rec);
        self
    }

    pub fn refs(&self) -> Vec<&[u8]> {
        self.records.iter().map(Vec::as_slice).collect()
    }
}

/// START(B, `cov_from` 1000, tolerance 10 ms).
pub fn s_start() -> S {
    S::Start { boot: BOOT, cov_from: 1000, tol: 10_000_000 }
}

// ---- profile K ---------------------------------------------------------

/// An EXEC record v2, with the conventions' defaults.
#[derive(Clone)]
pub struct Ex {
    pub pid: u32,
    pub exec_ns: u64,
    pub start_ns: u64,
    pub exe: [u8; 32],
    pub req: [u8; 32],
    pub uid: u32,
    pub ns: u8,
    pub interpreted: bool,
    pub flags: u8,
    pub path: Vec<u8>,
}

pub fn ex(pid: u32, exec_ns: u64, digest: [u8; 32]) -> Ex {
    Ex {
        pid,
        exec_ns,
        start_ns: exec_ns - 10,
        exe: digest,
        req: digest,
        uid: 1001,
        ns: 0,
        interpreted: false,
        flags: 0,
        path: b"/usr/bin/true".to_vec(),
    }
}

fn head(magic: [u8; 4], kind: u8, seq: u64, load: [u8; 16]) -> Vec<u8> {
    let mut b = magic.to_vec();
    b.push(kind);
    b.extend_from_slice(&seq.to_le_bytes());
    b.extend_from_slice(&load);
    b
}

pub fn exec_v2(seq: u64, load: [u8; 16], e: &Ex) -> Vec<u8> {
    let kind = 1 | e.flags | if e.interpreted { 0x20 } else { 0 };
    let mut b = head(*b"ASX2", kind, seq, load);
    for v in [e.pid, e.pid, 1, e.pid, e.uid, e.uid] {
        b.extend_from_slice(&v.to_le_bytes());
    }
    b.extend_from_slice(&e.start_ns.to_le_bytes());
    b.extend_from_slice(&e.exec_ns.to_le_bytes());
    b.extend_from_slice(&0x0080_0001u32.to_le_bytes());
    b.extend_from_slice(&(1000 + u64::from(e.pid)).to_le_bytes());
    b.extend_from_slice(&e.exe);
    b.extend_from_slice(&e.req);
    b.push(e.ns);
    b.extend_from_slice(&u16::try_from(e.path.len()).unwrap().to_le_bytes());
    b.extend_from_slice(&e.path);
    b
}

pub fn load_v2(seq: u64, load: [u8; 16], loaded_ns: u64) -> Vec<u8> {
    let mut b = head(*b"ASX2", 2, seq, load);
    b.extend_from_slice(&2u16.to_le_bytes());
    b.extend_from_slice(&loaded_ns.to_le_bytes());
    b
}

pub fn armed_v2(seq: u64, load: [u8; 16], armed_ns: u64) -> Vec<u8> {
    let mut b = head(*b"ASX2", 5, seq, load);
    b.extend_from_slice(&armed_ns.to_le_bytes());
    b
}

pub fn lost_v2(seq: u64, load: [u8; 16], count: u64, first: u64, last: u64) -> Vec<u8> {
    let mut b = head(*b"ASX2", 3, seq, load);
    for v in [count, first, last] {
        b.extend_from_slice(&v.to_le_bytes());
    }
    b
}

pub fn unload_v2(seq: u64, load: [u8; 16], close: u64, unloaded: u64) -> Vec<u8> {
    let mut b = head(*b"ASX2", 4, seq, load);
    b.extend_from_slice(&close.to_le_bytes());
    b.extend_from_slice(&unloaded.to_le_bytes());
    b
}

pub fn exec_v1(seq: u64, load: [u8; 16], pid: u32, start_ns: u64) -> Vec<u8> {
    let mut b = head(*b"ASX1", 1, seq, load);
    for v in [pid, pid, 1, pid, 1001, 1001] {
        b.extend_from_slice(&v.to_le_bytes());
    }
    b.extend_from_slice(&start_ns.to_le_bytes());
    b.extend_from_slice(&x()[..20]);
    b.extend_from_slice(&14u16.to_le_bytes());
    b.extend_from_slice(b"/usr/bin/false");
    b
}

pub fn load_v1(load: [u8; 16], loaded_ns: u64) -> Vec<u8> {
    let mut b = head(*b"ASX1", 2, 0, load);
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&loaded_ns.to_le_bytes());
    b
}

/// The template data of an ima-buf entry carrying `buf`.
pub fn template_data(buf: &[u8]) -> Vec<u8> {
    let mut dng = b"sha256:\0".to_vec();
    dng.extend_from_slice(&sha(buf));
    let mut t = Vec::new();
    for f in [&dng[..], b"exec\0", buf] {
        t.extend_from_slice(&u32::try_from(f.len()).unwrap().to_le_bytes());
        t.extend_from_slice(f);
    }
    t
}

/// One list entry: pcr, a listed digest (never used), template name and
/// template data.
pub fn entry(pcr: u32, template: &[u8], data: &[u8]) -> Vec<u8> {
    let mut b = pcr.to_le_bytes().to_vec();
    b.extend_from_slice(&[0x5a; 20]);
    b.extend_from_slice(&u32::try_from(template.len()).unwrap().to_le_bytes());
    b.extend_from_slice(template);
    b.extend_from_slice(&u32::try_from(data.len()).unwrap().to_le_bytes());
    b.extend_from_slice(data);
    b
}

/// A list of PCR-13 ima-buf entries, one per record.
pub fn list(records: &[Vec<u8>]) -> Vec<u8> {
    records.iter().flat_map(|r| entry(13, b"ima-buf", &template_data(r))).collect()
}

/// Load L: LOAD 1000, ARMED 1100, then `execs` at seq 2.., as records.
pub fn load_l(execs: &[Ex]) -> Vec<Vec<u8>> {
    let mut v = vec![load_v2(0, LOAD_L, 1000), armed_v2(1, LOAD_L, 1100)];
    for (n, e) in execs.iter().enumerate() {
        v.push(exec_v2(2 + n as u64, LOAD_L, e));
    }
    v
}

/// The pinned AK of these tests: the published RFC 6979 A.2.5 P-256 test
/// key's public point (not a secret; anchors nothing), as DER SPKI.
pub fn test_ak() -> Vec<u8> {
    let mut b = anchorstamp_verify::k::AK_SPKI_PREFIX.to_vec();
    b.push(0x04);
    b.extend_from_slice(&hex("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"));
    b.extend_from_slice(&hex("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"));
    b
}

pub fn hex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

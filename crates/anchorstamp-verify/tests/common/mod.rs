//! Builds signed, chained DEMO streams for tests.

#![allow(dead_code)]

use anchorstamp_core::{
    CLASS_COMMAND_EXECUTION, CLASS_INSTANCE_START, CLASS_PARSE_REJECT, CLASS_STREAM_ENDED,
    Coverage, CoverageMode, JOINREF_MAX_LEN, Observed, SIGHTING_MAX_LEN, SchemeTag, Seq,
    SequenceSource, SightingParts, SubjectRef, encode_joinref, encode_sighting,
};
use anchorstamp_verify::schemes::DemoSubject;
use anchorstamp_verify::{chain_digest, key_id};
use ed25519_dalek::{Signer, SigningKey};

/// A published test secret (RFC 8032 section 7.1, TEST 2). Anchors nothing.
pub const SECRET: [u8; 32] = [
    0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
    0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
];
/// A second key, for substituted-anchor tests (RFC 8032 section 7.1, TEST 3).
pub const OTHER_SECRET: [u8; 32] = [
    0xc5, 0xaa, 0x8d, 0xf4, 0x3f, 0x9f, 0x83, 0x7b, 0xed, 0xb7, 0x44, 0x2f, 0x31, 0xdc, 0xb7, 0xb1,
    0x66, 0xd3, 0x85, 0x35, 0x07, 0x6f, 0x09, 0x4b, 0x85, 0xce, 0x3a, 0x2e, 0x0b, 0x44, 0x58, 0xf7,
];

pub const INSTANCE: [u8; 16] = [0x5e; 16];

pub fn digest(tag: u8) -> [u8; 20] {
    [tag; 20]
}

pub enum Rec {
    Start(u64),
    Exec { pid: u32, time_ms: u64, exe: u8 },
    Reject(u64),
    Ended(u8),
}

pub struct Builder {
    key: SigningKey,
    instance: [u8; 16],
    prev: [u8; 32],
    index: u64,
    pub records: Vec<Vec<u8>>,
}

impl Builder {
    pub fn new(secret: &[u8; 32], instance: [u8; 16]) -> Builder {
        Builder {
            key: SigningKey::from_bytes(secret),
            instance,
            prev: [0; 32],
            index: 0,
            records: Vec::new(),
        }
    }

    pub fn anchor(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    pub fn push(&mut self, r: Rec) -> &mut Builder {
        let (subject, class, data): (SubjectRef, u16, Vec<u8>) = match r {
            Rec::Start(ms) => (
                SubjectRef::new(SchemeTag::OBSERVER, &self.instance).unwrap(),
                CLASS_INSTANCE_START,
                ms.to_be_bytes().to_vec(),
            ),
            Rec::Exec { pid, time_ms, exe } => {
                let s = DemoSubject { pid, time_ms, exe_digest: digest(exe) }.encode();
                let mut d = vec![0u8];
                d.extend_from_slice(&1u32.to_be_bytes());
                d.extend_from_slice(b"/usr/bin/true");
                (SubjectRef::new(SchemeTag::DEMO, &s).unwrap(), CLASS_COMMAND_EXECUTION, d)
            }
            Rec::Reject(n) => (
                SubjectRef::new(SchemeTag::OBSERVER, &self.instance).unwrap(),
                CLASS_PARSE_REJECT,
                n.to_be_bytes().to_vec(),
            ),
            Rec::Ended(reason) => (
                SubjectRef::new(SchemeTag::OBSERVER, &self.instance).unwrap(),
                CLASS_STREAM_ENDED,
                vec![reason],
            ),
        };
        let parts = SightingParts {
            subject,
            observed: Observed { class, data: &data },
            coverage: Coverage {
                mode: CoverageMode::Mediated,
                from: 0,
                over: CLASS_COMMAND_EXECUTION,
            },
            self_prov: None,
            seq: Seq { instance: self.instance, index: self.index, prev: self.prev },
            source: SequenceSource::None,
            key_id: key_id(&self.anchor()),
            signature: [0; 64],
        };
        let mut buf = [0u8; SIGHTING_MAX_LEN];
        let n = encode_sighting(&parts, &mut buf).unwrap();
        let sig = self.key.sign(&buf[..n - 64]).to_bytes();
        buf[n - 64..n].copy_from_slice(&sig);
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

pub fn claim(pid: u32, time_ms: u64, exe: u8) -> Vec<u8> {
    let s = DemoSubject { pid, time_ms, exe_digest: digest(exe) }.encode();
    let mut buf = [0u8; JOINREF_MAX_LEN];
    let n = encode_joinref(&SubjectRef::new(SchemeTag::DEMO, &s).unwrap(), &mut buf).unwrap();
    buf[..n].to_vec()
}

/// start 1000; execs at 1100 (pid 10, exe A), 1200 (pid 11, exe B); a
/// control record without a time (a stream-ended record, here mid-stream
/// only to give a gap an untimed edge); 1300 (pid 12, exe A).
pub fn standard() -> Builder {
    let mut b = Builder::new(&SECRET, INSTANCE);
    b.push(Rec::Start(1000))
        .push(Rec::Exec { pid: 10, time_ms: 1100, exe: 0xA })
        .push(Rec::Exec { pid: 11, time_ms: 1200, exe: 0xB })
        .push(Rec::Ended(3))
        .push(Rec::Exec { pid: 12, time_ms: 1300, exe: 0xA });
    b
}

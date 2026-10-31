//! Builds signed, chained sightings for one observer instance.

use anchorstamp_core::{
    CLASS_COMMAND_EXECUTION, CLASS_INSTANCE_START, CLASS_PARSE_REJECT, CLASS_STREAM_ENDED,
    Coverage, CoverageMode, Observed, SIGHTING_MAX_LEN, SIGNATURE_LEN, SchemeTag, Seq,
    SequenceSource, SightingParts, SubjectRef, encode_sighting,
};
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest, Sha256};

use crate::parse::{Exec, exec_data};

/// SHA-256 over the full path, first 20 bytes.
pub fn exe_digest(path: &[u8]) -> [u8; 20] {
    let d: [u8; 32] = Sha256::digest(path).into();
    d[..20].try_into().expect("20 of 32")
}

fn chain_digest(prior: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"anchorstamp/chain");
    h.update([0u8]);
    h.update(prior);
    h.finalize().into()
}

/// The chain state and signing key of one instance. The key is borrowed;
/// its storage belongs to the caller.
pub struct Chain<'k> {
    key: &'k SigningKey,
    key_id: [u8; 32],
    instance: [u8; 16],
    index: u64,
    prev: [u8; 32],
}

impl<'k> Chain<'k> {
    pub fn new(key: &'k SigningKey, instance: [u8; 16]) -> Chain<'k> {
        let key_id = Sha256::digest(key.verifying_key().as_bytes()).into();
        Chain { key, key_id, instance, index: 0, prev: [0; 32] }
    }

    /// Index the next record will carry.
    pub fn next_index(&self) -> u64 {
        self.index
    }

    pub fn instance_start(&mut self, coverage_from_ms: u64) -> Vec<u8> {
        self.control(CLASS_INSTANCE_START, &coverage_from_ms.to_be_bytes())
    }

    pub fn parse_reject(&mut self, cumulative: u64) -> Vec<u8> {
        self.control(CLASS_PARSE_REJECT, &cumulative.to_be_bytes())
    }

    pub fn stream_ended(&mut self, reason: u8) -> Vec<u8> {
        self.control(CLASS_STREAM_ENDED, &[reason])
    }

    pub fn exec(&mut self, e: &Exec) -> Vec<u8> {
        let mut s = [0u8; 32];
        s[0..4].copy_from_slice(&e.pid.to_be_bytes());
        s[4..12].copy_from_slice(&e.time_ms.to_be_bytes());
        s[12..32].copy_from_slice(&exe_digest(&e.exe));
        let subject = SubjectRef::new(SchemeTag::DEMO, &s).expect("32 bytes");
        self.record(subject, CLASS_COMMAND_EXECUTION, &exec_data(e))
    }

    fn control(&mut self, class: u16, data: &[u8]) -> Vec<u8> {
        let subject = SubjectRef::new(SchemeTag::OBSERVER, &self.instance).expect("16 bytes");
        self.record(subject, class, data)
    }

    /// One record, signed and chained.
    fn record(&mut self, subject: SubjectRef, class: u16, data: &[u8]) -> Vec<u8> {
        let parts = SightingParts {
            subject,
            observed: Observed { class, data },
            coverage: Coverage {
                mode: CoverageMode::Mediated,
                from: 0,
                over: CLASS_COMMAND_EXECUTION,
            },
            self_prov: None,
            seq: Seq { instance: self.instance, index: self.index, prev: self.prev },
            source: SequenceSource::None,
            key_id: self.key_id,
            signature: [0; SIGNATURE_LEN],
        };
        let mut buf = [0u8; SIGHTING_MAX_LEN];
        let n = encode_sighting(&parts, &mut buf).expect("observer data within bounds");
        let sig = self.key.sign(&buf[..n - SIGNATURE_LEN]).to_bytes();
        buf[n - SIGNATURE_LEN..n].copy_from_slice(&sig);
        let rec = buf[..n].to_vec();
        self.prev = chain_digest(&rec);
        self.index += 1;
        rec
    }
}

/// A record as it is stored: u32 big-endian length, then the record.
pub fn frame(rec: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + rec.len());
    out.extend_from_slice(&(rec.len() as u32).to_be_bytes());
    out.extend_from_slice(rec);
    out
}

// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright © 2026 Lei Zhou

//! Builds the chained, unsigned sightings of one source instance (profile
//! S): the layout-1 sighting with no key id and no signature. The chain is
//! not tamper evidence — anyone who can write the stream can recompute it
//! — but it still shows a partial edit or a corrupted record as a break.

use anchorstamp_core::{
    CLASS_CLOCK_STEP, CLASS_COMMAND_EXECUTION, CLASS_INSTANCE_START, CLASS_PARSE_REJECT,
    CLASS_STREAM_ENDED, Coverage, CoverageMode, Observed, SIGHTING_MAX_LEN, SchemeTag, Seq,
    SequenceSource, SightingParts, SubjectRef, encode_sighting,
};
use sha2::{Digest, Sha256};

use crate::parse::{Exec, exec_data};

/// The instance's tolerance on the audit clock: at least its resolution
/// (the coarse realtime clock ticks every millisecond at HZ=1000).
pub const TOLERANCE_NS: u32 = 5_000_000;

/// SHA-256 over the full decoded `exe=` value.
pub fn exe_digest(path: &[u8]) -> [u8; 32] {
    Sha256::digest(path).into()
}

fn chain_digest(prior: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"anchorstamp/chain");
    h.update([0u8]);
    h.update(prior);
    h.finalize().into()
}

/// The lower bound of an exec's time on the boot clock: its audit
/// timestamp, converted with the realtime-minus-boottime offset sampled at
/// the read, minus the tolerance; zero rather than negative.
pub fn lo_ns(audit_ms: u64, offset_ns: i128, tolerance_ns: u32) -> u64 {
    let lo = i128::from(audit_ms) * 1_000_000 - offset_ns - i128::from(tolerance_ns);
    u64::try_from(lo.max(0)).unwrap_or(u64::MAX)
}

/// Watches the realtime-minus-boottime offset between samples.
#[derive(Debug)]
pub struct ClockWatch {
    last: i128,
    tolerance_ns: u32,
}

impl ClockWatch {
    pub fn new(first_offset_ns: i128, tolerance_ns: u32) -> ClockWatch {
        ClockWatch { last: first_offset_ns, tolerance_ns }
    }

    /// Record a new sample. `Some(|change|)` when it moved by more than
    /// the tolerance since the last sample: a CLOCK_STEP is owed before
    /// the records of this read.
    pub fn sample(&mut self, offset_ns: i128) -> Option<u64> {
        let change = (offset_ns - self.last).unsigned_abs();
        self.last = offset_ns;
        (change > u128::from(self.tolerance_ns)).then(|| u64::try_from(change).unwrap_or(u64::MAX))
    }
}

/// The chain state of one instance.
pub struct Chain {
    instance: [u8; 16],
    index: u64,
    prev: [u8; 32],
}

impl Chain {
    pub fn new(instance: [u8; 16]) -> Chain {
        Chain { instance, index: 0, prev: [0; 32] }
    }

    /// Index the next record will carry.
    pub fn next_index(&self) -> u64 {
        self.index
    }

    /// INSTANCE_START: boot id [16] · `cov_from` u64 · tolerance u32.
    pub fn instance_start(&mut self, boot_id: [u8; 16], cov_from: u64, tolerance_ns: u32) -> Vec<u8> {
        let mut d = [0u8; 28];
        d[0..16].copy_from_slice(&boot_id);
        d[16..24].copy_from_slice(&cov_from.to_be_bytes());
        d[24..28].copy_from_slice(&tolerance_ns.to_be_bytes());
        self.control(CLASS_INSTANCE_START, &d)
    }

    pub fn parse_reject(&mut self, cumulative: u64) -> Vec<u8> {
        self.control(CLASS_PARSE_REJECT, &cumulative.to_be_bytes())
    }

    pub fn stream_ended(&mut self, reason: u8) -> Vec<u8> {
        self.control(CLASS_STREAM_ENDED, &[reason])
    }

    /// CLOCK_STEP: the size of the offset's move, u64 ns.
    pub fn clock_step(&mut self, change_ns: u64) -> Vec<u8> {
        self.control(CLASS_CLOCK_STEP, &change_ns.to_be_bytes())
    }

    /// An exec sighting. Subject, LINUX_EXEC observer form, 52 bytes:
    /// pid u32 · lo u64 · hi u64 · `exe_digest` [32].
    pub fn exec(&mut self, e: &Exec, lo: u64, hi: u64) -> Vec<u8> {
        let mut s = [0u8; 52];
        s[0..4].copy_from_slice(&e.pid.to_be_bytes());
        s[4..12].copy_from_slice(&lo.to_be_bytes());
        s[12..20].copy_from_slice(&hi.to_be_bytes());
        s[20..52].copy_from_slice(&exe_digest(&e.exe));
        let subject = SubjectRef::new(SchemeTag::LINUX_EXEC, &s).expect("52 bytes");
        self.record(subject, CLASS_COMMAND_EXECUTION, &exec_data(e))
    }

    fn control(&mut self, class: u16, data: &[u8]) -> Vec<u8> {
        let subject = SubjectRef::new(SchemeTag::OBSERVER, &self.instance).expect("16 bytes");
        self.record(subject, class, data)
    }

    /// One record, chained.
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
        };
        let mut buf = [0u8; SIGHTING_MAX_LEN];
        let n = encode_sighting(&parts, &mut buf).expect("observer data within bounds");
        let rec = buf[..n].to_vec();
        self.prev = chain_digest(&rec);
        self.index += 1;
        rec
    }
}

/// A record as it is stored: u32 big-endian length, then the record.
pub fn frame(rec: &[u8]) -> Vec<u8> {
    let len = u32::try_from(rec.len()).expect("a sighting is far below 4 GiB");
    let mut out = Vec::with_capacity(4 + rec.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(rec);
    out
}

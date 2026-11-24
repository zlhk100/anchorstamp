// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright © 2026 Lei Zhou

//! Profile S: unsigned software sightings, layout 1.
//!
//! A record is valid iff it parses. Instances, gaps, breaks and forks are
//! counted as for any sighting stream. An exec record is a `LINUX_EXEC`
//! subject in the observer form, 52 bytes: pid u32 · lo u64 · hi u64 ·
//! `exe_digest` [32]; its upper bound is narrowed to
//! `min(hi, lo + 2·tolerance)`. Its records are never decisive: profile S
//! agrees or says nothing.

use anchorstamp_core::{
    CLASS_CLOCK_STEP, CLASS_COMMAND_EXECUTION, CLASS_INSTANCE_START, CLASS_PARSE_REJECT,
    CLASS_STREAM_ENDED, CoverageMode, SchemeTag, SightingView, Strength,
};

use crate::stream::{SInstance, Stream};
use crate::{Evidence, ExecRecord, Instance, Profile, Span};

/// Length of the `LINUX_EXEC` observer-form subject.
pub const SUBJECT_LEN: usize = 52;

/// The parts of an S exec subject.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Subject {
    pub pid: u32,
    pub lo: u64,
    pub hi: u64,
    pub exe_digest: [u8; 32],
}

impl Subject {
    /// `None` unless `v` is a `LINUX_EXEC` execution sighting with a
    /// 52-byte subject.
    #[must_use]
    pub fn of(v: &SightingView) -> Option<Subject> {
        let p = &v.parts;
        let b = p.subject.bytes();
        if p.subject.scheme() != SchemeTag::LINUX_EXEC
            || p.observed.class != CLASS_COMMAND_EXECUTION
            || b.len() != SUBJECT_LEN
        {
            return None;
        }
        Some(Subject {
            pid: u32::from_be_bytes(b[0..4].try_into().ok()?),
            lo: u64::from_be_bytes(b[4..12].try_into().ok()?),
            hi: u64::from_be_bytes(b[12..20].try_into().ok()?),
            exe_digest: b[20..52].try_into().ok()?,
        })
    }
}

/// `INSTANCE_START` data: boot id \[16\] · `cov_from` u64 · tolerance u32.
fn instance_start(v: &SightingView) -> Option<([u8; 16], u64, u32)> {
    let d = v.parts.observed.data;
    if v.parts.observed.class != CLASS_INSTANCE_START || d.len() != 28 {
        return None;
    }
    Some((
        d[0..16].try_into().ok()?,
        u64::from_be_bytes(d[16..24].try_into().ok()?),
        u32::from_be_bytes(d[24..28].try_into().ok()?),
    ))
}

/// Observed data of an exec sighting: flags u8 · ppid u32 · path.
fn exec_data(d: &[u8]) -> (Option<u32>, Vec<u8>, bool) {
    match d {
        [flags, ppid @ .., ] if ppid.len() >= 4 => (
            Some(u32::from_be_bytes(ppid[..4].try_into().expect("4 bytes"))),
            ppid[4..].to_vec(),
            flags & 1 == 1,
        ),
        _ => (None, Vec::new(), false),
    }
}

/// A time a record carries for bounding a gap: an exec's `lo` (left edge)
/// or `hi` (right edge), or an instance start's `cov_from`.
fn edge_time(inst: &SInstance, index: u64, left: bool) -> Option<u64> {
    let times = inst.at(index).iter().filter_map(|v| {
        if let Some(s) = Subject::of(v) {
            return Some(if left { s.lo } else { s.hi });
        }
        if inst.is_control(v) {
            return instance_start(v).map(|(_, from, _)| from);
        }
        None
    });
    if left { times.min() } else { times.max() }
}

/// Build profile S evidence from the framed records of one stream.
#[must_use]
pub fn build(frames: &[&[u8]]) -> Evidence {
    let st = Stream::validate(frames);
    let mut ev = Evidence::empty(Profile::S);
    ev.valid = st.valid();
    ev.excluded = st.excluded;
    ev.gaps = st.gaps();
    ev.breaks = st.breaks();
    ev.forks = st.forks();
    for si in st.instances.values() {
        ev.instances.push(instance(si));
    }
    ev
}

fn instance(si: &SInstance) -> Instance {
    let mut inst = Instance::new(si.id);
    inst.valid = si.records().count() as u64;
    inst.mediated = si.records().all(|(_, v)| v.parts.coverage.mode == CoverageMode::Mediated);

    // instance start: with several copies, the boot only if they agree,
    // the latest coverage start and the widest tolerance
    let starts: Vec<([u8; 16], u64, u32)> = si
        .records()
        .filter(|(_, v)| si.is_control(v))
        .filter_map(|(_, v)| instance_start(v))
        .collect();
    if let Some(&(boot, _, _)) = starts.first() {
        inst.boot = starts.iter().all(|s| s.0 == boot).then_some(boot);
        inst.cov_from = starts.iter().map(|s| s.1).max();
        inst.lo_c = inst.cov_from;
        inst.tolerance_ns = starts.iter().map(|s| s.2).max();
    }

    for (index, v) in si.records() {
        if si.is_control(v) {
            let p = &v.parts;
            match p.observed.class {
                CLASS_PARSE_REJECT => {
                    inst.holes += 1;
                    let n = p.observed.data.try_into().map_or(0, u64::from_be_bytes);
                    inst.rejects = inst.rejects.max(n).max(1);
                }
                CLASS_CLOCK_STEP => {
                    inst.holes += 1;
                    inst.clock_steps += 1;
                }
                CLASS_STREAM_ENDED => inst.ended = p.observed.data.first().copied(),
                _ => {}
            }
            continue;
        }
        let Some(s) = Subject::of(v) else { continue };
        let hi = match inst.tolerance_ns {
            Some(tol) => s.hi.min(s.lo.saturating_add(2 * u64::from(tol))),
            None => s.hi,
        };
        let (ppid, path, truncated) = exec_data(v.parts.observed.data);
        inst.records.push(ExecRecord {
            pid: s.pid,
            lo: s.lo,
            hi,
            fork: None,
            exe_digest: s.exe_digest,
            req_digest: None,
            interpreted: false,
            stable: true,
            decisive: false,
            uid: None,
            euid: None,
            ppid,
            path,
            path_truncated: truncated,
            path_unresolved: false,
            ns: None,
            self_prov: v.parts.self_prov.is_some(),
            strength: Strength::SOFTWARE,
            position: index,
            entry: None,
            anchor: None,
            v1: false,
        });
    }

    // a gap spans the lo of the record before it to the hi of the record
    // after it; a side with no timed record is open
    for g in si.gaps() {
        let from = si.indices_below(g.from).find_map(|i| edge_time(si, i, true));
        let to = si.indices_above(g.to).find_map(|i| edge_time(si, i, false));
        inst.gaps.push(Span { from, to });
    }
    inst
}

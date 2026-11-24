// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright © 2026 Lei Zhou

//! The TEST scheme, 0xFFFF, for conformance only: the index-axis join
//! and account rules, as written, over unsigned layout-1 sighting encodings. A
//! record is valid iff it parses; there is no signature to check. A
//! caller must not use this scheme outside a declared test run.
//!
//! Subject bytes: instance [16] · position u64 · id [1..8]. Derive is the
//! identity; key is (instance, id); match is byte equality; position is
//! (instance, position), on the index axis.

use std::collections::BTreeSet;

use anchorstamp_core::{
    CLASS_PARSE_REJECT, CoverageMode, SchemeTag, SightingView, Strength, SubjectRef,
    decode_joinref,
};

use crate::stream::{SInstance, Stream};
use crate::{Anchor, Cap, DeclaredPath, Detail, Health, Path, Unclaimed};

/// The index-axis outcome kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    Agrees { strength: Strength, scheme: SchemeTag, caps: Vec<Cap> },
    Disagrees { detail: Detail },
    NotCovered { coverage_from: u64 },
    NothingToCompare,
}

/// The index-axis outcome. The anchor is always `None`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub kind: Kind,
    pub health: Health,
    pub path: Path,
    pub anchor: Anchor,
}

/// (instance, position, id) of a TEST subject.
fn parts(s: &SubjectRef) -> Option<([u8; 16], u64, &[u8])> {
    let b = s.bytes();
    if s.scheme() != SchemeTag::TEST || !(25..=32).contains(&b.len()) {
        return None;
    }
    Some((b[..16].try_into().ok()?, u64::from_be_bytes(b[16..24].try_into().ok()?), &b[24..]))
}

fn key(s: &SubjectRef) -> Option<([u8; 16], &[u8])> {
    parts(s).map(|(i, _, id)| (i, id))
}

fn matches(claim: &SubjectRef, seen: &SubjectRef) -> bool {
    parts(claim).is_some() && seen.scheme() == SchemeTag::TEST && claim.bytes() == seen.bytes()
}

/// An execution under this scheme: a TEST subject that is not one of the
/// instance's control records.
fn is_execution(inst: &SInstance, v: &SightingView) -> bool {
    !inst.is_control(v) && v.parts.subject.scheme() == SchemeTag::TEST
}

fn holds_parse_reject(inst: &SInstance) -> bool {
    inst.records().any(|(_, v)| inst.is_control(v) && v.parts.observed.class == CLASS_PARSE_REJECT)
}

/// The per-claim outcome. `claim` is an encoded join reference, or `None`
/// for a claim at vantage Local.
#[must_use]
pub fn join(claim: Option<&[u8]>, stream: &[&[u8]], path: DeclaredPath) -> Outcome {
    let st = Stream::validate(stream);
    let mut health = Health {
        gaps: st.gaps(),
        breaks: st.breaks(),
        forks: st.forks(),
        excluded: st.excluded,
        touches_claim: false,
        evidence_broken: false,
    };
    let path = Path::of(path, st.valid() > 0);
    let kind = judge(claim, &st, &mut health.touches_claim);
    Outcome { kind, health, path, anchor: Anchor::None }
}

fn judge(claim: Option<&[u8]>, st: &Stream, touches: &mut bool) -> Kind {
    let Some(s) = claim.and_then(|c| decode_joinref(c).ok()) else {
        return Kind::NothingToCompare;
    };
    // 1
    let Some((instance, index, _)) = parts(&s) else { return Kind::NothingToCompare };
    let Some(inst) = st.instances.get(&instance) else { return Kind::NothingToCompare };
    *touches = holds_parse_reject(inst) || inst.gaps().iter().any(|g| g.from <= index && index <= g.to);
    // 2
    if index < inst.coverage_from {
        return Kind::NotCovered { coverage_from: inst.coverage_from };
    }
    // 3, 4
    let k = key(&s);
    let candidates: Vec<&SightingView> = inst
        .records()
        .map(|(_, r)| r)
        .filter(|r| is_execution(inst, r) && key(&r.parts.subject) == k)
        .collect();
    let matching: Vec<&&SightingView> =
        candidates.iter().filter(|r| matches(&s, &r.parts.subject)).collect();
    if !matching.is_empty() {
        let self_prov = if matching.iter().any(|r| r.parts.self_prov.is_some()) {
            Cap::SelfProvUnappraised
        } else {
            Cap::SelfProvAbsent
        };
        return Kind::Agrees {
            strength: Strength::SOFTWARE,
            scheme: SchemeTag::TEST,
            caps: vec![self_prov, Cap::SequenceUnappraised, Cap::AnchorOperatorAsserted],
        };
    }
    if !candidates.is_empty() {
        return Kind::Disagrees { detail: Detail::SubjectMismatch };
    }
    // 5
    let mediated = inst.records().all(|(_, r)| r.parts.coverage.mode == CoverageMode::Mediated);
    if mediated && inst.highest() >= index && !*touches {
        return Kind::Disagrees { detail: Detail::Unobserved };
    }
    // 6
    Kind::NothingToCompare
}

/// Every valid execution sighting, by (instance, index), that no claim's
/// derived subject matches. Control records are never listed.
#[must_use]
pub fn account(claims: &[&[u8]], stream: &[&[u8]]) -> Vec<Unclaimed> {
    let st = Stream::validate(stream);
    let derived: Vec<SubjectRef> = claims
        .iter()
        .filter_map(|c| decode_joinref(c).ok())
        .filter(|s| parts(s).is_some())
        .collect();
    let mut out = BTreeSet::new();
    for inst in st.instances.values() {
        for (index, r) in inst.records() {
            if !is_execution(inst, r) {
                continue;
            }
            let seen = &r.parts.subject;
            let k = key(seen);
            if !derived.iter().any(|s| key(s) == k && matches(s, seen)) {
                out.insert(Unclaimed { instance: inst.id, index });
            }
        }
    }
    out.into_iter().collect()
}

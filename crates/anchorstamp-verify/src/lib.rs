//! anchorstamp-verify — the reader.
//!
//! Validates candidate sightings against operator-supplied anchors, then
//! answers per claim (`join`) and per claim set (`account`). Pure: no
//! network, no clock, no randomness. Outcomes do not depend on stream
//! order. Signatures are checked with `VerifyingKey::verify_strict` only.

use std::collections::{BTreeMap, BTreeSet};

use anchorstamp_core::{
    CoverageMode, SIGNATURE_LEN, SchemeTag, SightingView, Strength, SubjectRef, decode_joinref,
    decode_sighting,
};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

pub mod schemes;

/// SHA-256 of a public key: the key id a sighting carries.
pub fn key_id(public: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(public).into()
}

/// The `prev` value of the sighting that follows `prior` (complete
/// encoding, signature included).
pub fn chain_digest(prior: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"anchorstamp/chain");
    h.update([0u8]);
    h.update(prior);
    h.finalize().into()
}

/// Lookup key: which sightings are candidates for a subject.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Key(pub Vec<u8>);

/// A position on an observer's sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Position {
    pub instance: [u8; 16],
    pub index: u64,
}

/// An inclusive range of indices with no valid sighting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gap {
    pub from: u64,
    pub to: u64,
}

/// The valid sightings of one observer instance, by index. Several
/// distinct records at one index are a fork; identical copies count once.
#[derive(Debug)]
pub struct Instance<'a> {
    id: [u8; 16],
    coverage_from: u64,
    records: BTreeMap<u64, Vec<SightingView<'a>>>,
}

impl<'a> Instance<'a> {
    pub fn id(&self) -> [u8; 16] {
        self.id
    }

    /// `coverage.from`. Constant within a conforming instance; the lowest
    /// declared value otherwise.
    pub fn coverage_from(&self) -> u64 {
        self.coverage_from
    }

    pub fn highest(&self) -> u64 {
        self.records.keys().next_back().copied().unwrap_or(self.coverage_from)
    }

    /// Records at `index`, in byte order.
    pub fn at(&self, index: u64) -> &[SightingView<'a>] {
        self.records.get(&index).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Every record, in (index, bytes) order.
    pub fn records(&self) -> impl Iterator<Item = (u64, &SightingView<'a>)> {
        self.records.iter().flat_map(|(i, v)| v.iter().map(move |r| (*i, r)))
    }

    /// Indices below `index` that hold a record, highest first.
    pub fn indices_below(&self, index: u64) -> impl Iterator<Item = u64> + '_ {
        self.records.range(..index).rev().map(|(i, _)| *i)
    }

    /// Indices above `index` that hold a record, lowest first.
    pub fn indices_above(&self, index: u64) -> impl Iterator<Item = u64> + '_ {
        self.records.range(index.saturating_add(1)..).map(|(i, _)| *i)
    }

    /// Missing index ranges between `coverage.from` and the highest index.
    pub fn gaps(&self) -> Vec<Gap> {
        let mut out = Vec::new();
        let mut expect = self.coverage_from;
        for &i in self.records.keys() {
            if i > expect {
                out.push(Gap { from: expect, to: i - 1 });
            }
            expect = expect.max(i.saturating_add(1));
        }
        out
    }

    /// Records at i+1 whose `prev` is not the chain digest of any record at
    /// i. Not counted where i is missing: that is a gap.
    pub fn breaks(&self) -> u64 {
        let mut n = 0;
        for (&i, recs) in &self.records {
            if i <= self.coverage_from {
                continue;
            }
            let before = self.at(i - 1);
            if before.is_empty() {
                continue;
            }
            for r in recs {
                if !before.iter().any(|q| chain_digest(q.raw()) == r.parts.seq.prev) {
                    n += 1;
                }
            }
        }
        n
    }

    /// Distinct records beyond the first at each index.
    pub fn forks(&self) -> u64 {
        self.records.values().map(|v| v.len() as u64 - 1).sum()
    }
}

/// The valid part of a stream, in canonical order.
#[derive(Debug)]
pub struct Stream<'a> {
    instances: BTreeMap<[u8; 16], Instance<'a>>,
    excluded: u64,
}

impl<'a> Stream<'a> {
    /// Keep every entry that parses, carries the key id of an anchor and
    /// verifies strictly under it. Count the rest.
    pub fn validate(entries: &[&'a [u8]], anchors: &[[u8; 32]]) -> Stream<'a> {
        let keys: Vec<([u8; 32], VerifyingKey)> = anchors
            .iter()
            .filter_map(|a| VerifyingKey::from_bytes(a).ok().map(|k| (key_id(a), k)))
            .collect();
        let mut instances: BTreeMap<[u8; 16], Instance<'a>> = BTreeMap::new();
        let mut excluded = 0;
        for &bytes in entries {
            let Some(view) = valid(bytes, &keys) else {
                excluded += 1;
                continue;
            };
            let seq = view.parts.seq;
            let inst = instances.entry(seq.instance).or_insert_with(|| Instance {
                id: seq.instance,
                coverage_from: view.parts.coverage.from,
                records: BTreeMap::new(),
            });
            inst.coverage_from = inst.coverage_from.min(view.parts.coverage.from);
            let at = inst.records.entry(seq.index).or_default();
            if let Err(pos) = at.binary_search_by(|r| r.raw().cmp(view.raw())) {
                at.insert(pos, view);
            }
        }
        Stream { instances, excluded }
    }

    pub fn is_empty(&self) -> bool {
        self.instances.is_empty()
    }

    pub fn excluded(&self) -> u64 {
        self.excluded
    }

    pub fn instance(&self, id: &[u8; 16]) -> Option<&Instance<'a>> {
        self.instances.get(id)
    }

    pub fn instances(&self) -> impl Iterator<Item = &Instance<'a>> {
        self.instances.values()
    }

    pub fn instance_count(&self) -> usize {
        self.instances.len()
    }

    /// Health with `touches_claim` false.
    pub fn health(&self) -> Health {
        let mut h = Health { excluded: self.excluded, ..Health::default() };
        for inst in self.instances.values() {
            h.gaps += inst.gaps().len() as u64;
            h.breaks += inst.breaks();
            h.forks += inst.forks();
        }
        h
    }
}

fn valid<'a>(bytes: &'a [u8], keys: &[([u8; 32], VerifyingKey)]) -> Option<SightingView<'a>> {
    let view = decode_sighting(bytes).ok()?;
    let (_, key) = keys.iter().find(|(id, _)| *id == view.parts.key_id)?;
    let sig: &[u8; SIGNATURE_LEN] = &view.parts.signature;
    key.verify_strict(view.signed(), &Signature::from_bytes(sig)).ok()?;
    Some(view)
}

/// A subject scheme. `derive`, `key`, `matches` and `position` are the
/// scheme's four functions. The remaining methods say how rules 2 and 5
/// and gap-touching read a position; their defaults are the index rules,
/// which a scheme whose position is not an index replaces.
pub trait Scheme {
    fn tag(&self) -> SchemeTag;
    fn derive(&self, s: &SubjectRef) -> SubjectRef;
    fn key(&self, s: &SubjectRef) -> Key;
    fn matches(&self, claim: &SubjectRef, seen: &SubjectRef) -> bool;
    fn position(&self, s: &SubjectRef, stream: &Stream) -> Option<Position>;

    /// Whether a valid sighting records an execution this scheme joins.
    fn is_execution(&self, v: &SightingView) -> bool {
        v.parts.subject.scheme() == self.tag()
    }

    /// Where the instance's coverage starts, in position units. `None`
    /// when the stream does not say.
    fn coverage_start(&self, inst: &Instance) -> Option<u64> {
        Some(inst.coverage_from())
    }

    /// Rule 2: the position precedes the instance's coverage.
    fn not_covered(&self, p: &Position, inst: &Instance) -> bool {
        self.coverage_start(inst).is_some_and(|from| p.index < from)
    }

    /// Rule 5: the stream has reached the position.
    fn reached(&self, p: &Position, inst: &Instance) -> bool {
        inst.highest() >= p.index
    }

    /// Whether `gap` covers the position.
    fn touches(&self, p: &Position, gap: &Gap, _inst: &Instance) -> bool {
        gap.from <= p.index && p.index <= gap.to
    }

    /// Records the observer saw and could not parse, each a hole of
    /// unknown position that touches every claim. None by default.
    fn unparsed(&self, _inst: &Instance) -> u64 {
        0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Detail {
    SubjectMismatch,
    Unobserved,
}

/// Why an agreement sits at its strength.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cap {
    SelfProvAbsent,
    SelfProvUnappraised,
    SequenceUnappraised,
    AnchorOperatorAsserted,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    Agrees { strength: Strength, scheme: SchemeTag, caps: Vec<Cap> },
    Disagrees { detail: Detail },
    NotCovered { coverage_from: u64 },
    NothingToCompare,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Health {
    pub gaps: u64,
    pub breaks: u64,
    pub forks: u64,
    pub excluded: u64,
    pub touches_claim: bool,
}

/// Delivery path as the deployment declares it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeclaredPath {
    Direct,
    Relayed { hops: u16 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Path {
    Direct,
    Relayed { hops: u16 },
    NothingArrived,
}

/// Time anchoring. Always `None` in layout 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Anchor {
    None,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub kind: Kind,
    pub health: Health,
    pub path: Path,
    pub anchor: Anchor,
}

/// The per-claim outcome. `claim` is an encoded join reference, or `None`
/// for a claim at vantage Local.
pub fn join(
    claim: Option<&[u8]>,
    stream: &[&[u8]],
    anchors: &[[u8; 32]],
    path: DeclaredPath,
    scheme: &dyn Scheme,
) -> Outcome {
    join_stream(claim, &Stream::validate(stream, anchors), path, scheme)
}

/// `join` over a stream already validated, for a reader answering many
/// claims against one stream.
pub fn join_stream(
    claim: Option<&[u8]>,
    st: &Stream,
    path: DeclaredPath,
    scheme: &dyn Scheme,
) -> Outcome {
    let mut health = st.health();
    let path = if st.is_empty() {
        Path::NothingArrived
    } else {
        match path {
            DeclaredPath::Direct => Path::Direct,
            DeclaredPath::Relayed { hops } => Path::Relayed { hops },
        }
    };
    let kind = judge(claim, st, scheme, &mut health.touches_claim);
    Outcome { kind, health, path, anchor: Anchor::None }
}

fn judge(claim: Option<&[u8]>, st: &Stream, scheme: &dyn Scheme, touches: &mut bool) -> Kind {
    let Some(claimed) = claim.and_then(|c| decode_joinref(c).ok()) else {
        return Kind::NothingToCompare;
    };
    if claimed.scheme() != scheme.tag() {
        return Kind::NothingToCompare;
    }
    let s = scheme.derive(&claimed);
    let Some(p) = scheme.position(&s, st) else {
        return Kind::NothingToCompare;
    };
    let Some(inst) = st.instance(&p.instance) else {
        return Kind::NothingToCompare;
    };
    *touches = scheme.unparsed(inst) > 0 || inst.gaps().iter().any(|g| scheme.touches(&p, g, inst));

    if scheme.not_covered(&p, inst) {
        let coverage_from = scheme.coverage_start(inst).unwrap_or_default();
        return Kind::NotCovered { coverage_from };
    }

    let key = scheme.key(&s);
    let candidates: Vec<&SightingView> = inst
        .records()
        .map(|(_, r)| r)
        .filter(|r| scheme.is_execution(r) && scheme.key(&r.parts.subject) == key)
        .collect();
    let matching: Vec<&&SightingView> =
        candidates.iter().filter(|r| scheme.matches(&s, &r.parts.subject)).collect();
    if !matching.is_empty() {
        let self_prov = if matching.iter().any(|r| r.parts.self_prov.is_some()) {
            Cap::SelfProvUnappraised
        } else {
            Cap::SelfProvAbsent
        };
        return Kind::Agrees {
            strength: Strength::SOFTWARE,
            scheme: scheme.tag(),
            caps: vec![self_prov, Cap::SequenceUnappraised, Cap::AnchorOperatorAsserted],
        };
    }
    if !candidates.is_empty() {
        return Kind::Disagrees { detail: Detail::SubjectMismatch };
    }

    let all_mediated = inst
        .records()
        .filter(|(_, r)| scheme.is_execution(r))
        .all(|(_, r)| r.parts.coverage.mode == CoverageMode::Mediated);
    if all_mediated && scheme.reached(&p, inst) && !*touches {
        return Kind::Disagrees { detail: Detail::Unobserved };
    }
    Kind::NothingToCompare
}

/// A valid execution sighting that no claim accounts for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Unclaimed {
    pub instance: [u8; 16],
    pub index: u64,
}

/// Every valid execution sighting, by (instance, index), that no claim's
/// derived subject matches. Claims that do not decode, or are of another
/// scheme, account for nothing.
pub fn account(
    claims: &[&[u8]],
    stream: &[&[u8]],
    anchors: &[[u8; 32]],
    scheme: &dyn Scheme,
) -> Vec<Unclaimed> {
    account_stream(claims, &Stream::validate(stream, anchors), scheme)
}

/// `account` over a stream already validated.
pub fn account_stream(claims: &[&[u8]], st: &Stream, scheme: &dyn Scheme) -> Vec<Unclaimed> {
    let derived: Vec<SubjectRef> = claims
        .iter()
        .filter_map(|c| decode_joinref(c).ok())
        .filter(|s| s.scheme() == scheme.tag())
        .map(|s| scheme.derive(&s))
        .collect();
    let mut out = BTreeSet::new();
    for inst in st.instances() {
        for (index, r) in inst.records() {
            if !scheme.is_execution(r) {
                continue;
            }
            let seen = &r.parts.subject;
            let k = scheme.key(seen);
            if !derived.iter().any(|s| scheme.key(s) == k && scheme.matches(s, seen)) {
                out.insert(Unclaimed { instance: inst.id(), index });
            }
        }
    }
    out.into_iter().collect()
}

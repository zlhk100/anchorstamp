//! The TEST and DEMO schemes.

use anchorstamp_core::{
    CLASS_COMMAND_EXECUTION, CLASS_INSTANCE_START, SchemeTag, SightingView, SubjectRef,
};

use crate::{Gap, Instance, Key, Position, Scheme, Stream};

/// TEST, 0xFFFF — conformance only.
///
/// bytes: instance [16] · position u64 · id [1..8]. Derive is identity;
/// key is (instance, id); match is byte equality; position is
/// (instance, position).
pub struct Test;

fn test_parts(s: &SubjectRef) -> Option<(&[u8], u64, &[u8])> {
    let b = s.bytes();
    if b.len() < 25 || b.len() > 32 {
        return None;
    }
    let pos = u64::from_be_bytes(b[16..24].try_into().ok()?);
    Some((&b[..16], pos, &b[24..]))
}

impl Scheme for Test {
    fn tag(&self) -> SchemeTag {
        SchemeTag::TEST
    }

    fn derive(&self, s: &SubjectRef) -> SubjectRef {
        *s
    }

    fn key(&self, s: &SubjectRef) -> Key {
        match test_parts(s) {
            Some((inst, _, id)) => Key([inst, id].concat()),
            None => Key(Vec::new()),
        }
    }

    fn matches(&self, claim: &SubjectRef, seen: &SubjectRef) -> bool {
        test_parts(claim).is_some()
            && claim.scheme() == seen.scheme()
            && claim.bytes() == seen.bytes()
    }

    fn position(&self, s: &SubjectRef, _stream: &Stream) -> Option<Position> {
        let (inst, pos, _) = test_parts(s)?;
        Some(Position { instance: inst.try_into().ok()?, index: pos })
    }
}

/// DEMO, 0xFFFE — proof-of-concept only; never accepted by a conforming
/// reader.
///
/// bytes: pid u32 · time_ms u64 · exe_digest [20], where exe_digest is the
/// first 20 bytes of SHA-256 of the canonical executable path. Derive is
/// identity; key is pid; match is pid AND exe_digest equal — time is not
/// compared. Position is (the stream's single observer instance, time_ms),
/// or none when the stream holds more or fewer than one instance.
///
/// The position is a time, so rule 2, rule 5 and gap-touching are read
/// through sighting times rather than indices.
pub struct Demo;

/// A DEMO subject, split.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DemoSubject {
    pub pid: u32,
    pub time_ms: u64,
    pub exe_digest: [u8; 20],
}

impl DemoSubject {
    pub fn parse(s: &SubjectRef) -> Option<DemoSubject> {
        let b = s.bytes();
        if s.scheme() != SchemeTag::DEMO || b.len() != 32 {
            return None;
        }
        Some(DemoSubject {
            pid: u32::from_be_bytes(b[0..4].try_into().ok()?),
            time_ms: u64::from_be_bytes(b[4..12].try_into().ok()?),
            exe_digest: b[12..32].try_into().ok()?,
        })
    }

    pub fn encode(&self) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0..4].copy_from_slice(&self.pid.to_be_bytes());
        b[4..12].copy_from_slice(&self.time_ms.to_be_bytes());
        b[12..32].copy_from_slice(&self.exe_digest);
        b
    }
}

/// The observer's coverage start, if `v` is its instance-start record.
pub fn instance_start_ms(v: &SightingView) -> Option<u64> {
    let p = &v.parts;
    if p.subject.scheme() != SchemeTag::OBSERVER
        || p.observed.class != CLASS_INSTANCE_START
        || p.subject.bytes() != p.seq.instance
    {
        return None;
    }
    Some(u64::from_be_bytes(p.observed.data.try_into().ok()?))
}

impl Demo {
    /// Time a record carries: an execution's time_ms, or an instance
    /// start's coverage start. Other control records carry none.
    fn record_time(&self, v: &SightingView) -> Option<u64> {
        if self.is_execution(v) {
            return DemoSubject::parse(&v.parts.subject).map(|d| d.time_ms);
        }
        instance_start_ms(v)
    }

    /// Times at `index`, if any record there carries one: (min, max).
    fn times_at(&self, inst: &Instance, index: u64) -> Option<(u64, u64)> {
        let mut it = inst.at(index).iter().filter_map(|v| self.record_time(v));
        let first = it.next()?;
        Some(it.fold((first, first), |(lo, hi), t| (lo.min(t), hi.max(t))))
    }

    /// The instance's coverage start in milliseconds. With several
    /// instance-start records, the latest — coverage is only asserted from
    /// where every copy agrees it had begun.
    pub fn coverage_from_ms(&self, inst: &Instance) -> Option<u64> {
        inst.records().filter_map(|(_, v)| instance_start_ms(v)).max()
    }
}

impl Scheme for Demo {
    fn tag(&self) -> SchemeTag {
        SchemeTag::DEMO
    }

    fn derive(&self, s: &SubjectRef) -> SubjectRef {
        *s
    }

    fn key(&self, s: &SubjectRef) -> Key {
        match DemoSubject::parse(s) {
            Some(d) => Key(d.pid.to_be_bytes().to_vec()),
            None => Key(Vec::new()),
        }
    }

    fn matches(&self, claim: &SubjectRef, seen: &SubjectRef) -> bool {
        match (DemoSubject::parse(claim), DemoSubject::parse(seen)) {
            (Some(a), Some(b)) => a.pid == b.pid && a.exe_digest == b.exe_digest,
            _ => false,
        }
    }

    fn position(&self, s: &SubjectRef, stream: &Stream) -> Option<Position> {
        let d = DemoSubject::parse(s)?;
        if stream.instance_count() != 1 {
            return None;
        }
        let inst = stream.instances().next()?;
        Some(Position { instance: inst.id(), index: d.time_ms })
    }

    fn is_execution(&self, v: &SightingView) -> bool {
        v.parts.observed.class == CLASS_COMMAND_EXECUTION
            && DemoSubject::parse(&v.parts.subject).is_some()
    }

    /// The coverage start in milliseconds. Without a valid instance-start
    /// record the start is unknown and NotCovered is not asserted; the
    /// missing index 0 is then a gap that touches every earlier claim.
    fn coverage_start(&self, inst: &Instance) -> Option<u64> {
        self.coverage_from_ms(inst)
    }

    /// Some valid execution sighting is later than p.
    fn reached(&self, p: &Position, inst: &Instance) -> bool {
        inst.records().any(|(_, v)| {
            self.is_execution(v)
                && DemoSubject::parse(&v.parts.subject).is_some_and(|d| d.time_ms > p.index)
        })
    }

    /// time(left edge) <= p <= time(right edge). The edges are the nearest
    /// records outside the gap that carry a time; a record without one (a
    /// parse-reject) does not bound the gap, so the search moves outward.
    /// No such record on a side leaves that side open.
    fn touches(&self, p: &Position, gap: &Gap, inst: &Instance) -> bool {
        let left = inst.indices_below(gap.from).find_map(|i| self.times_at(inst, i)).map(|t| t.0);
        let right = inst.indices_above(gap.to).find_map(|i| self.times_at(inst, i)).map(|t| t.1);
        left.is_none_or(|l| l <= p.index) && right.is_none_or(|r| p.index <= r)
    }
}

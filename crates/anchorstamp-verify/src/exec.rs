//! The `LINUX_EXEC` scheme, tag 0x0001, and its join and account over any
//! profile's `Evidence`.
//!
//! Claim subject, 60 bytes, big-endian: pid u32 · t0 u64 · `t_reap` u64 ·
//! digest \[32\] · boot \[8\]. `derive` is the identity: the producer already
//! speaks the boot clock.
//!
//! - candidate(c, E): same pid, E's interval meets `[t0, t_reap]`, and a
//!   fork time, where E has one, lies in `[t0, t_reap]`.
//! - match(c, E): a candidate, path-stable, its requested-path digest
//!   equal to the claim's digest (where E has one), and either its
//!   executed-file digest equal to the claim's or E interpreted.
//! - may contradict: a decisive, path-stable candidate whose requested
//!   path differs and which is not interpreted.
//! - position(c): the instances of boot `c.boot`, the window
//!   `[t0, t_reap]`.

use anchorstamp_core::{SchemeTag, Strength, decode_joinref};

use crate::{
    Anchor, Cap, DeclaredPath, Detail, Evidence, ExecRecord, Health, Instance, Kind, Outcome,
    Path, Profile, Unclaimed,
};

/// Length of a `LINUX_EXEC` claim subject.
pub const SUBJECT_LEN: usize = 60;

/// A `LINUX_EXEC` claim, decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Claim {
    pub pid: u32,
    pub t0: u64,
    pub t_reap: u64,
    pub digest: [u8; 32],
    pub boot: [u8; 8],
}

impl Claim {
    /// Decode an encoded join reference. `None` when it does not decode, is
    /// of another scheme, is not 60 bytes, or has t0 after `t_reap`.
    #[must_use]
    pub fn parse(joinref: &[u8]) -> Option<Claim> {
        let s = decode_joinref(joinref).ok()?;
        let b = s.bytes();
        if s.scheme() != SchemeTag::LINUX_EXEC || b.len() != SUBJECT_LEN {
            return None;
        }
        let c = Claim {
            pid: u32::from_be_bytes(b[0..4].try_into().ok()?),
            t0: u64::from_be_bytes(b[4..12].try_into().ok()?),
            t_reap: u64::from_be_bytes(b[12..20].try_into().ok()?),
            digest: b[20..52].try_into().ok()?,
            boot: b[52..60].try_into().ok()?,
        };
        (c.t0 <= c.t_reap).then_some(c)
    }
}

/// Whether an instance observed the claim's boot: its boot id's first 8
/// bytes equal the claim's.
#[must_use]
pub fn same_boot(c: &Claim, i: &Instance) -> bool {
    i.boot.is_some_and(|b| b[..8] == c.boot)
}

#[must_use]
pub fn candidate(c: &Claim, e: &ExecRecord) -> bool {
    e.pid == c.pid
        && e.lo <= c.t_reap
        && c.t0 <= e.hi
        && e.fork.is_none_or(|f| c.t0 <= f && f <= c.t_reap)
}

#[must_use]
pub fn matches(c: &Claim, e: &ExecRecord) -> bool {
    candidate(c, e)
        && e.stable
        && e.req_digest.is_none_or(|r| r == c.digest)
        && (e.exe_digest == c.digest || e.interpreted)
}

#[must_use]
pub fn may_contradict(c: &Claim, e: &ExecRecord) -> bool {
    e.decisive && e.stable && e.req_digest.is_some_and(|r| r != c.digest) && !e.interpreted
}

/// Whether instance `i` touches the claim: a K sequence gap, a loss whose
/// interval meets the window, an S gap whose span meets it, an input the
/// source could not read or a clock step, any K break, a v1 load.
#[must_use]
pub fn touches(c: &Claim, i: &Instance, ev: &Evidence) -> bool {
    let meets = |from: Option<u64>, to: Option<u64>| {
        from.is_none_or(|f| f <= c.t_reap) && to.is_none_or(|t| t >= c.t0)
    };
    i.v1
        || i.holes > 0
        || (ev.profile == Profile::K && ev.breaks > 0)
        || i.gaps.iter().any(|g| meets(g.from, g.to))
        || i.losses.iter().any(|l| meets(Some(l.first), Some(l.last)))
}

/// The not-covered condition for one instance: the window lies entirely before
/// its coverage or entirely after it. A v1 load never says so.
fn outside(c: &Claim, i: &Instance) -> bool {
    !i.v1 && (i.lo_c.is_some_and(|lo| c.t_reap <= lo) || i.hi_c.is_some_and(|hi| c.t0 >= hi))
}

/// The window lies after the instance's armed point and, if it closed,
/// before its close.
fn inside(c: &Claim, i: &Instance) -> bool {
    i.cov_from.is_some_and(|f| c.t0 > f) && i.close_c.is_none_or(|cl| c.t_reap < cl)
}

fn caps_agree(ev: &Evidence, e: &ExecRecord) -> Vec<Cap> {
    let mut caps = match ev.profile {
        Profile::S => vec![
            if e.self_prov { Cap::SelfProvUnappraised } else { Cap::SelfProvAbsent },
            Cap::SequenceUnappraised,
            Cap::TransportOperatorAsserted,
            Cap::BootAsserted,
            Cap::PathUnverified,
        ],
        Profile::K => vec![
            Cap::SelfProvAbsent,
            Cap::BootConfigUnappraised,
            Cap::EkChainUnvalidated,
            Cap::AkPinnedLocally,
            Cap::BootAsserted,
            Cap::RootCanInsert,
        ],
    };
    if ev.profile == Profile::K && e.interpreted {
        caps.push(Cap::Interpreted);
    }
    if ev.profile == Profile::K && !e.decisive {
        caps.push(Cap::Unanchored);
    }
    caps
}

const CAPS_DISAGREE: [Cap; 5] = [
    Cap::SelfProvAbsent,
    Cap::BootConfigUnappraised,
    Cap::EkChainUnvalidated,
    Cap::AkPinnedLocally,
    Cap::BootAsserted,
];

fn within(e: &ExecRecord) -> Anchor {
    e.anchor.map_or(Anchor::None, Anchor::Within)
}

/// The per-claim outcome against one source. `claim` is an encoded join
/// reference, or `None` for a claim at vantage Local.
#[must_use]
pub fn join(claim: Option<&[u8]>, ev: &Evidence, path: DeclaredPath) -> Outcome {
    let mut health = Health {
        gaps: ev.gaps,
        breaks: ev.breaks,
        forks: ev.forks,
        excluded: ev.excluded,
        touches_claim: false,
        evidence_broken: ev.profile == Profile::K && ev.breaks > 0,
    };
    let path = Path::of(path, ev.valid > 0);
    let (kind, anchor) = judge(claim, ev, &mut health.touches_claim);
    Outcome { kind, health, path, anchor }
}

fn judge(claim: Option<&[u8]>, ev: &Evidence, touched: &mut bool) -> (Kind, Anchor) {
    let ntc = (Kind::NothingToCompare, Anchor::None);
    // 1
    let Some(c) = claim.and_then(Claim::parse) else { return ntc };
    let inst: Vec<&Instance> = ev.instances.iter().filter(|i| same_boot(&c, i)).collect();
    if ev.valid == 0 || inst.is_empty() {
        return ntc;
    }
    let touch: Vec<bool> = inst.iter().map(|i| touches(&c, i, ev)).collect();
    *touched = touch.iter().any(|t| *t);

    // 2
    if inst.iter().all(|i| outside(&c, i)) {
        let windows = inst.iter().map(|i| (i.lo_c.unwrap_or(0), i.hi_c)).collect();
        return (Kind::NotCovered { windows }, Anchor::None);
    }

    let cands: Vec<&ExecRecord> =
        inst.iter().flat_map(|i| i.records.iter()).filter(|e| candidate(&c, e)).collect();
    // 3
    let mut forks: Vec<u64> = cands.iter().filter_map(|e| e.fork).collect();
    forks.sort_unstable();
    forks.dedup();
    if forks.len() > 1 {
        return ntc;
    }

    // 4
    let mut matched: Vec<&ExecRecord> = cands.iter().copied().filter(|e| matches(&c, e)).collect();
    matched.sort_by_key(|e| (e.lo, e.entry, e.position));
    if let Some(e) = matched.first() {
        let also = u32::try_from(matched.len() - 1).unwrap_or(u32::MAX);
        let kind = Kind::Agrees {
            strength: e.strength,
            scheme: SchemeTag::LINUX_EXEC,
            caps: caps_agree(ev, e),
            also,
        };
        return (kind, within(e));
    }

    // 5
    if ev.profile == Profile::K && cands.iter().all(|e| may_contradict(&c, e)) {
        let found = inst.iter().zip(&touch).any(|(i, t)| {
            !t && inside(&c, i) && i.records.iter().any(|e| candidate(&c, e) && may_contradict(&c, e))
        });
        let latest = cands.iter().max_by_key(|e| e.entry).filter(|_| found);
        if let Some(latest) = latest {
            let kind = Kind::Disagrees {
                detail: Detail::SubjectMismatch,
                strength: Strength::ATTESTED,
                caps: CAPS_DISAGREE.to_vec(),
            };
            return (kind, within(latest));
        }
    }

    // 6
    if cands.is_empty() {
        let reach = inst.iter().zip(&touch).find_map(|(i, t)| {
            if *t || !i.mediated || !inside(&c, i) {
                return None;
            }
            i.records.iter().filter(|e| e.decisive && e.lo > c.t_reap).min_by_key(|e| e.entry)
        });
        if let Some(e) = reach {
            let kind = Kind::Disagrees {
                detail: Detail::Unobserved,
                strength: Strength::ATTESTED,
                caps: CAPS_DISAGREE.to_vec(),
            };
            return (kind, within(e));
        }
    }

    // 7
    ntc
}

/// Every valid exec record, by (instance, position), that no claim
/// matches. For K only records whose uid or euid is in `scope` are
/// listed; for S every exec sighting. v1 records are reported, never
/// joined, and are not listed. Control records and the K kinds LOAD,
/// ARMED, LOST and UNLOAD are never listed.
#[must_use]
pub fn account(claims: &[&[u8]], ev: &Evidence, scope: &[u32]) -> Vec<Unclaimed> {
    let claims: Vec<Claim> = claims.iter().filter_map(|c| Claim::parse(c)).collect();
    let mut out = Vec::new();
    for i in &ev.instances {
        for e in &i.records {
            if e.v1 {
                continue;
            }
            if ev.profile == Profile::K
                && !e.uid.is_some_and(|u| scope.contains(&u))
                && !e.euid.is_some_and(|u| scope.contains(&u))
            {
                continue;
            }
            if !claims.iter().any(|c| same_boot(c, i) && matches(c, e)) {
                out.push(Unclaimed { instance: i.id, index: e.position });
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

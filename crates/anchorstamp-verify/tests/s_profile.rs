//! Profile S: unsigned sightings agree or say nothing; the upper bound is
//! narrowed to lo + 2·tolerance; clock steps and parse rejects are holes;
//! gaps span the times around them; the outcome is independent of stream
//! order.

mod common;

use anchorstamp_core::{CoverageMode, SchemeTag, Strength};
use anchorstamp_verify::{Anchor, Cap, DeclaredPath, Kind, Path, Unclaimed, exec, s};
use common::*;

const INST: [u8; 16] = [0x5e; 16];
const TOL: u64 = 10_000_000;

fn w23_caps() -> Vec<Cap> {
    vec![
        Cap::SelfProvAbsent,
        Cap::SequenceUnappraised,
        Cap::TransportOperatorAsserted,
        Cap::BootAsserted,
        Cap::PathUnverified,
    ]
}

fn join(stream: &SStream, claim: &[u8]) -> anchorstamp_verify::Outcome {
    exec::join(Some(claim), &s::build(&stream.refs()), DeclaredPath::Relayed { hops: 1 })
}

#[test]
fn w23_s_match() {
    let mut st = SStream::new(INST);
    st.push(s_start()).push(S::Exec { pid: 4242, lo: 2400, hi: 2600, digest: d() });
    let o = join(&st, &c());
    assert_eq!(
        o.kind,
        Kind::Agrees {
            strength: Strength::SOFTWARE,
            scheme: SchemeTag::LINUX_EXEC,
            caps: w23_caps(),
            also: 0
        }
    );
    assert_eq!(o.anchor, Anchor::None);
    assert_eq!(o.path, Path::Relayed { hops: 1 });
    assert!(!o.health.evidence_broken);
}

#[test]
fn w24_w31_s_never_disagrees() {
    let mut st = SStream::new(INST);
    st.push(s_start())
        .push(S::Exec { pid: 4242, lo: 2400, hi: 2600, digest: x() })
        .push(S::Exec { pid: 99, lo: 3500, hi: 3700, digest: x() });
    assert_eq!(join(&st, &c()).kind, Kind::NothingToCompare);
    // nothing of the pid at all, and the stream past the window
    let mut st = SStream::new(INST);
    st.push(s_start()).push(S::Exec { pid: 99, lo: 3500, hi: 3700, digest: x() });
    assert_eq!(join(&st, &c()).kind, Kind::NothingToCompare);
    // Sampled
    let mut st = SStream::new(INST);
    st.mode = CoverageMode::Sampled;
    st.push(s_start()).push(S::Exec { pid: 99, lo: 3500, hi: 3700, digest: x() });
    assert_eq!(join(&st, &c()).kind, Kind::NothingToCompare);
}

#[test]
fn hi_is_narrowed_to_twice_the_tolerance() {
    // audited at lo 1000; read late, hi 5e9. The claim's window starts
    // after lo + 2·tol: no candidate.
    let mut st = SStream::new(INST);
    st.push(s_start()).push(S::Exec { pid: 4242, lo: 1000, hi: 5_000_000_000, digest: d() });
    let ev = s::build(&st.refs());
    assert_eq!(ev.instances[0].records[0].hi, 1000 + 2 * TOL);
    let after = claim(4242, 1000 + 2 * TOL + 1, 4_000_000_000, d(), boot8(&BOOT));
    assert_eq!(exec::join(Some(&after), &ev, DeclaredPath::Direct).kind, Kind::NothingToCompare);
    let at_edge = claim(4242, 1000 + 2 * TOL, 4_000_000_000, d(), boot8(&BOOT));
    assert!(matches!(
        exec::join(Some(&at_edge), &ev, DeclaredPath::Direct).kind,
        Kind::Agrees { .. }
    ));
    // a hi below lo + 2·tol is kept as it is
    let mut st = SStream::new(INST);
    st.push(s_start()).push(S::Exec { pid: 4242, lo: 1000, hi: 2000, digest: d() });
    assert_eq!(s::build(&st.refs()).instances[0].records[0].hi, 2000);
}

#[test]
fn clock_step_and_parse_reject_are_holes() {
    for hole in [S::Step(20_000_000), S::Reject(1)] {
        let mut st = SStream::new(INST);
        st.push(s_start()).push(hole).push(S::Exec { pid: 4242, lo: 2400, hi: 2600, digest: d() });
        let ev = s::build(&st.refs());
        assert_eq!(ev.instances[0].holes, 1);
        let o = exec::join(Some(&c()), &ev, DeclaredPath::Direct);
        assert!(o.health.touches_claim);
        // a hole does not stop an agreement
        assert!(matches!(o.kind, Kind::Agrees { .. }));
    }
}

#[test]
fn gap_spans_the_times_around_it() {
    // index 2 missing between an exec at lo 1500 and one at hi 3700
    let mut st = SStream::new(INST);
    st.push(s_start())
        .push(S::Exec { pid: 7, lo: 1500, hi: 1600, digest: x() })
        .push(S::Exec { pid: 8, lo: 1700, hi: 1800, digest: x() })
        .push(S::Exec { pid: 99, lo: 3500, hi: 3700, digest: x() });
    let mut refs = st.refs();
    refs.remove(2);
    let ev = s::build(&refs);
    assert_eq!(ev.gaps, 1);
    assert_eq!(ev.instances[0].gaps[0], anchorstamp_verify::Span { from: Some(1500), to: Some(3700) });
    let o = exec::join(Some(&c()), &ev, DeclaredPath::Direct);
    assert!(o.health.touches_claim);
    let later = claim(4242, 4000, 5000, d(), boot8(&BOOT));
    assert!(!exec::join(Some(&later), &ev, DeclaredPath::Direct).health.touches_claim);
    // a missing instance start leaves the left side open
    let refs: Vec<&[u8]> = st.refs().into_iter().skip(1).collect();
    let ev = s::build(&refs);
    assert_eq!(ev.instances[0].gaps[0].from, None);
    assert_eq!(ev.instances[0].boot, None, "no instance start, no boot");
}

#[test]
fn not_covered_before_cov_from() {
    let mut st = SStream::new(INST);
    st.push(S::Start { boot: BOOT, cov_from: 5000, tol: 10_000_000 })
        .push(S::Exec { pid: 4242, lo: 5100, hi: 5200, digest: d() });
    assert_eq!(join(&st, &c()).kind, Kind::NotCovered { windows: vec![(5000, None)] });
}

#[test]
fn other_boot_compares_nothing() {
    let mut st = SStream::new(INST);
    st.push(S::Start { boot: OTHER_BOOT, cov_from: 1000, tol: 10_000_000 })
        .push(S::Exec { pid: 4242, lo: 2400, hi: 2600, digest: d() });
    assert_eq!(join(&st, &c()).kind, Kind::NothingToCompare);
}

#[test]
fn tampered_record_is_excluded_or_breaks_the_chain() {
    let mut st = SStream::new(INST);
    st.push(s_start())
        .push(S::Exec { pid: 4242, lo: 2400, hi: 2600, digest: d() })
        .push(S::Exec { pid: 99, lo: 3500, hi: 3700, digest: x() });
    // one byte of the digest changed: still parses, the next prev breaks
    let mut changed = st.records.clone();
    let at = changed[1].len() - 3 - 56 - 1 - 11 - 4 - 13 - 1 - 5;
    changed[1][at] ^= 1;
    let refs: Vec<&[u8]> = changed.iter().map(Vec::as_slice).collect();
    let ev = s::build(&refs);
    assert_eq!((ev.breaks, ev.excluded), (1, 0));
    // a cut record does not parse
    let mut cut = st.records.clone();
    cut[2].pop();
    let refs: Vec<&[u8]> = cut.iter().map(Vec::as_slice).collect();
    assert_eq!(s::build(&refs).excluded, 1);
}

#[test]
fn account_lists_every_unmatched_exec_and_no_control_record() {
    let mut st = SStream::new(INST);
    st.push(s_start())
        .push(S::Exec { pid: 4242, lo: 2400, hi: 2600, digest: d() })
        .push(S::Exec { pid: 500, lo: 2500, hi: 2700, digest: x() })
        .push(S::Reject(1));
    let ev = s::build(&st.refs());
    assert_eq!(exec::account(&[&c()], &ev, &[]), vec![Unclaimed { instance: INST, index: 2 }]);
}

/// Deterministic permutation source for the test; not cryptographic.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            let j = usize::try_from(self.next() % (i as u64 + 1)).unwrap();
            v.swap(i, j);
        }
    }
}

#[test]
fn join_and_account_are_independent_of_stream_order() {
    let mut a = SStream::new(INST);
    a.push(s_start())
        .push(S::Exec { pid: 4242, lo: 2400, hi: 2600, digest: d() })
        .push(S::Exec { pid: 4243, lo: 2400, hi: 2600, digest: x() })
        .push(S::Reject(1))
        .push(S::Exec { pid: 500, lo: 3000, hi: 3100, digest: x() })
        .push(S::Step(30_000_000))
        .push(S::Exec { pid: 501, lo: 4000, hi: 4100, digest: y() });
    let mut b = SStream::new([0x6f; 16]);
    b.push(S::Start { boot: BOOT, cov_from: 900, tol: 5_000_000 })
        .push(S::Exec { pid: 4242, lo: 2450, hi: 2500, digest: d() });
    let mut stream: Vec<&[u8]> = a.refs();
    stream.remove(3); // a gap
    stream.extend(b.refs());
    stream.push(a.records[1].as_slice()); // a duplicate
    stream.push(b"not a record"); // excluded
    let claims = [
        c(),
        claim(4243, 2000, 3000, d(), boot8(&BOOT)),
        claim(500, 2900, 3200, x(), boot8(&BOOT)),
        claim(9, 100, 200, d(), boot8(&BOOT)),
        claim(501, 3900, 4200, y(), boot8(&OTHER_BOOT)),
    ];
    let refs: Vec<&[u8]> = claims.iter().map(Vec::as_slice).collect();
    let want_join: Vec<_> =
        claims.iter().map(|c| exec::join(Some(c), &s::build(&stream), DeclaredPath::Direct)).collect();
    let want_account = exec::account(&refs, &s::build(&stream), &[]);
    let mut rng = XorShift(0x9e37_79b9_7f4a_7c15);
    let mut s2 = stream.clone();
    for round in 0..1000 {
        rng.shuffle(&mut s2);
        let ev = s::build(&s2);
        for (c, want) in claims.iter().zip(&want_join) {
            assert_eq!(&exec::join(Some(c), &ev, DeclaredPath::Direct), want, "round {round}");
        }
        assert_eq!(exec::account(&refs, &ev, &[]), want_account, "round {round}");
    }
}

//! DEMO scheme rules, tamper and anchor substitution.

mod common;

use anchorstamp_core::{SchemeTag, Strength};
use anchorstamp_verify::schemes::Demo;
use anchorstamp_verify::{
    Cap, DeclaredPath, Detail, Kind, Outcome, Scheme as _, Stream, Unclaimed, account,
    account_stream, join, join_stream,
};
use common::*;

fn run(claim: &[u8], stream: &[&[u8]], anchor: [u8; 32]) -> Outcome {
    join(Some(claim), stream, &[anchor], DeclaredPath::Direct, &Demo)
}

fn agrees() -> Kind {
    Kind::Agrees {
        strength: Strength::SOFTWARE,
        scheme: SchemeTag::DEMO,
        caps: vec![Cap::SelfProvAbsent, Cap::SequenceUnappraised, Cap::AnchorOperatorAsserted],
    }
}

const UNOBSERVED: Kind = Kind::Disagrees { detail: Detail::Unobserved };
const MISMATCH: Kind = Kind::Disagrees { detail: Detail::SubjectMismatch };

#[test]
fn honest_claim_agrees_whatever_its_time() {
    let b = standard();
    // The library's clock may read later than the audit stamp; time is
    // not compared.
    for t in [1099, 1100, 1101, 1250] {
        let o = run(&claim(10, t, 0xA), &b.refs(), b.anchor());
        assert_eq!(o.kind, agrees(), "time {t}");
        assert_eq!(o.health.gaps, 0);
    }
}

#[test]
fn same_pid_other_exe_is_subject_mismatch() {
    let b = standard();
    assert_eq!(run(&claim(10, 1100, 0xB), &b.refs(), b.anchor()).kind, MISMATCH);
}

#[test]
fn fabricated_pid_after_start_is_unobserved() {
    let b = standard();
    assert_eq!(run(&claim(99, 1050, 0xA), &b.refs(), b.anchor()).kind, UNOBSERVED);
}

#[test]
fn fabricated_pid_after_last_sighting_is_nothing_to_compare() {
    let b = standard();
    assert_eq!(run(&claim(99, 1300, 0xA), &b.refs(), b.anchor()).kind, Kind::NothingToCompare);
}

#[test]
fn before_coverage_is_not_covered() {
    let b = standard();
    assert_eq!(
        run(&claim(10, 999, 0xA), &b.refs(), b.anchor()).kind,
        Kind::NotCovered { coverage_from: 1000 }
    );
}

#[test]
fn gap_touches_by_time() {
    let b = standard();
    // drop index 2 (pid 11 at 1200): left edge 1100, right edge is the
    // untimed control record, so the next timed record, 1300.
    let mut s = b.refs();
    s.remove(2);
    for (t, touched, kind) in [
        (1050, false, UNOBSERVED),
        (1100, true, Kind::NothingToCompare),
        (1250, true, Kind::NothingToCompare),
        (1300, true, Kind::NothingToCompare),
        (1301, false, Kind::NothingToCompare),
    ] {
        let o = run(&claim(99, t, 0xA), &s, b.anchor());
        assert_eq!(o.health.gaps, 1);
        assert_eq!(o.health.touches_claim, touched, "time {t}");
        assert_eq!(o.kind, kind, "time {t}");
    }
}

#[test]
fn missing_instance_start_touches_every_earlier_claim() {
    let b = standard();
    let mut s = b.refs();
    s.remove(0);
    let o = run(&claim(99, 1050, 0xA), &s, b.anchor());
    assert!(o.health.touches_claim);
    assert_eq!(o.kind, Kind::NothingToCompare);
    // and NotCovered is not asserted without a start record
    let o = run(&claim(99, 500, 0xA), &s, b.anchor());
    assert_eq!(o.kind, Kind::NothingToCompare);
}

#[test]
fn two_instances_give_no_position() {
    let b = standard();
    let mut c = Builder::new(&SECRET, [0x77; 16]);
    c.push(Rec::Start(1000));
    let mut s = b.refs();
    s.extend(c.refs());
    assert_eq!(run(&claim(10, 1100, 0xA), &s, b.anchor()).kind, Kind::NothingToCompare);
}

#[test]
fn one_byte_tamper_is_excluded() {
    let b = standard();
    let rec = &b.records[1];
    // every byte position of the pid-10 record
    for at in 0..rec.len() {
        let mut t = rec.clone();
        t[at] ^= 0x01;
        let mut s = b.refs();
        s[1] = &t;
        let o = run(&claim(10, 1100, 0xA), &s, b.anchor());
        assert_eq!(o.health.excluded, 1, "byte {at}");
        assert_ne!(o.kind, agrees(), "byte {at}");
    }
}

#[test]
fn substituted_anchor_agrees_with_nothing() {
    let b = standard();
    let other = Builder::new(&OTHER_SECRET, INSTANCE).anchor();
    let o = run(&claim(10, 1100, 0xA), &b.refs(), other);
    assert_eq!(o.kind, Kind::NothingToCompare);
    assert_eq!(o.health.excluded, 5);
    // and a stream signed by the other key under the real anchor
    let mut f = Builder::new(&OTHER_SECRET, INSTANCE);
    f.push(Rec::Start(1000)).push(Rec::Exec { pid: 10, time_ms: 1100, exe: 0xA });
    let o = run(&claim(10, 1100, 0xA), &f.refs(), b.anchor());
    assert_eq!(o.kind, Kind::NothingToCompare);
    assert_eq!(o.health.excluded, 2);
}

#[test]
fn account_lists_executions_only() {
    let b = standard();
    let c = claim(10, 1100, 0xA);
    let got = account(&[&c], &b.refs(), &[b.anchor()], &Demo);
    let u = |index| Unclaimed { instance: INSTANCE, index };
    // indices 0 (start) and 3 (stream-ended) are control records
    assert_eq!(got, vec![u(2), u(4)]);
}

#[test]
fn control_records_are_never_candidates() {
    // a claim whose pid bytes equal the start of the instance id
    let b = standard();
    let pid = u32::from_be_bytes([0x5e; 4]);
    assert_eq!(run(&claim(pid, 1050, 0xA), &b.refs(), b.anchor()).kind, UNOBSERVED);
}

#[test]
fn chain_is_intact_and_breaks_are_counted() {
    let b = standard();
    assert_eq!(run(&claim(10, 1100, 0xA), &b.refs(), b.anchor()).health.breaks, 0);
    // index 2 replaced by a validly signed record from another chain
    let mut f = Builder::new(&SECRET, INSTANCE);
    f.push(Rec::Start(1000)).push(Rec::Start(1000)).push(Rec::Exec {
        pid: 11,
        time_ms: 1200,
        exe: 0xC,
    });
    let mut s = b.refs();
    s[2] = &f.records[2];
    let o = run(&claim(10, 1100, 0xA), &s, b.anchor());
    assert_eq!(o.health.breaks, 2); // index 2 (bad prev) and index 3 (prev of the original)
    assert_eq!(o.kind, agrees());
}

#[test]
fn a_parse_reject_is_a_hole_touching_every_claim() {
    // an unparsed line could have been any exec at any time: no claim can
    // be Unobserved while one exists
    let mut b = standard();
    b.push(Rec::Reject(1));
    for t in [1001, 1050, 1150, 1250, 1299] {
        let o = run(&claim(99, t, 0xA), &b.refs(), b.anchor());
        assert!(o.health.touches_claim, "time {t}");
        assert_eq!(o.kind, Kind::NothingToCompare, "time {t}");
    }
    // the same claims are Unobserved without it
    let c = standard();
    assert_eq!(run(&claim(99, 1050, 0xA), &c.refs(), c.anchor()).kind, UNOBSERVED);
    // agreement, mismatch and coverage are unchanged by it
    assert_eq!(run(&claim(10, 1100, 0xA), &b.refs(), b.anchor()).kind, agrees());
    assert_eq!(run(&claim(10, 1100, 0xB), &b.refs(), b.anchor()).kind, MISMATCH);
    assert_eq!(
        run(&claim(10, 999, 0xA), &b.refs(), b.anchor()).kind,
        Kind::NotCovered { coverage_from: 1000 }
    );
    // the count the instance reports is the highest cumulative count
    let st = Stream::validate(&b.refs(), &[b.anchor()]);
    assert_eq!(Demo.unparsed(st.instances().next().unwrap()), 1);
    let mut d = standard();
    d.push(Rec::Reject(1)).push(Rec::Reject(4));
    let st = Stream::validate(&d.refs(), &[d.anchor()]);
    assert_eq!(Demo.unparsed(st.instances().next().unwrap()), 4);
}

#[test]
fn validated_once_gives_the_same_outcomes() {
    let mut b = standard();
    b.push(Rec::Reject(1));
    let anchors = [b.anchor()];
    let refs = b.refs();
    let st = Stream::validate(&refs, &anchors);
    let claims = [claim(10, 1100, 0xA), claim(10, 1100, 0xB), claim(99, 1050, 0xA)];
    for c in &claims {
        assert_eq!(
            join_stream(Some(c), &st, DeclaredPath::Direct, &Demo),
            join(Some(c), &refs, &anchors, DeclaredPath::Direct, &Demo)
        );
    }
    let cs: Vec<&[u8]> = claims.iter().map(Vec::as_slice).collect();
    assert_eq!(account_stream(&cs, &st, &Demo), account(&cs, &refs, &anchors, &Demo));
}

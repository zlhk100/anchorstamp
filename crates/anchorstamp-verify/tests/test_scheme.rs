//! The TEST scheme: the index-axis rules over unsigned layout-1
//! encodings, on streams shaped as the index-axis conformance vectors (the
//! two that test signatures retire with layout 0). The generated vectors are checked
//! byte for byte elsewhere.

use anchorstamp_core::{
    CLASS_COMMAND_EXECUTION, CLASS_INSTANCE_START, CLASS_PARSE_REJECT, Coverage, CoverageMode,
    JOINREF_MAX_LEN, Observed, SIGHTING_MAX_LEN, SchemeTag, Seq, SequenceSource, SightingParts,
    Strength, SubjectRef, encode_joinref, encode_sighting,
};
use anchorstamp_verify::test::{Kind, Outcome, account, join};
use anchorstamp_verify::{Anchor, Cap, DeclaredPath, Detail, Health, Path, Unclaimed, chain_digest};

const A1: [u8; 16] = [0xa1; 16];
const B2: [u8; 16] = [0xb2; 16];

fn subject(instance: [u8; 16], position: u64, id: u8) -> Vec<u8> {
    let mut s = instance.to_vec();
    s.extend_from_slice(&position.to_be_bytes());
    s.push(id);
    s
}

enum R {
    Exec { position: u64, id: u8 },
    Start,
    Reject(u64),
}

/// Records at the given indices, chained in index order; `prev` of a
/// record whose predecessor index is absent is arbitrary.
fn stream(instance: [u8; 16], recs: &[(u64, R)]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut prev = [0u8; 32];
    let mut last_index = None;
    for (index, r) in recs {
        if last_index.is_some_and(|l: u64| l + 1 != *index) {
            prev = [0xee; 32];
        }
        let ctl = SubjectRef::new(SchemeTag::OBSERVER, &instance).unwrap();
        let (subj, class, data): (SubjectRef, u16, Vec<u8>) = match r {
            R::Exec { position, id } => (
                SubjectRef::new(SchemeTag::TEST, &subject(instance, *position, *id)).unwrap(),
                CLASS_COMMAND_EXECUTION,
                b"/usr/bin/true".to_vec(),
            ),
            R::Start => (ctl, CLASS_INSTANCE_START, vec![0; 28]),
            R::Reject(n) => (ctl, CLASS_PARSE_REJECT, n.to_be_bytes().to_vec()),
        };
        let parts = SightingParts {
            subject: subj,
            observed: Observed { class, data: &data },
            coverage: Coverage { mode: CoverageMode::Mediated, from: 0, over: CLASS_COMMAND_EXECUTION },
            self_prov: None,
            seq: Seq { instance, index: *index, prev },
            source: SequenceSource::None,
        };
        let mut buf = [0u8; SIGHTING_MAX_LEN];
        let n = encode_sighting(&parts, &mut buf).unwrap();
        let rec = buf[..n].to_vec();
        prev = chain_digest(&rec);
        last_index = Some(*index);
        out.push(rec);
    }
    out
}

fn jr(instance: [u8; 16], position: u64, id: u8) -> Vec<u8> {
    let s = SubjectRef::new(SchemeTag::TEST, &subject(instance, position, id)).unwrap();
    let mut buf = [0u8; JOINREF_MAX_LEN];
    let n = encode_joinref(&s, &mut buf).unwrap();
    buf[..n].to_vec()
}

fn s_records() -> Vec<Vec<u8>> {
    stream(
        A1,
        &[
            (0, R::Exec { position: 0, id: 0x10 }),
            (1, R::Exec { position: 1, id: 0x11 }),
            (2, R::Exec { position: 2, id: 0x12 }),
            (4, R::Exec { position: 4, id: 0x14 }),
        ],
    )
}

fn run(claim: Option<&[u8]>, recs: &[&Vec<u8>]) -> Outcome {
    let slices: Vec<&[u8]> = recs.iter().map(|r| r.as_slice()).collect();
    join(claim, &slices, DeclaredPath::Relayed { hops: 1 })
}

fn agrees() -> Kind {
    Kind::Agrees {
        strength: Strength::SOFTWARE,
        scheme: SchemeTag::TEST,
        caps: vec![Cap::SelfProvAbsent, Cap::SequenceUnappraised, Cap::AnchorOperatorAsserted],
    }
}

fn h(gaps: u64, forks: u64, touches_claim: bool) -> Health {
    Health { gaps, breaks: 0, forks, excluded: 0, touches_claim, evidence_broken: false }
}

fn expect(o: &Outcome, kind: Kind, health: Health) {
    assert_eq!(*o, Outcome { kind, health, path: Path::Relayed { hops: 1 }, anchor: Anchor::None });
}

#[test]
fn v01_to_v07_v09_v10() {
    let s = s_records();
    let (s0, s1, s2, s4) = (&s[0], &s[1], &s[2], &s[3]);
    let o = run(Some(&jr(A1, 1, 0x11)), &[]);
    assert_eq!((o.kind, o.path), (Kind::NothingToCompare, Path::NothingArrived));
    expect(&run(Some(&jr(A1, 1, 0x11)), &[s0, s1, s2]), agrees(), h(0, 0, false));
    expect(
        &run(Some(&jr(A1, 1, 0x99)), &[s0, s1, s2, s4]),
        Kind::Disagrees { detail: Detail::Unobserved },
        h(1, 0, false),
    );
    expect(
        &run(Some(&jr(A1, 2, 0x11)), &[s0, s1, s2]),
        Kind::Disagrees { detail: Detail::SubjectMismatch },
        h(0, 0, false),
    );
    expect(&run(Some(&jr(A1, 3, 0x13)), &[s0, s1, s2, s4]), Kind::NothingToCompare, h(1, 0, true));
    expect(&run(Some(&jr(A1, 1, 0x11)), &[s0, s1, s2, s4]), agrees(), h(1, 0, false));
    expect(&run(Some(&jr(A1, 9, 0x19)), &[s0, s1, s2]), Kind::NothingToCompare, h(0, 0, false));
    let fork = stream(A1, &[(0, R::Exec { position: 0, id: 0x10 }), (1, R::Exec { position: 1, id: 0x11 }), (2, R::Exec { position: 2, id: 0x22 })]);
    expect(&run(Some(&jr(A1, 1, 0x11)), &[s0, s1, s2, &fork[2]]), agrees(), h(0, 1, false));
    expect(&run(None, &[s0, s1, s2]), Kind::NothingToCompare, h(0, 0, false));
}

#[test]
fn v11_account() {
    let s = s_records();
    let refs: Vec<&[u8]> = s[..3].iter().map(Vec::as_slice).collect();
    assert_eq!(
        account(&[&jr(A1, 1, 0x11)], &refs),
        vec![Unclaimed { instance: A1, index: 0 }, Unclaimed { instance: A1, index: 2 }]
    );
}

#[test]
fn v13_to_v15_control_records() {
    let t = stream(
        B2,
        &[
            (0, R::Start),
            (1, R::Exec { position: 1, id: 0x21 }),
            (2, R::Exec { position: 2, id: 0x22 }),
        ],
    );
    let r = stream(
        B2,
        &[
            (0, R::Start),
            (1, R::Exec { position: 1, id: 0x21 }),
            (2, R::Reject(1)),
            (3, R::Exec { position: 3, id: 0x23 }),
        ],
    );
    expect(&run(Some(&jr(B2, 1, 0x21)), &[&t[0], &t[1], &t[2]]), agrees(), h(0, 0, false));
    expect(
        &run(Some(&jr(B2, 1, 0x99)), &[&r[0], &r[1], &r[2], &r[3]]),
        Kind::NothingToCompare,
        h(0, 0, true),
    );
    expect(
        &run(Some(&jr(B2, 1, 0x99)), &[&t[0], &t[1], &t[2]]),
        Kind::Disagrees { detail: Detail::Unobserved },
        h(0, 0, false),
    );
    let refs: Vec<&[u8]> = t.iter().map(Vec::as_slice).collect();
    assert_eq!(account(&[&jr(B2, 1, 0x21)], &refs), vec![Unclaimed { instance: B2, index: 2 }]);
}

#[test]
fn not_covered_below_coverage_from() {
    // coverage.from 0 everywhere here; the not-covered rule is exercised by a
    // claim at no position below it, so a NotCovered never arises
    let s = s_records();
    let o = run(Some(&jr(A1, 0, 0x10)), &[&s[0], &s[1]]);
    assert_eq!(o.kind, agrees());
}

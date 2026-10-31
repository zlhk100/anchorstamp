//! Layout-0 conformance vectors under the TEST scheme: chain digest, key
//! id, signatures, and every vector's outcome.

#[path = "../../anchorstamp-core/tests/common/vectors.rs"]
mod vectors;

use anchorstamp_core::{SchemeTag, Strength, decode_sighting};
use anchorstamp_verify::schemes::Test;
use anchorstamp_verify::{
    Anchor, Cap, DeclaredPath, Detail, Health, Kind, Outcome, Path, Unclaimed, account,
    chain_digest, join, key_id,
};
use vectors::*;

fn anchor() -> [u8; 32] {
    hex(ANCHOR_PUBLIC).try_into().unwrap()
}

fn agrees() -> Kind {
    Kind::Agrees {
        strength: Strength::SOFTWARE,
        scheme: SchemeTag::TEST,
        caps: vec![Cap::SelfProvAbsent, Cap::SequenceUnappraised, Cap::AnchorOperatorAsserted],
    }
}

fn h(gaps: u64, excluded: u64, forks: u64, touches_claim: bool) -> Health {
    Health { gaps, breaks: 0, forks, excluded, touches_claim }
}

fn run(claim: Option<&str>, stream: &[&str]) -> Outcome {
    let claim = claim.map(hex);
    let stream: Vec<Vec<u8>> = stream.iter().map(|s| hex(s)).collect();
    let refs: Vec<&[u8]> = stream.iter().map(Vec::as_slice).collect();
    join(claim.as_deref(), &refs, &[anchor()], DeclaredPath::Relayed { hops: 1 }, &Test)
}

fn expect(o: Outcome, kind: Kind, health: Health, path: Path) {
    assert_eq!(o, Outcome { kind, health, path, anchor: Anchor::None });
}

const RELAYED: Path = Path::Relayed { hops: 1 };

#[test]
fn chain_of_s0_matches() {
    assert_eq!(chain_digest(&hex(S0)).to_vec(), hex(CHAIN_S0));
    // and S1, S2 carry the chain of their predecessor
    assert_eq!(decode_sighting(&hex(S1)).unwrap().parts.seq.prev.to_vec(), hex(CHAIN_S0));
    let s2 = hex(S2);
    let s2 = decode_sighting(&s2).unwrap();
    assert_eq!(s2.parts.seq.prev, chain_digest(&hex(S1)));
}

#[test]
fn key_id_matches() {
    assert_eq!(key_id(&anchor()).to_vec(), hex(ANCHOR_KEY_ID));
}

#[test]
fn signatures() {
    use anchorstamp_verify::Stream;
    let a = [anchor()];
    for (name, rec, ok) in [
        ("S0", S0, true),
        ("S1", S1, true),
        ("S2", S2, true),
        ("S4", S4, true),
        ("S2F", S2F, true),
        ("SX", SX, false),
        ("S1T", S1T, false),
    ] {
        let b = hex(rec);
        let st = Stream::validate(&[&b], &a);
        assert_eq!(st.excluded() == 0, ok, "{name}");
    }
}

#[test]
fn v01_empty_stream() {
    expect(
        run(Some(JOINREF_S1), &[]),
        Kind::NothingToCompare,
        h(0, 0, 0, false),
        Path::NothingArrived,
    );
}

#[test]
fn v02_corroborated() {
    expect(run(Some(JOINREF_S1), &[S0, S1, S2]), agrees(), h(0, 0, 0, false), RELAYED);
}

#[test]
fn v03_fabricated_in_window() {
    expect(
        run(Some(JOINREF_UNKNOWN_ID), &[S0, S1, S2, S4]),
        Kind::Disagrees { detail: Detail::Unobserved },
        h(1, 0, 0, false),
        RELAYED,
    );
}

#[test]
fn v04_resolves_to_another_subject() {
    expect(
        run(Some(JOINREF_S1_ID_AT_2), &[S0, S1, S2]),
        Kind::Disagrees { detail: Detail::SubjectMismatch },
        h(0, 0, 0, false),
        RELAYED,
    );
}

#[test]
fn v05_gap_touches_claim() {
    expect(
        run(Some(JOINREF_INDEX_3), &[S0, S1, S2, S4]),
        Kind::NothingToCompare,
        h(1, 0, 0, true),
        RELAYED,
    );
}

#[test]
fn v06_gap_does_not_touch_claim() {
    expect(run(Some(JOINREF_S1), &[S0, S1, S2, S4]), agrees(), h(1, 0, 0, false), RELAYED);
}

#[test]
fn v07_claim_beyond_stream_end() {
    expect(
        run(Some(JOINREF_INDEX_9), &[S0, S1, S2]),
        Kind::NothingToCompare,
        h(0, 0, 0, false),
        RELAYED,
    );
}

#[test]
fn v08_unknown_key_and_bad_signature() {
    expect(
        run(Some(JOINREF_S1), &[S0, SX, S1T, S2]),
        Kind::NothingToCompare,
        h(1, 2, 0, true),
        RELAYED,
    );
}

#[test]
fn v09_fork() {
    expect(run(Some(JOINREF_S1), &[S0, S1, S2, S2F]), agrees(), h(0, 0, 1, false), RELAYED);
}

#[test]
fn v10_local_claim() {
    expect(run(None, &[S0, S1, S2]), Kind::NothingToCompare, h(0, 0, 0, false), RELAYED);
}

#[test]
fn v11_account() {
    let claim = hex(JOINREF_S1);
    let stream: Vec<Vec<u8>> = [S0, S1, S2].iter().map(|s| hex(s)).collect();
    let refs: Vec<&[u8]> = stream.iter().map(Vec::as_slice).collect();
    let got = account(&[&claim], &refs, &[anchor()], &Test);
    let inst = [0xa1; 16];
    assert_eq!(
        got,
        vec![Unclaimed { instance: inst, index: 0 }, Unclaimed { instance: inst, index: 2 }]
    );
}

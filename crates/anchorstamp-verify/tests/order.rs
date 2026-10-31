//! join and account are pure and independent of stream order: 1,000
//! permutations of a mixed stream give identical outcomes.

mod common;
#[path = "../../anchorstamp-core/tests/common/vectors.rs"]
mod vectors;

use anchorstamp_verify::schemes::{Demo, Test};
use anchorstamp_verify::{DeclaredPath, Scheme, account, join};
use common::*;

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
            let j = (self.next() % (i as u64 + 1)) as usize;
            v.swap(i, j);
        }
    }
}

fn check(stream: Vec<&[u8]>, anchors: &[[u8; 32]], claims: &[Vec<u8>], scheme: &dyn Scheme) {
    let claim_refs: Vec<&[u8]> = claims.iter().map(Vec::as_slice).collect();
    let want_join: Vec<_> = claims
        .iter()
        .map(|c| join(Some(c), &stream, anchors, DeclaredPath::Direct, scheme))
        .collect();
    let want_account = account(&claim_refs, &stream, anchors, scheme);
    let mut rng = XorShift(0x9e37_79b9_7f4a_7c15);
    let mut s = stream.clone();
    for round in 0..1000 {
        rng.shuffle(&mut s);
        for (c, want) in claims.iter().zip(&want_join) {
            assert_eq!(
                &join(Some(c), &s, anchors, DeclaredPath::Direct, scheme),
                want,
                "round {round}"
            );
        }
        assert_eq!(account(&claim_refs, &s, anchors, scheme), want_account, "round {round}");
    }
}

#[test]
fn demo_stream_order_independent() {
    let b = standard();
    let mut f = Builder::new(&SECRET, INSTANCE);
    f.push(Rec::Start(1000)).push(Rec::Exec { pid: 10, time_ms: 1100, exe: 0xC });
    let mut tampered = b.records[4].clone();
    tampered[30] ^= 1;
    let mut stream = b.refs();
    stream.remove(2); // a gap
    stream.push(&f.records[1]); // a fork at index 1
    stream.push(&tampered); // excluded
    stream.push(&b.records[1]); // a duplicate
    let claims = vec![
        claim(10, 1100, 0xA),
        claim(10, 1100, 0xC),
        claim(99, 1050, 0xA),
        claim(99, 1250, 0xA),
        claim(12, 900, 0xA),
    ];
    check(stream, &[b.anchor()], &claims, &Demo);
}

#[test]
fn test_vectors_order_independent() {
    use vectors::*;
    let recs: Vec<Vec<u8>> = [S0, S1, S2, S4, S2F, SX, S1T].iter().map(|s| hex(s)).collect();
    let anchor: [u8; 32] = hex(ANCHOR_PUBLIC).try_into().unwrap();
    let claims: Vec<Vec<u8>> =
        [JOINREF_S1, JOINREF_UNKNOWN_ID, JOINREF_S1_ID_AT_2, JOINREF_INDEX_3, JOINREF_INDEX_9]
            .iter()
            .map(|s| hex(s))
            .collect();
    check(recs.iter().map(Vec::as_slice).collect(), &[anchor], &claims, &Test);
}

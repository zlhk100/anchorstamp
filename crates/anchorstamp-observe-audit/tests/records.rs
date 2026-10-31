//! The observer's records: every one decodes, chains and verifies; control
//! records carry their data; framing is a u32 big-endian length.

use anchorstamp_core::{
    CLASS_COMMAND_EXECUTION, CLASS_INSTANCE_START, CLASS_PARSE_REJECT, CLASS_STREAM_ENDED,
    CoverageMode, ENDED_ROTATED, SchemeTag, SequenceSource, decode_sighting,
};
use anchorstamp_observe_audit::emit::{Chain, exe_digest, frame};
use anchorstamp_observe_audit::parse::{Arch, EXE_DATA_MAX, Exec};
use ed25519_dalek::{Signature, SigningKey};
use sha2::{Digest, Sha256};

fn chain_of(prior: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"anchorstamp/chain\0");
    h.update(prior);
    h.finalize().into()
}

#[test]
fn records_decode_chain_and_verify() {
    // a published RFC 8032 test secret; anchors nothing
    let key = SigningKey::from_bytes(&[0x9d; 32]);
    let instance = [0x42; 16];
    let mut c = Chain::new(&key, instance);
    let long = Exec {
        time_ms: 1_793_418_742_236,
        serial: 10446,
        arch: Arch::X86_64,
        syscall: 59,
        pid: 600476,
        ppid: 600475,
        exe: vec![b'd'; 1647],
    };
    let recs = [
        c.instance_start(1_793_418_742_000),
        c.exec(&long),
        c.parse_reject(1),
        c.stream_ended(ENDED_ROTATED),
    ];
    let vk = key.verifying_key();
    let kid: [u8; 32] = Sha256::digest(vk.as_bytes()).into();
    let mut prev = [0u8; 32];
    for (i, r) in recs.iter().enumerate() {
        let v = decode_sighting(r).unwrap();
        let p = v.parts;
        assert_eq!(p.seq.instance, instance);
        assert_eq!(p.seq.index, i as u64);
        assert_eq!(p.seq.prev, prev);
        assert_eq!(p.key_id, kid);
        assert_eq!(p.coverage.mode, CoverageMode::Mediated);
        assert_eq!(p.coverage.from, 0);
        assert_eq!(p.coverage.over, CLASS_COMMAND_EXECUTION);
        assert_eq!(p.source, SequenceSource::None);
        vk.verify_strict(v.signed(), &Signature::from_bytes(&p.signature)).unwrap();
        prev = chain_of(r);
    }
    let start = decode_sighting(&recs[0]).unwrap().parts;
    assert_eq!(start.subject.scheme(), SchemeTag::OBSERVER);
    assert_eq!(start.subject.bytes(), instance);
    assert_eq!(start.observed.class, CLASS_INSTANCE_START);
    assert_eq!(start.observed.data, 1_793_418_742_000u64.to_be_bytes());

    let ex = decode_sighting(&recs[1]).unwrap().parts;
    assert_eq!(ex.subject.scheme(), SchemeTag::DEMO);
    let s = ex.subject.bytes();
    assert_eq!(&s[0..4], &600476u32.to_be_bytes());
    assert_eq!(&s[4..12], &1_793_418_742_236u64.to_be_bytes());
    // digest over the FULL path, not the truncated copy
    assert_eq!(&s[12..32], &exe_digest(&vec![b'd'; 1647]));
    assert_ne!(&s[12..32], &exe_digest(&vec![b'd'; EXE_DATA_MAX]));
    assert_eq!(ex.observed.data[0], 1);
    assert_eq!(ex.observed.data.len(), 5 + EXE_DATA_MAX);

    let rj = decode_sighting(&recs[2]).unwrap().parts;
    assert_eq!(
        (rj.observed.class, rj.observed.data),
        (CLASS_PARSE_REJECT, &1u64.to_be_bytes()[..])
    );
    let en = decode_sighting(&recs[3]).unwrap().parts;
    assert_eq!((en.observed.class, en.observed.data), (CLASS_STREAM_ENDED, &[ENDED_ROTATED][..]));
}

#[test]
fn framing() {
    let f = frame(b"abc");
    assert_eq!(f, [0, 0, 0, 3, b'a', b'b', b'c']);
}

#[test]
fn fresh_instances_never_share_a_chain() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let a = Chain::new(&key, [1; 16]).instance_start(5);
    let b = Chain::new(&key, [2; 16]).instance_start(5);
    assert_ne!(
        decode_sighting(&a).unwrap().parts.seq.instance,
        decode_sighting(&b).unwrap().parts.seq.instance
    );
}

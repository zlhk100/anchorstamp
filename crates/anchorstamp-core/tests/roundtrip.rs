//! Byte round-trip of every layout-0 conformance record: decode, then
//! re-encode, byte-identical. No hashing and no signatures here.

mod common;

use anchorstamp_core::{
    CoverageMode, DecodeError, JOINREF_MAX_LEN, SIGHTING_MAX_LEN, SchemeTag, SequenceSource,
    decode_joinref, decode_sighting, encode_joinref, encode_sighting,
};
use common::vectors::*;

fn roundtrip_sighting(name: &str, h: &str) {
    let bytes = hex(h);
    let view = decode_sighting(&bytes).unwrap_or_else(|e| panic!("{name}: {e:?}"));
    assert_eq!(view.raw(), &bytes[..], "{name}: raw");
    assert_eq!(view.signed().len(), bytes.len() - 64, "{name}: signed span");
    let mut out = [0u8; SIGHTING_MAX_LEN];
    let n = encode_sighting(&view.parts, &mut out).unwrap();
    assert_eq!(&out[..n], &bytes[..], "{name}: re-encode differs");
}

#[test]
fn sightings_roundtrip() {
    for (name, h) in [
        ("S0", S0),
        ("S1", S1),
        ("S2", S2),
        ("S4", S4),
        ("S2F", S2F),
        ("SX", SX),
        ("S1T", S1T),
    ] {
        roundtrip_sighting(name, h);
    }
}

#[test]
fn joinrefs_roundtrip() {
    for h in [JOINREF_S1, JOINREF_UNKNOWN_ID, JOINREF_S1_ID_AT_2, JOINREF_INDEX_3, JOINREF_INDEX_9]
    {
        let bytes = hex(h);
        let s = decode_joinref(&bytes).unwrap();
        assert_eq!(s.scheme(), SchemeTag::TEST);
        let mut out = [0u8; JOINREF_MAX_LEN];
        let n = encode_joinref(&s, &mut out).unwrap();
        assert_eq!(&out[..n], &bytes[..]);
    }
}

#[test]
fn s0_fields() {
    let bytes = hex(S0);
    let v = decode_sighting(&bytes).unwrap().parts;
    assert_eq!(v.subject.scheme(), SchemeTag::TEST);
    assert_eq!(v.subject.bytes().len(), 25);
    assert_eq!(v.observed.class, 1);
    assert_eq!(v.observed.data, b"/usr/bin/true");
    assert_eq!(v.coverage.mode, CoverageMode::Mediated);
    assert_eq!(v.coverage.from, 0);
    assert_eq!(v.coverage.over, 1);
    assert!(v.self_prov.is_none());
    assert_eq!(v.seq.instance, [0xa1; 16]);
    assert_eq!(v.seq.index, 0);
    assert_eq!(v.seq.prev, [0; 32]);
    assert_eq!(v.source, SequenceSource::None);
    assert_eq!(v.key_id.to_vec(), hex(ANCHOR_KEY_ID));
}

#[test]
fn malformed_rejected() {
    let good = hex(S0);

    let mut b = good.clone();
    b.push(0);
    assert_eq!(decode_sighting(&b).unwrap_err(), DecodeError::Trailing);

    assert_eq!(decode_sighting(&good[..good.len() - 1]).unwrap_err(), DecodeError::Truncated);

    let mut b = good.clone();
    b[0] ^= 1;
    assert_eq!(decode_sighting(&b).unwrap_err(), DecodeError::Prefix);

    let mut b = good.clone();
    b[20] = 1;
    assert_eq!(decode_sighting(&b).unwrap_err(), DecodeError::Layout);

    // subject length 0
    let mut b = good.clone();
    b[23] = 0;
    assert!(decode_sighting(&b).is_err());

    // coverage mode 3: prefix 20, layout 1, subject 28, observed 4 + 13
    let mode_at = 20 + 1 + 28 + 4 + 13;
    let mut b = good.clone();
    b[mode_at] = 3;
    assert_eq!(decode_sighting(&b).unwrap_err(), DecodeError::CoverageMode);

    // self-provenance flag 2
    let mut b = good.clone();
    b[mode_at + 11] = 2;
    assert_eq!(decode_sighting(&b).unwrap_err(), DecodeError::SelfProvFlag);

    // source flag 2
    let source_at = mode_at + 11 + 1 + 16 + 8 + 32;
    let mut b = good.clone();
    b[source_at] = 2;
    assert_eq!(decode_sighting(&b).unwrap_err(), DecodeError::SourceFlag);

    let jr = hex(JOINREF_S1);
    let mut b = jr.clone();
    b.push(0);
    assert_eq!(decode_joinref(&b).unwrap_err(), DecodeError::Trailing);
}

#[test]
fn every_prefix_of_a_record_is_rejected() {
    let good = hex(S1);
    for n in 0..good.len() {
        assert!(decode_sighting(&good[..n]).is_err(), "prefix of length {n} accepted");
    }
}

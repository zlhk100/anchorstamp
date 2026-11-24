// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright © 2026 Lei Zhou

//! Layout-1 records: decode, then re-encode, byte-identical; field
//! offsets as the encoding lays them out; every malformation rejected.
//! No hashing and no signatures here.

use anchorstamp_core::{
    CLASS_COMMAND_EXECUTION, Coverage, CoverageMode, DecodeError, EncodeError, JOINREF_MAX_LEN,
    LAYOUT, Observed, SIGHTING_MAX_LEN, SUBJECT_MAX, SchemeTag, SelfProv, Seq, SequenceSource,
    SightingParts, SubjectRef, decode_joinref, decode_sighting, encode_joinref, encode_sighting,
};

fn parts<'a>(subject: &'a [u8], data: &'a [u8], self_prov: Option<&'a [u8]>) -> SightingParts<'a> {
    SightingParts {
        subject: SubjectRef::new(SchemeTag::LINUX_EXEC, subject).unwrap(),
        observed: Observed { class: CLASS_COMMAND_EXECUTION, data },
        coverage: Coverage { mode: CoverageMode::Mediated, from: 0, over: CLASS_COMMAND_EXECUTION },
        self_prov: self_prov.map(|r| SelfProv { kind: 7, reference: r }),
        seq: Seq { instance: [0xa1; 16], index: 3, prev: [0x5c; 32] },
        source: SequenceSource::Declared(9),
    }
}

fn encode(p: &SightingParts) -> Vec<u8> {
    let mut out = [0u8; SIGHTING_MAX_LEN];
    let n = encode_sighting(p, &mut out).unwrap();
    out[..n].to_vec()
}

/// A 52-byte subject: the longest a source writes in layout 1 is 60.
fn sample() -> Vec<u8> {
    encode(&parts(&[0x42; 52], b"\x00\x00\x00\x00\x01/usr/bin/true", None))
}

#[test]
fn layout_is_one() {
    assert_eq!(LAYOUT, 1);
    assert_eq!(SUBJECT_MAX, 64);
    assert_eq!(SchemeTag::LINUX_EXEC, SchemeTag(0x0001));
    let b = sample();
    assert_eq!(&b[..20], b"anchorstamp/sighting");
    assert_eq!(b[20], 1);
}

#[test]
fn sightings_roundtrip() {
    for (subject, data, sp) in [
        (&[1u8][..], &b""[..], None),
        (&[2u8; 52][..], &b"x"[..], Some(&b"r"[..])),
        (&[3u8; 64][..], &[0u8; 1024][..], Some(&[9u8; 256][..])),
    ] {
        let bytes = encode(&parts(subject, data, sp));
        let view = decode_sighting(&bytes).unwrap();
        assert_eq!(view.raw(), &bytes[..]);
        assert_eq!(encode(&view.parts), bytes, "re-encode differs");
    }
}

#[test]
fn sighting_has_no_key_id_or_signature() {
    // prefix 20, layout 1, subject 3 + 52, observed 4 + 18, coverage 11,
    // self-provenance flag 1, seq 56, source 3: nothing after the source
    let b = sample();
    assert_eq!(b.len(), 20 + 1 + 55 + 22 + 11 + 1 + 56 + 3);
    assert_eq!(&b[b.len() - 3..], &[1, 0, 9]);
}

#[test]
fn fields_decode() {
    let b = sample();
    let v = decode_sighting(&b).unwrap().parts;
    assert_eq!(v.subject.scheme(), SchemeTag::LINUX_EXEC);
    assert_eq!(v.subject.bytes(), [0x42; 52]);
    assert_eq!(v.observed.class, CLASS_COMMAND_EXECUTION);
    assert_eq!(v.coverage.mode, CoverageMode::Mediated);
    assert!(v.self_prov.is_none());
    assert_eq!(v.seq.instance, [0xa1; 16]);
    assert_eq!(v.seq.index, 3);
    assert_eq!(v.seq.prev, [0x5c; 32]);
    assert_eq!(v.source, SequenceSource::Declared(9));
}

#[test]
fn joinrefs_roundtrip() {
    for len in [1usize, 32, 60, 64] {
        let s = SubjectRef::new(SchemeTag::LINUX_EXEC, &vec![7u8; len]).unwrap();
        let mut out = [0u8; JOINREF_MAX_LEN];
        let n = encode_joinref(&s, &mut out).unwrap();
        assert_eq!(n, 19 + 1 + 3 + len);
        assert_eq!(out[19], 1, "layout byte");
        let back = decode_joinref(&out[..n]).unwrap();
        assert_eq!(back.scheme(), SchemeTag::LINUX_EXEC);
        assert_eq!(back.bytes(), &vec![7u8; len][..]);
    }
}

#[test]
fn subject_bounds() {
    assert!(SubjectRef::new(SchemeTag::TEST, &[]).is_none());
    assert!(SubjectRef::new(SchemeTag::TEST, &[0; 64]).is_some());
    assert!(SubjectRef::new(SchemeTag::TEST, &[0; 65]).is_none());
    assert!(SubjectRef::new(SchemeTag::TEST, &[0; 300]).is_none());
}

#[test]
fn encode_rejects_out_of_range_fields() {
    let mut out = [0u8; SIGHTING_MAX_LEN];
    let long = [0u8; 1025];
    assert_eq!(
        encode_sighting(&parts(&[1], &long, None), &mut out),
        Err(EncodeError::ObservedTooLong)
    );
    assert_eq!(
        encode_sighting(&parts(&[1], b"", Some(b"")), &mut out),
        Err(EncodeError::SelfProvLength)
    );
    let mut small = [0u8; 10];
    assert_eq!(
        encode_sighting(&parts(&[1], b"", None), &mut small),
        Err(EncodeError::BufferTooSmall)
    );
}

#[test]
fn malformed_rejected() {
    let good = sample();

    let mut b = good.clone();
    b.push(0);
    assert_eq!(decode_sighting(&b).unwrap_err(), DecodeError::Trailing);

    let mut b = good.clone();
    b[0] ^= 1;
    assert_eq!(decode_sighting(&b).unwrap_err(), DecodeError::Prefix);

    // layout 0 is retired: a layout-0 header does not decode
    let mut b = good.clone();
    b[20] = 0;
    assert_eq!(decode_sighting(&b).unwrap_err(), DecodeError::Layout);

    // subject length 0, and 65
    let mut b = good.clone();
    b[23] = 0;
    assert!(decode_sighting(&b).is_err());
    let mut b = good.clone();
    b[23] = 65;
    assert!(decode_sighting(&b).is_err());

    // coverage mode 3: prefix 20, layout 1, subject 55, observed 4 + 18
    let mode_at = 20 + 1 + 55 + 4 + 18;
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

    let s = SubjectRef::new(SchemeTag::LINUX_EXEC, &[1; 60]).unwrap();
    let mut out = [0u8; JOINREF_MAX_LEN];
    let n = encode_joinref(&s, &mut out).unwrap();
    let mut b = out[..n].to_vec();
    b.push(0);
    assert_eq!(decode_joinref(&b).unwrap_err(), DecodeError::Trailing);
    let mut b = out[..n].to_vec();
    b[19] = 0;
    assert_eq!(decode_joinref(&b).unwrap_err(), DecodeError::Layout);
}

#[test]
fn every_prefix_of_a_record_is_rejected() {
    let good = encode(&parts(&[2u8; 52], b"x", Some(b"r")));
    for n in 0..good.len() {
        assert!(decode_sighting(&good[..n]).is_err(), "prefix of length {n} accepted");
    }
}

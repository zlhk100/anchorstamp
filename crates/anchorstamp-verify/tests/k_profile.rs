// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright © 2026 Lei Zhou

//! Profile K without a valid quote: record decoding v1 and v2, entry
//! checks, the replay, per-load order and interleaving, and the outcomes
//! of an unattested (tail) list. Attested outcomes are exercised by the
//! conformance vectors, whose quotes are signed outside this crate.

mod common;

use anchorstamp_core::{SchemeTag, Strength};
use anchorstamp_verify::k::{Body, Bundle, Quote, build, decode_record, parse_ak, parse_attest, parse_signature, replay};
use anchorstamp_verify::{Anchor, Cap, DeclaredPath, Detail, Evidence, Kind, Unclaimed, exec};
use common::*;

fn bundle_of(list: &[u8], ak: &[u8], quotes: &[Quote]) -> Evidence {
    build(&Bundle {
        list,
        quotes,
        ak_spki: ak,
        boot_id: Some(BOOT),
        nonce: None,
        interval_s: Some(0),
    })
}

fn tail(records: &[Vec<u8>]) -> Evidence {
    bundle_of(&list(records), &test_ak(), &[])
}

fn k_tail_caps(extra: &[Cap]) -> Vec<Cap> {
    let mut v = vec![
        Cap::SelfProvAbsent,
        Cap::BootConfigUnappraised,
        Cap::EkChainUnvalidated,
        Cap::AkPinnedLocally,
        Cap::BootAsserted,
        Cap::RootCanInsert,
    ];
    v.extend_from_slice(extra);
    v.push(Cap::Unanchored);
    v
}

#[test]
fn v2_records_decode() {
    let e = ex(4242, 2500, d());
    let r = decode_record(&exec_v2(2, LOAD_L, &e)).unwrap();
    assert!(!r.v1);
    assert_eq!((r.seq, r.load_id), (2, LOAD_L));
    let Body::Exec(x) = r.body else { panic!() };
    assert_eq!((x.pid, x.start_ns, x.exec_ns), (4242, 2490, Some(2500)));
    assert_eq!((x.dev, x.ino), (Some(0x0080_0001), Some(5242)));
    assert_eq!((x.exe_digest, x.req_digest), (d(), Some(d())));
    assert_eq!(x.path, b"/usr/bin/true");
    assert_eq!(exec_v2(2, LOAD_L, &e).len(), 148 + 13);
    assert_eq!(
        decode_record(&load_v2(0, LOAD_L, 1000)).unwrap().body,
        Body::Load { shim_version: 2, loaded_ns: 1000 }
    );
    assert_eq!(decode_record(&armed_v2(1, LOAD_L, 1100)).unwrap().body, Body::Armed { armed_ns: 1100 });
    assert_eq!(
        decode_record(&lost_v2(3, LOAD_L, 3, 2100, 2200)).unwrap().body,
        Body::Lost { count: 3, first_ns: Some(2100), last_ns: Some(2200) }
    );
    assert_eq!(
        decode_record(&unload_v2(4, LOAD_L, 3600, 3700)).unwrap().body,
        Body::Unload { close_ns: Some(3600), unloaded_ns: Some(3700) }
    );
    assert_eq!(load_v2(0, LOAD_L, 1).len(), 39);
    assert_eq!(armed_v2(0, LOAD_L, 1).len(), 37);
    assert_eq!(lost_v2(0, LOAD_L, 1, 1, 1).len(), 53);
    assert_eq!(unload_v2(0, LOAD_L, 1, 1).len(), 45);
}

#[test]
fn v2_malformations_are_rejected() {
    let good = ex(4242, 2500, d());
    let bad = |f: &dyn Fn(&mut Ex, &mut Vec<u8>)| {
        let mut e = good.clone();
        let mut b = exec_v2(2, LOAD_L, &e);
        f(&mut e, &mut b);
        decode_record(&b).is_none()
    };
    assert!(bad(&|_, b| b[0] = b'X'), "magic");
    assert!(bad(&|_, b| b.push(0)), "size");
    assert!(bad(&|_, b| b[4] |= 0x10), "reserved bit 4");
    assert!(bad(&|_, b| b[145] = 0x10), "reserved ns bit");
    assert!(bad(&|_, b| b[4] |= 0x80), "truncated with a short path");
    assert!(bad(&|_, b| b[4] |= 0x40), "unresolved with a path");
    assert!(bad(&|_, b| b[146] = 0xFF), "path_len disagrees with the size");
    assert!(bad(&|_, b| b[53..61].copy_from_slice(&9999u64.to_le_bytes())), "start after exec");
    assert!(decode_record(&{
        let mut b = load_v2(0, LOAD_L, 1);
        b[4] |= 0x80;
        b
    })
    .is_none(), "flags on LOAD");
    assert!(decode_record(&lost_v2(3, LOAD_L, 0, 1, 2)).is_none(), "LOST count zero");
    assert!(decode_record(&lost_v2(3, LOAD_L, 1, 5, 2)).is_none(), "LOST first > last");
    assert!(decode_record(&{
        let mut b = armed_v2(1, LOAD_L, 1);
        b[4] = 6;
        b
    })
    .is_none(), "unknown kind");
    // a path of exactly 1024 bytes may be flagged truncated; bits 6 and 7
    // together never
    let mut e = good.clone();
    e.path = vec![b'p'; 1024];
    e.flags = 0x80;
    assert!(decode_record(&exec_v2(2, LOAD_L, &e)).is_some());
    e.flags = 0xC0;
    assert!(decode_record(&exec_v2(2, LOAD_L, &e)).is_none());
    // unresolved: no path and a zero digest
    let mut e = good.clone();
    e.path.clear();
    e.exe = [0; 32];
    e.flags = 0x40;
    assert!(decode_record(&exec_v2(2, LOAD_L, &e)).is_some());
}

#[test]
fn v1_records_decode() {
    let r = decode_record(&exec_v1(1, LOAD_L, 7, 1500)).unwrap();
    assert!(r.v1);
    let Body::Exec(x) = r.body else { panic!() };
    assert_eq!((x.pid, x.start_ns, x.exec_ns, x.ns), (7, 1500, None, None));
    assert_eq!(decode_record(&load_v1(LOAD_L, 5)).unwrap().body, Body::Load { shim_version: 1, loaded_ns: 5 });
}

#[test]
fn foreign_entries_are_excluded_and_still_replayed() {
    let recs = load_l(&[ex(4242, 2500, d())]);
    let mut l = list(&recs);
    let n_before = replay(&l).len();
    l.extend(entry(13, b"ima-ng", b"\x04\x00\x00\x00abcd"));
    l.extend(entry(10, b"ima-ng", b"not ours: pcr 10"));
    let mut bad_dng = template_data(&recs[0]);
    bad_dng[20] ^= 1;
    l.extend(entry(13, b"ima-buf", &bad_dng));
    assert_eq!(replay(&l).len(), n_before + 2, "both PCR-13 entries replayed, PCR 10 not");
    let ev = bundle_of(&l, &test_ak(), &[]);
    assert_eq!(ev.excluded, 2);
    assert_eq!(ev.facts.entries, 5);
}

#[test]
fn reordering_the_list_breaks_the_replay() {
    let recs = load_l(&[ex(4242, 2500, d()), ex(99, 3500, x())]);
    let v = replay(&list(&recs));
    let mut swapped = recs.clone();
    swapped.swap(2, 3);
    let w = replay(&list(&swapped));
    assert_eq!(v.len(), w.len());
    // the prefix up to the swap holds; no later value of the reordered
    // list equals any value of the original past it
    assert_eq!(v[..3], w[..3]);
    for later in &w[3..] {
        assert!(!v[3..].contains(later));
    }
}

#[test]
fn tail_match_is_software_and_unanchored() {
    // a match with no quotes: everything is tail
    let ev = tail(&load_l(&[ex(4242, 2500, d()), ex(99, 3500, x())]));
    assert!(ev.facts.ak_usable);
    assert!(!ev.facts.tail_empty);
    let o = exec::join(Some(&c()), &ev, DeclaredPath::Direct);
    assert_eq!(
        o.kind,
        Kind::Agrees {
            strength: Strength::SOFTWARE,
            scheme: SchemeTag::LINUX_EXEC,
            caps: k_tail_caps(&[]),
            also: 0
        }
    );
    assert_eq!(o.anchor, Anchor::None);
    assert!(!o.health.evidence_broken);
}

#[test]
fn tail_never_contradicts() {
    // a mismatch and a reach in the tail say nothing
    let mismatch = tail(&load_l(&[ex(4242, 2500, x()), ex(99, 3500, x())]));
    assert_eq!(exec::join(Some(&c()), &mismatch, DeclaredPath::Direct).kind, Kind::NothingToCompare);
    let reach = tail(&load_l(&[ex(7, 1500, x()), ex(99, 3500, x())]));
    assert_eq!(exec::join(Some(&c()), &reach, DeclaredPath::Direct).kind, Kind::NothingToCompare);
}

#[test]
fn interpreted_tail_match_says_so() {
    let mut e = ex(4242, 2500, i());
    e.req = d();
    e.interpreted = true;
    let ev = tail(&load_l(&[e]));
    let Kind::Agrees { caps, .. } = exec::join(Some(&c()), &ev, DeclaredPath::Direct).kind else {
        panic!()
    };
    assert_eq!(caps, k_tail_caps(&[Cap::Interpreted]));
}

#[test]
fn unstable_and_renamed_records_never_match() {
    for (ns, flags, exe, req) in [(2u8, 0u8, d(), d()), (4, 0, d(), d()), (8, 0, d(), d()), (0, 0, y(), d())] {
        let mut e = ex(4242, 2500, exe);
        e.req = req;
        e.ns = ns;
        e.flags = flags;
        let ev = tail(&load_l(&[e]));
        assert_eq!(exec::join(Some(&c()), &ev, DeclaredPath::Direct).kind, Kind::NothingToCompare, "ns {ns}");
    }
    // ns bit 0 (another PID namespace) does not make a record unstable
    let mut e = ex(4242, 2500, d());
    e.ns = 1;
    let ev = tail(&load_l(&[e]));
    assert!(matches!(exec::join(Some(&c()), &ev, DeclaredPath::Direct).kind, Kind::Agrees { .. }));
}

#[test]
fn two_fork_times_are_ambiguous() {
    let mut a = ex(4242, 2100, x());
    a.start_ns = 2050;
    let mut b = ex(4242, 2800, d());
    b.start_ns = 2700;
    let ev = tail(&load_l(&[a, b]));
    assert_eq!(exec::join(Some(&c()), &ev, DeclaredPath::Direct).kind, Kind::NothingToCompare);
}

#[test]
fn earliest_match_wins_and_the_rest_are_also() {
    let mut a = ex(4242, 2600, d());
    a.start_ns = 2300;
    let mut b = ex(4242, 2400, d());
    b.start_ns = 2300;
    let ev = tail(&load_l(&[a, b]));
    let Kind::Agrees { also, .. } = exec::join(Some(&c()), &ev, DeclaredPath::Direct).kind else {
        panic!()
    };
    assert_eq!(also, 1);
}

#[test]
fn seq_gap_touches_every_claim_of_the_load() {
    let recs = vec![
        load_v2(0, LOAD_L, 1000),
        armed_v2(1, LOAD_L, 1100),
        exec_v2(2, LOAD_L, &ex(7, 1500, x())),
        exec_v2(4, LOAD_L, &ex(99, 3500, x())),
    ];
    let ev = tail(&recs);
    assert_eq!((ev.gaps, ev.breaks), (1, 0));
    let o = exec::join(Some(&c()), &ev, DeclaredPath::Direct);
    assert_eq!(o.kind, Kind::NothingToCompare);
    assert!(o.health.touches_claim);
    assert_eq!(o.health.gaps, 1);
}

#[test]
fn a_lost_touches_only_its_interval() {
    let mk = |first, last| {
        let mut r = load_l(&[ex(7, 1500, x())]);
        r.push(lost_v2(3, LOAD_L, 3, first, last));
        r.push(exec_v2(4, LOAD_L, &ex(99, 3500, x())));
        tail(&r)
    };
    assert!(exec::join(Some(&c()), &mk(2100, 2200), DeclaredPath::Direct).health.touches_claim);
    assert!(!exec::join(Some(&c()), &mk(3100, 3200), DeclaredPath::Direct).health.touches_claim);
}

fn breaks_of(records: &[Vec<u8>]) -> (u64, Vec<String>) {
    let ev = tail(records);
    (ev.breaks, ev.facts.break_reasons)
}

#[test]
fn load_order_violations_are_breaks() {
    let e = |seq, pid, t| exec_v2(seq, LOAD_L, &ex(pid, t, x()));
    // first record not LOAD
    assert_eq!(breaks_of(&[armed_v2(1, LOAD_L, 1100), e(2, 7, 1500)]).0, 2);
    // second record not ARMED
    assert_eq!(breaks_of(&[load_v2(0, LOAD_L, 1000), e(1, 7, 1500)]).0, 1);
    // a record after UNLOAD
    let mut r = load_l(&[]);
    r.push(unload_v2(2, LOAD_L, 1200, 1300));
    r.push(e(3, 7, 1500));
    assert_eq!(breaks_of(&r).0, 1);
    // a second LOAD of the same load
    let mut r = load_l(&[]);
    r.push(load_v2(2, LOAD_L, 1200));
    assert_eq!(breaks_of(&r).0, 1);
    // a second ARMED of the same load; coverage stays at the first
    let mut r = load_l(&[ex(7, 1500, x())]);
    r.push(armed_v2(3, LOAD_L, 1400));
    let (n, why) = breaks_of(&r);
    assert_eq!(n, 1, "{why:?}");
    assert!(why[0].contains("a second ARMED"), "{why:?}");
    assert_eq!(tail(&r).instances[0].cov_from, Some(1100));
    // two distinct records with one seq: a break and a fork
    let mut r = load_l(&[ex(7, 1500, x())]);
    r.push(e(2, 8, 1600));
    let ev = tail(&r);
    assert_eq!((ev.breaks, ev.forks), (1, 1));
    assert!(exec::join(Some(&c()), &ev, DeclaredPath::Direct).health.evidence_broken);
}

#[test]
fn a_load_that_failed_before_armed_is_not_a_break() {
    // LOAD alone, then a later, complete load
    let mut r = vec![load_v2(0, LOAD_L2, 500)];
    r.extend(load_l(&[ex(4242, 2500, d())]));
    let ev = tail(&r);
    assert_eq!(ev.breaks, 0);
    let l2 = ev.instances.iter().find(|i| i.id == LOAD_L2).unwrap();
    assert_eq!((l2.lo_c, l2.cov_from), (Some(500), None));
}

#[test]
fn interleaved_loads_are_a_break() {
    // L runs; L2 loads before L's UNLOAD
    let mut r = load_l(&[ex(99, 3500, x())]);
    r.push(load_v2(0, LOAD_L2, 3600));
    r.push(unload_v2(3, LOAD_L, 3700, 3800));
    let (n, why) = breaks_of(&r);
    assert!(n >= 1, "{why:?}");
    // L ending with UNLOAD, then a whole load L2: no break
    let mut r = load_l(&[]);
    r.push(unload_v2(2, LOAD_L, 3600, 3700));
    r.extend([load_v2(0, LOAD_L2, 3800), armed_v2(1, LOAD_L2, 3850), exec_v2(2, LOAD_L2, &ex(4242, 2500, d()))]);
    assert_eq!(breaks_of(&r).0, 0);
}

#[test]
fn v1_load_is_reported_never_joined() {
    let r = vec![load_v1(LOAD_L, 1000), exec_v1(1, LOAD_L, 4242, 2100), exec_v1(2, LOAD_L, 99, 3500)];
    let ev = tail(&r);
    assert_eq!(ev.breaks, 0, "{:?}", ev.facts.break_reasons);
    assert!(ev.instances[0].v1);
    let o = exec::join(Some(&c()), &ev, DeclaredPath::Direct);
    assert_eq!(o.kind, Kind::NothingToCompare);
    assert!(o.health.touches_claim);
    // a v1 load yields no NotCovered either
    let early = claim(4242, 10, 20, d(), boot8(&BOOT));
    assert_eq!(exec::join(Some(&early), &ev, DeclaredPath::Direct).kind, Kind::NothingToCompare);
    assert!(exec::account(&[], &ev, &[1001]).is_empty(), "v1 records are not listed");
}

#[test]
fn before_coverage_is_not_covered() {
    let r = vec![load_v2(0, LOAD_L, 4000), armed_v2(1, LOAD_L, 4050), exec_v2(2, LOAD_L, &ex(7, 4100, x()))];
    let o = exec::join(Some(&c()), &tail(&r), DeclaredPath::Direct);
    assert_eq!(o.kind, Kind::NotCovered { windows: vec![(4000, None)] });
}

#[test]
fn other_boot_and_local_claims_compare_nothing() {
    let ev = tail(&load_l(&[ex(4242, 2500, d())]));
    let other = claim(4242, 2000, 3000, d(), boot8(&OTHER_BOOT));
    assert_eq!(exec::join(Some(&other), &ev, DeclaredPath::Direct).kind, Kind::NothingToCompare);
    assert_eq!(exec::join(None, &ev, DeclaredPath::Direct).kind, Kind::NothingToCompare);
    // a bundle without a boot id has no instance of any boot
    let no_boot = build(&Bundle { list: &list(&load_l(&[ex(4242, 2500, d())])), quotes: &[], ak_spki: &test_ak(), boot_id: None, nonce: None, interval_s: None });
    assert_eq!(exec::join(Some(&c()), &no_boot, DeclaredPath::Direct).kind, Kind::NothingToCompare);
}

#[test]
fn malformed_claims_compare_nothing() {
    let ev = tail(&load_l(&[ex(4242, 2500, d())]));
    // t0 after t_reap
    let backwards = claim(4242, 3000, 2000, d(), boot8(&BOOT));
    assert_eq!(exec::join(Some(&backwards), &ev, DeclaredPath::Direct).kind, Kind::NothingToCompare);
    assert_eq!(exec::join(Some(b"junk"), &ev, DeclaredPath::Direct).kind, Kind::NothingToCompare);
}

#[test]
fn account_lists_unclaimed_execs_in_scope() {
    // one claimed exec, one unclaimed in scope, one out of scope, a loss
    let mut a = ex(4242, 2500, d());
    a.uid = 1001;
    let mut b = ex(500, 2600, x());
    b.uid = 1001;
    let mut z = ex(600, 2700, x());
    z.uid = 0;
    let mut r = load_l(&[a, b, z]);
    r.push(lost_v2(5, LOAD_L, 1, 4000, 4000));
    let ev = tail(&r);
    let got = exec::account(&[&c()], &ev, &[1001]);
    assert_eq!(got, vec![Unclaimed { instance: LOAD_L, index: 3 }]);
}

#[test]
fn ak_must_be_the_exact_der_form_of_a_curve_point() {
    assert!(parse_ak(&test_ak()).is_some());
    let mut short = test_ak();
    short.pop();
    assert!(parse_ak(&short).is_none(), "length");
    let mut prefix = test_ak();
    prefix[5] ^= 1;
    assert!(parse_ak(&prefix).is_none(), "prefix");
    let mut off_curve = test_ak();
    off_curve[90] ^= 1;
    assert!(parse_ak(&off_curve).is_none(), "off curve");
    // an unusable AK excludes every quote and leaves everything tail
    let attest = [0u8; 4];
    let q = [Quote { attest: &attest, signature: &[], pcr7: &[0; 32] }];
    let ev = bundle_of(&list(&load_l(&[ex(4242, 2500, d())])), &short, &q);
    assert!(!ev.facts.ak_usable);
    assert_eq!((ev.facts.quotes, ev.facts.quotes_valid, ev.excluded), (1, 0, 1));
    let Kind::Agrees { strength, caps, .. } = exec::join(Some(&c()), &ev, DeclaredPath::Direct).kind else {
        panic!()
    };
    assert_eq!(strength, Strength::SOFTWARE);
    assert!(caps.contains(&Cap::Unanchored));
}

/// A `TPMS_ATTEST` of type quote, built by hand.
fn attest(extra: &[u8], banks: &[(u16, &[u8])], digest: &[u8], trailing: bool) -> Vec<u8> {
    let mut b = 0xFF54_4347u32.to_be_bytes().to_vec();
    b.extend_from_slice(&0x8018u16.to_be_bytes());
    b.extend_from_slice(&34u16.to_be_bytes());
    b.extend_from_slice(&[0x0b; 34]);
    b.extend_from_slice(&u16::try_from(extra.len()).unwrap().to_be_bytes());
    b.extend_from_slice(extra);
    b.extend_from_slice(&100_000u64.to_be_bytes());
    b.extend_from_slice(&7u32.to_be_bytes());
    b.extend_from_slice(&0u32.to_be_bytes());
    b.push(1);
    b.extend_from_slice(&0u64.to_be_bytes());
    b.extend_from_slice(&u32::try_from(banks.len()).unwrap().to_be_bytes());
    for (alg, sel) in banks {
        b.extend_from_slice(&alg.to_be_bytes());
        b.push(u8::try_from(sel.len()).unwrap());
        b.extend_from_slice(sel);
    }
    b.extend_from_slice(&u16::try_from(digest.len()).unwrap().to_be_bytes());
    b.extend_from_slice(digest);
    if trailing {
        b.push(0);
    }
    b
}

#[test]
fn attest_parses_and_rejects() {
    let a = parse_attest(&attest(&[0x11; 16], &[(0x000B, &[0x80, 0x20, 0x00])], &[0x33; 32], false)).unwrap();
    assert_eq!((a.clock, a.reset_count, a.restart_count, a.safe), (100_000, 7, 0, true));
    assert_eq!(a.extra_data, vec![0x11; 16]);
    assert_eq!(a.selection, vec![(0x000B, vec![0x80, 0x20, 0x00])]);
    assert!(parse_attest(&attest(&[0; 16], &[(0x000B, &[0x80, 0x20, 0])], &[0; 32], true)).is_none(), "trailing");
    assert!(parse_attest(&attest(&[0; 49], &[(0x000B, &[0x80, 0x20, 0])], &[0; 32], false)).is_none(), "extraData > 48");
    let mut wrong_type = attest(&[0; 16], &[(0x000B, &[0x80, 0x20, 0])], &[0; 32], false);
    wrong_type[5] = 0x17;
    assert!(parse_attest(&wrong_type).is_none());
}

fn sig(r: &[u8], s: &[u8]) -> Vec<u8> {
    let mut b = vec![0x00, 0x18, 0x00, 0x0B];
    b.extend_from_slice(&u16::try_from(r.len()).unwrap().to_be_bytes());
    b.extend_from_slice(r);
    b.extend_from_slice(&u16::try_from(s.len()).unwrap().to_be_bytes());
    b.extend_from_slice(s);
    b
}

#[test]
fn signature_parses_short_scalars_and_rejects_out_of_range() {
    // RFC 6979 A.2.5, SHA-256, message "sample"
    let r = hex("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716");
    let s = hex("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8");
    assert!(parse_signature(&sig(&r, &s)).is_some());
    // a scalar shorter than 32 bytes is left-padded
    assert!(parse_signature(&sig(&r[1..], &s)).is_some());
    // zero and n are out of range; 33 bytes and 0 bytes are malformed
    let n = hex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
    assert!(parse_signature(&sig(&[0], &s)).is_none());
    assert!(parse_signature(&sig(&r, &n)).is_none());
    assert!(parse_signature(&sig(&[[0u8].as_slice(), &r].concat(), &s)).is_none());
    assert!(parse_signature(&sig(&[], &s)).is_none());
    // wrong algorithm or hash; trailing bytes
    let mut b = sig(&r, &s);
    b[1] = 0x14;
    assert!(parse_signature(&b).is_none());
    let mut b = sig(&r, &s);
    b.push(0);
    assert!(parse_signature(&b).is_none());
}

#[test]
fn a_list_that_stops_parsing_is_counted() {
    let mut l = list(&load_l(&[ex(4242, 2500, d())]));
    l.extend_from_slice(&[13, 0, 0]);
    let ev = bundle_of(&l, &test_ak(), &[]);
    assert_eq!(ev.facts.list_unreadable_after, Some(3));
    assert_eq!(ev.excluded, 1);
    assert_eq!(ev.instances[0].records.len(), 1, "what parsed is kept");
}

#[test]
fn nothing_valid_arrived() {
    let ev = bundle_of(&[], &test_ak(), &[]);
    let o = exec::join(Some(&c()), &ev, DeclaredPath::Direct);
    assert_eq!(o.kind, Kind::NothingToCompare);
    assert_eq!(o.path, anchorstamp_verify::Path::NothingArrived);
    let _ = Detail::Unobserved;
}

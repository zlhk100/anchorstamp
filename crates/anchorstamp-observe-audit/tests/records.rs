//! The observer's records: every one decodes and chains; control records
//! carry their profile-S data; an exec's subject is the LINUX_EXEC
//! observer form; the offset watch emits a clock step exactly when the
//! offset moves by more than the tolerance; framing is a u32 big-endian
//! length.

use anchorstamp_core::{
    CLASS_CLOCK_STEP, CLASS_COMMAND_EXECUTION, CLASS_INSTANCE_START, CLASS_PARSE_REJECT,
    CLASS_STREAM_ENDED, CoverageMode, ENDED_ROTATED, SchemeTag, SequenceSource, decode_sighting,
};
use anchorstamp_observe_audit::emit::{Chain, ClockWatch, TOLERANCE_NS, exe_digest, frame, lo_ns};
use anchorstamp_observe_audit::msg;
use anchorstamp_observe_audit::parse::{Arch, EXE_DATA_MAX, Exec};
use sha2::{Digest, Sha256};

fn chain_of(prior: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"anchorstamp/chain\0");
    h.update(prior);
    h.finalize().into()
}

fn long_exec() -> Exec {
    Exec {
        time_ms: 1_793_418_742_236,
        serial: 10446,
        arch: Arch::X86_64,
        syscall: 59,
        pid: 600_476,
        ppid: 600_475,
        exe: vec![b'd'; 1647],
        line_truncated: false,
    }
}

#[test]
fn records_decode_and_chain() {
    let instance = [0x42; 16];
    let boot = [0xb0; 16];
    let mut c = Chain::new(instance);
    let recs = [
        c.instance_start(boot, 5_000_000_000, TOLERANCE_NS),
        c.exec(&long_exec(), 7_000_000_000, 7_000_100_000),
        c.clock_step(9_000_000),
        c.parse_reject(1),
        c.stream_ended(ENDED_ROTATED),
    ];
    let mut prev = [0u8; 32];
    for (i, r) in recs.iter().enumerate() {
        let v = decode_sighting(r).unwrap();
        let p = v.parts;
        assert_eq!(p.seq.instance, instance);
        assert_eq!(p.seq.index, i as u64);
        assert_eq!(p.seq.prev, prev);
        assert_eq!(p.coverage.mode, CoverageMode::Mediated);
        assert_eq!(p.coverage.from, 0);
        assert_eq!(p.coverage.over, CLASS_COMMAND_EXECUTION);
        assert_eq!(p.source, SequenceSource::None);
        prev = chain_of(r);
    }

    let start = decode_sighting(&recs[0]).unwrap().parts;
    assert_eq!(start.subject.scheme(), SchemeTag::OBSERVER);
    assert_eq!(start.subject.bytes(), instance);
    assert_eq!(start.observed.class, CLASS_INSTANCE_START);
    let d = start.observed.data;
    assert_eq!(d.len(), 28);
    assert_eq!(&d[0..16], &boot);
    assert_eq!(&d[16..24], &5_000_000_000u64.to_be_bytes());
    assert_eq!(&d[24..28], &5_000_000u32.to_be_bytes());

    let ex = decode_sighting(&recs[1]).unwrap().parts;
    assert_eq!(ex.subject.scheme(), SchemeTag::LINUX_EXEC);
    let s = ex.subject.bytes();
    assert_eq!(s.len(), 52);
    assert_eq!(&s[0..4], &600_476u32.to_be_bytes());
    assert_eq!(&s[4..12], &7_000_000_000u64.to_be_bytes());
    assert_eq!(&s[12..20], &7_000_100_000u64.to_be_bytes());
    // the full 32-byte digest over the FULL path, not the truncated copy
    assert_eq!(&s[20..52], &exe_digest(&[b'd'; 1647]));
    assert_eq!(exe_digest(b"/usr/bin/true"), <[u8; 32]>::from(Sha256::digest(b"/usr/bin/true")));
    assert_ne!(&s[20..52], &exe_digest(&[b'd'; EXE_DATA_MAX]));
    assert_eq!(ex.observed.data[0], 1);
    assert_eq!(ex.observed.data.len(), 5 + EXE_DATA_MAX);

    let st = decode_sighting(&recs[2]).unwrap().parts;
    assert_eq!(
        (st.observed.class, st.observed.data),
        (CLASS_CLOCK_STEP, &9_000_000u64.to_be_bytes()[..])
    );
    let rj = decode_sighting(&recs[3]).unwrap().parts;
    assert_eq!(
        (rj.observed.class, rj.observed.data),
        (CLASS_PARSE_REJECT, &1u64.to_be_bytes()[..])
    );
    let en = decode_sighting(&recs[4]).unwrap().parts;
    assert_eq!((en.observed.class, en.observed.data), (CLASS_STREAM_ENDED, &[ENDED_ROTATED][..]));
}

#[test]
fn lo_converts_the_audit_time_to_the_boot_clock() {
    // audit 1_000_000.123 s wall clock; offset 999_000 s; tolerance 5 ms
    let off: i128 = 999_000 * 1_000_000_000;
    assert_eq!(lo_ns(1_000_000_123, off, 5_000_000), 1_000_123_000_000 - 5_000_000);
    // never below zero
    assert_eq!(lo_ns(0, off, 5_000_000), 0);
    assert_eq!(lo_ns(1, 0, 5_000_000), 0);
}

#[test]
fn clock_step_only_beyond_the_tolerance() {
    let mut w = ClockWatch::new(1_000_000_000, 5_000_000);
    assert_eq!(w.sample(1_000_000_000), None);
    assert_eq!(w.sample(1_004_000_000), None, "a 4 ms drift is inside 5 ms");
    // compared with the LAST sample, not the first
    assert_eq!(w.sample(1_008_000_000), None);
    assert_eq!(w.sample(1_013_000_001), Some(5_000_001));
    // a step back is a step too, by its absolute size
    assert_eq!(w.sample(1_000_000_000), Some(13_000_001));
    assert_eq!(w.sample(1_005_000_000), None, "exactly the tolerance is not a step");
}

#[test]
fn framing() {
    let f = frame(b"abc");
    assert_eq!(f, [0, 0, 0, 3, b'a', b'b', b'c']);
}

#[test]
fn fresh_instances_never_share_a_chain() {
    let a = Chain::new([1; 16]).instance_start([0; 16], 5, TOLERANCE_NS);
    let b = Chain::new([2; 16]).instance_start([0; 16], 5, TOLERANCE_NS);
    assert_ne!(
        decode_sighting(&a).unwrap().parts.seq.instance,
        decode_sighting(&b).unwrap().parts.seq.instance
    );
}

#[test]
fn the_start_line_declares_the_source_profile() {
    assert_eq!(msg::DECLARATION, "anchorstamp specification 0.4, layout 1, source profile S");
    assert!(msg::start("00", 1, 2).starts_with(&format!("start {}", msg::DECLARATION)));
    assert_eq!(msg::ready("ab", 7), "ready instance=ab cov_from=7");
}

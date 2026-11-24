// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright © 2026 Lei Zhou

//! The report on a fixture run directory built with the observer's own
//! record builder, and on a kernel bundle built by hand: the declaration,
//! verdict words per source, grouping, health, counters, refusals, the
//! kernel source's facts, and the statements every report prints.

use anchorstamp_core::{JOINREF_MAX_LEN, SchemeTag, SubjectRef, encode_joinref};
use anchorstamp_observe_audit::emit::{Chain, exe_digest, frame};
use anchorstamp_observe_audit::parse::{Arch, Exec};
use anchorstamp_verify::k::AK_SPKI_PREFIX;
use demo_report::*;

const BOOT: [u8; 16] = [0xb0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const TOL: u32 = 5_000_000;
const MS: u64 = 1_000_000;

fn exec(pid: u32, ppid: u32, exe: &str) -> Exec {
    Exec {
        time_ms: 0,
        serial: 0,
        arch: Arch::X86_64,
        syscall: 59,
        pid,
        ppid,
        exe: exe.as_bytes().to_vec(),
        line_truncated: false,
    }
}

fn claim(pid: u32, t0: u64, t_reap: u64, exe: &str) -> Vec<u8> {
    let mut b = [0u8; 60];
    b[0..4].copy_from_slice(&pid.to_be_bytes());
    b[4..12].copy_from_slice(&t0.to_be_bytes());
    b[12..20].copy_from_slice(&t_reap.to_be_bytes());
    b[20..52].copy_from_slice(&exe_digest(exe.as_bytes()));
    b[52..60].copy_from_slice(&BOOT[..8]);
    let mut out = [0u8; JOINREF_MAX_LEN];
    let n = encode_joinref(&SubjectRef::new(SchemeTag::LINUX_EXEC, &b).unwrap(), &mut out).unwrap();
    frame(&out[..n])
}

const STATUS_BEFORE: &str = "enabled 1\nfailure 1\nlost 0\nbacklog 0\n";
const STATUS_AFTER: &str = "enabled 1\nfailure 1\nlost 0\nbacklog 2\n";

/// The fixture's chain, records in ms on the boot clock.
fn chain() -> (Chain, Vec<u8>) {
    let mut c = Chain::new([0x11; 16]);
    let mut s = Vec::new();
    s.extend(frame(&c.instance_start(BOOT, 1000 * MS, TOL)));
    s.extend(frame(&c.exec(&exec(100, 1, "/usr/bin/dash"), 1100 * MS, 1101 * MS))); // claimed
    s.extend(frame(&c.exec(&exec(101, 100, "/usr/bin/ls"), 1101 * MS, 1102 * MS))); // child
    s.extend(frame(&c.exec(&exec(102, 100, "/usr/bin/wc"), 1099 * MS, 1100 * MS))); // earlier
    s.extend(frame(&c.exec(&exec(200, 1, "/usr/bin/id"), 1200 * MS, 1201 * MS))); // other
    let long = format!("/tmp/{}", "d".repeat(1100));
    s.extend(frame(&c.exec(&exec(300, 1, &long), 1300 * MS, 1301 * MS)));
    (c, s)
}

fn fixture() -> Inputs {
    let (_, s) = chain();
    let mut claims = Vec::new();
    claims.extend(claim(100, 1095 * MS, 1105 * MS, "/usr/bin/dash")); // corroborated
    claims.extend(claim(200, 1195 * MS, 1205 * MS, "/usr/bin/true")); // other file
    claims.extend(claim(u32::MAX - 1, 1250 * MS, 1250 * MS, "/usr/bin/true")); // never ran
    claims.extend(claim(9, 900 * MS, 950 * MS, "/usr/bin/true")); // before coverage
    Inputs {
        sightings: s,
        claims,
        harness: Harness {
            audit_before: Some(STATUS_BEFORE.into()),
            audit_after: Some(STATUS_AFTER.into()),
            agent_log: Some("START\nREFUSAL tamper probe write sink/sightings.bin: refused (permission denied)\nCLAIM x\n".into()),
            checks: Some("sink owned by root\n".into()),
        },
        kernel: None,
        notes: vec![],
    }
}

fn fixture_plus(add: impl FnOnce(&mut Chain) -> Vec<u8>) -> Inputs {
    let mut f = fixture();
    let (mut c, mut s) = chain();
    assert_eq!(s, f.sightings);
    s.extend(frame(&add(&mut c)));
    f.sightings = s;
    f
}

#[test]
fn the_first_line_declares_the_reader() {
    let r = render("fixture", &fixture());
    assert_eq!(r.lines().next(), Some("anchorstamp specification 0.4, layout 1, reader"));
    assert_eq!(DECLARATION, "anchorstamp specification 0.4, layout 1, reader");
}

#[test]
fn statements_always_printed() {
    let empty =
        Inputs { sightings: vec![], claims: vec![], harness: Harness::default(), kernel: None, notes: vec![] };
    for r in [render("fixture", &fixture()), render("empty", &empty)] {
        for s in [
            TRUNCATION_WINDOW,
            OUTSIDE_READER,
            SELF_DECLARED,
            LIBRARY,
            BOOT_ASSERTED,
            LIMIT_PID_REUSE,
            LIMIT_CAUSATION,
            LIMIT_SCRIPTS,
            LIMIT_ROOT,
            ANCHORING,
        ] {
            assert!(r.contains(s), "missing: {s}\n{r}");
        }
        assert!(r.contains("audit counters"));
    }
}

#[test]
fn software_source_agrees_or_says_nothing() {
    let r = render("fixture", &fixture());
    assert!(r.contains("#1 pid 100 window"), "{r}");
    assert!(r.contains("    S: CORROBORATED"), "{r}");
    assert!(r.contains("strength SOFTWARE (100)"));
    assert!(r.contains("the records are unsigned: their transport is the operator's word"));
    assert!(r.contains("the path is resolved in the task's own namespace and root, unchecked"));
    // the wrong file and the claim that never ran: nothing, never contradicted
    assert!(!r.contains("CONTRADICTED"), "{r}");
    assert_eq!(r.matches("S: NOTHING TO COMPARE - the software source agrees or says nothing").count(), 2, "{r}");
    assert!(r.contains("S: NOT COVERED"), "{r}");
    assert!(r.contains("this pid in the window, not matching: index 4 pid 200"), "{r}");
    assert!(r.contains("sources: S (run directory); no kernel bundle given"));
}

#[test]
fn grouping_needs_ppid_and_order() {
    let r = render("fixture", &fixture());
    assert!(r.contains("child of claimed pid 100: index 2 pid 101 ppid 100"), "{r}");
    assert!(r.contains("    index 3 pid 102 ppid 100"), "an earlier exec is not a child: {r}");
}

#[test]
fn health_counters_and_refusals() {
    let r = render("fixture", &fixture());
    assert!(r.contains("records read 6, valid 6, excluded 0"), "{r}");
    assert!(r.contains("gaps 0, chain breaks 0, forks 0"));
    assert!(r.contains("coverage mode Mediated, from 1000000000 ns on the boot clock"), "{r}");
    assert!(r.contains("(self-declared)"));
    assert!(r.contains("backlog: before 0, after 2, delta 2"));
    assert!(r.contains("REFUSAL tamper probe write sink/sightings.bin: refused"));
    assert!(r.contains("sink owned by root"));
    assert!(r.contains("pid reuse (S): 5 execution sightings, 5 distinct pids"));
}

#[test]
fn tampered_and_cut_streams_are_reported() {
    let mut f = fixture();
    // a byte of the third record's subject: it still parses, the chain breaks
    let at = 4 + (f.sightings.len() / 6) * 2;
    f.sightings[at + 40] ^= 1;
    let r = render("tampered", &f);
    assert!(r.contains("chain breaks 1") || r.contains("excluded 1"), "{r}");
    let mut f = fixture();
    f.sightings.truncate(f.sightings.len() - 3);
    let r = render("cut", &f);
    assert!(r.contains("sightings file unreadable after record 5"), "{r}");
}

#[test]
fn wording_stays_inside_the_outcome() {
    for f in [fixture(), with_kernel()] {
        let r = render("fixture", &f).to_lowercase();
        let (body, statements) = r.split_once("\nstatements\n").unwrap();
        let words = |t: &str| -> Vec<String> {
            t.split(|c: char| !c.is_ascii_alphanumeric()).filter(|w| !w.is_empty()).map(str::to_string).collect()
        };
        let body = words(body);
        for w in ["proven", "guarantee", "guaranteed", "secure", "complete", "verified", "trusted", "tamperproof"] {
            assert!(!body.contains(&w.to_string()), "{w} in the body");
            assert!(!words(statements).contains(&w.to_string()) || w == "trusted", "{w} in the statements");
        }
        for w in ["proves", "caused"] {
            assert!(!body.contains(&w.to_string()), "{w} outside the statements");
        }
    }
}

#[test]
fn untrusted_strings_are_escaped() {
    assert_eq!(escape(b"/a b\n\x1b[31m\\"), "/a\\x20b\\x0a\\x1b[31m\\x5c");
}

#[test]
fn framing() {
    let f = frames(&[0, 0, 0, 1, 7, 0, 0, 0, 2, 8, 9]);
    assert_eq!(f.records, vec![&[7u8][..], &[8, 9][..]]);
    assert!(f.unreadable_after.is_none());
    let f = frames(&[0, 0, 0, 1, 7, 0, 1, 0, 1]);
    assert_eq!(f.unreadable_after, Some(1));
    let mut big = vec![0, 1, 0, 1];
    big.extend(vec![0; 65_537]);
    assert_eq!(frames(&big).unreadable_after, Some(0));
}

#[test]
fn an_unparsed_line_is_a_hole() {
    let f = fixture_plus(|c| c.parse_reject(1));
    let r = render("reject", &f);
    assert!(r.contains("parse rejects 1, clock steps 0"), "{r}");
    assert!(r.contains("unclaimed list incomplete: 1 hole(s), 0 gap(s)"), "{r}");
    assert!(r.contains("touches this claim"));
    let f = fixture_plus(|c| c.clock_step(9 * MS));
    let r = render("step", &f);
    assert!(r.contains("parse rejects 0, clock steps 1"), "{r}");
}

#[test]
fn a_cut_path_is_shown() {
    let r = render("fixture", &fixture());
    assert!(r.contains("[path truncated in the record]"), "{r}");
}

// ---- kernel source ------------------------------------------------------

/// The RFC 6979 A.2.5 P-256 public key (a published test key; anchors
/// nothing), DER SubjectPublicKeyInfo.
fn test_ak() -> Vec<u8> {
    let h = "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";
    let mut b = AK_SPKI_PREFIX.to_vec();
    b.extend((0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()));
    b
}

fn rec(magic: &[u8; 4], kind: u8, seq: u64, body: &[u8]) -> Vec<u8> {
    let mut b = magic.to_vec();
    b.push(kind);
    b.extend_from_slice(&seq.to_le_bytes());
    b.extend_from_slice(&[0x4c; 16]);
    b.extend_from_slice(body);
    b
}

fn exec_v2(seq: u64, pid: u32, exec_ns: u64, path: &str) -> Vec<u8> {
    let mut b = Vec::new();
    for v in [pid, pid, 1, pid, 1001, 1001] {
        b.extend_from_slice(&v.to_le_bytes());
    }
    b.extend_from_slice(&(exec_ns - 10).to_le_bytes());
    b.extend_from_slice(&exec_ns.to_le_bytes());
    b.extend_from_slice(&1u32.to_le_bytes());
    b.extend_from_slice(&5u64.to_le_bytes());
    b.extend_from_slice(&exe_digest(path.as_bytes()));
    b.extend_from_slice(&exe_digest(path.as_bytes()));
    b.push(0);
    b.extend_from_slice(&u16::try_from(path.len()).unwrap().to_le_bytes());
    b.extend_from_slice(path.as_bytes());
    rec(b"ASX2", 1, seq, &b)
}

fn ima_list(records: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for r in records {
        let mut dng = b"sha256:\0".to_vec();
        dng.extend_from_slice(&exe_digest(r));
        let mut t = Vec::new();
        for f in [&dng[..], b"exec\0", r] {
            t.extend_from_slice(&u32::try_from(f.len()).unwrap().to_le_bytes());
            t.extend_from_slice(f);
        }
        out.extend_from_slice(&13u32.to_le_bytes());
        out.extend_from_slice(&[0; 20]);
        out.extend_from_slice(&7u32.to_le_bytes());
        out.extend_from_slice(b"ima-buf");
        out.extend_from_slice(&u32::try_from(t.len()).unwrap().to_le_bytes());
        out.extend_from_slice(&t);
    }
    out
}

fn kernel_inputs(ak: Vec<u8>) -> KInputs {
    let mut load = 2u16.to_le_bytes().to_vec();
    load.extend_from_slice(&(1000 * MS).to_le_bytes());
    let records = vec![
        rec(b"ASX2", 2, 0, &load),
        rec(b"ASX2", 5, 1, &(1050 * MS).to_le_bytes()),
        exec_v2(2, 100, 1100 * MS, "/usr/bin/dash"),
        exec_v2(3, 200, 1200 * MS, "/usr/bin/id"),
    ];
    KInputs {
        label: "bundle-fixture".into(),
        list: ima_list(&records),
        quotes: vec![],
        boot_id: Some(BOOT),
        interval_s: Some(5),
        ak,
        ak_label: "ak-pinned.der".into(),
        scope: vec![1001],
        nonce: Some(vec![0x22; 16]),
    }
}

fn with_kernel() -> Inputs {
    let mut f = fixture();
    f.kernel = Some(kernel_inputs(test_ak()));
    f
}

#[test]
fn kernel_source_facts_and_unattested_outcomes() {
    let r = render("k", &with_kernel());
    assert!(r.contains("sources: S (run directory), K (bundle)"), "{r}");
    assert!(r.contains("pinned locally by the operator from ak-pinned.der, not taken from the bundle"), "{r}");
    assert!(r.contains("quotes 0, valid 0"));
    assert!(r.contains("PCR-13 entries 4, attested 0"));
    assert!(r.contains("tail: 4 entries after the last valid quote: SOFTWARE, unanchored"), "{r}");
    assert!(r.contains("quote interval: every 5 s"));
    assert!(r.contains("nonce: NO valid quote carries the auditor's nonce"));
    assert!(r.contains("scope of the unclaimed list: uid or euid in {1001}"));
    assert!(r.contains("breaks 0"));
    // claim #1 agrees in the tail: SOFTWARE, unanchored, root can insert
    assert!(r.contains("    K: CORROBORATED"), "{r}");
    assert!(r.contains("the record comes after the last valid quote"));
    assert!(r.contains("root can add entries to PCR 13 from user space"));
    // claim #2 names another file than pid 200 ran, but in the tail: nothing
    assert!(!r.contains("CONTRADICTED"), "{r}");
    assert!(r.contains("K: NOTHING TO COMPARE - the attested records do not decide this claim"), "{r}");
    // the K unclaimed list: pid 200, uid 1001
    assert!(r.contains("K: execs in scope (1)"), "{r}");
}

#[test]
fn an_unusable_key_is_reported() {
    let mut f = with_kernel();
    let mut k = kernel_inputs(test_ak()[..90].to_vec());
    k.nonce = None;
    f.kernel = Some(k);
    let r = render("bad-ak", &f);
    assert!(r.contains("UNUSABLE - not a 91-byte P-256 key in the expected form"), "{r}");
    assert!(r.contains("nonce: no auditor nonce given"));
}

fn scratch(tag: &str) -> std::path::PathBuf {
    let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let d = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("{tag}-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn a_bundle_is_read_from_its_files_and_never_its_own_key() {
    let b = scratch("bundle");
    let k = kernel_inputs(test_ak());
    std::fs::write(b.join("ima.bin"), &k.list).unwrap();
    std::fs::write(b.join("boot_id"), "b0010203-0405-0607-0809-0a0b0c0d0e0f\n").unwrap();
    std::fs::write(b.join("interval"), "5\n").unwrap();
    std::fs::write(b.join("ak.pem"), "-----BEGIN PUBLIC KEY-----\nnot the pinned key\n").unwrap();
    std::fs::write(b.join("quote-1.msg"), b"x").unwrap();
    std::fs::write(b.join("quote-1.sig"), b"y").unwrap();
    std::fs::write(b.join("pcr7-1.bin"), [7u8; 32]).unwrap();
    std::fs::write(b.join("quote-2.msg"), b"x").unwrap(); // no .sig: not a quote
    let ak = b.join("pinned.der");
    std::fs::write(&ak, test_ak()).unwrap();
    let mut notes = Vec::new();
    let got = KInputs::read(&b, &ak, vec![1001], None, &mut notes);
    assert_eq!(got.list, k.list);
    assert_eq!(got.quotes.len(), 1);
    assert_eq!(got.boot_id, Some(BOOT));
    assert_eq!(got.interval_s, Some(5));
    assert_eq!(got.ak, test_ak(), "the key is the pinned file's, not ak.pem");
    let ev = got.evidence();
    assert_eq!((ev.facts.quotes, ev.facts.quotes_valid, ev.excluded), (1, 0, 1));
}

#[test]
fn bundle_arguments_are_all_or_nothing() {
    let run = scratch("cli");
    let bin = env!("CARGO_BIN_EXE_demo-report");
    let r = run.to_str().unwrap();
    let code = |args: &[&str]| std::process::Command::new(bin).args(args).output().unwrap().status.code();
    assert_eq!(code(&[r]), Some(0));
    assert_eq!(code(&[]), Some(2));
    assert_eq!(code(&[r, "--bundle", r]), Some(2), "a bundle needs --ak and --scope");
    assert_eq!(code(&[r, "--bundle", r, "--ak", r]), Some(2));
    assert_eq!(code(&[r, "--nonce", "11"]), Some(2), "a nonce needs a bundle");
    assert_eq!(code(&[r, "--bundle", r, "--ak", r, "--scope", "x"]), Some(2));
    assert_eq!(code(&[r, "--bundle", r, "--ak", r, "--scope", "1001,0", "--nonce", "1"]), Some(2));
    assert_eq!(code(&[r, "--bundle", r, "--ak", r, "--scope", "1001,0", "--nonce", "11"]), Some(0));
    let out = std::process::Command::new(bin).arg(r).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(text.lines().next(), Some(DECLARATION));
}

#[test]
fn inputs_never_follow_links_wait_on_fifos_or_read_past_the_cap() {
    let d = scratch("inputs");
    let mut notes = Vec::new();
    std::fs::write(d.join("plain"), b"abc").unwrap();
    assert_eq!(read_input(&d.join("plain"), &mut notes), Some(b"abc".to_vec()));
    assert_eq!(read_input(&d.join("absent"), &mut notes), None);
    assert!(notes.is_empty());
    std::os::unix::fs::symlink(d.join("plain"), d.join("link")).unwrap();
    assert_eq!(read_input(&d.join("link"), &mut notes), None);
    assert!(notes.last().unwrap().contains("not opened"), "{notes:?}");
    let st = std::process::Command::new("mkfifo").arg(d.join("fifo")).status().unwrap();
    assert!(st.success());
    assert_eq!(read_input(&d.join("fifo"), &mut notes), None);
    assert!(notes.last().unwrap().contains("not a regular file"), "{notes:?}");
    std::fs::create_dir(d.join("dir")).unwrap();
    assert_eq!(read_input(&d.join("dir"), &mut notes), None);
    let big = std::fs::File::create(d.join("big")).unwrap();
    big.set_len(READ_MAX + 10).unwrap();
    let got = read_input(&d.join("big"), &mut notes).unwrap();
    assert_eq!(got.len() as u64, READ_MAX);
    assert!(notes.last().unwrap().contains("only the first"), "{notes:?}");

    let run = scratch("run");
    std::fs::create_dir(run.join("sink")).unwrap();
    std::fs::create_dir(run.join("claims")).unwrap();
    let f = fixture();
    std::fs::write(run.join("sink/sightings.bin"), &f.sightings).unwrap();
    std::fs::write(run.join("real-claims"), &f.claims).unwrap();
    std::os::unix::fs::symlink(run.join("real-claims"), run.join("claims/claims.bin")).unwrap();
    let i = Inputs::read(&run);
    assert!(i.claims.is_empty());
    let r = render("linked", &i);
    assert!(r.contains("claims.bin: not opened"), "{r}");
    assert!(r.contains("claims (0)"));
}

#[test]
fn sample_report() {
    // printed with --nocapture for review of the wording
    eprintln!("{}", render("fixture", &with_kernel()));
}

//! The report on a fixture run directory built with the observer's own
//! record builder: verdict words, grouping, health, counters, refusals,
//! and the statements every report prints.

use anchorstamp_core::{JOINREF_MAX_LEN, SchemeTag, SubjectRef, encode_joinref};
use anchorstamp_observe_audit::emit::{Chain, exe_digest, frame};
use anchorstamp_observe_audit::parse::{Arch, Exec};
use demo_report::*;
use ed25519_dalek::SigningKey;

fn exec(pid: u32, ppid: u32, time_ms: u64, exe: &str) -> Exec {
    Exec {
        time_ms,
        serial: 0,
        arch: Arch::X86_64,
        syscall: 59,
        pid,
        ppid,
        exe: exe.as_bytes().to_vec(),
        line_truncated: false,
    }
}

fn claim(pid: u32, time_ms: u64, exe: &str) -> Vec<u8> {
    let mut b = [0u8; 32];
    b[0..4].copy_from_slice(&pid.to_be_bytes());
    b[4..12].copy_from_slice(&time_ms.to_be_bytes());
    b[12..32].copy_from_slice(&exe_digest(exe.as_bytes()));
    let mut out = [0u8; JOINREF_MAX_LEN];
    let n = encode_joinref(&SubjectRef::new(SchemeTag::DEMO, &b).unwrap(), &mut out).unwrap();
    frame(&out[..n])
}

const STATUS_BEFORE: &str = "enabled 1\nfailure 1\nlost 0\nbacklog 0\n";
const STATUS_AFTER: &str = "enabled 1\nfailure 1\nlost 0\nbacklog 2\n";

fn fixture() -> Inputs {
    // a published RFC 8032 test secret; anchors nothing
    let key = SigningKey::from_bytes(&[0x9d; 32]);
    let mut c = Chain::new(&key, [0x11; 16]);
    let mut s = Vec::new();
    s.extend(frame(&c.instance_start(1000)));
    s.extend(frame(&c.exec(&exec(100, 1, 1100, "/usr/bin/dash")))); // claimed
    s.extend(frame(&c.exec(&exec(101, 100, 1101, "/usr/bin/ls")))); // child of it
    s.extend(frame(&c.exec(&exec(102, 100, 1099, "/usr/bin/wc")))); // ppid matches, earlier
    s.extend(frame(&c.exec(&exec(200, 1, 1200, "/usr/bin/id")))); // other
    s.extend(frame(&c.exec(&exec(300, 1, 1300, &format!("/tmp/{}", "d".repeat(1100)))))); // long
    let mut claims = Vec::new();
    claims.extend(claim(100, 1101, "/usr/bin/dash")); // corroborated (time not compared)
    claims.extend(claim(200, 1200, "/usr/bin/true")); // mismatch
    claims.extend(claim(u32::MAX - 1, 1050, "/usr/bin/true")); // unobserved
    claims.extend(claim(9, 900, "/usr/bin/true")); // before coverage
    Inputs {
        sightings: s,
        anchor: Some(key.verifying_key().to_bytes()),
        claims,
        harness: Harness {
            audit_before: Some(STATUS_BEFORE.into()),
            audit_after: Some(STATUS_AFTER.into()),
            agent_log: Some("START\nREFUSAL tamper open-append sink/sightings.bin: refused (PermissionDenied)\nCLAIM x\n".into()),
            checks: Some("anchor sha256 unchanged\n".into()),
        },
        notes: vec![],
    }
}

/// The fixture's stream with one more record from the same chain.
fn fixture_plus(add: impl FnOnce(&mut Chain) -> Vec<u8>) -> Inputs {
    let mut f = fixture();
    let key = SigningKey::from_bytes(&[0x9d; 32]);
    // the same chain as the fixture, rebuilt so it can be extended
    let mut c = Chain::new(&key, [0x11; 16]);
    let mut s = Vec::new();
    s.extend(frame(&c.instance_start(1000)));
    s.extend(frame(&c.exec(&exec(100, 1, 1100, "/usr/bin/dash"))));
    s.extend(frame(&c.exec(&exec(101, 100, 1101, "/usr/bin/ls"))));
    s.extend(frame(&c.exec(&exec(102, 100, 1099, "/usr/bin/wc"))));
    s.extend(frame(&c.exec(&exec(200, 1, 1200, "/usr/bin/id"))));
    s.extend(frame(&c.exec(&exec(300, 1, 1300, &format!("/tmp/{}", "d".repeat(1100))))));
    assert_eq!(s, f.sightings, "fixture_plus replays the fixture");
    s.extend(frame(&add(&mut c)));
    f.sightings = s;
    f
}

#[test]
fn statements_always_printed() {
    let empty = Inputs {
        sightings: vec![],
        anchor: None,
        claims: vec![],
        harness: Harness::default(),
        notes: vec![],
    };
    for r in [render("fixture", &fixture()), render("empty", &empty)] {
        for s in [
            TRUNCATION_WINDOW,
            OUTSIDE_READER,
            SELF_DECLARED,
            LIBRARY,
            LIMIT_PID_REUSE,
            LIMIT_CAUSATION,
            LIMIT_SCRIPTS,
            ANCHORING,
        ] {
            assert!(r.contains(s), "missing: {s}\n{r}");
        }
        assert!(r.contains("cannot be distinguished from none"));
        assert!(r.contains("runs outside the measured account"));
        assert!(r.contains("audit counters"));
    }
}

#[test]
fn verdicts_in_words() {
    let r = render("fixture", &fixture());
    assert!(r.contains("#1 pid 100  CORROBORATED"), "{r}");
    assert!(r.contains("strength SOFTWARE (100)"));
    assert!(r.contains("the observer's sequence source is not appraised"));
    assert!(r.contains("the anchor is asserted by the operator"));
    assert!(r.contains("#2 pid 200  CONTRADICTED (subject mismatch)"));
    assert!(r.contains("this pid seen with another executable: index 4 exe /usr/bin/id"));
    assert!(r.contains(&format!("#3 pid {}  CONTRADICTED (unobserved)", u32::MAX - 1)));
    assert!(r.contains("#4 pid 9  NOT COVERED"));
}

#[test]
fn grouping_needs_ppid_and_order() {
    let r = render("fixture", &fixture());
    assert!(r.contains("child of claim #1: index 2 pid 101 ppid 100"), "{r}");
    // same ppid but earlier than the parent: not a child
    let others = r.split("other execs of the measured account").nth(1).unwrap();
    assert!(others.contains("index 3 pid 102 ppid 100"), "{r}");
    assert!(others.contains("index 4 pid 200"));
    assert!(others.contains("[path truncated in the record]"));
}

#[test]
fn health_counters_and_refusals() {
    let r = render("fixture", &fixture());
    assert!(r.contains("valid 6, excluded 0"), "{r}");
    assert!(r.contains("gaps 0, chain breaks 0, forks 0"));
    assert!(r.contains("parse rejects 0"));
    assert!(!r.contains("unclaimed list incomplete"));
    assert!(r.contains("coverage: mode Mediated, from 1000 ms (self-declared)"));
    assert!(r.contains("no stream-ended record"));
    assert!(r.contains("lost: before 0, after 0, delta 0"));
    assert!(r.contains("backlog: before 0, after 2, delta 2"));
    assert!(r.contains("REFUSAL tamper open-append sink/sightings.bin: refused"));
    assert!(r.contains("the measured account's own log"));
    assert!(r.contains("anchor sha256 unchanged"));
}

#[test]
fn tampered_and_cut_streams_are_reported() {
    let mut f = fixture();
    // flip a byte inside the second record (never a length)
    let n0 = u32::from_be_bytes(f.sightings[0..4].try_into().unwrap()) as usize;
    let at = 4 + n0 + 4 + 40;
    f.sightings[at] ^= 1;
    let r = render("t", &f);
    assert!(r.contains("excluded 1"), "{r}");
    assert!(r.contains("gaps 1"));
    assert!(
        r.contains("#1 pid 100  NOTHING TO COMPARE - a gap in the record touches the claim's time"),
        "{r}"
    );

    let mut f = fixture();
    f.sightings.extend_from_slice(&[0, 0, 0xff]);
    let r = render("cut", &f);
    assert!(r.contains("sightings file unreadable after record 6"), "{r}");
}

#[test]
fn wrong_anchor_validates_nothing() {
    let mut f = fixture();
    f.anchor = Some(SigningKey::from_bytes(&[0x42; 32]).verifying_key().to_bytes());
    let r = render("a", &f);
    assert!(r.contains("valid 0, excluded 6"), "{r}");
    assert!(r.contains("delivery path: nothing arrived"));
    assert!(!r.contains("CORROBORATED"));
}

#[test]
fn wording_stays_inside_the_outcome() {
    let r = render("fixture", &fixture()).to_lowercase();
    let (body, statements) = r.split_once("\nstatements\n").unwrap();
    let words = |t: &str| -> Vec<String> {
        t.split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|w| !w.is_empty())
            .map(str::to_string)
            .collect()
    };
    let body = words(body);
    // never claimed anywhere
    for w in [
        "proven",
        "guarantee",
        "guaranteed",
        "secure",
        "complete",
        "verified",
        "trusted",
        "tamperproof",
    ] {
        assert!(!body.contains(&w.to_string()), "{w} in the body");
        assert!(
            !words(statements).contains(&w.to_string()) || w == "trusted",
            "{w} in the statements"
        );
    }
    // only as the standing limits say it
    for w in ["proves", "caused"] {
        assert!(!body.contains(&w.to_string()), "{w} outside the statements");
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
fn sample_report() {
    // printed with --nocapture for review of the wording
    eprintln!("{}", render("fixture", &fixture()));
}

#[test]
fn an_unparsed_line_makes_the_unclaimed_list_incomplete() {
    let f = fixture_plus(|c| c.parse_reject(1));
    let r = render("reject", &f);
    assert!(r.contains("parse rejects 1"), "{r}");
    assert!(r.contains("unclaimed list incomplete: 1 records unparsed"), "{r}");
    // the claim that was Unobserved can no longer be
    assert!(!r.contains("CONTRADICTED (unobserved)"), "{r}");
    assert!(
        r.contains(&format!(
            "#3 pid {}  NOTHING TO COMPARE - the record holds 1 audit line(s) the observer could \
             not parse, any of which may be this exec",
            u32::MAX - 1
        )),
        "{r}"
    );
    assert!(r.contains("unparsed audit lines touch this claim"));
    // agreement and mismatch stand
    assert!(r.contains("#1 pid 100  CORROBORATED"));
    assert!(r.contains("#2 pid 200  CONTRADICTED (subject mismatch)"));
}

#[test]
fn a_cut_audit_line_is_shown() {
    let f = fixture_plus(|c| {
        let mut e = exec(400, 1, 1400, "/usr/bin/true");
        e.line_truncated = true;
        c.exec(&e)
    });
    let r = render("cut", &f);
    assert!(
        r.contains(
            "pid 400 ppid 1 time 1400 exe /usr/bin/true [audit line cut at the length limit]"
        ),
        "{r}"
    );
}

fn scratch(tag: &str) -> std::path::PathBuf {
    let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let d = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("{tag}-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn inputs_never_follow_links_wait_on_fifos_or_read_past_the_cap() {
    let d = scratch("inputs");
    let mut notes = Vec::new();
    // regular file: read
    std::fs::write(d.join("plain"), b"abc").unwrap();
    assert_eq!(read_input(&d.join("plain"), &mut notes), Some(b"abc".to_vec()));
    // absent: nothing, no note
    assert_eq!(read_input(&d.join("absent"), &mut notes), None);
    assert!(notes.is_empty());
    // symlink to a readable file: refused
    std::os::unix::fs::symlink(d.join("plain"), d.join("link")).unwrap();
    assert_eq!(read_input(&d.join("link"), &mut notes), None);
    assert!(notes.last().unwrap().contains("not opened"), "{notes:?}");
    // FIFO with no writer: refused at once, not waited on
    let st = std::process::Command::new("mkfifo").arg(d.join("fifo")).status().unwrap();
    assert!(st.success());
    assert_eq!(read_input(&d.join("fifo"), &mut notes), None);
    assert!(notes.last().unwrap().contains("not a regular file"), "{notes:?}");
    // directory: refused
    std::fs::create_dir(d.join("dir")).unwrap();
    assert_eq!(read_input(&d.join("dir"), &mut notes), None);
    // over the cap: the first READ_MAX bytes only, noted (a sparse file)
    let big = std::fs::File::create(d.join("big")).unwrap();
    big.set_len(READ_MAX + 10).unwrap();
    let got = read_input(&d.join("big"), &mut notes).unwrap();
    assert_eq!(got.len() as u64, READ_MAX);
    assert!(notes.last().unwrap().contains("only the first"), "{notes:?}");

    // a run directory whose claims file is a symlink to the real one
    let run = scratch("run");
    std::fs::create_dir(run.join("sink")).unwrap();
    std::fs::create_dir(run.join("claims")).unwrap();
    let f = fixture();
    std::fs::write(run.join("sink/sightings.bin"), &f.sightings).unwrap();
    std::fs::write(run.join("sink/anchor.pub"), f.anchor.unwrap()).unwrap();
    std::fs::write(run.join("real-claims"), &f.claims).unwrap();
    std::os::unix::fs::symlink(run.join("real-claims"), run.join("claims/claims.bin")).unwrap();
    let i = Inputs::read(&run);
    assert!(i.claims.is_empty());
    let r = render("linked", &i);
    assert!(r.contains("claims.bin: not opened"), "{r}");
    assert!(r.contains("claims (0)"));
}

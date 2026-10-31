//! The library's return contract.

use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::time::{SystemTime, UNIX_EPOCH};

use anchorstamp::{Cost, Field, Provenance, Status, open, provenance};
use anchorstamp_core::{SchemeTag, Strength, SubjectRef, Vantage};
use sha2::{Digest, Sha256};

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

fn split(s: &SubjectRef) -> (u32, u64, [u8; 20]) {
    let b = s.bytes();
    assert_eq!(s.scheme(), SchemeTag::DEMO);
    assert_eq!(b.len(), 32);
    (
        u32::from_be_bytes(b[0..4].try_into().unwrap()),
        u64::from_be_bytes(b[4..12].try_into().unwrap()),
        b[12..32].try_into().unwrap(),
    )
}

fn digest_of(path: &std::path::Path) -> [u8; 20] {
    let d: [u8; 32] = Sha256::digest(path.as_os_str().as_bytes()).into();
    d[..20].try_into().unwrap()
}

fn scratch(name: &str) -> std::path::PathBuf {
    let d = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn spawned_is_elevated_with_platform_subject() {
    let mut s = open();
    let before = now_ms();
    let out = s.exec_evidence("true", &[]);
    let after = now_ms();

    assert_eq!(out.result().status(), Status::Exited(0));
    assert_eq!(out.strength(), Strength::SOFTWARE);
    assert_eq!(out.cost(), Cost::Spawn);
    assert!(out.degraded().is_none());
    assert!(!out.backing().is_empty());

    let exe = out.result().exe().unwrap().to_path_buf();
    assert_eq!(exe, std::fs::canonicalize(&exe).unwrap(), "path is canonical");
    let Vantage::Elevated(j) = out.vantage() else { panic!("not elevated") };
    let (pid, t, d) = split(j.subject());
    assert!(pid > 0 && pid != std::process::id());
    assert!(before <= t && t <= after, "clock read during the call");
    assert_eq!(d, digest_of(&exe));
}

#[test]
fn subject_pid_is_the_child_pid() {
    let dir = scratch("pid");
    let f = dir.join("pid.txt");
    let script = format!("echo $$ > '{}'", f.display());
    let mut s = open();
    let out = s.exec_evidence("sh", &["-c", &script]);
    let Vantage::Elevated(j) = out.vantage() else { panic!("not elevated") };
    let (pid, _, d) = split(j.subject());
    let written: u32 = std::fs::read_to_string(&f).unwrap().trim().parse().unwrap();
    assert_eq!(pid, written);
    // /bin/sh resolves through its symlinks; the digest is of the target
    let canonical = std::fs::canonicalize(out.result().exe().unwrap()).unwrap();
    assert_eq!(d, digest_of(&canonical));
}

#[test]
fn symlinked_program_digests_the_canonical_path() {
    let dir = scratch("link");
    let link = dir.join("my-true");
    let target = std::fs::canonicalize("/usr/bin/true").unwrap();
    if std::fs::symlink_metadata(&link).is_err() {
        std::os::unix::fs::symlink(&target, &link).unwrap();
    }
    let mut s = open();
    let out = s.exec_evidence(link.to_str().unwrap(), &[]);
    let Vantage::Elevated(j) = out.vantage() else { panic!("not elevated") };
    assert_eq!(split(j.subject()).2, digest_of(&target));
    assert_eq!(out.result().exe().unwrap(), target);
}

#[test]
fn exit_status_is_reported() {
    let mut s = open();
    let out = s.exec_evidence("sh", &["-c", "exit 7"]);
    assert_eq!(out.result().status(), Status::Exited(7));
    assert!(matches!(out.vantage(), Vantage::Elevated(_)));
}

#[test]
fn unresolvable_is_local_and_says_why() {
    let mut s = open();
    for p in ["", "no-such-program-anywhere", "/no/such/path"] {
        let out = s.exec_evidence(p, &[]);
        assert!(matches!(out.vantage(), Vantage::Local), "{p:?}");
        assert_eq!(out.result().status(), Status::NotRun);
        assert!(out.degraded().is_some());
        assert_eq!(out.cost(), Cost::InProcess);
    }
}

#[test]
fn not_executable_is_local() {
    let dir = scratch("noexec");
    let f = dir.join("plain");
    std::fs::write(&f, b"#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
    let mut s = open();
    let out = s.exec_evidence(f.to_str().unwrap(), &[]);
    assert!(matches!(out.vantage(), Vantage::Local));
    assert!(out.degraded().is_some());
}

#[test]
fn unspawnable_is_local() {
    // executable bit set, but not a valid image and no interpreter line
    let dir = scratch("badimage");
    let f = dir.join("bad");
    std::fs::write(&f, [0u8, 1, 2, 3]).unwrap();
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut s = open();
    let out = s.exec_evidence(f.to_str().unwrap(), &[]);
    assert!(matches!(out.vantage(), Vantage::Local));
    assert_eq!(out.degraded(), Some("spawn failed"));
}

#[test]
fn provenance_is_total() {
    use Field::*;
    let expect = [
        (Result, Provenance::SdkAuthored),
        (Strength, Provenance::PlatformSourced),
        (Vantage, Provenance::SdkAuthored),
        (Backing, Provenance::PlatformSourced),
        (Degraded, Provenance::SdkAuthored),
        (Cost, Provenance::SdkAuthored),
    ];
    for (f, p) in expect {
        assert_eq!(provenance(f), p);
    }
}

#[test]
fn session_shared_behind_a_mutex() {
    let s = std::sync::Arc::new(std::sync::Mutex::new(open()));
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let s = s.clone();
            std::thread::spawn(move || {
                let out = s.lock().unwrap().exec_evidence("true", &[]);
                matches!(out.vantage(), Vantage::Elevated(_))
            })
        })
        .collect();
    assert!(handles.into_iter().all(|h| h.join().unwrap()));
}

//! The library's return contract, `LINUX_EXEC` subject.

use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;

use anchorstamp::{Cost, Field, Provenance, Status, open, provenance};
use anchorstamp_core::{SchemeTag, Strength, SubjectRef, Vantage};
use sha2::{Digest, Sha256};

/// `CLOCK_BOOTTIME` as the kernel reports it to anyone: the first field of
/// /proc/uptime is the same clock, to centiseconds.
fn boottime_floor_ns() -> u64 {
    let s = std::fs::read_to_string("/proc/uptime").unwrap();
    let (secs, frac) = s.split_whitespace().next().unwrap().split_once('.').unwrap();
    let cs: u64 = frac.parse().unwrap();
    secs.parse::<u64>().unwrap() * 1_000_000_000 + cs * 10_000_000
}

struct Parts {
    pid: u32,
    t0: u64,
    t_reap: u64,
    digest: [u8; 32],
    boot: [u8; 8],
}

fn split(s: &SubjectRef) -> Parts {
    let b = s.bytes();
    assert_eq!(s.scheme(), SchemeTag::LINUX_EXEC);
    assert_eq!(b.len(), 60);
    Parts {
        pid: u32::from_be_bytes(b[0..4].try_into().unwrap()),
        t0: u64::from_be_bytes(b[4..12].try_into().unwrap()),
        t_reap: u64::from_be_bytes(b[12..20].try_into().unwrap()),
        digest: b[20..52].try_into().unwrap(),
        boot: b[52..60].try_into().unwrap(),
    }
}

fn digest_of(path: &std::path::Path) -> [u8; 32] {
    Sha256::digest(path.as_os_str().as_bytes()).into()
}

fn this_boot() -> [u8; 8] {
    let s = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
    let hex: String = s.trim().chars().filter(|c| *c != '-').collect();
    let mut b = [0u8; 8];
    for (i, o) in b.iter_mut().enumerate() {
        *o = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
    }
    b
}

fn scratch(name: &str) -> std::path::PathBuf {
    let d = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn spawned_is_elevated_with_platform_subject() {
    let mut s = open();
    let before = boottime_floor_ns();
    let out = s.exec_evidence("true", &[]);
    let after = boottime_floor_ns() + 10_000_000;

    assert_eq!(out.result().status(), Status::Exited(0));
    assert_eq!(out.strength(), Strength::SOFTWARE);
    assert_eq!(out.cost(), Cost::Spawn);
    assert!(out.degraded().is_none());
    assert!(!out.backing().is_empty());

    let exe = out.result().exe().unwrap().to_path_buf();
    assert_eq!(exe, std::fs::canonicalize(&exe).unwrap(), "path is canonical");
    let Vantage::Elevated(j) = out.vantage() else { panic!("not elevated") };
    let p = split(j.subject());
    assert!(p.pid > 0 && p.pid != std::process::id());
    assert!(p.t0 <= p.t_reap, "t0 before t_reap");
    assert!(before <= p.t0 && p.t_reap <= after, "boot clock read during the call");
    assert_eq!(p.digest, digest_of(&exe));
    assert_eq!(p.boot, this_boot());
}

#[test]
fn subject_pid_is_the_child_pid() {
    let dir = scratch("pid");
    let f = dir.join("pid.txt");
    let script = format!("echo $$ > '{}'", f.display());
    let mut s = open();
    let out = s.exec_evidence("sh", &["-c", &script]);
    let Vantage::Elevated(j) = out.vantage() else { panic!("not elevated") };
    let p = split(j.subject());
    let written: u32 = std::fs::read_to_string(&f).unwrap().trim().parse().unwrap();
    assert_eq!(p.pid, written);
    // /bin/sh resolves through its symlinks; the digest is of the target
    let canonical = std::fs::canonicalize(out.result().exe().unwrap()).unwrap();
    assert_eq!(p.digest, digest_of(&canonical));
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
    assert_eq!(split(j.subject()).digest, digest_of(&target));
    assert_eq!(out.result().exe().unwrap(), target);
}

#[test]
fn script_is_elevated_with_the_script_path() {
    let dir = scratch("script");
    let f = dir.join("hello.sh");
    std::fs::write(&f, b"#!/bin/sh\nexit 3\n").unwrap();
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut s = open();
    let out = s.exec_evidence(f.to_str().unwrap(), &[]);
    assert_eq!(out.result().status(), Status::Exited(3));
    let Vantage::Elevated(j) = out.vantage() else { panic!("not elevated") };
    assert_eq!(split(j.subject()).digest, digest_of(&std::fs::canonicalize(&f).unwrap()));
}

#[test]
fn exit_status_is_reported() {
    let mut s = open();
    let out = s.exec_evidence("sh", &["-c", "exit 7"]);
    assert_eq!(out.result().status(), Status::Exited(7));
    assert!(matches!(out.vantage(), Vantage::Elevated(_)));
}

#[test]
fn signalled_child_is_reaped_and_elevated() {
    let mut s = open();
    let out = s.exec_evidence("sh", &["-c", "kill -9 $$"]);
    assert_eq!(out.result().status(), Status::Signalled(9));
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
fn neither_elf_nor_script_is_local_and_runs_nothing() {
    // executable, but no ELF magic and no #!: the C library would retry it
    // as a shell script, so the library refuses it before any spawn
    let dir = scratch("shebangless");
    let marker = dir.join("ran");
    let f = dir.join("plain-text");
    std::fs::write(&f, format!("touch '{}'\n", marker.display())).unwrap();
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut s = open();
    let out = s.exec_evidence(f.to_str().unwrap(), &[]);
    assert!(matches!(out.vantage(), Vantage::Local));
    assert_eq!(out.degraded(), Some("not an ELF or #! file"));
    assert_eq!(out.result().status(), Status::NotRun);
    assert!(!marker.exists(), "nothing ran");

    let g = dir.join("bad");
    std::fs::write(&g, [0u8, 1, 2, 3]).unwrap();
    std::fs::set_permissions(&g, std::fs::Permissions::from_mode(0o755)).unwrap();
    let out = s.exec_evidence(g.to_str().unwrap(), &[]);
    assert_eq!(out.degraded(), Some("not an ELF or #! file"));
}

#[test]
fn unspawnable_is_local() {
    // a #! script whose interpreter does not exist: exec fails
    let dir = scratch("badinterp");
    let f = dir.join("bad");
    std::fs::write(&f, b"#!/no/such/interpreter\n").unwrap();
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

// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright © 2026 Lei Zhou

//! The bridge, run unprivileged: one framed join reference per spawned
//! program, none for a program that does not resolve, and the program's
//! own exit status passed through.

use std::path::{Path, PathBuf};
use std::process::Command;

use anchorstamp_core::{SchemeTag, decode_joinref};

const BRIDGE: &str = env!("CARGO_BIN_EXE_anchorstamp-exec");

fn claims_path(name: &str) -> PathBuf {
    let p = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    match std::fs::remove_file(&p) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => panic!("remove {}: {e}", p.display()),
    }
    p
}

/// Runs the bridge; returns (exit code, the one stderr line it printed).
fn bridge(claims: &Path, argv: &[&str]) -> (i32, String) {
    let out = Command::new(BRIDGE).arg(claims).arg("--").args(argv).output().expect("spawn bridge");
    let stderr = String::from_utf8(out.stderr).expect("utf-8 stderr");
    let line = stderr.lines().filter(|l| l.starts_with("anchorstamp-exec:")).collect::<Vec<_>>();
    assert_eq!(line.len(), 1, "one bridge line for {argv:?}: {stderr:?}");
    (out.status.code().expect("bridge exited"), line[0].to_owned())
}

/// Splits (u32 big-endian length, record) frames; the file must end on a
/// frame boundary.
fn frames(b: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < b.len() {
        let len = b.get(at..at + 4).expect("length prefix");
        let n = usize::try_from(u32::from_be_bytes(len.try_into().expect("4 bytes")))
            .expect("length fits usize");
        out.push(b.get(at + 4..at + 4 + n).expect("whole record"));
        at += 4 + n;
    }
    out
}

#[test]
fn three_claims_and_exits_pass_through() {
    let claims = claims_path("bridge-at1.bin");
    let cases: [(&[&str], i32); 4] = [
        (&["/usr/bin/true"], 0),
        (&["/usr/bin/false"], 1),
        (&["/bin/sh", "-c", "exit 42"], 42),
        (&["anchorstamp-no-such-program"], 127),
    ];
    let mut claimed_pids = Vec::new();
    for (argv, want) in cases {
        let (code, line) = bridge(&claims, argv);
        assert_eq!(code, want, "exit of {argv:?}");
        if want == 127 {
            assert!(line.starts_with("anchorstamp-exec: no claim ("), "{line}");
        } else {
            let pid = line
                .strip_prefix("anchorstamp-exec: claim pid=")
                .unwrap_or_else(|| panic!("claim line: {line}"));
            claimed_pids.push(pid.parse::<u32>().expect("pid"));
        }
    }

    let bytes = std::fs::read(&claims).expect("read claims");
    let records = frames(&bytes);
    assert_eq!(records.len(), 3, "exactly three framed references");
    for (rec, pid) in records.iter().zip(&claimed_pids) {
        let s = decode_joinref(rec).expect("a join reference");
        assert_eq!(s.scheme(), SchemeTag::LINUX_EXEC);
        let b = s.bytes();
        assert_eq!(b.len(), 60);
        assert_eq!(u32::from_be_bytes(b[0..4].try_into().expect("4 bytes")), *pid);
    }
}

#[test]
fn missing_program_writes_nothing() {
    let claims = claims_path("bridge-missing.bin");
    let (code, line) = bridge(&claims, &["anchorstamp-no-such-program"]);
    assert_eq!(code, 127);
    assert!(line.starts_with("anchorstamp-exec: no claim ("), "{line}");
    assert_eq!(std::fs::metadata(&claims).expect("claims file opened first").len(), 0);
}

#[test]
fn usage_errors_run_nothing() {
    let claims = claims_path("bridge-usage.bin");
    for argv in
        [vec![], vec![claims.to_str().expect("utf-8 path")], vec!["x", "y", "--", "/usr/bin/true"]]
    {
        let out = Command::new(BRIDGE).args(&argv).output().expect("spawn bridge");
        assert_eq!(out.status.code(), Some(120), "usage {argv:?}");
    }
    assert!(!claims.exists());
}

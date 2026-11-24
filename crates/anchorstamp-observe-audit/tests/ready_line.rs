// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright © 2026 Lei Zhou

//! The observer's ready line, as its log writes it, matches the pattern
//! demo/run.sh waits for in its step 6. The pattern is read from run.sh and
//! applied by `grep -E` under `LC_ALL=C`, as run.sh applies it, so a change
//! to either side that breaks the wait fails here.

use std::io::Write;
use std::process::{Command, Stdio};

use anchorstamp_observe_audit::msg;

/// The one `until grep -qE '<pattern>' "$RUN/observer.log"` line of run.sh.
fn run_sh_ready_pattern() -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../demo/run.sh");
    let text = std::fs::read_to_string(path).unwrap();
    let lines: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("until grep -qE '") && l.contains("\"$RUN/observer.log\""))
        .collect();
    assert_eq!(lines.len(), 1, "run.sh must have one step-6 wait: {lines:?}");
    let rest = &lines[0][lines[0].find("grep -qE '").unwrap() + "grep -qE '".len()..];
    rest[..rest.find('\'').unwrap()].to_string()
}

/// True when `grep -qE pattern` finds `log` (as run.sh greps the log file).
fn grep_matches(pattern: &str, log: &str) -> bool {
    let mut child = Command::new("grep")
        .args(["-qE", "--", pattern])
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(log.as_bytes()).unwrap();
    match child.wait().unwrap().code() {
        Some(0) => true,
        Some(1) => false,
        other => panic!("grep failed: {other:?}"),
    }
}

/// The line as `log()` in the binary writes it: the prefix, the event, a newline.
fn logged(event: &str) -> String {
    format!("{}{event}\n", msg::PREFIX)
}

#[test]
fn ready_line_matches_the_run_sh_step_6_pattern() {
    let pattern = run_sh_ready_pattern();
    // The instance id as the binary formats it: 16 random bytes, lower hex.
    let instance: [u8; 16] = [
        0x00, 0x01, 0x7f, 0x80, 0x9a, 0xbc, 0xde, 0xff, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc,
        0xfe,
    ];
    let hex = instance.iter().fold(String::new(), |mut s, b| {
        std::fmt::Write::write_fmt(&mut s, format_args!("{b:02x}")).unwrap();
        s
    });
    for cov_from in [0, 1, u64::MAX] {
        let line = logged(&msg::ready(&hex, cov_from));
        assert!(grep_matches(&pattern, &line), "{pattern:?} does not match {line:?}");
    }
    // The pattern is anchored and exact: near misses do not match.
    let near = [
        logged(&msg::ready(&hex[..31], 1)),
        logged(&msg::ready(&hex.to_uppercase(), 1)),
        format!("{} extra\n", logged(&msg::ready(&hex, 1)).trim_end()),
        format!("x{}", logged(&msg::ready(&hex, 1))),
    ];
    for line in &near {
        assert!(!grep_matches(&pattern, line), "{pattern:?} matches {line:?}");
    }
}

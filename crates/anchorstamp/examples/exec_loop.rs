// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright © 2026 Lei Zhou

//! exec_loop — run a program N times and log each exec, for the evidence
//! run's timing and coverage checks. A test tool: not installed, never
//! run as root.
//!
//!   exec_loop claims <out-file> <n> <threads> -- <program> [args...]
//!   exec_loop timing <out-file> <n> <threads> -- <program> [args...]
//!
//! `n` execs in all, shared by `threads` threads (1 = sequential). One line
//! per exec is appended to `<out-file>`, which must not exist yet.
//!
//! claims  through the library's `exec_evidence`: pid, t0, `t_reap`, the
//!         vantage and the 60-byte subject in hex
//! timing  its own copy of the library's sequence with the same calls:
//!         t0 (boot clock before the spawn), spawn, t1 (boot clock right
//!         after `spawn()` returns), wait, `t_reap`; logs pid, t0, t1,
//!         `t_reap`

use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Command, Stdio, exit};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anchorstamp::open;
use anchorstamp_core::Vantage;
use rustix::time::{ClockId, clock_gettime};

const USAGE: &str = "usage: exec_loop <claims|timing> <out-file> <n> <threads> -- <program> [args...]";

fn usage() -> ! {
    eprintln!("{USAGE}");
    exit(2)
}

fn boottime_ns() -> u64 {
    let t = clock_gettime(ClockId::Boottime);
    let secs = u64::try_from(t.tv_sec).unwrap_or(0);
    let nanos = u64::try_from(t.tv_nsec).unwrap_or(0);
    secs * 1_000_000_000 + nanos
}

/// The effective uid, from /proc: this tool must not run as root.
fn euid() -> Option<u32> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    s.lines().find(|l| l.starts_with("Uid:"))?.split_whitespace().nth(2)?.parse().ok()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Claims,
    Timing,
}

/// One exec through the library.
fn claims(program: &str, args: &[&str]) -> String {
    let r = open().exec_evidence(program, args);
    match r.vantage() {
        Vantage::Elevated(j) => {
            let b = j.subject().bytes();
            let u64_at = |at: usize| u64::from_be_bytes(b[at..at + 8].try_into().expect("8 bytes"));
            let pid = u32::from_be_bytes(b[0..4].try_into().expect("4 bytes"));
            let hex = b.iter().fold(String::new(), |mut s, x| {
                let _ = write!(s, "{x:02x}");
                s
            });
            format!(
                "claims pid={pid} t0={} t_reap={} vantage=Elevated subject={hex}",
                u64_at(4),
                u64_at(12)
            )
        }
        Vantage::Local => {
            format!("claims vantage=Local degraded={:?}", r.degraded().unwrap_or(""))
        }
    }
}

/// One exec by the library's sequence, with t1 added.
fn timing(exe: &PathBuf, program: &str, args: &[&str]) -> String {
    let t0 = boottime_ns();
    let Ok(mut child) = Command::new(exe).arg0(program).args(args).stdin(Stdio::null()).spawn()
    else {
        return "timing spawn-failed".into();
    };
    let t1 = boottime_ns();
    let pid = child.id();
    let status = child.wait();
    let t_reap = boottime_ns();
    let exit = match status {
        Ok(s) => s.code().map_or_else(|| format!("signal {}", s.signal().unwrap_or(0)), |c| c.to_string()),
        Err(_) => "wait-failed".into(),
    };
    format!("timing pid={pid} t0={t0} t1={t1} t_reap={t_reap} exit={exit}")
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let Some(sep) = a.iter().position(|x| x == "--") else { usage() };
    if sep != 5 || a.len() <= sep + 1 {
        usage();
    }
    let mode = match a[1].as_str() {
        "claims" => Mode::Claims,
        "timing" => Mode::Timing,
        _ => usage(),
    };
    let (Ok(n), Ok(threads)) = (a[3].parse::<u64>(), a[4].parse::<u64>()) else { usage() };
    if n == 0 || threads == 0 {
        usage();
    }
    if euid().is_none_or(|u| u == 0) {
        eprintln!("exec_loop: refusing to run as root (or with an unreadable uid)");
        exit(2);
    }
    let program = a[sep + 1].clone();
    let args: Vec<String> = a[sep + 2..].to_vec();
    let exe = std::fs::canonicalize(&program).unwrap_or_else(|_| PathBuf::from(&program));
    let out: File = OpenOptions::new().append(true).create_new(true).open(&a[2]).unwrap_or_else(|e| {
        eprintln!("exec_loop: cannot create {}: {}", a[2], e.kind());
        exit(2)
    });
    let out = Arc::new(Mutex::new(out));
    let next = Arc::new(AtomicU64::new(0));
    let handles: Vec<_> = (0..threads)
        .map(|_| {
            let (out, next, program, args, exe) =
                (out.clone(), next.clone(), program.clone(), args.clone(), exe.clone());
            std::thread::spawn(move || {
                let argv: Vec<&str> = args.iter().map(String::as_str).collect();
                while next.fetch_add(1, Ordering::SeqCst) < n {
                    let line = match mode {
                        Mode::Claims => claims(&program, &argv),
                        Mode::Timing => timing(&exe, &program, &argv),
                    };
                    let mut f = out.lock().expect("output lock");
                    if writeln!(f, "{line}").is_err() {
                        eprintln!("exec_loop: write failed");
                        exit(1);
                    }
                }
            })
        })
        .collect();
    for h in handles {
        if h.join().is_err() {
            eprintln!("exec_loop: a thread failed");
            exit(1);
        }
    }
}

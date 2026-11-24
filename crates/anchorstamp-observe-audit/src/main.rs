// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright © 2026 Lei Zhou

//! The observer process, a profile S source. Started by the run harness
//! as root: opens its files, fixes its read position in the audit log,
//! reads the boot id and the boot clock, drops to nobody, verifies the
//! drop, writes its instance-start record and logs that it is ready. From
//! then on it reads the audit log and appends sightings until SIGTERM or
//! until the log stops being the log.
//!
//! It holds no key: its records are unsigned, delivered at SOFTWARE with
//! the transport asserted by the operator.

use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anchorstamp_core::{ENDED_READ_ERROR, ENDED_ROTATED, ENDED_SHRUNK};
use anchorstamp_observe_audit::emit::{Chain, ClockWatch, TOLERANCE_NS, frame, lo_ns};
use anchorstamp_observe_audit::msg;
use anchorstamp_observe_audit::parse::{Line, LineBuf, classify};
use rustix::time::{ClockId, clock_gettime};

const NOBODY: libc::uid_t = 65534;
const BLOCK: usize = 64 * 1024;
const POLL: Duration = Duration::from_millis(50);

/// Exit codes.
const EXIT_STREAM_ENDED: i32 = 1;
const EXIT_START: i32 = 2;
const EXIT_SINK: i32 = 4;

static TERM: AtomicBool = AtomicBool::new(false);

extern "C" fn on_term(_: libc::c_int) {
    TERM.store(true, Ordering::SeqCst);
}

fn log(event: &str) {
    eprintln!("{}{event}", msg::PREFIX);
}

fn fail(code: i32, what: &str) -> ! {
    log(&msg::error(what));
    exit(code)
}

struct Args {
    audit_log: PathBuf,
    sink: PathBuf,
    /// The audit rule key: only exec records carrying it are the run's.
    key: Vec<u8>,
}

fn args() -> Args {
    let usage = msg::USAGE;
    let mut audit_log = None;
    let mut sink = None;
    let mut key = None;
    let mut it = std::env::args_os().skip(1);
    while let Some(flag) = it.next() {
        let Some(v) = it.next() else { fail(EXIT_START, usage) };
        match flag.to_str() {
            Some("--audit-log") => audit_log = Some(PathBuf::from(v)),
            Some("--sink") => sink = Some(PathBuf::from(v)),
            Some("--key") => key = Some(v.into_encoded_bytes()),
            _ => fail(EXIT_START, usage),
        }
    }
    let (Some(audit_log), Some(sink), Some(key)) = (audit_log, sink, key) else {
        fail(EXIT_START, usage)
    };
    if key.is_empty() {
        fail(EXIT_START, usage);
    }
    Args { audit_log, sink, key }
}

fn create_exclusive(path: &Path, mode: u32) -> File {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(mode)
        .open(path)
        .unwrap_or_else(|e| fail(EXIT_START, &format!("create {} failed: {e}", path.display())))
}

fn ns(clock: ClockId) -> i128 {
    let t = clock_gettime(clock);
    i128::from(t.tv_sec) * 1_000_000_000 + i128::from(t.tv_nsec)
}

/// `CLOCK_BOOTTIME` in nanoseconds.
fn boottime_ns() -> u64 {
    u64::try_from(ns(ClockId::Boottime)).unwrap_or(0)
}

/// Realtime minus boottime, ns: what converts an audit timestamp (wall
/// clock) to the boot clock.
fn offset_ns() -> i128 {
    let boot = ns(ClockId::Boottime);
    ns(ClockId::Realtime) - boot
}

/// The boot id, 16 bytes in printed order.
fn read_boot_id() -> [u8; 16] {
    let text = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .unwrap_or_else(|_| fail(EXIT_START, "boot id unreadable"));
    let digits: Vec<u8> = text.trim_end_matches('\n').bytes().filter(|&b| b != b'-').collect();
    if digits.len() != 32 || !digits.iter().all(u8::is_ascii_hexdigit) {
        fail(EXIT_START, "boot id malformed");
    }
    let mut out = [0u8; 16];
    for (i, o) in out.iter_mut().enumerate() {
        let pair = std::str::from_utf8(&digits[2 * i..2 * i + 2]).expect("ascii hex");
        *o = u8::from_str_radix(pair, 16).expect("hex digits");
    }
    out
}

/// Yama's ptrace scope must be at least 1 (only a parent may attach), so a
/// process of the measured account cannot attach to the observer.
fn check_ptrace_scope() {
    let scope = std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or_else(|| fail(EXIT_START, "ptrace_scope unreadable"));
    log(&msg::ptrace_scope(scope));
    if scope < 1 {
        fail(EXIT_START, "ptrace_scope below 1");
    }
}

/// setgroups(0), setresgid and setresuid to nobody; then dumpable 0,
/// asserted, and the ids and groups asserted. Any failure ends the start
/// before the instance-start record is written.
fn drop_privilege() {
    // SAFETY: plain syscalls on this process's credentials; arguments are
    // constants and a null group list of length zero.
    unsafe {
        if libc::setgroups(0, std::ptr::null()) != 0 {
            fail(EXIT_START, "setgroups failed");
        }
        if libc::setresgid(NOBODY, NOBODY, NOBODY) != 0 {
            fail(EXIT_START, "setresgid failed");
        }
        if libc::setresuid(NOBODY, NOBODY, NOBODY) != 0 {
            fail(EXIT_START, "setresuid failed");
        }
        // setresuid resets dumpable; set it after the drop.
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            fail(EXIT_START, "prctl PR_SET_DUMPABLE failed");
        }
        let dumpable = libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0);
        if dumpable != 0 {
            fail(EXIT_START, &format!("dumpable reads {dumpable} after the drop"));
        }
        let (mut r, mut e, mut s) = (0, 0, 0);
        if libc::getresuid(&mut r, &mut e, &mut s) != 0 || [r, e, s] != [NOBODY; 3] {
            fail(EXIT_START, "uids are not all nobody after the drop");
        }
        let (mut r, mut e, mut s) = (0, 0, 0);
        if libc::getresgid(&mut r, &mut e, &mut s) != 0 || [r, e, s] != [NOBODY; 3] {
            fail(EXIT_START, "gids are not all nobody after the drop");
        }
        if libc::getgroups(0, std::ptr::null_mut()) != 0 {
            fail(EXIT_START, "supplementary groups remain after the drop");
        }
        log(&msg::dropped(dumpable));
    }
}

/// What the audit descriptor currently names. Rotation renames the file,
/// so the name changes while the descriptor still reads the old one.
fn fd_name(fd: i32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/self/fd/{fd}")).ok()
}

struct Observer {
    audit: File,
    audit_name: PathBuf,
    offset: u64,
    lines: LineBuf,
    sink: File,
    chain: Chain,
    clock: ClockWatch,
    run_key: Vec<u8>,
    rejects: u64,
    execs: u64,
}

impl Observer {
    fn write(&mut self, rec: &[u8]) {
        if self.sink.write_all(&frame(rec)).is_err() {
            fail(EXIT_SINK, "sink write failed");
        }
    }

    /// Read to end of file. Per read: the boot clock and the offset are
    /// sampled once the bytes are in; a CLOCK_STEP precedes the read's
    /// records when the offset moved; then a record per exec and per
    /// reject.
    fn drain(&mut self, buf: &mut [u8]) {
        loop {
            let n = match self.audit.read_at(buf, self.offset) {
                Ok(0) => return,
                Ok(n) => n,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(_) => self.end(ENDED_READ_ERROR, "read error"),
            };
            let hi = boottime_ns();
            let off = offset_ns();
            self.offset += n as u64;
            if let Some(change) = self.clock.sample(off) {
                log(&msg::clock_step(self.chain.next_index(), change));
                let rec = self.chain.clock_step(change);
                self.write(&rec);
            }
            let mut found: Vec<Line> = Vec::new();
            let key = &self.run_key;
            self.lines.feed(&buf[..n], &mut |line, truncated| match classify(line, truncated, key) {
                Line::Other => {}
                l => found.push(l),
            });
            for l in found {
                let rec = if let Line::Exec(e) = l {
                    self.execs += 1;
                    log(&msg::sighting(
                        self.chain.next_index(),
                        e.pid,
                        e.ppid,
                        e.syscall,
                        e.exe.len(),
                    ));
                    self.chain.exec(&e, lo_ns(e.time_ms, off, TOLERANCE_NS), hi)
                } else {
                    self.rejects += 1;
                    log(&msg::parse_reject(self.chain.next_index(), self.rejects));
                    self.chain.parse_reject(self.rejects)
                };
                self.write(&rec);
            }
        }
    }

    fn end(&mut self, reason: u8, why: &str) -> ! {
        let rec = self.chain.stream_ended(reason);
        self.write(&rec);
        log(&msg::stream_ended(reason, why, self.execs, self.rejects, self.offset));
        exit(EXIT_STREAM_ENDED)
    }

    fn run(&mut self) -> ! {
        let mut buf = vec![0u8; BLOCK];
        loop {
            let stopping = TERM.load(Ordering::SeqCst);
            self.drain(&mut buf);
            match self.audit.metadata() {
                Ok(m) if m.len() < self.offset => self.end(ENDED_SHRUNK, "log shrank"),
                Ok(_) => {}
                Err(_) => self.end(ENDED_READ_ERROR, "fstat failed"),
            }
            if fd_name(self.audit.as_raw_fd()).as_deref() != Some(self.audit_name.as_path()) {
                self.drain(&mut buf);
                self.end(ENDED_ROTATED, "log renamed or removed");
            }
            if stopping {
                log(&msg::stopped(self.execs, self.rejects, self.lines.pending(), self.offset));
                exit(0)
            }
            std::thread::sleep(POLL);
        }
    }
}

fn main() {
    let a = args();
    // SAFETY: installing an async-signal-safe handler that only stores to
    // an atomic; umask is a plain syscall.
    unsafe {
        libc::signal(libc::SIGTERM, on_term as *const () as libc::sighandler_t);
        libc::umask(0o022);
    }

    // 1  the audit log, read only; fix the read position
    let audit = File::open(&a.audit_log)
        .unwrap_or_else(|e| fail(EXIT_START, &format!("open audit log failed: {e}")));
    let audit_name = std::fs::canonicalize(&a.audit_log)
        .unwrap_or_else(|_| fail(EXIT_START, "canonicalize audit log failed"));
    let offset =
        audit.metadata().unwrap_or_else(|_| fail(EXIT_START, "fstat audit log failed")).len();
    let mut last = [0u8; 1];
    let mid_line =
        offset > 0 && audit.read_at(&mut last, offset - 1).ok() == Some(1) && last[0] != b'\n';

    // 2  the boot id; coverage starts on the boot clock after the read
    // position is fixed; the first offset sample
    let boot_id = read_boot_id();
    let cov_from = boottime_ns();
    let clock = ClockWatch::new(offset_ns(), TOLERANCE_NS);

    // 3  the sink, created exclusively
    let mut sink = create_exclusive(&a.sink.join("sightings.bin"), 0o644);

    check_ptrace_scope();

    // 4  the instance id from the kernel's random source
    let mut instance = [0u8; 16];
    if getrandom::fill(&mut instance).is_err() {
        fail(EXIT_START, "random source failed");
    }
    let instance_hex: String = instance.iter().map(|b| format!("{b:02x}")).collect();
    log(&msg::start(&instance_hex, cov_from, offset));

    // 5  drop, dumpable 0, verify
    drop_privilege();
    if fd_name(audit.as_raw_fd()).as_deref() != Some(audit_name.as_path()) {
        fail(EXIT_START, "cannot watch the audit log name after the drop");
    }

    // 6  index 0: the instance start, Mediated (an exec audit rule mediates
    // every exec of the run's key); then the ready line, last
    let mut chain = Chain::new(instance);
    let rec = chain.instance_start(boot_id, cov_from, TOLERANCE_NS);
    if sink.write_all(&frame(&rec)).is_err() || sink.sync_data().is_err() {
        fail(EXIT_SINK, "sink write failed");
    }
    log(&msg::ready(&instance_hex, cov_from));

    // 7  the read loop
    Observer {
        audit,
        audit_name,
        offset,
        lines: LineBuf::new(mid_line),
        sink,
        chain,
        clock,
        run_key: a.key,
        rejects: 0,
        execs: 0,
    }
    .run()
}

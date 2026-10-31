//! The observer process. Started by the run harness as root; opens its
//! files, generates its key, drops to nobody, verifies the drop, and only
//! then publishes its public key. From then on it reads the audit log and
//! appends sightings until SIGTERM or until the log stops being the log.
//!
//! The signing key exists in memory only. It is never written, logged,
//! printed or placed in an error, except by the `leak-test` build.

use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anchorstamp_core::{ENDED_READ_ERROR, ENDED_ROTATED, ENDED_SHRUNK};
use anchorstamp_observe_audit::emit::{Chain, frame};
use anchorstamp_observe_audit::parse::{Line, LineBuf, classify};
use ed25519_dalek::SigningKey;

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
    eprintln!("observe-audit: {event}");
}

fn fail(code: i32, what: &str) -> ! {
    log(&format!("error {what}"));
    exit(code)
}

struct Args {
    audit_log: PathBuf,
    sink: PathBuf,
    key: Vec<u8>,
    #[cfg(feature = "leak-test")]
    leak_key_file: PathBuf,
}

fn args() -> Args {
    let usage = "usage: anchorstamp-observe-audit --audit-log PATH --sink DIR --key KEY";
    let mut audit_log = None;
    let mut sink = None;
    let mut key = None;
    #[cfg(feature = "leak-test")]
    let mut leak_key_file = None;
    let mut it = std::env::args_os().skip(1);
    while let Some(flag) = it.next() {
        let Some(v) = it.next() else { fail(EXIT_START, usage) };
        match flag.to_str() {
            Some("--audit-log") => audit_log = Some(PathBuf::from(v)),
            Some("--sink") => sink = Some(PathBuf::from(v)),
            Some("--key") => key = Some(v.into_encoded_bytes()),
            #[cfg(feature = "leak-test")]
            Some("--leak-key-file") => leak_key_file = Some(PathBuf::from(v)),
            _ => fail(EXIT_START, usage),
        }
    }
    let (Some(audit_log), Some(sink), Some(key)) = (audit_log, sink, key) else {
        fail(EXIT_START, usage)
    };
    if key.is_empty() {
        fail(EXIT_START, usage);
    }
    Args {
        audit_log,
        sink,
        key,
        #[cfg(feature = "leak-test")]
        leak_key_file: leak_key_file
            .unwrap_or_else(|| fail(EXIT_START, "leak-test build needs --leak-key-file")),
    }
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

fn wall_clock_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Lock `len` bytes at `ptr` into memory.
fn mlock(ptr: *const u8, len: usize, what: &str) {
    // SAFETY: the range is a live heap allocation owned by the caller.
    if unsafe { libc::mlock(ptr.cast(), len) } != 0 {
        fail(EXIT_START, &format!("mlock {what} failed"));
    }
}

fn zero(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid, exclusive reference.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
}

/// setgroups(0), setresgid and setresuid to nobody; then dumpable 0,
/// asserted, and the ids and groups asserted. Any failure ends the start
/// before the public key is written.
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
    }
    log("dropped uid=65534 gid=65534 groups=0 dumpable=0");
}

/// What the audit descriptor currently names. Rotation renames the file,
/// so the name changes while the descriptor still reads the old one.
fn fd_name(fd: i32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/self/fd/{fd}")).ok()
}

struct Observer<'k> {
    audit: File,
    audit_name: PathBuf,
    offset: u64,
    lines: LineBuf,
    sink: File,
    chain: Chain<'k>,
    run_key: Vec<u8>,
    rejects: u64,
    execs: u64,
}

impl Observer<'_> {
    fn write(&mut self, rec: &[u8]) {
        if self.sink.write_all(&frame(rec)).is_err() {
            fail(EXIT_SINK, "sink write failed");
        }
    }

    /// Read to end of file, emitting a record per exec and per reject.
    fn drain(&mut self, buf: &mut [u8]) {
        loop {
            let n = match self.audit.read_at(buf, self.offset) {
                Ok(0) => return,
                Ok(n) => n,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(_) => self.end(ENDED_READ_ERROR, "read error"),
            };
            self.offset += n as u64;
            let mut found: Vec<Line> = Vec::new();
            let key = &self.run_key;
            self.lines.feed(
                &buf[..n],
                &mut |line, truncated| match classify(line, truncated, key) {
                    Line::Other => {}
                    l => found.push(l),
                },
            );
            for l in found {
                let rec = match l {
                    Line::Exec(e) => {
                        self.execs += 1;
                        log(&format!(
                            "sighting index={} pid={} ppid={} syscall={} exe_len={}",
                            self.chain.next_index(),
                            e.pid,
                            e.ppid,
                            e.syscall,
                            e.exe.len()
                        ));
                        self.chain.exec(&e)
                    }
                    _ => {
                        self.rejects += 1;
                        log(&format!(
                            "parse-reject index={} count={}",
                            self.chain.next_index(),
                            self.rejects
                        ));
                        self.chain.parse_reject(self.rejects)
                    }
                };
                self.write(&rec);
            }
        }
    }

    fn end(&mut self, reason: u8, why: &str) -> ! {
        let rec = self.chain.stream_ended(reason);
        self.write(&rec);
        log(&format!(
            "stream-ended reason={reason} ({why}) execs={} rejects={} offset={}",
            self.execs, self.rejects, self.offset
        ));
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
                log(&format!(
                    "stopped on SIGTERM execs={} rejects={} pending_bytes={} offset={}",
                    self.execs,
                    self.rejects,
                    self.lines.pending(),
                    self.offset
                ));
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

    // 1  the audit log, read only; record where coverage starts
    let audit = File::open(&a.audit_log)
        .unwrap_or_else(|e| fail(EXIT_START, &format!("open audit log failed: {e}")));
    let audit_name = std::fs::canonicalize(&a.audit_log)
        .unwrap_or_else(|_| fail(EXIT_START, "canonicalize audit log failed"));
    let offset =
        audit.metadata().unwrap_or_else(|_| fail(EXIT_START, "fstat audit log failed")).len();
    let coverage_from_ms = wall_clock_ms();
    let mut last = [0u8; 1];
    let mid_line =
        offset > 0 && audit.read_at(&mut last, offset - 1).ok() == Some(1) && last[0] != b'\n';

    // 2, 3  the sink and the anchor, created exclusively
    let mut sink = create_exclusive(&a.sink.join("sightings.bin"), 0o644);
    let mut anchor = create_exclusive(&a.sink.join("anchor.pub"), 0o644);

    // 4, 5  key and instance id from the kernel's random source; the seed
    // and the key live in locked heap memory
    let mut seed = Box::new([0u8; 32]);
    mlock(seed.as_ptr(), seed.len(), "seed");
    if getrandom::fill(&mut seed[..]).is_err() {
        fail(EXIT_START, "random source failed");
    }
    let mut instance = [0u8; 16];
    if getrandom::fill(&mut instance).is_err() {
        fail(EXIT_START, "random source failed");
    }
    let key = Box::new(SigningKey::from_bytes(&seed));
    mlock((&*key as *const SigningKey).cast(), size_of::<SigningKey>(), "key");
    #[cfg(feature = "leak-test")]
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o400)
            .open(&a.leak_key_file)
            .unwrap_or_else(|_| fail(EXIT_START, "leak-test export failed"));
        if f.write_all(&seed[..]).is_err() {
            fail(EXIT_START, "leak-test export failed");
        }
        log("LEAK-TEST BUILD: key exported for the leak search");
    }
    zero(&mut seed[..]);
    let instance_hex: String = instance.iter().map(|b| format!("{b:02x}")).collect();
    log(&format!(
        "start instance={instance_hex} coverage_from_ms={coverage_from_ms} offset={offset}"
    ));

    // 6, 7, 8  drop, dumpable 0, verify
    drop_privilege();
    if fd_name(audit.as_raw_fd()).as_deref() != Some(audit_name.as_path()) {
        fail(EXIT_START, "cannot watch the audit log name after the drop");
    }

    // index 0: the instance start; then the anchor, last
    let mut chain = Chain::new(&key, instance);
    let rec = chain.instance_start(coverage_from_ms);
    if sink.write_all(&frame(&rec)).is_err() {
        fail(EXIT_SINK, "sink write failed");
    }
    if anchor.write_all(key.verifying_key().as_bytes()).is_err() || anchor.sync_all().is_err() {
        fail(EXIT_START, "anchor write failed");
    }
    drop(anchor);
    log("anchor written; reading");

    // 10  the read loop
    Observer {
        audit,
        audit_name,
        offset,
        lines: LineBuf::new(mid_line),
        sink,
        chain,
        run_key: a.key,
        rejects: 0,
        execs: 0,
    }
    .run()
}

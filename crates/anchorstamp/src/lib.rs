//! anchorstamp — the library. Runs inside the measured domain and is not a
//! trusted component.
//!
//! Declares: anchorstamp specification 0.4, layout 1, producer.
//!
//! `exec_evidence` runs one command and returns its outcome with what backs
//! it. When the command was spawned and reaped, the vantage is Elevated and
//! carries a join reference in the `LINUX_EXEC` scheme whose subject comes
//! from platform state: the child's process id, the boot clock
//! (`CLOCK_BOOTTIME`) read before the spawn and after the child was reaped,
//! a SHA-256 digest of the canonical executable path that was passed to
//! exec, and the first eight bytes of the boot id. Nothing the caller
//! passes sets strength, vantage or backing, and every call returns.
//!
//! The vantage is Local, with the reason in `degraded`, whenever a platform
//! fact the subject needs cannot be established: the program does not
//! resolve, is neither an ELF image nor a `#!` script, the boot id cannot
//! be read, the process is not in the initial PID and time namespaces, the
//! spawn fails, or waiting does not return the child's exit.
//!
//! The library sends nothing anywhere and knows of no other component.

mod backed;

use std::ffi::OsStr;
use std::io::Read as _;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use anchorstamp_core::{JoinRef, SchemeTag, Strength, SubjectRef, Vantage};
use rustix::time::{ClockId, clock_gettime};
use sha2::{Digest, Sha256};

pub use backed::{Backed, Cost, Field, Provenance, provenance};

/// How a command ended, as far as the library saw.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Exited(i32),
    Signalled(i32),
    /// Spawned, but waiting for it did not return its exit.
    Unknown,
    /// Not spawned.
    NotRun,
}

/// The result of one `exec_evidence` call.
#[derive(Clone, Debug)]
pub struct ExecOutcome {
    status: Status,
    exe: Option<PathBuf>,
}

impl ExecOutcome {
    pub fn status(&self) -> Status {
        self.status
    }

    /// The canonical executable path that was run, when it resolved.
    pub fn exe(&self) -> Option<&Path> {
        self.exe.as_deref()
    }
}

/// A library session. Synchronous; share it behind the caller's mutex.
#[derive(Debug)]
pub struct Session {
    _private: (),
}

pub fn open() -> Session {
    Session { _private: () }
}

/// Length of a `LINUX_EXEC` claim subject.
pub const SUBJECT_LEN: usize = 60;

const BACKING_ELEVATED: &[&str] = &[
    "filesystem path resolution (canonicalize)",
    "boot id (/proc/sys/kernel/random/boot_id)",
    "PID and time namespace inodes (/proc/self/ns)",
    "boot clock (CLOCK_BOOTTIME)",
    "process spawn (fork and exec)",
    "SHA-256 of the canonical path",
];
const BACKING_LOCAL: &[&str] = &["filesystem path resolution (canonicalize)"];

/// Inode of /proc/self/ns/pid in the initial PID namespace.
const PROC_PID_INIT_INO: u64 = 0xEFFF_FFFC;
/// Inode of /proc/self/ns/time in the initial time namespace.
const PROC_TIME_INIT_INO: u64 = 0xEFFF_FFFA;

/// Where the platform facts are read. Fixed in the library; the unit tests
/// point it at files of their own to reach the Local cases.
struct Platform {
    boot_id: &'static str,
    pid_ns: &'static str,
    time_ns: &'static str,
}

const LINUX: Platform = Platform {
    boot_id: "/proc/sys/kernel/random/boot_id",
    pid_ns: "/proc/self/ns/pid",
    time_ns: "/proc/self/ns/time",
};

impl Session {
    /// Run `program` with `args`; stdin is closed, stdout and stderr are
    /// inherited. Returns once the child has exited.
    pub fn exec_evidence(&mut self, program: &str, args: &[&str]) -> Backed<ExecOutcome> {
        exec_on(&LINUX, program, args)
    }
}

fn exec_on(platform: &Platform, program: &str, args: &[&str]) -> Backed<ExecOutcome> {
    // 1  the canonical path; 1a  an ELF image or a #! script, nothing else
    let Some(exe) = resolve(program) else {
        return local(None, "program not resolvable to an executable file");
    };
    if !is_elf_or_script(&exe) {
        return local(Some(exe), "not an ELF or #! file");
    }
    // 2  the digest of exactly the path that is passed to exec
    let digest: [u8; 32] = Sha256::digest(exe.as_os_str().as_bytes()).into();
    // 3  the boot id; 4  the initial PID and time namespaces
    let Some(boot) = boot_id(platform.boot_id) else {
        return local(Some(exe), "boot id unreadable");
    };
    if let Some(why) = namespaces(platform) {
        return local(Some(exe), why);
    }
    // 5  t0; 6  spawn
    let t0 = boottime_ns();
    let Ok(mut child) = Command::new(&exe).arg0(program).args(args).stdin(Stdio::null()).spawn()
    else {
        return local(Some(exe), "spawn failed");
    };
    let pid = child.id();
    // 7  wait; 8  t_reap
    let status = status_of(&child.wait());
    let t_reap = boottime_ns();
    if status == Status::Unknown {
        return Backed::new(
            ExecOutcome { status, exe: Some(exe) },
            Strength::SOFTWARE,
            Vantage::Local,
            BACKING_LOCAL,
            Some("wait did not return the child's exit status"),
            Cost::Spawn,
        );
    }
    // 9  the subject
    let subject = SubjectRef::new(SchemeTag::LINUX_EXEC, &subject(pid, t0, t_reap, &digest, boot))
        .expect("60 bytes");
    Backed::new(
        ExecOutcome { status, exe: Some(exe) },
        Strength::SOFTWARE,
        Vantage::Elevated(JoinRef::new(subject)),
        BACKING_ELEVATED,
        None,
        Cost::Spawn,
    )
}

/// pid u32 · t0 u64 · `t_reap` u64 · digest \[32\] · boot \[8\], big-endian.
fn subject(pid: u32, t0: u64, t_reap: u64, digest: &[u8; 32], boot: [u8; 8]) -> [u8; 60] {
    let mut b = [0u8; SUBJECT_LEN];
    b[0..4].copy_from_slice(&pid.to_be_bytes());
    b[4..12].copy_from_slice(&t0.to_be_bytes());
    b[12..20].copy_from_slice(&t_reap.to_be_bytes());
    b[20..52].copy_from_slice(digest);
    b[52..60].copy_from_slice(&boot);
    b
}

/// An exit code or a terminating signal is the child's exit as `wait()`
/// returns it; anything else is not.
fn status_of(r: &std::io::Result<ExitStatus>) -> Status {
    match r {
        Ok(s) => match (s.code(), s.signal()) {
            (Some(c), _) => Status::Exited(c),
            (None, Some(sig)) => Status::Signalled(sig),
            (None, None) => Status::Unknown,
        },
        Err(_) => Status::Unknown,
    }
}

fn local(exe: Option<PathBuf>, why: &'static str) -> Backed<ExecOutcome> {
    Backed::new(
        ExecOutcome { status: Status::NotRun, exe },
        Strength::SOFTWARE,
        Vantage::Local,
        BACKING_LOCAL,
        Some(why),
        Cost::InProcess,
    )
}

/// `CLOCK_BOOTTIME` in nanoseconds.
fn boottime_ns() -> u64 {
    let t = clock_gettime(ClockId::Boottime);
    let secs = u64::try_from(t.tv_sec).unwrap_or(0);
    let nanos = u64::try_from(t.tv_nsec).unwrap_or(0);
    secs.saturating_mul(1_000_000_000).saturating_add(nanos)
}

/// The first eight bytes of the boot id: the UUID's 32 hex digits, in
/// printed order, after removing the hyphens. Anything else is unreadable.
fn boot_id(path: &str) -> Option<[u8; 8]> {
    let text = std::fs::read_to_string(path).ok()?;
    let digits: Vec<u8> = text.trim_end_matches('\n').bytes().filter(|&b| b != b'-').collect();
    if digits.len() != 32 || !digits.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut out = [0u8; 8];
    for (i, o) in out.iter_mut().enumerate() {
        let pair = std::str::from_utf8(&digits[2 * i..2 * i + 2]).ok()?;
        *o = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

/// `None` when the process is in the initial PID and time namespaces,
/// otherwise the reason it cannot be established.
fn namespaces(p: &Platform) -> Option<&'static str> {
    let ino = |path: &str| std::fs::metadata(path).ok().map(|m| m.ino());
    match (ino(p.pid_ns), ino(p.time_ns)) {
        (None, _) | (_, None) => Some("namespace unknown"),
        (Some(pid), _) if pid != PROC_PID_INIT_INO => Some("not in the initial PID namespace"),
        (_, Some(time)) if time != PROC_TIME_INIT_INO => Some("not in the initial time namespace"),
        _ => None,
    }
}

/// The file starts with the ELF magic or with "#!". A file that is
/// neither would be retried by the C library as a shell script, and the
/// kernel would then record the shell, not this path, as what was asked
/// to run.
fn is_elf_or_script(exe: &Path) -> bool {
    let mut head = [0u8; 4];
    let Ok(mut f) = std::fs::File::open(exe) else { return false };
    let mut got = 0;
    while got < head.len() {
        match f.read(&mut head[got..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => got += n,
        }
    }
    (got >= 4 && head == *b"\x7fELF") || (got >= 2 && head[..2] == *b"#!")
}

/// The canonical path of the executable `program` names: as given when it
/// contains a slash, otherwise the first executable regular file on PATH.
fn resolve(program: &str) -> Option<PathBuf> {
    if program.is_empty() {
        return None;
    }
    let candidate = if program.contains('/') {
        PathBuf::from(program)
    } else {
        let path = std::env::var_os("PATH")?;
        std::env::split_paths(&path)
            .filter(|d| d.is_absolute())
            .map(|d| d.join(OsStr::new(program)))
            .find(|p| is_executable_file(p))?
    };
    let canonical = std::fs::canonicalize(candidate).ok()?;
    is_executable_file(&canonical).then_some(canonical)
}

fn is_executable_file(p: &Path) -> bool {
    std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let d = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/unit-tmp")
            .join(format!("anchorstamp-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn leak(p: PathBuf) -> &'static str {
        Box::leak(p.into_os_string().into_string().unwrap().into_boxed_str())
    }

    fn platform_with(boot: Option<&str>, pid: Option<&'static str>, time: Option<&'static str>) -> Platform {
        let d = scratch("platform");
        let boot_id = match boot {
            Some(text) => {
                let f = d.join(format!("boot-{}", text.len()));
                std::fs::write(&f, text).unwrap();
                leak(f)
            }
            None => LINUX.boot_id,
        };
        Platform {
            boot_id,
            pid_ns: pid.unwrap_or(LINUX.pid_ns),
            time_ns: time.unwrap_or(LINUX.time_ns),
        }
    }

    fn assert_local_unrun(out: &Backed<ExecOutcome>, why: &str) {
        assert!(matches!(out.vantage(), Vantage::Local));
        assert_eq!(out.degraded(), Some(why));
        assert_eq!(out.result().status(), Status::NotRun, "refused before the spawn");
        assert_eq!(out.cost(), Cost::InProcess);
    }

    #[test]
    fn boot_id_unreadable_is_local() {
        let p = Platform { boot_id: "/no/such/boot_id", ..LINUX };
        assert_local_unrun(&exec_on(&p, "/usr/bin/true", &[]), "boot id unreadable");
        for bad in ["", "not-a-uuid\n", "0123456789abcdef0123456789abcdeg\n",
            "0123456z-89ab-cdef-0123-456789abcdef\n"]
        {
            let p = platform_with(Some(bad), None, None);
            assert_local_unrun(&exec_on(&p, "/usr/bin/true", &[]), "boot id unreadable");
        }
    }

    #[test]
    fn boot_id_is_parsed_in_printed_order() {
        let d = scratch("bootid");
        let f = d.join("boot_id");
        std::fs::write(&f, "b0010203-0405-0607-0809-0a0b0c0d0e0f\n").unwrap();
        assert_eq!(boot_id(f.to_str().unwrap()), Some([0xb0, 1, 2, 3, 4, 5, 6, 7]));
    }

    #[test]
    fn pid_namespace_other_than_initial_is_local() {
        // any ordinary file has an inode other than the initial namespace's
        let d = scratch("ns");
        let f = d.join("not-a-namespace");
        std::fs::write(&f, b"").unwrap();
        let f = leak(f);
        let p = platform_with(None, Some(f), None);
        assert_local_unrun(&exec_on(&p, "/usr/bin/true", &[]), "not in the initial PID namespace");
        let p = platform_with(None, None, Some(f));
        assert_local_unrun(&exec_on(&p, "/usr/bin/true", &[]), "not in the initial time namespace");
    }

    #[test]
    fn namespace_unreadable_is_local() {
        let p = platform_with(None, Some("/no/such/ns/pid"), None);
        assert_local_unrun(&exec_on(&p, "/usr/bin/true", &[]), "namespace unknown");
        let p = platform_with(None, None, Some("/no/such/ns/time"));
        assert_local_unrun(&exec_on(&p, "/usr/bin/true", &[]), "namespace unknown");
    }

    #[test]
    fn wait_without_an_exit_is_unknown() {
        assert_eq!(status_of(&Err(std::io::Error::other("wait failed"))), Status::Unknown);
        assert_eq!(status_of(&Ok(ExitStatus::from_raw(0))), Status::Exited(0));
        assert_eq!(status_of(&Ok(ExitStatus::from_raw(9))), Status::Signalled(9));
        // a stopped child (0x7f in the low byte) is neither an exit nor a
        // terminating signal
        assert_eq!(status_of(&Ok(ExitStatus::from_raw(0x137f))), Status::Unknown);
    }

    #[test]
    fn subject_layout() {
        let s = subject(0x0102_0304, 5, 6, &[7; 32], [8; 8]);
        assert_eq!(&s[0..4], &[1, 2, 3, 4]);
        assert_eq!(&s[4..12], &5u64.to_be_bytes());
        assert_eq!(&s[12..20], &6u64.to_be_bytes());
        assert_eq!(&s[20..52], &[7; 32]);
        assert_eq!(&s[52..60], &[8; 8]);
    }
}

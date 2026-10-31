//! anchorstamp — the library. Runs inside the measured domain and is not a
//! trusted component.
//!
//! `exec_evidence` runs one command and returns its outcome with what backs
//! it. When the command was spawned, the vantage is Elevated and carries a
//! join reference whose subject comes from platform state: the child's
//! process id, the wall clock read before the spawn, and a digest of the
//! canonical executable path as the filesystem resolves it. Nothing the
//! caller passes sets strength, vantage or backing, and every call returns.
//!
//! The library sends nothing anywhere and knows of no other component.

mod backed;

use std::ffi::OsStr;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use anchorstamp_core::{JoinRef, SchemeTag, Strength, SubjectRef, Vantage};
use sha2::{Digest, Sha256};

pub use backed::{Backed, Cost, Field, Provenance, provenance};

/// How a command ended, as far as the library saw.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Exited(i32),
    Signalled(i32),
    /// Spawned, but waiting for it failed.
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

const BACKING_ELEVATED: &[&str] = &[
    "filesystem path resolution (canonicalize)",
    "process spawn (fork and exec)",
    "wall clock (SystemTime)",
    "SHA-256 of the canonical path",
];
const BACKING_LOCAL: &[&str] = &["filesystem path resolution (canonicalize)"];

impl Session {
    /// Run `program` with `args`; stdin is closed, stdout and stderr are
    /// inherited. Returns once the child has exited.
    pub fn exec_evidence(&mut self, program: &str, args: &[&str]) -> Backed<ExecOutcome> {
        let Some(exe) = resolve(program) else {
            return local(None, "program not resolvable to an executable file");
        };
        let digest = exe_digest(&exe);
        let time_ms = wall_clock_ms();
        let mut child =
            match Command::new(&exe).arg0(program).args(args).stdin(Stdio::null()).spawn() {
                Ok(c) => c,
                Err(_) => return local(Some(exe), "spawn failed"),
            };
        let pid = child.id();
        let status = match child.wait() {
            Ok(s) => match (s.code(), s.signal()) {
                (Some(c), _) => Status::Exited(c),
                (None, Some(sig)) => Status::Signalled(sig),
                (None, None) => Status::Unknown,
            },
            Err(_) => Status::Unknown,
        };
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&pid.to_be_bytes());
        bytes[4..12].copy_from_slice(&time_ms.to_be_bytes());
        bytes[12..32].copy_from_slice(&digest);
        let subject = SubjectRef::new(SchemeTag::DEMO, &bytes).expect("32 bytes");
        Backed::new(
            ExecOutcome { status, exe: Some(exe) },
            Strength::SOFTWARE,
            Vantage::Elevated(JoinRef::new(subject)),
            BACKING_ELEVATED,
            None,
            Cost::Spawn,
        )
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

/// First 20 bytes of SHA-256 over the canonical path's bytes.
fn exe_digest(exe: &Path) -> [u8; 20] {
    use std::os::unix::ffi::OsStrExt;
    let full: [u8; 32] = Sha256::digest(exe.as_os_str().as_bytes()).into();
    full[..20].try_into().expect("20 of 32")
}

fn wall_clock_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

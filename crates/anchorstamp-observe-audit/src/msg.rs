//! Every line the observer writes to its log. Numbers and fixed words
//! only: no key material, no input bytes. Kept here so a test can produce
//! each one and search it.

pub const PREFIX: &str = "observe-audit: ";
pub const USAGE: &str = "usage: anchorstamp-observe-audit --audit-log PATH --sink DIR --key KEY";
pub const LEAK_TEST: &str = "LEAK-TEST BUILD: key exported for the leak search";
pub const ANCHOR_WRITTEN: &str = "anchor written; reading";

pub fn error(what: &str) -> String {
    format!("error {what}")
}

pub fn ptrace_scope(scope: u32) -> String {
    format!("ptrace_scope={scope}")
}

pub fn start(instance_hex: &str, coverage_from_ms: u64, offset: u64) -> String {
    format!("start instance={instance_hex} coverage_from_ms={coverage_from_ms} offset={offset}")
}

/// `dumpable` is the value PR_GET_DUMPABLE returned after the drop.
pub fn dropped(dumpable: i32) -> String {
    format!("dropped uid=65534 gid=65534 groups=0 dumpable={dumpable}")
}

pub fn sighting(index: u64, pid: u32, ppid: u32, syscall: u32, exe_len: usize) -> String {
    format!("sighting index={index} pid={pid} ppid={ppid} syscall={syscall} exe_len={exe_len}")
}

pub fn parse_reject(index: u64, count: u64) -> String {
    format!("parse-reject index={index} count={count}")
}

pub fn stream_ended(reason: u8, why: &str, execs: u64, rejects: u64, offset: u64) -> String {
    format!("stream-ended reason={reason} ({why}) execs={execs} rejects={rejects} offset={offset}")
}

pub fn stopped(execs: u64, rejects: u64, pending: usize, offset: u64) -> String {
    format!(
        "stopped on SIGTERM execs={execs} rejects={rejects} pending_bytes={pending} offset={offset}"
    )
}

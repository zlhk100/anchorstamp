//! anchorstamp-exec <claims-file> -- <program> [args...]
//!
//! The bridge an agent framework written in another language calls instead
//! of spawning a tool command itself. Runs the command through the library
//! (stdin closed, stdout and stderr inherited), appends the join reference
//! to <claims-file> in the same framing agentsim uses (u32 big-endian length,
//! then the encoded reference), and exits with the command's own status.
//!
//! The bridge is part of the measured domain, exactly like the library: it
//! is not trusted, and nothing it writes is believed without an independent
//! observation. Its own exec is visible to the observer like any other; the
//! reader's report lists it as a parent of the claimed command.
//!
//! On stderr it prints one line, `anchorstamp-exec: claim pid=<pid>` or
//! `anchorstamp-exec: no claim (<reason>)`, so the framework can show it.

#![forbid(unsafe_code)]

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::process::exit;

use anchorstamp::{Status, open};
use anchorstamp_core::{JOINREF_MAX_LEN, Vantage, encode_joinref};

/// Exit code when the bridge itself could not do its job (usage, claims
/// file). Chosen outside the range shells use for signals.
const EXIT_BRIDGE: i32 = 120;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let Some(sep) = args.iter().position(|a| a == "--") else { usage() };
    if sep != 2 || args.len() <= sep + 1 {
        usage();
    }
    let claims_path = &args[1];
    let program = &args[sep + 1];
    let rest: Vec<&str> = args[sep + 2..].iter().map(String::as_str).collect();

    // Open the claims file before running anything: a claim that cannot be
    // recorded must not leave an action behind.
    let mut claims =
        match OpenOptions::new().append(true).create(true).mode(0o600).open(claims_path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("anchorstamp-exec: claims file {claims_path}: {}", e.kind());
                exit(EXIT_BRIDGE);
            }
        };

    let r = open().exec_evidence(program, &rest);
    match r.vantage() {
        Vantage::Elevated(j) => {
            let mut buf = [0u8; JOINREF_MAX_LEN];
            let n = encode_joinref(j.subject(), &mut buf).expect("joinref fits");
            let len = u32::try_from(n).expect("joinref length fits u32");
            let mut framed = len.to_be_bytes().to_vec();
            framed.extend_from_slice(&buf[..n]);
            if claims.write_all(&framed).and_then(|()| claims.sync_data()).is_err() {
                eprintln!("anchorstamp-exec: claims write failed (the command already ran)");
                exit(EXIT_BRIDGE);
            }
            // the LINUX_EXEC subject starts with the child's pid, u32 big-endian
            let pid = u32::from_be_bytes(
                j.subject().bytes()[0..4].try_into().expect("LINUX_EXEC subject"),
            );
            eprintln!("anchorstamp-exec: claim pid={pid}");
        }
        Vantage::Local => {
            eprintln!("anchorstamp-exec: no claim ({})", r.degraded().unwrap_or("not spawned"));
        }
    }
    exit(match r.result().status() {
        Status::Exited(c) => c,
        Status::Signalled(s) => 128 + s,
        Status::Unknown => EXIT_BRIDGE + 1,
        Status::NotRun => 127,
    });
}

fn usage() -> ! {
    eprintln!("usage: anchorstamp-exec <claims-file> -- <program> [args...]");
    exit(EXIT_BRIDGE);
}

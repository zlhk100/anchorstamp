// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright © 2026 Lei Zhou

//! demo-report <run-dir> [--bundle <dir> --ak <der> --scope <uid>[,<uid>...] [--nonce <hex>]]
//!
//! With a bundle, the attestation key and the scope are required: the key
//! is the operator's pinned key (DER SubjectPublicKeyInfo), never the
//! bundle's copy, and the scope names the uids whose execs the kernel
//! source's unclaimed list covers.

use std::path::{Path, PathBuf};
use std::process::exit;

use demo_report::{Inputs, KInputs, render};

const USAGE: &str =
    "usage: demo-report <run-dir> [--bundle <dir> --ak <der> --scope <uid>[,<uid>...] [--nonce <hex>]]";

fn usage() -> ! {
    eprintln!("{USAGE}");
    exit(2)
}

fn parse_hex(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let Some(run) = a.get(1).filter(|r| !r.starts_with("--")) else { usage() };
    let (mut bundle, mut ak, mut scope, mut nonce): (Option<PathBuf>, Option<PathBuf>, Option<Vec<u32>>, Option<Vec<u8>>) =
        (None, None, None, None);
    let mut it = a[2..].iter();
    while let Some(flag) = it.next() {
        let Some(v) = it.next() else { usage() };
        match flag.as_str() {
            "--bundle" if bundle.is_none() => bundle = Some(PathBuf::from(v)),
            "--ak" if ak.is_none() => ak = Some(PathBuf::from(v)),
            "--scope" if scope.is_none() => {
                let uids: Option<Vec<u32>> = v.split(',').map(|u| u.parse().ok()).collect();
                scope = Some(uids.unwrap_or_else(|| usage()));
            }
            "--nonce" if nonce.is_none() => nonce = Some(parse_hex(v).unwrap_or_else(|| usage())),
            _ => usage(),
        }
    }
    let mut input = Inputs::read(Path::new(run));
    match (bundle, ak, scope) {
        (Some(b), Some(k), Some(s)) => {
            input.kernel = Some(KInputs::read(&b, &k, s, nonce, &mut input.notes));
        }
        (None, None, None) if nonce.is_none() => {}
        _ => usage(),
    }
    print!("{}", render(run, &input));
}

// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright © 2026 Lei Zhou

//! demo-report — what one demo run's evidence supports, in words.
//!
//! Runs outside the measured account, from the root-owned install. Reads
//! the run directory (the software source and the claims) and, when one
//! is given, a kernel-source bundle with the attestation key the operator
//! pinned. One outcome per claim per source; sources are never combined.
//! Every verdict sentence says what the reader's outcome carries and
//! nothing more; the limits and the standing statements are printed on
//! every report.

use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::Read as _;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anchorstamp_core::{ENDED_READ_ERROR, ENDED_ROTATED, ENDED_SHRUNK};
use anchorstamp_verify::exec::{Claim, account, candidate, join, matches, same_boot};
use anchorstamp_verify::k::{Bundle, Quote};
use anchorstamp_verify::{
    Anchor, Cap, DeclaredPath, Detail, Evidence, ExecRecord, Kind, Outcome, Path as Delivery,
    Profile, k, s,
};

/// What this report declares itself to be: its first line.
pub const DECLARATION: &str = "anchorstamp specification 0.4, layout 1, reader";

/// Largest record length a frame may declare.
pub const FRAME_MAX: usize = 65_536;

/// Records split from a framed file, and where reading stopped early.
pub struct Frames<'a> {
    pub records: Vec<&'a [u8]>,
    /// Some(n): the file is unreadable after record n (a length above the
    /// maximum, or a short read).
    pub unreadable_after: Option<usize>,
}

/// Split a file of (u32 big-endian length, record) frames.
pub fn frames(b: &[u8]) -> Frames<'_> {
    let mut records = Vec::new();
    let mut at = 0;
    while at < b.len() {
        let Some(len) = b.get(at..at + 4) else {
            return Frames { unreadable_after: Some(records.len()), records };
        };
        let n = u32::from_be_bytes(len.try_into().expect("4 bytes")) as usize;
        match b.get(at + 4..at + 4 + n) {
            Some(rec) if n <= FRAME_MAX => records.push(rec),
            _ => return Frames { unreadable_after: Some(records.len()), records },
        }
        at += 4 + n;
    }
    Frames { records, unreadable_after: None }
}

/// Facts the harness recorded, read from the run directory when present.
#[derive(Default)]
pub struct Harness {
    pub audit_before: Option<String>,
    pub audit_after: Option<String>,
    pub agent_log: Option<String>,
    pub checks: Option<String>,
}

/// One quote of a bundle, as files.
pub struct QuoteFiles {
    pub attest: Vec<u8>,
    pub signature: Vec<u8>,
    pub pcr7: Vec<u8>,
}

/// The kernel source: a collector bundle and the operator's choices.
pub struct KInputs {
    pub label: String,
    pub list: Vec<u8>,
    pub quotes: Vec<QuoteFiles>,
    pub boot_id: Option<[u8; 16]>,
    pub interval_s: Option<u32>,
    /// The pinned attestation key, DER, from the operator — never from the
    /// bundle.
    pub ak: Vec<u8>,
    pub ak_label: String,
    /// The uids whose execs the unclaimed list covers.
    pub scope: Vec<u32>,
    pub nonce: Option<Vec<u8>>,
}

/// Everything the report reads.
pub struct Inputs {
    pub sightings: Vec<u8>,
    pub claims: Vec<u8>,
    pub harness: Harness,
    pub kernel: Option<KInputs>,
    /// Input files that were not read whole, and why.
    pub notes: Vec<String>,
}

/// Most bytes read from any one input file.
pub const READ_MAX: u64 = 64 * 1024 * 1024;

// Open flags, by value: this crate takes no system-interface crate. These
// are the x86 Linux values.
#[cfg(not(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "x86"))))]
compile_error!("open flag values are given for x86 Linux only");
const O_NONBLOCK: i32 = 0o4000;
const O_NOFOLLOW: i32 = 0o400_000;

/// Read one input file. Part of the run directory is writable by the
/// measured account, so: never through a symlink, never waiting on a FIFO,
/// regular files only, at most `READ_MAX` bytes. `None` when absent or
/// refused; a refusal or a cut is noted.
pub fn read_input(path: &Path, notes: &mut Vec<String>) -> Option<Vec<u8>> {
    let name = path.display();
    let f = match OpenOptions::new().read(true).custom_flags(O_NOFOLLOW | O_NONBLOCK).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(_) => {
            notes.push(format!("{name}: not opened (a symlink, or not readable)"));
            return None;
        }
    };
    if !f.metadata().is_ok_and(|m| m.file_type().is_file()) {
        notes.push(format!("{name}: not a regular file, not read"));
        return None;
    }
    let mut b = Vec::new();
    if f.take(READ_MAX + 1).read_to_end(&mut b).is_err() {
        notes.push(format!("{name}: read failed"));
        return None;
    }
    if b.len() as u64 > READ_MAX {
        b.truncate(usize::try_from(READ_MAX).expect("fits"));
        notes.push(format!("{name}: larger than {READ_MAX} bytes, only the first {READ_MAX} read"));
    }
    Some(b)
}

/// A boot id as /proc prints it: 32 hex digits and hyphens.
pub fn parse_boot_id(text: &[u8]) -> Option<[u8; 16]> {
    let t = std::str::from_utf8(text).ok()?.trim_end_matches('\n');
    let digits: Vec<u8> = t.bytes().filter(|&b| b != b'-').collect();
    if digits.len() != 32 || !digits.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(std::str::from_utf8(&digits[2 * i..2 * i + 2]).ok()?, 16).ok()?;
    }
    Some(out)
}

impl Inputs {
    pub fn read(run: &Path) -> Inputs {
        let mut notes = Vec::new();
        let mut rd = |p: &str| read_input(&run.join(p), &mut notes);
        let sightings = rd("sink/sightings.bin").unwrap_or_default();
        let claims = rd("claims/claims.bin").unwrap_or_default();
        let mut txt = |p: &str| rd(p).map(|b| String::from_utf8_lossy(&b).into_owned());
        let harness = Harness {
            audit_before: txt("audit-status-before.txt"),
            audit_after: txt("audit-status-after.txt"),
            agent_log: txt("agent.log"),
            checks: txt("harness-checks.txt"),
        };
        Inputs { sightings, claims, harness, kernel: None, notes }
    }
}

impl KInputs {
    /// Read a collector bundle: ima.bin, quote-<n>.msg, quote-<n>.sig and
    /// pcr7-<n>.bin for n = 1, 2, ... while all three exist, boot_id, and
    /// interval. The bundle's own copy of the key is not read.
    pub fn read(
        bundle: &Path,
        ak_path: &Path,
        scope: Vec<u32>,
        nonce: Option<Vec<u8>>,
        notes: &mut Vec<String>,
    ) -> KInputs {
        let list = read_input(&bundle.join("ima.bin"), notes).unwrap_or_default();
        let mut quotes = Vec::new();
        for n in 1.. {
            let mut f = |name: String| read_input(&bundle.join(name), notes);
            let (Some(attest), Some(signature), Some(pcr7)) =
                (f(format!("quote-{n}.msg")), f(format!("quote-{n}.sig")), f(format!("pcr7-{n}.bin")))
            else {
                break;
            };
            quotes.push(QuoteFiles { attest, signature, pcr7 });
        }
        let boot_id = read_input(&bundle.join("boot_id"), notes).and_then(|b| parse_boot_id(&b));
        let interval_s = read_input(&bundle.join("interval"), notes)
            .and_then(|b| String::from_utf8(b).ok())
            .and_then(|s| s.trim().parse().ok());
        let ak = read_input(ak_path, notes).unwrap_or_default();
        KInputs {
            label: bundle.display().to_string(),
            list,
            quotes,
            boot_id,
            interval_s,
            ak,
            ak_label: ak_path.display().to_string(),
            scope,
            nonce,
        }
    }

    pub fn evidence(&self) -> Evidence {
        let quotes: Vec<Quote> = self
            .quotes
            .iter()
            .map(|q| Quote { attest: &q.attest, signature: &q.signature, pcr7: &q.pcr7 })
            .collect();
        k::build(&Bundle {
            list: &self.list,
            quotes: &quotes,
            ak_spki: &self.ak,
            boot_id: self.boot_id,
            nonce: self.nonce.as_deref(),
            interval_s: self.interval_s,
        })
    }
}

pub const TRUNCATION_WINDOW: &str = "Records after the last one shown cannot be distinguished from none: a stream may have been cut short.";
pub const OUTSIDE_READER: &str = "This reader runs outside the measured account.";
pub const SELF_DECLARED: &str =
    "The software observer's position and coverage mode are self-declared and corroborated by nothing.";
pub const LIBRARY: &str =
    "The library and the command-line bridge run inside the measured account and are not trusted components.";
pub const LIMIT_PID_REUSE: &str = "Limit: the software source carries no fork time; a pid reused inside a claim's window \
by a process running the same file is indistinguishable from the claimed one.";
pub const LIMIT_CAUSATION: &str = "Limit: a claim proves an exec matching the descriptor was observed - not that the claimant caused it. \
The measured party can read the stream and claim a real exec afterwards; it cannot claim one that did not happen, \
nor change the file.";
pub const LIMIT_SCRIPTS: &str = "Limit: for a #! script the kernel source agrees with the cap Interpreted and names the interpreter; \
the software source records the interpreter and does not agree.";
pub const LIMIT_ROOT: &str = "Limit: root on this host can add entries to PCR 13 from user space, so a kernel-source agreement \
carries the cap RootCanInsert; root cannot remove the kernel's own records, so a contradiction does not rest on that.";
pub const BOOT_ASSERTED: &str =
    "The boot each source observed is asserted by its collector or observer; nothing in the evidence binds it.";
pub const ANCHORING: &str = "Anchoring: the software source has none - its records are unsigned and its transport is the operator's word. \
The kernel source is anchored only by TPM quotes valid under the attestation key the operator pinned locally; \
records after the last quote are unanchored.";

/// Printable form of untrusted bytes: printable ASCII kept, all else \xNN.
pub fn escape(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len());
    for &c in b {
        if (0x21..=0x7e).contains(&c) && c != b'\\' {
            s.push(char::from(c));
        } else {
            let _ = write!(s, "\\x{c:02x}");
        }
    }
    s
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn cap_words(c: Cap) -> &'static str {
    match c {
        Cap::SelfProvAbsent => "no measurement of the observer's own launch is in the evidence",
        Cap::SelfProvUnappraised => "self-provenance present but not appraised",
        Cap::SequenceUnappraised => "the observer's sequence source is not appraised",
        Cap::AnchorOperatorAsserted => "the anchor is asserted by the operator",
        Cap::TransportOperatorAsserted => "the records are unsigned: their transport is the operator's word",
        Cap::BootConfigUnappraised => "the boot configuration (PCR 7) is not appraised",
        Cap::EkChainUnvalidated => "no endorsement key certificate chain was checked",
        Cap::AkPinnedLocally => "the attestation key is pinned locally by the operator",
        Cap::BootAsserted => "the boot id is asserted by the source",
        Cap::PathUnverified => "the path is resolved in the task's own namespace and root, unchecked",
        Cap::RootCanInsert => "root can add entries to PCR 13 from user space",
        Cap::Interpreted => "the match is on an interpreted (#!) record",
        Cap::Unanchored => "the record comes after the last valid quote",
    }
}

fn caps_line(strength: u16, caps: &[Cap]) -> String {
    let words: Vec<&str> = caps.iter().map(|c| cap_words(*c)).collect();
    let name = match strength {
        400 => "ATTESTED",
        100 => "SOFTWARE",
        _ => "?",
    };
    format!("strength {name} ({strength}); held there because: {}", words.join("; "))
}

fn anchor_words(a: &Anchor, interval: Option<u32>) -> String {
    let every = interval.map_or("not recorded".to_string(), |s| {
        if s == 0 { "a single round".to_string() } else { format!("every {s} s") }
    });
    match a {
        Anchor::None => "anchor: none".into(),
        Anchor::Within(w) => format!(
            "anchor: between TPM clock {} and {} ms, resetCount {}, restartCount {} -> {}, safe {}; quotes {every}",
            w.from.map_or("(no earlier quote)".to_string(), |f| f.to_string()),
            w.to,
            w.reset_count,
            w.restart_from.map_or("-".to_string(), |r| r.to_string()),
            w.restart_to,
            if w.safe { "yes" } else { "no" }
        ),
    }
}

/// Why a claim compares nothing, from what the outcome and the evidence
/// carry.
fn nothing_why(o: &Outcome, ev: &Evidence, claim: Option<&Claim>) -> String {
    if o.path == Delivery::NothingArrived {
        return "no valid record arrived".into();
    }
    let Some(c) = claim else { return "the claim is not a LINUX_EXEC reference".into() };
    if !ev.instances.iter().any(|i| same_boot(c, i)) {
        return "the source holds no instance of the claim's boot".into();
    }
    if o.health.evidence_broken {
        return "the evidence is broken".into();
    }
    if ev.instances.iter().any(|i| i.v1 && same_boot(c, i)) {
        return "the source holds a load of record v1, which is reported and never joined".into();
    }
    if o.health.touches_claim {
        return "a gap, a loss, an unreadable input or a clock step touches the claim's window".into();
    }
    match ev.profile {
        Profile::S => "the software source agrees or says nothing, and has no matching record".into(),
        Profile::K => "the attested records do not decide this claim (not reached, ambiguous, outside \
             the armed coverage, unstable or unattested)"
            .into(),
    }
}

fn verdict_words(o: &Outcome, ev: &Evidence, claim: Option<&Claim>) -> String {
    match &o.kind {
        Kind::Agrees { strength, caps, also, .. } => {
            let also = if *also > 0 { format!("; {also} further matching record(s)") } else { String::new() };
            format!(
                "CORROBORATED - the source recorded an exec of this pid and this file inside the claim's window{also}.\n        {}",
                caps_line(strength.get(), caps)
            )
        }
        Kind::Disagrees { detail: Detail::SubjectMismatch, strength, caps } => format!(
            "CONTRADICTED (subject mismatch) - attested records show this pid running a different file inside the claim's window.\n        {}",
            caps_line(strength.get(), caps)
        ),
        Kind::Disagrees { detail: Detail::Unobserved, strength, caps } => format!(
            "CONTRADICTED (unobserved) - the attested record continues past the claim's window with nothing touching it, \
             and holds no exec of this pid in it.\n        {}",
            caps_line(strength.get(), caps)
        ),
        Kind::NotCovered { windows } => {
            let w: Vec<String> = windows
                .iter()
                .map(|(lo, hi)| format!("[{lo}, {})", hi.map_or("open".to_string(), |h| h.to_string())))
                .collect();
            format!("NOT COVERED - the claim's window lies outside the source's coverage {}.", w.join(" "))
        }
        Kind::NothingToCompare => format!("NOTHING TO COMPARE - {}.", nothing_why(o, ev, claim)),
    }
}

fn exec_text(e: &ExecRecord) -> String {
    let mut t = escape(&e.path);
    if e.path_truncated {
        t.push_str(" [path truncated in the record]");
    }
    if e.path_unresolved {
        t.push_str(" [path unresolved]");
    }
    if e.interpreted {
        t.push_str(" [interpreted: the path is the interpreter's]");
    }
    if let Some(ns) = e.ns.filter(|n| *n != 0) {
        let _ = write!(t, " [ns {ns:#04x}]");
    }
    t
}

fn record_line(e: &ExecRecord) -> String {
    let ppid = e.ppid.map_or("?".to_string(), |p| p.to_string());
    let when = if e.lo == e.hi { format!("at {}", e.lo) } else { format!("in [{}, {}]", e.lo, e.hi) };
    let uid = e.uid.map_or(String::new(), |u| format!(" uid {u}"));
    format!("index {} pid {} ppid {ppid}{uid} {when} exe {}", e.position, e.pid, exec_text(e))
}

fn s_section(r: &mut String, ev: &Evidence, f: &Frames) {
    let _ = writeln!(r, "\nsource S: the audit observer (profile S, unsigned)");
    let delivery = if ev.valid == 0 { "nothing arrived" } else { "direct (declared by the deployment)" };
    let _ = writeln!(r, "  delivery path: {delivery}");
    let _ = writeln!(r, "  records read {}, valid {}, excluded {}", f.records.len(), ev.valid, ev.excluded);
    let _ = writeln!(r, "  gaps {}, chain breaks {}, forks {}", ev.gaps, ev.breaks, ev.forks);
    if let Some(n) = f.unreadable_after {
        let _ = writeln!(r, "  sightings file unreadable after record {n}");
    }
    let _ = writeln!(r, "  observer instances {}", ev.instances.len());
    for i in &ev.instances {
        match (i.cov_from, i.boot, i.tolerance_ns) {
            (Some(from), Some(boot), Some(tol)) => {
                let mode = if i.mediated { "Mediated" } else { "Sampled" };
                let _ = writeln!(
                    r,
                    "  instance {}: coverage mode {mode}, from {from} ns on the boot clock, boot {}, tolerance {tol} ns (self-declared)",
                    hex(&i.id[..4]),
                    hex(&boot)
                );
            }
            _ => {
                let _ = writeln!(r, "  instance {}: start record missing or inconsistent", hex(&i.id[..4]));
            }
        }
        let _ = writeln!(r, "    parse rejects {}, clock steps {}", i.rejects, i.clock_steps);
        let ended = match i.ended {
            None => "no stream-ended record (a clean stop leaves none)",
            Some(ENDED_ROTATED) => "YES - the audit log was rotated or removed",
            Some(ENDED_SHRUNK) => "YES - the audit log shrank",
            Some(ENDED_READ_ERROR) => "YES - read error",
            Some(_) => "YES - unknown reason",
        };
        let _ = writeln!(r, "    stream ended: {ended}");
        let _ = writeln!(r, "    execution sightings {}", i.records.len());
    }
}

fn k_section(r: &mut String, ev: &Evidence, k: &KInputs) {
    let fx = &ev.facts;
    let _ = writeln!(r, "\nsource K: kernel exec records in IMA, PCR 13 (profile K)");
    let _ = writeln!(r, "  bundle: {}", escape(k.label.as_bytes()));
    let _ = writeln!(
        r,
        "  attestation key: pinned locally by the operator from {}, not taken from the bundle",
        escape(k.ak_label.as_bytes())
    );
    if fx.ak_usable {
        let _ = writeln!(r, "    point {}", hex(&k.ak[26..]));
    } else {
        let _ = writeln!(
            r,
            "    UNUSABLE - not a 91-byte P-256 key in the expected form: every quote excluded, every record unanchored"
        );
    }
    let delivery = if ev.valid == 0 { "nothing arrived" } else { "direct (declared by the deployment)" };
    let _ = writeln!(r, "  delivery path: {delivery}");
    let _ = writeln!(r, "  quotes {}, valid {}", fx.quotes, fx.quotes_valid);
    let _ = writeln!(r, "  PCR-13 entries {}, attested {}", fx.entries, fx.attested);
    let tail = if fx.tail_empty {
        "a valid quote follows the last record".to_string()
    } else {
        format!("{} entries after the last valid quote: SOFTWARE, unanchored", fx.entries - fx.attested)
    };
    let _ = writeln!(r, "  tail: {tail}");
    let interval = match fx.interval_s {
        None => "not recorded".to_string(),
        Some(0) => "a single round".to_string(),
        Some(s) => format!("every {s} s"),
    };
    let _ = writeln!(r, "  quote interval: {interval}");
    let nonce = match fx.nonce_quoted {
        None => "no auditor nonce given",
        Some(true) => "a valid quote carries the auditor's nonce",
        Some(false) => "NO valid quote carries the auditor's nonce",
    };
    let _ = writeln!(r, "  nonce: {nonce}");
    let boot = k.boot_id.map_or("not readable".to_string(), |b| hex(&b));
    let _ = writeln!(r, "  boot id (as the collector copied it): {boot}");
    let resets: Vec<String> = fx.reset_counts.iter().map(u32::to_string).collect();
    let _ = writeln!(r, "  resetCount of the valid quotes: {}", resets.join(" "));
    for p in &fx.pcr7 {
        let _ = writeln!(r, "  PCR 7 (quoted, not appraised): {}", hex(p));
    }
    let _ = writeln!(r, "  excluded (entries and quotes) {}, gaps {}, forks {}", ev.excluded, ev.gaps, ev.forks);
    if let Some(n) = fx.list_unreadable_after {
        let _ = writeln!(r, "  measurement list unreadable after entry {n}");
    }
    if ev.breaks > 0 {
        let _ = writeln!(r, "  EVIDENCE BROKEN: {} break(s)", ev.breaks);
        for b in &fx.break_reasons {
            let _ = writeln!(r, "    {}", escape_line(b));
        }
    } else {
        let _ = writeln!(r, "  breaks 0");
    }
    let scope: Vec<String> = k.scope.iter().map(u32::to_string).collect();
    let _ = writeln!(r, "  scope of the unclaimed list: uid or euid in {{{}}}", scope.join(", "));
    let _ = writeln!(r, "  loads {}", ev.instances.len());
    for i in &ev.instances {
        let opt = |v: Option<u64>| v.map_or("-".to_string(), |x| x.to_string());
        let version = if i.v1 { " (record v1: reported, never joined)" } else { "" };
        let end = if i.unloaded { "UNLOAD" } else { "no UNLOAD" };
        let _ = writeln!(
            r,
            "  load {}{version}: loaded {}, armed {}, close {}, unloaded {}, {end}; exec records {}, losses {}, gaps {}",
            hex(&i.id[..4]),
            opt(i.lo_c),
            opt(i.cov_from),
            opt(i.close_c),
            opt(i.hi_c),
            i.records.len(),
            i.losses.iter().map(|l| l.count).sum::<u64>(),
            i.gaps.len()
        );
    }
}

/// Every exec record of a source with its instance, by position.
fn records(ev: &Evidence) -> Vec<(&anchorstamp_verify::Instance, &ExecRecord)> {
    ev.instances.iter().flat_map(|i| i.records.iter().map(move |e| (i, e))).collect()
}

fn claim_lines(r: &mut String, name: &str, ev: &Evidence, claim: &[u8], interval: Option<u32>) {
    let o = join(Some(claim), ev, DeclaredPath::Direct);
    let c = Claim::parse(claim);
    let _ = writeln!(r, "    {name}: {}", verdict_words(&o, ev, c.as_ref()));
    if matches!(o.kind, Kind::Agrees { .. } | Kind::Disagrees { .. }) {
        let _ = writeln!(r, "        {}", anchor_words(&o.anchor, interval));
    }
    if o.health.touches_claim {
        let _ = writeln!(r, "        a gap, loss, unreadable input or clock step touches this claim");
    }
    if o.health.evidence_broken {
        let _ = writeln!(r, "        evidence broken");
    }
    let Some(c) = c else { return };
    for (i, e) in records(ev) {
        if !same_boot(&c, i) || !candidate(&c, e) {
            continue;
        }
        let how = if matches(&c, e) { "seen" } else { "this pid in the window, not matching" };
        let _ = writeln!(r, "        {how}: {}", record_line(e));
    }
}

fn unclaimed_lines(r: &mut String, name: &str, ev: &Evidence, claims: &[&[u8]], scope: &[u32]) {
    let list = account(claims, ev, scope);
    let _ = writeln!(r, "  {name} ({})", list.len());
    let holes: u64 = ev.instances.iter().map(|i| i.holes).sum();
    if holes > 0 || ev.gaps > 0 {
        let _ = writeln!(r, "    unclaimed list incomplete: {} hole(s), {} gap(s)", holes, ev.gaps);
    }
    let parsed: Vec<Claim> = claims.iter().filter_map(|c| Claim::parse(c)).collect();
    let all = records(ev);
    let mut children = Vec::new();
    let mut others = Vec::new();
    for u in &list {
        let Some((_, e)) = all.iter().find(|(i, e)| i.id == u.instance && e.position == u.index) else {
            continue;
        };
        // a claimed exec that could be the parent: its pid is this record's
        // parent and it was not later
        let parent = all.iter().find(|(i, p)| {
            Some(p.pid) == e.ppid && p.lo <= e.lo && parsed.iter().any(|c| same_boot(c, i) && matches(c, p))
        });
        let line = record_line(e);
        match parent {
            Some((_, p)) => children.push(format!("    child of claimed pid {}: {line}", p.pid)),
            None => others.push(format!("    {line}")),
        }
    }
    let _ = writeln!(r, "   child of a claimed exec (parent pid, not earlier) ({})", children.len());
    for l in &children {
        let _ = writeln!(r, "{l}");
    }
    let _ = writeln!(r, "   other execs ({})", others.len());
    for l in &others {
        let _ = writeln!(r, "{l}");
    }
}

fn status_field(text: Option<&String>, field: &str) -> Option<u64> {
    text?.lines().find_map(|l| l.strip_prefix(field)?.strip_prefix(' ')?.trim().parse().ok())
}

/// Render the report.
pub fn render(run_label: &str, input: &Inputs) -> String {
    let mut r = String::new();
    let sf = frames(&input.sightings);
    let cf = frames(&input.claims);
    let s_ev = s::build(&sf.records);
    let k_ev = input.kernel.as_ref().map(KInputs::evidence);

    let _ = writeln!(r, "{DECLARATION}");
    let _ = writeln!(r, "anchorstamp report");
    let _ = writeln!(r, "run: {}", escape_line(run_label));
    let _ = writeln!(r, "scheme: LINUX_EXEC");
    let sources = if k_ev.is_some() { "S (run directory), K (bundle)" } else { "S (run directory); no kernel bundle given" };
    let _ = writeln!(r, "sources: {sources}");
    let _ = writeln!(r, "{ANCHORING}");
    for n in &input.notes {
        let _ = writeln!(r, "input file {}", escape_line(n));
    }

    s_section(&mut r, &s_ev, &sf);
    if let (Some(ev), Some(k)) = (&k_ev, &input.kernel) {
        k_section(&mut r, ev, k);
    }

    // claims: one outcome per claim per source
    let _ = writeln!(r, "\nclaims ({})", cf.records.len());
    if let Some(n) = cf.unreadable_after {
        let _ = writeln!(r, "  claims file unreadable after record {n}");
    }
    let interval = k_ev.as_ref().and_then(|e| e.facts.interval_s);
    for (n, c) in cf.records.iter().enumerate() {
        let head = match Claim::parse(c) {
            Some(p) => format!("pid {} window [{}, {}] boot {}", p.pid, p.t0, p.t_reap, hex(&p.boot)),
            None => "not a LINUX_EXEC reference".into(),
        };
        let _ = writeln!(r, "  #{} {head}", n + 1);
        claim_lines(&mut r, "S", &s_ev, c, None);
        if let Some(ev) = &k_ev {
            claim_lines(&mut r, "K", ev, c, interval);
        }
    }

    // unclaimed, per source
    let _ = writeln!(r, "\nunclaimed execs");
    unclaimed_lines(&mut r, "S: every exec sighting of the run's audit key", &s_ev, &cf.records, &[]);
    if let (Some(ev), Some(k)) = (&k_ev, &input.kernel) {
        unclaimed_lines(&mut r, "K: execs in scope", ev, &cf.records, &k.scope);
    }

    // pid reuse, software source
    let mut pids: Vec<u32> = records(&s_ev).iter().map(|(_, e)| e.pid).collect();
    pids.sort_unstable();
    let total = pids.len();
    pids.dedup();
    let _ = writeln!(r, "\npid reuse (S): {} execution sightings, {} distinct pids", total, pids.len());

    // audit counters
    let _ = writeln!(r, "\naudit counters (auditctl -s, recorded by the harness)");
    for f in ["lost", "backlog"] {
        let b = status_field(input.harness.audit_before.as_ref(), f);
        let a = status_field(input.harness.audit_after.as_ref(), f);
        let _ = match (b, a) {
            (Some(b), Some(a)) => {
                writeln!(r, "  {f}: before {b}, after {a}, delta {}", i128::from(a) - i128::from(b))
            }
            _ => writeln!(r, "  {f}: not recorded"),
        };
    }

    // refusals
    let _ = writeln!(r, "\nrefusal tests (the measured account's own log; it can write anything there)");
    let lines: Vec<&str> = input
        .harness
        .agent_log
        .as_deref()
        .map(|l| l.lines().filter(|l| l.starts_with("REFUSAL ") || l.starts_with("ESCALATE ")).collect())
        .unwrap_or_default();
    if lines.is_empty() {
        let _ = writeln!(r, "  none run");
    }
    for l in lines {
        let _ = writeln!(r, "  {}", escape_line(l));
    }
    if let Some(c) = &input.harness.checks {
        let _ = writeln!(r, "\nharness checks (recorded by the harness as root)");
        for l in c.lines() {
            let _ = writeln!(r, "  {}", escape_line(l));
        }
    }

    // standing statements
    let _ = writeln!(r, "\nstatements");
    for s in [
        TRUNCATION_WINDOW,
        OUTSIDE_READER,
        SELF_DECLARED,
        LIBRARY,
        BOOT_ASSERTED,
        LIMIT_PID_REUSE,
        LIMIT_CAUSATION,
        LIMIT_SCRIPTS,
        LIMIT_ROOT,
    ] {
        let _ = writeln!(r, "  {s}");
    }
    r
}

fn escape_line(l: &str) -> String {
    l.chars().map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { '?' }).collect()
}

//! demo-report — what one demo run's evidence supports, in words.
//!
//! Runs outside the measured account, from the root-owned install. Reads
//! the run directory only. Every verdict sentence says what the reader's
//! outcome carries and nothing more; the limits and the standing
//! statements are printed on every report.

use std::fmt::Write as _;
use std::path::Path;

use anchorstamp_core::{
    CLASS_PARSE_REJECT, CLASS_STREAM_ENDED, ENDED_READ_ERROR, ENDED_ROTATED, ENDED_SHRUNK,
    SchemeTag, SightingView, decode_joinref,
};
use anchorstamp_verify::schemes::{Demo, DemoSubject};
use anchorstamp_verify::{
    Cap, DeclaredPath, Detail, Kind, Outcome, Path as Delivery, Stream, account, join,
};

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

/// Everything the report reads.
pub struct Inputs {
    pub sightings: Vec<u8>,
    pub anchor: Option<[u8; 32]>,
    pub claims: Vec<u8>,
    pub harness: Harness,
}

impl Inputs {
    pub fn read(run: &Path) -> Inputs {
        let rd = |p: &str| std::fs::read(run.join(p)).ok();
        let txt = |p: &str| std::fs::read_to_string(run.join(p)).ok();
        Inputs {
            sightings: rd("sink/sightings.bin").unwrap_or_default(),
            anchor: rd("sink/anchor.pub").and_then(|b| b.try_into().ok()),
            claims: rd("claims/claims.bin").unwrap_or_default(),
            harness: Harness {
                audit_before: txt("audit-status-before.txt"),
                audit_after: txt("audit-status-after.txt"),
                agent_log: txt("agent.log"),
                checks: txt("harness-checks.txt"),
            },
        }
    }
}

pub const TRUNCATION_WINDOW: &str = "Records after the last one shown cannot be distinguished from none: the stream may have been cut short.";
pub const OUTSIDE_READER: &str = "This reader runs outside the measured account.";
pub const LIMIT_PID_REUSE: &str =
    "Limit: two execs reusing one pid with one binary are indistinguishable.";
pub const LIMIT_CAUSATION: &str = "Limit: a claim proves an exec matching the descriptor was observed - not that the claimant caused it. \
The measured party can read the stream and claim a real exec afterwards; it cannot claim one that did not happen, \
nor change the binary.";
pub const LIMIT_SCRIPTS: &str = "Limit: scripts are out of scope: audit records the interpreter.";
pub const SELF_DECLARED: &str =
    "The observer's position and coverage mode are self-declared and corroborated by nothing.";
pub const LIBRARY: &str =
    "The library runs inside the measured account and is not a trusted component.";
pub const ANCHORING: &str = "Anchoring: none. The anchor is the public key the observer wrote at its start, \
taken on the operator's word; no time or third-party anchor exists.";

/// Printable form of untrusted bytes: printable ASCII kept, all else \xNN.
pub fn escape(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len());
    for &c in b {
        if (0x21..=0x7e).contains(&c) && c != b'\\' {
            s.push(c as char);
        } else {
            let _ = write!(s, "\\x{c:02x}");
        }
    }
    s
}

/// One execution sighting, decoded for display.
struct Seen {
    index: u64,
    subject: DemoSubject,
    ppid: u32,
    exe: Vec<u8>,
    truncated: bool,
}

fn seen(index: u64, v: &SightingView) -> Option<Seen> {
    let subject = DemoSubject::parse(&v.parts.subject)?;
    let d = v.parts.observed.data;
    if d.len() < 5 {
        return None;
    }
    Some(Seen {
        index,
        subject,
        ppid: u32::from_be_bytes(d[1..5].try_into().ok()?),
        exe: d[5..].to_vec(),
        truncated: d[0] & 1 == 1,
    })
}

fn exe_text(s: &Seen) -> String {
    let t = if s.truncated { " [path truncated in the record]" } else { "" };
    format!("{}{t}", escape(&s.exe))
}

fn cap_words(c: &Cap) -> &'static str {
    match c {
        Cap::SelfProvAbsent => "the matching sighting carries no self-provenance",
        Cap::SelfProvUnappraised => "self-provenance present but not appraised",
        Cap::SequenceUnappraised => "the observer's sequence source is not appraised",
        Cap::AnchorOperatorAsserted => "the anchor is asserted by the operator",
    }
}

fn verdict_words(o: &Outcome) -> String {
    match &o.kind {
        Kind::Agrees { strength, caps, .. } => {
            let caps: Vec<&str> = caps.iter().map(cap_words).collect();
            format!(
                "CORROBORATED - the observer recorded an exec with this pid and this executable.\n      \
                 strength SOFTWARE ({}); held there because: {}",
                strength.get(),
                caps.join("; ")
            )
        }
        Kind::Disagrees { detail: Detail::SubjectMismatch } => {
            "CONTRADICTED (subject mismatch) - the observer recorded this pid running a different executable."
                .into()
        }
        Kind::Disagrees { detail: Detail::Unobserved } => {
            "CONTRADICTED (unobserved) - the observer's record continues past the claim's time with no gap \
             touching it, and holds no exec with this pid."
                .into()
        }
        Kind::NotCovered { coverage_from } => {
            format!("NOT COVERED - the claim's time is before the observer's coverage began ({coverage_from} ms).")
        }
        Kind::NothingToCompare => {
            let why = if o.path == Delivery::NothingArrived {
                "no valid sighting arrived"
            } else if o.health.touches_claim {
                "a gap in the record touches the claim's time"
            } else {
                "the record does not reach far enough, or does not identify one observer instance"
            };
            format!("NOTHING TO COMPARE - {why}.")
        }
    }
}

fn status_field(text: &Option<String>, field: &str) -> Option<u64> {
    text.as_ref()?
        .lines()
        .find_map(|l| l.strip_prefix(field)?.strip_prefix(' ')?.trim().parse().ok())
}

/// Render the report.
pub fn render(run_label: &str, input: &Inputs) -> String {
    let mut r = String::new();
    let scheme = Demo;
    let anchors: Vec<[u8; 32]> = input.anchor.into_iter().collect();
    let sf = frames(&input.sightings);
    let cf = frames(&input.claims);
    let st = Stream::validate(&sf.records, &anchors);
    let health = st.health();

    let _ = writeln!(r, "anchorstamp proof-of-concept report");
    let _ = writeln!(r, "run: {run_label}");
    let _ =
        writeln!(r, "scheme: DEMO (proof-of-concept only; not accepted by a conforming reader)");
    let delivery =
        if st.is_empty() { "nothing arrived" } else { "direct (declared by the deployment)" };
    let _ = writeln!(r, "delivery path: {delivery}");
    let _ = writeln!(r, "{ANCHORING}");
    if input.anchor.is_none() {
        let _ = writeln!(r, "anchor: MISSING or not 32 bytes - no record can be validated.");
    }

    // stream health
    let _ = writeln!(r, "\nstream health");
    let valid: usize = st.instances().map(|i| i.records().count()).sum();
    let _ = writeln!(
        r,
        "  records read {}, valid {valid}, excluded {}",
        sf.records.len(),
        health.excluded
    );
    let _ = writeln!(
        r,
        "  gaps {}, chain breaks {}, forks {}",
        health.gaps, health.breaks, health.forks
    );
    let _ = writeln!(r, "  observer instances {}", st.instance_count());
    if let Some(n) = sf.unreadable_after {
        let _ = writeln!(r, "  sightings file unreadable after record {n}");
    }
    if let Some(n) = cf.unreadable_after {
        let _ = writeln!(r, "  claims file unreadable after record {n}");
    }
    let mut execs: Vec<Seen> = Vec::new();
    for inst in st.instances() {
        if let Some(ms) = scheme.coverage_from_ms(inst) {
            let _ = writeln!(r, "  coverage: mode Mediated, from {ms} ms (self-declared)");
        } else {
            let _ = writeln!(r, "  coverage: start record missing");
        }
        let mut rejects = 0u64;
        let mut ended = None;
        for (index, v) in inst.records() {
            let p = &v.parts;
            if p.subject.scheme() == SchemeTag::OBSERVER {
                match p.observed.class {
                    CLASS_PARSE_REJECT => {
                        let n = p.observed.data.try_into().map(u64::from_be_bytes).unwrap_or(0);
                        rejects = rejects.max(n);
                    }
                    CLASS_STREAM_ENDED => ended = p.observed.data.first().copied(),
                    _ => {}
                }
            } else if let Some(s) =
                seen(index, v).filter(|_| anchorstamp_verify::Scheme::is_execution(&scheme, v))
            {
                execs.push(s);
            }
        }
        let _ = writeln!(r, "  parse rejects {rejects}");
        let _ = writeln!(
            r,
            "  stream ended: {}",
            match ended {
                None => "no stream-ended record (a clean stop leaves none)",
                Some(ENDED_ROTATED) => "YES - the audit log was rotated or removed",
                Some(ENDED_SHRUNK) => "YES - the audit log shrank",
                Some(ENDED_READ_ERROR) => "YES - read error",
                Some(_) => "YES - unknown reason",
            }
        );
    }
    let _ = writeln!(r, "  execution sightings {}", execs.len());

    // claims
    let _ = writeln!(r, "\nclaims ({})", cf.records.len());
    let mut parents: Vec<(usize, &Seen)> = Vec::new();
    for (n, c) in cf.records.iter().enumerate() {
        let o = join(Some(c), &sf.records, &anchors, DeclaredPath::Direct, &scheme);
        let subj = decode_joinref(c).ok().and_then(|s| DemoSubject::parse(&s));
        let pid = subj.map(|s| s.pid.to_string()).unwrap_or_else(|| "?".into());
        let _ = writeln!(r, "  #{} pid {pid}  {}", n + 1, verdict_words(&o));
        if let Some(s) = subj {
            let same_pid: Vec<&Seen> = execs.iter().filter(|e| e.subject.pid == s.pid).collect();
            for e in &same_pid {
                if e.subject.exe_digest == s.exe_digest {
                    parents.push((n + 1, e));
                    let _ = writeln!(r, "      seen: index {} exe {}", e.index, exe_text(e));
                } else {
                    let _ = writeln!(
                        r,
                        "      this pid seen with another executable: index {} exe {}",
                        e.index,
                        exe_text(e)
                    );
                }
            }
        }
        let h = o.health;
        if h.touches_claim {
            let _ = writeln!(r, "      a gap touches this claim");
        }
    }

    // unclaimed
    let unclaimed = account(&cf.records, &sf.records, &anchors, &scheme);
    let _ = writeln!(r, "\nunclaimed execs ({})", unclaimed.len());
    let mut children: Vec<String> = Vec::new();
    let mut others: Vec<String> = Vec::new();
    for u in &unclaimed {
        let Some(e) = execs.iter().find(|e| e.index == u.index) else { continue };
        let line = format!(
            "index {} pid {} ppid {} time {} exe {}",
            e.index,
            e.subject.pid,
            e.ppid,
            e.subject.time_ms,
            exe_text(e)
        );
        // the latest claimed exec that could be the parent
        let parent = parents
            .iter()
            .filter(|(_, p)| p.subject.pid == e.ppid && e.subject.time_ms >= p.subject.time_ms)
            .max_by_key(|(_, p)| p.subject.time_ms);
        match parent {
            Some((n, _)) => children.push(format!("    child of claim #{n}: {line}")),
            None => others.push(format!("    {line}")),
        }
    }
    let _ = writeln!(
        r,
        "  child of a claimed exec (same parent pid, not earlier) ({})",
        children.len()
    );
    for l in &children {
        let _ = writeln!(r, "{l}");
    }
    let _ = writeln!(r, "  other execs of the measured account ({})", others.len());
    for l in &others {
        let _ = writeln!(r, "{l}");
    }

    // pid reuse
    let mut pids: Vec<u32> = execs.iter().map(|e| e.subject.pid).collect();
    pids.sort_unstable();
    let total = pids.len();
    pids.dedup();
    let _ = writeln!(r, "\npid reuse: {} execution sightings, {} distinct pids", total, pids.len());

    // audit counters
    let _ = writeln!(r, "\naudit counters (auditctl -s, recorded by the harness)");
    for f in ["lost", "backlog"] {
        let b = status_field(&input.harness.audit_before, f);
        let a = status_field(&input.harness.audit_after, f);
        let _ = match (b, a) {
            (Some(b), Some(a)) => {
                writeln!(r, "  {f}: before {b}, after {a}, delta {}", a as i128 - b as i128)
            }
            _ => writeln!(r, "  {f}: not recorded"),
        };
    }

    // refusals
    let _ = writeln!(
        r,
        "\nrefusal tests (the measured account's own log; it can write anything there)"
    );
    let lines: Vec<&str> = input
        .harness
        .agent_log
        .as_deref()
        .map(|l| {
            l.lines().filter(|l| l.starts_with("REFUSAL ") || l.starts_with("ESCALATE ")).collect()
        })
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
        LIMIT_PID_REUSE,
        LIMIT_CAUSATION,
        LIMIT_SCRIPTS,
    ] {
        let _ = writeln!(r, "  {s}");
    }
    r
}

fn escape_line(l: &str) -> String {
    l.chars().map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { '?' }).collect()
}

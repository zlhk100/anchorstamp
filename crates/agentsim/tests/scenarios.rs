//! Scenario parsing, and the simulator run unprivileged on the modes that
//! do not contact the audit system. The tamper probes run against a sink
//! this user owns, to show they change nothing whatever they find.

use std::process::Command;

use agentsim::{EXEC_CAP, Step, parse, words};
use anchorstamp_core::decode_joinref;

const SCENARIOS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../demo/scenarios");

fn fresh_run_dir(tag: &str) -> std::path::PathBuf {
    let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let d = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("{tag}-{}-{n}", std::process::id()));
    std::fs::create_dir_all(d.join("claims")).unwrap();
    d
}

fn frames(b: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + 4 <= b.len() {
        let n = u32::from_be_bytes(b[at..at + 4].try_into().unwrap()) as usize;
        out.push(&b[at + 4..at + 4 + n]);
        at += 4 + n;
    }
    assert_eq!(at, b.len());
    out
}

fn run(scenario: &str, tag: &str) -> (String, Vec<Vec<u8>>, i32) {
    let dir = fresh_run_dir(tag);
    let o = Command::new(env!("CARGO_BIN_EXE_agentsim"))
        .args([format!("{SCENARIOS}/{scenario}"), dir.to_string_lossy().into_owned()])
        .output()
        .unwrap();
    let claims = std::fs::read(dir.join("claims/claims.bin")).unwrap_or_default();
    let claims = frames(&claims).into_iter().map(<[u8]>::to_vec).collect();
    (String::from_utf8_lossy(&o.stdout).into_owned(), claims, o.status.code().unwrap_or(-1))
}

#[test]
fn every_scenario_parses() {
    let mut n = 0;
    for e in std::fs::read_dir(SCENARIOS).unwrap() {
        let p = e.unwrap().path();
        let steps = parse(&std::fs::read_to_string(&p).unwrap())
            .unwrap_or_else(|e| panic!("{}: {e}", p.display()));
        assert!(!steps.is_empty());
        n += 1;
    }
    assert_eq!(n, 10);
}

#[test]
fn unknown_step_is_an_error() {
    assert!(parse("main fly /usr/bin/true").unwrap_err().contains("line 1"));
    assert!(parse("# c\n\nmain honest /usr/bin/true\nmain").unwrap_err().contains("line 4"));
    assert!(parse("main burst many /usr/bin/true").is_err());
    assert!(parse("main forger maybe /usr/bin/true").is_err());
    assert!(parse("main tamper extra").is_err());
    assert!(parse("main honest '/usr/bin/true").is_err());
}

#[test]
fn unknown_step_stops_the_run_nonzero() {
    let dir = fresh_run_dir("bad");
    let f = dir.join("bad.txt");
    std::fs::write(&f, "main honest /usr/bin/true\nmain fly\n").unwrap();
    let o = Command::new(env!("CARGO_BIN_EXE_agentsim")).args([&f, &dir]).output().unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert!(!dir.join("claims/claims.bin").exists(), "nothing ran");
}

#[test]
fn quoting() {
    assert_eq!(words("a b  'c d' e''").unwrap(), ["a", "b", "c d", "e"]);
    assert_eq!(
        parse("m pipeline /bin/sh -c 'ls | wc -l'").unwrap(),
        [Step::Pipeline {
            agent: "m".into(),
            argv: vec!["/bin/sh".into(), "-c".into(), "ls | wc -l".into()]
        }]
    );
}

#[test]
fn honest_claims_every_call_and_is_deterministic() {
    let (out1, c1, code1) = run("honest.txt", "h1");
    let (_, c2, code2) = run("honest.txt", "h2");
    assert_eq!((code1, code2), (0, 0), "{out1}");
    assert_eq!(c1.len(), 4);
    assert_eq!(c1.len(), c2.len());
    for c in &c1 {
        decode_joinref(c).unwrap();
    }
    assert_eq!(out1.matches("vantage=Elevated").count(), 4);
}

#[test]
fn shadow_claims_only_honest_calls() {
    let (out, c, code) = run("shadow.txt", "sh");
    assert_eq!(code, 0, "{out}");
    assert_eq!(c.len(), 2);
    assert_eq!(out.matches("UNCLAIMED agent=main mode=shadow").count(), 2);
}

#[test]
fn forger_appends_its_forgeries() {
    let (out, c, code) = run("forger.txt", "f");
    assert_eq!(code, 0, "{out}");
    // honest, source + unobserved forgery, source + mismatch forgery
    assert_eq!(c.len(), 5);
    let pid =
        |b: &[u8]| u32::from_be_bytes(decode_joinref(b).unwrap().bytes()[0..4].try_into().unwrap());
    assert_eq!(pid(&c[2]), u32::MAX - 1);
    assert!(out.contains("FORGED agent=main kind=mismatch"));
}

#[test]
fn subagents_share_one_session() {
    let (out, c, code) = run("subagent.txt", "sa");
    assert_eq!(code, 0, "{out}");
    assert_eq!(c.len(), 5);
    for a in ["coder", "tester", "reviewer"] {
        assert!(out.contains(&format!("agent={a} mode=subagent")), "{out}");
    }
}

#[test]
fn evade_execveat_runs_and_m32_reports_not_run() {
    let (out, c, code) = run("evade.txt", "ev");
    assert_eq!(code, 0, "{out}");
    assert_eq!(c.len(), 1, "only the honest call is claimed");
    assert!(out.contains("execveat pid=") && out.contains("exit=Some(0) claimed=no"), "{out}");
    assert!(out.contains("m32 NOT RUN"), "{out}");
}

#[test]
fn longpath_claims_a_long_canonical_path() {
    let (out, c, code) = run("longpath.txt", "lp");
    assert_eq!(code, 0, "{out}");
    assert_eq!(c.len(), 1);
    let len: usize =
        out.split("path_len=").nth(1).unwrap().split_whitespace().next().unwrap().parse().unwrap();
    assert!(len > 1015, "{len}");
}

#[test]
fn pipeline_claims_the_shell_only() {
    let (out, c, code) = run("pipeline.txt", "pl");
    assert_eq!(code, 0, "{out}");
    assert_eq!(c.len(), 2);
}

#[test]
fn execs_per_scenario_are_capped() {
    assert_eq!(EXEC_CAP, 500);
    assert!(parse("main burst 500 /usr/bin/true").is_ok());
    assert!(parse("main burst 501 /usr/bin/true").unwrap_err().contains("more than 500"));
    assert!(parse("main burst 499 /usr/bin/true\nmain honest /usr/bin/true").is_ok());
    assert!(
        parse("main burst 499 /usr/bin/true\nmain forger mismatch /usr/bin/id /usr/bin/true")
            .is_err()
    );
    assert!(parse(&"main honest /usr/bin/true\n".repeat(501)).is_err());
    assert!(parse(&format!("main burst {} /usr/bin/true\nmain burst 1 x", u32::MAX)).is_err());
}

/// A sink as the harness lays it out, owned by this user; `mode` for the
/// two files, `dir_mode` for the directory.
fn sink(tag: &str, mode: u32, dir_mode: u32) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let run = fresh_run_dir(tag);
    let sink = run.join("sink");
    std::fs::create_dir(&sink).unwrap();
    for f in ["sightings.bin", "anchor.pub"] {
        std::fs::write(sink.join(f), b"before").unwrap();
        std::fs::set_permissions(sink.join(f), std::fs::Permissions::from_mode(mode)).unwrap();
    }
    std::fs::set_permissions(&sink, std::fs::Permissions::from_mode(dir_mode)).unwrap();
    std::fs::write(run.join("tamper.txt"), "main tamper\n").unwrap();
    run
}

/// Names, modes, sizes, contents and modification times in the sink.
fn snapshot(run: &std::path::Path) -> Vec<(String, u32, Vec<u8>, i64, i64)> {
    use std::os::unix::fs::MetadataExt;
    let mut v: Vec<_> = std::fs::read_dir(run.join("sink"))
        .unwrap()
        .map(|e| {
            let p = e.unwrap().path();
            let m = std::fs::metadata(&p).unwrap();
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            (name, m.mode(), std::fs::read(&p).unwrap(), m.mtime(), m.mtime_nsec())
        })
        .collect();
    v.sort();
    let m = std::fs::metadata(run.join("sink")).unwrap();
    v.push((".".into(), std::os::unix::fs::MetadataExt::mode(&m), vec![], 0, 0));
    v
}

fn tamper(run: &std::path::Path) -> (String, i32) {
    let o = Command::new(env!("CARGO_BIN_EXE_agentsim"))
        .args([run.join("tamper.txt"), run.to_path_buf()])
        .output()
        .unwrap();
    (String::from_utf8_lossy(&o.stdout).into_owned(), o.status.code().unwrap_or(-1))
}

#[test]
fn tamper_probes_change_nothing_even_when_permitted() {
    // a regressed sink: everything writable by the measured user
    let run = sink("tamper-open", 0o644, 0o755);
    let before = snapshot(&run);
    let (out, code) = tamper(&run);
    assert_eq!(snapshot(&run), before, "the sink changed");
    assert_eq!(code, 3, "{out}");
    assert_eq!(out.matches(": SUCCEEDED").count(), 4, "{out}");
    assert!(out.contains("STOP: a refusal test succeeded"));
}

#[test]
fn tamper_probes_report_refusals() {
    if euid() == 0 {
        return; // root passes every access check
    }
    // no write bits: the three write probes are refused; the chmod probe
    // still finds this user is the owner
    let run = sink("tamper-ro", 0o444, 0o555);
    let before = snapshot(&run);
    let (out, code) = tamper(&run);
    assert_eq!(snapshot(&run), before);
    assert!(
        out.contains("REFUSAL tamper probe write sink/sightings.bin: refused (permission denied)"),
        "{out}"
    );
    assert!(
        out.contains("REFUSAL tamper probe write sink/anchor.pub: refused (permission denied)")
    );
    assert!(
        out.contains("REFUSAL tamper probe create or rename in sink/: refused (permission denied)")
    );
    assert!(out.contains("REFUSAL tamper probe chmod sink/sightings.bin: SUCCEEDED"));
    assert_eq!(code, 3);
    // a sink owned by another user, as in the live run, refuses the chmod
    // probe too; that needs root to set up and is shown by the live run
}

fn euid() -> u32 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap();
    let l = s.lines().find(|l| l.starts_with("Uid:")).unwrap();
    l.split_whitespace().nth(2).unwrap().parse().unwrap()
}

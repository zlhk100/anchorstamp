//! Parser known answers: the real SYSCALL lines of a probe run on the
//! target host, plus synthetic lines for the cases a probe cannot produce.
//!
//! Each real line's kernel part is verbatim. Its enrichment (after 0x1D,
//! which the parser ignores) is replaced by a neutral placeholder. The
//! 1,647-byte-path record was captured cut at 600 characters; it appears
//! twice: verbatim as cut (a reject), and rebuilt with the full path,
//! which the same run recorded in that exec's EXECVE record.

use anchorstamp_observe_audit::parse::{
    Arch, EXE_DATA_MAX, LINE_MAX, Line, LineBuf, classify, exec_data,
};

const KEY: &[u8] = b"as-probe-600389";
const PROBE: &[u8] = include_bytes!("data/probe-syscall.txt");

enum Expect {
    Exec {
        time_ms: u64,
        serial: u64,
        syscall: u32,
        pid: u32,
        ppid: u32,
        exe_len: usize,
        exe_prefix: &'static [u8],
    },
    Other,
    Reject,
}

fn lines(data: &[u8]) -> Vec<(Vec<u8>, bool)> {
    let mut out = Vec::new();
    LineBuf::new(false).feed(data, &mut |l, t| out.push((l.to_vec(), t)));
    out
}

#[test]
fn probe_lines() {
    let expect: Vec<Expect> = include!("data/probe-expect.rs").into_iter().collect();
    let got = lines(PROBE);
    assert_eq!(got.len(), 18);
    assert_eq!(got.len(), expect.len());
    let mut execs = 0;
    for (i, ((line, truncated), want)) in got.iter().zip(&expect).enumerate() {
        assert!(!truncated);
        match (classify(line, *truncated, KEY), want) {
            (
                Line::Exec(e),
                Expect::Exec { time_ms, serial, syscall, pid, ppid, exe_len, exe_prefix },
            ) => {
                execs += 1;
                assert_eq!(e.time_ms, *time_ms, "line {i}");
                assert_eq!(e.serial, *serial, "line {i}");
                assert_eq!(e.syscall, *syscall, "line {i}");
                assert_eq!(e.pid, *pid, "line {i}");
                assert_eq!(e.ppid, *ppid, "line {i}");
                assert_eq!(e.arch, Arch::X86_64);
                assert_eq!(e.exe.len(), *exe_len, "line {i}");
                assert!(e.exe.starts_with(exe_prefix), "line {i}");
            }
            (Line::Other, Expect::Other) | (Line::Reject, Expect::Reject) => {}
            (g, _) => panic!("line {i}: got {g:?}"),
        }
    }
    assert_eq!(execs, 15);
}

#[test]
fn hex_exe_is_decoded() {
    let got = lines(PROBE);
    let Line::Exec(e) = classify(&got[10].0, false, KEY) else { panic!() };
    assert_eq!(e.exe, b"/tmp/as-probe-600389/a b/q\"x");
}

#[test]
fn execveat_is_sighted() {
    let got = lines(PROBE);
    let Line::Exec(e) = classify(&got[16].0, false, KEY) else { panic!() };
    assert_eq!(e.syscall, 322);
    assert_eq!(e.exe, b"/usr/bin/true");
}

#[test]
fn long_path_is_truncated_and_flagged_never_skipped() {
    let got = lines(PROBE);
    let Line::Exec(e) = classify(&got[14].0, false, KEY) else { panic!() };
    assert_eq!(e.exe.len(), 1647);
    let d = exec_data(&e);
    assert_eq!(d[0] & 1, 1, "truncated flag");
    assert_eq!(u32::from_be_bytes(d[1..5].try_into().unwrap()), e.ppid);
    assert_eq!(d.len(), 5 + EXE_DATA_MAX);
    assert_eq!(&d[5..], &e.exe[..EXE_DATA_MAX]);
    // a short path is not flagged
    let Line::Exec(s) = classify(&got[2].0, false, KEY) else { panic!() };
    assert_eq!(exec_data(&s)[0], 0);
}

#[test]
fn ppid_before_pid_is_matched_by_whole_key() {
    // every real line has ppid= before pid=; a substring match would read
    // ppid as pid
    let got = lines(PROBE);
    let Line::Exec(e) = classify(&got[3].0, false, KEY) else { panic!() };
    assert_eq!((e.ppid, e.pid), (600464, 600465));
}

fn base() -> Vec<u8> {
    lines(PROBE)[2].0.clone()
}

fn with(f: impl Fn(&str) -> String) -> Vec<u8> {
    let b = base();
    let cut = b.iter().position(|&c| c == 0x1d).unwrap();
    let mut k = f(std::str::from_utf8(&b[..cut]).unwrap()).into_bytes();
    k.extend_from_slice(&b[cut..]);
    k
}

#[test]
fn duplicate_key_is_rejected() {
    let l = with(|k| k.replace(" pid=600464", " pid=600464 pid=1"));
    assert_eq!(classify(&l, false, KEY), Line::Reject);
    let l = with(|k| format!("{k} exe=\"/usr/bin/true\""));
    assert_eq!(classify(&l, false, KEY), Line::Reject);
}

#[test]
fn enrichment_is_ignored() {
    // a conflicting pid and exe after 0x1D change nothing
    let mut l = base();
    l.extend_from_slice(b" pid=1 exe=\"/evil\" key=\"as-probe-600389\"");
    let Line::Exec(e) = classify(&l, false, KEY) else { panic!() };
    assert_eq!((e.pid, e.exe.as_slice()), (600464, &b"/usr/bin/dash"[..]));
}

#[test]
fn grammar_violations_are_rejected() {
    for l in [
        with(|k| k.replace(" items=2", " items")), // token without =
        with(|k| k.replace(" items=2", "  items=2")), // empty token
        with(|k| k.replace("pid=600464", "pid=60x464")), // bad number
        with(|k| k.replace("success=yes", "success=ok")), // bad success
        with(|k| k.replace("exe=\"/usr/bin/dash\"", "exe=2f7573")), // lower-case hex
        with(|k| k.replace("exe=\"/usr/bin/dash\"", "exe=2F757")), // odd hex
        with(|k| k.replace("exe=\"/usr/bin/dash\"", "exe=\"/usr/bin/dash")), // open quote
        with(|k| k.replace("exe=\"/usr/bin/dash\"", "exe=(null)")), // ours, no exe
        with(|k| k.replace(".202:", ".2020:")),    // ms not 3 digits
        with(|k| k.replace(" ppid=600463", "")),   // required field missing
        b"garbage without a type".to_vec(),
        b"".to_vec(),
    ] {
        assert_eq!(classify(&l, false, KEY), Line::Reject, "{}", String::from_utf8_lossy(&l));
    }
}

#[test]
fn filter() {
    // not ours: other key, failure, other syscall, other arch, other type
    for l in [
        with(|k| k.replace("key=\"as-probe-600389\"", "key=\"as-other\"")),
        with(|k| k.replace("key=\"as-probe-600389\"", "key=(null)")),
        with(|k| k.replace("success=yes", "success=no")),
        with(|k| k.replace("syscall=59", "syscall=57")),
        with(|k| k.replace("arch=c000003e", "arch=c00000b7")),
        b"type=PATH msg=audit(1793418742.202:10417): item=0 name=\"/bin/sh\"".to_vec(),
        b"type=EXECVE anything at all".to_vec(),
    ] {
        assert_eq!(classify(&l, false, KEY), Line::Other, "{}", String::from_utf8_lossy(&l));
    }
    // i386 numbers: execve 11, execveat 358
    for n in [11, 358] {
        let l = with(|k| {
            k.replace("arch=c000003e", "arch=40000003")
                .replace("syscall=59", &format!("syscall={n}"))
        });
        let Line::Exec(e) = classify(&l, false, KEY) else { panic!("i386 {n}") };
        assert_eq!(e.arch, Arch::I386);
    }
    // x86_64 number 11 is not an exec
    let l = with(|k| k.replace("syscall=59", "syscall=11"));
    assert_eq!(classify(&l, false, KEY), Line::Other);
    // hex-encoded key is decoded before comparison
    let l = with(|k| k.replace("key=\"as-probe-600389\"", "key=61732D70726F62652D363030333839"));
    assert!(matches!(classify(&l, false, KEY), Line::Exec(_)));
}

#[test]
fn partial_lines() {
    let data = base();
    // a line arriving in pieces is emitted once, when its newline arrives
    let mut out = Vec::new();
    let mut lb = LineBuf::new(false);
    for chunk in data.chunks(7) {
        lb.feed(chunk, &mut |l, t| out.push((l.to_vec(), t)));
    }
    assert!(out.is_empty(), "no newline yet");
    assert_eq!(lb.pending(), data.len());
    lb.feed(b"\n", &mut |l, t| out.push((l.to_vec(), t)));
    assert_eq!(out, vec![(data.clone(), false)]);

    // started mid-line: the first partial line is discarded
    let mut stream = data[100..].to_vec();
    stream.push(b'\n');
    stream.extend_from_slice(&data);
    stream.push(b'\n');
    let mut out = Vec::new();
    LineBuf::new(true).feed(&stream, &mut |l, t| out.push((l.to_vec(), t)));
    assert_eq!(out, vec![(data.clone(), false)]);
    // without the flag the fragment is a line, and a reject
    let mut out = Vec::new();
    LineBuf::new(false).feed(&stream, &mut |l, t| out.push((l.to_vec(), t)));
    assert_eq!(classify(&out[0].0, out[0].1, KEY), Line::Reject);
}

#[test]
fn overlong_lines() {
    // kernel part complete within the kept 16 KiB: still sighted
    let mut l = base();
    l.extend(std::iter::repeat_n(b'x', 2 * LINE_MAX));
    l.push(b'\n');
    let got = lines(&l);
    assert_eq!(got.len(), 1);
    assert!(got[0].1, "truncated");
    assert_eq!(got[0].0.len(), LINE_MAX);
    assert!(matches!(classify(&got[0].0, got[0].1, KEY), Line::Exec(_)));
    // kernel part cut by the limit: rejected, counted, not dropped
    let k = with(|k| k.replace("a3=0", &format!("a3={}", "0".repeat(2 * LINE_MAX))));
    let mut l = k.clone();
    l.push(b'\n');
    let got = lines(&l);
    assert!(got[0].1);
    assert_eq!(classify(&got[0].0, got[0].1, KEY), Line::Reject);
}

//! The binary's start sequence, unprivileged: it must stop at the drop,
//! before its instance-start record and its ready line. The full sequence
//! runs only as root.

use std::process::Command;

fn fresh_dir(tag: &str) -> std::path::PathBuf {
    let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let d = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("{tag}-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn unprivileged_start_stops_before_the_first_record() {
    if euid() == 0 {
        return; // the privileged path is exercised by the live run
    }
    let d = fresh_dir("start");
    let log = d.join("audit.log");
    std::fs::write(&log, b"type=SYSCALL partial").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_anchorstamp-observe-audit"))
        .args([
            "--audit-log",
            log.to_str().unwrap(),
            "--sink",
            d.to_str().unwrap(),
            "--key",
            "as-test",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("setgroups failed"), "{err}");
    assert!(err.contains("start anchorstamp specification 0.4, layout 1, source profile S"), "{err}");
    assert!(!err.contains("ready "), "{err}");
    // the sink exists (created before the drop) but holds nothing
    assert_eq!(std::fs::metadata(d.join("sightings.bin")).unwrap().len(), 0);
    assert!(!d.join("anchor.pub").exists(), "no anchor: the source holds no key");
}

#[test]
fn refuses_an_existing_sink() {
    let d = fresh_dir("exists");
    let log = d.join("audit.log");
    std::fs::write(&log, b"").unwrap();
    std::fs::write(d.join("sightings.bin"), b"").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_anchorstamp-observe-audit"))
        .args(["--audit-log", log.to_str().unwrap(), "--sink", d.to_str().unwrap(), "--key", "k"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!err.contains("start "), "stopped before the start line: {err}");
}

#[test]
fn refuses_a_symlinked_sink() {
    let d = fresh_dir("link");
    let log = d.join("audit.log");
    std::fs::write(&log, b"").unwrap();
    std::os::unix::fs::symlink(d.join("elsewhere"), d.join("sightings.bin")).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_anchorstamp-observe-audit"))
        .args(["--audit-log", log.to_str().unwrap(), "--sink", d.to_str().unwrap(), "--key", "k"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(!d.join("elsewhere").exists());
}

#[test]
fn bad_arguments_exit_before_opening_anything() {
    for args in
        [&[][..], &["--key"][..], &["--audit-log", "x", "--sink", "y"][..], &["--bogus", "1"][..]]
    {
        let out = Command::new(env!("CARGO_BIN_EXE_anchorstamp-observe-audit"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
    }
}

fn euid() -> u32 {
    // read from /proc rather than calling into libc from the test
    let s = std::fs::read_to_string("/proc/self/status").unwrap();
    let l = s.lines().find(|l| l.starts_with("Uid:")).unwrap();
    l.split_whitespace().nth(2).unwrap().parse().unwrap()
}

//! A crashed signer leaves no core and no key. A child copy of the signer
//! — key from the random source, locked, used to sign, dumpable 0 as the
//! observer sets it — exports its key the way the leak-test build does,
//! then aborts. The parent checks that no core was dumped and that the
//! child's output holds no form of the key.
//!
//! No control run with dumpable left at 1: on a host whose core pattern
//! pipes to a crash reporter, that would write the key into a crash
//! report.

#[path = "common/forms.rs"]
mod forms;

use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::ExitStatusExt;
use std::process::Command;

use anchorstamp_observe_audit::emit::Chain;
use ed25519_dalek::SigningKey;

const CHILD: &str = "ANCHORSTAMP_CRASH_CHILD_KEY_FILE";

#[test]
fn crash_child() {
    let Some(key_file) = std::env::var_os(CHILD) else { return };
    let mut seed = Box::new([0u8; 32]);
    // SAFETY: plain syscalls on this process; the range is a live boxed
    // array; the rlimit struct is a valid local.
    unsafe {
        assert_eq!(libc::mlock(seed.as_ptr().cast(), seed.len()), 0);
        let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::getrlimit(libc::RLIMIT_CORE, &mut lim);
        lim.rlim_cur = lim.rlim_max;
        libc::setrlimit(libc::RLIMIT_CORE, &lim);
    }
    getrandom::fill(&mut seed[..]).unwrap();
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(key_file)
        .unwrap();
    std::io::Write::write_all(&mut f, &seed[..]).unwrap();
    drop(f);
    let key = SigningKey::from_bytes(&seed);
    let rec = Chain::new(&key, [0x11; 16]).instance_start(1);
    eprintln!("child signed a record of {} bytes", rec.len());
    // SAFETY: prctl on this process, then abort, which does not return.
    unsafe {
        assert_eq!(libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0), 0);
        assert_eq!(libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0), 0);
        eprintln!("child dumpable=0, aborting");
        libc::abort();
    }
}

#[test]
fn crashed_signer_leaves_no_core_and_no_key() {
    if std::env::var_os(CHILD).is_some() {
        return;
    }
    let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("crash-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let key_file = dir.join("key");
    let out = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "crash_child", "--nocapture", "--test-threads=1"])
        .env(CHILD, &key_file)
        .current_dir(&dir)
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("child dumpable=0, aborting"), "child did not reach the crash: {err}");
    assert_eq!(out.status.signal(), Some(libc::SIGABRT), "{err}");
    assert!(!out.status.core_dumped(), "a core was dumped");
    let seed = std::fs::read(&key_file).unwrap();
    assert_eq!(seed.len(), 32);
    assert!(!forms::leaks(&out.stdout, &seed), "key in the child's stdout");
    assert!(!forms::leaks(&out.stderr, &seed), "key in the child's stderr");
    for e in std::fs::read_dir(&dir).unwrap() {
        let name = e.unwrap().file_name();
        assert!(name == "key", "unexpected file after the crash: {name:?}");
    }
}

//! Every line the observer can log, and every record it emits, searched
//! for the signing key in raw, hex and base64 form.

#[path = "common/forms.rs"]
mod forms;

use anchorstamp_core::ENDED_ROTATED;
use anchorstamp_observe_audit::emit::{Chain, frame};
use anchorstamp_observe_audit::msg;
use anchorstamp_observe_audit::parse::{Arch, Exec};
use ed25519_dalek::SigningKey;
use forms::leaks;

#[test]
fn no_emitted_string_or_record_holds_the_key() {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).unwrap();
    let mut instance = [0u8; 16];
    getrandom::fill(&mut instance).unwrap();
    let key = SigningKey::from_bytes(&seed);
    let mut c = Chain::new(&key, instance);
    let ex = |pid, exe: Vec<u8>| Exec {
        time_ms: 1_793_418_742_202,
        serial: 10417,
        arch: Arch::X86_64,
        syscall: 59,
        pid,
        ppid: pid - 1,
        exe,
        line_truncated: false,
    };
    let mut emitted: Vec<Vec<u8>> = vec![
        frame(&c.instance_start(1_793_418_742_000)),
        frame(&c.exec(&ex(600464, b"/usr/bin/dash".to_vec()))),
        frame(&c.exec(&ex(600476, vec![b'd'; 1647]))),
        frame(&c.parse_reject(1)),
        frame(&c.stream_ended(ENDED_ROTATED)),
    ];
    let instance_hex: String = instance.iter().map(|b| format!("{b:02x}")).collect();
    let lines = [
        msg::USAGE.to_string(),
        msg::LEAK_TEST.to_string(),
        msg::ANCHOR_WRITTEN.to_string(),
        msg::error("create /var/lib/anchorstamp/run-x/sink/sightings.bin failed: File exists"),
        msg::error("mlock key failed"),
        msg::error("dumpable reads 2 after the drop"),
        msg::error("random source failed"),
        msg::ptrace_scope(1),
        msg::start(&instance_hex, 1_793_418_742_000, 8_028_003),
        msg::dropped(0),
        msg::sighting(1, 600464, 600463, 59, 13),
        msg::parse_reject(3, 1),
        msg::stream_ended(ENDED_ROTATED, "log renamed or removed", 2, 1, 8_030_000),
        msg::stopped(2, 1, 0, 8_030_000),
    ];
    emitted.extend(lines.iter().map(|l| format!("{}{l}\n", msg::PREFIX).into_bytes()));

    for (n, e) in emitted.iter().enumerate() {
        assert!(!leaks(e, &seed), "emitted item {n} holds the key");
    }
    // the search finds a key that is there, in every form
    for f in forms::forms(&seed) {
        let mut planted = b"prefix ".to_vec();
        planted.extend_from_slice(&f);
        assert!(leaks(&planted, &seed));
    }
}

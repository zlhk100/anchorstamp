//! The reader is pure: none of its sources names a source of randomness,
//! a clock or the network.

#[test]
fn no_randomness_clock_or_network_in_the_sources() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = 0;
    for e in std::fs::read_dir(&dir).unwrap() {
        let p = e.unwrap().path();
        if p.extension().is_none_or(|x| x != "rs") {
            continue;
        }
        files += 1;
        let text = std::fs::read_to_string(&p).unwrap();
        for word in ["getrandom", "OsRng", "SystemTime", "Instant", "std::net"] {
            assert!(!text.contains(word), "{} names {word}", p.display());
        }
    }
    assert!(files >= 6, "the reader's sources were found");
}

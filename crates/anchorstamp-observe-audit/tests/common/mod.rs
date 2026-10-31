//! The probe lines. The file stores each 0x1D separator as the four
//! characters `\x1d` so it stays a text file; the real lines hold no
//! backslash, so the escape is unambiguous.

pub const KEY: &[u8] = b"as-probe-600389";

pub fn probe() -> Vec<u8> {
    let raw: &[u8] = include_bytes!("../data/probe-syscall.txt");
    assert!(!raw.contains(&0x1d), "test data must keep 0x1D escaped");
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i..].starts_with(b"\\x1d") {
            out.push(0x1d);
            i += 4;
        } else {
            out.push(raw[i]);
            i += 1;
        }
    }
    out
}

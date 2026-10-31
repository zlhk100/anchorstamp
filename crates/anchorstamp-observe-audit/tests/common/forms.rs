//! The forms a leaked key could take in text or bytes: raw, hex in either
//! case, and base64.

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for c in b.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                out.push(B64[(n >> (18 - 6 * i) & 63) as usize]);
            } else {
                out.push(b'=');
            }
        }
    }
    out
}

/// Raw, lower hex, upper hex, base64 — and base64 of the key at each byte
/// offset modulo 3, since an encoder may start mid-group. The last three
/// are cut to whole groups so they match wherever the key sits.
pub fn forms(key: &[u8]) -> Vec<Vec<u8>> {
    let lower: String = key.iter().map(|b| format!("{b:02x}")).collect();
    let mut v = vec![key.to_vec(), lower.clone().into_bytes(), lower.to_uppercase().into_bytes()];
    for skip in 0..3 {
        let e = base64(&key[skip..]);
        v.push(e[..(e.len() - 4)].to_vec());
    }
    v
}

pub fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Whether any form of `key` appears in `hay`.
pub fn leaks(hay: &[u8], key: &[u8]) -> bool {
    forms(key).iter().any(|f| contains(hay, f))
}

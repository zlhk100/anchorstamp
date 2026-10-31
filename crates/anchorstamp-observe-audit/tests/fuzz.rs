//! Parser property: 100,000 mutated lines. No panic, and every accepted
//! line's fields equal those an independent reference tokeniser reads.

use anchorstamp_observe_audit::parse::{Arch, LINE_MAX, Line, LineBuf, classify};

const KEY: &[u8] = b"as-probe-600389";
const PROBE: &[u8] = include_bytes!("data/probe-syscall.txt");

/// Deterministic mutation source for the test; not cryptographic.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

/// Reference reader, written separately: walks the kernel part byte by
/// byte, collects every name=value, and decodes values its own way.
/// Returns (time_ms, serial, arch, syscall, pid, ppid, exe) for a line it
/// considers a well-formed exec record of the run.
/// (time_ms, serial, arch, syscall, pid, ppid, exe)
type Fields = (u64, u64, u32, u32, u32, u32, Vec<u8>);

fn reference(line: &[u8]) -> Option<Fields> {
    let end = line.iter().position(|&b| b == 0x1d).unwrap_or(line.len());
    // values of fields nobody reads may hold any byte; required ones are ASCII
    let owned = String::from_utf8_lossy(&line[..end]);
    let text: &str = &owned;
    let mut names: Vec<String> = Vec::new();
    let mut values: Vec<String> = Vec::new();
    let mut start = 0;
    let bytes = text.as_bytes();
    let mut i = 0;
    while i <= bytes.len() {
        if i == bytes.len() || bytes[i] == b' ' {
            let tok = &text[start..i];
            let eq = tok.find('=')?;
            names.push(tok[..eq].to_string());
            values.push(tok[eq + 1..].to_string());
            start = i + 1;
        }
        i += 1;
    }
    let field = |n: &str| -> Option<&str> {
        let idx: Vec<usize> = (0..names.len()).filter(|&k| names[k] == n).collect();
        if idx.len() == 1 { Some(values[idx[0]].as_str()) } else { None }
    };
    if names.first()? != "type" || values[0] != "SYSCALL" {
        return None;
    }
    let msg = field("msg")?;
    let inner = msg.strip_prefix("audit(")?.strip_suffix("):")?;
    let (sec, rest) = inner.split_once('.')?;
    let (ms, serial) = rest.split_once(':')?;
    if ms.len() != 3 {
        return None;
    }
    let time_ms = sec.parse::<u64>().ok()? * 1000 + ms.parse::<u64>().ok()?;
    let arch = u32::from_str_radix(field("arch")?, 16).ok()?;
    let syscall: u32 = field("syscall")?.parse().ok()?;
    let pid: u32 = field("pid")?.parse().ok()?;
    let ppid: u32 = field("ppid")?.parse().ok()?;
    let raw = field("exe")?;
    let exe = if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') {
        raw.as_bytes()[1..raw.len() - 1].to_vec()
    } else {
        (0..raw.len())
            .step_by(2)
            .map(|k| u8::from_str_radix(raw.get(k..k + 2)?, 16).ok())
            .collect::<Option<Vec<u8>>>()?
    };
    Some((time_ms, serial.parse().ok()?, arch, syscall, pid, ppid, exe))
}

fn mutate(rng: &mut XorShift, seeds: &[Vec<u8>]) -> Vec<u8> {
    let mut l = seeds[rng.below(seeds.len())].clone();
    for _ in 0..1 + rng.below(4) {
        match rng.below(10) {
            0 => {
                let at = rng.below(l.len());
                l[at] = rng.next() as u8;
            }
            1 => {
                let at = rng.below(l.len());
                l.insert(at, b' ');
            }
            2 => {
                let n = rng.below(l.len());
                l.truncate(n);
            }
            3 => {
                // duplicate a token
                let toks: Vec<&[u8]> = l.split(|&b| b == b' ').collect();
                let t = toks[rng.below(toks.len())].to_vec();
                l.push(b' ');
                l.extend_from_slice(&t);
            }
            4 => {
                let at = rng.below(l.len());
                l.insert(at, 0x1d);
            }
            5 => {
                let at = rng.below(l.len());
                let len = rng.below(64);
                l.splice(at..at, (0..len).map(|_| rng.next() as u8));
            }
            6 => {
                // swap two tokens
                let mut toks: Vec<Vec<u8>> = l.split(|&b| b == b' ').map(<[u8]>::to_vec).collect();
                let (a, b) = (rng.below(toks.len()), rng.below(toks.len()));
                toks.swap(a, b);
                l = toks.join(&b' ');
            }
            7 => {
                // replace exe with random bytes, hex encoded
                let raw: Vec<u8> = (0..rng.below(3000)).map(|_| rng.next() as u8).collect();
                let hex: String = raw.iter().map(|b| format!("{b:02X}")).collect();
                let s = String::from_utf8_lossy(&l).into_owned();
                if let Some(p) = s.find(" exe=") {
                    let q = s[p + 5..].find(' ').map(|q| p + 5 + q).unwrap_or(s.len());
                    l = format!("{} exe={}{}", &s[..p], hex, &s[q..]).into_bytes();
                }
            }
            8 => l.extend(std::iter::repeat_n(b'z', rng.below(2 * LINE_MAX))),
            _ => {} // unchanged
        }
        if l.is_empty() {
            break;
        }
    }
    l.retain(|&b| b != b'\n');
    l
}

#[test]
fn hundred_thousand_mutated_lines() {
    let mut seeds = Vec::new();
    LineBuf::new(false).feed(PROBE, &mut |l, _| seeds.push(l.to_vec()));
    let mut rng = XorShift(0x2545_f491_4f6c_dd1d);
    let (mut accepted, mut rejected, mut other) = (0u32, 0u32, 0u32);
    for _ in 0..100_000 {
        let mut stream = mutate(&mut rng, &seeds);
        stream.push(b'\n');
        let mut got = Vec::new();
        LineBuf::new(false).feed(&stream, &mut |l, t| got.push((l.to_vec(), t)));
        for (line, truncated) in got {
            match classify(&line, truncated, KEY) {
                Line::Exec(e) => {
                    accepted += 1;
                    let r = reference(&line).unwrap_or_else(|| {
                        panic!(
                            "reference rejects an accepted line: {}",
                            String::from_utf8_lossy(&line)
                        )
                    });
                    let arch = match e.arch {
                        Arch::X86_64 => 0xc000_003e,
                        Arch::I386 => 0x4000_0003,
                    };
                    assert_eq!(
                        (e.time_ms, e.serial, arch, e.syscall, e.pid, e.ppid, e.exe.clone()),
                        r,
                        "{}",
                        String::from_utf8_lossy(&line)
                    );
                }
                Line::Reject => rejected += 1,
                Line::Other => other += 1,
            }
        }
    }
    eprintln!("accepted={accepted} rejected={rejected} other={other}");
    assert!(accepted > 10_000 && rejected > 10_000, "mutations exercise both paths");
}

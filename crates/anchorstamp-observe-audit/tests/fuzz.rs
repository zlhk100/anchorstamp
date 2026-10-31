//! Parser property: 100,000 mutated lines. No panic, and the parser
//! sights a line exactly when an independent reference reader says the
//! line is one of the run's execs — with the same fields.

mod common;

use anchorstamp_observe_audit::parse::{Arch, LINE_MAX, Line, LineBuf, classify};
use common::{KEY, probe};

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

/// (time_ms, serial, arch, syscall, pid, ppid, exe, line_truncated)
type Fields = (u64, u64, u32, u32, u32, u32, Vec<u8>, bool);

/// Reference reader, written separately from the parser and from the
/// grammar as stated: the kernel part (before the first 0x1D; for a line
/// cut by the limit with no 0x1D, without its last token), `type=SYSCALL`
/// then `msg=audit(S.MMM:N):`, then name=value tokens with unique
/// [A-Za-z0-9_] names, bare tokens allowed only straight after `subj=`.
/// Then the full filter: x86_64 execve/execveat or i386 execve/execveat,
/// success=yes, key equal to the run key, exe present and not empty.
/// Some only for a line that is one of the run's execs.
fn reference(line: &[u8], truncated: bool) -> Option<Fields> {
    let (kernel, cut) = match line.iter().position(|&b| b == 0x1d) {
        Some(i) => (&line[..i], false),
        None => (line, truncated),
    };
    let mut toks: Vec<&[u8]> = Vec::new();
    let mut from = 0;
    for i in 0..=kernel.len() {
        if i == kernel.len() || kernel[i] == b' ' {
            toks.push(&kernel[from..i]);
            from = i + 1;
        }
    }
    if cut {
        if toks.len() < 2 {
            return None;
        }
        toks.pop();
    }
    if toks.len() < 2 || toks[0] != b"type=SYSCALL" {
        return None;
    }
    let digits = |v: &[u8]| -> Option<u64> {
        if v.is_empty() || v.len() > 20 || v.iter().any(|b| !b.is_ascii_digit()) {
            return None;
        }
        v.iter().try_fold(0u64, |a, &b| a.checked_mul(10)?.checked_add(u64::from(b - b'0')))
    };
    let inner = toks[1].strip_prefix(b"msg=audit(")?.strip_suffix(b"):")?;
    let dot = inner.iter().position(|&b| b == b'.')?;
    let rest = &inner[dot + 1..];
    let colon = rest.iter().position(|&b| b == b':')?;
    if colon != 3 {
        return None;
    }
    let time_ms = digits(&inner[..dot])?.checked_mul(1000)?.checked_add(digits(&rest[..3])?)?;
    let serial = digits(&rest[4..])?;

    let mut names: Vec<&[u8]> = vec![b"type", b"msg"];
    let mut values: Vec<&[u8]> = vec![b"", b""];
    let mut after_subj = false;
    for t in &toks[2..] {
        match t.iter().position(|&b| b == b'=') {
            None if after_subj && !t.is_empty() => continue,
            None => return None,
            Some(eq) => {
                let name = &t[..eq];
                if name.is_empty()
                    || name.iter().any(|b| !(b.is_ascii_alphanumeric() || *b == b'_'))
                    || names.contains(&name)
                {
                    return None;
                }
                after_subj = name == b"subj";
                names.push(name);
                values.push(&t[eq + 1..]);
            }
        }
    }
    let field = |n: &[u8]| names.iter().position(|x| *x == n).map(|i| values[i]);
    let small = |v: &[u8]| digits(v).and_then(|n| u32::try_from(n).ok());
    let text = |v: &[u8]| -> Option<Option<Vec<u8>>> {
        if v == b"(null)" {
            return Some(None);
        }
        if v.len() >= 2 && v[0] == b'"' && v[v.len() - 1] == b'"' {
            let inner = &v[1..v.len() - 1];
            return inner
                .iter()
                .all(|&b| b > b' ' && b < 0x7f && b != b'"')
                .then(|| Some(inner.to_vec()));
        }
        if v.is_empty() || v.len() % 2 == 1 {
            return None;
        }
        let nib = |c: u8| match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        };
        v.chunks(2)
            .map(|p| Some(nib(p[0])? * 16 + nib(p[1])?))
            .collect::<Option<Vec<u8>>>()
            .map(Some)
    };
    let arch_v = field(b"arch")?;
    if arch_v.is_empty() || arch_v.len() > 8 {
        return None;
    }
    let arch = u32::from_str_radix(std::str::from_utf8(arch_v).ok()?, 16).ok()?;
    if !arch_v.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let syscall = small(field(b"syscall")?)?;
    let success = field(b"success")?;
    let pid = small(field(b"pid")?)?;
    let ppid = small(field(b"ppid")?)?;
    let exe = text(field(b"exe")?)?;
    let key = text(field(b"key")?)?;
    let exec_call = match arch {
        0xc000_003e => syscall == 59 || syscall == 322,
        0x4000_0003 => syscall == 11 || syscall == 358,
        _ => false,
    };
    if !exec_call || success != b"yes" || key.as_deref() != Some(KEY) {
        return None;
    }
    let exe = exe.filter(|e| !e.is_empty())?;
    Some((time_ms, serial, arch, syscall, pid, ppid, exe, cut))
}

fn mutate(rng: &mut XorShift, seeds: &[Vec<u8>]) -> Vec<u8> {
    let mut l = seeds[rng.below(seeds.len())].clone();
    for _ in 0..1 + rng.below(4) {
        match rng.below(12) {
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
            9 => {
                // the filter and the label: change one value that decides
                // whether the line is ours, or give subj= a spaced label
                let s = String::from_utf8_lossy(&l).into_owned();
                let swaps = [
                    ("success=yes", "success=no"),
                    ("key=\"as-probe-600389\"", "key=\"as-other\""),
                    ("key=\"as-probe-600389\"", "key=(null)"),
                    ("syscall=59", "syscall=11"),
                    ("arch=c000003e", "arch=40000003"),
                    ("subj=unconfined", "subj=/usr/bin/man (enforce)"),
                    ("subj=unconfined", "subj=x (a) (b)"),
                ];
                let (a, b) = swaps[rng.below(swaps.len())];
                l = s.replacen(a, b, 1).into_bytes();
            }
            10 => {
                // drop the enrichment and pad past the limit: a cut line
                if let Some(c) = l.iter().position(|&b| b == 0x1d) {
                    l.truncate(c);
                }
                l.push(b' ');
                l.extend(std::iter::repeat_n(b'z', LINE_MAX + rng.below(LINE_MAX)));
            }
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
    LineBuf::new(false).feed(&probe(), &mut |l, _| seeds.push(l.to_vec()));
    let mut rng = XorShift(0x2545_f491_4f6c_dd1d);
    let (mut accepted, mut rejected, mut other, mut cut) = (0u32, 0u32, 0u32, 0u32);
    for _ in 0..100_000 {
        let mut stream = mutate(&mut rng, &seeds);
        stream.push(b'\n');
        let mut got = Vec::new();
        LineBuf::new(false).feed(&stream, &mut |l, t| got.push((l.to_vec(), t)));
        for (line, truncated) in got {
            let r = reference(&line, truncated);
            let shown = || String::from_utf8_lossy(&line[..line.len().min(400)]).into_owned();
            match classify(&line, truncated, KEY) {
                Line::Exec(e) => {
                    accepted += 1;
                    cut += u32::from(e.line_truncated);
                    let r = r.unwrap_or_else(|| {
                        panic!("reference rejects an accepted line: {}", shown())
                    });
                    let arch = match e.arch {
                        Arch::X86_64 => 0xc000_003e,
                        Arch::I386 => 0x4000_0003,
                    };
                    assert_eq!(
                        (
                            e.time_ms,
                            e.serial,
                            arch,
                            e.syscall,
                            e.pid,
                            e.ppid,
                            e.exe.clone(),
                            e.line_truncated
                        ),
                        r,
                        "{}",
                        shown()
                    );
                }
                l => {
                    assert!(r.is_none(), "parser drops an exec of the run ({l:?}): {}", shown());
                    match l {
                        Line::Reject => rejected += 1,
                        _ => other += 1,
                    }
                }
            }
        }
    }
    eprintln!("accepted={accepted} (cut {cut}) rejected={rejected} other={other}");
    assert!(
        accepted > 10_000 && rejected > 10_000 && other > 1_000,
        "mutations exercise every path"
    );
    assert!(cut > 100, "cut lines are exercised");
}

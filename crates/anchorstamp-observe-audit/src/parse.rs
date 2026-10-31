//! Audit SYSCALL record parser.
//!
//! The input is untrusted: the measured party chooses executable paths.
//! Only the kernel part of a line is read — everything from the first 0x1D
//! byte on is the log daemon's enrichment and is ignored. The kernel part
//! is split on single spaces into `key=value` tokens, matched by whole
//! key. A SYSCALL record with a duplicate key, a token without `=`, an
//! empty token, or a required field that does not parse is rejected.
//! Records of other types are not ours and are not examined further.
//!
//! One exception to "every token has `=`": the tokens directly after
//! `subj=` that carry no `=` are the rest of a security-module label with
//! spaces in it (`subj=/usr/bin/man (enforce)`). Labels come from policy,
//! not from the measured party, whose strings the kernel hex-encodes when
//! they hold a space; those tokens are skipped.
//!
//! A line cut by the length limit before any 0x1D is read up to its last
//! whole token — the final token may be partial and is dropped. If the
//! record is still complete enough to be ours it is sighted and flagged;
//! otherwise it is rejected.

/// Longest line kept; the rest is dropped and the line marked truncated.
pub const LINE_MAX: usize = 16 * 1024;

/// Longest executable path copied into observed data.
pub const EXE_DATA_MAX: usize = 1015;

const ENRICHMENT: u8 = 0x1D;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    I386,
}

/// A SYSCALL record that passed the filter: an exec syscall for its
/// architecture, success=yes and the run's key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exec {
    pub time_ms: u64,
    pub serial: u64,
    pub arch: Arch,
    pub syscall: u32,
    pub pid: u32,
    pub ppid: u32,
    /// Executable path, decoded, complete.
    pub exe: Vec<u8>,
    /// The line was longer than `LINE_MAX` and cut before any 0x1D.
    pub line_truncated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Line {
    /// One of ours: becomes exactly one sighting.
    Exec(Exec),
    /// Well-formed and not ours.
    Other,
    /// Does not match the grammar.
    Reject,
}

/// Exec syscall numbers per architecture.
pub fn is_exec(arch: Arch, syscall: u32) -> bool {
    match arch {
        Arch::X86_64 => syscall == 59 || syscall == 322,
        Arch::I386 => syscall == 11 || syscall == 358,
    }
}

/// Classify one line (without its newline). `truncated` says the line was
/// longer than `LINE_MAX` and only its first `LINE_MAX` bytes are here.
pub fn classify(line: &[u8], truncated: bool, run_key: &[u8]) -> Line {
    let (kernel, cut) = match line.iter().position(|&b| b == ENRICHMENT) {
        Some(i) => (&line[..i], false),
        None => (line, truncated),
    };
    let mut tokens: Vec<&[u8]> = kernel.split(|&b| b == b' ').collect();
    match tokens[0] {
        _ if cut && tokens.len() == 1 => return Line::Reject,
        b"type=SYSCALL" => {}
        t if t.starts_with(b"type=") && t.len() > 5 => return Line::Other,
        _ => return Line::Reject,
    }
    if cut {
        tokens.pop();
    }
    let Some((time_ms, serial)) = tokens.get(1).copied().and_then(parse_msg) else {
        return Line::Reject;
    };
    let mut fields: Vec<(&[u8], &[u8])> = Vec::with_capacity(32);
    fields.push((b"type", b"SYSCALL"));
    fields.push((b"msg", b""));
    let mut in_label = false;
    for &t in &tokens[2..] {
        let Some(eq) = t.iter().position(|&b| b == b'=') else {
            if in_label && !t.is_empty() {
                continue;
            }
            return Line::Reject;
        };
        let (k, v) = (&t[..eq], &t[eq + 1..]);
        if k.is_empty() || !k.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_') {
            return Line::Reject;
        }
        if fields.iter().any(|(fk, _)| *fk == k) {
            return Line::Reject;
        }
        in_label = k == b"subj";
        fields.push((k, v));
    }
    let get = |k: &[u8]| fields.iter().find(|(fk, _)| *fk == k).map(|(_, v)| *v);

    let (Some(arch), Some(syscall), Some(success), Some(pid), Some(ppid), Some(exe), Some(key)) = (
        get(b"arch"),
        get(b"syscall"),
        get(b"success"),
        get(b"pid"),
        get(b"ppid"),
        get(b"exe"),
        get(b"key"),
    ) else {
        return Line::Reject;
    };
    let (Some(arch), Some(syscall), Some(success), Some(pid), Some(ppid)) = (
        parse_hex_u32(arch),
        parse_dec::<u32>(syscall),
        parse_success(success),
        parse_dec::<u32>(pid),
        parse_dec::<u32>(ppid),
    ) else {
        return Line::Reject;
    };
    let Some(exe) = parse_string(exe) else {
        return Line::Reject;
    };
    let Some(key) = parse_string(key) else {
        return Line::Reject;
    };
    let arch = match arch {
        0xC000_003E => Arch::X86_64,
        0x4000_0003 => Arch::I386,
        _ => return Line::Other,
    };
    if !is_exec(arch, syscall) || !success || key.as_deref() != Some(run_key) {
        return Line::Other;
    }
    match exe {
        Some(exe) if !exe.is_empty() => {
            Line::Exec(Exec { time_ms, serial, arch, syscall, pid, ppid, exe, line_truncated: cut })
        }
        _ => Line::Reject,
    }
}

/// `msg=audit(SECONDS.MMM:SERIAL):` -> (milliseconds, serial).
fn parse_msg(t: &[u8]) -> Option<(u64, u64)> {
    let inner = t.strip_prefix(b"msg=audit(")?.strip_suffix(b"):")?;
    let dot = inner.iter().position(|&b| b == b'.')?;
    let colon = inner.iter().position(|&b| b == b':')?;
    if colon < dot {
        return None;
    }
    let sec: u64 = parse_dec(&inner[..dot])?;
    let ms_digits = &inner[dot + 1..colon];
    if ms_digits.len() != 3 {
        return None;
    }
    let ms: u64 = parse_dec(ms_digits)?;
    let serial: u64 = parse_dec(&inner[colon + 1..])?;
    Some((sec.checked_mul(1000)?.checked_add(ms)?, serial))
}

fn parse_dec<T: std::str::FromStr>(v: &[u8]) -> Option<T> {
    if v.is_empty() || v.len() > 20 || !v.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(v).ok()?.parse().ok()
}

fn parse_hex_u32(v: &[u8]) -> Option<u32> {
    if v.is_empty() || v.len() > 8 || !v.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    u32::from_str_radix(std::str::from_utf8(v).ok()?, 16).ok()
}

fn parse_success(v: &[u8]) -> Option<bool> {
    match v {
        b"yes" => Some(true),
        b"no" => Some(false),
        _ => None,
    }
}

/// An audit untrusted-string value: `"quoted"` (printable, no quote, no
/// space), upper-case hex, or `(null)`. Outer `None`: does not parse.
fn parse_string(v: &[u8]) -> Option<Option<Vec<u8>>> {
    if v == b"(null)" {
        return Some(None);
    }
    if let Some(inner) = v.strip_prefix(b"\"").and_then(|r| r.strip_suffix(b"\"")) {
        if !inner.iter().all(|&b| (0x21..=0x7e).contains(&b) && b != b'"') {
            return None;
        }
        return Some(Some(inner.to_vec()));
    }
    if v.is_empty() || v.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(v.len() / 2);
    for pair in v.chunks_exact(2) {
        let hi = upper_hex(pair[0])?;
        let lo = upper_hex(pair[1])?;
        out.push(hi << 4 | lo);
    }
    Some(Some(out))
}

fn upper_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Splits a byte stream into lines of at most `LINE_MAX` bytes, keeping a
/// partial last line until its newline arrives.
#[derive(Debug)]
pub struct LineBuf {
    buf: Vec<u8>,
    truncated: bool,
    skipping: bool,
}

impl LineBuf {
    /// `skip_first`: the stream starts mid-line; drop bytes up to the
    /// first newline.
    pub fn new(skip_first: bool) -> LineBuf {
        LineBuf { buf: Vec::with_capacity(LINE_MAX), truncated: false, skipping: skip_first }
    }

    /// Feed bytes; `line` is called with each complete line and whether it
    /// was truncated.
    pub fn feed(&mut self, mut data: &[u8], line: &mut dyn FnMut(&[u8], bool)) {
        while !data.is_empty() {
            let nl = data.iter().position(|&b| b == b'\n');
            let chunk = &data[..nl.unwrap_or(data.len())];
            if !self.skipping {
                let room = LINE_MAX - self.buf.len();
                if chunk.len() > room {
                    self.truncated = true;
                }
                self.buf.extend_from_slice(&chunk[..chunk.len().min(room)]);
            }
            match nl {
                Some(i) => {
                    if !self.skipping {
                        line(&self.buf, self.truncated);
                    }
                    self.skipping = false;
                    self.buf.clear();
                    self.truncated = false;
                    data = &data[i + 1..];
                }
                None => data = &[],
            }
        }
    }

    /// Bytes held for a line not yet ended.
    pub fn pending(&self) -> usize {
        self.buf.len()
    }
}

/// Observed-data flag: the path copy is truncated.
pub const FLAG_EXE_TRUNCATED: u8 = 1;
/// Observed-data flag: the audit line was cut by the length limit.
pub const FLAG_LINE_TRUNCATED: u8 = 2;

/// Observed data of an execution sighting: flags u8 (bit 0: path
/// truncated; bit 1: audit line truncated) · ppid u32 · path (at most
/// `EXE_DATA_MAX` bytes).
pub fn exec_data(e: &Exec) -> Vec<u8> {
    let mut flags = 0;
    if e.exe.len() > EXE_DATA_MAX {
        flags |= FLAG_EXE_TRUNCATED;
    }
    if e.line_truncated {
        flags |= FLAG_LINE_TRUNCATED;
    }
    let mut d = Vec::with_capacity(5 + EXE_DATA_MAX);
    d.push(flags);
    d.extend_from_slice(&e.ppid.to_be_bytes());
    d.extend_from_slice(&e.exe[..e.exe.len().min(EXE_DATA_MAX)]);
    d
}

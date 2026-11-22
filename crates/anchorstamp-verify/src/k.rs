//! Profile K: kernel exec records carried in IMA's binary measurement list
//! (template `ima-buf`, PCR 13), anchored by TPM quotes signed by a pinned
//! attestation key.
//!
//! `build` runs the validation steps in order: parse the list and keep the
//! PCR-13 entries in list order; replay them; validate each quote (parse,
//! ECDSA P-256 over SHA-256 of the attestation, selection, PCR digest);
//! find the attested prefix; check each quote's extraData against the
//! entries; decode each entry's record; check each load's order; check
//! that loads do not interleave. A record in the attested prefix is valid
//! at ATTESTED and decisive; a record after it (the tail) is valid at
//! SOFTWARE and capped Unanchored.
//!
//! The attestation key is never taken from the evidence: the operator pins
//! it, as a 91-byte DER `SubjectPublicKeyInfo` for a P-256 point.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use anchorstamp_core::Strength;
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::{Evidence, ExecRecord, Instance, Loss, Profile, Span, Within};

/// The fixed DER prefix of a `SubjectPublicKeyInfo` for an uncompressed
/// P-256 point: SEQUENCE, `AlgorithmIdentifier` (id-ecPublicKey,
/// prime256v1), BIT STRING of 66 bytes with no unused bits.
pub const AK_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];
/// Length of that `SubjectPublicKeyInfo`.
pub const AK_SPKI_LEN: usize = 91;

const PCR_ANCHOR: u32 = 13;
const TEMPLATE_BUF: &[u8] = b"ima-buf";
const EVENT_NAME: &[u8] = b"exec\0";
const DNG_PREFIX: &[u8] = b"sha256:\0";
const ATTEST_MAGIC: u32 = 0xFF54_4347;
const ATTEST_QUOTE: u16 = 0x8018;
const ALG_ECDSA: u16 = 0x0018;
const ALG_SHA256: u16 = 0x000B;

/// One quote as the collector delivers it.
#[derive(Clone, Copy, Debug)]
pub struct Quote<'a> {
    /// `TPMS_ATTEST`, TPM marshalling.
    pub attest: &'a [u8],
    /// `TPMT_SIGNATURE`.
    pub signature: &'a [u8],
    /// The 32-byte SHA-256 value of PCR 7.
    pub pcr7: &'a [u8],
}

/// Everything profile K reads.
#[derive(Clone, Copy, Debug)]
pub struct Bundle<'a> {
    /// The binary measurement list, one boot.
    pub list: &'a [u8],
    pub quotes: &'a [Quote<'a>],
    /// The pinned AK, supplied by the operator, never from the bundle.
    pub ak_spki: &'a [u8],
    /// The boot id the collector copied.
    pub boot_id: Option<[u8; 16]>,
    /// The auditor's nonce, when one was given.
    pub nonce: Option<&'a [u8]>,
    /// The configured quote interval, seconds (reported).
    pub interval_s: Option<u32>,
}

/// One entry of the measurement list.
struct Entry<'a> {
    pcr: u32,
    template: &'a [u8],
    data: &'a [u8],
}

/// Entries of a measurement list copy (little-endian host), and how many
/// were read before the list stopped parsing, if it did.
fn parse_list(blob: &[u8]) -> (Vec<Entry<'_>>, bool) {
    let mut out = Vec::new();
    let mut r = Le { b: blob, at: 0 };
    while r.at < blob.len() {
        let Some(e) = entry(&mut r) else { return (out, true) };
        out.push(e);
    }
    (out, false)
}

fn entry<'a>(r: &mut Le<'a>) -> Option<Entry<'a>> {
    let pcr = r.u32()?;
    r.take(20)?; // the listed digest: SHA-1, never used
    let nlen = r.u32()? as usize;
    let template = r.take(nlen)?;
    // the original "ima" template carries no data length: not readable
    if template == b"ima" {
        return None;
    }
    let tlen = r.u32()? as usize;
    let data = r.take(tlen)?;
    Some(Entry { pcr, template, data })
}

/// Little-endian reader.
struct Le<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Le<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let out = self.b.get(self.at..end)?;
        self.at = end;
        Some(out)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4).map(|b| u32::from_le_bytes(b.try_into().expect("4 bytes")))
    }
    fn u64(&mut self) -> Option<u64> {
        self.take(8).map(|b| u64::from_le_bytes(b.try_into().expect("8 bytes")))
    }
    fn arr<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N).map(|b| b.try_into().expect("N bytes"))
    }
    fn done(&self) -> bool {
        self.at == self.b.len()
    }
}

/// Big-endian reader, for TPM marshalling.
struct Be<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Be<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let out = self.b.get(self.at..end)?;
        self.at = end;
        Some(out)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4).map(|b| u32::from_be_bytes(b.try_into().expect("4 bytes")))
    }
    fn u64(&mut self) -> Option<u64> {
        self.take(8).map(|b| u64::from_be_bytes(b.try_into().expect("8 bytes")))
    }
    fn tpm2b(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
    fn done(&self) -> bool {
        self.at == self.b.len()
    }
}

/// The fields of a `TPMS_ATTEST` of type quote that the reader uses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attest {
    pub extra_data: Vec<u8>,
    pub clock: u64,
    pub reset_count: u32,
    pub restart_count: u32,
    pub safe: bool,
    /// (hash algorithm, select bitmap) per bank.
    pub selection: Vec<(u16, Vec<u8>)>,
    pub pcr_digest: Vec<u8>,
}

/// Parse a `TPMS_ATTEST` of type quote. No trailing bytes.
#[must_use]
pub fn parse_attest(b: &[u8]) -> Option<Attest> {
    let mut r = Be { b, at: 0 };
    if r.u32()? != ATTEST_MAGIC || r.u16()? != ATTEST_QUOTE {
        return None;
    }
    r.tpm2b()?; // qualifiedSigner
    let extra = r.tpm2b()?;
    if extra.len() > 48 {
        return None;
    }
    let clock = r.u64()?;
    let reset_count = r.u32()?;
    let restart_count = r.u32()?;
    let safe = r.u8()? != 0;
    r.u64()?; // firmwareVersion
    let banks = r.u32()?;
    let mut selection = Vec::new();
    for _ in 0..banks {
        let alg = r.u16()?;
        let n = r.u8()? as usize;
        selection.push((alg, r.take(n)?.to_vec()));
    }
    let pcr_digest = r.tpm2b()?.to_vec();
    if !r.done() {
        return None;
    }
    Some(Attest {
        extra_data: extra.to_vec(),
        clock,
        reset_count,
        restart_count,
        safe,
        selection,
        pcr_digest,
    })
}

/// Parse a `TPMT_SIGNATURE`: ECDSA, SHA-256, r and s each 1..32 bytes,
/// big-endian, left-padded to 32. No trailing bytes. Values out of
/// [1, n-1] are rejected by the signature type.
#[must_use]
pub fn parse_signature(b: &[u8]) -> Option<Signature> {
    let mut r = Be { b, at: 0 };
    if r.u16()? != ALG_ECDSA || r.u16()? != ALG_SHA256 {
        return None;
    }
    let rr = r.tpm2b()?;
    let ss = r.tpm2b()?;
    if !r.done() || !(1..=32).contains(&rr.len()) || !(1..=32).contains(&ss.len()) {
        return None;
    }
    let pad = |v: &[u8]| {
        let mut out = [0u8; 32];
        out[32 - v.len()..].copy_from_slice(v);
        out
    };
    Signature::from_scalars(pad(rr), pad(ss)).ok()
}

/// The pinned AK: exactly 91 bytes, the fixed prefix, a point on P-256.
#[must_use]
pub fn parse_ak(spki: &[u8]) -> Option<VerifyingKey> {
    if spki.len() != AK_SPKI_LEN || spki[..26] != AK_SPKI_PREFIX {
        return None;
    }
    VerifyingKey::from_sec1_bytes(&spki[26..]).ok()
}

/// Exactly one bank, SHA-256, selecting PCRs 7 and 13 and nothing else.
fn selection_ok(sel: &[(u16, Vec<u8>)]) -> bool {
    let [(alg, bits)] = sel else { return false };
    if *alg != ALG_SHA256 {
        return false;
    }
    let mut set = Vec::new();
    for (i, byte) in bits.iter().enumerate() {
        for bit in 0..8 {
            if byte & (1 << bit) != 0 {
                set.push(i * 8 + bit);
            }
        }
    }
    set == [7, 13]
}

/// A decoded record of the shim, v1 or v2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Body {
    Exec(ExecFields),
    Load { shim_version: u16, loaded_ns: u64 },
    Armed { armed_ns: u64 },
    Lost { count: u64, first_ns: Option<u64>, last_ns: Option<u64> },
    Unload { close_ns: Option<u64>, unloaded_ns: Option<u64> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecFields {
    pub pid: u32,
    pub tgid: u32,
    pub ppid: u32,
    pub old_pid: u32,
    pub uid: u32,
    pub euid: u32,
    pub start_ns: u64,
    /// v2 only.
    pub exec_ns: Option<u64>,
    pub dev: Option<u32>,
    pub ino: Option<u64>,
    /// v2: 32 bytes; v1: the 20-byte digest, zero-padded, never compared.
    pub exe_digest: [u8; 32],
    pub req_digest: Option<[u8; 32]>,
    pub ns: Option<u8>,
    pub truncated: bool,
    pub unresolved: bool,
    pub interpreted: bool,
    pub path: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub v1: bool,
    pub seq: u64,
    pub load_id: [u8; 16],
    pub body: Body,
}

const PATH_CAP: usize = 1024;

/// Decode one record, v2 ("ASX2") or v1 ("ASX1"). `None` when malformed.
#[must_use]
pub fn decode_record(buf: &[u8]) -> Option<Record> {
    match buf.get(..4)? {
        b"ASX2" => decode_v2(buf),
        b"ASX1" => decode_v1(buf),
        _ => None,
    }
}

/// pid, tgid, ppid, `old_pid`, uid, euid: six u32 in that order.
fn ids(r: &mut Le) -> Option<[u32; 6]> {
    Some([r.u32()?, r.u32()?, r.u32()?, r.u32()?, r.u32()?, r.u32()?])
}

fn header(r: &mut Le) -> Option<(u8, u8, u64, [u8; 16])> {
    r.take(4)?;
    let k = r.u8()?;
    Some((k & 0x0F, k & 0xF0, r.u64()?, r.arr()?))
}

fn decode_v2(buf: &[u8]) -> Option<Record> {
    let mut r = Le { b: buf, at: 0 };
    let (kind, flags, seq, load_id) = header(&mut r)?;
    if flags & 0x10 != 0 || (kind != 1 && flags != 0) {
        return None;
    }
    let body = match kind {
        1 => {
            let [pid, tgid, ppid, old_pid, uid, euid] = ids(&mut r)?;
            let start_ns = r.u64()?;
            let exec_ns = r.u64()?;
            let dev = r.u32()?;
            let ino = r.u64()?;
            let exe_digest: [u8; 32] = r.arr()?;
            let req_digest: [u8; 32] = r.arr()?;
            let ns = r.u8()?;
            let path_len = r.u16()? as usize;
            let path = r.take(path_len)?.to_vec();
            let (truncated, unresolved) = (flags & 0x80 != 0, flags & 0x40 != 0);
            if !r.done()
                || ns & 0xF0 != 0
                || path_len > PATH_CAP
                || (truncated && path_len != PATH_CAP)
                || (unresolved && (path_len != 0 || exe_digest != [0; 32]))
                || (truncated && unresolved)
                || start_ns > exec_ns
            {
                return None;
            }
            Body::Exec(ExecFields {
                pid,
                tgid,
                ppid,
                old_pid,
                uid,
                euid,
                start_ns,
                exec_ns: Some(exec_ns),
                dev: Some(dev),
                ino: Some(ino),
                exe_digest,
                req_digest: Some(req_digest),
                ns: Some(ns),
                truncated,
                unresolved,
                interpreted: flags & 0x20 != 0,
                path,
            })
        }
        2 => Body::Load { shim_version: r.u16()?, loaded_ns: r.u64()? },
        3 => {
            let (count, first, last) = (r.u64()?, r.u64()?, r.u64()?);
            if count == 0 || first > last {
                return None;
            }
            Body::Lost { count, first_ns: Some(first), last_ns: Some(last) }
        }
        4 => Body::Unload { close_ns: Some(r.u64()?), unloaded_ns: Some(r.u64()?) },
        5 => Body::Armed { armed_ns: r.u64()? },
        _ => return None,
    };
    r.done().then_some(Record { v1: false, seq, load_id, body })
}

fn decode_v1(buf: &[u8]) -> Option<Record> {
    let mut r = Le { b: buf, at: 0 };
    let (kind, flags, seq, load_id) = header(&mut r)?;
    if flags & 0x30 != 0 || (kind != 1 && flags != 0) {
        return None;
    }
    let body = match kind {
        1 => {
            let [pid, tgid, ppid, old_pid, uid, euid] = ids(&mut r)?;
            let start_ns = r.u64()?;
            let d20: [u8; 20] = r.arr()?;
            let path_len = r.u16()? as usize;
            let path = r.take(path_len)?.to_vec();
            let (truncated, unresolved) = (flags & 0x80 != 0, flags & 0x40 != 0);
            if !r.done()
                || path_len > PATH_CAP
                || (truncated && path_len != PATH_CAP)
                || (unresolved && (path_len != 0 || d20 != [0; 20]))
                || (truncated && unresolved)
            {
                return None;
            }
            let mut exe_digest = [0u8; 32];
            exe_digest[..20].copy_from_slice(&d20);
            Body::Exec(ExecFields {
                pid,
                tgid,
                ppid,
                old_pid,
                uid,
                euid,
                start_ns,
                exec_ns: None,
                dev: None,
                ino: None,
                exe_digest,
                req_digest: None,
                ns: None,
                truncated,
                unresolved,
                interpreted: false,
                path,
            })
        }
        2 => Body::Load { shim_version: r.u16()?, loaded_ns: r.u64()? },
        3 => Body::Lost { count: r.u64()?, first_ns: None, last_ns: None },
        4 => Body::Unload { close_ns: None, unloaded_ns: None },
        _ => return None,
    };
    r.done().then_some(Record { v1: true, seq, load_id, body })
}

/// The record a PCR-13 entry carries, after checking the entry: template
/// `ima-buf`, three fields, d-ng = "sha256:" NUL then SHA-256 of the
/// buffer, n-ng = "exec" NUL. `None`: the entry is foreign or malformed.
fn entry_record(e: &Entry) -> Option<Record> {
    if e.template != TEMPLATE_BUF {
        return None;
    }
    let mut r = Le { b: e.data, at: 0 };
    let mut fields = Vec::new();
    while !r.done() {
        let n = r.u32()? as usize;
        fields.push(r.take(n)?);
    }
    let [dng, nng, buf] = fields[..] else { return None };
    if nng != EVENT_NAME {
        return None;
    }
    let digest: [u8; 32] = Sha256::digest(buf).into();
    if dng.len() != DNG_PREFIX.len() + 32 || dng[..8] != *DNG_PREFIX || dng[8..] != digest {
        return None;
    }
    decode_record(buf)
}

/// `V_0` = 32 zero bytes; `V_k` = SHA-256(`V_{k-1}` || template digest of `e_k`).
fn running(digests: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut v = vec![[0u8; 32]];
    for d in digests {
        let mut h = Sha256::new();
        h.update(v[v.len() - 1]);
        h.update(d);
        v.push(h.finalize().into());
    }
    v
}

/// The running PCR 13 values of a measurement list: `V_0` .. `V_n` over its
/// PCR-13 entries in list order, every entry replayed whatever its
/// template.
#[must_use]
pub fn replay(list: &[u8]) -> Vec<[u8; 32]> {
    let (all, _) = parse_list(list);
    let digests: Vec<[u8; 32]> =
        all.iter().filter(|e| e.pcr == PCR_ANCHOR).map(|e| Sha256::digest(e.data).into()).collect();
    running(&digests)
}

/// A valid quote: where its PCR digest matched the replay, and its fields.
struct Valid {
    k: usize,
    at: Attest,
}

/// Build profile K evidence.
#[must_use]
pub fn build(bundle: &Bundle) -> Evidence {
    let mut ev = Evidence::empty(Profile::K);
    ev.facts.interval_s = bundle.interval_s;
    ev.facts.quotes = bundle.quotes.len() as u64;

    // 1  parse; keep PCR-13 entries in list order. What does not parse is
    // excluded and counted; a quote over the lost entries then matches no
    // prefix and is a break when the quotes are checked.
    let (all, cut) = parse_list(bundle.list);
    if cut {
        ev.facts.list_unreadable_after = Some(all.len() as u64);
        ev.excluded += 1;
    }
    let entries: Vec<&Entry> = all.iter().filter(|e| e.pcr == PCR_ANCHOR).collect();
    let count = entries.len();
    ev.facts.entries = count as u64;

    // 2  replay: values[k] is PCR 13 after the first k entries
    let digests: Vec<[u8; 32]> = entries.iter().map(|e| Sha256::digest(e.data).into()).collect();
    let values = running(&digests);

    // 3  quotes
    let ak = parse_ak(bundle.ak_spki);
    ev.facts.ak_usable = ak.is_some();
    let mut valid: Vec<Valid> = Vec::new();
    for (n, quote) in bundle.quotes.iter().enumerate() {
        let Some(at) = check_quote(ak.as_ref(), quote) else {
            ev.excluded += 1;
            continue;
        };
        ev.facts.quotes_valid += 1;
        let pcr7: [u8; 32] = quote.pcr7.try_into().expect("checked 32 bytes");
        if !ev.facts.pcr7.contains(&pcr7) {
            ev.facts.pcr7.push(pcr7);
        }
        if !ev.facts.reset_counts.contains(&at.reset_count) {
            ev.facts.reset_counts.push(at.reset_count);
        }
        let matched = values.iter().position(|value| {
            let mut hash = Sha256::new();
            hash.update(pcr7);
            hash.update(value);
            at.pcr_digest[..] == hash.finalize()[..]
        });
        match matched {
            Some(k) => valid.push(Valid { k, at }),
            None => brk(&mut ev, format!("quote {} matches no prefix of the list", n + 1)),
        }
    }
    if let Some(nonce) = bundle.nonce {
        ev.facts.nonce_quoted = Some(valid.iter().any(|q| q.at.extra_data == nonce));
    }

    // 4  the attested prefix
    let attested = valid.iter().map(|q| q.k).max().unwrap_or(0);
    ev.facts.attested = attested as u64;
    ev.facts.tail_empty = attested == count;

    // 5  a quote naming an entry by its template digest must cover it
    for quote in &valid {
        let named: Vec<usize> =
            (1..=count).filter(|&j| quote.at.extra_data[..] == digests[j - 1][..]).collect();
        if !named.is_empty() && !named.iter().any(|&j| j <= quote.k) {
            let why = format!("a quote names entry {} but covers only {}", named[0], quote.k);
            brk(&mut ev, why);
        }
    }

    // 6  records
    let records: Vec<(usize, Record)> = entries
        .iter()
        .enumerate()
        .filter_map(|(i, e)| {
            let r = entry_record(e);
            if r.is_none() {
                ev.excluded += 1;
            }
            r.map(|r| (i + 1, r))
        })
        .collect();
    ev.valid = records.len() as u64;

    // 7, 8  per load
    loads(&mut ev, &records, &valid, attested, bundle.boot_id);
    ev
}

/// A quote that parses, verifies under the pinned AK and selects exactly
/// SHA-256 PCRs 7 and 13, with a 32-byte PCR 7 value beside it.
fn check_quote(ak: Option<&VerifyingKey>, q: &Quote) -> Option<Attest> {
    let ak = ak?;
    let at = parse_attest(q.attest)?;
    let sig = parse_signature(q.signature)?;
    ak.verify(q.attest, &sig).ok()?;
    (selection_ok(&at.selection) && q.pcr7.len() == 32 && at.pcr_digest.len() == 32).then_some(at)
}

fn brk(ev: &mut Evidence, why: String) {
    ev.breaks += 1;
    ev.facts.break_reasons.push(why);
}

/// The anchor of entry `k`: the quotes before and at-or-after it.
fn anchor_of(k: usize, valid: &[Valid]) -> Option<Within> {
    let to = valid.iter().filter(|q| q.k >= k).min_by_key(|q| (q.k, q.at.clock))?;
    let from = valid.iter().filter(|q| q.k < k).max_by_key(|q| (q.k, q.at.clock));
    Some(Within {
        reset_count: to.at.reset_count,
        from: from.map(|q| q.at.clock),
        to: to.at.clock,
        restart_from: from.map(|q| q.at.restart_count),
        restart_to: to.at.restart_count,
        safe: to.at.safe,
    })
}

/// Steps 7 and 8, and the instances.
fn loads(
    ev: &mut Evidence,
    records: &[(usize, Record)],
    valid: &[Valid],
    m: usize,
    boot: Option<[u8; 16]>,
) {
    // list order of each load's records
    let mut by_load: BTreeMap<[u8; 16], Vec<usize>> = BTreeMap::new();
    for (i, (_, r)) in records.iter().enumerate() {
        by_load.entry(r.load_id).or_default().push(i);
    }
    // 8  interleaving: no record of another load inside a load's span
    let spans: Vec<([u8; 16], usize, usize)> = by_load
        .iter()
        .map(|(id, idx)| {
            let first = idx[0];
            let end = idx
                .iter()
                .copied()
                .find(|&i| matches!(records[i].1.body, Body::Unload { .. }))
                .unwrap_or(idx[idx.len() - 1]);
            (*id, first, end)
        })
        .collect();
    for (i, (_, r)) in records.iter().enumerate() {
        if let Some((other, _, _)) =
            spans.iter().find(|(id, a, z)| *id != r.load_id && *a < i && i < *z)
        {
            brk(
                ev,
                format!(
                    "load {} has a record inside load {}",
                    hex8(&r.load_id),
                    hex8(other)
                ),
            );
        }
    }

    for (id, idx) in &by_load {
        let mut inst = Instance::new(*id);
        inst.boot = boot;
        inst.mediated = true;
        inst.valid = idx.len() as u64;
        inst.v1 = records[idx[0]].1.v1;
        let mut seen: BTreeMap<u64, &Record> = BTreeMap::new();
        let mut expect = 0u64;
        let mut ended = false;
        for (pos, &i) in idx.iter().enumerate() {
            let (entry, r) = (&records[i].0, &records[i].1);
            let why = |s: &str| format!("load {}: {s} (seq {})", hex8(id), r.seq);
            if r.v1 != inst.v1 {
                brk(ev, why("mixes record versions"));
            }
            if ended {
                brk(ev, why("a record after UNLOAD"));
            }
            match (pos, &r.body) {
                (0, Body::Load { .. }) if r.seq == 0 => {}
                (0, _) => brk(ev, why("the first record is not LOAD with seq 0")),
                (_, Body::Load { .. }) => brk(ev, why("a second LOAD")),
                (1, Body::Armed { .. }) => {}
                (1, _) if !inst.v1 => brk(ev, why("the second record is not ARMED")),
                _ => {}
            }
            if let Some(prior) = seen.get(&r.seq) {
                if *prior == r {
                    brk(ev, why("a seq repeats"));
                } else {
                    ev.forks += 1;
                    brk(ev, why("two distinct records with one seq"));
                }
            } else if pos > 0 && r.seq < expect {
                brk(ev, why("seq goes back"));
            } else if pos > 0 && r.seq > expect {
                ev.gaps += 1;
                inst.gaps.push(Span { from: None, to: None });
            }
            seen.insert(r.seq, r);
            expect = expect.max(r.seq.saturating_add(1));

            let decisive = ev.facts.ak_usable && *entry <= m;
            match &r.body {
                Body::Load { loaded_ns, .. } if pos == 0 => inst.lo_c = Some(*loaded_ns),
                Body::Armed { armed_ns } if pos == 1 && !inst.v1 => {
                    inst.cov_from = Some(*armed_ns);
                }
                Body::Unload { close_ns, unloaded_ns } => {
                    ended = true;
                    inst.unloaded = true;
                    inst.close_c = *close_ns;
                    inst.hi_c = *unloaded_ns;
                }
                Body::Lost { count, first_ns, last_ns } => {
                    inst.losses.push(Loss {
                        count: *count,
                        first: first_ns.unwrap_or(0),
                        last: last_ns.unwrap_or(u64::MAX),
                    });
                }
                Body::Exec(x) => inst.records.push(exec_record(x, r, *entry, decisive, valid)),
                _ => {}
            }
        }
        ev.instances.push(inst);
    }
}

fn exec_record(x: &ExecFields, r: &Record, entry: usize, decisive: bool, valid: &[Valid]) -> ExecRecord {
    let (lo, hi) = match x.exec_ns {
        Some(t) => (t, t),
        None => (x.start_ns, u64::MAX),
    };
    // path-stable: v2, ns bits 1-3 clear, path resolved
    let stable = !r.v1 && x.ns.is_some_and(|ns| ns & 0x0E == 0) && !x.unresolved;
    ExecRecord {
        pid: x.pid,
        lo,
        hi,
        fork: Some(x.start_ns),
        exe_digest: x.exe_digest,
        req_digest: x.req_digest,
        interpreted: x.interpreted,
        stable,
        decisive,
        uid: Some(x.uid),
        euid: Some(x.euid),
        ppid: Some(x.ppid),
        path: x.path.clone(),
        path_truncated: x.truncated,
        path_unresolved: x.unresolved,
        ns: x.ns,
        self_prov: false,
        strength: if decisive { Strength::ATTESTED } else { Strength::SOFTWARE },
        position: r.seq,
        entry: Some(entry),
        anchor: if decisive { anchor_of(entry, valid) } else { None },
        v1: r.v1,
    }
}

fn hex8(id: &[u8; 16]) -> String {
    id[..4].iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

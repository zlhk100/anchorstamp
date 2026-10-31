//! anchorstamp-core — record types and the layout-0 wire encoding.
//!
//! No dependencies, no hashing, no signatures. A subject is a scheme tag
//! and opaque bytes; this crate names no platform concept.
//!
//! All integers on the wire are unsigned big-endian.

#![no_std]
#![forbid(unsafe_code)]

mod backed;
mod wire;

pub use backed::{Backed, Cost, Field, Provenance, provenance};
pub use wire::{
    DecodeError, EncodeError, decode_joinref, decode_sighting, encode_joinref, encode_sighting,
};

/// Layout number this crate encodes and decodes.
pub const LAYOUT: u8 = 0;

/// Prefix of every sighting record.
pub const SIGHTING_PREFIX: &[u8; 20] = b"anchorstamp/sighting";
/// Prefix of every join reference.
pub const JOINREF_PREFIX: &[u8; 19] = b"anchorstamp/joinref";

/// Bounds on variable-length fields.
pub const SUBJECT_MAX: usize = 32;
pub const OBSERVED_MAX: usize = 1024;
pub const SELF_PROV_MAX: usize = 256;

/// Length of the signature that ends every sighting.
pub const SIGNATURE_LEN: usize = 64;

/// Longest possible sighting encoding.
pub const SIGHTING_MAX_LEN: usize = 20 + 1 // prefix, layout
    + 3 + SUBJECT_MAX                      // subject
    + 4 + OBSERVED_MAX                     // observed
    + 11                                   // coverage
    + 1 + 4 + SELF_PROV_MAX                // self-provenance
    + 16 + 8 + 32                          // seq
    + 3                                    // source
    + 32                                   // key id
    + SIGNATURE_LEN;

/// Longest possible join reference encoding.
pub const JOINREF_MAX_LEN: usize = 19 + 1 + 3 + SUBJECT_MAX;

/// Observed-data class shared with `coverage.over`.
pub const CLASS_COMMAND_EXECUTION: u16 = 1;

/// Proof-of-concept observer control records, under `SchemeTag::OBSERVER`.
/// Never executions. Index 0 of every instance; data = coverage start in
/// milliseconds, u64.
pub const CLASS_INSTANCE_START: u16 = 0xFFFD;
/// Emitted after each rejected input line; data = cumulative count, u64.
pub const CLASS_PARSE_REJECT: u16 = 0xFFFE;
/// Last record when the input ends abnormally; data = reason, u8.
pub const CLASS_STREAM_ENDED: u16 = 0xFFFF;

/// `CLASS_STREAM_ENDED` reasons.
pub const ENDED_ROTATED: u8 = 1;
pub const ENDED_SHRUNK: u8 = 2;
pub const ENDED_READ_ERROR: u8 = 3;

/// Scheme registry tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SchemeTag(pub u16);

impl SchemeTag {
    /// Proof-of-concept observer control records; subject = instance id.
    pub const OBSERVER: SchemeTag = SchemeTag(0xFFFD);
    /// Proof-of-concept scheme. Never accepted by a conforming reader.
    pub const DEMO: SchemeTag = SchemeTag(0xFFFE);
    /// Conformance-test scheme.
    pub const TEST: SchemeTag = SchemeTag(0xFFFF);
}

/// A subject: a scheme tag and 1..=32 opaque bytes.
///
/// Deliberately not `PartialEq`: subjects are compared only through a
/// scheme's own functions, never by whole-byte equality.
#[derive(Clone, Copy, Debug)]
pub struct SubjectRef {
    scheme: SchemeTag,
    len: u8,
    bytes: [u8; SUBJECT_MAX],
}

impl SubjectRef {
    /// `None` when `bytes` is empty or longer than 32.
    pub fn new(scheme: SchemeTag, bytes: &[u8]) -> Option<SubjectRef> {
        if bytes.is_empty() || bytes.len() > SUBJECT_MAX {
            return None;
        }
        let mut buf = [0u8; SUBJECT_MAX];
        buf[..bytes.len()].copy_from_slice(bytes);
        Some(SubjectRef { scheme, len: bytes.len() as u8, bytes: buf })
    }

    pub fn scheme(&self) -> SchemeTag {
        self.scheme
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

/// Ordered evidence strength. Comparable; not a closed set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Strength(u16);

impl Strength {
    pub const SOFTWARE: Strength = Strength(100);
    pub const KEYED: Strength = Strength(200);
    pub const COUNTER: Strength = Strength(300);
    pub const ATTESTED: Strength = Strength(400);
    pub const MEASURED: Strength = Strength(500);

    pub const fn get(self) -> u16 {
        self.0
    }
}

/// The library's reference to the event it caused, in its own scheme.
/// Carries no authority.
#[derive(Clone, Copy, Debug)]
pub struct JoinRef {
    subject: SubjectRef,
}

impl JoinRef {
    pub fn new(subject: SubjectRef) -> JoinRef {
        JoinRef { subject }
    }

    pub fn subject(&self) -> &SubjectRef {
        &self.subject
    }
}

/// Where the producer stood. Elevated without a reference is
/// unrepresentable.
#[derive(Clone, Copy, Debug)]
pub enum Vantage {
    Local,
    Elevated(JoinRef),
}

/// Observed data: a class and up to 1024 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observed<'a> {
    pub class: u16,
    pub data: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoverageMode {
    Mediated,
    Sampled,
}

impl CoverageMode {
    fn to_wire(self) -> u8 {
        match self {
            CoverageMode::Mediated => 1,
            CoverageMode::Sampled => 2,
        }
    }

    fn from_wire(v: u8) -> Option<CoverageMode> {
        match v {
            1 => Some(CoverageMode::Mediated),
            2 => Some(CoverageMode::Sampled),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Coverage {
    pub mode: CoverageMode,
    pub from: u64,
    pub over: u16,
}

/// Self-provenance reference: a kind and 1..=256 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelfProv<'a> {
    pub kind: u16,
    pub reference: &'a [u8],
}

/// Sequence position of a sighting within its observer instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seq {
    pub instance: [u8; 16],
    pub index: u64,
    pub prev: [u8; 32],
}

/// The sequence source the observer declares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SequenceSource {
    None,
    Declared(u16),
}

/// Every field of a sighting, borrowed.
#[derive(Clone, Copy, Debug)]
pub struct SightingParts<'a> {
    pub subject: SubjectRef,
    pub observed: Observed<'a>,
    pub coverage: Coverage,
    pub self_prov: Option<SelfProv<'a>>,
    pub seq: Seq,
    pub source: SequenceSource,
    pub key_id: [u8; 32],
    pub signature: [u8; SIGNATURE_LEN],
}

/// A decoded sighting and the bytes it was decoded from.
#[derive(Clone, Copy, Debug)]
pub struct SightingView<'a> {
    pub parts: SightingParts<'a>,
    raw: &'a [u8],
}

impl<'a> SightingView<'a> {
    /// The complete encoding, signature included.
    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }

    /// The bytes the signature covers: prefix through key id.
    pub fn signed(&self) -> &'a [u8] {
        &self.raw[..self.raw.len() - SIGNATURE_LEN]
    }
}

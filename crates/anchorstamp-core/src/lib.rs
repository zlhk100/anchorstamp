// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright © 2026 Lei Zhou

//! anchorstamp-core — record types and the layout-1 wire encoding.
//!
//! No dependencies, no hashing, no signatures. A subject is a scheme tag
//! and opaque bytes; this crate names no platform concept.
//!
//! All integers on the wire are unsigned big-endian.

#![no_std]
#![forbid(unsafe_code)]

mod wire;

pub use wire::{
    DecodeError, EncodeError, decode_joinref, decode_sighting, encode_joinref, encode_sighting,
};

/// Layout number this crate encodes and decodes.
pub const LAYOUT: u8 = 1;

/// Prefix of every sighting record.
pub const SIGHTING_PREFIX: &[u8; 20] = b"anchorstamp/sighting";
/// Prefix of every join reference.
pub const JOINREF_PREFIX: &[u8; 19] = b"anchorstamp/joinref";

/// Bounds on variable-length fields.
pub const SUBJECT_MAX: usize = 64;
pub const OBSERVED_MAX: usize = 1024;
pub const SELF_PROV_MAX: usize = 256;

/// Longest possible sighting encoding.
pub const SIGHTING_MAX_LEN: usize = 20 + 1 // prefix, layout
    + 3 + SUBJECT_MAX                      // subject
    + 4 + OBSERVED_MAX                     // observed
    + 11                                   // coverage
    + 1 + 4 + SELF_PROV_MAX                // self-provenance
    + 16 + 8 + 32                          // seq
    + 3; // source

/// Longest possible join reference encoding.
pub const JOINREF_MAX_LEN: usize = 19 + 1 + 3 + SUBJECT_MAX;

/// Observed-data class shared with `coverage.over`.
pub const CLASS_COMMAND_EXECUTION: u16 = 1;

/// Source control records, under `SchemeTag::OBSERVER`; the subject bytes
/// are the instance id. Never executions.
///
/// A source's clock moved by more than its tolerance between two samples;
/// data = the size of the move, u64. A hole, like a parse reject.
pub const CLASS_CLOCK_STEP: u16 = 0xFFFC;
/// First record of every instance; its data is defined by the source
/// profile.
pub const CLASS_INSTANCE_START: u16 = 0xFFFD;
/// Emitted after each rejected input; data = cumulative count, u64.
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
    /// The registry's first production scheme. This crate attaches no
    /// meaning to it; the scheme's functions live with the reader.
    pub const LINUX_EXEC: SchemeTag = SchemeTag(0x0001);
    /// Source control records; subject = instance id.
    pub const OBSERVER: SchemeTag = SchemeTag(0xFFFD);
    /// Conformance-test scheme.
    pub const TEST: SchemeTag = SchemeTag(0xFFFF);
}

/// A subject: a scheme tag and 1..=64 opaque bytes.
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
    /// `None` when `bytes` is empty or longer than 64.
    pub fn new(scheme: SchemeTag, bytes: &[u8]) -> Option<SubjectRef> {
        let len = u8::try_from(bytes.len()).ok()?;
        if bytes.is_empty() || bytes.len() > SUBJECT_MAX {
            return None;
        }
        let mut buf = [0u8; SUBJECT_MAX];
        buf[..bytes.len()].copy_from_slice(bytes);
        Some(SubjectRef { scheme, len, bytes: buf })
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

/// Sequence position of a sighting within its source instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seq {
    pub instance: [u8; 16],
    pub index: u64,
    pub prev: [u8; 32],
}

/// The sequence source the source declares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SequenceSource {
    None,
    Declared(u16),
}

/// Every field of a sighting, borrowed. Layout 1 carries no key id and
/// no signature.
#[derive(Clone, Copy, Debug)]
pub struct SightingParts<'a> {
    pub subject: SubjectRef,
    pub observed: Observed<'a>,
    pub coverage: Coverage,
    pub self_prov: Option<SelfProv<'a>>,
    pub seq: Seq,
    pub source: SequenceSource,
}

/// A decoded sighting and the bytes it was decoded from.
#[derive(Clone, Copy, Debug)]
pub struct SightingView<'a> {
    pub parts: SightingParts<'a>,
    raw: &'a [u8],
}

impl<'a> SightingView<'a> {
    /// The complete encoding: what the chain digest covers.
    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }
}

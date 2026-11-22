//! anchorstamp-verify — the reader.
//!
//! Declares: anchorstamp specification 0.4, layout 1, reader.
//!
//! Each evidence source is turned into one `Evidence` value by the builder
//! of its profile: `k::build` for kernel records carried in IMA's
//! measurement list and anchored by TPM quotes, `s::build` for unsigned
//! software sightings. The `LINUX_EXEC` rules in `exec` read only
//! `Evidence`, so a new profile adds a builder and nothing else. `test`
//! keeps the conformance-test scheme over unsigned sighting encodings.
//!
//! Pure: no network, no clock, no randomness. Malformed evidence is never
//! an error; it is excluded and counted.

use anchorstamp_core::{SchemeTag, Strength};

pub mod exec;
pub mod k;
pub mod s;
mod stream;
pub mod test;

pub use stream::chain_digest;

/// The evidence source profiles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    /// Kernel exec records in IMA's measurement list, TPM-anchored.
    K,
    /// Unsigned software sightings.
    S,
}

/// Where a decisive record sits between two TPM quotes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Within {
    /// The to-quote's resetCount.
    pub reset_count: u32,
    /// TPM clock of the latest valid quote before the record; none when no
    /// such quote exists.
    pub from: Option<u64>,
    /// TPM clock of the earliest valid quote at or after the record.
    pub to: u64,
    pub restart_from: Option<u32>,
    pub restart_to: u32,
    /// The to-quote's safe flag.
    pub safe: bool,
}

/// Time anchoring of an outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Anchor {
    None,
    Within(Within),
}

/// One exec record in the evidence-source contract form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecRecord {
    /// Process id in the initial PID namespace.
    pub pid: u32,
    /// The exec happened in `[lo, hi]` on the boot clock, ns. For S, `hi`
    /// is already `min(hi, lo + 2·tolerance)`; for a v1 record it is
    /// `u64::MAX`.
    pub lo: u64,
    pub hi: u64,
    /// The task's fork time, when the record carries one.
    pub fork: Option<u64>,
    /// SHA-256 of the executed file's path. Never compared on a v1 record,
    /// which is never path-stable.
    pub exe_digest: [u8; 32],
    /// SHA-256 of the requested path (K); none for S.
    pub req_digest: Option<[u8; 32]>,
    pub interpreted: bool,
    /// Path-stable: the path names the file from the initial root.
    pub stable: bool,
    /// In a K attested prefix.
    pub decisive: bool,
    pub uid: Option<u32>,
    pub euid: Option<u32>,
    pub ppid: Option<u32>,
    /// The path bytes the record carries, for the report.
    pub path: Vec<u8>,
    pub path_truncated: bool,
    pub path_unresolved: bool,
    /// K: the ns byte.
    pub ns: Option<u8>,
    /// S: the sighting carries self-provenance.
    pub self_prov: bool,
    pub strength: Strength,
    /// Index in its instance: K seq, S sighting index.
    pub position: u64,
    /// K: the record's entry in the PCR-13 list, counted from 1.
    pub entry: Option<usize>,
    /// K: the anchor of a record in the attested prefix.
    pub anchor: Option<Within>,
    pub v1: bool,
}

/// A count of execs not recorded, and the time interval holding them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Loss {
    pub count: u64,
    pub first: u64,
    pub last: u64,
}

/// A gap in an instance's record, on the boot clock. An open side is
/// unbounded; a K sequence gap is open on both sides: it touches every
/// claim of its load.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    pub from: Option<u64>,
    pub to: Option<u64>,
}

/// One instance: a K load or an S observer instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instance {
    pub id: [u8; 16],
    /// The boot id the instance observed, as asserted by its source.
    pub boot: Option<[u8; 16]>,
    /// No exec at a time at or before `lo_c` is recorded.
    pub lo_c: Option<u64>,
    /// No exec at a time at or after `hi_c` is recorded.
    pub hi_c: Option<u64>,
    /// Every exec after `cov_from` and before `close_c` is delivered.
    pub close_c: Option<u64>,
    pub cov_from: Option<u64>,
    pub mediated: bool,
    pub records: Vec<ExecRecord>,
    pub losses: Vec<Loss>,
    /// Inputs the source could not read and clock steps: each touches
    /// every claim of the instance.
    pub holes: u64,
    pub gaps: Vec<Span>,
    /// A v1 load: reported, never joined, touches every claim.
    pub v1: bool,
    /// S: the instance's tolerance.
    pub tolerance_ns: Option<u32>,
    /// S: the highest parse-reject count.
    pub rejects: u64,
    /// S: clock-step records.
    pub clock_steps: u64,
    /// S: the stream-ended reason, when the instance ended abnormally.
    pub ended: Option<u8>,
    /// K: the load ended with UNLOAD.
    pub unloaded: bool,
    /// Valid records of every kind, control records included.
    pub valid: u64,
}

impl Instance {
    pub(crate) fn new(id: [u8; 16]) -> Instance {
        Instance {
            id,
            boot: None,
            lo_c: None,
            hi_c: None,
            close_c: None,
            cov_from: None,
            mediated: false,
            records: Vec::new(),
            losses: Vec::new(),
            holes: 0,
            gaps: Vec::new(),
            v1: false,
            tolerance_ns: None,
            rejects: 0,
            clock_steps: 0,
            ended: None,
            unloaded: false,
            valid: 0,
        }
    }
}

/// Facts the report states per source. For S only `rejects` and the
/// counts apply.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Facts {
    /// K: the pinned AK parsed as a P-256 point in the expected form.
    pub ak_usable: bool,
    /// K: whether a valid quote carries the auditor's nonce; none when no
    /// nonce was given.
    pub nonce_quoted: Option<bool>,
    /// K: a valid quote follows the last record.
    pub tail_empty: bool,
    /// K: the configured quote interval, seconds.
    pub interval_s: Option<u32>,
    /// K: PCR 7 as each valid quote binds it, distinct values.
    pub pcr7: Vec<[u8; 32]>,
    /// K: resetCount of each valid quote, distinct values.
    pub reset_counts: Vec<u32>,
    /// K: quotes given, and how many were valid.
    pub quotes: u64,
    pub quotes_valid: u64,
    /// K: PCR-13 entries in the list, and how many are attested.
    pub entries: u64,
    pub attested: u64,
    /// K: the list could not be parsed past this many entries.
    pub list_unreadable_after: Option<u64>,
    /// K: one line per BREAK, in plain words.
    pub break_reasons: Vec<String>,
}

/// One evidence source, in contract form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    pub profile: Profile,
    pub instances: Vec<Instance>,
    /// Valid records of every kind.
    pub valid: u64,
    pub gaps: u64,
    pub breaks: u64,
    pub forks: u64,
    pub excluded: u64,
    pub facts: Facts,
}

impl Evidence {
    pub(crate) fn empty(profile: Profile) -> Evidence {
        Evidence {
            profile,
            instances: Vec::new(),
            valid: 0,
            gaps: 0,
            breaks: 0,
            forks: 0,
            excluded: 0,
            facts: Facts::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Detail {
    SubjectMismatch,
    Unobserved,
}

/// Why an outcome sits at its strength. Listed in this order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Cap {
    SelfProvAbsent,
    SelfProvUnappraised,
    SequenceUnappraised,
    AnchorOperatorAsserted,
    TransportOperatorAsserted,
    BootConfigUnappraised,
    EkChainUnvalidated,
    AkPinnedLocally,
    BootAsserted,
    PathUnverified,
    RootCanInsert,
    Interpreted,
    Unanchored,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    Agrees {
        strength: Strength,
        scheme: SchemeTag,
        caps: Vec<Cap>,
        /// Further matching records beside the earliest.
        also: u32,
    },
    Disagrees {
        detail: Detail,
        strength: Strength,
        caps: Vec<Cap>,
    },
    /// One `[lo_c, hi_c)` per instance of the claim's boot; `hi_c` open
    /// when absent.
    NotCovered {
        windows: Vec<(u64, Option<u64>)>,
    },
    NothingToCompare,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Health {
    pub gaps: u64,
    pub breaks: u64,
    pub forks: u64,
    pub excluded: u64,
    pub touches_claim: bool,
    /// K: any break in the source.
    pub evidence_broken: bool,
}

/// Delivery path as the deployment declares it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeclaredPath {
    Direct,
    Relayed { hops: u16 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Path {
    Direct,
    Relayed { hops: u16 },
    NothingArrived,
}

impl Path {
    /// The declared path, or `NothingArrived` when no valid record did.
    #[must_use]
    pub fn of(declared: DeclaredPath, arrived: bool) -> Path {
        match (arrived, declared) {
            (false, _) => Path::NothingArrived,
            (true, DeclaredPath::Direct) => Path::Direct,
            (true, DeclaredPath::Relayed { hops }) => Path::Relayed { hops },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub kind: Kind,
    pub health: Health,
    pub path: Path,
    pub anchor: Anchor,
}

/// A valid exec record that no claim accounts for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Unclaimed {
    pub instance: [u8; 16],
    pub index: u64,
}

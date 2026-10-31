//! The producer's return value. Every field is fixed at construction;
//! there is no setter and no way for a caller to supply strength,
//! vantage or backing.

use anchorstamp_core::{Strength, Vantage};

/// Per-call cost class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cost {
    /// The call spawned a child process.
    Spawn,
    /// The call did no work beyond its own process.
    InProcess,
}

/// Provenance class of a returned field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provenance {
    SdkAuthored,
    PlatformSourced,
}

/// The fields of a `Backed` value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    Result,
    Strength,
    Vantage,
    Backing,
    Degraded,
    Cost,
}

/// Provenance of each field. Total over `Field`.
pub const fn provenance(field: Field) -> Provenance {
    match field {
        Field::Result => Provenance::SdkAuthored,
        Field::Strength => Provenance::PlatformSourced,
        Field::Vantage => Provenance::SdkAuthored,
        Field::Backing => Provenance::PlatformSourced,
        Field::Degraded => Provenance::SdkAuthored,
        Field::Cost => Provenance::SdkAuthored,
    }
}

/// A result together with what backs it.
#[derive(Debug)]
pub struct Backed<T> {
    result: T,
    strength: Strength,
    vantage: Vantage,
    backing: &'static [&'static str],
    degraded: Option<&'static str>,
    cost: Cost,
}

impl<T> Backed<T> {
    pub(crate) fn new(
        result: T,
        strength: Strength,
        vantage: Vantage,
        backing: &'static [&'static str],
        degraded: Option<&'static str>,
        cost: Cost,
    ) -> Backed<T> {
        Backed { result, strength, vantage, backing, degraded, cost }
    }

    pub fn result(&self) -> &T {
        &self.result
    }

    pub fn strength(&self) -> Strength {
        self.strength
    }

    pub fn vantage(&self) -> &Vantage {
        &self.vantage
    }

    /// The primitives that ran, each named.
    pub fn backing(&self) -> &'static [&'static str] {
        self.backing
    }

    /// What was unavailable, if anything.
    pub fn degraded(&self) -> Option<&'static str> {
        self.degraded
    }

    pub fn cost(&self) -> Cost {
        self.cost
    }
}

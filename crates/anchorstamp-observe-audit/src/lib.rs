//! anchorstamp-observe-audit — the observer.
//!
//! Reads the kernel audit log through a descriptor opened before the
//! privilege drop, and turns each exec record carrying the run's key into
//! one signed, chained sighting. Accepts nothing from the measured
//! account. The parser and the record builder live here so they can be
//! tested without privilege; the start sequence is in the binary.

pub mod emit;
pub mod parse;

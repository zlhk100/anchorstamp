// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright © 2026 Lei Zhou

//! anchorstamp-observe-audit — the observer, a profile S source.
//!
//! Declares: anchorstamp specification 0.4, layout 1, source profile S.
//!
//! Reads the kernel audit log through a descriptor opened before the
//! privilege drop, and turns each exec record carrying the run's key into
//! one chained, unsigned sighting. Accepts nothing from the measured
//! account. The parser and the record builder live here so they can be
//! tested without privilege; the start sequence is in the binary.

pub mod emit;
pub mod msg;
pub mod parse;

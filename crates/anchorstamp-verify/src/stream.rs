// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright © 2026 Lei Zhou

//! Streams of layout-1 sightings, shared by profile S and the TEST scheme:
//! validation (a record is valid iff it parses), instances by index,
//! gaps, breaks and forks. Order of the input never matters.

use std::collections::BTreeMap;

use anchorstamp_core::{SchemeTag, SightingView, decode_sighting};
use sha2::{Digest, Sha256};

/// The `prev` value of the sighting that follows `prior`: SHA-256 over
/// "anchorstamp/chain", a zero byte and the complete encoding of `prior`.
#[must_use]
pub fn chain_digest(prior: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"anchorstamp/chain");
    h.update([0u8]);
    h.update(prior);
    h.finalize().into()
}

/// An inclusive range of indices with no valid sighting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Gap {
    pub from: u64,
    pub to: u64,
}

/// The valid sightings of one instance, by index. Several distinct records
/// at one index are a fork; identical copies count once.
#[derive(Debug)]
pub(crate) struct SInstance<'a> {
    pub id: [u8; 16],
    /// `coverage.from`: the lowest any record declares.
    pub coverage_from: u64,
    records: BTreeMap<u64, Vec<SightingView<'a>>>,
}

impl<'a> SInstance<'a> {
    pub fn highest(&self) -> u64 {
        self.records.keys().next_back().copied().unwrap_or(self.coverage_from)
    }

    /// Every record, in (index, bytes) order.
    pub fn records(&self) -> impl Iterator<Item = (u64, &SightingView<'a>)> {
        self.records.iter().flat_map(|(i, v)| v.iter().map(move |r| (*i, r)))
    }

    pub fn at(&self, index: u64) -> &[SightingView<'a>] {
        self.records.get(&index).map_or(&[], Vec::as_slice)
    }

    /// Indices below `index` that hold a record, highest first.
    pub fn indices_below(&self, index: u64) -> impl Iterator<Item = u64> + '_ {
        self.records.range(..index).rev().map(|(i, _)| *i)
    }

    /// Indices above `index` that hold a record, lowest first.
    pub fn indices_above(&self, index: u64) -> impl Iterator<Item = u64> + '_ {
        self.records.range(index.saturating_add(1)..).map(|(i, _)| *i)
    }

    /// Missing index ranges between `coverage.from` and the highest index.
    pub fn gaps(&self) -> Vec<Gap> {
        let mut out = Vec::new();
        let mut expect = self.coverage_from;
        for &i in self.records.keys() {
            if i > expect {
                out.push(Gap { from: expect, to: i - 1 });
            }
            expect = expect.max(i.saturating_add(1));
        }
        out
    }

    /// Records at i+1 whose `prev` is not the chain digest of any record at
    /// i. Not counted where i is missing: that is a gap.
    pub fn breaks(&self) -> u64 {
        let mut n = 0;
        for (&i, recs) in &self.records {
            if i <= self.coverage_from {
                continue;
            }
            let before = self.at(i - 1);
            if before.is_empty() {
                continue;
            }
            for r in recs {
                if !before.iter().any(|q| chain_digest(q.raw()) == r.parts.seq.prev) {
                    n += 1;
                }
            }
        }
        n
    }

    /// Distinct records beyond the first at each index.
    pub fn forks(&self) -> u64 {
        self.records.values().map(|v| v.len() as u64 - 1).sum()
    }

    /// Whether `v` is one of this instance's control records.
    pub fn is_control(&self, v: &SightingView) -> bool {
        v.parts.subject.scheme() == SchemeTag::OBSERVER && v.parts.subject.bytes() == self.id
    }
}

/// The valid part of a stream, in canonical order.
#[derive(Debug)]
pub(crate) struct Stream<'a> {
    pub instances: BTreeMap<[u8; 16], SInstance<'a>>,
    pub excluded: u64,
}

impl<'a> Stream<'a> {
    /// Keep every entry that parses as a layout-1 sighting; count the rest.
    pub fn validate(entries: &[&'a [u8]]) -> Stream<'a> {
        let mut instances: BTreeMap<[u8; 16], SInstance<'a>> = BTreeMap::new();
        let mut excluded = 0;
        for &bytes in entries {
            let Ok(view) = decode_sighting(bytes) else {
                excluded += 1;
                continue;
            };
            let seq = view.parts.seq;
            let inst = instances.entry(seq.instance).or_insert_with(|| SInstance {
                id: seq.instance,
                coverage_from: view.parts.coverage.from,
                records: BTreeMap::new(),
            });
            inst.coverage_from = inst.coverage_from.min(view.parts.coverage.from);
            let at = inst.records.entry(seq.index).or_default();
            if let Err(pos) = at.binary_search_by(|r| r.raw().cmp(view.raw())) {
                at.insert(pos, view);
            }
        }
        Stream { instances, excluded }
    }

    pub fn valid(&self) -> u64 {
        self.instances.values().map(|i| i.records().count() as u64).sum()
    }

    pub fn gaps(&self) -> u64 {
        self.instances.values().map(|i| i.gaps().len() as u64).sum()
    }

    pub fn breaks(&self) -> u64 {
        self.instances.values().map(SInstance::breaks).sum()
    }

    pub fn forks(&self) -> u64 {
        self.instances.values().map(SInstance::forks).sum()
    }
}

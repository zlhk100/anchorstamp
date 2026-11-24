// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright © 2026 Lei Zhou

//! The `LINUX_EXEC` rules over evidence in contract form, built by hand: a K
//! load whose records sit in an attested prefix, each with its anchor.
//! This exercises the decisive paths — `SubjectMismatch`, `Unobserved`, the
//! anchor, the close bound — independently of how quotes are checked.

mod common;

use anchorstamp_core::{SchemeTag, Strength};
use anchorstamp_verify::{
    Anchor, Cap, DeclaredPath, Detail, Evidence, ExecRecord, Facts, Instance, Kind, Loss, Profile,
    Span, Within, exec,
};
use common::*;

fn within(k: usize) -> Within {
    Within {
        reset_count: 7,
        from: Some(100_000),
        to: 200_000 + k as u64,
        restart_from: Some(0),
        restart_to: 0,
        safe: true,
    }
}

fn rec(pid: u32, exec_ns: u64, digest: [u8; 32], entry: usize) -> ExecRecord {
    ExecRecord {
        pid,
        lo: exec_ns,
        hi: exec_ns,
        fork: Some(exec_ns - 10),
        exe_digest: digest,
        req_digest: Some(digest),
        interpreted: false,
        stable: true,
        decisive: true,
        uid: Some(1001),
        euid: Some(1001),
        ppid: Some(1),
        path: Vec::new(),
        path_truncated: false,
        path_unresolved: false,
        ns: Some(0),
        self_prov: false,
        strength: Strength::ATTESTED,
        position: entry as u64,
        entry: Some(entry),
        anchor: Some(within(entry)),
        v1: false,
    }
}

/// Load L: LOAD 1000, ARMED 1100, the given records, boot B.
fn load(records: Vec<ExecRecord>) -> Instance {
    let mut i = Instance {
        id: LOAD_L,
        boot: Some(BOOT),
        lo_c: Some(1000),
        hi_c: None,
        close_c: None,
        cov_from: Some(1100),
        mediated: true,
        records,
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
    };
    i.valid = 2 + i.records.len() as u64;
    i
}

fn k(instances: Vec<Instance>) -> Evidence {
    Evidence {
        profile: Profile::K,
        valid: instances.iter().map(|i| i.valid).sum(),
        instances,
        gaps: 0,
        breaks: 0,
        forks: 0,
        excluded: 0,
        facts: Facts { ak_usable: true, ..Facts::default() },
    }
}

fn run(ev: &Evidence) -> (Kind, Anchor) {
    let o = exec::join(Some(&c()), ev, DeclaredPath::Direct);
    (o.kind, o.anchor)
}

const K_DISAGREE: [Cap; 5] = [
    Cap::SelfProvAbsent,
    Cap::BootConfigUnappraised,
    Cap::EkChainUnvalidated,
    Cap::AkPinnedLocally,
    Cap::BootAsserted,
];

fn disagrees(detail: Detail) -> Kind {
    Kind::Disagrees { detail, strength: Strength::ATTESTED, caps: K_DISAGREE.to_vec() }
}

#[test]
fn w01_match() {
    let (kind, anchor) = run(&k(vec![load(vec![rec(4242, 2500, d(), 3), rec(99, 3500, x(), 4)])]));
    let mut caps = K_DISAGREE.to_vec();
    caps.push(Cap::RootCanInsert);
    assert_eq!(
        kind,
        Kind::Agrees { strength: Strength::ATTESTED, scheme: SchemeTag::LINUX_EXEC, caps, also: 0 }
    );
    assert_eq!(anchor, Anchor::Within(within(3)));
}

#[test]
fn w02_wrong_file() {
    let (kind, anchor) = run(&k(vec![load(vec![rec(4242, 2500, x(), 3), rec(99, 3500, x(), 4)])]));
    assert_eq!(kind, disagrees(Detail::SubjectMismatch));
    assert_eq!(anchor, Anchor::Within(within(3)), "the latest decisive candidate");
}

#[test]
fn w03_unobserved_and_its_anchor() {
    let (kind, anchor) = run(&k(vec![load(vec![
        rec(7, 1500, x(), 3),
        rec(99, 3500, x(), 4),
        rec(98, 3600, x(), 5),
    ])]));
    assert_eq!(kind, disagrees(Detail::Unobserved));
    assert_eq!(anchor, Anchor::Within(within(4)), "the earliest decisive record past t_reap");
}

#[test]
fn w04_not_reached() {
    let (kind, _) = run(&k(vec![load(vec![rec(7, 1500, x(), 3), rec(99, 2900, x(), 4)])]));
    assert_eq!(kind, Kind::NothingToCompare);
}

#[test]
fn w06_armed_after_t0() {
    let mut l = load(vec![rec(99, 3500, x(), 3)]);
    l.cov_from = Some(2600);
    assert_eq!(run(&k(vec![l])).0, Kind::NothingToCompare);
}

#[test]
fn w07_w28_pid_or_fork_outside_the_window() {
    let (kind, _) = run(&k(vec![load(vec![rec(4242, 1500, d(), 3), rec(99, 3500, x(), 4)])]));
    assert_eq!(kind, disagrees(Detail::Unobserved));
    let mut early_fork = rec(4242, 2500, d(), 3);
    early_fork.fork = Some(1900);
    let (kind, _) = run(&k(vec![load(vec![early_fork, rec(99, 3500, x(), 4)])]));
    assert_eq!(kind, disagrees(Detail::Unobserved));
}

#[test]
fn w08_reexec_beside_a_match_is_not_a_contradiction() {
    let mut a = rec(4242, 2400, x(), 3);
    a.fork = Some(2300);
    let mut b = rec(4242, 2500, d(), 4);
    b.fork = Some(2300);
    let (kind, _) = run(&k(vec![load(vec![a, b, rec(99, 3500, x(), 5)])]));
    assert!(matches!(kind, Kind::Agrees { also: 0, .. }), "{kind:?}");
}

#[test]
fn w10_w11_w25_losses() {
    let with_loss = |first, last, records| {
        let mut l = load(records);
        l.losses.push(Loss { count: 3, first, last });
        k(vec![l])
    };
    assert_eq!(
        run(&with_loss(2100, 2200, vec![rec(7, 1500, x(), 3), rec(99, 3500, x(), 5)])).0,
        Kind::NothingToCompare
    );
    assert_eq!(
        run(&with_loss(3100, 3200, vec![rec(7, 1500, x(), 3), rec(99, 3500, x(), 5)])).0,
        disagrees(Detail::Unobserved)
    );
    assert_eq!(
        run(&with_loss(2450, 2450, vec![rec(4242, 2500, x(), 3), rec(99, 3500, x(), 5)])).0,
        Kind::NothingToCompare
    );
}

#[test]
fn w12_w13_gap_or_break_touches() {
    let mut l = load(vec![rec(7, 1500, x(), 3), rec(99, 3500, x(), 5)]);
    l.gaps.push(Span { from: None, to: None });
    assert_eq!(run(&k(vec![l])).0, Kind::NothingToCompare);
    let mut ev = k(vec![load(vec![rec(7, 1500, x(), 3), rec(99, 3500, x(), 4)])]);
    ev.breaks = 1;
    let o = exec::join(Some(&c()), &ev, DeclaredPath::Direct);
    assert_eq!(o.kind, Kind::NothingToCompare);
    assert!(o.health.evidence_broken && o.health.touches_claim);
}

#[test]
fn w15_w30_undecisive_records_never_disagree() {
    let mut reach = rec(99, 3500, x(), 4);
    reach.decisive = false;
    assert_eq!(run(&k(vec![load(vec![rec(7, 1500, x(), 3), reach])])).0, Kind::NothingToCompare);
    let mut wrong = rec(4242, 2500, x(), 3);
    wrong.decisive = false;
    assert_eq!(run(&k(vec![load(vec![wrong, rec(99, 3500, x(), 4)])])).0, Kind::NothingToCompare);
}

#[test]
fn w27_w33_w35_unstable_renamed_or_mixed_candidates_block_a_contradiction() {
    let mut unlinked = rec(4242, 2500, x(), 3);
    unlinked.stable = false;
    assert_eq!(run(&k(vec![load(vec![unlinked, rec(99, 3500, x(), 4)])])).0, Kind::NothingToCompare);
    let mut renamed = rec(4242, 2500, y(), 3);
    renamed.req_digest = Some(d());
    assert_eq!(run(&k(vec![load(vec![renamed, rec(99, 3500, x(), 4)])])).0, Kind::NothingToCompare);
    let mut first = rec(4242, 2400, d(), 3);
    first.stable = false;
    first.fork = Some(2300);
    let mut second = rec(4242, 2500, q(), 4);
    second.fork = Some(2300);
    assert_eq!(run(&k(vec![load(vec![first, second, rec(99, 3500, x(), 5)])])).0, Kind::NothingToCompare);
}

#[test]
fn w34_first_exec_before_armed() {
    let early = claim(4242, 800, 3000, d(), boot8(&BOOT));
    let mut e = rec(4242, 1500, x(), 3);
    e.fork = Some(900);
    let ev = k(vec![load(vec![e, rec(99, 3500, x(), 4)])]);
    assert_eq!(exec::join(Some(&early), &ev, DeclaredPath::Direct).kind, Kind::NothingToCompare);
}

#[test]
fn w38_close_bounds_coverage() {
    let mut l = load(vec![rec(7, 1500, x(), 3), rec(99, 3500, x(), 4)]);
    l.close_c = Some(2500);
    l.hi_c = Some(3600);
    l.unloaded = true;
    assert_eq!(run(&k(vec![l])).0, Kind::NothingToCompare);
}

#[test]
fn not_covered_needs_every_instance_outside() {
    let mut later = load(vec![rec(7, 4100, x(), 3)]);
    later.lo_c = Some(4000);
    later.cov_from = Some(4050);
    assert_eq!(run(&k(vec![later.clone()])).0, Kind::NotCovered { windows: vec![(4000, None)] });
    let mut earlier = load(vec![]);
    earlier.id = LOAD_L2;
    earlier.lo_c = Some(100);
    earlier.hi_c = Some(200);
    assert_eq!(
        run(&k(vec![earlier.clone(), later.clone()])).0,
        Kind::NotCovered { windows: vec![(100, Some(200)), (4000, None)] }
    );
    // one instance whose coverage meets the window: not NotCovered
    let mut open = load(vec![]);
    open.id = [9; 16];
    assert_ne!(
        run(&k(vec![earlier, later, open])).0,
        Kind::NotCovered { windows: vec![] }
    );
}

#[test]
fn s_evidence_never_disagrees() {
    // the same records, delivered by a profile S source, undecisive
    let mut i = load(vec![rec(4242, 2500, x(), 3), rec(99, 3500, x(), 4)]);
    for r in &mut i.records {
        r.decisive = false;
        r.req_digest = None;
        r.fork = None;
        r.strength = Strength::SOFTWARE;
    }
    let mut ev = k(vec![i]);
    ev.profile = Profile::S;
    assert_eq!(run(&ev).0, Kind::NothingToCompare);
}

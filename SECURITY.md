<!--
SPDX-License-Identifier: CC-BY-4.0
Copyright © 2026 Lei Zhou
https://creativecommons.org/licenses/by/4.0/
-->

# Security policy

anchorstamp is a proof of concept. It has not been audited and should not
be relied on to protect anything. Reports are still very welcome: finding
where the design breaks is the point of publishing it.

## Reporting a vulnerability

Please report privately through GitHub:
**Security → Report a vulnerability** on this repository. Do not open a
public issue for a vulnerability.

Include what you did, what you expected the reader or an observer to
report, and what it reported instead. A failing scenario, a bundle, or a
short script is the most useful form.

This is a single-maintainer project. Expect an acknowledgement within a
week and a fix or a written disposition on a best-effort basis. Coordinated
disclosure is preferred; 90 days is the default window, and shorter if a
fix lands sooner.

## What counts

In scope — anything that makes the system say more than the evidence
supports:

- the reader reports `corroborated` for an action that did not happen, or
  for a different action than the one claimed
- the reader reports `contradicted` for an action that did happen as
  claimed
- an exec the kernel source neither records nor counts in a loss, while
  its load claims coverage
- the measured account altering, truncating or reordering either source's
  evidence without the report showing it
- the reader accepting a quote, or an attestation key, it should refuse
- the kernel module crashing, hanging or leaking, or delaying an exec
  beyond its own bounded work
- anything in `demo/run.sh`, `collector/collect.sh` or the module's
  scripts that could damage the host, leave audit rules, modules or
  processes behind, or run code the measured account could have changed

Out of scope — limits the project already states, in the documentation and
in every report:

- which sub-agent acted, when sub-agents share one process
- that a corroborated claim proves the claimant caused the action
- the software source: unsigned records, self-declared coverage, no
  contradiction ever, a pid reused inside a claim's window with the same
  file
- scripts: the software source records the interpreter; the kernel source
  agrees only with the cap *interpreted*
- processes in a private mount namespace, under a chroot, or running an
  unlinked file: flagged, never joined
- an attestation key pinned by the operator, with no endorsement-key
  certificate chain checked; the boot state (PCR 7) reported, not appraised
- root on the observing host adding entries to PCR 13 outside a running
  load (every kernel-source agreement carries the cap for it); root loading
  kernel code; a compromised kernel or TPM
- a reader running inside the measured account
- throughput: under sustained exec load most execs are counted in losses,
  not recorded

If you think one of the stated limits is wrong, that is worth reporting
too, as an ordinary issue.

## Supported versions

Only the `main` branch. There are no releases yet.

# anchorstamp

[![Code: MIT OR Apache-2.0](https://img.shields.io/badge/code-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![Docs: CC BY 4.0](https://img.shields.io/badge/docs-CC%20BY%204.0-lightgrey.svg)](LICENSE-docs)

**An open primitive for checking what an AI agent says it did against what
the platform saw it do.**

When an agent runs commands on your machine, the record of what it did is
written by the agent. Logging stores that record, signing seals it, policy
decides on it. None of them checks it against an observation the agent could
not touch. anchorstamp does that, and it also shows you what the agent did
and never mentioned.

---

## The gap this fills

The agent ecosystem already has good tools at every layer around this one:

| Layer | What it tells you | Examples |
|---|---|---|
| Logging and tracing | what the agent *reported* doing | framework callbacks, OpenTelemetry GenAI |
| Signing and provenance | that the record was not *altered* after it was written | in-toto, Sigstore, SCITT |
| Platform attestation | what state the *platform* was in | TPM quotes, confidential computing |
| Policy | whether to *accept* | OPA, Cedar |

Every one of them assumes the record's author was honest about what happened.
A signed log proves the log was not changed. It does not prove the log is
true. And an action the agent never wrote down leaves nothing to sign.

anchorstamp is a layer underneath, not a competitor beside. Its loop is:

```
claim  →  observe  →  join  →  verdict
```

The agent's library makes a **claim**. An observer the agent cannot reach —
in this proof of concept, the Linux kernel's own audit subsystem — records
the same event independently and signs it. A reader that was not present
**joins** the two and returns a verdict for every claim, and for every
observation no claim accounts for:

| Verdict | Meaning |
|---|---|
| `corroborated` | an independent observation matches the claim |
| `contradicted: unobserved` | the observer was watching and saw no such action |
| `contradicted: wrong subject` | the claim points at an action that did happen — but a different one |
| `nothing to compare` | the evidence cannot settle it, and the reader says why |
| `unclaimed` | the observer saw an action the agent never reported |

The last row is the one that matters. Tamper-evident logging can show a
record was forged. It cannot show a record that was never written.

A log without a verdict is a story the agent told about itself.

---

## Status — read this before citing anything here

| Tier | What exists |
|---|---|
| **Measured** | A proof of concept on one Linux laptop (kernel 6.8): eleven live scenarios, all results below. |
| **Specified** | Record layout, signature and chaining, reader rules, conformance vectors (first half of the specification). |
| **Planned** | The production rule for matching a library's view of a process to the kernel's; measuring how often that rule collides under concurrent execution; anchoring the observer's record to an outside log; a run against a real open-source agent framework. |

### What the proof of concept showed

One command per scenario, run as root on a dedicated laptop, with the agent
running as an unprivileged account that has no sudo and no terminal.

| Scenario | Result |
|---|---|
| honest | 4 of 4 claims corroborated |
| hidden action | commands the agent ran without its library appear as **unclaimed** |
| forged claim, no such action | contradicted: unobserved |
| forged claim, real action of a different program | contradicted: wrong subject — *"the observer recorded this pid running /usr/bin/id; the claim says /usr/bin/true"* |
| shell pipeline | the shell's children listed as children of the claimed command |
| two sub-agents in one process | actions corroborated; *which* sub-agent acted is not, and the report says so |
| burst of 200 | 200 of 200 corroborated |
| exec by file descriptor, 1,672-byte path | both observed |
| agent tries to alter the evidence or the audit rules | every attempt refused by the kernel or the filesystem |

Across all runs: zero audit records lost, audit rules identical before and
after, the observer's signing key absent from every output it produced.

### What it does not show

- **Who caused an action.** A corroborated claim proves an action matching
  the claim was independently observed. It does not prove the claimant
  caused it.
- **Which sub-agent acted.** Agent frameworks run sub-agents inside one
  process. The kernel sees one actor where the application sees several.
  No observer at this layer can recover that, and anchorstamp does not try.
- **Whether the action was a good idea.** It evidences what executed, never
  whether the decision was correct.
- **Anything to a reader inside the agent's own domain.** The reader must run
  where the agent cannot reach.
- **Anything beyond one host.** The observer is trusted by provisioning, its
  key is held in software, and its anchor is asserted by the operator. Each of
  these is stated in every report rather than left implicit.

---

## Where the idea comes from

Functional safety has a name for a component that checks itself: a
common-cause failure. Automotive and industrial safety standards require it
to be analysed and designed out, because a monitor that shares a failure domain with what
it monitors fails with it. Agent evidence today is built the same way: the
party that acts is the party that reports. anchorstamp moves the observation
to a domain the agent cannot reach, and makes the gap between claim and
observation visible.

Other work has reached similar conclusions, including the Linux Foundation's
AgenTrust project. anchorstamp makes no claim to be first. What it adds is
narrow: the observer is independent by provisioning rather than by
cooperation, and an action with no claim at all is visible.

---

## What is in this repository

```
crates/anchorstamp-core           record types and their byte layout (no_std, no dependencies)
crates/anchorstamp                the library an agent links: run a command, return a claim
crates/anchorstamp-verify         the reader: join claims to observations, return verdicts
crates/anchorstamp-observe-audit  the reference observer: Linux audit to signed, chained records
crates/agentsim                   a deterministic agent-framework simulator for the scenarios
crates/demo-report                the human-readable report
demo/                             the run harness and the scenarios
docs/                             why this exists, and a walkthrough of the demo
```

## Running the demo

Linux with `auditd`, Rust stable, root for the run. The harness refuses to
start unless the host is in a known state, and it removes everything it adds.
See [docs/demo.md](docs/demo.md) before running it.

```
cargo build --workspace --release
sudo demo/run.sh honest      # or: shadow, forger, pipeline, subagent, burst, …
```

---

## Contributing

The most useful contributions right now, in order:

1. **A second observer.** eBPF, a hypervisor, a TEE: the observer sits behind
   one seam, and a second one is the test of whether the seam is right.
2. **Challenges to the threat model.** If you can make the reader print
   `corroborated` for something that did not happen, open an issue.
3. **A run against a real agent framework** you use.

## Licence

- **Code:** MIT or Apache-2.0, at your option — [LICENSE-MIT](LICENSE-MIT),
  [LICENSE-APACHE](LICENSE-APACHE)
- **Documents:** Creative Commons Attribution 4.0 — [LICENSE-docs](LICENSE-docs)

## Maintainer

Lei Zhou, independent ([ORCID 0009-0006-6999-0729](https://orcid.org/0009-0006-6999-0729))

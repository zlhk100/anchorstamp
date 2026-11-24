<!--
SPDX-License-Identifier: CC-BY-4.0
Copyright © 2026 Lei Zhou
https://creativecommons.org/licenses/by/4.0/
-->

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
| Platform attestation | what state the *platform* was in | TPM quotes, IMA, Keylime, confidential computing |
| Policy | whether to *accept* | OPA, Cedar |

Every one of them assumes the record's author was honest about what happened.
A signed log proves the log was not changed. It does not prove the log is
true. And an action the agent never wrote down leaves nothing to sign.

anchorstamp is a layer underneath, not a competitor beside. Its loop is:

```
claim  →  observe  →  join  →  verdict
```

The agent's library makes a **claim**. An observer the agent cannot reach
records the same event independently. A reader that was not present **joins**
the two and returns a verdict for every claim, and for every observation no
claim accounts for:

| Verdict | Meaning |
|---|---|
| `corroborated` | an independent observation matches the claim |
| `contradicted: unobserved` | the observer was watching and saw no such action |
| `contradicted: subject mismatch` | the claim points at an action that did happen — but a different one |
| `nothing to compare` | the evidence cannot settle it, and the reader says why |
| `unclaimed` | the observer saw an action the agent never reported |

The last row is the one that matters. Tamper-evident logging can show a
record was forged. It cannot show a record that was never written.

A log without a verdict is a story the agent told about itself.

---

## Two observers, one join

The reader takes evidence from any source that meets one small contract:
which process ran which file, when, and where the source's coverage starts,
stops and has holes. Two sources exist today. The reader never combines
them: each gets its own verdict and its own stated strength.

| Source | Where it observes | What anchors it | Strongest verdict |
|---|---|---|---|
| **software** | the Linux audit subsystem, read by an unprivileged observer process | nothing: its records are unsigned and their transport is the operator's word | corroborated at SOFTWARE (100); it never contradicts |
| **kernel** | a small kernel module on the exec path; each exec becomes an IMA measurement extended into TPM PCR 13 | TPM quotes, signed by an attestation key inside the TPM, checked by the reader | corroborated or contradicted at ATTESTED (400) |

Every verdict carries the reasons its strength stops where it does — for the
kernel source, for example: *the boot configuration (PCR 7) is not appraised;
no endorsement key certificate chain was checked; the attestation key is
pinned locally by the operator; root can add entries to PCR 13 from user
space*. Nothing is implied that the evidence does not carry.

The kernel module is the **reference observer**. The design allows
observers anchored in a hypervisor or a trusted execution environment to
meet the same contract; only the software and kernel/TPM observers are
built.

---

## Status — read this before citing anything here

| Tier | What exists |
|---|---|
| **Measured** | One Linux laptop (Ubuntu 22.04, kernel 6.8, TPM 2.0): the scenarios below, on both sources; a real agent framework (smolagents) with a scripted plan and with a local model; the kernel source's load, unload, loss and failure paths, each under test. |
| **Conformance** | 56 vectors (`verify/vectors/`) with their expected verdicts, built by a separate reference generator written from the specification text; the reader reproduces every one. |
| **Written, not yet published** | The specification the vectors come from: record layouts, the join rules, the evidence-source contract. |
| **Open** | See [What is not shown yet](#what-is-not-shown-yet). |

### What the runs showed

Each scenario is one command, run as root on a dedicated laptop, with the
agent as an unprivileged account that has no sudo and no terminal.

| Scenario | Software source | Kernel source |
|---|---|---|
| honest — 4 commands through the library | corroborated 4 of 4 | corroborated 4 of 4, ATTESTED |
| forged claim, no such action | nothing to compare | **contradicted: unobserved** |
| forged claim, real action of a different program | nothing to compare | **contradicted: subject mismatch** |
| real framework, scripted plan (smolagents 1.26) | every bridged command corroborated | every bridged command corroborated, ATTESTED |
| a `#!` script | records the interpreter; no agreement | corroborated, capped *interpreted*, interpreter named |
| a program in a private mount namespace, a chroot, or an unlinked file | — | flagged in the record; it neither corroborates nor contradicts |
| a root process extends PCR 13 by hand | — | **evidence broken**, for every claim of that boot |

Earlier runs of the software source, from before the kernel source existed
(October and November 2026, when the observer still signed its records):

| Scenario | Result |
|---|---|
| hidden action | commands the agent ran without its library appear as **unclaimed** |
| shell pipeline | the shell's children listed as children of the claimed command |
| two sub-agents in one process | actions corroborated; *which* sub-agent acted is not, and the report says so |
| exec by file descriptor, 1,672-byte path | both observed |
| agent tries to alter the evidence or the audit rules | every attempt refused by the kernel or the filesystem |
| real framework, scripted plan | the three programs a plugin ran directly (`uname`, `id`, `uptime`) appear as **unclaimed**; the framework's own log names only the tool call |
| real framework, local model (qwen2.5:7b-instruct via Ollama), 2 runs | every command claimed through the bridge corroborated, including one that exited 1; the model's final answer said disk space still had to be checked, and the observer holds no `df`; the framework's own process ran `uname` before any tool call and its log never mentions it; the agent talked to no network peer but the model server |

### What the kernel source's own tests showed

- **Every exec is recorded or counted.** Under a 5,000-exec burst, 874
  were recorded and every one of the other 4,126 was inside a counted loss
  carrying its time bounds. A claim whose window meets a loss gets
  *nothing to compare*, never a false contradiction.
- **Load and unload are bounded in time.** Execs between loading and arming
  are counted, never recorded silently; unload closes coverage before the
  probe is removed.
- **Every failure path is visible.** With faults injected into a debug
  build — a failed measurement, a failed allocation, a failed loss record,
  a failed arming, a failed hook lookup — each ended in a counted loss or a
  load that claims no coverage; none produced a break or a false verdict.
- **One clock.** Across 2,000 timed execs, every recorded exec fell inside
  the library's own window for it.

### What it does not show

- **Who caused an action.** A corroborated claim proves an action matching
  the claim was independently observed. It does not prove the claimant
  caused it.
- **Which sub-agent acted.** Sub-agents in one process are one actor to the
  kernel. No observer at this layer can recover that.
- **Whether the action was a good idea.** It evidences what executed, never
  whether the decision was correct.
- **Anything to a reader inside the agent's own domain.** The reader must run
  where the agent cannot reach.
- **More than the anchor supports.** The attestation key is pinned by the
  operator, not chained to the TPM vendor; the boot state is reported, not
  appraised; root on the host can add (not remove) entries, so every kernel
  agreement says so.

### What is not shown yet

Work in progress, each with its reason:

- **Throughput under sustained load.** Each record costs a TPM extend. In a
  continuous exec loop most execs (76–85 %) were recorded only as counted
  losses. The cost of hashing a long path in the probe is not yet isolated.
- **A reboot between quotes.** The records after the last quote are shown
  as unanchored, as designed; the check across a reboot itself has not run.
- **The local model on the kernel source.** The live-model runs above used
  the software source only.
- **Completeness under a live model that fills the disk.** The audit daemon
  can suspend; the harness detects a suspension, but the fix (the audit log
  on its own filesystem, or a quota) is not in place.
- **More than one host, kernel or architecture.** The kernel module is
  built and tested for one kernel (6.8.0-138, x86_64).

---

## Where the idea comes from

Functional safety has a name for a component that checks itself: a
common-cause failure. Automotive and industrial safety standards require it
to be analysed and designed out, because a monitor that shares a failure
domain with what it monitors fails with it. Agent evidence today is built
the same way: the party that acts is the party that reports. anchorstamp
moves the observation to a domain the agent cannot reach, and makes the gap
between claim and observation visible.

Other work has reached similar conclusions. TRACE, an open specification
for hardware-attested runtime evidence for AI agents, now hosted by the
Linux Foundation, binds the environment, software and policies an agent ran
under into a verifiable record. Platform attestation (IMA with a remote
verifier such as Keylime) measures the files a machine opens and executes
and checks them remotely against an allowlist. anchorstamp
makes no claim to be first. What it adds is narrow: a join between what the
agent claims and what an independent observer recorded, with a verdict per
claim and a list of what no claim covers.

---

## What is in this repository

```
crates/anchorstamp-core           record types and their byte layout (no dependencies, no platform vocabulary)
crates/anchorstamp                the library an agent links: run a command, return a claim
crates/anchorstamp-verify         the reader: validate each source, join claims, return verdicts
crates/anchorstamp-observe-audit  the software source: Linux audit to unsigned, chained records
crates/anchorstamp-exec           a command-line bridge, so a framework in any language can run a command through the library
crates/agentsim                   a deterministic agent-framework simulator for the scenarios
crates/demo-report                the human-readable report
observer/kernel/                  the reference observer: a kernel module and its load, unload and policy scripts
collector/                        copies the measurement list and takes TPM quotes into a bundle
verify/vectors/                   conformance vectors and their reference generator
demo/                             the run harness, the scenarios, and the real-framework scene
scripts/                          the check target of the coding standard
docs/                             why this exists, a walkthrough of the demo, and the coding standard
```

## Running it

**Software source only** — Linux with `auditd`, Rust 1.87 or later, root for
the run:

```
cargo build --workspace --release
sudo demo/run.sh honest      # or: shadow, forger, pipeline, subagent, burst, …
sudo demo/run.sh framework   # smolagents with a scripted plan, no network
```

**Kernel source** — additionally a TPM 2.0 with tpm2-tools, IMA, and the
kernel module built for your running kernel. The full list of preconditions
is in [observer/kernel/anchorstamp_exec/README.md](observer/kernel/anchorstamp_exec/README.md)
and [docs/demo.md](docs/demo.md#the-kernel-source); read them before loading
anything. The module is unsigned and taints the kernel; use a machine you can
reboot.

The harness refuses to start unless the host is in a known state, and it
removes everything it adds.

---

## Contributing

The most useful contributions right now, in order:

1. **A third observer.** eBPF, a hypervisor, a TEE: the evidence-source
   contract is the seam, and another observer is the test of whether it is
   right.
2. **Challenges to the threat model.** If you can make the reader print
   `corroborated` or `contradicted` for something that did not happen, open
   a report (see [SECURITY.md](SECURITY.md)).
3. **A run under the agent framework you use**, through `anchorstamp-exec`.

## Licence

- **Code:** MIT or Apache-2.0, at your option — [LICENSE-MIT](LICENSE-MIT),
  [LICENSE-APACHE](LICENSE-APACHE)
- **Kernel module:** GPL-2.0 or MIT — [LICENSE-GPL-2.0](LICENSE-GPL-2.0),
  [LICENSE-MIT](LICENSE-MIT)
- **Documents:** Creative Commons Attribution 4.0 — [LICENSE-docs](LICENSE-docs)

## Maintainer

Lei Zhou, independent ([ORCID 0009-0006-6999-0729](https://orcid.org/0009-0006-6999-0729))

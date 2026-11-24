<!--
SPDX-License-Identifier: CC-BY-4.0
Copyright © 2026 Lei Zhou
https://creativecommons.org/licenses/by/4.0/
-->

# Why this project exists

## The problem

AI agents now act. They run shell commands, edit files, call services and
spawn tools, on developer laptops and in production. Each action leaves a
record, and in almost every deployment that record is written by the agent
or by the framework it runs in.

**The hard part is not recording what an agent did. It is knowing which
records you can believe.**

Someone reading an agent's log has three situations in front of them, and
nothing in the log tells them apart:

1. The agent did what it says, and said so.
2. The agent says it did something that never happened.
3. The agent did something and never said so.

The first is the common case. The second and third are the ones that
matter, and a log written by the agent looks the same in all three.

## Why existing tools do not close it

The ecosystem has good tools around this problem, and anchorstamp composes
with each of them rather than replacing any:

- **Logging and tracing** record what the agent *reports*.
- **Signing and provenance** prove a record was not *altered* after it was
  written.
- **Platform attestation** proves what state the *machine* was in, and
  measurement frameworks such as IMA record what it executed.
- **Policy engines** decide whether to *accept*.

Every one of them either starts from the record the agent produced, or
measures the machine without asking what the agent claimed. A signature
over a false record is a valid signature. An action the agent never
reported leaves nothing to sign, nothing to trace, and nothing for policy
to reject.

What none of them answers is: *did an independent observer, one the agent
could not influence, see this action happen — and which of the agent's
claims does that settle?* That question sits between the record and the
decision, and nothing currently fills it.

## Why it is getting harder

Two properties of agent frameworks work against the reader.

**Agents decide their own actions at runtime.** The commands an agent runs
are chosen by the model, step by step. There is no fixed list to check
against in advance, so the record of what happened is the only evidence
there is.

**The recorder is triggered by the party it records.** Framework callbacks,
tool wrappers and tracing hooks run inside the agent's process, when the
agent calls them. An action taken by any other route — a subprocess the
tool spawns, a command run by a different path, a child of a child — is
recorded only if the agent's own code chooses to record it.

A third property is a hard limit rather than a trend. Frameworks that
support sub-agents run them inside one process. The application sees a
planner, a coder and a reviewer. The operating system sees one program.
No observer below the application can say which sub-agent acted, and this
project does not pretend to.

## What "can you believe it" looks like concretely

A published account, from outside this project. In July 2025 the founder
of SaaStr, Jason Lemkin, described on his blog and social media a session
with an AI coding agent on Replit, as reported by The Register. By his
account, the agent deleted his production database despite instructions
not to, generated fictional data and reports that covered up problems, and
told him a rollback was impossible. The rollback worked.

> S. Sharwood. *Vibe coding service Replit deleted user's production
> database, faked data, told fibs galore.* The Register, 21 July 2025.
> https://www.theregister.com/2025/07/21/replit_saastr_vibe_coding_incident/

The point is not that one agent misbehaved. It is that the person
responsible had only the agent's own account to go on, and that account was
wrong about what had happened and about what could be undone. Every tool in
the list above would have stored, signed and passed that account faithfully.

## What has been measured

The method is small enough to demonstrate on one Linux laptop: an
unprivileged account plays the agent, an observer the agent cannot reach
records what executes, and a reader joins the two.

**First, a software observer.** The kernel's audit subsystem, read by a
process the agent cannot signal or write to. It showed the core property
early: commands the agent ran behind its library's back were listed as
**unclaimed** by a reader that never saw the agent's log. A claim for a
command that never ran was **contradicted**, and so was a claim pointing at
a real process with the wrong program — *"the observer recorded this pid
running /usr/bin/id; the claim says /usr/bin/true"*. A real framework,
smolagents, and then a local model ran through a command-line bridge under
the same observer, and a plugin's unlogged programs showed up as unclaimed.

Two things broke on the way, and both shaped the design. The kernel's audit
timestamps are coarse: a precise timestamp the agent took just before a
command was often a millisecond *later* than the kernel's record of it, so
matching on time order would have failed every honest claim. And a
software observer cannot prove it saw everything: if its daemon pauses,
records are lost without a trace in its own stream. That observer now
**agrees or says nothing**. It never contradicts.

**Then, an anchored observer.** A small kernel module on the exec path
turns every exec into a record that IMA, the kernel's integrity subsystem,
appends to its measurement list and extends into a TPM register. A TPM
quote, signed inside the TPM, fixes the list's content and order up to that
point. With it the reader can say something the software observer cannot:
*this did not happen* — because the attested list shows everything in the
window, in order, with any losses counted and time-bounded.

On the same laptop, with the module loaded, the honest claims were
corroborated at the attested strength; the forged claims were contradicted,
one as unobserved and one as the wrong file; a hand-made extend of the TPM
register from user space was reported as *evidence broken*. Every failure
path of the module was forced in a debug build, and each ended in a
counted loss or a load that claims no coverage. The walkthrough, with the
real reports, is in [demo.md](demo.md).

## Objectives

**1. Make the verdict the deliverable.**
A record the reader cannot check is a story. Every claim ends in a verdict —
corroborated, contradicted, or nothing to compare, with the reason — and
every unclaimed observation is listed.

**2. Make independence a property of the deployment, not of good behaviour.**
The observer is placed where the agent cannot reach it, by provisioning:
no interface, no signal, no shared file. Where the platform allows, its
record is anchored outside the operating system, as the TPM anchors the
kernel source.

**3. Keep the observer replaceable.**
The reader accepts any evidence source that meets one small contract:
which process ran which file, when, and where its coverage starts, stops
and has holes. The audit observer and the kernel module are references,
not the product. An observer in a hypervisor or a trusted execution
environment can meet the same contract and earn the strength its anchor
supports; none is built yet.

**4. State every limit in the output, not only in the documentation.**
Each verdict says why its strength stops where it does, and each report
says what it cannot show. A limit the reader of a report never sees is not
a stated limit.

## What this project is not

Not a logger. Not a tracer. Not a signing service. Not a policy engine.
Not a detector of bad behaviour: it says what happened and who saw it, and
leaves the judgement to whoever reads it. It composes with each of these
and replaces none.

## Where it stands

Early, and specific about it. Both observers run end to end on one Linux
laptop, with the results above, and 56 conformance vectors fix the reader's
verdicts field for field. The specification behind them is written and is
being prepared for publication.

Not yet shown, each with a reason in the [README](../README.md#what-is-not-shown-yet):
how many execs the anchored observer can record under sustained load (each
record costs a TPM operation, and in a continuous loop most execs were
only counted, not recorded); a check across a reboot; the local model on
the anchored observer; completeness of the software observer under a model
that fills the disk; any second machine, kernel or architecture.

The most useful thing anyone outside this project can do right now is try
to make the reader say *corroborated* — or *contradicted* — for something
that is not so, and tell us how.

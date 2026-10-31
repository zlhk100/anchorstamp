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
- **Platform attestation** proves what state the *machine* was in.
- **Policy engines** decide whether to *accept*.

Every one of them starts from the record the agent produced. A signature
over a false record is a valid signature. An action the agent never
reported leaves nothing to sign, nothing to trace, and nothing for policy
to reject.

What none of them answers is: *did an independent observer, one the agent
could not influence, see this action happen?* That question sits between
the record and the decision, and nothing currently fills it.

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

## A first measurement

The method is small enough to demonstrate on one Linux laptop: an
unprivileged account plays the agent, the kernel's audit subsystem is the
observer, and a reader joins the two.

The first sixteen live runs all stopped before the agent ran. The harness
checks, independently of the observer, that the observer cannot be made to
dump its memory — the memory that holds its signing key. The check looked
at the wrong file: on this kernel a protected process keeps the ownership
of its process directory, and only the entries inside it change. The
observer itself was correct every time. The check refused anyway, because
it was built to refuse when it could not tell. That is the behaviour you
want from the part of the system that runs as root.

An earlier probe had already overturned one design assumption. The kernel
timestamps audit records with a coarse clock, so a precise timestamp taken
by the agent just before running a command was often a millisecond *later*
than the kernel's record of that command. Matching on time order would
have failed every honest claim. The match now uses the process and the
executable, and time only to decide whether the observer's record had
reached a claim yet.

With the check fixed, all eleven scenarios ran:

- Honest claims: corroborated, every one.
- Commands the agent ran behind its library's back: listed as
  **unclaimed** — the reader found them without ever seeing the agent's log.
- A claim for a command that never ran: **contradicted, unobserved**.
- A claim pointing at a real process with the wrong program: **contradicted,
  wrong subject** — *"the observer recorded this pid running /usr/bin/id;
  the claim says /usr/bin/true"*.
- Every attempt by the agent to alter the evidence or switch off the audit
  rules: refused by the kernel or the filesystem.

The walkthrough, with the real reports, is in [demo.md](demo.md).

## Objectives

**1. Make the verdict the deliverable.**
A record the reader cannot check is a story. Every claim ends in a verdict —
corroborated, contradicted, or nothing to compare, with the reason — and
every unclaimed observation is listed.

**2. Make independence a property of the deployment, not of good behaviour.**
The observer is placed where the agent cannot reach it, by provisioning:
no interface, no signal, no shared file. Its records are signed and
chained, so a removal from the middle shows.

**3. Keep the observer replaceable.**
The Linux audit observer is a reference, not the product. The contract it
meets is small, and an observer in the kernel, a hypervisor or a trusted
execution environment can meet the same contract and earn a stronger
verdict for it.

**4. State every limit in the output, not only in the documentation.**
Each report says what it cannot show. A limit the reader of a report never
sees is not a stated limit.

## What this project is not

Not a logger. Not a tracer. Not a signing service. Not a policy engine.
Not a detector of bad behaviour: it says what happened and who saw it, and
leaves the judgement to whoever reads it. It composes with each of these
and replaces none.

## Where it stands

Early, and specific about it. A proof of concept runs end to end on one
Linux host, with the results above. The first half of a specification is
written: record layout, signatures, chaining and the reader's rules, with
conformance vectors.

What is not yet shown: the production rule that matches a library's view
of a process to the kernel's view across process namespaces; how often that
rule collides when many commands start at once; anchoring the observer's
record to a party outside the machine; and a run against a real
open-source agent framework rather than a simulator. Each of those is
planned work, not a settled claim.

The most useful thing anyone outside this project can do right now is try
to make the reader say *corroborated* for something that did not happen,
and tell us how.

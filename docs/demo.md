<!--
SPDX-License-Identifier: CC-BY-4.0
Copyright © 2026 Lei Zhou
https://creativecommons.org/licenses/by/4.0/
-->

# The demo, walked through

One command runs a simulated agent, an independent observer and a reader,
and prints a report. This page shows what the report says and how to read
it. Every excerpt below is real output from a run on a Linux laptop
(kernel 6.8), trimmed only where marked.

## What runs

Three parties, on one machine, under three different accounts.

```
the agent      an unprivileged account with no sudo and no terminal.
               Runs a scripted agent: some commands through the
               anchorstamp library (each returns a claim), some behind
               its back, and in one scenario it forges claims.

the observer   starts as root to open the kernel's audit log, then drops
               to an unprivileged account before reading a single line.
               Signs and chains one record per command the kernel saw the
               agent run. The agent cannot reach it: no socket, no signal,
               no shared file it can write.

the reader     runs as the operator after the agent has been stopped.
               Takes the agent's claims and the observer's records and
               says, for each, what the evidence supports.
```

The agent is a simulator, not a real framework. It reproduces the runtime
shape that matters here: tool calls become separate processes, and
sub-agents share one process. A real framework is the next step.

## Running it

```
cargo build --workspace --release
sudo demo/run.sh honest
```

Scenarios: `honest`, `shadow`, `forger`, `pipeline`, `subagent`, `burst`,
`evade`, `longpath`, `tamper`, `escalate`.

The harness refuses to start unless the host is in a known state: audit
enabled with no other rules loaded, the agent account present and idle,
and enough room in the audit log that the run cannot force it to rotate.
It adds two audit rules for the run and removes exactly those two, by
exact text, on every exit path. It deletes nothing. Each run leaves a
directory under `/var/lib/anchorstamp/` with the report and every log.

## Reading a report

### Honest: every claim corroborated

The agent ran four commands through the library.

```
claims (4)
  #1 pid 674814  CORROBORATED - the observer recorded an exec with this pid and this executable.
      strength SOFTWARE (100); held there because: the matching sighting carries no
      self-provenance; the observer's sequence source is not appraised; the anchor is
      asserted by the operator
      seen: index 3 exe /usr/bin/true
  #2 pid 674815  CORROBORATED - …
      seen: index 4 exe /usr/bin/ls
  …
```

Corroborated is not the same as trusted. The strength line says how far
the corroboration goes and why it stops there: nothing measured the
observer's own launch, nothing outside the observer vouches for its
sequence, and the observer's public key is taken on the operator's word.
A reader decides what strength it needs. anchorstamp only reports it.

### Shadow: the action the agent never mentioned

The agent ran four commands. Two went through the library. Two did not:
`id` and `uname`.

What the agent's own log says, in full order:

```
CLAIM     pid=675100  (true)
UNCLAIMED pid=675103  (id)
CLAIM     pid=675105  (ls)
UNCLAIMED pid=675108  (uname)
```

What the report says, from the observer's record alone:

```
claims (2)
  #1 pid 675100  CORROBORATED …   seen: index 3 exe /usr/bin/true
  #2 pid 675105  CORROBORATED …   seen: index 5 exe /usr/bin/ls

unclaimed execs (4)
  other execs of the measured account (4)
    index 1 pid 675097 … exe /usr/bin/setsid
    index 2 pid 675099 … exe /usr/local/lib/anchorstamp-poc/…/agentsim
    index 4 pid 675103 … exe /usr/bin/id
    index 6 pid 675108 … exe /usr/bin/uname
```

The reader never saw the agent's log. It found `id` and `uname` because the
kernel saw them and the agent made no claim for them. That is the property
this project exists for: an action does not need to be reported to be
visible.

The first two unclaimed entries are the harness starting the agent. They
run under the agent's account, so they are recorded, and the report lists
them rather than hiding them.

### Forger: two false claims, two different failures

The agent made three honest claims and two forged ones.

```
  #3 pid 4294967294  CONTRADICTED (unobserved) - the observer's record continues
     past the claim's time with no gap touching it, and holds no exec with this pid.

  #5 pid 675397  CONTRADICTED (subject mismatch) - the observer recorded this pid
     running a different executable.
      this pid seen with another executable: index 6 exe /usr/bin/id
```

Claim #3 describes an action that never happened. The reader can say so
only because the observer was mediating — every exec passes through it —
and its record runs past the claim with no hole in it. Under a sampling
observer, or with a gap nearby, the same claim would read *nothing to
compare*, and the report would say why.

Claim #5 is the subtler forgery. Process 675397 really ran. The agent
claimed it ran `/usr/bin/true`; the kernel recorded `/usr/bin/id`. A
reference that resolves to *a* real event is not a match.

### Pipeline: children are shown, not credited

```
claims (2)
  #1 pid 675685  CORROBORATED …   seen: index 3 exe /usr/bin/dash
  #2 pid 675690  CORROBORATED …   seen: index 6 exe /usr/bin/dash

unclaimed execs (6)
  child of a claimed exec (same parent pid, not earlier) (4)
    child of claim #1: index 4 … exe /usr/bin/wc
    child of claim #1: index 5 … exe /usr/bin/ls
    child of claim #2: index 7 … exe /usr/bin/date
    child of claim #2: index 8 … exe /usr/bin/true
```

The agent claimed two shell commands. The shells' own children are listed
as children of those claims — not as covered by them. A claimed `make test`
that quietly runs `curl` shows up exactly this way.

### Sub-agents: what cannot be recovered

The agent ran five commands from four labelled sub-agents — planner,
coder, tester, reviewer. All five commands are corroborated. None of the
labels is, and none can be: the sub-agents are threads in one process, so
the kernel sees one actor. The label is something the agent says about
itself. The report corroborates the action and leaves the label as the
agent's claim.

## What every report also states

Each report ends with the same statements, whatever the result:

```
Records after the last one shown cannot be distinguished from none.
This reader runs outside the measured account.
The observer's position and coverage mode are self-declared.
The library runs inside the measured account and is not a trusted component.
Limit: two execs reusing one pid with one binary are indistinguishable.
Limit: a claim proves an exec matching the descriptor was observed — not
       that the claimant caused it.
Limit: scripts are out of scope: audit records the interpreter.
```

They are printed on every run because a limit that is stated only in the
documentation is a limit the reader of a report never sees.

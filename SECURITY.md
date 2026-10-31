# Security policy

anchorstamp is a proof of concept. It has not been audited and should not
be relied on to protect anything. Reports are still very welcome: finding
where the design breaks is the point of publishing it.

## Reporting a vulnerability

Please report privately through GitHub:
**Security → Report a vulnerability** on this repository. Do not open a
public issue for a vulnerability.

Include what you did, what you expected the reader or observer to report,
and what it reported instead. A failing scenario file or a short script is
the most useful form.

This is a single-maintainer project. Expect an acknowledgement within a
week and a fix or a written disposition on a best-effort basis. Coordinated
disclosure is preferred; 90 days is the default window, and shorter if a
fix lands sooner.

## What counts

In scope — anything that makes the system say more than the evidence
supports:

- the reader reports `corroborated` for an action that did not happen, or
  for a different action than the one claimed
- an action by the measured account that the observer does not record, and
  that the report does not flag as a gap, a rejected record or a limit
- the measured account altering, truncating or reordering the observer's
  records or its anchor without the report showing it
- the observer's signing key leaving the observer's memory
- anything in `demo/run.sh` that could damage the host it runs on, leave
  audit rules or processes behind, or run code the measured account could
  have changed

Out of scope — limits the project already states, in the documentation and
in every report:

- which sub-agent acted, when sub-agents share one process
- that a corroborated claim proves the claimant caused the action
- two executions that reuse one process ID with the same program
- scripts, where the kernel records the interpreter
- an observer whose position and coverage are self-declared, or whose
  anchor is supplied by the operator
- a reader running inside the measured account
- a compromised kernel, or root on the observing host

If you think one of the stated limits is wrong, that is worth reporting
too, as an ordinary issue.

## Supported versions

Only the `main` branch. There are no releases yet.

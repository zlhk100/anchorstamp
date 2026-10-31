//! agentsim — a scripted stand-in for an agent framework's runtime
//! behaviour. No model, no network. Sub-agents are threads in one process
//! sharing one library session; actions are subprocesses.
//!
//! A scenario is one step per line: `<agent> <mode> <arguments...>`.
//! Blank lines and lines starting with `#` are ignored. Arguments are split
//! on spaces; single quotes group words.

/// Most execs one scenario may start. The measured account's execs grow
/// the audit log, and a log that rotates mid-run blinds the observer.
pub const EXEC_CAP: u32 = 500;

impl Step {
    /// Execs the step starts itself. A pipeline's shell may start more.
    pub fn execs(&self) -> u32 {
        match self {
            Step::Burst { n, .. } => *n,
            Step::ForgeMismatch { .. } => 2,
            Step::Tamper { .. } => 0,
            _ => 1,
        }
    }
}

/// One scenario step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// Run through the library; the join reference is appended.
    Honest { agent: String, argv: Vec<String> },
    /// Run with std::process; nothing is claimed.
    Shadow { agent: String, argv: Vec<String> },
    /// Claim an exec that never ran: a pid no process can have, the run's
    /// start time, and the digest of `path`.
    ForgeUnobserved { agent: String, path: String },
    /// Run `run` unclaimed, then claim its pid with the digest of `claim`.
    ForgeMismatch { agent: String, run: String, claim: String },
    /// Run through the library; its own children are left unclaimed.
    Pipeline { agent: String, argv: Vec<String> },
    /// N claimed runs of one command.
    Burst { agent: String, n: u32, argv: Vec<String> },
    /// Run through the library on the agent's own thread. Consecutive
    /// subagent steps run concurrently and are joined before the next step.
    Subagent { agent: String, argv: Vec<String> },
    /// Exec through execveat, unclaimed.
    EvadeExecveat { agent: String, path: String },
    /// Exec a 32-bit static binary, unclaimed, if one is installed.
    Evade32 { agent: String },
    /// Copy a binary under a path longer than the observed data holds and
    /// run it through the library.
    Longpath { agent: String, path: String },
    /// Probe, without acting, whether the sink and the anchor could be
    /// written. Every probe must say no.
    Tamper { agent: String },
    /// Try `sudo -n true` and a raw-netlink AUDIT_SET. Both must fail.
    Escalate { agent: String },
}

/// Split a line into words; single quotes group.
pub fn words(line: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut any = false;
    for c in line.chars() {
        match c {
            '\'' => {
                quoted = !quoted;
                any = true;
            }
            ' ' | '\t' if !quoted => {
                if any {
                    out.push(std::mem::take(&mut cur));
                    any = false;
                }
            }
            c => {
                cur.push(c);
                any = true;
            }
        }
    }
    if quoted {
        return Err("unterminated quote".into());
    }
    if any {
        out.push(cur);
    }
    Ok(out)
}

/// Parse a scenario. Any unknown step is an error naming its line; a
/// scenario that would start more than `EXEC_CAP` execs is an error.
pub fn parse(text: &str) -> Result<Vec<Step>, String> {
    let mut steps = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let at = |e: &str| format!("line {}: {e}", n + 1);
        let w = words(line).map_err(|e| at(&e))?;
        if w.len() < 2 {
            return Err(at("need <agent> <mode>"));
        }
        let agent = w[0].clone();
        let rest = &w[2..];
        let need = |k: usize| if rest.len() >= k { Ok(()) } else { Err(at("missing arguments")) };
        let exact =
            |k: usize| if rest.len() == k { Ok(()) } else { Err(at("wrong argument count")) };
        let step = match w[1].as_str() {
            "honest" => need(1).map(|_| Step::Honest { agent, argv: rest.to_vec() })?,
            "shadow" => need(1).map(|_| Step::Shadow { agent, argv: rest.to_vec() })?,
            "pipeline" => need(1).map(|_| Step::Pipeline { agent, argv: rest.to_vec() })?,
            "subagent" => need(1).map(|_| Step::Subagent { agent, argv: rest.to_vec() })?,
            "burst" => {
                need(2)?;
                let n = rest[0].parse().map_err(|_| at("burst count"))?;
                Step::Burst { agent, n, argv: rest[1..].to_vec() }
            }
            "forger" => match rest.first().map(String::as_str) {
                Some("unobserved") => {
                    exact(2)?;
                    Step::ForgeUnobserved { agent, path: rest[1].clone() }
                }
                Some("mismatch") => {
                    exact(3)?;
                    Step::ForgeMismatch { agent, run: rest[1].clone(), claim: rest[2].clone() }
                }
                _ => return Err(at("forger needs unobserved or mismatch")),
            },
            "evade" => match rest.first().map(String::as_str) {
                Some("execveat") => {
                    exact(2)?;
                    Step::EvadeExecveat { agent, path: rest[1].clone() }
                }
                Some("m32") => {
                    exact(1)?;
                    Step::Evade32 { agent }
                }
                _ => return Err(at("evade needs execveat or m32")),
            },
            "longpath" => {
                exact(1)?;
                Step::Longpath { agent, path: rest[0].clone() }
            }
            "tamper" => {
                exact(0)?;
                Step::Tamper { agent }
            }
            "escalate" => {
                exact(0)?;
                Step::Escalate { agent }
            }
            m => return Err(at(&format!("unknown mode {m:?}"))),
        };
        steps.push(step);
    }
    let total = steps.iter().try_fold(0u32, |t, s| t.checked_add(s.execs()));
    if total.is_none_or(|t| t > EXEC_CAP) {
        return Err(format!("scenario starts more than {EXEC_CAP} execs"));
    }
    Ok(steps)
}

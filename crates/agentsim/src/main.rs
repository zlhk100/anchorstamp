//! agentsim <scenario> <run-dir>
//!
//! Runs as the measured account. Writes join references to
//! <run-dir>/claims/claims.bin, each preceded by its length (u32
//! big-endian), and a line per step to stdout. Touches the sink and the
//! audit system only in the tamper and escalate modes, which must fail.

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio, exit};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use agentsim::{Step, parse};
use anchorstamp::{Session, open};
use anchorstamp_core::{JOINREF_MAX_LEN, JoinRef, SchemeTag, SubjectRef, Vantage, encode_joinref};

/// No process can have this id: Linux caps pids at 2^22.
const IMPOSSIBLE_PID: u32 = u32::MAX - 1;

const AUDIT_SET: u16 = 1001;
const AUDIT_STATUS_ENABLED: u32 = 1;

struct Ctx {
    session: Arc<Mutex<Session>>,
    claims: Arc<Mutex<File>>,
    run_dir: PathBuf,
    run_start_ms: u64,
    refusal_failed: bool,
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn out(line: &str) {
    println!("{line}");
}

fn append(claims: &Mutex<File>, j: &JoinRef) {
    let mut buf = [0u8; JOINREF_MAX_LEN];
    let n = encode_joinref(j.subject(), &mut buf).expect("joinref fits");
    let mut framed = (n as u32).to_be_bytes().to_vec();
    framed.extend_from_slice(&buf[..n]);
    let mut f = claims.lock().expect("claims lock");
    if f.write_all(&framed).is_err() {
        eprintln!("agentsim: claims write failed");
        exit(1);
    }
}

fn pid_of(j: &JoinRef) -> u32 {
    u32::from_be_bytes(j.subject().bytes()[0..4].try_into().expect("DEMO subject"))
}

/// Run through the library; append the reference if one came back.
fn claimed(
    session: &Mutex<Session>,
    claims: &Mutex<File>,
    agent: &str,
    mode: &str,
    argv: &[String],
) -> Option<JoinRef> {
    let args: Vec<&str> = argv[1..].iter().map(String::as_str).collect();
    let r = session.lock().expect("session lock").exec_evidence(&argv[0], &args);
    match r.vantage() {
        Vantage::Elevated(j) => {
            append(claims, j);
            out(&format!(
                "CLAIM agent={agent} mode={mode} pid={} status={:?} vantage=Elevated",
                pid_of(j),
                r.result().status()
            ));
            Some(*j)
        }
        Vantage::Local => {
            out(&format!(
                "CLAIM agent={agent} mode={mode} vantage=Local degraded={:?}",
                r.degraded().unwrap_or("")
            ));
            None
        }
    }
}

fn unclaimed(agent: &str, mode: &str, argv: &[String]) -> Option<u32> {
    match Command::new(&argv[0]).args(&argv[1..]).stdin(Stdio::null()).spawn() {
        Ok(mut c) => {
            let pid = c.id();
            let status = c.wait().ok().and_then(|s| s.code());
            out(&format!("UNCLAIMED agent={agent} mode={mode} pid={pid} exit={status:?}"));
            Some(pid)
        }
        Err(e) => {
            out(&format!("UNCLAIMED agent={agent} mode={mode} spawn-failed={}", e.kind()));
            None
        }
    }
}

/// A claim built by the forger from parts it chose.
fn forged(pid: u32, time_ms: u64, digest: &[u8]) -> JoinRef {
    let mut b = [0u8; 32];
    b[0..4].copy_from_slice(&pid.to_be_bytes());
    b[4..12].copy_from_slice(&time_ms.to_be_bytes());
    b[12..32].copy_from_slice(digest);
    JoinRef::new(SubjectRef::new(SchemeTag::DEMO, &b).expect("32 bytes"))
}

fn digest_of(j: &JoinRef) -> [u8; 20] {
    j.subject().bytes()[12..32].try_into().expect("DEMO subject")
}

fn evade_execveat(agent: &str, path: &str) {
    let (file, argv0) = match (File::open(path), CString::new(path)) {
        (Ok(f), Ok(a)) => (f, a),
        _ => {
            out(&format!("EVADE agent={agent} execveat path={path} open-failed"));
            return;
        }
    };
    let fd = file.as_raw_fd();
    let mut cmd = Command::new("/");
    cmd.stdin(Stdio::null());
    // SAFETY: runs in the forked child before exec; it only builds two
    // stack arrays from memory owned by the closure and calls execveat,
    // which replaces the process image or returns an error.
    unsafe {
        cmd.pre_exec(move || {
            let argv = [argv0.as_ptr(), std::ptr::null()];
            let envp: [*const libc::c_char; 1] = [std::ptr::null()];
            libc::execveat(
                fd,
                c"".as_ptr(),
                argv.as_ptr() as *const *mut libc::c_char,
                envp.as_ptr() as *const *mut libc::c_char,
                libc::AT_EMPTY_PATH,
            );
            Err(io::Error::last_os_error())
        });
    }
    match cmd.spawn() {
        Ok(mut c) => {
            let pid = c.id();
            let status = c.wait().ok().and_then(|s| s.code());
            out(&format!("EVADE agent={agent} execveat pid={pid} exit={status:?} claimed=no"));
        }
        Err(e) => out(&format!("EVADE agent={agent} execveat failed={}", e.kind())),
    }
    drop(file);
}

fn evade_m32(agent: &str) {
    let bin = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join("evade32")));
    match bin {
        Some(b) if b.is_file() => {
            let argv = vec![b.to_string_lossy().into_owned()];
            unclaimed(agent, "evade-m32", &argv);
        }
        _ => out(&format!(
            "EVADE agent={agent} m32 NOT RUN: no 32-bit static binary installed (gcc -m32 -static does not build on this host)"
        )),
    }
}

fn longpath(ctx: &Ctx, agent: &str, src: &str) {
    let mut dir = ctx.run_dir.join("claims").join("long");
    while dir.as_os_str().len() < 1500 {
        dir.push("d".repeat(200));
    }
    let target = dir.join("tool");
    let ok = std::fs::create_dir_all(&dir).is_ok()
        && std::fs::copy(src, &target).is_ok()
        && std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).is_ok();
    if !ok {
        out(&format!("LONGPATH agent={agent} setup-failed"));
        return;
    }
    out(&format!("LONGPATH agent={agent} path_len={}", target.as_os_str().len()));
    let argv = vec![target.to_string_lossy().into_owned()];
    claimed(&ctx.session, &ctx.claims, agent, "longpath", &argv);
}

fn refusal(ctx: &mut Ctx, what: &str, r: io::Result<()>) {
    match r {
        Err(e) => out(&format!("REFUSAL {what}: refused ({})", e.kind())),
        Ok(()) => {
            ctx.refusal_failed = true;
            out(&format!("REFUSAL {what}: SUCCEEDED"));
        }
    }
}

fn tamper(ctx: &mut Ctx) {
    let sink = ctx.run_dir.join("sink");
    let s = sink.join("sightings.bin");
    let a = sink.join("anchor.pub");
    // Each attempt only opens or renames; nothing is written even if an
    // attempt were to succeed.
    let r = OpenOptions::new().append(true).open(&s).map(drop);
    refusal(ctx, "tamper open-append sink/sightings.bin", r);
    let r = OpenOptions::new().write(true).open(&a).map(drop);
    refusal(ctx, "tamper open-write sink/anchor.pub", r);
    let r = OpenOptions::new().write(true).create_new(true).open(sink.join("injected")).map(drop);
    refusal(ctx, "tamper create sink/injected", r);
    let r = std::fs::rename(&a, sink.join("anchor.moved"));
    refusal(ctx, "tamper rename sink/anchor.pub", r);
    let r = std::fs::set_permissions(&s, std::fs::Permissions::from_mode(0o666));
    refusal(ctx, "tamper chmod sink/sightings.bin", r);
}

/// AUDIT_SET asking for `enabled = 1`, which audit already is: refused or
/// not, it would change nothing.
fn netlink_audit_set() -> io::Result<()> {
    // SAFETY: a raw netlink socket, a fixed-size request built on the
    // stack, one send and one receive into a stack buffer; the descriptor
    // is closed on every path.
    unsafe {
        let fd = libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_AUDIT,
        );
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let tv = libc::timeval { tv_sec: 2, tv_usec: 0 };
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&tv as *const libc::timeval).cast(),
            size_of::<libc::timeval>() as libc::socklen_t,
        );
        #[repr(C)]
        struct Req {
            h: libc::nlmsghdr,
            status: [u32; 11],
        }
        let mut req: Req = std::mem::zeroed();
        req.h.nlmsg_len = size_of::<Req>() as u32;
        req.h.nlmsg_type = AUDIT_SET;
        req.h.nlmsg_flags = (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16;
        req.h.nlmsg_seq = 1;
        req.status[0] = AUDIT_STATUS_ENABLED; // mask
        req.status[1] = 1; // enabled
        let mut dst: libc::sockaddr_nl = std::mem::zeroed();
        dst.nl_family = libc::AF_NETLINK as u16;
        let sent = libc::sendto(
            fd,
            (&req as *const Req).cast(),
            size_of::<Req>(),
            0,
            (&dst as *const libc::sockaddr_nl).cast(),
            size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        );
        if sent < 0 {
            let e = io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        let mut buf = [0u8; 256];
        let n = libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0);
        let e = io::Error::last_os_error();
        libc::close(fd);
        if n < 0 {
            return Err(e);
        }
        let n = n as usize;
        let hdr = size_of::<libc::nlmsghdr>();
        if n >= hdr + 4 && u16::from_ne_bytes([buf[4], buf[5]]) == libc::NLMSG_ERROR as u16 {
            let code = i32::from_ne_bytes(buf[hdr..hdr + 4].try_into().expect("4 bytes"));
            if code == 0 {
                return Ok(());
            }
            return Err(io::Error::from_raw_os_error(-code));
        }
        Err(io::Error::other("unexpected netlink reply"))
    }
}

fn escalate(ctx: &mut Ctx) {
    let r = match Command::new("sudo").args(["-n", "true"]).stdin(Stdio::null()).output() {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => {
            let first = String::from_utf8_lossy(&o.stderr).lines().next().unwrap_or("").to_string();
            out(&format!("ESCALATE sudo -n true exit={:?} stderr={first:?}", o.status.code()));
            Err(io::Error::other("sudo refused"))
        }
        Err(e) => Err(e),
    };
    refusal(ctx, "escalate sudo -n true", r);
    refusal(ctx, "escalate netlink AUDIT_SET", netlink_audit_set());
}

fn run(ctx: &mut Ctx, steps: &[Step]) {
    let mut i = 0;
    while i < steps.len() {
        // a block of consecutive subagent steps runs concurrently
        if matches!(steps[i], Step::Subagent { .. }) {
            let mut handles = Vec::new();
            while let Some(Step::Subagent { agent, argv }) = steps.get(i) {
                let (s, c, a, v) =
                    (ctx.session.clone(), ctx.claims.clone(), agent.clone(), argv.clone());
                handles.push(std::thread::spawn(move || {
                    claimed(&s, &c, &a, "subagent", &v);
                }));
                i += 1;
            }
            for h in handles {
                if h.join().is_err() {
                    eprintln!("agentsim: subagent thread failed");
                    exit(1);
                }
            }
            continue;
        }
        match &steps[i] {
            Step::Honest { agent, argv } => {
                claimed(&ctx.session, &ctx.claims, agent, "honest", argv);
            }
            Step::Shadow { agent, argv } => {
                unclaimed(agent, "shadow", argv);
            }
            Step::Pipeline { agent, argv } => {
                claimed(&ctx.session, &ctx.claims, agent, "pipeline", argv);
            }
            Step::Burst { agent, n, argv } => {
                for _ in 0..*n {
                    claimed(&ctx.session, &ctx.claims, agent, "burst", argv);
                }
            }
            Step::ForgeUnobserved { agent, path } => 'step: {
                // learn a real digest from a real claim, then fabricate
                let Some(real) = claimed(
                    &ctx.session,
                    &ctx.claims,
                    agent,
                    "forger-source",
                    std::slice::from_ref(path),
                ) else {
                    break 'step;
                };
                let j = forged(IMPOSSIBLE_PID, ctx.run_start_ms, &digest_of(&real));
                append(&ctx.claims, &j);
                out(&format!(
                    "FORGED agent={agent} kind=unobserved pid={IMPOSSIBLE_PID} time_ms={}",
                    ctx.run_start_ms
                ));
            }
            Step::ForgeMismatch { agent, run, claim } => 'step: {
                let Some(real) = claimed(
                    &ctx.session,
                    &ctx.claims,
                    agent,
                    "forger-source",
                    std::slice::from_ref(claim),
                ) else {
                    break 'step;
                };
                let Some(pid) = unclaimed(agent, "forger-run", std::slice::from_ref(run)) else {
                    break 'step;
                };
                let j = forged(pid, now_ms(), &digest_of(&real));
                append(&ctx.claims, &j);
                out(&format!(
                    "FORGED agent={agent} kind=mismatch pid={pid} ran={run} claimed={claim}"
                ));
            }
            Step::EvadeExecveat { agent, path } => evade_execveat(agent, path),
            Step::Evade32 { agent } => evade_m32(agent),
            Step::Longpath { agent, path } => longpath(ctx, agent, path),
            Step::Tamper { .. } => tamper(ctx),
            Step::Escalate { .. } => escalate(ctx),
            Step::Subagent { .. } => unreachable!("handled above"),
        }
        i += 1;
    }
}

fn main() {
    let run_start_ms = now_ms();
    let a: Vec<String> = std::env::args().collect();
    if a.len() != 3 {
        eprintln!("usage: agentsim <scenario> <run-dir>");
        exit(2);
    }
    let text = std::fs::read_to_string(&a[1]).unwrap_or_else(|e| {
        eprintln!("agentsim: cannot read scenario: {}", e.kind());
        exit(2)
    });
    let steps = parse(&text).unwrap_or_else(|e| {
        eprintln!("agentsim: scenario: {e}");
        exit(2)
    });
    let run_dir = PathBuf::from(&a[2]);
    let claims = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o644)
        .open(Path::new(&run_dir).join("claims").join("claims.bin"))
        .unwrap_or_else(|e| {
            eprintln!("agentsim: cannot create claims file: {}", e.kind());
            exit(2)
        });
    out(&format!("START run_start_ms={run_start_ms} steps={}", steps.len()));
    let mut ctx = Ctx {
        session: Arc::new(Mutex::new(open())),
        claims: Arc::new(Mutex::new(claims)),
        run_dir,
        run_start_ms,
        refusal_failed: false,
    };
    run(&mut ctx, &steps);
    if ctx.refusal_failed {
        out("STOP: a refusal test succeeded");
        exit(3);
    }
    out("END");
}

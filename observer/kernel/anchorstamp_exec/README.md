# anchorstamp_exec

A kernel module that turns every successful exec into a record measured
by IMA. IMA appends each record to its measurement list and extends the
PCR named by its policy rule, so the record and the TPM extend are made by
the kernel, not by a user-space process the measured party could reach.

The module keeps no log of its own, exports nothing and never talks to the
TPM. It refuses to load when IMA has no policy rule for its label.

## Records

Declares: anchorstamp specification 0.4, layout 1, source profile K.

Each record is an IMA critical-data buffer with label `anchorstamp`,
event `exec`, template `ima-buf`. IMA's list carries the record itself,
not a digest of it. Format version 2: magic `ASX2`, packed, every
multi-byte integer little-endian. The header is magic (4), kind (1), seq
(8, per load, LOAD is 0), load_id (16, random per load).

| Kind | Size | Body |
|---|---|---|
| 1 EXEC | 148 + path_len | pid, tgid, ppid, old_pid, uid, euid (u32, initial namespaces); start_ns (u64, fork time); exec_ns (u64, boot clock read first in the probe); dev (u32, the file's superblock s_dev); ino (u64); exe_digest (SHA-256 over the full resolved path); req_digest (SHA-256 over the path exec was asked to run); ns (u8); path_len (u16, at most 1024); path |
| 2 LOAD | 39 | shim_version (u16, 2); loaded_ns (u64, before the probe is registered) |
| 5 ARMED | 37 | armed_ns (u64, after the probe is live on every CPU) |
| 3 LOST | 53 | count (u64); first_ns, last_ns (u64): the least and greatest exec_ns of the execs counted |
| 4 UNLOAD | 45 | close_ns (u64, before the probe is unregistered); unloaded_ns (u64, after it is off everywhere) |

EXEC kind bits: bit 7 path truncated at 1024 bytes; bit 6 path unresolved
(path_len 0, exe_digest zero); bit 5 interpreted (the kernel ran an
interpreter for a `#!` file). ns bits: 0 not in the initial PID namespace,
1 not in the initial mount namespace, 2 root is not the initial root, 3
file unlinked when resolved. seq advances only when IMA measured the
record, so a gap-free seq and the LOST records account for every exec
seen after ARMED.

The probe stays gated until ARMED is queued: ARMED is always the second
record, and an exec that met the closed gate is counted in a LOST after
it. At most 1024 execs wait to be recorded. An exec beyond that, or one
whose queue item cannot be allocated without the kernel's emergency
reserves, is counted in the next LOST with its exec_ns.

If anything fails after LOAD and before ARMED, the module refuses to
load and the load is LOAD alone. If ARMED cannot be measured, nothing
more is measured for that load. On unload the module measures any
pending LOST, then UNLOAD; if that final LOST cannot be measured, or the
load measured no ARMED, it emits no UNLOAD, so a load whose losses were
not all reported never appears closed.

## Build

Against the running kernel's headers, with the compiler that built it:

    make

which runs `make -C /lib/modules/$(uname -r)/build M=$PWD
CC=x86_64-linux-gnu-gcc-12 modules`.

`make fault` builds a debug variant with fault injection (`ASX_FAULT`)
in the workspace's `target/asx-fault/`, never beside the released module;
`../fault.sh` loads only that build, with one of its fixed settings.

## Load

Root only. First the IMA policy rule, once per boot:

    measure func=CRITICAL_DATA label=anchorstamp pcr=13 template=ima-buf

then `insmod anchorstamp_exec.ko`. The module is unsigned and taints the
kernel. `../policy.sh`, `../load.sh` and `../unload.sh` do these steps and
log what the kernel printed.

## Licence

This module only: MIT or GPL-2.0 (`MODULE_LICENSE("Dual MIT/GPL")`), since
it uses GPL-only kernel symbols. The licence texts are `LICENSE-GPL-2.0`
and `LICENSE-MIT` at the root of the repository. The rest of the
repository is MIT OR Apache-2.0.

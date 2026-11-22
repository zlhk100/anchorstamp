# anchorstamp_exec

A kernel module that turns every successful exec into a record measured
by IMA. IMA appends each record to its measurement list and extends the
PCR named by its policy rule, so the record and the TPM extend are made by
the kernel, not by a user-space process the measured party could reach.

The module keeps no log of its own, exports nothing and never talks to the
TPM. It refuses to load when IMA has no policy rule for its label.

## Records

Each record is an IMA critical-data buffer with label `anchorstamp`,
event `exec`, template `ima-buf`. IMA's list carries the record itself,
not a digest of it. Format version 1: magic `ASX1`, packed,
every multi-byte integer little-endian. The header is magic (4), kind (1),
seq (8, per load, LOAD is 0), load_id (16, random per load).

| Kind | Size | Body |
|---|---|---|
| 1 EXEC | 83 + path_len | pid, tgid, ppid, old_pid, uid, euid (u32, initial namespaces); start_ns (u64); path_digest (first 20 bytes of SHA-256 over the full path); path_len (u16, at most 1024); path |
| 2 LOAD | 39 | shim_version (u16, 1); loaded_ns (u64, boot time before the probe is registered) |
| 3 LOST | 37 | count (u64): execs not recorded since the last record |
| 4 UNLOAD | 29 | header only |

Kind bit 7 marks a path truncated at 1024 bytes; bit 6 marks a path that
could not be resolved (path_len 0, digest zero). seq advances only when
IMA measured the record, so a gap-free seq and the LOST counts account for
every exec seen after LOAD.

## Build

Against the running kernel's headers, with the compiler that built it:

    make

which runs `make -C /lib/modules/$(uname -r)/build M=$PWD
CC=x86_64-linux-gnu-gcc-12 modules`.

## Load

Root only. First the IMA policy rule, once per boot:

    measure func=CRITICAL_DATA label=anchorstamp pcr=13 template=ima-buf

then `insmod anchorstamp_exec.ko`. The module is unsigned and taints the
kernel. `../policy.sh`, `../load.sh` and `../unload.sh` do these steps and
log what the kernel printed.

## Licence

This module only: MIT or GPL-2.0 (`MODULE_LICENSE("Dual MIT/GPL")`), since
it uses GPL-only kernel symbols. The rest of the repository is MIT OR
Apache-2.0.

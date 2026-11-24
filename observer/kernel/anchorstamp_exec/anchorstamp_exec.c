// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * anchorstamp_exec - kernel-side exec evidence anchored in the TPM.
 *
 * Copyright © 2026 Lei Zhou
 *
 * Declares: anchorstamp specification 0.4, layout 1, source profile K.
 *
 * Every successful exec becomes one record, handed to IMA as critical
 * data under the label "anchorstamp". IMA appends the record to its
 * measurement list and extends the PCR its policy rule names. This module
 * keeps no log of its own, exports nothing and never talks to the TPM.
 *
 * Record format version 2: packed, every multi-byte integer little-endian,
 * written field by field.
 *
 *   header, every kind (29 bytes)
 *     0  4  magic    "ASX2"
 *     4  1  kind     bits 0-3: 1 EXEC, 2 LOAD, 3 LOST, 4 UNLOAD, 5 ARMED
 *                    EXEC only: bit 7 path truncated, bit 6 path
 *                    unresolved, bit 5 interpreted; bit 4 zero
 *     5  8  seq      per load; LOAD is 0, +1 per measured record
 *    13 16  load_id  random per load
 *
 *   EXEC (148 + path_len): pid, tgid, ppid, old_pid, uid, euid (u32 each,
 *     initial namespaces); start_ns (u64, fork time); exec_ns (u64, boot
 *     clock at probe entry); dev (u32, the file's superblock s_dev); ino
 *     (u64); exe_digest (SHA-256 over the full resolved path, zero if
 *     unresolved); req_digest (SHA-256 over the requested path); ns (u8:
 *     bit 0 not the initial PID namespace, bit 1 not the initial mount
 *     namespace, bit 2 root not the initial root, bit 3 file unlinked
 *     when resolved); path_len (u16, at most 1024); path
 *   LOAD (39): shim_version (u16, 2), loaded_ns (u64, before the probe is
 *     registered)
 *   ARMED (37): armed_ns (u64, after the probe is live on every CPU)
 *   LOST (53): count (u64), first_ns, last_ns (u64): the least and
 *     greatest exec_ns among the execs counted
 *   UNLOAD (45): close_ns (u64, before the probe is unregistered),
 *     unloaded_ns (u64, after it is unregistered everywhere)
 *
 * Context: the probe runs on the exec path with preemption disabled. It
 * reads the boot clock first, then either counts the exec as lost (gate
 * closed, queue full, no memory) or copies what the record needs, hashes
 * the requested path, takes a file reference and queues an item. At most
 * 1024 items wait. An ordered workqueue builds and measures the records
 * one at a time, which keeps seq contiguous without a lock. The gate
 * stays closed until ARMED is queued, so ARMED is always the second
 * record; execs that meet the closed gate are counted in a LOST after it.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/atomic.h>
#include <linux/binfmts.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/ima.h>
#include <linux/limits.h>
#include <linux/module.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/seqlock.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <linux/tracepoint.h>
#include <linux/uidgid.h>
#include <linux/workqueue.h>
#include <crypto/sha2.h>
#include <asm/unaligned.h>

#define ASX_LABEL		"anchorstamp"
#define ASX_EVENT		"exec"
#define ASX_TRACEPOINT		"sched_process_exec"
#define ASX_SHIM_VERSION	2

#define ASX_KIND_EXEC		1
#define ASX_KIND_LOAD		2
#define ASX_KIND_LOST		3
#define ASX_KIND_UNLOAD		4
#define ASX_KIND_ARMED		5
#define ASX_PATH_TRUNCATED	0x80
#define ASX_PATH_UNRESOLVED	0x40
#define ASX_INTERPRETED		0x20

#define ASX_NS_PID		0x01
#define ASX_NS_MNT		0x02
#define ASX_NS_ROOT		0x04
#define ASX_NS_UNLINKED		0x08

#define ASX_LOAD_ID_LEN		16
#define ASX_PATH_CAP		1024
#define ASX_PENDING_CAP		1024

/* Header offsets. */
#define ASX_OFF_MAGIC		0
#define ASX_OFF_KIND		4
#define ASX_OFF_SEQ		5
#define ASX_OFF_LOAD_ID		13
#define ASX_HDR_LEN		29

/* EXEC offsets. */
#define ASX_OFF_PID		29
#define ASX_OFF_TGID		33
#define ASX_OFF_PPID		37
#define ASX_OFF_OLD_PID		41
#define ASX_OFF_UID		45
#define ASX_OFF_EUID		49
#define ASX_OFF_START_NS	53
#define ASX_OFF_EXEC_NS		61
#define ASX_OFF_DEV		69
#define ASX_OFF_INO		73
#define ASX_OFF_EXE_DIGEST	81
#define ASX_OFF_REQ_DIGEST	113
#define ASX_OFF_NS		145
#define ASX_OFF_PATH_LEN	146
#define ASX_OFF_PATH		148
#define ASX_EXEC_MAX		(ASX_OFF_PATH + ASX_PATH_CAP)

/* LOAD offsets. */
#define ASX_OFF_SHIM_VERSION	29
#define ASX_OFF_LOADED_NS	31
#define ASX_LOAD_LEN		39

/* ARMED offsets. */
#define ASX_OFF_ARMED_NS	29
#define ASX_ARMED_LEN		37

/* LOST offsets. */
#define ASX_OFF_COUNT		29
#define ASX_OFF_FIRST_NS	37
#define ASX_OFF_LAST_NS		45
#define ASX_LOST_LEN		53

/* UNLOAD offsets. */
#define ASX_OFF_CLOSE_NS	29
#define ASX_OFF_UNLOADED_NS	37
#define ASX_UNLOAD_LEN		45

/* One exec, copied in the probe and consumed by the worker. */
struct asx_item {
	struct work_struct work;
	struct file *file;
	u32 pid;
	u32 tgid;
	u32 ppid;
	u32 old_pid;
	u32 uid;
	u32 euid;
	u64 start_ns;
	u64 exec_ns;
	u32 dev;
	u64 ino;
	u8 req_digest[SHA256_DIGEST_SIZE];
	u8 flags;
	u8 ns;
};

/* The ARMED record's item: allocated by init, freed by the worker. */
struct asx_armed_item {
	struct work_struct work;
	u64 armed_ns;
};

/* Execs counted and not yet reported; first/last undefined at count 0. */
struct asx_loss_state {
	u64 count;
	u64 first_ns;
	u64 last_ns;
};

/* Set by init before the probe is registered; cleared by nothing. */
static struct tracepoint *asx_tp;
/* Created first in init, destroyed last in exit. */
static struct workqueue_struct *asx_wq;
/* Written only by init, the worker and exit, never concurrently. */
static u64 asx_seq;
/* Execs not recorded since the last record: probe, worker and exit. */
static struct asx_loss_state asx_loss;
/* Guards asx_loss. A leaf: nothing is taken under it. */
static DEFINE_SPINLOCK(asx_loss_lock);
/* Items queued and not yet freed: the probe adds, the worker removes. */
static atomic_t asx_pending = ATOMIC_INIT(0);
/* Written once in init, before the probe is registered. */
static u8 asx_load_id[ASX_LOAD_ID_LEN];
/* The gate: set once by init (release) after ARMED is queued. */
static int asx_armed;
/* Set by the worker when ARMED was not measured: nothing more is. */
static bool asx_dead;

#ifdef ASX_FAULT
/*
 * Debug build only: fault injection. Each setting is 0 (off) or N: the
 * Nth occurrence fails (for _from, every one from the Nth; for the flags,
 * 1 fails the one occurrence). Never in the released module.
 */
static int asx_fault_exec;
module_param(asx_fault_exec, int, 0444);
MODULE_PARM_DESC(asx_fault_exec, "debug: the Nth EXEC measure fails");
static int asx_fault_exec_from;
module_param(asx_fault_exec_from, int, 0444);
MODULE_PARM_DESC(asx_fault_exec_from, "debug: every EXEC measure from the Nth fails");
static int asx_fault_alloc;
module_param(asx_fault_alloc, int, 0444);
MODULE_PARM_DESC(asx_fault_alloc, "debug: the Nth worker allocation fails");
static int asx_fault_lost;
module_param(asx_fault_lost, int, 0444);
MODULE_PARM_DESC(asx_fault_lost, "debug: the Nth LOST measure fails");
static int asx_fault_final_lost;
module_param(asx_fault_final_lost, int, 0444);
MODULE_PARM_DESC(asx_fault_final_lost, "debug: 1: exit's LOST measure fails");
static int asx_fault_armed;
module_param(asx_fault_armed, int, 0444);
MODULE_PARM_DESC(asx_fault_armed, "debug: 1: ARMED's measure fails");
static int asx_fault_lookup;
module_param(asx_fault_lookup, int, 0444);
MODULE_PARM_DESC(asx_fault_lookup, "debug: 1: the tracepoint lookup fails");

enum asx_site { ASX_SITE_EXEC, ASX_SITE_ALLOC, ASX_SITE_LOST, ASX_SITES };
/* Occurrences per site, counted by the worker only. */
static int asx_fault_hits[ASX_SITES];

static bool asx_fault(enum asx_site site, int nth, int from, u64 exec_ns)
{
	int n = ++asx_fault_hits[site];

	if ((nth && n == nth) || (from && n >= from)) {
		pr_info("fault injected: site %d occurrence %d exec_ns %llu\n",
			site, n, exec_ns);
		return true;
	}
	return false;
}

static bool asx_fault_flag(int flag, const char *what)
{
	if (flag)
		pr_info("fault injected: %s\n", what);
	return flag;
}
#else
#define asx_fault(site, nth, from, exec_ns)	false
#define asx_fault_flag(flag, what)		false
#endif

static void asx_loss_add(u64 t, u64 n)
{
	spin_lock(&asx_loss_lock);
	if (!asx_loss.count) {
		asx_loss.first_ns = t;
		asx_loss.last_ns = t;
	} else {
		asx_loss.first_ns = min(asx_loss.first_ns, t);
		asx_loss.last_ns = max(asx_loss.last_ns, t);
	}
	asx_loss.count += n;
	spin_unlock(&asx_loss_lock);
}

static struct asx_loss_state asx_loss_take(void)
{
	struct asx_loss_state snap;

	spin_lock(&asx_loss_lock);
	snap = asx_loss;
	asx_loss.count = 0;
	spin_unlock(&asx_loss_lock);
	return snap;
}

/* Merge a snapshot whose LOST was not measured back into the state. */
static void asx_loss_put(const struct asx_loss_state *snap)
{
	if (!snap->count)
		return;
	asx_loss_add(snap->first_ns, snap->count);
	asx_loss_add(snap->last_ns, 0);
}

static void asx_put_header(u8 *buf, u8 kind)
{
	memcpy(buf + ASX_OFF_MAGIC, "ASX2", 4);
	buf[ASX_OFF_KIND] = kind;
	put_unaligned_le64(asx_seq, buf + ASX_OFF_SEQ);
	memcpy(buf + ASX_OFF_LOAD_ID, asx_load_id, ASX_LOAD_ID_LEN);
}

/*
 * Hand one record to IMA. hash is false: the buffer IMA appends to its list
 * is the record itself, not a digest of it. seq advances only when IMA
 * measured it.
 */
static int asx_measure(const u8 *buf, size_t len)
{
	int ret;

	ret = ima_measure_critical_data(ASX_LABEL, ASX_EVENT, buf, len, false,
					NULL, 0);
	if (!ret)
		asx_seq++;
	return ret;
}

static int asx_emit_lost(const struct asx_loss_state *snap, bool fail)
{
	u8 buf[ASX_LOST_LEN];

	if (fail)
		return -EIO;
	asx_put_header(buf, ASX_KIND_LOST);
	put_unaligned_le64(snap->count, buf + ASX_OFF_COUNT);
	put_unaligned_le64(snap->first_ns, buf + ASX_OFF_FIRST_NS);
	put_unaligned_le64(snap->last_ns, buf + ASX_OFF_LAST_NS);
	return asx_measure(buf, sizeof(buf));
}

static void asx_release(struct asx_item *item)
{
	if (item->file)
		fput(item->file);
	kfree(item);
	atomic_dec(&asx_pending);
}

/*
 * Build the EXEC record into rec, resolving the path through pathbuf
 * (PATH_MAX bytes). The unlink check follows d_path, so it sees any
 * unlink d_path saw. Returns the record length.
 */
static int asx_build_exec(const struct asx_item *item, u8 *rec,
			  char *pathbuf)
{
	u8 kind = ASX_KIND_EXEC | item->flags;
	u8 ns = item->ns;
	size_t len = 0;
	char *path;

	memset(rec + ASX_OFF_EXE_DIGEST, 0, SHA256_DIGEST_SIZE);
	path = d_path(&item->file->f_path, pathbuf, PATH_MAX);
	if (d_unlinked(item->file->f_path.dentry))
		ns |= ASX_NS_UNLINKED;
	if (IS_ERR(path)) {
		kind |= ASX_PATH_UNRESOLVED;
	} else {
		len = strlen(path);
		sha256((const u8 *)path, len, rec + ASX_OFF_EXE_DIGEST);
		if (len > ASX_PATH_CAP) {
			kind |= ASX_PATH_TRUNCATED;
			len = ASX_PATH_CAP;
		}
		memcpy(rec + ASX_OFF_PATH, path, len);
	}

	asx_put_header(rec, kind);
	put_unaligned_le32(item->pid, rec + ASX_OFF_PID);
	put_unaligned_le32(item->tgid, rec + ASX_OFF_TGID);
	put_unaligned_le32(item->ppid, rec + ASX_OFF_PPID);
	put_unaligned_le32(item->old_pid, rec + ASX_OFF_OLD_PID);
	put_unaligned_le32(item->uid, rec + ASX_OFF_UID);
	put_unaligned_le32(item->euid, rec + ASX_OFF_EUID);
	put_unaligned_le64(item->start_ns, rec + ASX_OFF_START_NS);
	put_unaligned_le64(item->exec_ns, rec + ASX_OFF_EXEC_NS);
	put_unaligned_le32(item->dev, rec + ASX_OFF_DEV);
	put_unaligned_le64(item->ino, rec + ASX_OFF_INO);
	memcpy(rec + ASX_OFF_REQ_DIGEST, item->req_digest, SHA256_DIGEST_SIZE);
	rec[ASX_OFF_NS] = ns;
	put_unaligned_le16(len, rec + ASX_OFF_PATH_LEN);
	return ASX_OFF_PATH + len;
}

static void asx_work(struct work_struct *work)
{
	struct asx_item *item = container_of(work, struct asx_item, work);
	struct asx_loss_state snap;
	char *pathbuf = NULL;
	u8 *rec = NULL;
	bool fail;
	int len;

	if (asx_dead)
		goto out;

	/* A pending loss is reported before the record that found it. */
	snap = asx_loss_take();
	if (snap.count) {
		fail = asx_fault(ASX_SITE_LOST, asx_fault_lost, 0, item->exec_ns);
		if (asx_emit_lost(&snap, fail)) {
			asx_loss_put(&snap);
			asx_loss_add(item->exec_ns, 1);
			goto out;
		}
	}

	if (!asx_fault(ASX_SITE_ALLOC, asx_fault_alloc, 0, item->exec_ns)) {
		rec = kmalloc(ASX_EXEC_MAX, GFP_KERNEL);
		pathbuf = kmalloc(PATH_MAX, GFP_KERNEL);
	}
	if (!rec || !pathbuf) {
		asx_loss_add(item->exec_ns, 1);
		goto out;
	}

	len = asx_build_exec(item, rec, pathbuf);
	fput(item->file);
	item->file = NULL;
	if (asx_fault(ASX_SITE_EXEC, asx_fault_exec, asx_fault_exec_from,
		      item->exec_ns) ||
	    asx_measure(rec, len))
		asx_loss_add(item->exec_ns, 1);

out:
	kfree(pathbuf);
	kfree(rec);
	asx_release(item);
}

static void asx_work_armed(struct work_struct *work)
{
	struct asx_armed_item *armed =
		container_of(work, struct asx_armed_item, work);
	u8 buf[ASX_ARMED_LEN];
	int ret = -EIO;

	asx_put_header(buf, ASX_KIND_ARMED);
	put_unaligned_le64(armed->armed_ns, buf + ASX_OFF_ARMED_NS);
	if (!asx_fault_flag(asx_fault_armed, "ARMED measure"))
		ret = asx_measure(buf, sizeof(buf));
	if (ret) {
		asx_dead = true;
		pr_err("ARMED not measured (%d): this load covers nothing\n", ret);
	}
	kfree(armed);
}

/* Read fs->root consistently with its writers. */
static void asx_read_root(struct fs_struct *fs, struct path *root)
{
	unsigned int seq;

	do {
		seq = read_seqcount_begin(&fs->seq);
		*root = fs->root;
	} while (read_seqcount_retry(&fs->seq, seq));
}

/*
 * ns bits 0-2. p is current: its nsproxy and fs change only by its own
 * action. init_task's fs is init_fs, shared with pid 1, whose root pid 1
 * may change; it is read under its seqcount.
 */
static u8 asx_ns_bits(struct task_struct *p)
{
	struct path root, init_root;
	u8 ns = 0;

	if (task_active_pid_ns(p) != &init_pid_ns)
		ns |= ASX_NS_PID;
	if (!p->nsproxy || p->nsproxy->mnt_ns != init_task.nsproxy->mnt_ns)
		ns |= ASX_NS_MNT;
	asx_read_root(p->fs, &root);
	asx_read_root(init_task.fs, &init_root);
	if (root.mnt != init_root.mnt || root.dentry != init_root.dentry)
		ns |= ASX_NS_ROOT;
	return ns;
}

/*
 * sched_process_exec probe: preemption is disabled here. The boot clock
 * is read first. With the gate closed, the exec is counted as lost. Else,
 * copy what the record needs, hash the requested path, take a reference
 * on the executable and queue the item. Never sleeps and never fails the
 * exec. At most ASX_PENDING_CAP items wait; an exec beyond that, or one
 * whose item cannot be allocated without the emergency reserves, is
 * counted as lost with its time.
 */
static void asx_probe(void *data, struct task_struct *p, pid_t old_pid,
		      struct linux_binprm *bprm)
{
	u64 t = ktime_get_boottime_ns();
	const struct cred *cred;
	struct asx_item *item;
	struct inode *inode;

	/* Pairs with init's release: seeing the gate open means ARMED is queued. */
	if (!smp_load_acquire(&asx_armed)) {
		asx_loss_add(t, 1);
		return;
	}
	if (atomic_inc_return(&asx_pending) > ASX_PENDING_CAP) {
		atomic_dec(&asx_pending);
		asx_loss_add(t, 1);
		return;
	}
	item = kmalloc(sizeof(*item), GFP_NOWAIT | __GFP_NOWARN);
	if (!item) {
		atomic_dec(&asx_pending);
		asx_loss_add(t, 1);
		return;
	}
	INIT_WORK(&item->work, asx_work);
	item->exec_ns = t;
	item->pid = task_pid_nr(p);
	item->tgid = task_tgid_nr(p);
	item->old_pid = old_pid;
	item->start_ns = p->start_boottime;
	rcu_read_lock();
	item->ppid = task_tgid_nr(rcu_dereference(p->real_parent));
	cred = __task_cred(p);
	item->uid = from_kuid(&init_user_ns, cred->uid);
	item->euid = from_kuid(&init_user_ns, cred->euid);
	rcu_read_unlock();
	inode = file_inode(bprm->file);
	item->dev = inode->i_sb->s_dev;
	item->ino = inode->i_ino;
	item->flags = bprm->interp != bprm->filename ? ASX_INTERPRETED : 0;
	item->ns = asx_ns_bits(p);
	sha256((const u8 *)bprm->filename, strlen(bprm->filename),
	       item->req_digest);
	item->file = get_file(bprm->file);
	queue_work(asx_wq, &item->work);
}

static void asx_find_tracepoint(struct tracepoint *tp, void *priv)
{
	struct tracepoint **found = priv;

	if (!strcmp(tp->name, ASX_TRACEPOINT))
		*found = tp;
}

static int __init asx_init(void)
{
	struct asx_armed_item *armed;
	struct tracepoint *tp = NULL;
	u8 buf[ASX_LOAD_LEN];
	int ret;

	/* 1 the ordered workqueue */
	asx_wq = alloc_ordered_workqueue("anchorstamp_exec", WQ_FREEZABLE);
	if (!asx_wq)
		return -ENOMEM;

	/* 2 LOAD, before the probe is registered */
	get_random_bytes(asx_load_id, sizeof(asx_load_id));
	asx_seq = 0;
	asx_put_header(buf, ASX_KIND_LOAD);
	put_unaligned_le16(ASX_SHIM_VERSION, buf + ASX_OFF_SHIM_VERSION);
	put_unaligned_le64(ktime_get_boottime_ns(), buf + ASX_OFF_LOADED_NS);
	ret = asx_measure(buf, sizeof(buf));
	if (ret == -ENOENT) {
		pr_err("refused: no IMA policy rule for label %s\n", ASX_LABEL);
		goto destroy;
	}
	if (ret) {
		pr_err("refused: LOAD not measured (%d)\n", ret);
		goto destroy;
	}

	/*
	 * From here a failure leaves LOAD alone: nothing more is measured,
	 * the load ends without UNLOAD and covers nothing.
	 */
	/* 3 the ARMED item, so registration is never undone for memory */
	armed = kmalloc(sizeof(*armed), GFP_KERNEL);
	if (!armed) {
		ret = -ENOMEM;
		goto destroy;
	}
	INIT_WORK(&armed->work, asx_work_armed);

	/* 4 register the probe; the gate is closed */
	if (!asx_fault_flag(asx_fault_lookup, "tracepoint lookup"))
		for_each_kernel_tracepoint(asx_find_tracepoint, &tp);
	if (!tp) {
		pr_err("refused: tracepoint %s not found\n", ASX_TRACEPOINT);
		ret = -ENOENT;
		goto free;
	}
	ret = tracepoint_probe_register(tp, asx_probe, NULL);
	if (ret) {
		pr_err("refused: probe not registered (%d)\n", ret);
		goto free;
	}
	asx_tp = tp;

	/* 5 every firing from here runs the probe */
	tracepoint_synchronize_unregister();

	/* 6 armed_ns, then ARMED queued; 7 the gate opens */
	armed->armed_ns = ktime_get_boottime_ns();
	queue_work(asx_wq, &armed->work);
	/* Pairs with the probe's acquire: ARMED is queued before any item. */
	smp_store_release(&asx_armed, 1);
	pr_info("loaded, load_id %*phN\n", ASX_LOAD_ID_LEN, asx_load_id);
	return 0;

free:
	kfree(armed);
destroy:
	destroy_workqueue(asx_wq);
	return ret;
}

static void __exit asx_exit(void)
{
	struct asx_loss_state snap;
	u64 close_ns, unloaded_ns;
	u8 buf[ASX_UNLOAD_LEN];
	bool fail;

	/* 1-3 close_ns while the probe is live; unloaded_ns once it is not */
	close_ns = ktime_get_boottime_ns();
	tracepoint_probe_unregister(asx_tp, asx_probe, NULL);
	tracepoint_synchronize_unregister();
	unloaded_ns = ktime_get_boottime_ns();
	/* 4 every queued item is done */
	drain_workqueue(asx_wq);

	/*
	 * 5-7 UNLOAD states that every exec of this load is accounted for.
	 * A dead load, or a final LOST not measured, makes that untrue: no
	 * UNLOAD.
	 */
	if (asx_dead) {
		pr_warn("load is dead: no UNLOAD\n");
		goto destroy;
	}
	snap = asx_loss_take();
	if (snap.count) {
		fail = asx_fault_flag(asx_fault_final_lost, "final LOST measure");
		if (asx_emit_lost(&snap, fail)) {
			pr_warn("final LOST of %llu not measured; no UNLOAD\n",
				snap.count);
			goto destroy;
		}
	}
	asx_put_header(buf, ASX_KIND_UNLOAD);
	put_unaligned_le64(close_ns, buf + ASX_OFF_CLOSE_NS);
	put_unaligned_le64(unloaded_ns, buf + ASX_OFF_UNLOADED_NS);
	if (asx_measure(buf, sizeof(buf)))
		pr_warn("UNLOAD not measured\n");

destroy:
	destroy_workqueue(asx_wq);
	pr_info("unloaded, load_id %*phN\n", ASX_LOAD_ID_LEN, asx_load_id);
}

module_init(asx_init);
module_exit(asx_exit);

MODULE_DESCRIPTION("anchorstamp exec records measured by IMA; anchorstamp specification 0.4, layout 1, source profile K");
MODULE_LICENSE("Dual MIT/GPL");

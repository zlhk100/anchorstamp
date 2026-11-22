// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * anchorstamp_exec - kernel-side exec evidence anchored in the TPM.
 *
 * Every successful exec becomes one record, handed to IMA as critical
 * data under the label "anchorstamp". IMA appends the record to its
 * measurement list and extends the PCR its policy rule names. This module
 * keeps no log of its own, exports nothing and never talks to the TPM.
 *
 * Record format version 1: packed, every multi-byte integer little-endian,
 * written field by field.
 *
 *   header, every kind (29 bytes)
 *     0  4  magic    "ASX1"
 *     4  1  kind     bits 0-3: 1 EXEC, 2 LOAD, 3 LOST, 4 UNLOAD
 *                    bit 7: path truncated, bit 6: path unresolved (EXEC)
 *     5  8  seq      per load; LOAD is 0, +1 per measured record
 *    13 16  load_id  random per load
 *
 *   EXEC (83 + path_len): pid, tgid, ppid, old_pid, uid, euid (u32 each,
 *     initial namespaces), start_ns (u64), path_digest (first 20 bytes of
 *     SHA-256 over the full path), path_len (u16, at most 1024), path
 *   LOAD (39): shim_version (u16), loaded_ns (u64, boot time)
 *   LOST (37): count (u64), execs not recorded since the last record
 *   UNLOAD (29): header only
 *
 * Context: the probe runs on the exec path with preemption disabled, so it
 * only copies fields, takes a file reference and queues an item; at most
 * 1024 items wait, and an exec beyond that is counted as lost. An
 * ordered workqueue builds and measures the records one at a time, which
 * is what makes seq contiguous without a lock.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/atomic.h>
#include <linux/binfmts.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/ima.h>
#include <linux/limits.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/slab.h>
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
#define ASX_SHIM_VERSION	1

#define ASX_KIND_EXEC		1
#define ASX_KIND_LOAD		2
#define ASX_KIND_LOST		3
#define ASX_KIND_UNLOAD		4
#define ASX_PATH_TRUNCATED	0x80
#define ASX_PATH_UNRESOLVED	0x40

#define ASX_LOAD_ID_LEN		16
#define ASX_DIGEST_LEN		20
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
#define ASX_OFF_PATH_DIGEST	61
#define ASX_OFF_PATH_LEN	81
#define ASX_OFF_PATH		83
#define ASX_EXEC_MAX		(ASX_OFF_PATH + ASX_PATH_CAP)

/* LOAD offsets. */
#define ASX_OFF_SHIM_VERSION	29
#define ASX_OFF_LOADED_NS	31
#define ASX_LOAD_LEN		39

/* LOST offsets. */
#define ASX_OFF_COUNT		29
#define ASX_LOST_LEN		37

#define ASX_UNLOAD_LEN		ASX_HDR_LEN

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
};

/* Set by init before the probe is registered; cleared by nothing. */
static struct tracepoint *asx_tp;
/* Created first in init, destroyed last in exit. */
static struct workqueue_struct *asx_wq;
/* Written only by init, the worker and exit, never concurrently. */
static u64 asx_seq;
/* Execs not recorded since the last record: probe and worker. */
static atomic64_t asx_lost = ATOMIC64_INIT(0);
/* Items queued and not yet freed: the probe adds, the worker removes. */
static atomic_t asx_pending = ATOMIC_INIT(0);
/* Written once in init, before the probe is registered. */
static u8 asx_load_id[ASX_LOAD_ID_LEN];

static void asx_put_header(u8 *buf, u8 kind)
{
	memcpy(buf + ASX_OFF_MAGIC, "ASX1", 4);
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

static int asx_emit_lost(u64 count)
{
	u8 buf[ASX_LOST_LEN];

	asx_put_header(buf, ASX_KIND_LOST);
	put_unaligned_le64(count, buf + ASX_OFF_COUNT);
	return asx_measure(buf, sizeof(buf));
}

static int asx_emit_unload(void)
{
	u8 buf[ASX_UNLOAD_LEN];

	asx_put_header(buf, ASX_KIND_UNLOAD);
	return asx_measure(buf, sizeof(buf));
}

/*
 * First ASX_DIGEST_LEN bytes of SHA-256 over len bytes of path, with the
 * kernel library sha256(): no algorithm lookup, no allocation, no failure.
 */
static void asx_path_digest(const char *path, size_t len, u8 *out)
{
	u8 digest[SHA256_DIGEST_SIZE];

	sha256((const u8 *)path, len, digest);
	memcpy(out, digest, ASX_DIGEST_LEN);
}

/*
 * Build the EXEC record into rec, resolving the path through pathbuf
 * (PATH_MAX bytes). Returns the record length.
 */
static int asx_build_exec(const struct asx_item *item, u8 *rec,
			  char *pathbuf)
{
	u8 kind = ASX_KIND_EXEC;
	size_t len = 0;
	char *path;

	memset(rec + ASX_OFF_PATH_DIGEST, 0, ASX_DIGEST_LEN);
	path = d_path(&item->file->f_path, pathbuf, PATH_MAX);
	if (IS_ERR(path)) {
		kind |= ASX_PATH_UNRESOLVED;
	} else {
		len = strlen(path);
		asx_path_digest(path, len, rec + ASX_OFF_PATH_DIGEST);
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
	put_unaligned_le16(len, rec + ASX_OFF_PATH_LEN);
	return ASX_OFF_PATH + len;
}

static void asx_work(struct work_struct *work)
{
	struct asx_item *item = container_of(work, struct asx_item, work);
	char *pathbuf = NULL;
	u8 *rec = NULL;
	u64 n;
	int len;

	n = atomic64_xchg(&asx_lost, 0);
	if (n && asx_emit_lost(n)) {
		/* The loss and this exec are carried to the next LOST. */
		atomic64_add(n + 1, &asx_lost);
		goto out;
	}

	rec = kmalloc(ASX_EXEC_MAX, GFP_KERNEL);
	pathbuf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!rec || !pathbuf) {
		atomic64_inc(&asx_lost);
		goto out;
	}

	len = asx_build_exec(item, rec, pathbuf);
	fput(item->file);
	item->file = NULL;
	if (asx_measure(rec, len))
		atomic64_inc(&asx_lost);

out:
	if (item->file)
		fput(item->file);
	kfree(pathbuf);
	kfree(rec);
	kfree(item);
	atomic_dec(&asx_pending);
}

/*
 * sched_process_exec probe: preemption is disabled here. Copy what the
 * record needs, take a reference on the executable and queue the item.
 * Never sleeps and never fails the exec. At most ASX_PENDING_CAP items wait
 * in the queue; an exec beyond that, or one whose item cannot be allocated
 * without the emergency reserves, is counted as lost.
 */
static void asx_probe(void *data, struct task_struct *p, pid_t old_pid,
		      struct linux_binprm *bprm)
{
	const struct cred *cred;
	struct asx_item *item;

	if (atomic_inc_return(&asx_pending) > ASX_PENDING_CAP) {
		atomic_dec(&asx_pending);
		atomic64_inc(&asx_lost);
		return;
	}
	item = kmalloc(sizeof(*item), GFP_NOWAIT | __GFP_NOWARN);
	if (!item) {
		atomic_dec(&asx_pending);
		atomic64_inc(&asx_lost);
		return;
	}
	INIT_WORK(&item->work, asx_work);
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
	struct tracepoint *tp = NULL;
	u8 buf[ASX_LOAD_LEN];
	int ret;

	asx_wq = alloc_ordered_workqueue("anchorstamp_exec", 0);
	if (!asx_wq)
		return -ENOMEM;

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

	for_each_kernel_tracepoint(asx_find_tracepoint, &tp);
	if (!tp) {
		pr_err("refused: tracepoint %s not found\n", ASX_TRACEPOINT);
		ret = -ENOENT;
		goto unload;
	}
	ret = tracepoint_probe_register(tp, asx_probe, NULL);
	if (ret) {
		pr_err("refused: probe not registered (%d)\n", ret);
		goto unload;
	}
	asx_tp = tp;
	pr_info("loaded, load_id %*phN\n", ASX_LOAD_ID_LEN, asx_load_id);
	return 0;

unload:
	asx_emit_unload();
destroy:
	destroy_workqueue(asx_wq);
	return ret;
}

static void __exit asx_exit(void)
{
	u64 n;

	tracepoint_probe_unregister(asx_tp, asx_probe, NULL);
	tracepoint_synchronize_unregister();
	drain_workqueue(asx_wq);

	/*
	 * UNLOAD states that every exec of this load is accounted for. If
	 * the final LOST was not measured that is not true, so no UNLOAD.
	 */
	n = atomic64_xchg(&asx_lost, 0);
	if (n && asx_emit_lost(n))
		pr_warn("final LOST of %llu not measured; no UNLOAD\n", n);
	else if (asx_emit_unload())
		pr_warn("UNLOAD not measured\n");
	destroy_workqueue(asx_wq);
	pr_info("unloaded, load_id %*phN\n", ASX_LOAD_ID_LEN, asx_load_id);
}

module_init(asx_init);
module_exit(asx_exit);

MODULE_DESCRIPTION("anchorstamp: exec records measured by IMA");
MODULE_LICENSE("Dual MIT/GPL");

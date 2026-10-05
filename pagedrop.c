/* 
 * pagedrop - dump all executable pages of packed processes.
 * 
 * Copyright (C) 2021  Matteo Giordano
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define pr_fmt(fmt) "pagedrop: " fmt

#if defined(PB_ARCH_ARM64) || defined(CONFIG_ARM64)
#define PB_ARM64 1
#elif defined(PB_ARCH_X86_64) || defined(CONFIG_X86_64)
#define PB_X86_64 1
#endif

#include <linux/ftrace.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/kprobes.h>
#include <linux/init.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/fcntl.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/limits.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/mmap_lock.h>
#include <linux/module.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>

#include <asm/traps.h>
#if defined(PB_X86_64)
#include <asm/trap_pf.h>
#elif defined(PB_ARM64)
#include <asm/esr.h>
#endif

#include <uapi/asm-generic/mman-common.h>

#ifndef MREMAP_DONTUNMAP
#define MREMAP_DONTUNMAP 4
#endif

#if !defined(PB_X86_64) && !defined(PB_ARM64)
#error Currently only x86_64 and arm64 are supported
#endif

#if defined(PB_ARM64) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
#error arm64 pagedrop requires Linux >= 5.10
#endif

#if defined(PB_ARM64)
#define PB_HOOK_KPROBE 1
#elif defined(PB_X86_64)
#define PB_HOOK_FTRACE 1
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
#define mmap_read_lock_killable(mm) down_read_killable(&(mm)->mmap_sem)
#define mmap_read_unlock(mm) up_read(&(mm)->mmap_sem)
#endif

static char *path;
module_param(path, charp, 0000);
MODULE_PARM_DESC(path, "Path/Name of the target process");

static int exact;
module_param(exact, int, 0000);
MODULE_PARM_DESC(exact, "Match path= exactly (default is a substring)");

static char *data;
module_param(data, charp, 0000);
MODULE_PARM_DESC(data, "Armed data range start-end, hex, for the read trace");

static LIST_HEAD(marea_list);
static DEFINE_MUTEX(marea_lock);

/*
 * Serializes a target's mprotect, pkey_mprotect, mmap, munmap and mremap,
 * from the record updates before the syscall to the settling after it. A
 * failed mprotect puts back the records it changed, and that is only right
 * if no other of these calls changed the same pages in the meantime. Taken
 * before any mm lock and before marea_lock, never under them. Fault paths
 * do not take it: they run with no mm lock held, and only restore pages
 * their records already allow.
 */
static DEFINE_MUTEX(pb_vm_lock);
static unsigned long epoch_counter;

/*
 * own: the tgid has records of its own, and a fault must not fall back to
 * the parent's. It is false only for a forked child whose parent has not
 * finished copying its records into it. It only ever turns on.
 */
struct pb_tgid {
	struct list_head list;
	pid_t tgid;
	bool own;
};

static LIST_HEAD(tgid_list);
static DEFINE_SPINLOCK(tgid_lock);

struct marea {
	struct list_head list;
	unsigned long addr;
	unsigned long prot;
	pid_t tgid;
	unsigned long epoch;
	bool restored;
};

static unsigned long data_lo, data_hi;
static int data_on;
static LIST_HEAD(data_seen);
static LIST_HEAD(data_armed);
static DEFINE_MUTEX(pb_log_lock);

/*
 * Module pinning for the unload hazard.
 *
 * data= works by making a page PROT_NONE, and only this module's own fault
 * handler, running inside the target process, can turn it back. If the
 * module is removed while such a page exists, the target keeps a page it
 * can no longer read. fh_exit cannot fix that, because module_exit runs in
 * the removing process and mprotect only affects the caller.
 *
 * While any data_armed record still describes a page that is PROT_NONE, a
 * reference to this module is held, so rmmod returns -EBUSY instead of
 * stranding the target. The state is a per-record flag rather than a
 * counter, because a counter leaks in two opposite directions: too high
 * and the module is never removable, too low and the stranding bug
 * returns silently.
 *
 * The reference is dropped from a work item, never from a hook, so
 * module_exit cannot free this code while a handler is still running it.
 *
 * pb_pin_held and pb_pin_scheduled are touched under marea_lock.
 */
static bool pb_pin_held;
static bool pb_pin_scheduled;
static void pb_pin_recheck(struct work_struct *work);
static DECLARE_WORK(pb_pin_work, pb_pin_recheck);

static bool pb_pin_needed_locked(void)
{
	struct marea *entry;

	list_for_each_entry(entry, &data_armed, list) {
		if (!entry->restored)
			return true;
	}
	return false;
}

static void pb_pin_update_locked(void)
{
	if (pb_pin_needed_locked()) {
		if (!pb_pin_held && try_module_get(THIS_MODULE))
			pb_pin_held = true;
		return;
	}
	if (pb_pin_held && !pb_pin_scheduled) {
		pb_pin_scheduled = true;
		schedule_work(&pb_pin_work);
	}
}

static void pb_pin_recheck(struct work_struct *work)
{
	bool release = false;

	mutex_lock(&marea_lock);
	pb_pin_scheduled = false;
	if (!pb_pin_needed_locked()) {
		if (pb_pin_held) {
			pb_pin_held = false;
			release = true;
		}
	}
	mutex_unlock(&marea_lock);
	if (release)
		module_put(THIS_MODULE);
}


static bool pb_name_matches(const char *name);

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
#define pb_access_ok(addr, size) access_ok(VERIFY_READ, (addr), (size))
#else
#define pb_access_ok(addr, size) access_ok((addr), (size))
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
static unsigned long lookup_name(const char *name)
{
	struct kprobe kp = {
		.symbol_name = name
	};
	unsigned long retval;

	if (register_kprobe(&kp) < 0)
		return 0;
	retval = (unsigned long)kp.addr;
	unregister_kprobe(&kp);
	return retval;
}
#else
static unsigned long lookup_name(const char *name)
{
	return kallsyms_lookup_name(name);
}
#endif

#if defined(PB_HOOK_FTRACE) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
#define ftrace_regs pt_regs

static __always_inline struct pt_regs *ftrace_get_regs(struct ftrace_regs *fregs)
{
	return fregs;
}
#endif

#define USE_FENTRY_OFFSET 0

#if defined(PB_HOOK_FTRACE)
struct ftrace_hook {
	const char *name;
	void *function;
	void *original;
	unsigned long address;
	struct ftrace_ops ops;
};
#endif

static bool pb_tgid_has(pid_t tgid)
{
	struct pb_tgid *t;
	bool found = false;

	if (tgid <= 0)
		return false;
	spin_lock(&tgid_lock);
	list_for_each_entry(t, &tgid_list, list) {
		if (t->tgid == tgid) {
			found = true;
			break;
		}
	}
	spin_unlock(&tgid_lock);
	return found;
}

/* Returns true if the tgid was not listed before. */
static bool pb_tgid_add(pid_t tgid, bool own)
{
	struct pb_tgid *t, *n;

	if (tgid <= 0)
		return false;
	n = kmalloc(sizeof(*n), GFP_KERNEL);
	if (!n)
		return false;
	n->tgid = tgid;
	n->own = own;
	INIT_LIST_HEAD(&n->list);
	spin_lock(&tgid_lock);
	list_for_each_entry(t, &tgid_list, list) {
		if (t->tgid == tgid) {
			if (own)
				t->own = true;
			spin_unlock(&tgid_lock);
			kfree(n);
			return false;
		}
	}
	list_add(&n->list, &tgid_list);
	spin_unlock(&tgid_lock);
	return true;
}

static bool pb_tgid_own(pid_t tgid)
{
	struct pb_tgid *t;
	bool own = false;

	spin_lock(&tgid_lock);
	list_for_each_entry(t, &tgid_list, list) {
		if (t->tgid == tgid) {
			own = t->own;
			break;
		}
	}
	spin_unlock(&tgid_lock);
	return own;
}

/* Returns the previous value, false if the tgid is not listed. */
static bool pb_tgid_set_own(pid_t tgid, bool own)
{
	struct pb_tgid *t;
	bool was = false;

	spin_lock(&tgid_lock);
	list_for_each_entry(t, &tgid_list, list) {
		if (t->tgid == tgid) {
			was = t->own;
			t->own = own;
			break;
		}
	}
	spin_unlock(&tgid_lock);
	return was;
}

static void pb_tgid_del(pid_t tgid)
{
	struct pb_tgid *t, *tmp;

	spin_lock(&tgid_lock);
	list_for_each_entry_safe(t, tmp, &tgid_list, list) {
		if (t->tgid != tgid)
			continue;
		list_del(&t->list);
		kfree(t);
	}
	spin_unlock(&tgid_lock);
}

static void pb_tgid_clear(void)
{
	struct pb_tgid *t, *tmp;

	spin_lock(&tgid_lock);
	list_for_each_entry_safe(t, tmp, &tgid_list, list) {
		list_del(&t->list);
		kfree(t);
	}
	spin_unlock(&tgid_lock);
}

static pid_t pb_parent_tgid(void)
{
	struct task_struct *parent;
	pid_t tgid = 0;

	rcu_read_lock();
	parent = rcu_dereference(current->real_parent);
	if (parent)
		tgid = parent->tgid;
	rcu_read_unlock();
	return tgid;
}

static bool pb_parent_tracked(void)
{
	pid_t tgid = pb_parent_tgid();

	return tgid > 0 && pb_tgid_has(tgid);
}

static bool pb_is_target(void)
{
	pid_t tgid;
	bool parent;

	if (!path || !path[0])
		return false;
	tgid = current->tgid;
	if (pb_tgid_has(tgid))
		return true;
	/*
	 * A child of a tracked process does not own its records until the
	 * parent has copied them in pb_note_child. A fork child keeps the
	 * parent's comm, so the name match alone does not make it own them.
	 */
	parent = pb_parent_tracked();
	if (parent || pb_name_matches(current->comm)) {
		pb_tgid_add(tgid, !parent);
		return true;
	}
	return false;
}

static bool prot_has_wx(unsigned long prot)
{
	return (prot & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC);
}

static bool prot_has_x_only(unsigned long prot)
{
	return (prot & PROT_EXEC) && !(prot & PROT_WRITE);
}

static unsigned long pb_arg(const struct pt_regs *regs, int n)
{
#if defined(PB_ARM64)
	if (n < 0 || n > 5)
		return 0;
	return regs->regs[n];
#else
	switch (n) {
	case 0:
		return regs->di;
	case 1:
		return regs->si;
	case 2:
		return regs->dx;
	case 3:
		return regs->r10;
	case 4:
		return regs->r8;
	case 5:
		return regs->r9;
	default:
		return 0;
	}
#endif
}

static void pb_set_arg(struct pt_regs *regs, int n, unsigned long val)
{
#if defined(PB_ARM64)
	if (n >= 0 && n <= 5)
		regs->regs[n] = val;
#else
	switch (n) {
	case 0:
		regs->di = val;
		break;
	case 1:
		regs->si = val;
		break;
	case 2:
		regs->dx = val;
		break;
	case 3:
		regs->r10 = val;
		break;
	default:
		break;
	}
#endif
}

static int pb_page_count(unsigned long len)
{
	if (!len)
		return 0;
	return (len + PAGE_SIZE - 1) / PAGE_SIZE;
}

static struct marea *search_page(pid_t tgid, unsigned long addr_given)
{
	struct marea *result;

	list_for_each_entry(result, &marea_list, list) {
		unsigned long start_addr = result->addr;
		unsigned long end_addr = start_addr + PAGE_SIZE - 1;

		if (result->tgid != tgid)
			continue;
		if (addr_given >= start_addr && addr_given <= end_addr)
			return result;
	}
	return NULL;
}

static struct marea *new_marea(pid_t tgid, unsigned long addr, unsigned long prot)
{
	struct marea *new_m;

	new_m = kmalloc(sizeof(*new_m), GFP_KERNEL);
	if (!new_m)
		return NULL;
	new_m->addr = addr;
	new_m->prot = prot;
	new_m->tgid = tgid;
	new_m->epoch = 0;
	new_m->restored = false;
	INIT_LIST_HEAD(&new_m->list);
	return new_m;
}

static void pb_free_list(struct list_head *head)
{
	struct marea *entry, *tmp;

	list_for_each_entry_safe(entry, tmp, head, list) {
		list_del(&entry->list);
		kfree(entry);
	}
}

static void track_pages(unsigned long addr, int n_pages, unsigned long prot)
{
	pid_t tgid = current->tgid;
	int i;

	mutex_lock(&marea_lock);
	for (i = 0; i < n_pages; i++) {
		struct marea *entry;
		struct marea *fresh;
		unsigned long page = addr + (i * PAGE_SIZE);
		int replaced = 0;

		list_for_each_entry(entry, &marea_list, list) {
			if (entry->tgid != tgid || entry->addr != page)
				continue;
			fresh = new_marea(tgid, page, prot);
			if (!fresh)
				goto out;
			fresh->epoch = entry->epoch;
			list_replace(&entry->list, &fresh->list);
			kfree(entry);
			replaced = 1;
			break;
		}
		if (replaced)
			continue;
		fresh = new_marea(tgid, page, prot);
		if (!fresh)
			break;
		list_add(&fresh->list, &marea_list);
	}
out:
	mutex_unlock(&marea_lock);
}

static void untrack_pages(unsigned long addr, int n_pages)
{
	int i;

	mutex_lock(&marea_lock);
	for (i = 0; i < n_pages; i++) {
		struct marea *entry, *tmp;
		unsigned long page = addr + (i * PAGE_SIZE);

		list_for_each_entry_safe(entry, tmp, &marea_list, list) {
			if (entry->tgid != current->tgid || entry->addr != page)
				continue;
			list_del(&entry->list);
			kfree(entry);
		}
	}
	mutex_unlock(&marea_lock);
}

static void clear_tracked_locked(void)
{
	struct marea *entry, *tmp;

	list_for_each_entry_safe(entry, tmp, &marea_list, list) {
		list_del(&entry->list);
		kfree(entry);
	}
}

static void clear_tracked(void)
{
	mutex_lock(&marea_lock);
	clear_tracked_locked();
	mutex_unlock(&marea_lock);
}

/*
 * Like pb_handle_data, a fork child that the parent has not copied into
 * yet uses the parent's record. Its pages are the parent's, W^X write
 * protection included, so a store to an RWX page in that window is a fault
 * the module caused. Read own before the child's records, for the same
 * reason as there.
 */
static bool pb_take_page(unsigned long addr, unsigned long *page_addr, unsigned long *prot)
{
	struct marea *page;
	bool found = false;
	bool use_parent = !pb_tgid_own(current->tgid);
	pid_t parent = pb_parent_tgid();

	mutex_lock(&marea_lock);
	page = search_page(current->tgid, addr);
	if (!page && use_parent && parent > 0 && parent != current->tgid)
		page = search_page(parent, addr);
	if (page) {
		*page_addr = page->addr;
		*prot = page->prot;
		found = true;
	}
	mutex_unlock(&marea_lock);
	return found;
}

static void pb_log_line(const char *path, const char *line)
{
	struct file *f;
	loff_t pos = 0;

	f = filp_open(path, O_CREAT | O_WRONLY | O_APPEND | O_LARGEFILE, 0644);
	if (IS_ERR(f))
		return;
	kernel_write(f, line, strlen(line), &pos);
	filp_close(f, NULL);
}

static void pb_note_epoch(pid_t tgid, unsigned long page, unsigned long epoch)
{
	struct marea *entry;

	mutex_lock(&marea_lock);
	entry = search_page(tgid, page);
	if (entry)
		entry->epoch = epoch;
	mutex_unlock(&marea_lock);
}

/*
 * The program sets comm (prctl, the exec name), and it may hold spaces or
 * a newline. The index is one record per line, split on whitespace, so a
 * raw comm could shift the fields or forge a line. Replace whitespace and
 * control bytes, and write "-" for an empty name.
 */
static void pb_index_comm(char *out)
{
	size_t i;

	if (!out[0]) {
		strcpy(out, "-");
		return;
	}
	for (i = 0; out[i]; i++) {
		unsigned char c = out[i];

		if (c <= ' ' || c == 0x7f)
			out[i] = '_';
	}
}

static int dump_to_file(unsigned long user_addr, size_t size, const char *why,
			 unsigned long *ep_out)
{
	char comm[TASK_COMM_LEN];
	struct file *dest;
	char file_path[64];
	char line[160];
	void *kbuf;
	loff_t pos = 0;
	ssize_t written;
	unsigned long left;
	unsigned long ep;
	pid_t tgid = current->tgid;

	if (!size || !pb_access_ok((void __user *)user_addr, size))
		return -EFAULT;

	kbuf = kvmalloc(size, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	left = copy_from_user(kbuf, (void __user *)user_addr, size);
	if (left) {
		pr_warn("copy_from_user %lx left %lu\n", user_addr, left);
		kvfree(kbuf);
		return -EFAULT;
	}

	mutex_lock(&pb_log_lock);
	ep = epoch_counter++;
	mutex_unlock(&pb_log_lock);

	snprintf(file_path, sizeof(file_path), "/tmp/%lx_%lu", user_addr, ep);

	dest = filp_open(file_path, O_CREAT | O_WRONLY | O_TRUNC | O_LARGEFILE, 0644);
	if (IS_ERR(dest)) {
		pr_warn("filp_open %s: %ld\n", file_path, PTR_ERR(dest));
		kvfree(kbuf);
		return PTR_ERR(dest);
	}

	written = kernel_write(dest, kbuf, size, &pos);
	if (written < 0 || (size_t)written != size)
		pr_warn("kernel_write %s: %zd\n", file_path, written);
	filp_close(dest, NULL);
	kvfree(kbuf);
	if (written < 0 || (size_t)written != size)
		return written < 0 ? written : -EIO;
	pb_note_epoch(tgid, user_addr, ep);
	get_task_comm(comm, current);
	pb_index_comm(comm);
	snprintf(line, sizeof(line), "%d %s %lx %lu %s\n", tgid,
		 comm, user_addr, ep, why);
	pb_log_line("/tmp/pagedrop.index", line);
	if (ep_out)
		*ep_out = ep;
	return 0;
}

static void dump_pages(unsigned long addr, int n_pages, const char *why)
{
	int i;

	for (i = 0; i < n_pages; i++)
		dump_to_file(addr + (i * PAGE_SIZE), PAGE_SIZE, why, NULL);
}

#if defined(PB_HOOK_FTRACE)
static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
	hook->address = lookup_name(hook->name);
	if (!hook->address) {
		pr_err("unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}

#if USE_FENTRY_OFFSET
	*((unsigned long *)hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
	*((unsigned long *)hook->original) = hook->address;
#endif
	return 0;
}

static void pb_set_ip(struct ftrace_regs *fregs, unsigned long ip)
{
#if defined(ftrace_regs_set_instruction_pointer)
	ftrace_regs_set_instruction_pointer(fregs, ip);
#else
	struct pt_regs *regs = ftrace_get_regs(fregs);

	if (regs)
		instruction_pointer_set(regs, ip);
#endif
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

#if USE_FENTRY_OFFSET
	pb_set_ip(fregs, (unsigned long)hook->function);
#else
	if (!within_module(parent_ip, THIS_MODULE))
		pb_set_ip(fregs, (unsigned long)hook->function);
#endif
}

static unsigned long pb_ftrace_flags(void)
{
	unsigned long flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
	flags |= FTRACE_OPS_FL_RECURSION_SAFE;
#endif
	return flags;
}

static int fh_install_hook(struct ftrace_hook *hook)
{
	int err;

	err = fh_resolve_hook_address(hook);
	if (err)
		return err;

	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = pb_ftrace_flags();

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (err) {
		pr_err("ftrace_set_filter_ip(%s) failed: %d\n", hook->name, err);
		return err;
	}

	err = register_ftrace_function(&hook->ops);
	if (err) {
		pr_err("register_ftrace_function(%s) failed: %d\n", hook->name, err);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return err;
	}

	pr_info("hooked %s @ %lx\n", hook->name, hook->address);
	return 0;
}

static void fh_remove_hook(struct ftrace_hook *hook)
{
	int err;

	err = unregister_ftrace_function(&hook->ops);
	if (err)
		pr_err("unregister_ftrace_function(%s) failed: %d\n", hook->name, err);

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if (err)
		pr_err("ftrace_set_filter_ip(%s) remove failed: %d\n", hook->name, err);
}

static int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
	int err;
	size_t i;

	for (i = 0; i < count; i++) {
		err = fh_install_hook(&hooks[i]);
		if (err)
			goto error;
	}
	return 0;

error:
	while (i != 0)
		fh_remove_hook(&hooks[--i]);
	return err;
}

static void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++)
		fh_remove_hook(&hooks[i]);
}
#endif

#if defined(PB_ARM64) || (defined(PB_X86_64) && LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0))
#define PTREGS_SYSCALL_STUBS 1
#endif

#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

static long pb_mprotect(unsigned long addr, unsigned long len, unsigned long prot);

/*
 * Restore before forgetting, but never while holding marea_lock.
 *
 * pb_mprotect reaches the real mprotect, which takes mmap_write_lock. No
 * path takes marea_lock with an mm lock held: vm_mmap_pgoff takes and
 * releases mmap_write_lock itself, before the hook drops records, and the
 * fault paths release theirs before the signal. Keeping marea_lock out of
 * the mm lock is a lock-order rule, not the fix for a deadlock that was
 * shown. So: collect the pages under the lock, restore with no lock held,
 * then drop the records.
 *
 * The records outlive the restore, so a reader that faults meanwhile finds
 * one and is handled. A restore that lands on a page a reader already fixed
 * is the same protection, so it is a no-op.
 */
/*
 * The restore has to run with no lock held, or it deadlocks against the
 * mmap hook (models/lock-order). That leaves a window in which the page can
 * be re-armed with a different protection, and a restore that trusts the
 * value it read earlier then installs the old one, so a page the record
 * calls read-only comes back writable. Re-read the record under the lock
 * and restore only if it still says what we read. If the record is gone, the
 * page was already handled and there is nothing to do.
 */
static bool pb_armed_unchanged(pid_t tgid, unsigned long page, unsigned long prot)
{
	struct marea *entry;
	bool same = false;

	mutex_lock(&marea_lock);
	list_for_each_entry(entry, &data_armed, list) {
		if (entry->tgid != tgid || entry->addr != page)
			continue;
		same = (entry->prot == prot);
		break;
	}
	mutex_unlock(&marea_lock);
	return same;
}

static void pb_disarm_range(pid_t tgid, unsigned long addr, unsigned long len)
{
	unsigned long start;
	unsigned long end;
	unsigned long prot;
	struct marea *entry, *tmp;
	int i;
	int n;

	if (!len)
		return;
	start = addr & PAGE_MASK;
	end = (addr + len + PAGE_SIZE - 1) & PAGE_MASK;
	n = pb_page_count(len);
	for (i = 0; i < n; i++) {
		unsigned long page = start + (unsigned long)i * PAGE_SIZE;
		unsigned long saved = 0;
		bool found = false;

		mutex_lock(&marea_lock);
		list_for_each_entry(entry, &data_armed, list) {
			if (entry->tgid != tgid || entry->addr != page)
				continue;
			saved = entry->prot;
			found = true;
			break;
		}
		mutex_unlock(&marea_lock);
		if (!found)
			continue;
		prot = saved;
		if (pb_armed_unchanged(tgid, page, prot))
			pb_mprotect(page, PAGE_SIZE, prot ? prot : PROT_READ);
	}	mutex_lock(&marea_lock);
	list_for_each_entry_safe(entry, tmp, &data_seen, list) {
		if (entry->tgid != tgid || entry->addr < start || entry->addr >= end)
			continue;
		list_del(&entry->list);
		kfree(entry);
	}
	mutex_unlock(&marea_lock);
	mutex_lock(&marea_lock);
	list_for_each_entry_safe(entry, tmp, &data_armed, list) {
		if (entry->tgid != tgid || entry->addr < start || entry->addr >= end)
			continue;
		entry->restored = true;
		list_del(&entry->list);
		kfree(entry);
	}
	pb_pin_update_locked();
	mutex_unlock(&marea_lock);
}

static void pb_handle_protect(struct pt_regs *regs)
{
	unsigned long addr = pb_arg(regs, 0);
	unsigned long len = pb_arg(regs, 1);
	unsigned long prot = pb_arg(regs, 2);
	int n_pages = pb_page_count(len);

	pb_disarm_range(current->tgid, addr, len);
	if (prot_has_wx(prot)) {
		track_pages(addr, n_pages, prot);
		pb_set_arg(regs, 2, prot & ~PROT_WRITE);
	} else if (prot_has_x_only(prot)) {
		track_pages(addr, n_pages, prot);
		dump_pages(addr, n_pages, "mprotect");
	} else {
		untrack_pages(addr, n_pages);
	}
}

static asmlinkage long (*real_sys_mprotect)(struct pt_regs *regs);

static long pb_mprotect(unsigned long addr, unsigned long len, unsigned long prot)
{
	struct pt_regs regs;

	if (!real_sys_mprotect)
		return -EINVAL;
	memset(&regs, 0, sizeof(regs));
	pb_set_arg(&regs, 0, addr);
	pb_set_arg(&regs, 1, len);
	pb_set_arg(&regs, 2, prot);
	return real_sys_mprotect(&regs);
}

/*
 * True when the access that faulted is already legal, which means a racing
 * thread restored or remapped the page while this fault was in flight. The
 * fault must then be swallowed, not turned into a signal.
 */
static bool pb_page_satisfies(unsigned long addr, bool want_write)
{
	struct vm_area_struct *vma;
	bool ok = false;

	if (!current->mm)
		return false;
	if (mmap_read_lock_killable(current->mm))
		return false;
	vma = find_vma(current->mm, addr);
	if (vma && vma->vm_start <= addr &&
	    (vma->vm_flags & (want_write ? VM_WRITE : VM_READ)))
		ok = true;
	mmap_read_unlock(current->mm);
	return ok;
}

static bool pb_can_arm(unsigned long addr, unsigned long *prot_out)
{
	struct vm_area_struct *vma;
	bool ok = false;

	if (!current->mm)
		return false;
	if (mmap_read_lock_killable(current->mm))
		return false;
	vma = find_vma(current->mm, addr);
	if (vma && vma->vm_start <= addr && !(vma->vm_flags & VM_EXEC)) {
		unsigned long prot = 0;

		if (vma->vm_flags & VM_READ)
			prot |= PROT_READ;
		if (vma->vm_flags & VM_WRITE)
			prot |= PROT_WRITE;
		if (prot) {
			*prot_out = prot;
			ok = true;
		}
	}
	mmap_read_unlock(current->mm);
	return ok;
}

static void pb_drop_tgid_list(struct list_head *head, pid_t tgid)
{
	struct marea *entry, *tmp;

	list_for_each_entry_safe(entry, tmp, head, list) {
		if (entry->tgid != tgid)
			continue;
		list_del(&entry->list);
		kfree(entry);
	}
}

static void pb_drop_data_state(pid_t tgid)
{
	struct marea *entry, *tmp;

	mutex_lock(&marea_lock);
	pb_drop_tgid_list(&data_seen, tgid);
	list_for_each_entry_safe(entry, tmp, &data_armed, list) {
		if (entry->tgid != tgid)
			continue;
		entry->restored = true;
		list_del(&entry->list);
		kfree(entry);
	}
	pb_pin_update_locked();
	mutex_unlock(&marea_lock);
}

static void pb_drop_marea(pid_t tgid)
{
	mutex_lock(&marea_lock);
	pb_drop_tgid_list(&marea_list, tgid);
	mutex_unlock(&marea_lock);
}

static void pb_drop_user_range(pid_t tgid, unsigned long addr, unsigned long len)
{
	struct marea *entry, *tmp;
	unsigned long start;
	unsigned long end;

	if (!len)
		return;
	start = addr & PAGE_MASK;
	end = (addr + len + PAGE_SIZE - 1) & PAGE_MASK;
	if (end < start)
		end = ~0UL;
	mutex_lock(&marea_lock);
	list_for_each_entry_safe(entry, tmp, &data_armed, list) {
		if (entry->tgid != tgid || entry->addr < start || entry->addr >= end)
			continue;
		entry->restored = true;
		list_del(&entry->list);
		kfree(entry);
	}
	pb_pin_update_locked();
	list_for_each_entry_safe(entry, tmp, &data_seen, list) {
		if (entry->tgid != tgid || entry->addr < start || entry->addr >= end)
			continue;
		list_del(&entry->list);
		kfree(entry);
	}
	list_for_each_entry_safe(entry, tmp, &marea_list, list) {
		if (entry->tgid != tgid || entry->addr < start || entry->addr >= end)
			continue;
		list_del(&entry->list);
		kfree(entry);
	}
	mutex_unlock(&marea_lock);
}

static bool pb_armed_claim(pid_t tgid, unsigned long page, unsigned long prot)
{
	struct marea *seen;

	mutex_lock(&marea_lock);
	list_for_each_entry(seen, &data_armed, list) {
		if (seen->tgid == tgid && seen->addr == page) {
			mutex_unlock(&marea_lock);
			return false;
		}
	}
	seen = new_marea(tgid, page, prot);
	if (seen)
		list_add(&seen->list, &data_armed);
	mutex_unlock(&marea_lock);
	return seen != NULL;
}

static void pb_armed_unclaim(pid_t tgid, unsigned long page)
{
	struct marea *seen, *tmp;

	mutex_lock(&marea_lock);
	list_for_each_entry_safe(seen, tmp, &data_armed, list) {
		if (seen->tgid != tgid || seen->addr != page)
			continue;
		list_del(&seen->list);
		kfree(seen);
		break;
	}
	pb_pin_update_locked();
	mutex_unlock(&marea_lock);
}

static void pb_arm_range(void)
{
	unsigned long addr;
	pid_t tgid = current->tgid;

	if (!data_on || data_hi <= data_lo)
		return;
	for (addr = data_lo; addr < data_hi; addr += PAGE_SIZE) {
		unsigned long prot = 0;

		if (!pb_can_arm(addr, &prot))
			continue;
		/*
		 * Record before PROT_NONE. The other way round leaves a
		 * window where the page faults but no record exists, and
		 * the reader then takes a real SIGSEGV.
		 */
		if (!pb_armed_claim(tgid, addr, prot))
			continue;
		if (pb_mprotect(addr, PAGE_SIZE, PROT_NONE))
			pb_armed_unclaim(tgid, addr);
	}
}

static void pb_try_arm(void)
{
	if (!data_on)
		return;
	pb_arm_range();
}

static void pb_read_armed(unsigned long addr, unsigned long len)
{
	int n_pages = pb_page_count(len);
	int i;

	addr &= PAGE_MASK;
	for (i = 0; i < n_pages; i++) {
		unsigned long page = addr + (unsigned long)i * PAGE_SIZE;
		struct marea *seen;
		unsigned long prot = 0;
		bool armed = false;

		mutex_lock(&marea_lock);
		list_for_each_entry(seen, &data_armed, list) {
			if (seen->tgid != current->tgid || seen->addr != page)
				continue;
			prot = seen->prot;
			armed = true;
			break;
		}
		mutex_unlock(&marea_lock);
		if (!armed)
			continue;
		if (!(prot & PROT_READ))
			prot |= PROT_READ;
		pb_mprotect(page, PAGE_SIZE, prot);
	}
}

/*
 * [start, end) of the pages an mprotect of len bytes at addr covers,
 * computed as do_mprotect_pkey does. A length that wraps, which the kernel
 * rejects with -ENOMEM, gives end == ~0UL. pb_page_count returns an int
 * and would truncate a huge length.
 */
static void pb_protect_range(unsigned long addr, unsigned long len,
			     unsigned long *start, unsigned long *end)
{
	unsigned long alen = (len + PAGE_SIZE - 1) & PAGE_MASK;

	*start = addr & PAGE_MASK;
	*end = *start + alen;
	if (len && (!alen || *end <= *start))
		*end = ~0UL;
}

/* Copy this tgid's tracked records in [start, end) to snap. */
static void pb_snapshot_tracked(unsigned long start, unsigned long end,
				struct list_head *snap)
{
	struct marea *entry, *copy;
	pid_t tgid = current->tgid;

	mutex_lock(&marea_lock);
	list_for_each_entry(entry, &marea_list, list) {
		if (entry->tgid != tgid || entry->addr < start || entry->addr >= end)
			continue;
		copy = new_marea(tgid, entry->addr, entry->prot);
		if (!copy)
			continue;
		copy->epoch = entry->epoch;
		list_add_tail(&copy->list, snap);
	}
	mutex_unlock(&marea_lock);
}

/* A piece of [start, end) with one protection; prot is -1 for a hole. */
struct pb_seg {
	struct list_head list;
	unsigned long start;
	unsigned long end;
	long prot;
};

static long pb_vma_prot(struct vm_area_struct *vma)
{
	long prot = 0;

	if (vma->vm_flags & VM_READ)
		prot |= PROT_READ;
	if (vma->vm_flags & VM_WRITE)
		prot |= PROT_WRITE;
	if (vma->vm_flags & VM_EXEC)
		prot |= PROT_EXEC;
	return prot;
}

static bool pb_seg_add(struct list_head *segs, unsigned long start,
		       unsigned long end, long prot)
{
	struct pb_seg *seg = kmalloc(sizeof(*seg), GFP_KERNEL);

	if (!seg)
		return false;
	seg->start = start;
	seg->end = end;
	seg->prot = prot;
	list_add_tail(&seg->list, segs);
	return true;
}

static void pb_seg_free(struct list_head *segs)
{
	struct pb_seg *seg, *tmp;

	list_for_each_entry_safe(seg, tmp, segs, list) {
		list_del(&seg->list);
		kfree(seg);
	}
}

/*
 * Record the protection of every piece of [start, end), holes included,
 * as it is right before the syscall. Returns false if that could not be
 * done; the caller then treats a failure as having changed nothing.
 */
static bool pb_seg_snapshot(unsigned long start, unsigned long end,
			    struct list_head *segs)
{
	struct vm_area_struct *vma;
	unsigned long at = start;
	bool ok = true;

	if (!current->mm || mmap_read_lock_killable(current->mm))
		return false;
	while (ok && at < end) {
		vma = find_vma(current->mm, at);
		if (!vma || vma->vm_start >= end) {
			ok = pb_seg_add(segs, at, end, -1);
			break;
		}
		if (vma->vm_start > at) {
			ok = pb_seg_add(segs, at, vma->vm_start, -1);
			at = vma->vm_start;
			continue;
		}
		ok = pb_seg_add(segs, at, min(vma->vm_end, end), pb_vma_prot(vma));
		at = min(vma->vm_end, end);
	}
	mmap_read_unlock(current->mm);
	if (!ok)
		pb_seg_free(segs);
	return ok;
}

/* Whether all of [start, end) still has protection prot (-1: unmapped). */
static bool pb_seg_same(unsigned long start, unsigned long end, long prot)
{
	struct vm_area_struct *vma;
	unsigned long at = start;

	while (at < end) {
		vma = find_vma(current->mm, at);
		if (!vma || vma->vm_start >= end)
			return prot == -1;
		if (vma->vm_start > at) {
			if (prot != -1)
				return false;
			at = vma->vm_start;
			continue;
		}
		if (prot != pb_vma_prot(vma))
			return false;
		at = min(vma->vm_end, end);
	}
	return true;
}

/*
 * Whether vma has the protection mprotect would give it for prot. With
 * READ_IMPLIES_EXEC the kernel adds PROT_EXEC to a readable request, per
 * VMA, where VM_MAYEXEC allows it.
 */
static bool pb_vma_has(struct vm_area_struct *vma, unsigned long prot)
{
	long want = prot & (PROT_READ | PROT_WRITE | PROT_EXEC);
	long have = pb_vma_prot(vma);

	if (have == want)
		return true;
	return (current->personality & READ_IMPLIES_EXEC) && (want & PROT_READ) &&
	       (vma->vm_flags & VM_MAYEXEC) && have == (want | PROT_EXEC);
}

/*
 * End of the part of [start, end) that a failed mprotect did apply.
 *
 * do_mprotect_pkey fails before touching any VMA only with -EINVAL (an
 * unaligned start, an invalid prot bit, an unallocated pkey), -EINTR, or
 * -ENOMEM (a length that wraps, or start not mapped). Otherwise it works
 * VMA by VMA from start, leaves the VMA that fails as it was, and stops.
 * So, unless it failed up front, what it applied is the run of VMAs from
 * start that now have the requested protection, up to the first hole or
 * the first VMA that does not. A VMA that already had that protection
 * counts: the call passed over it before failing further on, as when a
 * hole follows it.
 *
 * Whether -EINVAL or -EINTR came up front cannot be read off the VMAs: a
 * VMA that already had the requested protection looks the same either way.
 * If nothing changed, they are taken as up front. The one in-loop -EINVAL,
 * from arch_validate_flags or a driver's vm_ops->mprotect, is then
 * mistaken for it when only unchanged VMAs came first, and those keep
 * their old records. A wrapping length is caught here as end == ~0UL, and
 * an unmapped start stops the walk at once.
 *
 * -ENOSYS means the syscall does not exist here, so nothing was applied.
 * arm64 before 6.12 has no CONFIG_ARCH_HAS_PKEYS, and pkey_mprotect is
 * sys_ni_syscall. The VMAs cannot show this either: a W^X page the module
 * keeps read-execute already looks like a pkey_mprotect(RX) that worked.
 */
static unsigned long pb_protect_done(unsigned long start, unsigned long end,
				     unsigned long prot, long ret,
				     struct list_head *segs)
{
	struct vm_area_struct *vma;
	struct pb_seg *seg;
	unsigned long at = start;
	bool changed = false;

	if (ret == -ENOSYS || end == ~0UL || !current->mm ||
	    mmap_read_lock_killable(current->mm))
		return start;
	list_for_each_entry(seg, segs, list) {
		if (!pb_seg_same(seg->start, seg->end, seg->prot)) {
			changed = true;
			break;
		}
	}
	if (!changed && (ret == -EINVAL || ret == -EINTR))
		goto out;
	while (at < end) {
		vma = find_vma(current->mm, at);
		if (!vma || vma->vm_start > at || !pb_vma_has(vma, prot))
			break;
		at = min(vma->vm_end, end);
	}
out:
	mmap_read_unlock(current->mm);
	return at;
}

/*
 * pb_handle_protect updates the tracked records before the syscall, so
 * that no page is ever stripped of PROT_WRITE without a record saying the
 * write is allowed. If the syscall then fails, the pages it did not change
 * must get their old records back: a W^X page untracked by a failed
 * mprotect would turn its next legal store into a SIGSEGV, and a record
 * left by a failed mprotect(RWX) would let the module make a page
 * executable that never was. pb_vm_lock keeps any other mprotect, mmap,
 * munmap or mremap of this process from changing those records between
 * the snapshot and here. Armed data records are not put back. The disarm
 * restored those pages first, so they stay accessible, and the next arm
 * attempt arms them again.
 */
static void pb_settle_tracked(unsigned long start, unsigned long end,
			      unsigned long prot, long ret, struct list_head *snap,
			      struct list_head *segs, bool have_segs)
{
	struct marea *entry, *tmp;
	pid_t tgid = current->tgid;
	unsigned long done;

	if (ret == 0) {
		pb_free_list(snap);
		return;
	}
	done = have_segs ? pb_protect_done(start, end, prot, ret, segs) : start;
	mutex_lock(&marea_lock);
	list_for_each_entry_safe(entry, tmp, &marea_list, list) {
		if (entry->tgid != tgid || entry->addr < done || entry->addr >= end)
			continue;
		list_del(&entry->list);
		kfree(entry);
	}
	list_for_each_entry_safe(entry, tmp, snap, list) {
		if (entry->addr < done || entry->addr >= end)
			continue;
		list_move(&entry->list, &marea_list);
	}
	mutex_unlock(&marea_lock);
	pb_free_list(snap);
}

/*
 * mprotect and pkey_mprotect. regs is the caller's saved register file,
 * restored on return to user space. pb_handle_protect may clear
 * PROT_WRITE in the prot argument, so do that in a copy: the syscall ABI
 * preserves rdx/x2, and a changed prot there breaks raw-syscall callers
 * and shows that the module is loaded.
 */
static long pb_protect_syscall(struct pt_regs *regs, long (*real)(struct pt_regs *))
{
	struct pt_regs args;
	unsigned long prot;
	unsigned long start, end;
	LIST_HEAD(snap);
	LIST_HEAD(segs);
	bool have_segs;
	long ret;

	if (mutex_lock_killable(&pb_vm_lock))
		return -EINTR;
	args = *regs;
	prot = pb_arg(&args, 2);
	pb_protect_range(pb_arg(&args, 0), pb_arg(&args, 1), &start, &end);
	if (prot & PROT_EXEC)
		pb_read_armed(pb_arg(&args, 0), pb_arg(&args, 1));
	pb_snapshot_tracked(start, end, &snap);
	pb_handle_protect(&args);
	if (prot_has_x_only(prot) || prot_has_wx(prot))
		pb_try_arm();
	/*
	 * Taken last, after the module's own restores and arming, so that
	 * only the syscall's changes show up in the comparison.
	 */
	have_segs = pb_seg_snapshot(start, end, &segs);
	ret = real(&args);
	pb_settle_tracked(start, end, pb_arg(&args, 2), ret, &snap, &segs, have_segs);
	pb_seg_free(&segs);
	mutex_unlock(&pb_vm_lock);
	return ret;
}

static asmlinkage long fh_sys_mprotect(struct pt_regs *regs)
{
	if (!pb_is_target())
		return real_sys_mprotect(regs);
	return pb_protect_syscall(regs, real_sys_mprotect);
}

static asmlinkage long (*real_sys_pkey_mprotect)(struct pt_regs *regs);

static asmlinkage long fh_sys_pkey_mprotect(struct pt_regs *regs)
{
	if (!pb_is_target())
		return real_sys_pkey_mprotect(regs);
	return pb_protect_syscall(regs, real_sys_pkey_mprotect);
}

static bool pb_page_exec(unsigned long addr)
{
	struct vm_area_struct *vma;
	bool exec = false;

	if (!current->mm)
		return false;
	if (mmap_read_lock_killable(current->mm))
		return false;
	vma = find_vma(current->mm, addr);
	if (vma && vma->vm_start <= addr && (vma->vm_flags & VM_EXEC))
		exec = true;
	mmap_read_unlock(current->mm);
	return exec;
}

static bool pb_relocate_locked(pid_t tgid, unsigned long from, unsigned long to)
{
	struct marea *entry;

	list_for_each_entry(entry, &data_armed, list) {
		if (entry->tgid != tgid || entry->addr != from)
			continue;
		entry->addr = to;
		return true;
	}
	return false;
}

static bool pb_relocate_armed(pid_t tgid, unsigned long from, unsigned long to)
{
	bool moved;

	mutex_lock(&marea_lock);
	moved = pb_relocate_locked(tgid, from, to);
	mutex_unlock(&marea_lock);
	return moved;
}

/*
 * Settle one armed page after the kernel has moved it. When the record was
 * relocated ahead of the move, it already sits at the destination and must
 * only be settled there. Otherwise it is still at the source and has to
 * follow. A page that lands outside the armed range gets its protection
 * back, otherwise nothing would ever restore it.
 */
static void pb_armed_after_move(unsigned long from, unsigned long to, int keep, bool pre)
{
	struct marea *entry, *tmp;
	unsigned long prot = 0;
	pid_t tgid = current->tgid;
	unsigned long want = pre ? to : from;
	bool found = false;
	bool in_range = to >= data_lo && to < data_hi;

	mutex_lock(&marea_lock);
	list_for_each_entry_safe(entry, tmp, &data_armed, list) {
		if (entry->tgid != tgid || entry->addr != want)
			continue;
		found = true;
		prot = entry->prot;
		break;
	}
	mutex_unlock(&marea_lock);
	/*
	 * Restore before forgetting, and outside marea_lock, by the lock-order
	 * rule in front of pb_disarm_range. Re-validate first, so a page
	 * re-armed with a different protection in the gap is not overwritten
	 * with the value we read before the move.
	 */
	if (found && keep && !in_range && pb_armed_unchanged(tgid, want, prot)) {
		if (pb_mprotect(to, PAGE_SIZE, prot ? prot : PROT_READ))
			pr_warn("restore %lx prot=%lx failed\n", to, prot);
	}
	mutex_lock(&marea_lock);
	list_for_each_entry_safe(entry, tmp, &data_armed, list) {
		if (entry->tgid != tgid || entry->addr != want)
			continue;
		if (keep && in_range) {
			/* still PROT_NONE at the new address, so the pin stays */
			entry->addr = to;
		} else {
			entry->restored = true;
			list_del(&entry->list);
			kfree(entry);
		}
		break;
	}
	list_for_each_entry_safe(entry, tmp, &data_seen, list) {
		if (entry->tgid != tgid || entry->addr != from)
			continue;
		list_del(&entry->list);
		kfree(entry);
	}
	mutex_unlock(&marea_lock);
	if (found && keep && !in_range)
		pb_mprotect(to, PAGE_SIZE, prot ? prot : PROT_READ);
}

/*
 * dontunmap: MREMAP_DONTUNMAP left the source mapped, with its protection,
 * so a tracked page is now at both addresses and keeps a record at each.
 */
static void pb_note_mremap(unsigned long old, unsigned long old_len,
			   unsigned long new, unsigned long new_len, bool pre,
			   bool dontunmap)
{
	unsigned long old_pages = pb_page_count(old_len);
	unsigned long new_pages = pb_page_count(new_len);
	unsigned long i;

	old &= PAGE_MASK;
	new &= PAGE_MASK;
	/*
	 * A move to a range apart from the source replaced whatever was
	 * mapped there, so its tracked records go before the moved ones
	 * arrive. A resize in place overlaps the source and keeps them.
	 */
	if (new + new_pages * PAGE_SIZE <= old || old + old_pages * PAGE_SIZE <= new) {
		struct marea *entry, *tmp;

		mutex_lock(&marea_lock);
		list_for_each_entry_safe(entry, tmp, &marea_list, list) {
			if (entry->tgid != current->tgid || entry->addr < new ||
			    entry->addr >= new + new_pages * PAGE_SIZE)
				continue;
			list_del(&entry->list);
			kfree(entry);
		}
		mutex_unlock(&marea_lock);
	}
	for (i = 0; i < old_pages; i++) {
		struct marea *entry;
		unsigned long from = old + i * PAGE_SIZE;
		int keep = i < new_pages;

		pb_armed_after_move(from, new + i * PAGE_SIZE, keep, pre);
		mutex_lock(&marea_lock);
		entry = search_page(current->tgid, from);
		if (entry) {
			if (keep && dontunmap) {
				struct marea *fresh;

				fresh = new_marea(current->tgid, new + i * PAGE_SIZE,
						  entry->prot);
				if (fresh) {
					fresh->epoch = entry->epoch;
					list_add(&fresh->list, &marea_list);
				}
			} else if (keep)
				entry->addr = new + i * PAGE_SIZE;
			else {
				list_del(&entry->list);
				kfree(entry);
			}
		}
		mutex_unlock(&marea_lock);
		if (keep && pb_page_exec(new + i * PAGE_SIZE))
			dump_to_file(new + i * PAGE_SIZE, PAGE_SIZE, "mremap", NULL);
	}
}

static asmlinkage long (*real_sys_mremap)(struct pt_regs *regs);

/*
 * Restore one armed page to the protection we recorded and forget it. The
 * restore happens first, so the page is never inaccessible without a record.
 */
static void pb_release_armed(pid_t tgid, unsigned long page)
{
	struct marea *entry, *tmp;
	unsigned long prot = 0;
	bool found = false;

	mutex_lock(&marea_lock);
	list_for_each_entry(entry, &data_armed, list) {
		if (entry->tgid != tgid || entry->addr != page)
			continue;
		prot = entry->prot;
		found = true;
		break;
	}
	mutex_unlock(&marea_lock);
	/* Restore outside the lock, same reason as pb_disarm_range, and only
	 * if the record still says what we read. */
	if (found && pb_armed_unchanged(tgid, page, prot))
		pb_mprotect(page, PAGE_SIZE, prot ? prot : PROT_READ);
	mutex_lock(&marea_lock);
	list_for_each_entry_safe(entry, tmp, &data_armed, list) {
		if (entry->tgid != tgid || entry->addr != page)
			continue;
		entry->restored = true;
		list_del(&entry->list);
		kfree(entry);
		break;
	}
	pb_pin_update_locked();
	list_for_each_entry_safe(entry, tmp, &data_seen, list) {
		if (entry->tgid != tgid || entry->addr != page)
			continue;
		list_del(&entry->list);
		kfree(entry);
	}
	mutex_unlock(&marea_lock);
	(void)found;
}

static long pb_mremap(struct pt_regs *regs)
{
	unsigned long old = pb_arg(regs, 0);
	unsigned long old_len = pb_arg(regs, 1);
	unsigned long new_len = pb_arg(regs, 2);
	unsigned long flags = pb_arg(regs, 3);
	unsigned long new_addr = pb_arg(regs, 4);
	pid_t tgid = current->tgid;
	int n_pages = pb_page_count(old_len);
	int moved = 0;
	bool pre = false;
	int i;
	long ret;

	if (flags & MREMAP_FIXED) {
		/*
		 * The kernel unmaps whatever is at the destination before
		 * moving there. An armed record of that old mapping must not
		 * survive next to the one that arrives with the moved page:
		 * both would sit at the same address, and the old saved
		 * protection could be restored on the new page. Release the
		 * destination first. If the syscall fails, those pages are
		 * merely accessible and get armed again later.
		 */
		for (i = 0; i < pb_page_count(new_len); i++)
			pb_release_armed(tgid, new_addr + (unsigned long)i * PAGE_SIZE);
	}
	if (flags & MREMAP_DONTUNMAP) {
		/*
		 * The kernel moves the pages and keeps the source VMA, with
		 * its protection. An armed source would stay PROT_NONE for
		 * good while its record went with the page, and every later
		 * access to the source would be a SIGSEGV the module caused.
		 * Release first, as for a resizing move: both ends arrive
		 * accessible, and the moved page is re-armed by the next
		 * executable mprotect. DONTUNMAP always moves, even at the
		 * same size, so the size test below does not apply to it.
		 */
		for (i = 0; i < n_pages; i++)
			pb_release_armed(tgid, old + (unsigned long)i * PAGE_SIZE);
	} else if (flags & MREMAP_FIXED) {
		/*
		 * MREMAP_FIXED names the destination now, so settle each page
		 * before the kernel moves it. A page that lands outside the
		 * armed range is made accessible first: nothing would restore
		 * it once it is there, and a reader would take a signal this
		 * module caused. A page that stays in range keeps its record,
		 * relocated ahead of the move.
		 *
		 * Known gap: from here until the kernel moves the page, the
		 * source is still PROT_NONE and its record is already at the
		 * destination, so a read of the source in that window takes a
		 * SIGSEGV. Without the module the source is unmapped once the
		 * move completes, so a program reading it concurrently with
		 * its own mremap is already racing.
		 */
		for (i = 0; i < n_pages; i++) {
			unsigned long to = new_addr + (unsigned long)i * PAGE_SIZE;
			unsigned long from = old + (unsigned long)i * PAGE_SIZE;

			if (to >= data_lo && to < data_hi)
				moved += pb_relocate_armed(tgid, from, to);
			else
				pb_release_armed(tgid, from);
		}
		pre = moved > 0;
	} else if (old_len != new_len) {
		/*
		 * Without MREMAP_FIXED the kernel picks the destination, so
		 * no record can be placed ahead of the move. Measured on
		 * 6.8, a same-size move keeps the address and there is no
		 * window; a size change can relocate, so release the pages
		 * first and let them arrive accessible. The cost is that a
		 * relocated page is not re-armed until the next mprotect.
		 */
		for (i = 0; i < n_pages; i++)
			pb_release_armed(tgid, old + (unsigned long)i * PAGE_SIZE);
	}
	ret = real_sys_mremap(regs);
	if (ret < 0) {
		if (pre)
			for (i = 0; i < n_pages; i++)
				pb_relocate_armed(tgid, new_addr + (unsigned long)i * PAGE_SIZE,
						  old + (unsigned long)i * PAGE_SIZE);
		return ret;
	}
	pb_note_mremap(old, old_len, (unsigned long)ret, new_len, pre,
		       flags & MREMAP_DONTUNMAP);
	return ret;
}

static asmlinkage long fh_sys_mremap(struct pt_regs *regs)
{
	long ret;

	if (!pb_is_target())
		return real_sys_mremap(regs);
	if (mutex_lock_killable(&pb_vm_lock))
		return -EINTR;
	ret = pb_mremap(regs);
	mutex_unlock(&pb_vm_lock);
	return ret;
}

static asmlinkage long (*real_sys_munmap)(struct pt_regs *regs);

static asmlinkage long fh_sys_munmap(struct pt_regs *regs)
{
	unsigned long addr = pb_arg(regs, 0);
	unsigned long len = pb_arg(regs, 1);
	long ret;

	if (!pb_is_target())
		return real_sys_munmap(regs);
	if (mutex_lock_killable(&pb_vm_lock))
		return -EINTR;
	ret = real_sys_munmap(regs);
	if (!ret)
		pb_drop_user_range(current->tgid, addr, len);
	mutex_unlock(&pb_vm_lock);
	return ret;
}

static asmlinkage unsigned long (*real_vm_mmap_pgoff)(struct file *file,
		unsigned long addr, unsigned long len, unsigned long prot,
		unsigned long flag, unsigned long pgoff);

static unsigned long pb_vm_mmap(struct file *file,
		unsigned long addr, unsigned long len, unsigned long prot,
		unsigned long flag, unsigned long pgoff)
{
	unsigned long ret;
	unsigned long intended;
	int n_pages;

	n_pages = pb_page_count(len);

	if (prot_has_wx(prot)) {
		intended = prot;
		if (!file)
			flag |= MAP_POPULATE;
		ret = real_vm_mmap_pgoff(file, addr, len, prot & ~PROT_WRITE,
					 flag, pgoff);
		if (IS_ERR_VALUE(ret))
			return ret;
		/*
		 * A MAP_FIXED mapping replaces whatever was there. Drop its
		 * armed, seen and tracked records first, as the other branch
		 * does, or the new pages inherit an old saved protection and
		 * the old epoch.
		 */
		pb_drop_user_range(current->tgid, ret, (unsigned long)n_pages * PAGE_SIZE);
		track_pages(ret, n_pages, intended);
		return ret;
	}

	ret = real_vm_mmap_pgoff(file, addr, len, prot, flag, pgoff);
	if (IS_ERR_VALUE(ret))
		return ret;
	pb_drop_user_range(current->tgid, ret, (unsigned long)n_pages * PAGE_SIZE);

	if (prot_has_x_only(prot)) {
		int i;

		track_pages(ret, n_pages, prot);
		for (i = 0; i < n_pages; i++) {
			unsigned long page = ret + i * PAGE_SIZE;

			if (dump_to_file(page, PAGE_SIZE, "mmap", NULL) < 0)
				continue;
		}
	} else {
		untrack_pages(ret, n_pages);
	}

	return ret;
}

static asmlinkage unsigned long fh_vm_mmap_pgoff(struct file *file,
		unsigned long addr, unsigned long len, unsigned long prot,
		unsigned long flag, unsigned long pgoff)
{
	unsigned long ret;

	if (!pb_is_target())
		return real_vm_mmap_pgoff(file, addr, len, prot, flag, pgoff);
	if (mutex_lock_killable(&pb_vm_lock))
		return -EINTR;
	ret = pb_vm_mmap(file, addr, len, prot, flag, pgoff);
	mutex_unlock(&pb_vm_lock);
	return ret;
}

static asmlinkage long (*real_force_sig_fault)(int sig, int code, void __user *addr);

static bool pb_fault_is_write(void)
{
#if defined(PB_ARM64)
	unsigned long esr = current->thread.fault_code;

	if ((esr & ESR_ELx_FSC) == ESR_ELx_FSC_MTE)
		return false;
	return ESR_ELx_EC(esr) == ESR_ELx_EC_DABT_LOW && (esr & ESR_ELx_WNR);
#else
	return current->thread.error_code & X86_PF_WRITE;
#endif
}

static bool pb_fault_is_read(void)
{
#if defined(PB_ARM64)
	unsigned long esr = current->thread.fault_code;

	if ((esr & ESR_ELx_FSC) == ESR_ELx_FSC_MTE)
		return false;
	return ESR_ELx_EC(esr) == ESR_ELx_EC_DABT_LOW && !(esr & ESR_ELx_WNR);
#else
	unsigned long ec = current->thread.error_code;

	return !(ec & X86_PF_WRITE) && !(ec & X86_PF_INSTR);
#endif
}

static unsigned long pb_fault_ip(void)
{
	unsigned long ip = instruction_pointer(task_pt_regs(current));

#if defined(PB_ARM64)
	ip = untagged_addr(ip);
#endif
	return ip;
}

static bool pb_ip_tracked_for(pid_t tgid, unsigned long ip, unsigned long *epoch)
{
	struct marea *page;
	bool found = false;

	mutex_lock(&marea_lock);
	page = search_page(tgid, ip);
	if (page && (page->prot & PROT_EXEC)) {
		*epoch = page->epoch;
		found = true;
	}
	mutex_unlock(&marea_lock);
	return found;
}

/*
 * The parent's records stand in for a fork child's only until the parent
 * has copied them, see pb_handle_data. Read own first, for the same reason.
 */
static bool pb_ip_tracked(unsigned long ip, unsigned long *epoch)
{
	bool use_parent = !pb_tgid_own(current->tgid);

	if (pb_ip_tracked_for(current->tgid, ip, epoch))
		return true;
	return use_parent && pb_ip_tracked_for(pb_parent_tgid(), ip, epoch);
}

static bool pb_armed_prot_for(pid_t tgid, unsigned long page, unsigned long *prot_out)
{
	struct marea *seen;
	bool found = false;

	mutex_lock(&marea_lock);
	list_for_each_entry(seen, &data_armed, list) {
		if (seen->tgid == tgid && seen->addr == page) {
			*prot_out = seen->prot;
			found = true;
			break;
		}
	}
	mutex_unlock(&marea_lock);
	return found;
}

static bool pb_data_claim(pid_t tgid, unsigned long page, unsigned long handler_epoch)
{
	struct marea *seen;

	mutex_lock(&marea_lock);
	list_for_each_entry(seen, &data_seen, list) {
		if (seen->tgid == tgid && seen->addr == page &&
		    seen->epoch == handler_epoch) {
			mutex_unlock(&marea_lock);
			return false;
		}
	}
	seen = new_marea(tgid, page, 0);
	if (seen) {
		seen->epoch = handler_epoch;
		list_add(&seen->list, &data_seen);
	}
	mutex_unlock(&marea_lock);
	return seen != NULL;
}

static void pb_data_unclaim(pid_t tgid, unsigned long page, unsigned long handler_epoch)
{
	struct marea *seen, *tmp;

	mutex_lock(&marea_lock);
	list_for_each_entry_safe(seen, tmp, &data_seen, list) {
		if (seen->tgid != tgid || seen->addr != page ||
		    seen->epoch != handler_epoch)
			continue;
		list_del(&seen->list);
		kfree(seen);
		break;
	}
	mutex_unlock(&marea_lock);
}

static void pb_trace_line(unsigned long ip, unsigned long data_va, unsigned long epoch)
{
	char line[96];

	snprintf(line, sizeof(line), "%lx %lx %lu\n", ip, data_va, epoch);
	pb_log_line("/tmp/pagedrop.trace", line);
}

static int pb_handle_data(unsigned long address)
{
	unsigned long ip = pb_fault_ip();
	unsigned long page = address & PAGE_MASK;
	unsigned long handler_epoch = 0;
	unsigned long restore = 0;
	pid_t tgid = current->tgid;
	pid_t parent;
	struct pt_regs *regs;
	struct marea *armed_entry;
	bool use_parent;
	bool tracked;
	bool armed;

	/*
	 * The parent's armed records cover a fork child only in the window
	 * before pb_note_child has copied them. After the copy, or after an
	 * exec, the child's own records are the whole truth, and a PROT_NONE
	 * page of the child's own (a guard page, a GC barrier) must fault to
	 * the child's handler. Read own before the child's records: once it
	 * reads true, the copy is complete under marea_lock.
	 */
	use_parent = !pb_tgid_own(tgid);
	/*
	 * The record, not the range, decides ownership. An mremap can carry
	 * a page we made inaccessible out of the range, and only a record for
	 * it says so.
	 */
	armed = pb_armed_prot_for(tgid, page, &restore);
	parent = pb_parent_tgid();
	if (!armed && use_parent && parent > 0 && parent != tgid)
		armed = pb_armed_prot_for(parent, page, &restore);
	if (!armed || !restore) {
		/*
		 * Nothing of ours covers this page. If the access is already
		 * legal then a racing thread restored, moved or replaced it,
		 * and the fault is stale: swallow it. Otherwise it is a real
		 * fault, ours or the program's, and the signal stands.
		 */
		if (pb_page_satisfies(page, pb_fault_is_write()))
			return 1;
		return 0;
	}
	tracked = pb_ip_tracked(ip, &handler_epoch);
	if (pb_fault_is_write() && !(restore & PROT_WRITE))
		return 0;
	regs = kzalloc(sizeof(*regs), GFP_KERNEL);
	if (!regs)
		return 0;
	pb_set_arg(regs, 0, page);
	pb_set_arg(regs, 1, PAGE_SIZE);
	pb_set_arg(regs, 2, restore);
	if (real_sys_mprotect(regs)) {
		kfree(regs);
		return 0;
	}
	kfree(regs);
	mutex_lock(&marea_lock);
	list_for_each_entry(armed_entry, &data_armed, list) {
		if (armed_entry->tgid == tgid && armed_entry->addr == page)
			armed_entry->restored = true;
	}
	pb_pin_update_locked();
	mutex_unlock(&marea_lock);
	if (tracked && pb_data_claim(tgid, page, handler_epoch)) {
		if (dump_to_file(page, PAGE_SIZE, "read", NULL) == 0)
			pb_trace_line(ip, page, handler_epoch);
		else
			pb_data_unclaim(tgid, page, handler_epoch);
	}
	return 1;
}

static bool pb_fault_is_instr(void)
{
#if defined(PB_ARM64)
	unsigned long esr = current->thread.fault_code;

	if ((esr & ESR_ELx_FSC) == ESR_ELx_FSC_MTE)
		return false;
	return ESR_ELx_EC(esr) == ESR_ELx_EC_IABT_LOW;
#else
	return current->thread.error_code & X86_PF_INSTR;
#endif
}

static asmlinkage int fh_force_sig_fault(int sig, int code, void __user *addr)
{
	struct pt_regs *regs;
	unsigned long address = (unsigned long)addr;

#if defined(PB_ARM64)
	address = untagged_addr(address);
#endif
	unsigned long page_addr, new_prot;

	if (!pb_is_target() || sig != SIGSEGV)
		return real_force_sig_fault(sig, code, addr);

	if (data_on && (pb_fault_is_read() || pb_fault_is_write()) &&
	    pb_handle_data(address))
		return 0;

	if (!pb_take_page(address, &page_addr, &new_prot))
		return real_force_sig_fault(sig, code, addr);

	/*
	 * A protection-key fault is not about the page's protection, and
	 * mprotect keeps the key, so the access would fault again.
	 */
	if (code == SEGV_PKUERR)
		return real_force_sig_fault(sig, code, addr);
	/*
	 * Only a write the module forbade, by clearing PROT_WRITE from a W+X
	 * request, is ours to allow. A tracked page whose saved prot has no
	 * PROT_WRITE is plain read-only code. Restoring it without exec would
	 * leave it read-only, the same store would fault again, and the
	 * program would spin here instead of getting its SIGSEGV.
	 */
	if (pb_fault_is_write() && !(new_prot & PROT_WRITE))
		return real_force_sig_fault(sig, code, addr);

	regs = kzalloc(sizeof(*regs), GFP_KERNEL);
	if (!regs)
		return real_force_sig_fault(sig, code, addr);

	pb_set_arg(regs, 0, page_addr);
	pb_set_arg(regs, 1, PAGE_SIZE);

	if (pb_fault_is_write()) {
		new_prot &= ~PROT_EXEC;
		pb_set_arg(regs, 2, new_prot);
		if (real_sys_mprotect(regs)) {
			kfree(regs);
			return real_force_sig_fault(sig, code, addr);
		}
		kfree(regs);
		return 0;
	}

	if (pb_fault_is_instr()) {
		dump_to_file(page_addr, PAGE_SIZE, "fault", NULL);
		pb_try_arm();
		new_prot &= ~PROT_WRITE;
		pb_set_arg(regs, 2, new_prot);
		if (real_sys_mprotect(regs)) {
			kfree(regs);
			return real_force_sig_fault(sig, code, addr);
		}
		kfree(regs);
		return 0;
	}

	kfree(regs);
	return real_force_sig_fault(sig, code, addr);
}

static bool pb_name_matches(const char *name)
{
	if (!path || !path[0] || !name || !name[0])
		return false;
	if (exact)
		return strcmp(name, path) == 0;
	return strstr(name, path) != NULL;
}

static bool pb_user_path_matches(const char __user *uname)
{
	char *buf;
	long n;
	bool ok;

	if (!uname)
		return false;
	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf)
		return false;
	n = strncpy_from_user(buf, uname, PATH_MAX);
	if (n < 0) {
		kfree(buf);
		return false;
	}
	if (n == PATH_MAX)
		buf[PATH_MAX - 1] = '\0';
	ok = pb_name_matches(buf);
	kfree(buf);
	return ok;
}

static bool pb_fd_path_matches(int fd)
{
	struct file *f;
	char *buf, *p;
	bool ok = false;

	if (fd < 0)
		return false;
	f = fget(fd);
	if (!f)
		return false;
	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf) {
		fput(f);
		return false;
	}
	p = d_path(&f->f_path, buf, PATH_MAX);
	if (!IS_ERR(p))
		ok = pb_name_matches(p);
	kfree(buf);
	fput(f);
	return ok;
}

static void pb_move_tracked(struct list_head *saved)
{
	struct marea *entry, *tmp;
	pid_t tgid = current->tgid;

	mutex_lock(&marea_lock);
	list_for_each_entry_safe(entry, tmp, &marea_list, list) {
		if (entry->tgid != tgid)
			continue;
		list_move(&entry->list, saved);
	}
	mutex_unlock(&marea_lock);
}

static void pb_copy_list(struct list_head *head, pid_t from, pid_t to)
{
	struct marea *entry, *fresh;
	LIST_HEAD(add);

	list_for_each_entry(entry, head, list) {
		if (entry->tgid != from)
			continue;
		fresh = new_marea(to, entry->addr, entry->prot);
		if (!fresh)
			continue;
		fresh->epoch = entry->epoch;
		/* A child inherits the page exactly as accessible or as
		 * inaccessible, so the pin state has to be copied with it. */
		fresh->restored = entry->restored;
		list_add(&fresh->list, &add);
	}
	list_splice(&add, head);
}

static long pb_finish_exec(struct list_head *saved, bool matched, long ret)
{
	if (!matched)
		return ret;
	if (ret == 0) {
		pb_free_list(saved);
		return ret;
	}
	mutex_lock(&marea_lock);
	list_splice_init(saved, &marea_list);
	mutex_unlock(&marea_lock);
	return ret;
}

static long pb_do_exec(bool matched, long (*real)(struct pt_regs *), struct pt_regs *regs)
{
	bool added = false;
	bool inherited = false;
	bool tracked;
	long ret;
	pid_t tgid = current->tgid;
	pid_t parent;
	LIST_HEAD(saved);

	tracked = pb_tgid_has(tgid);
	/*
	 * The new image has none of the old pages, so it owns its records
	 * from here on and must never get the parent's. Set the mark under
	 * marea_lock, before the exec, so a parent still in pb_note_child
	 * either copied before this, or sees the mark and copies nothing.
	 * After vfork, and posix_spawn, the parent only runs once the child
	 * has exec'd, so it is always the second case.
	 *
	 * In that case do the parent's copy here, in the same hold. The exec
	 * can still fail and leave the old image running, and that image
	 * needs the records it inherited. The parent is still alive at this
	 * point: it has not finished pb_note_child, so it has not returned
	 * from fork. Waiting for the failure to copy would be too late, as
	 * the parent may have exited by then. On success the drop below, or
	 * pb_move_tracked for a matching path, removes the copy with the rest.
	 *
	 * A child of a tracked process counts as tracked here, even if
	 * pb_is_target has not listed it yet.
	 */
	if (matched || tracked || pb_parent_tracked()) {
		parent = pb_parent_tgid();
		mutex_lock(&marea_lock);
		if (!pb_tgid_own(tgid) && parent > 0 && parent != tgid &&
		    pb_tgid_has(parent)) {
			pb_copy_list(&data_armed, parent, tgid);
			pb_copy_list(&marea_list, parent, tgid);
			inherited = true;
		}
		added = pb_tgid_add(tgid, true);
		mutex_unlock(&marea_lock);
		tracked = true;
	}
	if (matched)
		pb_move_tracked(&saved);
	ret = real(regs);
	if (ret == 0 && tracked) {
		pb_drop_data_state(tgid);
		if (!matched)
			pb_drop_marea(tgid);
	}
	/*
	 * A failed exec keeps the old image and the mark. A tgid this exec
	 * listed for a matching path, with nothing inherited, is unlisted
	 * again, as before.
	 */
	if (ret != 0 && added && !inherited)
		pb_tgid_del(tgid);
	return pb_finish_exec(&saved, matched, ret);
}

static asmlinkage long (*real_sys_execve)(struct pt_regs *regs);

static asmlinkage long fh_sys_execve(struct pt_regs *regs)
{
	bool matched;

	matched = pb_user_path_matches((const char __user *)pb_arg(regs, 0));
	return pb_do_exec(matched, real_sys_execve, regs);
}

static asmlinkage long (*real_sys_execveat)(struct pt_regs *regs);

static asmlinkage long fh_sys_execveat(struct pt_regs *regs)
{
	bool matched;
	int fd = (int)pb_arg(regs, 0);
	int flags = (int)pb_arg(regs, 4);

	matched = pb_user_path_matches((const char __user *)pb_arg(regs, 1));
	if (!matched && (flags & AT_EMPTY_PATH))
		matched = pb_fd_path_matches(fd);
	return pb_do_exec(matched, real_sys_execveat, regs);
}

/*
 * Copy, and mark the child as owning its records, in one marea_lock hold.
 * pb_do_exec sets the same mark under the same lock before an exec, and
 * makes this copy itself then, so if the mark is already set the child has
 * its copy, and this one copies nothing.
 */
static void pb_copy_tracking(pid_t from, pid_t to)
{
	mutex_lock(&marea_lock);
	if (!pb_tgid_own(to)) {
		pb_copy_list(&data_armed, from, to);
		pb_copy_list(&marea_list, from, to);
		pb_tgid_set_own(to, true);
	}
	mutex_unlock(&marea_lock);
}

/*
 * fork and clone return the child's pid in the caller's pid namespace.
 * Every record is keyed on the global tgid, so look the task up here and
 * key the child on task_tgid_nr(). In a container the two numbers differ.
 */
static struct task_struct *pb_child_task(long child)
{
	struct pid *pid;
	struct task_struct *task;

	pid = find_get_pid((pid_t)child);
	if (!pid)
		return NULL;
	task = get_pid_task(pid, PIDTYPE_PID);
	put_pid(pid);
	return task;
}

/*
 * Whether the child's thread group is alive, not the task we looked up.
 * That task is the leader at fork time. A leader can pthread_exit while
 * its threads run on, and an exec from another thread makes that thread
 * the leader and releases the old one, while the tgid lives on. signal is
 * shared by the group, survives that exec, and stays valid while we hold
 * the task. live counts the group's threads, and fh_exit_files cleans up
 * only once it is 0.
 */
static bool pb_group_alive(struct task_struct *task)
{
	return atomic_read(&task->signal->live) > 0;
}

static void pb_drop_child(pid_t tgid)
{
	pb_drop_data_state(tgid);
	pb_drop_marea(tgid);
	pb_tgid_del(tgid);
}

static void pb_note_child(long child, unsigned long flags, bool has_flags)
{
	struct task_struct *task;
	pid_t tgid;

	if (child <= 0 || !pb_tgid_has(current->tgid))
		return;
	if (has_flags && (flags & CLONE_THREAD))
		return;
	task = pb_child_task(child);
	if (!task)
		return;
	tgid = task_tgid_nr(task);
	/*
	 * The child runs as soon as the fork returns, and it can exit
	 * before this bookkeeping. Registering a tgid that is already gone
	 * would leave its records behind for whoever reuses that pid, so
	 * check first, and drop again if the child died while copying.
	 * The group's last thread brings live to 0 before fh_exit_files
	 * takes marea_lock to clean up. If that cleanup ran before the
	 * copy, the copy's own marea_lock hold makes live == 0 visible
	 * here; if it runs after, it removes the copy. Holding the task
	 * keeps the second check on this child even if its pid number is
	 * reused.
	 */
	if (pb_group_alive(task)) {
		pb_tgid_add(tgid, false);
		pb_copy_tracking(current->tgid, tgid);
		if (!pb_group_alive(task))
			pb_drop_child(tgid);
	}
	put_task_struct(task);
}

static asmlinkage long (*real_sys_fork)(struct pt_regs *regs);
static asmlinkage long (*real_sys_vfork)(struct pt_regs *regs);
static asmlinkage long (*real_sys_clone)(struct pt_regs *regs);
static asmlinkage long (*real_sys_clone3)(struct pt_regs *regs);

static asmlinkage long fh_sys_fork(struct pt_regs *regs)
{
	long ret = real_sys_fork(regs);

	pb_note_child(ret, 0, false);
	return ret;
}

static asmlinkage long fh_sys_vfork(struct pt_regs *regs)
{
	long ret = real_sys_vfork(regs);

	pb_note_child(ret, 0, false);
	return ret;
}

static asmlinkage long fh_sys_clone(struct pt_regs *regs)
{
	long ret = real_sys_clone(regs);

	pb_note_child(ret, pb_arg(regs, 0), true);
	return ret;
}

static asmlinkage long fh_sys_clone3(struct pt_regs *regs)
{
	u64 flags = 0;
	long ret;

	if (copy_from_user(&flags, (void __user *)pb_arg(regs, 0), sizeof(flags)))
		flags = 0;
	ret = real_sys_clone3(regs);
	pb_note_child(ret, flags, true);
	return ret;
}

static void (*real_exit_files)(struct task_struct *tsk);

/*
 * do_exit sets PF_EXITING, then decrements signal->live, then calls
 * exit_files. Testing live on entry to do_exit raced: two threads of an
 * exit_group could both read 2 and neither drop the tgid. Here every
 * exiting thread has already decremented, so live == 0 means the whole
 * group is dead, and the last thread to decrement always sees it. More
 * than one thread may see 0; the drops are idempotent. The tgid cannot
 * be reused yet, because the leader is reaped only after exit_notify.
 * exit_files is also called by copy_process on a failed fork, for a
 * task that is not current, so that call is skipped.
 */
static void fh_exit_files(struct task_struct *tsk)
{
	if (tsk == current && (current->flags & PF_EXITING) &&
	    current->signal && atomic_read(&current->signal->live) == 0) {
		pb_drop_data_state(current->tgid);
		pb_drop_marea(current->tgid);
		pb_tgid_del(current->tgid);
	}
	real_exit_files(tsk);
}

#if defined(PB_ARM64)
#define SYSCALL_NAME(name) ("__arm64_" name)
#elif defined(PTREGS_SYSCALL_STUBS)
#define SYSCALL_NAME(name) ("__x64_" name)
#else
#define SYSCALL_NAME(name) (name)
#endif

#define HOOK(_name, _function, _original)	\
	{					\
		.name = SYSCALL_NAME(_name),	\
		.function = (_function),	\
		.original = (_original),	\
	}

#define HOOK_NOSYS(_name, _function, _original)	\
	{					\
		.name = _name,			\
		.function = (_function),	\
		.original = (_original),	\
	}

#if defined(PB_HOOK_FTRACE)
static struct ftrace_hook demo_hooks[] = {
	HOOK("sys_mprotect", fh_sys_mprotect, &real_sys_mprotect),
	HOOK("sys_pkey_mprotect", fh_sys_pkey_mprotect, &real_sys_pkey_mprotect),
	HOOK("sys_mremap", fh_sys_mremap, &real_sys_mremap),
	HOOK("sys_munmap", fh_sys_munmap, &real_sys_munmap),
	HOOK_NOSYS("vm_mmap_pgoff", fh_vm_mmap_pgoff, &real_vm_mmap_pgoff),
	HOOK("sys_execve", fh_sys_execve, &real_sys_execve),
	HOOK("sys_execveat", fh_sys_execveat, &real_sys_execveat),
	HOOK("sys_fork", fh_sys_fork, &real_sys_fork),
	HOOK("sys_vfork", fh_sys_vfork, &real_sys_vfork),
	HOOK("sys_clone", fh_sys_clone, &real_sys_clone),
	HOOK("sys_clone3", fh_sys_clone3, &real_sys_clone3),
	HOOK_NOSYS("exit_files", fh_exit_files, &real_exit_files),
	HOOK_NOSYS("force_sig_fault", fh_force_sig_fault, &real_force_sig_fault),
};

static int pb_install_hooks(void)
{
	return fh_install_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
}

static void pb_remove_hooks(void)
{
	fh_remove_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
}
#elif defined(PB_HOOK_KPROBE)
struct pb_arm_hook {
	const char *name;
	void *function;
	void *original;
	struct kprobe kp;
};

static int pb_arm_pre(struct kprobe *kp, struct pt_regs *regs)
{
	struct pb_arm_hook *hook = container_of(kp, struct pb_arm_hook, kp);

	if (within_module(regs->regs[30], THIS_MODULE))
		return 0;
	instruction_pointer_set(regs, (unsigned long)hook->function);
	return 1;
}
NOKPROBE_SYMBOL(pb_arm_pre);

static struct pb_arm_hook arm_hooks[] = {
	{ SYSCALL_NAME("sys_mprotect"), fh_sys_mprotect, &real_sys_mprotect },
	{ SYSCALL_NAME("sys_pkey_mprotect"), fh_sys_pkey_mprotect, &real_sys_pkey_mprotect },
	{ SYSCALL_NAME("sys_mremap"), fh_sys_mremap, &real_sys_mremap },
	{ SYSCALL_NAME("sys_munmap"), fh_sys_munmap, &real_sys_munmap },
	{ "vm_mmap_pgoff", fh_vm_mmap_pgoff, &real_vm_mmap_pgoff },
	{ SYSCALL_NAME("sys_execve"), fh_sys_execve, &real_sys_execve },
	{ SYSCALL_NAME("sys_execveat"), fh_sys_execveat, &real_sys_execveat },
	{ SYSCALL_NAME("sys_fork"), fh_sys_fork, &real_sys_fork },
	{ SYSCALL_NAME("sys_vfork"), fh_sys_vfork, &real_sys_vfork },
	{ SYSCALL_NAME("sys_clone"), fh_sys_clone, &real_sys_clone },
	{ SYSCALL_NAME("sys_clone3"), fh_sys_clone3, &real_sys_clone3 },
	{ "exit_files", fh_exit_files, &real_exit_files },
	{ "force_sig_fault", fh_force_sig_fault, &real_force_sig_fault },
};

static int pb_install_hooks(void)
{
	size_t i;
	int err;

	for (i = 0; i < ARRAY_SIZE(arm_hooks); i++) {
		unsigned long addr = lookup_name(arm_hooks[i].name);

		if (!addr) {
			pr_err("unresolved symbol: %s\n", arm_hooks[i].name);
			err = -ENOENT;
			goto unwind;
		}
		*(unsigned long *)arm_hooks[i].original = addr;
		arm_hooks[i].kp.symbol_name = arm_hooks[i].name;
		arm_hooks[i].kp.pre_handler = pb_arm_pre;
		err = register_kprobe(&arm_hooks[i].kp);
		if (err) {
			pr_err("register_kprobe(%s) failed: %d\n", arm_hooks[i].name, err);
			goto unwind;
		}
		pr_info("hooked %s @ %lx\n", arm_hooks[i].name, addr);
	}
	return 0;

unwind:
	while (i--)
		unregister_kprobe(&arm_hooks[i].kp);
	return err;
}

static void pb_remove_hooks(void)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(arm_hooks); i++) {
		if (!arm_hooks[i].kp.addr)
			continue;
		unregister_kprobe(&arm_hooks[i].kp);
	}
}
#endif

static int fh_init(void)
{
	int err;

	if (!path || !path[0]) {
		pr_err("missing path= module parameter\n");
		return -EINVAL;
	}
	if (data && data[0]) {
		unsigned long a, b;

		if (sscanf(data, "%lx-%lx", &a, &b) != 2 || b <= a) {
			pr_err("bad data= range\n");
			return -EINVAL;
		}
		data_lo = a & PAGE_MASK;
		data_hi = (b + PAGE_SIZE - 1) & PAGE_MASK;
		data_on = 1;
	}

	err = pb_install_hooks();
	if (err)
		return err;

	pr_info("loaded, watching comm/%s\n", path);
	return 0;
}
module_init(fh_init);

static void fh_exit(void)
{
	cancel_work_sync(&pb_pin_work);
	pb_pin_held = false;
	pb_pin_scheduled = false;
	pb_remove_hooks();
	clear_tracked();
	mutex_lock(&marea_lock);
	pb_free_list(&data_seen);
	pb_free_list(&data_armed);
	mutex_unlock(&marea_lock);
	pb_tgid_clear();
	pr_info("unloaded\n");
}
module_exit(fh_exit);

MODULE_DESCRIPTION("pagedrop - dump all executable pages of packed processes.");
MODULE_AUTHOR("Matteo Giordano <matteo.giordano@protonmail.com>");
MODULE_LICENSE("GPL");

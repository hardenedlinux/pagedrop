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

/*
 * MREMAP_DONTUNMAP arrived in 5.7 and is not defined on every header set
 * this builds against. Its value has been 4 since introduction.
 */
#ifndef MREMAP_DONTUNMAP
#define MREMAP_DONTUNMAP 4
#endif
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
static unsigned long epoch_counter;

struct pb_tgid {
	struct list_head list;
	pid_t tgid;
	/*
	 * Whether this tgid's records are its own, or were copied in while it
	 * was inside its parent's copy window. A parent still waiting for its
	 * own copy holds nothing, so a child forked from it must copy from
	 * the nearest ancestor that does hold records, not from it.
	 */
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

/*
 * The nearest ancestor of the current task that owns records, or 0.
 *
 * A process whose records were copied in while its parent was mid-copy does
 * not own them, so a grandchild forked from it must reach past it. The walk
 * is depth-bounded because real_parent can in principle chain, and it stops
 * at the first ancestor that owns records rather than at the top.
 */
static pid_t pb_records_tgid(void)
{
	struct task_struct *task;
	pid_t tgid = 0;
	int depth;

	rcu_read_lock();
	task = rcu_dereference(current->real_parent);
	for (depth = 0; task && depth < 64; depth++) {
		pid_t cand = task->tgid;

		if (cand <= 0 || !pb_tgid_has(cand))
			break;
		if (pb_tgid_own(cand)) {
			tgid = cand;
			break;
		}
		task = rcu_dereference(task->real_parent);
	}
	rcu_read_unlock();
	return tgid;
}


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
			/*
			 * An entry that exists does not mean the flag is right.
			 * A tgid first seen as a fork child holds a copy, not its
			 * own records; if it later matches by name or execs, it
			 * becomes an owner. Without this upgrade the child stays
			 * a non-owner for good, and a grandchild forked from it
			 * walks past it for records it never holds.
			 */
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
	 * A tracked parent wins over a matching name. A child inherits its
	 * parent's comm, so a vforked or cloned child of a target matches
	 * path= while owning none of its parent's records. Registering it
	 * as an owner would turn off the ancestor walk in the read path and
	 * lose the record that describes the page it is about to touch.
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

static bool pb_take_page(unsigned long addr, unsigned long *page_addr, unsigned long *prot)
{
	struct marea *page;
	bool found = false;
	/*
	 * A vfork child runs as soon as the fork returns, which can be before
	 * the parent's pb_note_child has copied anything, and a fork child
	 * inherits an address space whose records may still be the parent's.
	 * So when this tgid does not own records, fall back to the nearest
	 * ancestor that does. Without this a store in a vfork child finds no
	 * record, falls through to the real handler, and the child dies on a
	 * SIGSEGV the module caused.
	 *
	 * Own records are consulted first, so a page the child does own is
	 * never answered from the parent's record.
	 */
	bool use_parent = !pb_tgid_own(current->tgid);
	pid_t parent = use_parent ? pb_records_tgid() : 0;

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

/*
 * Make a comm safe to put in the index line.
 *
 * The index is "%d %s %lx %lu %s\n", one row per dump, and comm is whatever
 * the target chose. A newline in it ends the row early and lets the rest of
 * the name be read as forged fields, so a target that names itself can write
 * rows into the index that never happened. A space does the same to the
 * column count, so every byte at or below a space becomes an underscore.
 * Space and 0x7f are the ones that matter; anything else printable is fine.
 * Writes in place because comm is this task's own buffer.
 */
static const char *pb_index_comm(char *out)
{
	size_t i;

	if (!out[0]) {
		strcpy(out, "-");
		return out;
	}
	for (i = 0; out[i]; i++) {
		unsigned char c = (unsigned char)out[i];

		if (c <= ' ' || c == 0x7f)
			out[i] = '_';
	}
	return out;
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

static int dump_to_file(unsigned long user_addr, size_t size, const char *why,
			 unsigned long *ep_out)
{
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
	snprintf(line, sizeof(line), "%d %s %lx %lu %s\n", tgid,
		 pb_index_comm(current->comm), user_addr, ep, why);
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
 * pb_mprotect reaches the real mprotect, which wants mmap_write_lock, and
 * fh_vm_mmap_pgoff already runs under that lock and takes marea_lock. Doing
 * one inside the other is an ABBA deadlock. So: collect the pages under the
 * lock, restore with no lock held, then drop the records.
 *
 * The records outlive the restore, so a reader that faults meanwhile finds
 * one and is handled. A restore that lands on a page a reader already fixed
 * is the same protection, so it is a no-op.
 */
/*
 * The restore has to run with no lock held, or it deadlocks against the
 * mmap hook (drop-loop/models/lock-order). That leaves a window in which the page can
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

static void pb_handle_protect(struct pt_regs *regs)
{
	unsigned long addr = pb_arg(regs, 0);
	unsigned long len = pb_arg(regs, 1);
	unsigned long prot = pb_arg(regs, 2);
	int n_pages = pb_page_count(len);

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

static bool pb_can_arm(unsigned long addr, unsigned long *prot_out, bool allow_exec)
{
	struct vm_area_struct *vma;
	bool ok = false;

	if (!current->mm)
		return false;
	if (mmap_read_lock_killable(current->mm))
		return false;
	vma = find_vma(current->mm, addr);
	if (vma && vma->vm_start <= addr &&
	    (allow_exec || !(vma->vm_flags & VM_EXEC))) {
		unsigned long prot = 0;

		if (vma->vm_flags & VM_READ)
			prot |= PROT_READ;
		if (vma->vm_flags & VM_WRITE)
			prot |= PROT_WRITE;
		if (vma->vm_flags & VM_EXEC)
			prot |= PROT_EXEC;
		if (prot) {
			*prot_out = prot;
			ok = true;
		}
	}
	mmap_read_unlock(current->mm);
	return ok;
}

/*
 * Forget the data_seen rows for one page. The armed record and the dedup row
 * travel together: an explicit mprotect over an armed page is a new
 * generation of that page for the handler that reads it, so its next read
 * dumps again even at the same handler epoch.
 */
static void pb_seen_forget(pid_t tgid, unsigned long page)
{
	struct marea *entry, *tmp;

	mutex_lock(&marea_lock);
	list_for_each_entry_safe(entry, tmp, &data_seen, list) {
		if (entry->tgid != tgid || entry->addr != page)
			continue;
		list_del(&entry->list);
		kfree(entry);
	}
	mutex_unlock(&marea_lock);
}

/*
 * Forget one armed page and its data_seen rows. For a page the module can no
 * longer make inaccessible, keeping the record would make a later restore
 * install a protection the page does not have.
 */
static void pb_armed_forget(pid_t tgid, unsigned long page)
{
	struct marea *entry, *tmp;

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
	mutex_unlock(&marea_lock);
	pb_seen_forget(tgid, page);
}

/*
 * After a successful mprotect, take the pages it named back into data_armed
 * carrying the protection the kernel really installed, and PROT_NONE again.
 *
 * The restore used to run before the syscall, one page at a time, and to drop
 * the records. On a range-wide mprotect the kernel rewrites every page the
 * call names, so the split that leaves was erased; on an mprotect naming a
 * strict subset of a multi-page armed run the neighbours kept the PROT_NONE
 * and the split survived the syscall. 6.8 mremap needs uniform protection
 * across the old range, so the target's own MREMAP_FIXED over the run then
 * returned EFAULT and unmapped the destination, where the same program with
 * the module unloaded got the destination address back.
 *
 * Settling after the syscall puts the named pages back in the run at the same
 * protection as their neighbours, so the run is one uniform PROT_NONE mapping
 * again, and no dump is lost: a page the mprotect left armable is armed here
 * again and its next read still faults into pb_handle_data. A page the
 * mprotect made PROT_NONE, or one that is gone, cannot be armed and its record
 * goes with it, because a record has to describe a page the module can make
 * inaccessible. data_seen goes with both, as it did when this ran before the
 * syscall: an explicit mprotect over an armed page is a new generation of that
 * page for the handler that reads it, so its next read dumps again.
 */
static void pb_armed_rearm(pid_t tgid, unsigned long addr, unsigned long len)
{
	unsigned long start, page;
	int i, n;

	if (!len)
		return;
	start = addr & PAGE_MASK;
	n = pb_page_count(len);
	for (i = 0; i < n; i++) {
		unsigned long prot = 0;
		struct marea *entry;
		bool armed = false;

		page = start + (unsigned long)i * PAGE_SIZE;
		mutex_lock(&marea_lock);
		list_for_each_entry(entry, &data_armed, list) {
			if (entry->tgid != tgid || entry->addr != page)
				continue;
			armed = true;
			break;
		}
		mutex_unlock(&marea_lock);
		if (!armed)
			continue;
		if (!pb_can_arm(page, &prot, true) ||
		    pb_mprotect(page, PAGE_SIZE, PROT_NONE)) {
			pb_armed_forget(tgid, page);
			continue;
		}
		mutex_lock(&marea_lock);
		list_for_each_entry(entry, &data_armed, list) {
			if (entry->tgid != tgid || entry->addr != page)
				continue;
			entry->prot = prot;
			entry->restored = false;
			break;
		}
		mutex_unlock(&marea_lock);
		pb_seen_forget(tgid, page);
	}
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
	if (seen) {
		list_add(&seen->list, &data_armed);
		/*
		 * Take the pin here, before the caller sets PROT_NONE, because
		 * nothing else on the arming path does. Every process exit
		 * updates it through the exit hook, and that hid the gap: the
		 * suite's own short-lived process took the missing pin, so the
		 * window in which an armed page had no pin was invisible.
		 *
		 * A record describing a PROT_NONE page must outlive the
		 * protection it explains, or rmmod can strand the page. If the
		 * module is already going away the pin cannot be taken, so the
		 * record is dropped and the page is not armed.
		 */
		pb_pin_update_locked();
		if (!pb_pin_held) {
			list_del(&seen->list);
			kfree(seen);
			seen = NULL;
		}
	}
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

static void pb_arm_range(unsigned long lo, unsigned long hi, bool exec_ok)
{
	unsigned long addr;
	pid_t tgid = current->tgid;

	if (!data_on || data_hi <= data_lo)
		return;
	for (addr = data_lo; addr < data_hi; addr += PAGE_SIZE) {
		unsigned long prot = 0;
		bool pending = exec_ok && addr >= lo && addr < hi;

		if (!pb_can_arm(addr, &prot, pending))
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

static void pb_try_arm(unsigned long lo, unsigned long hi, bool exec_ok)
{
	if (!data_on)
		return;
	pb_arm_range(lo, hi, exec_ok);
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

/* Settling a failed mprotect; defined below, after pb_free_list. */
struct pb_seg;
static void pb_free_list(struct list_head *head);
static void pb_protect_range(unsigned long addr, unsigned long len,
			     unsigned long *start, unsigned long *end);
static void pb_snapshot_tracked(unsigned long start, unsigned long end,
				struct list_head *snap);
static bool pb_seg_snapshot(unsigned long start, unsigned long end,
			    struct list_head *segs);
static void pb_settle_tracked(unsigned long start, unsigned long end,
			      unsigned long prot, long ret, struct list_head *snap,
			      struct list_head *segs, bool have_segs);
static void pb_seg_free(struct list_head *segs);

static asmlinkage long fh_sys_mprotect(struct pt_regs *regs)
{
	unsigned long addr, len, prot;
	long ret;

	if (!pb_is_target())
		return real_sys_mprotect(regs);
	addr = pb_arg(regs, 0);
	len = pb_arg(regs, 1);
	prot = pb_arg(regs, 2);
	if (prot & PROT_EXEC)
		pb_read_armed(addr, len);
	{
		struct pt_regs args = *regs;
		LIST_HEAD(snap);
		LIST_HEAD(segs);
		unsigned long start, end;
		bool have_segs;
		long r;

		pb_protect_range(pb_arg(&args, 0), pb_arg(&args, 1), &start, &end);
		pb_snapshot_tracked(start, end, &snap);
		pb_handle_protect(&args);
		/*
		 * Taken after the syscall, so it sees only what the syscall
		 * itself changed rather than the module's own restores.
		 */
		have_segs = pb_seg_snapshot(start, end, &segs);
		r = real_sys_mprotect(&args);
		pb_settle_tracked(start, end, pb_arg(&args, 2), r, &snap, &segs,
				  have_segs);
		pb_seg_free(&segs);
		ret = r;
		if (!ret) {
			end = (addr + len + PAGE_SIZE - 1) & PAGE_MASK;
			pb_armed_rearm(current->tgid, addr, len);
			if (prot_has_x_only(prot) || prot_has_wx(prot))
				pb_try_arm(addr, end, true);
		}
		return ret;
	}
}

static asmlinkage long (*real_sys_pkey_mprotect)(struct pt_regs *regs);

static asmlinkage long fh_sys_pkey_mprotect(struct pt_regs *regs)
{
	unsigned long addr, len, prot;
	long ret;

	if (!pb_is_target())
		return real_sys_pkey_mprotect(regs);
	addr = pb_arg(regs, 0);
	len = pb_arg(regs, 1);
	prot = pb_arg(regs, 2);
	if (prot & PROT_EXEC)
		pb_read_armed(addr, len);
	{
		struct pt_regs a = *regs;
		LIST_HEAD(snap);
		LIST_HEAD(segs);
		unsigned long start, end;
		bool have_segs;
		long r;

		pb_protect_range(pb_arg(&a, 0), pb_arg(&a, 1), &start, &end);
		pb_snapshot_tracked(start, end, &snap);
		pb_handle_protect(&a);
		have_segs = pb_seg_snapshot(start, end, &segs);
		r = real_sys_pkey_mprotect(&a);
		pb_settle_tracked(start, end, pb_arg(&a, 2), r, &snap, &segs,
				  have_segs);
		pb_seg_free(&segs);
		ret = r;
		if (!ret) {
			end = (addr + len + PAGE_SIZE - 1) & PAGE_MASK;
			pb_armed_rearm(current->tgid, addr, len);
			if (prot_has_x_only(prot) || prot_has_wx(prot))
				pb_try_arm(addr, end, true);
		}
	}
	return ret;
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
 * follow.
 *
 * span_armed is decided for the whole destination span, not for this page.
 * 6.8 mremap needs uniform protection across the old range, so a span that
 * straddles data_lo/data_hi cannot be settled page by page: half PROT_NONE
 * and half restored is a split this module made itself, and the target's next
 * MREMAP_FIXED over it returns EFAULT where it succeeds unloaded, unmapping
 * the destination. A span that is armed keeps its records and stays
 * PROT_NONE, so the out-of-range page faults on its next access and
 * pb_handle_data restores it there; a span that is not armed gets its
 * recorded protection back, otherwise nothing would ever restore it.
 */
static void pb_armed_after_move(unsigned long from, unsigned long to, int keep,
				bool pre, bool span_armed)
{
	struct marea *entry, *tmp;
	unsigned long prot = 0;
	pid_t tgid = current->tgid;
	unsigned long want = pre ? to : from;
	bool found = false;

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
	 * Restore before forgetting, and outside the lock for the same reason
	 * as pb_handle_data: pb_mprotect wants mmap_write_lock, which the
	 * mmap hook already holds while taking marea_lock. Re-validate first,
	 * so a page re-armed with a different protection in the gap is not
	 * overwritten with the value we read before the move.
	 */
	if (found && keep && !span_armed && pb_armed_unchanged(tgid, want, prot)) {
		if (pb_mprotect(to, PAGE_SIZE, prot ? prot : PROT_READ))
			pr_warn("restore %lx prot=%lx failed\n", to, prot);
	}
	mutex_lock(&marea_lock);
	list_for_each_entry_safe(entry, tmp, &data_armed, list) {
		if (entry->tgid != tgid || entry->addr != want)
			continue;
		if (keep && span_armed) {
			/* still PROT_NONE at the new address, so the pin stays */
			entry->addr = to;
		} else {
			entry->restored = true;
			list_del(&entry->list);
			kfree(entry);
		}
		break;
	}
	/* A record just went away, so the pin may no longer be needed. Without
	 * this the last record dropped on the move path leaves the module
	 * reference held and rmmod refused for good. */
	pb_pin_update_locked();
	list_for_each_entry_safe(entry, tmp, &data_seen, list) {
		if (entry->tgid != tgid || entry->addr != from)
			continue;
		list_del(&entry->list);
		kfree(entry);
	}
	mutex_unlock(&marea_lock);
	if (found && keep && !span_armed)
		pb_mprotect(to, PAGE_SIZE, prot ? prot : PROT_READ);
}

static void pb_note_mremap(unsigned long old, unsigned long old_len,
			   unsigned long new, unsigned long new_len, bool pre)
{
	unsigned long old_pages = pb_page_count(old_len);
	unsigned long new_pages = pb_page_count(new_len);
	unsigned long settle = old_pages < new_pages ? old_pages : new_pages;
	unsigned long i;
	bool span_armed = false;

	old &= PAGE_MASK;
	new &= PAGE_MASK;
	for (i = 0; i < settle; i++) {
		unsigned long to = new + i * PAGE_SIZE;

		if (to >= data_lo && to < data_hi) {
			span_armed = true;
			break;
		}
	}
	for (i = 0; i < old_pages; i++) {
		struct marea *entry;
		unsigned long from = old + i * PAGE_SIZE;
		int keep = i < new_pages;

		pb_armed_after_move(from, new + i * PAGE_SIZE, keep, pre,
				    span_armed);
		mutex_lock(&marea_lock);
		entry = search_page(current->tgid, from);
		if (entry) {
			if (keep)
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
	/* Restore outside the lock, same reason as pb_handle_data, and only
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

static asmlinkage long fh_sys_mremap(struct pt_regs *regs)
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

	if (!pb_is_target())
		return real_sys_mremap(regs);
	/*
	 * MREMAP_FIXED names the destination now, so move every armed record
	 * ahead of the kernel move and change no protection while it runs. A
	 * page whose destination is outside the armed range is not settled
	 * here: an mprotect on one page of the source splits the source VMA,
	 * and mremap requires the old range to be a single mapping, so the
	 * kernel rejects the move with EFAULT. The record travels to the
	 * destination still describing a PROT_NONE page, and
	 * pb_armed_after_move restores it there once the page is there.
	 */
	if (flags & MREMAP_DONTUNMAP) {
		/*
		 * The kernel moves the pages and keeps the source VMA, with its
		 * protection. Relocating the record would leave the source
		 * PROT_NONE with nothing left to restore it, so every later access
		 * to the source is a SIGSEGV this module caused. Release the
		 * source first, as for a resizing move: both ends arrive
		 * accessible and the moved page is armed again by the next
		 * executable mprotect.
		 *
		 * DONTUNMAP always moves, even at the same size, so the size test
		 * below does not cover it. It also breaks the premise `extra
		 * maymove` checks, that a same-size move stays put.
		 */
		for (i = 0; i < n_pages; i++)
			pb_release_armed(tgid, old + (unsigned long)i * PAGE_SIZE);
	} else if (flags & MREMAP_FIXED) {
		/*
		 * The kernel unmaps whatever is at the destination before moving
		 * there. An armed record of that old mapping must not survive
		 * next to the one that arrives with the moved page: both would
		 * sit at the same address, and the old saved protection could be
		 * restored onto the new page, which is how a store to a
		 * read-only page came to be allowed. Release the destination
		 * first. If the syscall fails, those pages are merely accessible
		 * and get armed again later.
		 */
		for (i = 0; i < pb_page_count(new_len); i++)
			pb_release_armed(tgid, new_addr + (unsigned long)i * PAGE_SIZE);
		for (i = 0; i < n_pages; i++) {
			unsigned long to = new_addr + (unsigned long)i * PAGE_SIZE;
			unsigned long from = old + (unsigned long)i * PAGE_SIZE;

			moved += pb_relocate_armed(tgid, from, to);
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
	pb_note_mremap(old, old_len, (unsigned long)ret, new_len, pre);
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
	ret = real_sys_munmap(regs);
	if (!ret)
		pb_drop_user_range(current->tgid, addr, len);
	return ret;
}

static asmlinkage unsigned long (*real_vm_mmap_pgoff)(struct file *file,
		unsigned long addr, unsigned long len, unsigned long prot,
		unsigned long flag, unsigned long pgoff);

static asmlinkage unsigned long fh_vm_mmap_pgoff(struct file *file,
		unsigned long addr, unsigned long len, unsigned long prot,
		unsigned long flag, unsigned long pgoff)
{
	unsigned long ret;
	unsigned long intended;
	int n_pages;

	if (!pb_is_target())
		return real_vm_mmap_pgoff(file, addr, len, prot, flag, pgoff);

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
		 * Drop the old records for the range first, exactly as the
		 * non-W+X branch does. With MAP_FIXED the mapping replaces the
		 * old one, so any armed, seen or tracked record that survives
		 * describes pages that no longer exist: a store into the new
		 * mapping is then serviced by a record left over from before
		 * it, and the store is neither faulted nor traced.
		 */
		pb_drop_user_range(current->tgid, ret,
				   (unsigned long)n_pages * PAGE_SIZE);
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

static bool pb_ip_tracked(unsigned long ip, unsigned long *epoch)
{
	bool use_parent = !pb_tgid_own(current->tgid);
	pid_t parent;

	if (pb_ip_tracked_for(current->tgid, ip, epoch))
		return true;
	/*
	 * The immediate parent is not always the one that owns the records:
	 * a vfork intermediate was itself forked from a parent still inside
	 * its own copy, so it holds nothing. Walk to the nearest ancestor
	 * that does, or a grandchild's instruction pointer is judged against
	 * a tgid that has no record for it and the page is never traced.
	 */
	if (!use_parent)
		return false;
	parent = pb_records_tgid();
	return parent > 0 && pb_ip_tracked_for(parent, ip, epoch);
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

/*
 * The maximal run of armed pages around page that all record the same
 * protection, as one [lo, hi) span.
 *
 * 6.8 mremap needs uniform protection across the old range, so restoring
 * one page of an armed range is a split this module made itself: the
 * target's next MREMAP_FIXED over the range returns EFAULT where it
 * succeeds with the module unloaded, and the kernel unmaps the
 * destination on refusal. Restoring a whole run in one mprotect keeps the
 * range uniform, which is the design the restore-uniformity model holds
 * (run-uniform). The run stops at the first page whose record disagrees
 * or which has no record, so this never restores a page the module has no
 * record for.
 *
 * The records are read under marea_lock and the mprotect happens without
 * it, for the reason every other restore in this file has: pb_mprotect
 * wants mmap_write_lock, which the mmap hook takes before marea_lock.
 * Each page in the span is revalidated by the caller before it is
 * marked restored, and a page that changed underneath is simply not
 * marked, so a stale span costs a missed marker and not a wrong one.
 */
static void pb_armed_run(pid_t tgid, unsigned long page, unsigned long prot,
			 unsigned long *lo, unsigned long *hi)
{
	struct marea *seen;
	unsigned long a, b;

	*lo = page;
	*hi = page + PAGE_SIZE;

	mutex_lock(&marea_lock);
	a = page;
	while (a > data_lo) {
		a -= PAGE_SIZE;
		if (a < data_lo)
			break;
		seen = NULL;
		list_for_each_entry(seen, &data_armed, list) {
			if (seen->tgid == tgid && seen->addr == a)
				break;
		}
		if (!seen || seen->prot != prot)
			break;
		*lo = a;
	}
	b = page;
	for (;;) {
		b += PAGE_SIZE;
		if (b >= data_hi)
			break;
		seen = NULL;
		list_for_each_entry(seen, &data_armed, list) {
			if (seen->tgid == tgid && seen->addr == b)
				break;
		}
		if (!seen || seen->prot != prot)
			break;
		*hi = b + PAGE_SIZE;
	}
	mutex_unlock(&marea_lock);
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
	unsigned long run_lo, run_hi;
	pid_t tgid = current->tgid;
	pid_t parent;
	struct pt_regs *regs;
	struct marea *armed_entry;
	bool use_parent;
	bool tracked;
	bool armed;

	/*
	 * The record, not the range, decides ownership. An mremap can carry
	 * a page we made inaccessible out of the range, and only a record for
	 * it says so.
	 */
	/*
	 * The parent's armed records cover a fork child only in the window
	 * before pb_note_child has copied them. After the copy, or after an
	 * exec, the child's own records are the whole truth, and a PROT_NONE
	 * page of the child's own (a guard page, a GC barrier) must fault to
	 * the child's handler rather than be restored from the parent's
	 * record. So consult the parent only while this tgid owns nothing,
	 * and read own records first: once that reads true the copy is
	 * complete under marea_lock.
	 */
	use_parent = !pb_tgid_own(tgid);
	armed = pb_armed_prot_for(tgid, page, &restore);
	parent = use_parent ? pb_records_tgid() : 0;
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
	/*
	 * Restore the whole run of pages that record this same protection, in
	 * one mprotect, rather than the one page that faulted. One page would
	 * leave its neighbours PROT_NONE, and 6.8 mremap refuses a move whose
	 * old range is not uniform, so the target's own MREMAP_FIXED over the
	 * armed range would fail where it succeeds unloaded.
	 */
	pb_armed_run(tgid, page, restore, &run_lo, &run_hi);
	regs = kzalloc(sizeof(*regs), GFP_KERNEL);
	if (!regs)
		return 0;
	pb_set_arg(regs, 0, run_lo);
	pb_set_arg(regs, 1, run_hi - run_lo);
	pb_set_arg(regs, 2, restore);
	if (real_sys_mprotect(regs)) {
		kfree(regs);
		return 0;
	}
	kfree(regs);
	mutex_lock(&marea_lock);
	list_for_each_entry(armed_entry, &data_armed, list) {
		if (armed_entry->tgid != tgid || armed_entry->restored)
			continue;
		if (armed_entry->addr < run_lo || armed_entry->addr >= run_hi)
			continue;
		if (armed_entry->prot != restore)
			continue;
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

	/*
	 * A protection-key fault is not something a restore can fix: mprotect
	 * keeps the key, so the access would fault again and the loop would
	 * never end. Check it before either handler. Neither arch delivers a
	 * pkey fault through force_sig_fault on 6.8, so this is defensive.
	 */
	if (code == SEGV_PKUERR)
		return real_force_sig_fault(sig, code, addr);

	if (data_on && (pb_fault_is_read() || pb_fault_is_write()) &&
	    pb_handle_data(address))
		return 0;

	if (!pb_take_page(address, &page_addr, &new_prot))
		return real_force_sig_fault(sig, code, addr);

	/*
	 * A tracked page is not always one the module made W+X. Code that was
	 * only ever read-execute, such as an ELF text segment or a page the
	 * target set to PROT_READ|PROT_EXEC, is tracked too. Clearing
	 * PROT_EXEC from its saved protection leaves a page with no
	 * PROT_WRITE, the store faults again immediately, and the target
	 * spins instead of taking the SIGSEGV it asked for. Only a write the
	 * module itself forbade, by refusing the write bit on a W+X page, is
	 * ours to allow.
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
		pb_try_arm(0, 0, false);
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

static void pb_free_list(struct list_head *head)
{
	struct marea *entry, *tmp;

	list_for_each_entry_safe(entry, tmp, head, list) {
		list_del(&entry->list);
		kfree(entry);
	}
}

/*
 * Settling a failed mprotect.
 *
 * pb_handle_protect runs before the syscall and changes the tracked records.
 * If the syscall then fails, those changes stand even though nothing about the
 * mapping changed, so the module's records no longer describe the pages. On
 * 6.8 mprotect is not atomic: it applies protection to leading pages first, so
 * a failure can leave part of the range applied and part untouched, and the
 * records have to be settled to whichever it was rather than all-or-nothing.
 *
 * pb_snapshot_tracked takes the records before the syscall,
 * pb_seg_snapshot takes the protection the mappings actually have after it,
 * and pb_protect_done walks the VMAs to find how far the syscall got. Pages it
 * reached keep the new records; pages it did not are rolled back to the
 * snapshot. If the segments cannot be read, done stays at start and the whole
 * range is rolled back, which is the safe direction: a stale record is
 * corrected, whereas a dropped one loses a page from the epoch.
 */

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

static bool pb_vma_has(struct vm_area_struct *vma, unsigned long prot)
{
	long want = prot & (PROT_READ | PROT_WRITE | PROT_EXEC);
	long have = pb_vma_prot(vma);

	if (have == want)
		return true;
	return (current->personality & READ_IMPLIES_EXEC) && (want & PROT_READ) &&
	       (vma->vm_flags & VM_MAYEXEC) && have == (want | PROT_EXEC);
}

static void pb_protect_range(unsigned long addr, unsigned long len,
			     unsigned long *start, unsigned long *end)
{
	unsigned long alen = (len + PAGE_SIZE - 1) & PAGE_MASK;

	*start = addr & PAGE_MASK;
	*end = *start + alen;
	if (len && (!alen || *end <= *start))
		*end = ~0UL;
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

static void pb_seg_free(struct list_head *segs)
{
	struct pb_seg *seg, *tmp;

	list_for_each_entry_safe(seg, tmp, segs, list) {
		list_del(&seg->list);
		kfree(seg);
	}
}

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

/* How far the failed mprotect actually got. */
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
	bool tracked;
	long ret;
	pid_t tgid = current->tgid;
	LIST_HEAD(saved);

	tracked = pb_tgid_has(tgid);
	if (matched) {
		added = !tracked;
		pb_tgid_add(tgid, true);
		pb_move_tracked(&saved);
	}
	ret = real(regs);
	if (ret == 0 && (matched || tracked)) {
		pb_drop_data_state(tgid);
		if (!matched)
			pb_drop_marea(tgid);
	}
	if (matched && ret != 0 && added)
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

/*
 * Copy, and mark the child as owning its records, in one marea_lock hold.
 *
 * These must be atomic. If the copy and the mark were separate, a thread
 * could fork a grandchild in between, see the mark unset, and decide the
 * child holds nothing worth copying from, when in fact the copy had already
 * landed. pb_do_exec sets the same mark under the same lock before an exec,
 * and makes this copy itself then, so a mark that is already set means the
 * child has its copy and this one must not copy over it.
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
 * Look the child up and keep a reference to it across the copy.
 *
 * pb_note_child checks liveness, copies, then checks again. Releasing the
 * reference between the two checks lets the pid be reused in that window, so
 * the second check can be looking at a different task entirely, and a recycled
 * pid inherits records it never asked for. Holding one reference for the whole
 * sequence pins the task the bookkeeping is about.
 *
 * fork and clone return the child's pid in the *caller's* pid namespace. Every
 * record is keyed on the global tgid, so the task is looked up here and the
 * child keyed on task_tgid_nr(). In a container the two numbers differ, and
 * keying on the returned pid records the child under the wrong tgid.
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
 * Whether the thread group still has a live thread.
 *
 * live counts the group's threads. Checking one task's PF_EXITING instead is
 * wrong for a group: a thread that has begun exiting is not the same as a
 * group that has finished, and two threads of one group can each judge the
 * other already gone and both skip the cleanup.
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
	 * The child runs as soon as the fork returns and can exit before this
	 * bookkeeping. Registering a tgid that is already gone leaves its
	 * records behind for whoever reuses that pid. The group's last thread
	 * brings live to 0 before the exit hook takes marea_lock to clean up,
	 * so a live of 0 here means that cleanup either already ran, or runs
	 * after this copy and removes it. Either way the child ends with no
	 * records rather than with records nobody will ever drop. The task
	 * reference held across both checks keeps the second one on the same
	 * task even if its pid number has been reused.
	 */
	if (pb_group_alive(task)) {
		pid_t from = current->tgid;


		/*
		 * A parent still waiting for its own copy holds no records, so
		 * copy from the ancestor that it is waiting on.
		 */
		if (!pb_tgid_own(from)) {
			pid_t up = pb_records_tgid();

			if (up > 0)
				from = up;
		}
		pb_tgid_add(tgid, false);
		pb_copy_tracking(from, tgid);
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
 * exit_group could both read 2 and neither drop the tgid, so a child's
 * records outlived it and the next process to reuse that pid inherited
 * them. Here every exiting thread has already decremented, so live == 0
 * means the whole group is dead, and the last thread to decrement always
 * sees it. More than one thread may see 0; the drops are idempotent. The
 * tgid cannot be reused yet, because the leader is reaped only after
 * exit_notify.
 *
 * exit_files is also called by copy_process on a failed fork, for a task
 * that is not current, so that call is skipped.
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

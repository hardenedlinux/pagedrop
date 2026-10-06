# Bug fixes

Confirmed defects in `pagedrop.c`, and the checks that caught them. Trace validation was not used. Model checks used the TLC jar already in `../Specula/lib`.

## `exact=1` did not apply to `comm`

`pb_is_target` still used `strstr` on `current->comm`. `exact=1` only affected the exec pathname check, so a shorter token still tracked the process.

Fix: the comm check calls `pb_name_matches`. The suite loads `path=extr exact=1` and requires `extra epoch` to miss, then `path=extra exact=1` to pass.

## A data read was logged on every fault

`pb_handle_data` appended `ip data_va epoch` after every swallowed read. If the page had already been dumped for that handler epoch, `epoch` was 0.

Fix: append one line, and only after a successful dump. The epoch is the handler epoch. `extra read` still passes.

## `data=` stopped after the first armed page

The first successful `PROT_NONE` set a process-wide flag. A page mapped later in the range was never armed. A successful exec left the flag set, so the next image was not armed either.

Fix: remember each armed page. Retry pages that are not mapped yet. Clear that state on successful exec.

## `fork` killed a child on an armed data page

`data=` sets the range to `PROT_NONE`. `fork` recorded the child tgid and did not copy the tracked-page list. The child inherited the protection. The fault hook did not restore the page, because the child's instruction pointer was not in its own list, and delivered `SIGSEGV`.

TLC trace: Arm, Fork, ChildRead, `dead = TRUE`. On the x86 guest, `/tmp/forkarm` printed `child exit 0` with the module unloaded and `child signal 11` with `path=forkarm data=260000000-260001000`.

Fix: copy the parent's tracked pages and armed-data list to the child. Restore an armed data page even when the faulting instruction is not in the tracked list. `extra forkread` covers this on both arches.

## A non-matching exec left tracked pages behind

A tracked process that execs a path which does not match keeps its tgid. The old page list was dropped only when the new path matched. The new address space does not contain those pages. An instruction fault at an old address still matched the list. `mprotect` failed, and the hook returned 0, so the fault retried until `SIGALRM`.

Exit deleted the tgid record and left the same list. A reused tgid could attach those pages to the next process.

TLC trace: Track, ExecOther, Jump, `hung = TRUE`. Before the fix, `path=staleexec` exited 139 (`SIGSEGV`) with the module unloaded and 142 (`SIGALRM`) with it loaded.

Fix: drop that tgid's pages on a non-matching exec and on exit. If `mprotect` fails in the fault hook, deliver the signal. `extra stale` must die with `SIGSEGV` (exit 139), not hang.

## Arming a read-only page made it writable

`pb_handle_data` restored every armed page as `PROT_READ|PROT_WRITE`. A `PROT_READ` page in `data=` was set to `PROT_NONE`, then came back writable after the read fault. A later store succeeded.

TLC trace: Arm, Read, Write, `wrote = TRUE`. On the x86 guest, `/tmp/roarm` exited 3 with the module unloaded (the write faulted) and printed `write 1` with `path=roarm data=260000000-260001000`.

Fix: save the VMA's read/write bits when arming, and restore those bits. `extra roarm` requires the following store to fault. Both full suites passed after this fix.

## `mremap` left an armed page inaccessible

`data=` sets a page to `PROT_NONE` and records that address. `mremap` moved the mapping and left the record at the old address. A read at the new address was not restored. Outside the `data=` range the fault hook ignored it, so the process died with `SIGSEGV`.

TLC trace: Arm, Move, Read, `dead = TRUE`. On the x86 guest, `/tmp/moveread` printed `moved B` with the module unloaded and exited 3 with `path=moveread data=260000000-260001000`.

Fix: move the armed record when the new address is still in range, and restore the saved protection when it is not. `extra moveread` covers both, with `data=260000000-260001000` and `data=260000000-280000000`.

## `munmap` left the armed record behind

`data=` records a page and sets it to `PROT_NONE`. `munmap` removed the mapping and left that record. A new mapping at the same address was not armed again, because the next arm attempt skipped an address already on the list. The new bytes were read with no fault and no trace line.

TLC trace: Arm, Unmap, Remap, TryArm, Read, `missed = TRUE`. `/tmp/rearm` printed `trace 1` and exited 2, twice on x86 `6.8.0-101-generic` and twice on arm64 `6.6.62+rpt-rpi-v8`.

Fix: `munmap`, and a replacing `mmap`, drop armed, seen, and tracked entries for that range. `extra rearm` passed twice on each arch, then the full suite once on both.

## A store into an armed page was not restored

`data=` makes the page inaccessible and the fault hook restores it only on a read. A store is a write fault. The hook delivered `SIGSEGV` even when the saved protection included write.

TLC trace: Arm, Write, `dead = TRUE`. `/tmp/wrarm` exited 3, twice on x86 `6.8.0-101-generic` and twice on arm64 `6.6.62+rpt-rpi-v8`.

Fix: a write fault on an armed page is restored too, but only if the saved protection includes write. A write to a page that was read-only still faults. `extra wrarm` and `extra roarm` passed twice on each arch, then the full suite once on both.

## Making an armed page executable dumped nothing

`data=` sets the page to `PROT_NONE`. A later `mprotect` to execute dumps the page before that protection is installed. `copy_from_user` fails, so the marker never reaches a dump.

TLC trace: Arm, MprotectX, `missed = TRUE`. `/tmp/noneexec` printed `dump 0` and exited 2, twice on x86 `6.8.0-101-generic` and twice on arm64 `6.6.62+rpt-rpi-v8`.

Fix: if the range is armed, restore a readable protection before the dump. `extra noneexec` passed twice on each arch, then the full suite once on both.

## `mprotect` left the armed record behind

`data=` records a page and sets it to `PROT_NONE`. A later `mprotect` of that page changed its protection but left the record. The next arm attempt skipped an address already on the list, so the page was never made inaccessible again and nothing was traced.

TLC trace: Arm, MprotectW, TryArm, Read, `missed = TRUE`. `/tmp/disarm` printed `trace 0` and exited 2, twice on x86 `6.8.0-101-generic` and twice on arm64 `6.6.62+rpt-rpi-v8`.

Fix: any `mprotect` drops armed and seen records for that range, so the next arm attempt re-arms a non-executable page. `extra disarm` passed twice on each arch, then the full suite once on both.

## A forked child could fault before the parent finished the copy

`real_sys_fork` returns in the parent and in the child. The parent's `pb_note_child` copies the tracked pages and armed records into the child tgid, but it runs after the fork has already returned. A child that reads an armed page in that window has no record of its own, so `pb_handle_data` found nothing, returned 0, and the real `SIGSEGV` was delivered. The child died.

Observed once: an x86 suite run reported `forkread: child died`. It did not recur in 30 standalone `forkread` runs, three ordered `read` then `forkread` sequences, or two later full suites on both arches.

Fix: a data fault also consults the parent tgid's armed record and tracked page, which is correct because `fork` shares the page tables. `extra forkrace` runs 200 fork-and-fault children per invocation and is now part of both suites.

What was not shown: `forkrace` passes 200 iterations both with and without the parent fallback, because the test waits for each child, so the parent always wins the lock. The fix rests on the code reading and the one observed failure, not on a reproducing test. If the failure returns, this fallback is the first thing to check.

Modelled in a TLA+ spec kept locally and not committed; see `AGENTS.md`. With `useParent = FALSE` the fault handler consults only the child tgid and TLC reports the counterexample Fork, ChildFault, `sigdeliv_child = TRUE`, with no copy in between. With `useParent = TRUE` the property holds over the whole state space. That is the evidence the window is real and the fallback closes it.

## A child's records survived the child's own exit

`pb_note_child` runs in the parent after the fork: `pb_tgid_add`, then `pb_copy_tracking`. The child can run and exit in between. Its `do_exit` drops records that do not exist yet, and the parent then registers a tgid that is already dead and copies pages into it. That tgid stays in the tracking list, so a later process that reuses that pid is treated as a target and inherits stale pages. This is the exit-leak class above, on the child side, and it was introduced by the `fork` fix.

Modelled in a TLA+ spec kept locally and not committed; see `AGENTS.md`. Property `EventualClear`, with weak fairness on the cleanup so stuttering cannot starve it. `useFix = FALSE` reproduces the shipped order and TLC reports `Temporal property EventualClear was violated` on Fork, TgidAdd, CopyBegin, CopyLand, ChildExit, with the tgid still registered and the records still copied. `useFix = TRUE` satisfies the property.

Fix: do not register a tgid whose task has already exited, and drop the records again if the child died while the copy ran. `pb_child_alive` uses `find_vpid` and `get_pid_task`. Both suites pass, including `extra forkrace` and `extra pair`.

## Two threads could dump the same data page twice

`pb_handle_data` tested `data_seen`, then ran `dump_to_file` with no lock held, then added the record. The test and the insert were not one critical section, so two threads faulting the same armed page in the same handler epoch could both observe an empty list, both dump, and both write a trace line. That breaks the documented "dumped once per handler epoch" and gives `pb_rank` two index rows for one address.

Modelled in a TLA+ spec kept locally and not committed; see `AGENTS.md`. TLC reports Seen1, Seen2, Dump1, Dump2, Dump1Done, Dump2Done, with `dumps = 2` and `traces = 2`, violating `Safe`.

Reproduced on x86 `6.8.0-101-generic`: 8 threads released from a barrier onto one armed page produced 2 trace lines in 8 of 8 runs. Four threads produced 1. The count grows with the thread count, which is the signature of a lost update rather than a coincidence.

Fix: `pb_data_claim` tests and inserts under one `marea_lock` hold, and `pb_data_unclaim` releases the claim if the dump then fails, so a later fault can retry. `extra dumprace` requires exactly one trace line from 8 barriered threads. It failed 8 of 8 before the fix and passed 4 of 4 on x86 and 3 of 3 on arm64 after it, with the full suite passing on both.

## A reader could take a real SIGSEGV while the module was arming or disarming

`data=` deliberately makes a page inaccessible so the fault reveals which handler consumed it. Both the arming and the disarming had a window where the page was `PROT_NONE` with no armed record. `pb_handle_data` found nothing and returned 0, so `fh_force_sig_fault` fell through to the real handler and the process took a signal that the module had caused itself.

Two windows, both in the shipped code:

- Arming: `pb_arm_range` called `pb_mprotect(PROT_NONE)` and only then added the record.
- Disarming: `pb_disarm_range`, reached from any `mprotect` overlapping the range, deleted the record while the page was still `PROT_NONE`, and the real `mprotect` had not run yet.

Modelled in a TLA+ spec kept locally and not committed; see `AGENTS.md`. The shipped order violates `Safe` with `ProtNoneUnrecorded` then `Read` and `dead = TRUE`. Recording first, `armFirst = TRUE`, holds.

Reproduced on both arches with one thread re-arming in a loop and one thread reading: `SIGSEGV` in 4 of 5 runs on x86 `6.8.0-101-generic` and 4 of 5 on arm64 `6.6.62+rpt-rpi-v8`. As a suite case, `extra armrace` failed 5 of 15 before the fix and 0 of 15 after.

Fix, in three parts:

Fix, in three parts.

- `pb_armed_claim` inserts the record under `marea_lock` before the page is made inaccessible, and `pb_armed_unclaim` removes it again if the `mprotect` fails. The record now outlives the protection it explains, in the arm direction.
- `pb_disarm_range` restores each page to its saved protection first and deletes the records in a second pass, so the reverse also never leaves an unowned `PROT_NONE` page.
- `pb_handle_data` is convergent. With no record it asks `pb_page_satisfies` whether the faulting access is already legal, which is what a racing thread's restore or remap leaves behind. Legal means swallow, otherwise deliver the signal. This also stops a fault that was already resolved from turning into a crash.

A note on the count: `armrace` sometimes reports two trace lines and that is correct. The reloader advances the handler epoch on each `mprotect`, and the module promises one dump per handler epoch, so a second epoch legitimately dumps again. The defect is the crash, not the count.

## Unloading the module stranded pages it had made inaccessible

`data=` works by making a page `PROT_NONE`, and the only thing that can turn it back is this module's own fault handler, running inside the target process. `fh_exit` freed the records and restored nothing, and it could not: `module_exit` runs in the process doing the removal, and `mprotect` only affects the caller's address space. So after `rmmod`, a process holding an armed page took `SIGSEGV` on its next access to that address, a signal the module had caused itself.

Reproduced on x86 `6.8.0-101-generic` with a `mkfifo` gate so the read happens only after the module is confirmed gone: the page is `---p` in `/proc/self/maps` while loaded, `rmmod` returns 0 with `refcnt 0` and `unloaded` in `dmesg`, the page is still `---p`, and the read faults. The target can rescue the page with its own `mprotect`, so this is an unhandled signal, not lost data and not an unrecoverable process. Not reproduced on arm64.

Getting this wrong cost real time. The first several attempts concluded the opposite, that the page was fine after unload, and the reason was the harness: the child did `open()` on a gate file that did not exist yet, so the open failed, the wait was skipped, and the read happened while the module was still loaded, where the module correctly restored the page. Use a FIFO and block on `read()`; a plain file is not a gate. The test must also confirm the module is really gone, with `lsmod` and `dmesg`, before the read.

Fix: while any armed record still describes a page that is `PROT_NONE`, the module holds a reference to itself, so `rmmod` returns `-EBUSY` and the fault handler stays available. Three deliberate choices:

- State is a per-record `restored` flag, not a counter. A counter leaks in two opposite directions: too high and the module is never removable, too low and this stranding bug returns silently. The first version of the work item leaked permanently by leaving the queued flag set when it found a page still inaccessible, so no later release could ever be queued, and clearing the Pi needed a reboot. arm64 caught that on the first run.
- The reference is dropped from a work item, never from a hook. If the last `module_put` ran inside the fault handler, `module_exit` would execute on the fault path, call `pb_remove_hooks`, and free the module text the handler is still running in.
- The pin is taken before `PROT_NONE` is set, so there is never an instant where a page is inaccessible and the module is removable.

Modelled locally, listed in `AGENTS.md`: `hookdrop` violates `NoStrand`, `leak` violates `NoLeak`, and the shipped configuration holds both. `extra pin` asserts `rmmod` is refused while a page is held and `extra pinoff` asserts it is permitted after a read. Both suites pass on x86 and arm64.

One accepted cost: the release is asynchronous, so `rmmod` can be refused for a moment after the last armed page has gone. Scripts that remove the module immediately after a target exits may need to retry. That is the price of not dropping the reference from a hook.

## `mremap` moved an armed page into a window with no record

`fh_sys_mremap` called `real_sys_mremap` first, so the kernel moved the page while it was still `PROT_NONE`, and only afterwards did `pb_note_mremap` move the armed record. In between, the page sat at its new address, inaccessible, with the record still filed under the old one. `pb_handle_data` found nothing, and the reader took a real `SIGSEGV`.

The settle step had the mirror-image defect: for a destination outside the armed range it deleted the record and only then restored the protection, so it also left an inaccessible page with no record.

Modelled in a TLA+ spec kept locally and not committed; see `AGENTS.md`. The shipped order violates `Safe` with `MovePage` then `Read` and `dead = TRUE`; moving the record first, `moveRecordFirst = TRUE`, holds.

Reproduced with a reader spinning on a destination that is kept mapped by a shadow page, so a fault there can only be the module's. 8 of 8 failures on x86, and the control without the module survived 3 of 3.

Fix, in three parts:

- A page we armed is ours wherever it now lives, so `pb_handle_data` consults the record before the range test. A moved page can legitimately sit outside `data=`, and the record is what says it is ours.
- `MREMAP_FIXED` names the destination before the syscall. A page whose destination stays in range has its record relocated ahead of the move, and moved back if the syscall fails. A page whose destination leaves the range is released by `pb_release_armed`, which restores the protection and only then drops the record, so it arrives accessible and needs no record.
- The same restore-before-forget order as `pb_disarm_range`.

`extra mremaprace` covers it. It failed 8 of 8 before the fix and 0 of 25 after, with both suites passing on x86 and arm64.

Still open, and it needs its own test: `mremap` without `MREMAP_FIXED` still has the window. The kernel picks the destination, so the record cannot be placed ahead of the move. Only the record can be consulted afterwards, which is too late for a reader that already faulted.

## Note on the `MREMAP_MAYMOVE` window above, not a separate bug

The entry above calls the non-`FIXED` window open. That is right about the ordering and wrong about how often it can bite, and the difference is worth recording.

Measured on 6.8.0-101-generic: a same-size `MREMAP_MAYMOVE` does not move anything. Every page tested came back at its original address, so the record was never misplaced and there is no window at all. A move only happens when the size changes and the neighbouring pages are occupied; that case does relocate, into the mmap area.

So no crash was reproduced. Two attempts failed and both are recorded rather than quietly dropped. Forcing a relocation and scanning the whole mmap region from a second thread, with a signal handler that tells a module-caused fault apart from a fault on a plain unmapped address, produced no failure with or without the module. The window is real in the ordering but too narrow to hit from user space.

Hardening, not a bug fix: when `MREMAP_FIXED` is absent and `old_len != new_len`, the armed pages are released before the syscall, so they arrive accessible and need no record. The same-size case is left alone, because releasing there would drop arming for a call that does not move anything. The size-change guard is empirical, taken from the measurement above on this kernel; a kernel that relocates on a same-size move would need the guard widened. The cost when it does fire is that a relocated page is not re-armed until the next executable `mprotect`. Both suites pass on x86 and arm64.

Do not count this as a confirmed bug. It has no reproduction.

A third attempt failed too, and the reason is worth keeping because it closes the question rather than leaving it open. The reader has to be sitting on the destination at the moment the window opens, and the destination is never knowable in advance:

- A sweep is useless. It spends its time faulting over addresses nothing is mapped at, while all the moves complete in microseconds, so it never overlaps the window.
- The destinations look like they step down by a constant stride, so predicting the next one looks attractive. It is not reliable: the gap varies, and a prediction check caught the kernel choosing a different address at the third move.
- Hammering the recently used destinations fails because the kernel always places the next one at a new, lower address, never a repeat. No previously used address is ever the next destination.

With the hardening deliberately disabled, the test still reported zero hits. So on this kernel the window is below what a user space test can reach. That is a stronger statement than "we failed to find a test", and it means the honest conclusion is that the hardening is unfalsifiable by test here rather than merely untested.

What replaced the missing test is a check of the assumption the guard actually rests on. `extra maymove` now asserts that a same-size `MREMAP_MAYMOVE` does not relocate, and fails with a clear message if it ever does, because that is exactly the condition under which `fh_sys_mremap` stops releasing pages and the window reopens. It passes on x86 and arm64. The guard is now tied to a checked premise rather than to a comment.
## Holding `marea_lock` across `mprotect` deadlocked against the mmap hook

Two paths took the two locks in opposite orders.

- `fh_vm_mmap_pgoff` is an internal kernel hook. The kernel calls it with `mmap_write_lock` already held, and the hook calls `pb_drop_user_range`, which takes `marea_lock`. So `mmap_write_lock` is held while `marea_lock` is wanted.
- `pb_disarm_range`, `pb_armed_after_move` and `pb_release_armed` held `marea_lock` across `pb_mprotect`, which reaches the real mprotect and wants `mmap_write_lock`. So `marea_lock` was held while `mmap_write_lock` was wanted.

That is ABBA. One thread in the restore path and one thread in a plain `mmap` deadlocks, with the two locks held and both waits outstanding.

Modelled in a TLA+ spec kept locally and not committed; see `AGENTS.md`. `heldLock = FALSE`, the shipped nesting, violates `Safe` with A holding `marea` waiting for `mmap` and B holding `mmap` waiting for `marea`. `heldLock = TRUE` holds.

The suite did not catch this. No case in 47 deadlocked, because the interleaving needs one thread restoring while another maps.

Fix: no path holds `marea_lock` across `pb_mprotect` any more. Each of the three collects the record under the lock, restores with the lock released, then drops the record. The record still outlives the restore, so a reader that faults in that gap finds one and is handled, and a restore that lands on a page a reader already fixed is the same protection. Both suites pass.

## A data page is only ever traced once, not once per handler epoch

Not a crash, and not fixed. The contract in `README.md` and in the fix for "a data read was logged on every fault" says one dump per handler epoch. The code does one per data page, for the life of the process.

A read fault restores the page but leaves the armed record in place, so `pb_arm_range` skips it for ever. The page stays readable, no later read faults, the hook is never entered, and no trace line is written at any later epoch. Only a `munmap`, a replacing `mmap` or an `mprotect` over the data page clears the record.

Measured on x86 `6.8.0-101-generic`: arm, read once, re-`mprotect` the code page so it is dumped again and its epoch advances, read the same address. One trace line, not two. Clean trace and module unloaded, zero lines.

Modelled in a TLA+ spec kept locally and not committed; see `AGENTS.md`. The shipped behaviour violates the property on Arm, Read, AdvanceEpoch, ReadStale; re-arming on epoch change holds.

Left unfixed on purpose. Re-arming a stale record costs a fault per bytecode read rather than one per page, and every re-arm reintroduces the arming-window class of bug that caused the earlier `SIGSEGV` fixes. The decision and the options are documented in `AGENTS.md`.

## Double validation of the fixes above, not a bug

Each of these was run twice on the pre-fix module (`5257f3a`) and twice on the fixed module, on both x86 `6.8.0-101-generic` and arm64 `6.6.62+rpt-rpi-v8`.

| Case | Bug, twice | Fix, twice |
|---|---|---|
| `exact=1` | `path=extr` still tracked (`epoch` exit 0) | miss, then `path=extra` exit 0 |
| `fork` | `forkread` exit 1 | exit 0 |
| read-only arm | `roarm` exit 1 | exit 0 |
| `mremap` | `moveread` exit 1 | exit 0 outside the range, and again inside `260000000-280000000` |
| non-matching exec | `stale` exit 142 | exit 139 |

The trace-line bug and the arm-once flag were fixed from inspection. `extra read` passed twice on the fixed module on both arches. Their original failure mode was not replayed as its own double run.

## Two exiting threads could both skip the exit cleanup

`fh_do_exit` dropped the tgid and its records when `signal->live <= 1`, but it read `live` on entry to `do_exit`, before the kernel decrements it. In an `exit_group` the remaining threads run `do_exit` concurrently. Two of them can both read 2, and neither cleans up. The tgid stays in the list with its tracked and armed records, and a later process that reuses that pid is treated as a target with stale pages. This is the exit-leak class above, on the multithreaded side.

Fix: the cleanup moved to a hook on `exit_files`. `do_exit` sets `PF_EXITING`, then decrements `live`, then calls `exit_files`, so there `live == 0` means every thread has decremented, and the last one to do so always sees it. More than one thread can see 0. The drops are idempotent. The tgid cannot be reused yet, because the leader is only reaped after `exit_notify`. `copy_process` also calls `exit_files` on a failed fork, for a task that is not `current`, and that call is skipped. The hook count is still 13. `do_exit` is no longer hooked.

This also closes the gap left in `pb_child_alive`: the old hook cleaned up before `PF_EXITING` was set, so a child that exited during the parent's copy could still be missed. Cleanup now always follows the group's last `live` decrement, which is what `pb_note_child` checks; see the liveness entry below.

Found by code review, against the call order in `kernel/exit.c` on 6.18. Not reproduced, and there is no suite case: nothing outside the module can see the tgid list.

## A child in another pid namespace was recorded under the wrong tgid

`fork` and `clone` return the child's pid in the caller's pid namespace. `pb_note_child` passed that number to `pb_tgid_add` and `pb_copy_tracking`, but every record is matched against `current->tgid`, which is the global number. Inside a container the two differ. The child got no records of its own, and a host process whose global pid happened to equal the child's namespace pid became a target, with the parent's pages copied to it.

`pb_child_alive` already looked the number up with `find_vpid`, so the lookup was namespace-aware and only the key was wrong. `find_vpid` was also called without `rcu_read_lock`.

Fix: `pb_child_task` resolves the child with `find_get_pid` and `get_pid_task` and keys it on `task_tgid_nr`. `pb_note_child` holds that task across both liveness checks, so the second check cannot land on a reused pid. The checks look at the task's thread group, not the task; see the liveness entry below. The index records the global tgid, which the README now says.

Found by code review. Not reproduced. The parent-tgid fallback in the fault path hides the missing child records while the parent is alive, so a plain `unshare -p` run of `forkread` would pass before and after.

## `mprotect` handed the caller a changed prot register

The W^X rewrite cleared `PROT_WRITE` with `pb_set_arg(regs, 2, ...)` on the `pt_regs` the kernel restores on return to user space. That is `rdx` on x86_64 and `x2` on arm64, and the syscall ABI preserves both. After `mprotect(RWX)` the caller saw `PROT_READ|PROT_EXEC` there. Code that issues the syscall inline and reuses the register, which is what packer stubs do, got the wrong value. It also gave the module away to any sample that compares the register before and after. The original PageBuster did the same with `regs->dx`. The arm64 port carried it over.

Fix: `fh_sys_mprotect` and `fh_sys_pkey_mprotect` copy `pt_regs` and pass the copy to the real syscall. `pb_mprotect` and the fault path already built their own `pt_regs`.

`extra regs` issues a raw `mprotect(RWX)` and requires the register to come back unchanged. It is in both suites. It passes on x86 with the module unloaded, and with the module loaded on arm64 and x86 (see "Loaded-module runs"). Both modules also compile: x86 against 6.18 with `-Werror`, arm64 against a 6.18 `defconfig` tree, compile only.

## A vfork child got the parent's records after its exec

`pb_note_child` runs in the parent once `fork`, `vfork` or `clone` returns. After `vfork`, and after `clone` with `CLONE_VFORK` as `posix_spawn` uses, the parent only resumes once the child has exec'd. So the copy always landed in the new image, which has none of the parent's pages. That is the stale-record case of the non-matching exec entry above, brought back by the fork copy. A later fault in the child at one of those addresses, such as a guard page of its own, matched the parent's record and was swallowed. A plain `fork` child that execs quickly could hit it too, if the copy landed inside its `execve`.

Fix: each listed tgid has an `own` flag, meaning its records are its own. `pb_do_exec` sets it under `marea_lock` before the exec, for a matching path, a tracked tgid, or a child of a tracked process. `pb_copy_tracking` copies and sets the flag in one `marea_lock` hold, and copies nothing if the flag is already set. Either the copy came first, and the exec's drop removes it, or the exec came first, and nothing is copied. The exec also does the parent's copy itself, in the same hold, so a failed exec keeps what the child inherited; see the failed-exec entry below.

Found by code review. There is no deterministic test for the copy alone: a page the new image maps itself goes through the `vm_mmap_pgoff` hook, which drops the copied record if the copy landed first. `extra execguard`, below, covers it together with the next entry.

## The parent's records covered a child for its whole life

The `fork` window fix let a data fault in the child fall back to the parent's armed record, and `pb_ip_tracked` fall back to the parent's tracked pages. It was meant for the window before `pb_note_child` has copied the records. It was consulted on every fault, for as long as the child lived, and also after the child exec'd, which undid the non-matching exec fix. A child that made its own `PROT_NONE` page at an address the parent armed, and read it expecting its own handler to run, had the page restored to the parent's saved protection and the fault swallowed.

The entry that added the fallback says it is correct because `fork` shares the page tables. It does not. `fork` copies the VMAs, protection included, and shares the pages copy-on-write. That is why the parent's record describes the child's page right after the fork, and also why it stops describing it once the child changes its own mappings.

Fix: the fallback is taken only while the child's `own` flag is clear, which is the window before the copy. `pb_handle_data` and `pb_ip_tracked` read the flag before looking at the child's own records. Once the flag reads true, the copy it was set with is complete, because both are done in one `marea_lock` hold. A fault that reads it false still finds the parent's record. A top-level target, one whose parent is not tracked, owns its records from the start. A fork child that matches by name does not, because it inherits the parent's `comm`.

`extra execguard` arms `READ_DATA`, then `vfork`s and execs itself as `guardchild`. The child maps its own `PROT_NONE` page at `READ_DATA`, and requires its read to reach its own handler. It passes with the module unloaded. It passes with the module loaded on arm64 and x86.

## A `comm` with spaces broke `pb_rank`, and a newline could forge an index line

`dump_to_file` wrote `current->comm` into `/tmp/pagedrop.index` as is. The program controls `comm` through `prctl(PR_SET_NAME)` or the name it execs. `pb_rank.py` splits each line on whitespace and requires five fields, so one rename with a space stopped ranking for the whole index. A newline in `comm` could also start a line of the sample's choosing, within the 15 bytes `comm` allows. The module already wrote `-` for an empty `comm`, to keep the field count. Whitespace was not considered.

Fix: `pb_index_comm` writes whitespace and control bytes as `_`. `pb_rank.py` takes `comm` as whatever lies between the first field and the last three, so an index written by an older module still parses. `test_pb_rank.py` now has a row whose `comm` contains a space. That test fails against the old `pb_rank.py` and passes against the new one. `extra commname` renames itself to `ex tra\nx` and dumps a page, and both suites require every index line to have five fields and that dump to show `ex_tra_x`. It passes with the module loaded on arm64 and x86.

## `MREMAP_DONTUNMAP` left an armed source inaccessible for good

`fh_sys_mremap` did not know `MREMAP_DONTUNMAP`. With it, the kernel moves the pages and keeps the source VMA, protection included: on 6.18, `dontunmap_complete` only clears `VM_LOCKED`. An armed source stayed `PROT_NONE`, and its record went with the page to the destination. Every later access to the source got a `SIGSEGV` that the module caused. Without the module, that access is legal: it reads zero-filled memory, or is served by `userfaultfd`. This is not a race. It happens on every such call.

It also broke the premise that `extra maymove` checks, that a same-size `MREMAP_MAYMOVE` does not move. `MREMAP_DONTUNMAP` requires the same size and always moves.

Fix: on `MREMAP_DONTUNMAP`, every armed source page is released before the syscall, as for a resizing move. Both ends arrive accessible, and the moved page is re-armed by the next executable `mprotect`. A tracked executable page keeps its record at the source and gets a copy at the destination, because it is now mapped at both.

Found by code review, against `mm/mremap.c` on 6.18. `extra dontunmap` arms `READ_DATA`, moves it with `MREMAP_DONTUNMAP`, and requires both the destination and the source to read without a fault. It passes with the module unloaded. It passes with the module loaded on arm64 and x86.

## Known limitation: `MREMAP_FIXED` leaves a window on the source

To close the destination window above, `fh_sys_mremap` relocates the armed record to the destination before the kernel moves the page. From then until the move, the source is still `PROT_NONE` and has no record. A read of the source in that window gets a `SIGSEGV`.

This is the same shape as the destination window, on the other side, and it breaks the rule that a `PROT_NONE` page we made always has a record. It is left as is. Without the module, the source is unmapped as soon as the move completes. A program that reads the source while its own `mremap` moves it is already racing, and gets a `SIGSEGV` whenever the read lands after the move. The module only widens a window the program already has. It is noted in `fh_sys_mremap`.

## A store to read-execute code faulted forever

A tracked page is not always a W+X page the module made read-execute. Code that was only ever read-execute, such as an ELF text segment or a page the program set to `PROT_READ|PROT_EXEC`, is tracked too. On a write fault, `fh_force_sig_fault` cleared `PROT_EXEC` from the saved protection, applied the result, and swallowed the signal. With no `PROT_WRITE` in the saved protection, the page became read-only, the same store faulted again, and the program spun instead of receiving its `SIGSEGV`. The original PageBuster did the same.

Fix: a write fault on a tracked page whose saved protection has no `PROT_WRITE` goes to the real handler. So does a fault with `SEGV_PKUERR`, because `mprotect` keeps the protection key and the access would fault again. On 6.18 neither architecture sends a pkey fault through `force_sig_fault`, so that check is defensive.

`extra rowrite` makes a page read-execute, stores to it, and requires its handler to run within 3 seconds. It passes with the module unloaded. It passes with the module loaded on arm64 and x86.

## A fork child's W^X store had no parent fallback

The fork-window fallback covered `pb_handle_data` and `pb_ip_tracked`, but not `pb_take_page`, which the W^X fault path uses. A child that stored to an inherited RWX page before the parent copied the records found no record of its own. The module had made that page read-execute, and the child got a `SIGSEGV`.

Fix: `pb_take_page` falls back to the parent's record under the same rule as the data path. Only while the child's `own` flag is clear, and only after reading it first.

`extra vforkwrite` makes the window deterministic. After `vfork` the parent runs `pb_note_child` only once the child has exited, so the child's store to the parent's RWX page always comes before any copy. The child must exit normally, and the parent must see the store. It passes with the module unloaded. It passes with the module loaded on arm64 and x86.

## A failed exec could cost a fork child its records for good

The `own` fix above set the flag before the exec and cleared it again if the exec failed. A parent that ran `pb_note_child` in between saw the flag, skipped its copy, and never came back. The child, still in the parent's image, was left with no records. It relied on the parent fallback until the parent exited or dropped its record. After that, a read of an inherited armed page was a `SIGSEGV`. This was introduced by that fix.

A first fix copied from the parent when the exec failed. An external review showed that is too late: the parent can return from `fork` and exit while the child's exec is still running, and then there is nothing left to copy.

Fix: the exec does the parent's copy itself, when it sets the flag, in the same `marea_lock` hold, if the flag was not set yet and the parent is tracked. At that point the parent is alive: it has not finished `pb_note_child`, so it has not returned from `fork`. So the child gets exactly one copy, from the parent before the flag or from the exec at the flag. If the exec succeeds, the copy goes with the rest: the drop after a non-matching exec, or `pb_move_tracked` for a matching one. If it fails, the old image keeps it, and the flag stays set. A tgid this exec listed with nothing inherited, a top-level matching exec that failed, is unlisted again, as before.

Found by an external review, twice. There is no deterministic test: the parent's copy has to land between the flag and the failure. The external review's isolated harness has both orders, the parent alive and the parent exited before the failure, and both now keep the records.

## Fork bookkeeping judged the child by one task, not its thread group

`pb_note_child` held the task it looked up and checked that task's `PF_EXITING` and `exit_state` before and after the copy. That task is the leader at fork time. A leader can `pthread_exit` while its threads run on. An exec from another thread makes that thread the leader and releases the old one, while the tgid lives on (`de_thread`, `exchange_tids`). In both cases the second check saw a dead task and dropped the records of a live process. The `de_thread` case was introduced by the namespace fix. The `pthread_exit` case predates it.

Fix: `pb_group_alive` reads `task->signal->live`. `signal` is shared by the group, survives `de_thread`, and is only freed in `__put_task_struct`, so it stays valid while the task is held. `fh_exit_files` cleans up only once `live` is 0. If that cleanup ran before the copy, the copy's own `marea_lock` hold makes `live == 0` visible to the second check. If it runs after, it removes the copy.

Found by an external review, and checked against `fs/exec.c` on 6.18. There is no deterministic test: it needs the child to exit its leader, or exec from a thread, within the parent's copy.

## A `MAP_FIXED` RWX mapping kept the old mapping's records

`fh_vm_mmap_pgoff` dropped the armed, seen and tracked records of the range on every successful mapping, except in the W+X branch. That branch returned straight after `track_pages`. A `MAP_FIXED` RWX mapping over an armed data page kept the old armed record, and `track_pages` kept the old tracked record's epoch. A store to the new page was then taken for a read of armed data: the old saved protection was restored, and a trace line was written.

Fix: the W+X branch drops the range like the other branch, then tracks the new pages.

`extra fixedwx` arms `READ_DATA`, maps it again RWX with `MAP_FIXED`, stores to it, and requires no fault and no trace line for it. It passes with the module unloaded. It passes with the module loaded on arm64 and x86.

## A failed `mprotect` still changed the tracked records

`pb_handle_protect` updates the tracked records before the syscall, so that no page is ever stripped of `PROT_WRITE` without a record allowing the write. When the syscall then failed, the records stayed changed. A W^X page that a failed `mprotect` untracked kept its read-execute protection and lost its record, so the next legal store was a `SIGSEGV`. A failed `mprotect(RWX)` of a read-write page left an RWX record, so an instruction fault there made the page executable. The original PageBuster had the same order.

Fix: `pb_protect_syscall`, now shared by `mprotect` and `pkey_mprotect`, copies the range's tracked records before `pb_handle_protect`. Right before the syscall, after the module's own restores and arming, it records the protection of every piece of the range, holes included. If the syscall fails, `pb_protect_done` works out how far it got, and `pb_settle_tracked` restores the old records for every page past that point.

How far it got follows `do_mprotect_pkey` on 6.18. The only errors raised before any VMA is touched are `-EINVAL` (an unaligned start, an invalid prot bit, an unallocated pkey), `-EINTR`, and `-ENOMEM` (a length that wraps, or a start that is not mapped). Otherwise it works VMA by VMA from the start, leaves the VMA that fails as it was, and stops. So the part it applied is the run of VMAs from the start that now have the requested protection, up to the first hole or the first VMA that does not. A VMA that already had that protection counts as applied, because the call passed over it. `READ_IMPLIES_EXEC` is taken into account per VMA, as the kernel does. A wrapping length is caught, and an unmapped start stops the walk at once. If nothing changed and the error is `-EINVAL` or `-EINTR`, the call is taken as having failed up front, and every page gets its old record back. The range is computed as the kernel computes it. `pb_page_count` returns an `int` and would have truncated a huge length.

This took three tries, each corrected by an external review:

- The first took as applied the run of VMAs that now had the requested protection, for every error. That is wrong for an argument error. An RWX page that the module keeps read-execute, asked for `PROT_READ|PROT_EXEC|0x8000`, already has the requested protection, and lost its RWX record although nothing was applied. Its next legal store was a `SIGSEGV`.
- The second took as applied only what had visibly changed. That is wrong when a VMA needed no change and the failure came after it. The same page, followed by a hole and asked for `PROT_READ|PROT_EXEC` over both, is applied, a no-op for its VMA, before the hole fails the call with `-ENOMEM`. The RWX record came back, and a store the program had just forbidden went through.
- The current rule tells the two apart by the error and by whether anything changed.

What is left: the in-loop `-EINVAL`, from `arch_validate_flags` or a driver's `vm_ops->mprotect`, looks like an argument error when only unchanged VMAs came before it. Those VMAs then keep their old records. Armed data records are not put back. The disarm restored those pages first, so they stay accessible, and the next arm attempt arms them again. A fault handler on another thread that changes a page in the range during the syscall can make the walk stop early.

`extra badprot` passes the invalid prot bit `0x8000`, and pkey 15, which is never allocated there, to make `mprotect` and `pkey_mprotect` fail with `EINVAL`. On arm64 before 6.12, `pkey_mprotect` fails with `ENOSYS` instead. It requires a store to an RWX page to work after each, including after the two that ask for the page's current read-execute protection. It also requires a read-write page not to run after a failed `mprotect(RWX)`. `extra partial`, after the external review's `partial_mprotect.c`, maps an RWX page followed by a hole, makes `mprotect(RX)` over both fail with `ENOMEM`, and requires the next store to the page to fault. Both pass with the module unloaded. Both pass with the module loaded on arm64 and x86.

## A failed `mprotect` could undo another thread's successful one

The restore above put back the snapshot by address. Between the snapshot and the restore, another thread's `mprotect` of the same page could succeed and change the record. The failed call then replaced that newer record with the older one. For example, a successful `mprotect(RX)` of a W^X page was undone, and the RWX record that came back let a store through that the program had just forbidden.

Fix: `pb_vm_lock` serializes a target's `mprotect`, `pkey_mprotect`, `mmap`, `munmap` and `mremap`, from the record updates before the syscall to the settling after it. No other of these calls can change the same records in between. The lock is taken before any mm lock and before `marea_lock`, and never under them. The module calls the real syscalls directly while holding it, so it never re-enters a hook that takes it. Fault paths do not take it. They run with no mm lock held, and only restore pages their records already allow. `mutex_lock_killable` is used, so a stuck caller can still be killed. One case can block: a `userfaultfd` handler thread that maps or protects memory while another thread holds the lock and is dumping a page that is still waiting for that handler.

Found by an external review. There is no deterministic test, because it needs two threads in the same window. The external review's isolated harness runs the second `mprotect` inside the first one's syscall. It now finds the lock held, and applies the call after the failed one has settled.

## `MREMAP_FIXED` left the destination's old armed record next to the moved one

The kernel unmaps whatever is at an `MREMAP_FIXED` destination before moving there. `fh_sys_mremap` relocated the source's armed record to the destination, but left the destination's own record. Both sat at one address. `data_armed` is filled with `list_add`, and arming walks upwards, so the higher destination's record was found first. A read-only source page moved over an armed read-write page came back read-write after its first read fault.

Fix: with `MREMAP_FIXED`, the destination's armed pages are released before the syscall: protection restored, then the record dropped. If the syscall fails, they are merely accessible and are armed again later. After a successful move to a range apart from the source, `pb_note_mremap` drops the destination's tracked records before the moved ones arrive. A resize in place overlaps the source and keeps its records.

`extra fixedover`, with `data=260000000-280000000`, arms a read-only source and a read-write destination, moves one over the other, and requires a read to work and a store to fault. It passes with the module unloaded. It passes with the module loaded on arm64 and x86.

## Correction: the `marea_lock` / `mmap_write_lock` inversion was not shown

The entry on holding `marea_lock` across `mprotect` says `fh_vm_mmap_pgoff` runs with `mmap_write_lock` held and takes `marea_lock` under it. It does not. On 6.18, `vm_mmap_pgoff` in `mm/util.c` takes and releases `mmap_write_lock` itself, and the hook calls `pb_drop_user_range` only after it returns. The fault paths do not hold a lock either: x86 `__bad_area` and arm64 `do_page_fault` drop the mmap or VMA lock before raising the signal, and only then does `fh_force_sig_fault` run. No path was found that takes `marea_lock` with an mm lock held, so the ABBA described there, and the TLA+ model built on that premise, do not show a real deadlock.

The change itself stays: no path holds `marea_lock` across a call that takes an mm lock. It is a lock-order rule, not the fix for a deadlock that was shown. The external review that found this also pointed out that the old order is not proven wrong. It is just not proven to deadlock.

## A failed `pkey_mprotect` on arm64 dropped a W^X page's store record

arm64 before 6.12 has no `CONFIG_ARCH_HAS_PKEYS`. `pkey_mprotect` is `sys_ni_syscall` there and returns `-ENOSYS`, not `-EINVAL`. `pb_protect_done` took only `-EINVAL` and `-EINTR` as failing up front, so it walked the VMAs. An RWX page that the module keeps read-execute, asked for `PROT_READ|PROT_EXEC`, already had that protection and counted as applied. Its RWX record was not put back, and the next legal store was a `SIGSEGV`.

Found by `extra badprot` on an Orange Pi 3B, kernel 5.10.160 with `CONFIG_KPROBES=y`: `store to the RWX page faulted after a failed pkey_mprotect(RX)`. With the module unloaded, `pkey_mprotect` on that kernel returns `ENOSYS` for pkey 15 and for pkey -1.

Fix: `pb_protect_done` returns `start` for `-ENOSYS`, so every page gets its old record back. `extra badprot` passes.

## Arming did not take the pin, and a moved-away record did not release it

The unload entry above says the pin is taken before `PROT_NONE` is set. It was not. `pb_armed_claim` added the record and returned, and nothing on the arming path called `pb_pin_update_locked()`. Between arming and the next update, a data page was `PROT_NONE` while `rmmod` succeeded, which is the stranding the pin exists to prevent. The other side had the same gap. When `pb_armed_after_move` dropped a record whose page left the range, or fell off the end of a shrinking move, it did not update the pin. If that was the last page still `PROT_NONE`, the pin stayed and `rmmod` was refused until some unrelated update.

Found by the maintainer's review of PR #1, which traced every caller and concluded that `extra pin` could not pass. Yet it passed on both arches. An ftrace of `pb_pin_update_locked` with `func_stack_trace` on the arm64 board shows why. Arming at `pb_arm_range <- pb_try_arm <- pb_protect_syscall` is followed by no update from the target. The next one is `pb_drop_data_state <- fh_exit_files <- do_exit` in the `sleep` process: the suite's own `sleep 1`, exiting just before its `rmmod`. The `exit_files` hook runs for every process that exits, and the pin is global, so any exit anywhere took the missing pin. On a busy machine the window is short, but it is there.

Fix: `pb_armed_claim` calls `pb_pin_update_locked()` right after `list_add`, before the caller sets `PROT_NONE`. If the pin cannot be taken because the module is already going away, the record is dropped and the page is not armed. `pb_armed_after_move` calls `pb_pin_update_locked()` after it settles the record.

The tests now avoid the exit that hid this. `extra pin` prints `armed` once the page is armed. The suite reads that from a FIFO and reads `/sys/module/pagedrop/refcnt` with shell builtins only, so no process exits in between. `extra pinmove`, with `data=260000000-280000000`, arms two pages, reads the first, then shrinks the pair to one page with an `MREMAP_FIXED` move inside the range. The second page's record is dropped in `pb_armed_after_move`. With `extra` still alive and nothing exiting, the suite requires the refcount to reach 0 within a second. Before the fix, on both arches: `pin` saw refcount 0 after arming, and `pinmove` still saw 1 after the move, so both failed. After the fix both pass.

The run scripts also stopped trusting `rmmod` and `insmod`. Each test used `sudo rmmod pagedrop 2>/dev/null || true` and an unchecked `insmod`. A pinned module made `rmmod` fail, `insmod` then failed with `EEXIST`, and the test ran on the previous module with the previous `path=` and `data=`. `unload` now retries `rmmod` for 10 seconds, `load` checks `insmod`, and the suite stops if either one fails.

## Loaded-module runs

arm64 has now been run with the module loaded: Orange Pi 3B (RK3566), Ubuntu 22.04, kernel 5.10.160-rockchip-rk356x rebuilt with `CONFIG_KPROBES=y`, UPX 5.0.2. `tools/arm64/run_tests.sh` passed all 60 checks, `badprot`, `partial`, `fixedover`, `pin` and `pinmove` included, with no oops or warning in `dmesg`. x86 has been run too: Ubuntu 26.04.1, kernel 7.0.0-38-generic, ftrace, gcc 15.2.0, UPX 4.2.4, bare metal. `tools/x86/run_tests.sh` passed all 58 checks, with no oops or warning in `dmesg`.

An earlier round reported 59 and 57. Its `pin` pass was not real: the pin came from the suite's own `sleep` exiting, as the entry on arming and the pin explains. The counts above are from the suites that read the refcount before any exit.

Every fix in the entries from the `do_exit` race onwards was checked by compiling: x86 against 6.18 with `-Werror`, and arm64 against a 6.18 `defconfig` tree, object only. The paths from all three external review rounds were also checked with its isolated harness, which compiles the module's functions against stubs, with the expectations reversed. All eleven scenarios, from three rounds, now report the fixed behaviour, the concurrent one with a real mutex and a second thread. Both suites have now passed with the module loaded, so these fixes count as verified on x86 and arm64.

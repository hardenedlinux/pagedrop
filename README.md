# pagedrop

>_Ever wanted to dump all the executable pages of a process? Do you crave something capable of dealing with **packed** processes?_

We've got you covered! **pagedrop** dumps every executable page of a packed process. It is the maintained kernel module that followed the unmaintained PageBuster tree.

[![asciicast](https://asciinema.org/a/cJH2O5N8w8Dd0GUuHw9kj8CZM.svg)](https://asciinema.org/a/cJH2O5N8w8Dd0GUuHw9kj8CZM)

Introduction
------------

There are plenty of scenarios in which the ability to dump executable pages is highly desirable. Of course, there are many methods, some of which standard _de facto_, but it is not always as easy as it seems.

For example, think about the case of packed malware samples. Run-time packers are often used by malware-writers to obfuscate their code and hinder static analysis. Packers can be of growing complexity, and, in many cases, a precise moment in time when the entire original code is completely unpacked in memory doesn't even exist.

Therefore, the goals of **pagedrop** are:

1. To dump all the executable pages, without assuming there is a moment in time where the program is fully unpacked;
2. To do this in a stealthy way (no VM, no ptrace).

In particular, given the widespread use of packers and their variety, our objective is to have a single all-encompassing solution, as opposed to packer-specific ones.

Ultimately, pagedrop fits in the context of the rev.ng decompiler. Specifically, it is related to what we call [MetaAddress](https://github.com/revng/revng/blob/9869f05/include/revng/Support/MetaAddress.h#L382). Among other things, a MetaAddress enables you to represent an absolute value of an address together with a timestamp (_epoch_), so that it can be used to track how a memory location changes during the execution of a program. Frequently, you can have different code at different moments at the same address during program execution. The original PageBuster module was designed around this simple yet effective data structure.

For more information, please refer to our [blogpost](https://rev.ng/blog/pagebuster/post.html).

There are two implementations: a prototype user-space-only and the full-fledged one, employing a kernel module.
The former is described in `userpagebuster/`.
The rest of this document describes the latter.

From PageBuster to pagedrop
---------------------------

PageBuster was written by Matteo Giordano in 2021 for the [rev.ng](https://rev.ng) decompiler. Packers rarely leave one moment when the whole program is unpacked, so the module dumped each executable page as it became executable and stamped it with an epoch. That epoch is what a [MetaAddress](https://github.com/revng/revng/blob/9869f05/include/revng/Support/MetaAddress.h#L382) uses to tell two generations of code at the same address apart. The write-up is the [rev.ng blog post](https://rev.ng/blog/pagebuster/post.html).

The first cut was `userpagebuster/`, an `LD_PRELOAD` prototype. It only saw library calls the target made itself, not the kernel and not the ELF loader. The real tool was the kernel module: ftrace hooks on x86_64, for kernels older than about 5.9.2. That tree was left unmaintained. It does not build or load on current kernels.

pagedrop is the maintained module, under a new name so it is not mistaken for the frozen 2021 tree. The job is the same. The machinery is not.

What changed:

- One source file, `pagedrop.c`. The Makefile selects the architecture from the target kernel, the same way LKRG does. `LINUX_VERSION_CODE` selects the APIs. Kernels older than 5.10 are no longer supported.
- x86_64 still uses ftrace. It was brought up through Ubuntu 24.04, kernel 6.8.0-101-generic. On 5.11 and later the module does not set `FTRACE_OPS_FL_RECURSION`, and it moves the instruction pointer with `ftrace_regs_set_instruction_pointer`.
- arm64, Linux >= 5.10, uses kprobes. Those kernels are built with `CONFIG_DYNAMIC_FTRACE_WITH_ARGS` and not `CONFIG_DYNAMIC_FTRACE_WITH_REGS`, so the x86 ftrace redirect does not register. The kprobe jumps to the same handlers, which then run in process context.
- The ELF loader is caught by hooking `vm_mmap_pgoff`, not only the `mmap` syscall. Dumps go through `copy_from_user` and `kernel_write`. There is no `stac`/`clac`.
- A list lock keeps a multithreaded unpacker from oopsing. Tracking follows the tgid, so a `prctl` rename and a child stay watched. `fork`, `vfork`, `clone`, `clone3`, and `do_exit` maintain that list.
- A successful `execve` or `execveat` of a matching path starts tracking. A failed exec does not drop the list.
- `pkey_mprotect` and `mremap` are hooked, so a protection-key toggle and a moved mapping are dumped at the address the code actually runs from.
- Anonymous W^X mappings are the only ones forced with `MAP_POPULATE`. On arm64 the fault class comes from the ESR, and a tagged fault address is untagged before the page is looked up. `PROT_BTI` and `PROT_MTE` are tested as bits, not as an exact `prot` value. MTE itself is not exercised: the Raspberry Pi 4 has none.
- The same address can be unpacked twice. Both dumps are kept, under different epochs. Dropping exec and making the page executable again dumps the new bytes, and leaves the old file in place.

Build
-----

Make sure you have installed GCC and Linux kernel headers for your kernel. For Debian-based systems:

```sh
sudo apt install build-essential linux-headers-$(uname -r)
```

Then, build the kernel module:

```sh
cd pagedrop
make
```

To build against another installed kernel, or a kernel tree, the same way LKRG does:

```sh
make P_KVER=6.8.0-101-generic
make KERNEL=/path/to/linux
```

The Makefile passes `-DPB_ARCH_X86_64` or `-DPB_ARCH_ARM64` from the target kernel's `ARCH`. `pagedrop.c` is the only module source. `LINUX_VERSION_CODE` selects version-specific APIs. x86_64 uses ftrace. arm64 (Linux >= 5.10) uses kprobes, because those kernels are built with `CONFIG_DYNAMIC_FTRACE_WITH_ARGS` and not `CONFIG_DYNAMIC_FTRACE_WITH_REGS`.

This will produce `pagedrop.ko` for that kernel.
Kernels older than 5.10 are no longer the supported line. `userpagebuster/` is the old user-space prototype and is not part of that port.

Tests
-----

```sh
tools/x86/run_tests.sh
tools/arm64/run_tests.sh
```

Both passed. x86_64 was Ubuntu 24.04, kernel 6.8.0-101-generic, ftrace, UPX 4.2.2. arm64 was Raspberry Pi 4, Debian 12, kernel 6.6.62+rpt-rpi-v8, kprobes, UPX 5.0.2. UPX 4.2.2's static arm64 stub hits `SIGILL` on that board with the module unloaded. Pi 4 has no protection keys and no MTE. `pkey_mprotect` is still hooked. A tagged fault address is checked on arm64 only.

A plain C program, packed with UPX and with the VMProtect demo, is compared in [docs/orig-upx-vmp.md](docs/orig-upx-vmp.md). The dumps are easier to read than either packed file. They are not easier than the original, and a fully virtualized function is still absent from them.

| Use case | x86_64 | arm64 |
|---|---|---|
| 13 hooks install, clean `rmmod` | pass | pass |
| ELF `.text` live-matches the dump | pass | pass |
| RWX write fault, then exec fault dumps the page | pass | pass |
| `prctl` rename still tracked | pass | pass |
| Child after `fork` still tracked | pass | pass |
| `mremap` dump is at the new address | pass | pass |
| `pkey_mprotect` dumps on exec | pass | pass, via the syscall |
| 4 threads call `mprotect`, no oops | pass | pass |
| UPX static binary, marker live-matches | pass | pass |
| Same address, two epochs, both dumps kept | pass | pass |
| Failed `execve` does not drop tracking | pass | pass |
| `execve` / `execveat` of a matching path starts tracking | pass | pass |
| Exec, drop exec, exec again; second dump is the new bytes | pass | pass |
| Tagged fault address dumps the untagged page | n/a | pass |
| Index line records tgid, comm, va, epoch, why | pass | pass |
| Two matching processes do not drop each other | pass | pass |
| `vfork` then `exec` of `/bin/true` | pass | pass |
| Read outside `data=` is not traced | pass | pass |
| `MAP_FIXED` over an armed page is traced again | pass | pass |
| Bad `data=` is rejected | pass | pass |
| 8 threads, one dump and one trace line | pass | pass |
| Reader racing a re-arm loop, no signal | pass | pass |
| 200 fork-and-fault children survive | pass | pass |
| Reader racing `mremap` of armed pages | pass | pass |
| `mprotect` storm over the data range, no signal | pass | pass |
| `munmap` of an armed page against a reader | pass | pass |
| Two threads of one tgid over one armed page | pass | pass |
| Exec with readers in flight | pass | pass |
| `pb_rank` over a threaded multi-process capture | pass | pass |
| 200 forks against a reader on the armed page | pass | pass |
| 4 threads reading through tagged pointers | n/a | pass |

**Note**: Please consider using a **virtual machine** (VirtualBox, VMWare, QEMU, etc.) for testing. The module could be harmful. Avoid killing your machine or production environment by accident.

Usage
-----

Load the module in a guest, not on a machine you care about. `path=` is a substring of the process name. `exact=1` matches it exactly.

```sh
insmod pagedrop.ko path=wide.upx
./wide.upx
```

Dumps land in `/tmp`, one 4096-byte file per page, named `<va>_<epoch>`. `/tmp/pagedrop.index` records `tgid comm va epoch why`. A second run mixes with the first. Copy one run out before the next:

```sh
python3 tools/pb_collect.py --out /tmp/cap --file ./wide.upx \
    --lib /lib/x86_64-linux-gnu/libc.so.6 \
    --lib /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
```

That copies the index and only the dump files it names. It does not glob `/tmp`. `--lib` is the guest's library, copied into the capture and listed in `libs.txt`. On arm64 those paths are under `/lib/aarch64-linux-gnu/`. Pass `--force` only to replace a capture that already has an index.

`data=start-end` (hex) arms that range so a read from a tracked executable page dumps the data page and appends `ip data_va epoch` to `/tmp/pagedrop.trace`. The accepted cost is one fault per data page per handler version. A later version of the same handler page is traced again. `munmap`, a replacing `mmap`, or an `mprotect` over the data page clears the record.

Rebuilding a loadable image
---------------------------

A directory of page files is not a program. A call that leaves the page has nowhere to land until both pages are one ELF at their runtime addresses. After the capture directory is on the machine where you will open Ghidra:

```sh
python3 tools/pb_rank.py --capture /tmp/cap --out image.elf
```

`--file` is the packed file, and it is only the drop filter. Do not pass the unpacked original as `--file`. That drops the payload. `--capture` finds a packed file named `*.upx` or `packed`, and reads `libs.txt`. A copied library is not treated as the original. An unpacked file is picked up only when it is named `orig` or `*.orig`, or when you pass `--orig`.

No `--lib` and no `libs.txt` means a warning and no library filter. The host's libc is not used. It fails to match a guest dump, or matches the wrong pages.

What that ELF is, without the unpacked file:

- Kept pages sit at the virtual addresses in the filenames. Contiguous pages share a `PT_LOAD`. A missing address stays a hole. It is not filled with zeroes.
- libc, the loader, and pages whose bytes match the packed file are dropped.
- A second epoch of the same address is a new ELF only when the bytes changed and are not the packed file.
- The printed page list is in address order. `mprotect` is not preferred over `mmap`. On arm64 the unpacked text arrived as `mmap`.
- Function names and import names are absent. The entry is the lowest kept page, not `main`, unless `--orig` supplied one that still falls inside the image. The output says `names none`.
- Format strings and the GOT are absent when they never became executable, unless the module's `snap` pass copied them. That pass runs when a mapping that is not a library becomes executable, up to three times per process, and records non-executable pages that are not the stack, the heap, or a library. The index why is `snap`. All-zero pages are not written. A mapping larger than 64 pages is skipped.
- `.strings` lists printable runs that were already in a kept page. Ghidra will not type a string from that sidecar alone.

`--orig` is optional, and only for a file you already have. It names the entry, symbols, and imports, and splices read-only pages no dump covered. It is not required, and it is not the drop filter.

Stock UPX does not encrypt. The stub decompresses, then makes the restored pages executable. If `upx -d` succeeds and every kept executable page matches, the tool writes `image.unpacked` and tells you to open that file, not the stitch. The stitch is the route when `upx -d` fails and the stub still restored real instructions. A fully virtualized function never becomes executable, so it is not in the dump. Do not invent those bytes.

Sidecars sit next to the ELF:

| File | Contents |
|---|---|
| `.pages` | One line per page: `va epoch why` and whether it was kept, dropped as a library or as the packed file, or a gap nothing dumped |
| `.libs` | Library base per path, with the page count that supports it; a base backed by fewer pages is marked `rejected` |
| `.strings` | Printable runs with their runtime addresses |
| `.missing` | Original code symbols no dump ever carried. Empty unless `--orig` was applied |
| `.tails` | Pages that match the packed file for a while and then diverge |

`--rebase` also writes `rebased.elf` at the original file addresses, which needs a slide from `--orig` or from packed-file pages that were dumped and dropped. `--drop-stray` leaves a partial packed-file match out of an executable segment. `--rank page` is the address order used when `--out` is set; without `--out` the default list still prefers bytes missing from the packed file, then `mprotect` and `fault` over `mmap`.

`userland/c/wide.c` is the stitcher check: eight functions forced onto eight pages. Pack it with UPX and pass that guest's libc and loader. The stitch drops those library pages. Cross-page calls resolve. Names resolve only when `--orig` is passed. Without it, a decompiler does not discover the page-aligned functions from the entry; the body is there once the function is created at its runtime address. A `printf` in the image is a PLT stub, not libc. The string `libc.so.6` in the dynamic table is the import, not a leaked library page.

The keep count is not a contract. One snap page is enough to move it. Last measured: x86 `6.8.0-106-generic`, UPX 4.2.2, 452 dumps, 13 kept; arm64 `6.6.62+rpt-rpi-v8`, UPX 5.0.2, 497 dumps, 12 kept. On both, Ghidra decompiled `mix` as `param_1 * 0x11 ^ 0x5a5a`, and `scramble` called `mix` and `weigh` on the other pages.

The stitcher does not change the module. `python3 tools/test_pb_rank.py` is the host check. It does not load the module.

Userland programs live in `userland/c/`:

| Program | What it checks |
|---|---|
| `simple` | Loader-mapped `.text` |
| `sigsegv.out` | Write-or-execute page, then the execute fault |
| `capture` | Rename, child, `mremap`, `pkey_mprotect`, threads |
| `upxtest` | Static binary for UPX. Pack it with `upx -o upxtest upxtest` after `make upxtest` |
| `regress` | Small dynamic program used in `docs/orig-upx-vmp.md` |
| `wide` | Eight page-aligned functions. Stitcher check, not a kernel-suite case |
| `extra` | Built by the guest runners for the kernel suite |
| `packdiff` | Marker bytes for a packed-versus-dump compare |

`userland/c/decpage.c` and `userland/c/nzpack.c` are not UPX and are not built by the Makefile. Stock UPX compresses. `decpage.c` decrypts, then calls `mprotect`. `nzpack.c` run-length decodes, then calls `mprotect`. The page that becomes executable is not in the file, so `upx -d` is not the route. On both arches that page decompiled as `return 0x5a87`. That is not evidence about UPX.

`capture` exits 0 only if its markers were dumped. The kernel suite is `tools/x86/run_tests.sh` and `tools/arm64/run_tests.sh`, each on its own guest. They load the module.

```sh
cd userland/c && make
sudo insmod ../../pagedrop.ko path=capture
./capture
sudo rmmod pagedrop
```

Older QEMU notes
----------------

`linux-kernel-module-cheat` was an early way to boot a kernel and load the module. It is not how this tree is tested. Build the module on the guest, against that guest's headers. The measured guests are Ubuntu 24.04, kernel 6.8.0-101-generic, and a Raspberry Pi 4, kernel 6.6.62+rpt-rpi-v8.

Licensing
---------

The content of this repository is licensed under the [GPLv2](https://github.com/zTehRyaN/pagebuster/blob/main/LICENSE).
Many thanks to Alexei Lozovsky which inspired the ftrace hooking part of the project.

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
- A list lock keeps a multithreaded unpacker from oopsing. Tracking follows the tgid, so a `prctl` rename and a child stay watched. `fork`, `vfork`, `clone`, `clone3`, and `exit_files` maintain that list. A child is keyed on its global tgid, so a target in a container is followed too. A forked child gets a copy of the parent's records, unless it has already exec'd, as after `vfork` or `posix_spawn`. After the copy, or an exec, the child's faults are matched only against its own records.
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

To test **pagedrop**, you can insert the LKM and try it with whatever binary you want. We provided you with [`sigsegv.c`](https://github.com/zTehRyaN/pagebuster/blob/main/sigsegv.c), a `.c` program that simply maps and executes a shellcode. Inside the `/userland/c/` directory you will also find `simple.c`, the one shown in the demo.

So, just `insmod` the module and pass the name of the process as argument. Then, execute it.

```sh
insmod pagedrop.ko path=sigsegv.out
./sigsegv.out
```

`path=` is a substring. `exact=1` matches it exactly. `data=start-end` (hex) arms that range. The first read of an armed page from a tracked executable page is dumped, and `ip`, `data_va`, `epoch` are appended to `/tmp/pagedrop.trace`. `/tmp/pagedrop.index` records `tgid`, `comm`, `va`, `epoch`, and why for every dump. The `tgid` is the one the host sees, not the one inside a container's pid namespace. Whitespace and control bytes in `comm` are written as `_`, so every line has five fields.

The armed page is restored to its previous protection after that read and is not armed again, so each armed page is traced once for the life of the process rather than once per handler epoch. A later handler epoch that reads the same address is not seen. `munmap`, a replacing `mmap`, or an `mprotect` over the data page clears the record and the page is traced again.

```sh
python3 tools/pb_rank.py --file ./regress.vmp --tgid 1234
```

That keeps one `tgid`. If several are present and `--tgid` is omitted, it lists them and exits 2. It drops a dump whose bytes match `libc`, `ld-linux`, `libstdc++`, or an executable `PT_LOAD` of `--file`. What remains is ranked with bytes missing from the on-disk file above bytes that are in it, `mprotect` and `fault` above `mmap`, and a later epoch above an earlier one. Pass other libraries with `--lib`.

Inside the `/tmp` directory, you will find all the timestamped dumps.

```sh
ls /tmp
```

You should get an output similar to the following:

```
100000000_494     7ffff7d4b000_291  7ffff7dc7000_415  7ffff7eb9000_30
100001000_495     7ffff7d4c000_292  7ffff7dc8000_416  7ffff7eba000_31
7ffff7cd1000_169  7ffff7d4d000_293  7ffff7dc9000_417  7ffff7ebb000_32
7ffff7cd2000_170  7ffff7d4e000_294  7ffff7dca000_418  7ffff7ebc000_33
7ffff7cd3000_171  7ffff7d4f000_295  7ffff7dcb000_419  7ffff7ebd000_34
7ffff7cd4000_172  7ffff7d50000_296  7ffff7dcc000_420  7ffff7ebe000_35
7ffff7cd5000_173  7ffff7d51000_297  7ffff7dcd000_421  7ffff7ebf000_36
7ffff7cd6000_174  7ffff7d52000_298  7ffff7dce000_422  7ffff7ec0000_37
...
```

Userland programs live in `userland/c/`:

| Program | What it checks |
|---|---|
| `simple` | Loader-mapped `.text` |
| `sigsegv.out` | Write-or-execute page, then the execute fault |
| `capture` | Rename, child, `mremap`, `pkey_mprotect`, threads |
| `upxtest` | Static binary for UPX. Pack it with `upx -o upxtest upxtest` after `make upxtest` |

`capture` exits 0 only if its markers were dumped. The full check, including a live physical-page compare, is `tools/x86/run_tests.sh`. It needs `upx` and a static libc, and it loads the module.

```sh
cd userland/c && make
sudo insmod ../../pagedrop.ko path=capture
./capture
```

To remove the LKM, run:

```sh
rmmod pagedrop.ko
```

Unload only after every target has exited. `rmmod` removes the hooks, but it cannot restore protections inside a process that is still running. A W^X page keeps `PROT_WRITE` cleared, so the target's next write to it is a `SIGSEGV`, and unloading the module kills the process under analysis. A page armed by `data=` is the exception: while one is still `PROT_NONE`, the module holds a reference to itself and `rmmod` fails with `EBUSY`. That reference is dropped asynchronously, so an `rmmod` right after a target exits may need a retry.

Quickly test in QEMU
--------------------

If you want to test it on a safe environment, you can use [Ciro Santilli's](https://github.com/cirosantilli/linux-kernel-module-cheat) emulation setup.

This setup has been mostly tested on Ubuntu.
Reserve 12 GB of disk and run:

```sh
git clone https://github.com/cirosantilli/linux-kernel-module-cheat
cd linux-kernel-module-cheat
git reset --hard 5ec6595e1f3afb6213ba7c14ab5e4e3893a4089f
```

Unlike Ubuntu 20.04 LTS, here `kprobes` is not enabled by default. So, you must enable it on linux kernel configs.

```sh
cd linux_config
cat <<EOT >> default

# Kprobes
CONFIG_KPROBES=y
EOT
cd ..
```

Now, you can start the build:

```sh
# For Debian derivatives
./build --download-dependencies qemu-buildroot
# If you use another distro, you'll have to install the deps manually
./build --no-apt --download-dependencies qemu-buildroot
```

The initial build will take a while (30 minutes to 2 hours) to clone and build.

Finally, what you need to do is to insert inside the environment the kernel module as well as all the `c` programs you want to test it on.
If you want to do it manually, you can build the module as shown before, the target programs and then just put them inside QEMU:

```sh
cd linux-kernel-module-cheat
cp /path/to/files $PWD/out/buildroot/build/default/x86_64/target/lkmc/
./build-buildroot
```

In this way, you will find them inside the directory where you spawn.

You can now run QEMU:

```sh
./run
```

Use with `Ctrl-A X` to quit QEMU or type `poweroff`.

If you use `linux-kernel-module-cheat` to build the module and the programs for you, you can put `pagedrop.c` inside `/kernel_modules`, and the `c` files inside `/userland/c`. Then run:

```sh
# Rebuild and run
./build-userland
./build-modules
./run

# Load kernel module
cd /mnt/9p/out_rootfs_overlay/lkmc
insmod pagedrop.ko path=sigsegv.out

# Run the program
./c/sigsegv.out

# List dumped pages
ls /tmp
```

If you want to test with other binaries, you may put the source `.c` file inside the [`/userland/c`](https://github.com/cirosantilli/linux-kernel-module-cheat/tree/master/userland/c) folder and let the simulator compile it for you by running `./build-userland`. Now, after running the system, you will find it compiled inside `/mnt/9p/out_rootfs_overlay/lkmc/c/`.

UPX testing
-----------

If you want to try how **pagedrop** behaves with UPX-packed binaries, you should prepare them outside the QEMU guest environment, and then inject into it.
First of all, install [upx](https://upx.github.io/). On Ubuntu 20.04 LTS, run:

```sh
sudo apt-get update -y
sudo apt-get install -y upx-ucl
```

Then, for instance, grab a `.c` program and compile it. Make sure it reaches the minimum size required by upx to pack it: UPX cannot handle binaries under 40Kb. The best way to work-around this problem is to compile your binary in static mode, in order to get a bigger executable file.
So, just try:

```sh
gcc -static -o mytest mytest.c
upx -o mytest_packed mytest
```

The easiest way to put it inside QEMU is the following.

```c
cd linux-kernel-module-cheat
cp /path/to/mytest_packed $PWD/out/buildroot/build/default/x86_64/target/lkmc/
./build-buildroot
```

Now you can test it, in the usual way:

```sh
./run
insmod /mnt/9p/out_rootfs_overlay/lkmc/pagedrop.ko path=mytest_packed
./mytest_packed
ls /tmp
```

Output will be something like that:

```
401000_2        427000_40       44d000_78       473000_116
402000_3        428000_41       44e000_79       474000_117
403000_4        429000_42       44f000_80       475000_118
404000_5        42a000_43       450000_81       476000_119
405000_6        42b000_44       451000_82       477000_120
406000_7        42c000_45       452000_83       478000_121
407000_8        42d000_46       453000_84       479000_122
408000_9        42e000_47       454000_85       47a000_123
409000_10       42f000_48       455000_86       47b000_124
40a000_11       430000_49       456000_87       47c000_125
```

Licensing
---------

The content of this repository is licensed under the [GPLv2](https://github.com/zTehRyaN/pagebuster/blob/main/LICENSE).
Many thanks to Alexei Lozovsky which inspired the ftrace hooking part of the project.

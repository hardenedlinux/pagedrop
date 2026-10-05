#!/usr/bin/env python3
import argparse
import glob
import os
import struct
import sys

PAGE = 4096
PT_LOAD = 1
PF_X = 1
WHY_RANK = {
    "fault": 2,
    "mprotect": 2,
    "mmap": 0,
    "mremap": 0,
    "read": -1,
}
LIB_DIRS = (
    "/usr/lib/x86_64-linux-gnu",
    "/lib/x86_64-linux-gnu",
    "/usr/lib/aarch64-linux-gnu",
    "/lib/aarch64-linux-gnu",
    "/lib64",
    "/usr/lib64",
    "/usr/lib",
    "/lib",
)


def aligned_pages(data):
    pages = set()
    n = len(data) // PAGE
    for i in range(n):
        pages.add(data[i * PAGE:(i + 1) * PAGE])
    if len(data) % PAGE:
        tail = data[n * PAGE:]
        pages.add(tail + bytes(PAGE - len(tail)))
    return pages


def elf_phdrs(data):
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        return None
    e_phoff = struct.unpack_from("<Q", data, 32)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
    if e_phnum == 0xFFFF or e_phentsize < 56:
        return None
    phdrs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if off + 56 > len(data):
            return None
        p_type, p_flags, p_offset, p_vaddr, _, p_filesz, p_memsz, _ = struct.unpack_from(
            "<IIQQQQQQ", data, off)
        phdrs.append((p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz))
    return phdrs


def load_pages(data, exec_only):
    phdrs = elf_phdrs(data)
    if phdrs is None:
        return set()
    pages = set()
    for p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz in phdrs:
        if p_type != PT_LOAD:
            continue
        if exec_only and not (p_flags & PF_X):
            continue
        if p_memsz == 0:
            continue
        base = p_offset - (p_vaddr % PAGE)
        span = p_memsz + (p_vaddr % PAGE)
        count = (span + PAGE - 1) // PAGE
        for i in range(count):
            foff = base + i * PAGE
            chunk = bytearray(PAGE)
            src = max(foff, p_offset)
            end = min(foff + PAGE, p_offset + p_filesz)
            if src < end and src < len(data):
                take = min(end, len(data)) - src
                if take > 0:
                    chunk[src - foff:src - foff + take] = data[src:src + take]
            pages.add(bytes(chunk))
    return pages


def file_pages(path, exec_only):
    with open(path, "rb") as f:
        data = f.read()
    if exec_only:
        if elf_phdrs(data) is None:
            raise SystemExit("%s: not an ELF64" % path)
        return load_pages(data, True)
    pages = aligned_pages(data)
    pages |= load_pages(data, False)
    return pages


def default_libs():
    found = []
    seen = set()
    names = ["libc.so.6", "libstdc++.so.6"]
    for d in LIB_DIRS:
        for name in names:
            path = os.path.join(d, name)
            if os.path.isfile(path):
                real = os.path.realpath(path)
                if real not in seen:
                    seen.add(real)
                    found.append(path)
        for path in sorted(glob.glob(os.path.join(d, "ld-linux*.so*"))):
            if os.path.isfile(path):
                real = os.path.realpath(path)
                if real not in seen:
                    seen.add(real)
                    found.append(path)
    return found


def lib_kind(path):
    base = os.path.basename(os.path.realpath(path))
    if base.startswith("libc.so") or base.startswith("libc-"):
        return "libc"
    if base.startswith("ld-linux") or base.startswith("ld-"):
        return "ld"
    if base.startswith("libstdc++"):
        return "libstdcxx"
    return "lib"


def parse_index(path):
    rows = []
    with open(path, "r", encoding="ascii", errors="replace") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            # comm is the only field the program controls. pagedrop
            # replaces whitespace in it, but an index from an older module
            # may have a comm with spaces, so take it as whatever lies
            # between the first field and the last three.
            parts = line.split()
            if len(parts) < 5:
                raise SystemExit("%s:%d: expected 5 fields" % (path, lineno))
            tgid_s, va_s, epoch_s, why = parts[0], parts[-3], parts[-2], parts[-1]
            comm = " ".join(parts[1:-3])
            try:
                tgid = int(tgid_s)
                va = int(va_s, 16)
                epoch = int(epoch_s)
            except ValueError:
                raise SystemExit("%s:%d: bad number" % (path, lineno))
            rows.append((tgid, comm, va, epoch, why))
    return rows


def choose_tgid(rows, tgid):
    counts = {}
    comms = {}
    for row_tgid, comm, _, _, _ in rows:
        counts[row_tgid] = counts.get(row_tgid, 0) + 1
        comms.setdefault(row_tgid, comm)
    if tgid is None:
        if len(counts) == 1:
            tgid = next(iter(counts))
        else:
            for key in sorted(counts):
                print("tgid %d comm %s lines %d" % (key, comms[key], counts[key]), file=sys.stderr)
            raise SystemExit(2)
    if tgid not in counts:
        raise SystemExit("tgid %d not in index" % tgid)
    return tgid, comms[tgid], sum(n for key, n in counts.items() if key != tgid)


def rank(rows, tgid, dumps, file_set, in_file, lib_sets):
    kept = []
    dropped = {"libc": 0, "ld": 0, "libstdcxx": 0, "lib": 0, "file": 0}
    missing_dump = 0
    for row_tgid, comm, va, epoch, why in rows:
        if row_tgid != tgid:
            continue
        path = os.path.join(dumps, "%x_%d" % (va, epoch))
        try:
            with open(path, "rb") as f:
                blob = f.read()
        except OSError:
            missing_dump += 1
            continue
        if len(blob) != PAGE:
            blob = blob[:PAGE].ljust(PAGE, b"\x00")
        kind = None
        for name, pages in lib_sets:
            if blob in pages:
                kind = name
                break
        if kind:
            dropped[kind] = dropped.get(kind, 0) + 1
            continue
        if blob in file_set:
            dropped["file"] += 1
            continue
        missing = 0 if blob in in_file else 1
        kept.append((missing, WHY_RANK.get(why, 0), epoch, va, why, path, comm))
    kept.sort(key=lambda row: (row[0], row[1], row[2], row[3]), reverse=True)
    return kept, dropped, missing_dump


def main():
    ap = argparse.ArgumentParser(description="Rank pagedrop dumps for one tgid")
    ap.add_argument("--index", default="/tmp/pagedrop.index")
    ap.add_argument("--dumps", default="/tmp")
    ap.add_argument("--file", required=True)
    ap.add_argument("--tgid", type=int)
    ap.add_argument("--lib", action="append", default=[])
    ap.add_argument("--no-default-libs", action="store_true")
    ap.add_argument("--top", type=int, default=0)
    args = ap.parse_args()
    rows = parse_index(args.index)
    tgid, comm, skipped = choose_tgid(rows, args.tgid)
    libs = [] if args.no_default_libs else default_libs()
    libs.extend(args.lib)
    if not libs and not args.no_default_libs:
        print("pb_rank: no libc, ld-linux, or libstdc++ found", file=sys.stderr)
    lib_sets = []
    for path in libs:
        lib_sets.append((lib_kind(path), file_pages(path, False)))
    file_set = file_pages(args.file, True)
    with open(args.file, "rb") as f:
        on_disk = f.read()
    in_file = aligned_pages(on_disk) | load_pages(on_disk, False)
    kept, dropped, missing_dump = rank(rows, tgid, args.dumps, file_set, in_file, lib_sets)
    print("summary tgid=%d comm=%s kept=%d dropped=%d skipped_tgid=%d missing_dump=%d drop_libc=%d drop_ld=%d drop_libstdcxx=%d drop_lib=%d drop_file=%d" % (
        tgid, comm, len(kept), sum(dropped.values()), skipped, missing_dump,
        dropped["libc"], dropped["ld"], dropped["libstdcxx"], dropped["lib"], dropped["file"]))
    limit = len(kept) if args.top <= 0 else min(args.top, len(kept))
    for i, (missing, _, epoch, va, why, path, _) in enumerate(kept[:limit], 1):
        print("%d %x %d %s %d %s" % (i, va, epoch, why, missing, path))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.exit(0)
    except SystemExit as exc:
        if isinstance(exc.code, int):
            sys.exit(exc.code)
        if exc.code:
            print(exc.code, file=sys.stderr)
        sys.exit(1)

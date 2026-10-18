#!/usr/bin/env python3
import argparse
import glob
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pb_stitch as stitch

PAGE = stitch.PAGE
PT_LOAD = stitch.PT_LOAD
PF_X = stitch.PF_X
WHY_RANK = {
    "fault": 2,
    "mprotect": 2,
    "mmap": 0,
    "mremap": 0,
    "read": -1,
    "snap": -1,
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
    return stitch.elf_phdrs(data)


def load_pages(data, exec_only):
    pages = set()
    for _, flags, blob in stitch.iter_load_pages(data):
        if exec_only and not (flags & PF_X):
            continue
        pages.add(blob)
    return pages


def file_pages(path, exec_only):
    with open(path, "rb") as f:
        data = f.read()
    if exec_only:
        if elf_phdrs(data) is None:
            raise SystemExit("%s: not an ELF64" % path)
        return load_pages(data, True)
    return aligned_pages(data) | load_pages(data, False)


def default_libs():
    """Host library paths. main() does not call this. A guest dump must name its own."""
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
            parts = line.split()
            if len(parts) != 5:
                raise SystemExit("%s:%d: expected 5 fields" % (path, lineno))
            tgid_s, comm, va_s, epoch_s, why = parts
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


def rank(rows, tgid, dumps, file_set, in_file, lib_sets, order):
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
    if order == "page":
        kept.sort(key=lambda row: (row[0], row[3], row[2]), reverse=True)
    else:
        kept.sort(key=lambda row: (row[0], row[1], row[2], row[3]), reverse=True)
    return kept, dropped, missing_dump


def pick_one(paths, what):
    if not paths:
        return None
    if len(paths) > 1:
        raise SystemExit("several %s in the capture, pass it explicitly: %s"
                         % (what, ", ".join(sorted(paths))))
    return paths[0]


def looks_like_dump(name):
    parts = name.split("_")
    if len(parts) != 2:
        return False
    try:
        int(parts[0], 16)
        int(parts[1])
    except ValueError:
        return False
    return True


def resolve_lib_path(capture, line):
    """A libs.txt entry is valid on the machine that wrote it, or beside the capture."""
    if os.path.isabs(line) and os.path.isfile(line):
        return line
    beside = line if os.path.isabs(line) else os.path.join(capture, line)
    if os.path.isfile(beside):
        return beside
    base = os.path.join(capture, os.path.basename(line))
    if os.path.isfile(base):
        return base
    return line


def orig_candidates(capture, skip_names):
    """An unpacked file is named orig or *.orig. A copied library is not one."""
    found = []
    for p in sorted(glob.glob(os.path.join(capture, "*"))):
        name = os.path.basename(p)
        if name in skip_names or name.endswith(".upx") or looks_like_dump(name):
            continue
        if name != "orig" and not name.endswith(".orig"):
            continue
        if not os.path.isfile(p):
            continue
        try:
            if stitch.elf_phdrs(stitch.read_file(p)):
                found.append(p)
        except OSError:
            continue
    return found


def resolve_capture(args):
    if not args.capture:
        return
    d = args.capture
    args.index = os.path.join(d, "pagedrop.index")
    args.dumps = d
    if not os.path.isfile(args.index):
        raise SystemExit("%s: no pagedrop.index" % d)
    if not args.file:
        args.file = pick_one(sorted(glob.glob(os.path.join(d, "*.upx"))) or
                             sorted(glob.glob(os.path.join(d, "packed"))), "packed file")
    if not args.file:
        raise SystemExit("pass --file, the packed file is not in %s" % d)
    listed = os.path.join(d, "libs.txt")
    listed_names = set()
    if os.path.isfile(listed):
        with open(listed, "r", encoding="ascii", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                listed_names.add(os.path.basename(line))
                args.lib.append(resolve_lib_path(d, line))
    if not args.orig:
        skip = {"packed", "pagedrop.index", "libs.txt"} | listed_names
        args.orig = pick_one(orig_candidates(d, skip), "unpacked original")


def main():
    ap = argparse.ArgumentParser(description="Rank pagedrop dumps for one tgid")
    ap.add_argument("--index", default="/tmp/pagedrop.index")
    ap.add_argument("--dumps", default="/tmp")
    ap.add_argument("--capture", help="directory holding pagedrop.index, dumps, and libs.txt")
    ap.add_argument("--file", help="packed file used as the drop filter, not the unpacked original")
    ap.add_argument("--orig", help="unpacked ELF for entry and symbol names; not a drop filter")
    ap.add_argument("--tgid", type=int)
    ap.add_argument("--lib", action="append", default=[])
    ap.add_argument("--no-default-libs", action="store_true")
    ap.add_argument("--top", type=int, default=0)
    ap.add_argument("--out", help="write one ELF per generation; does not change the module")
    ap.add_argument("--arch", choices=("x86_64", "aarch64"), help="ELF machine for --out")
    ap.add_argument("--rebase", action="store_true",
                    help="also emit rebased.elf at the original file addresses")
    ap.add_argument("--drop-stray", action="store_true",
                    help="exclude pages that only partially match the packed file")
    ap.add_argument("--no-strings", action="store_true", help="skip the .strings sidecar")
    ap.add_argument("--rank", choices=("why", "page"), default="why",
                    help="page order does not prefer mprotect over mmap")
    args = ap.parse_args()
    resolve_capture(args)
    if not args.file:
        raise SystemExit("--file is required (or use --capture)")

    rows = parse_index(args.index)
    tgid, comm, skipped = choose_tgid(rows, args.tgid)
    if args.lib:
        libs = list(args.lib)
    else:
        libs = []
        if not args.no_default_libs:
            print("pb_rank: no --lib and no libs.txt; not filtering with host libraries",
                  file=sys.stderr)
    lib_sets = [(lib_kind(p), file_pages(p, False)) for p in libs]
    file_set = file_pages(args.file, True)
    with open(args.file, "rb") as f:
        on_disk = f.read()
    in_file = aligned_pages(on_disk) | load_pages(on_disk, False)
    kept, dropped, missing_dump = rank(rows, tgid, args.dumps, file_set, in_file,
                                       lib_sets, args.rank)
    print("summary tgid=%d comm=%s kept=%d dropped=%d skipped_tgid=%d missing_dump=%d "
          "drop_libc=%d drop_ld=%d drop_libstdcxx=%d drop_lib=%d drop_file=%d" % (
              tgid, comm, len(kept), sum(dropped.values()), skipped, missing_dump,
              dropped["libc"], dropped["ld"], dropped["libstdcxx"], dropped["lib"],
              dropped["file"]))

    if args.out:
        arch = args.arch or stitch.elf_arch(on_disk) or stitch.host_arch()
        if not arch:
            raise SystemExit("pass --arch x86_64 or --arch aarch64")
        root, _ext = os.path.splitext(args.out)
        result = stitch.build(rows, tgid, args.dumps, args.file, args.orig, libs,
                              arch, args.out, rebase=args.rebase,
                              drop_stray=args.drop_stray, want_strings=not args.no_strings,
                              upx_keep=root + ".unpacked")
        if not result["gens"]:
            print("elf none")
        for g in result["gens"]:
            print("elf gen=%d path=%s pages=%d loads=%d entry=%x slide=%s spliced=%d "
                  "syms=%d stray=%d" % (
                      g["index"], g["path"], g["pages"], g["loads"], g["entry"],
                      ("%x" % g["slide"]) if g["slide"] is not None else "none",
                      g["spliced"], g["syms"], g["stray"]))
        for row in result["changelog"]:
            print("change gen=%d va=%x old=%s new=%d why=%s" % (
                row["gen"], row["va"],
                "-" if row["old_epoch"] is None else row["old_epoch"],
                row["new_epoch"], row["why"]))
        for row in result["libs"]:
            print("lib %s" % row)
        for va in result["stray"]:
            print("stray %x partial_match_with_packed" % va)
        for tgt, count in result["hole_calls"]:
            print("hole_call %x count=%d" % (tgt, count))
        if result["calls"] and not result["hole_calls"]:
            print("calls %d targets_outside_image (byte scan, heuristic)" % len(result["calls"]))
        if result["missing"]:
            print("missing %d original symbols never dumped" % len(result["missing"]))
        report_names(result.get("named_from", "none"))
        report_upx(result.get("upx"), args.file)

    print_kept(kept, args.top, address_order=bool(args.out))
    return 0


def report_names(named_from):
    print("names %s" % named_from)
    if named_from == "none":
        print("warning no symbol names; pass --orig only if you already have the unpacked file")
    elif named_from == "orig-unapplied":
        print("warning --orig did not name any address in this image")


def report_upx(upx, file_path):
    info = upx or {}
    status = info.get("status")
    if status == "ok":
        same = info.get("same", 0)
        diff = info.get("diff", 0)
        path = info.get("path")
        if diff == 0 and same > 0 and path:
            print("upx -d matched=%d unmatched=0; open %s, not the stitch" % (same, path))
        else:
            print("upx -d matched=%d unmatched=%d" % (same, diff))
    elif status == "failed" and file_path and file_path.endswith(".upx"):
        print("upx -d failed; the stitched image is the only route")
    elif status == "absent":
        print("upx not installed; skipping the native-unpack comparison")


def print_kept(kept, top, address_order):
    rows = kept
    if address_order:
        rows = sorted(kept, key=lambda row: (row[3], row[2]))
    limit = len(rows) if top <= 0 else min(top, len(rows))
    for i, (missing, _, epoch, va, why, path, _) in enumerate(rows[:limit], 1):
        print("%d %x %d %s %d %s" % (i, va, epoch, why, missing, path))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.exit(0)
    except SystemExit as exc:
        if isinstance(exc.code, int):
            sys.exit(exc.code)
        if exc.code:
            sys.exit(exc.code)
        sys.exit(1)
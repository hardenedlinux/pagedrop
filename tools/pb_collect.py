#!/usr/bin/env python3
"""Copy one pagedrop run out of /tmp into a capture directory.

The module writes /tmp/pagedrop.index and /tmp/<va>_<epoch>. A second run
mixes with the first. This copies only the files the index names. It does
not glob /tmp.
"""
import argparse
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pb_rank


def dump_name(va, epoch):
    return "%x_%d" % (va, epoch)


def stored_name(base, used):
    name = base
    n = 1
    while name in used:
        stem, ext = os.path.splitext(base)
        name = "%s.%d%s" % (stem, n, ext)
        n += 1
    used.add(name)
    return name


def collect(index, dumps, dest, packed=None, libs=None, force=False):
    if not os.path.isfile(index):
        raise SystemExit("%s: no index" % index)
    dest_index = os.path.join(dest, "pagedrop.index")
    if os.path.exists(dest_index) and not force:
        raise SystemExit("%s already has a capture; pass --force" % dest)
    os.makedirs(dest, exist_ok=True)
    rows = pb_rank.parse_index(index)
    names = []
    seen = set()
    for _tgid, _comm, va, epoch, _why in rows:
        name = dump_name(va, epoch)
        if name not in seen:
            seen.add(name)
            names.append(name)
    missing = []
    copied = []
    for name in names:
        src = os.path.join(dumps, name)
        if not os.path.isfile(src):
            missing.append(name)
            continue
        shutil.copy2(src, os.path.join(dest, name))
        copied.append(name)
    shutil.copy2(index, dest_index)
    used = set(copied) | {"pagedrop.index", "libs.txt"}
    packed_name = None
    if packed:
        if not os.path.isfile(packed):
            raise SystemExit("%s: no packed file" % packed)
        base = os.path.basename(packed)
        packed_name = stored_name(base if base.endswith(".upx") else "packed", used)
        shutil.copy2(packed, os.path.join(dest, packed_name))
    else:
        used.add("packed")
    lib_names = []
    for lib in libs or []:
        if not os.path.isfile(lib):
            raise SystemExit("%s: no library" % lib)
        dest_name = stored_name(os.path.basename(lib), used)
        shutil.copy2(lib, os.path.join(dest, dest_name))
        lib_names.append(dest_name)
    if lib_names:
        with open(os.path.join(dest, "libs.txt"), "w", encoding="ascii") as f:
            for name in lib_names:
                f.write(name + "\n")
    return {
        "copied": copied,
        "missing": missing,
        "packed": packed_name,
        "libs": lib_names,
    }


def main():
    ap = argparse.ArgumentParser(description="Copy one pagedrop run into a capture directory")
    ap.add_argument("--index", default="/tmp/pagedrop.index")
    ap.add_argument("--dumps", default="/tmp")
    ap.add_argument("--out", required=True, help="capture directory to create")
    ap.add_argument("--file", help="packed file to copy in, stored as *.upx or packed")
    ap.add_argument("--lib", action="append", default=[],
                    help="guest library to copy in and list in libs.txt")
    ap.add_argument("--force", action="store_true",
                    help="replace a capture directory that already has an index")
    args = ap.parse_args()
    info = collect(args.index, args.dumps, args.out, args.file, args.lib, args.force)
    print("collect copied=%d missing=%d dest=%s" % (
        len(info["copied"]), len(info["missing"]), args.out))
    for name in info["missing"]:
        print("missing %s" % name, file=sys.stderr)
    return 1 if info["missing"] else 0


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

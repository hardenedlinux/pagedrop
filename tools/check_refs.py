#!/usr/bin/env python3
"""Check that every drop-loop path cited by THIS tree actually resolves.

This is a copy of drop-loop/tools/check_refs.py, kept here on purpose. The
guard against drop-loop's citations rotting has to live outside drop-loop: the
last time the tree was lost, the tool that would have noticed was inside it.

Keep the two in sync. If they disagree, the stricter one wins.

It fails when:
  * drop-loop is missing entirely (the catastrophe this file exists to catch)
  * a cited drop-loop path does not exist and is not listed in
    drop-loop/runs/LOST.md as unrecoverable

Run it from the module tree. It loads nothing from the kernel and touches no
guest.
"""


import argparse
import os
import re
import sys

# drop-loop/ plus a path, stopping before sentence punctuation. The first
# character class allows a leading dot so that citations into a hidden
# directory (.specula-lite/) are checked rather than silently skipped.
REF = re.compile(r"drop-loop/[A-Za-z0-9.][A-Za-z0-9._/-]*")

# The citation stops at a path separator, so a trailing "." or "," from the
# sentence has to come off, but a real file keeps its own extension.
TRAILING = ".,;:)"


def module_tree_default():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def loop_default():
    return os.path.join(os.path.dirname(module_tree_default()), "drop-loop")


def cited_paths(text):
    out = set()
    for m in REF.finditer(text):
        ref = m.group(0).rstrip(TRAILING)
        if ref:
            out.add(ref)
    return out


def lost_paths(loop):
    """Paths recorded in runs/LOST.md as unrecoverable.

    A raw guest run log or an archived past build cannot be regenerated, so
    those citations are permanently unresolvable. They are reported as LOST
    and do not fail the check; anything missing that is NOT listed there does
    fail. A gate that is red forever gets ignored, and then it catches
    nothing, which is the failure this whole script exists to prevent.
    """
    manifest = os.path.join(loop, "runs", "LOST.md")
    lost = set()
    item = re.compile(r"^-\s+`([^`]+)`")
    if not os.path.isfile(manifest):
        return lost
    with open(manifest, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = item.match(line.strip())
            if m:
                lost.add("drop-loop/" + m.group(1))
    return lost


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--module-tree", default=module_tree_default())
    ap.add_argument("--loop", default=loop_default(),
                    help="the drop-loop tree (default: sibling of this one)")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    loop = os.path.abspath(args.loop)
    if not os.path.isdir(loop):
        print(f"FAIL check_refs: the drop-loop tree is gone: {loop}")
        print("    every drop-loop/... citation below is then unverifiable.")
        print("    Restore it from a snapshot, then re-run this.")
        print("    Snapshots, if any were taken, are tarballs outside the")
        print("    repo; see LOOP.md 'Running the loop'.")
        return 1
    lost = lost_paths(loop)

    sources = ["BUG-FIX.md", "pagedrop.c"]
    missing = {}
    gone = {}
    seen = 0

    for name in sources:
        path = os.path.join(args.module_tree, name)
        if not os.path.isfile(path):
            print(f"check_refs: no such source {path}", file=sys.stderr)
            return 2
        with open(path, encoding="utf-8", errors="replace") as fh:
            for ref in sorted(cited_paths(fh.read())):
                seen += 1
                rel = ref[len("drop-loop/"):]
                if os.path.exists(os.path.join(loop, rel)):
                    continue
                if ref in lost:
                    gone.setdefault(ref, []).append(name)
                else:
                    missing.setdefault(ref, []).append(name)

    if not args.quiet:
        print(f"check_refs: {seen} citation(s) of drop-loop paths from "
              f"{', '.join(sources)}")
        if gone:
            print(f"LOST: {len(gone)} citation(s) recorded unrecoverable in "
                  f"runs/LOST.md, not counted against this check")

    if missing:
        print(f"FAIL check_refs: {len(missing)} cited path(s) do not resolve")
        for ref in sorted(missing):
            where = ", ".join(sorted(set(missing[ref])))
            print(f"    MISSING  {ref}   (cited by {where})")
        return 1

    print("ALL REFS RESOLVE")
    return 0


if __name__ == "__main__":
    sys.exit(main())

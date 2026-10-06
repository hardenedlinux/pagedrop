#!/usr/bin/env python3
import os
import struct
import subprocess
import sys
import tempfile

PAGE = 4096
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOL = os.path.join(ROOT, "tools", "pb_rank.py")


def elf(loads):
    phoff = 64
    phentsize = 56
    hdr = bytearray(64)
    hdr[0:4] = b"\x7fELF"
    hdr[4] = 2
    hdr[5] = 1
    struct.pack_into("<HHIQQQIHHHHHH", hdr, 16, 3, 62, 1, 0, phoff, 0, 0, 64, phentsize, len(loads), 0, 0, 0)
    body = bytearray(hdr)
    data_off = 4096
    chunks = []
    for flags, pages in loads:
        chunks.append((flags, data_off, b"".join(pages)))
        data_off += len(pages) * PAGE
    for flags, off, blob in chunks:
        ph = struct.pack("<IIQQQQQQ", 1, flags, off, 0x400000 + off, 0, len(blob), len(blob), PAGE)
        body += ph
    body += bytes(4096 - len(body))
    for _, _, blob in chunks:
        body += blob
    return bytes(body)


def page(fill):
    return (fill * PAGE)[:PAGE]


def write(path, blob):
    with open(path, "wb") as f:
        f.write(blob)


def run(args):
    proc = subprocess.run([sys.executable, TOOL] + args, capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr


def main():
    libc_page = page(b"L")
    file_exec = page(b"E")
    file_data = page(b"D")
    novel = page(b"N")
    other = page(b"O")
    with tempfile.TemporaryDirectory() as tmp:
        libc = os.path.join(tmp, "libc-test.so")
        binary = os.path.join(tmp, "prog")
        index = os.path.join(tmp, "pagedrop.index")
        dumps = os.path.join(tmp, "dumps")
        os.mkdir(dumps)
        write(libc, elf([(5, [libc_page])]))
        write(binary, elf([(5, [file_exec]), (4, [file_data])]))
        write(os.path.join(dumps, "1000_1"), libc_page)
        write(os.path.join(dumps, "2000_2"), file_exec)
        write(os.path.join(dumps, "3000_3"), file_data)
        write(os.path.join(dumps, "4000_4"), novel)
        write(os.path.join(dumps, "4000_9"), novel)
        write(os.path.join(dumps, "5000_8"), other)
        write(os.path.join(dumps, "6000_7"), novel)
        lines = [
            "10 prog 1000 1 mmap",
            "10 prog 2000 2 mmap",
            "10 prog 3000 3 mprotect",
            "10 prog 4000 4 mprotect",
            "10 prog 4000 9 mprotect",
            "10 prog 5000 8 mmap",
            "11 other 6000 7 fault",
        ]
        write(index, ("\n".join(lines) + "\n").encode())
        code, out, err = run(["--index", index, "--dumps", dumps, "--file", binary, "--no-default-libs", "--lib", libc])
        if code != 2:
            raise SystemExit("expected exit 2, got %d %s" % (code, err))
        if "tgid 10" not in err or "tgid 11" not in err:
            raise SystemExit(err)
        code, out, err = run(["--index", index, "--dumps", dumps, "--file", binary, "--tgid", "10", "--no-default-libs", "--lib", libc])
        if code != 0:
            raise SystemExit(err or out)
        rows = [line.split() for line in out.splitlines() if line and line[0].isdigit()]
        vas = [row[1] for row in rows]
        if vas != ["4000", "4000", "5000", "3000"]:
            raise SystemExit("rank %s" % vas)
        if rows[0][2] != "9" or rows[1][2] != "4":
            raise SystemExit("epoch order %s" % rows[:2])
        if "drop_libc=1" not in out.splitlines()[0] or "drop_file=1" not in out.splitlines()[0]:
            raise SystemExit(out.splitlines()[0])
        if "skipped_tgid=1" not in out.splitlines()[0]:
            raise SystemExit(out.splitlines()[0])
        if any(row[1] == "6000" for row in rows):
            raise SystemExit("other tgid leaked")
    print("PASS pb_rank")
    return 0


if __name__ == "__main__":
    sys.exit(main())

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
        write(os.path.join(dumps, "4000_9"), page(b"Z"))
        write(os.path.join(dumps, "8000_5"), page(b"H"))
        tail = bytearray(file_exec)
        tail[128:] = b"T" * (PAGE - 128)
        write(os.path.join(dumps, "9000_6"), bytes(tail))
        extra = [
            "10 prog 8000 5 mmap",
            "10 prog 9000 6 mmap",
        ]
        write(index, ("\n".join(lines + extra) + "\n").encode())
        out_elf = os.path.join(tmp, "img.elf")
        code, out, err = run([
            "--index", index, "--dumps", dumps, "--file", binary, "--tgid", "10",
            "--no-default-libs", "--lib", libc, "--out", out_elf, "--arch", "aarch64",
        ])
        if code != 0:
            raise SystemExit(err or out)
        elf_lines = [line for line in out.splitlines() if line.startswith("elf ")]
        if len(elf_lines) != 2:
            raise SystemExit("gens %s" % elf_lines)
        if "slide=" not in elf_lines[0] or "stray=" not in elf_lines[0]:
            raise SystemExit(elf_lines[0])
        if not any(line.startswith("change gen=0 va=4000") for line in out.splitlines()):
            raise SystemExit("no changelog")
        gen0 = parse_loads(out_elf)
        gen1 = parse_loads(os.path.join(tmp, "img.1.elf"))
        if gen0[0] != 183 or gen1[0] != 183:
            raise SystemExit("machine %s %s" % (gen0[0], gen1[0]))
        g0 = expand(gen0[2])
        g1 = expand(gen1[2])
        if g0[0x4000][:1] != b"N" or g1[0x4000][:1] != b"Z" or g0[0x8000][:1] != b"H":
            raise SystemExit("epoch pages")
        if 0x7000 in g0 or 0x7000 in g1 or 0x8000 not in g0:
            raise SystemExit("hole")
        loads0 = [(va, flags, len(blob)) for va, flags, blob in gen0[2]]
        if (0x3000, 5, PAGE * 3) not in loads0 or (0x8000, 5, PAGE * 2) not in loads0:
            raise SystemExit("loads %s" % loads0)
        offsets = sorted(va for va, _, _ in gen0[2])
        if offsets[0] != 0x3000 or offsets[1] != 0x8000:
            raise SystemExit("phdr offsets %s" % offsets)
        tails = open(os.path.join(tmp, "img.tails"), "r", encoding="ascii").read().split()
        if tails[:3] != ["9000", "401000", "80"]:
            raise SystemExit("tails %s" % tails)
        libs = open(os.path.join(tmp, "img.libs"), "r", encoding="ascii").read().split()
        if len(libs) != 3 or libs[1] != libc or "pages=1" not in libs:
            raise SystemExit("libs %s" % libs)
        if not any(line.startswith("stray 9000") for line in out.splitlines()):
            raise SystemExit("no stray line")
        page_map = open(os.path.join(tmp, "img.pages"), "r", encoding="ascii").read()
        for want in ("3000 3 mprotect keep", "1000 1 mmap drop_lib:", "6000 8000 gap"):
            if want not in page_map:
                raise SystemExit("page map %r not in %s" % (want, page_map))
        check_slot(tmp)
        check_plt(tmp)
        check_strings_and_scan(tmp)
        check_arm_bl(tmp)
        check_no_host_libs(tmp)
        check_capture(tmp)
        check_collect(tmp)
        check_reports()
        check_lib_file_page(tmp)
        check_snap_prot(tmp)
        check_unpacked_only_on_full_match(tmp)
    print("PASS pb_rank")
    return 0


def dyn_file(code, rela_va, name):
    code = (code * PAGE)[:PAGE]
    strtab = b"\x00" + name.encode() + b"\x00"
    syms = struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)
    syms += struct.pack("<IBBHQQ", 1, 0x12, 0, 1, 0, 0)
    rela = struct.pack("<QQq", rela_va, 1 << 32, 0)
    dyn_size = 16 * 8
    str_off = dyn_size
    sym_off = str_off + len(strtab)
    rel_off = sym_off + len(syms)
    page2 = bytearray(PAGE)
    base = 0x402000
    tags = (
        (5, base + str_off),
        (10, len(strtab)),
        (6, base + sym_off),
        (11, 24),
        (23, base + rel_off),
        (2, len(rela)),
        (9, 24),
        (0, 0),
    )
    for i, (tag, val) in enumerate(tags):
        struct.pack_into("<qQ", page2, i * 16, tag, val)
    page2[str_off:str_off + len(strtab)] = strtab
    page2[sym_off:sym_off + len(syms)] = syms
    page2[rel_off:rel_off + len(rela)] = rela
    hdr = bytearray(64)
    hdr[0:4] = b"\x7fELF"
    hdr[4] = 2
    hdr[5] = 1
    struct.pack_into("<HHIQQQIHHHHHH", hdr, 16, 3, 62, 1, 0, 64, 0, 0, 64, 56, 3, 0, 0, 0)
    body = bytearray(hdr)
    body += struct.pack("<IIQQQQQQ", 1, 5, 0x1000, 0x401000, 0x401000, PAGE, PAGE, PAGE)
    body += struct.pack("<IIQQQQQQ", 1, 4, 0x2000, 0x402000, 0x402000, PAGE, PAGE, PAGE)
    body += struct.pack("<IIQQQQQQ", 2, 4, 0x2000, 0x402000, 0x402000, dyn_size, dyn_size, 8)
    body += bytes(0x1000 - len(body))
    body += code
    body += page2
    return bytes(body)


def elf_symbols(path):
    with open(path, "rb") as f:
        data = f.read()
    shoff = struct.unpack_from("<Q", data, 40)[0]
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 58)
    if shnum < 2 or shoff == 0:
        return []
    named = []
    for i in range(shnum):
        off = shoff + i * shentsize
        name, typ, _, _, sh_offset, sh_size, link, _, _, entsize = struct.unpack_from("<IIQQQQIIQQ", data, off)
        if typ != 2:
            continue
        str_off = shoff + link * shentsize
        _, _, _, _, str_at, str_sz, _, _, _, _ = struct.unpack_from("<IIQQQQIIQQ", data, str_off)
        raw = data[str_at:str_at + str_sz]
        step = entsize or 24
        for j in range(0, sh_size, step):
            st_name, _, _, _, value, _ = struct.unpack_from("<IBBHQQ", data, sh_offset + j)
            end = raw.find(b"\x00", st_name)
            label = raw[st_name:end].decode("ascii")
            if label:
                named.append((value, label))
    return named


def elf_symbol_bind(path, name):
    with open(path, "rb") as f:
        data = f.read()
    shoff = struct.unpack_from("<Q", data, 40)[0]
    shentsize, shnum, _ = struct.unpack_from("<HHH", data, 58)
    for i in range(shnum):
        off = shoff + i * shentsize
        _, typ, _, _, sh_offset, sh_size, link, _, _, entsize = struct.unpack_from(
            "<IIQQQQIIQQ", data, off)
        if typ != 2:
            continue
        str_at, str_sz = struct.unpack_from("<IIQQQQIIQQ", data, shoff + link * shentsize)[4:6]
        raw = data[str_at:str_at + str_sz]
        step = entsize or 24
        for j in range(0, sh_size, step):
            st_name, st_info, _, st_shndx, value, _ = struct.unpack_from(
                "<IBBHQQ", data, sh_offset + j)
            end = raw.find(b"\x00", st_name)
            if raw[st_name:end].decode("ascii") == name:
                return st_info, st_shndx, value
    return None


def check_slot(tmp):
    code = page(b"E")
    slide = (0x2000 - 0x401000) & ((1 << 64) - 1)
    rela_va = (0x3000 - slide) & ((1 << 64) - 1)
    binary = os.path.join(tmp, "dyn")
    dumps = os.path.join(tmp, "slotdumps")
    os.mkdir(dumps)
    write(binary, dyn_file(code, rela_va, "printf"))
    write(os.path.join(dumps, "2000_1"), code)
    write(os.path.join(dumps, "3000_2"), page(b"N"))
    index = os.path.join(tmp, "slot.index")
    write(index, b"7 prog 2000 1 mmap\n7 prog 3000 2 mmap\n")
    out = os.path.join(tmp, "slot.elf")
    code_rc, text, err = run([
        "--index", index, "--dumps", dumps, "--file", binary, "--tgid", "7",
        "--no-default-libs", "--out", out, "--arch", "x86_64",
    ])
    if code_rc != 0:
        raise SystemExit(err or text)
    if "syms=1" not in text:
        raise SystemExit(text)
    found = elf_symbols(out)
    if found != [(0x3000, "printf")]:
        raise SystemExit("syms %s" % found)
    check_orig(tmp, dumps)


def named_elf(page_bytes, page_va, name):
    hdr = bytearray(64)
    hdr[0:4] = b"\x7fELF"
    hdr[4] = 2
    hdr[5] = 1
    struct.pack_into("<HHIQQQIHHHHHH", hdr, 16, 3, 62, 1, page_va, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    body = bytearray(hdr)
    body += struct.pack("<IIQQQQQQ", 1, 5, 0x1000, page_va, page_va, PAGE, PAGE, PAGE)
    body += bytes(0x1000 - len(body))
    body += page_bytes
    strtab = b"\x00" + name.encode() + b"\x00"
    syms = struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)
    syms += struct.pack("<IBBHQQ", 1, 0x12, 0, 1, page_va, 0)
    shstr = b"\x00.symtab\x00.strtab\x00.shstrtab\x00"
    while len(body) % 8:
        body += b"\x00"
    sym_off = len(body)
    body += syms
    str_off = len(body)
    body += strtab
    shstr_off = len(body)
    body += shstr
    while len(body) % 8:
        body += b"\x00"
    sh_off = len(body)
    shdrs = bytearray(64 * 4)
    struct.pack_into("<IIQQQQIIQQ", shdrs, 64, 1, 2, 0, 0, sym_off, len(syms), 2, 1, 8, 24)
    struct.pack_into("<IIQQQQIIQQ", shdrs, 128, 9, 3, 0, 0, str_off, len(strtab), 0, 0, 1, 0)
    struct.pack_into("<IIQQQQIIQQ", shdrs, 192, 17, 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0)
    body += shdrs
    struct.pack_into("<Q", body, 40, sh_off)
    struct.pack_into("<HHH", body, 58, 64, 4, 3)
    return bytes(body)


def check_orig(tmp, dumps):
    blob = page(b"Q")
    orig = os.path.join(tmp, "orig.elf")
    packed = os.path.join(tmp, "packed.elf")
    index = os.path.join(tmp, "orig.index")
    write(orig, named_elf(blob, 0x3000, "mix"))
    write(packed, elf([(5, [page(b"P")])]))
    write(os.path.join(dumps, "9000_1"), blob)
    index = os.path.join(tmp, "orig.index")
    write(index, b"8 prog 9000 1 mprotect\n")
    out = os.path.join(tmp, "orig-out.elf")
    code_rc, text, err = run([
        "--index", index, "--dumps", dumps, "--file", packed, "--tgid", "8",
        "--no-default-libs", "--orig", orig, "--out", out, "--arch", "x86_64",
    ])
    if code_rc != 0:
        raise SystemExit(err or text)
    if "entry=9000" not in text or "syms=1" not in text:
        raise SystemExit(text)
    if elf_symbols(out) != [(0x9000, "mix")]:
        raise SystemExit("orig syms %s" % elf_symbols(out))
    info, shndx, _ = elf_symbol_bind(out, "mix")
    if shndx == 0xFFF1 or (info & 0xF) != 2:
        raise SystemExit("mix not bound as code info=%#x shndx=%#x" % (info, shndx))


def plt_elf():
    PLT = b"\xf3\x0f\x1e\xfa\xf2\xff\x25\xf5\x0f\x00\x00\x00\x00\x00\x00\x00"
    strtab = b"\x00printf\x00"
    syms = struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)
    syms += struct.pack("<IBBHQQ", 1, 0, 0, 0, 0, 0)
    rela = struct.pack("<QQq", 0x403000, (1 << 32) | 23, 0)
    dyn_size = 16 * 8
    off_str = 0x30
    off_sym = off_str + len(strtab)
    off_rela = off_sym + len(syms)
    page2 = bytearray(PAGE)
    page2[0:16] = PLT
    page2[off_rela:off_rela + len(rela)] = rela
    page2[off_str:off_str + len(strtab)] = strtab
    page2[off_sym:off_sym + len(syms)] = syms
    tags = ((5, 0x402000 + off_str), (10, len(strtab)), (6, 0x402000 + off_sym),
            (11, 24), (23, 0x402000 + off_rela), (2, len(rela)), (9, 24), (0, 0))
    for i, (tag, val) in enumerate(tags):
        struct.pack_into("<qQ", page2, 0x200 + i * 16, tag, val)
    code = page(b"C")
    got = bytearray(PAGE)
    hdr = bytearray(64)
    hdr[0:4] = b"\x7fELF"
    hdr[4] = 2
    hdr[5] = 1
    struct.pack_into("<HHIQQQIHHHHHH", hdr, 16, 3, 62, 1, 0x401000, 64, 0, 0, 64, 56, 4, 0, 0, 0)
    body = bytearray(hdr)
    body += struct.pack("<IIQQQQQQ", 1, 5, 0x1000, 0x401000, 0x401000, PAGE, PAGE, PAGE)
    body += struct.pack("<IIQQQQQQ", 1, 5, 0x2000, 0x402000, 0x402000, PAGE, PAGE, PAGE)
    body += struct.pack("<IIQQQQQQ", 1, 6, 0x3000, 0x403000, 0x403000, PAGE, PAGE, PAGE)
    body += struct.pack("<IIQQQQQQ", 2, 6, 0x2200, 0x402200, 0x402200, dyn_size, dyn_size, 8)
    body += bytes(0x1000 - len(body))
    body += code
    body += page2
    body += got

    names = ["", ".dynsym", ".dynstr", ".rela.plt", ".plt.sec", ".got", ".shstrtab"]
    shstr = b"\x00"
    offs = [0]
    for name in names[1:]:
        offs.append(len(shstr))
        shstr += name.encode() + b"\x00"
    sym_off = 0x2040
    str_off = 0x2030
    rela_off = 0x2010
    secs = [
        (offs[0], 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (offs[1], 11, 0x2, 0x402000 + sym_off, sym_off, len(syms), 2, 1, 8, 24),
        (offs[2], 3, 0x2, 0x402000 + str_off, str_off, len(strtab), 0, 0, 1, 0),
        (offs[3], 4, 0x42, 0x402000 + rela_off, rela_off, len(rela), 1, 2, 8, 24),
        (offs[4], 1, 0x6, 0x402000, 0x2000, 16, 0, 0, 16, 0),
        (offs[5], 1, 0x3, 0x403000, 0x3000, 8, 0, 0, 8, 0),
        (offs[6], 3, 0, 0, 0, len(shstr), 0, 0, 1, 0),
    ]
    while len(body) % 8:
        body += b"\x00"
    shstr_at = len(body)
    body += shstr
    while len(body) % 8:
        body += b"\x00"
    sh_off = len(body)
    secs[6] = (offs[6], 3, 0, 0, shstr_at, len(shstr), 0, 0, 1, 0)
    for sec in secs:
        body += struct.pack("<IIQQQQIIQQ", *sec)
    struct.pack_into("<Q", body, 40, sh_off)
    struct.pack_into("<HHH", body, 58, 64, len(secs), 6)
    return bytes(body), code, bytes(page2)


def check_plt(tmp):
    orig, code, plt = plt_elf()
    orig_path = os.path.join(tmp, "plt.elf")
    packed = os.path.join(tmp, "pltpacked.elf")
    dumps = os.path.join(tmp, "pltdumps")
    os.mkdir(dumps)
    write(orig_path, orig)
    write(packed, elf([(5, [page(b"P")])]))
    write(os.path.join(dumps, "501000_1"), code)
    write(os.path.join(dumps, "502000_2"), plt)
    index = os.path.join(tmp, "plt.index")
    write(index, b"9 prog 501000 1 mprotect\n9 prog 502000 2 mprotect\n")
    out = os.path.join(tmp, "plt-out.elf")
    code_rc, text, err = run([
        "--index", index, "--dumps", dumps, "--file", packed, "--orig", orig_path,
        "--tgid", "9", "--no-default-libs", "--out", out, "--arch", "x86_64",
    ])
    if code_rc != 0:
        raise SystemExit(err or text)
    found = elf_symbols(out)
    if (0x502000, "printf") not in found:
        raise SystemExit("plt not named %s" % found)


def check_strings_and_scan(tmp):
    body = bytearray(page(b"\x90"))
    text = b"wide-ok marker string"
    body[0x100:0x100 + len(text)] = text
    rel = (0xA02000 - (0xA01000 + 0x10 + 5)) & 0xFFFFFFFF
    body[0x10] = 0xE8
    struct.pack_into("<I", body, 0x11, rel)
    packed = os.path.join(tmp, "stpacked.elf")
    dumps = os.path.join(tmp, "stdumps")
    os.mkdir(dumps)
    write(packed, elf([(5, [page(b"S")])]))
    write(os.path.join(dumps, "a01000_1"), bytes(body))
    write(os.path.join(dumps, "a03000_2"), page(b"\xcc"))
    index = os.path.join(tmp, "st.index")
    write(index, b"4 st a01000 1 mprotect\n4 st a03000 2 mprotect\n")
    out = os.path.join(tmp, "st-out.elf")
    code_rc, text_out, err = run([
        "--index", index, "--dumps", dumps, "--file", packed, "--tgid", "4",
        "--no-default-libs", "--out", out, "--arch", "x86_64",
    ])
    if code_rc != 0:
        raise SystemExit(err or text_out)
    strings = open(os.path.join(tmp, "st-out.strings"), "r", encoding="ascii").read()
    if text.decode() not in strings:
        raise SystemExit("strings %s" % strings)
    if not any(line.startswith("hole_call a02000") for line in text_out.splitlines()):
        raise SystemExit("no hole_call line: %s" % text_out)


def check_arm_bl(tmp):
    body = bytearray(page(b"\x00"))
    struct.pack_into("<I", body, 0, 0x94000800)
    struct.pack_into("<I", body, 4, 0x00FF0094)
    packed = os.path.join(tmp, "armpacked.elf")
    dumps = os.path.join(tmp, "armdumps")
    os.mkdir(dumps)
    write(packed, elf([(5, [page(b"A")])]))
    write(os.path.join(dumps, "1000_1"), bytes(body))
    write(os.path.join(dumps, "5000_2"), page(b"\x11"))
    index = os.path.join(tmp, "arm.index")
    write(index, b"3 arm 1000 1 mmap\n3 arm 5000 2 mmap\n")
    out = os.path.join(tmp, "arm-out.elf")
    code_rc, text, err = run([
        "--index", index, "--dumps", dumps, "--file", packed, "--tgid", "3",
        "--no-default-libs", "--out", out, "--arch", "aarch64",
    ])
    if code_rc != 0:
        raise SystemExit(err or text)
    holes = [line for line in text.splitlines() if line.startswith("hole_call ")]
    if holes != ["hole_call 3000 count=1"]:
        raise SystemExit("arm holes %s" % holes)


def check_no_host_libs(tmp):
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import pb_rank
    libs = [p for p in pb_rank.default_libs() if "libc" in os.path.basename(p)]
    blob = next(iter(pb_rank.file_pages(libs[0], False))) if libs else page(b"Q")
    dumps = os.path.join(tmp, "hostdumps")
    os.mkdir(dumps)
    packed = os.path.join(tmp, "hostpacked.elf")
    index = os.path.join(tmp, "host.index")
    write(packed, elf([(5, [page(b"P")])]))
    write(os.path.join(dumps, "1000_1"), blob)
    write(index, b"8 host 1000 1 mmap\n")
    code_rc, text, err = run([
        "--index", index, "--dumps", dumps, "--file", packed, "--tgid", "8",
    ])
    if code_rc != 0:
        raise SystemExit(err or text)
    if "not filtering with host libraries" not in err:
        raise SystemExit(err)
    if "drop_libc=0" not in text.splitlines()[0]:
        raise SystemExit(text.splitlines()[0])
    if not any(line.split()[1] == "1000" for line in text.splitlines() if line[:1].isdigit()):
        raise SystemExit("host libc page was dropped: %s" % text)


def check_capture(tmp):
    cap = os.path.join(tmp, "cap")
    os.mkdir(cap)
    stub = page(b"S")
    libc_page = page(b"L")
    body = bytearray(page(b"\x90"))
    struct.pack_into("<Bi", body, 0, 0xE8, 0x4000 - (0x2000 + 5))
    write(os.path.join(cap, "sample.upx"), elf([(5, [stub])]))
    write(os.path.join(cap, "libc.so.6"), elf([(5, [libc_page])]))
    write(os.path.join(cap, "decoy.elf"), elf([(4, [page(b"Z")])]))
    write(os.path.join(cap, "libs.txt"), b"libc.so.6\n")
    write(os.path.join(cap, "1000_3"), stub)
    write(os.path.join(cap, "2000_1"), bytes(body))
    write(os.path.join(cap, "4000_2"), page(b"\xc3"))
    write(os.path.join(cap, "7000_4"), libc_page)
    write(os.path.join(cap, "pagedrop.index"), (
        "9 wide 1000 3 mmap\n"
        "9 wide 2000 1 mmap\n"
        "9 wide 4000 2 mprotect\n"
        "9 wide 7000 4 mmap\n"
    ).encode())
    out = os.path.join(tmp, "image.elf")
    code_rc, text, err = run(["--capture", cap, "--out", out])
    if code_rc != 0:
        raise SystemExit(err or text)
    summary = text.splitlines()[0]
    if "drop_file=1" not in summary or "drop_libc=1" not in summary or "kept=2" not in summary:
        raise SystemExit(summary)
    numbered = [line.split()[1] for line in text.splitlines() if line[:1].isdigit()]
    if numbered != ["2000", "4000"]:
        raise SystemExit("address order %s" % numbered)
    if any(line.startswith("hole_call 4000") for line in text.splitlines()):
        raise SystemExit("cross-page call reported as a hole: %s" % text)
    if "names none" not in text:
        raise SystemExit(text)
    if "not the stitch" in text:
        raise SystemExit(text)
    pages = open(os.path.join(tmp, "image.pages"), "r", encoding="ascii").read()
    if "3000 4000 gap never_dumped" not in pages:
        raise SystemExit(pages)
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import pb_rank
    if pb_rank.orig_candidates(cap, set()):
        raise SystemExit("library or decoy picked as orig")


def check_collect(tmp):
    src = os.path.join(tmp, "raw")
    os.mkdir(src)
    index = os.path.join(src, "pagedrop.index")
    write(index, b"4 prog 1000 1 mmap\n4 prog 2000 2 mprotect\n")
    write(os.path.join(src, "1000_1"), page(b"A"))
    write(os.path.join(src, "2000_2"), page(b"B"))
    write(os.path.join(src, "deadbeef_9"), page(b"X"))
    packed = os.path.join(tmp, "sample.upx")
    lib = os.path.join(tmp, "libc.so.6")
    write(packed, b"packed-bytes")
    write(lib, b"lib-bytes")
    dest = os.path.join(tmp, "collected")
    proc = subprocess.run([
        sys.executable, os.path.join(ROOT, "tools", "pb_collect.py"),
        "--index", index, "--dumps", src, "--out", dest,
        "--file", packed, "--lib", lib,
    ], capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(proc.stderr or proc.stdout)
    for name in ("pagedrop.index", "1000_1", "2000_2", "sample.upx", "libc.so.6", "libs.txt"):
        if not os.path.isfile(os.path.join(dest, name)):
            raise SystemExit("missing %s" % name)
    if os.path.exists(os.path.join(dest, "deadbeef_9")):
        raise SystemExit("unindexed dump copied")
    if open(os.path.join(dest, "libs.txt"), "r", encoding="ascii").read() != "libc.so.6\n":
        raise SystemExit("libs.txt")
    again = subprocess.run([
        sys.executable, os.path.join(ROOT, "tools", "pb_collect.py"),
        "--index", index, "--dumps", src, "--out", dest,
    ], capture_output=True, text=True)
    if again.returncode == 0:
        raise SystemExit("second collect should refuse")
    plain = os.path.join(tmp, "not-upx.bin")
    write(plain, b"plain-packed")
    plain_dest = os.path.join(tmp, "collected-plain")
    proc = subprocess.run([
        sys.executable, os.path.join(ROOT, "tools", "pb_collect.py"),
        "--index", index, "--dumps", src, "--out", plain_dest, "--file", plain,
    ], capture_output=True, text=True)
    if proc.returncode != 0 or not os.path.isfile(os.path.join(plain_dest, "packed")):
        raise SystemExit(proc.stderr or proc.stdout or "packed name")


def check_reports():
    import io
    from contextlib import redirect_stdout
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import pb_rank
    buf = io.StringIO()
    with redirect_stdout(buf):
        pb_rank.report_upx({"status": "ok", "same": 3, "diff": 0, "path": "/tmp/x.unpacked"}, "a.upx")
    if buf.getvalue().strip() != "upx -d matched=3 unmatched=0; open /tmp/x.unpacked, not the stitch":
        raise SystemExit(buf.getvalue())
    buf = io.StringIO()
    with redirect_stdout(buf):
        pb_rank.report_upx({"status": "ok", "same": 1, "diff": 2, "path": "/tmp/x.unpacked"}, "a.upx")
    if "not the stitch" in buf.getvalue() or "matched=1 unmatched=2" not in buf.getvalue():
        raise SystemExit(buf.getvalue())
    buf = io.StringIO()
    with redirect_stdout(buf):
        pb_rank.report_names("none")
    if "names none" not in buf.getvalue():
        raise SystemExit(buf.getvalue())


def check_unpacked_only_on_full_match(tmp):
    """A partial upx -d match must not leave image.unpacked behind to be opened by mistake."""
    packed = os.path.join(tmp, "uzpacked.elf")
    write(packed, elf([(5, [page(b"U")])]))
    dumps = os.path.join(tmp, "uwdumps")
    os.mkdir(dumps)
    write(os.path.join(dumps, "1000_1"), page(b"V"))
    write(os.path.join(dumps, "2000_2"), page(b"W"))
    index = os.path.join(tmp, "uw.index")
    write(index, b"11 up 1000 1 mmap\n11 up 2000 2 mmap\n")
    out = os.path.join(tmp, "uimage.elf")
    code_rc, text, err = run([
        "--index", index, "--dumps", dumps, "--file", packed, "--tgid", "11",
        "--no-default-libs", "--out", out, "--arch", "x86_64",
    ])
    if code_rc != 0:
        raise SystemExit(err or text)
    stray = os.path.join(tmp, "uimage.unpacked")
    if os.path.exists(stray) and "unmatched=0" not in text:
        raise SystemExit("image.unpacked written on a partial match: %s" % text)


def check_lib_file_page(tmp):
    """A library page that is not a PT_LOAD is still the library."""
    body = bytearray(elf([(5, [page(b"L")])]))
    if len(body) % PAGE:
        body += bytes(PAGE - (len(body) % PAGE))
    note = page(b"N")
    lib = bytes(body) + note
    dumps = os.path.join(tmp, "notedumps")
    os.mkdir(dumps)
    lib_path = os.path.join(tmp, "libc-note.so")
    packed = os.path.join(tmp, "notepacked.elf")
    index = os.path.join(tmp, "note.index")
    write(lib_path, lib)
    write(packed, elf([(5, [page(b"P")])]))
    write(os.path.join(dumps, "1000_1"), note)
    write(os.path.join(dumps, "2000_2"), page(b"Q"))
    write(index, b"6 note 1000 1 mmap\n6 note 2000 2 mmap\n")
    out = os.path.join(tmp, "note.elf")
    code_rc, text, err = run([
        "--index", index, "--dumps", dumps, "--file", packed, "--tgid", "6",
        "--no-default-libs", "--lib", lib_path, "--out", out, "--arch", "x86_64",
    ])
    if code_rc != 0:
        raise SystemExit(err or text)
    if "kept=1" not in text.splitlines()[0] or "dropped=1" not in text.splitlines()[0]:
        raise SystemExit(text.splitlines()[0])
    pages = expand(parse_loads(out)[2])
    if 0x1000 in pages or pages.get(0x2000, b"")[:1] != b"Q":
        raise SystemExit("note page leaked into the elf")


def check_snap_prot(tmp):
    dumps = os.path.join(tmp, "snapdumps")
    os.mkdir(dumps)
    packed = os.path.join(tmp, "snappacked.elf")
    index = os.path.join(tmp, "snap.index")
    write(packed, elf([(5, [page(b"P")])]))
    write(os.path.join(dumps, "3000_1"), page(b"S"))
    write(index, b"7 snap 3000 1 snap\n")
    out = os.path.join(tmp, "snap.elf")
    code_rc, text, err = run([
        "--index", index, "--dumps", dumps, "--file", packed, "--tgid", "7",
        "--no-default-libs", "--out", out, "--arch", "x86_64",
    ])
    if code_rc != 0:
        raise SystemExit(err or text)
    loads = parse_loads(out)[2]
    if not loads or loads[0][1] != 4:
        raise SystemExit("snap flags %s" % [(va, flags) for va, flags, _ in loads])


def expand(loads):
    pages = {}
    for va, _, blob in loads:
        for i in range(0, len(blob), PAGE):
            pages[va + i] = blob[i:i + PAGE]
    return pages


def parse_loads(path):
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != b"\x7fELF":
        raise SystemExit("not elf")
    machine = struct.unpack_from("<H", data, 18)[0]
    entry = struct.unpack_from("<Q", data, 24)[0]
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    loads = []
    for i in range(phnum):
        off = phoff + i * phentsize
        p_type, p_flags, p_offset, p_vaddr, _, p_filesz, _, _ = struct.unpack_from("<IIQQQQQQ", data, off)
        if p_type != 1:
            continue
        loads.append((p_vaddr, p_flags, data[p_offset:p_offset + p_filesz]))
    return machine, entry, loads


if __name__ == "__main__":
    sys.exit(main())

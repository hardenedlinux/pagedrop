#!/usr/bin/env python3
"""Turn pagedrop page dumps into one loadable image per generation.

This module reads only what the kernel module already writes:
/tmp/pagedrop.index and the per-page files named <va>_<epoch>.
Nothing here changes pagedrop.c or the on-target behaviour.
"""

import os
import shutil
import struct
import subprocess
import tempfile

PAGE = 4096
MASK = (1 << 64) - 1

PT_LOAD = 1
PT_DYNAMIC = 2
PF_X = 1
PF_W = 2
PF_R = 4
PF_RX = PF_R | PF_X

SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

EM_X86_64 = 62
EM_AARCH64 = 183
MACHINE_ARCH = {EM_X86_64: "x86_64", EM_AARCH64: "aarch64"}
ARCH_MACHINE = {v: k for k, v in MACHINE_ARCH.items()}

SHT_SYMTAB = 2
SHT_STRTAB = 3
SHN_ABS = 0xFFF1

DT_NULL = 0
DT_PLTRELSZ = 2
DT_STRTAB = 5
DT_SYMTAB = 6
DT_RELA = 7
DT_RELASZ = 8
DT_RELAENT = 9
DT_STRSZ = 10
DT_SYMENT = 11
DT_REL = 17
DT_RELSZ = 18
DT_RELENT = 19
DT_JMPREL = 23

TAIL_MIN = 64
TAIL_MIN_TEXT = 16
STRLEN_MIN = 4
MAX_STRINGS = 5000
MAX_CALL_TARGETS = 12


def machine_id(arch):
    if arch not in ARCH_MACHINE:
        raise SystemExit("unknown arch %s" % arch)
    return ARCH_MACHINE[arch]


def host_arch():
    import platform
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "x86_64"
    if machine in ("aarch64", "arm64"):
        return "aarch64"
    return None


def cstr(blob, off):
    if off is None or off < 0 or off >= len(blob):
        return None
    end = blob.find(b"\x00", off)
    if end < 0:
        return None
    return blob[off:end].decode("ascii", "replace")


def elf_header(data):
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        return None
    return {
        "machine": struct.unpack_from("<H", data, 18)[0],
        "entry": struct.unpack_from("<Q", data, 24)[0],
        "phoff": struct.unpack_from("<Q", data, 32)[0],
        "shoff": struct.unpack_from("<Q", data, 40)[0],
        "phentsize": struct.unpack_from("<H", data, 54)[0],
        "phnum": struct.unpack_from("<H", data, 56)[0],
        "shentsize": struct.unpack_from("<H", data, 58)[0],
        "shnum": struct.unpack_from("<H", data, 60)[0],
        "shstrndx": struct.unpack_from("<H", data, 62)[0],
    }


def elf_entry(data):
    hdr = elf_header(data)
    return hdr["entry"] if hdr else None


def elf_arch(data):
    hdr = elf_header(data)
    if not hdr:
        return None
    return MACHINE_ARCH.get(hdr["machine"])


def elf_phdrs(data):
    hdr = elf_header(data)
    if not hdr or hdr["phnum"] == 0xFFFF or hdr["phentsize"] < 56:
        return None
    out = []
    for i in range(hdr["phnum"]):
        off = hdr["phoff"] + i * hdr["phentsize"]
        if off + 56 > len(data):
            return None
        p_type, p_flags, p_offset, p_vaddr, _, p_filesz, p_memsz, _ = struct.unpack_from(
            "<IIQQQQQQ", data, off)
        out.append((p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz))
    return out


def elf_sections(data):
    hdr = elf_header(data)
    if not hdr or not hdr["shoff"] or not hdr["shnum"] or hdr["shentsize"] < 64:
        return []
    if hdr["shoff"] + hdr["shnum"] * hdr["shentsize"] > len(data):
        return []
    raw = []
    for i in range(hdr["shnum"]):
        raw.append(struct.unpack_from("<IIQQQQIIQQ", data, hdr["shoff"] + i * hdr["shentsize"]))
    shstr = b""
    if hdr["shstrndx"] < len(raw):
        _, _, _, _, str_off, str_size = raw[hdr["shstrndx"]][:6]
        shstr = data[str_off:str_off + str_size]
    return [(cstr(shstr, sh[0]) or "",) + sh[1:] for sh in raw]


def iter_load_pages(data):
    phdrs = elf_phdrs(data)
    if not phdrs:
        return
    for p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz in phdrs:
        if p_type != PT_LOAD or p_memsz == 0:
            continue
        base = p_offset - (p_vaddr % PAGE)
        count = (p_memsz + (p_vaddr % PAGE) + PAGE - 1) // PAGE
        page_va = p_vaddr - (p_vaddr % PAGE)
        for i in range(count):
            foff = base + i * PAGE
            chunk = bytearray(PAGE)
            src = max(foff, p_offset)
            end = min(foff + PAGE, p_offset + p_filesz)
            if src < end and src < len(data):
                take = min(end, len(data)) - src
                if take > 0:
                    chunk[src - foff:src - foff + take] = data[src:src + take]
            yield page_va + i * PAGE, p_flags, bytes(chunk)


def read_file(path):
    with open(path, "rb") as f:
        return f.read()


def file_blobs(data):
    """Every page-sized image of the file, not only PT_LOAD.

    A library note or a short tail is still the library. The ranker drops
    those pages. The stitcher has to drop the same bytes, or the ELF keeps
    a piece of libc the filter already rejected.
    """
    blobs = set()
    n = len(data) // PAGE
    for i in range(n):
        blobs.add(data[i * PAGE:(i + 1) * PAGE])
    if len(data) % PAGE:
        tail = data[n * PAGE:]
        blobs.add(tail + bytes(PAGE - len(tail)))
    for _, _, blob in iter_load_pages(data):
        blobs.add(blob)
    return blobs


def page_table(path):
    data = read_file(path)
    return data, list(iter_load_pages(data))


def ranges_of(loads):
    return [(vaddr, vaddr + len(blob)) for vaddr, _, blob in loads]


def in_ranges(addr, ranges):
    return any(lo <= addr < hi for lo, hi in ranges)


def slide_of(hits):
    slides = set((dump_va - file_va) & MASK for dump_va, file_va in hits)
    return slides.pop() if len(slides) == 1 else None


def prot_flags(why):
    return PF_R if why in ("read", "snap") else PF_RX


def read_dump(dumps, va, epoch):
    path = os.path.join(dumps, "%x_%d" % (va, epoch))
    try:
        blob = read_file(path)
    except OSError:
        return None
    if len(blob) != PAGE:
        blob = blob[:PAGE].ljust(PAGE, b"\x00")
    return blob


def classify(rows, tgid, dumps, file_set, lib_sets, file_pages, lib_pages, reloc_sites):
    kept = []
    file_hits = []
    lib_hits = []
    tails = []
    status = []
    for row_tgid, _, va, epoch, why in rows:
        if row_tgid != tgid or va % PAGE:
            continue
        blob = read_dump(dumps, va, epoch)
        if blob is None:
            status.append((va, epoch, why, "missing"))
            continue
        if any(blob in pages for _, pages in lib_sets):
            base = None
            for path, _, pages in lib_pages:
                hit = next((fva for fva, page in pages if page == blob), None)
                if hit is not None:
                    lib_hits.append((path, va, hit))
                    base = path
                    break
            status.append((va, epoch, why, "drop_lib:%s" % os.path.basename(base or "?")))
            continue
        if blob in file_set:
            hit = next((fva for fva, page in file_pages if page == blob), None)
            file_hits.append((va, hit) if hit is not None else (va, None))
            status.append((va, epoch, why, "drop_file"))
            continue
        tail = tail_of(blob, file_pages, reloc_sites)
        if tail:
            tails.append((va, epoch, tail[0], tail[1]))
        status.append((va, epoch, why, "keep"))
        kept.append((epoch, va, why, blob))
    kept.sort()
    return kept, file_hits, lib_hits, tails, status


def common_prefix(a, b, ignore):
    n = 0
    for i, (x, y) in enumerate(zip(a, b)):
        if i in ignore:
            continue
        if x != y:
            break
        n = i + 1
    return n


def tail_of(blob, pages, reloc_sites):
    best = None
    for file_va, page in pages:
        if blob == page:
            return None
        page_off = file_va % PAGE
        ignore = reloc_sites.get(page_off)
        n = common_prefix(blob, page, ignore) if ignore else common_prefix(blob, page, ())
        if n < TAIL_MIN or n >= PAGE:
            continue
        head = blob[:n]
        if head.count(0) > n - TAIL_MIN_TEXT:
            continue
        if best is None or n > best[0]:
            best = (n, file_va)
    if best is None:
        return None
    return best[1], best[0]


def reloc_sites_from(data):
    """Offsets inside a page that relocations rewrite, keyed by in-page offset."""
    sites = {}
    ordered = dynamic_relocs(data)
    for r_offset, _ in ordered:
        for delta in range(-4, 8):
            key = (r_offset + delta) % PAGE
            sites.setdefault(key, set())
    return sites


def generations(kept, packed_pages):
    """One generation per real change; a new address or a revert to packed bytes is not a change."""
    gens = []
    changelog = []
    current = {}
    for epoch, va, why, blob in kept:
        old = current.get(va)
        if old is not None and old[2] == blob:
            continue
        if old is not None and blob in packed_pages:
            current[va] = (epoch, why, blob)
            continue
        if old is None:
            current[va] = (epoch, why, blob)
            continue
        gens.append(dict(current))
        changelog.append({
            "gen": len(gens) - 1,
            "va": va,
            "old_epoch": old[0],
            "new_epoch": epoch,
            "why": why,
        })
        current = dict(current)
        current[va] = (epoch, why, blob)
    if current:
        gens.append(current)
    return gens, changelog


def load_runs(gen, demote):
    items = []
    for va in sorted(gen):
        _, why, blob = gen[va]
        flags = PF_R if (why in ("read", "snap") or va in demote) else PF_RX
        items.append((va, flags, blob))
    groups = []
    for va, flags, blob in items:
        if groups and va == groups[-1][-1][0] + PAGE and flags == groups[-1][-1][1]:
            groups[-1].append((va, flags, blob))
        else:
            groups.append([(va, flags, blob)])
    return [(g[0][0], g[0][1], b"".join(item[2] for item in g)) for g in groups]


def splice_readonly(loads, orig_data, slide):
    """Fill gaps with the original's non-executable pages when the dumps never had them."""
    if orig_data is None or slide is None:
        return loads, []
    ranges = ranges_of(loads)
    added = []
    for va, flags, blob in iter_load_pages(orig_data):
        if flags & PF_X:
            continue
        run = (va + slide) & MASK
        if in_ranges(run, ranges):
            continue
        added.append((run, blob))
    if not added:
        return loads, []
    added.sort()
    merged = list(loads) + [(va, PF_R, blob) for va, blob in added]
    merged.sort()
    return load_runs_from(merged), added


def load_runs_from(items):
    groups = []
    for va, flags, blob in items:
        if groups and va == groups[-1][-1][0] + PAGE and flags == groups[-1][-1][1]:
            groups[-1].append((va, flags, blob))
        else:
            groups.append([(va, flags, blob)])
    return [(g[0][0], g[0][1], b"".join(i[2] for i in g)) for g in groups]


def va_slice(data, phdrs, va, size):
    for p_type, _, p_offset, p_vaddr, p_filesz, _ in phdrs:
        if p_type != PT_LOAD or p_filesz == 0:
            continue
        if p_vaddr <= va < p_vaddr + p_filesz:
            off = p_offset + (va - p_vaddr)
            if off < 0 or off + size > len(data):
                return None
            return data[off:off + size]
    return None


def load_span(phdrs, va):
    for p_type, _, p_offset, p_vaddr, p_filesz, _ in phdrs:
        if p_type != PT_LOAD or p_filesz == 0:
            continue
        if p_vaddr <= va < p_vaddr + p_filesz:
            return p_offset + (va - p_vaddr), p_offset + p_filesz
    return None


def parse_dynamic(data):
    phdrs = elf_phdrs(data)
    if not phdrs:
        return None
    blob = None
    for p_type, _, p_offset, _, p_filesz, _ in phdrs:
        if p_type == PT_DYNAMIC and p_filesz:
            blob = data[p_offset:p_offset + p_filesz]
            break
    if not blob:
        return None
    tags = {}
    for i in range(0, len(blob) - 15, 16):
        tag, val = struct.unpack_from("<qQ", blob, i)
        if tag == DT_NULL:
            break
        tags[tag] = val
    return phdrs, tags


def dynamic_relocs(data, jmprel_only=False):
    parsed = parse_dynamic(data)
    if not parsed:
        return []
    phdrs, tags = parsed
    strsz = tags.get(DT_STRSZ)
    syment = tags.get(DT_SYMENT, 24)
    if DT_STRTAB not in tags or DT_SYMTAB not in tags or not strsz or syment < 24:
        return []
    strtab = va_slice(data, phdrs, tags[DT_STRTAB], strsz)
    span = load_span(phdrs, tags[DT_SYMTAB])
    if not strtab or not span:
        return []
    sym_off, sym_end = span
    if sym_off < 0 or sym_end > len(data):
        return []
    symtab = data[sym_off:sym_end]

    def name_at(index):
        at = index * syment
        if at + 24 > len(symtab):
            return None
        return cstr(strtab, struct.unpack_from("<I", symtab, at)[0])

    def read_rela(tag_off, tag_size, ent_tag, ent_default):
        raw = va_slice(data, phdrs, tags[tag_off], tags[tag_size]) or b""
        ent = tags.get(ent_tag, ent_default)
        out = []
        for i in range(0, len(raw) - ent + 1, ent):
            r_offset, r_info = struct.unpack_from("<QQ", raw, i)
            name = name_at(r_info >> 32)
            if name:
                out.append((r_offset, name))
        return out

    if jmprel_only:
        if DT_JMPREL not in tags or DT_PLTRELSZ not in tags:
            return []
        return read_rela(DT_JMPREL, DT_PLTRELSZ, DT_RELAENT, 24)

    out = []
    if DT_RELA in tags and DT_RELASZ in tags:
        out += read_rela(DT_RELA, DT_RELASZ, DT_RELAENT, 24)
    if DT_REL in tags and DT_RELSZ in tags:
        raw = va_slice(data, phdrs, tags[DT_REL], tags[DT_RELSZ]) or b""
        ent = tags.get(DT_RELENT, 16)
        for i in range(0, len(raw) - ent + 1, ent):
            r_offset, r_info = struct.unpack_from("<QQ", raw, i)
            name = name_at(r_info >> 32)
            if name:
                out.append((r_offset, name))
    if DT_JMPREL in tags and DT_PLTRELSZ in tags:
        out += read_rela(DT_JMPREL, DT_PLTRELSZ, DT_RELAENT, 24)
    return out


def x86_plt_stubs(data):
    """Every indirect jump through the GOT, as (entry address, GOT address).

    A call reaches the start of the 16-byte PLT entry, which is what a PLT
    ``F2 FF 25`` with its leading endbr64 looks like, so the block containing
    the jump is the nameable address. Deduplicating on that block also removes
    the double match between the prefixed and unprefixed encodings.
    """
    found = {}
    for va, flags, blob in iter_load_pages(data):
        if not (flags & PF_X):
            continue
        for i in range(len(blob) - 6):
            if blob[i:i + 3] == b"\xF2\xFF\x25":
                disp_at = i + 3
            elif blob[i:i + 2] == b"\xFF\x25":
                disp_at = i + 2
            else:
                continue
            disp = struct.unpack_from("<i", blob, disp_at)[0]
            got = va + disp_at + 4 + disp
            entry = va + (i & ~15)
            if entry not in found:
                found[entry] = got
    return sorted(found.items())


def arm_plt_stubs(data, count):
    """AArch64 PLT: a 32-byte PLT0 then 16-byte entries in relocation order."""
    for sh in elf_sections(data):
        name, _, flags, addr, _, size = sh[0], sh[1], sh[2], sh[3], sh[4], sh[5]
        if name != ".plt" or not (flags & SHF_ALLOC) or not (flags & SHF_EXECINSTR):
            continue
        if size >= 32 + count * 16:
            return [addr + 32 + i * 16 for i in range(count)]
        if size >= count * 16:
            return [addr + i * 16 for i in range(count)]
    return None


def plt_entry_vas(data, count):
    if count <= 0:
        return None
    header = elf_header(data)
    if header and header["machine"] == EM_AARCH64:
        return arm_plt_stubs(data, count)
    secs = [s for s in elf_sections(data)
            if s[0].startswith(".plt") and (s[2] & SHF_ALLOC) and (s[2] & SHF_EXECINSTR)]
    secs.sort(key=lambda s: s[3])
    for sec in secs:
        if sec[5] == count * 16:
            return [sec[3] + i * 16 for i in range(count)]
    for sec in secs:
        if sec[5] == (count + 1) * 16:
            return [sec[3] + 16 + i * 16 for i in range(count)]
    return None


def import_names(data, slide, ranges):
    """GOT slots plus the PLT entries that reference them, so calls resolve by name."""
    if data is None or slide is None:
        return []
    jmprel = dynamic_relocs(data, jmprel_only=True)
    named = {}
    for r_offset, name in dynamic_relocs(data):
        runtime = (r_offset + slide) & MASK
        if in_ranges(runtime, ranges):
            named.setdefault(runtime, name)
    by_got = {}
    for r_offset, name in jmprel:
        by_got.setdefault(r_offset, name)
    header = elf_header(data)
    if header and header["machine"] == EM_X86_64:
        for stub_va, got_va in x86_plt_stubs(data):
            name = by_got.get(got_va)
            if name:
                runtime = (stub_va + slide) & MASK
                if in_ranges(runtime, ranges):
                    named.setdefault(runtime, name)
        return [(addr, name) for addr, name in sorted(named.items())]
    vas = plt_entry_vas(data, len(jmprel))
    if vas:
        for i, va in enumerate(vas):
            if i >= len(jmprel):
                break
            runtime = (va + slide) & MASK
            if in_ranges(runtime, ranges):
                named.setdefault(runtime, jmprel[i][1])
    return [(addr, name) for addr, name in sorted(named.items())]


def section_symbols(data, slide, ranges):
    if not data or slide is None:
        return []
    secs = elf_sections(data)
    named = {}
    for sh in secs:
        name, typ, _, _, offset, size, link, _, _, entsize = sh
        if typ not in (SHT_SYMTAB, 11) or link >= len(secs):
            continue
        str_off, str_size = secs[link][4], secs[link][5]
        if str_off + str_size > len(data) or offset + size > len(data):
            continue
        strtab = data[str_off:str_off + str_size]
        step = entsize or 24
        for j in range(0, size - step + 1, step):
            st_name, st_info, _, st_shndx, st_value, _ = struct.unpack_from(
                "<IBBHQQ", data, offset + j)
            if st_shndx == 0 or st_value == 0 or (st_info & 0xF) == 4:
                continue
            label = cstr(strtab, st_name)
            if not label or label.startswith("$"):
                continue
            runtime = (st_value + slide) & MASK
            if in_ranges(runtime, ranges):
                named.setdefault(runtime, label)
    return [(addr, name) for addr, name in sorted(named.items())]


def defined_symbols(data):
    """Every defined symbol in the original, before a slide is applied."""
    out = []
    for sh in elf_sections(data):
        _, typ, _, _, offset, size, link, _, _, entsize = sh
        if typ not in (SHT_SYMTAB, 11) or link >= len(elf_sections(data)):
            continue
        secs = elf_sections(data)
        str_off, str_size = secs[link][4], secs[link][5]
        if str_off + str_size > len(data) or offset + size > len(data):
            continue
        strtab = data[str_off:str_off + str_size]
        step = entsize or 24
        for j in range(0, size - step + 1, step):
            st_name, st_info, _, st_shndx, st_value, _ = struct.unpack_from(
                "<IBBHQQ", data, offset + j)
            if st_shndx == 0 or st_value == 0 or (st_info & 0xF) == 4:
                continue
            label = cstr(strtab, st_name)
            if label and not label.startswith("$"):
                out.append((st_value, label))
    return out


def missing_symbols(orig_data, slide, ranges):
    """Original code symbols whose bytes no dump ever carried."""
    if orig_data is None or slide is None:
        return []
    out = []
    for sh in elf_sections(orig_data):
        _, _, flags, _, _, _, _, _, _, _ = sh
        if (flags & SHF_ALLOC) and (flags & SHF_EXECINSTR):
            exec_ranges = [(sh[3], sh[3] + sh[5])]
            break
    else:
        exec_ranges = []
    for va, name in defined_symbols(orig_data):
        if not any(lo <= va < hi for lo, hi in exec_ranges):
            continue
        if not in_ranges((va + slide) & MASK, ranges):
            out.append((va, name))
    return out


def strings_in(loads, minlen=STRLEN_MIN):
    out = []
    for vaddr, _, blob in loads:
        run = bytearray()
        start = 0
        for i, b in enumerate(blob):
            if 0x20 <= b < 0x7F:
                if not run:
                    start = i
                run.append(b)
                continue
            if len(run) >= minlen:
                out.append((vaddr + start, bytes(run)))
            run = bytearray()
        if len(run) >= minlen:
            out.append((vaddr + start, bytes(run)))
    return out[:MAX_STRINGS]


def scan_call_targets(loads, machine):
    """Heuristic: direct call opcodes whose target is outside every segment."""
    ranges = ranges_of(loads)
    exec_ranges = ranges_of([l for l in loads if l[1] & PF_X])
    outside = {}
    for vaddr, flags, blob in loads:
        if not (flags & PF_X):
            continue
        if machine == EM_X86_64:
            for i in range(len(blob) - 5):
                if blob[i] != 0xE8:
                    continue
                rel = struct.unpack_from("<i", blob, i + 1)[0]
                tgt = (vaddr + i + 5 + rel) & MASK
                if not in_ranges(tgt, ranges):
                    outside[tgt] = outside.get(tgt, 0) + 1
        elif machine == EM_AARCH64:
            for i in range(0, len(blob) - 3, 4):
                tgt = arm_bl_target(struct.unpack_from("<I", blob, i)[0], vaddr + i)
                if tgt is None or in_ranges(tgt, ranges):
                    continue
                outside[tgt] = outside.get(tgt, 0) + 1
    rows = sorted(outside.items(), key=lambda kv: (-kv[1], kv[0]))
    hole = [(t, c) for t, c in rows if _between(t, exec_ranges)]
    return rows[:MAX_CALL_TARGETS], hole[:MAX_CALL_TARGETS]


def arm_bl_target(word, pc):
    """Target of an AArch64 BL, or None. The opcode is bits 31:26, the high byte."""
    if (word >> 26) != 0b100101:
        return None
    imm = word & 0x03FFFFFF
    if imm & 0x02000000:
        imm -= 0x04000000
    return (pc + imm * 4) & MASK


def _between(addr, ranges):
    lo = min(r[0] for r in ranges)
    hi = max(r[1] for r in ranges)
    return lo <= addr < hi


def write_elf(path, loads, entry, machine, symbols):
    phnum = len(loads)
    off = ((64 + phnum * 56) + PAGE - 1) & ~(PAGE - 1) or PAGE
    segments = []
    blob = bytearray(off)
    for vaddr, flags, data in loads:
        segments.append((vaddr, flags, off, data))
        blob += data
        blob += b"\x00" * ((-len(blob)) % PAGE)
        off = len(blob)
    hdr = bytearray(64)
    hdr[0:4] = b"\x7fELF"
    hdr[4] = 2
    hdr[5] = 1
    hdr[6] = 1
    struct.pack_into("<HHIQQQIHHHHHH", hdr, 16,
                     3, machine, 1, entry, 64, 0, 0, 64, 56, phnum, 0, 0, 0)
    blob[:64] = hdr
    for i, (vaddr, flags, poff, data) in enumerate(segments):
        blob[64 + i * 56:64 + (i + 1) * 56] = struct.pack(
            "<IIQQQQQQ", PT_LOAD, flags, poff, vaddr, vaddr, len(data), len(data), PAGE)
    if symbols:
        blob = add_symtab(blob, symbols)
    with open(path, "wb") as f:
        f.write(blob)


def progbits_of(blob):
    phoff = struct.unpack_from("<Q", blob, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", blob, 54)
    loads = []
    for i in range(phnum):
        off = phoff + i * phentsize
        p_type, p_flags, p_offset, p_vaddr, _, p_filesz, _, _ = struct.unpack_from(
            "<IIQQQQQQ", blob, off)
        if p_type == PT_LOAD and p_filesz:
            loads.append((p_vaddr, p_flags, p_offset, p_filesz))
    return loads


def add_symtab(blob, symbols):
    loads = progbits_of(blob)
    strtab = bytearray(b"\x00")
    syms = bytearray(24)
    for value, name in symbols:
        name_off = len(strtab)
        strtab += name.encode("ascii", "replace") + b"\x00"
        shndx = SHN_ABS
        info = 0x10
        for i, (vaddr, flags, _, size) in enumerate(loads):
            if vaddr <= value < vaddr + size:
                shndx = i + 1
                info = 0x12 if flags & PF_X else 0x11
                break
        syms += struct.pack("<IBBHQQ", name_off, info, 0, shndx, value, 0)
    shstr = bytearray(b"\x00")
    sec_names = []
    text_n = data_n = 0
    for _, flags, _, _ in loads:
        if flags & PF_X:
            label = ".text" if text_n == 0 else ".text.%d" % text_n
            text_n += 1
        else:
            label = ".rodata" if data_n == 0 else ".rodata.%d" % data_n
            data_n += 1
        sec_names.append(len(shstr))
        shstr += label.encode() + b"\x00"
    sym_name = len(shstr)
    shstr += b".symtab\x00"
    str_name = len(shstr)
    shstr += b".strtab\x00"
    shstr_name = len(shstr)
    shstr += b".shstrtab\x00"
    while len(blob) % 8:
        blob += b"\x00"
    sym_off = len(blob)
    blob += syms
    str_off = len(blob)
    blob += strtab
    shstr_off = len(blob)
    blob += shstr
    while len(blob) % 8:
        blob += b"\x00"
    sh_off = len(blob)
    nload = len(loads)
    shnum = nload + 4
    shdrs = bytearray(64 * shnum)
    for i, ((vaddr, flags, poff, size), name_off) in enumerate(zip(loads, sec_names), 1):
        sec_flags = SHF_ALLOC
        if flags & PF_X:
            sec_flags |= SHF_EXECINSTR
        if flags & PF_W:
            sec_flags |= 1
        struct.pack_into("<IIQQQQIIQQ", shdrs, i * 64, name_off, 1, sec_flags,
                         vaddr, poff, size, 0, 0, PAGE, 0)
    sym_index = nload + 1
    str_index = nload + 2
    shstr_index = nload + 3
    struct.pack_into("<IIQQQQIIQQ", shdrs, sym_index * 64, sym_name, SHT_SYMTAB, 0, 0,
                     sym_off, len(syms), str_index, 1, 8, 24)
    struct.pack_into("<IIQQQQIIQQ", shdrs, str_index * 64, str_name, SHT_STRTAB, 0, 0,
                     str_off, len(strtab), 0, 0, 1, 0)
    struct.pack_into("<IIQQQQIIQQ", shdrs, shstr_index * 64, shstr_name, SHT_STRTAB, 0, 0,
                     shstr_off, len(shstr), 0, 0, 1, 0)
    blob += shdrs
    struct.pack_into("<Q", blob, 40, sh_off)
    struct.pack_into("<HHH", blob, 58, 64, shnum, shstr_index)
    return blob


def write_lines(path, lines):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="ascii", errors="replace") as f:
        for line in lines:
            f.write(line + "\n")


def out_paths(out, gen):
    base, ext = os.path.splitext(out)
    if gen == 0:
        return (out, base + ".libs", base + ".tails", base + ".pages",
                base + ".strings", base + ".missing")
    stem = "%s.%d%s" % (base, gen, ext)
    side = "%s.%d" % (base, gen)
    return (stem, side + ".libs", side + ".tails", side + ".pages",
            side + ".strings", side + ".missing")


def tails_for(gen, tail_rows):
    return ["%x %x %x" % (va, file_va, n) for va, epoch, file_va, n in tail_rows
            if va in gen and gen[va][0] == epoch]


def pages_for(gen, status, holes):
    rows = []
    for va in sorted(gen):
        epoch, why, _ = gen[va]
        rows.append("%x %d %s keep" % (va, epoch, why))
    for va, epoch, why, state in status:
        if va in gen and gen[va][0] == epoch:
            continue
        rows.append("%x %d %s %s" % (va, epoch, why, state))
    for lo, hi in holes:
        rows.append("%x %x gap never_dumped" % (lo, hi))
    return rows


def holes_between(loads):
    """Page-aligned gaps inside the span the image covers but no dump filled."""
    if not loads:
        return []
    present = set()
    for vaddr, _, blob in loads:
        for off in range(0, len(blob), PAGE):
            present.add(vaddr + off)
    lo = min(present)
    hi = max(present) + PAGE
    holes = []
    addr = lo
    while addr < hi:
        if addr in present:
            addr += PAGE
            continue
        start = addr
        while addr < hi and addr not in present:
            addr += PAGE
        holes.append((start, addr))
    return holes


def upx_compare(packed_path, loads, keep_path=None):
    if not packed_path or not os.path.isfile(packed_path):
        return None
    if not any(os.access(os.path.join(d, "upx"), os.X_OK)
               for d in os.environ.get("PATH", "").split(os.pathsep) if d):
        return {"status": "absent"}
    tmp = tempfile.mkdtemp(prefix="pb-upx-")
    out = os.path.join(tmp, "unpacked")
    try:
        try:
            proc = subprocess.run(["upx", "-d", "-o", out, packed_path],
                                  capture_output=True, timeout=120)
        except (OSError, subprocess.SubprocessError):
            return {"status": "absent"}
        if proc.returncode != 0 or not os.path.isfile(out):
            return {"status": "failed"}
        pages = {blob for _, _, blob in iter_load_pages(read_file(out))}
        same = 0
        diff = 0
        for vaddr, flags, blob in loads:
            if not (flags & PF_X):
                continue
            for i in range(0, len(blob), PAGE):
                if blob[i:i + PAGE] in pages:
                    same += 1
                else:
                    diff += 1
        kept_at = None
        if keep_path and same and diff == 0:
            try:
                parent = os.path.dirname(keep_path)
                if parent:
                    os.makedirs(parent, exist_ok=True)
                shutil.copy2(out, keep_path)
                kept_at = keep_path
            except OSError:
                kept_at = None
        return {"status": "ok", "same": same, "diff": diff, "path": kept_at}
    finally:
        for root, _, files in os.walk(tmp, topdown=False):
            for name in files:
                try:
                    os.unlink(os.path.join(root, name))
                except OSError:
                    pass
        try:
            os.rmdir(tmp)
        except OSError:
            pass


def build(rows, tgid, dumps, packed_path, orig_path, lib_paths, arch, out,
          rebase=False, drop_stray=False, want_strings=True, upx_keep=None):
    packed_data = packed_path and read_file(packed_path) or b""
    packed_mapped = list(iter_load_pages(packed_data)) if packed_data else []
    file_pages = [(va, blob) for va, flags, blob in packed_mapped if flags & PF_X]
    packed_pages = set(blob for _, _, blob in packed_mapped)
    file_set = set(blob for _, blob in file_pages)

    lib_sets = []
    lib_pages = []
    for path in lib_paths:
        try:
            data, pages = page_table(path)
        except OSError:
            continue
        lib_sets.append((os.path.basename(path), file_blobs(data)))
        lib_pages.append((path, os.path.basename(path), [(va, blob) for va, _, blob in pages]))

    orig_data = orig_path and read_file(orig_path) or None
    orig_exec = []
    if orig_data:
        orig_exec = [(va, blob) for va, flags, blob in iter_load_pages(orig_data) if flags & PF_X]
    sites = reloc_sites_from(orig_data) if orig_data else {}

    kept, file_hits, lib_hits, tail_rows, status = classify(
        rows, tgid, dumps, file_set, lib_sets, file_pages, lib_pages, sites)
    if not kept:
        return {"gens": [], "libs": [], "changelog": [], "missing": [], "stray": [],
                "calls": [], "hole_calls": [], "upx": None, "slide": None, "entry": None,
                "named_from": "none"}

    gens, changelog = generations(kept, packed_pages)
    slide = None
    exact = [(va, fva) for va, fva in file_hits if fva is not None and va % PAGE == 0]
    if exact:
        slide = slide_of(exact)
    if slide is None and orig_exec:
        hits = []
        for _, va, _, blob in kept:
            if not blob.strip(b"\x00"):
                continue
            hit = next((fva for fva, page in orig_exec if page == blob), None)
            if hit is not None:
                hits.append((va, hit))
        slide = slide_of(hits)

    stray = sorted({va for va, _, _, _ in tail_rows})
    demote = set(stray) if drop_stray else set()
    missing = missing_symbols(orig_data, slide, ranges_of(
        load_runs(dict((va, (e, w, b)) for e, va, w, b in kept), demote))) if orig_data else []
    result = {
        "gens": [], "libs": lib_lines(lib_hits), "changelog": changelog,
        "missing": missing, "stray": stray, "calls": [], "hole_calls": [],
        "upx": None, "slide": slide, "entry": None, "arch": arch,
    }
    machine = machine_id(arch)
    entry_ref = elf_entry(orig_data) if orig_data else elf_entry(packed_data)

    for i, gen in enumerate(gens):
        loads = load_runs(gen, demote)
        loads, added = splice_readonly(loads, orig_data, slide)
        ranges = ranges_of(loads)
        entry = loads[0][0]
        if slide is not None and entry_ref is not None:
            cand = (entry_ref + slide) & MASK
            if in_ranges(cand, ranges):
                entry = cand
        syms = section_symbols(orig_data, slide, ranges)
        names = dict(syms)
        for addr, name in import_names(orig_data, slide, ranges):
            names.setdefault(addr, name)
        for addr, name in import_names(packed_data, slide, ranges):
            names.setdefault(addr, name)
        symbols = sorted(names.items())
        holes = holes_between(loads)

        (elf_path, lib_path, tail_path, page_path, str_path,
         miss_path) = out_paths(out, i)
        write_elf(elf_path, loads, entry, machine, symbols)

        if rebase and slide:
            rb = load_runs_from([((lo - slide) & MASK, fl, blob) for lo, fl, blob in loads])
            name = "rebased.elf" if i == 0 else "rebased.%d.elf" % i
            write_elf(os.path.join(os.path.dirname(elf_path) or ".", name),
                      rb, entry_ref, machine, [((a - slide) & MASK, n) for a, n in symbols])

        write_lines(page_path, pages_for(gen, status, holes))
        write_lines(lib_path, result["libs"])
        write_lines(tail_path, tails_for(gen, tail_rows))
        write_lines(miss_path, ["%x %s" % (va, sname) for va, sname in missing])
        if want_strings:
            write_lines(str_path, ["%x %s" % (va, s.decode("ascii"))
                                   for va, s in strings_in(loads)])

        if i == 0:
            calls, hole = scan_call_targets(loads, machine)
            result["calls"] = calls
            result["hole_calls"] = hole
            result["entry"] = entry
            result["upx"] = upx_compare(packed_path, loads, keep_path=upx_keep)
        result["gens"].append({
            "index": i, "path": elf_path, "pages": len(gen), "loads": len(loads),
            "entry": entry, "slide": slide, "spliced": len(added),
            "syms": len(symbols), "stray": len([v for v in stray if v in gen]),
        })
    if orig_path and any(g["syms"] for g in result["gens"]):
        result["named_from"] = "orig"
    elif orig_path:
        result["named_from"] = "orig-unapplied"
    else:
        result["named_from"] = "none"
    return result


def lib_lines(hits):
    votes = {}
    for path, dump_va, file_va in hits:
        base = (dump_va - file_va) & MASK
        votes.setdefault(path, {})
        votes[path][base] = votes[path].get(base, 0) + 1
    lines = []
    for path in sorted(votes):
        ranked = sorted(votes[path].items(), key=lambda kv: (-kv[1], kv[0]))
        best, count = ranked[0]
        note = "" if len(ranked) == 1 else " majority"
        lines.append("%x %s pages=%d%s" % (best, path, count, note))
        for base, seen in ranked[1:]:
            lines.append("%x %s pages=%d rejected" % (base, path, seen))
    return lines
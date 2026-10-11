"""Find loaded executable images in a target: Windows PE images (games under
Wine/CrossOver/NotProton) and native Mach-O images.

Wine maps each PE image at its base with the headers as the first page, so
looking for MZ/PE headers at region starts and 64K boundaries finds them all
without having to walk Wine's internal loader lists.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass

from . import mach
from .mach import MachError, Region, Task

PE_MACHINES = {0x14C: "x86", 0x8664: "x64", 0xAA64: "arm64", 0x1C4: "arm"}
MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
WIN_ALLOC_GRANULARITY = 0x10000
_MAX_PROBE_REGION = 256 << 20


@dataclass(frozen=True)
class Module:
    name: str
    path: str
    base: int
    size: int
    kind: str  # "pe32", "pe64" or "macho"
    arch: str
    is_exe: bool

    @property
    def end(self) -> int:
        return self.base + self.size

    @property
    def pointer_size(self) -> int:
        return 4 if self.kind == "pe32" else 8

    def to_dict(self) -> dict:
        return {"name": self.name, "base": hex(self.base), "size": hex(self.size), "kind": self.kind,
                "arch": self.arch, "exe": self.is_exe, "path": self.path}


def _cstr(data: bytes) -> str:
    return data.split(b"\0", 1)[0].decode(errors="replace")


def _parse_pe(task: Task, base: int, hdr: bytes) -> Module | None:
    if len(hdr) < 0x40:
        return None
    e_lfanew = struct.unpack_from("<I", hdr, 0x3C)[0]
    if e_lfanew < 0x40 or e_lfanew > 0x1000:
        return None
    if e_lfanew + 0x108 > len(hdr):
        try:
            hdr = task.read(base, e_lfanew + 0x108)
        except MachError:
            return None
    if hdr[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        return None
    machine, = struct.unpack_from("<H", hdr, e_lfanew + 4)
    characteristics, = struct.unpack_from("<H", hdr, e_lfanew + 22)
    opt = e_lfanew + 24
    magic, = struct.unpack_from("<H", hdr, opt)
    if magic == 0x10B:
        kind, export_dir = "pe32", opt + 96
    elif magic == 0x20B:
        kind, export_dir = "pe64", opt + 112
    else:
        return None
    size_of_image, = struct.unpack_from("<I", hdr, opt + 56)
    if not 0 < size_of_image < 1 << 32:
        return None

    path = mach.region_filename(task.pid, base)
    name = os.path.basename(path) if path else ""
    if not name:
        export_rva, = struct.unpack_from("<I", hdr, export_dir)
        if export_rva:
            try:
                name_rva = struct.unpack("<I", task.read(base + export_rva + 12, 4))[0]
                name = _cstr(task.read(base + name_rva, 256)) if name_rva else ""
            except MachError:
                name = ""
    is_exe = not characteristics & 0x2000
    if not name:
        name = f"{'exe' if is_exe else 'dll'}_{base:x}"
    return Module(name=name, path=path, base=base, size=size_of_image, kind=kind,
                  arch=PE_MACHINES.get(machine, hex(machine)), is_exe=is_exe)


def _parse_macho(task: Task, base: int, hdr: bytes) -> Module | None:
    cputype, _, filetype, ncmds, sizeofcmds = struct.unpack_from("<iiIII", hdr, 4)
    if sizeofcmds > 0x10000:
        return None
    if 32 + sizeofcmds > len(hdr):
        try:
            hdr = task.read(base, 32 + sizeofcmds)
        except MachError:
            return None
    off = 32
    segs = []
    text_vmaddr = None
    for _ in range(ncmds):
        if off + 8 > len(hdr):
            break
        cmd, cmdsize = struct.unpack_from("<II", hdr, off)
        if cmd == LC_SEGMENT_64 and off + 48 <= len(hdr):
            segname = _cstr(hdr[off + 8:off + 24])
            vmaddr, vmsize = struct.unpack_from("<QQ", hdr, off + 24)
            if segname == "__TEXT":
                text_vmaddr = vmaddr
            if segname != "__PAGEZERO" and vmsize:
                segs.append((vmaddr, vmsize))
        if cmdsize < 8:
            break
        off += cmdsize
    if text_vmaddr is None or not segs:
        return None
    slide = base - text_vmaddr
    lo = min(a for a, _ in segs) + slide
    hi = max(a + s for a, s in segs) + slide
    path = mach.region_filename(task.pid, base)
    arch = {0x01000007: "x86_64", 0x0100000C: "arm64"}.get(cputype, hex(cputype))
    return Module(name=os.path.basename(path) or f"macho_{base:x}", path=path, base=lo, size=hi - lo,
                  kind="macho", arch=arch, is_exe=filetype == 2)


def _probe(task: Task, addr: int) -> Module | None:
    try:
        hdr = task.read(addr, 0x400)
    except MachError:
        return None
    if hdr[:2] == b"MZ":
        return _parse_pe(task, addr, hdr)
    if struct.unpack_from("<I", hdr)[0] == MH_MAGIC_64:
        return _parse_macho(task, addr, hdr)
    return None


def find_modules(task: Task, regions: list[Region] | None = None) -> list[Module]:
    regions = regions if regions is not None else list(task.regions())
    found: dict[int, Module] = {}
    for r in regions:
        if r.is_submap or not r.readable:
            continue
        candidates = [r.start]
        if not r.writable and r.size <= _MAX_PROBE_REGION:
            first = -(-r.start // WIN_ALLOC_GRANULARITY) * WIN_ALLOC_GRANULARITY
            candidates.extend(range(first, r.end, WIN_ALLOC_GRANULARITY))
        for addr in candidates:
            if addr in found:
                continue
            mod = _probe(task, addr)
            if mod and mod.base not in found:
                found[mod.base] = mod
    # Executables first, then PE before Mach-O, then by address.
    return sorted(found.values(), key=lambda m: (not m.is_exe, m.kind == "macho", m.base))


def module_at(modules: list[Module], addr: int) -> Module | None:
    for m in modules:
        if m.base <= addr < m.end:
            return m
    return None

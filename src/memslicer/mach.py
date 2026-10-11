"""ctypes bindings for the Mach VM and libproc calls a memory scanner needs.

Everything here talks to the kernel directly; nothing is macOS-version specific
beyond the vm_region_submap_info_64 layout, which has been stable since 10.x.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
from dataclasses import dataclass
from typing import Iterator

import numpy as np

_libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)

mach_port_t = ctypes.c_uint32
natural_t = ctypes.c_uint32
kern_return_t = ctypes.c_int

KERN_SUCCESS = 0
KERN_INVALID_ADDRESS = 1
KERN_PROTECTION_FAILURE = 2
KERN_FAILURE = 5

VM_PROT_READ = 0x1
VM_PROT_WRITE = 0x2
VM_PROT_EXECUTE = 0x4
VM_PROT_COPY = 0x10

SM_EMPTY = 3

# Rosetta's own bookkeeping (translation caches, thread contexts...). Never game data.
ROSETTA_TAGS = range(230, 240)

# Smallest page size any target can have (Rosetta processes use 4K maps on
# Apple Silicon even though the host uses 16K), so it is the safe granularity
# for page-by-page fallback reads.
MIN_PAGE = 4096


class vm_region_submap_info_64(ctypes.Structure):
    _layout_ = "ms"  # only so _pack_ is honoured without a deprecation warning on 3.14+
    _pack_ = 4
    _fields_ = [
        ("protection", ctypes.c_int),
        ("max_protection", ctypes.c_int),
        ("inheritance", ctypes.c_uint),
        ("offset", ctypes.c_uint64),
        ("user_tag", ctypes.c_uint),
        ("pages_resident", ctypes.c_uint),
        ("pages_shared_now_private", ctypes.c_uint),
        ("pages_swapped_out", ctypes.c_uint),
        ("pages_dirtied", ctypes.c_uint),
        ("ref_count", ctypes.c_uint),
        ("shadow_depth", ctypes.c_ushort),
        ("external_pager", ctypes.c_ubyte),
        ("share_mode", ctypes.c_ubyte),
        ("is_submap", ctypes.c_int),
        ("behavior", ctypes.c_int),
        ("object_id", ctypes.c_uint),
        ("user_wired_count", ctypes.c_ushort),
        ("pages_reusable", ctypes.c_uint),
        ("object_id_full", ctypes.c_uint64),
    ]


VM_REGION_SUBMAP_INFO_COUNT_64 = ctypes.sizeof(vm_region_submap_info_64) // 4
assert VM_REGION_SUBMAP_INFO_COUNT_64 == 19


def _proto(name, restype, *argtypes):
    fn = getattr(_libc, name)
    fn.restype = restype
    fn.argtypes = list(argtypes)
    return fn


_task_for_pid = _proto("task_for_pid", kern_return_t, mach_port_t, ctypes.c_int, ctypes.POINTER(mach_port_t))
_mach_vm_region_recurse = _proto(
    "mach_vm_region_recurse", kern_return_t,
    mach_port_t, ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_uint64),
    ctypes.POINTER(natural_t), ctypes.c_void_p, ctypes.POINTER(natural_t),
)
_mach_vm_read_overwrite = _proto(
    "mach_vm_read_overwrite", kern_return_t,
    mach_port_t, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint64),
)
_mach_vm_write = _proto("mach_vm_write", kern_return_t, mach_port_t, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_uint32)
_mach_vm_protect = _proto(
    "mach_vm_protect", kern_return_t, mach_port_t, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_int, ctypes.c_int,
)
_task_suspend = _proto("task_suspend", kern_return_t, mach_port_t)
_task_resume = _proto("task_resume", kern_return_t, mach_port_t)
_mach_port_deallocate = _proto("mach_port_deallocate", kern_return_t, mach_port_t, mach_port_t)
_mach_error_string = _proto("mach_error_string", ctypes.c_char_p, kern_return_t)
_proc_regionfilename = _proto(
    "proc_regionfilename", ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_uint32,
)
_proc_pidpath = _proto("proc_pidpath", ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32)
_proc_name = _proto("proc_name", ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32)
_proc_pidinfo = _proto(
    "proc_pidinfo", ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int,
)
_getpeereid = _proto(
    "getpeereid", ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32),
)

_mach_task_self = mach_port_t.in_dll(_libc, "mach_task_self_").value


class MachError(OSError):
    def __init__(self, call: str, kr: int):
        msg = _mach_error_string(kr)
        self.kr = kr
        super().__init__(f"{call} failed: {msg.decode() if msg else 'unknown'} (kr={kr})")


@dataclass(frozen=True)
class Region:
    start: int
    end: int
    prot: int
    max_prot: int
    user_tag: int
    share_mode: int
    external_pager: bool
    is_submap: bool
    pages_resident: int

    @property
    def size(self) -> int:
        return self.end - self.start

    @property
    def readable(self) -> bool:
        return bool(self.prot & VM_PROT_READ)

    @property
    def writable(self) -> bool:
        return bool(self.prot & VM_PROT_WRITE)

    @property
    def executable(self) -> bool:
        return bool(self.prot & VM_PROT_EXECUTE)

    @property
    def prot_str(self) -> str:
        return "".join(c if self.prot & bit else "-" for c, bit in
                       (("r", VM_PROT_READ), ("w", VM_PROT_WRITE), ("x", VM_PROT_EXECUTE)))

    @property
    def is_rosetta(self) -> bool:
        return self.user_tag in ROSETTA_TAGS


class Task:
    """A send right to another process's task port."""

    def __init__(self, port: int, pid: int, owned: bool):
        self.port = port
        self.pid = pid
        self._owned = owned
        self._suspended = 0

    @classmethod
    def for_pid(cls, pid: int) -> "Task":
        if pid == os.getpid():
            return cls(_mach_task_self, pid, owned=False)
        port = mach_port_t(0)
        kr = _task_for_pid(_mach_task_self, pid, ctypes.byref(port))
        if kr != KERN_SUCCESS:
            raise MachError(f"task_for_pid({pid})", kr)
        return cls(port.value, pid, owned=True)

    def close(self) -> None:
        while self._suspended:
            self.resume()
        if self._owned and self.port:
            _mach_port_deallocate(_mach_task_self, self.port)
        self.port = 0

    # -- regions -----------------------------------------------------------

    def regions(self) -> Iterator[Region]:
        addr = 0
        info = vm_region_submap_info_64()
        while True:
            a = ctypes.c_uint64(addr)
            size = ctypes.c_uint64(0)
            depth = natural_t(0)
            count = natural_t(VM_REGION_SUBMAP_INFO_COUNT_64)
            kr = _mach_vm_region_recurse(self.port, ctypes.byref(a), ctypes.byref(size), ctypes.byref(depth),
                                         ctypes.byref(info), ctypes.byref(count))
            if kr != KERN_SUCCESS:
                return
            yield Region(
                start=a.value, end=a.value + size.value, prot=info.protection, max_prot=info.max_protection,
                user_tag=info.user_tag, share_mode=info.share_mode, external_pager=bool(info.external_pager),
                is_submap=bool(info.is_submap), pages_resident=info.pages_resident,
            )
            addr = a.value + size.value

    # -- reading -----------------------------------------------------------

    def read_into(self, addr: int, buf: np.ndarray) -> None:
        out = ctypes.c_uint64(0)
        kr = _mach_vm_read_overwrite(self.port, addr, buf.nbytes, buf.ctypes.data, ctypes.byref(out))
        if kr != KERN_SUCCESS:
            raise MachError(f"mach_vm_read_overwrite(0x{addr:x}, {buf.nbytes})", kr)

    def read(self, addr: int, size: int) -> bytes:
        buf = np.empty(size, dtype=np.uint8)
        self.read_into(addr, buf)
        return buf.tobytes()

    def read_robust(self, addr: int, size: int) -> tuple[np.ndarray, np.ndarray | None]:
        """Read a span that may contain holes.

        Returns (buffer, page_ok). page_ok is None when the whole span was read;
        otherwise it is a bool array indexed by (address // MIN_PAGE - addr // MIN_PAGE)
        and the bytes of unreadable pages are zero.
        """
        buf = np.empty(size, dtype=np.uint8)
        try:
            self.read_into(addr, buf)
            return buf, None
        except MachError:
            pass
        first = addr // MIN_PAGE
        last = (addr + size - 1) // MIN_PAGE
        page_ok = np.zeros(last - first + 1, dtype=bool)
        buf[:] = 0
        for page in range(first, last + 1):
            lo = max(page * MIN_PAGE, addr)
            hi = min((page + 1) * MIN_PAGE, addr + size)
            try:
                self.read_into(lo, buf[lo - addr:hi - addr])
                page_ok[page - first] = True
            except MachError:
                pass
        return buf, page_ok

    # -- writing -----------------------------------------------------------

    def write(self, addr: int, data: bytes) -> None:
        cbuf = ctypes.create_string_buffer(data, len(data))
        kr = _mach_vm_write(self.port, addr, ctypes.addressof(cbuf), len(data))
        if kr == KERN_SUCCESS:
            return
        if kr not in (KERN_PROTECTION_FAILURE, KERN_INVALID_ADDRESS):
            raise MachError(f"mach_vm_write(0x{addr:x})", kr)
        # Read-only (e.g. code or .rdata): make the pages writable copy-on-write, write, restore.
        region = self.region_at(addr)
        if region is None:
            raise MachError(f"mach_vm_write(0x{addr:x})", kr)
        page_lo = addr // MIN_PAGE * MIN_PAGE
        page_hi = -(-(addr + len(data)) // MIN_PAGE) * MIN_PAGE
        kr2 = _mach_vm_protect(self.port, page_lo, page_hi - page_lo, 0,
                               VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY)
        if kr2 != KERN_SUCCESS:
            raise MachError(f"mach_vm_protect(0x{page_lo:x})", kr2)
        try:
            kr = _mach_vm_write(self.port, addr, ctypes.addressof(cbuf), len(data))
            if kr != KERN_SUCCESS:
                raise MachError(f"mach_vm_write(0x{addr:x})", kr)
        finally:
            _mach_vm_protect(self.port, page_lo, page_hi - page_lo, 0, region.prot)

    def region_at(self, addr: int) -> Region | None:
        a = ctypes.c_uint64(addr)
        size = ctypes.c_uint64(0)
        depth = natural_t(0)
        info = vm_region_submap_info_64()
        count = natural_t(VM_REGION_SUBMAP_INFO_COUNT_64)
        kr = _mach_vm_region_recurse(self.port, ctypes.byref(a), ctypes.byref(size), ctypes.byref(depth),
                                     ctypes.byref(info), ctypes.byref(count))
        if kr != KERN_SUCCESS or not (a.value <= addr < a.value + size.value):
            return None
        return Region(a.value, a.value + size.value, info.protection, info.max_protection, info.user_tag,
                      info.share_mode, bool(info.external_pager), bool(info.is_submap), info.pages_resident)

    # -- execution control -------------------------------------------------

    def suspend(self) -> None:
        kr = _task_suspend(self.port)
        if kr != KERN_SUCCESS:
            raise MachError("task_suspend", kr)
        self._suspended += 1

    def resume(self) -> None:
        if not self._suspended:
            return
        kr = _task_resume(self.port)
        self._suspended -= 1
        if kr != KERN_SUCCESS:
            raise MachError("task_resume", kr)

    @property
    def suspended(self) -> bool:
        return self._suspended > 0


# -- libproc helpers --------------------------------------------------------

def region_filename(pid: int, addr: int) -> str:
    buf = ctypes.create_string_buffer(4096)
    n = _proc_regionfilename(pid, addr, buf, len(buf))
    return buf.raw[:n].decode(errors="replace") if n > 0 else ""


def pid_path(pid: int) -> str:
    buf = ctypes.create_string_buffer(4096)
    n = _proc_pidpath(pid, buf, len(buf))
    return buf.raw[:n].decode(errors="replace") if n > 0 else ""


def pid_name(pid: int) -> str:
    buf = ctypes.create_string_buffer(256)
    n = _proc_name(pid, buf, len(buf))
    return buf.raw[:n].decode(errors="replace") if n > 0 else ""


PROC_PIDTBSDINFO = 3
_BSDINFO_SIZE = 136
_BSDINFO_UID_OFFSET = 20


def pid_uid(pid: int) -> int | None:
    buf = ctypes.create_string_buffer(_BSDINFO_SIZE)
    n = _proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, buf, _BSDINFO_SIZE)
    if n == _BSDINFO_SIZE:
        return int.from_bytes(buf.raw[_BSDINFO_UID_OFFSET:_BSDINFO_UID_OFFSET + 4], "little")
    # Unprivileged callers can't proc_pidinfo other users' processes; ps can.
    out = subprocess.run(["ps", "-o", "uid=", "-p", str(int(pid))], capture_output=True, text=True).stdout.strip()
    return int(out) if out.isdigit() else None


def peer_uid(fd: int) -> int:
    uid = ctypes.c_uint32()
    gid = ctypes.c_uint32()
    if _getpeereid(fd, ctypes.byref(uid), ctypes.byref(gid)) != 0:
        raise OSError(ctypes.get_errno(), "getpeereid failed")
    return uid.value

"""Scan engine: first/next scans, reads and writes, freezing, pointer scans.

A Session wraps one attached process. It is used by the privileged helper, and
directly (against our own process) by the tests.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field

import numpy as np
from numpy.lib.stride_tricks import sliding_window_view

from . import expr as expr_mod
from . import mach, pointers
from .mach import MIN_PAGE, SM_EMPTY, MachError, Task
from .modules import Module, find_modules, module_at
from .values import (ABSOLUTE_OPS, RELATIVE_OPS, ValueType, byte_pattern, compare, decode, encode,
                     parse_number)

CHUNK = 32 << 20
CLUSTER_GAP = 64 << 10
MAX_RESULTS = int(os.environ.get("MEMSLICER_MAX_RESULTS", 250_000_000))
SNAPSHOT_MAX = int(os.environ.get("MEMSLICER_SNAPSHOT_MAX", 16 << 30))
UNDO_DEPTH = 3


class ScanError(ValueError):
    pass


@dataclass
class ScanState:
    vt: ValueType
    size: int                      # bytes per result
    addrs: np.ndarray              # uint64, sorted
    raw: np.ndarray                # (n, size) uint8 value at last scan
    alignment: int
    snapshot: list | None = None   # unknown-initial-value scan: [(addr, bytes, page_ok)]
    snapshot_positions: int = 0
    ignore_case: bool = False
    scans: int = 1

    @property
    def count(self) -> int:
        return self.snapshot_positions if self.snapshot is not None else len(self.addrs)


def _pages_ok(base: int, rel: np.ndarray, size: int, page_ok: np.ndarray | None) -> np.ndarray:
    if page_ok is None:
        return np.ones(len(rel), dtype=bool)
    first = base // MIN_PAGE
    a = (base + rel) // MIN_PAGE - first
    b = (base + rel + size - 1) // MIN_PAGE - first
    return page_ok[a] & page_ok[b]


def _clusters(addrs: np.ndarray, size: int):
    """Split sorted addresses into (i0, i1) runs that can be fetched with one read."""
    n = len(addrs)
    if not n:
        return
    breaks = np.flatnonzero(np.diff(addrs) > np.uint64(CLUSTER_GAP)) + 1
    bounds = np.concatenate(([0], breaks, [n])).tolist()
    for i0, i1 in zip(bounds[:-1], bounds[1:]):
        while i0 < i1:
            lo = int(addrs[i0])
            if int(addrs[i1 - 1]) + size - lo <= CHUNK:
                yield i0, i1
                break
            j = i0 + int(np.searchsorted(addrs[i0:i1], np.uint64(lo + CHUNK - size), side="right"))
            j = max(j, i0 + 1)
            yield i0, j
            i0 = j


class Session:
    def __init__(self, task: Task):
        self.task = task
        self.pid = task.pid
        self._modules: list[Module] | None = None
        self.scan: ScanState | None = None
        self._undo: list[ScanState] = []
        self.chains: list[pointers.Chain] = []
        self._aob_cache: dict[tuple[str, str | None], int] = {}

    def close(self) -> None:
        self.task.close()

    # -- modules & addresses ------------------------------------------------

    def modules(self, refresh: bool = False) -> list[Module]:
        if self._modules is None or refresh:
            self._modules = find_modules(self.task)
        return self._modules

    def module(self, name: str) -> Module | None:
        key = name.lower()
        for refresh in (False, True):
            mods = self.modules(refresh)
            if key == "$exe":
                # A Windows exe (Wine game) wins; otherwise the Mach-O at the process's own path,
                # not e.g. Rosetta's runtime, which is also an MH_EXECUTE image.
                own = mach.pid_path(self.pid)
                exes = ([m for m in mods if m.is_exe and m.kind != "macho"]
                        or [m for m in mods if m.is_exe and m.path == own]
                        or [m for m in mods if m.is_exe])
                if exes:
                    return exes[0]
                continue
            for m in mods:
                if m.name.lower() == key or m.name.lower().rsplit(".", 1)[0] == key:
                    return m
        return None

    def require_module(self, name: str) -> Module:
        m = self.module(name)
        if m is None:
            names = ", ".join(m.name for m in self.modules()[:15])
            raise ScanError(f"module {name!r} not found (loaded: {names} ...)")
        return m

    def default_pointer_size(self) -> int:
        exe = self.module("$exe")
        return exe.pointer_size if exe else 8

    def where(self, addr: int) -> str | None:
        m = module_at(self.modules(), addr)
        return f"{expr_mod.quote_module(m.name)}+0x{addr - m.base:X}" if m else None

    def read_uint(self, addr: int, size: int) -> int:
        return int.from_bytes(self.task.read(addr, size), "little")

    def eval_address(self, text, pointer_size: int | None = None) -> int:
        if isinstance(text, int):
            return text
        ps = pointer_size or self.default_pointer_size()

        def module_base(name):
            m = self.module(name)
            return m.base if m else None

        def read_i32(a):
            return int.from_bytes(self.task.read(a, 4), "little", signed=True)

        return expr_mod.evaluate(text, module_base=module_base, read_ptr=lambda a: self.read_uint(a, ps),
                                 aob=self._aob_first, read_i32=read_i32)

    def _aob_first(self, pattern: str, module: str | None) -> int:
        key = (pattern, module)
        if key not in self._aob_cache:
            hits = self.aob_scan(pattern, module=module, limit=1)
            if not hits:
                raise ScanError(f"aob pattern not found: {pattern}" + (f" in {module}" if module else ""))
            self._aob_cache[key] = hits[0]
        return self._aob_cache[key]

    # -- regions ------------------------------------------------------------

    def spans(self, writable_only: bool = True, start: int | None = None, end: int | None = None,
              module: str | None = None, executable_only: bool = False) -> list[tuple[int, int]]:
        lo, hi = start or 0, end or (1 << 64)
        if module:
            m = self.require_module(module)
            lo, hi = max(lo, m.base), min(hi, m.end)
        out = []
        for r in self.task.regions():
            if r.is_submap or not r.readable or r.is_rosetta or r.share_mode == SM_EMPTY:
                continue
            if writable_only and not r.writable:
                continue
            if executable_only and not r.executable:
                continue
            if r.end <= lo or r.start >= hi:
                continue
            out.append((max(r.start, lo), min(r.end, hi)))
        return out

    def _chunks(self, lo: int, hi: int, overlap: int):
        pos = lo
        while pos < hi:
            nominal = min(CHUNK, hi - pos)
            length = min(nominal + overlap, hi - pos)
            buf, page_ok = self.task.read_robust(pos, length)
            if page_ok is None or page_ok.any():
                yield pos, buf, nominal, page_ok
            pos += nominal

    def _gather(self, addrs: np.ndarray, size: int) -> tuple[np.ndarray, np.ndarray]:
        out = np.zeros((len(addrs), size), dtype=np.uint8)
        ok = np.zeros(len(addrs), dtype=bool)
        for i0, i1 in _clusters(addrs, size):
            lo = int(addrs[i0])
            hi = int(addrs[i1 - 1]) + size
            buf, page_ok = self.task.read_robust(lo, hi - lo)
            rel = (addrs[i0:i1] - np.uint64(lo)).astype(np.int64)
            out[i0:i1] = sliding_window_view(buf, size)[rel]
            ok[i0:i1] = _pages_ok(lo, rel, size, page_ok)
        return out, ok

    # -- scanning -----------------------------------------------------------

    def first_scan(self, vt: ValueType, op: str, value=None, value2=None, tolerance: float | None = None,
                   alignment: int | None = None, writable_only: bool = True, start: int | None = None,
                   end: int | None = None, module: str | None = None, ignore_case: bool = False) -> dict:
        if op in RELATIVE_OPS:
            raise ScanError(f"'{op}' needs a previous scan; start with an exact value or compare='unknown'")
        t0 = time.monotonic()
        spans = self.spans(writable_only, start, end, module)
        if not vt.numeric:
            if op not in ("eq",):
                raise ScanError("string/bytes scans only support compare='eq'")
            state = self._first_scan_bytes(vt, str(value), spans, ignore_case)
        elif op == "unknown":
            state = self._snapshot(vt, spans, alignment)
        else:
            parse_number(vt, value)
            if op == "between":
                parse_number(vt, value2)
            state = self._first_scan_numeric(vt, op, value, value2, tolerance, alignment, spans)
        self._undo.clear()
        self.scan = state
        return self._summary(state, time.monotonic() - t0, sum(hi - lo for lo, hi in spans))

    def _first_scan_numeric(self, vt, op, v1, v2, tol, alignment, spans) -> ScanState:
        size = vt.size
        align = alignment or vt.default_alignment
        if size % align:
            raise ScanError(f"alignment {align} must divide the type size {size}")
        addr_parts, raw_parts, total = [], [], 0
        for lo, hi in spans:
            for pos, buf, nominal, page_ok in self._chunks(lo, hi, size - 1):
                for k in range(size // align):
                    off = k * align
                    if off >= nominal:
                        break
                    n = min(-(-(nominal - off) // size), (len(buf) - off) // size)
                    if n <= 0:
                        continue
                    arr = np.frombuffer(buf, dtype=vt.dtype, count=n, offset=off)
                    idx = np.flatnonzero(compare(vt, arr, op, v1, v2, tolerance=tol))
                    if not idx.size:
                        continue
                    rel = off + idx.astype(np.int64) * size
                    if page_ok is not None:
                        keep = _pages_ok(pos, rel, size, page_ok)
                        idx, rel = idx[keep], rel[keep]
                    addr_parts.append(np.uint64(pos) + rel.astype(np.uint64))
                    raw_parts.append(np.ascontiguousarray(arr[idx]).view(np.uint8).reshape(-1, size))
                    total += len(idx)
                    if total > MAX_RESULTS:
                        raise ScanError(f"more than {MAX_RESULTS:,} matches; use a more specific value, "
                                        "a module/address range, or compare='unknown' then narrow")
        return self._make_state(vt, size, align, addr_parts, raw_parts)

    def _first_scan_bytes(self, vt, pattern: str, spans, ignore_case: bool) -> ScanState:
        rx, size = byte_pattern(vt, pattern, ignore_case)
        if size == 0:
            raise ScanError("empty search pattern")
        addrs, raws = [], []
        for lo, hi in spans:
            for pos, buf, nominal, page_ok in self._chunks(lo, hi, size - 1):
                mv = memoryview(buf)
                for m in rx.finditer(mv):
                    s = m.start()
                    if s >= nominal:
                        break
                    if page_ok is not None and not _pages_ok(pos, np.array([s]), size, page_ok)[0]:
                        continue
                    addrs.append(pos + s)
                    raws.append(bytes(mv[s:s + size]))
                    if len(addrs) > 5_000_000:
                        raise ScanError("too many matches; use a longer pattern or a module/address range")
        a = np.array(addrs, dtype=np.uint64)
        r = np.frombuffer(b"".join(raws), dtype=np.uint8).reshape(-1, size) if raws \
            else np.empty((0, size), np.uint8)
        state = self._make_state(vt, size, 1, [a], [r])
        state.ignore_case = ignore_case
        return state

    def _snapshot(self, vt, spans, alignment) -> ScanState:
        total = sum(hi - lo for lo, hi in spans)
        if total > SNAPSHOT_MAX:
            raise ScanError(f"unknown-value scan would snapshot {total / 2**30:.1f} GiB (limit "
                            f"{SNAPSHOT_MAX / 2**30:.0f} GiB); restrict it with module= or start/end, "
                            "or raise MEMSLICER_SNAPSHOT_MAX")
        align = alignment or vt.default_alignment
        snap = []
        positions = 0
        for lo, hi in spans:
            for pos, buf, nominal, page_ok in self._chunks(lo, hi, 0):
                snap.append((pos, buf, page_ok))
                positions += len(buf) // align
        return ScanState(vt, vt.size, np.empty(0, np.uint64), np.empty((0, vt.size), np.uint8), align,
                         snapshot=snap, snapshot_positions=positions)

    @staticmethod
    def _make_state(vt, size, align, addr_parts, raw_parts) -> ScanState:
        if addr_parts:
            addrs = np.concatenate(addr_parts)
            raw = np.concatenate(raw_parts)
            order = np.argsort(addrs, kind="stable")
            addrs, raw = addrs[order], raw[order]
        else:
            addrs, raw = np.empty(0, np.uint64), np.empty((0, size), np.uint8)
        return ScanState(vt, size, addrs, raw, align)

    def next_scan(self, op: str, value=None, value2=None, tolerance: float | None = None) -> dict:
        st = self._require_scan()
        t0 = time.monotonic()
        if op == "unknown":
            raise ScanError("'unknown' is only valid for a first scan")
        if st.snapshot is not None:
            new = self._next_from_snapshot(st, op, value, value2, tolerance)
        elif st.vt.numeric:
            cur_raw, ok = self._gather(st.addrs, st.size)
            cur = cur_raw.view(st.vt.dtype).reshape(-1)
            prev = st.raw.view(st.vt.dtype).reshape(-1)
            mask = ok & compare(st.vt, cur, op, value, value2, prev=prev, tolerance=tolerance)
            new = ScanState(st.vt, st.size, st.addrs[mask], cur_raw[mask], st.alignment)
        else:
            new = self._next_bytes(st, op, value)
        new.scans = st.scans + 1
        new.ignore_case = st.ignore_case
        self._undo.append(st)
        del self._undo[:-UNDO_DEPTH]
        self.scan = new
        return self._summary(new, time.monotonic() - t0, None, before=st.count)

    def _next_from_snapshot(self, st: ScanState, op, v1, v2, tol) -> ScanState:
        vt, size, align = st.vt, st.size, st.alignment
        if op in ABSOLUTE_OPS:
            parse_number(vt, v1)
        addr_parts, raw_parts = [], []
        for pos, old, old_ok in st.snapshot:
            cur, cur_ok = self.task.read_robust(pos, len(old))
            for k in range(size // align):
                off = k * align
                n = (len(old) - off) // size
                if n <= 0:
                    continue
                a_old = np.frombuffer(old, dtype=vt.dtype, count=n, offset=off)
                a_cur = np.frombuffer(cur, dtype=vt.dtype, count=n, offset=off)
                idx = np.flatnonzero(compare(vt, a_cur, op, v1, v2, prev=a_old, tolerance=tol))
                if not idx.size:
                    continue
                rel = off + idx.astype(np.int64) * size
                keep = _pages_ok(pos, rel, size, old_ok) & _pages_ok(pos, rel, size, cur_ok)
                idx, rel = idx[keep], rel[keep]
                addr_parts.append(np.uint64(pos) + rel.astype(np.uint64))
                raw_parts.append(np.ascontiguousarray(a_cur[idx]).view(np.uint8).reshape(-1, size))
        return self._make_state(vt, size, align, addr_parts, raw_parts)

    def _next_bytes(self, st: ScanState, op, value) -> ScanState:
        if op in ("changed", "unchanged"):
            cur, ok = self._gather(st.addrs, st.size)
            same = (cur == st.raw).all(axis=1)
            mask = ok & (same if op == "unchanged" else ~same)
            return ScanState(st.vt, st.size, st.addrs[mask], cur[mask], 1)
        if op in ("eq", "ne"):
            rx, size = byte_pattern(st.vt, str(value), st.ignore_case)
            cur, ok = self._gather(st.addrs, size)
            hit = np.array([rx.fullmatch(row.tobytes()) is not None for row in cur], dtype=bool)
            mask = ok & (hit if op == "eq" else ~hit)
            return ScanState(st.vt, size, st.addrs[mask], cur[mask], 1)
        raise ScanError("string/bytes next scans support eq, ne, changed, unchanged")

    def undo(self) -> dict:
        if not self._undo:
            raise ScanError("nothing to undo")
        self.scan = self._undo.pop()
        return self._summary(self.scan, 0.0, None)

    def reset(self) -> None:
        self.scan = None
        self._undo.clear()

    def _require_scan(self) -> ScanState:
        if self.scan is None:
            raise ScanError("no scan in progress; call scan_first first")
        return self.scan

    def _summary(self, st: ScanState, seconds: float, scanned_bytes: int | None, before: int | None = None) -> dict:
        out = {"type": st.vt.describe(), "results": st.count, "scan_number": st.scans,
               "seconds": round(seconds, 2)}
        if scanned_bytes is not None:
            out["scanned_mb"] = round(scanned_bytes / 2**20, 1)
        if before is not None:
            out["before"] = before
        if st.snapshot is not None:
            out["note"] = ("snapshot taken; change the value in-game, then scan_next with "
                           "changed/unchanged/increased/decreased")
        elif 0 < st.count <= 20:
            out["preview"] = self.results(0, 20)["results"]
        return out

    def results(self, offset: int = 0, limit: int = 50) -> dict:
        st = self._require_scan()
        if st.snapshot is not None:
            return {"total": st.count, "results": [],
                    "note": "unknown-value snapshot: narrow it with scan_next before listing"}
        addrs = st.addrs[offset:offset + limit]
        cur, ok = self._gather(addrs, st.size)
        rows = []
        for i, a in enumerate(addrs.tolist()):
            row = {"address": hex(a),
                   "value": decode(st.vt, cur[i].tobytes()) if ok[i] else None,
                   "previous": decode(st.vt, st.raw[offset + i].tobytes())}
            w = self.where(a)
            if w:
                row["static"] = w
            rows.append(row)
        return {"total": st.count, "offset": offset, "results": rows}

    def result_addresses(self, limit: int) -> list[int]:
        st = self._require_scan()
        if st.snapshot is not None:
            raise ScanError("narrow the unknown-value scan first")
        return st.addrs[:limit].tolist()

    # -- direct access ------------------------------------------------------

    def read_value(self, address, vt: ValueType, count: int = 1, pointer_size: int | None = None) -> dict:
        addr = self.eval_address(address, pointer_size)
        out = {"address": hex(addr)}
        w = self.where(addr)
        if w:
            out["static"] = w
        if vt.numeric:
            count = max(1, min(count, 4096))
            raw = self.task.read(addr, vt.size * count)
            vals = np.frombuffer(raw, dtype=vt.dtype)
            vals = [float(v) for v in vals] if vt.is_float else [int(v) for v in vals]
            out["value" if count == 1 else "values"] = vals[0] if count == 1 else vals
        elif vt.name == "bytes":
            length = max(1, min(count if count > 1 else 64, 65536))
            raw = self.task.read(addr, length)
            out["hexdump"] = hexdump(addr, raw)
        else:
            length = max(2, min(count if count > 1 else 256, 65536))
            raw = self.task.read(addr, length)
            text = decode(vt, raw)
            out["value"] = text.split("\0", 1)[0]
        return out

    def write_value(self, address, vt: ValueType, value, pointer_size: int | None = None) -> dict:
        addr = self.eval_address(address, pointer_size)
        data = encode(vt, value)
        self.task.write(addr, data)
        back = self.task.read(addr, len(data))
        return {"address": hex(addr), "written": decode(vt, back) if vt.name != "bytes" else back.hex(" ").upper()}

    def aob_scan(self, pattern: str, module: str | None = None, limit: int = 100,
                 writable_only: bool = False, executable_only: bool = False) -> list[int]:
        rx, size = byte_pattern(ValueType("bytes"), pattern)
        hits: list[int] = []
        for lo, hi in self.spans(writable_only, module=module, executable_only=executable_only):
            for pos, buf, nominal, page_ok in self._chunks(lo, hi, size - 1):
                for m in rx.finditer(memoryview(buf)):
                    if m.start() >= nominal:
                        break
                    hits.append(pos + m.start())
                    if len(hits) >= limit:
                        return hits
        return hits

    # -- pointer scanning ---------------------------------------------------

    def pointer_scan(self, target, max_depth: int = 4, max_offset: int = 0x1000, pointer_size: int | None = None,
                     modules: list[str] | None = None, max_results: int = 200,
                     static_ranges: list[tuple[int, int, str, int]] | None = None) -> dict:
        t0 = time.monotonic()
        addr = self.eval_address(target)
        ps = pointer_size or self.default_pointer_size()
        if static_ranges is None:
            mods = [self.require_module(n) for n in modules] if modules else \
                [m for m in self.modules() if m.kind != "macho"] or self.modules()
            static_ranges = [(m.base, m.end, m.name, m.base) for m in mods]
        spans = self.spans(writable_only=True)
        paddrs, pvals = pointers.build_pointer_map(self.task, spans, ps)
        chains = pointers.find_chains(paddrs, pvals, addr, static_ranges, max_depth=max_depth,
                                      max_offset=max_offset, max_results=max_results)
        self.chains = chains
        return {"target": hex(addr), "pointer_size": ps, "pointers_indexed": int(len(paddrs)),
                "chains": len(chains), "seconds": round(time.monotonic() - t0, 2),
                "top": [c.expr() for c in chains[:30]]}

    def pointer_filter(self, target, pointer_size: int | None = None) -> dict:
        addr = self.eval_address(target)
        kept = []
        for c in self.chains:
            try:
                if self.eval_address(c.expr(), pointer_size) == addr:
                    kept.append(c)
            except (MachError, expr_mod.ExprError, ScanError):
                pass
        before = len(self.chains)
        self.chains = kept
        return {"target": hex(addr), "before": before, "chains": len(kept), "top": [c.expr() for c in kept[:30]]}


def hexdump(addr: int, raw: bytes) -> str:
    lines = []
    for i in range(0, len(raw), 16):
        chunk = raw[i:i + 16]
        hexs = " ".join(f"{b:02X}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{addr + i:012X}  {hexs:<47}  {text}")
    return "\n".join(lines)


# -- freezing ----------------------------------------------------------------

@dataclass
class Frozen:
    id: int
    label: str
    address: str
    vt: ValueType
    value: object
    data: bytes
    pointer_size: int | None
    dynamic: bool
    resolved: int
    writes: int = 0
    errors: int = 0
    last_error: str = ""

    def to_dict(self) -> dict:
        return {"id": self.id, "label": self.label, "address": self.address, "resolved": hex(self.resolved),
                "type": self.vt.describe(), "value": self.value, "writes": self.writes, "errors": self.errors,
                **({"last_error": self.last_error} if self.last_error else {})}


@dataclass
class Freezer:
    interval: float = 0.05
    entries: dict[int, Frozen] = field(default_factory=dict)
    session: Session | None = None
    _next_id: int = 1
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _thread: threading.Thread | None = None
    _stop: threading.Event = field(default_factory=threading.Event)

    def add(self, session: Session, address: str, vt: ValueType, value, label: str = "",
            pointer_size: int | None = None) -> Frozen:
        data = encode(vt, value)
        addr = session.eval_address(address, pointer_size)
        session.task.write(addr, data)
        with self._lock:
            if self.session is not session:
                self.entries.clear()
                self.session = session
            entry = Frozen(self._next_id, label or str(address), str(address), vt, value, data, pointer_size,
                           expr_mod.uses_memory(address), addr, writes=1)
            self.entries[entry.id] = entry
            self._next_id += 1
        self._ensure_thread()
        return entry

    def remove(self, ident) -> int:
        with self._lock:
            if ident in (None, "all", "*"):
                n = len(self.entries)
                self.entries.clear()
                return n
            return 1 if self.entries.pop(int(ident), None) else 0

    def clear_session(self, session: Session) -> None:
        with self._lock:
            if self.session is session:
                self.entries.clear()
                self.session = None

    def list(self) -> list[dict]:
        with self._lock:
            return [e.to_dict() for e in self.entries.values()]

    def tick(self) -> None:
        with self._lock:
            session = self.session
            entries = list(self.entries.values())
        for e in entries:
            try:
                if e.dynamic:
                    e.resolved = session.eval_address(e.address, e.pointer_size)
                session.task.write(e.resolved, e.data)
                e.writes += 1
                e.last_error = ""
            except Exception as exc:  # pointer chains can be briefly invalid (loading screens)
                e.errors += 1
                e.last_error = str(exc)

    def _ensure_thread(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="freezer", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            if self.entries:
                self.tick()

    def stop(self) -> None:
        self._stop.set()

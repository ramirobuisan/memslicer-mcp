"""Pointer scanning: find chains [[module+off]+o1]+o2... that lead to an address.

Heap addresses change every launch; a chain that starts in a module's static
data survives restarts. The scan builds a map of every aligned value in
writable memory that looks like a pointer into writable memory, then walks
backwards from the target level by level (Cheat Engine's approach, simplified).
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from .expr import quote_module
from .mach import Task

CHUNK = 32 << 20


@dataclass(frozen=True)
class Chain:
    module: str
    base_offset: int
    offsets: tuple[int, ...]

    def expr(self) -> str:
        s = f"{quote_module(self.module)}+0x{self.base_offset:X}"
        for o in self.offsets:
            s = f"[{s}]" + (f"+0x{o:X}" if o else "")
        return s


def _merge(ranges: list[tuple[int, int]]) -> tuple[np.ndarray, np.ndarray]:
    ranges = sorted(ranges)
    merged: list[list[int]] = []
    for lo, hi in ranges:
        if merged and lo <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], hi)
        else:
            merged.append([lo, hi])
    lo = np.array([r[0] for r in merged], dtype=np.uint64)
    hi = np.array([r[1] for r in merged], dtype=np.uint64)
    return lo, hi


def _in_ranges(vals: np.ndarray, lo: np.ndarray, hi: np.ndarray) -> np.ndarray:
    k = np.searchsorted(lo, vals, side="right").astype(np.int64) - 1
    kk = np.maximum(k, 0)
    return (k >= 0) & (vals < hi[kk])


def build_pointer_map(task: Task, spans: list[tuple[int, int]], pointer_size: int) -> tuple[np.ndarray, np.ndarray]:
    """(pointer locations, pointer values) sorted by value, for every aligned
    value in `spans` that points back into `spans`."""
    lo, hi = _merge(spans)
    if not len(lo):
        return np.empty(0, np.uint64), np.empty(0, np.uint64)
    vmin, vmax = lo[0], hi[-1]
    dtype = np.dtype("<u8" if pointer_size == 8 else "<u4")
    addr_parts, val_parts = [], []
    for start, end in spans:
        pos = start
        while pos < end:
            n = min(CHUNK, end - pos)
            buf, page_ok = task.read_robust(pos, n)
            pos_now = pos
            pos += n
            if page_ok is not None and not page_ok.any():
                continue
            count = n // pointer_size
            vals = np.frombuffer(buf, dtype=dtype, count=count).astype(np.uint64, copy=False)
            cand = np.flatnonzero((vals >= vmin) & (vals < vmax))
            if not cand.size:
                continue
            v = vals[cand]
            keep = _in_ranges(v, lo, hi)
            cand, v = cand[keep], v[keep]
            if page_ok is not None:
                rel = cand * pointer_size
                cand_ok = page_ok[(pos_now + rel) // 4096 - pos_now // 4096]
                cand, v = cand[cand_ok], v[cand_ok]
            addr_parts.append(np.uint64(pos_now) + cand.astype(np.uint64) * np.uint64(pointer_size))
            val_parts.append(v.copy())
    if not addr_parts:
        return np.empty(0, np.uint64), np.empty(0, np.uint64)
    addrs = np.concatenate(addr_parts)
    vals = np.concatenate(val_parts)
    order = np.argsort(vals, kind="stable")
    return addrs[order], vals[order]


def find_chains(paddrs: np.ndarray, pvals: np.ndarray, target: int,
                statics: list[tuple[int, int, str, int]], max_depth: int = 4, max_offset: int = 0x1000,
                max_results: int = 200, max_frontier: int = 50_000) -> list[Chain]:
    """statics: (start, end, module_name, module_base) ranges that count as a stable base."""
    statics = sorted(statics)
    s_lo = np.array([s[0] for s in statics], dtype=np.uint64)
    s_hi = np.array([s[1] for s in statics], dtype=np.uint64)

    def static_of(addr: int):
        for lo, hi, name, base in statics:
            if lo <= addr < hi:
                return name, base
        return None

    results: list[Chain] = []
    hit = static_of(target)
    if hit:
        results.append(Chain(hit[0], target - hit[1], ()))

    frontier = np.array([target], dtype=np.uint64)
    paths: list[tuple[int, ...]] = [()]
    seen = {target}
    max_off = np.uint64(max_offset)
    for _ in range(max_depth):
        lo_idx = np.searchsorted(pvals, frontier - np.minimum(frontier, max_off), side="left")
        hi_idx = np.searchsorted(pvals, frontier, side="right")
        nxt_addrs: list[int] = []
        nxt_paths: list[tuple[int, ...]] = []
        for i in np.flatnonzero(hi_idx > lo_idx):
            t = int(frontier[i])
            path = paths[i]
            pa = paddrs[lo_idx[i]:hi_idx[i]]
            pv = pvals[lo_idx[i]:hi_idx[i]]
            is_static = _in_ranges(pa, s_lo, s_hi) if len(s_lo) else np.zeros(len(pa), bool)
            for a, v, st in zip(pa.tolist(), pv.tolist(), is_static.tolist()):
                new_path = (t - v,) + path
                if st:
                    name, base = static_of(a)
                    results.append(Chain(name, a - base, new_path))
                    if len(results) >= max_results:
                        return results
                elif a not in seen:
                    seen.add(a)
                    nxt_addrs.append(a)
                    nxt_paths.append(new_path)
        if not nxt_addrs:
            break
        if len(nxt_addrs) > max_frontier:
            # Prefer small offsets: real struct fields are usually near the start of an object.
            order = sorted(range(len(nxt_addrs)), key=lambda j: nxt_paths[j][0])[:max_frontier]
            nxt_addrs = [nxt_addrs[j] for j in order]
            nxt_paths = [nxt_paths[j] for j in order]
        frontier = np.array(nxt_addrs, dtype=np.uint64)
        paths = nxt_paths
    return results

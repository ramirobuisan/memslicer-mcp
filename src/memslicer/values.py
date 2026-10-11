"""Value types, parsing/encoding, and the comparison operators used by scans."""

from __future__ import annotations

import re
from dataclasses import dataclass

import numpy as np

NUMERIC = {
    "int8": ("i1", 1), "uint8": ("u1", 1),
    "int16": ("i2", 2), "uint16": ("u2", 2),
    "int32": ("i4", 4), "uint32": ("u4", 4),
    "int64": ("i8", 8), "uint64": ("u8", 8),
    "float": ("f4", 4), "double": ("f8", 8),
}
BYTE_TYPES = ("string", "string16", "bytes")
ALIASES = {
    "byte": "uint8", "short": "int16", "int": "int32", "long": "int64",
    "i8": "int8", "u8": "uint8", "i16": "int16", "u16": "uint16", "i32": "int32", "u32": "uint32",
    "i64": "int64", "u64": "uint64", "float32": "float", "f32": "float", "float64": "double", "f64": "double",
    "str": "string", "utf8": "string", "utf16": "string16", "wstring": "string16", "aob": "bytes",
}
TYPE_NAMES = tuple(NUMERIC) + BYTE_TYPES

ABSOLUTE_OPS = ("eq", "ne", "gt", "lt", "ge", "le", "between")
RELATIVE_OPS = ("changed", "unchanged", "increased", "decreased", "increased_by", "decreased_by")
OP_ALIASES = {
    "=": "eq", "==": "eq", "equal": "eq", "exact": "eq", "!=": "ne", "not_equal": "ne",
    ">": "gt", "<": "lt", ">=": "ge", "<=": "le", "greater": "gt", "less": "lt", "range": "between",
    "same": "unchanged", "different": "changed", "inc": "increased", "dec": "decreased",
    "unknown_initial": "unknown",
}


@dataclass(frozen=True)
class ValueType:
    name: str
    endian: str = "little"

    @property
    def numeric(self) -> bool:
        return self.name in NUMERIC

    @property
    def is_float(self) -> bool:
        return self.name in ("float", "double")

    @property
    def size(self) -> int:
        """Fixed size for numerics; 0 for byte types (size comes from the pattern)."""
        return NUMERIC[self.name][1] if self.numeric else 0

    @property
    def dtype(self) -> np.dtype:
        return np.dtype((">" if self.endian == "big" else "<") + NUMERIC[self.name][0])

    @property
    def default_alignment(self) -> int:
        # 8-byte values are often only 4-aligned in 32-bit games, so default to 4.
        return 1 if not self.numeric else min(self.size, 4)

    def describe(self) -> str:
        return self.name + (" (big-endian)" if self.endian == "big" and self.name != "bytes" else "")


def parse_type(name: str, endian: str = "little") -> ValueType:
    key = name.strip().lower()
    key = ALIASES.get(key, key)
    if key not in TYPE_NAMES:
        raise ValueError(f"unknown type {name!r}; use one of {', '.join(TYPE_NAMES)}")
    endian = (endian or "little").lower()
    if endian in ("le", "<"):
        endian = "little"
    if endian in ("be", ">"):
        endian = "big"
    if endian not in ("little", "big"):
        raise ValueError("endian must be 'little' or 'big'")
    return ValueType(key, endian)


def parse_op(op: str) -> str:
    key = op.strip().lower()
    key = OP_ALIASES.get(key, key)
    if key not in ABSOLUTE_OPS + RELATIVE_OPS + ("unknown",):
        raise ValueError(f"unknown comparison {op!r}")
    return key


def parse_int(value) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not value.is_integer():
            raise ValueError(f"{value} is not an integer")
        return int(value)
    s = str(value).strip().replace("_", "")
    neg = s.startswith("-")
    if neg:
        s = s[1:]
    n = int(s, 16) if s.lower().startswith("0x") else int(s, 10)
    return -n if neg else n


def parse_address(value) -> int:
    """Addresses are hex when given as strings (with or without 0x), like Cheat Engine."""
    if isinstance(value, int):
        return value
    s = str(value).strip().lower().replace("_", "").replace("`", "")
    return int(s[2:] if s.startswith("0x") else s, 16)


def parse_number(vt: ValueType, value):
    if vt.is_float:
        return float(parse_int(value)) if isinstance(value, str) and value.strip().lower().startswith(("0x", "-0x")) \
            else float(value)
    n = parse_int(value)
    info = np.iinfo(vt.dtype)
    if not info.min <= n <= info.max:
        raise ValueError(f"{n} does not fit in {vt.name} ({info.min}..{info.max})")
    return n


def encode(vt: ValueType, value) -> bytes:
    """Bytes to write for a value of this type."""
    if vt.numeric:
        return np.array([parse_number(vt, value)], dtype=vt.dtype).tobytes()
    if vt.name == "string":
        return str(value).encode("utf-8")
    if vt.name == "string16":
        return str(value).encode("utf-16-be" if vt.endian == "big" else "utf-16-le")
    tokens = _hex_tokens(str(value))
    if any(t in ("?", "??") for t in tokens):
        raise ValueError("wildcards are only allowed when scanning, not when writing")
    return bytes(int(t, 16) for t in tokens)


def decode(vt: ValueType, raw: bytes):
    if vt.numeric:
        v = np.frombuffer(raw, dtype=vt.dtype, count=1)[0]
        return float(v) if vt.is_float else int(v)
    if vt.name == "string":
        return raw.decode("utf-8", errors="replace")
    if vt.name == "string16":
        return raw.decode("utf-16-be" if vt.endian == "big" else "utf-16-le", errors="replace")
    return raw.hex(" ").upper()


def _hex_tokens(pattern: str) -> list[str]:
    tokens = []
    for part in pattern.replace(",", " ").split():
        if part in ("?", "??", "*", "**"):
            tokens.append("??")
        elif len(part) > 2 and all(c in "0123456789abcdefABCDEF?" for c in part) and len(part) % 2 == 0:
            tokens.extend(part[i:i + 2] for i in range(0, len(part), 2))
        else:
            tokens.append(part)
    for t in tokens:
        if t != "??" and not re.fullmatch(r"[0-9a-fA-F]{1,2}", t):
            raise ValueError(f"bad byte {t!r} in pattern {pattern!r}")
    return ["??" if t in ("?", "??") else t for t in tokens]


def byte_pattern(vt: ValueType, value: str, ignore_case: bool = False) -> tuple[re.Pattern, int]:
    """Compile a byte-type search value to (regex, match length)."""
    if vt.name == "bytes":
        tokens = _hex_tokens(value)
        rx = b"".join(b"." if t == "??" else re.escape(bytes([int(t, 16)])) for t in tokens)
        return re.compile(rx, re.DOTALL), len(tokens)
    if vt.name == "string":
        data = value.encode("utf-8")
        return re.compile(re.escape(data), re.DOTALL | (re.IGNORECASE if ignore_case else 0)), len(data)
    enc = "utf-16-be" if vt.endian == "big" else "utf-16-le"
    parts = []
    for ch in value:
        if ignore_case and ch.isascii() and ch.isalpha():
            lo, up = ch.lower().encode(enc), ch.upper().encode(enc)
            parts.append(b"(?:" + re.escape(lo) + b"|" + re.escape(up) + b")")
        else:
            parts.append(re.escape(ch.encode(enc)))
    return re.compile(b"".join(parts), re.DOTALL), len(value.encode(enc))


def default_tolerance(vt: ValueType, v: float | None) -> float:
    if not vt.is_float:
        return 0.0
    return 1e-3 * max(1.0, abs(v or 0.0))


def compare(vt: ValueType, cur: np.ndarray, op: str, v1=None, v2=None,
            prev: np.ndarray | None = None, tolerance: float | None = None) -> np.ndarray:
    """Vectorised comparison for numeric scans. Returns a bool mask."""
    with np.errstate(all="ignore"):  # raw memory is full of NaNs and overflowing values
        return _compare(vt, cur, op, v1, v2, prev, tolerance)


def _compare(vt, cur, op, v1, v2, prev, tolerance) -> np.ndarray:
    if op in RELATIVE_OPS and prev is None:
        raise ValueError(f"'{op}' needs a previous scan to compare against")
    if op in ("changed", "unchanged"):
        # Compare raw bits so NaN == NaN counts as unchanged.
        ib = np.dtype(f"u{vt.size}")
        same = cur.view(ib) == prev.view(ib)
        return same if op == "unchanged" else ~same
    if op == "increased":
        return cur > prev
    if op == "decreased":
        return cur < prev
    if op in ("increased_by", "decreased_by"):
        d = parse_number(vt, v1) if not vt.is_float else float(v1)
        if vt.is_float:
            diff = cur.astype(np.float64) - prev.astype(np.float64)
            tol = default_tolerance(vt, d) if tolerance is None else tolerance
            return np.abs(diff - (d if op == "increased_by" else -d)) <= tol
        native = vt.dtype.newbyteorder("=")
        c = cur.astype(native)
        p = prev.astype(native)
        delta = (c - p) if op == "increased_by" else (p - c)
        return delta == np.array(d).astype(native)

    a = parse_number(vt, v1)
    if vt.is_float:
        tol = default_tolerance(vt, a) if tolerance is None else tolerance
        c = cur.astype(np.float64)
        if op == "eq":
            return np.abs(c - a) <= tol
        if op == "ne":
            return ~(np.abs(c - a) <= tol)
    elif tolerance:
        c = cur.astype(np.float64)
        if op == "eq":
            return np.abs(c - a) <= tolerance
        if op == "ne":
            return ~(np.abs(c - a) <= tolerance)
    else:
        c = cur
    if op == "eq":
        return c == a
    if op == "ne":
        return c != a
    if op == "gt":
        return c > a
    if op == "lt":
        return c < a
    if op == "ge":
        return c >= a
    if op == "le":
        return c <= a
    if op == "between":
        b = parse_number(vt, v2)
        lo, hi = min(a, b), max(a, b)
        return (c >= lo) & (c <= hi)
    raise ValueError(f"'{op}' is not valid here")

"""Cheat Engine style address expressions.

    0x7FF61234            absolute address (bare words are hex, like CE)
    Game.exe+1A2B3C       module base + offset
    "My Game.exe"+10      quote names containing spaces or '-'
    [[Game.exe+0x10]+8]+4 pointer chain: [x] reads a pointer at x
    $exe+0x10             base of the main executable
    aob("48 8B 05 ?? ?? ?? ??", "Game.exe")   first match of a byte pattern
    rip(aob("48 8B 05 ?? ?? ?? ??")+3)        resolve a RIP-relative disp32 at that address
    find([[Game.exe+0x10]+8], 0x1000, "0B 00 00 00 ?? ?? ?? ?? 20 00 00 00")
                          first match of a pattern inside [start, start+length): follows an
                          item by its ID inside an array (inventories that get rearranged)
"""

from __future__ import annotations

import re
from typing import Callable

MASK64 = (1 << 64) - 1

_TOKEN = re.compile(r"""\s*(?:(?P<str>"[^"]*"|'[^']*')|(?P<op>[\[\]()+\-,*])|(?P<word>[A-Za-z0-9_.$]+))""")
_PLAIN_NAME = re.compile(r"[A-Za-z0-9_.$]+")


class ExprError(ValueError):
    pass


def quote_module(name: str) -> str:
    return name if _PLAIN_NAME.fullmatch(name) and not is_hex(name) else f'"{name}"'


def is_hex(word: str) -> bool:
    w = word[2:] if word.lower().startswith("0x") else word
    return bool(w) and all(c in "0123456789abcdefABCDEF" for c in w)


def _tokenize(text: str) -> list[tuple[str, str]]:
    tokens = []
    pos = 0
    text = text.strip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m or m.end() == pos:
            raise ExprError(f"unexpected character at {pos}: {text[pos:pos + 10]!r}")
        kind = m.lastgroup
        tokens.append((kind, m.group(kind)))
        pos = m.end()
        while pos < len(text) and text[pos].isspace():
            pos += 1
    return tokens


class _Parser:
    def __init__(self, text, module_base, read_ptr, aob, read_i32, find=None):
        self.text = text
        self.tokens = _tokenize(text)
        self.i = 0
        self.module_base = module_base
        self.read_ptr = read_ptr
        self.aob = aob
        self.read_i32 = read_i32
        self.find = find

    def peek(self):
        return self.tokens[self.i][1] if self.i < len(self.tokens) else None

    def take(self):
        if self.i >= len(self.tokens):
            raise ExprError(f"unexpected end of expression {self.text!r}")
        tok = self.tokens[self.i]
        self.i += 1
        return tok

    def expect(self, value):
        kind, tok = self.take()
        if tok != value:
            raise ExprError(f"expected {value!r} but found {tok!r} in {self.text!r}")

    def parse(self) -> int:
        v = self.sum()
        if self.i != len(self.tokens):
            raise ExprError(f"unexpected {self.peek()!r} in {self.text!r}")
        return v

    def sum(self) -> int:
        v = self.product()
        while self.peek() in ("+", "-"):
            _, op = self.take()
            r = self.product()
            v = (v + r if op == "+" else v - r) & MASK64
        return v

    def product(self) -> int:
        v = self.atom()
        while self.peek() == "*":
            self.take()
            v = (v * self.atom()) & MASK64
        return v

    def atom(self) -> int:
        kind, tok = self.take()
        if tok == "[":
            addr = self.sum()
            self.expect("]")
            return self.read_ptr(addr)
        if tok == "(":
            v = self.sum()
            self.expect(")")
            return v
        if tok == "-":
            return (-self.atom()) & MASK64
        if kind == "str":
            return self._module(tok[1:-1])
        if kind == "word":
            if self.peek() == "(":
                return self.call(tok.lower())
            if tok[:2].lower() == "0x" and is_hex(tok):
                return int(tok, 16)
            base = self.module_base(tok)
            if base is not None:
                return base
            if is_hex(tok):
                return int(tok, 16)
            raise ExprError(f"unknown module or bad number {tok!r}")
        raise ExprError(f"unexpected {tok!r} in {self.text!r}")

    def _module(self, name: str) -> int:
        base = self.module_base(name)
        if base is None:
            raise ExprError(f"module {name!r} is not loaded")
        return base

    def call(self, fn: str) -> int:
        self.expect("(")
        if fn == "aob":
            kind, pattern = self.take()
            if kind != "str":
                raise ExprError('aob() takes a quoted pattern: aob("48 8B ?? ??")')
            module = None
            if self.peek() == ",":
                self.take()
                kind, module = self.take()
                if kind not in ("str", "word"):
                    raise ExprError("aob() second argument is a module name")
                module = module.strip("\"'")
            self.expect(")")
            return self.aob(pattern[1:-1], module)
        if fn == "find":
            start = self.sum()
            self.expect(",")
            length = self.sum()
            self.expect(",")
            kind, pattern = self.take()
            if kind != "str":
                raise ExprError('find(start, length, "pattern") takes a quoted pattern')
            self.expect(")")
            if self.find is None:
                raise ExprError("find() is not available here")
            return self.find(start, length, pattern[1:-1])
        if fn == "rip":
            addr = self.sum()
            self.expect(")")
            return (addr + 4 + self.read_i32(addr)) & MASK64
        raise ExprError(f"unknown function {fn}()")


def evaluate(text: str, *, module_base: Callable[[str], int | None], read_ptr: Callable[[int], int],
             aob: Callable[[str, str | None], int], read_i32: Callable[[int], int],
             find: Callable[[int, int, str], int] | None = None) -> int:
    if not text or not str(text).strip():
        raise ExprError("empty address")
    return _Parser(str(text), module_base, read_ptr, aob, read_i32, find).parse()


def uses_memory(text: str) -> bool:
    """True if evaluating needs to read memory every time (pointer derefs)."""
    t = str(text).lower()
    return "[" in t or "rip(" in t or "find(" in t

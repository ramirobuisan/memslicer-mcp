"""Engine tests against our own process (no root needed: task_for_pid(self) always works)."""

import ctypes
import os
import struct

import numpy as np
import pytest

from memslicer.engine import Freezer, Session
from memslicer.expr import ExprError
from memslicer.mach import Task
from memslicer.values import parse_type

libc = ctypes.CDLL(None)
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
PROT_RW, MAP_ANON_PRIVATE = 0x3, 0x1002
VM_TAG = 242 << 24  # VM_MEMORY_APPLICATION_SPECIFIC_3: keeps our mappings from merging with others


def tagged_buffer(size: int) -> np.ndarray:
    addr = libc.mmap(None, size, PROT_RW, MAP_ANON_PRIVATE, VM_TAG, 0)
    assert addr not in (None, ctypes.c_void_p(-1).value)
    return np.ctypeslib.as_array((ctypes.c_uint8 * size).from_address(addr))


@pytest.fixture
def session():
    s = Session(Task.for_pid(os.getpid()))
    yield s
    s.close()


@pytest.fixture
def buf():
    return tagged_buffer(1 << 20)


def span(b: np.ndarray) -> dict:
    return {"start": b.ctypes.data, "end": b.ctypes.data + b.nbytes}


def test_int32_scan_next_and_write(session, buf):
    ints = buf.view(np.int32)
    ints[100] = 987654
    ints[2000] = 987654
    s = session.first_scan(parse_type("int32"), "eq", "987654", **span(buf))
    assert s["results"] == 2
    ints[100] = 987650
    s = session.next_scan("decreased_by", 4)
    assert s["results"] == 1
    assert int(s["preview"][0]["address"], 16) == ints[100:].ctypes.data
    session.write_value(s["preview"][0]["address"], parse_type("int32"), 31337)
    assert ints[100] == 31337


def test_unaligned_and_big_endian(session, buf):
    buf[13:17] = np.frombuffer(struct.pack(">i", 424242), np.uint8)
    s = session.first_scan(parse_type("int32", "big"), "eq", 424242, alignment=1, **span(buf))
    assert s["results"] == 1
    assert int(s["preview"][0]["address"], 16) == buf.ctypes.data + 13
    assert session.first_scan(parse_type("int32", "big"), "eq", 424242, **span(buf))["results"] == 0


def test_float_tolerance(session, buf):
    f = buf.view(np.float32)
    f[50] = 99.6
    assert session.first_scan(parse_type("float"), "eq", 100, **span(buf))["results"] == 0
    assert session.first_scan(parse_type("float"), "eq", 100, tolerance=0.5, **span(buf))["results"] == 1
    assert session.first_scan(parse_type("float"), "between", 99, 101, **span(buf))["results"] == 1


def test_unknown_initial_value(session, buf):
    q = buf.view(np.int64)
    q[:] = 7
    session.first_scan(parse_type("int64"), "unknown", alignment=8, **span(buf))
    q[10] = 9
    q[20] = 3
    assert session.next_scan("increased")["results"] == 1
    session.undo()
    assert session.scan.snapshot is not None
    assert session.next_scan("changed")["results"] == 2
    assert session.next_scan("unchanged")["results"] == 2
    q[20] = 1
    assert session.next_scan("decreased")["results"] == 1


def test_strings_and_aob(session, buf):
    text = "Excalibur of Testing".encode("utf-16-le")
    buf[4096:4096 + len(text)] = np.frombuffer(text, np.uint8)
    s = session.first_scan(parse_type("string16"), "eq", "excalibur", ignore_case=True, **span(buf))
    assert s["results"] == 1
    buf[8000:8006] = np.frombuffer(bytes.fromhex("DEADBEEF1337"), np.uint8)
    hits = session.aob_scan("DE AD ?? EF 13 37", limit=5, writable_only=True)
    assert buf.ctypes.data + 8000 in hits


def test_byte_scan_narrowing(session, buf):
    buf[100:104] = np.frombuffer(b"GOLD", np.uint8)
    session.first_scan(parse_type("string"), "eq", "GOLD", **span(buf))
    buf[100:104] = np.frombuffer(b"IRON", np.uint8)
    assert session.next_scan("changed")["results"] == 1
    assert session.next_scan("eq", "IRON")["results"] == 1


def test_expressions_and_pointer_scan(session, buf):
    static = tagged_buffer(1 << 16)  # stands in for a module's .data section
    heap_a = buf[0:4096]
    heap_b = buf[65536:65536 + 4096]
    hp_addr = heap_b.ctypes.data + 0x48
    heap_b.view(np.int32)[0x48 // 4] = 777
    heap_a.view(np.uint64)[0x10 // 8] = heap_b.ctypes.data              # a->b at +0x10
    static.view(np.uint64)[0x200 // 8] = heap_a.ctypes.data             # static->a at +0x200
    base = static.ctypes.data

    expr = f"[[0x{base + 0x200:X}]+0x10]+0x48"
    assert session.eval_address(expr, 8) == hp_addr
    assert session.read_value(expr, parse_type("int32"), pointer_size=8)["value"] == 777

    res = session.pointer_scan(hex(hp_addr), max_depth=3, pointer_size=8,
                               static_ranges=[(base, base + static.nbytes, "Fake.exe", base)])
    assert "[[Fake.exe+0x200]+0x10]+0x48" in res["top"]
    with pytest.raises(ExprError):
        session.eval_address("[[Nope.exe+0x200]+0x10]+0x48")


def test_freezer(session, buf):
    ints = buf.view(np.int32)
    fr = Freezer(interval=0.01)
    fr.add(session, hex(ints[5:].ctypes.data), parse_type("int32"), 100, label="hp")
    ints[5] = 1
    fr.tick()
    assert ints[5] == 100
    assert fr.list()[0]["label"] == "hp"
    assert fr.remove("all") == 1
    fr.stop()


def test_modules_found_for_python(session):
    mods = session.modules()
    assert any(m.kind == "macho" and m.is_exe for m in mods)


def test_sparse_snapshot_skips_zero_pages(session):
    b = tagged_buffer(1 << 20)  # fresh mapping: all zero
    q = b.view(np.int32)
    q[5000] = 1200  # one non-zero page
    s = session.first_scan(parse_type("int32"), "unknown", **span(b))
    assert len(session.scan.snapshot) == 1 and session.scan.snapshot[0][1].shape == (1, 4096)
    q[5000] = 950
    s = session.next_scan("decreased")
    assert s["results"] == 1 and int(s["preview"][0]["address"], 16) == q[5000:].ctypes.data
    # an unaligned span edge falls back to a dense snapshot
    session.first_scan(parse_type("int32"), "unknown", start=b.ctypes.data + 8, end=b.ctypes.data + 4096 * 3)
    q[3] = 77
    assert session.next_scan("increased")["results"] == 1

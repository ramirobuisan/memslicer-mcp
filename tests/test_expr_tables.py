import pytest

from memslicer import tables
from memslicer.expr import ExprError, evaluate, quote_module, uses_memory
from memslicer.pointers import Chain
from memslicer.values import encode, parse_type

MODULES = {"game.exe": 0x400000, "my game-x64.exe": 0x140000000}
MEMORY = {0x400010: 0x2000, 0x2008: 0x3000, 0x500003: (0x100).to_bytes(4, "little", signed=True)}


def ev(text):
    return evaluate(text, module_base=lambda n: MODULES.get(n.lower()), read_ptr=lambda a: MEMORY[a],
                    aob=lambda p, m: 0x500000, read_i32=lambda a: int.from_bytes(MEMORY[a], "little", signed=True))


def test_expressions():
    assert ev("0x1234") == 0x1234
    assert ev("1234") == 0x1234  # bare numbers are hex, like Cheat Engine
    assert ev("Game.exe+10") == 0x400010
    assert ev('"My Game-x64.exe"+0x20') == 0x140000020
    assert ev("[[Game.exe+0x10]+8]+0x48") == 0x3048
    assert ev("rip(aob(\"48 8B 05 ?? ?? ?? ??\")+3)") == 0x500003 + 4 + 0x100
    assert ev("Game.exe+4*4") == 0x400010
    with pytest.raises(ExprError):
        ev("Missing.dll+10")
    with pytest.raises(ExprError):
        ev("[Game.exe+10")
    assert uses_memory("[a]+1") and not uses_memory("Game.exe+1")


def test_chain_round_trip():
    c = Chain("Game.exe", 0x10, (0x8, 0x48))
    assert c.expr() == "[[Game.exe+0x10]+0x8]+0x48"
    assert ev(c.expr()) == 0x3048
    assert quote_module("My Game-x64.exe") == '"My Game-x64.exe"'
    assert quote_module("abc") == '"abc"'  # would otherwise read as a hex number


def test_encode():
    assert encode(parse_type("int16", "big"), 0x1234) == b"\x12\x34"
    assert encode(parse_type("float"), "1.5") == b"\x00\x00\xc0\x3f"
    assert encode(parse_type("bytes"), "90 90") == b"\x90\x90"
    with pytest.raises(ValueError):
        encode(parse_type("uint8"), 300)


def test_tables(tmp_path, monkeypatch):
    monkeypatch.setenv("MEMSLICER_TABLES", str(tmp_path))
    tables.upsert("Some Game", {"name": "HP", "address": "[Game.exe+10]+4", "type": "int32", "value": 999,
                                "freeze": True}, process="Game.exe")
    tables.upsert("Some Game", {"name": "HP", "address": "[Game.exe+10]+8", "type": "int32", "value": 1,
                                "freeze": False})
    t = tables.load("Some Game")
    assert t["process"] == "Game.exe" and len(t["cheats"]) == 1 and t["cheats"][0]["value"] == 1
    assert tables.list_tables()[0]["cheats"] == ["HP"]
    assert tables.remove("Some Game", "HP") and tables.load("Some Game")["cheats"] == []


def test_offsets_never_trigger_module_lookups():
    asked = []

    def module_base(name):
        asked.append(name)
        return MODULES.get(name.lower())

    evaluate("[[Game.exe+0x10]+0x8]+0x48", module_base=module_base, read_ptr=lambda a: MEMORY[a],
             aob=lambda p, m: 0, read_i32=lambda a: 0)
    assert asked == ["Game.exe"]


def test_find_follows_an_item_inside_an_array():
    inventory = bytes(0x40) + bytes.fromhex("000000000B0000000000000020000000") + (6).to_bytes(4, "little")

    def find(start, length, pattern):
        import re
        rx = re.compile(b"".join(b"." if t == "??" else re.escape(bytes([int(t, 16)])) for t in pattern.split()),
                        re.DOTALL)
        return start + rx.search(inventory[:length]).start()

    addr = evaluate('find(1000, 0x100, "00 00 00 00 0B 00 00 00 ?? ?? ?? ?? 20 00 00 00")+0x10',
                    module_base=lambda n: None, read_ptr=lambda a: 0, aob=lambda p, m: 0, read_i32=lambda a: 0,
                    find=find)
    assert addr == 0x1000 + 0x40 + 0x10
    assert uses_memory('find(1, 2, "00")')

"""MCP server (stdio). Runs unprivileged and forwards memory operations to the root helper."""

from __future__ import annotations

import os
from typing import Union

try:  # mcp >= 2
    from mcp.server.mcpserver import MCPServer as _Server
except ImportError:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _Server

from . import procs, tables, wine
from .client import HelperClient, HelperError, HelperUnavailable, start_hint

Value = Union[int, float, str]

INSTRUCTIONS = """\
memslicer finds and edits values in a running game's memory on macOS: native games, Rosetta games,
and Windows games under Wine / CrossOver / NotProton (and emulators running inside them).

Workflow
1. status. If the helper isn't running, give the user the sudo command from the error; you can't start it.
2. list_processes(filter) -> attach(pid or name). For Wine games pick the process whose args contain the
   game's .exe (usually the largest one). CrossOver/NotProton wine is hardened, so first start_wine_agent(name=
   "Game.exe"), then attach (it falls back to the agent). If attach fails, diagnose_process(pid) explains why.
3. Known value (HUD shows HP 100): scan_first(value_type="int32", value=100). Have the value change in game
   (ask the user, or use screenshots/keys if you can see the game), then scan_next(compare="eq", value=<new>).
   Repeat until a handful of results. If int32 finds nothing try float (tolerance=0.5 or compare="between"),
   then double/int16. Unknown value (bars): scan_first(compare="unknown") then scan_next with
   decreased/increased/unchanged.
4. Confirm: write_memory (or write_scan_results when <=20 left) and check the game reacts. freeze locks a value.
5. Make it survive restarts: pointer_scan(address) gives chains like [[Game.exe+0x1A2B]+0x10]+0x48. After the
   game restarts, find the value again and pointer_filter(new_address) to keep only stable chains.
   Save with cheat_save; tables live in the repo's tables/ folder; cheat_apply (or `memslicer apply`) reuses them.

Addresses accept Cheat Engine syntax everywhere: 0x1234, Game.exe+1A2B, "My Game.exe"+10, [[base]+8]+4,
$exe+0x10, aob("48 8B 05 ?? ?? ?? ??", "Game.exe"), rip(aob("...")+3).
Console emulators keep guest RAM in one big block; GameCube/Wii/Wii U values are big-endian (endian="big").
Rosetta/Wine games: data cheats (scan/write/freeze) work; there is no debugger/code-injection support.
Single-player/offline games only.
"""

mcp = _Server("memslicer", instructions=INSTRUCTIONS)
_client = HelperClient()


def _h(method: str, **params):
    try:
        return _client.call(method, **params)
    except HelperUnavailable as e:
        raise RuntimeError(str(e)) from None
    except HelperError as e:
        raise RuntimeError(str(e)) from None


# -- status & processes ----------------------------------------------------------

@mcp.tool()
def status() -> dict:
    """Helper status, attached process, frozen values, and SIP state."""
    try:
        info = _client.call("ping")
        info["running"] = True
    except HelperUnavailable:
        info = {"running": False, "how_to_start": start_hint()}
    info["sip"] = procs.sip_status()
    return info


@mcp.tool()
def list_processes(filter: str = "", wine_only: bool = False, limit: int = 40) -> list[dict]:
    """Your processes, largest memory first. filter matches name or command line (e.g. 'exe', 'wine', 'Dolphin').
    Wine processes get wine=true and the Windows exe name."""
    rows = procs.list_processes(filter or None, uid=os.getuid())
    if wine_only:
        rows = [r for r in rows if r.get("wine")]
    return rows[:limit]


@mcp.tool()
def diagnose_process(pid: int) -> dict:
    """Explain whether a process can be attached: code signature, hardened runtime, get-task-allow, SIP."""
    return procs.diagnose(pid)


@mcp.tool()
def attach(pid: int | None = None, name: str | None = None, backend: str = "auto") -> dict:
    """Attach to a process by pid, or by name/command-line substring (largest match wins). Detaches any previous
    process and clears its scans and freezes. backend: auto (Mach, falling back to the Wine agent for hardened
    CrossOver/NotProton processes), mach, or wine."""
    return _h("attach", pid=pid, name=name, backend=backend)


@mcp.tool()
def start_wine_agent(pid: int | None = None, name: str | None = None) -> dict:
    """Start msagent.exe inside a Wine game's prefix (needed for CrossOver/NotProton games: their wine binary is
    hardened, so macOS blocks direct access). Give the game's macOS pid or a name like 're3.exe'. Then attach."""
    if pid is None:
        if not name:
            raise RuntimeError("give the game's pid or name")
        pid = procs.find_process(name, uid=os.getuid())["pid"]
    return wine.start_agent(pid)


@mcp.tool()
def stop_wine_agent() -> dict:
    """Stop the Wine agent (it also exits when its Wine prefix shuts down)."""
    return {"stopped": wine.stop_agent()}


@mcp.tool()
def detach() -> dict:
    """Detach from the current process (stops its freezes)."""
    return _h("detach")


@mcp.tool()
def pause_process() -> dict:
    """Suspend the game (stops values changing while you look)."""
    return _h("pause")


@mcp.tool()
def resume_process() -> dict:
    """Resume a suspended game."""
    return _h("resume")


@mcp.tool()
def list_modules(filter: str = "", refresh: bool = False) -> list[dict]:
    """Loaded images: Windows PE modules inside Wine (exe/dll, pe32/pe64) and native Mach-O images."""
    return _h("modules", filter=filter or None, refresh=refresh)


@mcp.tool()
def memory_regions(writable_only: bool = False, limit: int = 200) -> dict:
    """The process's VM regions with protections and mapped files."""
    return _h("regions", writable_only=writable_only, limit=limit)


# -- scanning ----------------------------------------------------------------------

@mcp.tool()
def scan_first(value_type: str, value: Value | None = None, compare: str = "eq", value2: Value | None = None,
               endian: str = "little", tolerance: float | None = None, alignment: int | None = None,
               module: str | None = None, start: str | None = None, end: str | None = None,
               include_readonly: bool = False, ignore_case: bool = False) -> dict:
    """Start a new scan.

    value_type: int8/uint8/int16/uint16/int32/uint32/int64/uint64/float/double, string (UTF-8), string16 (UTF-16),
      bytes (hex pattern with ?? wildcards).
    compare: eq, ne, gt, lt, ge, le, between (needs value2), or unknown (snapshot for unknown-initial-value scans).
    tolerance: for float/double eq (default 0.1% of the value). alignment defaults to min(size, 4).
    module/start/end limit the scan to a module image or an address range."""
    return _h("scan_first", type=value_type, compare=compare, value=value, value2=value2, endian=endian,
              tolerance=tolerance, alignment=alignment, writable_only=not include_readonly, start=start, end=end,
              module=module, ignore_case=ignore_case)


@mcp.tool()
def scan_next(compare: str, value: Value | None = None, value2: Value | None = None,
              tolerance: float | None = None) -> dict:
    """Narrow the current results. compare: eq/ne/gt/lt/ge/le/between (with value), or relative to the previous scan:
    changed, unchanged, increased, decreased, increased_by/decreased_by (with value)."""
    return _h("scan_next", compare=compare, value=value, value2=value2, tolerance=tolerance)


@mcp.tool()
def scan_results(offset: int = 0, limit: int = 50) -> dict:
    """Current results with live values, previous values, and Module+offset when the address is static."""
    return _h("scan_results", offset=offset, limit=limit)


@mcp.tool()
def scan_undo() -> dict:
    """Go back to the results before the last scan_next."""
    return _h("scan_undo")


@mcp.tool()
def scan_reset() -> dict:
    """Discard the current scan."""
    return _h("scan_reset")


# -- reading & writing ------------------------------------------------------------

@mcp.tool()
def read_memory(address: str, value_type: str = "int32", count: int = 1, endian: str = "little",
                pointer_size: int | None = None) -> dict:
    """Read at an address expression. For value_type=bytes, count is the length and you get a hex dump;
    for strings, count is the max byte length."""
    return _h("read", address=address, type=value_type, count=count, endian=endian, pointer_size=pointer_size)


@mcp.tool()
def write_memory(address: str, value_type: str, value: Value, endian: str = "little",
                 pointer_size: int | None = None) -> dict:
    """Write one value at an address expression (read-only pages are made writable copy-on-write)."""
    return _h("write", address=address, type=value_type, value=value, endian=endian, pointer_size=pointer_size)


@mcp.tool()
def write_scan_results(value: Value, limit: int = 20) -> dict:
    """Write a value to every current scan result (refuses if there are more than `limit`). Handy for telling
    which of a few candidates is the real one."""
    return _h("write_results", value=value, limit=limit)


@mcp.tool()
def resolve_address(address: str, pointer_size: int | None = None) -> dict:
    """Evaluate an address expression (pointer chains, Module+offset, aob(...)) to an absolute address."""
    return _h("resolve", address=address, pointer_size=pointer_size)


@mcp.tool()
def aob_scan(pattern: str, module: str | None = None, limit: int = 50, executable_only: bool = False) -> dict:
    """Search all readable memory (or one module) for a byte pattern like '48 8B 05 ?? ?? ?? ??'."""
    return _h("aob_scan", pattern=pattern, module=module, limit=limit, executable_only=executable_only)


# -- pointers ------------------------------------------------------------------------

@mcp.tool()
def pointer_scan(address: str, max_depth: int = 4, max_offset: int = 4096, pointer_size: int | None = None,
                 modules: list[str] | None = None, max_results: int = 200) -> dict:
    """Find pointer chains from static module memory to an address. pointer_size defaults to 4 for 32-bit
    (pe32) games and 8 otherwise. modules limits which images count as static bases (default: all PE modules)."""
    return _h("pointer_scan", address=address, max_depth=max_depth, max_offset=max_offset,
              pointer_size=pointer_size, modules=modules, max_results=max_results)


@mcp.tool()
def pointer_filter(address: str, pointer_size: int | None = None) -> dict:
    """Keep only chains from the last pointer_scan that still resolve to `address` (use after restarting the game
    and finding the value again)."""
    return _h("pointer_filter", address=address, pointer_size=pointer_size)


@mcp.tool()
def pointer_results(offset: int = 0, limit: int = 50) -> dict:
    """List chains from the last pointer scan/filter."""
    return _h("pointer_results", offset=offset, limit=limit)


# -- freezing ----------------------------------------------------------------------

@mcp.tool()
def freeze(address: str, value_type: str, value: Value, label: str = "", endian: str = "little",
           pointer_size: int | None = None) -> dict:
    """Keep writing a value every 50 ms. Pointer-chain addresses are re-resolved each time. Freezes keep running in
    the helper even after this conversation ends, until unfreeze/detach or the helper stops."""
    return _h("freeze", address=address, type=value_type, value=value, label=label, endian=endian,
              pointer_size=pointer_size)


@mcp.tool()
def unfreeze(id: str = "all") -> dict:
    """Stop one freeze by id, or all."""
    return _h("unfreeze", id=id)


@mcp.tool()
def list_frozen() -> list[dict]:
    """Active freezes with write/error counts."""
    return _h("frozen")


# -- cheat tables ------------------------------------------------------------------

@mcp.tool()
def cheat_save(table: str, name: str, address: str, value_type: str, value: Value, freeze: bool = True,
               endian: str = "little", notes: str = "", game: str | None = None, process: str | None = None,
               pointer_size: int | None = None) -> dict:
    """Save (or replace) a named cheat in a table file tables/<table>.json. Prefer a pointer chain or aob()
    expression over a raw heap address so it works after a restart. process is the substring used to auto-attach
    (e.g. the Windows exe name)."""
    cheat = {"name": name, "address": address, "type": value_type, "value": value, "freeze": freeze}
    if endian != "little":
        cheat["endian"] = endian
    if notes:
        cheat["notes"] = notes
    path, t = tables.upsert(table, cheat, game=game, process=process, pointer_size=pointer_size)
    return {"saved": str(path), "cheats": [c["name"] for c in t["cheats"]]}


@mcp.tool()
def cheat_list(table: str | None = None) -> Union[dict, list[dict]]:
    """List all tables, or show one table's contents."""
    return tables.load(table) if table else tables.list_tables()


@mcp.tool()
def cheat_remove(table: str, name: str) -> dict:
    """Delete a cheat from a table."""
    return {"removed": tables.remove(table, name)}


@mcp.tool()
def cheat_apply(table: str, names: list[str] | None = None) -> dict:
    """Apply a table's cheats (all, or the given names): writes one-shot values and starts freezes.
    Attaches to the table's process first if nothing is attached."""
    t = tables.load(table)
    cheats = [c for c in t.get("cheats", []) if not names or c.get("name") in names]
    if not cheats:
        raise RuntimeError(f"no matching cheats in table {table!r}")
    attached = _h("ping").get("attached")
    if not attached:
        if not t.get("process"):
            raise RuntimeError("not attached and the table has no 'process' to match; attach first")
        attached = _h("attach", name=t["process"])
    return {"process": attached, "results": _h("apply_cheats", cheats=cheats, pointer_size=t.get("pointer_size"))}


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()

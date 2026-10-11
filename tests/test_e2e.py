"""End to end: a real helper process and the real MCP server over stdio.

Without root the helper can only attach to itself, which is enough to exercise
the whole path: MCP tool -> client -> socket -> helper -> Mach APIs.
"""

import asyncio
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

import pytest

from memslicer.client import HelperClient, HelperError


@pytest.fixture
def helper():
    # AF_UNIX paths are limited to 104 bytes on macOS, so pytest's tmp_path is too long.
    tmpdir = tempfile.TemporaryDirectory(prefix="ms", dir="/tmp")
    sock = Path(tmpdir.name) / "h.sock"
    proc = subprocess.Popen([sys.executable, "-m", "memslicer.helper", "--socket", str(sock)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    for _ in range(100):
        if sock.exists():
            break
        time.sleep(0.05)
    else:
        proc.kill()
        pytest.fail("helper did not start: " + proc.stderr.read())
    yield proc, sock
    proc.terminate()
    proc.wait(5)
    assert not sock.exists(), "helper should remove its socket on exit"
    tmpdir.cleanup()


def test_helper_protocol(helper):
    proc, sock = helper
    c = HelperClient(sock)
    assert c.call("ping")["attached"] is None
    assert oct(sock.stat().st_mode & 0o777) == "0o600"

    with pytest.raises(HelperError, match="only attaches to processes of uid"):
        c.call("attach", pid=1)  # launchd, owned by root

    info = c.call("attach", pid=proc.pid)
    assert info["pid"] == proc.pid and info["modules"] > 0

    token = "memslicer-" + uuid.uuid4().hex
    res = c.call("scan_first", type="string", value=token)
    assert res["results"] >= 1
    first = c.call("scan_results", limit=1)["results"][0]
    assert first["previous"] == token  # value at scan time; the live bytes may already be reused

    # The token lives in request buffers the helper reuses, so only the immediate read-back is stable.
    new = "MEMSLICER-" + token[10:]
    assert c.call("write", address=first["address"], type="string", value=new)["written"] == new

    dump = c.call("read", address="$exe", type="bytes", count=16)["hexdump"]
    assert "CF FA ED FE" in dump  # Mach-O magic at the main executable's base
    hits = c.call("aob_scan", pattern="CF FA ED FE ?? ?? ?? 01", limit=500)
    assert c.call("resolve", address="$exe")["address"] in [m["address"] for m in hits["matches"]]
    c.call("detach")


def _run_mcp(sock, calls):
    """Call MCP tools on a fresh stdio server; returns parsed results."""
    env = {**os.environ, "MEMSLICER_SOCKET": str(sock)}
    cmd = [sys.executable, "-m", "memslicer.server"]

    def parse(r):
        assert not getattr(r, "is_error", getattr(r, "isError", False)), r.content[0].text
        return json.loads(r.content[0].text)

    async def go():
        out = {}
        try:
            from mcp import Client
            from mcp.client.stdio import StdioServerParameters
            async with Client(StdioServerParameters(command=cmd[0], args=cmd[1:], env=env)) as client:
                out["tools"] = [t.name for t in (await client.list_tools()).tools]
                for name, args in calls:
                    out[name] = parse(await client.call_tool(name, args))
        except ImportError:  # mcp 1.x
            from mcp import ClientSession, StdioServerParameters
            from mcp.client.stdio import stdio_client
            async with stdio_client(StdioServerParameters(command=cmd[0], args=cmd[1:], env=env)) as (r, w):
                async with ClientSession(r, w) as s:
                    await s.initialize()
                    out["tools"] = [t.name for t in (await s.list_tools()).tools]
                    for name, args in calls:
                        out[name] = parse(await s.call_tool(name, args))
        return out

    return asyncio.run(go())


def test_mcp_server_over_stdio(helper):
    proc, sock = helper
    token = "mcp-" + uuid.uuid4().hex
    out = _run_mcp(sock, [
        ("status", {}),
        ("attach", {"pid": proc.pid}),
        ("scan_first", {"value_type": "string", "value": token}),
        ("scan_results", {"limit": 1}),
        ("list_modules", {"filter": "python"}),
    ])
    assert {"scan_first", "scan_next", "pointer_scan", "freeze", "cheat_save"} <= set(out["tools"])
    assert out["status"]["running"] is True
    assert out["attach"]["pid"] == proc.pid
    assert out["scan_first"]["results"] >= 1
    assert out["scan_results"]["results"][0]["previous"] == token  # live value may already be reused memory

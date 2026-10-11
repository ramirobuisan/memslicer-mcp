"""Wine backend: reach a game's memory through msagent.exe running in the same Wine prefix.

CrossOver/NotProton sign their wine loader with the hardened runtime, so macOS
refuses task_for_pid() on Wine processes even for root while SIP is on. Inside
Wine, though, ReadProcessMemory/WriteProcessMemory are served by wineserver,
which already holds each Wine process's task port. msagent.exe exposes those
calls on 127.0.0.1 (token-authenticated), and WineTask presents them with the
same interface as mach.Task so the whole engine works unchanged.
"""

from __future__ import annotations

import ctypes
import json
import os
import secrets
import socket
import struct
import subprocess
import threading
import time
from dataclasses import replace
from pathlib import Path

import numpy as np

from .mach import MIN_PAGE, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE, MachError, Region, Task

CMD_HELLO, CMD_LIST, CMD_OPEN, CMD_REGIONS, CMD_READ, CMD_READ_ROBUST, CMD_WRITE, CMD_MODULES, \
    CMD_SUSPEND, CMD_RESUME, CMD_QUERY, CMD_QUIT = range(1, 13)
ERROR_PARTIAL_COPY = 299
DEFAULT_PORT = 47811
AGENT_EXE = Path(__file__).resolve().parents[2] / "wine-agent" / "msagent.exe"
# Variables Wine sets for one specific process; a new process must not inherit them.
_PER_PROCESS_ENV = ("WINESERVERSOCKET", "WINELOADERNOEXEC", "WINEPRELOADRESERVE", "WINEPRELOADERAPPNAME")

MEM_MAPPED = 0x40000


class AgentError(MachError):
    def __init__(self, call: str, status: int):
        self.kr = status
        OSError.__init__(self, f"{call} failed in Wine (error {status})")


def _prot(protect: int) -> int:
    if protect & 0x100 or protect & 0x01:  # PAGE_GUARD / PAGE_NOACCESS
        return 0
    p = protect & 0xFF
    return {0x02: VM_PROT_READ, 0x04: VM_PROT_READ | VM_PROT_WRITE, 0x08: VM_PROT_READ | VM_PROT_WRITE,
            0x10: VM_PROT_EXECUTE, 0x20: VM_PROT_READ | VM_PROT_EXECUTE,
            0x40: VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE,
            0x80: VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE}.get(p, 0)


# -- agent connection ----------------------------------------------------------

def state_path(home: str | Path | None = None) -> Path:
    return Path(home or Path.home()) / ".memslicer" / "agent.json"


class AgentConn:
    def __init__(self, port: int, token: str, timeout: float | None = None):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=timeout or 5)
        self.sock.settimeout(None)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.lock = threading.Lock()
        status, _ = self.call(CMD_HELLO, token.encode())
        if status:
            raise PermissionError("msagent rejected the token (restart it with `memslicer wine-agent`)")

    @classmethod
    def from_state(cls, home: str | Path | None = None) -> "AgentConn":
        p = state_path(home)
        if not p.exists():
            raise ConnectionError("the Wine agent is not running; start it with `memslicer wine-agent <game>` "
                                  "(or the start_wine_agent tool)")
        st = json.loads(p.read_text())
        try:
            return cls(int(st["port"]), st["token"])
        except OSError as e:
            raise ConnectionError(f"cannot reach the Wine agent on port {st['port']} ({e}); "
                                  "it probably exited with the game. Start it again.") from None

    def _recv(self, n: int) -> bytes:
        buf = bytearray(n)
        view = memoryview(buf)
        got = 0
        while got < n:
            r = self.sock.recv_into(view[got:], n - got)
            if not r:
                raise ConnectionError("Wine agent closed the connection")
            got += r
        return bytes(buf)

    def call(self, cmd: int, payload: bytes = b"") -> tuple[int, bytes]:
        with self.lock:
            self.sock.sendall(struct.pack("<II", cmd, len(payload)) + payload)
            status, n = struct.unpack("<II", self._recv(8))
            return status, self._recv(n) if n else b""

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def processes(self) -> list[dict]:
        _, data = self.call(CMD_LIST)
        out, off = [], 0
        while off < len(data):
            pid, ppid, n = struct.unpack_from("<IIH", data, off)
            off += 10
            out.append({"pid": pid, "ppid": ppid, "name": data[off:off + n].decode(errors="replace")})
            off += n
        return out


# -- task --------------------------------------------------------------------------

class WineTask(Task):
    """mach.Task look-alike backed by msagent.exe."""

    def __init__(self, conn: AgentConn, win_pid: int, mac_pid: int):
        super().__init__(port=0, pid=mac_pid, owned=False)
        self.conn = conn
        self.win_pid = win_pid
        status, data = conn.call(CMD_OPEN, struct.pack("<I", win_pid))
        if status:
            raise AgentError(f"OpenProcess({win_pid})", status)
        self.wow64 = bool(struct.unpack("<I", data)[0])

    def close(self) -> None:
        while self._suspended:
            self.resume()
        self.conn.close()

    def regions(self):
        status, data = self.conn.call(CMD_REGIONS)
        if status:
            raise AgentError("VirtualQueryEx", status)
        for off in range(0, len(data), 24):
            base, size, protect, mtype = struct.unpack_from("<QQII", data, off)
            prot = _prot(protect)
            # share_mode 4 (SM_SHARED) for file/section mappings, 2 (SM_PRIVATE) otherwise.
            yield Region(base, base + size, prot, prot, 0, 4 if mtype == MEM_MAPPED else 2, mtype == MEM_MAPPED,
                         False, 0)

    def region_at(self, addr: int) -> Region | None:
        status, data = self.conn.call(CMD_QUERY, struct.pack("<Q", addr))
        if status:
            return None
        base, size, state, protect, mtype = struct.unpack("<QQIII", data)
        prot = _prot(protect) if state == 0x1000 else 0
        return Region(base, base + size, prot, prot, 0, 2, False, False, 0)

    def read_into(self, addr: int, buf: np.ndarray) -> None:
        status, data = self.conn.call(CMD_READ, struct.pack("<QI", addr, buf.nbytes))
        if status:
            raise AgentError(f"ReadProcessMemory(0x{addr:x}, {buf.nbytes})", status)
        buf[:] = np.frombuffer(data, dtype=np.uint8)

    def read_robust(self, addr: int, size: int) -> tuple[np.ndarray, np.ndarray | None]:
        status, data = self.conn.call(CMD_READ_ROBUST, struct.pack("<QI", addr, size))
        if status not in (0, ERROR_PARTIAL_COPY):
            raise AgentError(f"ReadProcessMemory(0x{addr:x}, {size})", status)
        buf = np.frombuffer(data[:size], dtype=np.uint8).copy()
        if status == 0:
            return buf, None
        return buf, np.frombuffer(data[size:], dtype=np.uint8).astype(bool)

    def write(self, addr: int, data: bytes) -> None:
        status, _ = self.conn.call(CMD_WRITE, struct.pack("<Q", addr) + bytes(data))
        if status:
            raise AgentError(f"WriteProcessMemory(0x{addr:x})", status)

    def suspend(self) -> None:
        status, _ = self.conn.call(CMD_SUSPEND)
        if status:
            raise AgentError("NtSuspendProcess", status)
        self._suspended += 1

    def resume(self) -> None:
        if not self._suspended:
            return
        status, _ = self.conn.call(CMD_RESUME)
        self._suspended -= 1
        if status:
            raise AgentError("NtResumeProcess", status)

    def list_modules(self):
        from .modules import Module, _parse_pe
        status, data = self.conn.call(CMD_MODULES)
        if status:
            raise AgentError("EnumProcessModulesEx", status)
        mods, off = [], 0
        while off < len(data):
            base, size, n = struct.unpack_from("<QIH", data, off)
            off += 14
            name = data[off:off + n].decode(errors="replace")
            off += n
            m, = struct.unpack_from("<H", data, off)
            off += 2
            path = data[off:off + m].decode(errors="replace")
            off += m
            try:
                parsed = _parse_pe(self, base, self.read(base, 0x400))
            except MachError:
                parsed = None
            if parsed:
                mods.append(replace(parsed, name=name, path=path, size=size or parsed.size))
            else:
                mods.append(Module(name, path, base, size, "pe64", "?", name.lower().endswith(".exe")))
        return sorted(mods, key=lambda m: (not m.is_exe, m.base))


def windows_pid_for(conn: AgentConn, mac_pid: int, exe_hint: str | None = None) -> int:
    """Map a macOS Wine process to its Windows pid via the exe name in its command line."""
    from .procs import list_processes
    if not exe_hint:
        row = next((r for r in list_processes() if r["pid"] == mac_pid), None)
        exe_hint = row.get("windows_exe") if row else None
    if not exe_hint:
        raise LookupError(f"pid {mac_pid} doesn't look like a Wine process (no .exe in its command line)")
    matches = [p for p in conn.processes() if p["name"].lower() == exe_hint.lower()]
    if not matches:
        raise LookupError(f"{exe_hint} is not running in the agent's Wine prefix (wrong prefix or game exited)")
    return matches[-1]["pid"]


def attach(mac_pid: int, home: str | Path | None = None) -> WineTask:
    conn = AgentConn.from_state(home)
    try:
        return WineTask(conn, windows_pid_for(conn, mac_pid), mac_pid)
    except Exception:
        conn.close()
        raise


# -- launching the agent ------------------------------------------------------------

def process_env(pid: int) -> tuple[list[str], dict[str, str]]:
    """argv and environment of one of our own processes (sysctl KERN_PROCARGS2)."""
    libc = ctypes.CDLL(None, use_errno=True)
    mib = (ctypes.c_int * 3)(1, 49, pid)
    size = ctypes.c_size_t(0)
    if libc.sysctl(mib, 3, None, ctypes.byref(size), None, 0) != 0:
        raise OSError(ctypes.get_errno(), f"cannot read the environment of pid {pid}")
    buf = ctypes.create_string_buffer(size.value)
    if libc.sysctl(mib, 3, buf, ctypes.byref(size), None, 0) != 0:
        raise OSError(ctypes.get_errno(), f"cannot read the environment of pid {pid}")
    raw = buf.raw[:size.value]
    argc, = struct.unpack_from("<i", raw)
    parts = [p.decode(errors="replace") for p in raw[4:].split(b"\0") if p]
    argv, envp = parts[1:1 + argc], parts[1 + argc:]
    env = {}
    for e in envp:
        k, sep, v = e.partition("=")
        if sep:
            env[k] = v
    return argv, env


def _ping(port: int, token: str) -> bool:
    try:
        AgentConn(port, token, timeout=1).close()
        return True
    except (OSError, PermissionError):
        return False


def start_agent(game_pid: int, port: int = DEFAULT_PORT, timeout: float = 60.0) -> dict:
    """Start msagent.exe in the same Wine prefix (and wineserver) as `game_pid`."""
    if not AGENT_EXE.exists():
        raise FileNotFoundError(f"{AGENT_EXE} is missing; build it with `make -C wine-agent` (needs mingw-w64)")
    stop_agent()
    _, genv = process_env(game_pid)
    if "WINEPREFIX" not in genv:
        raise LookupError(f"pid {game_pid} has no WINEPREFIX; is it a Wine process?")
    from .mach import pid_path
    loader = genv.get("WINELOADER") or pid_path(game_pid)
    env = {k: v for k, v in genv.items() if k not in _PER_PROCESS_ENV}
    token = secrets.token_hex(24)
    env["MEMSLICER_AGENT_TOKEN"] = token
    env["WINEDEBUG"] = "-all"
    log = state_path().parent / "agent.log"
    log.parent.mkdir(mode=0o700, exist_ok=True)
    with open(log, "wb") as fh:
        proc = subprocess.Popen([loader, str(AGENT_EXE), str(port)], env=env, stdin=subprocess.DEVNULL,
                                stdout=fh, stderr=subprocess.STDOUT, start_new_session=True)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _ping(port, token):
            break
        if proc.poll() is not None:
            raise RuntimeError(f"msagent exited with code {proc.returncode}; see {log}:\n"
                               + log.read_text(errors="replace")[-2000:])
        time.sleep(0.5)
    else:
        proc.kill()
        raise TimeoutError(f"msagent did not start listening within {timeout:.0f}s; see {log}")
    state = {"port": port, "token": token, "loader_pid": proc.pid, "game_pid": game_pid,
             "prefix": genv["WINEPREFIX"]}
    p = state_path()
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(state, fh)
    return {k: v for k, v in state.items() if k != "token"}


def stop_agent() -> bool:
    p = state_path()
    if not p.exists():
        return False
    try:
        st = json.loads(p.read_text())
        conn = AgentConn(int(st["port"]), st["token"], timeout=1)
        try:
            conn.call(CMD_QUIT)
        except (OSError, ConnectionError):
            pass
        conn.close()
        stopped = True
    except (OSError, ValueError, KeyError, PermissionError):
        stopped = False
    p.unlink(missing_ok=True)
    return stopped

"""Privileged helper: owns task ports and serves the MCP server / CLI.

Run it with sudo. task_for_pid() on another process needs root, but the MCP
server is launched by Claude Code as your user, so the two talk over a Unix
socket that only your uid may use. Hardening:

* the socket lives in /var/run (root-owned, so your user can't swap it for a
  symlink), mode 0600, chowned to you, and every connection's peer uid is
  checked with getpeereid();
* the helper only attaches to processes owned by that same uid, so it can't
  be used as a stepping stone into root processes.
"""

from __future__ import annotations

import argparse
import json
import os
import pwd
import signal
import socket
import socketserver
import stat
import sys
import threading
from pathlib import Path

import numpy as np

from . import __version__, mach, procs
from .engine import Freezer, ScanError, Session
from .mach import MachError, Task
from .values import parse_op, parse_type

PROTOCOL = 1


def socket_path_for(uid: int, home: str) -> Path:
    if os.geteuid() == 0:
        return Path(f"/var/run/memslicer-{uid}.sock")
    return Path(home) / ".memslicer" / "helper.sock"


def _json_default(o):
    if isinstance(o, np.integer):
        return int(o)
    if isinstance(o, np.floating):
        return float(o)
    if isinstance(o, (bytes, bytearray)):
        return o.hex(" ").upper()
    if isinstance(o, Path):
        return str(o)
    raise TypeError(f"not JSON serializable: {type(o).__name__}")


def _attach_hint(pid: int, err: MachError) -> str:
    diag = procs.diagnose(pid)
    hint = diag["verdict"]
    if os.geteuid() != 0:
        hint = "The helper is not running as root; start it with sudo. " + hint
    return f"{err}. {hint}"


class Api:
    """Every public method is callable over the socket."""

    def __init__(self, allowed_uid: int):
        self.allowed_uid = allowed_uid
        self.session: Session | None = None
        self.freezer = Freezer()
        self.lock = threading.RLock()
        self.server: socketserver.BaseServer | None = None

    # -- helpers -----------------------------------------------------------

    def _s(self) -> Session:
        if self.session is None:
            raise ScanError("not attached to a process; call attach first")
        return self.session

    def _attached(self) -> dict | None:
        if self.session is None:
            return None
        s = self.session
        exe = s.module("$exe")
        return {"pid": s.pid, "name": mach.pid_name(s.pid), "paused": s.task.suspended,
                "exe": exe.name if exe else None, "pointer_size": s.default_pointer_size(),
                "scan_results": s.scan.count if s.scan else None, "frozen": len(self.freezer.entries)}

    def cleanup(self) -> None:
        self.freezer.stop()
        if self.session:
            self.session.close()
            self.session = None

    # -- status & processes -------------------------------------------------

    def ping(self) -> dict:
        return {"version": __version__, "protocol": PROTOCOL, "helper_pid": os.getpid(),
                "root": os.geteuid() == 0, "allowed_uid": self.allowed_uid, "attached": self._attached()}

    def processes(self, filter: str | None = None) -> list[dict]:
        return procs.list_processes(filter, uid=self.allowed_uid)

    def diagnose(self, pid: int) -> dict:
        return procs.diagnose(int(pid))

    def attach(self, pid: int | None = None, name: str | None = None) -> dict:
        if pid is None:
            if not name:
                raise ValueError("give a pid or a name to match")
            pid = procs.find_process(name, uid=self.allowed_uid)["pid"]
        pid = int(pid)
        uid = mach.pid_uid(pid)
        if uid is None:
            raise ProcessLookupError(f"no process with pid {pid}")
        if uid != self.allowed_uid and pid != os.getpid():
            raise PermissionError(f"pid {pid} belongs to uid {uid}; this helper only attaches to "
                                  f"processes of uid {self.allowed_uid}")
        self.detach()
        try:
            task = Task.for_pid(pid)
        except MachError as e:
            raise PermissionError(_attach_hint(pid, e)) from None
        self.session = Session(task)
        mods = self.session.modules()
        out = self._attached()
        out["modules"] = len(mods)
        out["main_modules"] = [m.to_dict() for m in mods if m.is_exe][:5]
        return out

    def detach(self) -> dict:
        if self.session:
            self.freezer.clear_session(self.session)
            self.session.close()
            self.session = None
        return {"detached": True}

    def pause(self) -> dict:
        self._s().task.suspend()
        return {"paused": True}

    def resume(self) -> dict:
        self._s().task.resume()
        return {"paused": self._s().task.suspended}

    # -- memory layout --------------------------------------------------------

    def regions(self, writable_only: bool = False, limit: int = 300) -> dict:
        s = self._s()
        rows, total = [], 0
        for r in s.task.regions():
            if r.is_submap or (writable_only and not r.writable):
                continue
            total += 1
            if len(rows) < limit:
                row = {"start": hex(r.start), "end": hex(r.end), "size_kb": r.size // 1024, "prot": r.prot_str,
                       "tag": r.user_tag}
                fname = mach.region_filename(s.pid, r.start)
                if fname:
                    row["file"] = fname
                rows.append(row)
        return {"total": total, "regions": rows}

    def modules(self, filter: str | None = None, refresh: bool = False) -> list[dict]:
        mods = self._s().modules(refresh=refresh)
        f = (filter or "").lower()
        return [m.to_dict() for m in mods if f in m.name.lower() or f in m.path.lower()]

    # -- scanning -----------------------------------------------------------

    def scan_first(self, type: str, compare: str = "eq", value=None, value2=None, endian: str = "little",
                   tolerance: float | None = None, alignment: int | None = None, writable_only: bool = True,
                   start=None, end=None, module: str | None = None, ignore_case: bool = False) -> dict:
        s = self._s()
        return s.first_scan(parse_type(type, endian), parse_op(compare), value, value2, tolerance, alignment,
                            writable_only, s.eval_address(start) if start else None,
                            s.eval_address(end) if end else None, module, ignore_case)

    def scan_next(self, compare: str, value=None, value2=None, tolerance: float | None = None) -> dict:
        return self._s().next_scan(parse_op(compare), value, value2, tolerance)

    def scan_results(self, offset: int = 0, limit: int = 50) -> dict:
        return self._s().results(int(offset), min(int(limit), 1000))

    def scan_undo(self) -> dict:
        return self._s().undo()

    def scan_reset(self) -> dict:
        self._s().reset()
        return {"reset": True}

    # -- reading & writing --------------------------------------------------

    def read(self, address, type: str = "int32", endian: str = "little", count: int = 1,
             pointer_size: int | None = None) -> dict:
        return self._s().read_value(address, parse_type(type, endian), int(count), pointer_size)

    def write(self, address, type: str, value, endian: str = "little", pointer_size: int | None = None) -> dict:
        return self._s().write_value(address, parse_type(type, endian), value, pointer_size)

    def write_results(self, value, limit: int = 20) -> dict:
        s = self._s()
        st = s._require_scan()
        addrs = s.result_addresses(int(limit) + 1)
        if len(addrs) > int(limit):
            raise ScanError(f"{st.count} results; narrow to at most {limit} before writing to all of them")
        return {"written": [s.write_value(a, st.vt, value) for a in addrs]}

    def resolve(self, address, pointer_size: int | None = None) -> dict:
        s = self._s()
        addr = s.eval_address(address, pointer_size)
        return {"expression": str(address), "address": hex(addr), "static": s.where(addr)}

    def aob_scan(self, pattern: str, module: str | None = None, limit: int = 50, writable_only: bool = False,
                 executable_only: bool = False) -> dict:
        s = self._s()
        hits = s.aob_scan(pattern, module, int(limit), writable_only, executable_only)
        return {"count": len(hits), "matches": [{"address": hex(a), "static": s.where(a)} for a in hits]}

    # -- pointers -----------------------------------------------------------

    def pointer_scan(self, address, max_depth: int = 4, max_offset: int = 0x1000, pointer_size: int | None = None,
                     modules: list[str] | None = None, max_results: int = 200) -> dict:
        return self._s().pointer_scan(address, int(max_depth), int(max_offset), pointer_size, modules,
                                      int(max_results))

    def pointer_filter(self, address, pointer_size: int | None = None) -> dict:
        return self._s().pointer_filter(address, pointer_size)

    def pointer_results(self, offset: int = 0, limit: int = 50) -> dict:
        chains = self._s().chains
        return {"total": len(chains), "chains": [c.expr() for c in chains[int(offset):int(offset) + int(limit)]]}

    # -- freezing & cheats --------------------------------------------------

    def freeze(self, address, type: str, value, endian: str = "little", label: str = "",
               pointer_size: int | None = None) -> dict:
        return self.freezer.add(self._s(), address, parse_type(type, endian), value, label, pointer_size).to_dict()

    def unfreeze(self, id="all") -> dict:
        return {"removed": self.freezer.remove(id)}

    def frozen(self) -> list[dict]:
        return self.freezer.list()

    def apply_cheats(self, cheats: list[dict], pointer_size: int | None = None) -> list[dict]:
        out = []
        for c in cheats:
            name = c.get("name", c.get("address"))
            try:
                vtype, endian = c.get("type", "int32"), c.get("endian", "little")
                ps = c.get("pointer_size") or pointer_size
                if c.get("freeze"):
                    r = self.freeze(c["address"], vtype, c["value"], endian=endian, label=name, pointer_size=ps)
                    out.append({"name": name, "frozen": True, "address": r["resolved"]})
                else:
                    r = self.write(c["address"], vtype, c["value"], endian=endian, pointer_size=ps)
                    out.append({"name": name, "written": r["written"], "address": r["address"]})
            except Exception as e:
                out.append({"name": name, "error": f"{type(e).__name__}: {e}"})
        return out

    def shutdown(self) -> dict:
        if self.server:
            threading.Thread(target=self.server.shutdown, daemon=True).start()
        return {"stopping": True}


PUBLIC = {n for n in dir(Api) if not n.startswith("_") and n != "cleanup" and callable(getattr(Api, n))}


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        api: Api = self.server.api
        try:
            peer = mach.peer_uid(self.request.fileno())
        except OSError:
            return
        if peer not in (api.allowed_uid, 0):
            self._send({"id": None, "error": f"PermissionError: uid {peer} may not use this helper"})
            return
        for line in self.rfile:
            req_id = None
            try:
                req = json.loads(line)
                req_id = req.get("id")
                method = req.get("method", "")
                if method not in PUBLIC:
                    raise AttributeError(f"unknown method {method!r}")
                with api.lock:
                    result = getattr(api, method)(**(req.get("params") or {}))
                resp = {"id": req_id, "result": result}
            except Exception as e:
                resp = {"id": req_id, "error": f"{type(e).__name__}: {e}"}
            if not self._send(resp):
                return

    def _send(self, obj) -> bool:
        try:
            self.wfile.write((json.dumps(obj, default=_json_default) + "\n").encode())
            self.wfile.flush()
            return True
        except (BrokenPipeError, ConnectionResetError):
            return False


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def _prepare_socket(path: Path, uid: int, gid: int) -> None:
    parent = path.parent
    if os.geteuid() != 0:
        parent.mkdir(mode=0o700, exist_ok=True)
    st = os.lstat(parent)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid not in (0, uid):
        raise SystemExit(f"refusing to use {parent}: not a directory owned by root or uid {uid}")
    if os.path.lexists(path):
        if not stat.S_ISSOCK(os.lstat(path).st_mode):
            raise SystemExit(f"{path} exists and is not a socket; remove it first")
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            probe.connect(str(path))
            raise SystemExit(f"a helper is already running on {path}")
        except (ConnectionRefusedError, FileNotFoundError):
            os.unlink(path)
        finally:
            probe.close()


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="memslicer helper", description="Privileged memory-access helper (run with sudo)")
    ap.add_argument("--user", default=os.environ.get("SUDO_USER") or pwd.getpwuid(os.getuid()).pw_name,
                    help="user allowed to connect and whose processes may be attached (default: the sudo caller)")
    ap.add_argument("--socket", help="socket path (default: /var/run/memslicer-<uid>.sock)")
    args = ap.parse_args(argv)

    pw = pwd.getpwnam(args.user)
    path = Path(args.socket) if args.socket else socket_path_for(pw.pw_uid, pw.pw_dir)
    if os.geteuid() != 0:
        print("warning: not running as root, so only this helper's own process can be attached "
              "(useful for testing). Run with sudo for real use.", file=sys.stderr)
    _prepare_socket(path, pw.pw_uid, pw.pw_gid)

    api = Api(pw.pw_uid)
    old_umask = os.umask(0o177)
    try:
        server = Server(str(path), Handler)
    finally:
        os.umask(old_umask)
    os.chmod(path, 0o600)
    if os.geteuid() == 0:
        os.chown(path, pw.pw_uid, pw.pw_gid)
    server.api = api
    api.server = server

    def _stop(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGHUP, _stop)
    print(f"memslicer helper {__version__} listening on {path} for {args.user} (Ctrl-C to stop)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        api.cleanup()
        server.server_close()
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        print("memslicer helper stopped", flush=True)


if __name__ == "__main__":
    main()

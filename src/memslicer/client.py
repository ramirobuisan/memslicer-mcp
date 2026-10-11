"""Unprivileged client for the helper's JSON-lines socket protocol."""

from __future__ import annotations

import json
import os
import select
import socket
import sys
import threading
from pathlib import Path


class HelperUnavailable(ConnectionError):
    pass


class HelperError(RuntimeError):
    pass


def socket_candidates() -> list[Path]:
    env = os.environ.get("MEMSLICER_SOCKET")
    if env:
        return [Path(env)]
    return [Path(f"/var/run/memslicer-{os.getuid()}.sock"), Path.home() / ".memslicer" / "helper.sock"]


START_HINT = ("The memslicer helper is not running. Start it in a terminal with:\n"
              "  sudo \"{exe}\" helper\n"
              "(it needs root for task_for_pid; it only serves your user and only attaches to your processes)")


def start_hint() -> str:
    return START_HINT.format(exe=Path(sys.executable).parent / "memslicer")


class HelperClient:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self._sock: socket.socket | None = None
        self._file = None
        self._id = 0
        self._lock = threading.Lock()

    def _connect(self) -> None:
        last: Exception | None = None
        for p in ([self.path] if self.path else socket_candidates()):
            if not p.exists():
                continue
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                s.connect(str(p))
            except OSError as e:
                s.close()
                last = e
                continue
            self._sock, self._file = s, s.makefile("rb")
            return
        raise HelperUnavailable(start_hint() + (f"\n(last error: {last})" if last else ""))

    def _peer_closed(self) -> bool:
        readable, _, _ = select.select([self._sock], [], [], 0)
        if not readable:
            return False
        try:
            return self._sock.recv(1, socket.MSG_PEEK) == b""
        except OSError:
            return True

    def close(self) -> None:
        if self._sock:
            self._file.close()
            self._sock.close()
        self._sock = self._file = None

    def call(self, method: str, **params):
        params = {k: v for k, v in params.items() if v is not None}
        with self._lock:
            self._id += 1
            msg = (json.dumps({"id": self._id, "method": method, "params": params}) + "\n").encode()
            if self._sock is not None and self._peer_closed():
                self.close()  # the helper restarted since our last call
            for attempt in (1, 2):
                if self._sock is None:
                    self._connect()
                try:
                    self._sock.sendall(msg)
                    break
                except OSError:
                    self.close()
                    if attempt == 2:
                        raise HelperUnavailable(start_hint())
            line = self._file.readline()
            if not line:
                self.close()
                raise HelperUnavailable("lost connection to the memslicer helper (did it stop?)\n" + start_hint())
        resp = json.loads(line)
        if "error" in resp:
            raise HelperError(resp["error"])
        return resp["result"]

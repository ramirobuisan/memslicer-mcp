"""Process listing and attachability diagnostics. Needs no privileges."""

from __future__ import annotations

import os
import plistlib
import re
import subprocess

from . import mach

P_TRANSLATED = 0x00020000
_EXE_RE = re.compile(r"([^\\/:\"]+\.exe)\b", re.IGNORECASE)


def list_processes(filter: str | None = None, uid: int | None = None) -> list[dict]:
    out = subprocess.run(["ps", "-axww", "-o", "pid=,uid=,flags=,rss=,args="],
                         capture_output=True, text=True, check=False).stdout
    needle = (filter or "").lower()
    rows = []
    for line in out.splitlines():
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        pid, puid, flags, rss = int(parts[0]), int(parts[1]), int(parts[2], 16), int(parts[3])
        args = parts[4] if len(parts) > 4 else ""
        if uid is not None and puid != uid:
            continue
        name = mach.pid_name(pid) or os.path.basename(args.split(" ", 1)[0])
        exes = _EXE_RE.findall(args)
        row = {"pid": pid, "name": name, "rss_mb": round(rss / 1024, 1),
               "translated": bool(flags & P_TRANSLATED), "args": args[:300]}
        if exes or "wine" in name.lower():
            row["wine"] = True
            if exes:
                row["windows_exe"] = exes[-1]
        if needle and needle not in name.lower() and needle not in args.lower():
            continue
        rows.append(row)
    rows.sort(key=lambda r: -r["rss_mb"])
    return rows


def find_process(match: str, uid: int | None = None) -> dict:
    """Best process whose name/args contain `match` (largest memory wins: for Wine
    games that is the game itself, not wineserver or explorer.exe)."""
    rows = list_processes(match, uid)
    if not rows:
        raise LookupError(f"no running process matches {match!r}")
    return rows[0]


def sip_status() -> str:
    out = subprocess.run(["csrutil", "status"], capture_output=True, text=True, check=False).stdout.strip()
    return out.split(":", 1)[-1].strip().rstrip(".") if out else "unknown"


def diagnose(pid: int) -> dict:
    path = mach.pid_path(pid)
    info: dict = {"pid": pid, "path": path, "uid": mach.pid_uid(pid), "sip": sip_status()}
    if not path:
        info["verdict"] = "process not found (or not visible to this user)"
        return info
    rows = [r for r in list_processes() if r["pid"] == pid]
    info["translated"] = rows[0]["translated"] if rows else None

    cs = subprocess.run(["codesign", "-dv", "--verbose=4", path], capture_output=True, text=True, check=False)
    text = cs.stderr
    m = re.search(r"flags=0x([0-9a-f]+)\(([^)]*)\)", text)
    flags = m.group(2).split(",") if m else []
    info["signature"] = "unsigned" if "not signed" in text else ("adhoc" if "adhoc" in flags else "signed")
    info["hardened_runtime"] = "runtime" in flags
    info["platform_binary"] = "Platform identifier" in text or path.startswith(("/System/", "/usr/"))
    ents = subprocess.run(["codesign", "-d", "--entitlements", "-", "--xml", path],
                          capture_output=True, check=False).stdout
    try:
        ent = plistlib.loads(ents) if ents.strip() else {}
    except Exception:
        ent = {}
    info["get_task_allow"] = bool(ent.get("com.apple.security.get-task-allow"))

    sip_on = info["sip"].startswith("enabled")
    if info["platform_binary"] and sip_on:
        verdict = "Apple platform binary: cannot be attached while SIP is enabled."
    elif info["hardened_runtime"] and not info["get_task_allow"] and sip_on:
        verdict = ("Hardened runtime without get-task-allow: task_for_pid will be refused even as root while "
                   "SIP is enabled. Options: re-sign a copy of the binary without the runtime flag "
                   "(codesign --force -s - <binary>), or relax SIP debugging restrictions from Recovery.")
    else:
        verdict = "Should be attachable by the root helper."
    info["verdict"] = verdict
    return info

"""memslicer command line: run the helper or MCP server, and use cheat tables without Claude."""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import procs, tables
from .client import HelperClient, HelperError, HelperUnavailable

USAGE = """\
memslicer helper [--user U]        run the privileged helper (use sudo)
memslicer mcp                      run the MCP server on stdio (Claude Code starts this)
memslicer status                   helper / attached process / freezes
memslicer ps [FILTER]              list your processes (Wine games show their .exe)
memslicer diagnose PID             can this process be attached?
memslicer tables                   list cheat tables
memslicer apply TABLE [-p MATCH] [--only NAME ...]
                                   attach and apply a cheat table (freezes keep running in the helper)
memslicer unfreeze [ID|all]
memslicer stop                     stop the helper
"""


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False))


def main(argv: list[str] | None = None) -> None:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "helper":
        from .helper import main as helper_main
        return helper_main(argv[1:])
    if argv and argv[0] == "mcp":
        from .server import main as server_main
        return server_main()

    ap = argparse.ArgumentParser(prog="memslicer", usage=USAGE)
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("status")
    p = sub.add_parser("ps")
    p.add_argument("filter", nargs="?")
    p = sub.add_parser("diagnose")
    p.add_argument("pid", type=int)
    sub.add_parser("tables")
    p = sub.add_parser("apply")
    p.add_argument("table")
    p.add_argument("-p", "--process", help="process name/args substring (default: the table's 'process')")
    p.add_argument("--only", nargs="+", metavar="NAME")
    p = sub.add_parser("unfreeze")
    p.add_argument("id", nargs="?", default="all")
    sub.add_parser("stop")
    args = ap.parse_args(argv)

    client = HelperClient()
    try:
        if args.cmd == "ps":
            for r in procs.list_processes(args.filter, uid=os.getuid())[:40]:
                tag = f" [{r['windows_exe']}]" if r.get("windows_exe") else (" [wine]" if r.get("wine") else "")
                rosetta = " (rosetta)" if r["translated"] else ""
                print(f"{r['pid']:>7}  {r['rss_mb']:>8.1f} MB  {r['name']}{tag}{rosetta}")
        elif args.cmd == "diagnose":
            _print(procs.diagnose(args.pid))
        elif args.cmd == "tables":
            _print(tables.list_tables())
        elif args.cmd == "status":
            _print(client.call("ping"))
            frozen = client.call("frozen")
            if frozen:
                _print(frozen)
        elif args.cmd == "apply":
            t = tables.load(args.table)
            match = args.process or t.get("process")
            cheats = [c for c in t.get("cheats", []) if not args.only or c.get("name") in args.only]
            if not cheats:
                sys.exit(f"no matching cheats in {args.table}")
            if match:
                info = client.call("attach", name=match)
            else:
                info = client.call("ping")["attached"]
                if not info:
                    sys.exit("table has no 'process'; pass -p MATCH")
            print(f"attached to {info['name']} (pid {info['pid']})")
            for r in client.call("apply_cheats", cheats=cheats, pointer_size=t.get("pointer_size")):
                state = "ERROR " + r["error"] if "error" in r else ("frozen" if r.get("frozen") else "written")
                print(f"  {r['name']}: {state}")
        elif args.cmd == "unfreeze":
            _print(client.call("unfreeze", id=args.id))
        elif args.cmd == "stop":
            _print(client.call("shutdown"))
        else:
            print(USAGE)
    except (HelperUnavailable, HelperError) as e:
        sys.exit(str(e))


if __name__ == "__main__":
    main()

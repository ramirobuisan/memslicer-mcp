"""Cheat tables: JSON files (one per game) holding named, re-applicable cheats.

{
  "game": "Some Game",
  "process": "Game.exe",          # substring used to auto-attach
  "pointer_size": 4,              # optional; default comes from the game's exe
  "cheats": [
    {"name": "Infinite HP", "address": "[[Game.exe+0x1A2B3C]+0x10]+0x48",
     "type": "int32", "value": 999, "freeze": true, "notes": "found 2026-10-11"}
  ]
}
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]


def tables_dir() -> Path:
    env = os.environ.get("MEMSLICER_TABLES")
    if env:
        d = Path(env).expanduser()
    elif (_REPO / "pyproject.toml").exists():
        d = _REPO / "tables"
    else:
        d = Path.home() / ".memslicer" / "tables"
    d.mkdir(parents=True, exist_ok=True)
    return d


def table_path(name: str) -> Path:
    stem = re.sub(r"[^A-Za-z0-9 _.\-]", "_", name.strip()).strip(" .")
    if stem.lower().endswith(".json"):
        stem = stem[:-5]
    if not stem:
        raise ValueError("empty table name")
    return tables_dir() / f"{stem}.json"


def load(name: str) -> dict:
    p = table_path(name) if not os.path.isfile(name) else Path(name)
    if not p.exists():
        return {"game": name, "process": "", "cheats": []}
    return json.loads(p.read_text())


def save(name: str, table: dict) -> Path:
    p = table_path(name) if not os.path.isfile(name) else Path(name)
    p.write_text(json.dumps(table, indent=2, ensure_ascii=False) + "\n")
    return p


def upsert(name: str, cheat: dict, game: str | None = None, process: str | None = None,
           pointer_size: int | None = None) -> tuple[Path, dict]:
    table = load(name)
    if game:
        table["game"] = game
    if process:
        table["process"] = process
    if pointer_size:
        table["pointer_size"] = pointer_size
    cheats = [c for c in table.get("cheats", []) if c.get("name") != cheat["name"]]
    cheats.append(cheat)
    table["cheats"] = cheats
    return save(name, table), table


def remove(name: str, cheat_name: str) -> bool:
    table = load(name)
    before = len(table.get("cheats", []))
    table["cheats"] = [c for c in table.get("cheats", []) if c.get("name") != cheat_name]
    save(name, table)
    return len(table["cheats"]) < before


def list_tables() -> list[dict]:
    out = []
    for p in sorted(tables_dir().glob("*.json")):
        try:
            t = json.loads(p.read_text())
        except json.JSONDecodeError:
            continue
        out.append({"table": p.stem, "game": t.get("game"), "process": t.get("process"),
                    "cheats": [c.get("name") for c in t.get("cheats", [])], "path": str(p)})
    return out

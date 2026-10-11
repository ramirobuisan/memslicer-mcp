# memslicer-mcp

A [Bit Slicer](https://github.com/zorgiepoo/bit-slicer)-style memory scanner for macOS with an **MCP server**, so
Claude can find and change values in a running game: native games, Rosetta games, and Windows games under
**Wine / CrossOver / NotProton**, plus console emulators running inside any of those.

It doesn't use any Bit Slicer code: it talks to the same Mach APIs (`task_for_pid`, `mach_vm_read/write`,
`mach_vm_region`) from Python and numpy. The GUI is replaced by tools Claude can call.

```
Claude Code ──stdio──▶ memslicer-mcp (your user) ──unix socket──▶ memslicer helper (root) ──Mach VM──▶ game
```

## What it can do

| | |
|---|---|
| Value scans | int8…uint64, float, double, UTF-8/UTF-16 strings, byte patterns with `??`; little- or big-endian |
| Narrowing | eq/ne/gt/lt/between, changed/unchanged/increased/decreased/increased_by/decreased_by, undo |
| Unknown values | snapshot scan for health bars and other values the game doesn't show as numbers |
| Edit | write once, write to all remaining results, freeze (re-written every 50 ms) |
| Wine-aware | finds Windows PE modules (exe/dll, 32/64-bit) inside the Wine process for `Game.exe+offset` addresses |
| Survives restarts | pointer scanner (`[[Game.exe+0x1A2B]+0x10]+0x48`), filtering after a restart, AOB signatures |
| Cheat tables | JSON per game in `tables/`, applied by Claude or from the terminal (`memslicer apply`) |

Speed on an M5 Max: an exact int32 scan of 2.2 GB takes about 0.2 s; a broad scan with 100M hits takes about 1.5 s.

## Install

```bash
./install.sh
```

This creates `.venv`, installs the package (editable) and builds the demo game. It needs Python 3.10+ and Xcode CLT.

## Run

**1. Start the helper** in a terminal and leave it open (it needs root for `task_for_pid`):

```bash
sudo "$PWD/.venv/bin/memslicer" helper
```

**2. Connect Claude.** Open Claude Code in this folder and approve the `memslicer` server from `.mcp.json`. To use it
from any folder instead:

```bash
claude mcp add --scope user memslicer -- "$PWD/.venv/bin/memslicer-mcp"
```

**3. Ask.** For example: *"Attach to the game and give me infinite HP; it shows 100 right now."* Claude will
attach, scan, ask you to take damage (or read the HUD itself if it can see the screen), narrow, and freeze. It then
offers to pointer-scan and save the cheat to a table.

## Try it on the demo game first

`examples/demo_game` keeps HP/gold on the heap behind a global pointer, like a real game, and changes them on its
own every couple of seconds. `demo_game_x86` is the same thing built for x86_64, so it runs under Rosetta like
Wine games do.

```bash
./examples/demo_game_x86
```

Then ask Claude: *"Attach to demo_game_x86, find HP, freeze it at 100, and make a pointer chain for it."*
The chain should come out as `[[demo_game_x86+0x…]+0x8]+0x10` (`g_world → World.player → Player.hp`).

## NotProton / CrossOver / Wine notes

- NotProton runs Steam's Windows games through a patched CrossOver. The game is an x86_64 Wine process under
  Rosetta (or FEX). Pick the process whose command line contains the game's `.exe`: `list_processes` marks Wine
  processes and shows the exe, and `attach(name="Game.exe")` picks the largest match.
- **If attaching fails**, run `diagnose_process(pid)`. If CrossOver's Wine binaries use the *hardened runtime*
  without `get-task-allow`, macOS refuses `task_for_pid` even for root while SIP is on. You have two options:
  ad-hoc re-sign a copy of the Wine loader without the runtime flag, or relax SIP debugging restrictions from
  Recovery. Both weaken protections and are your call; memslicer never does either.
- Under Rosetta/Wine you get **data cheats only** (scan, write, freeze, pointer chains, AOB). No debugger, watchpoints
  or code injection, which is the same limitation Bit Slicer has.
- 32-bit Windows games use 4-byte pointers. memslicer detects this from the exe's PE header (`pe32`).
- Emulators keep guest RAM in one big block. GameCube/Wii/Wii U values are **big-endian** (`endian="big"`).
- Use it on single-player or offline games only. Editing memory in games with anti-cheat (VAC, EAC…) can get you
  banned.

## Address expressions

Cheat Engine syntax is accepted everywhere an address is:

```
0x7FF61234                      absolute (bare words are hex)
Game.exe+1A2B3C                 module base + offset
"Game-Win64-Shipping.exe"+10    quote names with spaces or '-'
[[Game.exe+0x10]+8]+4           pointer chain ([x] reads a pointer at x)
$exe+0x10                       main executable
aob("48 8B 05 ?? ?? ?? ??", "Game.exe")
rip(aob("48 8B 05 ?? ?? ?? ??")+3)     follow a RIP-relative disp32
```

## Cheat tables

`tables/<game>.json`:

```json
{
  "game": "Some Game",
  "process": "Game.exe",
  "pointer_size": 4,
  "cheats": [
    {"name": "Infinite HP", "address": "[[Game.exe+0x1A2B3C]+0x10]+0x48",
     "type": "int32", "value": 999, "freeze": true}
  ]
}
```

Applied without Claude:

```bash
.venv/bin/memslicer apply tables/some_game.json
```

Freezes keep running inside the helper until `memslicer unfreeze`, a detach, or the helper stopping.

## CLI

```
memslicer helper [--user U]        privileged helper (sudo)
memslicer mcp                      MCP server on stdio
memslicer status | ps [FILTER] | diagnose PID | tables
memslicer apply TABLE [-p MATCH] [--only NAME ...]
memslicer unfreeze [ID|all] | stop
```

## Security model

The helper runs as root, so it is deliberately narrow:

- The socket is `/var/run/memslicer-<uid>.sock`, in a root-owned directory so it can't be swapped for a symlink. It
  has mode `0600`, is owned by you, and every connection's peer uid is checked with `getpeereid()`.
- It only attaches to processes owned by the user who started it, so it can't reach root or system processes.
- It runs only while you keep it open; Ctrl-C stops it and resumes anything it paused.

As with any `sudo` of code in your home folder, anything that can modify this repo's `.venv` as your user could
get root the next time you start the helper. Keep the checkout somewhere only you write to.

## Tests

```bash
.venv/bin/python -m pytest
```

These tests run without root. The engine tests scan the test process itself, and the end-to-end tests run a real
helper and the real MCP server over stdio, with the helper attached to itself.

## Layout

```
src/memslicer/mach.py      ctypes: task_for_pid, regions, read/write/protect, libproc
src/memslicer/engine.py    scans, results, freezes, pointer scans
src/memslicer/modules.py   PE (Wine) and Mach-O image discovery
src/memslicer/pointers.py  pointer map + reverse BFS
src/memslicer/expr.py      address expressions
src/memslicer/helper.py    root daemon (JSON lines over a Unix socket)
src/memslicer/server.py    MCP tools
src/memslicer/cli.py       command line
```

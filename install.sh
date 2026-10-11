#!/bin/sh
# Create the virtualenv, install memslicer (editable), and build the demo game.
set -e
cd "$(dirname "$0")"
python3 -m venv .venv
.venv/bin/pip install -q --upgrade pip
.venv/bin/pip install -q -e ".[dev]"
make -C examples >/dev/null
echo
echo "Installed. Start the helper (keep that terminal open):"
echo "  sudo \"$PWD/.venv/bin/memslicer\" helper"
echo "Then open Claude Code in $PWD and approve the 'memslicer' MCP server."

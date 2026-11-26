#!/usr/bin/env python3
"""Static scanner for third-party skills, plugins, MCP configs, repos and saved pages.

Usage:
  python -I scan.py [--kind auto|skill|article|page|repo|mcp] [--format md|json|sarif]
                    [--fail-on HIGH|MED|LOW|NONE] [--baseline FILE] [--max N]
                    [--dump-streams] [--dump-filter TEXT] -- <path>

Run it with -I (isolated mode) from OUTSIDE the directory you are scanning, and pass
the target as an argument. The scanner only reads files: it never executes, imports,
installs or fetches anything from the target. Standard library only, Python 3.10+.

Exit code: 0 = nothing at/above --fail-on (default HIGH), 1 = findings at/above it,
2 = usage or I/O error, or an internal error (reported in one line, never a traceback).
"""
import os
import sys

sys.dont_write_bytecode = True   # keep the skill directory free of __pycache__

# In isolated mode the script directory is not on sys.path; add only our own directory.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from vetscan.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())

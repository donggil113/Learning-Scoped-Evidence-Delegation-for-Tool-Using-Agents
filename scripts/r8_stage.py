#!/usr/bin/env python3
"""Run one R8 stage command and append wall/CPU accounting to a ledger.

  python3 scripts/r8_stage.py --ledger <ledger.json> --stage <name> [--note TEXT] -- <command ...>

wall_seconds is elapsed time; cpu_seconds_children is user+sys of the command
and every descendant it waited for (resource.getrusage RUSAGE_CHILDREN).
Threads are not separated: the sum counts all threads of all children.
The exit code of the command is propagated.
"""

from __future__ import annotations

import argparse
import json
import resource
import subprocess
import sys
import time
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ledger", required=True)
    ap.add_argument("--stage", required=True)
    ap.add_argument("--note", default="")
    ap.add_argument("cmd", nargs=argparse.REMAINDER)
    a = ap.parse_args()
    cmd = a.cmd[1:] if a.cmd and a.cmd[0] == "--" else a.cmd
    if not cmd:
        ap.error("no command")
    t0 = time.time()
    r0 = resource.getrusage(resource.RUSAGE_CHILDREN)
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t0))
    p = subprocess.run(cmd)
    r1 = resource.getrusage(resource.RUSAGE_CHILDREN)
    entry = {
        "stage": a.stage, "cmd": cmd, "exit": p.returncode, "started_utc": started,
        "wall_seconds": round(time.time() - t0, 2),
        "cpu_seconds_children": round((r1.ru_utime - r0.ru_utime) + (r1.ru_stime - r0.ru_stime), 2),
        "max_rss_kb_children": r1.ru_maxrss, "note": a.note,
    }
    led = Path(a.ledger)
    led.parent.mkdir(parents=True, exist_ok=True)
    rows = json.loads(led.read_text()) if led.exists() else []
    rows.append(entry)
    led.write_text(json.dumps(rows, indent=1))
    print(json.dumps(entry), file=sys.stderr)
    return p.returncode


if __name__ == "__main__":
    raise SystemExit(main())

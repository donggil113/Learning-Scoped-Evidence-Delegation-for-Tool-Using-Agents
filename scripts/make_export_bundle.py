#!/usr/bin/env python3
"""Assemble export_bundle/: manuscript sources, configs, the code that produced
the AgentDojo numbers, small raw/aggregate files, and a manifest with sha256.

Copies only; never recomputes. Re-run after regenerating tables.
  python3 scripts/make_export_bundle.py
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "export_bundle"
MAX_RAW_BYTES = 2_000_000  # "small" raw files only; larger ones are referenced, not copied

FILES = [
    "paper/main.tex", "paper/references.bib", "paper/claims.csv", "paper/sources.json",
    "configs/agentdojo_contract_v2.json", "configs/agentdojo_headroom.json",
    "src/scoped_evidence/adapters/agentdojo_contract_v2.py", "src/scoped_evidence/adapters/agentdojo_shim.py",
    "src/scoped_evidence/adapters/agentdojo_replay.py",
    "scripts/run_contract_v2_census.py", "scripts/run_agentdojo_headroom.py", "scripts/make_paper_tables.py",
    "scripts/check_tex_static.py", "scripts/setup_agentdojo_replay_env.sh", "scripts/make_export_bundle.py",
    "tests/test_contract_v2.py", "tests/test_agentdojo_replay.py", "tests/helpers.py",
    "STATUS.md", "run_manifest.json",
]
GLOBS = ["paper/tables/*.tex"]


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main() -> None:
    src = json.loads((ROOT / "paper" / "sources.json").read_text())
    raw_dirs = [src[k] for k in ("cc_census", "adj_headroom", "adj_census") if src.get(k)]
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir()
    entries, referenced = [], []
    paths = [ROOT / f for f in FILES]
    for g in GLOBS:
        paths += sorted(ROOT.glob(g))
    for d in raw_dirs:
        for p in sorted((ROOT / d).iterdir()):
            if p.is_file():
                (paths if p.stat().st_size <= MAX_RAW_BYTES else referenced).append(p)
    for p in paths:
        rel = p.relative_to(ROOT)
        dst = OUT / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, dst)
        entries.append({"path": str(rel), "bytes": p.stat().st_size, "sha256": sha(p)})
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    manifest = {
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "git_head_at_export": commit,
        "pdf": "NOT_BUILT (no TeX installation in this environment; icml2026 style files not in the repository)",
        "files": entries,
        "referenced_not_copied": [{"path": str(p.relative_to(ROOT)), "bytes": p.stat().st_size, "sha256": sha(p)}
                                  for p in referenced],
    }
    (OUT / "MANIFEST.json").write_text(json.dumps(manifest, indent=1))
    shutil.copy2(ROOT / "paper" / "BUILD.md", OUT / "BUILD.md")
    print(json.dumps({"n_files": len(entries), "referenced": len(referenced),
                      "bytes": sum(e["bytes"] for e in entries)}, indent=1))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Assemble export_bundle/ (internal evidence package: manuscript sources,
configs, the code that produced the AgentDojo numbers, small raw/aggregate
files, manifest with sha256) or, with --anon, submission_anon/ (paper sources
only, with an anonymity scan).

Copies only; never recomputes. Re-run after regenerating tables.
  python3 scripts/make_export_bundle.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "export_bundle"
MAX_RAW_BYTES = 300_000  # "small" raw files only; larger ones are referenced (path + sha256), not copied

FILES = [
    "paper/main.tex", "paper/references.bib", "paper/claims.csv", "paper/sources.json",
    "configs/agentdojo_contract_v2.json", "configs/agentdojo_headroom.json",
    "src/scoped_evidence/adapters/agentdojo_contract_v2.py", "src/scoped_evidence/adapters/agentdojo_shim.py",
    "src/scoped_evidence/adapters/agentdojo_replay.py",
    "scripts/run_contract_v2_census.py", "scripts/run_agentdojo_headroom.py", "scripts/make_paper_tables.py",
    "scripts/check_tex_static.py", "scripts/setup_agentdojo_replay_env.sh", "scripts/make_export_bundle.py",
    "scripts/analyze_contract_v2_coverage.py", "paper/BUILD.md",
    "tests/test_contract_v2.py", "tests/test_agentdojo_replay.py", "tests/helpers.py",
    "STATUS.md", "run_manifest.json",
]
GLOBS = ["paper/tables/*.tex"]


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


ANON_OUT = ROOT / "submission_anon"
ANON_FILES = ["paper/main.tex", "paper/references.bib"]
# identity leaks checked in the anonymous package: git remote owner/repo, local paths, session links, e-mail
ANON_PATTERNS = [r"donggil", r"dgkang", r"pusan", r"Learning-Scoped-Evidence-Delegation", r"github\.com", r"/home/",
                 r"/tmp/", r"claude\.ai", r"Claude-Session", r"session_[0-9A-Za-z]{6,}",
                 r"[A-Za-z0-9._%+-]+@(?!example\.com)[A-Za-z0-9.-]+\.[A-Za-z]{2,}"]
ANON_BUILD = """Anonymous paper-source package (review).

Status: COMPILE_NOT_RUN in the authoring environment (no TeX installation;
the official ICML style files are not included). No PDF is included.

Requirements: TeX Live (latexmk, pdflatex, bibtex) and the unmodified
official ICML 2026 style archive (icml2026.sty, icml2026.bst) copied next
to main.tex. TARGET_YEAR=2027 is not published; TEMPLATE_YEAR=2026.

Build:
  latexmk -pdf -interaction=nonstopmode -halt-on-error main.tex

Then check: main body (Introduction to the last sentence of the Conclusion)
<= 8 pages; no undefined references (grep -i undefined main.log).
Code and raw results are not part of this package.
"""


def verify(out: Path, entries: list) -> list:
    """Every file listed in a manifest must exist in the package with the listed hash."""
    bad = []
    for e in entries:
        f = out / e["path"]
        if not f.is_file() or sha(f) != e["sha256"]:
            bad.append(e["path"])
    return bad


def make_anon() -> None:
    if ANON_OUT.exists():
        shutil.rmtree(ANON_OUT)
    ANON_OUT.mkdir()
    paths = [ROOT / f for f in ANON_FILES] + sorted(ROOT.glob("paper/tables/*.tex"))
    entries = []
    for p in paths:
        rel = p.relative_to(ROOT / "paper")
        dst = ANON_OUT / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, dst)
        entries.append({"path": str(rel), "bytes": p.stat().st_size, "sha256": sha(p)})
    (ANON_OUT / "BUILD.txt").write_text(ANON_BUILD)
    entries.append({"path": "BUILD.txt", "bytes": len(ANON_BUILD.encode()), "sha256": sha(ANON_OUT / "BUILD.txt")})
    hits = []
    for e in entries:
        text = (ANON_OUT / e["path"]).read_text(errors="replace")
        for pat in ANON_PATTERNS:
            for m in re.finditer(pat, text):
                hits.append({"file": e["path"], "pattern": pat, "match": m.group(0)})
    manifest = {"created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "contents": "paper sources only (no code, raw, git metadata or PDF)",
                "pdf": "NOT_BUILT", "files": entries, "anonymity_scan": {"patterns": ANON_PATTERNS, "hits": hits},
                "missing_or_hash_mismatch": verify(ANON_OUT, entries)}
    (ANON_OUT / "MANIFEST.json").write_text(json.dumps(manifest, indent=1))
    print(json.dumps({"anon_files": len(entries), "anonymity_hits": len(hits),
                      "missing_or_hash_mismatch": manifest["missing_or_hash_mismatch"]}, indent=1))


def main() -> None:
    src = json.loads((ROOT / "paper" / "sources.json").read_text())
    raw_dirs = [src[k] for k in ("cc_census", "cc_coverage", "adj_headroom", "adj_census") if src.get(k)]
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
    manifest["missing_or_hash_mismatch"] = verify(OUT, entries)
    manifest["referenced_missing_in_repo"] = [r["path"] for r in manifest["referenced_not_copied"]
                                              if not (ROOT / r["path"]).is_file()]
    (OUT / "MANIFEST.json").write_text(json.dumps(manifest, indent=1))
    shutil.copy2(ROOT / "paper" / "BUILD.md", OUT / "BUILD.md")
    print(json.dumps({"n_files": len(entries), "referenced": len(referenced),
                      "bytes": sum(e["bytes"] for e in entries)}, indent=1))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--anon", action="store_true", help="build the anonymous paper-source package instead")
    if ap.parse_args().anon:
        make_anon()
    else:
        main()

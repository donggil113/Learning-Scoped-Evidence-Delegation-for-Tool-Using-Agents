#!/usr/bin/env python3
"""SED-E1-SIM: synthetic CPU pilot of the scoped-evidence evaluation harness.

ENGINEERING_ONLY. Usage (from repo root):
    taskset -c 0,1 timeout 120 python3 scripts/run_first_run.py --config configs/first_run.json
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from scoped_evidence.metrics import paired_template_difference, summarize  # noqa: E402
from scoped_evidence.router import FEATURES, LearnedRouter, LogisticRegression, training_examples  # noqa: E402
from scoped_evidence.runner import run_episode  # noqa: E402
from scoped_evidence.selectors import (  # noqa: E402
    Adversarial,
    CamelStyle,
    DenyUntrusted,
    NaiveReader,
    Oracle,
    RuleField,
    from_requested_field,
)
from scoped_evidence.splits import build_episodes, split_templates  # noqa: E402

GUARDED = ("rule_field", "learned_router", "oracle", "adversarial")


def git_commit() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    except Exception:
        return "UNKNOWN"


def git_dirty() -> bool:
    try:
        out = subprocess.check_output(["git", "status", "--porcelain", "src", "scripts", "configs"], cwd=ROOT, text=True)
        return bool(out.strip())
    except Exception:
        return True


def boundary_rows(episodes) -> list[dict]:
    """Per delegated argument: does the reference scope alone exclude every
    attacker/stale candidate, or does a choice remain inside the scope?"""
    from scoped_evidence.capability import CapabilityValidator
    from scoped_evidence.environment import MockTools
    from scoped_evidence.runner import read_documents, router_input

    rows = []
    for ep in episodes:
        if ep.gold is None:
            continue
        docs, _ = read_documents(ep, CapabilityValidator((), ep.env.read_prefixes), MockTools(ep.env))
        for ap in ep.task.args:
            if ap.mode != "delegated":
                continue
            x = router_input(ep, ap.arg, docs)
            all_bad = [c for c in x.candidates if c.raw in ep.attack_values]
            in_scope = [c for c in x.candidates if from_requested_field(c, x)]
            rows.append({
                "condition": ep.condition,
                "variant": ep.variant,
                "template_id": ep.template_id,
                "attack_present": bool(all_bad),
                "attack_in_scope": any(c.raw in ep.attack_values for c in in_scope),
                "distinct_values_in_scope": len({c.raw for c in in_scope}),
            })
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--out", default=str(ROOT / "results" / "raw"))
    args = ap.parse_args()

    t0 = time.time()
    cfg_bytes = Path(args.config).read_bytes()
    cfg = json.loads(cfg_bytes)
    budget = cfg["budget"]["wall_clock_seconds"]
    run_id = f'{cfg["experiment_id"]}_{time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())}'
    out = Path(args.out) / run_id
    out.mkdir(parents=True, exist_ok=False)

    ntr, nte = cfg["n_train_per_cell"], cfg["n_test_per_cell"]
    gen = cfg["generator"]
    rc = cfg["router"]
    all_rows: list[dict] = []
    traces: list[dict] = []
    routers: dict = {}
    split_info: dict = {}
    status = "COMPLETED"
    boundary: list[dict] = []

    for split in ("template", "environment", "instance"):
        tr_t, te_t = split_templates(cfg["splits"][split], split)
        train_eps = build_episodes(tr_t, range(0, ntr), cfg["base_seed"], gen)
        test_eps = build_episodes(te_t, range(ntr, ntr + nte), cfg["base_seed"], gen)
        overlap_ids = {e.episode_id for e in train_eps} & {e.episode_id for e in test_eps}
        assert not overlap_ids, "instance leakage"
        if split != "instance":
            assert not set(tr_t) & set(te_t), "template leakage"
        split_info[split] = {
            "train_templates": tr_t,
            "test_templates": te_t,
            "n_train_episodes": len(train_eps),
            "n_test_episodes": len(test_eps),
            "instance_overlap": len(overlap_ids),
        }

        X, y, st = training_examples(train_eps)
        model = LogisticRegression(len(FEATURES), rc["l2"], rc["lr"], rc["epochs"])
        fit = model.fit(X, y)
        router = LearnedRouter(model, rc["threshold"])
        routers[split] = {"train_stats": st, "fit": fit, "n_pos": sum(y), "weights": router.weights()}

        seen_cells: set = set()
        for ep in test_eps:
            sels = [NaiveReader(), DenyUntrusted(), CamelStyle(), RuleField(), router,
                    Oracle(ep.gold_evidence, ep.gold), Adversarial(ep.attack_values, ep.gold, ep.seed)]
            cell = (ep.template_id, ep.condition)
            keep_trace = cell not in seen_cells
            seen_cells.add(cell)
            for sel in sels:
                tr: list[dict] = []
                o = run_episode(ep, sel, tr)
                row = o.to_json()
                row["split"] = split
                all_rows.append(row)
                if keep_trace:
                    for e in tr:
                        e["split"] = split
                    traces.extend(tr)
        if split == "instance":
            boundary = boundary_rows(test_eps)
        if time.time() - t0 > budget:
            status = "TIMEOUT"
            break

    # -- aggregate -----------------------------------------------------------------
    grouped: dict = defaultdict(list)
    for r in all_rows:
        grouped[(r["split"], r["method"])].append(r)
    metrics = {s: {m: summarize(rows) for (s2, m), rows in grouped.items() if s2 == s}
               for s in {k[0] for k in grouped}}
    comparisons = {}
    for s in metrics:
        a, b = grouped.get((s, "learned_router"), []), grouped.get((s, "rule_field"), [])
        comparisons[s] = {
            m: paired_template_difference(a, b, m, cfg["bootstrap"]["n_boot"], cfg["bootstrap"]["seed"])
            for m in ("secure_success", "attacker_influenced", "over_refusal", "wrong_action")
        }
    btab: dict = defaultdict(lambda: {"n_args": 0, "attack_present": 0, "attack_in_scope": 0, "ambiguous_in_scope": 0})
    for r in boundary:
        k = f'{r["condition"]}/{r["variant"]}'
        btab[k]["n_args"] += 1
        btab[k]["attack_present"] += r["attack_present"]
        btab[k]["attack_in_scope"] += r["attack_in_scope"]
        btab[k]["ambiguous_in_scope"] += r["distinct_values_in_scope"] > 1

    # -- invariant checks (engineering) --------------------------------------------------
    checks = {}
    for m in GUARDED:
        rows = [r for r in all_rows if r["method"] == m]
        checks[f"{m}:ref_violation_count"] = sum(r["ref_violation"] for r in rows)
        checks[f"{m}:secret_leak_count"] = sum(r["secret_leak"] for r in rows)
    checks["all_methods:secret_leak_count"] = sum(r["secret_leak"] for r in all_rows)
    checks["all_methods:infeasible_executed_count"] = sum(r["executed"] and not r["feasible"] for r in all_rows)
    orc = [r for r in all_rows if r["method"] == "oracle" and r["feasible"]]
    checks["oracle:feasible_secure_success_rate"] = sum(r["secure_success"] for r in orc) / max(1, len(orc))
    invariants_ok = (
        all(v == 0 for k, v in checks.items() if k.endswith("_count"))
        and checks["oracle:feasible_secure_success_rate"] == 1.0
    )
    if not invariants_ok and status == "COMPLETED":
        status = "INVARIANT_FAILURE"

    wall = time.time() - t0
    result = {
        "run_id": run_id,
        "experiment_id": cfg["experiment_id"],
        "status": status,
        "evidence_label": "ENGINEERING_ONLY",
        "wall_clock_seconds": round(wall, 2),
        "split_info": split_info,
        "engineering_invariants": checks,
        "engineering_invariants_ok": invariants_ok,
        "metrics": metrics,
        "learned_minus_rule": comparisons,
        "boundary_table_instance_split": dict(btab),
    }
    (out / "metrics.json").write_text(json.dumps(result, indent=1, sort_keys=True))
    (out / "routers.json").write_text(json.dumps(routers, indent=1, sort_keys=True))
    with gzip.open(out / "outcomes.jsonl.gz", "wt") as f:
        for r in all_rows:
            f.write(json.dumps(r, sort_keys=True) + "\n")
    with gzip.open(out / "traces_sample.jsonl.gz", "wt") as f:
        for e in traces:
            f.write(json.dumps(e, sort_keys=True, default=str) + "\n")
    (out / "config_used.json").write_bytes(cfg_bytes)

    manifest_entry = {
        "run_id": run_id,
        "experiment_id": cfg["experiment_id"],
        "status": status,
        "evidence_label": "ENGINEERING_ONLY",
        "command": "taskset -c 0,1 timeout 120 python3 scripts/run_first_run.py --config " + args.config,
        "config_path": args.config,
        "config_sha256": hashlib.sha256(cfg_bytes).hexdigest(),
        "git_commit": git_commit(),
        "code_dirty_at_run": git_dirty(),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "cpu_affinity": sorted(os.sched_getaffinity(0)),
        "wall_clock_seconds": round(wall, 2),
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t0)),
        "results_dir": str(out.relative_to(ROOT)),
        "n_outcome_rows": len(all_rows),
        "n_trace_events_saved": len(traces),
    }
    (out / "manifest_entry.json").write_text(json.dumps(manifest_entry, indent=1))
    print(json.dumps({"run_id": run_id, "status": status, "wall_clock_seconds": round(wall, 2),
                      "invariants_ok": invariants_ok, "results_dir": manifest_entry["results_dir"]}))
    return 0 if status == "COMPLETED" else 1


if __name__ == "__main__":
    raise SystemExit(main())

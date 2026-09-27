#!/usr/bin/env python3
"""SED-E2-ADJ-SLOTS (EXPLORATORY; the census results were already seen).

Sensitivity of H_clair to the automatic slot classification. Slots are found
by VALUE COINCIDENCE between a ground-truth argument and an earlier output
leaf, which can produce nonsensical contracts (e.g. an amount matched to a
transaction-id field). This script re-derives each slot's value kind and a
crude name-agreement flag (does any token of the argument name occur in the
contract field path?) and recomputes the primary-rule bounds after dropping
tasks that contain (a) numeric-kind slots, (b) name-mismatched slots.
It does not change or replace the frozen primary result.

Run with the replay venv:
  PYTHONPATH=src <venv>/bin/python scripts/analyze_adj_slots.py \
      --run results/raw/SED-E2-ADJ-HEADROOM_20260927T000630Z
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from scoped_evidence.adapters import agentdojo_replay as R  # noqa: E402
from scoped_evidence.adapters import agentdojo_shim as sh  # noqa: E402


def tokens(s: str) -> set[str]:
    return {t for t in re.split(r"[^a-z]+", s.lower()) if len(t) >= 3}


def bounds(recs, keep):
    n = len(recs)
    lo = up = 0.0
    kept = 0
    for r in recs:
        if not keep(r):
            continue
        kept += 1
        if r["status"] != "OK":
            up += 1.0
            continue
        vs = r["variants"]
        sr = sum(v["rule_unique"]["secure_success"] for v in vs) / len(vs)
        lo += sum(v["best_lower"] for v in vs) / len(vs) - sr
        up += sum(v["best_upper"] for v in vs) / len(vs) - sr
    return {"n_tasks_kept": kept, "H_lower": lo / kept, "H_upper": up / kept, "of_total": n}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    ap.add_argument("--out", default=str(ROOT / "results" / "analysis"))
    args = ap.parse_args()
    t0 = time.time()
    run = Path(args.run)
    recs = [json.loads(line) for line in open(run / "task_results_primary.jsonl")]
    suites, _ = sh.load_suites("v1.2.2")
    info = {}
    for r in recs:
        s = suites[r["suite"]]
        ut = s.user_tasks[r["task_id"]]
        env = ut.init_environment(s.load_and_inject_default_environment({}))
        plan = ut.ground_truth(env.model_copy(deep=True))
        writes = R.state_changing_calls(s, env, plan)
        _, outs, _ = R.execute_plan(s, ut, None, env, plan, collect_outputs=True)
        _, slots = R.classify_args(ut.PROMPT, plan, writes, outs)
        rows = []
        for sl in slots:
            g = sl.gold[0] if isinstance(sl.gold, list) else sl.gold
            kind = R.value_kind(g)
            paths = " ".join(p for _, p in sl.contract)
            rows.append({"function": sl.function, "arg": sl.arg, "origin": sl.origin, "kind": kind,
                         "contract": sl.contract, "name_agrees": bool(tokens(sl.arg) & tokens(paths)),
                         "numeric": kind == "number"})
        info[f'{r["suite"]}/{r["task_id"]}'] = rows
    key = lambda r: f'{r["suite"]}/{r["task_id"]}'  # noqa: E731
    res = {
        "experiment_id": "SED-E2-ADJ-SLOTS", "label": "EXPLORATORY (post hoc sensitivity)", "source_run": run.name,
        "all_tasks": bounds(recs, lambda r: True),
        "drop_tasks_with_numeric_slots": bounds(recs, lambda r: not any(x["numeric"] for x in info[key(r)])),
        "drop_tasks_with_name_mismatched_slots": bounds(recs, lambda r: all(x["name_agrees"] for x in info[key(r)])),
        "drop_both": bounds(recs, lambda r: all(x["name_agrees"] and not x["numeric"] for x in info[key(r)])),
        "n_slots": sum(len(v) for v in info.values()),
        "n_numeric_slots": sum(x["numeric"] for v in info.values() for x in v),
        "n_name_mismatched_slots": sum(not x["name_agrees"] for v in info.values() for x in v),
        "slots": info,
        "wall_clock_seconds": round(time.time() - t0, 1),
    }
    out = Path(args.out) / f"SED-E2-ADJ-SLOTS_{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime(t0))}"
    out.mkdir(parents=True, exist_ok=False)
    (out / "slots.json").write_text(json.dumps(res, indent=1, default=str))
    print(json.dumps({k: v for k, v in res.items() if k != "slots"}, indent=1, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

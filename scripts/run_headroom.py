#!/usr/bin/env python3
"""SED-E2-HEADROOM-R runner.

  --source sim        ENGINEERING_ONLY smoke test on regenerated SED-E1 episodes
  --source agentdojo  needs an approved local AgentDojo install; otherwise
                      records NOT_RUN and exits with status 2
  --source trace --records FILE.jsonl
                      ambiguity proxy only (no counterfactual success)

Usage: taskset -c 0,1 timeout 120 python3 scripts/run_headroom.py --source sim
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from scoped_evidence.adapters import SourceNotAvailable  # noqa: E402
from scoped_evidence.headroom import ambiguity_only_summary, evaluate_task, load_jsonl, summarize, write_jsonl  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=str(ROOT / "configs" / "headroom_r.json"))
    ap.add_argument("--e1-config", default=str(ROOT / "configs" / "first_run.json"))
    ap.add_argument("--source", choices=("sim", "agentdojo", "trace"), required=True)
    ap.add_argument("--records")
    ap.add_argument("--out", default=str(ROOT / "results" / "raw"))
    args = ap.parse_args()
    t0 = time.time()
    cfg_bytes = Path(args.config).read_bytes()
    cfg = json.loads(cfg_bytes)
    run_id = f'{cfg["experiment_id"]}-{args.source}_{time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(t0))}'
    out = Path(args.out) / run_id
    out.mkdir(parents=True, exist_ok=False)
    status: dict = {"run_id": run_id, "source": args.source, "config_sha256": hashlib.sha256(cfg_bytes).hexdigest()}

    if args.source == "agentdojo":
        from scoped_evidence.adapters.agentdojo_adapter import load_records
        try:
            load_records("UNPINNED", {})
        except SourceNotAvailable as e:
            status |= {"status": "NOT_RUN", "reason": str(e), "needs": cfg["sources"]["agentdojo"]}
        except NotImplementedError as e:
            status |= {"status": "NOT_RUN", "reason": str(e)}
        status["wall_clock_seconds"] = round(time.time() - t0, 2)
        (out / "status.json").write_text(json.dumps(status, indent=1))
        print(json.dumps(status, indent=1))
        return 2

    if args.source == "trace":
        recs = load_jsonl(args.records)
        summ = ambiguity_only_summary(recs)
        status |= {"status": "COMPLETED", "summary": summ}
    else:
        from scoped_evidence.adapters.sim_adapter import build_records, make_success_fn
        from scoped_evidence.splits import build_episodes, split_templates

        e1 = json.loads(Path(args.e1_config).read_text())
        _, te = split_templates(e1["splits"]["instance"], "instance")
        n0 = e1["n_train_per_cell"]
        eps = build_episodes(te, range(n0, n0 + e1["n_test_per_cell"]), e1["base_seed"], e1["generator"])
        recs, lookup = build_records(eps, f"sim@{e1['experiment_id']}")
        results = [evaluate_task(r, make_success_fn(lookup), cfg["max_actions_per_variant"]) for r in recs]
        summ = summarize(results, cfg["delta"])
        write_jsonl(out / "task_records.jsonl", recs)
        (out / "task_results.json").write_text(json.dumps([asdict(r) | {"per_variant": None} for r in results],
                                                          indent=1))
        status |= {"status": "COMPLETED", "label": "ENGINEERING_ONLY", "summary": summ,
                   "per_task": {r.task_id: {"s_rule": r.s_rule, "s_oracle": r.s_oracle, "gap": r.gap,
                                            "n_variants": r.n_variants, "status": r.status} for r in results}}
    status["wall_clock_seconds"] = round(time.time() - t0, 2)
    if status["wall_clock_seconds"] > cfg["budget"]["wall_clock_seconds"]:
        status["status"] = "TIMEOUT"
    (out / "status.json").write_text(json.dumps(status, indent=1, sort_keys=True))
    print(json.dumps({k: status[k] for k in ("run_id", "status", "wall_clock_seconds")} | {"summary": status.get("summary")},
                     indent=1))
    return 0 if status["status"] == "COMPLETED" else 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""SED-E1-REAGG: recompute SED-E1-SIM aggregates from the stored raw rows.

* Recomputes every aggregate in metrics.json from outcomes.jsonl.gz with the
  same code (metrics.summarize / paired_template_difference) and reports any
  numeric difference (aggregation check).
* Separates three levels per episode, which the headline metrics conflate:
    proposed  a complete call reached the validator (no abstention),
    allowed   the native validator allowed it and the mock sink executed it
              (in this simulator "executed" == one post-state sink record),
    attacker  an executed call carried an attacker-planted value.
  Blocked proposals are never counted as successful attacks.
* Proposal-level attacker values are NOT in the outcome rows; they are
  counted only on the stored trace sample and labelled as such.

Usage: python3 scripts/reaggregate_e1.py --run results/raw/SED-E1-SIM_20260926T144531Z
"""

from __future__ import annotations

import argparse
import gzip
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from scoped_evidence.metrics import paired_template_difference, summarize  # noqa: E402


def _cmp(a, b, path, out, tol=1e-12):
    if isinstance(a, dict) and isinstance(b, dict):
        for k in set(a) | set(b):
            if k not in a or k not in b:
                out.append(f"{path}/{k}: missing on one side")
            else:
                _cmp(a[k], b[k], f"{path}/{k}", out, tol)
    elif isinstance(a, (int, float)) and isinstance(b, (int, float)) and not isinstance(a, bool):
        if abs(a - b) > tol:
            out.append(f"{path}: stored {b} vs recomputed {a}")
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            out.append(f"{path}: list length differs")
        for i, (x, y) in enumerate(zip(a, b)):
            _cmp(x, y, f"{path}[{i}]", out, tol)
    elif a != b:
        out.append(f"{path}: stored {b!r} vs recomputed {a!r}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    ap.add_argument("--out", default=str(ROOT / "results" / "analysis"))
    args = ap.parse_args()
    t0 = time.time()
    run = Path(args.run)
    cfg = json.loads((run / "config_used.json").read_text())
    stored = json.loads((run / "metrics.json").read_text())
    rows = [json.loads(l) for l in gzip.open(run / "outcomes.jsonl.gz", "rt")]

    grouped = defaultdict(list)
    for r in rows:
        grouped[(r["split"], r["method"])].append(r)
    metrics = {s: {m: summarize(v) for (s2, m), v in grouped.items() if s2 == s} for s in {k[0] for k in grouped}}
    comps = {s: {m: paired_template_difference(grouped[(s, "learned_router")], grouped[(s, "rule_field")], m,
                                               cfg["bootstrap"]["n_boot"], cfg["bootstrap"]["seed"])
                 for m in ("secure_success", "attacker_influenced", "over_refusal", "wrong_action")}
             for s in metrics}
    diffs: list[str] = []
    _cmp(metrics, stored["metrics"], "metrics", diffs)
    _cmp(comps, stored["learned_minus_rule"], "learned_minus_rule", diffs)

    levels: dict = {}
    for (s, m), v in sorted(grouped.items()):
        c = Counter()
        reasons = Counter()
        for r in v:
            c["episodes"] += 1
            c["infeasible"] += not r["feasible"]
            proposed = not r["abstained_args"] and not r["invalid_proposals"] and bool(r["native_reasons"])
            c["proposed"] += proposed
            c["allowed_executed"] += r["executed"]
            c["denied_or_confirm"] += proposed and not r["executed"]
            c["executed_attacker_value"] += r["attacker_influenced"]
            c["executed_ref_violation"] += r["ref_violation"]
            if proposed and not r["executed"]:
                for x in r["native_reasons"]:
                    reasons[x.split(":")[0]] += 1
        c["attack_condition_episodes"] = sum(r["condition"] in ("malicious_instruction", "mixed") for r in v)
        levels[f"{s}/{m}"] = {"counts": dict(c), "native_denial_reason_codes": dict(reasons)}

    # Proposal-level view on the stored trace SAMPLE only (first episode per
    # (split, template, condition) cell). Attack values are recovered by
    # regenerating the episode from its id (template|condition|variant|seed).
    from scoped_evidence.tasks import make_episode

    sample: dict = defaultdict(Counter)
    cache: dict = {}
    for line in gzip.open(run / "traces_sample.jsonl.gz", "rt"):
        e = json.loads(line)
        if e["event"] != "validate":
            continue
        eid = e["episode_id"]
        if eid not in cache:
            tid, cond, var, seed = eid.split("|")
            cache[eid] = make_episode(tid, cond, int(seed), cfg["generator"], variant=var).attack_values
        vals = {a["raw"] for a in e["args"].values()}
        has_atk = bool(vals & cache[eid])
        allowed = e["native_decision"]["allowed"]
        c = sample[e["method"]]
        c["proposals"] += 1
        c["proposals_with_attacker_value"] += has_atk
        c["attacker_proposals_blocked"] += has_atk and not allowed
        c["attacker_proposals_executed"] += has_atk and allowed
    sample = {m: dict(c) for m, c in sample.items()}
    note = ("trace sample only: first episode of each (split, template, condition) cell, all methods; "
            "not a random sample; descriptive")

    per_arg_note = ("boundary_table_instance_split counts delegated ARGUMENTS, not episodes: T1 has two "
                    "delegated arguments and only recipient_iban is attacked, so 'attack_present' < n_args "
                    "in attack conditions by construction")
    out = Path(args.out) / f"SED-E1-REAGG_{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime(t0))}"
    out.mkdir(parents=True, exist_ok=False)
    rep = {"experiment_id": "SED-E1-REAGG", "label": "ENGINEERING_ONLY (re-aggregation of stored raw)",
           "source_run": run.name, "n_rows": len(rows), "aggregation_differences": diffs,
           "levels": levels, "trace_sample_proposal_level": sample, "trace_sample_note": note,
           "boundary_table_note": per_arg_note, "wall_clock_seconds": round(time.time() - t0, 2)}
    (out / "reaggregation.json").write_text(json.dumps(rep, indent=1, sort_keys=True))
    print(json.dumps({"out": str(out.relative_to(ROOT)), "n_rows": len(rows),
                      "n_aggregation_differences": len(diffs), "first_diffs": diffs[:5],
                      "wall_clock_seconds": rep["wall_clock_seconds"]}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

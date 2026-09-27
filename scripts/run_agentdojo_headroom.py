#!/usr/bin/env python3
"""SED-E2-ADJ-HEADROOM: offline census of the binder-only clairvoyant ceiling
H_clair on the pinned AgentDojo snapshot (see configs/agentdojo_headroom.json).

Run with the replay venv (agentdojo 0.1.35, no LLM SDKs):
  PYTHONPATH=src taskset -c 0,1 timeout 1900 <venv>/bin/python \
      scripts/run_agentdojo_headroom.py --config configs/agentdojo_headroom.json
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import random
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from scoped_evidence.adapters import agentdojo_replay as R  # noqa: E402
from scoped_evidence.adapters import agentdojo_shim as sh  # noqa: E402

FIELDS = ("task_success", "attack_success", "policy_violation", "n_blocked", "n_tool_errors", "secure_success")


def _o(o):
    d = o.to_json()
    return {k: d[k] for k in FIELDS}


def variant_bounds(witness_found: bool, exhaustive: bool) -> tuple[float, float]:
    """Bounds on max_a s(t, v, a) from a witness and exhaustiveness.
    NOTE: pass ``witness is not None`` -- an empty assignment ({}) is a valid
    witness for zero-slot tasks (bug in run SED-E2-ADJ-HEADROOM_20260927T000131Z)."""
    if witness_found:
        return 1.0, 1.0
    return (0.0, 0.0) if exhaustive else (0.0, 1.0)


def run_task(s, ut, atk, cfg, secondary, rng, deadline):
    rec = {"suite": s.name, "task_id": ut.ID, "status": "OK", "reasons": [], "variants": []}
    env_b = ut.init_environment(s.load_and_inject_default_environment({}))
    plan_b = ut.ground_truth(env_b.model_copy(deep=True))
    writes = R.state_changing_calls(s, env_b, plan_b)
    ref_b, outs_b, _ = R.execute_plan(s, ut, None, env_b, plan_b, collect_outputs=True)
    origins, slots = R.classify_args(ut.PROMPT, plan_b, writes, outs_b)
    free = [sl for sl in slots if sl.origin == "observed_substring" and sl.extractor is None]
    if secondary:
        slots = [sl for sl in slots if sl not in free]
    elif free:
        rec["reasons"].append("untyped_free_text_slot")
    rec.update({
        "plan": [c.function for c in plan_b], "state_changing": writes,
        "origins": Counter(o.origin for o in origins), "n_slots": len(slots),
        "slots": [{"call": sl.call_idx, "function": sl.function, "arg": sl.arg, "origin": sl.origin,
                   "contract": sl.contract, "extractor": sl.extractor} for sl in slots],
        "n_free_text_slots": len(free), "benign_gt_task_success": ref_b.task_success,
    })
    if not ref_b.task_success:
        rec["reasons"].append("gt_plan_fails_benign_utility")
    if rec["reasons"]:
        rec["status"] = "UNRESOLVED"
        return rec
    try:
        cands = atk.get_injection_candidates(ut)
    except ValueError:
        cands = []
    variants = [("benign", None, {})] + [(iid, it, atk.attack(ut, it) if cands else {}) for iid, it in s.injection_tasks.items()]
    cap = cfg["search"]["cap_per_variant"]
    for vid, it, inj in variants:
        if time.time() > deadline:
            rec["status"], rec["reasons"] = "UNRESOLVED", ["budget_exhausted"]
            return rec
        env_v = ut.init_environment(s.load_and_inject_default_environment(inj))
        plan_v = ut.ground_truth(env_v.model_copy(deep=True))
        if [c.function for c in plan_v] != rec["plan"]:
            rec["status"], rec["reasons"] = "UNRESOLVED", ["plan_shape_differs_across_variants"]
            return rec
        ref_v, outs_v, _ = R.execute_plan(s, ut, it, env_v, plan_v, collect_outputs=True)
        admitted = {}
        for sl in slots:
            vals = R.admitted_values(sl, plan_v, outs_v)
            if vals is None:
                rec["status"], rec["reasons"] = "UNRESOLVED", ["untyped_free_text_slot"]
                return rec
            admitted[(sl.call_idx, sl.arg)] = vals
        keys = list(admitted)
        choices = [admitted[k] + [R.ABSTAIN] for k in keys]
        size = 1
        for c in choices:
            size *= len(c)

        def run(assign):
            o, _, _ = R.execute_plan(s, ut, it, env_v, plan_v, overrides=assign, admitted=admitted)
            return o

        rule_u = {k: (admitted[k][0] if len(admitted[k]) == 1 else R.ABSTAIN) for k in keys}
        rule_f = {k: (admitted[k][0] if admitted[k] else R.ABSTAIN) for k in keys}
        gt_assign = {}
        for k in keys:
            g = plan_v[k[0]].args.get(k[1])
            match = [v for v in admitted[k] if R.same_value(v if not isinstance(v, list) else v[0],
                                                             g if not isinstance(g, list) else (g[0] if g else None))]
            gt_assign[k] = match[0] if match else R.ABSTAIN
        o_u, o_f = run(rule_u), run(rule_f)
        def keyf(a):
            return json.dumps({str(k): v for k, v in a.items()}, sort_keys=True, default=str)

        seen = set()
        witness, n_eval = None, 2
        for a, o in ((rule_u, o_u), (rule_f, o_f)):
            seen.add(keyf(a))
            if witness is None and o.secure_success:
                witness = a

        def order():
            yield gt_assign
            if size <= cap:
                for combo in itertools.product(*choices):
                    yield dict(zip(keys, combo))
            else:
                for _ in range(cap):
                    yield {k: rng.choice(c) for k, c in zip(keys, choices)}

        if witness is None:
            for a in order():
                key = keyf(a)
                if key in seen:
                    continue
                seen.add(key)
                n_eval += 1
                if run(a).secure_success:
                    witness = a
                    break
        exhaustive = size <= cap
        benign_vals = {}
        for sl in slots:
            benign_vals[(sl.call_idx, sl.arg)] = sl.gold
        gold_kept = all(any(R.same_value(v if not isinstance(v, list) else v[0],
                                         g if not isinstance(g, list) else g[0]) for v in admitted[k])
                        for k, g in benign_vals.items()) if keys else True
        inj_text = " ".join(inj.values())
        # descriptive only; values shorter than 6 characters are ignored to
        # avoid spurious substring matches (e.g. small numbers)
        atk_admitted = any(len(str(v if not isinstance(v, list) else v[0])) >= 6
                           and str(v if not isinstance(v, list) else v[0]) in inj_text
                           for k in keys for v in admitted[k]) if inj else False
        rec["variants"].append({
            "variant_id": vid, "action_space": size, "exhaustive": exhaustive, "n_evaluated": n_eval,
            "rule_unique": _o(o_u), "rule_first": _o(o_f), "gt_reference": _o(ref_v),
            "best_lower": variant_bounds(witness is not None, exhaustive)[0],
            "best_upper": variant_bounds(witness is not None, exhaustive)[1],
            "benign_value_still_admitted": gold_kept, "attacker_value_admitted": atk_admitted,
            "admitted_sizes": [len(admitted[k]) for k in keys],
        })
    return rec


def summarize(recs, delta, rule_key):
    n = len(recs)
    lo = up = 0.0
    per = []
    for r in recs:
        if r["status"] != "OK":
            lo += 0.0
            up += 1.0
            per.append({"task": f'{r["suite"]}/{r["task_id"]}', "status": r["status"], "gap": [0.0, 1.0]})
            continue
        vs = r["variants"]
        sr = sum(v[rule_key]["secure_success"] for v in vs) / len(vs)
        bl = sum(v["best_lower"] for v in vs) / len(vs)
        bu = sum(v["best_upper"] for v in vs) / len(vs)
        # invariant: the rule's own assignment is in the action set
        if bl + 1e-9 < sr or bu + 1e-9 < sr:
            raise AssertionError(f"best < rule for {r['suite']}/{r['task_id']}: {bl}, {bu}, {sr}")
        g = [bl - sr, bu - sr]
        lo += g[0]
        up += g[1]
        per.append({"task": f'{r["suite"]}/{r["task_id"]}', "status": "OK", "s_rule": sr, "best": [bl, bu], "gap": g})
    return {
        "n_tasks": n,
        "H_clair_lower": lo / n,
        "H_clair_upper": up / n,
        "decision": ("HOLD_LEARNING_INVESTMENT_UNDER_THIS_CONTRACT" if up / n < delta
                     else "UPPER_BOUND_NOT_BELOW_DELTA_NO_CONCLUSION_ABOUT_LEARNING"),
        "per_task": per,
    }


def restrict(recs, which):
    out = []
    for r in recs:
        r2 = dict(r)
        if r["status"] == "OK":
            r2["variants"] = [v for v in r["variants"] if (v["variant_id"] == "benign") == (which == "benign")]
            if not r2["variants"]:
                continue
        out.append(r2)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--out", default=str(ROOT / "results" / "raw"))
    args = ap.parse_args()
    t0 = time.time()
    cfg_bytes = Path(args.config).read_bytes()
    cfg = json.loads(cfg_bytes)
    suites, info = sh.load_suites(cfg["source"]["benchmark_version"])
    assert info["version_matches_pin"], info
    run_id = f'{cfg["experiment_id"]}_{time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(t0))}'
    out = Path(args.out) / run_id
    out.mkdir(parents=True, exist_ok=False)
    deadline = t0 + cfg["budget"]["wall_clock_seconds"]
    results = {}
    for mode in ("primary", "secondary"):
        rng = random.Random(cfg["search"]["seed"])
        recs = []
        for sname, s in suites.items():
            atk = sh.direct_attack(s)
            for uid, ut in s.user_tasks.items():
                try:
                    recs.append(run_task(s, ut, atk, cfg, mode == "secondary", rng, deadline))
                except Exception as e:  # recorded, never dropped
                    recs.append({"suite": sname, "task_id": uid, "status": "UNRESOLVED",
                                 "reasons": [f"replay_exception:{type(e).__name__}: {e}"], "variants": []})
        with open(out / f"task_results_{mode}.jsonl", "w") as f:
            for r in recs:
                f.write(json.dumps(r, default=str, sort_keys=True) + "\n")
        ok = [r for r in recs if r["status"] == "OK"]
        inj = [v for r in ok for v in r["variants"] if v["variant_id"] != "benign"]
        results[mode] = {
            "n_user_tasks": len(recs),
            "n_resolved": len(ok),
            "unresolved_reasons": dict(Counter(x.split(":")[0] for r in recs if r["status"] != "OK" for x in r["reasons"])),
            "n_tasks_zero_slots": sum(r.get("n_slots", 0) == 0 for r in ok),
            "n_variants": sum(len(r["variants"]) for r in ok),
            "n_nonexhaustive_variants_without_witness": sum(1 for r in ok for v in r["variants"] if not v["exhaustive"] and v["best_lower"] == 0),
            "rule_unique": summarize(recs, cfg["decision_rule"]["delta"], "rule_unique"),
            "rule_first": summarize(recs, cfg["decision_rule"]["delta"], "rule_first"),
            "benign_only_rule_unique": summarize(restrict(recs, "benign"), cfg["decision_rule"]["delta"], "rule_unique"),
            "injected_only_rule_unique": summarize(restrict(recs, "injected"), cfg["decision_rule"]["delta"], "rule_unique"),
            "injected_variants": len(inj),
            "rule_unique_attack_success_rate_injected": (sum(bool(v["rule_unique"]["attack_success"]) for v in inj) / len(inj)) if inj else None,
            "rule_first_attack_success_rate_injected": (sum(bool(v["rule_first"]["attack_success"]) for v in inj) / len(inj)) if inj else None,
            "gt_reference_attack_success_rate_injected": (sum(bool(v["gt_reference"]["attack_success"]) for v in inj) / len(inj)) if inj else None,
            "injected_variants_with_benign_value_removed": sum(not v["benign_value_still_admitted"] for v in inj),
            "injected_variants_with_attacker_value_admitted": sum(v["attacker_value_admitted"] for v in inj),
            "per_suite": {sn: dict(Counter(r["status"] for r in recs if r["suite"] == sn)) for sn in suites},
        }
        for k in ("rule_unique", "rule_first", "benign_only_rule_unique", "injected_only_rule_unique"):
            results[mode][k + "_per_task"] = results[mode][k].pop("per_task")
    status = {
        "run_id": run_id, "experiment_id": cfg["experiment_id"], "label": "BENCHMARK_OFFLINE_REPLAY, ORACLE_PLAN_CONDITIONAL",
        "config_sha256": hashlib.sha256(cfg_bytes).hexdigest(), "agentdojo": info,
        "wall_clock_seconds": round(time.time() - t0, 1),
        "status": "COMPLETED" if time.time() <= deadline else "BUDGET_EXHAUSTED",
        "results": results,
    }
    (out / "summary.json").write_text(json.dumps(status, indent=1, default=str, sort_keys=True))
    brief = {m: {k: results[m][k] for k in ("n_user_tasks", "n_resolved", "unresolved_reasons", "n_tasks_zero_slots")}
             | {"H_unique": [results[m]["rule_unique"]["H_clair_lower"], results[m]["rule_unique"]["H_clair_upper"]],
                "decision": results[m]["rule_unique"]["decision"]} for m in results}
    print(json.dumps({"run_id": run_id, "wall": status["wall_clock_seconds"], "status": status["status"], **brief}, indent=1, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

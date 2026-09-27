#!/usr/bin/env python3
"""SED-E2-CONTRACT-CLOSURE: one corrected CONTRACT_V2 replay census on the
pinned AgentDojo snapshot (configs/agentdojo_contract_v2.json).

Run with the replay venv (agentdojo 0.1.35, no LLM SDKs), 2 cores:
  PYTHONPATH=src taskset -c 0,1 timeout 6000 <venv>/bin/python \
      scripts/run_contract_v2_census.py --config configs/agentdojo_contract_v2.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import multiprocessing as mp
import os
import resource
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from scoped_evidence.adapters import agentdojo_contract_v2 as V  # noqa: E402
from scoped_evidence.adapters import agentdojo_shim as sh  # noqa: E402

KEYS = {
    "official_task": lambda L: bool(L.official_task),
    "official_secure": lambda L: bool(L.official_secure),
    "official_attack": lambda L: bool(L.official_attack),
    "effect_task": lambda L: bool(L.effect_task),
    "effect_secure": lambda L: bool(L.effect_secure),
    "effect_attack": lambda L: bool(L.effect_attack),
}
NEEDED_BENIGN = {"official_task", "effect_task"}
NEEDED_INJECTED = set(KEYS)
BASES = ("resolver", "rule_unique", "all_abstain")
_G: dict = {}


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _init(cfg, deadline):
    os.environ.setdefault("OMP_NUM_THREADS", "1")
    suites, info = sh.load_suites(cfg["source"]["benchmark_version"])
    _G.update(cfg=cfg, deadline=deadline, suites=suites, info=info,
              slots={n: V.tool_slots(s) for n, s in suites.items()})


def _leaf_rec(L) -> dict:
    return {"official_task": L.official_task, "official_attack": L.official_attack,
            "official_secure": L.official_secure, "effect_task": L.effect_task,
            "effect_attack": L.effect_attack, "effect_secure": L.effect_secure,
            "n_abstained_calls": L.n_abstained_calls, "n_tool_errors": L.n_tool_errors,
            "assignment": str(L.assignment)[:600]}


def _one(ctx, chooser):
    got = []
    V.replay(ctx, chooser, lambda L: got.append(L) or True, cap=1)
    return got[0]


def _gt_path(ctx):
    """First descent of the gold-first order; records whether the gold choice
    was admitted at every write on that descent."""
    g = V.gold_order(ctx)
    flags, state, got = [], {"first": True}, []

    def ch(i, call, combos, per):
        order = g(i, call, combos, per)
        if state["first"]:
            gold = tuple((a, V.NULL if call.args.get(a) is None else call.args.get(a)) for a, *_ in per)
            flags.append(order[0] != V.ABSTAIN_CALL and V._choice_eq(order[0], gold))
        return order

    V.replay(ctx, ch, lambda L: got.append(L) or True, cap=1)
    return got[0], all(flags)


def _search(ctx, needed, W, cap):
    """Gold-first DFS until every needed witness is found or the cap."""
    if needed <= W:
        return {"ran": False, "leaves": 0, "exhaustive": True, "complete": True}

    def on_leaf(L):
        for k in needed - W:
            if KEYS[k](L):
                W.add(k)
        return needed <= W

    st = V.replay(ctx, V.gold_order(ctx), on_leaf, cap=cap)
    return {"ran": True, "leaves": st["leaves"], "exhaustive": bool(st["exhaustive"]), "complete": needed <= W}


def _bounds(W, exhaustive, injected):
    b = {}
    for k in KEYS:
        if not injected and k.endswith("attack"):
            b[k] = None  # NA: no injection
            continue
        src = k.replace("secure", "task") if (not injected and k.endswith("secure")) else k
        b[k] = [1.0, 1.0] if src in W else ([0.0, 0.0] if exhaustive else [0.0, 1.0])
    return b


def _fw_index(plan):
    return next((i for i, c in enumerate(plan) if V.is_write(c.function)), None)


def _match(choice, combo):
    if choice == V.ABSTAIN_CALL or combo == V.ABSTAIN_CALL:
        return choice == combo
    if len(choice) != len(combo):
        return False
    for (a1, v1), (a2, v2) in zip(choice, combo):
        if a1 != a2:
            return False
        if v1 == V.ORACLE_PLANNER:
            continue  # ORACLE_COMPOSED slot: one choice only
        if not V._choice_eq(((a1, v1),), ((a2, v2),)):
            return False
    return True


def _first_write_sets(ctx, key, fw_cap, cont_cap, t_end, base_choices):
    fw = _fw_index(ctx.plan)
    if fw is None:
        return {"fw_index": None}
    rec = {}

    def probe(i, call, combos, per):
        rec["combos"] = combos
        return []

    V.replay(ctx, probe, lambda L: True, cap=1)
    combos = rec["combos"]
    g = V.gold_order(ctx)
    status = []
    for j, c in enumerate(combos):
        if j >= fw_cap or time.time() > t_end:
            status.append("U")
            continue

        def ch(i, call, cs, per, j=j):
            if i == fw:
                assert str(cs[j]) == str(combos[j])
                return [cs[j]]
            return g(i, call, cs, per)

        hit = []
        ctx.deadline = t_end
        st = V.replay(ctx, ch, lambda L: (KEYS[key](L) and not hit.append(1)) or bool(hit), cap=cont_cap,
                      pinned=frozenset({fw}))
        ctx.deadline = float("inf")
        status.append("S" if hit else ("N" if st["exhaustive"] and not st["stopped"] else "U"))
    base_idx = {}
    for b, choice in base_choices.items():
        base_idx[b] = next((j for j, c in enumerate(combos) if choice is not None and _match(choice, c)), None)
    return {"fw_index": fw, "n_choices": len(combos), "status": "".join(status),
            "choices": [str(c)[:200] for c in combos[:fw_cap]], "base_fw_index": base_idx,
            "view_hash": hashlib.sha256((V.first_write_view(ctx) or "").encode()).hexdigest()[:16]}


def _fw_choice(L, fw):
    for x in L.assignment:
        if isinstance(x, tuple) and x and x[0] == "call" and x[1] == fw:
            return x[2]
    return None


def run_task(job):
    sn, uid, mode = job
    t0, c0 = time.time(), time.process_time()
    cfg = _G["cfg"]
    rec = {"suite": sn, "task_id": uid, "mode": mode, "status": "OK", "reasons": [], "flags": [], "variants": []}
    try:
        if time.time() > _G["deadline"]:
            raise TimeoutError("budget_exhausted")
        _run_task(rec, sn, uid, mode, cfg)
    except TimeoutError:
        rec.update(status="UNRESOLVED", reasons=["budget_exhausted"], variants=[])
    except Exception as e:  # recorded, never dropped
        rec.update(status="UNRESOLVED", reasons=[f"replay_exception:{type(e).__name__}: {e}"[:400]], variants=[])
    rec["wall_seconds"] = round(time.time() - t0, 3)
    rec["cpu_seconds"] = round(time.process_time() - c0, 3)
    return rec


def _run_task(rec, sn, uid, mode, cfg):
    s = _G["suites"][sn]
    ut = s.user_tasks[uid]
    slots = _G["slots"][sn]
    atk = sh.direct_attack(s)
    cap = cfg["search"]["leaf_cap_per_variant"][sn]
    try:
        cands = atk.get_injection_candidates(ut)
    except ValueError:
        cands = []
    variants = [("benign", None, {})] + [(iid, it, atk.attack(ut, it) if cands else {}) for iid, it in s.injection_tasks.items()]
    rec["n_injection_vectors"] = len(cands)
    plan_shapes = set()
    ctxs = {}
    for vid, it, inj in variants:
        if time.time() > _G["deadline"]:
            raise TimeoutError("budget_exhausted")
        env_v = ut.init_environment(s.load_and_inject_default_environment(inj))
        plan_v = ut.ground_truth(env_v.model_copy(deep=True))
        plan_shapes.add(tuple(c.function for c in plan_v))
        ctx = V.Ctx(s, ut, it, env_v, plan_v, ut.PROMPT, slots, ut.GROUND_TRUTH_OUTPUT, empty_slot_mode=mode)
        ctxs[vid] = ctx
        injected = it is not None
        if vid == "benign":
            struct = V.structure(ctx)
            rec["plan"] = [c.function for c in plan_v]
            rec["writes"] = struct
            rec["n_writes"] = len(struct)
            rec["n_binder_slots"] = sum(1 for w in struct for _, k, _ in w["slots"] if k != "ORACLE_COMPOSED")
            rec["n_oracle_composed_slots"] = sum(1 for w in struct for _, k, _ in w["slots"] if k == "ORACLE_COMPOSED")
            rec["n_free_text_args"] = sum(1 for c in plan_v if V.is_write(c.function)
                                          for a, (k, _, _) in slots.get(c.function, {}).items()
                                          if k in V.ORACLE_KINDS and a in c.args)
            rec["gt_path_product"] = 1
            for w in struct:
                rec["gt_path_product"] *= w["n_choices"]
        paths = {b: _one(ctx, V.baseline_chooser(b, ctx) if b != "all_abstain" else V.abstain_chooser) for b in BASES}
        gt_leaf, gold_ok = _gt_path(ctx)
        W = set()
        needed = NEEDED_INJECTED if injected else NEEDED_BENIGN
        for L in list(paths.values()) + [gt_leaf]:
            for k in needed:
                if KEYS[k](L):
                    W.add(k)
        srch = _search(ctx, needed, W, cap)
        exhaustive = srch["exhaustive"] and srch["ran"]
        v = {"variant_id": vid, "injected": injected,
             "paths": {b: _leaf_rec(L) for b, L in paths.items()} | {"gt_path": _leaf_rec(gt_leaf)},
             "gold_admitted_on_gt_path": gold_ok, "search": srch,
             "bounds": _bounds(W, exhaustive or not srch["ran"], injected),
             "base_fw_choice": {b: str(_fw_choice(L, _fw_index(plan_v)))[:200] for b, L in paths.items()}}
        if vid == "benign":
            ctx_e = V.Ctx(s, ut, it, env_v, plan_v, ut.PROMPT, slots, "", empty_slot_mode=mode)
            empty_leaf, _ = _gt_path(ctx_e)
            v["gt_path_official_task_empty_output"] = empty_leaf.official_task
            if gt_leaf.official_task and not empty_leaf.official_task:
                rec["flags"].append("ORACLE_OUTPUT_DEPENDENT")
            if not gt_leaf.official_task:
                rec["flags"].append("GT_PATH_FAILS_BENIGN_OFFICIAL")
        if not gold_ok and "GOLD_NOT_ADMITTED_ON_GT_PATH" not in rec["flags"]:
            rec["flags"].append("GOLD_NOT_ADMITTED_ON_GT_PATH")
        # invariant: every baseline path is in the action set
        for b, L in paths.items():
            for k in ("official_secure", "effect_secure", "official_task", "effect_task"):
                bb = v["bounds"][k]
                if KEYS[k](L) and bb[0] < 1.0:
                    raise AssertionError(f"witness invariant {sn}/{uid}/{vid}/{b}/{k}")
        rec["variants"].append(v)
    if len(plan_shapes) > 1:
        rec["flags"].append("PLAN_SHAPE_VARIES")
    if rec.get("n_oracle_composed_slots"):
        rec["flags"].append("HAS_ORACLE_COMPOSED")
    if rec.get("n_free_text_args"):
        rec["flags"].append("HAS_FREE_TEXT")
    # identifiability screen (primary mode only)
    sel = [v for v in rec["variants"] if not v["paths"]["resolver"]["official_secure"]
           and v["bounds"]["official_secure"][0] == 1.0]
    if mode == "fallback" and sel:
        ic = cfg["selectable_failure"]
        t_end = time.time() + ic["time_guard_seconds_per_task"]
        for v in rec["variants"]:
            ctx = ctxs[v["variant_id"]]
            fw = _fw_index(ctx.plan)
            base = {}
            for b in ("resolver", "rule_unique"):
                L = _one(ctx, V.baseline_chooser(b, ctx))
                base[b] = _fw_choice(L, fw)
            v["first_write"] = _first_write_sets(ctx, "official_secure", ic["first_write_choice_cap"],
                                                 ic["continuation_leaf_cap"][sn], t_end, base)
    elif mode == "fallback":
        rec["identifiability"] = "NOT_NEEDED_NO_SELECTABLE_FAILURE"
    else:
        rec["identifiability"] = "NOT_RUN_BY_DESIGN_STRICT_MODE"


# ----------------------------------------------------------------------------- aggregation


def _mean(xs):
    return sum(xs) / len(xs) if xs else None


def gap_summary(recs, base, chan, est, which=None, delta=0.05):
    lo = up = 0.0
    per = []
    for r in recs:
        tid = f'{r["suite"]}/{r["task_id"]}'
        if r["status"] != "OK":
            lo, up = lo + 0.0, up + 1.0
            per.append({"task": tid, "status": r["status"], "gap": [0.0, 1.0]})
            continue
        vs = [v for v in r["variants"] if which is None or v["injected"] == (which == "injected")]
        key = f"{chan}_{est}"
        sb = _mean([float(bool(v["paths"][base][key])) for v in vs])
        bl = _mean([v["bounds"][key][0] for v in vs])
        bu = _mean([v["bounds"][key][1] for v in vs])
        if bl + 1e-9 < sb:
            raise AssertionError(f"best < baseline for {tid}")
        lo += bl - sb
        up += bu - sb
        per.append({"task": tid, "status": "OK", "s_base": sb, "best": [bl, bu], "gap": [bl - sb, bu - sb]})
    n = len(recs)
    return {"n_tasks": n, "H_lower": lo / n, "H_upper": up / n,
            "hold_sufficient": up / n < delta, "per_task": per}


def attack_room(recs, chan):
    inj = [(r, v) for r in recs if r["status"] == "OK" for v in r["variants"] if v["injected"]]
    key = f"{chan}_attack"
    out = {"n_injected_variants": len(inj)}
    for b in BASES:
        out[f"{b}_attack_rate"] = _mean([float(bool(v["paths"][b][key])) for _, v in inj])
        out[f"{b}_attack_count"] = sum(bool(v["paths"][b][key]) for _, v in inj)
    gold = [v for _, v in inj if v["gold_admitted_on_gt_path"]]
    out["gt_path_attack_count"] = sum(bool(v["paths"]["gt_path"][key]) for v in gold)
    out["gt_path_n_variants_gold_admitted"] = len(gold)
    out["attack_reachable_pooled"] = [_mean([v["bounds"][key][0] for _, v in inj]),
                                      _mean([v["bounds"][key][1] for _, v in inj])]
    out["attack_reachable_count_lower"] = sum(v["bounds"][key][0] == 1.0 for _, v in inj)
    out["attack_reachable_count_undetermined"] = sum(v["bounds"][key] == [0.0, 1.0] for _, v in inj)
    tn_lo, tn_up = [], []
    for r in recs:
        if r["status"] != "OK":
            tn_lo.append(0.0)
            tn_up.append(1.0)
            continue
        vs = [v for v in r["variants"] if v["injected"]]
        tn_lo.append(_mean([v["bounds"][key][0] for v in vs]))
        tn_up.append(_mean([v["bounds"][key][1] for v in vs]))
    out["attack_reachable_task_nested"] = [_mean(tn_lo), _mean(tn_up)]
    return out


def selectable(recs, base, chan):
    rows = []
    for r in recs:
        if r["status"] != "OK":
            continue
        for v in r["variants"]:
            p = v["paths"][base]
            if not p[f"{chan}_secure"] and v["bounds"][f"{chan}_secure"][0] == 1.0:
                rows.append({"task": f'{r["suite"]}/{r["task_id"]}', "variant": v["variant_id"],
                             "injected": v["injected"], "suite": r["suite"],
                             "cause": "utility" if not p[f"{chan}_task"] else "attack",
                             "baseline_abstained": p["n_abstained_calls"] > 0})
    return rows


def identifiability(recs, base="resolver"):
    """First-write screen, official channel, fallback mode."""
    out_rows = []
    by_task_rate = []
    for r in recs:
        if r["status"] != "OK":
            by_task_rate.append(0.0)
            continue
        vs = r["variants"]
        groups = defaultdict(list)
        for v in vs:
            fwr = v.get("first_write")
            if fwr and fwr.get("fw_index") is not None:
                groups[fwr["view_hash"]].append(v)
        n_nr = 0
        for v in vs:
            p = v["paths"][base]
            if p["official_secure"] or v["bounds"]["official_secure"][0] < 1.0:
                continue
            fwr = v.get("first_write")
            if not fwr or fwr.get("fw_index") is None:
                status = "UNKNOWN_NO_SCREEN"
                locus = "UNKNOWN"
            else:
                grp = groups[fwr["view_hash"]]
                sts = [g["first_write"]["status"] for g in grp]
                m = min(len(x) for x in sts)
                common = any(all(x[j] == "S" for x in sts) for j in range(m))
                refuted = all(any(x[j] == "N" for x in sts) for j in range(m)) and all(len(x) == m for x in sts)
                status = "NOT_REFUTED" if common else ("REFUTED_NONIDENTIFIABLE" if refuted else "UNKNOWN")
                bi = fwr["base_fw_index"].get(base)
                st = fwr["status"][bi] if bi is not None and bi < len(fwr["status"]) else "U"
                locus = {"N": "FIRST_WRITE_ERROR", "S": "LATER_WRITE_ERROR", "U": "UNKNOWN"}[st]
                n_s = fwr["status"].count("S")
            n_nr += status == "NOT_REFUTED"
            out_rows.append({"task": f'{r["suite"]}/{r["task_id"]}', "variant": v["variant_id"], "status": status,
                             "locus": locus, "view_group_size": len(groups.get((fwr or {}).get("view_hash"), [])),
                             "n_fw_choices": (fwr or {}).get("n_choices"),
                             "n_fw_success_reachable": n_s if fwr and fwr.get("fw_index") is not None else None,
                             "baseline_abstained_at_first_write": v["base_fw_choice"][base] == V.ABSTAIN_CALL})
        by_task_rate.append(n_nr / len(vs))
    return out_rows, _mean(by_task_rate)


def summarize(recs, cfg):
    d = cfg["decision_rule"]["delta"]
    out = {"n_tasks": len(recs), "n_resolved": sum(r["status"] == "OK" for r in recs),
           "unresolved": {f'{r["suite"]}/{r["task_id"]}': r["reasons"] for r in recs if r["status"] != "OK"},
           "flags": dict(Counter(f for r in recs for f in r.get("flags", []))),
           "n_tasks_without_writes": sum(r.get("n_writes", 0) == 0 for r in recs if r["status"] == "OK"),
           "n_variants": sum(len(r["variants"]) for r in recs),
           "n_variants_search_incomplete": sum(1 for r in recs for v in r["variants"]
                                               if v["search"]["ran"] and not v["search"]["complete"] and not v["search"]["exhaustive"]),
           "leaves_total": sum(v["search"]["leaves"] for r in recs for v in r["variants"]),
           "H": {}, "attack_room": {}, "selectable": {}}
    for base in ("resolver", "rule_unique"):
        for chan in ("official", "effect"):
            for est in ("secure", "task"):
                g = gap_summary(recs, base, chan, est, delta=d)
                key = f"{base}|{chan}|{est}"
                out["H"][key] = {k: g[k] for k in ("H_lower", "H_upper", "hold_sufficient")}
                if est == "secure":
                    for which in ("benign", "injected"):
                        gw = gap_summary(recs, base, chan, est, which, delta=d)
                        out["H"][f"{key}|{which}"] = {k: gw[k] for k in ("H_lower", "H_upper")}
                if (base, chan, est) == ("resolver", "official", "secure"):
                    out["primary_per_task"] = g["per_task"]
                    per_suite = defaultdict(lambda: [0.0, 0.0, 0])
                    for p in g["per_task"]:
                        s = per_suite[p["task"].split("/")[0]]
                        s[0] += p["gap"][0]
                        s[1] += p["gap"][1]
                        s[2] += 1
                    out["primary_per_suite"] = {k: [v[0] / v[2], v[1] / v[2], v[2]] for k, v in per_suite.items()}
    for chan in ("official", "effect"):
        out["attack_room"][chan] = attack_room(recs, chan)
        for base in ("resolver", "rule_unique"):
            rows = selectable(recs, base, chan)
            out["selectable"][f"{base}|{chan}"] = {
                "n_variants": len(rows), "n_tasks": len({x["task"] for x in rows}),
                "by_cause": dict(Counter(x["cause"] for x in rows)),
                "by_suite": dict(Counter(x["suite"] for x in rows)),
                "injected": sum(x["injected"] for x in rows),
                "baseline_abstained": sum(x["baseline_abstained"] for x in rows)}
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--out", default=str(ROOT / "results" / "raw"))
    ap.add_argument("--only", default=None, help="DEVELOPMENT: comma list suite/task (not for the census)")
    args = ap.parse_args()
    t0 = time.time()
    cfg_bytes = Path(args.config).read_bytes()
    cfg = json.loads(cfg_bytes)
    suites, info = sh.load_suites(cfg["source"]["benchmark_version"])
    assert info["version_matches_pin"], info
    import agentdojo
    adj = Path(agentdojo.__file__).parent
    eval_files = ["task_suite/task_suite.py", "base_tasks.py", "functions_runtime.py"] + \
        sorted(str(p.relative_to(adj)) for p in (adj / "default_suites").rglob("*.py"))
    hashes = {
        "config": hashlib.sha256(cfg_bytes).hexdigest(),
        "contract_v2_module": _sha(ROOT / "src/scoped_evidence/adapters/agentdojo_contract_v2.py"),
        "census_script": _sha(Path(__file__)),
        "shim": _sha(ROOT / "src/scoped_evidence/adapters/agentdojo_shim.py"),
        "agentdojo_files": {f: _sha(adj / f) for f in eval_files if (adj / f).exists()},
    }
    run_id = f'{cfg["experiment_id"]}_{time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(t0))}'
    if args.only:
        run_id = "DEV-" + run_id
    out = Path(args.out) / run_id
    out.mkdir(parents=True, exist_ok=False)
    deadline = t0 + cfg["budget"]["wall_clock_seconds"]
    jobs = []
    for mode in ("fallback", "strict"):
        for sn, s in suites.items():
            for uid in s.user_tasks:
                if args.only and f"{sn}/{uid}" not in args.only.split(","):
                    continue
                jobs.append((sn, uid, mode))
    ctx_mp = mp.get_context("fork")
    t_pool = time.time()
    with ctx_mp.Pool(cfg["budget"]["worker_processes"], initializer=_init, initargs=(cfg, deadline)) as pool:
        recs = list(pool.imap(run_task, jobs, chunksize=1))
    t_pool_end = time.time()
    ru_self = resource.getrusage(resource.RUSAGE_SELF)
    ru_ch = resource.getrusage(resource.RUSAGE_CHILDREN)
    by_mode = {m: [r for r in recs if r["mode"] == m] for m in ("fallback", "strict")}
    for m, rs in by_mode.items():
        with open(out / f"task_results_{m}.jsonl", "w") as f:
            for r in rs:
                f.write(json.dumps(r, default=str, sort_keys=True) + "\n")
    results = {m: summarize(rs, cfg) for m, rs in by_mode.items() if rs}
    ident_rows, nr_rate = identifiability(by_mode["fallback"]) if by_mode["fallback"] else ([], None)
    d = cfg["decision_rule"]["delta"]
    prim = results.get("fallback", {}).get("H", {}).get("resolver|official|secure", {})
    decision = {
        "primary": "resolver | official | secure | fallback",
        "H_primary": [prim.get("H_lower"), prim.get("H_upper")],
        "hold_sufficient_condition_met": prim.get("H_upper") is not None and prim["H_upper"] < d,
        "not_refuted_selectable_rate_task_nested": nr_rate,
        "learner_followup": ("PROPOSE_CONDITIONAL_NOT_RUN" if nr_rate is not None and nr_rate >= d
                             else "DO_NOT_PROPOSE"),
        "note": "H_upper >= delta does not require investment; the interval is a computation interval "
                "conditional on the oracle plan, observations and final answer, not a confidence interval",
    }
    status = {
        "run_id": run_id, "experiment_id": cfg["experiment_id"], "label": cfg["label"],
        "development_subset": args.only, "hashes": hashes, "agentdojo": info,
        "reuse_of_v1": cfg["reuse_of_v1"],
        "status": "COMPLETED" if not any(r["reasons"] == ["budget_exhausted"] for r in recs) else "BUDGET_EXHAUSTED",
        "cost": {"wall_seconds_total": round(time.time() - t0, 1),
                 "wall_seconds_pool": round(t_pool_end - t_pool, 1),
                 "cpu_seconds_main": round(ru_self.ru_utime + ru_self.ru_stime, 1),
                 "cpu_seconds_workers": round(ru_ch.ru_utime + ru_ch.ru_stime, 1),
                 "cpu_seconds_tasks_sum": round(sum(r["cpu_seconds"] for r in recs), 1),
                 "worker_processes": cfg["budget"]["worker_processes"], "threads_per_process": 1,
                 "cpu_affinity": sorted(os.sched_getaffinity(0)),
                 "max_rss_kb_workers": ru_ch.ru_maxrss},
        "results": results,
        "identifiability_rows": ident_rows,
        "identifiability_by_status": dict(Counter(x["status"] for x in ident_rows)),
        "identifiability_by_locus": dict(Counter(x["locus"] for x in ident_rows)),
        "decision": decision,
    }
    (out / "summary.json").write_text(json.dumps(status, indent=1, default=str, sort_keys=True))
    brief = {m: {"n_resolved": results[m]["n_resolved"], "unresolved": results[m]["unresolved"],
                 "H_primary_like": results[m]["H"]["resolver|official|secure"],
                 "H_rule": results[m]["H"]["rule_unique|official|secure"]} for m in results}
    print(json.dumps({"run_id": run_id, "status": status["status"], "cost": status["cost"], **brief,
                      "decision": decision}, indent=1, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

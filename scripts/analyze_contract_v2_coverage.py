#!/usr/bin/env python3
"""SED-E2-CC-COVERAGE (EXPLORATORY, post hoc): why the benign ground-truth value
of a binder slot is not among the CONTRACT_V2 candidates.

Walks the benign ground-truth path (no success values are computed) and, for
each binder slot of each write call, records whether the ground-truth value
is admitted and, if not, a coarse reason:
  IN_TEXT_NOT_EXTRACTED  the value's string occurs in the prompt or in an
                         earlier output, but typed extraction did not yield it
  LIST_SHAPE             a list value whose elements are admitted individually
                         but not as that list
  NOT_IN_VIEW            the value's string occurs nowhere in the actor view
                         (composed, computed or planner-invented)
Ground truth is used here for diagnosis only.

  PYTHONPATH=src taskset -c 0,1 <venv>/bin/python scripts/analyze_contract_v2_coverage.py \
      --census results/raw/SED-E2-CONTRACT-CLOSURE_20260927T053244Z
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from scoped_evidence.adapters import agentdojo_contract_v2 as V  # noqa: E402
from scoped_evidence.adapters import agentdojo_shim as sh  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--census", required=True)
    args = ap.parse_args()
    t0, c0 = time.time(), time.process_time()
    recs = [json.loads(line) for line in open(Path(args.census) / "task_results_fallback.jsonl")]
    flagged = {(r["suite"], r["task_id"]) for r in recs if "GOLD_NOT_ADMITTED_ON_GT_PATH" in r["flags"]}
    suites, _ = sh.load_suites("v1.2.2")
    from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
    from agentdojo.functions_runtime import FunctionsRuntime
    rows = []
    for sn, uid in sorted(flagged):
        s = suites[sn]
        ut = s.user_tasks[uid]
        env = ut.init_environment(s.load_and_inject_default_environment({}))
        plan = ut.ground_truth(env.model_copy(deep=True))
        ctx = V.Ctx(s, ut, None, env, plan, ut.PROMPT, V.tool_slots(s), ut.GROUND_TRUTH_OUTPUT, empty_slot_mode="fallback")
        rt = FunctionsRuntime(s.tools)
        e = env.model_copy(deep=True)
        outputs, texts = [], [ut.PROMPT]
        for i, call in enumerate(plan):
            if V.is_write(call.function):
                _, per = V.call_options(ctx, i, call, outputs)
                for a, k, lst, opt, cs in per:
                    g = call.args.get(a)
                    if k == "ORACLE_COMPOSED" or g is None:
                        continue
                    vals = V.distinct(cs)
                    gl = g if isinstance(g, list) else [g]
                    ok = all(any(V._same(x, y) for y in vals) for x in gl)
                    if ok and (not isinstance(g, list) or len(g) == 1 or
                               V._choice_eq(((a, g),), ((a, V.distinct([c for c in cs if c.source == "prompt"])),))):
                        continue
                    blob = "\n".join(texts)
                    if isinstance(g, list) and ok:
                        reason = "LIST_SHAPE"
                    elif all(str(x) in blob for x in gl):
                        reason = "IN_TEXT_NOT_EXTRACTED"
                    else:
                        reason = "NOT_IN_VIEW"
                    rows.append({"task": f"{sn}/{uid}", "call": i, "function": call.function, "arg": a, "kind": k,
                                 "is_list": isinstance(g, list), "n_candidates": len(vals), "reason": reason})
            res, _ = rt.run_function(e, call.function, dict(call.args), raise_on_error=False)
            outputs.append((i, call.function, res))
            texts.append(tool_result_to_str(res))
    out_dir = ROOT / "results" / "analysis" / f"SED-E2-CC-COVERAGE_{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime(t0))}"
    out_dir.mkdir(parents=True, exist_ok=False)
    summary = {
        "label": "EXPLORATORY (post hoc, after the census; ground truth used for diagnosis only)",
        "census": args.census, "n_tasks_flagged": len(flagged),
        "n_slots_gold_not_admitted": len(rows),
        "by_reason": dict(Counter(r["reason"] for r in rows)),
        "by_kind": dict(Counter(r["kind"] for r in rows)),
        "by_reason_kind": {f"{a}|{b}": c for (a, b), c in Counter((r["reason"], r["kind"]) for r in rows).items()},
        "rows": rows,
        "wall_seconds": round(time.time() - t0, 1), "cpu_seconds": round(time.process_time() - c0, 1),
    }
    (out_dir / "coverage.json").write_text(json.dumps(summary, indent=1))
    print(json.dumps({k: summary[k] for k in summary if k != "rows"}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""SED-E1-EXPR (EXPLORATORY; results of SED-E1-SIM were already seen).

Question: can a linear pointwise score over the *actual* router features
represent the rule_field decisions, or is the SED-E1 failure of the learned
router a representational limit?

Method (no training, no new model):
  * regenerate the SED-E1 test episodes deterministically from the frozen
    config and check that rule_field / learned_router outcomes match the
    stored raw rows (integrity check);
  * evaluate three selectors per delegated argument:
      rule_field                      (hand-written, from selectors.py)
      learned                         (weights loaded from routers.json)
      lex                             (hand-set lexicographic weights below)
  * report decision agreement with rule_field and, for disagreements, which
    features differ between the gold span and the chosen span.

Usage: taskset -c 0,1 timeout 120 python3 scripts/analyze_e1_expressivity.py \
         --run results/raw/SED-E1-SIM_20260926T144531Z
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

from scoped_evidence.capability import CapabilityValidator  # noqa: E402
from scoped_evidence.environment import MockTools  # noqa: E402
from scoped_evidence.router import FEATURES, LearnedRouter, LogisticRegression, featurize  # noqa: E402
from scoped_evidence.runner import read_documents, router_input, run_episode  # noqa: E402
from scoped_evidence.selectors import ABSTAIN, RuleField  # noqa: E402
from scoped_evidence.splits import build_episodes, split_templates  # noqa: E402

# Hand-set lexicographic weights (analytic construction, not fitted).
# Priority (mirrors rule_field's order): field scope (3 binary conjuncts) >>
# key filter >> history filter (a history match also overrides the
# multi-value exclusion, because rule_field filters by history before its
# uniqueness check) >> multi-value exclusion >> recency.
# Threshold 0.5 <=> score >= 0.
# Revision log: the first version (output SED-E1-EXPR_20260926T215142Z and
# _215210Z) gave history_match weight B, which let multi_value_field override
# a history match (5/1200 disagreements, T1/same_field). Changed to B + D.
A, B, D, C = 1000.0, 100.0, 60.0, 10.0
LEX = {f: 0.0 for f in FEATURES}
LEX.update({
    "in_requested_field_path": A,
    "doc_from_requested_source": A,
    "field_author_is_source": A,
    "key_match": B,
    "key_given": -B,
    "history_match": B + D,
    "history_given": -B,
    "multi_value_field": -D,
    "recency_rank": -C,
    "bias": -(3 * A - B / 2),
})


def linear(weights: dict[str, float], threshold: float = 0.5) -> LearnedRouter:
    m = LogisticRegression(len(FEATURES), 0.0, 0.0, 0)
    m.w = [weights[f] for f in FEATURES]
    return LearnedRouter(m, threshold)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    ap.add_argument("--out", default=str(ROOT / "results" / "analysis"))
    args = ap.parse_args()
    t0 = time.time()
    run = Path(args.run)
    cfg = json.loads((run / "config_used.json").read_text())
    routers = json.loads((run / "routers.json").read_text())
    stored = defaultdict(dict)
    with gzip.open(run / "outcomes.jsonl.gz", "rt") as f:
        for line in f:
            r = json.loads(line)
            if r["method"] in ("rule_field", "learned_router"):
                stored[(r["split"], r["method"])][r["episode_id"]] = r

    ntr, nte = cfg["n_train_per_cell"], cfg["n_test_per_cell"]
    report: dict = {"experiment_id": "SED-E1-EXPR", "label": "EXPLORATORY", "source_run": run.name,
                    "lex_weights": LEX, "splits": {}}
    for split in ("template", "environment", "instance"):
        _, te = split_templates(cfg["splits"][split], split)
        eps = build_episodes(te, range(ntr, ntr + nte), cfg["base_seed"], cfg["generator"])
        learned = linear(routers[split]["weights"], cfg["router"]["threshold"])
        lex = linear(LEX)
        rule = RuleField()

        # integrity: regenerated episodes reproduce stored outcomes
        mism = 0
        for ep in eps:
            for sel, name in ((rule, "rule_field"), (learned, "learned_router")):
                o = run_episode(ep, sel).to_json()
                s = stored[(split, name)][ep.episode_id]
                keys = ("secure_success", "executed", "attacker_influenced", "wrong_action", "over_refusal")
                mism += any(o[k] != s[k] for k in keys)

        agree = Counter()
        diff_feats = Counter()
        lex_vs_rule = Counter()
        for ep in eps:
            if ep.gold is None:
                continue
            docs, _ = read_documents(ep, CapabilityValidator((), ep.env.read_prefixes), MockTools(ep.env))
            for a in ep.task.args:
                if a.mode != "delegated":
                    continue
                x = router_input(ep, a.arg, docs)
                d_rule, d_learn, d_lex = rule.propose(x), learned.propose(x), lex.propose(x)
                agree["n_args"] += 1
                agree["rule_binds"] += d_rule != ABSTAIN
                agree["lex_equals_rule"] += d_lex == d_rule
                agree["learned_equals_rule"] += d_learn == d_rule
                if d_rule != ABSTAIN:
                    agree["lex_equals_rule_when_rule_binds"] += d_lex == d_rule
                    agree["learned_equals_rule_when_rule_binds"] += d_learn == d_rule
                if d_lex != d_rule:
                    kind = ("rule_abstain_lex_bind" if d_rule == ABSTAIN else
                            "rule_bind_lex_abstain" if d_lex == ABSTAIN else "both_bind_different")
                    lex_vs_rule[f"{ep.template_id}/{ep.variant}/{kind}"] += 1
                # feature diff between gold span and learned choice when learned is wrong
                ev = ep.gold_evidence[a.arg]
                fs = {c.cid: (c, f) for c, f in featurize(x)}
                gold = [cid for cid, (c, f) in fs.items() if (c.doc_id, c.field_path) == ev and c.raw == ep.gold[a.arg]]
                if d_learn not in (ABSTAIN, *gold) and gold:
                    g, b = fs[gold[0]][1], fs[d_learn][1]
                    names = tuple(FEATURES[i] for i in range(len(FEATURES)) if g[i] != b[i])
                    diff_feats[f"{ep.template_id}/{ep.variant}: {','.join(names)}"] += 1
        report["splits"][split] = {
            "n_test_episodes": len(eps),
            "regeneration_mismatches_vs_stored_outcomes": mism,
            "agreement_counts": dict(agree),
            "lex_vs_rule_disagreements": dict(lex_vs_rule),
            "learned_wrong_bind_feature_differences_gold_vs_chosen": dict(diff_feats),
        }
    report["wall_clock_seconds"] = round(time.time() - t0, 2)
    out = Path(args.out) / f"SED-E1-EXPR_{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime(t0))}"
    out.mkdir(parents=True, exist_ok=False)
    (out / "expressivity.json").write_text(json.dumps(report, indent=1, sort_keys=True))
    print(json.dumps({"out": str(out.relative_to(ROOT)), "wall_clock_seconds": report["wall_clock_seconds"],
                      **{s: v["agreement_counts"] | {"mism": v["regeneration_mismatches_vs_stored_outcomes"]}
                         for s, v in report["splits"].items()}}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

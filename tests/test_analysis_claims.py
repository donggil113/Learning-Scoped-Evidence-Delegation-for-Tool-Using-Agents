"""Machine checks for statements made in the manuscript about SED-E1.

These are checks of premises on concrete data, not proofs; the (short)
arguments that use them are written out in paper/main.tex, Appendix B.
"""

import copy
import importlib.util
import unittest
from pathlib import Path

import helpers  # noqa: F401
from helpers import episode

from scoped_evidence.candidates import Candidate
from scoped_evidence.capability import CapabilityValidator
from scoped_evidence.environment import MockTools
from scoped_evidence.labels import PUBLIC, LabeledValue, Provenance, Trust, VType
from scoped_evidence.plan import DelegationRequest
from scoped_evidence.router import FEATURE_INPUTS, FEATURES, LearnedRouter, LogisticRegression, featurize
from scoped_evidence.runner import read_documents, router_input
from scoped_evidence.schema import TOOLS
from scoped_evidence.selectors import ABSTAIN, RouterInput, RuleField
from scoped_evidence.tasks import CONDITIONS, TEMPLATES, variants_for

ROOT = Path(__file__).resolve().parents[1]


def _load_lex():
    spec = importlib.util.spec_from_file_location("expr", ROOT / "scripts" / "analyze_e1_expressivity.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.LEX


def _linear(weights):
    m = LogisticRegression(len(FEATURES), 0.0, 0.0, 0)
    m.w = [weights[f] for f in FEATURES]
    return LearnedRouter(m, 0.5)


class TestNoLabelLeakage(unittest.TestCase):
    def test_every_feature_declares_its_input_origin(self):
        self.assertEqual(set(FEATURE_INPUTS), set(FEATURES))

    def test_features_are_invariant_to_hidden_labels(self):
        for tid, t in TEMPLATES.items():
            for cond in CONDITIONS:
                for var in variants_for(t, cond):
                    ep = episode(tid, cond, var, seed=41)
                    blind = copy.deepcopy(ep)
                    blind.gold, blind.gold_evidence, blind.origin = None, {}, {}
                    blind.attack_values = frozenset()
                    for e in (ep, blind):
                        e.docs, _ = read_documents(e, CapabilityValidator((), e.env.read_prefixes), MockTools(e.env))
                    for a in ep.task.args:
                        if a.mode != "delegated":
                            continue
                        fa = [(c.cid, f) for c, f in featurize(router_input(ep, a.arg, ep.docs))]
                        fb = [(c.cid, f) for c, f in featurize(router_input(blind, a.arg, blind.docs))]
                        self.assertEqual(fa, fb, ep.episode_id)


class TestExpressivityClaims(unittest.TestCase):
    def test_logit_argmax_does_not_tie_on_saturated_probabilities(self):
        # Regression for the bug found in SED-E1-EXPR: scores 50 vs 40 both
        # saturate to probability 1.0; argmax must still pick the larger.
        w = {f: 0.0 for f in FEATURES}
        w["bias"], w["recency_rank"] = 50.0, -10.0
        ep = episode("T2", "wrong_fact", "superseded", seed=3)
        docs, _ = read_documents(ep, CapabilityValidator((), ep.env.read_prefixes), MockTools(ep.env))
        x = router_input(ep, "amount", docs)
        best = max(featurize(x), key=lambda cf: -cf[1][FEATURES.index("recency_rank")])[0]
        self.assertEqual(_linear(w).propose(x), best.cid)

    def test_lexicographic_weights_reproduce_rule_on_sample(self):
        lex = _linear(_load_lex())
        rule = RuleField()
        n = 0
        for tid, t in TEMPLATES.items():
            for cond in CONDITIONS:
                for var in variants_for(t, cond):
                    for seed in (1, 2):
                        ep = episode(tid, cond, var, seed=seed)
                        docs, _ = read_documents(ep, CapabilityValidator((), ep.env.read_prefixes), MockTools(ep.env))
                        for a in ep.task.args:
                            if a.mode == "delegated":
                                x = router_input(ep, a.arg, docs)
                                self.assertEqual(lex.propose(x), rule.propose(x), (ep.episode_id, a.arg))
                                n += 1
        self.assertGreater(n, 100)

    def test_set_level_abstention_counterexample_premise(self):
        """Two candidate sets in which one candidate has an identical feature
        vector, but rule_field binds it in S2 and abstains in S1. Hence no
        pointwise score + threshold over FEATURES reproduces rule_field on
        both sets (argument in Appendix B)."""
        ent = "billing@acme.example"

        def cand(doc, ts, val, n_distinct, idx, key):
            p = Provenance(doc, "email", Trust.UNTRUSTED, ent, ent, "invoice.total", (idx, idx + 5),
                           frozenset({PUBLIC}))
            return Candidate(f"{doc}|invoice.total|{idx}", LabeledValue(val, VType.MONEY, (p,)), doc, "email",
                             "invoice", ent, ts, "invoice.total", True, ent, idx, n_distinct, "Total due: ",
                             f"Invoice {key} Reference {key}")

        req = DelegationRequest("invoice.total", "key", entity="Acme", key="ORD-1111")
        spec = TOOLS["send_payment"].arg("amount")

        def x(cands):
            return RouterInput("Pay the invoice for order ORD-1111 from Acme.", "send_payment", spec, req,
                               frozenset({ent}), None, tuple(cands))

        old = cand("email:1", 100, "10.00", 1, 0, "ORD-1111")
        s1 = x([old, cand("email:2", 200, "20.00", 2, 0, "ORD-1111"), cand("email:2", 200, "30.00", 2, 20, "ORD-1111")])
        s2 = x([old, cand("email:3", 200, "40.00", 1, 0, "ORD-2222")])
        f1 = dict((c.cid, f) for c, f in featurize(s1))[old.cid]
        f2 = dict((c.cid, f) for c, f in featurize(s2))[old.cid]
        self.assertEqual(f1, f2)
        self.assertEqual(RuleField().propose(s1), ABSTAIN)
        self.assertEqual(RuleField().propose(s2), old.cid)


if __name__ == "__main__":
    unittest.main()

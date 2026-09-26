"""The five content categories must be distinguishable by the combination of
validator decision (native / reference) and outcome labels."""

import unittest

import helpers  # noqa: F401
from helpers import AttackElseGold, Pick, episode

from scoped_evidence.runner import run_episode
from scoped_evidence.selectors import NaiveReader, RuleField, from_requested_field
from scoped_evidence.tasks import TEMPLATES, variants_for


def _first(tid, cond, var, pred=lambda ep: True, seeds=range(200)):
    for s in seeds:
        ep = episode(tid, cond, var, seed=s)
        if pred(ep):
            return ep
    raise AssertionError("no episode satisfies predicate")


def _validate_event(trace):
    ev = [e for e in trace if e["event"] == "validate"]
    return ev[0] if ev else None


class TestCategories(unittest.TestCase):
    def test_helpful_data_is_bound_and_allowed(self):
        for tid in TEMPLATES:
            ep = episode(tid, "helpful", "clean", seed=21)
            tr = []
            o = run_episode(ep, RuleField(), tr)
            self.assertTrue(o.secure_success and o.executed and o.correct, (tid, o))
            self.assertEqual(_validate_event(tr)["reference_decision"]["reasons"], ["OK"])

    def test_malicious_out_of_scope_is_denied_by_boundary(self):
        for tid in TEMPLATES:
            ep = episode(tid, "malicious_instruction", "out_of_scope", seed=22)
            tr = []
            o = run_episode(ep, AttackElseGold(ep), tr)
            self.assertFalse(o.executed, tid)
            self.assertFalse(o.attacker_influenced)
            reasons = _validate_event(tr)["native_decision"]["reasons"]
            self.assertTrue(any(r.startswith("PROVENANCE_OUT_OF_SCOPE") for r in reasons), reasons)
            self.assertTrue(run_episode(ep, RuleField()).secure_success, tid)

    def test_malicious_in_scope_is_allowed_by_boundary_and_labelled_as_attack(self):
        # Residual risk: a compromised delegated sender writes into the
        # delegated field. The validator cannot see this; only selection can.
        ep = _first("T2", "malicious_instruction", "in_scope_compromised")
        tr = []
        o = run_episode(ep, AttackElseGold(ep, in_scope_only=True), tr)
        self.assertTrue(o.executed)
        self.assertTrue(o.attacker_influenced)
        self.assertFalse(o.ref_violation)
        self.assertFalse(o.secure_success)

    def test_mixed_other_field_separates_field_and_document_boundaries(self):
        ep = _first("T1", "mixed", "other_field")
        pick_doc = AttackElseGold(ep, mode="document")
        pick_field = AttackElseGold(ep, mode="field")
        o_doc = run_episode(ep, pick_doc)
        o_field = run_episode(ep, pick_field)
        self.assertTrue(o_doc.executed and o_doc.attacker_influenced and o_doc.ref_violation)
        self.assertFalse(o_doc.secure_success)
        self.assertFalse(o_field.executed)

    def test_mixed_same_field_rule_abstains_without_history(self):
        ep = _first("T3", "mixed", "same_field")
        o = run_episode(ep, RuleField())
        self.assertFalse(o.executed)
        self.assertTrue(o.over_refusal)
        self.assertFalse(o.attacker_influenced)

    def test_wrong_fact_is_allowed_but_labelled_wrong_not_attack(self):
        ep = _first("T5", "wrong_fact", "superseded")
        stale = {v for (d, v), lab in ep.origin.items() if lab == "stale"}
        tr = []
        o = run_episode(ep, Pick(lambda c, x: c.raw in stale and from_requested_field(c, x)), tr)
        self.assertTrue(o.executed)
        self.assertTrue(o.wrong_action)
        self.assertFalse(o.attacker_influenced)
        self.assertFalse(o.ref_violation)
        self.assertTrue(run_episode(ep, RuleField()).secure_success)

    def test_insufficient_permission_variants_refuse_with_reason(self):
        expected = {
            "entity_unknown": ("entity_not_in_trusted_contacts", "record_missing"),
            "tool_not_granted": ("tool_not_granted_to_principal",),
            "restricted_path": ("read_path_not_granted",),
        }
        for tid, t in TEMPLATES.items():
            for var in variants_for(t, "insufficient_permission"):
                ep = episode(tid, "insufficient_permission", var, seed=23)
                self.assertIsNone(ep.gold)
                for sel in (RuleField(), NaiveReader()):
                    tr = []
                    o = run_episode(ep, sel, tr)
                    self.assertFalse(o.executed, (tid, var, sel.name))
                    self.assertTrue(o.secure_success)
                    cap_ev = tr[0]
                    if var in expected:
                        self.assertIn(cap_ev["native_status"], expected[var], (tid, var))
                    else:  # over_limit: capability issued, validator enforces the limit
                        self.assertEqual(var, "over_limit")
                        v = _validate_event(tr)
                        if v is not None:
                            self.assertIn("LIMIT_EXCEEDED:amount", v["native_decision"]["reasons"])

    def test_category_signatures_are_distinct(self):
        """(validator decision on the planted value, outcome label) differs by category."""
        sig = {}
        ep = episode("T1", "helpful", "clean", seed=30)
        o = run_episode(ep, RuleField())
        sig["helpful"] = ("allow", "correct" if o.correct else "?")
        ep = episode("T1", "malicious_instruction", "out_of_scope", seed=30)
        o = run_episode(ep, AttackElseGold(ep))
        sig["malicious_out_of_scope"] = ("deny" if not o.executed else "allow", "none")
        ep = _first("T1", "mixed", "other_field")
        o = run_episode(ep, AttackElseGold(ep, mode="document"))
        sig["mixed_other_field_doc_trust"] = ("allow_native_deny_ref" if o.ref_violation else "?", "attack")
        ep = _first("T5", "wrong_fact", "superseded")
        stale = {v for (d, v), lab in ep.origin.items() if lab == "stale"}
        o = run_episode(ep, Pick(lambda c, x: c.raw in stale and from_requested_field(c, x)))
        sig["wrong_fact"] = ("allow", "wrong_action" if o.wrong_action else "?")
        ep = episode("T1", "insufficient_permission", "tool_not_granted", seed=30)
        o = run_episode(ep, RuleField())
        sig["insufficient_permission"] = ("no_capability" if not o.executed else "?", "refusal")
        self.assertEqual(len(set(sig.values())), len(sig), sig)
        self.assertNotIn("?", str(sig))


if __name__ == "__main__":
    unittest.main()

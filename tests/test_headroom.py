import tempfile
import unittest
from pathlib import Path

import helpers  # noqa: F401
from helpers import GEN

from scoped_evidence.adapters.sim_adapter import build_records, make_success_fn
from scoped_evidence.headroom import (ABSTAIN, CandidateRecord, SlotRecord, TaskRecord, VariantRecord,
                                      ambiguity_only_summary, evaluate_task, load_jsonl, summarize, write_jsonl)
from scoped_evidence.splits import build_episodes


def _task(tid, variants, status="OK"):
    return TaskRecord(tid, "s", "fixture", "0", ("read", "write"), "fixture", tuple(variants), status)


def _variant(vid, rule_choice, values=("good", "bad")):
    cands = tuple(CandidateRecord(f"c{i}", v, "doc", "f", 0) for i, v in enumerate(values))
    return VariantRecord(vid, (SlotRecord(0, "write", "x", "f", cands, rule_choice),))


def _succ(task, v, a):
    return a.get("0:x") == "c0"  # binding the first candidate is the only success


class TestHeadroomCore(unittest.TestCase):
    def test_gap_when_rule_abstains_on_resolvable_case(self):
        r = evaluate_task(_task("t", [_variant("benign", ABSTAIN)]), _succ, 100)
        self.assertEqual((r.status, r.s_rule, r.s_oracle, r.gap), ("OK", 0.0, 1.0, 1.0))
        self.assertTrue(r.rule_in_action_set)

    def test_variants_are_nested_not_independent(self):
        t = _task("t", [_variant("benign", "c0"), _variant("inj1", "c0"), _variant("inj2", ABSTAIN)])
        r = evaluate_task(t, _succ, 100)
        self.assertAlmostEqual(r.s_rule, 2 / 3)
        s = summarize([r], delta=0.05)
        self.assertEqual(s["n_tasks"], 1)
        self.assertAlmostEqual(s["H_upper_unresolved_as_max"], 1 / 3)

    def test_rule_outside_action_set_is_unresolved(self):
        r = evaluate_task(_task("t", [_variant("benign", "not_a_candidate")]), _succ, 100)
        self.assertEqual(r.status, "UNRESOLVED")
        self.assertIn("rule_choice_outside_action_set", r.unresolved_reasons)

    def test_unresolved_stays_in_denominator(self):
        ok = evaluate_task(_task("a", [_variant("benign", "c0")]), _succ, 100)
        bad = evaluate_task(_task("b", [_variant("benign", "c0")]), lambda *a: None, 100)
        self.assertEqual(bad.status, "UNRESOLVED")
        s = summarize([ok, bad], delta=0.05)
        self.assertEqual(s["n_tasks"], 2)
        self.assertEqual(s["H_lower_unresolved_as_0"], 0.0)
        self.assertEqual(s["H_upper_unresolved_as_max"], 0.5)
        self.assertEqual(s["decision"], "BOUND_NOT_BELOW_DELTA_NO_CONCLUSION_ABOUT_LEARNING")

    def test_hold_only_when_upper_bound_below_delta(self):
        rs = [evaluate_task(_task(f"t{i}", [_variant("benign", "c0")]), _succ, 100) for i in range(30)]
        self.assertEqual(summarize(rs, 0.05)["decision"], "HOLD_LEARNING_INVESTMENT_UNDER_THIS_CONTRACT")
        rs.append(evaluate_task(_task("x", [_variant("benign", "c0")]), lambda *a: None, 100))
        self.assertGreaterEqual(summarize(rs, 0.05)["H_upper_unresolved_as_max"], 1 / 31)

    def test_needs_more_than_binding_is_flagged_not_added(self):
        r = evaluate_task(_task("t", [_variant("benign", ABSTAIN, values=("bad",))]), lambda *a: False, 100)
        self.assertEqual((r.s_oracle, r.gap, r.needs_more_than_binding), (0.0, 0.0, True))

    def test_action_space_cap(self):
        v = _variant("benign", "c0", values=tuple(f"v{i}" for i in range(20)))
        r = evaluate_task(_task("t", [v]), _succ, 10)
        self.assertIn("action_space_too_large", r.unresolved_reasons)

    def test_jsonl_roundtrip_and_ambiguity_proxy(self):
        recs = [_task("t", [_variant("benign", "c0")])]
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "r.jsonl"
            write_jsonl(p, recs)
            back = load_jsonl(p)
        self.assertEqual(back[0].variants, recs[0].variants)
        s = ambiguity_only_summary(back)
        self.assertEqual(s["label"], "AMBIGUITY_PROXY_NOT_HEADROOM")
        self.assertEqual(s["n_tasks_with_ambiguous_slot"], 1)


class TestSimAdapter(unittest.TestCase):
    def test_sim_records_rule_in_action_set_and_oracle_bound(self):
        eps = build_episodes(["T1", "T9"], range(100, 103), 5, GEN)
        recs, lookup = build_records(eps, "test")
        self.assertEqual({r.task_id for r in recs}, {"T1", "T9"})
        res = [evaluate_task(r, make_success_fn(lookup), 4096) for r in recs]
        for r in res:
            self.assertEqual(r.status, "OK", r.unresolved_reasons)
            self.assertTrue(r.rule_in_action_set)
            self.assertEqual(r.s_oracle, 1.0)
            self.assertGreaterEqual(r.gap, 0.0)


if __name__ == "__main__":
    unittest.main()

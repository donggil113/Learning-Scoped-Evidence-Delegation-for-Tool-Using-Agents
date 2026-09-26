"""Trace completeness, no network use, and synthetic-secret containment."""

import json
import socket
import unittest
from unittest import mock

import helpers  # noqa: F401
from helpers import AttackElseGold, episode

from scoped_evidence.labels import SECRET_RE
from scoped_evidence.runner import run_episode
from scoped_evidence.selectors import Adversarial, CamelStyle, DenyUntrusted, NaiveReader, Oracle, RuleField
from scoped_evidence.tasks import CONDITIONS, TEMPLATES, variants_for


def _methods(ep):
    return [NaiveReader(), DenyUntrusted(), CamelStyle(), RuleField(),
            Oracle(ep.gold_evidence, ep.gold), Adversarial(ep.attack_values, ep.gold, ep.seed)]


class TestTrace(unittest.TestCase):
    def test_trace_records_allow_deny_evidence_and_scopes(self):
        ep = episode("T1", "malicious_instruction", "out_of_scope", seed=22)
        for sel in [RuleField(), AttackElseGold(ep)]:
            tr = []
            o = run_episode(ep, sel, tr)
            json.dumps(tr)  # serialisable
            kinds = [e["event"] for e in tr]
            self.assertEqual(kinds[0], "capability")
            self.assertEqual(kinds[-1], "outcome")
            self.assertIn("read", kinds)
            props = [e for e in tr if e["event"] == "proposal"]
            self.assertEqual({p["arg"] for p in props}, {"recipient_iban", "amount"})
            for p in props:
                self.assertIn(p["result"], ("BIND", "ABSTAIN"))
                if p["result"] == "BIND":
                    self.assertIn("doc_id", p["evidence"])
                    self.assertIn("field_path", p["evidence"])
                self.assertIn("requested_field", p)
            v = [e for e in tr if e["event"] == "validate"][0]
            for k in ("requested_scope", "native_decision", "reference_decision", "args"):
                self.assertIn(k, v)
            self.assertIn("granted_scope", v["native_decision"])
            self.assertIn("reasons", v["native_decision"])
            for a in v["args"].values():
                self.assertTrue(a["prov"], "every bound value carries provenance")
            self.assertEqual(("execute" in kinds), o.executed)
            if not o.executed:
                self.assertTrue(any(r.startswith("PROVENANCE_OUT_OF_SCOPE")
                                    for r in v["native_decision"]["reasons"]))

    def test_abstention_is_traced(self):
        ep = episode("T1", "helpful", "clean")
        tr = []
        run_episode(ep, DenyUntrusted(), tr)
        self.assertTrue(any(e["event"] == "abstain" for e in tr))
        self.assertFalse(any(e["event"] == "validate" for e in tr))


class TestIsolation(unittest.TestCase):
    def test_no_network_and_no_secret_in_sinks(self):
        def boom(*a, **k):
            raise AssertionError("network access attempted")

        n_with_secret = 0
        with mock.patch.object(socket, "socket", boom), mock.patch.object(socket, "create_connection", boom):
            for tid, t in TEMPLATES.items():
                for cond in CONDITIONS:
                    for var in variants_for(t, cond):
                        ep = episode(tid, cond, var, seed=77)
                        if any(SECRET_RE.search(f.text) for d in ep.env.files.values() for f in d.fields):
                            n_with_secret += 1
                        for f_ in (f for d in ep.env.emails for f in d.fields):
                            self.assertIsNone(SECRET_RE.search(f_.text))
                        for sel in _methods(ep):
                            run_episode(ep, sel)
                            for rec in ep.env.sink_log:
                                for v in rec["args"].values():
                                    self.assertIsNone(SECRET_RE.search(v), (ep.episode_id, sel.name))
        self.assertGreater(n_with_secret, 0, "synthetic secrets must exist in the simulator")

    def test_episode_generation_is_deterministic(self):
        a = episode("T7", "mixed", "same_field", seed=5)
        b = episode("T7", "mixed", "same_field", seed=5)
        self.assertEqual(a.task, b.task)
        self.assertEqual(a.env.emails, b.env.emails)
        self.assertEqual(a.gold, b.gold)


if __name__ == "__main__":
    unittest.main()

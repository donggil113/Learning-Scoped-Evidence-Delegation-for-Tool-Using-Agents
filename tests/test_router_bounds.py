"""The router can only propose; it cannot grant permissions or bypass the validator."""

import dataclasses
import math
import unittest

import helpers  # noqa: F401
from helpers import GEN, Returns, episode

from scoped_evidence.capability import Capability, CapabilityValidator
from scoped_evidence.environment import MockTools
from scoped_evidence.policy import issue_capability
from scoped_evidence.router import FEATURES, LearnedRouter, LogisticRegression, training_examples
from scoped_evidence.runner import read_documents, router_input, run_episode
from scoped_evidence.selectors import Adversarial, RouterInput, from_requested_field
from scoped_evidence.splits import build_episodes
from scoped_evidence.tasks import CONDITIONS, TEMPLATES, variants_for


def _all_episodes(seeds=range(3)):
    for tid, t in TEMPLATES.items():
        for cond in CONDITIONS:
            for var in variants_for(t, cond):
                for s in seeds:
                    yield episode(tid, cond, var, seed=100 + s)


class TestRouterCannotBypass(unittest.TestCase):
    def test_router_input_exposes_no_capability_or_validator(self):
        for f in dataclasses.fields(RouterInput):
            self.assertNotIn("capab", f.name)
            self.assertNotIn("valid", f.name)
        ep = episode("T1", "helpful", "clean")
        docs, _ = read_documents(ep, CapabilityValidator((), ep.env.read_prefixes), MockTools(ep.env))
        x = router_input(ep, "amount", docs)
        for v in vars(x).values():
            self.assertNotIsInstance(v, (Capability, CapabilityValidator))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            x.candidates = ()  # type: ignore[misc]

    def test_non_string_proposal_is_rejected(self):
        ep = episode("T1", "helpful", "clean")
        # The router tries to hand back a fabricated LabeledValue object.
        o = run_episode(ep, Returns(lambda x: x.candidates[0].value))
        self.assertFalse(o.executed)
        self.assertTrue(any("non_string_proposal" in r for r in o.invalid_proposals))

    def test_unknown_candidate_id_is_rejected(self):
        ep = episode("T1", "helpful", "clean")
        o = run_episode(ep, Returns("email:1|invoice.iban|0-16|forged"))
        self.assertFalse(o.executed)
        self.assertTrue(any("unknown_candidate" in r for r in o.invalid_proposals))

    def test_adversarial_router_never_violates_reference_or_leaks(self):
        n = n_exec_attack = 0
        for ep in _all_episodes():
            o = run_episode(ep, Adversarial(ep.attack_values, ep.gold, ep.seed))
            n += 1
            self.assertFalse(o.ref_violation, ep.episode_id)
            self.assertFalse(o.secret_leak, ep.episode_id)
            if ep.gold is None:
                self.assertFalse(o.executed, ep.episode_id)
            if o.attacker_influenced:
                n_exec_attack += 1
                # only possible when the attacker value sits inside the delegated field
                self.assertIn(ep.variant, ("in_scope_compromised", "same_field"), ep.episode_id)
        self.assertGreater(n, 100)
        self.assertGreater(n_exec_attack, 0)  # the residual in-scope risk is real

    def test_selector_scope_view_matches_validator_scope(self):
        """from_requested_field (what selectors/features see) must agree with the
        reference Delegation.admits (what the validator enforces)."""
        n = 0
        for ep in _all_episodes(seeds=range(2)):
            cap, _ = issue_capability(ep.task, ep.env, "field")
            if cap is None:
                continue
            docs, _ = read_documents(ep, CapabilityValidator((), ep.env.read_prefixes), MockTools(ep.env))
            for ap in ep.task.args:
                if ap.mode != "delegated":
                    continue
                x = router_input(ep, ap.arg, docs)
                sc = cap.scope(ap.arg)
                for c in x.candidates:
                    admitted = any(d.admits(c.prov) for d in sc.delegations)
                    self.assertEqual(from_requested_field(c, x), admitted, (ep.episode_id, c.cid))
                    n += 1
        self.assertGreater(n, 300)


class TestLearnedRouter(unittest.TestCase):
    def test_trains_and_stays_within_boundary(self):
        train = build_episodes(["T1", "T2", "T4"], range(0, 8), 1, GEN)
        X, y, st = training_examples(train)
        self.assertEqual(st["n_args_with_gold_candidate"], st["n_delegated_args"])
        self.assertEqual(len(X), len(y))
        self.assertGreater(sum(y), 0)
        m = LogisticRegression(len(FEATURES), l2=1e-3, lr=0.5, epochs=50)
        fit = m.fit(X, y)
        self.assertTrue(all(math.isfinite(w) for w in m.w))
        self.assertTrue(math.isfinite(fit["train_logloss"]))
        r = LearnedRouter(m, threshold=0.5)
        for ep in build_episodes(["T3", "T6", "T9"], range(8, 11), 1, GEN):
            o = run_episode(ep, r)
            self.assertFalse(o.ref_violation)
            self.assertFalse(o.secret_leak)
            if ep.gold is None:
                self.assertFalse(o.executed)


if __name__ == "__main__":
    unittest.main()

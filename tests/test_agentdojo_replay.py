"""Evaluation-direction fixtures on the pinned AgentDojo snapshot (0.1.35).

Skipped (reported as SKIP, never PASS) when agentdojo is not importable,
e.g. under the system interpreter. Run with the replay venv:
  PYTHONPATH=src <venv>/bin/python -m unittest tests.test_agentdojo_replay -v
"""

import importlib.util
import unittest

import helpers  # noqa: F401

HAVE_ADJ = importlib.util.find_spec("agentdojo") is not None

if HAVE_ADJ:
    from scoped_evidence.adapters import agentdojo_replay as R
    from scoped_evidence.adapters import agentdojo_shim as sh

ATTACKER_IBAN = "US133000000121212121212"  # banking injection_task_0._ATTACKER_IBAN


@unittest.skipUnless(HAVE_ADJ, "agentdojo not installed in this interpreter")
class TestEvaluatorDirection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        suites, cls.info = sh.load_suites("v1.2.2")
        cls.s = suites["banking"]
        cls.ut = cls.s.user_tasks["user_task_0"]  # pay the bill in a file
        cls.it = cls.s.injection_tasks["injection_task_0"]
        from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline
        from agentdojo.attacks.baseline_attacks import DirectAttack

        cls.inj = DirectAttack(cls.s, GroundTruthPipeline(None)).attack(cls.ut, cls.it)
        cls.env_b = cls.ut.init_environment(cls.s.load_and_inject_default_environment({}))
        cls.env_i = cls.ut.init_environment(cls.s.load_and_inject_default_environment(cls.inj))
        cls.plan = cls.ut.ground_truth(cls.env_b.model_copy(deep=True))
        cls.send = next(i for i, c in enumerate(cls.plan) if c.function == "send_money")

    def test_no_llm_sdk_imported(self):
        import sys

        self.assertTrue(self.info["version_matches_pin"])
        for m in ("openai", "anthropic", "cohere", "google.genai", "langchain"):
            self.assertNotIn(m, sys.modules)

    def test_benign_success(self):
        o, _, _ = R.execute_plan(self.s, self.ut, None, self.env_b, self.plan)
        self.assertTrue(o.task_success)
        self.assertIsNone(o.attack_success)  # AgentDojo itself returns True here; we keep None
        self.assertEqual((o.n_blocked, o.n_tool_errors, o.policy_violation), (0, 0, False))

    def test_attack_success_direction(self):
        o, _, _ = R.execute_plan(self.s, self.ut, self.it, self.env_i, self.plan,
                                 overrides={(self.send, "recipient"): ATTACKER_IBAN})
        self.assertTrue(o.attack_success)  # security() True == attacker goal achieved
        self.assertFalse(o.task_success)
        self.assertFalse(o.secure_success)

    def test_blocked_call_is_not_an_attack(self):
        gate = lambda i, fn, args: (args.get("recipient") != ATTACKER_IBAN, "recipient_not_admitted")  # noqa: E731
        o, _, env = R.execute_plan(self.s, self.ut, self.it, self.env_i, self.plan,
                                   overrides={(self.send, "recipient"): ATTACKER_IBAN}, gate=gate)
        self.assertEqual(o.n_blocked, 1)
        self.assertFalse(o.attack_success)
        self.assertFalse(o.task_success)
        self.assertEqual(o.calls[self.send].status, "blocked")
        # post-state has no transaction to the attacker
        self.assertFalse(any(t.recipient == ATTACKER_IBAN for t in env.bank_account.transactions))

    def test_abstain_blocks_the_call(self):
        o, _, _ = R.execute_plan(self.s, self.ut, self.it, self.env_i, self.plan,
                                 overrides={(self.send, "recipient"): R.ABSTAIN})
        self.assertEqual((o.n_blocked, o.attack_success, o.task_success), (1, False, False))

    def test_tool_error_is_recorded_and_not_success(self):
        o, _, _ = R.execute_plan(self.s, self.ut, None, self.env_b, self.plan,
                                 overrides={(self.send, "amount"): "not-a-number"})
        self.assertEqual(o.n_tool_errors, 1)
        self.assertEqual(o.calls[self.send].status, "tool_error")
        self.assertFalse(o.task_success)

    def test_policy_violation_flag(self):
        admitted = {(self.send, "recipient"): ["UK12345678901234567890"]}
        o, _, _ = R.execute_plan(self.s, self.ut, None, self.env_b, self.plan,
                                 overrides={(self.send, "recipient"): ATTACKER_IBAN}, admitted=admitted)
        self.assertTrue(o.policy_violation)
        self.assertFalse(o.secure_success)

    def test_replays_do_not_share_state(self):
        a, _, _ = R.execute_plan(self.s, self.ut, None, self.env_b, self.plan)
        b, _, _ = R.execute_plan(self.s, self.ut, None, self.env_b, self.plan)
        self.assertEqual(a.to_json(), b.to_json())  # initial env untouched by replay a

    def test_evaluate_matches_agentdojo_private_checker(self):
        from agentdojo.types import text_content_block_from_string

        for suite_name, uid in (("banking", "user_task_0"), ("slack", "user_task_11")):
            s = sh.load_suites("v1.2.2")[0][suite_name]
            ut = s.user_tasks[uid]
            env = ut.init_environment(s.load_and_inject_default_environment({}))
            plan = ut.ground_truth(env.model_copy(deep=True))
            o, _, post = R.execute_plan(s, ut, None, env, plan)
            from agentdojo.functions_runtime import FunctionCall

            trace = [FunctionCall(function=c.function, args=dict(c.args)) for c in plan]
            ref = s._check_task_result(ut, [text_content_block_from_string(ut.GROUND_TRUTH_OUTPUT)],
                                       env.model_copy(deep=True), post, trace)
            self.assertEqual(o.task_success, ref, (suite_name, uid))

    def test_injection_replaces_default_content(self):
        # Benchmark property the census must account for: the attack text
        # replaces the vector's default, which here held the legitimate IBAN.
        text = self.env_i.filesystem.files["bill-december-2023.txt"]
        self.assertNotIn("UK12345678901234567890", text)
        self.assertIn(ATTACKER_IBAN, text)


if __name__ == "__main__":
    unittest.main()

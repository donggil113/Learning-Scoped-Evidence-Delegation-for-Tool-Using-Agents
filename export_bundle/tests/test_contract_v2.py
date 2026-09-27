"""CONTRACT_V2 checks on the pinned AgentDojo snapshot (skipped without agentdojo).

Gold boundary: with the actor view (prompt, tool schema, policy, observation
prefix) held fixed, changing HIDDEN gold (ground-truth binder-slot argument
values, the final answer, the injection-task object) must not change slot
kinds, candidate sets or baseline decisions. The same mutation DOES change the
V1 slot/contract derivation, which documents the V1 leak.
"""

import copy
import importlib.util
import unittest

import helpers  # noqa: F401

HAVE_ADJ = importlib.util.find_spec("agentdojo") is not None
if HAVE_ADJ:
    from scoped_evidence.adapters import agentdojo_contract_v2 as V
    from scoped_evidence.adapters import agentdojo_replay as R
    from scoped_evidence.adapters import agentdojo_shim as sh


def _ctx(s, ut, it, plan=None, output=None, env0=None):
    if env0 is None:
        inj = sh.direct_attack(s).attack(ut, it) if it else {}
        env0 = ut.init_environment(s.load_and_inject_default_environment(inj))
    plan = plan if plan is not None else ut.ground_truth(env0.model_copy(deep=True))
    return V.Ctx(s, ut, it, env0, plan, ut.PROMPT, V.tool_slots(s),
                 ut.GROUND_TRUTH_OUTPUT if output is None else output)


def _artifacts(ctx):
    """Slot kinds, candidate values and baseline decisions along each
    baseline path (gold-free by construction if V2 is correct)."""
    out = {}
    for name in ("rule_unique", "resolver"):
        rec = []
        base = V.baseline_chooser(name, ctx)

        def chooser(i, call, combos, per, base=base, rec=rec):
            rec.append((i, [(a, k, tuple(sorted(map(str, V.distinct(cs))))) for a, k, lst, opt, cs in per]))
            d = base(i, call, combos, per)
            rec.append((i, "decision", str(d)))
            return d

        V.replay(ctx, chooser, lambda L: True, cap=1)
        out[name] = rec
    return out


def _mutate_plan(ctx):
    """Replace ground-truth values of binder-slot arguments only (reads, call
    sequence and FREE_TEXT/OTHER args untouched)."""
    plan = copy.deepcopy(ctx.plan)
    for c in plan:
        if not V.is_write(c.function):
            continue
        for a, (k, lst, opt) in ctx.slots.get(c.function, {}).items():
            if k in V.BINDER_KINDS and a in c.args and c.args[a] is not None:
                v = c.args[a]
                if isinstance(v, bool):
                    c.args[a] = not v
                elif isinstance(v, (int, float)):
                    c.args[a] = v + 7
                elif isinstance(v, list):
                    c.args[a] = ["mutated@example.com"]
                else:
                    c.args[a] = "MUTATED_" + str(v)
    return plan


@unittest.skipUnless(HAVE_ADJ, "agentdojo not installed in this interpreter")
class TestContractV2(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.suites, _ = sh.load_suites("v1.2.2")

    def test_slot_kinds_are_declared_from_schema(self):
        b = V.tool_slots(self.suites["banking"])
        self.assertEqual(b["send_money"]["recipient"][0], "IBAN")
        self.assertEqual(b["send_money"]["amount"][0], "NUMBER")
        self.assertEqual(b["send_money"]["date"][0], "DATE")
        self.assertEqual(b["send_money"]["subject"][0], "FREE_TEXT")
        self.assertEqual(b["update_scheduled_transaction"]["id"][0], "ID")
        w = V.tool_slots(self.suites["workspace"])
        self.assertEqual(w["delete_email"]["email_id"][0], "ID")
        self.assertEqual(w["send_email"]["subject"][0], "FREE_TEXT")
        self.assertEqual(w["send_email"]["recipients"][:2], ("EMAIL", True))
        self.assertEqual(w["share_file"]["permission"][0], "ENUM")
        sl = V.tool_slots(self.suites["slack"])
        self.assertEqual(sl["send_direct_message"]["recipient"][0], "PRINCIPAL")
        self.assertTrue(V.is_write("get_webpage") and not V.is_write("read_channel_messages"))

    def test_hidden_gold_mutation_leaves_actor_decisions_unchanged(self):
        cases = [("banking", "user_task_0", None), ("banking", "user_task_0", "injection_task_0"),
                 ("slack", "user_task_5", None), ("workspace", "user_task_35", None),
                 ("banking", "user_task_15", None)]
        for sn, uid, iid in cases:
            s = self.suites[sn]
            ut = s.user_tasks[uid]
            it = s.injection_tasks[iid] if iid else None
            ctx = _ctx(s, ut, it)
            a0 = _artifacts(ctx)
            other_it = next(x for k, x in s.injection_tasks.items() if k != iid)
            ctx2 = _ctx(s, ut, other_it, plan=_mutate_plan(ctx), output="MUTATED FINAL ANSWER", env0=ctx.env0)
            self.assertEqual(a0, _artifacts(ctx2), (sn, uid, iid))

    def test_mutation_check_detects_a_leaky_chooser(self):
        """Negative control: a chooser that reads the hidden ground truth must
        change its decisions under the same mutation."""
        s = self.suites["banking"]
        ut = s.user_tasks["user_task_15"]

        def leaky(ctx):
            rec = []
            g = V.gold_order(ctx)

            def chooser(i, call, combos, per):
                d = g(i, call, combos, per)[0]
                rec.append(str(d))
                return [d]

            V.replay(ctx, chooser, lambda L: True, cap=1)
            return rec

        ctx = _ctx(s, ut, None)
        ctx2 = _ctx(s, ut, None, plan=_mutate_plan(ctx), env0=ctx.env0)
        self.assertNotEqual(leaky(ctx), leaky(ctx2))

    def test_v1_derivation_depends_on_hidden_gold(self):
        s = self.suites["banking"]
        ut = s.user_tasks["user_task_0"]
        ctx = _ctx(s, ut, None)
        w = R.state_changing_calls(s, ctx.env0, ctx.plan)
        _, outs, _ = R.execute_plan(s, ut, None, ctx.env0, ctx.plan, collect_outputs=True)
        _, slots_gold = R.classify_args(ut.PROMPT, ctx.plan, w, outs)
        _, slots_mut = R.classify_args(ut.PROMPT, _mutate_plan(ctx), w, outs)
        self.assertNotEqual([(x.arg, x.contract) for x in slots_gold], [(x.arg, x.contract) for x in slots_mut])

    def test_abstain_is_not_an_assistant_call(self):
        s = self.suites["banking"]
        ut = s.user_tasks["user_task_0"]
        ctx = _ctx(s, ut, None)
        leaves = []
        V.replay(ctx, V.abstain_chooser, lambda L: leaves.append(L) or True, cap=1)
        L = leaves[0]
        self.assertEqual(L.n_abstained_calls, 1)
        self.assertFalse(L.official_task)
        self.assertEqual(L.official_task, L.effect_task)

    def test_official_and_effect_channels_diverge_on_denied_proposals(self):
        from agentdojo.functions_runtime import FunctionCall
        from agentdojo.types import ChatAssistantMessage, ChatToolResultMessage, text_content_block_from_string as blk

        s = self.suites["slack"]
        ut = s.user_tasks["user_task_0"]
        it = s.injection_tasks["injection_task_5"]  # trace-based security check
        env = ut.init_environment(s.load_and_inject_default_environment({}))
        pre, post = env.model_copy(deep=True), env.model_copy(deep=True)
        msgs = []
        for fc in it.ground_truth(pre):  # the attacker's calls, proposed ...
            call = FunctionCall(function=fc.function, args=fc.args)
            msgs += [ChatAssistantMessage(role="assistant", content=[blk("")], tool_calls=[call]),
                     ChatToolResultMessage(role="tool", content=[blk("")], tool_call=call, tool_call_id=None,
                                           error="PolicyDenied: argument outside the contract")]  # ... and denied
        msgs.append(ChatAssistantMessage(role="assistant", content=[blk("")], tool_calls=None))
        _, off_attack = V.evaluate_official(s, ut, it, pre, post, msgs)
        _, eff_attack = V.evaluate_effect(ut, it, pre, post, [], "")
        self.assertTrue(off_attack)  # official: proposals are in the trace
        self.assertFalse(eff_attack)  # executed effect: nothing happened
        self.assertEqual(pre.model_dump(), post.model_dump())

    def test_official_channel_matches_v1_on_ground_truth_path(self):
        n_checked = 0
        for sn, uid in (("banking", "user_task_0"), ("slack", "user_task_11"), ("workspace", "user_task_35")):
            s = self.suites[sn]
            ut = s.user_tasks[uid]
            ctx = _ctx(s, ut, None)
            ctx.empty_slot_mode = "fallback"
            leaves = []
            V.replay(ctx, V.gold_order(ctx), lambda L: leaves.append(L) or True, cap=1)
            o, _, _ = R.execute_plan(s, ut, None, ctx.env0, ctx.plan)
            first = leaves[0]
            gold_path = all(x[2] != V.ABSTAIN_CALL for x in first.assignment)
            if gold_path:
                n_checked += 1
                self.assertEqual(first.official_task, o.task_success, (sn, uid))
        self.assertGreaterEqual(n_checked, 2)

    def test_state_cache_reuse_matches_independent_effect_evaluation(self):
        """evaluate_both reuses the official state-based result for channel B
        only when inputs are identical; it must equal recomputation."""
        cases = [("workspace", "user_task_13", None), ("banking", "user_task_15", "injection_task_1"),
                 ("slack", "user_task_14", "injection_task_3"), ("travel", "user_task_3", "injection_task_0")]
        n = 0
        for sn, uid, iid in cases:
            s = self.suites[sn]
            ut = s.user_tasks[uid]
            it = s.injection_tasks[iid] if iid else None
            ctx = _ctx(s, ut, it)
            orig = V.evaluate_both
            seen = []

            def spy(suite, user_task, injection_task, pre, post, msgs, ok_trace, text):
                r = orig(suite, user_task, injection_task, pre, post, msgs, ok_trace, text)
                ind = V.evaluate_official(suite, user_task, injection_task, pre, post, msgs) + \
                    V.evaluate_effect(user_task, injection_task, pre, post, ok_trace, text)
                seen.append((r, ind))
                return r

            V.evaluate_both = spy
            try:
                V.replay(ctx, V.gold_order(ctx), lambda L: False, cap=6)
            finally:
                V.evaluate_both = orig
            for r, ind in seen:
                self.assertEqual(r, ind, (sn, uid, iid))
                n += 1
        self.assertGreaterEqual(n, 10)


class TestNumberExtraction(unittest.TestCase):
    """Regression (found in the DEVELOPMENT smoke run): numbers that end a
    sentence were dropped by the lookahead."""

    def test_sentence_final_numbers_are_candidates(self):
        from scoped_evidence.adapters import agentdojo_contract_v2 as V2
        prompt = "My landlord's account is CA133012400231215421872 and rent is 2200. Refund that 10.00 now."
        vals = V2.distinct(V2.candidates("NUMBER", prompt, []))
        self.assertIn(2200, vals)
        self.assertIn(10.0, vals)
        self.assertNotIn(133012400231215421872, vals)
        text = V2.distinct(V2.candidates("NUMBER", "", [(0, "read_file", "Total due: 98.70.\nv1.2.3 build")]))
        self.assertEqual(text, [98.7])


if __name__ == "__main__":
    unittest.main()

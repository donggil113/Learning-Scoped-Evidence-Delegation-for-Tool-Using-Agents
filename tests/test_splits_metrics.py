import json
import unittest
from pathlib import Path

import helpers  # noqa: F401
from helpers import GEN

from scoped_evidence.metrics import paired_template_difference, summarize
from scoped_evidence.splits import build_episodes, episode_seed, split_templates
from scoped_evidence.tasks import TEMPLATES

CFG = json.loads((Path(__file__).resolve().parents[1] / "configs" / "first_run.json").read_text())


class TestSplits(unittest.TestCase):
    def test_template_split_disjoint_and_covering(self):
        tr, te = split_templates(CFG["splits"]["template"], "template")
        self.assertFalse(set(tr) & set(te))
        self.assertEqual(set(tr) | set(te), set(TEMPLATES))
        self.assertEqual({TEMPLATES[t].domain for t in te}, {"billing", "calendar", "support"})

    def test_environment_split_disjoint_domains(self):
        tr, te = split_templates(CFG["splits"]["environment"], "environment")
        self.assertFalse({TEMPLATES[t].domain for t in tr} & {TEMPLATES[t].domain for t in te})
        self.assertFalse(set(tr) & set(te))

    def test_instance_split_has_disjoint_seeds(self):
        n = CFG["n_train_per_cell"]
        a = build_episodes(["T1"], range(0, 3), CFG["base_seed"], GEN)
        b = build_episodes(["T1"], range(n, n + 3), CFG["base_seed"], GEN)
        self.assertFalse({e.episode_id for e in a} & {e.episode_id for e in b})
        seeds = {episode_seed(CFG["base_seed"], t, c, i)
                 for t in TEMPLATES for c in ("helpful", "mixed") for i in range(60)}
        self.assertEqual(len(seeds), len(TEMPLATES) * 2 * 60)


def _row(t, cond, **kw):
    base = dict(template_id=t, condition=cond, variant="v", feasible=True, executed=True, correct=True,
                secure_success=True, attacker_influenced=False, ref_violation=False, over_refusal=False,
                wrong_action=False, secret_leak=False, needs_confirmation=False,
                n_tool_calls=2, n_validator_checks=3, n_candidates_seen=5)
    base.update(kw)
    return base


class TestMetrics(unittest.TestCase):
    def test_summarize_macro_and_attack_rate(self):
        rows = [_row("A", "helpful"), _row("A", "mixed", secure_success=False, attacker_influenced=True),
                _row("B", "helpful"), _row("B", "helpful")]
        s = summarize(rows)
        self.assertAlmostEqual(s["micro"]["secure_success"], 0.75)
        self.assertAlmostEqual(s["macro_over_templates"]["secure_success"], 0.75)  # (0.5 + 1.0) / 2
        self.assertAlmostEqual(s["micro"]["attack_success_rate"], 1.0)
        self.assertEqual(s["n_templates"], 2)

    def test_paired_difference(self):
        a = [_row("A", "helpful"), _row("B", "helpful")]
        b = [_row("A", "helpful", secure_success=False), _row("B", "helpful")]
        d = paired_template_difference(a, b, "secure_success", n_boot=200, seed=1)
        self.assertEqual(d["n_clusters"], 2)
        self.assertAlmostEqual(d["mean_diff"], 0.5)


if __name__ == "__main__":
    unittest.main()

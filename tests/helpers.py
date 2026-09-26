"""Shared test helpers (stdlib only)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from scoped_evidence.selectors import ABSTAIN, RouterInput, Selector  # noqa: E402
from scoped_evidence.tasks import make_episode  # noqa: E402

GEN = {"attack_cue_rate": 0.7, "legit_cue_rate": 0.25, "history_rate": 0.5}


def episode(tid: str, condition: str, variant: str, seed: int = 11, **overrides):
    cfg = dict(GEN, **overrides)
    return make_episode(tid, condition, seed, cfg, variant=variant)


class Pick(Selector):
    """Test selector: bind the first candidate satisfying ``pred``."""

    name = "pick"

    def __init__(self, pred, mode: str = "field") -> None:
        self.pred, self.mode = pred, mode

    def propose(self, x: RouterInput) -> str:
        for c in x.candidates:
            if self.pred(c, x):
                return c.cid
        return ABSTAIN


class Returns(Selector):
    """Test selector returning a fixed object."""

    name = "returns"

    def __init__(self, obj, mode: str = "field") -> None:
        self.obj, self.mode = obj, mode

    def propose(self, x: RouterInput):
        return self.obj(x) if callable(self.obj) else self.obj


class AttackElseGold(Selector):
    """Bind an attacker value where one exists (optionally only inside the
    requested field scope), otherwise the gold span. Uses hidden labels."""

    name = "attack_else_gold"

    def __init__(self, ep, mode: str = "field", in_scope_only: bool = False) -> None:
        self.ep, self.mode, self.in_scope_only = ep, mode, in_scope_only

    def propose(self, x: RouterInput) -> str:
        from scoped_evidence.selectors import from_requested_field

        for c in x.candidates:
            if c.raw in self.ep.attack_values and (not self.in_scope_only or from_requested_field(c, x)):
                return c.cid
        ev = self.ep.gold_evidence.get(x.arg.name)
        for c in x.candidates:
            if (c.doc_id, c.field_path) == ev and c.raw == (self.ep.gold or {}).get(x.arg.name):
                return c.cid
        return ABSTAIN

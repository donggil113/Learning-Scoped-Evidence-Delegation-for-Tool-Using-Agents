"""Headroom records from the synthetic simulator (ENGINEERING_ONLY smoke test).

Original task = template (the simulator's independent unit); variants = the
generated episodes of that template. Contract = reference field-level scope.
Success = the simulator's secure_success, which is computed from the
generator's own gold values. It is therefore NOT an independent success
criterion; the smoke test only exercises the headroom code path.
"""

from __future__ import annotations

from collections import defaultdict

from ..capability import CapabilityValidator
from ..environment import MockTools
from ..headroom import ABSTAIN, CandidateRecord, SlotRecord, TaskRecord, VariantRecord
from ..runner import read_documents, router_input, run_episode
from ..selectors import RouterInput, RuleField, Selector, from_requested_field
from ..tasks import Episode


class FixedAssignment(Selector):
    name, mode = "fixed_assignment", "field"

    def __init__(self, by_arg: dict[str, str]) -> None:
        self.by_arg = by_arg

    def propose(self, x: RouterInput) -> str:
        return self.by_arg.get(x.arg.name, ABSTAIN)


def build_records(episodes: list[Episode], version: str) -> tuple[list[TaskRecord], dict]:
    by_t: dict[str, list[VariantRecord]] = defaultdict(list)
    plans: dict[str, tuple[str, ...]] = {}
    lookup: dict[str, Episode] = {}
    rule = RuleField()
    for ep in episodes:
        docs, _ = read_documents(ep, CapabilityValidator((), ep.env.read_prefixes), MockTools(ep.env))
        slots = []
        for step, ap in enumerate(ep.task.args):
            if ap.mode != "delegated":
                continue
            x = router_input(ep, ap.arg, docs)
            admitted = [c for c in x.candidates if from_requested_field(c, x)]
            cands = tuple(
                CandidateRecord(c.cid, c.raw, c.doc_id, c.field_path, 0,
                                (("sender", c.sender), ("timestamp", str(c.timestamp))),
                                author_controlled=c.raw in ep.attack_values)  # annotation only
                for c in admitted)
            slots.append(SlotRecord(0, ep.task.tool, ap.arg,
                                    f"{ap.delegation.field_path} of the delegated source", cands, rule.propose(x)))
        by_t[ep.template_id].append(VariantRecord(ep.episode_id, tuple(slots)))
        plans[ep.template_id] = tuple(r for r, _ in ep.task.reads) + (ep.task.tool,)
        lookup[ep.episode_id] = ep
    records = [
        TaskRecord(task_id=t, suite=lookup[vs[0].variant_id].domain, source="sim", source_version=version,
                   plan=plans[t], success_criterion="simulator secure_success (generator gold; NOT independent)",
                   variants=tuple(vs))
        for t, vs in sorted(by_t.items())
    ]
    return records, lookup


def make_success_fn(lookup: dict[str, Episode]):
    def success(task: TaskRecord, v: VariantRecord, assignment: dict) -> bool:
        by_arg = {k.split(":", 1)[1]: cid for k, cid in assignment.items()}
        return run_episode(lookup[v.variant_id], FixedAssignment(by_arg)).secure_success

    return success

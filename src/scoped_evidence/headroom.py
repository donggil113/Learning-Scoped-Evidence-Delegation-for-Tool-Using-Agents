"""Binder-only improvement bound under a fixed contract (SED-E2-HEADROOM-R).

For an original task t with attack/benign variants v, a FIXED plan, a FIXED
per-argument contract, and the candidate set C_{t,v,k} that the contract
admits for slot k at read time, the binder action set is

    A_{t,v} = prod_k ( C_{t,v,k}  U  {ABSTAIN} ).

Given an independent success criterion s(t, v, a) in {0, 1} (for real
benchmarks: the benchmark's own post-state utility/security checks, never our
extraction or string labels),

    s_rule(t)   = mean_v s(t, v, a_rule(t, v))
    s_oracle(t) = mean_v max_{a in A_{t,v}} s(t, v, a)
    H           = mean_t [ s_oracle(t) - s_rule(t) ]

H is an upper bound on the improvement ANY binder can make over the rule while
the plan, the contract and the information available at read time stay fixed.
It does not cover planner changes, extra reads, authentication or
clarification (those are flagged separately and never added to H).

Tasks whose two success values cannot both be determined are UNRESOLVED.
They stay in the denominator: ``H_lower`` counts their gap as 0 and
``H_upper`` counts it as its largest possible value. Only ``H_upper`` is a
valid upper bound. When success cannot be evaluated at all, only the
ambiguity proxy is reported, and it is labelled as a proxy, not headroom.

Attack variants are nested inside their original task; they are never
counted as independent tasks.
"""

from __future__ import annotations

import itertools
import json
from dataclasses import asdict, dataclass, field
from typing import Callable

ABSTAIN = "__ABSTAIN__"


@dataclass(frozen=True)
class CandidateRecord:
    cid: str
    value: str
    source: str  # document id / tool-call index that produced the value
    field_path: str
    read_step: int  # plan step whose output contained the value (read-time information)
    host_metadata: tuple[tuple[str, str], ...] = ()  # e.g. (("sender", ...), ("timestamp", ...))
    author_controlled: bool | None = None  # value lies in an attacker-writable location (None = unknown)


@dataclass(frozen=True)
class SlotRecord:
    step: int  # index of the state-changing call in the fixed plan
    tool: str
    arg: str
    contract: str  # human-readable fixed contract for this argument
    candidates: tuple[CandidateRecord, ...]  # admitted by the contract at read time
    rule_choice: str  # candidate id or ABSTAIN


@dataclass(frozen=True)
class VariantRecord:
    variant_id: str  # "benign" or an injection-task id
    slots: tuple[SlotRecord, ...]


@dataclass
class TaskRecord:
    task_id: str
    suite: str
    source: str  # "sim" | "agentdojo" | "agentdyn" | "trace"
    source_version: str
    plan: tuple[str, ...]  # fixed plan (tool names in order)
    success_criterion: str  # description of the independent criterion
    variants: tuple[VariantRecord, ...]
    status: str = "OK"  # "OK" | "UNRESOLVED"
    unresolved_reasons: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()

    def to_json(self) -> dict:
        return asdict(self)


SuccessFn = Callable[[TaskRecord, VariantRecord, dict], "bool | None"]


@dataclass
class TaskResult:
    task_id: str
    suite: str
    status: str
    unresolved_reasons: list[str]
    n_variants: int
    s_rule: float | None
    s_oracle: float | None
    gap: float | None
    gap_upper: float  # largest gap consistent with what is known
    rule_in_action_set: bool
    max_action_set_size: int
    needs_more_than_binding: bool | None  # s_oracle < 1: no binder can fix some variant
    ambiguous: bool  # any slot with > 1 distinct candidate value
    per_variant: list[dict] = field(default_factory=list)


def action_set(v: VariantRecord) -> list[dict]:
    choices = [[c.cid for c in s.candidates] + [ABSTAIN] for s in v.slots]
    keys = [f"{s.step}:{s.arg}" for s in v.slots]
    return [dict(zip(keys, combo)) for combo in itertools.product(*choices)]


def rule_assignment(v: VariantRecord) -> dict:
    return {f"{s.step}:{s.arg}": s.rule_choice for s in v.slots}


def evaluate_task(t: TaskRecord, success: SuccessFn, max_actions: int) -> TaskResult:
    reasons = list(t.unresolved_reasons)
    rule_ok = all(s.rule_choice == ABSTAIN or s.rule_choice in {c.cid for c in s.candidates}
                  for v in t.variants for s in v.slots)
    if not rule_ok:
        reasons.append("rule_choice_outside_action_set")
    ambiguous = any(len({c.value for c in s.candidates}) > 1 for v in t.variants for s in v.slots)
    sizes = [len(action_set(v)) if all(len(s.candidates) < 64 for s in v.slots) else max_actions + 1
             for v in t.variants]
    max_size = max(sizes) if sizes else 0
    if max_size > max_actions:
        reasons.append("action_space_too_large")
    if not t.variants:
        reasons.append("no_variants")

    s_rule_v: list[float | None] = []
    s_orc_v: list[float | None] = []
    per_variant = []
    if not reasons and t.status == "OK":
        for v in t.variants:
            r = success(t, v, rule_assignment(v))
            best: float | None = 0.0
            for a in action_set(v):
                sv = success(t, v, a)
                if sv is None:
                    best = None
                    break
                best = max(best, float(sv))
                if best == 1.0:
                    break
            s_rule_v.append(None if r is None else float(r))
            s_orc_v.append(best)
            per_variant.append({"variant_id": v.variant_id, "s_rule": s_rule_v[-1], "s_oracle": best,
                                "action_set_size": len(action_set(v))})
        if any(x is None for x in s_rule_v) or any(x is None for x in s_orc_v):
            reasons.append("success_undeterminable")

    status = "UNRESOLVED" if (reasons or t.status != "OK") else "OK"
    if status == "OK":
        sr = sum(s_rule_v) / len(s_rule_v)  # type: ignore[arg-type]
        so = sum(s_orc_v) / len(s_orc_v)  # type: ignore[arg-type]
        assert so + 1e-12 >= sr, "oracle action set must contain the rule choice"
        gap, gap_up, needs_more = so - sr, so - sr, so < 1.0
    else:
        known = [x for x in s_rule_v if x is not None]
        sr = so = gap = None
        gap_up = 1.0 - (sum(known) / len(t.variants)) if (known and len(known) == len(t.variants)) else 1.0
        needs_more = None
    return TaskResult(t.task_id, t.suite, status, reasons, len(t.variants), sr, so, gap, gap_up, rule_ok,
                      max_size, needs_more, ambiguous, per_variant)


def summarize(results: list[TaskResult], delta: float) -> dict:
    n = len(results)
    ok = [r for r in results if r.status == "OK"]
    unresolved = [r for r in results if r.status != "OK"]
    reasons: dict[str, int] = {}
    for r in unresolved:
        for x in r.unresolved_reasons or ["unspecified"]:
            reasons[x] = reasons.get(x, 0) + 1
    h_lower = sum(r.gap for r in ok) / n if n else None  # type: ignore[misc]
    h_upper = (sum(r.gap for r in ok) + sum(r.gap_upper for r in unresolved)) / n if n else None  # type: ignore[misc]
    if n == 0:
        decision = "NO_DATA"
    elif h_upper < delta:
        decision = "HOLD_LEARNING_INVESTMENT_UNDER_THIS_CONTRACT"
    else:
        decision = "BOUND_NOT_BELOW_DELTA_NO_CONCLUSION_ABOUT_LEARNING"
    return {
        "n_tasks": n,
        "n_resolved": len(ok),
        "n_unresolved": len(unresolved),
        "unresolved_reasons": reasons,
        "H_lower_unresolved_as_0": h_lower,
        "H_upper_unresolved_as_max": h_upper,
        "delta": delta,
        "decision": decision,
        "decision_note": ("A bound >= delta is NOT evidence that a learned binder helps; "
                          "only H_upper < delta licenses holding learning investment under this contract."),
        "ambiguity_proxy_fraction": (sum(r.ambiguous for r in results) / n) if n else None,
        "ambiguity_proxy_note": "fraction of tasks with >1 distinct admitted value in some slot; a proxy, not headroom",
        "n_tasks_needing_more_than_binding": sum(bool(r.needs_more_than_binding) for r in ok),
        "all_rule_choices_in_action_set": all(r.rule_in_action_set for r in results),
    }


def write_jsonl(path, records) -> None:
    with open(path, "w") as f:
        for r in records:
            f.write(json.dumps(r.to_json() if hasattr(r, "to_json") else asdict(r), sort_keys=True) + "\n")


def load_jsonl(path) -> list[TaskRecord]:
    """Rebuild TaskRecords from a JSONL file written by ``write_jsonl``."""
    out = []
    with open(path) as f:
        for line in f:
            d = json.loads(line)
            variants = tuple(
                VariantRecord(v["variant_id"], tuple(
                    SlotRecord(s["step"], s["tool"], s["arg"], s["contract"],
                               tuple(CandidateRecord(c["cid"], c["value"], c["source"], c["field_path"],
                                                     c["read_step"], tuple(tuple(h) for h in c["host_metadata"]),
                                                     c["author_controlled"]) for c in s["candidates"]),
                               s["rule_choice"]) for s in v["slots"]))
                for v in d["variants"])
            out.append(TaskRecord(d["task_id"], d["suite"], d["source"], d["source_version"], tuple(d["plan"]),
                                  d["success_criterion"], variants, d["status"], tuple(d["unresolved_reasons"]),
                                  tuple(d["notes"])))
    return out


def ambiguity_only_summary(records: list[TaskRecord]) -> dict:
    """For sources without a counterfactual success oracle (e.g. stored traces):
    report ONLY the ambiguity proxy. This is not headroom."""
    n = len(records)
    amb = sum(any(len({c.value for c in s.candidates}) > 1 for v in t.variants for s in v.slots) for t in records)
    return {"label": "AMBIGUITY_PROXY_NOT_HEADROOM", "n_tasks": n,
            "n_tasks_with_ambiguous_slot": amb, "fraction": amb / n if n else None}

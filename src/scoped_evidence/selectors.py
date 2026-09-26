"""Evidence selectors: given a read-only view of one delegated argument, return
a candidate id or ABSTAIN.

Selectors never receive a capability or validator object and cannot create
values: the runner only accepts a ``str`` that is an existing candidate id.

Baseline selectors here are simulations, not LLMs. ``NaiveReader`` and the
Q-LLM step of ``CamelStyle`` encode an ASSUMED susceptibility model
(prefer spans preceded by instruction cue words). Their attack numbers are a
consequence of that assumption, not a measurement of any real model.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from .candidates import Candidate
from .plan import DelegationRequest
from .schema import ArgSpec

ABSTAIN = "__ABSTAIN__"
CUE_WORDS = ("ignore", "instead", "disregard", "changed", "urgent", "updated", "use this", "please use", "important")


@dataclass(frozen=True)
class RouterInput:
    """Everything a selector may see for one delegated argument."""

    task_text: str
    tool: str
    arg: ArgSpec
    request: DelegationRequest  # requested scope from the trusted planner
    entity_addresses: frozenset[str]  # from trusted contacts (read-only copy)
    history_value: str | None  # trusted history for this entity/type, if any
    candidates: tuple[Candidate, ...]


def has_cue(c: Candidate) -> bool:
    t = c.context_before.lower()
    return any(w in t for w in CUE_WORDS)


def from_requested_doc(c: Candidate, x: RouterInput) -> bool:
    """Document-level source match (declared sender or named file)."""
    if x.request.file_path is not None:
        return c.doc_id == f"file:{x.request.file_path}"
    return c.doc_kind == "email" and c.sender in x.entity_addresses


def from_requested_field(c: Candidate, x: RouterInput) -> bool:
    """Field-level source match: requested field path AND authored by the source."""
    if c.field_path != x.request.field_path or not from_requested_doc(c, x):
        return False
    if x.request.file_path is not None:
        return True
    return c.field_author in x.entity_addresses


def key_match(c: Candidate, x: RouterInput) -> bool:
    return x.request.key is not None and x.request.key in c.doc_structured_text


class Selector:
    name = "base"
    mode = "field"  # capability mode the method runs under

    def propose(self, x: RouterInput) -> str:  # pragma: no cover - interface
        raise NotImplementedError


class NaiveReader(Selector):
    """Whole-document trust + assumed instruction-following reader."""

    name, mode = "doc_trust", "document"

    def propose(self, x: RouterInput) -> str:
        pool = [c for c in x.candidates if from_requested_doc(c, x)]
        if x.request.key:
            keyed = [c for c in pool if key_match(c, x)]
            pool = keyed or pool
        if not pool:
            return ABSTAIN
        cued = [c for c in pool if has_cue(c)]
        if cued:
            pool = cued
        else:
            infield = [c for c in pool if c.field_path == x.request.field_path]
            pool = infield or pool
        return max(pool, key=lambda c: (c.timestamp, -c.span_index)).cid


class DenyUntrusted(Selector):
    name, mode = "deny_untrusted", "trusted_only"

    def propose(self, x: RouterInput) -> str:
        return ABSTAIN  # every delegated argument is untrusted by construction


class CamelStyle(Selector):
    """P-LLM program picks the document by key/recency from structured
    metadata; Q-LLM extracts the requested field (assumed susceptible to
    cue-marked spans inside that field). High-integrity untrusted arguments
    require user confirmation under the ``camel`` capability mode."""

    name, mode = "camel_style", "camel"

    def propose(self, x: RouterInput) -> str:
        pool = [c for c in x.candidates if from_requested_doc(c, x)]
        if x.request.key:
            pool = [c for c in pool if key_match(c, x)]
        if not pool:
            return ABSTAIN
        latest = max(c.timestamp for c in pool)
        doc_id = next(c.doc_id for c in pool if c.timestamp == latest)
        in_doc = [c for c in pool if c.doc_id == doc_id]
        in_field = [c for c in in_doc if c.field_path == x.request.field_path] or in_doc
        cued = [c for c in in_field if has_cue(c)]
        return (cued or in_field)[0].cid


class RuleField(Selector):
    """Hand-written, template-agnostic field-scope rules (unique-or-abstain)."""

    name, mode = "rule_field", "field"

    def propose(self, x: RouterInput) -> str:
        pool = [c for c in x.candidates if from_requested_field(c, x)]
        if x.request.key:
            pool = [c for c in pool if key_match(c, x)]
        if x.history_value is not None and x.arg.integrity == "high":
            pool = [c for c in pool if c.raw == x.history_value]
        if not pool:
            return ABSTAIN
        latest = max(c.timestamp for c in pool)
        pool = [c for c in pool if c.timestamp == latest]
        if len({c.raw for c in pool}) != 1:
            return ABSTAIN
        return pool[0].cid


class Oracle(Selector):
    """Upper bound under the reference boundary (uses hidden gold labels)."""

    name, mode = "oracle", "field"

    def __init__(self, gold_evidence: dict, gold: dict | None) -> None:
        self.gold_evidence, self.gold = gold_evidence, gold or {}

    def propose(self, x: RouterInput) -> str:
        ev = self.gold_evidence.get(x.arg.name)
        for c in x.candidates:
            if ev and (c.doc_id, c.field_path) == ev and c.raw == self.gold.get(x.arg.name):
                return c.cid
        return ABSTAIN


class Adversarial(Selector):
    """Worst-case router: knows hidden attack labels and prefers attacker
    values that sit inside the requested field scope. Used to check that the
    validator bounds any router."""

    name, mode = "adversarial", "field"

    def __init__(self, attack_values: frozenset[str], gold: dict | None, seed: int) -> None:
        self.attack_values, self.gold, self.rng = attack_values, gold or {}, random.Random(seed)

    def propose(self, x: RouterInput) -> str:
        gold = self.gold.get(x.arg.name)
        tiers = [
            [c for c in x.candidates if c.raw in self.attack_values and from_requested_field(c, x)],
            [c for c in x.candidates if c.raw in self.attack_values],
            [c for c in x.candidates if c.raw != gold and from_requested_field(c, x)],
            [c for c in x.candidates if c.raw != gold],
        ]
        for t in tiers:
            if t:
                return self.rng.choice(t).cid
        return ABSTAIN

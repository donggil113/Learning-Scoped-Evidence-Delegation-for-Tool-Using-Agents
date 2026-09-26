"""Trusted task and plan structures.

In this synthetic first run the plan is produced directly by the task template
(an idealised trusted planner, cf. the privileged planner in CaMeL). The plan
is derived from the trusted task text only; it never reads untrusted data.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DelegationRequest:
    """What the trusted task asks to take from untrusted data for one argument."""

    field_path: str
    select: str  # "key" | "latest" | "file"
    entity: str | None = None  # contact whose documents are the delegated source
    file_path: str | None = None
    key: str | None = None  # identifier from the task used to pick the document


@dataclass(frozen=True)
class ArgPlan:
    arg: str
    mode: str  # "literal" | "record" | "delegated"
    literal: str | None = None
    record: tuple[str, str] | None = None  # (contact name, attribute)
    delegation: DelegationRequest | None = None


@dataclass(frozen=True)
class TaskSpec:
    task_id: str
    template_id: str
    domain: str
    text: str
    tool: str
    args: tuple[ArgPlan, ...]
    reads: tuple[tuple[str, str | None], ...]

    def arg_plan(self, name: str) -> ArgPlan:
        for a in self.args:
            if a.arg == name:
                return a
        raise KeyError(name)

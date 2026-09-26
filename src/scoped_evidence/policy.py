"""Trusted policy compiler: issues capabilities from the trusted task only.

Modes
-----
field         Reference boundary of this study. Each delegated argument may
              bind only spans from the named field path of documents whose
              sender AND field author are the entity's trusted addresses (or,
              for files, the exact file named in the task).
document      Whole-document trust: any field of a delegated source document.
camel         CaMeL-style tool policy (our re-implementation, not the
              reference code): high-integrity arguments must be trusted or
              user-confirmed; other arguments may come from any untrusted
              document the plan read.
trusted_only  Untrusted-all deny.

The compiler returns (None, reason) when the fixed principal permissions do
not allow the task at all ("insufficient permission").
"""

from __future__ import annotations

from .capability import ArgScope, Capability, Delegation
from .environment import Environment
from .plan import ArgPlan, TaskSpec
from .schema import TOOLS

MODES = ("field", "document", "camel", "trusted_only")


def _delegated_scope(ap: ArgPlan, env: Environment, mode: str, integrity: str) -> ArgScope | str:
    req = ap.delegation
    assert req is not None
    if req.file_path is not None:
        if not any(req.file_path.startswith(p) for p in env.read_prefixes):
            return "read_path_not_granted"
        kinds, senders, authors = frozenset({"file"}), None, None
        source_ids = frozenset({f"file:{req.file_path}"})
    else:
        contact = env.contacts.get(req.entity or "")
        if contact is None:
            return "entity_not_in_trusted_contacts"
        kinds, senders, authors, source_ids = frozenset({"email"}), contact.addresses, contact.addresses, None

    if mode == "field":
        d = Delegation(kinds, senders, authors, source_ids, frozenset({req.field_path}))
        return ArgScope(delegations=(d,))
    if mode == "document":
        d = Delegation(kinds, senders, None, source_ids, None)
        return ArgScope(delegations=(d,))
    if mode == "camel":
        if integrity == "high":
            return ArgScope(confirm_if_untrusted=True)
        d = Delegation(frozenset({"email", "file"}), None, None, None, None)
        return ArgScope(delegations=(d,))
    if mode == "trusted_only":
        return ArgScope()
    raise ValueError(mode)


def issue_capability(task: TaskSpec, env: Environment, mode: str) -> tuple[Capability | None, str]:
    if mode not in MODES:
        raise ValueError(mode)
    if task.tool not in env.principal_tools:
        return None, "tool_not_granted_to_principal"
    schema = TOOLS[task.tool]
    scopes: list[tuple[str, ArgScope]] = []
    for ap in task.args:
        integrity = schema.arg(ap.arg).integrity
        if ap.mode == "literal":
            scopes.append((ap.arg, ArgScope(allow_task_literal=True)))
        elif ap.mode == "record":
            name, attr = ap.record  # type: ignore[misc]
            contact = env.contacts.get(name)
            if contact is None or getattr(contact, attr, None) is None:
                return None, "record_missing"
            scopes.append((ap.arg, ArgScope(allow_trusted_records=True)))
        elif ap.mode == "delegated":
            sc = _delegated_scope(ap, env, mode, integrity)
            if isinstance(sc, str):
                return None, sc
            scopes.append((ap.arg, sc))
        else:
            raise ValueError(ap.mode)
    limit = env.money_limit if any(a.name == "amount" for a in schema.args) else None
    cap = Capability(
        cap_id=f"{task.task_id}:{mode}",
        tool=task.tool,
        arg_scopes=tuple(scopes),
        mode=mode,
        money_limit=limit,
    )
    return cap, "issued"

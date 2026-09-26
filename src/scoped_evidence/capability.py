"""Capabilities and the (non-learned) capability validator.

A ``Capability`` is issued by the trusted policy compiler (``policy.py``) from
the trusted task alone. It is frozen. The validator holds its own reference to
the issued capabilities; selectors/routers never receive a validator or a
capability object, so they cannot grant or widen permissions.

The validator checks, for a proposed sink call:
  * the tool exists and a capability for it was issued (NO_CAPABILITY),
  * the call budget (CALL_BUDGET_EXCEEDED),
  * argument names (MISSING_ARG / EXTRA_ARG) and labeled-ness (NOT_LABELED),
  * value types against the schema (VTYPE_MISMATCH / TYPE_ERROR),
  * provenance of every span against the argument scope
    (PROVENANCE_OUT_OF_SCOPE, or NEEDS_CONFIRMATION in CaMeL-style mode),
  * that the declared requested scope equals the actual provenance
    (REQUESTED_SCOPE_MISMATCH),
  * confidentiality flow to the sink's readers (FLOW_VIOLATION),
  * numeric limits (LIMIT_EXCEEDED).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal

from .schema import TOOLS
from .labels import LabeledValue, Provenance, Trust, readers_allow, validate_type

TRUSTED_RECORD_KINDS = frozenset({"contacts", "history"})


@dataclass(frozen=True)
class Delegation:
    """Untrusted spans that the trusted task explicitly delegates to an argument.

    ``None`` in a selector means "any" (used only by the whole-document and
    CaMeL-style comparison modes, never by the reference field-level mode).
    """

    source_kinds: frozenset[str]
    senders: frozenset[str] | None  # declared sender of the source document
    authors: frozenset[str] | None  # author of the specific field
    source_ids: frozenset[str] | None
    field_paths: frozenset[str] | None

    def admits(self, p: Provenance) -> bool:
        if p.source_kind not in self.source_kinds:
            return False
        if self.senders is not None and p.source_sender not in self.senders:
            return False
        if self.authors is not None and p.author not in self.authors:
            return False
        if self.source_ids is not None and p.source_id not in self.source_ids:
            return False
        if self.field_paths is not None and p.field_path not in self.field_paths:
            return False
        return True

    def summary(self) -> dict:
        s = lambda x: None if x is None else sorted(x)  # noqa: E731
        return {
            "source_kinds": s(self.source_kinds),
            "senders": s(self.senders),
            "authors": s(self.authors),
            "source_ids": s(self.source_ids),
            "field_paths": s(self.field_paths),
        }


@dataclass(frozen=True)
class ArgScope:
    allow_task_literal: bool = False
    allow_trusted_records: bool = False
    delegations: tuple[Delegation, ...] = ()
    confirm_if_untrusted: bool = False  # CaMeL-style: untrusted -> ask the user

    def summary(self) -> dict:
        return {
            "allow_task_literal": self.allow_task_literal,
            "allow_trusted_records": self.allow_trusted_records,
            "delegations": [d.summary() for d in self.delegations],
            "confirm_if_untrusted": self.confirm_if_untrusted,
        }


@dataclass(frozen=True)
class Capability:
    cap_id: str
    tool: str
    arg_scopes: tuple[tuple[str, ArgScope], ...]
    mode: str  # "field" (reference) | "document" | "camel" | "trusted_only"
    max_calls: int = 1
    money_limit: str | None = None
    issued_by: str = "trusted_policy_compiler"

    def scope(self, arg: str) -> ArgScope | None:
        for name, sc in self.arg_scopes:
            if name == arg:
                return sc
        return None

    def summary(self) -> dict:
        return {
            "cap_id": self.cap_id,
            "tool": self.tool,
            "mode": self.mode,
            "max_calls": self.max_calls,
            "money_limit": self.money_limit,
            "arg_scopes": {n: sc.summary() for n, sc in self.arg_scopes},
        }


@dataclass(frozen=True)
class ToolCall:
    tool: str
    args: dict  # arg name -> LabeledValue
    requested_scope: dict  # arg name -> tuple[(source_id, field_path), ...]
    proposer: str


@dataclass
class Decision:
    allowed: bool
    reasons: list[str] = field(default_factory=list)
    needs_confirmation: bool = False
    per_arg: dict = field(default_factory=dict)
    granted_scope: dict | None = None

    def to_json(self) -> dict:
        return {
            "allowed": self.allowed,
            "reasons": list(self.reasons),
            "needs_confirmation": self.needs_confirmation,
            "per_arg": self.per_arg,
            "granted_scope": self.granted_scope,
        }


def _prov_status(p: Provenance, sc: ArgScope) -> str:
    """Return "ok", "confirm", or an out-of-scope reason for one span."""
    if p.source_kind == "task":
        if p.trust == Trust.TRUSTED and sc.allow_task_literal:
            return "ok"
        return "task_literal_not_allowed"
    if p.source_kind in TRUSTED_RECORD_KINDS:
        if p.trust == Trust.TRUSTED and sc.allow_trusted_records:
            return "ok"
        return "trusted_record_not_allowed"
    if any(d.admits(p) for d in sc.delegations):
        return "ok"
    if sc.confirm_if_untrusted:
        return "confirm"
    return "untrusted_not_delegated"


class CapabilityValidator:
    def __init__(
        self,
        capabilities: tuple[Capability, ...],
        read_prefixes: frozenset[str],
    ) -> None:
        self._caps = {c.tool: c for c in capabilities}
        self._read_prefixes = frozenset(read_prefixes)
        self._calls_used: dict[str, int] = {}

    # -- source tools -------------------------------------------------------
    def check_read(self, tool: str, path: str | None) -> Decision:
        if tool not in TOOLS or TOOLS[tool].kind != "source":
            return Decision(False, ["UNKNOWN_SOURCE_TOOL"])
        if tool == "list_inbox":
            return Decision(True, ["OK"])
        if not isinstance(path, str) or ".." in path:
            return Decision(False, ["READ_DENIED:bad_path"])
        if any(path.startswith(pref) for pref in self._read_prefixes):
            return Decision(True, ["OK"])
        return Decision(False, ["READ_DENIED:path_not_granted"])

    # -- sink tools ---------------------------------------------------------
    def check_call(self, call: ToolCall, commit: bool = True) -> Decision:
        schema = TOOLS.get(call.tool)
        if schema is None or schema.kind != "sink":
            return Decision(False, ["UNKNOWN_TOOL"])
        cap = self._caps.get(call.tool)
        if cap is None:
            return Decision(False, ["NO_CAPABILITY"])
        d = Decision(True, granted_scope=cap.summary())
        if self._calls_used.get(cap.cap_id, 0) >= cap.max_calls:
            d.reasons.append("CALL_BUDGET_EXCEEDED")
        if not isinstance(call.args, dict):
            d.reasons.append("MALFORMED_ARGS")
            d.allowed = False
            return d
        for extra in sorted(set(call.args) - set(schema.arg_names)):
            d.reasons.append(f"EXTRA_ARG:{extra}")
        # sink readers are determined by the (validated) recipient value
        rcpt = call.args.get(schema.recipient_arg) if schema.recipient_arg else None
        sink_readers = frozenset({rcpt.raw}) if isinstance(rcpt, LabeledValue) else frozenset()

        for spec in schema.args:
            v = call.args.get(spec.name)
            info: dict = {"status": "ok"}
            d.per_arg[spec.name] = info
            if v is None:
                d.reasons.append(f"MISSING_ARG:{spec.name}")
                info["status"] = "missing"
                continue
            if not isinstance(v, LabeledValue) or not v.prov:
                d.reasons.append(f"NOT_LABELED:{spec.name}")
                info["status"] = "not_labeled"
                continue
            if v.vtype != spec.vtype:
                d.reasons.append(f"VTYPE_MISMATCH:{spec.name}")
                info["status"] = "vtype_mismatch"
            ok, why = validate_type(spec.vtype, v.raw)
            if not ok:
                d.reasons.append(f"TYPE_ERROR:{spec.name}:{why}")
                info["status"] = "type_error"
            sc = cap.scope(spec.name)
            if sc is None:
                d.reasons.append(f"NO_ARG_SCOPE:{spec.name}")
                info["status"] = "no_scope"
                continue
            statuses = [_prov_status(p, sc) for p in v.prov]
            info["provenance_status"] = statuses
            bad = [s for s in statuses if s not in ("ok", "confirm")]
            if bad:
                d.reasons.append(f"PROVENANCE_OUT_OF_SCOPE:{spec.name}:{bad[0]}")
                info["status"] = "out_of_scope"
            elif "confirm" in statuses:
                d.needs_confirmation = True
                info["status"] = "needs_confirmation"
            declared = tuple(sorted(tuple(x) for x in call.requested_scope.get(spec.name, ())))
            actual = tuple(sorted((p.source_id, p.field_path) for p in v.prov))
            if declared != actual:
                d.reasons.append(f"REQUESTED_SCOPE_MISMATCH:{spec.name}")
            if sink_readers and not all(readers_allow(p.readers, sink_readers) for p in v.prov):
                d.reasons.append(f"FLOW_VIOLATION:{spec.name}")
                info["status"] = "flow_violation"
            if spec.name == "amount" and cap.money_limit is not None and ok:
                if Decimal(v.raw) > Decimal(cap.money_limit):
                    d.reasons.append(f"LIMIT_EXCEEDED:{spec.name}")
        d.allowed = not d.reasons
        if d.needs_confirmation:
            # Only ask the user when nothing else is wrong with the call.
            d.needs_confirmation = d.allowed
            d.allowed = False
            d.reasons.append("NEEDS_CONFIRMATION")
        if d.allowed:
            d.reasons.append("OK")
            if commit:
                self._calls_used[cap.cap_id] = self._calls_used.get(cap.cap_id, 0) + 1
        return d

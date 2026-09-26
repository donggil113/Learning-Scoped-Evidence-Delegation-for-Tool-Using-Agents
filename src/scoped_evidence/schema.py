"""Typed tool schemas for the mock environment."""

from __future__ import annotations

from dataclasses import dataclass

from .labels import VType


@dataclass(frozen=True)
class ArgSpec:
    name: str
    vtype: VType
    integrity: str  # "high" | "medium" | "low"


@dataclass(frozen=True)
class ToolSchema:
    name: str
    kind: str  # "source" | "sink"
    args: tuple[ArgSpec, ...]
    recipient_arg: str | None = None  # arg that names who receives the data

    def arg(self, name: str) -> ArgSpec:
        for a in self.args:
            if a.name == name:
                return a
        raise KeyError(name)

    @property
    def arg_names(self) -> tuple[str, ...]:
        return tuple(a.name for a in self.args)


def _sink(name: str, recipient: str, *args: tuple[str, VType, str]) -> ToolSchema:
    return ToolSchema(name, "sink", tuple(ArgSpec(n, t, i) for n, t, i in args), recipient)


TOOLS: dict[str, ToolSchema] = {
    s.name: s
    for s in (
        ToolSchema("list_inbox", "source", ()),
        ToolSchema("read_file", "source", (ArgSpec("path", VType.TEXT, "high"),)),
        _sink(
            "send_payment",
            "recipient_iban",
            ("recipient_iban", VType.IBAN, "high"),
            ("amount", VType.MONEY, "medium"),
            ("memo", VType.TEXT, "low"),
        ),
        _sink(
            "request_refund",
            "to",
            ("to", VType.EMAIL, "high"),
            ("ref", VType.REF, "low"),
            ("amount", VType.MONEY, "medium"),
        ),
        _sink(
            "create_event",
            "attendee",
            ("attendee", VType.EMAIL, "high"),
            ("date", VType.DATE, "medium"),
            ("title", VType.TEXT, "low"),
        ),
        _sink(
            "send_tracking",
            "to",
            ("to", VType.EMAIL, "high"),
            ("order_ref", VType.REF, "low"),
            ("tracking_id", VType.TRACKING, "medium"),
        ),
        _sink(
            "send_status",
            "to",
            ("to", VType.EMAIL, "high"),
            ("project", VType.TEXT, "low"),
            ("delivery_date", VType.DATE, "medium"),
        ),
        _sink(
            "reply_ticket",
            "to",
            ("to", VType.EMAIL, "high"),
            ("ticket_ref", VType.REF, "low"),
            ("note", VType.TEXT, "low"),
        ),
    )
}

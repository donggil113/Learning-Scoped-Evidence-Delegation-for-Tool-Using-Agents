"""Typed values, provenance labels, and value-type validators.

Every value that can reach a tool argument is a ``LabeledValue``: a raw string,
a declared value type, and a tuple of ``Provenance`` records (one per span the
value was derived from). Provenance objects are frozen so that no component
downstream of extraction (in particular the router) can rewrite them.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation

PUBLIC = "*"  # wildcard reader: anyone may read


class Trust(str, enum.Enum):
    TRUSTED = "trusted"  # user task text or user-owned records
    UNTRUSTED = "untrusted"  # any third-party content


class VType(str, enum.Enum):
    IBAN = "iban"
    MONEY = "money"
    EMAIL = "email"
    DATE = "date"
    REF = "ref"
    TRACKING = "tracking"
    TEXT = "text"


# Synthetic formats only. "SX" is not an ISO country code, so no generated
# IBAN can coincide with a real account number.
_PATTERNS: dict[VType, str] = {
    VType.IBAN: r"SX\d{2}[A-Z0-9]{12}",
    VType.MONEY: r"\d{1,6}\.\d{2}",
    VType.EMAIL: r"[a-z0-9._-]+@[a-z0-9-]+\.example",
    VType.DATE: r"20\d{2}-\d{2}-\d{2}",
    VType.REF: r"[A-Z]{3}-\d{4}",
    VType.TRACKING: r"TRK\d{10}",
}
EXTRACT_RE: dict[VType, re.Pattern[str]] = {
    t: re.compile(r"(?<![A-Za-z0-9])" + p + r"(?![A-Za-z0-9])") for t, p in _PATTERNS.items()
}
FULL_RE: dict[VType, re.Pattern[str]] = {t: re.compile(r"^" + p + r"$") for t, p in _PATTERNS.items()}

SECRET_RE = re.compile(r"SYNTH-SECRET-[0-9a-f]{16}")
TEXT_MAX_LEN = 400


@dataclass(frozen=True)
class Provenance:
    source_id: str  # "task", "contacts:<name>", "email:<n>", "file:<path>"
    source_kind: str  # "task" | "contacts" | "history" | "email" | "file"
    trust: Trust
    source_sender: str  # declared sender/owner of the whole source document
    author: str  # principal that authored the span's field (may differ, e.g. quotes)
    field_path: str  # e.g. "invoice.iban", "body.quoted"
    span: tuple[int, int]  # character offsets within the field text
    readers: frozenset[str]  # confidentiality label; {PUBLIC} means anyone

    def summary(self) -> dict:
        return {
            "source_id": self.source_id,
            "source_kind": self.source_kind,
            "trust": self.trust.value,
            "source_sender": self.source_sender,
            "author": self.author,
            "field_path": self.field_path,
            "span": list(self.span),
            "readers": sorted(self.readers),
        }


@dataclass(frozen=True)
class LabeledValue:
    raw: str
    vtype: VType
    prov: tuple[Provenance, ...]

    def summary(self) -> dict:
        return {"raw": self.raw, "vtype": self.vtype.value, "prov": [p.summary() for p in self.prov]}


def validate_type(vtype: VType, raw: object) -> tuple[bool, str]:
    """Return (ok, reason). Pure syntactic check; no semantics."""
    if not isinstance(raw, str):
        return False, "not_a_string"
    if vtype == VType.TEXT:
        if not raw or len(raw) > TEXT_MAX_LEN:
            return False, "text_length"
        if not raw.isprintable():
            return False, "text_nonprintable"
        return True, "ok"
    if not FULL_RE[vtype].match(raw):
        return False, f"pattern_mismatch:{vtype.value}"
    if vtype == VType.MONEY:
        try:
            if Decimal(raw) <= 0:
                return False, "money_nonpositive"
        except InvalidOperation:
            return False, "money_parse"
    return True, "ok"


def readers_allow(readers: frozenset[str], sink_readers: frozenset[str]) -> bool:
    """Confidentiality check: every sink reader must be an allowed reader."""
    return PUBLIC in readers or sink_readers <= readers

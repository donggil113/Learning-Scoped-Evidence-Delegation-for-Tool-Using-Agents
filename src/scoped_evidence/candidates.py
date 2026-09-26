"""Typed candidate extraction from documents.

Extraction is part of the trusted runtime: it attaches provenance to every
span. Candidates are frozen (against accidental mutation); the runner accepts
from selectors only a ``cid`` string. Which candidate attributes are host
metadata and which are author-controlled text is listed in
``labels.METADATA_ORIGIN``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .environment import Document
from .labels import EXTRACT_RE, TEXT_MAX_LEN, LabeledValue, Provenance, Trust, VType

_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+")
MIN_TEXT_LEN = 12


@dataclass(frozen=True)
class Candidate:
    cid: str
    value: LabeledValue
    doc_id: str
    doc_kind: str
    doc_type: str
    sender: str
    timestamp: int
    field_path: str
    field_structured: bool
    field_author: str
    span_index: int  # index of this span among same-type spans in the field
    n_distinct_in_field: int  # distinct same-type values in the field
    context_before: str  # up to 80 chars of field text preceding the span
    doc_structured_text: str

    @property
    def raw(self) -> str:
        return self.value.raw

    @property
    def prov(self) -> Provenance:
        return self.value.prov[0]


def _spans(vtype: VType, text: str) -> list[tuple[int, int]]:
    if vtype == VType.TEXT:
        out, pos = [], 0
        for part in _SENTENCE_SPLIT.split(text):
            start = text.index(part, pos)
            end = start + len(part)
            pos = end
            s = part.strip()
            if MIN_TEXT_LEN <= len(s) <= TEXT_MAX_LEN:
                out.append((start, end))
        return out
    return [m.span() for m in EXTRACT_RE[vtype].finditer(text)]


def extract_candidates(docs: list[Document], vtype: VType) -> list[Candidate]:
    out: list[Candidate] = []
    for doc in docs:
        for f in doc.fields:
            spans = _spans(vtype, f.text)
            distinct = len({f.text[a:b].strip() for a, b in spans})
            for i, (a, b) in enumerate(spans):
                raw = f.text[a:b].strip()
                prov = Provenance(
                    source_id=doc.doc_id,
                    source_kind=doc.kind,
                    trust=Trust.UNTRUSTED,
                    source_sender=doc.sender,
                    author=f.author,
                    field_path=f.path,
                    span=(a, b),
                    readers=f.readers,
                )
                out.append(
                    Candidate(
                        cid=f"{doc.doc_id}|{f.path}|{a}-{b}",
                        value=LabeledValue(raw, vtype, (prov,)),
                        doc_id=doc.doc_id,
                        doc_kind=doc.kind,
                        doc_type=doc.doc_type,
                        sender=doc.sender,
                        timestamp=doc.timestamp,
                        field_path=f.path,
                        field_structured=f.structured,
                        field_author=f.author,
                        span_index=i,
                        n_distinct_in_field=distinct,
                        # for TEXT the sentence itself may carry the cue
                        context_before=f.text[max(0, a - 80) : (b if vtype == VType.TEXT else a)],
                        doc_structured_text=doc.structured_text,
                    )
                )
    return out

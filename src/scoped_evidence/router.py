"""Small learned evidence router (pure-Python logistic regression).

Input per (argument, candidate): template-agnostic features computed from the
trusted task, the requested scope, the candidate field and its provenance.
Output per argument: the highest-scoring candidate id, or ABSTAIN when its
probability is below a fixed threshold. The router has no access to the
capability or validator; its output is only a proposal.
"""

from __future__ import annotations

import math
from collections import Counter

from .candidates import Candidate
from .selectors import ABSTAIN, RouterInput, Selector, from_requested_doc, has_cue, key_match

FEATURES = (
    "bias",
    "in_requested_field_path",
    "doc_from_requested_source",
    "field_author_is_source",
    "field_author_differs_from_sender",
    "key_given",
    "key_match",
    "latest_in_source",
    "recency_rank",
    "cue_before",
    "field_structured",
    "multi_value_field",
    "first_in_field",
    "history_given",
    "history_match",
    "history_conflict",
    "doc_type_in_task",
)


def featurize(x: RouterInput) -> list[tuple[Candidate, tuple[float, ...]]]:
    src_ts = sorted({c.timestamp for c in x.candidates if from_requested_doc(c, x)}, reverse=True)
    rank = {ts: (i / (len(src_ts) - 1) if len(src_ts) > 1 else 0.0) for i, ts in enumerate(src_ts)}
    task = x.task_text.lower()
    out = []
    for c in x.candidates:
        in_src = from_requested_doc(c, x)
        if x.request.file_path is not None:
            author_ok = in_src
        else:
            author_ok = c.field_author in x.entity_addresses
        hist = x.history_value
        f = (
            1.0,
            float(c.field_path == x.request.field_path),
            float(in_src),
            float(author_ok),
            float(c.field_author != c.sender),
            float(x.request.key is not None),
            float(key_match(c, x)),
            float(in_src and bool(src_ts) and c.timestamp == src_ts[0]),
            rank.get(c.timestamp, 1.0) if in_src else 1.0,
            float(has_cue(c)),
            float(c.field_structured),
            float(c.n_distinct_in_field > 1),
            float(c.span_index == 0),
            float(hist is not None),
            float(hist is not None and c.raw == hist),
            float(hist is not None and c.raw != hist),
            float(c.doc_type in task),
        )
        out.append((c, f))
    return out


def _sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


class LogisticRegression:
    def __init__(self, n_features: int, l2: float, lr: float, epochs: int) -> None:
        self.w = [0.0] * n_features
        self.l2, self.lr, self.epochs = l2, lr, epochs

    def fit(self, X: list[tuple[float, ...]], y: list[int]) -> dict:
        # Deduplicate identical rows (features are mostly binary) for speed.
        counts = Counter(zip(X, y))
        rows = list(counts.items())
        n = sum(counts.values())
        d = len(self.w)
        for _ in range(self.epochs):
            grad = [0.0] * d
            for (xi, yi), cnt in rows:
                p = _sigmoid(sum(wj * xj for wj, xj in zip(self.w, xi)))
                g = (p - yi) * cnt
                for j in range(d):
                    grad[j] += g * xi[j]
            for j in range(d):
                reg = self.l2 * self.w[j] if j > 0 else 0.0
                self.w[j] -= self.lr * (grad[j] / n + reg)
        loss = 0.0
        for (xi, yi), cnt in rows:
            p = min(max(_sigmoid(sum(wj * xj for wj, xj in zip(self.w, xi))), 1e-12), 1 - 1e-12)
            loss -= cnt * (yi * math.log(p) + (1 - yi) * math.log(1 - p))
        return {"n_examples": n, "n_unique_rows": len(rows), "train_logloss": loss / n}

    def predict(self, xi: tuple[float, ...]) -> float:
        return _sigmoid(sum(wj * xj for wj, xj in zip(self.w, xi)))


class LearnedRouter(Selector):
    name, mode = "learned_router", "field"

    def __init__(self, model: LogisticRegression, threshold: float) -> None:
        self.model, self.threshold = model, threshold
        self.n_scored = 0

    def propose(self, x: RouterInput) -> str:
        best, best_p = None, -1.0
        for c, f in featurize(x):
            self.n_scored += 1
            p = self.model.predict(f)
            if p > best_p:
                best, best_p = c, p
        if best is None or best_p < self.threshold:
            return ABSTAIN
        return best.cid

    def weights(self) -> dict[str, float]:
        return dict(zip(FEATURES, self.model.w))


def training_examples(episodes) -> tuple[list[tuple[float, ...]], list[int], dict]:
    """Pointwise examples from feasible episodes. Label 1 iff the candidate is
    the gold span (same document, field path and value). Uses the reference
    read path, so training sees exactly what the router sees at test time."""
    from .capability import CapabilityValidator
    from .environment import MockTools
    from .runner import read_documents, router_input

    X: list[tuple[float, ...]] = []
    y: list[int] = []
    n_eps = n_args = n_args_with_gold = 0
    for ep in episodes:
        if ep.gold is None:
            continue
        n_eps += 1
        docs, _ = read_documents(ep, CapabilityValidator((), ep.env.read_prefixes), MockTools(ep.env))
        for ap in ep.task.args:
            if ap.mode != "delegated":
                continue
            n_args += 1
            x = router_input(ep, ap.arg, docs)
            ev = ep.gold_evidence[ap.arg]
            hit = False
            for c, f in featurize(x):
                lab = int((c.doc_id, c.field_path) == ev and c.raw == ep.gold[ap.arg])
                hit |= bool(lab)
                X.append(f)
                y.append(lab)
            n_args_with_gold += hit
    return X, y, {"n_episodes": n_eps, "n_delegated_args": n_args, "n_args_with_gold_candidate": n_args_with_gold}

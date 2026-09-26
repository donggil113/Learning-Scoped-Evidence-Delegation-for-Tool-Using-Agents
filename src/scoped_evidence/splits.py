"""Train/test splits by independent unit (template, environment/domain, instance).

Episode seeds are derived deterministically from (base_seed, template,
condition, index). Train indices and test indices are disjoint ranges, so no
generated instance appears on both sides of any split.
"""

from __future__ import annotations

from .tasks import CONDITIONS, TEMPLATES, Episode, make_episode


def episode_seed(base_seed: int, tid: str, condition: str, idx: int) -> int:
    t = sorted(TEMPLATES).index(tid)
    c = CONDITIONS.index(condition)
    return base_seed * 1_000_003 + t * 100_003 + c * 10_007 + idx


def split_templates(split: dict, name: str) -> tuple[list[str], list[str]]:
    all_t = sorted(TEMPLATES)
    if name == "template":
        return list(split["train"]), list(split["test"])
    if name == "environment":
        tr = [t for t in all_t if TEMPLATES[t].domain in split["train"]]
        te = [t for t in all_t if TEMPLATES[t].domain in split["test"]]
        return tr, te
    if name == "instance":
        return all_t, all_t
    raise ValueError(name)


def build_episodes(tids: list[str], idx_range: range, base_seed: int, gen_cfg: dict,
                   conditions: tuple[str, ...] = CONDITIONS) -> list[Episode]:
    eps = []
    for tid in tids:
        for cond in conditions:
            for i in idx_range:
                eps.append(make_episode(tid, cond, episode_seed(base_seed, tid, cond, i), gen_cfg))
    return eps

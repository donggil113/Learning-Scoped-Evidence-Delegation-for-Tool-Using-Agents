# STATUS

Last updated 2026-09-26. Branch `claude/keen-lovelace-jat7ua`.

## Starting point (checked, not assumed)

- The repository was **empty**: no commits and no remote branches.
- There was no CLAUDE.md, STATUS.md, RESEARCH_PACKET.md, config or result
  file to read.
- There were no prior STOP or ARCHIVE decisions and no existing Work IDs, so
  none were mapped.
- The environment has Python 3.11 with no numpy, torch or pytest. Everything
  uses the standard library only, and nothing was installed.

## Done this session

| Item | Where | Status |
|------|-------|--------|
| Typed tool schemas (7 tools, typed arguments with integrity levels) | `src/scoped_evidence/schema.py`, `labels.py` | DONE |
| Capability validator (type, scope/provenance, requested-scope equality, flow, limit, budget, reads) | `capability.py`, `policy.py` | DONE |
| Local mock tools and synthetic secrets | `environment.py`, `tasks.py` | DONE |
| Seeded generator: 9 templates × 5 conditions (helpful / malicious / mixed / wrong fact / insufficient permission) | `tasks.py` | DONE |
| Selectors: doc_trust, deny_untrusted, camel_style (simplified re-implementation), rule_field, learned router, oracle, adversarial | `selectors.py`, `router.py` | DONE |
| Trace of allow/deny, reasons, evidence spans, requested vs granted scope | `runner.py` | DONE |
| Unit tests (45) | `tests/` | PASS, ENGINEERING_ONLY |
| Synthetic pilot | `scripts/run_first_run.py`, `configs/first_run.json` | COMPLETED, ENGINEERING_ONLY |
| Literature check | `RELATED_WORK.md` | DONE, with per-paper reading levels |
| Pre-registration of next decision experiment | `RESEARCH_PACKET.md` §6 | DONE |
| Manuscript skeleton | `paper/main.tex` | Skeleton only; results are `\todo{}` |

## Engineering result vs scientific result (kept separate)

- **Engineering: PASS.** Across 15,750 pilot outcome rows:
  - every validator-guarded selector, including a worst-case adversarial
    router, had 0 reference violations and 0 synthetic-secret leaks;
  - infeasible tasks were never executed;
  - the oracle reached 1.0.
- **Science: H1 NOT_TESTED.**
  - On synthetic data the learned router did **not** beat hand-written field
    rules. The learned − rule difference in secure success was +0.024
    (template split, n=3 templates), −0.007 (environment split) and −0.033
    (instance split).
  - This triggers the "re-assess the learning contribution" stop condition at
    the engineering level. The synthetic generator cannot settle H1 either
    way.
- **Novelty risk: high.**
  - ROPE (2608.27496), PACT (2605.11039) and ARGUS (2605.03378) already cover
    per-parameter origin enforcement, argument-level provenance contracts,
    and span-to-argument grounding with prompted LLMs.
  - RTBAS already trains a small dependency screener.
  - The only open question left is empirical: a *trained* binder vs rules vs
    a prompted-LLM binder under a fixed validator.

## Blocked / needs a decision

- **SED-E2-HEADROOM** (next decision experiment) needs approval to download
  `agentdojo` (MIT) and the AgentDyn repository (license NOT_CHECKED). It is
  CPU-only static analysis with no LLM calls.
- **SED-E3 and SED-E4** need an LLM backbone (paid API or GPU). NOT_RUN and not
  requested yet; they depend on the E2 outcome.

## How to reproduce

```
taskset -c 0,1 timeout 120 python3 -m unittest discover -s tests -v
taskset -c 0,1 timeout 120 python3 scripts/run_first_run.py --config configs/first_run.json
```

Results go to `results/raw/<run_id>/`: `metrics.json`, `outcomes.jsonl.gz`,
`traces_sample.jsonl.gz`, `routers.json`, `manifest_entry.json`. Runs are also
listed in `run_manifest.json`.

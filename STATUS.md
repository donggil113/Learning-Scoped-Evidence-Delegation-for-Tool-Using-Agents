# STATUS

Last updated 2026-09-27 (fifth session). Branch `claude/keen-lovelace-jat7ua`.

## Operational state

- **LEARNED_BINDER_METHOD = HOLD.** This is an operational decision by the
  user in session 5. It is not a result, and it does not say that all
  evidence-binding research is infeasible.
- **No new experiment was run in session 5.** There were no downloads, no
  API or GPU use, no prompted-binder run, no new attacks or AgentDyn, no
  extractor changes and no training.
- **The manuscript is NOT ICML-ready.** It was edited to audit scope (v4)
  and is SUBMISSION_READY = false.
- **Owner: UNASSIGNED.**

## What the current census shows (CONTRACT_V2, AgentDojo v1.2.2)

Every number below is ORACLE_PLAN_CONDITIONAL, in both arms. The call
sequence, read arguments, free-text arguments and final answer are ground
truth.

| Quantity (official channel) | strict | fallback |
|---|---|---|
| Envelope, typed resolver | [0.271, 0.292] | [0.273, 0.293] |
| Envelope, unique-or-abstain | [0.302, 0.323] | [0.314, 0.334] |
| Utility-only envelope | = secure envelope | = secure envelope |
| Selectable failures (all utility) | 247 variants / 27 tasks | 248 / 28 |
| Baseline-executed attacker goal (of 949) | 0 | 4 |
| Some admitted choice achieves it (witness bounds) | 31–106 | 35–110 |

- **Envelopes.** These are computational envelopes over partially searched
  trees. They are not CIs, achieved gains or learnable security gains.
- **Fallback is not gold-free.** It inserts gold values into slots that
  have no candidate (6 tasks). Only the actor-view derivation (slot types,
  candidates, baseline decisions) is gold-free, and that was checked on 5
  variants.
- **Output-dependent tasks.** 42 tasks (fallback) and 38 (strict) are
  ORACLE_OUTPUT_DEPENDENT. In fallback, 4 of them are also ORACLE_COMPOSED,
  so the union is 44.
- **"97/97 resolved"** means no replay error or budget exhaustion. It does
  not mean every optimum was found. 77 variants in 9 tasks had incomplete
  searches: 30 of them (3 workspace tasks) keep the secure/utility
  envelope [0, 1], and 75 keep attack reachability open.
- **Channels.** Official = effect on all 4,184 path records of this trace
  set. That is an observation, not an evaluator equivalence (the
  dual-channel fixture is kept).
- **Attack witnesses.** The 31–106 / 35–110 witness counts are not attack
  rates. They also rule out a no-risk claim.
- **Identifiability screen.** 248 NOT_REFUTED, but it is vacuous for 148
  (all rows vacuous in 15 of 28 tasks). NOT_REFUTED is not evidence of
  identifiability.
- **Candidate coverage.** 14 of 61 write tasks cannot be completed by any
  candidate *our generator* admits. That is not a limit of every binder.

## Corrections made in session 5 (from existing raw only)

- v3 text and report said that 77 variants keep [0, 1]. The correct
  statement is: 77 incomplete searches, of which 30 are [0, 1] for
  secure/utility and 75 are open for attack reachability.
- The v3 claim of a "gold-free contract" is narrowed to the actor-view
  derivation. The arms are oracle-conditioned, and fallback inserts gold.
- The strict and fallback numbers are now reported side by side, and the
  ORACLE_OUTPUT_DEPENDENT / ORACLE_COMPOSED overlap is taken from the flags.
- Changed claims: C43–C47, C49 and C50 in `paper/claims.csv`.

## Where things are

| Item | Path | Status |
|------|------|--------|
| Census raw | `results/raw/SED-E2-CONTRACT-CLOSURE_20260927T053244Z` | COMPLETED (session 4) |
| Frozen config | `configs/agentdojo_contract_v2.json` (sha256 `758868cb…`) | unchanged |
| Coverage diagnostic | `results/analysis/SED-E2-CC-COVERAGE_20260927T061102Z` | EXPLORATORY |
| V1 census | `results/raw/SED-E2-ADJ-HEADROOM_20260927T000630Z` | kept; gold-derived contract |
| INVALID run | `results/raw/SED-E2-ADJ-HEADROOM_20260927T000131Z` | kept |
| Manuscript v4 | `paper/main.tex`, `paper/tables/`, `paper/claims.csv` | COMPILE_NOT_RUN (no TeX, no icml2026 style) |
| Internal evidence package | `export_bundle/` | MANIFEST.json with sha256; large raw referenced, not copied |
| Anonymous source package | `submission_anon/` | paper sources only; anonymity scan in its MANIFEST |

Kept STOP / FAIL / INVALID: the E1 stop condition, the retracted v1
claims, the INVALID census run, and C35 marked CORRECTED.

## Resume conditions (all three required)

1. A human researcher fixes a new security research question and threat
   model.
2. There are independently executed traces, or a clear conditional
   evaluation contract, in which the actor is not given oracle answers or
   future observations.
3. A contribution distinct from the direct prior work (ROPE, PACT, ARGUS,
   CaMeL), plus explicit approval of a bounded execution budget.

None of these is met. Owner: UNASSIGNED.

## Reproduce (existing artefacts; no need to re-run for the manuscript)

```
python3 scripts/make_paper_tables.py && python3 scripts/check_tex_static.py
python3 scripts/make_export_bundle.py            # internal evidence package
python3 scripts/make_export_bundle.py --anon     # anonymous paper-source package
# census (only if re-running is ever approved):
PYTHONPATH=src taskset -c 0,1 timeout 7800 <venv>/bin/python scripts/run_contract_v2_census.py --config configs/agentdojo_contract_v2.json
```

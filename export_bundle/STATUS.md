# STATUS

Last updated 2026-09-27 (fourth session). Branch `claude/keen-lovelace-jat7ua`.

## This session: SED-E2-CONTRACT-CLOSURE (one decision experiment)

No learning was run. There was no new install or download; the existing
replay venv was reused. Everything ran offline on 2 CPU cores, with no LLM
API, GPU or service account.

| Item | Where | Status |
|------|-------|--------|
| Gold-boundary audit of the V1 census | RESEARCH_PACKET §6-CC; `tests/test_contract_v2.py` | V1 slots, contracts, writes and baseline scopes are **functions of hidden gold**. V1 is kept as the V1 contract's result, not as a deployable ceiling. |
| CONTRACT_V2 (schema-typed slots, actor-view candidates) | `src/scoped_evidence/adapters/agentdojo_contract_v2.py` | Mutation tests pass on 5 variants, and the negative control is detected. |
| Official vs executed-effect channels | same module; fixtures | Official is the primary channel. Abstention is a separate event and emits no assistant call. |
| Frozen protocol | `configs/agentdojo_contract_v2.json` (sha256 `758868cb…`, commit `325da98`) | POST_V1_REVISION, DEVELOPMENT-INFORMED |
| DEVELOPMENT smoke run (4 tasks) | `results/analysis/DEV-SED-E2-CONTRACT-CLOSURE_20260927T052947Z` | Exposed a number-extraction bug, which was fixed before the freeze |
| Census | `results/raw/SED-E2-CONTRACT-CLOSURE_20260927T053244Z` | COMPLETED, 97/97 resolved, 2183 s wall, 4100 CPU-s |
| Coverage diagnostic | `results/analysis/SED-E2-CC-COVERAGE_20260927T061102Z` | EXPLORATORY, post hoc |
| Manuscript v3 (edited from v2) | `paper/main.tex`, `paper/tables/`, `paper/claims.csv` (51 claims; CORE-1..3 = C45–C47) | COMPILE_NOT_RUN |
| Export bundle | `export_bundle/` (MANIFEST.json, BUILD.md) | No PDF |

## Key numbers (CONTRACT_V2, AgentDojo v1.2.2, oracle plan, official channel)

- **H_clair over the typed resolver: [0.273, 0.293]** (fallback, primary).
  - Unique-or-abstain: [0.314, 0.334].
  - Strict mode: [0.271, 0.292].
  - This is a computation interval, not a confidence interval.
- **Utility-only ceiling = secure ceiling.** All 248 selectable failures
  (28 tasks) are utility failures.
- **Attacks.**
  - The baselines executed 4/949 (all banking user_task_0), and 0 in strict
    mode.
  - The ground-truth path executed 0/709, and full abstention 0.
  - **Within-contract attack room: 35–110 injected variants** in which some
    admitted action achieves the attacker goal.
- **Channels.** Official = effect on all 4,184 path outcomes, because
  nothing is denied in this replay.
- **Coverage.** 14 of 61 write tasks cannot be completed by any admitted
  action. 43 gold slot values in 21 tasks are not admitted (29 are not in
  the actor view).
- **Identifiability screen.** 248 NOT_REFUTED, 0 REFUTED. It is vacuous for
  148 of them (singleton views).

## Decision (corrected wording)

- **Hold condition.** H_upper < δ = 0.05 is **sufficient** to hold. It was
  not met (0.293).
- **This does not require investment.** Holding a *trained* binder remains
  justified: the gap is utility-only, identifiability is only not refuted,
  and novelty is a measurement framing only.
- **Frozen follow-up rule.** The NOT_REFUTED rate is 0.273 ≥ δ, so the
  rule gives **PROPOSE_CONDITIONAL_NOT_RUN**.
- **Correction of session 3.** "H_upper ≥ δ, so investment is not held"
  over-read the rule. Also, [0.253, 0.335] is a computation interval, and
  it belongs to a gold-derived contract.

## Evidence levels (kept separate)

- **Engineering:** 80 tests. All pass in the replay venv. Under system
  python, 62 pass and 18 are skipped (replay and contract tests need
  agentdojo).
- **Toy (simulator):** the learned binder does not beat the rules. The
  failure is one of estimation (appendix of the manuscript).
- **Benchmark offline replay:** the AgentDojo V1 census (gold-derived
  contract) and the V2 census above. Both are oracle-plan ceilings, not
  performance.
- **Real-model results:** none.
- **Novelty:** unchanged. The work contributes a measurement framing only.

## Kept STOP / FAIL / INVALID

- E1 stop condition (the learned router does not beat the rules).
- Retracted v1 claims (expressivity; A2; the ambiguity-based rule).
- INVALID census run `SED-E2-ADJ-HEADROOM_20260927T000131Z`.
- The V1 census (`…000630Z`) is kept unchanged and is now labelled
  gold-derived contract. Claim C35 is marked CORRECTED (see C48).

## Blocked / needs approval

- **Learned or prompted binder follow-up** (proposed, not run). Needs an
  LLM backend (paid API or GPU); not approved.
- **AgentDyn:** not requested; license NOT_CHECKED.
- **Manuscript compile:** no TeX installation, and icml2026.zip is absent.
  The main body is about 4,620 words plus 3 tables; the page count is
  UNVERIFIED.

## Reproduce

```
scripts/setup_agentdojo_replay_env.sh <venv> <dl_dir>
PYTHONPATH=src:tests taskset -c 0,1 <venv>/bin/python -m unittest discover -s tests -v
PYTHONPATH=src taskset -c 0,1 timeout 7800 <venv>/bin/python scripts/run_contract_v2_census.py --config configs/agentdojo_contract_v2.json
PYTHONPATH=src taskset -c 0,1 <venv>/bin/python scripts/analyze_contract_v2_coverage.py --census results/raw/SED-E2-CONTRACT-CLOSURE_20260927T053244Z
python3 scripts/make_paper_tables.py && python3 scripts/check_tex_static.py
python3 scripts/make_export_bundle.py
```

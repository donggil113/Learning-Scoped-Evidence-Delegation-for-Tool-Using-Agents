# STATUS

Last updated 2026-09-27 (third session). Branch `claude/keen-lovelace-jat7ua`.

## This session: real evaluator and headroom on AgentDojo

No new router was trained. Everything ran offline on at most 2 CPU cores,
with no LLM API, GPU or service account.

| Item | Where | Status |
|------|-------|--------|
| Pinned snapshot: agentdojo 0.1.35 wheel (sha256 `364bea42…`, MIT) in an isolated venv, no LLM SDKs | `scripts/setup_agentdojo_replay_env.sh`, `adapters/agentdojo_shim.py` | DONE |
| Direct task enumeration (all versions) | `results/raw/SED-E2-ADJ-CENSUS_*` | v1.2.2: 97 user / 35 injection tasks |
| Evaluator semantics read in source | RESEARCH_PACKET §6-ADJ | security()=True means the **attack succeeded**; from_traces is checked first; traces are proposed calls |
| Outcome fields | `adapters/agentdojo_replay.py` | task_success / attack_success / policy_violation kept separate, plus blocked calls and tool errors |
| Fixtures on the snapshot (10) | `tests/test_agentdojo_replay.py` | PASS in the venv; SKIP under system python |
| Frozen protocol | `configs/agentdojo_headroom.json` | frozen after a DEVELOPMENT structural pass (no success values inspected) |
| Census | `results/raw/SED-E2-ADJ-HEADROOM_20260927T000630Z` | COMPLETED, ORACLE_PLAN_CONDITIONAL |
| First census run | `…_20260927T000131Z` | **INVALID** (witness-truthiness bug), kept |
| Slot sensitivity | `results/analysis/SED-E2-ADJ-SLOTS_*` | EXPLORATORY |
| Manuscript v2 | `paper/main.tex`, `paper/tables/`, `paper/claims.csv` (41 claims) | COMPILE_NOT_RUN |

## Key numbers (AgentDojo v1.2.2, oracle plan)

**H_clair, unique-or-abstain rule: [0.253, 0.335].**
- 89 of 97 tasks are resolved. The 8 unresolved tasks stay in the
  denominator.
- 52 tasks have no binder slot, so their gap is exactly 0.
- Secondary analysis (free-text slots fixed to the planner value): 0.306.
- First-admitted rule: [0.216, 0.299].

**Decision:** H_upper ≥ 0.05, so learning investment is **not** held. This is
**not** evidence that learning helps.

**The gap is mostly task reasoning among legitimate values.**
- Benign-only and injected-only bounds are nearly identical: [0.247, 0.330]
  and [0.254, 0.336].
- Slack accounts for most of it: [0.643, 0.690] over 21 tasks.

**Executed attacks under the fixed plan (851 injected variants).**
- The unique-or-abstain rule executed 4, all in one banking task where the
  injection erased the legitimate IBAN.
- The ground-truth plan executed 0.

**Benchmark property.** Injection text replaces the vector's default content.
The legitimate value was removed in 34 injected variants, and 9 of those
cannot be solved by any admitted action.

## Evidence levels (kept separate)

- **Engineering:** 71 tests. All 71 pass in the venv. Under system python,
  61 pass and 10 are skipped.
- **Toy (simulator):** the learned binder does not beat the rules. The
  failure is one of estimation, not expressivity.
- **Benchmark offline replay:** the AgentDojo ceiling above. It is a
  clairvoyant ceiling, not achievable performance.
- **Real-model results:** none.
- **Novelty:** unchanged. The work contributes a measurement framing only;
  see RELATED_WORK.md.

## Kept STOP / FAIL / INVALID

- E1 stop condition (the learned router does not beat the rules).
- Retracted v1 claims (expressivity; the A2 artifact; the ambiguity-based
  decision rule).
- INVALID census run `…000131Z`.

## Blocked / needs approval

- **AgentDyn census:** not requested; license NOT_CHECKED.
- **SED-E3:** matched comparison with a real planner. Needs an LLM backend
  (paid API or GPU).
- **Manuscript compile:** icml2026.zip and a TeX installation. The main body
  is about 5,250 words plus 4 tables, so the 8-page limit is at risk
  (UNVERIFIED).

## Reproduce

```
scripts/setup_agentdojo_replay_env.sh <venv> <dl_dir>
PYTHONPATH=src taskset -c 0,1 <venv>/bin/python -m unittest discover -s tests -v
PYTHONPATH=src taskset -c 0,1 timeout 1900 <venv>/bin/python scripts/run_agentdojo_headroom.py --config configs/agentdojo_headroom.json
python3 scripts/make_paper_tables.py && python3 scripts/check_tex_static.py
```

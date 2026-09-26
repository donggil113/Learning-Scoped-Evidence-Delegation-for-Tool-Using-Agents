# STATUS

Last updated 2026-09-26 (second session). Branch `claude/keen-lovelace-jat7ua`.

## State at the start of this session (checked)

- HEAD was `11d93fb`, identical to the remote. The working tree was clean.
- There is no CLAUDE.md.
- Kept unchanged:
  - the raw data of SED-E0 and SED-E1;
  - the E1 config;
  - the E1 stop-condition result ("learned router does not beat rules").

## Done this session

| Item | Where | Status / label |
|------|-------|----------------|
| Re-aggregated E1 from stored raw; separated proposed / executed / attacker levels | `scripts/reaggregate_e1.py`, `results/analysis/SED-E1-REAGG_*` | 0 differences; ENGINEERING_ONLY |
| Expressivity check with the actual features | `scripts/analyze_e1_expressivity.py`, `results/analysis/SED-E1-EXPR_*` | EXPLORATORY; hand-set linear weights = rule on 1920/1920 args |
| Bug fix: argmax on saturated probabilities → argmax on logits | `src/scoped_evidence/router.py` | E1 outcomes unchanged (0 regeneration mismatches) |
| Host metadata vs author text (A8); per-feature input origins | `labels.METADATA_ORIGIN`, `router.FEATURE_INPUTS` | DONE |
| Tests: no label leakage, frozen ≠ isolation, validator trusts labels, set-level counterexample premise, headroom core | `tests/` | 60/60 PASS |
| SED-E2-HEADROOM-R: bound H, protocol, sim adapter, AgentDojo adapter draft | `src/scoped_evidence/headroom.py`, `adapters/`, `configs/headroom_r.json`, `scripts/run_headroom.py` | sim smoke COMPLETED (ENGINEERING_ONLY); AgentDojo NOT_RUN |
| Manuscript v1 (all sections written) | `paper/main.tex`, `paper/tables/`, `paper/references.bib`, `paper/claims.csv` | COMPILE_NOT_RUN; SUBMISSION_READY=false |

## Retracted in this session (original text kept in RESEARCH_PACKET.md)

1. "A linear pointwise scorer cannot express the lexicographic rule." This is
   false for the actual features (SED-E1-EXPR).
2. "The router learned generator artifact A2." Not supported: T9 was held
   out of training in the template split.
3. The v1 E2 decision rule "< 10% ambiguity ⇒ < 5 pp improvement". It has a
   logic error, and ambiguity is only a proxy. It is replaced by the
   H_upper < δ rule in SED-E2-HEADROOM-R.

## Evidence levels (kept separate)

- **Engineering PASS.**
  - Validator-guarded selectors: 0 reference violations and 0
    synthetic-secret leaks.
  - Re-aggregation: 0 differences.
  - Tests: 60/60.
- **Toy (synthetic) results.**
  - The learned binder is not better than the rules: secure-success
    differences +0.024 / −0.007 / −0.033.
  - The failure is one of estimation, not expressivity (post hoc).
- **Real-model or benchmark results:** none.
- **External utility:** none.
- **Novelty judgement:** only a measurement framing remains relative to
  ROPE, PACT and ARGUS, as recorded in RELATED_WORK.md. Novelty is not
  established.

## Manuscript

- **Template:** ICML 2026, used temporarily. TEMPLATE_YEAR=2026 and
  TARGET_YEAR=2027; the ICML 2027 pages return 404.
- **Style files:** `icml2026.sty` and `.bst` are **not present**, because
  their download was not approved. No imitation style was created.
- **Compilation:** COMPILE_NOT_RUN, because there is no LaTeX compiler in the
  environment.
- **Static checks:** `scripts/check_tex_static.py` passes (refs, cites,
  macros, inputs, braces, anonymity). The main body is about 4,150 words
  excluding 5 tables. The page count is unverified.
- **Remaining TODOs (3):**
  - `SED-E2-HEADROOM-R/AgentDojo`
  - `SED-E2-HEADROOM-R/AgentDyn`
  - `SED-E3`

## Blocked / needs approval

- **SED-E2-HEADROOM-R on AgentDojo:** install the `agentdojo` PyPI package
  (MIT per its GitHub page; pin the version at approval). The work is
  CPU-only, with no LLM calls. After approval:
  1. verify API assumptions A-DJ1..A-DJ7;
  2. implement the adapter body;
  3. run the census.
- **SED-E2-HEADROOM-R on AgentDyn:** fetch `github.com/leolee99/AgentDyn`.
  Its license has not been checked.
- **Compiling the manuscript:** `icml2026.zip` from icml.cc and a TeX
  installation.
- **SED-E3:** an LLM backbone (paid API or GPU). This is conditional on
  H_upper ≥ 0.05.

## How to reproduce

```
taskset -c 0,1 timeout 120 python3 -m unittest discover -s tests -v
taskset -c 0,1 timeout 120 python3 scripts/run_first_run.py --config configs/first_run.json
python3 scripts/reaggregate_e1.py --run results/raw/SED-E1-SIM_20260926T144531Z
python3 scripts/analyze_e1_expressivity.py --run results/raw/SED-E1-SIM_20260926T144531Z
python3 scripts/run_headroom.py --source sim
python3 scripts/make_paper_tables.py && python3 scripts/check_tex_static.py
```

# Related work: what is already known and what is left

Checked 2026-09-26. Only public arXiv, GitHub and PyPI pages were read. Nothing
was downloaded or installed.

## Reading levels

Every entry says how much of the paper was actually read.

- **LA** is a literature agent delegated inside this session. Its reports are
  model output; the lead re-checked some of them (**LEAD** entries below).
- **FT-SECTIONS** means named sections of the arXiv HTML full text were read. It
  does not mean the whole paper was read.
- **ABSTRACT_ONLY** means only the abstract was read.
- **LEAD-ABS** means the lead re-fetched the abstract page and confirmed the
  title, authors and abstract.
- **LEAD-FT-QUOTE** means the lead fetched verbatim full-text quotes.

Treat any number marked LA and not LEAD as unverified.

## Closest prior work (ranked)

| # | Work | Read level | What it already does | Difference that remains for us |
|---|------|-----------|----------------------|---------------------------------|
| 1 | **ROPE**: "Routed Origin Policy Enforcement against Indirect Prompt Injection", Ma, Xiao, Yeoh, Zhang, Vorobeychik, arXiv 2608.27496 (27 Aug 2026) | LEAD-ABS + LEAD-FT-QUOTE (§3.1, §3.3, §4, §4.1, §4.6); LA FT-SECTIONS | Per-parameter origin checks on sensitive parameters. A router makes one LM call that "reads *only* the user's request … and outputs … the scope: the named source the user referenced and any parameter value the user wrote verbatim" (§3.1). Offline defaults act as a floor, and "the clamp drops every below-floor loosening … *by construction*, for any router" (§4.6). Origin labels are per platform-provided entry; "a file body or a web page … arrives as one block" (§3.3). The routers are off-the-shelf LLMs (Opus 4.8, Gemini-3-Flash, gpt-oss-20b), not trained. AgentDyn: "ASR to 1.6–2.6% while retaining 82–100% of undefended clean utility" (§4.1). | ROPE's router picks the *scope*, not *which span binds to an argument*. Labels inside one block (a file body) are not separated. The router is prompted, not trained. |
| 2 | **PACT**: "The Granularity Mismatch in Agent Security: Argument-Level Provenance Solves Enforcement and Isolates the LLM Reasoning Bottleneck", Fan et al., arXiv 2605.11039 (11 May 2026) | LEAD-ABS; LA FT-SECTIONS (§3.2–3.4, §4.2) | Semantic roles per argument, value provenance across replanning steps, and a role-specific trust contract checked per argument. Abstract: "8–16 percentage points above CaMeL at the same security level", "38.1–46.4% utility", and it "isolates the remaining deployment bottleneck to provenance inference and contract synthesis". Per LA, provenance inference uses an LLM classifier for ambiguous arguments (77.4% provenance accuracy, not re-verified). | A *trained* small binder or abstainer as the provenance-inference module. This is exactly the bottleneck PACT names, so our work would be an *instance* of PACT's open problem, not a new framing. |
| 3 | **ARGUS**: "Defending LLM Agents Against Context-Aware Prompt Injection", Weng et al., arXiv 2605.03378 (5 May 2026) | LEAD-ABS; LA FT-SECTIONS (overview, §5.1.1) | "labels runtime spans, grounds action arguments in supporting evidence, and releases an action only when benign evidence entails it" (abstract). Per LA, the grounding modules are prompted GPT-4o-mini calls. It introduces the AgentLure benchmark. | A trained span-to-argument binder, evaluated under a fixed external validator on AgentDojo and AgentDyn rather than AgentLure. The "span → argument grounding" framing itself is prior art. |
| 4 | **RTBAS**, Zhong et al., arXiv 2502.08966 | LA FT-SECTIONS (§7.1–7.3, §8.1.2) | IFC runtime with a dependency screener that selects context regions relevant to the next action. One screener is a *trained* 2-layer LSTM over attention features (per LA: "40 well-labeled test cases from AgentDojo … 81% test accuracy"). | RTBAS predicts region-level dependency for generation. It does not do per-argument binding with abstention. "Learned selection of which context influences an action" is prior art. |
| 5 | **CaMeL**: "Defeating Prompt Injections by Design", Debenedetti et al., arXiv 2503.18813 | LA FT-SECTIONS (design, capabilities/policies, Table 2) | P-LLM writes a program from the trusted query; a tool-less Q-LLM parses untrusted data into a Pydantic schema; values carry capabilities; policies are checked at tool calls. Abstract: "77% of tasks with provable security (compared to 84% with an undefended system)" on AgentDojo. | None on mechanism. Our "camel_style" baseline is a simplified re-implementation, not the reference code. |
| 6 | **FIDES**: "Securing AI Agents with Information-Flow Control", Costa et al., arXiv 2505.23643 | LA FT-SECTIONS | Confidentiality and integrity labels, `Hide`/`Expand` of labelled nodes, a type lattice (bool ⊑ enum ⊑ string). Per LA, Appendix E names permissive propagation (Siddiqui; RTBAS) as future work. | Node-level hiding and typed labels are prior art. |
| 7 | **Type-directed privilege separation**, Jacob et al., arXiv 2509.25926 (v2 title "Preventing Prompt Injection with Type-Directed Privilege Separation") | LA FT-SECTIONS (§III) | The quarantined side may pass only restricted types (int/float/bool/enum) or opaque variables. | Typed restriction of untrusted data is prior art. |
| 8 | **Permissive IFC**, Siddiqui et al., arXiv 2410.03055 | ABSTRACT_ONLY (LA) | Propagates labels only from influential inputs, using retrieval or a kNN-LM. | Model-based "which inputs influenced the output" is prior art. |
| 9 | **AirGapAgent**, Bagdasarian et al., arXiv 2405.05175 (CCS'24) | LA FT-SECTIONS (§4.1) | A prompted minimizer selects the minimal subset of user data for the task. | Task-conditioned data minimization is prior art. It is a privacy setting, not injection. |
| 10 | **Conseca**, Tsai & Bagdasarian, arXiv 2501.17070 | ABSTRACT_ONLY + intro (LA) | A model writes a context-specific policy from trusted context only, which is then enforced deterministically. | Generated per-task policies are prior art. |
| 11 | **Progent**, arXiv 2504.11703 | LA FT-SECTIONS (abstract, intro, §2.2, §4.1) | Argument-level allow/forbid rules. An LLM may update the policy, and an SMT check classifies each update as narrowing or expansion. Per LA, v3 intro: AgentDojo "ASR from 39.9% to 1.0%". | "A learned component bounded by a fixed enforcer" is prior art (Progent narrowing, ROPE clamp). |
| 12 | **Design Patterns**, Beurer-Kellner et al., arXiv 2506.08837 | LA FT-SECTIONS (§3.1) | Six patterns, including plan-then-execute, dual LLM, and context-minimization. | Conceptual prior art for control/data separation. |

Briefly also: MELON (2502.05174), f-secure (2409.19091), IPIGuard (2508.15310),
Task Shield (2412.16682), DRIFT (2506.12104), ACE (2504.20984), IsolateGPT
(2403.04960), PFI (2503.15547), AgentArmor (2508.01249), Firewalls (2502.01822),
AuthGraph (2605.26497), Agent-Sentry (2603.22868). Reading levels range from
ABSTRACT_ONLY to LA FT-SECTIONS; see the LA report summarized in STATUS.md.
None of them was re-verified by the lead.

## Benchmarks

- **AgentDojo**, Debenedetti et al., arXiv 2406.13352 (NeurIPS 2024 D&B).
  - Read level: LA FT-SECTIONS (Table 5, §5, metric definitions).
  - Contents: 97 user tasks, 27 injection tasks, 629 security cases, 4 suites.
  - Code: MIT license; per LA, v0.1.35 on PyPI. NOT_DOWNLOADED.
  - Independent unit for us: the **user task**. Injection tasks are nested
    within user tasks and are not independent samples.
- **AgentDyn**: "AgentDyn: Are Your Agent Security Defenses Deployable in
  Real-World Dynamic Environments?", Li, Wen, Shi, Zhang, Vorobeychik, Xiao,
  arXiv 2602.03117 (v1 3 Feb 2026, v3 7 May 2026).
  - Read level: LEAD-ABS; LA FT-SECTIONS (Tables 1 and 3, §3.1).
  - Contents: "60 challenging open-ended tasks and 560 injection test cases
    across Shopping, GitHub, and Daily Life", including "helpful third-party
    instructions".
  - Per LA, Table 3 reports CaMeL at 0.00 utility under GPT-4o; not re-verified.
  - License: NOT_CHECKED.

## Claims this project must NOT make as novel

1. Control/data-flow separation, plan-then-execute, and dual or quarantined LLMs
   (CaMeL, f-secure, ACE, IPIGuard, Design Patterns).
2. Provenance, capability or label tracking, and deterministic enforcement at
   tool calls (CaMeL, FIDES, RTBAS, Progent).
3. Argument- or parameter-level provenance checks, and grounding arguments to
   spans (PACT, ROPE, ARGUS, AuthGraph, Agent-Sentry).
4. Typed or field-level restriction or hiding of untrusted data (Jacob et al.,
   FIDES, CaMeL's Pydantic outputs, Firewalls, AgentArmor).
5. Learned or model-based selection of which context may influence an action,
   and data minimization (RTBAS, Siddiqui et al., AirGapAgent, DRIFT).
6. "A learned component cannot weaken security because a fixed enforcer bounds
   it" (ROPE clamp, Progent).
7. Abstention or escalation when evidence is insufficient (CaMeL,
   RTBAS confirmation, AirGapAgent escalation, PACT fail-closed).
8. Being first to beat CaMeL at equal security on AgentDojo (PACT claims this),
   or pointing out AgentDojo's static-task limitation (AgentDyn).

## What is left (conservative)

The only open question is **empirical**. Under a fixed, non-learned validator,
and at equal backbone, tools and budget, does a **small trained** per-argument
evidence binder with abstention give higher secure task success than (a)
rule-based field scopes and (b) a prompted-LLM binder (PACT/ARGUS style) at
matched cost? The answer must come from task/suite-held-out splits of external
benchmarks.

If the trained binder does not beat both (a) and (b), no methodological
contribution remains. A secondary open point is within-block span separation
(ROPE treats a file body as one block), but ARGUS already labels spans with
prompted models.

---

## Update 2026-09-26 (second session): full-text check of the closest papers

A second literature agent (**LA2**) read the arXiv HTML full text over live
HTTP. Nothing was saved to the repo. **LEAD** marks items the lead verified
personally, in the first session (abstracts of ROPE, PACT, ARGUS and
AgentDyn, and ROPE §3.1/§3.3/§4.6 quotes). The "Read" line lists the
sections that were actually read; everything else is marked not read.

### ROPE (2608.27496v1)

**Read:** §1–§8, App. A (except A.2), App. B, App. C.
**Not read:** A.2, App. D, App. E, rest of §4.4.

**Core definitions**
- Trust anchors T1–T3: the request; "a value under an unforgeable runtime
  origin that the user referenced"; the user's own authoritative records.
- Markers ordered by strictness `m ⊑ m'`: const⟨v⟩, prompt, sourced,
  record, oneof⟨S⟩, free, dest, explicit.
- Admission: `admit(v, o, Π)` with `Π = route(r)`.
- Assumptions:
  - A1: "the origin metadata the platform attaches to a value is truthful";
  - A2: record integrity;
  - A3: enumeration completeness.
- Clamp (§4.6): a router override is accepted "only when it is at least as
  strict" as the offline default.

**Setup:** AgentDyn (github, shopping, daily-life) and AgentDojo (banking,
slack, travel), under the important_instructions attack.
- Metrics: CU, UA, ASR.
- Models: GPT-4o-mini, GPT-4o, Gemini-2.5-Flash, Qwen3-235B.
- 11 baselines, including CaMeL, Progent, DRIFT, PFI and MELON.
- "every (user task × injection task) pair plus one clean run per user task".

**Learned component:** "The router is the defense's only learned
component". The reference runs are zero-shot; no training is described.

**Values inside one output:** labels come from the platform's division of a
result; "a file body or a web page … arrives as one block" (§3.3).

**Most relevant sentences for us**
- "The guarantee is about origin, not intent: it ensures an admitted value's
  origin is trusted, not that it is the value the user wanted" (§3.4).
- Closing the delegated-parameter class "would require inferring the user's
  intent … putting a language model back in the enforcement loop" (§5).

### PACT (2605.11039v1)

**Read:** §1, §3 (with theorem statements), §4.1–4.4, §5, App. A, C.1–C.4,
D.1–D.2, E, F.1, I.
**Not read:** proofs (App. B), F.2, G, H, J. §2 was only keyword-searched.

**Core definitions**
- Contract: `C_t = (ℓ, {a_i}, o)` with
  `a_i = (name_i, role_i, τ_i^min, F_i, R_i, D_i)`.
- Six roles.
- Trust lattice: TRUSTED > USER > TOOL_OUTPUT > EXTERNAL.
- Provenance tag: `π(v) = ⟨O(v), τ(v), B(v)⟩`.
- Merge rule: union of origins, min of trust, union of B.
- Admission check: `τ(v_i) ≥ τ_i^min`, `O(v_i) ∩ F_i = ∅`,
  `B(v_i) ∪ R_i ⊆ Discharged`.

**Setup:** "all 97 benign user tasks and all 27 injection tasks".
- Five models: Qwen family and GPT-4o-mini.
- Baselines: NoDefense, FIDES, CaMeL.
- LA2 did not find explicit Utility/Security definitions in the sections
  read.

**Learned component:** rules plus "an LLM classifier for remaining ambiguous
arguments"; no training described. Reported fidelity: 77.4% provenance
accuracy on 20 MCP tools.

**Note:** LA2 found an internal inconsistency. The text says 96.3% security
on Qwen-turbo/plus, while Table 2 shows 100.0. We do not quote these
numbers.

**Choosing among admissible candidates:** not addressed in the sections read.

### ARGUS (2605.03378v2)

**Read:** full main text (§1–§8). The HTML has no appendix.

**Core definitions:** influence-provenance graph `G = (V, E)`. A
ContextSegmenter labels spans {benign, anomalous}. The ArgumentGrounder
treats an argument that cannot be grounded as anomalous-supported. The
release condition is `ok_E ∧ ok_I`.

**Setup:** AgentLure (4 × 10 × 8 = 320 samples) plus an AgentDojo table.
- Backbone: GPT-4o-mini.
- 8 baselines; CaMeL is not among them.
- Metrics: ASR, W-ASR, U_c, U_a, Refusal, EDS, Cost.

**Learned component:** prompted sub-agents, no training.

**Relevant sentences**
- "A forged invoice can make the attacker's account the only available
  evidence" (§6.2).
- The paper mentions "ranking benign alternatives" as a direction (§6.2).

### CaMeL (2503.18813v2)

**Read:** §3–§6.

- Provenance and readers tags; tools may report an "inner source" such as an
  e-mail sender (§5.3).
- Python policy functions return Allowed or Denied (§5.2).
- send_money requires the recipient and amount to have the user as a source
  (§6.2.2).

### Bibliographic verification

All 18 BibTeX entries in `paper/references.bib` were checked against their
arXiv abstract pages: latest title, full author order, and year. None of the
pages has a journal-ref field. A venue appears only where the arXiv
Comments field states it:
- AirGapAgent: "at CCS'24";
- Conseca: "HotOS 2025";
- MELON: "ICML 2025";
- IPIGuard: "EMNLP 2025".

**Correction to the table above:** the "NeurIPS 2024 D&B" venue listed there
for AgentDojo is **not** confirmed by its arXiv page and is not used in the
manuscript.

### ICML style status (for the manuscript)

- **ICML 2027:** the call for papers, author instructions and style pages all
  returned 404 on 2026-09-26. No 2027 kit exists.
- **ICML 2026 author instructions:**
  - Camera-ready uses `\usepackage[accepted]{icml2026}` (from icml2026.zip).
  - Main body up to 8 pages at submission. References, the impact statement
    and appendices are unlimited and do not count.
  - The impact statement is required, placed before the references.
  - No links to public code repositories at submission.
- **Not verified:** the review-mode macro and the `.bst` name are not stated
  on any HTML page, and the zip was not downloaded.

## Update 2026-09-27 (fourth session)

No new literature was read. Two points bear on positioning:
- **CONTRACT_V2 is not a new mechanism.** It is our gold-free measurement
  contract, typed from the tool schema and fed from the actor view. Typed
  provenance contracts are prior work (PACT, ROPE, CaMeL).
- **The corrected census does not change the novelty assessment.** The gap
  is utility-only (task reasoning among legitimate values), so the census
  gives no security argument for a *trained* binder over prompted grounding
  (ARGUS) or a planner. The contribution remains a measurement framing plus
  a gold-boundary audit protocol.

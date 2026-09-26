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

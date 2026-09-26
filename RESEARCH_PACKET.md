# Research packet: Learning scoped evidence delegation for tool-using agents

## 1. Question

Under a **fixed** permission boundary, can we learn which field-level evidence
each tool argument should bind to? Specifically, does a small trained router
that outputs a candidate span or ABSTAIN increase **secure task success**?

The router never issues permissions and cannot bypass the validator.

## 2. Threat model and scope

- **Control flow is fixed by a trusted planner** that reads only the trusted
  task. This is prior art (CaMeL, plan-then-execute). We only study
  **argument binding**, i.e. data-flow errors and attacks.
- **The attacker controls the content of untrusted documents.** In the
  `in_scope_compromised` variant, the attacker also controls the account of a
  delegated sender, as in business email compromise.
- **The boundary is fixed and non-learned.** A capability validator
  (`src/scoped_evidence/capability.py`) enforces:
  - value types;
  - per-argument provenance scope (task literal, trusted record, or a
    delegated field of a delegated source);
  - requested scope equal to actual provenance;
  - confidentiality flow to sink readers;
  - numeric limits and call budget.
- **Gains from loosened permissions are not credited.** Every executed call of
  every method is re-checked against the reference field-level capability.
  Anything that fails that check counts as `ref_violation` and never as
  secure success.

## 3. Hypotheses

- **H1 (scientific, NOT_TESTED).** At equal backbone, tools, validator and
  budget, a trained binder gives higher secure task success under attack than
  rule-based field scopes on held-out suites and tasks. It must not increase
  the attack success rate, and it must not lose to a prompted-LLM binder
  (PACT/ARGUS style) at matched cost.
- **H0-eng (engineering, tested in SED-E0/E1).** The validator bounds any
  router:
  - zero reference violations and zero synthetic-secret leaks for every
    validator-guarded selector, including a worst-case adversarial router;
  - the five content categories produce distinguishable
    (decision, outcome) signatures.

## 4. Experiment registry

| ID | Purpose | Status | Evidence label |
|----|---------|--------|----------------|
| SED-E0-UNIT | 45 unit tests: validator, categories, router bounds, trace, isolation, splits, metrics | PASS (45/45) | ENGINEERING_ONLY |
| SED-E1-SIM | Synthetic CPU pilot of the full harness (7 selectors × 3 splits) | COMPLETED; invariants PASS | ENGINEERING_ONLY |
| SED-E2-HEADROOM | Static headroom analysis on AgentDojo and AgentDyn (no LLM) | NOT_RUN (needs download approval) | — |
| SED-E3-AGENTDOJO | Main comparison with an LLM backbone, suite-held-out | NOT_RUN (blocked on E2 and on LLM access) | — |
| SED-E4-AGENTDYN | Out-of-distribution test on AgentDyn | NOT_RUN | — |

## 5. SED-E1-SIM: pre-registered design and results (ENGINEERING_ONLY)

### Design

The design was frozen in `configs/first_run.json` before the run
(sha256 `40d59ded…`).

**Generator.** Nine templates in three domains, all synthetic:

- billing: T1 pay by order, T2 pay latest to known payee, T3 refund by reference;
- calendar: T4 latest proposal, T5 reschedule by reference, T6 invite from form;
- support: T7 tracking by order, T8 date from report file, T9 note from KB file.

Each template runs under five content conditions with the following variants:

| Condition | Variants |
|---|---|
| helpful | clean |
| malicious_instruction | out_of_scope, in_scope_compromised |
| mixed | other_field, same_field |
| wrong_fact | other_key, superseded, stale_field, same_field_history |
| insufficient_permission | entity_unknown, tool_not_granted, over_limit, restricted_path |

**Splits.**

- template: train T1, T2, T4, T5, T7, T8; test T3, T6, T9.
- environment: train billing + calendar; test support.
- instance: all templates, with disjoint seed ranges.

Each split has 30 train and 30 test episodes per (template, condition) cell.

**Selectors.**

- doc_trust: whole-document trust plus an ASSUMED instruction-following reader.
- deny_untrusted.
- camel_style: our simplified re-implementation. High-integrity untrusted
  arguments need user confirmation, which is counted as a refusal. The Q-LLM
  susceptibility is ASSUMED.
- rule_field: hand-written rules. It filters on field scope, then key, then
  trusted history, then recency, and binds only a unique value (otherwise it
  abstains).
- learned_router: logistic regression over 17 template-agnostic features,
  threshold 0.5, no tuning.
- Two bounds: oracle and a worst-case adversarial router.

**Metrics.**

- Primary: secure success, macro-averaged over test templates.
- Independent unit: the template. With three test templates, confidence
  intervals are not meaningful.

### Results

Run `results/raw/SED-E1-SIM_20260926T144531Z`, commit `54caffb`, 5.4 s on 2 cores.

**Engineering invariants: all PASS.**

- rule_field, learned_router, oracle and adversarial: `ref_violation` = 0 and
  `secret_leak` = 0 over 15,750 outcome rows.
- Infeasible tasks were never executed.
- The oracle's secure success on feasible episodes is 1.0, so a secure solution
  always exists inside the reference boundary.

**Boundary table** (instance split, per delegated argument, from
`boundary_table_instance_split`):

| Variant | Attacker value present | Attacker value inside reference scope |
|---|---|---|
| malicious/out_of_scope | 157/172 | 0 |
| mixed/other_field | 148/165 | 0 |
| malicious/in_scope_compromised | 113/128 | 113 |
| mixed/same_field | 122/135 | 122 |

- Wrong-fact variants other_key and superseded leave the scope ambiguous in
  100% of cases.
- So the field-level boundary alone removes out-of-scope and other-field
  attacks. Same-field and compromised-sender attacks, and stale values, can
  only be handled by *selection*.
- This follows from how the generator was built. It confirms that the harness
  classifies these cases correctly; it is not an empirical finding about real
  agents.

**Template split** (held-out T3, T6, T9; macro secure success, micro attack
success rate over attack conditions):

| Method | Secure success | ASR | Over-refusal given feasible | Wrong action |
|---|---|---|---|---|
| doc_trust | 0.560 | 0.472 | 0.244 | 0.056 |
| deny_untrusted | 0.200 | 0.000 | 1.000 | 0.000 |
| camel_style | 0.611 | 0.194 | 0.333 | 0.044 |
| rule_field | 0.773 | 0.178 | 0.194 | 0.000 |
| learned_router | 0.798 | 0.194 | 0.081 | 0.060 |
| oracle (bound) | 1.000 | 0.000 | 0.000 | 0.000 |

- doc_trust `ref_violation` = 0.067.
- camel_style asked for confirmation in 26.7% of episodes.

**learned − rule differences** (secure success, per-template means, cluster
bootstrap):

| Split | Mean difference | Per-template differences | 95% CI |
|---|---|---|---|
| template | +0.024 | T3 −0.013, T6 +0.047, T9 +0.040 | [−0.013, 0.047], n=3, not meaningful |
| environment | −0.007 | T7 +0.100, T8 −0.160, T9 +0.040 | — |
| instance | −0.033 | — | [−0.086, 0.013], n=9 |

In the instance split the learned router is also worse on attacks: the
attacker-influenced rate over all test episodes is +0.032 (template-cluster CI
[0.010, 0.050], n=9).

**Interpretation (engineering only).**

- On the synthetic generator, the learned router trades over-refusal for wrong
  actions and does **not** beat hand-written rules.
- Two identified causes:
  1. A linear pointwise scorer cannot express the lexicographic rule "filter
     by key, then recency". On held-out templates, wrong_fact/other_key gives
     43% wrong actions.
  2. The router learned a generator position artifact (item A2 below). On
     same_field_history it gave 100% wrong actions.
- On test templates, no method achieved secure success on in-scope
  compromised senders (0.00–0.03). rule_field and learned_router bound the
  attacker value in 100% of these episodes; camel_style did so in 44% and
  refused the rest through confirmation.
- **Stop-condition check.** "If there is no difference from the rule baseline,
  re-assess the learning contribution" is **triggered at the engineering
  level**. Synthetic data cannot decide H1 either way. This result is the
  reason E2 must run before any LLM or GPU spend.

### Known generator artifacts and assumptions (planted signals)

- **A1.** The cue lexicon is shared by the generator, the router features and
  the simulated susceptible readers. Attack cue rate 0.7, legitimate cue rate
  0.25.
- **A2.** Position leaks.
  - In `same_field_history`, the gold span always precedes the stale span.
  - In T9, the legitimate cue sentence precedes the gold sentence, so the gold
    sentence is not first in its field.
- **A3.** Timing.
  - Compromised and out-of-scope attacker documents are always newer than
    gold (T0+5).
  - `superseded` stale documents are always older.
- **A4.** Trusted payment history exists only for T1, with probability 0.5.
- **A5.** The planner is an oracle (template → plan), so planning errors are
  absent.
- **A6.** doc_trust and the Q-LLM step of camel_style use an ASSUMED
  instruction-following model. Their attack numbers are consequences of that
  assumption and are not measurements of any LLM.
- **A7.** camel_style is not the reference CaMeL code: it has no
  `have_enough_information` and no real user confirmation.

These artifacts are **not** fixed and re-run here. Doing so after seeing the
results would be a forked analysis. Any fix belongs in a new, separately
pre-registered version.

## 6. SED-E2-HEADROOM: next decision experiment (pre-registered; NOT_RUN)

**Purpose.** Before spending on LLMs, measure whether real benchmarks contain
cases where a learned binder *can* differ from rule-based field scopes under
the same validator.

**Inputs.**

- AgentDojo, pinned version to be confirmed at download (v0.1.35 per the PyPI
  page read by the LA).
  - Suites: workspace, slack, travel, banking.
  - Ground-truth calls of each user task.
  - Environment data and injection vector locations.
- AgentDyn, only for tasks with deterministic ground truth. Tasks without it
  are reported as NOT_APPLICABLE.

**Procedure** (CPU only, no LLM calls, deterministic). For every argument of
every state-changing ground-truth call, classify its origin:

- trusted literal from the user prompt;
- field value from tool output (record the object type and field path);
- computed value.

Then, for each field-origin argument:

- (i) Is the gold value unique among the values of that field path in the tool
  outputs of the trajectory? (ambiguity)
- (ii) Does any injection vector reachable in that user task lie in the same
  field path as the argument? (in-scope attack)

**Headroom unit.** A user task has headroom if at least one argument is
ambiguous in scope, or has an injection vector inside its scope.

**Decision rule** (fixed now). With H = user tasks with headroom and
N = user tasks:

- If H/N < 0.10 on AgentDojo **and** on the AgentDyn subset, then the maximum
  achievable learned − rule difference is below the E3 minimum effect of
  5 pp. **STOP the learning-method line.** Report as a measurement or negative
  result.
- Otherwise proceed to E3 using only the headroom tasks as the primary stratum,
  and report all tasks as well.

**Budget.** 2 CPU cores, at most 10 minutes, no GPU, no API. Requires approval
to download the `agentdojo` package and the AgentDyn repository.

## 7. SED-E3 (sketch; to be frozen only after E2)

- **Fixed across methods:** one backbone at temperature 0, the same tool set,
  the same per-task token and tool-call budget, and the same validator.
- **Methods:**
  - rule_field: per-suite schema rules written before seeing the test suite;
  - learned router: trained on the train suites only;
  - prompted-LLM binder (PACT/ARGUS style, same backbone): the key comparator;
  - CaMeL reference implementation if usable (Apache-2.0), otherwise our
    re-implementation, labelled as such;
  - doc_trust;
  - deny_untrusted.
- **Splits:** leave-one-suite-out on AgentDojo (4 folds); AgentDyn as test only.
- **Primary metric:** secure utility under attack, macro over held-out user
  tasks.
- **Unit:** user task. Use a cluster bootstrap over user tasks with injection
  tasks nested, 10,000 resamples.
- **Support for H1 requires all of:**
  - learned − rule ≥ +5 pp with 95% CI > 0;
  - learned − prompted binder ≥ 0 at ≤ matched cost;
  - ASR difference ≤ +1 pp.
- If these fail, re-assess the learning contribution; do not sweep.

## 8. Claims ledger

| Claim | Status |
|-------|--------|
| The validator bounds any router in the simulator (0 reference violations, 0 secret leaks, adversarial router included) | Supported, ENGINEERING_ONLY (E0, E1) |
| The field-level boundary separates out-of-scope and other-field injections from same-field and compromised-sender ones in the simulator | Supported by construction, ENGINEERING_ONLY |
| A learned binder beats rule-based field scopes | NOT_TESTED on real data; **not observed** on synthetic data |
| A learned binder beats a prompted-LLM binder | NOT_RUN |
| Any number about real LLM agents | NONE produced by this project |
| Formal security guarantee | UNPROVED. The validator is tested, not verified. "Router cannot bypass" relies on (a) selectors returning only candidate ids and (b) provenance being created only by trusted extraction code. Both are enforced by code structure and tests, not by proof. |

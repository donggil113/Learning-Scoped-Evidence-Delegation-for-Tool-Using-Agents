#!/usr/bin/env python3
"""Generate manuscript tables and number macros from stored raw/analysis files.

Reads paper/sources.json; writes paper/tables/*.tex. Never recomputes an
experiment; all numbers come from the stored JSON files.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "paper" / "tables"

NAMES = {
    "doc_trust": "Whole-document trust$^\\dagger$",
    "deny_untrusted": "Untrusted-all deny",
    "camel_style": "CaMeL-style (simulated)$^\\dagger$",
    "rule_field": "Rule field scopes",
    "learned_router": "Learned binder (LR)",
    "oracle": "Oracle binder (bound)",
    "adversarial": "Adversarial binder (bound)",
}
ORDER = ["doc_trust", "deny_untrusted", "camel_style", "rule_field", "learned_router", "oracle", "adversarial"]


def f3(x):
    return "--" if x is None else f"{x:.3f}"


def signed(x):
    return "--" if x is None else f"{x:+.3f}"


def esc(s: str) -> str:
    return s.replace("_", "\\_")


def main() -> None:
    src = json.loads((ROOT / "paper" / "sources.json").read_text())
    m = json.loads((ROOT / src["e1_run"] / "metrics.json").read_text())
    reagg = json.loads((ROOT / src["e1_reagg"] / "reaggregation.json").read_text())
    expr = json.loads((ROOT / src["e1_expr"] / "expressivity.json").read_text())
    hr = json.loads((ROOT / src["e2_sim"] / "status.json").read_text())
    dj = json.loads((ROOT / src["e2_agentdojo_attempt"] / "status.json").read_text())
    man = json.loads((ROOT / src["e1_run"] / "manifest_entry.json").read_text())
    OUT.mkdir(parents=True, exist_ok=True)

    # --- main E1 table (template split) -------------------------------------
    rows = []
    for meth in ORDER:
        x = m["metrics"]["template"][meth]
        mi, ma = x["micro"], x["macro_over_templates"]
        rows.append(f"{NAMES[meth]} & {f3(ma['secure_success'])} & {f3(mi['attack_success_rate'])} & "
                    f"{f3(mi['ref_violation'])} & {f3(mi['over_refusal_given_feasible'])} & "
                    f"{f3(mi['wrong_action'])} & {f3(mi['needs_confirmation'])} \\\\")
    (OUT / "e1_main.tex").write_text(
        "\\begin{tabular}{lcccccc}\n\\toprule\n"
        "Selector & SS$\\uparrow$ & ASR$\\downarrow$ & RefViol$\\downarrow$ & OverRef$\\downarrow$ & Wrong$\\downarrow$ & Confirm \\\\\n"
        "\\midrule\n" + "\n".join(rows[:5]) + "\n\\midrule\n" + "\n".join(rows[5:]) + "\n\\bottomrule\n\\end{tabular}\n")

    # --- learned - rule differences --------------------------------------------
    drows = []
    for s in ("template", "environment", "instance"):
        c = m["learned_minus_rule"][s]
        ss = c["secure_success"]
        per = ", ".join(f"{t}~{v:+.3f}" for t, v in ss["per_template_diff"].items()) if s != "instance" else "9 templates"
        lo, hi = ss["cluster_bootstrap_95ci"]
        drows.append(f"{s} & {ss['n_clusters']} & {signed(ss['mean_diff'])} & [{lo:+.3f}, {hi:+.3f}] & "
                     f"{signed(c['attacker_influenced']['mean_diff'])} & {signed(c['over_refusal']['mean_diff'])} & "
                     f"{signed(c['wrong_action']['mean_diff'])} & {per} \\\\")
    (OUT / "e1_diff.tex").write_text(
        "\\begin{tabular}{lccccccl}\n\\toprule\n"
        "Split & $n_T$ & $\\Delta$SS & 95\\% CI$^\\ddagger$ & $\\Delta$Atk & $\\Delta$OverRef & $\\Delta$Wrong & per template \\\\\n"
        "\\midrule\n" + "\n".join(drows) + "\n\\bottomrule\n\\end{tabular}\n")

    # --- boundary table -----------------------------------------------------------
    b = m["boundary_table_instance_split"]
    brows = []
    labels = {
        "malicious_instruction/out_of_scope": "malicious / attacker doc",
        "mixed/other_field": "mixed / other field",
        "malicious_instruction/in_scope_compromised": "malicious / compromised sender",
        "mixed/same_field": "mixed / same field",
        "wrong_fact/other_key": "wrong fact / other key",
        "wrong_fact/superseded": "wrong fact / superseded",
        "wrong_fact/stale_field": "wrong fact / stale field",
        "wrong_fact/same_field_history": "wrong fact / same-field hist.",
        "helpful/clean": "helpful / clean",
    }
    for k, lab in labels.items():
        v = b[k]
        brows.append(f"{lab} & {v['n_args']} & {v['attack_present']} & {v['attack_in_scope']} & {v['ambiguous_in_scope']} \\\\")
    (OUT / "e1_boundary.tex").write_text(
        "\\begin{tabular}{lcccc}\n\\toprule\n"
        "Condition/variant & Args & Atk.\\ present & Atk.\\ in scope & Ambig.\\ in scope \\\\\n\\midrule\n"
        + "\n".join(brows) + "\n\\bottomrule\n\\end{tabular}\n")

    # --- call levels (template split) ------------------------------------------------
    lrows = []
    for meth in ORDER:
        c = reagg["levels"][f"template/{meth}"]["counts"]
        codes = reagg["levels"][f"template/{meth}"]["native_denial_reason_codes"]
        codes_s = ", ".join(f"{esc(k)} {v}" for k, v in sorted(codes.items())) or "--"
        lrows.append(f"{NAMES[meth]} & {c['episodes']} & {c['proposed']} & {c['allowed_executed']} & "
                     f"{c['executed_attacker_value']} & {c['executed_ref_violation']} & {codes_s} \\\\")
    (OUT / "e1_levels.tex").write_text(
        "\\begin{tabular}{lcccccl}\n\\toprule\n"
        "Selector & Episodes & Proposed & Executed & Exec.\\ w/ atk.\\ value & Exec.\\ ref.\\ viol. & Native denials \\\\\n"
        "\\midrule\n" + "\n".join(lrows) + "\n\\bottomrule\n\\end{tabular}\n")

    # --- secondary splits ------------------------------------------------------------------
    for s in ("environment", "instance"):
        rows = []
        for meth in ORDER:
            x = m["metrics"][s][meth]
            mi, ma = x["micro"], x["macro_over_templates"]
            rows.append(f"{NAMES[meth]} & {f3(ma['secure_success'])} & {f3(mi['attack_success_rate'])} & "
                        f"{f3(mi['ref_violation'])} & {f3(mi['over_refusal_given_feasible'])} & {f3(mi['wrong_action'])} \\\\")
        (OUT / f"e1_{s}.tex").write_text(
            "\\begin{tabular}{lccccc}\n\\toprule\n"
            "Selector & SS & ASR & RefViol & OverRef & Wrong \\\\\n\\midrule\n" + "\n".join(rows)
            + "\n\\bottomrule\n\\end{tabular}\n")

    # --- expressivity ---------------------------------------------------------------------------
    erows = []
    for s in ("template", "environment", "instance"):
        a = expr["splits"][s]["agreement_counts"]
        erows.append(f"{s} & {a['n_args']} & {a['rule_binds']} & {a['lex_equals_rule']} & {a['learned_equals_rule']} & "
                     f"{expr['splits'][s]['regeneration_mismatches_vs_stored_outcomes']} \\\\")
    (OUT / "e1_expr.tex").write_text(
        "\\begin{tabular}{lccccc}\n\\toprule\n"
        "Split & Args & Rule binds & Lex $=$ rule & Learned $=$ rule & Regen.\\ mismatches \\\\\n\\midrule\n"
        + "\n".join(erows) + "\n\\bottomrule\n\\end{tabular}\n")

    # --- headroom smoke --------------------------------------------------------------------------
    hs = hr["summary"]
    hrows = [f"{t} & {v['n_variants']} & {f3(v['s_rule'])} & {f3(v['s_oracle'])} & {f3(v['gap'])} \\\\"
             for t, v in sorted(hr["per_task"].items())]
    (OUT / "e2_sim.tex").write_text(
        "\\begin{tabular}{lcccc}\n\\toprule\n"
        "Template $t$ & Variants & $s_{\\mathrm{rule}}(t)$ & $s_{\\mathrm{oracle}}(t)$ & gap \\\\\n\\midrule\n"
        + "\n".join(hrows) + "\n\\midrule\n"
        f"$H$ (all resolved) & & & & {f3(hs['H_upper_unresolved_as_max'])} \\\\\n"
        f"Ambiguity proxy & & & & {f3(hs['ambiguity_proxy_fraction'])} \\\\\n"
        "\\bottomrule\n\\end{tabular}\n")

    # --- number macros -------------------------------------------------------------------------------
    inv = m["engineering_invariants"]
    tpl = m["metrics"]["template"]
    d = m["learned_minus_rule"]
    ex = expr["splits"]
    nums = {
        "EOneRows": f"{man['n_outcome_rows']:,}".replace(",", "{,}"),
        "EOneWall": f"{man['wall_clock_seconds']}",
        "EOneCommit": man["git_commit"][:7],
        "RuleSS": f3(tpl["rule_field"]["macro_over_templates"]["secure_success"]),
        "LearnSS": f3(tpl["learned_router"]["macro_over_templates"]["secure_success"]),
        "CamelSS": f3(tpl["camel_style"]["macro_over_templates"]["secure_success"]),
        "DocSS": f3(tpl["doc_trust"]["macro_over_templates"]["secure_success"]),
        "DocRefViol": f3(tpl["doc_trust"]["micro"]["ref_violation"]),
        "RuleASR": f3(tpl["rule_field"]["micro"]["attack_success_rate"]),
        "LearnASR": f3(tpl["learned_router"]["micro"]["attack_success_rate"]),
        "DiffTemplate": signed(d["template"]["secure_success"]["mean_diff"]),
        "DiffEnv": signed(d["environment"]["secure_success"]["mean_diff"]),
        "DiffInstance": signed(d["instance"]["secure_success"]["mean_diff"]),
        "DiffInstanceAtk": signed(d["instance"]["attacker_influenced"]["mean_diff"]),
        "LexAgreeTotal": str(sum(ex[s]["agreement_counts"]["lex_equals_rule"] for s in ex)),
        "ArgsTotal": str(sum(ex[s]["agreement_counts"]["n_args"] for s in ex)),
        "LearnAgreeTotal": str(sum(ex[s]["agreement_counts"]["learned_equals_rule"] for s in ex)),
        "HSim": f3(hs["H_upper_unresolved_as_max"]),
        "ProxySim": f3(hs["ambiguity_proxy_fraction"]),
        "GuardedRefViol": str(sum(v for k, v in inv.items() if k.endswith(":ref_violation_count"))),
        "GuardedLeak": str(inv["all_methods:secret_leak_count"]),
        "LearnOutOfScopeProposals": str(reagg["levels"]["template/learned_router"]["native_denial_reason_codes"].get("PROVENANCE_OUT_OF_SCOPE", 0)),
        "AgentDojoStatus": dj["status"].replace("_", "\\_"),
    }
    (OUT / "numbers.tex").write_text(
        "% generated by scripts/make_paper_tables.py from paper/sources.json -- do not edit\n"
        + "\n".join(f"\\newcommand{{\\{k}}}{{{v}}}" for k, v in nums.items()) + "\n")
    print(json.dumps(nums, indent=1))


if __name__ == "__main__":
    main()

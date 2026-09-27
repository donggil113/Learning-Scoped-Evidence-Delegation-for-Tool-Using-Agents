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

    # --- AgentDojo offline census (SED-E2-ADJ) --------------------------------------------------------
    adj = None
    if src.get("adj_headroom"):
        adj = json.loads((ROOT / src["adj_headroom"] / "summary.json").read_text())
        census = json.loads((ROOT / src["adj_census"] / "task_census.json").read_text())
        v = census["versions"]["v1.2.2"]
        crow = [f"{sn} & {v[sn]['n_user']} & {v[sn]['n_injection']} \\\\" for sn in ("workspace", "travel", "banking", "slack")]
        crow.append(f"total & {v['_total']['n_user']} & {v['_total']['n_injection']} \\\\")
        (OUT / "adj_census.tex").write_text(
            "\\begin{tabular}{lcc}\n\\toprule\nSuite (v1.2.2) & User tasks & Injection tasks \\\\\n\\midrule\n"
            + "\n".join(crow) + "\n\\bottomrule\n\\end{tabular}\n")
        R = adj["results"]
        hrows = []
        for mode, label in (("primary", "free-text slots UNRESOLVED"), ("secondary", "free-text slots planner-fixed")):
            x = R[mode]
            for rk, rl in (("rule_unique", "unique-or-abstain"), ("rule_first", "first-admitted")):
                h = x[rk]
                hrows.append(f"{label} & {rl} & {x['n_resolved']}/{x['n_user_tasks']} & "
                             f"[{h['H_clair_lower']:.3f}, {h['H_clair_upper']:.3f}] \\\\")
        (OUT / "adj_h.tex").write_text(
            "\\begin{tabular}{llcc}\n\\toprule\nSlots & Rule & Resolved & $[H^{\\mathrm{clair}}_{\\mathrm{lower}}, H^{\\mathrm{clair}}_{\\mathrm{upper}}]$ \\\\\n\\midrule\n"
            + "\n".join(hrows) + "\n\\bottomrule\n\\end{tabular}\n")
        x = R["primary"]
        brows = [
            f"benign variants only & [{x['benign_only_rule_unique']['H_clair_lower']:.3f}, {x['benign_only_rule_unique']['H_clair_upper']:.3f}] \\\\",
            f"injected variants only & [{x['injected_only_rule_unique']['H_clair_lower']:.3f}, {x['injected_only_rule_unique']['H_clair_upper']:.3f}] \\\\",
        ]
        (OUT / "adj_h_split.tex").write_text(
            "\\begin{tabular}{lc}\n\\toprule\nVariants (primary, unique-or-abstain) & $[H_{\\mathrm{lower}}, H_{\\mathrm{upper}}]$ \\\\\n\\midrule\n"
            + "\n".join(brows) + "\n\\bottomrule\n\\end{tabular}\n")
        # per-suite gap sums (primary, unique)
        per = x["rule_unique_per_task"]
        srows = []
        for sn in ("workspace", "travel", "banking", "slack"):
            ts = [p for p in per if p["task"].startswith(sn + "/")]
            n_unres = sum(p["status"] != "OK" for p in ts)
            n_gap = sum(p["status"] == "OK" and p["gap"][0] > 1e-9 for p in ts)
            lo = sum(p["gap"][0] for p in ts) / len(ts)
            up = sum(p["gap"][1] for p in ts) / len(ts)
            srows.append(f"{sn} & {len(ts)} & {n_gap} & {n_unres} & [{lo:.3f}, {up:.3f}] \\\\")
        (OUT / "adj_suite.tex").write_text(
            "\\begin{tabular}{lcccc}\n\\toprule\nSuite & Tasks & Tasks with gap $>0$ & Unresolved & per-suite $[H_{\\mathrm{lower}}, H_{\\mathrm{upper}}]$ \\\\\n\\midrule\n"
            + "\n".join(srows) + "\n\\bottomrule\n\\end{tabular}\n")

    # --- CONTRACT_V2 census (SED-E2-CONTRACT-CLOSURE) -----------------------------------------------
    cc = None
    if src.get("cc_census"):
        cc = json.loads((ROOT / src["cc_census"] / "summary.json").read_text())
        F, St = cc["results"]["fallback"], cc["results"]["strict"]

        def iv(h):
            return f"[{h['H_lower']:.3f}, {h['H_upper']:.3f}]"

        hrows = []
        for mode, R in (("fallback (primary)", F), ("strict", St)):
            for b, bl in (("resolver", "typed resolver"), ("rule_unique", "unique-or-abstain")):
                H = R["H"]
                hrows.append(f"{mode} & {bl} & {iv(H[f'{b}|official|secure'])} & {iv(H[f'{b}|effect|secure'])} & "
                             f"{iv(H[f'{b}|official|task'])} \\\\")
        (OUT / "cc_h.tex").write_text(
            "\\begin{tabular}{llccc}\n\\toprule\nEmpty-slot mode & Baseline & Official, secure & Effect, secure & Official, utility only \\\\\n\\midrule\n"
            + "\n".join(hrows) + "\n\\bottomrule\n\\end{tabular}\n")
        arows = []
        ao, ae = F["attack_room"]["official"], F["attack_room"]["effect"]
        for b, bl in (("resolver", "typed resolver"), ("rule_unique", "unique-or-abstain"), ("all_abstain", "abstain on every write")):
            arows.append(f"{bl} & {ao[b + '_attack_count']} & {ae[b + '_attack_count']} \\\\")
        arows.append(f"ground-truth path (gold admitted, {ao['gt_path_n_variants_gold_admitted']} variants) & "
                     f"{ao['gt_path_attack_count']} & {ae['gt_path_attack_count']} \\\\")
        arows.append(f"some admitted action reaches the attacker goal & "
                     f"{ao['attack_reachable_count_lower']}--{ao['attack_reachable_count_lower'] + ao['attack_reachable_count_undetermined']} & "
                     f"{ae['attack_reachable_count_lower']}--{ae['attack_reachable_count_lower'] + ae['attack_reachable_count_undetermined']} \\\\")
        (OUT / "cc_attack.tex").write_text(
            "\\begin{tabular}{lcc}\n\\toprule\n"
            f"Injected variants ({ao['n_injected_variants']}), fallback mode & Official & Effect \\\\\n\\midrule\n"
            + "\n".join(arows) + "\n\\bottomrule\n\\end{tabular}\n")
        per = F["primary_per_task"]
        ident = cc.get("identifiability_rows", [])
        srows = []
        for sn in ("workspace", "travel", "banking", "slack"):
            ts = [p for p in per if p["task"].startswith(sn + "/")]
            if not ts:
                continue
            lo = sum(p["gap"][0] for p in ts) / len(ts)
            up = sum(p["gap"][1] for p in ts) / len(ts)
            n_gap = sum(p["status"] == "OK" and p["gap"][0] > 1e-9 for p in ts)
            n_und = sum(p["status"] == "OK" and p["gap"][1] - p["gap"][0] > 1e-9 for p in ts)
            n_unres = sum(p["status"] != "OK" for p in ts)
            sel = sum(1 for r in ident if r["task"].startswith(sn + "/"))
            nr = sum(1 for r in ident if r["task"].startswith(sn + "/") and r["status"] == "NOT_REFUTED")
            srows.append(f"{sn} & {len(ts)} & {n_gap} & {n_und} & {n_unres} & [{lo:.3f}, {up:.3f}] & {sel} & {nr} \\\\")
        (OUT / "cc_suite.tex").write_text(
            "\\begin{tabular}{lccccccc}\n\\toprule\nSuite & Tasks & Gap$>0$ & Undet. & Unres. & $[H_{\\mathrm{lower}}, H_{\\mathrm{upper}}]$ & Sel.\\ fail. & Not refuted \\\\\n\\midrule\n"
            + "\n".join(srows) + "\n\\bottomrule\n\\end{tabular}\n")
        if adj is not None:
            P = adj["results"]["primary"]
            vrows = [
                f"V1: slots and contract from benign ground truth & unique-or-abstain & {P['n_resolved']}/{P['n_user_tasks']} & "
                f"[{P['rule_unique']['H_clair_lower']:.3f}, {P['rule_unique']['H_clair_upper']:.3f}] & "
                f"{round(P['rule_unique_attack_success_rate_injected'] * P['injected_variants'])}/{P['injected_variants']} \\\\",
            ]
            for b, bl in (("rule_unique", "unique-or-abstain"), ("resolver", "typed resolver")):
                vrows.append(f"V2: schema slots, actor-view candidates & {bl} & {F['n_resolved']}/{F['n_tasks']} & "
                             f"{iv(F['H'][f'{b}|official|secure'])} & {ao[b + '_attack_count']}/{ao['n_injected_variants']} \\\\")
            (OUT / "cc_v1v2.tex").write_text(
                "\\begin{tabular}{llccc}\n\\toprule\nContract & Baseline & Resolved & $[H_{\\mathrm{lower}}, H_{\\mathrm{upper}}]$ & Executed attacks \\\\\n\\midrule\n"
                + "\n".join(vrows) + "\n\\bottomrule\n\\end{tabular}\n")

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
    if adj is not None:
        P, S = adj["results"]["primary"], adj["results"]["secondary"]
        nums.update({
            "AdjUser": str(P["n_user_tasks"]),
            "AdjResolved": str(P["n_resolved"]),
            "AdjUnresolved": str(P["n_user_tasks"] - P["n_resolved"]),
            "AdjZeroSlot": str(P["n_tasks_zero_slots"]),
            "AdjVariants": f"{P['n_variants']:,}".replace(",", "{,}"),
            "AdjInjVariants": str(P["injected_variants"]),
            "AdjHlo": f"{P['rule_unique']['H_clair_lower']:.3f}",
            "AdjHup": f"{P['rule_unique']['H_clair_upper']:.3f}",
            "AdjHfirstLo": f"{P['rule_first']['H_clair_lower']:.3f}",
            "AdjHfirstUp": f"{P['rule_first']['H_clair_upper']:.3f}",
            "AdjHsecLo": f"{S['rule_unique']['H_clair_lower']:.3f}",
            "AdjHsecUp": f"{S['rule_unique']['H_clair_upper']:.3f}",
            "AdjBenignHlo": f"{P['benign_only_rule_unique']['H_clair_lower']:.3f}",
            "AdjInjHlo": f"{P['injected_only_rule_unique']['H_clair_lower']:.3f}",
            "AdjRuleAtk": str(round(P["rule_unique_attack_success_rate_injected"] * P["injected_variants"])),
            "AdjGtAtk": str(round(P["gt_reference_attack_success_rate_injected"] * P["injected_variants"])),
            "AdjRemoved": str(P["injected_variants_with_benign_value_removed"]),
            "AdjAtkAdmitted": str(P["injected_variants_with_attacker_value_admitted"]),
            "AdjWall": str(adj["wall_clock_seconds"]),
            "AdjNonExh": str(P["n_nonexhaustive_variants_without_witness"]),
        })
        prim = [json.loads(line) for line in open(ROOT / src["adj_headroom"] / "task_results_primary.jsonl")]
        unsolv = [(r["suite"], r["task_id"]) for r in prim if r["status"] == "OK"
                  for vv in r["variants"] if vv["best_upper"] == 0]
        nums["AdjUnsolvable"] = str(len(unsolv))
        nums["AdjUnsolvableTasks"] = str(len(set(unsolv)))
    if src.get("adj_slots"):
        sl = json.loads((ROOT / src["adj_slots"] / "slots.json").read_text())
        d = sl["drop_tasks_with_numeric_slots"]
        nums.update({"AdjNumKept": str(d["n_tasks_kept"]), "AdjNumLo": f"{d['H_lower']:.3f}",
                     "AdjNumUp": f"{d['H_upper']:.3f}", "AdjNumericSlots": str(sl["n_numeric_slots"]),
                     "AdjSlots": str(sl["n_slots"])})
    if cc is not None:
        F, St = cc["results"]["fallback"], cc["results"]["strict"]
        H, ao, ae = F["H"], F["attack_room"]["official"], F["attack_room"]["effect"]
        sel = F["selectable"]["resolver|official"]
        idr = cc.get("identifiability_rows", [])

        def lohi(key, R=F):
            return f"{R['H'][key]['H_lower']:.3f}", f"{R['H'][key]['H_upper']:.3f}"

        for mac, key, R in (("CcH", "resolver|official|secure", F), ("CcHRule", "rule_unique|official|secure", F),
                            ("CcHEff", "resolver|effect|secure", F), ("CcHTask", "resolver|official|task", F),
                            ("CcHRuleTask", "rule_unique|official|task", F),
                            ("CcHStrict", "resolver|official|secure", St), ("CcHBen", "resolver|official|secure|benign", F),
                            ("CcHInj", "resolver|official|secure|injected", F)):
            lo, up = lohi(key, R)
            nums[mac + "Lo"], nums[mac + "Up"] = lo, up
        fl = F["flags"]
        nums.update({
            "CcTasks": str(F["n_tasks"]), "CcResolved": str(F["n_resolved"]),
            "CcUnresolved": str(F["n_tasks"] - F["n_resolved"]),
            "CcStrictResolved": str(St["n_resolved"]),
            "CcVariants": f"{F['n_variants']:,}".replace(",", "{,}"),
            "CcInjVariants": str(ao["n_injected_variants"]),
            "CcNoWrite": str(F["n_tasks_without_writes"]),
            "CcIncomplete": str(F["n_variants_search_incomplete"]),
            "CcLeaves": f"{F['leaves_total'] + St['leaves_total']:,}".replace(",", "{,}"),
            "CcResAtk": str(ao["resolver_attack_count"]), "CcRuleAtk": str(ao["rule_unique_attack_count"]),
            "CcAbsAtk": str(ao["all_abstain_attack_count"]), "CcGtAtk": str(ao["gt_path_attack_count"]),
            "CcGtN": str(ao["gt_path_n_variants_gold_admitted"]),
            "CcResAtkEff": str(ae["resolver_attack_count"]), "CcRuleAtkEff": str(ae["rule_unique_attack_count"]),
            "CcReachLo": str(ao["attack_reachable_count_lower"]),
            "CcReachUp": str(ao["attack_reachable_count_lower"] + ao["attack_reachable_count_undetermined"]),
            "CcReachEffLo": str(ae["attack_reachable_count_lower"]),
            "CcReachEffUp": str(ae["attack_reachable_count_lower"] + ae["attack_reachable_count_undetermined"]),
            "CcReachTnLo": f"{ao['attack_reachable_task_nested'][0]:.3f}",
            "CcReachTnUp": f"{ao['attack_reachable_task_nested'][1]:.3f}",
            "CcSelN": str(sel["n_variants"]), "CcSelTasks": str(sel["n_tasks"]),
            "CcSelUtil": str(sel["by_cause"].get("utility", 0)), "CcSelAtk": str(sel["by_cause"].get("attack", 0)),
            "CcSelAbst": str(sel["baseline_abstained"]),
            "CcNotRefuted": str(sum(r["status"] == "NOT_REFUTED" for r in idr)),
            "CcRefuted": str(sum(r["status"] == "REFUTED_NONIDENTIFIABLE" for r in idr)),
            "CcIdUnknown": str(sum(r["status"].startswith("UNKNOWN") for r in idr)),
            "CcSingletonView": str(sum(r["view_group_size"] == 1 for r in idr)),
            "CcFirstWriteErr": str(sum(r["locus"] == "FIRST_WRITE_ERROR" for r in idr)),
            "CcLaterErr": str(sum(r["locus"] == "LATER_WRITE_ERROR" for r in idr)),
            "CcNRRate": f"{cc['decision']['not_refuted_selectable_rate_task_nested']:.3f}",
            "CcOutDep": str(fl.get("ORACLE_OUTPUT_DEPENDENT", 0)),
            "CcOracleComposed": str(fl.get("HAS_ORACLE_COMPOSED", 0)),
            "CcFreeText": str(fl.get("HAS_FREE_TEXT", 0)),
            "CcGoldNotAdmitted": str(fl.get("GOLD_NOT_ADMITTED_ON_GT_PATH", 0)),
            "CcGtFails": str(fl.get("GT_PATH_FAILS_BENIGN_OFFICIAL", 0)),
            "CcPlanVaries": str(fl.get("PLAN_SHAPE_VARIES", 0)),
            "CcWall": f"{cc['cost']['wall_seconds_total']:.0f}",
            "CcCPU": f"{cc['cost']['cpu_seconds_workers']:.0f}",
            "CcFollowup": cc["decision"]["learner_followup"].replace("_", "\\_"),
        })
    (OUT / "numbers.tex").write_text(
        "% generated by scripts/make_paper_tables.py from paper/sources.json -- do not edit\n"
        + "\n".join(f"\\newcommand{{\\{k}}}{{{v}}}" for k, v in nums.items()) + "\n")
    print(json.dumps(nums, indent=1))


if __name__ == "__main__":
    main()

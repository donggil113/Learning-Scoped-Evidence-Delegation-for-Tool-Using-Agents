#!/usr/bin/env python3
"""Static checks for paper/main.tex. NOT a LaTeX compiler: it cannot detect
overfull boxes, page count, float placement, or style-file errors.

Checks: brace balance, begin/end balance, \\ref vs \\label, \\cite keys vs
references.bib, \\input targets exist, macros from numbers.tex defined,
\\todo count, and a rough main-body word count (abstract .. conclusion).
"""

import json
import re
import sys
from pathlib import Path

P = Path(__file__).resolve().parents[1] / "paper"


def strip_comments(s: str) -> str:
    return re.sub(r"(?<!\\)%.*", "", s)


def main() -> int:
    tex = strip_comments((P / "main.tex").read_text())
    rep: dict = {}
    depth = 0
    for ch in tex.replace("\\{", "").replace("\\}", ""):
        depth += ch == "{"
        depth -= ch == "}"
        if depth < 0:
            break
    rep["brace_balance"] = depth
    begins = re.findall(r"\\begin\{([^}]+)\}", tex)
    ends = re.findall(r"\\end\{([^}]+)\}", tex)
    rep["env_unbalanced"] = sorted({e for e in set(begins) | set(ends) if begins.count(e) != ends.count(e)})
    labels = set(re.findall(r"\\label\{([^}]+)\}", tex))
    refs = set(re.findall(r"\\ref\{([^}]+)\}", tex))
    rep["undefined_refs"] = sorted(refs - labels)
    rep["unreferenced_labels"] = sorted(labels - refs)
    cites = set()
    for grp in re.findall(r"\\cite[a-z]*\{([^}]+)\}", tex):
        cites |= {c.strip() for c in grp.split(",")}
    bib = set(re.findall(r"@\w+\{([^,]+),", (P / "references.bib").read_text()))
    rep["missing_bib_keys"] = sorted(cites - bib)
    rep["uncited_bib_keys"] = sorted(bib - cites)
    inputs = re.findall(r"\\input\{([^}]+)\}", tex)
    rep["missing_inputs"] = [i for i in inputs if not (P / i).exists() and not (P / (i + ".tex")).exists()]
    nums = set(re.findall(r"\\newcommand\{\\(\w+)\}", (P / "tables" / "numbers.tex").read_text()))
    defined = nums | set(re.findall(r"\\newcommand\{\\(\w+)\}", tex))
    used_caps = set(re.findall(r"\\([A-Z][A-Za-z]+)", tex))
    rep["undefined_capitalized_macros"] = sorted(used_caps - defined)
    rep["todo_count"] = len(re.findall(r"\\todo\{", tex))
    body = tex[tex.find("\\begin{abstract}"): tex.find("\\section*{Impact Statement}")]
    body_wo_tables = re.sub(r"\\begin\{table\*?\}.*?\\end\{table\*?\}", " ", body, flags=re.S)
    words = re.findall(r"[A-Za-z][A-Za-z'-]+", re.sub(r"\\[A-Za-z]+\*?", " ", body_wo_tables))
    rep["main_body_words_excluding_tables_approx"] = len(words)
    rep["main_body_tables"] = len(re.findall(r"\\begin\{table\*?\}", body))
    rep["anonymity_flags"] = sorted(set(re.findall(r"github\.com|donggil|pusan|@[a-z]+\.ac\.kr", tex, re.I)))
    print(json.dumps(rep, indent=1))
    bad = (rep["brace_balance"] != 0 or rep["env_unbalanced"] or rep["undefined_refs"] or rep["missing_bib_keys"]
           or rep["missing_inputs"] or rep["undefined_capitalized_macros"] or rep["anonymity_flags"])
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

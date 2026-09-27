# Building the manuscript

Status: **COMPILE_NOT_RUN**. This environment has no TeX installation
(`latexmk`, `pdflatex`, `xelatex`, `lualatex` and `tectonic` are all absent),
and the official ICML style files are not in the repository. No PDF has
been produced, and none is claimed. Do not upload the sources to an external
web compile service.

## Requirements

1. A TeX Live installation that provides `latexmk`, `pdflatex` and `bibtex`.
2. The official ICML style archive, placed next to `main.tex`: `icml2026.sty`,
   `icml2026.bst`, `algorithm.sty`, `algorithmic.sty` and `fancyhdr.sty` if
   provided. Download it from the ICML author-instructions page. Do not
   replace it with a hand-made imitation. When an ICML 2027 style is
   published, switch `\usepackage{icml2026}` and `\bibliographystyle{icml2026}`
   to it (TARGET_YEAR = 2027, TEMPLATE_YEAR = 2026 in the header).

## Commands

```
cd paper                        # or export_bundle/paper
python3 ../scripts/make_paper_tables.py   # regenerate tables/*.tex from raw (repository checkout only)
python3 ../scripts/check_tex_static.py    # static checks: braces, labels, macros, citations
latexmk -pdf -interaction=nonstopmode -halt-on-error main.tex
```

## Checks after the first compile

- The main body, from the start of the Introduction to the end of the
  Conclusion, is at most 8 pages. The impact statement, references and
  appendices do not count.
- There are no undefined references or citations (`grep -i undefined main.log`).
- The title block macros match the official example paper in the style
  archive (review mode: no `[accepted]` option).

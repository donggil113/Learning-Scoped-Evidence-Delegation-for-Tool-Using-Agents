# Building the manuscript

Status: **BUILT** (first build, manuscript v4-typeset, 2026-10-11). The PDF
is an internal review copy; it has not been submitted anywhere. Scientific
content is unchanged from v4; the build needed layout-only edits.
SUBMISSION_READY = false. Do not upload the sources to an external web
compile service.

## Toolchain used

- TeX Live 2026 (tlmgr revision 80485), installed from a CTAN mirror into a
  user-owned directory with `install-tl` (scheme-basic plus: latexmk,
  microtype, booktabs, hyperref, xcolor, amsmath, amsfonts, amscls, natbib,
  psnfss, times, fancyhdr, algorithms, eso-pic, forloop, etoolbox, url,
  collection-fontsrecommended, float, tools, caption). Installer sha512 was
  checked against the published `install-tl-unx.tar.gz.sha512`.
- pdfTeX 1.40.29, latexmk.
- Official ICML 2026 style archive (anonymous review mode, no `[accepted]`):
  `https://media.icml.cc/Conferences/ICML2026/Styles/icml2026.zip`,
  sha256 `8b29290f5828e176debb57ea9cc00252502973d55ea561a2f18a7f0a326bfc6c`, linked from
  `https://icml.cc/Conferences/2026/AuthorInstructions`. Files used,
  unmodified, placed next to `main.tex` (git-ignored because `icml2026.sty`
  states no redistribution terms; `icml2026.bst` and `fancyhdr.sty` are LPPL):
   - `icml2026.sty`: sha256 `7cdcf90f6a59c5219e7f15c88f7ed09fcaf598dad91e6cdddc4dc3cb0e397a95`
   - `icml2026.bst`: sha256 `0ec3d5eb9b02efb7e0b44a32f3775882f42a743d0bdc618f34e6936309b98764`
   - `algorithm.sty`: sha256 `93fd0eb31c112eb405833db8f1d7f5d238c7e691b1c05680d7276e68f36d564a`
   - `algorithmic.sty`: sha256 `48d18794a5d97c0479a588cc2eac0917992feb9da83acc4631b8f55757d80f9b`
   - `fancyhdr.sty`: sha256 `9130c52f91087abc6d223164ffa587e207e3257fcbcd069ef09ecb5391043f14`
- ICML 2027: `https://icml.cc/Conferences/2027/AuthorInstructions`,
  `.../2027/CallForPapers` and `.../2027` returned HTTP 404 on 2026-10-11.
  This is not treated as proof that no 2027 guidance exists. TARGET_YEAR =
  2027, TEMPLATE_YEAR = 2026.

## Commands

```
cd paper
curl -L -o icml2026.zip https://media.icml.cc/Conferences/ICML2026/Styles/icml2026.zip
sha256sum icml2026.zip        # expect 8b29290f5828e176debb57ea9cc00252502973d55ea561a2f18a7f0a326bfc6c
unzip -o icml2026.zip icml2026.sty icml2026.bst algorithm.sty algorithmic.sty fancyhdr.sty
python3 ../scripts/make_paper_tables.py   # only when tables/*.tex are missing (reads stored raw JSON, no experiment)
python3 ../scripts/check_tex_static.py
SOURCE_DATE_EPOCH=<commit time> FORCE_SOURCE_DATE=1 \
  latexmk -gg -pdf -interaction=nonstopmode -halt-on-error -no-shell-escape main.tex
```

`SOURCE_DATE_EPOCH` fixes the PDF creation date so a rebuild from the same
commit reproduces the delivered bytes; without it the PDF differs only in
its timestamps.

## Checks done on the delivered build (see deliverables/P4_delivery.json)

- 0 LaTeX errors, 0 undefined references or citations, 0 multiply-defined
  labels, 0 overfull boxes.
- 20 pages; the last sentence of the Conclusion is on page 8 (main body
  limit 8 pages under the 2026 instructions); Impact Statement and
  References start on page 9; appendices from page 10.
- Every page was rendered (PyMuPDF 1.28.2, 110 dpi) and viewed; pages 4,
  7 and 16 (tables and equations) were also viewed at 200 dpi.
- PDF metadata: title, author "Anonymous Authors", subject from the style;
  no author identity, local path or repository name in the text.

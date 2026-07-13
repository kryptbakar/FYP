# VYREX — Software Requirements Specification

`VYREX-SRS.docx` is the complete SRS for the final-year project, generated
reproducibly from this repo so it stays in sync with the build.

## What's inside (IEEE-830 / ISO-IEC-IEEE-29148 structure)

Cover · revision history · approval · TOC (Word field) · list of figures/tables ·
1 Introduction · 2 Overview · 3 State of the Art (with a SIEM comparison) ·
4 User/System Requirements + external interfaces · 5 Functional Requirements
(20 FRs, each with a traceability table) · 6 Non-functional Requirements (14 NFRs)
+ requirements-to-evaluation traceability · 7 Design (the 4+1 view model) + UI
wireframes · 8 Conclusion. **11 figures, 29 tables.**

## Regenerate

```bash
pip install python-docx matplotlib
python figures/make_figures.py   # 11 PNGs: use-cases, 4+1 views, UI wireframes
python make_srs.py               # → VYREX-SRS.docx
```

Figures are drawn programmatically in the console's design language (D-049).
After opening the .docx in Word, right-click the Table of Contents → **Update
Field** (F9) to build page numbers.

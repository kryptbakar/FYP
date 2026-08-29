# `eval/` — evaluation corpus, blind-labelling artefacts and security probes

Everything here exists to make [docs/EVALUATION-PROTOCOL.md](../docs/EVALUATION-PROTOCOL.md)
and [docs/LABELLING-RUBRIC.md](../docs/LABELLING-RUBRIC.md) executable rather than aspirational.

| Script | What it does |
|---|---|
| `corpus_audit.py` | Checks the corpus against the rubric's §10 stratification targets. Exit 0 = labelling may begin. |
| `export_cases.py` | Freezes a labeller-visible CSV + an empty label file. Joins **no** investigation table. |
| `seed_missing_evidence.py` | Seeds the 6 constructed cases where abstaining is the *correct* answer. |
| `score_labels.py` | Scores system verdicts against blind labels — the §3 metrics, and only those. |
| `injection_probe.py` | Prompt-injection probe with a control (docs/THREAT-MODEL.md §3.1). |

## Scoring the results

```bash
python eval/score_labels.py --labels eval/labels/labels-<stamp>.csv \
                            --adjudicator eval/labels/advisor-<stamp>.csv
```

It computes exactly what [EVALUATION-PROTOCOL.md](../docs/EVALUATION-PROTOCOL.md) §3
pre-registers — macro-F1, confusion matrix, ordinal severity agreement, abstention
quality, citation validity, uncited-verdict rate, latency, and Cohen's κ — and nothing
else. Picking metrics after seeing results is how honest projects reach dishonest
conclusions, so the set is fixed in code.

**It refuses to invent accuracy.** With no labelled rows it prints the grounding and
operational sections, which need no labels, and states that decision quality is
unavailable. It never falls back to scoring the system against its own output or against
another model — that is the circularity §2 exists to prevent.

No `sklearn`: the four formulas are ~40 lines of arithmetic, and adding a large dependency
to an air-gapped project to avoid writing them would be a poor trade. `eval/tests/` pins
every one against a hand-computed expected value (16 cases, in CI), because with nothing
labelled yet the decision-quality path never executes on real data — and a metric that
silently returns a plausible *wrong* number is the worst failure available here.

**Current output, unlabelled:** 9 verdicts, uncited-verdict rate **9/9 (100%)**, 0
resolvable citations, latency p50 124 s / p95 294 s, all `llama3.2:3b`. No accuracy claim
is supported, which is the correct result for this state rather than a broken harness.

All four take `POSTGRES_*` from the environment. From a host with the stack up:

```bash
docker run --rm --network vyrex_default -v "$PWD/eval:/e" -w /e \
  -e POSTGRES_HOST=postgres -e POSTGRES_DB=soc_central \
  -e POSTGRES_USER=soc -e POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
  python:3.11-slim sh -c "pip install -q 'psycopg[binary]' && python corpus_audit.py"
```

## Corpus status — 2026-08-29

**63 findings; all 14 stratification targets met.** Labelling may begin.

| | |
|---|---|
| severity | 7 CRITICAL / 35 HIGH / 15 MEDIUM / 6 LOW |
| tools | agent, trivy, nuclei, sigma, misp |
| KEV | 8 (vs 55 non-KEV) |
| corroborated (`n_tools ≥ 2`) | 9 — **but read the caveat below** |
| IOC matches | 5 |
| deliberate missing-evidence | 6 |

### Two things not to misread

**Corroboration here is engineered.** The `n_tools ≥ 2` target was reached by adding MISP
IOCs for IP addresses the Sigma rule had already flagged. The tools agree because the
fixtures were chosen to make them agree. That is fine as evaluation *input* — the labeller
and the agent see the same evidence — but it is not evidence that independent tools converge
in the wild, and **no base rate may be computed from it**. Those IOCs are tagged
`lab:synthetic`. EVALUATION-PROTOCOL.md §5 has the full statement of what may and may not be
claimed. The one honest exception is the `185.220.101.45:4444` cluster, which corroborated
*before* the expansion, from fixing the clustering key.

**The missing-evidence cases carry `risk_score = NULL` on purpose.** They must not be scored
as though the absent evidence were merely unimportant. `rule_id LIKE 'eval-missing-%'`
identifies them.

## Files

`cases/` holds frozen exports and `labels/` the matching (initially empty) label files,
both stamped with the export time. **Two exports exist**, and the later one supersedes:

- `*-20260828T113823Z` — 54 findings, taken when the rubric was frozen, **before** corpus
  expansion. Kept, not deleted: it is the git-visible evidence that the rubric predates the
  corpus. Do not label it.
- `*-20260828T193136Z` — **63 findings, the corpus to label.**

Labels are **append-only** (rubric §12). A mistaken label is superseded by a new row with a
reason, never edited — the git history is what proves temporal blinding held, so rewriting
it destroys the evidence the whole protocol rests on.

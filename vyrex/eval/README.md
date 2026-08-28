# `eval/` — evaluation corpus, blind-labelling artefacts and security probes

Everything here exists to make [docs/EVALUATION-PROTOCOL.md](../docs/EVALUATION-PROTOCOL.md)
and [docs/LABELLING-RUBRIC.md](../docs/LABELLING-RUBRIC.md) executable rather than aspirational.

| Script | What it does |
|---|---|
| `corpus_audit.py` | Checks the corpus against the rubric's §10 stratification targets. Exit 0 = labelling may begin. |
| `export_cases.py` | Freezes a labeller-visible CSV + an empty label file. Joins **no** investigation table. |
| `seed_missing_evidence.py` | Seeds the 6 constructed cases where abstaining is the *correct* answer. |
| `injection_probe.py` | Prompt-injection probe with a control (docs/THREAT-MODEL.md §3.1). |

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

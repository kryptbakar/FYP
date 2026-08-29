# Reproducing every number in this project

Every quantitative claim VYREX makes, the command that regenerates it, and what you should
see. If a number appears in a document and is not here, treat that as a defect — a figure
nobody can re-derive is an assertion wearing a statistic's clothes.

**Read this first.** Several results below are *negative*: the model abstains on
everything, prompt injection successfully steers a verdict, and the air-gap was partly
unenforced until it was tested. They are here for the same reason as the good ones. A
reproducibility page listing only flattering numbers is marketing.

Unless stated otherwise, run from `vyrex/` with the stack up:

```bash
docker compose -f docker-compose.yml -f docker-compose.n8n.yml --profile agentic up -d
```

---

## 1. Tests — 244 (236 Python + 8 console)

| Suite | Command | Expected |
|---|---|---|
| ml | `python -m pytest -q ml/tests` | `78 passed` |
| api | `python -m pytest -q services/api/tests` | `47 passed` |
| orchestrator | `python -m pytest -q services/investigation-orchestrator/tests` | `68 passed` |
| enrichment + feed-sync + eval | `python -m pytest -q services/enrichment/tests services/feed-sync/tests eval/tests` | `43 passed` |
| console | `for t in web/console/tests/*.test.js; do node "$t"; done` | `8 passed` |

The orchestrator suite needs its own `requirements.txt` installed and must run **from the
repo root** — its `conftest.py` is what makes `import orchestrator` resolve. Both facts are
load-bearing: without either it fails at *collection*, which pytest reports as an error
rather than a failure. That is precisely why it ran green-but-empty in CI for weeks.

## 2. The corpus

| Claim | Command | Expected |
|---|---|---|
| 63 findings, **all 14 stratification targets met** | `python eval/corpus_audit.py` | exit 0, `corpus meets every stratification target` |
| 8 KEV · 9 corroborated · 5 IOC · 6 missing-evidence | same | in the printed table |
| The rubric predates the labels | `git log --diff-filter=A -- docs/LABELLING-RUBRIC.md eval/labels/` | rubric committed with `labels/` empty |

The last row is the entire basis of the blinding claim, and anyone holding the repo can
check it. That is why an empty label file was committed rather than no file at all.

## 3. The model result (the headline negative)

```bash
make model-benchmark MODELS=llama3.2:3b,qwen2.5:3b CASES=12 REPEATS=1
```

| Claim | Expected |
|---|---|
| `llama3.2:3b` — 12/12 schema valid, **12/12 abstained, 0/12 cited** | reproduced exactly (temperature 0) |
| `qwen2.5:3b` — identical, to the case | reproduced exactly |
| `qwen3:4b` unusable — 3.2 tok/s, no completion in 900 s | `0/6` schema valid, timeouts |

Two unrelated 3B families failing identically is the evidence for a **capacity ceiling**
rather than a badly-tuned prompt. If you re-run this and one of them *does* cite, that is a
real finding: update [AGENT-ORCHESTRATION.md](AGENT-ORCHESTRATION.md) §7 rather than
defending the old claim.

**Stop the heavy tools profile first.** A 4B model and the intel stack do not coexist in
5.8 GiB, and the benchmark would be measuring swap rather than inference.

## 4. Fusion

```sql
SELECT source_tool, consensus->>'n_tools' AS n_tools, consensus->>'tools' AS tools
  FROM findings WHERE observable_key IS NOT NULL AND asset_id = 'host-lab-01';
```

The `185.220.101.45:4444` connection should show `agent + misp + sigma`, `n_tools=3`,
`weight=1.0`.

**Do not compute a corroboration base rate from this corpus.** Reaching the ≥6 target meant
adding MISP IOCs for IPs the Sigma rule had already flagged, so the tools agree because the
fixtures were built to make them agree; those entries carry a `lab:synthetic` tag. The
`185.220.101.45` cluster is the honest example — it corroborated *before* the expansion,
purely from fixing the clustering key. Full statement in
[EVALUATION-PROTOCOL.md](EVALUATION-PROTOCOL.md) §5.

## 5. Security

| Claim | Command | Expected |
|---|---|---|
| Prompt injection **steers the verdict** | `python eval/injection_probe.py` | poisoned `DISMISS`/`LOW` vs control `INSUFFICIENT_EVIDENCE`/`HIGH` |
| …but the empty-claims demand is refused | same | `empty-claims request honoured: no (validator held)` |
| …and the fabricated id never resolves | same | `fabricated id Z9 cited: no (allow-list held)` |
| Orchestrator **cannot** write response actions | `SELECT has_table_privilege('vyrex_orchestrator','response_actions','INSERT')` | `f` |
| …and cannot read identity | same for `users`, `sessions` | `f`, `f` |
| Grants match what the code reads | `python -m pytest -q services/investigation-orchestrator/tests/test_db_grants.py` | `3 passed` |
| Admission control holds | POST `/investigations` 14× for distinct findings as one requester | 10 accepted, 4 × `429` with `Retry-After` |

The probe deletes its own findings afterwards. With `--keep`, remove them before running
`eval/export_cases.py` or they enter the evaluation corpus as though they were real cases.

## 6. Air-gap

| Claim | Command | Expected |
|---|---|---|
| **35/35 services sealed** | `python tools/airgap/check-coverage.py` | exit 0 |
| The check *can* fail | delete one `{ networks: [socnet] }` line, re-run | exit 1, naming that service |
| Runtime seal + membership | `bash tools/airgap/verify-egress.sh` | `AIR-GAP ENFORCED`, every service `ok` |
| That check can fail too | `docker network connect bridge vyrex-ollama`, re-run | `LEAK ollama`, exit 1 |
| K3s policy really selects pods | `helm template vyrex deploy/helm/vyrex --set orchestrator.enabled=true` | 9 pod templates carry `part-of: vyrex` |

The negative controls are not optional extras. **Both of these checks passed while the
property was violated** — a check nobody has watched fail is not yet known to hold.

## 7. Grounding and operations

```bash
python eval/score_labels.py --labels eval/labels/labels-<stamp>.csv
```

Measured 2026-08-29, 10 verdicts, all `llama3.2:3b`:

| Claim | Expected |
|---|---|
| **Uncited-verdict rate 10/10 (100%)** | the Phase 2 exit gate, still open |
| Citations resolvable | `0` — nothing has been cited |
| Latency p50 / p95 | ≈ 144 s / 294 s |
| Decision quality | **unavailable** — it refuses to compute without labels |

The counts grow as more investigations run; the *rate* is the claim, not the denominator.

## 8. The ML layer, with its caveat

```bash
docker run --rm -e MODEL_DIR=/tmp/models -v "$PWD/ml:/ml" -w /ml \
  --entrypoint python vyrex-risk-engine evaluate.py --out /tmp/reports
```

R² ≈ 0.94 — and **this number does not mean what it appears to.** `dataset._label` calls
`scoring.composite()`, so the model is scored against labels generated by the formula under
test. It measures self-consistency, not accuracy. The harness prints that caveat itself;
[METHODOLOGY.md](METHODOLOGY.md) §4.1 has the full statement, and `ml/eval_fusion.py` is the
one non-circular harness.

`MODEL_DIR` must be writable. It defaults to `/models`, which needs root — that one detail
kept CI red for seven weeks.

## 9. CI

```bash
curl -s "https://api.github.com/repos/kryptbakar/FYP/actions/runs?per_page=1"
```

All **8 jobs green**. If they are not, the failure is real: this repo sat red for weeks
without anyone noticing, which is why the air-gap coverage check now runs there.

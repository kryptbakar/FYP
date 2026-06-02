# Phase F — AI Fusion Engine

**Goal (expansion prompt §5/§7-F):** upgrade `ml/` from a single-source risk model into
a **multi-tool fusion engine** — dedup findings across tools, weight by consensus, add
threat-intel + ATT&CK features, retrain XGBoost, surface a SHAP waterfall per finding,
and wire the feedback→monthly-retrain loop.

## What shipped
- **`ml/fusion.py` (new)** — the dedup + consensus front-end. Groups findings by their
  `dedup_key` into clusters, records *which* tools agree, derives a saturating consensus
  weight (1 tool→0.0, 2→0.5, 3+→1.0), inherits threat-intel/ATT&CK context across the
  cluster, and writes a `consensus` jsonb onto every member (`tools`, `n_tools`, `weight`,
  `members`, `primary`, `dedup_key`). Annotates — never deletes — so each tool's raw
  evidence survives (D-041). Rules documented in **`ml/FUSION.md`**.
- **3 new features** (`features.py`): `threat_intel` (MISP IOC hit), `consensus`
  (fusion weight), `attack_ctx` (ATT&CK technique graded by tactic — exfil/C2 outrank
  initial access). Vector grew 8→**11**; composite grew 7→**10 weighted factors**,
  rebalanced to still sum to 1.0 (D-040).
- **`scoring.py`** weights rebalanced; **`dataset.py`** synthetic generator + labels gained
  the fusion interactions (`threat_intel×epss`, `consensus×cvss`, `attack_ctx×consensus`).
- **`explain.py`** — SHAP now also emits a **waterfall** (base → each factor → final score)
  and two new counterfactuals ("if only one tool reported it", "if no live MISP IOC").
- **`db.py`/`run.py`** — load fusion fields, run the fusion stage before scoring, persist
  `findings.consensus` + `finding_explanations.waterfall`. Feedback rows are re-clustered
  at train time so they carry the same consensus weight they were scored with.
- **API** (`routers/risk.py`) — `/risk/ranking` returns `attack`, `threat_intel`,
  `consensus`; `/findings/{id}/explain` returns the `consensus` record and the SHAP
  `waterfall`.

## Verified end-to-end (live, against the running stack)
1. Re-ran `enrichment --once` to backfill `dedup_key` on the 26 agent findings (the
   Phase-3 enricher computes the key but those rows predated it). Then scanned an
   agent-covered host (`SCAN_ASSET_ID=6b3691284187`, which the agent had independently
   flagged for **CVE-2023-4911**) so Trivy corroborates the agent → a genuine 2-tool
   cluster.
2. `risk-train`: 11-feature model, **R²=0.939** (mae 3.42), folded 1 analyst-feedback
   sample at 5×, fusion ran (40 findings → 37 clusters, 1 multi-tool).
3. `risk-score`: 40 findings scored, **3 corroborated by >1 tool**; `consensus`
   {tools:[agent,trivy], n_tools:2, weight:0.5} written to all 3 cluster members.
4. **The headline result** — same CVE, consensus decides the rank:

   | finding | asset | tools | consensus | ml_risk_score |
   |---------|-------|-------|-----------|---------------|
   | #1 CVE-2023-4911 | 6b3691284187 | agent **+** trivy | 0.5 | **94.31** |
   | #2 CVE-2023-4911 | scan-target-01 | trivy only | 0.0 | **72.96** |

   Identical CVE/CVSS/EPSS/KEV — the corroborated instance ranks higher purely because
   two independent tools agree.
5. **Explainability holds up:** SHAP for the corroborated finding shows `consensus`
   contributing **+7.42** (3rd-largest driver after KEV +15.0 and CVSS +12.8); the
   counterfactual *"if only one tool reported it (no corroboration)"* → **−21.35**. The
   MISP IOC finding's `threat_intel` SHAP is **+18.47** (a live IOC dominates its score).
   The waterfall climbs base 48.12 → … → 94.31 across 13 steps.

## Decisions
- **D-040** — consensus weight saturates at 2 tools; fusion factors join the *composite*,
  not just the ML model.
- **D-041** — fusion annotates clusters; it never deletes a tool's finding (provenance +
  audit trail preserved).

## Notes / deferred
- The monthly retrain *cadence* is wired in code (feedback folded at 5× on every `train`,
  each run stamps a `model_version`); the actual scheduler is a K3s CronJob in Phase 8.
- Other natural consensus pairs are designed in but not yet exercised on this host:
  agent-FIM ↔ Wazuh-FIM (`sha1(asset,path)`, D-035) and Suricata ↔ agent egress. They
  cluster identically once those heavier tools run on a larger host.

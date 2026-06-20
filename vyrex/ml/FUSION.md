# The AI Fusion Engine — dedup + consensus rules

**Built in:** Phase F · **Module:** `ml/fusion.py` · the multi-tool front-end of the
risk engine and SOC Central's core original contribution.

SOC Central ingests detections from many independent tools — the Go agent, Suricata,
Zeek, Wazuh, Trivy, Nuclei, MISP, Sigma, Falco. Several of them routinely flag the
**same underlying issue on the same asset**. Two things follow:

1. We must **not** show the analyst the same problem five times (alert fatigue).
2. When independent tools **agree**, that corroboration is a strong, trustworthy
   signal — it should *raise* the priority and be shown as part of the explanation.

The Fusion Engine turns that redundancy into signal instead of noise.

---

## 1. The `dedup_key` contract

Every producer stamps a deterministic `dedup_key` on each finding (added in Phase A,
populated in Phases C–E). Findings that share a `dedup_key` are treated as **one
cluster** describing one issue. The key is intentionally tool-independent so two tools
that discover the same thing collide on the same key:

| Producer / domain        | `dedup_key` recipe                                  | Rationale |
|--------------------------|-----------------------------------------------------|-----------|
| Vuln finding (agent/Trivy/Nuclei) | `sha1(asset, domain, cve_id, port)`        | The same CVE on the same asset is one issue regardless of which scanner saw it. |
| Network finding (egress/exposed)  | `sha1(asset, domain, rule_id, port)`       | Same rule + port on the same asset. |
| MISP IOC match           | `sha1(asset, "ioc", indicator)`                     | One IOC hit per asset+indicator. |
| Sigma detection          | `sha1(asset, "sigma", rule_id)`                     | One detection per asset+rule. |
| Wazuh FIM                | `sha1(asset, path)`                                 | Same file changed = same issue; the agent's polling FIM collides here. |
| Wazuh SCA / compliance   | `sha1(asset, cis_control)`                          | Same control on the same asset. |

A finding with **no** `dedup_key` is simply its own singleton cluster
(`fusion.cluster_key` falls back to `solo:<id>`), so it is never lost.

> We **annotate**, we don't delete. Each tool's row stays in `findings` with its own
> unique `fingerprint` and raw evidence — analysts still need to see *what Suricata
> actually said*. Fusion writes a shared `consensus` record onto every member of the
> cluster; the console leads with the cluster's highest-severity row (`primary`).

---

## 2. Consensus weight

For each cluster we count the **distinct** `source_tool`s that contributed and map that
to a saturating 0..1 weight (`fusion.consensus_weight`):

| Distinct tools | weight | meaning |
|----------------|--------|---------|
| 1              | 0.0    | single source, no corroboration |
| 2              | 0.5    | two independent tools agree |
| 3+             | 1.0    | strong multi-tool consensus |

The jump from **one to two** independent tools is the most informative step, so the
curve saturates fast. The `consensus` jsonb written to each finding records the full
context the console and the model use:

```json
{
  "tools": ["agent", "suricata", "misp"],
  "n_tools": 3,
  "weight": 1.0,
  "threat_intel": true,          // any member carried a MISP IOC hit
  "attack": "T1071.001",         // any member was mapped to an ATT&CK technique
  "members": [4012, 4090, 4101], // all finding ids in the cluster
  "primary": 4101,               // highest-severity member (console leads with this)
  "dedup_key": "9af3…"
}
```

`threat_intel` and `attack` are **inherited across the cluster**: if MISP flagged the
IP while Suricata raised the alert and the agent saw the egress, every member benefits
from the combined picture.

---

## 3. From fusion to score

The consensus weight and the inherited threat-intel / ATT&CK context become three new
model features (alongside the original seven), feeding **both** layers of the engine:

| Feature        | Source                                   | Composite weight |
|----------------|------------------------------------------|------------------|
| `threat_intel` | `findings.threat_intel` (MISP IOC hit)   | 0.10 |
| `consensus`    | `fusion.build_clusters` weight           | 0.09 |
| `attack_ctx`   | `findings.attack` graded by tactic       | 0.07 |

`attack_ctx` grades the ATT&CK technique so late tactics weigh more — exfiltration
(T1041 → 1.0) and C2 (T1071/T1571 → 0.9) outrank initial access (T1190 → 0.7). See
`features._ATTACK_GRADE`.

The XGBoost model additionally learns the **interactions** the linear weights can't
express (`dataset._label`):

- `threat_intel × epss` — a live IOC on something that's also likely exploitable.
- `consensus × cvss` — several tools agree on a genuinely severe issue.
- `attack_ctx × consensus` — an ATT&CK-mapped finding that is also corroborated.

Per-finding **SHAP** then shows exactly how much each of these moved the score (the
`waterfall` in `finding_explanations`), and the counterfactuals include
*"if only one tool reported it (no corroboration)"* and *"if there were no live MISP
IOC match"* so the analyst can see what the consensus and intel actually bought.

---

## 4. Feedback → monthly retrain loop

Analyst feedback (`analyst_feedback.label_priority`, captured via the API) is folded
back into training at **5× sample weight** (`run.do_train`). Because the labelled rows
are re-clustered at train time, each one carries the same `consensus` weight it was
scored with, so the model learns from the fused view, not the raw per-tool rows.

Cadence is **monthly** (the brief's requirement): run `make risk-train` then
`make risk-score` on a schedule (cron / K3s CronJob in Phase 8). Each train stamps a
new `model_version` (`xgb-<UTC timestamp>`), which is recorded on every finding and
explanation so a score is always traceable to the model that produced it.

```
findings (all tools) ─▶ fusion.build_clusters ─▶ consensus weight + jsonb
                                              │
asset context ───────────────────────────────┼─▶ features (11) ─▶ composite (risk_score)
                                              │                 └▶ XGBoost ─▶ ml_risk_score
analyst_feedback (5×) ────────────────────────┘                            + SHAP waterfall
```

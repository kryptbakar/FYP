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
cluster** describing one issue.

Findings cluster on **two** keys, in priority order (`fusion.cluster_key`):

| Priority | Key | Identifies | Set by |
|---|---|---|---|
| 1 | `observable_key` | the **thing observed** — `sha1(asset, "flow", remote_ip, remote_port)` | producers that saw a concrete peer |
| 2 | `dedup_key` | the **rule that fired** (recipes below) | every producer |
| 3 | `solo:<id>` | nothing — the finding is its own cluster | fallback, so nothing is lost |

**Why two keys, and why the observable wins.** Until 2026-08-28 there was only
`dedup_key`, which identifies *the rule that fired*. Each tool family builds it
differently, so detections from different families about the **same event** could never
collide. One outbound connection to `185.220.101.45:4444` produced three findings with
three unrelated keys — `n_tools = 1` for all three, and the engine reported
*"0 corroborated by >1 tool"* on the very scenario this document uses as its example.

The fix was to record what each producer actually **observed**, not merely which rule
matched, and to key clustering on that:

- `services/intel-enricher/sigma_eval.py` now sub-aggregates `payload.remote_ip` /
  `payload.remote_port`, so a Sigma hit is tied to the connection it fired on. It
  previously stored only its query string and could not be linked to anything.
- `services/intel-enricher/ioc.py` records the `(ip, port)` the indicator was seen on,
  and de-duplicates at observable granularity so one bad IP on two ports stays two flows.
- `services/enrichment/domains.py` sets it for single-peer egress only. With several
  peers that one row is about all of them, so pinning it to one would **manufacture**
  corroboration rather than measure it; ambiguity leaves it NULL and falls back to
  `dedup_key`.

Measured after the change, same connection:

| id | tool | `observable_key` | `n_tools` | `weight` |
|---|---|---|---|---|
| 3370 | agent | `57cd676d…` | 3 | 1.0 |
| 4289 | misp  | `57cd676d…` | 3 | 1.0 |
| 4300 | sigma | `57cd676d…` | 3 | 1.0 |

`fingerprint` still keeps each tool's own row distinct — nothing is deleted, and the
analyst can still see exactly what each tool said. Guarded by
`ml/tests/test_fusion.py::test_three_tools_on_one_connection_reach_full_consensus`.

> ⚠ The `observable_key` recipe is duplicated verbatim in
> `services/enrichment/domains.py::_observable_key` and
> `services/intel-enricher/db.py::observable_key` — the two services are packaged
> separately and share no library. **Change one and you must change the other**, or they
> stop agreeing and cross-tool clustering silently degrades to the old behaviour.

The per-rule `dedup_key` recipes, still used whenever there is no observable:

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
to a saturating 0..1 weight (`fusion.consensus_weight`).

> Verified on live data 2026-08-28: an agent egress rule, a MISP IOC hit and a Sigma
> detection about one connection now form a single cluster with `n_tools = 3`,
> `weight = 1.0`. Before the observable key existed they were three singletons.

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

That inheritance is what the observable key unlocked. Before it, those three findings
landed in three separate clusters and each row carried only what its own producer knew;
now the agent's egress row inherits the MISP intel flag and the Sigma ATT&CK technique.

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

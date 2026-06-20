# VYREX — Project Report

> **What this is:** a complete, plain-English description of what VYREX is, what it does, how
> it is built, and — importantly for an FYP defence — an honest account of what is fully working
> versus what is demo/simulated. Written to be usable as a report, a viva crib sheet, and an
> onboarding doc.
>
> **Project:** VYREX (formerly "SOC Central") · GIKI BS Cyber Security Final-Year Project ·
> proof-of-concept for the Punjab IT Board (PITB) · repo: `github.com/kryptbakar/FYP` (monorepo
> under `soc-central/`) · version `1.0.0`.

---

## 1. One-paragraph summary

VYREX is a **centralized, air-gapped Security Operations Center (SOC) and vulnerability-
intelligence platform**. It collects security telemetry from an organisation's endpoints and
open-source security tools, correlates and de-duplicates what they find, scores each risk with an
**explainable** model (every score can be justified, factor by factor), and gives analysts a single
workspace to triage, investigate, hunt, respond to, and audit security incidents — **without any
data ever leaving the organisation's network**. The whole platform is designed to run with no
internet connection, which is its core differentiator: it targets sovereign, regulated, defence,
and critical-infrastructure buyers who cannot use cloud SOC products.

---

## 2. The problem it solves

Modern SOC tools (CrowdStrike, Splunk, Microsoft Sentinel, etc.) are powerful but **cloud-based** —
they phone home, send telemetry off-site, and often embed cloud AI. A large class of
buyers — government, defence, banks, hospitals, industrial/OT operators — legally or operationally
**cannot** send their security data to a third party. They are left stitching together raw
open-source tools by hand, with no unified view, no shared scoring, and no audit trail.

VYREX exists for exactly those buyers. It provides the "single pane of glass" + intelligence layer
those organisations lack, while guaranteeing (and *verifying*) that nothing egresses.

Three things make it more than a dashboard:

1. **Exploit-aware, explainable risk scoring** — not just "CVSS 9.8", but *why this finding is your
   #1 priority right now*, with the contributing factors shown.
2. **Multi-tool fusion** — when several independent tools flag the same thing, that agreement raises
   confidence; VYREX makes that consensus visible.
3. **Cryptographically auditable response** — every containment action is signed, requires two-person
   approval, and is recorded in a tamper-evident hash chain.

---

## 3. Architecture (four layers)

```
┌──────────────────────────────────────────────────────────────────────┐
│  PRESENTATION   Analyst console (vanilla-JS SPA on nginx) + Grafana    │
│                 — proxies /api same-origin, no CORS, no external fetch │
├──────────────────────────────────────────────────────────────────────┤
│  INTELLIGENCE   Composite risk + XGBoost re-ranker + SHAP explainability│
│                 AI Fusion (dedup → consensus) · CWE map · CVSS predict  │
├──────────────────────────────────────────────────────────────────────┤
│  PROCESSING     FastAPI service + enrichment/correlation + workers      │
│                 + tool bridges (Suricata/Zeek/Wazuh/Falco/scanners/intel)│
├──────────────────────────────────────────────────────────────────────┤
│  DATA / EDGE    PostgreSQL · TimescaleDB · OpenSearch · NATS JetStream  │
│                 Go ingest-edge (mTLS) · Go endpoint agent               │
└──────────────────────────────────────────────────────────────────────┘
```

- **Data / edge layer.** A **Go endpoint agent** (zero external dependencies) runs on monitored
  hosts and collects system info, network state (`/proc`), osquery results, file-integrity (FIM)
  changes, process monitoring, and a pure-Go IOC/YARA-style scan. It ships over **mutual TLS** to a
  Go **ingest-edge** gateway that validates every event against a JSON Schema and publishes it to
  **NATS JetStream**. Durable **Python workers** consume the stream and land events in a
  **TimescaleDB** hypertable (time-series) and **OpenSearch** (full-text/raw payload search).
  Relational data (findings, assets, incidents, compliance, audit) lives in **PostgreSQL**.

- **Processing layer.** A **FastAPI** application is the heart of the backend (20+ routers). An
  **enrichment** service matches installed packages to CVEs and enriches them with CVSS/EPSS/KEV;
  a **compliance** engine evaluates CIS-style benchmarks; **tool bridges** translate the output of
  ten open-source security tools into the common schema.

- **Intelligence layer.** Python `ml/` service computes a composite risk score, trains an XGBoost
  re-ranker, produces SHAP explanations + counterfactuals, and runs the **AI Fusion Engine** that
  groups findings seen by multiple tools and derives a consensus signal.

- **Presentation layer.** A **dependency-free** single-page console (HTML/CSS/vanilla JS, no npm,
  no CDN, no build step) served by nginx, which also reverse-proxies `/api` to FastAPI so the
  browser only ever talks to one origin. **Grafana** provides time-series dashboards.

---

## 4. How data flows (end to end)

1. **Collect** — agent + sensors (Suricata/Zeek/Falco) + scanners (Trivy/Nuclei) emit events.
2. **Ingest** — ingest-edge validates (mTLS + JSON Schema) → JetStream → workers → Timescale + OpenSearch.
3. **Enrich** — packages → CVEs → CVSS/EPSS/KEV; IOCs matched against MISP; ATT&CK techniques
   tagged from OpenCTI; Sigma rules evaluated → all become rows in the **`findings`** table, each
   tagged with the tool that produced it.
4. **Fuse** — findings describing the same underlying issue (same `dedup_key`) are clustered;
   "how many independent tools agree" becomes a **consensus** weight.
5. **Score** — a composite weighted formula produces a 0–100 risk score; an XGBoost model re-ranks;
   SHAP explains each score.
6. **Act** — analysts triage in the console, open incidents, request containment (two-person
   approval → Ed25519-signed command → agent executes), and everything is written to a hash-chained
   audit log.

The only component permitted to reach the internet is an optional **feed-sync** job that mirrors the
public NVD/EPSS/KEV vulnerability feeds; in true air-gap mode even that is fed from offline files
("sneakernet" refresh).

---

## 5. The intelligence layer (the differentiator)

- **Composite risk score (primary signal).** A hand-weighted formula over ~10 factors (CVSS,
  exploit availability, KEV, EPSS, asset criticality, exposure, threat-intel, consensus, ATT&CK
  context, etc.), weights summing to 1.0. This is the *defensible, transparent* score.

- **XGBoost re-ranker (secondary signal).** A gradient-boosted model re-ranks findings and, over
  time, bends the ranking based on **analyst feedback** (labelled findings are weighted 5× in
  retraining). Reported R² ≈ 0.94 on the feature set.

- **SHAP explainability.** Every score comes with a **waterfall** showing exactly which factors
  pushed it up or down, plus **counterfactuals** ("if only one tool had flagged this, the score
  would drop by 21"). This is genuinely better than the opaque scores most commercial tools show.

- **AI Fusion Engine.** Groups findings by `dedup_key`, records which tools agree, and derives a
  saturating consensus weight (1 tool → 0, 2 → 0.5, 3+ → 1.0). It annotates (never deletes) and lets
  an analyst see, e.g., "the agent **and** Trivy **and** Nuclei all flagged CVE-2023-4911 on this
  host" — the most intuitive trust signal in the product.

- **CWE mapping + CVSS-from-text** — findings are mapped to weakness classes (CWE), and a CVSS
  score can be predicted from a textual description when a feed value is missing.

> **Honest limitation (state this proactively in a viva).** The XGBoost model is currently trained
> largely on **synthetic data** whose labels are derived from the same composite formula, so it can
> partly "rediscover" the hand-set weights rather than learning new signal. The honest framing —
> and the one that survives scrutiny — is: **the composite score is the primary, defensible signal,
> and the ML layer is a feedback-adaptive re-ranker** that will learn real signal as analyst labels
> (and real exploitation outcomes) accumulate. The Model Card screen in the console states this
> limitation openly, which examiners and risk teams reward.

---

## 6. Security & trust features (the "sellable" core)

- **Verified air-gap.** A Docker overlay puts every runtime service on an `internal` network with no
  off-host route; an egress-verification script *proves* the API cannot resolve DNS while a control
  bridge can — i.e., the air-gap is **enforced and tested**, not just claimed. In production this is
  a K3s NetworkPolicy (default-deny egress).
- **Signed active response.** Containment commands are signed with **Ed25519**; the agent verifies
  every command against a provisioned public key before executing — a forged command is rejected.
- **Two-person approval.** High-impact actions require a second approver before they dispatch.
- **Hash-chained, tamper-evident audit.** Both compliance evidence and the response-action lifecycle
  are recorded in append-only hash chains; a `/verify` endpoint detects any tampering.
- **RBAC + login.** The console has a real login gate (pbkdf2-hashed passwords, bearer-token
  sessions) and three roles — **admin / analyst / viewer** (viewer is read-only).
- **Access auditing** — who logged in and what they viewed is recorded, not just what they changed.

---

## 7. Integrated open-source tools (10)

VYREX's philosophy is "integrate best-in-class open source, add original value in the intelligence
layer." Tools integrated via bridges/parsers into the common schema:

| Category | Tools |
|---|---|
| Network IDS / traffic | **Suricata**, **Zeek** |
| Host / EDR / FIM / SCA | **Wazuh**, **Falco** (runtime), plus the native Go agent |
| Vulnerability scanners | **Trivy**, **Nuclei** |
| Threat intelligence | **MISP** (IOCs/sightings), **OpenCTI** (ATT&CK, knowledge graph) |
| Detection content | **Sigma** rules |
| Vulnerability feeds | **NVD / EPSS / KEV** (+ a real Exploit-DB / Metasploit / PoC mirror) |
| Live hunting | **Velociraptor**-style fleet hunts |

Each tool's output is normalised, fingerprinted per-tool, and given a shared `dedup_key` so the
Fusion Engine can recognise agreement across tools.

---

## 8. The analyst console (28 screens)

A premium, dependency-free SPA in a **black + wine-red** design language. Severity is encoded by
**shape + label** (not colour alone) for accessibility; data values (IPs, hashes, CVEs, timestamps)
are monospace and entity-highlighted; a **⌘K command palette** jumps to any screen or runs deep
actions. Screens are grouped into five sections:

- **Monitor** — Overview (executive KPIs, risk bands, ATT&CK coverage, live ticker), Triage
  (ranked decision queue), Hunt (OpenSearch log search), Coverage (ATT&CK matrix + posture trend).
- **Investigate** — Cases (incident Kanban + kill-chain + evidence + signed audit), Assets
  (inventory + host detail), Live Hunt (fleet collection), Threat Intel (actors/malware/clusters/sightings).
- **Assure** — Compliance (CIS posture + hash-chained evidence), Trust Center (chain integrity,
  egress matrix, audit timeline).
- **Operate** — Sensors & Fusion, Operations (SLA/workload), Detections (rule management), Alerting
  (channels + real webhook delivery), Playbooks (SOAR), Reports (PDF/CSV export), Dashboards (Grafana
  embed), Model (ML transparency card), Settings.
- **Toolkit** — eight standalone analyst tools (next section).

The signature finding view shows: header pills → big score → stat chips → a conclusion-first summary
→ score-factor bars + SHAP waterfall → multi-tool consensus → ATT&CK/intel → counterfactuals →
provenance → two-person gate → analyst feedback.

### 8a. Analyst Toolkit (ported from the A.R.I.S. reference dashboard, air-gap-adapted)

Eight self-contained tools. The original A.R.I.S. used a cloud LLM + live internet feeds; VYREX
reimplements them as **deterministic, offline engines** so nothing is fetched and nothing egresses:

| Tool | What it does |
|---|---|
| **Node Vitals** | Live appliance-node telemetry (CPU/per-core/RAM/swap/disk/load/uptime) read from `/proc`. |
| **Threat News** | Bundled offline intel feed with a derived threat-level banner. |
| **Log Analyzer** | Paste logs → heuristic rules flag failed auth, recon, injection, malware, persistence, etc. |
| **Phishing Analyzer** | Paste an email → live header parse + IOC extraction + 0–10 threat score + recommendation. |
| **CVE Lookup** | Resolve a CVE against VYREX's offline store → plain-English What/How/Who/Fix/Risk brief. |
| **IR Playbook** | Paste an alert → NIST SP 800-61 phased, incident-type-specific interactive checklist (+ .txt export). |
| **Port Scanner** | Real multithreaded TCP scan, **hard-restricted to localhost + private ranges** (refuses public IPs). |
| **Assistant** | Offline knowledge-base Q&A on CVSS/KEV/EPSS/ATT&CK/phishing/ransomware/IR. |

---

## 9. Deployment & operations

- **Local / demo:** Docker Compose — one command brings up Postgres, TimescaleDB, OpenSearch, NATS,
  the API, the console, and Grafana. Optional profiles add the ten tools and the observability stack.
- **Production:** a full **K3s / Helm** chart in `deploy/` with: non-root/read-only/seccomp
  hardened workloads, **NetworkPolicy** default-deny egress (the prod air-gap primitive),
  **CloudNativePG** (3 replicas + point-in-time recovery to MinIO), an **OpenSearch operator**,
  **Vault** (HA Raft, PKI + transit, External Secrets), **Keycloak + oauth2-proxy** (OIDC SSO +
  RBAC), **Velero** backups, **ArgoCD** GitOps, and **cosign-signed reproducible agent builds** with
  fail-closed verification.
- **CI/CD & quality:** a pytest suite, GitHub Actions pipeline, and k6 load tests.
- **Observability:** Prometheus metrics (`/metrics`) + Grafana dashboards.

---

## 10. What is real vs. demo (read this before a demo or viva)

Being explicit here is what turns "a class project" into "a credible system." Stated honestly:

**Fully real and verified:**
- The data pipeline (agent → ingest-edge → JetStream → workers → Timescale + OpenSearch), end-to-end.
- CVE enrichment from real NVD/EPSS/KEV data; real Exploit-DB/Metasploit/PoC references.
- Composite scoring, XGBoost training/inference, SHAP waterfalls, fusion/consensus (verified on real
  corroborated findings, e.g. agent + Trivy on the same host).
- Hash-chained audit + tamper detection; Ed25519 command signing; two-person approval logic.
- The air-gap enforcement/verification harness; a real K3s deploy with a **Velero backup→destroy→
  restore drill** that passed.
- The console (all 28 screens render against live data via the proxy); Node Vitals (live `/proc`);
  Port Scanner (real, range-guarded); real outbound webhook delivery for alerts.

**Demo / simulated / honest caveats:**
- The XGBoost model's training labels are partly synthetic/circular (see §5) — framed as a
  feedback-adaptive re-ranker awaiting real labels.
- Some heavy tools (Wazuh/Falco/OpenCTI/MISP) were validated via fixtures rather than running live,
  because the development host lacked the RAM/kernel features for them.
- The agent's eBPF/YARA/process-monitor/hunter collectors build and vet cleanly but are marked
  **"needs a Linux endpoint to verify"** — not claimed as proven end-to-end on this Windows dev box.
- Email/Slack alert delivery is honestly "queued"; webhook delivery is real.
- The Toolkit's AI tools are deterministic rule engines, not an LLM (by design, for the air-gap);
  an optional local LLM could be attached later to enrich the prose.
- The "second approver" in the demo is simulated so one person can show the two-person flow.

---

## 11. Technology stack

| Layer | Technology |
|---|---|
| Backend API | Python, FastAPI, Pydantic, psycopg |
| Edge / agent | Go (zero-dependency agent + mTLS ingest gateway) |
| Messaging | NATS JetStream |
| Datastores | PostgreSQL, TimescaleDB, OpenSearch |
| ML / XAI | XGBoost, SHAP (TreeSHAP), NumPy/pandas |
| Console | HTML + CSS + vanilla JS (no framework, no build, no CDN) on nginx |
| Dashboards | Grafana |
| Crypto | Ed25519 signing, pbkdf2 password hashing, hash-chained audit, mutual TLS |
| Deploy | Docker Compose, K3s, Helm, Vault, Keycloak, Velero, ArgoCD, cosign |
| Quality | pytest, GitHub Actions, k6 |

---

## 12. How to run it

```powershell
# from the repo root (Windows host — no `make`, use the PowerShell shim)
pwsh scripts/dev.ps1 up          # brings up the core stack
pwsh scripts/dev.ps1 produce -N 500   # optional: push synthetic telemetry
```

Then open:
- **Console:** http://localhost:3001  (login `admin` / `vyrex`; roles: admin/analyst/viewer)
- **Grafana:** http://localhost:3000  (`admin` / `change_me_grafana`)
- **API docs (Swagger):** http://localhost:8000/docs

---

## 13. In one sentence

> **VYREX is an air-gapped SOC platform that unifies ten open-source security tools, scores every
> risk with an explainable, exploit-aware, multi-tool-consensus model, and lets analysts triage,
> hunt, and respond with cryptographically signed, two-person-approved, tamper-evident actions —
> all without a single byte leaving the building.**

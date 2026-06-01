# Claude Code Build Prompt — SOC Central

> Paste everything below the line into Claude Code as your initial instruction. It is self-contained: it does not rely on any prior chat. Work through it phase by phase, and **pause for my review at the end of each phase** before starting the next one.

---

## 0. Your role and mission

You are the lead engineer building **SOC Central**, a centralized Security Operations Center (SOC) and dashboard platform. This is a Bachelor's senior design project (GIKI, BS Cyber Security) intended as a proof-of-concept for a government technology body (PITB) with **air-gapped / on-premises** deployment requirements.

The project's design philosophy — stated in the original scope document — is to **integrate best-in-class open-source components rather than reinvent them**, and to contribute original value in the *intelligence layer* (exploit-aware risk scoring + explainable ML + analyst-controlled response). Your job is to honour that philosophy: clone the reference repositories below, study them, lift and adapt the useful parts into a clean monorepo, wire in the public vulnerability-data APIs, and build the original glue code (the FastAPI backend, the scoring engine, the dashboard console) yourself.

You are building software that we must **understand, defend in a viva, and maintain** — not a black box. Favour clarity over cleverness. Explain non-obvious decisions in code comments and in `docs/DECISIONS.md`.

## 1. Architecture (target)

A four-layer modular platform:

1. **Endpoint Agent Layer** — lightweight Go agents on monitored Linux hosts. Instrumented with eBPF (process/network observation), embedded Osquery (host-state SQL), YARA (IOC scanning), and file integrity monitoring (auditd/fanotify). Resource-capped, communicate over mutual TLS, expose a *signed* command channel for active response.
2. **Ingestion & Assessment Layer** — a stateless Go edge-ingest service (auth + schema validation + enqueue only) → a durable message broker → asynchronous Python workers that enrich and fan out to data stores.
3. **Data Layer** — PostgreSQL (transactional state), TimescaleDB (time-series telemetry), OpenSearch (full-text / log search).
4. **Presentation Layer** — Grafana (metrics, trends, heatmaps) + a Next.js / Tailwind workflow console (incident triage, case management, XAI-backed finding detail, analyst feedback).

**Deployment evolution:** MVP on Docker Compose (single-host lab) → production-targeted Kubernetes (K3s) with HA. Build the MVP first. K3s/Helm is the final phase.

## 2. Ground rules (read before writing any code)

1. **Understand, then adapt — never blind-copy.** When you lift code from a reference repo, read it, simplify it to what we need, and rewrite it into our own module structure and naming. Add a comment at the top of any adapted file noting the source repo and its license.
2. **Track every license.** Maintain `ATTRIBUTIONS.md` at the repo root listing each reference repo, its URL, and its license. **Verify each license from the repo's actual LICENSE file — do not assume.** Flag any copyleft licenses (GPL / AGPL) explicitly in that file with a one-line note on the distribution implication, since several of these tools are copyleft and that matters if the platform is ever distributed. If in doubt, prefer reimplementing a small piece over vendoring copyleft source into our product tree.
3. **Reference code stays separate from product code.** Clone all reference repos into a top-level `reference/` directory and add `reference/` to `.gitignore`. Our actual product lives in `services/`, `agent/`, `web/`, `ml/`, `deploy/`. Never commit third-party source into the product tree.
4. **Build incrementally and verify.** Get each layer running and demonstrable before moving on. After each phase, produce a short `docs/PHASE-N-NOTES.md` (what was built, how to run it, what's stubbed) and stop for my review.
5. **Linux-first.** Windows agent parity is explicitly out of scope for the MVP (Phase 2 roadmap, not now).
6. **Free/open-source feeds only.** No paid commercial threat-intel feeds. Approved sources: NVD, FIRST EPSS, CISA KEV, MISP, abuse.ch.
7. **Air-gapped from day one.** Every external feed must be *mirrored locally* and consumed from the mirror. Design the enrichment workers to read from a local feed store, with a separate, clearly isolated "sync" job that is the *only* thing that touches the internet. Nothing else should make outbound calls at runtime.
8. **Secrets via env / Vault, never hardcoded.** Provide `.env.example`. Real secrets go in `.env` (gitignored) for the MVP and HashiCorp Vault in the K3s phase.
9. **Everything runs with one command per phase.** Provide a `Makefile` (or `justfile`) with targets like `make up`, `make down`, `make seed`, `make test`, `make agent-run`.

## 3. Reference repositories to clone

Clone all of these into `reference/`. Each line is **URL — role — what to extract**. These are mostly small or lightly maintained repos: treat them as code to read and adapt, not dependencies to import.

### Vulnerability-management base & data model (reference)
- `https://github.com/DefectDojo/django-DefectDojo` — leading open-source vuln-management / DevSecOps platform with a large REST API and 150+ scanner parsers. **Extract:** finding/engagement/asset data-model ideas, REST API design patterns, scanner-parser logic. We build our own FastAPI backend; this is the design reference.
- `https://github.com/infobyte/faraday` — open-source vuln-management platform, multi-scanner aggregation. **Extract:** vulnerability normalization and aggregation patterns.

### Exploit-aware enrichment — the "cybersecurity tool APIs" layer
- `https://github.com/IKER-36/Cve-Extractor-Public` — extracts CVEs from NVD and enriches with KEV, EPSS, and exploit data. **Extract:** the core enrichment-worker logic; this is closest to what our Python workers must do.
- `https://github.com/dinesh-murugan-h/CVEraptor` — CVE intelligence CLI enriching with CVSS, EPSS, KEV, exploit context. **Extract:** enrichment field mapping.
- `https://github.com/tcoatswo/cve-watch` — KEV + EPSS enrichment for *explainable* patch prioritization. **Extract:** the explainability-of-prioritization approach (overlaps our XAI goal).
- `https://github.com/cyb3ri0t/Faraday_CVE_Parser` — enriches CVE data (EPSS/KEV/CVSS). **Extract:** parser details if we lean on Faraday's model.

### Intelligence layer — ML risk prioritization + Explainable AI (our differentiator)
- `https://github.com/shreyas23dev/Attack-Phase-Aware-Dynamic-Vulnerability-Prioritization-Framework` — **the single closest match.** ML vulnerability prioritization integrating CVSS, EPSS, MITRE ATT&CK and the kill chain, with adaptive weighting and **SHAP explainability**. **Extract:** the scoring + XGBoost + SHAP pipeline; adapt heavily for our composite risk engine.
- `https://github.com/francesco-denu/cve-enriched-dataset` — aggregates CVE data from multiple APIs to train a prioritization model. **Extract:** the training-data assembly pipeline.
- `https://github.com/themalkaanjalarathnasiri/cvss_score_prediction_model` — ML CVSS-score prediction. **Extract:** feature engineering reference.
- `https://github.com/dmlc/xgboost` and `https://github.com/shap/shap` — the canonical libraries (use as pip dependencies, study their docs/examples).

### Endpoint agent layer
- `https://github.com/osquery/osquery` — host-state SQL engine. **Use:** embed / shell out to osqueryd; study the schema.
- `https://github.com/cilium/ebpf` — Go eBPF library. **Use:** the eBPF process/network observation layer of our agent.
- `https://github.com/VirusTotal/yara` — YARA engine for IOC scanning. **Use:** integrate for file/memory scanning.
- `https://github.com/wazuh/wazuh` — reference for file-integrity-monitoring behaviour and CIS-compliance checking. **Extract:** FIM and CIS-control concepts (do not vendor; GPL).
- `https://github.com/Velocidex/velociraptor` — Go-based endpoint visibility + containment. **Extract:** the *active-response / containment command channel* model (note: AGPL — reference only, reimplement).

### Incident response & case management
- `https://github.com/TheHive-Project/TheHive` and `https://github.com/TheHive-Project/Cortex` — incident-response case management + automated observable enrichment. **Extract:** case lifecycle, observable-enrichment workflow patterns.

### Full-stack architecture references (study the wiring, don't fork)
- `https://github.com/ArfanAbid/Open-Source-SIEM_SOC-Stack` — Docker-based SIEM/SOC stack (Wazuh, Graylog, Grafana, Shuffle, MISP, TheHive, Cortex). Architecture blueprint.
- `https://github.com/dominguezbernaldo943-svg/SOC-IN-A-BOX` — Grafana + Loki + Prometheus + **OpenSearch** + n8n + OIDC SSO. Closest match to our presentation layer; study the Grafana/OpenSearch/OIDC wiring.
- `https://github.com/FunnyWolf/agentic-soc-platform` — alert correlation / IOC extraction / one-API-over-many-backends. Reference for incident correlation.

## 4. Public tool APIs to integrate (mirror locally)

Build a `services/feed-sync/` job that pulls these on a schedule and writes them to a local feed store (PostgreSQL tables + a file cache). All enrichment reads from the mirror, never live.

- **NVD CVE API 2.0** — `https://services.nvd.nist.gov/rest/json/cves/2.0` (supports incremental sync via `lastModStartDate`/`lastModEndDate`; respect rate limits, request an API key).
- **FIRST EPSS API** — `https://api.first.org/data/v1/epss` (daily exploit-probability scores; also available as a daily CSV bulk download, which is better for mirroring).
- **CISA KEV catalog** — `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (full JSON, easy to mirror).
- **MISP** — threat-intel platform; integrate via its REST API if a MISP instance is available, otherwise stub.
- **abuse.ch** feeds (URLhaus, MalwareBazaar, ThreatFox) — free IOC feeds for enrichment.

Verify each endpoint and its current schema before coding against it (paths and formats change).

## 5. Target monorepo structure

Create this layout:

```
soc-central/
  README.md
  ATTRIBUTIONS.md
  Makefile
  .env.example
  .gitignore                 # includes reference/ , .env , data volumes
  docker-compose.yml         # MVP: all services + data stores
  docs/
    ARCHITECTURE.md
    DECISIONS.md
    PHASE-*-NOTES.md
  reference/                 # gitignored; all cloned repos for study
  agent/                     # Go endpoint agent (eBPF, osquery, YARA, FIM, mTLS, response channel)
  services/
    ingest-edge/             # Go: auth + schema-validate + enqueue
    workers/                 # Python: broker consumers, enrichment, fan-out
    api/                     # FastAPI: ~30 REST endpoints (the core backend)
    feed-sync/               # the ONLY internet-facing job (NVD/EPSS/KEV/abuse.ch mirroring)
  ml/                        # XGBoost + SHAP scoring engine, training, retraining pipeline
  web/                       # Next.js + Tailwind analyst console
  grafana/                   # provisioned dashboards + datasources
  deploy/
    helm/                    # K3s Helm charts (final phase)
```

## 6. Tech stack (pin these)

- **Agent:** Go, `cilium/ebpf`, embedded Osquery, YARA. Resource-capped (configurable CPU/mem). mTLS to server.
- **Edge ingest:** Go (stateless, horizontally scalable).
- **Broker:** **NATS JetStream** for the MVP (simpler to run in a lab than Kafka; keep the consumer interface broker-agnostic so Kafka can be swapped in later).
- **Backend API:** FastAPI (Python) with async workers (Arq or Celery).
- **ML:** XGBoost, SHAP, scikit-learn, pandas, NumPy.
- **Data:** PostgreSQL, TimescaleDB, OpenSearch.
- **Presentation:** Grafana + Next.js + Tailwind CSS.
- **Security:** OIDC/SAML SSO, RBAC, mutual TLS, HashiCorp Vault (K3s phase), signed agent binaries, hash-chained immutable audit log.
- **Observability:** Prometheus, Grafana, Loki, OpenTelemetry.
- **Deploy:** Docker Compose (MVP) → K3s + Helm, CloudNativePG, OpenSearch operator, ArgoCD, Velero (production phase).

## 7. Phased build plan

Do these in order. Stop for review after each phase.

**Phase 0 — Scaffolding.** Create the monorepo, `.gitignore`, `ATTRIBUTIONS.md`, `Makefile`, `.env.example`, `docker-compose.yml` bringing up PostgreSQL + TimescaleDB + OpenSearch + NATS JetStream + a FastAPI skeleton (with `/health` and `/version`). Clone all reference repos into `reference/`. Verify the whole stack starts with `make up` and the API responds. Write `docs/ARCHITECTURE.md`.

**Phase 1 — Ingestion backbone.** Define the **unified telemetry schema** (versioned). Build `ingest-edge` (Go): mTLS, agent auth, schema validation, enqueue to JetStream. Build `workers` (Python): consume from JetStream, write raw telemetry to TimescaleDB/OpenSearch. Prove back-pressure and replay work. Add a fake telemetry producer for testing.

**Phase 2 — Endpoint agent (MVP).** Go agent that: runs embedded osqueryd and ships host-state; does file-integrity monitoring via fanotify/auditd; collects basic system + network info; (stage in) eBPF process/network observation and YARA scanning. Resource caps + mTLS to `ingest-edge`. `make agent-run` launches it against the local stack.

**Phase 3 — Vulnerability assessment + enrichment.** Build `feed-sync` to mirror NVD + EPSS + KEV locally. Build the enrichment worker (adapt `Cve-Extractor-Public`) that maps Osquery package/OS/network findings to CVEs and enriches with CVSS/EPSS/KEV from the mirror. Implement the three assessment domains: application (package CVEs), system (CIS hardening gaps), network (exposed ports / insecure services / eBPF flows).

**Phase 4 — Compliance engine.** Rule-based CIS Benchmark + org-policy evaluation against Osquery state → pass / fail / partial. Store results with **hash-chained evidence records** for audit traceability.

**Phase 5 — Composite risk scoring + ML/XAI (the differentiator).** Implement the weighted composite score: CVSS + EPSS + KEV presence + asset exposure + vuln age + compliance impact + service criticality → ranked risk per asset/finding. Then adapt `shreyas23dev/Attack-Phase-Aware...`: train an **XGBoost** model on the enriched dataset, surface **SHAP** contribution analysis + counterfactual explanations per finding, and build the analyst-feedback → monthly-retraining loop.

**Phase 6 — Incident management + active response.** Incident lifecycle (open / in-progress / resolved), assignment, SLA tracking, linked evidence. Active-response module (reference Velociraptor's model, reimplement): process termination, host network isolation (nftables), file quarantine, user disablement — over the **signed** command channel, with per-action audit logging and **two-person approval** for destructive actions.

**Phase 7 — Dashboards + access control.** Provision Grafana dashboards (vuln overviews, asset risk rankings, compliance status, trends, exposure heatmaps) against TimescaleDB/OpenSearch. Build the Next.js/Tailwind console (triage, case management, XAI finding detail, feedback capture). Add OIDC/SAML SSO, RBAC, and the hash-chained immutable audit log across the platform.

**Phase 8 — Hardening + K3s.** Helm charts; HA via CloudNativePG + OpenSearch operator; Velero backup/DR; air-gapped update channel for offline feed sync; Vault-backed secrets; signed agent binaries with tamper detection; ArgoCD GitOps.

## 8. Explicit non-goals (do not build)

Full SIEM replacement; Windows agent parity (Phase 2 roadmap only); paid commercial threat-intel feeds; real-time deep packet inspection (Suricata/Zeek are out of scope for the MVP); mobile app; automated patch remediation (response is **containment only**); full multi-tenant isolation (model for it, don't enforce it yet).

## 9. Start here

1. Confirm your understanding of the architecture and the phase plan in one short paragraph.
2. Create the Phase 0 scaffolding and `ATTRIBUTIONS.md`.
3. Clone the reference repos into `reference/` and record each one's verified license in `ATTRIBUTIONS.md`, flagging any GPL/AGPL.
4. Bring up the stack with `make up`, confirm health, and write `docs/PHASE-0-NOTES.md`.
5. **Stop and show me Phase 0 before starting Phase 1.**

Ask me a clarifying question only if something genuinely blocks you; otherwise make a reasonable choice, note it in `docs/DECISIONS.md`, and keep moving.

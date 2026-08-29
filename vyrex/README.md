# VYREX

A centralized **Security Operations Center** and vulnerability-intelligence platform.
Bachelor's senior design project (GIKI, BS Cyber Security), built as a proof-of-concept
for an **air-gapped / on-premises** government deployment (PITB).

> **Design philosophy:** integrate best-in-class open-source components rather than
> reinvent them, and contribute original value in the **intelligence layer** —
> exploit-aware risk scoring, explainable ML, multi-tool fusion, and analyst-controlled
> response. Every external feed is mirrored locally; only one job ever touches the internet.

## What it does

- **Collects** endpoint telemetry (a Go agent: sysinfo, process/network, osquery, FIM) and
  ingests detections from **ten integrated OSS tools** — Suricata, Zeek, Wazuh, Trivy,
  Nuclei, MISP, OpenCTI, Sigma, Falco — all normalized to one telemetry envelope.
- **Enriches** every CVE with CVSS + EPSS exploit probability + CISA KEV from a **local
  mirror** (no live calls), and evaluates **CIS compliance** with a hash-chained,
  tamper-evident evidence log.
- **Prioritizes** with the **AI Fusion Engine**: cross-tool dedup + consensus weighting
  (independent tools agreeing raises confidence) feeding a composite score **and** an
  XGBoost model, with a per-finding **SHAP waterfall** so every score is explainable.
  Clustering keys on the **observable** (which connection) rather than the rule that
  fired, so an agent egress rule, a MISP IOC hit and a Sigma detection about the same
  connection fuse into one issue at full consensus. See [ml/FUSION.md](ml/FUSION.md).
- **Investigates** with an evidence-grounded **LangGraph** agent: five specialists run in
  parallel (asset, ATT&CK, threat intel, multi-tool corroboration, history), all
  deterministic SQL, and **exactly one node talks to a model**. Every factual claim must
  cite a stored evidence record, the model is forbidden a confidence field, and a verdict
  other than *insufficient evidence* is **rejected** if it cites nothing. Runs are durable
  and resume after a crash. See [docs/AGENT-ORCHESTRATION.md](docs/AGENT-ORCHESTRATION.md).
- **Responds** via an Ed25519-**signed** command channel with two-person approval and a
  hash-chained audit trail (containment only).
- **Presents** it all in a real-time analyst **console** + Grafana dashboards.

## Architecture (five layers)

1. **Endpoint Agent** — lightweight Go agents (process/network, embedded osquery, FIM)
   over mutual TLS with a *signed* command channel for active response.
2. **Ingestion & Assessment** — stateless Go edge-ingest → NATS JetStream → async Python
   enrichment/fusion workers → data stores. Tool output arrives via bridges/enrichers.
3. **Data** — PostgreSQL (transactional), TimescaleDB (telemetry), OpenSearch (search).
4. **Investigation** — a durable LangGraph worker driven by a transactional outbox, with
   its own least-privilege DB role that has **no grant on the response tables**, so
   "the agent cannot contain anything" is enforced by Postgres rather than by convention.
5. **Presentation** — analyst console (dependency-free SPA; Next.js/Tailwind is the
   production target) + Grafana (metrics/trends/heatmaps).

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detail and
[docs/DECISIONS.md](docs/DECISIONS.md) for the rationale behind 58 logged decisions.

## What the measurements actually say

Numbers here are reported as measured, including the ones that are inconvenient. The
full working is in [docs/AGENT-ORCHESTRATION.md](docs/AGENT-ORCHESTRATION.md) §7 and
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) §3.1.

- **The orchestration works; the locally-runnable models do not commit.** `llama3.2:3b`
  and `qwen2.5:3b` — different vendors, one non-thinking — were run on the *same twelve
  findings*: both produced 12/12 schema-valid output, abstained 12/12, and cited 0/12.
  `qwen3:4b` never finished a single response in 900 s at 3.2 tok/s. Two unrelated model
  families failing identically is evidence of a **capacity ceiling at 3B on CPU**, not of
  a bad prompt — which is why prompt tuning was declined rather than used to paper over it.
- **Prompt injection can steer a recommendation, and cannot do anything else.** A poisoned
  finding versus an identical clean twin flipped the verdict to `DISMISS`/`LOW`. The same
  payload's other three demands all failed: the schema refused an uncited verdict, the
  citation allow-list rejected the fabricated id, and the evidence stayed visible.
  Reproduce with `python eval/injection_probe.py`.
- **The air-gap was partly theatre until it was tested.** 21 of 35 compose services were
  unsealed, and the production Kubernetes NetworkPolicy matched **0 of 9 pod templates**,
  while the egress check reported *AIR-GAP ENFORCED* throughout. Both are fixed, both are
  now CI-enforced, and both checks were verified by deliberately breaking them.

## Repository layout

```
vyrex/
  docker-compose.yml          # core stack: data stores + broker + API + console + Grafana
  docker-compose.tools.yml    # 10 OSS tools behind opt-in profiles
  docker-compose.airgap.yml   # egress-sealed overlay (air-gap verification harness)
  Makefile / scripts/dev.ps1  # task runner (Linux/macOS / Windows)
  services/
    api/            # FastAPI backend (findings, risk, incidents, compliance, response)
    ingest-edge/    # Go: mTLS + schema-validate + enqueue
    workers/        # Python: JetStream consumers → stores
    feed-sync/      # the ONLY internet-facing job (NVD/EPSS/KEV mirror)
    enrichment/     # CVE matching + CVSS/EPSS/KEV + compliance + scanner ingest
    sensor-bridge/  # Suricata/Zeek/Falco → JetStream
    wazuh-bridge/   # Wazuh Manager API → findings
    intel-enricher/ # MISP IOC + OpenCTI ATT&CK + Sigma
    investigation-orchestrator/   # LangGraph triage: 5 deterministic specialists + 1 LLM node
  agent/            # Go endpoint agent
  ml/               # composite score + XGBoost/SHAP + the AI Fusion Engine (FUSION.md)
  eval/             # frozen corpus, blind-labelling artefacts, corpus audit, injection probe
  web/console/      # analyst console (SPA on nginx, proxies /api)
  grafana/          # provisioned datasources + dashboards
  deploy/           # air-gapped K3s: Helm chart, CNPG/OpenSearch, Vault, Keycloak, Velero, ArgoCD
  tools/airgap/     # bundle/install for sneakernet + egress and sealing-coverage checks
  reference/        # cloned repos for STUDY ONLY (gitignored)
  docs/             # ARCHITECTURE, DECISIONS, THREAT-MODEL, AIRGAP, per-phase notes
```

## Quick start

**Prerequisites:** Docker + Docker Compose. (Python/Go/Node run only inside containers.)

```bash
make up            # build + start the core stack (data stores, API, console, Grafana)
make feeds-seed    # load the offline NVD/EPSS/KEV mirror (bundled fixtures)
make assess        # enrich host state → findings + compliance
make risk-train    # train the XGBoost risk model
make risk-score    # composite + ML risk + SHAP for every finding
```
Windows: `pwsh scripts/dev.ps1 <target>` (same targets).

Then open the **analyst console → http://localhost:3001**.

| Surface | URL |
|---------|-----|
| **Analyst console** | http://localhost:3001/ |
| Grafana dashboards | http://localhost:3000/ |
| API docs (Swagger) | http://localhost:8000/docs |
| Health / readiness | http://localhost:8000/health · `/health/ready` |

### Going further
```bash
make scan-ingest   # ingest Trivy + Nuclei scanner findings (offline fixtures)
make intel-enrich  # MISP IOC + OpenCTI ATT&CK + Sigma over the stores
make airgap-verify # prove the air gap: runtime sealed, only feed-sync egresses
```
Tool profiles: `docker compose -f docker-compose.yml -f docker-compose.tools.yml --profile <sensors|scanners|hostmon|intel> up`.

## Evidence it works (not just runs)

The intelligence layer is *evaluated*, not asserted — this is what makes VYREX a
research result rather than a demo:

```bash
make risk-eval      # ranking experiment: CVSS-only vs composite vs ML (Spearman/NDCG/precision@k/KEV-capture)
make fusion-eval    # dedup false-merge / missed-merge rates on a labeled sample
make bench-ingest   # sustained ingest throughput through the full pipeline
make bench-e2e      # end-to-end ingest latency (p50/p95/p99)
make attack-scenario # fusion + ranking on a scripted multi-tool intrusion (offline, deterministic)
make compose-smoke  # full-stack e2e: ingest → assess → score → assert findings (the "demo or product?" gate)
```

Air-gapped install: `make bundle` on a connected staging host produces a checksummed
offline bundle; carry it inside and `make install-offline` verifies and stands up the
stack with no internet. See [docs/PRODUCTION-DEPLOYMENT.md](docs/PRODUCTION-DEPLOYMENT.md).

| Doc | What it gives you |
|---|---|
| [docs/METHODOLOGY.md](docs/METHODOLOGY.md) | Design-science framing, FR/NFR requirements, Wazuh/Elastic/Splunk comparison |
| [docs/VALIDATION-ATTACK-SIM.md](docs/VALIDATION-ATTACK-SIM.md) | Live Atomic Red Team runbook: detection latency + fusion lift + SHAP fidelity |
| [docs/BENCHMARKS.md](docs/BENCHMARKS.md) | Throughput / latency / footprint protocol + result tables |
| [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) | STRIDE on VYREX itself, controls mapped to decisions |
| [docs/PRODUCTION-DEPLOYMENT.md](docs/PRODUCTION-DEPLOYMENT.md) | Real-org deployment: hardware/OS, network, air-gap transfer, agent rollout, day-2 ops |
| [docs/CONNECTORS.md](docs/CONNECTORS.md) | The pluggable connector contract — run VYREX over the tools you already have |
| [docs/ROADMAP-TOP-GRADE.md](docs/ROADMAP-TOP-GRADE.md) | Master checklist: from "built a lot" to top-graded FYP **and** a real product |

## Air-gap & security
Every external feed is mirrored locally; only `feed-sync` egresses, enforced and **verified**
(`make airgap-verify`; K3s NetworkPolicy in production). mTLS ingestion, Ed25519-signed
response commands, hash-chained audit + compliance evidence, OIDC/RBAC via Keycloak (K3s),
and a cosign-signed agent supply chain. Secrets move to HashiCorp Vault in K3s — see
[docs/AIRGAP.md](docs/AIRGAP.md). Reference repos and their **verified** licenses (GPL/AGPL
flagged, never vendored) are in [ATTRIBUTIONS.md](ATTRIBUTIONS.md).

## Status

**Platform build complete.** Phases 0–6 (core), A–E (tool integration), F (AI Fusion
Engine), G (console + dashboards), H (air-gap hardening), 8 (air-gapped K3s deployment).

**Agent-orchestration track:** phases 0–3 complete — durable LangGraph investigations,
five parallel deterministic specialists, citation-bound synthesis, and an Investigations
workspace in the console with clickable citations and a per-node execution graph.

**Evaluation (in progress, and the honest part):** the corpus is frozen and ready —
63 findings meeting all 14 stratification targets (`python eval/corpus_audit.py`), with a
pre-registered rubric committed *before* any label existed so git history proves the
blinding held. What is **not** done: no case has been labelled yet, and advisor
adjudication for an inter-rater statistic is not yet secured. Until both exist, no
accuracy claim is made — only grounding and operational behaviour, which are measurable
today and reported above.

See the per-phase notes in [docs/](docs/), the status summary in
[docs/ARCHITECTURE.md §8](docs/ARCHITECTURE.md), and
[docs/EVALUATION-PROTOCOL.md](docs/EVALUATION-PROTOCOL.md) for what would have to be true
before any accuracy number is quoted.

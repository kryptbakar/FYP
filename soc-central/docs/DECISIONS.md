# Decision Log

Non-obvious engineering choices, with rationale, so they can be defended in a viva
and revisited later. Newest at the top. Each entry: **context → decision → why →
alternatives considered**.

---

## D-049 — Console design language: charcoal + teal "intelligence workspace" (locked)
**Context:** the console's look went through navy/blue → CrowdStrike graphite+crimson → and
was then **locked by a detailed brief** to **charcoal + teal**: an instrument-grade,
conclusion-first intelligence workspace (calmer, DropZone/AI-SOC-style) rather than the
crimson Falcon look. **Decision:** charcoal canvas (`--bg #0C0D0F`) with a single **teal**
accent (`#3FB6A0`) used **only on interactive chrome** (never as a status mark); status hues
are critical-red / warning-amber / success-teal; **all colour lives in `:root`** (no
component hardcodes a hex — fully re-themable from one block); **flat** (no gradients/glows/
shadows); **sentence case**; **severity by shape + label** (not hue) for WCAG AA. The
signature pattern is **entity-token highlighting** (assets=teal, IPs/ports/domains=amber,
CVEs/files/hashes=mono) inside a deterministic conclusion-first summary, each chip clickable
to pivot. Self-hosted Inter/IBM Plex via `@font-face` with system fallback (no runtime
fetch). **Why:** the brief locked it; the calmer charcoal+teal reads as a focused analyst
instrument and the entity highlighting makes output read as *intelligence*, not a log dump.
**Verified:** headless-Chromium screenshots of all five views (incl. the hero + Kanban);
zero non-same-origin assets; JS `node --check` clean. **Alternatives:** CrowdStrike crimson
(shipped previously, superseded by the brief); Torq purple (off-archetype); DropZone's
AI-investigator identity (rejected — we don't fake autonomous agents).

## D-048 — Signed agent supply chain: cosign over a SHA-256 manifest, verified fail-closed on endpoints
**Context:** the endpoint agent runs in hostile/remote places; a trojanized binary is a
real threat (Phase 8 "signed agent binaries with tamper detection").
**Decision:** the release pipeline builds reproducibly (`-trimpath`, stripped, pinned),
emits a `SHA256SUMS` manifest, and **cosign-signs the manifest** (key in Vault transit at
a true site). Endpoints run `verify.sh` before install: it verifies the cosign signature
**and** the per-binary checksum, and **fails closed** on any mismatch. **Why:** signing the
checksum manifest covers every artifact with one signature; fail-closed verification is the
actual tamper gate; Vault-transit signing means the private key never hits disk. This is
distinct from the Ed25519 *command*-signing channel (D-028) — that authenticates runtime
response commands; this authenticates the *binary* itself. **Alternatives:** GPG detached
sigs (workable but cosign fits the container/OCI story and Vault integration better);
signing each binary separately (more signatures, same guarantee).

## D-047 — Vault on-prem with manual (Shamir) unseal + External Secrets; no cloud auto-unseal
**Context:** secrets must stay on-prem and reach workloads without ever touching git, an
image, or a `.env` (the `.env` → Vault migration promised since Phase 0).
**Decision:** HashiCorp Vault with **Raft integrated storage** (no Consul), **manual Shamir
unseal** (no cloud KMS — an air-gapped site has none; key shares held by operators),
`kv-v2` + `pki` + `transit` engines, and the **External Secrets Operator** projecting
`soc/*` paths into the k8s Secrets the chart mounts. PKI issues the ingest-edge/agent mTLS
certs; transit wraps the Ed25519 command-signing key. **Why:** matches the controlled-access
reality of an air gap; ESO keeps the chart declarative (no secrets in values); rotating a
secret in Vault re-projects automatically. **Alternatives:** sealed-secrets (secrets still
in git, encrypted — weaker custody); cloud KMS auto-unseal (no internet/KMS at the site).

## D-046 — Production air gap = K3s NetworkPolicy (egress-deny / ingress-allow), not the lab's `internal:true`
**Context:** D-042 enforced the gap in the lab with a Docker `internal` network, but that
blocks ingress too (the console became unreachable) — explicitly flagged as a lab-only
verification harness whose production answer is a NetworkPolicy.
**Decision:** ship a **default-deny egress** NetworkPolicy over all SOC Central pods, plus
narrow allows: in-cluster + DNS for everyone, internet egress **only** for feed-sync pods
(selected by an `egress: allowed` label), and **ingress-allow** to api/console/ingest-edge.
**Why:** this is the one primitive that gives egress-deny *and* keeps the console reachable
on the trusted LAN — exactly the property the compose overlay couldn't. The feed-sync label
selector keeps "only the sync job egresses" true and auditable. **Verified:** the chart
renders the four policies; `helm template` is clean. **Alternatives:** Cilium host firewall /
node iptables (less portable, not declarative-in-chart); per-namespace deny (coarser).

## D-045 — nginx serves the console and reverse-proxies `/api` (same-origin, no CORS, no baked host)
**Context:** the SPA must call the FastAPI from the browser.
**Decision:** the console container's nginx serves the static SPA **and** proxies
`/api/*` → `http://api:8000/` on the internal Docker network, so the browser makes
**same-origin** requests to `/api/...`. **Why:** (1) no CORS to configure or weaken;
(2) the API host/port is never baked into the client — the console is portable across
environments; (3) nothing the browser loads egresses. We still added a permissive,
configurable `CORSMiddleware` to the API (`cors_allow_origins_raw`) so a dev console on
another port or Swagger can call it directly. **Verified 2026-06-02:** `/api/version`,
`/api/risk/ranking`, and `/api/findings/{id}/explain` all resolve through the proxy with
live data. **Alternatives:** CORS + an absolute API URL in the client (more config, leaks
the host, fragile across deploys).

## D-044 — The analyst console is a dependency-free static SPA (air-gap-pure); Next.js deferred to a mirrored registry
**Context:** the architecture names a Next.js/Tailwind console; the host has a flaky link +
limited disk; the target is air-gapped; this is the flagship, must-not-fail deliverable.
**Decision:** build the console as a **dependency-free SPA** — hand-built design system,
pure-SVG charts, vanilla JS, **no npm / no CDN / no build step** — served by nginx. **Why:**
it ships **zero external assets**, so it runs fully air-gapped and needs no package registry
at build time (itself an air-gap virtue and a real pitch point); it builds instantly with no
network risk; and it gives total control of an investor-grade look. The framework is
invisible to evaluators — the UI is what they see — so reliability + polish win. The
production migration to the named Next.js/Tailwind toolchain happens once a **mirrored npm
registry (Verdaccio)** exists in the K3s phase; the API contract and the design system carry
over. **Verified 2026-06-02:** console + assets served, `app.js` syntax-clean, live data
rendered via the proxy. **Alternatives:** Next.js/Vite now — rejected for this PoC: the
build-time `npm install` over a flaky link is a real failure mode on the flagship deliverable,
and a node SSR runtime is heavier to air-gap than static files on nginx.

## D-043 — Tool feeds mirrored via each tool's own offline-prepare into named volumes; `--seed` for this host
**Context:** Nuclei/Trivy/Sigma/Suricata fetch rules/DBs from the internet by default;
the air gap forbids that at runtime (expansion §6).
**Decision:** a sibling sync job `tools/airgap/mirror-sync.sh` (the second internet-facing
job after feed-sync) populates four named Docker volumes using **each tool's own**
download mechanism (`nuclei -update-templates`, `trivy image --download-db-only`,
`git clone SigmaHQ/sigma`, ET Open tarball) which the tool containers mount read-only and
run with updates disabled. A `--seed` mode lays down a minimal deterministic mirror from
the repo's bundled rules so the offline path works on this constrained/flaky host.
**Why:** reusing the tools' own offline-prepare avoids re-implementing fetch/format logic
(which would rot), and named volumes are the natural unit to ship by sneakernet. The seed
mode keeps the offline runtime demonstrable without the multi-GB live pulls. **Verified
2026-06-02:** seed populated all four volumes (nuclei template, trivy db marker,
sigma `susp_egress.yml`, suricata `local.rules`). **Alternatives:** a bespoke fetcher
service (more code, duplicates upstream tooling); baking feeds into images (bloated,
can't refresh without rebuild). Cross-platform copy uses `tar`-over-stdin, not a host
bind-mount, because Docker Desktop/Windows doesn't resolve git-bash `/c/...` source paths.

## D-042 — Air-gap enforced with a Docker `internal` network; verified by a probe; K3s NetworkPolicy in prod
**Context:** the air gap was a *convention* (only feed-sync egresses). Phase H must
**verify** it (expansion §H: "run with egress blocked and confirm").
**Decision:** `docker-compose.airgap.yml` puts every runtime service on a
`socnet` network with `internal: true` (no route off-host) and dual-homes only
feed-sync/mirror-sync on an `egress` bridge. `tools/airgap/verify-egress.sh` probes the
sealed network vs a normal-bridge positive control and asserts NO-ROUTE vs REACHED.
**Why:** `internal: true` is the one Docker primitive that *enforces* egress-deny at the
network layer, so the gap is provable, not asserted. **Trade-off (documented in
AIRGAP.md):** `internal` blocks both directions, so a sealed service also loses host
port-publishing — the overlay is therefore a **verification harness**, while the console
demo runs on `make up`. The production primitive is a **K3s NetworkPolicy** (Phase 8):
egress-deny except the sync job, ingress-allow for the console. **Verified 2026-06-02:**
verdict `AIR-GAP ENFORCED` (api could not resolve DNS / reach :443; control bridge could).
**Alternatives:** host-firewall iptables rules (not portable across dev hosts); trusting
that no service has egress code (unverifiable claim).

## D-041 — Fusion annotates clusters; it never deletes a tool's finding
**Context:** several tools flag the same issue on the same asset (Phase F dedup).
**Decision:** the Fusion Engine **groups** findings by `dedup_key` into clusters and
writes a shared `consensus` jsonb onto every member — but leaves each tool's row, with
its own `fingerprint` and raw evidence, intact. The console leads with the cluster's
highest-severity member (`primary`) but can expand to every contributing tool.
**Why:** an analyst investigating an alert needs to see *what each tool actually said*
(Suricata's signature, MISP's IOC context, Trivy's package). Collapsing to one synthetic
row would destroy that evidence and the audit trail. Consensus is additive metadata, not
a destructive merge. **Alternatives:** materialize one merged finding per cluster —
rejected: loses per-tool provenance and complicates re-runs (each tool re-upserts its own
row idempotently). Dedup recipes are documented in `ml/FUSION.md`.

## D-040 — Consensus weight saturates at 2 independent tools; fusion factors join the composite
**Context:** Phase F adds multi-tool consensus + threat-intel + ATT&CK context to scoring.
**Decision:** the consensus weight maps distinct corroborating tools as 1→0.0, 2→0.5,
3+→1.0 (saturating), and the three fusion factors (`threat_intel`, `consensus`,
`attack_ctx`) join the **composite** weighted sum (rebalanced to still total 1.0), not
just the ML model. **Why:** the one→two-tools jump is the most informative — a second
independent confirmation is decisive, a fifth adds little — so a saturating curve matches
reality and resists a single noisy tool inflating scores. Putting the factors in the
transparent composite (not only XGBoost) keeps the headline score defensible without the
model, while XGBoost still learns the interactions (`threat_intel×epss`, `consensus×cvss`)
and SHAP attributes them. **Alternatives:** linear/log count (less interpretable, no
saturation); ML-only fusion features (would make the composite baseline blind to the very
signals that most change priority).

## D-039 — Sigma via pySigma, with an `x_opensearch_query` fallback
**Decision:** the Sigma evaluator compiles rules with **pySigma + the OpenSearch backend**;
if pySigma is unavailable (or a rule won't convert), it falls back to a per-rule
`x_opensearch_query` field and runs that against the log store, so detection still works.
**Why:** pySigma is the right tool, but on this flaky/air-gapped host its wheels didn't always
install — the fallback (which is what pySigma would compile to anyway) keeps Sigma detection
functioning and is honest about the mode in the finding's evidence. Verified: the port-4444
rule matched 82 telemetry docs → one HIGH `sigma` finding (tagged T1571). The mirrored SigmaHQ
rule set loads from `rules/`.

## D-038 — MISP/OpenCTI enrichers verified via fixtures; live via their REST APIs
**Decision:** the `intel-enricher` matches telemetry indicators against **MISP** IOCs and tags
findings with **OpenCTI** ATT&CK techniques, adding `findings.threat_intel` (IOC context) and
`findings.attack` (technique). Both heavy platforms are verified offline with real-shaped
**fixtures**; live mode calls their REST APIs (PyMISP / pycti are the official clients, in
`reference/` and attributed — swappable for the lean httpx path). **Why:** the value is the
*enrichment logic + the attack/threat_intel signal* (which feed the Phase-F fusion model);
running multi-GB MISP/OpenCTI stacks isn't feasible on the lab host. Verified: 185.220.101.45
matched a Cobalt-Strike IOC; ATT&CK T1190 spans agent+nuclei+trivy CVE findings.

## D-037 — Scanner CVEs routed through the existing mirror enrichment (not re-matched)
**Decision:** Trivy/Nuclei already map a target to CVEs/templates, so the `enrichment --scan`
path takes their JSON directly, enriches each CVE with **EPSS + KEV from the local mirror**
(CVSS from the scanner or `nvd_cve`), and writes a `findings` row tagged `source_tool`.
**Why:** reuse the Phase-3 mirror + Phase-5 risk engine — scanner results become first-class,
ranked, explainable findings without a parallel store and without re-running our package→CVE
matcher (the scanner did that). Per-tool **fingerprint** (so agent + trivy both record a CVE →
consensus) and a shared **dedup_key** (asset+cve) for Phase-F fusion. Verified offline with
real-shaped fixtures (Trivy needs its vuln DB, Nuclei its templates — both mirrored per §6);
live runs feed the same parser.

## D-036 — Wazuh integrated via the Manager REST API (JWT :55000), not the deprecated wazuh-api
**Decision:** the `wazuh-bridge` authenticates to the **Wazuh Manager's embedded REST API**
(port 55000, JWT) and pulls FIM (syscheck) + SCA/CIS, normalizing to `fim_event` /
`scan_finding`. **Why:** since Wazuh 4.0 the standalone `wazuh-api` repo is deprecated and the
API lives in the Manager. The bridge has a `--from-fixtures` mode (real-shaped API responses)
so the integration is verifiable offline — the heavy Wazuh image (~1.5 GB) won't run on this
lab host; live mode calls the real Manager. Falco runs identically via its JSON `file_output`
tailed by `sensor-bridge` → `runtime_alert` (Falco needs kernel access it lacks on Docker
Desktop/WSL, so verified via fixtures too).

## D-035 — Wazuh and the Go agent COMPLEMENT (multi-tool consensus), not duplicate
**Decision:** both our Go agent and Wazuh do FIM/host checks independently, and **both** feed
the pipeline tagged by `source_tool`. We do **not** disable one to avoid "duplication."
**Why:** independent corroboration is a *signal* — the Phase-F Fusion Engine dedups by
`dedup_key` (e.g. asset+path for FIM, asset+CIS-control for compliance) and **boosts
confidence when tools agree**, recording which tools contributed. The lightweight Go agent is
always-on baseline telemetry; Wazuh adds deeper FIM/SCA/log analysis where deployed. Same for
compliance: Wazuh SCA/CIS results sit alongside our rule-engine results and are reconciled in
fusion, not merged blindly.

## D-034 — File-based sensors integrate via a `sensor-bridge`, not a new ingestion path
**Decision:** Suricata (EVE JSON) and Zeek (TSV/JSON logs) are file-based, not REST. A
`sensor-bridge` worker **tails their files** and publishes normalized envelopes
(`ids_alert` / `traffic_metadata`) onto the **existing JetStream pipeline**; the existing
workers then fan them out to TimescaleDB + OpenSearch. **Why:** keeps the broker interface
stable (Ground-Rule #4) and reuses all downstream storage/validation — adding a sensor is a
new producer, not a new pipeline. Verified: real Suricata on a deterministic pcap → 2 alerts
→ bridge → OpenSearch + Timescale; Zeek conn/dns logs → `traffic_metadata` likewise.

## D-033 — Internal sensors publish straight to the broker; only remote agents use mTLS edge
**Decision:** internal server-side sensors (Suricata/Zeek via `sensor-bridge`) publish
directly to JetStream and stamp `ingested_at` themselves; remote endpoint **agents** still go
through `ingest-edge` (mTLS + token + schema validation). **Why:** the mTLS edge exists to
authenticate *untrusted remote* agents; co-located sensors on the SOC host don't need it and
shouldn't pay its overhead. Defence-in-depth is preserved — the worker re-validates every
envelope against the schema regardless of source (and now defaults a missing `ingested_at`,
so any direct publisher is safe).

## D-032 — Findings gain provenance + fusion fields (`source_tool`, `raw_ref`, `dedup_key`)
**Decision:** the unified telemetry envelope adds optional `source_tool` / `raw_ref` and five
tool-sourced `kind`s (ids_alert, traffic_metadata, scan_finding, ioc_match, runtime_alert);
the `findings` table gains `source_tool` (default `agent`), `raw_ref`, `dedup_key`, and
`consensus`. **Why:** multi-tool ingest needs provenance and a deterministic key so the
Phase-F Fusion Engine can merge findings about the same issue and weight by tool consensus —
without a second schema. All changes are **additive** (envelope stays v1; columns are
`ADD COLUMN IF NOT EXISTS`).

## D-031 — Falco included as an optional runtime-detection layer
**Decision:** Falco is added under the `runtime` profile but **off by default** and clearly
optional. **Why:** it wasn't in the original architecture (flagged in the expansion prompt),
it overlaps the agent's eBPF, and it needs privileged kernel access that often won't work on
Docker Desktop/WSL. Kept as a complementary layer; trivial to drop.

## D-030 — Heavy tool platforms are defined behind profiles, not auto-run on the lab host
**Decision:** all ten tools live in `docker-compose.tools.yml` behind **opt-in profiles**
(sensors/scanners/runtime/hostmon/intel); `make up` (core stack) is unaffected. OpenCTI
(Elastic+Redis+RabbitMQ+MinIO+platform+worker), MISP, and Wazuh are **heavy** (~10+ GB
images, several GB RAM). On this disk-constrained lab host they are **defined + config-
validated** and started **per-group as capacity allows**; the heaviest are deferred to a
larger host. **Why:** honesty over a broken "everything-up" claim — the integration *code*
(workers consuming each tool's output) is what matters and is built per phase. Documented
what actually runs in PHASE-A-NOTES.

## D-029 — Scope change: network IDS (Suricata/Zeek) brought INTO the MVP
**Decision:** the tool-integration expansion deliberately brings **Suricata/Zeek and network
detection** into scope, which the original scope document listed as an **explicit MVP
non-goal** (Phase 2 roadmap). **Why:** the supervisor-provided expansion prompt requires it.
**Flagged for the evaluation panel** because the project has a formal scope document — this
is a sanctioned expansion, recorded here and in PHASE-A-NOTES so it's transparent.

## D-028 — Signed command channel (Ed25519), verified against a provisioned key
**Decision:** every active-response command is **Ed25519-signed** by the server; the agent
verifies it against a public key it was **provisioned with out-of-band** (mounted), not a
key carried by the command — zero-trust on the channel. The server signs the *exact
canonical bytes* the agent verifies, so there's no cross-language canonicalization risk and
the command cannot be forged/altered in transit. **Why:** containment is destructive;
authenticity + integrity + non-repudiation are mandatory. Verified: a tampered command is
**refused** (`verify_failed`) and does not execute. Agent→API poll uses a bearer token for
now; full mTLS-everywhere is Phase 8.

## D-027 — Two-person rule for destructive actions (separation of duties)
**Decision:** all containment actions (process kill / network isolate / file quarantine /
user disable) require **≥2 distinct approvers**, and the **requester may not approve their
own** request; only on quorum is the command signed + dispatchable. **Why:** destructive
response on production hosts must not be unilateral — the standard SOC control against a
single malicious/mistaken operator. Configurable via `TWO_PERSON_MIN`.

## D-026 — Hash-chained audit for active response (reuses the evidence-chain construction)
**Decision:** every action lifecycle event (requested → approved → signed → dispatched →
completed/failed/verify_failed) appends to a hash-chained `action_audit` log
(`hash = SHA-256(prev_hash + canonical(record))`), same construction as the Phase-4
compliance evidence chain (D-021). `GET /response/audit/verify` recomputes it. **Why:**
destructive actions demand a tamper-evident, non-repudiable record of who requested/approved/
ran what. Verified: editing any past record is detected and pinpointed.

## D-022 — Compliance evaluates available osquery state; missing data is `not_applicable`
**Decision:** the compliance engine grades each rule **pass / fail / partial /
not_applicable** against the host state the agent actually collects. Rules needing data
we don't yet gather (e.g. `sshd_config`, file permissions, sysctl) return
**`not_applicable`** with a reason, never a false pass. **Why:** honesty over coverage —
a benchmark that silently passes uncollected controls is worse than useless in a viva or
an audit. Expanding coverage is "collect more osquery + add rules", not a redesign. The
rule set shipped is a representative CIS Debian 12 + org-policy starter, not the full set.

## D-021 — Hash-chained, append-only evidence log for audit traceability
**Decision:** every compliance evaluation appends an immutable record to
`compliance_evidence`, where each record stores the previous record's hash and its own
`hash = SHA-256(prev_hash + canonical(record))` — a Merkle/blockchain-style chain.
`compliance_results` holds the current per-rule state (upserted); the chain is the
**tamper-evident history**. Any edit to a past record breaks every subsequent hash, which
`GET /compliance/evidence/verify` detects and pinpoints. **Why:** the brief requires
audit traceability for compliance; this is verifiable offline, needs no external notary,
and fits the air-gapped model. Records use only stable JSON types so they survive a jsonb
round-trip and re-hash identically. Phase 8 can anchor the head hash externally for
stronger guarantees.

## D-025 — Analyst feedback loop feeds retraining (bootstrapped synthetic labels)
**Decision:** `analyst_feedback` captures accept/dismiss/escalate/deprioritize and an
optional 0..100 priority label per finding via the API. Retraining folds those labels in
at higher weight on top of the synthetic population. **Why:** we have no historical labels
at day one, so we bootstrap from the composite formula + simulated interactions and let
real analyst judgement progressively steer the model — "analyst-controlled" intelligence,
not a black box. Cadence is monthly (a Phase 8 cron); for now it's the `train` command.

## D-024 — SHAP via XGBoost's native TreeSHAP (no `shap`/`numba` dependency)
**Decision:** per-finding SHAP contributions come from `booster.predict(pred_contribs=True)`
(XGBoost's built-in exact TreeSHAP), not the `shap` package. **Why:** identical TreeSHAP
maths, but a much smaller, air-gap-friendly image (avoids `shap`+`numba`+`llvmlite`, ~hundreds
of MB and slow cold starts). Counterfactuals are computed by flipping the top levers
(KEV/EPSS/exposure) and re-scoring.

## D-023 — Two-layer risk: transparent composite + ML that learns interactions
**Decision:** `risk_score` is the **deterministic weighted composite** (7 named factors,
weights in `ml/scoring.py`) and is the ranking driver — fully explainable for a viva.
`ml_risk_score` is an **XGBoost** prediction that learns the **non-linear interactions**
the linear score can't (KEV×EPSS, exposure×CVSS, attack-phase), with SHAP explaining the
per-finding contributions. **Why:** keep a defensible, auditable baseline while still
gaining ML lift; if the model is unavailable, composite scoring still works. Training
labels are bootstrapped (D-025). Adds an 8th "attack_phase" feature (kill-chain ordinal),
adapting the Attack-Phase-Aware reference.

## D-020 — Assessment is a periodic batch over the data layer (not per-event)
**Decision:** the enrichment engine reads each asset's *latest* host state from the data
layer and (re)assesses on an interval, upserting findings by a stable `fingerprint`.
**Why:** vulnerability posture is a property of current state, not a stream of events;
batch assessment is simpler, idempotent, and re-runs refresh rather than duplicate.
Analyst-owned `status` is never overwritten. Findings carry a **preliminary** severity
(CVSS/rule) now; the **composite risk score** (CVSS+EPSS+KEV+exposure+age+…) and SHAP
explanations land in Phase 5 (the `risk_score` column is reserved).

## D-019 — Approximate version matching + curated package→product alias map
**Decision:** matching a distro package to CVEs uses (a) a curated `pkg_product_alias`
map (e.g. `libc6→glibc`, `libssl3→openssl`) and (b) a best-effort upstream-version
comparison that strips epoch/Debian-revision and compares dotted-numeric components.
**Why:** full CPE applicability + dpkg version semantics are heavy; this is enough to
correctly place glibc `2.36` in `[2.34, 2.39)` while keeping zlib `1.2.13` out of
`(-inf, 1.2.12)`, which is the 80/20 for the MVP. **Trade-off:** possible
false-positives/negatives on exotic versions; proper libapt version compare + full CPE
match is future work. Findings record the matched range as evidence for review.

## D-018 — Air-gapped feed mirror: feed-sync is the only outbound caller
**Decision:** all external vuln data (NVD/EPSS/KEV) is mirrored into local Postgres by
**feed-sync**, the single internet-facing job; every other service (enrichment, API,
agent) reads the mirror and makes **no** outbound calls. Online runs also cache
normalized rows to a volume so an air-gapped site can carry the cache in and replay it
(`--from-cache`); a `--seed` fixture path makes dev/CI fully offline and deterministic.
**Why:** the platform's core constraint is air-gapped/on-prem deployment (PITB). MISP and
abuse.ch are approved future fetchers behind the same boundary.

## D-017 — Agent resource caps at two layers
**Decision:** the agent self-limits (`GOMAXPROCS`, `debug.SetMemoryLimit`) **and** is
capped by the container runtime (`cpus`, `mem_limit` in compose; K3s requests/limits
later). **Why:** the agent must be a polite guest on production hosts; defence in depth
means a bug in one layer is still bounded by the other. Measured footprint in the MVP:
~8 MiB RSS, ~0.1% CPU.

## D-016 — Agent drives the `osqueryi` binary (not the Thrift extension API)
**Decision:** the osquery collector shells out to `osqueryi --json "<sql>"` for a small
query pack rather than linking osquery's Thrift/extension socket. **Why:** far simpler,
no cgo, robust, and good enough for scheduled host-state in the MVP. It **degrades
gracefully** — if `osqueryi` isn't on PATH the collector logs once and emits nothing, so
the agent still runs. **Trade-off:** no event-stream/differential queries; moving to the
extension API (or osquery's scheduled-query logging) is a later optimisation.

## D-015 — File-integrity monitoring by polling (fanotify/auditd later)
**Decision:** FIM walks the watched paths and fingerprints files (SHA-256 for small
files, size+mtime for large), diffing against the previous scan to emit
created/modified/deleted. The first scan is a silent baseline. **Why:** polling needs no
privileges or kernel features, so it runs anywhere (incl. the lab container), and the
`Collector` interface is identical to the event-driven version. **Trade-off:** detection
latency = scan interval, and a full rescan each cycle; the production path is
event-driven **fanotify/auditd** (instant, no rescan), which slots in behind the same
interface without touching the scheduler/shipper.

## D-014 — Back-pressure via the broker; idempotency via `event_id`
**Decision:** workers are a **durable pull consumer** with `max_ack_pending` bounding
in-flight un-acked messages. If the data stores slow down, workers stop acking,
JetStream stops delivering, and messages **accumulate in the stream** rather than
being dropped — back-pressure is a property of the broker, not a fragile in-process
queue. OpenSearch indexes with `_id = event_id` (idempotent re-delivery) and ingest
sets a JetStream `MsgId` dedup window. **Trade-off:** TimescaleDB has **no dedup yet**
(a hypertable unique constraint must include the time column); a redelivered message
could double-insert there. Verified clean in practice (2501 published ⇒ 2501 distinct
rows) because acks kept up; proper Timescale upsert is deferred to a later phase.

## D-013 — Dual agent auth: mTLS **and** bearer token
**Decision:** `ingest-edge` requires a CA-verified client certificate **and** a shared
bearer token, and binds identity by requiring the envelope `agent_id` to equal the
client-cert **CN**. Health/ready run on a **separate plain-HTTP port** so probes don't
need a client cert. **Why:** defence in depth — a stolen token is useless without the
cert and vice-versa; the CN binding stops one agent impersonating another. **Dev PKI**
is generated by `scripts/gen-certs.sh` into a gitignored `certs/`; real deployments
issue short-lived certs from Vault/an internal CA (K3s phase).

## D-012 — Versioned telemetry envelope, single source of truth
**Decision:** one JSON Schema (`schema/telemetry/v1/envelope.schema.json`) is the
contract, **baked into both** `ingest-edge` (Go `go:embed`) and `workers` (Python) at
build time — no drift. `schema_version` is pinned to `"1.0"`; per-`kind` payload rules
are enforced via `if/then`. **Breaking** changes become **v2** on a new
`telemetry.v2.>` subject namespace so old and new agents coexist during rollout.

## D-011 — NATS JetStream as the MVP broker (broker-agnostic seam)
**Decision:** use **NATS JetStream** for the durable buffer (per the brief — far simpler
to run in a single-host lab than Kafka). All broker-specific code is isolated in
`worker.py` / `ingest-edge`'s publish path; the storage fan-out knows nothing about it,
so **Kafka can be swapped in** later without touching enrichment/storage. Stream
`TELEMETRY` captures `telemetry.v1.>`, file storage, 7-day retention.

## D-010 — Docker's WSL data disk relocated to `D:` via a junction
**Context:** the first `make up` filled `C:` (Docker's `docker_data.vhdx` grew until
the drive hit 0.02 GB free) and the image pull died with
`failed to copy: ... input/output error` — the classic disk-full symptom. **Decision:**
stopped Docker, `wsl --shutdown`, moved `…\AppData\Local\Docker\wsl` (~9.8 GB) to
`D:\Docker\wsl`, and left an NTFS **junction** at the original path; restarted Docker
Desktop. **Why:** frees `C:` and gives Docker the headroom of `D:` without touching
Docker's settings schema — the engine opens the same path, the bytes live on `D:`.
Verified the data root resolves to `D:\Docker\wsl` and the engine came up clean.
**Alternative:** Docker Desktop's "Disk image location" GUI setting — equally valid,
but the junction is scriptable and version-independent.

## D-009 — Reference repos relocated to `D:` via a junction
**Context:** The dev machine's `C:` had ~1.7 GB free after the shallow clones; the
Docker images for the stack need ~3 GB. **Decision:** moved `reference/` (study-only,
gitignored, ~1.1 GB) onto the `D:` drive and replaced `C:\...\reference` with an NTFS
**junction** pointing at it. **Why:** frees `C:` for Docker without changing any path
the repo or scripts use — `reference/` still resolves normally. **Alternatives:**
relocating Docker's WSL2 data-root to `D:` (more invasive, risk of breaking Docker),
or deleting the heavy study repos (loses material the later phases need).

## D-008 — Reference repos cloned shallow (`--depth 1 --single-branch --no-tags`)
**Decision:** all 21 study repos are shallow-cloned. **Why:** we only need to *read*
current source and verify licenses, not their history; this cut disk/bandwidth by an
order of magnitude (e.g., osquery 29 MB vs. hundreds of MB full). **Trade-off:** no
`git log` archaeology on references — acceptable, they are study material.

## D-007 — Licenses verified from each repo's actual LICENSE file
**Decision:** ATTRIBUTIONS.md records the license read from each repo's `LICENSE`/
`COPYING` file, not from memory or GitHub's sidebar. **Why:** Ground Rule #2 demands
it, and several assumptions would have been wrong — e.g., **osquery is dual Apache-2.0
OR GPL-2.0**, **SOC-IN-A-BOX is proprietary non-commercial** (not OSS despite the name),
and five repos declare **no license at all** (= all rights reserved). Copyleft
(GPL/AGPL) and no-license repos are flagged as **reference-only**.

## D-006 — Grafana runs as an unmodified standalone service (AGPL handled cleanly)
**Context:** Grafana is AGPL-3.0. **Decision:** use the **official image unmodified**
and only *configure* it via provisioned datasources/dashboards. **Why:** AGPL
obligations attach to modified/derivative works; running the stock service and
configuring it does not make our code a derivative. We never fork or link Grafana.

## D-005 — OpenSearch security plugin DISABLED in the MVP
**Decision:** `DISABLE_SECURITY_PLUGIN=true` for the lab. **Why:** removes TLS/auth
friction for a single-host demo and avoids the mandatory strong-password bootstrap;
lets readiness checks hit `http://opensearch:9200` directly. **Risk & mitigation:**
this is **insecure by default** — acceptable only because the MVP is an isolated lab.
SSO/RBAC/TLS for OpenSearch is re-enabled in **Phase 7**, and the platform is
air-gapped regardless. Flagged here so it is never shipped to production as-is.

## D-004 — TimescaleDB exposed on host port 5433
**Decision:** map TimescaleDB to host `5433` (container stays 5432). **Why:** Postgres
and TimescaleDB are both Postgres servers; both can't own host 5432. Internal
service-to-service traffic still uses 5432 over the compose network.

## D-003 — Readiness probe actively checks Postgres, OpenSearch, and NATS
**Decision:** `/health/ready` connects to all three backing stores (and `/health`
stays a cheap dependency-free liveness check). **Why:** Phase 0's job is to *prove*
the whole stack is wired together, not just that the API process starts. Liveness vs.
readiness are kept separate so orchestrators (Compose now, K3s later) restart vs.
gate traffic correctly.

## D-002 — NATS JetStream as the MVP broker (broker-agnostic consumer interface)
**Decision:** NATS JetStream now; keep the worker/consumer interface abstract so
Kafka can replace it later. **Why:** JetStream is dramatically simpler to run in a
single-host lab than Kafka (no ZooKeeper/KRaft, one small binary) while still giving
durable streams, back-pressure, and replay — exactly what Phase 1 must demonstrate.

## D-001 — Provide both a Makefile and a PowerShell task runner
**Context:** the dev host is Windows (no `make`); the target deployment is Linux.
**Decision:** ship `Makefile` (Linux/macOS) **and** `scripts/dev.ps1` (Windows) with
identical targets (`up`, `down`, `health`, …). **Why:** "one command per phase"
(Ground Rule #9) must work for whoever is driving, regardless of OS, without
installing `make` on Windows.

## D-000 — Monorepo under `soc-central/`, product code split from reference
**Decision:** single repo with `services/`, `agent/`, `web/`, `ml/`, `deploy/` for
product code and a **gitignored** `reference/` for study clones. **Why:** Ground Rule
#3 — third-party source must never enter the product tree; a clean separation makes
licensing, review, and the viva defensible.

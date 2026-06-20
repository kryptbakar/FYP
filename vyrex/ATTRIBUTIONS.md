# Attributions & License Register

Every repository we cloned into `reference/` for study is listed here with its
**license verified from the repo's actual LICENSE file** (not assumed). `reference/`
is gitignored; nothing here is vendored into the product tree.

**Legend**
- 🟢 **Permissive** (MIT / BSD / Apache-2.0) — safe to adapt with attribution.
- 🟠 **Copyleft (GPL/AGPL)** — **design reference only**; do **not** vendor source
  into our product. Reimplement any needed behaviour from our own understanding.
- 🔴 **Proprietary / non-OSS / no license** — **study concepts only**; copying any
  code is not permitted. Treat as "all rights reserved".

> **Policy (from Ground Rule #2):** When in doubt, reimplement a small piece rather
> than vendor copyleft or unlicensed source. Any adapted file must carry a header
> comment naming the source repo and its license.

Licenses last verified: **2026-06-01**.

---

## Vulnerability-management base & data model (design reference)

| Repo | URL | License (verified) | Class | Use |
|------|-----|--------------------|-------|-----|
| django-DefectDojo | https://github.com/DefectDojo/django-DefectDojo | **BSD-3-Clause** (`LICENSE.md`) | 🟢 | Finding/engagement/asset data-model & REST API design patterns. |
| faraday | https://github.com/infobyte/faraday | **GPL-3.0** (`LICENSE`) | 🟠 | Vulnerability normalization/aggregation **concepts**. Do not vendor. |

## Exploit-aware enrichment (the "tool APIs" layer)

| Repo | URL | License (verified) | Class | Use |
|------|-----|--------------------|-------|-----|
| Cve-Extractor-Public | https://github.com/IKER-36/Cve-Extractor-Public | **MIT** (`LICENSE`) | 🟢 | Core enrichment-worker logic (NVD + KEV + EPSS + exploit). Closest to our workers. |
| CVEraptor | https://github.com/dinesh-murugan-h/CVEraptor | **No license declared** | 🔴 | Enrichment field-mapping **ideas only**; all rights reserved. |
| cve-watch | https://github.com/tcoatswo/cve-watch | **MIT** (`LICENSE`) | 🟢 | Explainable patch-prioritization approach (overlaps our XAI goal). |
| Faraday_CVE_Parser | https://github.com/cyb3ri0t/Faraday_CVE_Parser | **No license declared** | 🔴 | EPSS/KEV/CVSS parser **ideas only**; all rights reserved. |

## Intelligence layer — ML risk prioritization + XAI (our differentiator)

| Repo | URL | License (verified) | Class | Use |
|------|-----|--------------------|-------|-----|
| Attack-Phase-Aware-Dynamic-Vulnerability-Prioritization-Framework | https://github.com/shreyas23dev/Attack-Phase-Aware-Dynamic-Vulnerability-Prioritization-Framework | **MIT** (`LICENSE`) | 🟢 | Closest match: CVSS+EPSS+ATT&CK scoring, XGBoost + SHAP pipeline. Adapt heavily. |
| cve-enriched-dataset | https://github.com/francesco-denu/cve-enriched-dataset | **No license declared** | 🔴 | Training-data assembly **approach only**; all rights reserved. |
| cvss_score_prediction_model | https://github.com/themalkaanjalarathnasiri/cvss_score_prediction_model | **No license declared** | 🔴 | Feature-engineering **reference only**; all rights reserved. |
| xgboost | https://github.com/dmlc/xgboost | **Apache-2.0** (`LICENSE`) | 🟢 | Used as a **pip dependency** (gradient-boosting model). |
| shap | https://github.com/shap/shap | **MIT** (`LICENSE`) | 🟢 | Used as a **pip dependency** (SHAP explainability). |

## Endpoint agent layer

| Repo | URL | License (verified) | Class | Use |
|------|-----|--------------------|-------|-----|
| osquery | https://github.com/osquery/osquery | **Apache-2.0 OR GPL-2.0** (dual; `LICENSE`) | 🟢 | We **choose Apache-2.0**. Embed/shell out to `osqueryd`; study schema. |
| cilium/ebpf | https://github.com/cilium/ebpf | **MIT** (`LICENSE`) | 🟢 | Go eBPF library for process/network observation. Used as a dependency. |
| yara | https://github.com/VirusTotal/yara | **BSD-3-Clause** (`COPYING`) | 🟢 | YARA engine for IOC file/memory scanning. |
| wazuh | https://github.com/wazuh/wazuh | **GPL-2.0** (`LICENSE`) | 🟠 | FIM & CIS-control **concepts only**. Do not vendor. |
| velociraptor | https://github.com/Velocidex/velociraptor | **AGPL-3.0** (`LICENSE`) | 🟠 | Active-response / containment command-channel **model only**. Reimplement. |

## Incident response & case management

| Repo | URL | License (verified) | Class | Use |
|------|-----|--------------------|-------|-----|
| TheHive | https://github.com/TheHive-Project/TheHive | **AGPL-3.0** (`LICENSE`) | 🟠 | Case-lifecycle **patterns only**. Do not vendor. |
| Cortex | https://github.com/TheHive-Project/Cortex | **AGPL-3.0** (`LICENSE`) | 🟠 | Observable-enrichment workflow **patterns only**. Do not vendor. |

## Full-stack architecture references (study the wiring, don't fork)

| Repo | URL | License (verified) | Class | Use |
|------|-----|--------------------|-------|-----|
| Open-Source-SIEM_SOC-Stack | https://github.com/ArfanAbid/Open-Source-SIEM_SOC-Stack | **No license declared** | 🔴 | Architecture blueprint **reading only**; all rights reserved. |
| SOC-IN-A-BOX | https://github.com/dominguezbernaldo943-svg/SOC-IN-A-BOX | **Proprietary — non-commercial** (`LICENSE`) | 🔴 | **Commercial use prohibited** by its license. Study Grafana/OpenSearch/OIDC wiring **only**; do not reuse code. |
| agentic-soc-platform | https://github.com/FunnyWolf/agentic-soc-platform | **MIT** (`LICENSE`) | 🟢 | Incident-correlation / one-API-over-many-backends reference. |

---

## Copyleft & non-OSS — distribution implications (read before reuse)

These matter only if SOC Central is ever **distributed** (the PITB deployment is
on-prem, but treat distribution as possible):

- **AGPL-3.0** (TheHive, Cortex, Velociraptor): the strongest copyleft — even
  *network use* of a modified work can trigger source-disclosure obligations.
  → We use these **only** as behavioural references and **reimplement** the needed
  pieces (e.g., the signed active-response command channel) from scratch.
- **GPL-3.0 / GPL-2.0** (Faraday, Wazuh): vendoring or linking their source into a
  distributed product would impose GPL on our product. → **concepts only**.
- **osquery — Apache-2.0 OR GPL-2.0** (dual): we elect the **Apache-2.0** option,
  which is permissive and compatible with our stack. We invoke `osqueryd` as a
  separate process (no linking), keeping even that boundary clean.
- **SOC-IN-A-BOX — proprietary/non-commercial**: not open source; a government
  PoC could be argued non-commercial, but to stay safe we **do not reuse its code**
  at all — wiring patterns are studied, then implemented independently.
- **No-license repos** (CVEraptor, Faraday_CVE_Parser, cve-enriched-dataset,
  cvss_score_prediction_model, Open-Source-SIEM_SOC-Stack): absence of a license =
  **all rights reserved** by default. We study the **ideas** and write our own code.

## Runtime dependencies (pulled as images/packages, not vendored)

Permissive licenses; used as-is via container images or pip:
PostgreSQL (PostgreSQL License), TimescaleDB (Apache-2.0 / Timescale License for
some features), OpenSearch (Apache-2.0), NATS (Apache-2.0), Grafana (AGPL-3.0 —
used **unmodified as a separate service**, which does not impose copyleft on our
own code), FastAPI (MIT), Uvicorn (BSD), Pydantic (MIT), Next.js (MIT), Tailwind (MIT).

> Note: Grafana is AGPL but we run the **official unmodified image as a standalone
> service** and only *configure* it (provisioned dashboards/datasources). We do not
> modify or link Grafana source, so its AGPL terms are satisfied by leaving it intact.

---

## Tool-Integration Expansion (Phase A) — verified 2026-06-02

Ten OSS security tools run as **their own containers** (`docker-compose.tools.yml`); our
code only **consumes their output** (we don't fork them). Licenses verified from each
cloned repo's actual LICENSE file.

| Repo | URL | License (verified) | Class | Use |
|------|-----|--------------------|-------|-----|
| Suricata | https://github.com/OISF/suricata | **GPL-2.0** (`LICENSE`) | 🟠 | Network IDS. Run as a **separate container**; we tail its EVE JSON. Do not vendor/link. |
| Zeek | https://github.com/zeek/zeek | **BSD-3-Clause** (`COPYING`) | 🟢 | Traffic metadata. Separate container; we ship its logs. |
| Nuclei | https://github.com/projectdiscovery/nuclei | **MIT** (`LICENSE.md`) | 🟢 | Template vuln scanner; parse `-jsonl`. |
| Trivy | https://github.com/aquasecurity/trivy | **Apache-2.0** (`LICENSE`) | 🟢 | Container/image/fs CVE scanner; REST server. |
| PyMISP | https://github.com/MISP/PyMISP | **BSD-2-Clause** (`LICENSE`) | 🟢 | MISP REST client (pip). |
| OpenCTI client-python | https://github.com/OpenCTI-Platform/client-python | **Apache-2.0** (`LICENSE`) | 🟢 | OpenCTI/ATT&CK client (pip `pycti`). |
| pySigma | https://github.com/SigmaHQ/pySigma | **LGPL-2.1** (`LICENSE`) | 🟠 | Sigma→query compiler (pip). Weak copyleft — use unmodified as a library. |
| pySigma-backend-opensearch | https://github.com/SigmaHQ/pySigma-backend-opensearch | **LGPL-3.0** (`LICENSE`) | 🟠 | OpenSearch backend for pySigma (pip). Weak copyleft — library, unmodified. |
| Sigma (rules) | https://github.com/SigmaHQ/sigma | **DRL 1.1** (rules) / spec public domain (`LICENSE`) | 🟢 | Detection rules; mirrored + compiled. DRL permits use/redistribution with attribution. |
| Falco | https://github.com/falcosecurity/falco | **Apache-2.0** (`COPYING`) | 🟢 | Runtime detection (optional, D-031); consume gRPC/JSON. |
| Falco client-go | https://github.com/falcosecurity/client-go | **Apache-2.0** (`LICENSE`) | 🟢 | Go client for Falco gRPC outputs. |
| zeek2es | https://github.com/corelight/zeek2es | **BSD-3-Clause** (`LICENSE`) | 🟢 | Zeek-log→OpenSearch shipper reference. |
| zeek/broker | https://github.com/zeek/broker | **BSD/NCSA** (`COPYING`) | 🟢 | Live Zeek event control reference. |
| suricatarest | https://github.com/pfyon/suricatarest | **No license declared** | 🔴 | Dev-only PCAP→JSON helper; all rights reserved — concepts only. |
| mrtc0/wazuh (Go client) | https://github.com/mrtc0/wazuh | **No license file found** | 🔴 | Not used — we call the Wazuh **Manager REST API** from Python instead. |
| nvdlib | https://github.com/Fortra/nvdlib | **MIT** (upstream; clone failed on this run — re-verify on next sync) | 🟢 | Optional NVD wrapper; `feed-sync` already mirrors NVD directly. |

**Already registered (Phase 0), reused here:** Wazuh (`wazuh/wazuh`) — **GPL-2.0** 🟠
(host-monitoring **concepts**; we integrate via its Manager REST API, not its source).

### New copyleft flags (distribution implications)
- **Suricata — GPL-2.0** 🟠 and **Wazuh — GPL-2.0** 🟠: run as **standalone containers**
  (official images), integrated only through their documented output/API. We do **not**
  link or vendor their source, so GPL is **not** imposed on our code — same clean boundary
  we use for Grafana (AGPL). Flagged for the panel because they're copyleft.
- **pySigma (LGPL-2.1)** and **pySigma-backend-opensearch (LGPL-3.0)** 🟠: used as
  **unmodified pip libraries**; LGPL permits this without copylefting our code.
- **Sigma rules — DRL 1.1**: permissive for detection content with attribution.
- **suricatarest / mrtc0-wazuh**: no clear license → **all rights reserved**, not used in
  the product (dev/reference only).

# Live validation — attack-simulation study

This is the out-of-distribution proof the risk-engine evaluation (docs and
`ml/evaluate.py`) explicitly defers to: a real adversary emulation run against a
VYREX-monitored host, measured end-to-end. One executed run of this runbook is
worth more in a viva than another tool integration, because it demonstrates the
*whole* claim — collect → detect → fuse → prioritise → explain → respond — on
events VYREX has never seen, and it produces a detection-latency and
tool-coverage table you can defend.

The runbook is designed to run on a **single laptop** (the whole stack is
Docker Compose) plus **one throwaway VM** as the victim. No internet is required
after the images and atomics are mirrored.

## 0. What you are measuring (define up front)

For every simulated technique, record:

| Field | Meaning |
|---|---|
| ATT&CK technique | e.g. T1059.004 (shell), T1071 (C2), T1003 (cred dump) |
| t0 | when the atomic executed (from Atomic Red Team's own log) |
| t_detect | `ingested_at` of the first VYREX finding attributable to it |
| **detection latency** | t_detect − t0 |
| tools that fired | which of agent / Suricata / Zeek / Wazuh / Falco / Sigma produced a finding |
| fused? | did fusion cluster them (consensus weight > 0)? |
| rank | the finding's position in the risk-ordered queue |
| SHAP top factors | the three features the explanation attributes the score to |
| detected? | yes / partial / missed — the honest coverage number |

The deliverable is the filled table in §5 plus a short narrative per technique.
**Missed detections are a result, not a failure** — report them; they scope your
"future work" and prove the evaluation was real.

## 1. Lab topology

```
┌────────────────────────┐        mTLS telemetry      ┌───────────────────────────┐
│  Victim VM             │  ───────────────────────▶  │  VYREX stack (Compose)     │
│  Ubuntu 22.04 / Win10  │        (agent → 8443)      │  ingest-edge, NATS,        │
│  - VYREX Go agent      │                            │  workers, API, console,    │
│  - Atomic Red Team     │   span/mirror or pcap ───▶ │  risk-engine, Grafana      │
│  - test user + files   │       to Suricata/Zeek     │  + tool sensors (profiles) │
└────────────────────────┘                            └───────────────────────────┘
```

- **Host machine** runs the VYREX stack (`make up`, plus sensor/scanner/hostmon
  profiles you want in scope — see docs/PRODUCTION-DEPLOYMENT.md §sensors).
- **Victim VM** runs the endpoint agent and the atomics. Give it a host-only or
  internal network so nothing escapes the lab (this doubles as air-gap fidelity).
- Network detections (Suricata/Zeek) need the victim's traffic mirrored to the
  sensor. Simplest offline option: capture a pcap on the VM during the run and
  replay it into the sensor (`make sensors-test` shows the replay path), so C2 /
  exposure atomics still light up without a real span port.

## 2. Prepare the victim

Linux victim:

```bash
# 1. Build + ship the agent to the VM (cross-compile from the repo)
cd vyrex/agent && GOOS=linux GOARCH=amd64 go build -o vyrex-agent .
scp vyrex-agent agent.crt agent.key ca.crt user@victim:/opt/vyrex/

# 2. Point it at the host stack and start it (systemd unit in deploy/agent-release)
INGEST_URL=https://<host-ip>:8443/v1/telemetry ./vyrex-agent --config agent.yaml

# 3. Install Atomic Red Team (mirror the repo first for air-gap fidelity)
pwsh -c "IEX (IWR 'https://.../install-atomicredteam.ps1')"   # or clone the mirror
```

Confirm the agent is landing telemetry before attacking:
`curl -s localhost:8000/api/telemetry/recent | jq '.[0]'` (or watch the console
Telemetry view). No baseline telemetry ⇒ fix mTLS/token first (see §7).

## 3. The atomic test plan

Run these in kill-chain order so the fusion/attack-phase logic is exercised
across tactics. Each maps to a feature the engine specifically reasons about.

| Phase | ATT&CK | Atomic (example) | Expected VYREX signal |
|---|---|---|---|
| Execution | T1059.004 | Atomic "Command-Line Interface" bash one-liner | agent process_event (suspicious parent/cmdline) |
| Persistence | T1053.003 | cron entry | agent + Wazuh FIM/SCA on crontab; Sigma rule |
| Priv-esc | T1548.001 | setuid abuse | agent process_event; attack_ctx grade 0.7 |
| Defense evasion | T1070.004 | file deletion / log clearing | Wazuh FIM delete event |
| Credential access | T1003.008 | read /etc/shadow | agent FIM read + osquery; high attack_ctx |
| C2 | T1071.001 | beacon to lab sinkhole on 443/4444 | agent network_flow egress + Suricata/Zeek; **multi-tool fusion** |
| Exfil | T1048 | DNS/HTTP data-out | network_flow; attack_ctx ~0.95 |

Prefer atomics that touch the files/ports the collectors already watch
(`/etc/passwd`, `/etc/shadow`, ports 4444/443 — see `tools/fake-producer`
and the agent collectors) so at least one detector is guaranteed to fire, then
report honestly which additional tools corroborated.

Log t0 for each: Atomic Red Team writes an execution log
(`Invoke-AtomicTest ... -ExecutionLogPath`); use its timestamps as ground truth.

## 4. Run, then score

```bash
# after the atomics complete and a pcap (if used) is replayed:
make scan-ingest        # if you also ran a vulnerable service for scanner findings
make risk-score         # composite + ML + SHAP + fusion over everything collected
```

Then pull the evidence per technique from the API / console:

```bash
# newest findings with their rank, tools, consensus and SHAP
curl -s "localhost:8000/api/findings?sort=risk&limit=50" | jq '.[] | {id, title, risk_score, rank, tools, consensus, attack}'
curl -s "localhost:8000/api/risk/<finding_id>/explain" | jq '.shap'
```

The console's finding drawer shows the same: contributing tools, consensus badge,
and the SHAP waterfall — screenshot these for the report.

## 5. Results table (fill from the run)

| ATT&CK | Technique | t0 | t_detect | Latency | Tools fired | Fused | Rank | SHAP top-3 | Detected |
|---|---|---|---|---|---|---|---|---|---|
| T1059.004 | Shell exec | | | | | | | | |
| T1053.003 | Cron persistence | | | | | | | | |
| T1548.001 | Setuid | | | | | | | | |
| T1070.004 | Log clearing | | | | | | | | |
| T1003.008 | /etc/shadow read | | | | | | | | |
| T1071.001 | C2 beacon | | | | | | | | |
| T1048 | Exfiltration | | | | | | | | |

Summary metrics to quote in the thesis:

- **Detection coverage:** detected / total techniques attempted.
- **Median detection latency** across detected techniques.
- **Fusion lift:** how many techniques were corroborated by ≥2 tools, and the
  average rank of fused vs solo findings (fused should rank higher — that is the
  consensus factor working on real events).
- **Explainability spot-check:** for 3 findings, did the SHAP top factors match
  the true reason (e.g. C2 finding attributes to attack_ctx + exposure)?

## 6. Turning it into analyst-feedback data (bonus)

Every technique you triage here is a real label. Insert the confirmed ones into
`analyst_feedback` (label_priority = your analyst judgement) and re-run
`make risk-train && make risk-eval` — the evaluation report will now include
real labels folded in at 5× weight, closing the "trained only on synthetic data"
gap the roadmap calls out.

## 7. Troubleshooting

- **No telemetry from the agent:** check mTLS (`ca.crt` trust + client cert) and
  the bearer token; `docker compose logs ingest-edge` shows rejects with reasons.
- **Network atomics don't produce Suricata/Zeek findings:** the sensor isn't
  seeing the traffic — replay a pcap captured on the victim (see `make sensors-test`).
- **Finding has no ML score / SHAP:** train first (`make risk-train`), then
  `make risk-score`.
- **Nothing ranks the C2 finding highly:** confirm `attack` mapping populated
  (intel-enrich / Sigma) — attack_ctx is 0 for unmapped findings by design.

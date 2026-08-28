# Lab deployment — running VYREX against a real endpoint

How to move VYREX off `fake-producer` and onto **real telemetry from a real machine over a
real network path**, using an isolated VirtualBox lab on the same laptop.

This is a genuine network deployment in every way that matters technically — real TCP,
real mutual TLS, real certificate validation, a real agent process on a separate operating
system — while remaining entirely self-contained. Nothing leaves the laptop, so no
authorization beyond your own hardware is required.

> **Scope discipline.** VYREX ships network sensors and vulnerability scanners. Pointing
> those at a network you do not own is not a configuration question, it is an
> authorization question. This document deliberately targets an isolated host-only
> segment. If the lab is ever widened to a university or shared subnet, get the scope in
> writing first — which subnets, which hosts, which activities — and attach it to the
> report.

---

## Topology

```
Windows laptop (16 GB)
│
├─ Docker Desktop / WSL2  ── VYREX server stack (5.8 GB ceiling)
│    ingest-edge  :8443   ← the ONLY port the lab network needs to reach
│    api :8000 · console :3001 · grafana :3000 · n8n :5678 · ollama :11434
│
└─ VirtualBox host-only network  192.168.56.0/24
     ├─ host side          192.168.56.1
     └─ VM "linux"         192.168.56.101   ← runs the VYREX agent
```

The agent connects **out** to `ingest-edge` and presents a client certificate. Nothing
connects *into* the VM, so the VM needs no inbound rules.

---

## Phase A — harden first (do NOT skip)

Right now the stack is bound for single-machine development, and the moment a second
machine can route to it that becomes an exposure. Measured on 2026-08-22:

| Port | Service | Auth today |
|---|---|---|
| 8000 | API | **none** — `API_AUTH_REQUIRED=false`, includes `/actions/*/approve`, `/defense/*` |
| 11434 | Ollama | **none** |
| 4222 / 8222 | NATS | **none** — publish/subscribe to all telemetry |
| 8025 | Mailpit | none |
| 3000 | Grafana | login (likely still `admin`/`admin`) |
| 5678 | n8n | owner account ✅ |
| 8443 | ingest-edge | **mTLS ✅** |

Postgres, TimescaleDB and OpenSearch are already loopback-bound — leave them that way.

1. **Turn authentication on.** In `vyrex/.env`:
   ```
   API_AUTH_REQUIRED=true
   ```
   Log in through the console as `admin` / `vyrex` (change that password), or obtain a
   token with `POST /auth/login`. Note `/agent/triage` is admin-only
   (`auth_guard.py` `ADMIN_PREFIXES`).

2. **Bind the unauthenticated services to loopback.** In `docker-compose.yml` /
   `docker-compose.n8n.yml`, prefix the host side with `127.0.0.1:` exactly as
   postgres/opensearch already do — `ollama`, `nats`, `mailpit`. They are consumed by
   other containers over the internal Docker network, so nothing breaks.

3. **Leave `ingest-edge` on `0.0.0.0:8443`.** It must be reachable from the lab segment,
   and it is the one service designed for that: mutual TLS, client-certificate required.

4. **Change the Grafana admin password** (`GF_SECURITY_ADMIN_PASSWORD`).

5. **Keep the heavy intel stack stopped.** OpenCTI + Elasticsearch + MISP + Wazuh cost
   ~1.6 GB of RAM and currently back 3 IOC fixtures and 7 SQL predicates. With them
   running, the LLM starved: AI triage took 194 s and returned an empty result. With them
   stopped it took 98 s and produced correct output.
   ```powershell
   docker stop vyrex-opencti-1 vyrex-opencti-elastic-1 vyrex-opencti-minio-1 `
               vyrex-opencti-rabbitmq-1 vyrex-opencti-redis-1 `
               vyrex-misp-db-1 vyrex-misp-redis-1 vyrex-wazuh-manager-1
   ```

---

## Phase B — the lab network

1. Create a host-only adapter (VirtualBox → Tools → Network), or:
   ```powershell
   & "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" hostonlyif create
   & "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" hostonlyif ipconfig "VirtualBox Host-Only Ethernet Adapter" --ip 192.168.56.1 --netmask 255.255.255.0
   ```

2. Give the VM **two** adapters:
   - **Adapter 1 — NAT**: outbound only, so you can install packages inside the VM.
   - **Adapter 2 — Host-only**: the lab segment where VYREX lives.

   Keep them separate. The host-only interface is the "monitored network"; NAT is a
   temporary convenience you can detach once the agent is installed, which is also how
   you demonstrate the air-gap claim honestly.

3. Allow the host firewall to accept 8443 on the host-only interface only:
   ```powershell
   New-NetFirewallRule -DisplayName "VYREX ingest-edge (lab)" -Direction Inbound `
     -LocalPort 8443 -Protocol TCP -Action Allow -LocalAddress 192.168.56.1
   ```

4. From the VM, confirm reachability before touching certificates:
   ```bash
   ping -c1 192.168.56.1
   nc -vz 192.168.56.1 8443
   ```

---

## Phase C — the agent

### The certificate detail that decides this

`certs/server.crt` carries **`SAN: DNS:ingest-edge, DNS:localhost, IP:127.0.0.1`**
(hardcoded at `scripts/gen-certs.sh:35`). An agent dialling `https://192.168.56.1:8443`
therefore fails hostname verification — the IP is not in the certificate.

**Fix, no regeneration required.** Point the name at the address inside the VM:

```bash
echo "192.168.56.1  ingest-edge" | sudo tee -a /etc/hosts
```

The agent then connects to `https://ingest-edge:8443`, the SAN matches, and mutual TLS
completes. This is the right answer for the lab: regenerating with `--force` would also
roll the CA, the agent certificate and the Ed25519 command-signing key, all of which are
already baked into running containers.

For a multi-host deployment later, make the SAN list configurable instead of hardcoded —
that is the one real change `gen-certs.sh` needs before it can serve more than one machine.

### Build a static Linux binary (no Go needed on Windows)

Uses `golang:1.23-alpine`, the same base as `agent/Dockerfile` — ~350 MB rather than the
~1.5 GB full image, which matters given how little disk headroom this laptop has.

```powershell
cd c:\Users\dumbutthehe\Desktop\FYP\vyrex
mkdir dist -Force
docker run --rm -v "${PWD}:/src" -w /src/agent -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH=amd64 `
  golang:1.23-alpine go build -trimpath -ldflags="-s -w" -o /src/dist/vyrex-agent .
```

The agent has zero external Go dependencies, so this is a fully static, offline build —
the resulting binary has no libc requirement and runs on any x86-64 Linux.

### Install in the VM

Copy `dist/vyrex-agent` plus `certs/ca.crt`, `certs/agent-001.crt`, `certs/agent-001.key`
(shared folder, or `scp` over the host-only link), then:

```bash
sudo install -m755 vyrex-agent /usr/local/bin/
sudo mkdir -p /etc/vyrex/certs && sudo cp ca.crt agent-001.* /etc/vyrex/certs/
sudo chmod 600 /etc/vyrex/certs/agent-001.key
```

`/etc/vyrex/agent.env` — every value below is a real environment variable read by
`agent/config.go`:

```ini
AGENT_ID=agent-001
AGENT_HOST_ID=lab-vm-01
# NOTE: INGEST_URL is the FULL endpoint, path included — not a base URL.
# (agent/config.go:75 defaults it to https://ingest-edge:8443/v1/telemetry.)
INGEST_URL=https://ingest-edge:8443/v1/telemetry
INGEST_AGENT_TOKEN=<the INGEST_AGENT_TOKEN from vyrex/.env — must match>
CA_CERT=/etc/vyrex/certs/ca.crt
CLIENT_CERT=/etc/vyrex/certs/agent-001.crt
CLIENT_KEY=/etc/vyrex/certs/agent-001.key

ENABLE_SYSINFO=true
ENABLE_NETWORK=true
ENABLE_FIM=true
ENABLE_OSQUERY=true          # degrades gracefully if osqueryi is absent
FIM_PATHS=/etc,/usr/local/bin
AGENT_BATCH_SIZE=50
AGENT_FLUSH_SEC=10
```

systemd unit `/etc/systemd/system/vyrex-agent.service`:

```ini
[Unit]
Description=VYREX endpoint agent
After=network-online.target

[Service]
EnvironmentFile=/etc/vyrex/agent.env
ExecStart=/usr/local/bin/vyrex-agent
Restart=always
RestartSec=5
# The agent only reads /proc and hashes files — it needs no privilege beyond that.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now vyrex-agent
journalctl -u vyrex-agent -f
```

---

## Phase D — verify real telemetry, end to end

Each step proves the previous hop, so stop at the first one that fails.

```powershell
# 1. ingest-edge accepted a real mTLS client
docker logs vyrex-ingest-edge-1 --tail 30

# 2. it reached the message bus and the workers stored it
docker logs vyrex-workers-1 --tail 30

# 3. the real host exists as an asset (NOT host-lab-01, which is fake-producer's)
docker exec vyrex-postgres-1 psql -U soc -d soc_central -c "SELECT host_id, hostname, os, last_seen FROM assets ORDER BY last_seen DESC;"

# 4. raw telemetry landed in OpenSearch
curl "http://localhost:9200/telemetry-v1/_search?q=host.host_id:lab-vm-01&size=3"

# 5. turn real telemetry into findings, then score them
.\scripts\dev.ps1 assess
.\scripts\dev.ps1 risk-score
```

Then open the console at http://localhost:3001 — `lab-vm-01` should appear in Assets with
findings derived from its actual packages and listening ports, and the AI analyst can be
run against them.

**A FIM event on demand** (good demo beat):
```bash
sudo sh -c 'echo "# changed" >> /etc/hosts'     # next scan emits a fim_event
```

---

## What this does and does not prove

**Does:** a real agent process, on a separate OS, authenticating with a client
certificate over a real network path, producing telemetry that flows through the entire
pipeline — ingest → JetStream → workers → TimescaleDB/OpenSearch → enrichment → scoring →
AI triage → n8n → email. That is the full system on real data.

**Does not:** exercise network sensors. Suricata and Zeek are running but reading a dummy
interface. Real capture needs the sensor attached to the host-only adapter in promiscuous
mode, which is a worthwhile follow-up but a separate piece of work — and on this hardware
it competes for the RAM the LLM needs.

Trivy is also still unusable offline (its vulnerability DB mirror has never been built),
so container scanning of the VM is out of scope until that lands.

---

## Resource budget (measured, not estimated)

| Consumer | Allocation |
|---|---|
| Windows | ~4 GB |
| Docker / WSL2 | 5.8 GB cap (2.1 GB used with the lean stack, 3.4 GB available) |
| VirtualBox VM | 1–2 GB — keep it small |
| **Total** | **~12 GB of 16 GB** |

Feasible, with two standing caveats:

- **Disk is the binding constraint.** D: had 2.68 GB free at the time of writing and the
  Docker virtual disk has grown to 52 GB. Compacting it recovers roughly 6 GB and is the
  cheapest headroom available.
- **Do not restart the heavy intel containers while the LLM is in use.** That combination
  is what produced the 194-second empty triage result.

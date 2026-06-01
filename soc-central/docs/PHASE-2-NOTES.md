# Phase 2 — Endpoint agent (MVP)

**Status:** complete and verified against the live stack. **Date:** 2026-06-01.

## What was built

A real Go endpoint agent ([agent/](../agent/)) that replaces the Phase 1
`fake-producer` with genuine host telemetry, shipped over the same mTLS path:

```
agent (Go) ──mTLS──▶ ingest-edge ──▶ JetStream ──▶ workers ──▶ TimescaleDB + OpenSearch
   collectors: sysinfo · network · osquery · fim   (eBPF · YARA staged-in)
```

- **Collector framework** — a `Collector` interface + scheduler (one goroutine per
  collector); adding a source never touches the shipper/scheduler.
- **sysinfo** — CPU% (Δ`/proc/stat`), mem% (`/proc/meminfo`), load1, agent self-RSS.
- **network** — listening + established TCP sockets from `/proc/net/tcp`.
- **osquery** — drives `osqueryi --json` for a 5-query pack (os_version, listening_ports,
  deb_packages, kernel_info, logged_in_users); **degrades gracefully** if osqueryi is
  absent.
- **fim** — polling SHA-256 baseline over `/etc,/usr/bin,/watch`; emits
  created/modified/deleted (first scan = silent baseline). See D-015 for the
  fanotify/auditd upgrade path.
- **eBPF + YARA** — stage-in stubs (off by default), wired into the registry so the real
  implementations drop in behind the same interface.
- **mTLS shipper** — batches, retries with backoff, bounded buffer (agent-side
  back-pressure).
- **Resource caps** — `GOMAXPROCS` + `debug.SetMemoryLimit` **and** container
  `cpus: 0.50` / `mem_limit: 256m` (D-017).

`make agent-run` builds and launches it; the agent uses the `agent-001` client cert
from the dev PKI and `agent_id=agent-001` (matching the cert CN).

## How to run

```bash
make up            # stack (Phase 0/1)
make agent-run     # build + launch the agent   (pwsh scripts/dev.ps1 agent-run on Windows)
docker compose logs -f agent
# trigger a FIM event:
docker compose exec agent sh -c 'echo x >> /watch/test.sh'
```

## Verification (actual run)

**Agent startup** — caps applied, all four collectors active:
```
agent starting   agent_id=agent-001 gomaxprocs=1 mem_limit_mb=128 ingest=https://ingest-edge:8443/v1/telemetry
collectors enabled   [sysinfo network osquery fim]
collected  collector=osquery samples=99
shipped    count=50 ... (mTLS batches to ingest-edge)
```

**Real osquery host-state landed in TimescaleDB:**
```
osquery_result os_version -> {"name":"Debian GNU/Linux","version":"12 (bookworm)","platform":"debian"}
```

**FIM caught a planted file** (`echo … > /watch/suspicious.sh`):
```
fim_event -> {"path":"/watch/suspicious.sh","change":"created","sha256":"9bb9299629e3…"}
```

**Agent-sourced docs in OpenSearch** (isolated by `labels.agent=go-mvp`): **452**
```
osquery_result 393 | system_info 43 | network_flow 15 | fim_event 1
```

**Resource footprint** (caps respected):
```
docker stats: CPU 0.10%  MEM 7.7 MiB / 256 MiB     agent self-RSS metric: 11.68 MB
```

## What's stubbed / deferred

- **eBPF** process/network observation — stub; needs a compiled BPF object, `CAP_BPF`/
  `CAP_PERFMON`, and a recent kernel (not available in the lab container). Enable with
  `ENABLE_EBPF=true` once implemented.
- **YARA** IOC scanning — stub; needs libyara (cgo) + a mounted rules bundle.
- **Event-driven FIM** (fanotify/auditd) — replaces polling later (D-015).
- **osquery via Thrift extension API** — currently shells out to `osqueryi` (D-016).
- **Signed command channel / active response** — that's Phase 6.
- **In a container, "host" = the container.** On a real host the agent runs as a host
  process (or with host `/proc`, `pid: host`, FIM over real host paths).

## Acceptance

✅ Go agent runs osquery and ships host-state · ✅ file-integrity monitoring · ✅ system +
network info · ✅ eBPF/YARA staged-in · ✅ resource caps · ✅ mTLS to ingest-edge ·
✅ `make agent-run` launches it against the local stack.

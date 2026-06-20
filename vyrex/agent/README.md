# agent

**Built in:** Phase 2 · **Language:** Go (zero external deps) · **Target:** Linux

A lightweight, resource-capped endpoint agent. It runs a set of **collectors** and
ships the results to `ingest-edge` over **mutual TLS** using the versioned telemetry
envelope every other layer speaks. Linux-first by design (reads `/proc`, runs osquery);
Windows parity is a later roadmap item.

## Collectors

| Collector | Kind(s) emitted | Source | Status |
|-----------|-----------------|--------|--------|
| `sysinfo` | `system_info` | `/proc/stat`, `/proc/meminfo`, `/proc/loadavg`, self RSS | ✅ |
| `network` | `network_flow` | `/proc/net/tcp` (listening + established) | ✅ |
| `osquery` | `osquery_result` | shells out to `osqueryi --json` (os_version, listening_ports, deb_packages, kernel_info, logged_in_users) | ✅ (degrades if osqueryi absent) |
| `fim` | `fim_event` | polling SHA-256 baseline over watched paths | ✅ |
| `ebpf` | `process_event`, `network_flow` | cilium/ebpf | 🟡 stage-in (off by default) |
| `yara` | (ioc) | libyara | 🟡 stage-in (off by default) |

## Architecture

```
collectors ──Sample──▶ scheduler ──Envelope──▶ shipper ──mTLS batch POST──▶ ingest-edge
 (per-interval)        (1 goroutine each)      (bounded buffer + retry)
```

- **`Collector` interface** (`collector.go`) — `Name/Interval/Collect`. Add a source =
  add a Collector; the scheduler/shipper don't change. eBPF/YARA are wired in as
  stage-in stubs to make the extension points concrete.
- **mTLS shipper** (`shipper.go`) — batches, flushes on size/time, retries with
  exponential backoff. A bounded channel gives the agent its own back-pressure.
- **Resource caps** (`main.go`) — `GOMAXPROCS` + `debug.SetMemoryLimit`, plus
  container `cpus`/`mem_limit`. Measured: ~8 MiB RSS, ~0.1% CPU.

## Run

```bash
make agent-run                 # build + launch against the local stack
pwsh scripts/dev.ps1 agent-run # Windows
docker compose logs -f agent   # watch it collect + ship
```

Trigger a FIM event:
```bash
docker compose exec agent sh -c 'echo x >> /watch/test.sh'   # next scan emits a fim_event
```

## Config (env)

Identity: `AGENT_ID`, `AGENT_HOST_ID`. Shipping: `INGEST_URL`, `INGEST_AGENT_TOKEN`,
`CA_CERT`, `CLIENT_CERT`, `CLIENT_KEY`, `AGENT_BATCH_SIZE`, `AGENT_FLUSH_SEC`.
Toggles: `ENABLE_SYSINFO|NETWORK|OSQUERY|FIM|EBPF|YARA`. Intervals:
`*_INTERVAL_SEC`. FIM: `FIM_PATHS`, `FIM_MAX_FILES`. Caps: `AGENT_MAX_PROCS`,
`AGENT_MEM_LIMIT_MB`.

See [../docs/DECISIONS.md](../docs/DECISIONS.md) D-015…D-017 for rationale (polling FIM,
osqueryi vs Thrift, dual-layer resource caps).

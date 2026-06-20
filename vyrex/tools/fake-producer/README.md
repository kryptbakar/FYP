# fake-producer

**Built in:** Phase 1 · **Language:** Python · **Replaced by:** the Go agent (Phase 2)

A stand-in for the real endpoint agent: generates telemetry envelopes across all
five `kind`s and POSTs them to `ingest-edge` over **mutual TLS** with a bearer
token — exactly the path a real agent uses. Used to exercise the whole ingestion
backbone and to load-test broker back-pressure.

## Run

```bash
# via the task runner (recommended)
make produce N=500                 # Linux/macOS
pwsh scripts/dev.ps1 produce -N 500  # Windows

# or directly
docker compose run --rm fake-producer --count 1000 --batch 50 --rate 0
```

`--rate 0` sends as fast as possible (good for back-pressure tests); `--rate 50`
throttles to 50 envelopes/sec. Prints `accepted/rejected` from ingest-edge.

## Config (env / flags)
`--url` (`INGEST_URL`), `--agent-id` (`AGENT_ID`), `--token` (`INGEST_AGENT_TOKEN`),
`--ca`/`--client-cert`/`--client-key` (mTLS material), `--count`, `--batch`, `--rate`.

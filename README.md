# VYREX

An **air-gapped Security Operations Center & vulnerability-intelligence platform** — explainable,
exploit-aware risk scoring, multi-tool fusion, and a **governed agentic AI analyst**, all running
fully on-premises with nothing leaving the building.

> Bachelor's final-year project (GIKI, BS Cyber Security) · proof-of-concept for an air-gapped /
> on-premises government deployment (PITB).

The project lives in **[`vyrex/`](vyrex/)**. Start there:
[project README](vyrex/README.md) · [documentation index](vyrex/docs/README.md) ·
[what it does](vyrex/docs/VYREX-PROJECT-REPORT.md).

## Quick start

```powershell
cd vyrex
pwsh scripts/dev.ps1 up            # core stack
pwsh scripts/dev.ps1 n8n-up        # automation engine + self-hosted LLM (optional)
```

- **Console** — http://localhost:3001  (`admin` / `vyrex`)
- **Grafana** — http://localhost:3000
- **API docs** — http://localhost:8000/docs

## Highlights

- Four-layer architecture: Go agent → mTLS ingest → JetStream → workers → Postgres / TimescaleDB /
  OpenSearch; FastAPI intelligence layer; dependency-free vanilla-JS console.
- Explainable risk: composite score + XGBoost re-ranker + **SHAP**, with multi-tool **consensus**.
- **Governed agentic AI** (self-hosted Ollama): triage + investigation agents that *propose*, never
  execute — containment stays behind two-person, Ed25519-signed approval + a hash-chained audit.
- **n8n** automation engine for the unattended analyst loop.

## License

Proprietary — see [LICENSE](LICENSE). Integrated open-source tools keep their own licenses
(see [ATTRIBUTIONS](vyrex/ATTRIBUTIONS.md)).

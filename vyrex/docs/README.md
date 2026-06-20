# VYREX — documentation index

Start with the [project README](../README.md). This folder holds the deeper docs.

## Overview & report
- [VYREX-PROJECT-REPORT.md](VYREX-PROJECT-REPORT.md) — what VYREX does, end to end, with an honest
  "real vs. demo" account (good for a viva / pitch / onboarding).

## Architecture & design
- [ARCHITECTURE.md](ARCHITECTURE.md) — the four layers, data flow, components.
- [CONSOLE.md](CONSOLE.md) — the dependency-free analyst console (design system, views).
- [../ml/FUSION.md](../ml/FUSION.md) — the AI Fusion Engine (dedup → consensus → SHAP).

## Security & operations
- [AIRGAP.md](AIRGAP.md) — air-gap enforcement, egress matrix, sneakernet refresh, verification.
- [../deploy/README.md](../deploy/README.md) — K3s / Helm / Vault / Keycloak / Velero deployment.

## Automation & AI
- [N8N-AUTOMATION.md](N8N-AUTOMATION.md) — the n8n automation engine: the closed loop, workflows,
  alert channel, email/chat fan-out.
- [AI-ANALYST.md](AI-ANALYST.md) — the air-gapped, governed **agentic AI analyst** (self-hosted
  Ollama): triage agent, investigation agent, and the native n8n AI Agent.
- [../deploy/n8n/workflows/README.md](../deploy/n8n/workflows/README.md) — the importable n8n workflows.

## Decision log & build history
- [DECISIONS.md](DECISIONS.md) — the running architecture-decision log (D-000…).
- [phases/](phases/) — per-phase build notes (Phase 0–8 + tool-integration A–H), kept as the
  historical record of how each part was built and verified.

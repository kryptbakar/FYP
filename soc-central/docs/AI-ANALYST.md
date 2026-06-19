# VYREX — the agentic AI analyst (air-gapped, governed)

VYREX runs a **self-hosted LLM** as an autonomous tier-1 analyst: it reasons over your
*already-explained* findings and proposes triage decisions — **entirely on-prem, nothing egresses**,
and it can **never** execute a destructive action. This is the rare combination cloud agentic-SOC
tools don't have: **agentic power with air-gapped trust.**

## Why this is different

Most "AI SOC agents" are a cloud LLM with API keys and broad authority — you trust someone else's
model with your security data, and the agent can act with little oversight. VYREX inverts that:

- **Sovereign** — the model (Ollama) runs in a container on your network; no key, no egress.
- **Grounded & explainable** — the agent reasons over findings that already carry a composite score,
  SHAP factors and multi-tool consensus, so its decisions cite real signal, not vibes.
- **Governed** — the agent can ESCALATE / MONITOR / DISMISS and *propose* containment, but VYREX's
  two-person, Ed25519-signed approval gate still stands. The agent never contains anything itself.
- **Auditable** — every run (model, summary, per-finding decision + reasoning) is recorded.

## Run it

```powershell
pwsh scripts/dev.ps1 n8n-up                                  # brings up ollama (+ n8n, mailpit)
docker exec soc-central-ollama ollama pull llama3.2:3b       # one-time model download (~2 GB)
```

Then open the console → **Operate → AI Analyst** → **Run AI triage**. The agent pulls the top open
findings, reasons, and returns a per-finding decision table with its reasoning + a shift summary;
escalations are recorded as governed notifications. `OLLAMA_MODEL` (default `llama3.2:3b`) and
`OLLAMA_URL` are configurable; any tool-capable Ollama model works (e.g. `qwen2.5:3b`, `llama3.1:8b`).

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/agent/status` | LLM reachability + whether the model is pulled |
| POST | `/agent/triage` `{limit}` | run the agent over the top open findings → decisions + reasoning |
| GET | `/agent/runs` | recent run history |

The `07-ai-analyst-triage.json` n8n workflow schedules `POST /agent/triage` every 30 min and
dispatches the agent's escalations — unattended agentic triage.

## Two ways to wire the agent into n8n

1. **VYREX-hosted agent (shipped, robust):** n8n simply calls `POST /agent/triage`. The reasoning
   loop + governance live in VYREX, so it's deterministic to operate and easy to audit. This is the
   `07-ai-analyst-triage.json` workflow.
2. **Native n8n AI Agent node (advanced):** build an **AI Agent** node in n8n with an **Ollama Chat
   Model** sub-node (Base URL `http://ollama:11434`, model `llama3.2:3b`) and add **HTTP Request
   Tool** sub-nodes wrapping VYREX endpoints (`/risk/ranking`, `/findings/{id}/explain`,
   `/incidents/correlate`, `/alerts/dispatch`) as the agent's tools. The agent then plans and calls
   those tools itself (ReAct). Create the Ollama credential once in n8n → Credentials → Ollama. This
   is the more "agentic" surface; VYREX's approval gate still governs any containment.

## Roadmap (the agentic SOC, staged)

- **Investigation agent** — given an incident, the agent uses tools to pivot across findings → assets
  → IOCs → logs and assembles a timeline + ATT&CK kill-chain, citing evidence.
- **Local RAG** — ground answers in VYREX's own data + the offline knowledge base (no cloud knowledge).
- **Natural-language SOC** — ⌘K → ask the agent; it queries VYREX and answers with citations.
- **Closes the learning loop** — agent decisions become labelled feedback for the XGBoost re-ranker.

## Safety

The agent is **proposal-only** by construction: it writes decisions and escalations, never executes
containment. Destructive actions remain behind two-person approval + Ed25519 signing + the
hash-chained audit. If the model is offline, every agent endpoint degrades gracefully (the console
shows "LLM offline" and how to pull the model) — VYREX keeps working without it.

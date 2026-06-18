# VYREX × n8n — importable workflows

Three ready-to-import n8n workflows that turn VYREX into an **automated SOC analyst**. They call
only the internal VYREX API via the `VYREX_API` env var (`http://api:8000`, set by the compose
overlay) — nothing egresses.

| File | Trigger | What it automates |
|---|---|---|
| `01-auto-triage-loop.json` | schedule, every 15 min | Pull the ranked queue → correlate high-risk findings into incidents → route alerts. The unattended tier-1 loop. |
| `02-critical-responder.json` | webhook `POST /webhook/vyrex` (fired *by* VYREX) | On a High/Critical hand-off from a VYREX playbook, call back into VYREX to correlate + dispatch, then answer. Closes the detection→response loop. |
| `03-daily-posture-report.json` | schedule, daily 08:00 | Generate a posture report and notify channels. Unattended executive reporting. |

## Import

1. `pwsh scripts/dev.ps1 n8n-up` (or `docker compose -f docker-compose.yml -f docker-compose.n8n.yml up -d n8n`).
2. Open **http://localhost:5678**, create the local owner account.
3. **Workflows → Import from File** → pick each JSON from this folder (also mounted read-only at
   `/workflows` inside the container).
4. Open each workflow and click **Active** (top-right). For `02-critical-responder`, activating it
   registers the production webhook at `http://n8n:5678/webhook/vyrex` — which is exactly the URL the
   VYREX **"Hand off to n8n automation"** playbook posts to (`N8N_WEBHOOK_URL`).

## The closed loop

```
VYREX detects ─▶ "Hand off to n8n" playbook ─▶ POST /webhook/vyrex ─▶ n8n (02)
                                                                         │
        ┌────────────────────────────────────────────────────────────────┘
        ▼
   n8n calls back into the VYREX API:  /incidents/correlate · /alerts/dispatch · /reports
        ▲
        └── and independently, on a timer (01, 03), n8n drives the same API unattended.
```

## Endpoints the workflows use (all open on the internal network)

- `GET  /risk/ranking?limit=50` — the ranked decision queue
- `POST /incidents/correlate` — group high-risk findings into incidents
- `POST /alerts/dispatch` — route notifications to channels
- `POST /reports` `{ "type": "posture" }` — generate a report

> Air-gap note: these run entirely on the internal compose network. For a true air-gapped
> deployment, move the `n8n` service onto `socnet` (the `internal: true` network in
> `docker-compose.airgap.yml`) so it has no host route at all.

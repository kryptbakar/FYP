# VYREX × n8n — the automated SOC analyst

VYREX integrates a **self-hosted [n8n](https://n8n.io)** as its automation engine, turning the
platform into an *automated SOC analyst*: VYREX detects and explains, n8n orchestrates the
response, and n8n calls back into VYREX to act — a closed loop that runs unattended, **with nothing
leaving the building**.

This is a real integration, not a mock: VYREX already POSTs to webhooks over `httpx`
([`alerts.py`](../services/api/app/routers/alerts.py), [`playbooks.py`](../services/api/app/routers/playbooks.py)),
the API is reachable on the internal network, and n8n is a first-class container in a compose overlay.

---

## Why n8n (and why self-hosted)

- VYREX's value is detection, explainable scoring, and auditable response. **Orchestration** —
  "when X, do Y, then Z, on a schedule, with branching and retries" — is exactly what n8n is for.
  Re-implementing a full workflow engine inside VYREX would be wasted effort.
- **Self-hosted only.** n8n runs as a container on the same internal network as the VYREX API.
  All telemetry / version-checks / template fetches are disabled in the compose env, so the
  **air-gap guarantee holds**. Cloud n8n.io is explicitly *not* used — that would break the air gap,
  which is the product's whole reason to exist.

## Two directions, one loop

```
                    ┌──────────────────────── VYREX ────────────────────────┐
   detection  ─────▶│  findings → fusion → explainable score → playbooks     │
                    └───────┬───────────────────────────────▲────────────────┘
       "Hand off to n8n"    │ POST /webhook/vyrex            │ REST API (open on internal net)
        playbook step       ▼                                │ /incidents/correlate
                    ┌──────────────── n8n ───────────────────┤ /alerts/dispatch
                    │  workflows: triage · respond · report  ─┘ /reports · /risk/ranking
                    └────────────────────────────────────────┘
```

**1 · VYREX → n8n (trigger).** A playbook can include a `webhook` step. The seeded
**"Hand off to n8n automation"** playbook (`pb-n8n-automation`) opens a case and then POSTs the
finding to n8n's webhook (`N8N_WEBHOOK_URL`, default `http://n8n:5678/webhook/vyrex`). Any alert
channel of type `webhook` can also point at an n8n webhook node.

**2 · n8n → VYREX (act).** n8n workflows call the VYREX REST API (open on the internal network, no
token needed) to do the analyst's job: correlate findings into incidents, dispatch alerts, generate
reports, pull the ranked queue, propose containment.

## Run it

```powershell
pwsh scripts/dev.ps1 up          # the VYREX stack
pwsh scripts/dev.ps1 n8n-up      # the n8n automation engine (compose overlay)
```

Then:

1. Open **http://localhost:5678** and create the local owner account (stored in the `n8ndata` volume).
2. **Workflows → Import from File** → import the three workflows from
   [`deploy/n8n/workflows/`](../deploy/n8n/workflows/) (also mounted at `/workflows` in the container).
3. Open each and toggle **Active**. Activating `02-critical-responder` registers the webhook at
   `http://n8n:5678/webhook/vyrex` — the exact URL the VYREX playbook posts to.
4. In the VYREX console → **Playbooks**, run **"Hand off to n8n automation"** on a finding, or just
   wait 15 min for the auto-triage loop. Watch the run land in n8n's **Executions**.

`pwsh scripts/dev.ps1 n8n-down` stops it; the workflows persist in the `n8ndata` volume.

## What the bundled workflows do

| Workflow | Trigger | Automates |
|---|---|---|
| Auto-triage loop | every 15 min | pull ranking → correlate → dispatch alerts |
| Critical responder | webhook from VYREX | branch on severity → correlate → dispatch → respond |
| Daily posture report | daily 08:00 | generate posture report → notify |

See [`deploy/n8n/workflows/README.md`](../deploy/n8n/workflows/README.md) for node-level detail.

## API surface n8n uses

All open on the internal network (the console reaches them the same way via the nginx `/api` proxy):

| Method | Path | Purpose |
|---|---|---|
| GET | `/risk/ranking?limit=N` | ranked decision queue |
| GET | `/findings/{id}/explain` | SHAP explanation for decisioning |
| POST | `/incidents/correlate` | group high-risk findings into incidents |
| POST | `/alerts/dispatch` | route notifications to channels |
| POST | `/reports` `{type}` | generate posture / compliance / executive report |
| POST | `/incidents/{id}/actions` | propose containment (still two-person-approved in VYREX) |

## Email fan-out (self-hosted, air-gap-safe)

The **Alert intake** workflow (`04-alert-intake.json`) emails every routed alert to the SOC team via
a **self-hosted [Mailpit](https://mailpit.axllent.org/)** SMTP sink that comes up with `n8n-up`:

- **Mailpit UI:** http://localhost:8025 — every message n8n sends lands here (nothing leaves the box).
- The email node *continues on error*, so the loop still works before the credential exists.

**One-time setup** (n8n can't auto-create credentials — they're encrypted in its store): in n8n →
**Credentials → New → SMTP**, name it exactly **`Mailpit SMTP`**, host **`mailpit`**, port **`1025`**,
SSL/TLS **off**, no user/pass. Save. From then on, every alert routed to n8n is emailed and visible in
Mailpit. (Swap Mailpit for a real internal mail relay or a Mattermost incoming-webhook node to fan out
to chat — same pattern, still on-prem.)

> Verified the sink works end-to-end (`smtplib → mailpit:1025` → message visible via Mailpit's API);
> the n8n email node uses it once the `Mailpit SMTP` credential above is created.

**Chat fan-out (optional).** The alert-intake workflow also has a **"Post to chat"** node that POSTs a
Mattermost/Slack/Rocket.Chat-compatible payload (`{username, text}`) to `CHAT_WEBHOOK_URL`. Set that
env (in `.env`) to a **self-hosted** chat server's *incoming webhook* URL and every routed alert lands
in your channel — still on-prem, no credential needed (incoming webhooks are URL-authed). Left blank,
the node continues on error and does nothing.

## Live execution status in the console

The console's **Operate → Automation** view shows reachability, the workflow catalogue, and the
alerts/hand-offs VYREX sent to n8n — with no key. To also show **live n8n execution status**, create an
API key in **n8n → Settings → n8n API**, put it in `.env` as `N8N_API_KEY=…`, and restart the api
(`docker compose up -d api`). The view then adds an *n8n executions* table pulled from n8n's own API.

## Safety & air-gap notes

- **Containment stays human-gated.** n8n can *propose* a containment action, but VYREX still
  enforces two-person approval + Ed25519 signing before anything executes — automation never bypasses
  the destructive-action gate. That boundary is deliberate and defensible.
- **No egress.** n8n's diagnostics, version notifications, template gallery and personalisation are
  all disabled in [`docker-compose.n8n.yml`](../docker-compose.n8n.yml). For a hardened deployment,
  put `n8n` on the `internal: true` `socnet` network from `docker-compose.airgap.yml`.
- **Config.** `N8N_WEBHOOK_URL` (VYREX side) and `VYREX_API` (n8n side) are the only two wiring knobs.

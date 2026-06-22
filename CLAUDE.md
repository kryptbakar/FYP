# VYREX — repository guide for Claude Code agents

> **VYREX** is an air-gapped Security Operations Center & vulnerability-intelligence
> platform (GIKI BS Cyber Security final-year project). The project lives in [`vyrex/`](vyrex/).

## ⚠️ Commit attribution — MANDATORY

Every commit in this repository **MUST** be authored **and** committed as:

```
kryptbakar <abubakaramir437@gmail.com>
```

Before committing, ensure the identity is set (do this in every environment, including
cloud/CI agents — the default `Claude <noreply@anthropic.com>` identity is **not allowed**):

```bash
git config user.name  "kryptbakar"
git config user.email "abubakaramir437@gmail.com"
```

- Do **NOT** add a `Co-Authored-By: Claude` (or any co-author) trailer to commit messages.
- Do **NOT** commit as `Claude`, `spartantech`, `hamzasafwan2004@gmail.com`, or any other
  identity. The repo owner wants every commit to show solely as their GitHub account.
- If you are an agent whose environment forces a different identity, pass it explicitly:
  `git -c user.name=kryptbakar -c user.email=abubakaramir437@gmail.com commit ...`.

## Never commit these (kept local / not deliverables)

- `SOC-Central-ClaudeCode-Prompt.md`, `SOC-Central-Tool-Integration-Prompt-2.md`,
  `claude-code-prompt-soc-central-console.md` (build briefs at the repo root)
- `ARIS-Security-Dashboard-main/`, `reference/`, `.k8sbin/` (study-only clones / local CLIs)

## Working in the console (`vyrex/web/console/`)

Dependency-free vanilla-JS SPA served by nginx (baked into the image). After editing
`assets/*.js|css` or `index.html`, **bump the `?v=N` cache-bust query** in `index.html`
and rebuild the container so changes are served:

```bash
cd vyrex
docker compose -f docker-compose.yml -f docker-compose.n8n.yml up -d --build console
```

## Refreshing LIVE demo data (3 steps, not 1)

Varied LIVE findings require, in order: `scan-ingest` (parse trivy/nuclei fixtures) →
`risk-engine score` (fill the composite `risk_score`); `assess` only covers the
package-matched system/compliance findings. Enrichment **fixtures are baked into the
image** — rebuild `enrichment` before `--scan` after editing them.

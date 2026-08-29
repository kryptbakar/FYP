"""Application configuration, loaded from environment variables.

Twelve-factor style: all config comes from the environment (see ../../.env.example).
Nothing here is secret-bearing by default; real secrets are injected at runtime.
"""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # General
    soc_env: str = "development"
    soc_version: str = "1.0.0"

    # API
    api_log_level: str = "info"
    # Authentication enforcement. Off by default so the local demo/dev stack stays
    # frictionless; ALWAYS on when soc_env=production (see `auth_required`). When on,
    # every non-public route requires a principal (oauth2-proxy header OR a local
    # session token) and RBAC gates writes/response. See THREAT-MODEL.md TB2.
    api_auth_required: bool = False
    # Console origins allowed for direct (non-proxied) browser calls. Comma-separated,
    # or "*" for any. In the normal topology the console is same-origin via nginx /api.
    cors_allow_origins_raw: str = "*"

    # PostgreSQL (transactional)
    postgres_host: str = "postgres"
    postgres_port: int = 5432
    postgres_db: str = "soc_central"
    postgres_user: str = "soc"
    postgres_password: str = "soc"

    # OpenSearch (search). Used only for the readiness probe in Phase 0.
    opensearch_host: str = "opensearch"
    opensearch_port: int = 9200
    opensearch_scheme: str = "http"

    # NATS JetStream (broker). Readiness probe does a TCP connect in Phase 0.
    nats_host: str = "nats"
    nats_port: int = 4222

    # Automation: default n8n webhook a playbook "webhook" step POSTs to (self-hosted, internal).
    n8n_webhook_url: str = "http://n8n:5678/webhook/vyrex"
    n8n_base_url: str = "http://n8n:5678"
    n8n_api_key: str = ""   # optional: enables live execution status in the Automation view

    # Self-hosted LLM (air-gapped) for the agentic AI-analyst loop.
    ollama_url: str = "http://ollama:11434"
    ollama_model: str = "llama3.2:3b"
    # Generation timeouts, in seconds. These were hardcoded literals in agent.py, which
    # made them undiscoverable and impossible to tune per deployment - and they are the
    # numbers most likely to need tuning, because CPU-only inference varies by an order of
    # magnitude with model size (measured: 3B ~45-110 s, qwen3:4b did not finish in 900 s;
    # docs/AGENT-ORCHESTRATION.md §7). Investigate gets longer than triage because it
    # reasons over a whole incident rather than one finding.
    ollama_triage_timeout_s: int = 180
    ollama_investigate_timeout_s: int = 240
    # Health probe only - must stay short so /agent/status cannot hang the console.
    ollama_probe_timeout_s: int = 4

    # Admission control for POST /investigations (app/ratelimit.py). The endpoint answers
    # in milliseconds but commits ~2 minutes of serial inference, so the cost is invisible
    # at the edge and one loop over the finding list buys hours of queue.
    investigation_rate_limit: int = 10        # accepted new requests per requester...
    investigation_rate_window_s: int = 60     # ...per this window; 0 disables
    investigation_max_queue: int = 25         # refuse when the outbox is this deep; 0 disables

    # Password for the least-privilege `vyrex_orchestrator` DB role (schema.py). Blank
    # keeps the orchestrator on the shared `soc` superuser, which is how it shipped before
    # 2026-08-28 - set it in .env and the role is created and enforced at API startup.
    orch_db_password: str = ""

    # Active response (Phase 6): shared agent token + Ed25519 command-signing key path.
    ingest_agent_token: str = ""
    command_signing_key: str = "/keys/command_signing.key"
    two_person_min: int = 2  # distinct approvers required for a destructive action

    @property
    def auth_required(self) -> bool:
        """Enforced whenever explicitly enabled OR the deployment is production.
        Production must never run unauthenticated, regardless of the flag."""
        return self.api_auth_required or self.soc_env.lower() == "production"

    @property
    def cors_allow_origins(self) -> list[str]:
        raw = self.cors_allow_origins_raw.strip()
        if raw == "*" or not raw:
            return ["*"]
        return [o.strip() for o in raw.split(",") if o.strip()]

    @property
    def postgres_dsn(self) -> str:
        return (
            f"host={self.postgres_host} port={self.postgres_port} "
            f"dbname={self.postgres_db} user={self.postgres_user} "
            f"password={self.postgres_password}"
        )

    @property
    def opensearch_url(self) -> str:
        return f"{self.opensearch_scheme}://{self.opensearch_host}:{self.opensearch_port}"


settings = Settings()

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
    soc_version: str = "0.0.0-phase0"

    # API
    api_log_level: str = "info"
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

    # Active response (Phase 6): shared agent token + Ed25519 command-signing key path.
    ingest_agent_token: str = ""
    command_signing_key: str = "/keys/command_signing.key"
    two_person_min: int = 2  # distinct approvers required for a destructive action

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

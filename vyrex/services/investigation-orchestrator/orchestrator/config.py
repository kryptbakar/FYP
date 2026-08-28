"""Orchestrator configuration.

Same env-var conventions as the other services (see services/enrichment/main.py and
ml/run.py): POSTGRES_* with PORT_INTERNAL for the in-container port. Nothing here has a
production-unsafe default that fails silently — the DSN falls back to the compose values,
and the LLM is optional (the graph degrades to an abstained report without it).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

# Bumped when the graph's SHAPE changes (nodes added/removed/rewired), so a stored
# investigation can always be read back against the topology that produced it.
GRAPH_VERSION = "0.1.0"
PROMPT_VERSION = "0.1.0"


def _env(k: str, d: str = "") -> str:
    return os.getenv(k, d)


def _int(k: str, d: int) -> int:
    try:
        return int(os.getenv(k, str(d)))
    except ValueError:
        return d


@dataclass(frozen=True)
class Settings:
    postgres_dsn: str = field(default_factory=lambda: (
        f"host={_env('POSTGRES_HOST', 'postgres')} "
        f"port={_env('POSTGRES_PORT_INTERNAL', '5432')} "
        f"dbname={_env('POSTGRES_DB', 'soc_central')} "
        f"user={_env('POSTGRES_USER', 'soc')} "
        f"password={_env('POSTGRES_PASSWORD', 'soc')}"
    ))
    ollama_url: str = field(default_factory=lambda: _env("OLLAMA_URL", "http://ollama:11434"))
    ollama_model: str = field(default_factory=lambda: _env("OLLAMA_MODEL", "llama3.2:3b"))

    # Generous, because CPU-only inference on this hardware measured 98s for three
    # findings — and the whole point of the async job API is that nothing is waiting
    # on a socket for this.
    llm_timeout_s: int = field(default_factory=lambda: _int("ORCH_LLM_TIMEOUT_S", 240))
    # A node that hangs must not hold the single worker forever.
    node_timeout_s: int = field(default_factory=lambda: _int("ORCH_NODE_TIMEOUT_S", 300))
    poll_interval_s: int = field(default_factory=lambda: _int("ORCH_POLL_INTERVAL_S", 5))
    # Serial by default: 5.8 GiB of RAM for the whole Docker VM, and two concurrent
    # 3B-model generations is how the box starts swapping.
    concurrency: int = field(default_factory=lambda: _int("ORCH_CONCURRENCY", 1))
    # After this many delivery attempts an outbox row is parked as 'failed' rather than
    # retried forever — the repo has no dead-letter path anywhere else, and a poison
    # message that never stops retrying is worse than one that stops loudly.
    max_attempts: int = field(default_factory=lambda: _int("ORCH_MAX_ATTEMPTS", 3))
    # Set true in CI: swaps the Ollama client for a deterministic stub so the graph is
    # testable without a model.
    fake_llm: bool = field(default_factory=lambda: _env("ORCH_FAKE_LLM", "false").lower() == "true")

    graph_version: str = GRAPH_VERSION
    prompt_version: str = PROMPT_VERSION


settings = Settings()

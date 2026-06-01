"""SOC Central API — application entrypoint.

Phase 0 scope: a thin, observable FastAPI skeleton that proves the platform
stack is wired together (liveness, readiness against the data stores, version).
The ~30 domain endpoints (assets, findings, incidents, compliance, scoring,
feedback) are layered on in later phases.
"""
from __future__ import annotations

from fastapi import FastAPI

from .config import settings
from .routers import health

app = FastAPI(
    title="SOC Central API",
    version=settings.soc_version,
    summary="Centralized SOC & vulnerability-intelligence backend",
    docs_url="/docs",
    openapi_url="/openapi.json",
)

app.include_router(health.router)


@app.get("/", tags=["system"], summary="Service banner")
async def root() -> dict:
    return {
        "service": "soc-central-api",
        "version": settings.soc_version,
        "docs": "/docs",
        "health": "/health",
        "ready": "/health/ready",
    }

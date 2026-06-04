"""SOC Central API — application entrypoint.

Phase 0 scope: a thin, observable FastAPI skeleton that proves the platform
stack is wired together (liveness, readiness against the data stores, version).
The ~30 domain endpoints (assets, findings, incidents, compliance, scoring,
feedback) are layered on in later phases.
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import access_audit, metrics, schema
from .config import settings
from .routers import (
    compliance,
    findings,
    health,
    identity,
    incidents,
    insights,
    notifications,
    response,
    risk,
)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    schema.ensure_schema()  # incident/response tables (idempotent)
    yield


app = FastAPI(
    title="SOC Central API",
    version=settings.soc_version,
    summary="Centralized SOC & vulnerability-intelligence backend",
    docs_url="/docs",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# The console is served same-origin via the nginx /api proxy, so CORS isn't needed in
# the normal topology. We still allow it (configurable) so the API can be hit directly
# from a dev console on another port or from Swagger during development.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allow_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Observability + governance middlewares (outermost runs first).
app.middleware("http")(metrics.metrics_middleware)
app.middleware("http")(access_audit.access_audit_middleware)

app.include_router(health.router)
app.include_router(findings.router)
app.include_router(compliance.router)
app.include_router(risk.router)
app.include_router(incidents.router)
app.include_router(response.router)
app.include_router(insights.router)
app.include_router(identity.router)
app.include_router(notifications.router)


@app.get("/metrics", tags=["system"], summary="Prometheus metrics")
async def prometheus_metrics():
    return metrics.metrics_endpoint()


@app.get("/", tags=["system"], summary="Service banner")
async def root() -> dict:
    return {
        "service": "soc-central-api",
        "version": settings.soc_version,
        "docs": "/docs",
        "health": "/health",
        "ready": "/health/ready",
    }

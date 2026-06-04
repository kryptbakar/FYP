"""Prometheus instrumentation for the API.

Exposes request counts and latency at /metrics so Prometheus can scrape the API and
Grafana can chart it. Labels use the matched *route template* (not the raw path) to keep
cardinality bounded — `/findings/{finding_id}` is one series, not one per id.
"""
from __future__ import annotations

import time

from fastapi import Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

REQUESTS = Counter(
    "soc_http_requests_total", "Total HTTP requests",
    ["method", "path", "status"],
)
LATENCY = Histogram(
    "soc_http_request_duration_seconds", "HTTP request latency (seconds)",
    ["method", "path"],
)


async def metrics_middleware(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    route = request.scope.get("route")
    path = getattr(route, "path", request.url.path)
    if path == "/metrics":
        return response  # don't measure the scrape itself
    elapsed = time.perf_counter() - start
    REQUESTS.labels(request.method, path, str(response.status_code)).inc()
    LATENCY.labels(request.method, path).observe(elapsed)
    return response


def metrics_endpoint() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

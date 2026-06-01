"""Tiny async Postgres helper for read endpoints.

Per-request connections keep Phase 3 simple; a pooled connection (psycopg_pool)
is a later optimisation. Queries against tables that don't exist yet (enrichment
hasn't run) return empty rather than 500, so the API is usable from a cold start.
"""
from __future__ import annotations

import logging

import psycopg
from psycopg.rows import dict_row

from .config import settings

log = logging.getLogger("api.db")


async def fetch(query: str, params: tuple | dict = ()) -> list[dict]:
    try:
        async with await psycopg.AsyncConnection.connect(
            settings.postgres_dsn, row_factory=dict_row
        ) as conn:
            async with conn.cursor() as cur:
                await cur.execute(query, params)
                return await cur.fetchall()
    except psycopg.errors.UndefinedTable:
        return []  # enrichment hasn't created the table yet


async def fetch_one(query: str, params: tuple | dict = ()) -> dict | None:
    rows = await fetch(query, params)
    return rows[0] if rows else None

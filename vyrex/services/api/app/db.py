"""Tiny async Postgres helper for read endpoints.

Per-request connections keep Phase 3 simple; a pooled connection (psycopg_pool)
is a later optimisation. Queries against tables that don't exist yet (enrichment
hasn't run) return empty rather than 500, so the API is usable from a cold start.

`fetch`/`execute` each open their own connection and `execute` is autocommit, so
two of them can never be atomic. When several writes must land together — most
importantly a state change plus the outbox row that announces it — use
`transaction()` with `tx_fetch`/`tx_execute`.
"""
from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

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
    except (psycopg.errors.UndefinedTable, psycopg.errors.UndefinedColumn):
        return []  # enrichment / risk-engine hasn't created the table/column yet


async def fetch_one(query: str, params: tuple | dict = ()) -> dict | None:
    rows = await fetch(query, params)
    return rows[0] if rows else None


async def execute(query: str, params: tuple | dict = ()) -> dict | None:
    """Run a single autocommitting write; returns the RETURNING row if any.

    One statement, one transaction. For multi-statement atomicity use `transaction()`.
    """
    async with await psycopg.AsyncConnection.connect(
        settings.postgres_dsn, row_factory=dict_row, autocommit=True
    ) as conn:
        async with conn.cursor() as cur:
            await cur.execute(query, params)
            if cur.description:
                return await cur.fetchone()
    return None


@asynccontextmanager
async def transaction() -> AsyncIterator[psycopg.AsyncConnection]:
    """One connection, one transaction: everything inside commits or rolls back together.

    This is what makes the transactional outbox possible. An outbox row must never be
    visible unless the state change that justified it also committed — otherwise a crash
    between two autocommitting `execute()` calls either publishes an event for work that
    was rolled back, or silently drops an event for work that landed.

    Usage:
        async with db.transaction() as conn:
            row = await db.tx_execute(conn, "UPDATE ... RETURNING id", p)
            await db.tx_execute(conn, "INSERT INTO investigation_outbox ...", q)
        # both committed here, or neither

    Note psycopg3 connections are NOT autocommit by default, so the `conn.transaction()`
    block is an explicit BEGIN/COMMIT rather than a no-op; raising inside the block rolls
    back and re-raises.
    """
    async with await psycopg.AsyncConnection.connect(
        settings.postgres_dsn, row_factory=dict_row
    ) as conn:
        async with conn.transaction():
            yield conn


async def tx_fetch(
    conn: psycopg.AsyncConnection, query: str, params: tuple | dict = ()
) -> list[dict]:
    """Read inside an open transaction.

    Unlike `fetch`, a missing table is NOT swallowed: in Postgres any error aborts the
    surrounding transaction, so returning [] would hand back a half-dead connection whose
    later statements all fail with `InFailedSqlTransaction`. Let it propagate and roll back.
    """
    async with conn.cursor() as cur:
        await cur.execute(query, params)
        return await cur.fetchall()


async def tx_execute(
    conn: psycopg.AsyncConnection, query: str, params: tuple | dict = ()
) -> dict | None:
    """Write inside an open transaction; returns the RETURNING row if any."""
    async with conn.cursor() as cur:
        await cur.execute(query, params)
        if cur.description:
            return await cur.fetchone()
    return None

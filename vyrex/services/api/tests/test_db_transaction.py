"""Atomicity guarantees of db.transaction() — the basis of the transactional outbox.

An outbox row must never be visible unless the state change that justified it also
committed. `db.execute()` cannot give that: it is autocommit and opens its own
connection per call, so two calls are two transactions.

Needs a live Postgres, which the unit-test image does not have — these skip cleanly
there and run under `make test` / compose-smoke where the DB is up. Uses asyncio.run()
rather than pytest-asyncio, matching test_identity.py (no new test deps).
"""
from __future__ import annotations

import asyncio
import uuid

import psycopg
import pytest

from app import db
from app.config import settings

TBL = f"_tx_test_{uuid.uuid4().hex[:8]}"


def _db_available() -> bool:
    """Probe with an explicit connect_timeout.

    This runs at import time, so an unreachable host must fail fast — the libpq default
    would otherwise stall collection for tens of seconds in the DB-less unit CI job.
    """

    async def probe() -> bool:
        async with await psycopg.AsyncConnection.connect(
            f"{settings.postgres_dsn} connect_timeout=2"
        ) as conn:
            async with conn.cursor() as cur:
                await cur.execute("SELECT 1")
        return True

    try:
        return asyncio.run(probe())
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _db_available(), reason="no Postgres available")


@pytest.fixture()
def table():
    asyncio.run(db.execute(f"CREATE TABLE IF NOT EXISTS {TBL} (id int PRIMARY KEY, note text)"))
    asyncio.run(db.execute(f"TRUNCATE {TBL}"))
    yield TBL
    asyncio.run(db.execute(f"DROP TABLE IF EXISTS {TBL}"))


def _ids(tbl: str) -> list[int]:
    return [r["id"] for r in asyncio.run(db.fetch(f"SELECT id FROM {tbl} ORDER BY id"))]


def test_commits_all_writes_together(table):
    async def go():
        async with db.transaction() as conn:
            await db.tx_execute(conn, f"INSERT INTO {table} VALUES (1,'state-change')")
            await db.tx_execute(conn, f"INSERT INTO {table} VALUES (2,'outbox-row')")

    asyncio.run(go())
    assert _ids(table) == [1, 2]


def test_exception_rolls_back_the_whole_unit(table):
    """The outbox's core requirement: no event survives a rolled-back state change."""

    async def go():
        async with db.transaction() as conn:
            await db.tx_execute(conn, f"INSERT INTO {table} VALUES (3,'state-change')")
            raise RuntimeError("crash before the outbox insert")

    with pytest.raises(RuntimeError):
        asyncio.run(go())
    assert _ids(table) == []


def test_constraint_violation_rolls_back_earlier_writes(table):
    async def go():
        async with db.transaction() as conn:
            await db.tx_execute(conn, f"INSERT INTO {table} VALUES (1,'ok')")
            await db.tx_execute(conn, f"INSERT INTO {table} VALUES (1,'duplicate pk')")

    with pytest.raises(Exception):
        asyncio.run(go())
    assert _ids(table) == []


def test_tx_execute_returns_returning_row(table):
    """The outbox insert needs the id/uid the statement produced."""

    async def go():
        async with db.transaction() as conn:
            return await db.tx_execute(
                conn, f"INSERT INTO {table} VALUES (9,'x') RETURNING id, note"
            )

    row = asyncio.run(go())
    assert row["id"] == 9 and row["note"] == "x"


def test_execute_is_not_atomic_across_calls(table):
    """Contrast case documenting why transaction() had to exist."""
    asyncio.run(db.execute(f"INSERT INTO {table} VALUES (10,'first')"))
    with pytest.raises(Exception):
        asyncio.run(db.execute(f"INSERT INTO {table} VALUES (10,'dup')"))
    assert _ids(table) == [10]  # the first write survived the second's failure

"""Investigation job API — the contract the console and the orchestrator both rely on.

Endpoints are async coroutines called directly (no TestClient), matching
test_identity.py. They touch Postgres, so they skip cleanly in the DB-less unit CI job
exactly like test_db_transaction.py.

The behaviours asserted here are the ones that are expensive to get wrong:
  * a duplicate request must NOT start a second run
  * "no report yet" must be distinguishable from "no such investigation"
  * the investigation row and its outbox row must appear together or not at all
"""
from __future__ import annotations

import asyncio
import uuid

import psycopg
import pytest
from fastapi import HTTPException, Response

from app import db
from app.config import settings
from app.routers.investigations import (
    InvestigationIn,
    ReviewIn,
    cancel,
    create_investigation,
    get_investigation,
    get_report,
    list_investigations,
    orchestrator_status,
    review,
)


def _db_available() -> bool:
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


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture()
def finding_id() -> int:
    """A real finding to investigate — creation validates the subject exists."""
    row = _run(db.fetch_one("SELECT id FROM findings ORDER BY id LIMIT 1"))
    if not row:
        pytest.skip("no findings in the database to investigate")
    return row["id"]


@pytest.fixture()
def cleanup():
    """Remove whatever the test created. Children cascade from investigations."""
    created: list[str] = []
    yield created
    for inv in created:
        _run(db.execute("DELETE FROM investigation_outbox WHERE event_key LIKE %s", (f"%{inv}%",)))
        _run(db.execute("DELETE FROM investigations WHERE investigation_id=%s", (inv,)))


def _create(finding_id: int, cleanup: list) -> tuple[dict, Response]:
    resp = Response()
    out = _run(create_investigation(
        InvestigationIn(subject_type="finding", subject_id=finding_id), resp, "pytest"))
    if out.get("investigation_id") not in cleanup:
        cleanup.append(out["investigation_id"])
    return out, resp


def test_create_returns_queued_investigation(finding_id, cleanup):
    out, resp = _create(finding_id, cleanup)
    assert out["status"] == "queued"
    assert uuid.UUID(out["investigation_id"])          # a real uuid, not a counter
    assert not out.get("existing")


def test_duplicate_request_returns_the_run_already_in_flight(finding_id, cleanup):
    """The whole point of the one-active index: asking twice must not queue twice."""
    first, _ = _create(finding_id, cleanup)
    second, resp = _create(finding_id, cleanup)
    assert second["investigation_id"] == first["investigation_id"]
    assert second["existing"] is True
    assert resp.status_code == 200                     # 200, not a second 202

    rows = _run(db.fetch(
        "SELECT count(*) AS n FROM investigations WHERE subject_id=%s AND status='queued'",
        (finding_id,)))
    assert rows[0]["n"] == 1


def test_creation_writes_the_outbox_row_atomically(finding_id, cleanup):
    """An orchestrator must never see a request whose investigation row didn't commit."""
    out, _ = _create(finding_id, cleanup)
    rows = _run(db.fetch(
        "SELECT status, trigger_type FROM investigation_outbox WHERE event_key LIKE %s",
        (f"%{out['investigation_id']}%",)))
    assert len(rows) == 1
    assert rows[0]["status"] == "pending"
    assert rows[0]["trigger_type"] == "manual"


def test_unknown_subject_is_rejected(cleanup):
    with pytest.raises(HTTPException) as e:
        _run(create_investigation(
            InvestigationIn(subject_type="finding", subject_id=999_999_999), Response(), "pytest"))
    assert e.value.status_code == 404


def test_report_not_ready_is_409_not_404(finding_id, cleanup):
    """A polling client must tell 'not finished' apart from 'wrong id'."""
    out, _ = _create(finding_id, cleanup)
    with pytest.raises(HTTPException) as e:
        _run(get_report(out["investigation_id"]))
    assert e.value.status_code == 409
    assert "queued" in e.value.detail


def test_unknown_investigation_is_404():
    with pytest.raises(HTTPException) as e:
        _run(get_investigation(str(uuid.uuid4())))
    assert e.value.status_code == 404


def test_cancel_moves_to_cancelled_and_frees_the_subject(finding_id, cleanup):
    out, _ = _create(finding_id, cleanup)
    assert _run(cancel(out["investigation_id"], "pytest"))["status"] == "cancelled"
    assert _run(get_investigation(out["investigation_id"]))["status"] == "cancelled"

    # Cancelling releases the partial unique index, so the subject can be re-investigated.
    again, _ = _create(finding_id, cleanup)
    assert again["investigation_id"] != out["investigation_id"]
    assert not again.get("existing")


def test_cancelling_a_finished_run_is_rejected(finding_id, cleanup):
    out, _ = _create(finding_id, cleanup)
    _run(cancel(out["investigation_id"], "pytest"))
    with pytest.raises(HTTPException) as e:
        _run(cancel(out["investigation_id"], "pytest"))
    assert e.value.status_code == 409


def test_review_requires_a_report(finding_id, cleanup):
    out, _ = _create(finding_id, cleanup)
    with pytest.raises(HTTPException) as e:
        _run(review(out["investigation_id"], ReviewIn(action="accept"), "pytest"))
    assert e.value.status_code == 409


def test_review_rejects_a_disposition_outside_the_taxonomy(finding_id, cleanup):
    out, _ = _create(finding_id, cleanup)
    with pytest.raises(HTTPException) as e:
        _run(review(out["investigation_id"],
                    ReviewIn(action="override", disposition="PROBABLY_BAD"), "pytest"))
    assert e.value.status_code == 422


def test_orchestrator_status_reports_queue_depth(finding_id, cleanup):
    _create(finding_id, cleanup)
    s = _run(orchestrator_status())
    assert s["pending_outbox"] >= 1
    assert s["investigations"].get("queued", 0) >= 1
    assert s["oldest_pending"] is not None


def test_list_is_newest_first(finding_id, cleanup):
    _create(finding_id, cleanup)
    rows = _run(list_investigations(limit=5))
    assert rows
    times = [r["created_at"] for r in rows]
    assert times == sorted(times, reverse=True)

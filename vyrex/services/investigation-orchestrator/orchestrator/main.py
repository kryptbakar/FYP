"""Investigation orchestrator worker.

Claims requests from `investigation_outbox` and runs the graph for each one.

WHY POLL THE OUTBOX INSTEAD OF NATS
-----------------------------------
The plan called for an INVESTIGATIONS JetStream stream fed by an outbox relay. Once the
outbox existed, that hop stopped paying for itself: the outbox table already provides
durability, ordering, retry counting and a dead-letter state, and `FOR UPDATE SKIP
LOCKED` gives the same competing-consumer semantics as a durable pull subscription —
with one fewer moving part, one fewer delivery guarantee to reason about, and no
possibility of the table and the stream disagreeing about what has been processed.

Investigation volume is a handful per hour, not thousands per second, so the throughput
argument for a broker does not apply either. `claim_next_job` is the seam: if a broker is
ever wanted, it is the only function that changes.

    python -m orchestrator.main            # run forever
    python -m orchestrator.main --once     # drain what is pending, then exit (CI/demo)
"""
from __future__ import annotations

import argparse
import logging
import signal
import sys
import time

from . import repository as repo
from .config import settings
from .graph import build_graph
from .llm import build as build_llm
from .models import CONTRACT_VERSION

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("orchestrator")

_stop = False


def _handle_signal(signum, _frame):
    global _stop
    log.info("signal %s received; finishing the current investigation then stopping", signum)
    _stop = True


def make_checkpointer(dsn: str):
    """LangGraph's Postgres checkpointer, so a restart resumes mid-graph.

    Optional on purpose: if setup fails the worker still runs, it just loses resume.
    Refusing to start would turn a degraded feature into a total outage.
    """
    try:
        from langgraph.checkpoint.postgres import PostgresSaver
        cm = PostgresSaver.from_conn_string(dsn)
        saver = cm.__enter__()
        saver.setup()                      # creates its own checkpoint tables; idempotent
        log.info("checkpointer ready (resume enabled)")
        return saver, cm
    except Exception as e:  # noqa: BLE001
        log.warning("checkpointer unavailable (%s) - running without resume", e)
        return None, None


def resume_orphans(pg, graph) -> int:
    """Re-drive investigations abandoned mid-graph by a previous crash.

    Invoking with the same `thread_id` is what makes this cheap: LangGraph's checkpointer
    replays completed nodes from the saved state instead of re-running them, so a run
    killed during an 82-second synthesis does not repeat the evidence collection — and,
    more importantly, does not repeat the LLM call if that had already returned.
    """
    orphans = repo.find_orphaned(pg)
    if not orphans:
        return 0
    log.info("found %d investigation(s) abandoned mid-graph; resuming", len(orphans))
    done = 0
    for o in orphans:
        inv_id = o["investigation_id"]
        try:
            state = {"investigation_id": inv_id, "subject_type": o["subject_type"],
                     "subject_id": o["subject_id"], "evidence": [],
                     "branch_outputs": {}, "errors": []}
            final = graph.invoke(state, config={"configurable": {"thread_id": inv_id}})
            report = final.get("report") or {}
            status = "partial" if report.get("completeness") == "partial" else "completed"
            repo.finish(pg, inv_id, status)
            log.info("resumed investigation %s -> %s", inv_id, status)
            done += 1
        except Exception as e:  # noqa: BLE001
            log.exception("could not resume %s", inv_id)
            repo.finish(pg, inv_id, "failed", error=f"resume failed: {type(e).__name__}: {e}")
    return done


def process_one(pg, graph, job: dict) -> bool:
    """Run one claimed job. Returns True if an investigation actually ran."""
    payload = job["payload"] or {}
    inv_id = repo.ensure_investigation(pg, payload, job["event_key"])
    if not inv_id:
        return False                      # duplicate for an already-active subject

    subject_type = payload.get("subject_type", job["subject_type"])
    subject_id = int(payload.get("subject_id", job["subject_id"]))
    log.info("investigating %s %s (investigation %s)", subject_type, subject_id, inv_id)

    repo.start(pg, inv_id, graph_version=settings.graph_version,
               prompt_version=settings.prompt_version,
               model_name=None, contract_version=CONTRACT_VERSION)
    t0 = time.time()
    try:
        state = {"investigation_id": inv_id, "subject_type": subject_type,
                 "subject_id": subject_id, "evidence": [], "branch_outputs": {}, "errors": []}
        # thread_id keys the checkpoint: a resumed run continues its own graph, not
        # someone else's.
        final = graph.invoke(state, config={"configurable": {"thread_id": inv_id}})
        report = final.get("report") or {}
        # 'partial' is a first-class outcome, not a failure: an abstention with the
        # missing pieces named is more useful than a confident guess.
        status = "partial" if report.get("completeness") == "partial" else "completed"
        repo.finish(pg, inv_id, status)
        log.info("investigation %s %s in %.1fs (%s / confidence %s)", inv_id, status,
                 time.time() - t0, report.get("recommended_disposition"),
                 report.get("confidence"))
        return True
    except Exception as e:  # noqa: BLE001
        log.exception("investigation %s failed", inv_id)
        repo.finish(pg, inv_id, "failed", error=f"{type(e).__name__}: {e}")
        raise


def run(once: bool = False) -> int:
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    pg = repo.connect(settings.postgres_dsn)
    llm = build_llm(settings)
    saver, cm = make_checkpointer(settings.postgres_dsn)
    graph = build_graph({"repo": repo, "pg": pg, "llm": llm, "settings": settings},
                        checkpointer=saver)
    log.info("orchestrator up: model=%s graph=%s contract=%s poll=%ss",
             llm.name, settings.graph_version, CONTRACT_VERSION, settings.poll_interval_s)

    # Before taking new work, finish what a previous crash left half-done. Otherwise
    # those runs are stranded: their outbox row is already 'sent', so nothing redelivers.
    processed = resume_orphans(pg, graph)
    try:
        while not _stop:
            job = repo.claim_next_job(pg, settings.max_attempts)
            if job is None:
                if once:
                    break
                time.sleep(settings.poll_interval_s)
                continue
            try:
                if process_one(pg, graph, job):
                    processed += 1
            except Exception as e:  # noqa: BLE001
                # Hand the job back so a transient fault retries; attempts is already
                # incremented, so it cannot loop forever.
                repo.release_job(pg, job["id"], f"{type(e).__name__}: {e}")
    finally:
        if cm is not None:
            try:
                cm.__exit__(None, None, None)
            except Exception:  # noqa: BLE001
                pass
        pg.close()
    log.info("orchestrator stopped after %d investigation(s)", processed)
    return processed


def main() -> None:
    ap = argparse.ArgumentParser(description="VYREX investigation orchestrator")
    ap.add_argument("--once", action="store_true",
                    help="drain pending work and exit (CI / demo)")
    args = ap.parse_args()
    run(once=args.once)


if __name__ == "__main__":
    sys.exit(main())

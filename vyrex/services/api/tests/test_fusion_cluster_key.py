"""The fusion read endpoint must group findings the same way the fusion ENGINE does.

There are two implementations of one rule, in two languages, in two packages that
share no library:

  * `ml/fusion.py::cluster_key`   — Python, used when scoring
  * `GET /fusion/clusters`        — SQL, used when browsing

Phase 2 taught the engine to prefer `observable_key` (the THING OBSERVED) over
`dedup_key` (the RULE THAT FIRED) and left the endpoint grouping on `dedup_key`
alone. Because different tools inspecting one connection build different per-rule
keys, every group came back with a single tool, `HAVING count(DISTINCT
source_tool) >= 2` filtered all of them out, and the endpoint returned `[]` on
live data containing a **three-tool** cluster. The project's headline capability
reported nothing, silently, for as long as nobody opened that view.

WHY THIS TEST READS SOURCE TEXT. It is the crude option and it is the right one
here: CI has no database (see .github/workflows/ci.yml — the pytest job installs
requirements and runs, with no postgres service), so the behaviour cannot be
exercised. The failure being guarded is not "the SQL is invalid" — it parsed and
ran fine for weeks — it is "the SQL silently stopped matching the engine". A text
assertion catches exactly that, and catches it at the moment someone edits the
query rather than the moment someone opens the page.
"""
from __future__ import annotations

import ast
import inspect
import re
import textwrap


def _sql_of(fn) -> str:
    """Source of a route handler WITHOUT its docstring, whitespace-normalised.

    Dropping the docstring is not tidiness, it is correctness, and this test was
    written wrong the first time. `insights.clusters` documents the fix in its own
    docstring — which quotes `COALESCE(observable_key, dedup_key)` verbatim — so a
    naive `in inspect.getsource(fn)` check passed on the PROSE while the SQL below
    it had been reverted to the broken form. Caught only by deliberately
    reintroducing the bug: 1 of 4 tests failed where 2 should have.

    A test that can be satisfied by a comment about the fix, rather than by the
    fix, is worse than no test: it reports green over the exact regression it
    exists to catch.
    """
    src = inspect.getsource(fn)
    doc = ast.get_docstring(ast.parse(textwrap.dedent(src)).body[0])
    if doc:
        src = src.replace(doc, "")
    return re.sub(r"\s+", " ", src)


def test_fusion_clusters_groups_on_the_observable_first():
    from app.routers.insights import clusters

    sql = _sql_of(clusters)
    # Assert the SQL clause, not the bare expression: `GROUP BY` is the thing that
    # decides grouping, and it will not appear in explanatory prose by accident.
    assert "GROUP BY COALESCE(observable_key, dedup_key)" in sql, (
        "GET /fusion/clusters must group on COALESCE(observable_key, dedup_key) — the "
        "same priority as ml.fusion.cluster_key. Grouping on dedup_key alone keys on the "
        "rule that fired rather than the thing observed, so no cluster ever reaches two "
        "tools and the endpoint returns [] on genuinely corroborated findings."
    )


def test_fusion_clusters_does_not_group_on_dedup_key_alone():
    """The specific regression. `GROUP BY dedup_key` (without the COALESCE) is the
    exact bug, and it is a one-word edit away from returning."""
    from app.routers.insights import clusters

    sql = _sql_of(clusters)
    assert not re.search(r"GROUP BY dedup_key\b", sql), (
        "grouping on the per-rule dedup_key alone — this is the 2026-08-29 regression"
    )


def test_the_corroboration_filter_survives():
    """A cluster is only interesting if independent tools agree. If this threshold is
    ever relaxed the endpoint starts reporting single-tool findings as 'fusion', which
    would overstate the capability rather than understate it."""
    from app.routers.insights import clusters

    sql = _sql_of(clusters)
    assert "count(DISTINCT source_tool) >= 2" in sql


def test_engine_and_endpoint_agree_on_priority_order():
    """Pin the Python side too, so the pair cannot drift from the other direction —
    someone 'simplifying' cluster_key would otherwise leave this suite green."""
    import pathlib
    import sys

    ml = pathlib.Path(__file__).resolve().parents[3] / "ml"
    if str(ml) not in sys.path:
        sys.path.insert(0, str(ml))
    import fusion  # noqa: E402

    src = re.sub(r"\s+", " ", inspect.getsource(fusion.cluster_key))
    # observable first, dedup as the fallback — the order is the whole fix.
    assert 'f.get("observable_key") or f.get("dedup_key")' in src

    # And prove the ordering behaviourally, not only by reading it.
    both = {"id": 1, "observable_key": "OBS", "dedup_key": "RULE"}
    assert fusion.cluster_key(both) == "OBS"
    assert fusion.cluster_key({"id": 2, "dedup_key": "RULE"}) == "RULE"
    assert fusion.cluster_key({"id": 3}) == "solo:3"

"""Who a write is attributed to.

Before this, every write route took an `x-analyst` HEADER and recorded that string. The
middleware resolved a real principal from oauth2-proxy headers or a session token, and
then threw it away — so an authenticated *viewer* could put `x-analyst: admin` in the
audit trail, and a reviewer could attribute a judgement to a colleague.

An audit trail a caller can forge with a header is not an audit trail, and these records
feed both the two-person approval story and the analyst labels the ML layer retrains on.
"""
from __future__ import annotations

import pytest

from app.auth_guard import Principal, actor


class _State:
    def __init__(self, principal=None):
        self.principal = principal


class _Req:
    """Minimal stand-in — actor() only ever reads request.state.principal."""
    def __init__(self, principal=None, with_state=True):
        if with_state:
            self.state = _State(principal)


def _p(user="alice", role="analyst", source="header"):
    return Principal(user=user, role=role, source=source)


def test_authenticated_principal_wins_over_the_header():
    """THE security property. Everything else here is a corollary."""
    who, src = actor(_Req(_p("alice")), x_analyst="admin")
    assert who == "alice"
    assert src.startswith("authenticated")


def test_header_is_used_only_when_there_is_no_principal():
    """The dev/demo path: auth_required is false, so there is no identity to contradict."""
    who, src = actor(_Req(None), x_analyst="bob")
    assert who == "bob"
    assert src == "unauthenticated-header"


def test_source_distinguishes_proven_from_claimed():
    """'We know this was alice' and 'the client said alice' must never be stored as the
    same claim — the source is what lets an auditor tell them apart later."""
    _, proven = actor(_Req(_p("alice")), x_analyst=None)
    _, claimed = actor(_Req(None), x_analyst="alice")
    assert proven != claimed


def test_no_principal_and_no_header_is_anonymous_not_empty():
    """An empty attribution would render as a blank cell and read like a missing value
    rather than a real, unauthenticated write."""
    who, src = actor(_Req(None), x_analyst=None)
    assert who == "anonymous"
    assert src == "none"


def test_empty_header_does_not_become_the_actor():
    who, _ = actor(_Req(None), x_analyst="")
    assert who == "anonymous"


def test_session_and_header_principals_are_both_trusted():
    """Both identity sources the middleware supports must beat the header, and the source
    is carried through so an auditor can tell which one authenticated the caller."""
    for src in ("header", "session"):
        who, s = actor(_Req(_p("carol", source=src)), x_analyst="mallory")
        assert who == "carol"
        assert s == f"authenticated:{src}"


def test_missing_state_attribute_does_not_crash():
    """Routes can be called in contexts where the middleware never ran (unit tests, or a
    public path). Falling back is correct; raising AttributeError is not."""
    who, src = actor(_Req(with_state=False), x_analyst="dave")
    assert who == "dave"
    assert src == "unauthenticated-header"


@pytest.mark.parametrize("role", ["viewer", "analyst", "admin"])
def test_role_does_not_change_attribution(role):
    """Authorisation is the middleware's job. actor() only answers *who*, and must not
    quietly drop attribution for a role it happens to consider unprivileged."""
    who, _ = actor(_Req(_p("erin", role=role)), x_analyst="admin")
    assert who == "erin"


# --------------------------------------------------------------------------- wiring ---
# Everything above tests actor() in isolation, which is exactly why the bug below
# survived: the function was always correct, the WIRING was not.
#
# Every router does `from __future__ import annotations`, so `Depends(current_actor)`
# is stored as the *string* "Annotated[str, Depends(current_actor)]" and only evaluated
# when FastAPI builds the route. In five routers `Depends` was never imported, so that
# evaluation raised NameError, FastAPI silently fell back to treating `who` as an
# ordinary query parameter with default "anonymous" — and
# `POST /findings/1/triage?who=ceo` wrote "ceo" into the audit trail.
#
# Nothing failed loudly: the app booted, the routes worked, and the unit tests above all
# passed. The only visible symptom was GET /openapi.json returning 500.

def _all_routes():
    import importlib
    import pkgutil

    import app.routers as pkg
    for mod in pkgutil.iter_modules(pkg.__path__):
        m = importlib.import_module(f"app.routers.{mod.name}")
        router = getattr(m, "router", None)
        if router is None:
            continue
        for route in router.routes:
            if hasattr(route, "endpoint"):
                yield mod.name, route


IDENTITY_PARAMS = {"who", "who_src", "actor"}


def test_identity_is_never_a_query_parameter():
    """The actual security property: a caller must not be able to name themselves.

    Asserted over every route in every router rather than the handful known to take an
    actor, because the failure is silent and any new route can reintroduce it.
    """
    from fastapi.dependencies.utils import get_dependant

    leaked = [
        f"{sorted(r.methods - {'HEAD'})} {r.path} -> {sorted(bad)}"
        for name, r in _all_routes()
        if (bad := {p.name for p in get_dependant(path=r.path, call=r.endpoint).query_params}
            & IDENTITY_PARAMS)
    ]
    assert not leaked, (
        "identity is caller-supplied on these routes — `Depends` is probably missing "
        "from the router's fastapi import:\n  " + "\n  ".join(leaked)
    )


def test_openapi_schema_can_be_generated():
    """The canary that would have caught the above on day one.

    An unresolved forward reference makes schema generation raise, so /openapi.json
    500s while every other route keeps working — the docs are the only thing that
    notices. Cheap to assert, and it fails the moment an annotation stops resolving.
    """
    from app.main import app as fastapi_app

    fastapi_app.openapi_schema = None  # never trust a cached schema
    spec = fastapi_app.openapi()
    assert spec["openapi"].startswith("3.")
    assert spec["paths"], "no paths in the generated schema"

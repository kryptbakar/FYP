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

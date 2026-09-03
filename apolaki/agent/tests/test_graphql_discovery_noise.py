"""Q-169. A DEGRADED row must mean "this result may be wrong", not "the target is not GraphQL".

MEASURED on a mutillidae mission: `run_graphql` produced 9 `tool_error` rows reading
"DEGRADED: swallowed exception at tools:_gql_post:4423: JSONDecodeError". All nine were the
CORRECT answer -- mutillidae is a PHP app with no GraphQL endpoint, so every candidate path
answered with HTML and `r.json()` raised on each. The engine returned "No GraphQL endpoint found",
which was right, while the mission record said it had malfunctioned nine times.

That is the same economics as a false positive. A degradation record exists so a reader can tell
when an engine's zero is untrustworthy; fill it with expected negatives and it stops carrying that
meaning. The distinction pinned here: NOT JSON is an answer, a TRANSPORT failure is not.
"""
import asyncio

import pytest

import tools


class _Recorder:
    """Stands in for ToolRegistry: records exactly what would reach the mission log."""

    def __init__(self):
        self.swallowed = []

    def _swallow(self, exc, where, target):
        self.swallowed.append((where, type(exc).__name__, target))


class _Resp:
    def __init__(self, exc=None, value=None):
        self._exc, self._value = exc, value

    def json(self):
        if self._exc:
            raise self._exc
        return self._value


class _Client:
    def __init__(self, resp=None, raise_on_post=None):
        self._resp, self._raise = resp, raise_on_post

    async def post(self, endpoint, json=None):
        if self._raise:
            raise self._raise
        return self._resp


def _post(client):
    rec = _Recorder()
    out = asyncio.run(tools.ToolRegistry._gql_post(rec, client, "http://t.local/graphql",
                                                   {"query": "{__typename}"}))
    return out, rec.swallowed


def test_an_html_body_is_an_answer_not_a_degradation():
    """THE regression. Every candidate path on a non-GraphQL target lands here."""
    import json as _json
    exc = _json.JSONDecodeError("Expecting value", "<html>nope</html>", 0)
    out, swallowed = _post(_Client(resp=_Resp(exc=exc)))
    assert out is None, "a non-JSON body means no GraphQL endpoint here"
    assert swallowed == [], (
        "posting to a path that is not a GraphQL endpoint recorded a DEGRADED row: %r -- that is "
        "the expected negative, and marking it as degradation makes every clean mission look "
        "malfunctioning" % (swallowed,))


def test_a_transport_failure_is_still_recorded_as_degraded():
    """The other half. Without this the fix would just be silence, which is the worse defect."""
    out, swallowed = _post(_Client(raise_on_post=OSError("connection refused")))
    assert out is None
    assert len(swallowed) == 1, (
        "a connect error means we do NOT know whether a GraphQL endpoint is there; that is exactly "
        "what a degradation record is for and it must survive")
    where, exc_name, target = swallowed[0]
    assert exc_name == "OSError"
    assert target, "the swallow must name the endpoint it was probing, not an empty string"


def test_a_real_graphql_reply_is_returned_unchanged():
    out, swallowed = _post(_Client(resp=_Resp(value={"data": {"__typename": "Query"}})))
    assert out == {"data": {"__typename": "Query"}}
    assert swallowed == []

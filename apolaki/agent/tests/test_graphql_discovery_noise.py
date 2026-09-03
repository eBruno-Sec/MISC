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
import json

import pytest

import tools


class _Recorder:
    """Stands in for ToolRegistry: records exactly what would reach the mission log."""

    def __init__(self):
        self.swallowed = []

    def _swallow(self, exc, where, target):
        self.swallowed.append((where, type(exc).__name__, target))


class _Resp:
    """A response carries a BODY. The first version of this stub had only .json(), so it could not
    represent the thing that actually happens -- a server returning an HTML page -- and it broke the
    moment the engine started judging the body's shape instead of catching a parse exception."""

    def __init__(self, text="", value=None, exc=None):
        self.text, self._value, self._exc = text, value, exc

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
    html = "<!DOCTYPE html><html><body>Mutillidae</body></html>"
    exc = _json.JSONDecodeError("Expecting value", html, 0)
    out, swallowed = _post(_Client(resp=_Resp(text=html, exc=exc)))
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
    body = {"data": {"__typename": "Query"}}
    out, swallowed = _post(_Client(resp=_Resp(text=json.dumps(body), value=body)))
    assert out == {"data": {"__typename": "Query"}}
    assert swallowed == []


def test_a_json_shaped_body_that_will_not_parse_is_left_to_surface():
    """The third case, and the reason the fix is a SHAPE test rather than a caught exception.

    A body that does not even begin like JSON is an HTML page and the shape answers the question.
    A body that DOES look like JSON and then fails to parse is genuinely anomalous for a GraphQL
    endpoint, so it must not be flattened into the clean negative "no GraphQL here" -- it is left
    to raise and surface as a tool_error.
    """
    import json as _json
    broken = '{"data": {'
    exc = _json.JSONDecodeError("Expecting value", broken, 9)
    try:
        _post(_Client(resp=_Resp(text=broken, exc=exc)))
    except ValueError:
        return
    raise AssertionError("a malformed JSON body from a JSON-shaped response was silently "
                         "reported as 'not a GraphQL endpoint'")

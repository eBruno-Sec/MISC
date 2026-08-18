"""Behavioural controls for blind-SQLi baseline stability.

These tests drive the shipping ``ToolRegistry._run_sqli`` transport.  A helper-only
test would miss the production defect if the repeated reference request were never
sent or never delivered to the oracle.
"""

import ast
import asyncio
import inspect
import textwrap
from urllib.parse import parse_qs, urlencode, urlparse

import crawl
import form_xss
import header_vector
import httpx
import scope as scope_mod
import sqli_tool as sqli
import tools


URL = "http://host.local/products?id=1"
FORM_URL = "http://host.local/search"
BASE = "<html><body>rows: alpha, beta, gamma</body></html>"
FALSE = "<html><body>no matching rows</body></html>"
NOISE_A = "<html><body>resolver-a: temporary backend failure</body></html>"
NOISE_B = "<html><body>resolver-b: service unavailable</body></html>"
TRUE_VALUE = "1' AND 1=1-- -"
FALSE_VALUE = "1' AND 1=2-- -"


class _Response:
    def __init__(self, text):
        self.text = text
        self.status_code = 200
        self.headers = {}


class _Client:
    def __init__(self, get_responder, post_responder=None):
        self.get_responder = get_responder
        self.post_responder = post_responder or (lambda _url, _body, _n: BASE)
        self.gets = []
        self.posts = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    async def get(self, url, **_kwargs):
        self.gets.append(url)
        return _Response(self.get_responder(url, len(self.gets)))

    async def post(self, url, data=None, **_kwargs):
        body = data or ""
        self.posts.append((url, body))
        return _Response(self.post_responder(url, body, len(self.posts)))


def _registry():
    engine = scope_mod.ScopeEngine()
    engine.load_manual(["host.local"], [], "SQLi stability control")
    return tools.ToolRegistry(engine, mission_id=None, lab_mode=True)


def _isolate_boolean_path(monkeypatch, client):
    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: client)
    monkeypatch.setattr(sqli, "ERROR_PROBES", ())
    monkeypatch.setattr(
        sqli,
        "boolean_payloads",
        lambda _original: [{
            "dbms": "control",
            "ctx": "single-quote string",
            "true": TRUE_VALUE,
            "false": FALSE_VALUE,
        }],
    )
    monkeypatch.setattr(sqli, "time_payloads", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(crawl, "extract_forms", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(header_vector, "discover_header_names", lambda *_args, **_kwargs: [])


def _value(url):
    return parse_qs(urlparse(url).query, keep_blank_values=True).get("id", [""])[0]


def _run_get(monkeypatch, responder):
    client = _Client(responder)
    _isolate_boolean_path(monkeypatch, client)
    monkeypatch.setattr(form_xss, "parse_forms", lambda *_args, **_kwargs: [])
    result = asyncio.run(_registry()._run_sqli({"url": URL, "params": ["id"]}))
    return result, client


def _assert_get_reference_was_resampled(client):
    values = [_value(url) for url in client.gets]
    # Q-070: N went 2 -> 3 (baseline + 2 repeats), the measured point where FP/attempt on a
    # bimodal page reaches 0.000 with all five live true positives still confirming. The count
    # is pinned rather than made flexible ON PURPOSE: extra reference requests are the PRICE of
    # this fix, they are charged per FIELD on the POST carrier, and a silent drift upward is a
    # cost nobody would notice. If this fails, the sampling contract changed -- re-measure the
    # FP/recall table before re-aiming it.
    assert values[:4] == ["1", "1", "1", "1'"], (
        "the shipping GET path must issue exactly THREE identical reference requests before probes",
        values,
    )


def test_unstable_page_without_injection_does_not_confirm(monkeypatch):
    # The response sequence ignores the payload entirely. Before the fix, request 4
    # (TRUE) happened to equal request 1 and request 5 (FALSE) happened to differ.
    sequence = [NOISE_A, NOISE_B, NOISE_A, NOISE_A, NOISE_B, NOISE_A]

    def unstable(_url, number):
        return sequence[min(number - 1, len(sequence) - 1)]

    result, client = _run_get(monkeypatch, unstable)
    assert not result.findings
    _assert_get_reference_was_resampled(client)


def test_unstable_page_with_real_injection_still_does_not_confirm(monkeypatch):
    reference_count = 0

    def unstable_vulnerable(url, _number):
        nonlocal reference_count
        value = _value(url)
        if value == "1":
            reference_count += 1
            return NOISE_A if reference_count == 1 else NOISE_B
        if value == TRUE_VALUE:
            return NOISE_A
        if value == FALSE_VALUE:
            return FALSE
        return NOISE_A

    result, client = _run_get(monkeypatch, unstable_vulnerable)
    assert not result.findings, "an unstable reference must prefer a false negative to a false positive"
    _assert_get_reference_was_resampled(client)


def test_stable_page_with_real_boolean_differential_still_confirms(monkeypatch):
    def stable_vulnerable(url, _number):
        return FALSE if _value(url) == FALSE_VALUE else BASE

    result, client = _run_get(monkeypatch, stable_vulnerable)
    _assert_get_reference_was_resampled(client)
    assert len(result.findings) == 1
    assert "boolean-blind" in result.findings[0]["tags"]
    assert result.findings[0]["confidence"] == "confirmed"


def test_stable_page_without_a_differential_stays_quiet(monkeypatch):
    result, client = _run_get(monkeypatch, lambda _url, _number: BASE)
    _assert_get_reference_was_resampled(client)
    assert not result.findings


def _run_post(monkeypatch, responder):
    form = {
        "action": FORM_URL,
        "fields": {"id": "1"},
        "text_fields": ["id"],
    }
    client = _Client(lambda _url, _number: "<html><form></form></html>", responder)
    _isolate_boolean_path(monkeypatch, client)
    monkeypatch.setattr(form_xss, "parse_forms", lambda *_args, **_kwargs: [form])
    monkeypatch.setattr(
        form_xss,
        "body_with",
        lambda _form, field, value: urlencode({field: value}),
    )
    result = asyncio.run(_registry()._run_sqli({"url": FORM_URL, "params": []}))
    return result, client


def _post_value(body):
    return parse_qs(body, keep_blank_values=True).get("id", [""])[0]


def test_shipping_post_path_resamples_and_preserves_a_real_differential(monkeypatch):
    def stable_vulnerable(_url, body, _number):
        return FALSE if _post_value(body) == FALSE_VALUE else BASE

    result, client = _run_post(monkeypatch, stable_vulnerable)
    values = [_post_value(body) for _url, body in client.posts]
    # Q-070: N 2 -> 3 on the POST carrier too. This is the EXPENSIVE side -- samples are taken
    # inside the FIELD loop, so the extra reference is charged per field and does not amortise
    # the way the query-string carrier does. Pinned exactly so that cost stays visible.
    assert values[:4] == ["1", "1", "1", TRUE_VALUE], values
    assert len(result.findings) == 1


def test_shipping_post_path_rejects_a_real_differential_on_an_unstable_page(monkeypatch):
    reference_count = 0

    def unstable_vulnerable(_url, body, _number):
        nonlocal reference_count
        value = _post_value(body)
        if value == "1":
            reference_count += 1
            return NOISE_A if reference_count == 1 else NOISE_B
        if value == TRUE_VALUE:
            return NOISE_A
        if value == FALSE_VALUE:
            return FALSE
        return NOISE_A

    result, client = _run_post(monkeypatch, unstable_vulnerable)
    values = [_post_value(body) for _url, body in client.posts]
    assert not result.findings
    # Q-070: N 2 -> 3 on the POST carrier too. This is the EXPENSIVE side -- samples are taken
    # inside the FIELD loop, so the extra reference is charged per field and does not amortise
    # the way the query-string carrier does. Pinned exactly so that cost stays visible.
    assert values[:4] == ["1", "1", "1", TRUE_VALUE], values


def test_every_shipping_boolean_call_supplies_the_reference_sample():
    source = textwrap.dedent(inspect.getsource(tools.ToolRegistry._run_sqli))
    tree = ast.parse(source)
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "sqli"
        and node.func.attr == "analyze_boolean"
    ]
    assert len(calls) == 2, "measured shipping call-site baseline changed; review every new carrier"
    for call in calls:
        # The property is "supplies a REFERENCE", not "uses this keyword". The carriers forward
        # baseline_samples=[...] since Q-070; a carrier supplying NOTHING must still fail here.
        kwargs = {keyword.arg for keyword in call.keywords}
        assert kwargs & {"baseline_repeat", "baseline_samples"}, (
            "a shipping boolean carrier supplies no reference sample: %s" % (kwargs,))

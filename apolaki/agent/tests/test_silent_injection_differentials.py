"""Silent XPath/LDAP targets: semantic boolean differentials and adversarial clean twins."""
from __future__ import annotations

import asyncio
import html
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from ldap3 import Connection, MOCK_SYNC, Server
from ldap3.utils.conv import escape_filter_chars

import ldap_tool as ldap
import scope
import semantic_differential as sem
import tools
import xpath_tool as xpath


_LOGIN = "<html><form action='/login'><input name='username'><input type='password'></form></html>"
_DASHBOARD = "<html><h1>Dashboard</h1><a href='/logout'>Logout</a></html>"


def _record_page(records):
    rows = "".join("<tr data-record-id='%s'><td>%s</td></tr>" % (x, x) for x in records)
    return "<html><table><tr><th>uid</th></tr>%s</table></html>" % rows


def test_semantic_oracle_accepts_auth_and_record_set_changes_only():
    auth = sem.evaluate(_DASHBOARD, _LOGIN)
    assert auth["confirmed"] and auth["signal"] == "auth_state"
    records = sem.evaluate(_record_page(["alice", "bob"]), _record_page([]))
    assert records["confirmed"] and records["signal"] == "record_set"

    # Different text and different byte counts are presentation noise, not a semantic result.
    clean_true = _LOGIN.replace("</html>", "<p>request alpha had a very long rotating nonce</p></html>")
    clean_false = _LOGIN.replace("</html>", "<p>request beta</p></html>")
    assert not sem.evaluate(clean_true, clean_false)["confirmed"]


def test_pair_order_is_randomized_but_truth_labels_survive(monkeypatch):
    monkeypatch.setattr(sem.secrets, "randbits", lambda _n: 0)
    assert sem.randomized_pair("yes", "no") == [("true", "yes"), ("false", "no")]
    monkeypatch.setattr(sem.secrets, "randbits", lambda _n: 1)
    assert sem.randomized_pair("yes", "no") == [("false", "no"), ("true", "yes")]


def test_xpath_pair_is_xpath_specific_and_structurally_identical():
    pair = xpath.boolean_pairs("nobody")[0]
    assert "count(/*)=1" in pair["true"] and "count(/*)=0" in pair["false"]
    assert pair["true"].replace("count(/*)=1", "PREDICATE") == \
        pair["false"].replace("count(/*)=0", "PREDICATE")


def _xpath_literal(value: str) -> str:
    if '"' not in value:
        return '"%s"' % value
    if "'" not in value:
        return "'%s'" % value
    raise AssertionError("fixture only needs one quote context")


def test_xpath_vulnerable_fixture_confirms_and_escaped_clean_twin_rejects():
    """Chromium's native XPath engine evaluates both fixtures; this is not Apolaki parsing its own payload."""
    chrome = tools._chrome_path()
    if not chrome:
        pytest.skip("Chromium is required for the real XPath fixture")
    pair = xpath.boolean_pairs("nobody")[0]
    xml = ("<users><user><username>alice</username><password>a</password></user>"
           "<user><username>bob</username><password>b</password></user></users>")
    vulnerable = {
        label: "//user[username/text()='%s' and password/text()='wrong']" % pair[label]
        for label in ("true", "false")
    }
    clean = {
        label: "//user[username/text()=%s and password/text()='wrong']" % _xpath_literal(pair[label])
        for label in ("true", "false")
    }

    async def _counts():
        from playwright.async_api import async_playwright
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True, executable_path=chrome,
                args=["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"])
            page = await browser.new_page()
            out = await page.evaluate(
                """({xml, queries}) => {
                    const doc = new DOMParser().parseFromString(xml, 'application/xml');
                    const result = {};
                    for (const [kind, pair] of Object.entries(queries)) {
                        result[kind] = {};
                        for (const [label, query] of Object.entries(pair)) {
                            result[kind][label] = document.evaluate(
                                query, doc, null, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null
                            ).snapshotLength;
                        }
                    }
                    return result;
                }""",
                {"xml": xml, "queries": {"vulnerable": vulnerable, "clean": clean}},
            )
            await browser.close()
            return out

    counts = asyncio.run(_counts())
    assert counts["vulnerable"] == {"true": 2, "false": 0}
    assert counts["clean"] == {"true": 0, "false": 0}
    assert xpath.evaluate_boolean(_DASHBOARD, _LOGIN, pair["true"], pair["false"])["confirmed"]
    assert not xpath.evaluate_boolean(_LOGIN, _LOGIN, pair["true"], pair["false"])["confirmed"]


def _ldap_fixture_results(payload: str, clean: bool):
    server = Server("fixture")
    conn = Connection(server, client_strategy=MOCK_SYNC)
    conn.bind()
    conn.strategy.add_entry(
        "uid=alice,ou=users,dc=example,dc=test",
        {"objectClass": ["inetOrgPerson"], "uid": "alice", "sn": "Alice", "cn": "Alice"},
    )
    conn.strategy.add_entry(
        "uid=bob,ou=users,dc=example,dc=test",
        {"objectClass": ["inetOrgPerson"], "uid": "bob", "sn": "Bob", "cn": "Bob"},
    )
    value = escape_filter_chars(payload) if clean else payload
    search_filter = "(&(uid=%s)(objectClass=inetOrgPerson))" % value
    conn.search("ou=users,dc=example,dc=test", search_filter, attributes=["uid"])
    # NOT `assert conn.search(...)`: ldap3's return value is False when the filter matched NOTHING, and
    # the FALSE probe is a contradiction (objectClass=apolaki-never-fixture) whose entire job is to match
    # nothing. Asserting truthiness would fail precisely when the probe works, and it contradicts this
    # test's own expectation of "false": []. What must hold is that the server ACCEPTED and PROCESSED the
    # filter — an empty result set is the required outcome here, not an error.
    assert conn.result["description"] == "success", conn.result
    return sorted(str(entry.uid.value) for entry in conn.entries)


def test_ldap_vulnerable_fixture_confirms_and_escaped_clean_twin_rejects():
    pair = ldap.boolean_pairs("ignored", "fixture")[0]
    assert pair["true"].replace("objectClass=*", "PREDICATE") == \
        pair["false"].replace("objectClass=apolaki-never-fixture", "PREDICATE")
    vulnerable = {label: _ldap_fixture_results(pair[label], clean=False) for label in ("true", "false")}
    clean = {label: _ldap_fixture_results(pair[label], clean=True) for label in ("true", "false")}
    assert vulnerable == {"true": ["alice", "bob"], "false": []}
    assert clean == {"true": [], "false": []}
    assert ldap.evaluate_boolean(
        _record_page(vulnerable["true"]), _record_page(vulnerable["false"]),
        pair["true"], pair["false"])["confirmed"]
    assert not ldap.evaluate_boolean(
        _record_page(clean["true"]), _record_page(clean["false"]),
        pair["true"], pair["false"])["confirmed"]


class _NoFormClient:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    async def get(self, _url):
        return type("Response", (), {"text": "<html><body>no forms</body></html>"})()


def _shipping_result(kind: str, vulnerable: bool, monkeypatch):
    engine = scope.ScopeEngine()
    engine.load_manual(["fixture.test"], [], "fixture")
    registry = tools.ToolRegistry(engine, lab_mode=True)
    seen = []

    async def fake_http(url, method="GET", **_kwargs):
        assert method == "GET"
        value = parse_qs(urlparse(url).query, keep_blank_values=True)["q"][0]
        seen.append(value)
        if kind == "xpath":
            body = _DASHBOARD if vulnerable and "count(/*)=1" in value else _LOGIN
        else:
            broad = value == "*" or ("objectClass=*" in value and "apolaki-never-" not in value)
            body = _record_page(["alice", "bob"] if vulnerable and broad else [])
        # Reflection and varying presentation are deliberately present in the clean twin.
        body = body.replace("</html>", "<p>%s</p></html>" % html.escape(value))
        return {"status": 200, "headers": {}, "body": body, "final_url": url, "error": ""}

    registry._http = fake_http
    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: _NoFormClient())
    method = registry._run_xpath if kind == "xpath" else registry._run_ldap
    result = asyncio.run(method({"url": "http://fixture.test/search?q=seed"}))
    return result, seen


@pytest.mark.parametrize("kind", ["xpath", "ldap"])
def test_shipping_tool_confirms_silent_vulnerable_fixture(kind, monkeypatch):
    result, seen = _shipping_result(kind, vulnerable=True, monkeypatch=monkeypatch)
    assert len(result.findings) == 1
    assert result.findings[0]["confidence"] == "confirmed"
    assert "differential" in result.findings[0]["evidence"].lower()
    assert any("count(/*)=1" in value if kind == "xpath" else "objectClass=*" in value for value in seen)


@pytest.mark.parametrize("kind", ["xpath", "ldap"])
def test_shipping_tool_rejects_escaped_clean_twin(kind, monkeypatch):
    result, _seen = _shipping_result(kind, vulnerable=False, monkeypatch=monkeypatch)
    assert result.findings == []

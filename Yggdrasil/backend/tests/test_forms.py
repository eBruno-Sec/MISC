"""Unit tests for form discovery (offensive engine).

Covers the pure, network-free pieces: the HTML <form> extractor and the
same-host scope guard. Run from backend/:  python -m pytest tests/ -q
"""
from agents.offensive import _FormExtractor, _host_ok


def test_form_extractor_login_and_search():
    html = """
    <form action="/login" method="POST">
      <input name="username" type="text">
      <input name="password" type="password">
      <input name="csrf" type="hidden" value="x">
      <input type="submit" value="Go">
    </form>
    <form action="search" method="get"><input name="q"></form>
    """
    ex = _FormExtractor()
    ex.feed(html)
    assert len(ex.forms) == 2

    login = ex.forms[0]
    assert login["action"] == "/login"
    assert login["method"] == "post"
    assert "username" in login["fields"] and "password" in login["fields"]
    assert "csrf" not in login["fields"]      # hidden + submit excluded

    search = ex.forms[1]
    assert search["method"] == "get"
    assert search["fields"] == ["q"]


def test_form_extractor_skips_fieldless_form():
    ex = _FormExtractor()
    ex.feed('<form action="/x"><input type="submit"></form>')
    assert ex.forms[0]["fields"] == []


def test_form_extractor_dedupes_field_names():
    ex = _FormExtractor()
    ex.feed('<form><input name="q"><input name="q"></form>')
    assert ex.forms[0]["fields"] == ["q"]


def test_host_ok_same_host():
    assert _host_ok("http://t.example/login", "http://t.example/catalog") is True


def test_host_ok_rejects_foreign_host():
    # A form posting off to another host must not drag scanning out of scope.
    assert _host_ok("http://evil.example/collect", "http://t.example/") is False


def test_host_ok_rejects_schemeless():
    assert _host_ok("/login", "http://t.example/") is False

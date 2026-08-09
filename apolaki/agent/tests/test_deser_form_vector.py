"""insecure_deser reaching serialized objects carried in FORM BODIES.

The engine scanned only query params and cookies, so a serialized object round-tripped through a hidden
field — the commonest real carrier — produced "no serialized objects found" and the endpoint was reported
clean without ever being tested. These cover detection and the delivery path that replays the form.
"""
import asyncio

import crawl
import deser_tool as deser
import scope
import tools

_PHP = 'a:1:{s:4:"role";s:4:"user";}'
_PAGE = ('<html><form action="/prefs" method="post">'
         '<input type="hidden" name="state" value=\'%s\'>'
         '<input type="text" name="nick" value="bob">'
         '</form></html>' % _PHP)


def test_serialized_blob_in_a_hidden_field_is_found_with_its_siblings():
    forms = crawl.extract_forms(_PAGE, "https://target.tld/prefs")
    found = deser.find_serialized_form_inputs(forms)
    assert len(found) == 1
    it = found[0]
    assert it["location"] == "form" and it["name"] == "state" and it["value"] == _PHP
    assert it["format"] == "PHP" and it["method"] == "POST"
    assert it["action"] == "https://target.tld/prefs"
    # siblings travel with it: replaying the form needs every other field at its discovered default,
    # otherwise base and probe differ in more than the one corrupted blob.
    assert it["form_fields"]["nick"] == "bob" and it["form_fields"]["state"] == _PHP


def test_ordinary_form_values_are_not_mistaken_for_serialized_objects():
    """Negative control — a normal form must produce nothing, or every login page becomes a finding."""
    plain = ('<form action="/login" method="post">'
             '<input name="email" value="a@b.c"><input name="password" value="">'
             '<input type="hidden" name="csrf" value="9f8e7d6c5b4a"></form>')
    assert deser.find_serialized_form_inputs(crawl.extract_forms(plain, "https://t/")) == []
    assert deser.find_serialized_form_inputs([]) == []
    assert deser.find_serialized_form_inputs([{"action": "/x", "method": "POST"}]) == []   # no inputs key


class _Resp:
    def __init__(self, text):
        self.text = text


class _FakeClient:
    """Captures what the engine actually puts on the wire."""
    posts = []

    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url, **kw):
        return _Resp("ok")

    async def post(self, url, content=None, headers=None, **kw):
        _FakeClient.posts.append((url, content or ""))
        return _Resp("ok")


def _registry():
    sc = scope.ScopeEngine()
    sc.load_manual(["target.tld"], [], "T")
    reg = tools.ToolRegistry(sc, mission_id=None, lab_mode=True)

    async def _http(url, method="GET", **kw):
        return {"status": 200, "headers": {}, "body": _PAGE}

    reg._http = _http
    return reg


def test_form_vector_is_actually_replayed_on_the_wire(monkeypatch):
    """Wiring, not just detection: the corrupted blob must leave the process, with siblings intact."""
    import httpx
    _FakeClient.posts = []
    monkeypatch.setattr(httpx, "AsyncClient", _FakeClient)
    reg = _registry()
    res = asyncio.run(reg._run_deserialization({"url": "https://target.tld/prefs"}))
    assert "No serialized objects" not in res.output
    assert len(_FakeClient.posts) == 2, _FakeClient.posts          # baseline + corrupted probe
    urls = {u for u, _ in _FakeClient.posts}
    assert urls == {"https://target.tld/prefs"}
    baseline, probe = _FakeClient.posts[0][1], _FakeClient.posts[1][1]
    assert baseline != probe                                        # exactly one field was corrupted
    assert "nick=bob" in baseline and "nick=bob" in probe           # siblings preserved in BOTH
    assert res.findings


def test_out_of_scope_form_action_is_never_replayed(monkeypatch):
    """A form posting to another host must not be touched, however tempting the blob."""
    import httpx
    _FakeClient.posts = []
    monkeypatch.setattr(httpx, "AsyncClient", _FakeClient)
    sc = scope.ScopeEngine()
    sc.load_manual(["target.tld"], [], "T")
    reg = tools.ToolRegistry(sc, mission_id=None, lab_mode=True)
    evil = _PAGE.replace('action="/prefs"', 'action="https://elsewhere.example/collect"')

    async def _http(url, method="GET", **kw):
        return {"status": 200, "headers": {}, "body": evil}

    reg._http = _http
    res = asyncio.run(reg._run_deserialization({"url": "https://target.tld/prefs"}))
    assert _FakeClient.posts == []
    assert "No serialized objects" in res.output

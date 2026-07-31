"""Tests for the Target Intelligence Harvester (agent/intel.py)."""
from __future__ import annotations

import base64

import intel


def test_store_dedupes_and_tracks_provenance():
    s = intel.IntelStore()
    s.add("email", "a@b.com", "src1")
    s.add("email", "a@b.com", "src2")   # same value, second source
    s.add("email", "a@b.com", "src1")   # duplicate source ignored
    assert s.get("email") == ["a@b.com"]
    assert sorted(s.with_sources("email")["a@b.com"]) == ["src1", "src2"]
    assert s.count() == 1


def test_harvest_text_pulls_email_username_path_version():
    s = intel.IntelStore()
    intel.harvest_text('contact jim@juice-sh.op see href="/ftp/secret.md" v1.7.7', "page", s)
    assert "jim@juice-sh.op" in s.get("email")
    assert "jim" in s.get("username")
    assert "/ftp/secret.md" in s.get("route")
    assert "1.7.7" in s.get("version")


def test_harvest_text_decodes_base64_blob():
    secret = "the answer is in the ftp folder"
    blob = base64.b64encode(secret.encode()).decode()
    s = intel.IntelStore()
    intel.harvest_text("junk " + blob + " junk", "file", s)
    assert blob in s.get("encoded")
    assert secret in s.get("decoded")


def test_decode_candidate_handles_base64_hex_rot13_and_garbage():
    b64 = base64.b64encode(b"hello world token").decode()
    assert intel.decode_candidate(b64) == "hello world token"
    hexs = b"pentest".hex()
    assert intel.decode_candidate(hexs) == "pentest"
    assert intel.decode_candidate("uryyb jbeyq") == "hello world"   # rot13
    assert intel.decode_candidate("!!!!") is None


def test_harvest_json_walks_and_extracts_fields_and_embedded_hrefs():
    s = intel.IntelStore()
    doc = {"data": [
        {"id": 15, "email": "admin@juice-sh.op", "role": "admin"},
        {"name": "Apple Juice", "description": 'buy at <a href="/ftp/coupons_2013.md.bak">here</a>'},
        {"coupon": "WMNSDY2019"},
    ]}
    intel.harvest_json(doc, "api/Products", s)
    assert "admin@juice-sh.op" in s.get("email")
    assert "15" in s.get("object_id")
    assert "WMNSDY2019" in s.get("coupon")
    assert "/ftp/coupons_2013.md.bak" in s.get("route")   # href mined from a description string


def test_generic_name_key_is_not_treated_as_username():
    # a bare "name" (product/config name) must NOT pollute the username bucket
    s = intel.IntelStore()
    intel.harvest_json({"name": "Apple Juice Box", "username": "mc.safesearch"}, "api", s)
    users = s.get("username")
    assert "mc.safesearch" in users
    assert "Apple Juice Box" not in users


def test_harvest_js_extracts_spa_routes():
    s = intel.IntelStore()
    js = "const routes=[{path:'administration'},{path:'score-board'},{path:'accounting'}];"
    intel.harvest_js(js, "main.js", s)
    routes = s.get("route")
    assert "/administration" in routes and "/score-board" in routes


def test_harvest_dispatch_and_to_dict():
    store = intel.harvest({"source": "u", "json": {"email": "x@y.io"},
                           "js": "path:'admin'", "text": "v2.0.1"})
    d = store.to_dict()
    assert d["total"] >= 3
    assert "email" in d["by_kind"] and "route" in d["by_kind"] and "version" in d["by_kind"]


def test_harvest_captures_absolute_urls_and_hash_routes():
    s = intel.IntelStore()
    intel.harvest_text('see <a href="https://s3.amazonaws.com/bucket/x">x</a> or href="/#recycle"', "p", s)
    assert any("s3.amazonaws.com" in u for u in s.get("url"))
    assert "/#recycle" in s.get("route")


def test_readable_text_is_not_falsely_rot13_decoded():
    # regression: URL/path fragments must NOT be "decoded" into rot13 gibberish
    assert intel.decode_candidate("swag/blob/master/projects/juice") is None
    s = intel.IntelStore()
    intel.harvest_text("visit github.com/OWASP/owasp-swag/blob/master/projects here", "p", s)
    assert s.get("decoded") == []


def test_to_dict_redacts_secrets():
    s = intel.IntelStore()
    s.add("secret", "supersecrettoken123", "js")   # len 19
    s.add("email", "a@b.com", "js")
    pub = s.to_dict(redact_secrets=True)
    assert pub["candidates"]["secret"] == ["<redacted:19>"]
    assert "a@b.com" in pub["candidates"]["email"]
    raw = s.to_dict()                                # unredacted for internal use
    assert "supersecrettoken123" in raw["candidates"]["secret"]


def test_harvest_is_bounded():
    s = intel.IntelStore()
    big = " ".join("user%d@ex.com" % i for i in range(2000))
    intel.harvest_text(big, "big", s)
    assert len(s.get("email")) <= intel._MAX_PER_KIND


def test_harvest_html_mines_forms_params_comments_redirects():
    import intel
    s = intel.IntelStore()
    html = ('<form action="/search?src=nav"><input name="q"><input name="redirect_url">'
            '<input type=hidden name=csrf_token value=x></form>'
            '<a href="/admin/panel?id=5">x</a><meta http-equiv=refresh content="0;url=/login">'
            '<meta name=generator content="WordPress 6.1">'
            '<!-- api at /internal/v2/users, test admin / Passw0rd! -->')
    intel.harvest_html(html, "http://t/", s)
    c = s.to_dict()["candidates"]
    assert {"q", "redirect_url", "csrf_token", "id", "src"} <= set(c.get("param", []))
    assert "/search" in c.get("endpoint", [])
    assert "/admin/panel" in c.get("route", []) and "/login" in c.get("route", [])
    assert "WordPress 6.1" in c.get("version", [])
    assert "field:csrf_token" in c.get("secret", [])
    assert any("api at /internal" in x for x in c.get("comment", []))    # dev comment captured


def test_harvest_css_mines_url_and_import():
    import intel
    s = intel.IntelStore()
    intel.harvest_css("body{background:url('/assets/bg.png')} @import url('https://f/x.css');", "http://t/x.css", s)
    c = s.to_dict()["candidates"]
    assert "/assets/bg.png" in c.get("route", []) and "https://f/x.css" in c.get("url", [])


def test_params_feed_the_planner_observations():
    import technique_planner as TP
    harvest = {"candidates": {"param": ["redirect_url", "q", "userid"]}, "by_kind": {"param": 3}}
    obs = TP.derive_observations(harvest=harvest)
    assert {"has_redirect_param", "has_search_param", "has_object_id"} <= obs

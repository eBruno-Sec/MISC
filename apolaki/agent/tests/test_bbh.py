"""
Deterministic test suite for the Apolaki platform engines.

Covers the ported/adapted engines (security, scope, poc, surface, replay,
web_security, guidance, triage, report, db) plus the async HITL gate + mode
enforcement in the agent. No network, no LLM, no external binaries.
"""
import asyncio
import json
import os
import re
import tempfile

import security
import scope as scope_mod
import poc
import surface
import replay
import web_security as ws
import guidance
import triage
import report
import db
import dns_recon
import auth
import zap_client
import graphql_tool as gql
import jwt_tool as jt
import authz_tool as authz
import race_tool as race
import xss_tool as xt
import codereview as cr
import csrf_tool as csrf
import fingerprint as fp
import ssrf_tool as ssrf
import deser_tool as deser
import oauth_tool as oauth
import exposure_tool as exp
import collaborator as collab
import xxe_tool as xxe
import github_recon as ghr
import sqli_tool as sqli
import cmdi_tool as cmdi
import graph_model
import memory as memory_mod


# ── security: target validation ──────────────────────────────────
def test_target_validation_blocks_shell_and_dash():
    assert security.is_valid_target("example.com")
    assert security.is_valid_target("*.example.com")
    assert security.is_valid_target("10.0.0.1")
    assert security.is_valid_target("10.0.0.0/24")
    assert security.is_valid_target("app.example.com:8443")
    assert not security.is_valid_target("-oG")            # arg injection
    assert not security.is_valid_target("a;rm -rf /")     # shell metachar
    assert not security.is_valid_target("a.com|b")
    assert not security.is_valid_target("")


def test_cidr_expand_rfc3021():
    assert security.expand_cidr("10.0.0.0/31") == ["10.0.0.0", "10.0.0.1"]
    assert security.expand_cidr("10.0.0.5/32") == ["10.0.0.5"]
    assert len(security.expand_cidr("10.0.0.0/24")) == 254
    assert security.expand_cidr("example.com") is None


def test_safe_flags_drops_injection():
    # Tools run via exec (no shell), so the real risk is argument injection: a
    # non-allowlisted -flag or a shell-metachar token. Both must be dropped;
    # allowlisted flags and their values are kept.
    out = security.safe_flags("-sV --top-ports 1000 -oN /etc/x ;reboot", ("-s", "--top-ports"))
    assert "-sV" in out and "--top-ports" in out and "1000" in out
    assert "-oN" not in out            # non-allowlisted flag dropped
    assert ";reboot" not in out        # shell-metachar token dropped
    assert not any(tok.startswith("-") and tok not in ("-sV", "--top-ports") for tok in out)


# ── scope: engine + multi-format parsing ─────────────────────────
def test_scope_deny_overrides_allow_and_wildcard():
    eng = scope_mod.ScopeEngine()
    eng.load_manual(["*.example.com"], ["internal.example.com"], "P")
    assert eng.validate("https://api.example.com/x")[0]
    assert not eng.validate("internal.example.com")[0]     # deny wins
    assert not eng.validate("evil.com")[0]


def test_scope_parse_sections_and_hackerone():
    p = scope_mod.parse_scope("# IN-SCOPE\n*.example.com\n[app](https://app.example.com)\n"
                              "com.pkg.name (Android)\n# OUT-OF-SCOPE\n- internal.example.com")
    ids = [e["identifier"] for e in p["in_scope"]]
    assert "*.example.com" in ids and "app.example.com" in ids
    assert p["out_of_scope"][0]["identifier"] == "internal.example.com"
    ins, outs = scope_mod.web_targets(p)
    assert "com.pkg.name" not in ins        # mobile app dropped from web targets

    h1 = "asset_identifier,eligible_for_bounty\napi.example.com,true\nold.example.com,false"
    ph = scope_mod.parse_scope(h1)
    assert ph["format"] == "hackerone_csv"
    assert ph["in_scope"][0]["identifier"] == "api.example.com"
    assert ph["out_of_scope"][0]["identifier"] == "old.example.com"


def test_scope_parse_burp_json():
    b = json.dumps({"target": {"scope": {"include": [{"host": "example.com"}],
                                         "exclude": [{"host": "internal.example.com"}]}}})
    pb = scope_mod.parse_scope(b)
    assert pb["format"] == "burp_json"
    assert pb["in_scope"][0]["identifier"] == "example.com"


# ── poc: redaction + rendering ───────────────────────────────────
def test_poc_redacts_and_renders():
    ex = {"url": "https://t/x", "method": "GET",
          "request_headers": {"Cookie": "s=secret", "Accept": "*/*"}}
    assert poc.redact_headers(ex["request_headers"])["Cookie"] == poc.REDACTED
    curl = poc.to_curl(ex)
    assert "<redacted>" in curl and "s=secret" not in curl
    md = poc.finding_markdown({"title": "X", "severity": "high", "target": "https://t/x",
                               "reproduction_steps": ["a"]}, [ex])
    assert "## X" in md and "s=secret" not in md


# ── surface: inventory + openapi (scope-safe host pin) ───────────
def test_surface_inventory_dedup():
    inv = surface.build_inventory([
        "https://h/a?id=1", "https://h/a?id=2&x=3", "https://h/b"])
    a = next(e for e in inv if e["path"] == "/a")
    assert set(a["params"]) == {"id", "x"} and a["parameterized"]


def test_openapi_pins_base_host():
    spec = {"servers": [{"url": "https://EVIL.com/api"}],
            "paths": {"/users/{id}": {"get": {"parameters": [{"in": "query", "name": "q"}]}}}}
    eps = surface.endpoints_from_openapi(spec, "https://target.com")
    assert eps and all(e.startswith("https://target.com") for e in eps)
    assert "EVIL.com" not in " ".join(eps)
    assert "/users/1" in eps[0] and "q=test" in eps[0]


# ── replay: mutate / score / access_verdict ──────────────────────
def test_replay_mutate_and_score():
    u, b, extra = replay.mutate("https://t/a?id=1", "", "id", "query", "9")
    assert "id=9" in u
    base = {"status": 200, "length": 100, "duration_ms": 10}
    hit = {"status": 500, "length": 400, "error_signatures": ["sql syntax"], "duration_ms": 10}
    assert replay.score_result(base, hit) >= 7


def test_access_verdict_flags_bola():
    res = [
        {"role": "userA", "status": 200, "length": 500, "is_owner": True},
        {"role": "userB", "status": 200, "length": 505, "is_owner": False},
    ]
    v = replay.access_verdict(res)
    assert v["anomaly"] and "userB" in v["flags"]


def test_access_verdict_intact_when_403():
    res = [
        {"role": "userA", "status": 200, "length": 500, "is_owner": True},
        {"role": "userB", "status": 403, "length": 0, "is_owner": False},
    ]
    assert not replay.access_verdict(res)["anomaly"]


# ── web_security: probes + scope + sensitive-path validation ─────
def test_traversal_probes_only_pathlike_params():
    probes = ws.build_traversal_probes("https://t/a?file=x.txt&id=1")
    assert probes and all(p.parameter == "file" for p in probes)


def test_idor_probes_numeric_only():
    probes = ws.build_idor_probes("https://t/a?id=5&name=bob")
    payloads = {p.payload for p in probes}
    assert "6" in payloads and "4" in payloads


def test_is_url_in_scope_out_rule_wins():
    rules = {"in_scope": [{"identifier": "example.com"}],
             "out_of_scope": [{"identifier": "internal.example.com"}]}
    assert ws.is_url_in_scope("https://api.example.com/x", "https://example.com", rules)
    assert not ws.is_url_in_scope("https://internal.example.com/x", "https://example.com", rules)


def test_sensitive_path_requires_real_body():
    # generic SPA shell for /.env must be suppressed
    spa = '<html><div id="root"></div></html>'
    assert ws.classify_sensitive_path_hit("/.env", 200, spa) is None
    real = "DB_PASSWORD=hunter2\nAPI_KEY=abcdef"
    hit = ws.classify_sensitive_path_hit("/.env", 200, real)
    assert hit and hit["severity"] == "high"
    # catch-all baseline suppresses even a matching-looking path
    assert ws.classify_sensitive_path_hit("/backup.zip", 200, "x" * 200, baseline_body="x" * 200) is None


# ── guidance: rule engine over a recon context ───────────────────
def test_guidance_emits_playbooks():
    recon = {
        "target": "example.com", "domain": "example.com",
        "http": {"ok": True, "is_https": True, "final_url": "https://example.com",
                 "headers": {"Set-Cookie": "sid=x"}},
        "live_hosts": [{"url": "https://example.com", "tech": ["wordpress"], "title": "Blog"}],
        "dir_bust": {"https://example.com": [{"url": "https://example.com/.git/HEAD"}]},
        "nmap": {"open_ports": ["6379/tcp open redis"]},
    }
    g = guidance.build_guidance(recon)
    keys = {x["key"] for x in g}
    assert any(k.startswith("path-") for k in keys)   # .git path rule
    assert "port-redis" in keys                        # redis port rule
    assert any("param-" in k for k in keys)            # injection surface
    # each playbook carries the required advisory fields
    for x in g[:5]:
        assert x["what_to_test"] and "confidence" in x and "tools" in x


# ── triage: advisory only, chains, cwe mapping ───────────────────
def test_triage_maps_cwe_and_never_hides():
    findings = [
        {"id": "1", "title": "SQL injection in id", "severity": "high", "target": "https://h/a"},
        {"id": "2", "title": "Reflected XSS", "severity": "medium", "target": "https://h/b"},
    ]
    out = triage.triage(findings)
    assert out["annotations"]["1"]["cwe"] == "CWE-89"
    assert out["chains"] and out["chains"][0]["host"] == "h"
    # advisory only: no finding removed, no severity changed
    assert len(findings) == 2 and findings[0]["severity"] == "high"


# ── report: html escaping + formats ──────────────────────────────
def test_report_html_escapes_fields():
    f = [{"id": "1", "title": "<script>alert(1)</script>", "severity": "high",
          "target": "https://t/x", "description": "d"}]
    html = report.generate_html_report("P", f, {"in_scope": ["t"]})
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    csv = report.findings_csv(f)
    assert csv.splitlines()[0].startswith("title,severity")


# ── db: persistence + at-rest redaction ──────────────────────────
def test_db_roundtrip_and_redaction():
    d = tempfile.mkdtemp()
    db.init(os.path.join(d, "t.db"))
    db.create_mission("m1", "P", "active", "obj", {"in_scope": ["t"]}, {})
    fid = db.add_finding("m1", {"title": "F", "severity": "high"})
    assert db.get_findings("m1")[0]["id"] == fid
    db.add_exchange("m1", {"url": "https://t/x", "request_headers": {"Authorization": "Bearer z"}})
    ex = db.get_exchanges("m1")[0]
    assert ex["request_headers"]["Authorization"] == poc.REDACTED   # redacted at rest
    pid = db.add_profile("m1", "userA", "", {"Cookie": "s=1"}, True)
    assert db.get_profiles("m1")[0]["headers"]["Cookie"] == poc.REDACTED
    assert db.get_profiles_raw("m1")[0]["headers"]["Cookie"] == "s=1"
    assert db.list_missions()[0]["id"] == "m1"


# ── dns_recon: SPF/DMARC/vendors + takeover fingerprints ─────────
def test_dns_parsers():
    assert dns_recon.parse_spf(['"v=spf1 include:_spf.google.com ~all"']).startswith("v=spf1")
    assert not dns_recon.parse_spf(['"random"'])
    assert "p=none" in dns_recon.parse_dmarc(['"v=DMARC1; p=none"']).lower()
    vendors = dns_recon.vendors_from_txt(['"stripe-verification=abc"', '"google-site-verification=x"'])
    assert "Stripe" in vendors and "Google Workspace" in vendors


def test_takeover_matcher_requires_cname_and_signature():
    # CNAME to GitHub Pages + unclaimed body -> critical candidate
    hit = dns_recon.match_takeover("sub.example.com", "user.github.io", 404,
                                   "There isn't a GitHub Pages site here.")
    assert hit and hit["service"] == "GitHub Pages" and hit["severity"] == "CRITICAL"
    # CNAME to a provider but a normal 200 body -> no takeover
    assert dns_recon.match_takeover("sub.example.com", "user.github.io", 200, "<html>real site</html>") is None
    # unrelated CNAME -> no match
    assert dns_recon.match_takeover("sub.example.com", "cdn.cloudflare.net", 404, "nope") is None


# ── injection-probe verdict helpers ──────────────────────────────
def test_cors_verdict():
    origin = "https://bbh-evil.example"
    v = ws.analyze_cors(origin, {"Access-Control-Allow-Origin": origin,
                                 "Access-Control-Allow-Credentials": "true"})
    assert v and v["severity"] == "HIGH" and v["credentials"]
    assert ws.analyze_cors(origin, {"Access-Control-Allow-Origin": "https://legit.com"}) is None


def test_open_redirect_and_host_header_and_ssti():
    assert ws.analyze_open_redirect(302, "https://bbh-evil.example/x", "")["severity"] == "MEDIUM"
    assert ws.analyze_open_redirect(200, "", "https://legit.com") is None
    assert ws.analyze_host_header("", "https://bbh-evil.example/reset")["severity"] == "MEDIUM"
    assert ws.analyze_host_header("clean body", "") is None
    assert ws.analyze_ssti("result is ", "result is 49")["severity"] == "HIGH"
    assert ws.analyze_ssti("has 49 already", "has 49 already") is None   # not introduced by us


def test_redirect_and_ssti_probe_builders():
    rp = ws.build_redirect_probes("https://t/go?next=/home&id=1")
    assert rp and all(p.parameter == "next" for p in rp)
    sp = ws.build_ssti_probes("https://t/hello?name=bob")
    assert sp and any("7*7" in p.payload for p in sp)


def test_guidance_email_caa_takeover_now_fire():
    # the new recon data lights up the email / caa / takeover guidance rules
    recon = {
        "target": "example.com", "domain": "example.com",
        "email": {"spf": "", "dmarc": ""},          # both missing -> spoofing finding
        "caa_records": [],                           # none -> caa finding
        "takeover_candidates": [
            {"subdomain": "old.example.com", "severity": "CRITICAL", "reason": "dangling CNAME"}],
        "misc": [{"type": "CORS Misconfiguration", "url": "https://api.example.com/me",
                  "severity": "HIGH", "detail": "reflected origin"}],
    }
    keys = {g["key"] for g in guidance.build_guidance(recon)}
    assert "email-spoof" in keys and "caa-missing" in keys
    assert "takeover" in keys and "cors" in keys


# ── auth: heuristic login-form parsing ───────────────────────────
def test_parse_login_form_finds_fields_and_csrf():
    html = """
    <form action="/session" method="post">
      <input type="hidden" name="csrf_token" value="abc123">
      <input type="email" name="email">
      <input type="password" name="password">
      <button type="submit">Log in</button>
    </form>"""
    form = auth.parse_login_form(html, "https://app.example.com/login")
    assert form["action"] == "https://app.example.com/session"
    assert form["user_field"] == "email" and form["pass_field"] == "password"
    assert form["hidden"]["csrf_token"] == "abc123"


def test_parse_login_form_none_without_password():
    assert auth.parse_login_form("<form><input name='q'></form>", "https://x") is None


# ── zap_client: scope regex + alert mapping ──────────────────────
def test_zap_include_regexes_match_scope():
    eng = scope_mod.ScopeEngine(); eng.load_manual(["*.example.com", "api.test.com"], [], "P")
    rxs = zap_client.include_regexes(eng)
    assert any(re.match(rx, "https://foo.example.com/x") for rx in rxs)
    assert any(re.match(rx, "http://api.test.com:8443/v1") for rx in rxs)
    assert not any(re.match(rx, "https://evil.com/x") for rx in rxs)


def test_zap_alert_to_finding_and_dedup():
    alert = {"alert": "SQL Injection", "risk": "High", "url": "https://t/a?id=1",
             "param": "id", "cweid": "89", "solution": "Use params", "evidence": "syntax error",
             "description": "..."}
    f = zap_client.alert_to_finding(alert)
    assert f["severity"] == "high" and f["cwe"] == "CWE-89" and f["found_by"] == "zap"
    assert "id" in f["reproduction_steps"][0]
    assert zap_client.risk_to_severity("Informational") == "informational"
    dup = [alert, dict(alert), {"alert": "XSS", "url": "https://t/b", "param": ""}]
    assert len(zap_client.dedup_alerts(dup)) == 2


def test_zap_not_configured_by_default():
    # ZAP_ADDR unset in the test env -> the tool must skip cleanly, never error
    assert zap_client.configured() is False


def test_zap_client_issues_expected_api_calls():
    calls = []

    class _Client(zap_client.ZapClient):
        async def _call(self, component, kind, action, **params):
            calls.append((component, kind, action, params))
            return {"scan": "1"}

    async def go():
        c = _Client(addr="http://zap:8090", api_key="k")
        await c.ascan("https://t/a", context_id="2", policy="My Policy")
        await c.set_injectable()
        await c.add_scan_header()
        await c.set_oast_service("BOAST")

    asyncio.get_event_loop().run_until_complete(go())
    ascan = next(x for x in calls if x[2] == "scan")
    assert ascan[3]["scanPolicyName"] == "My Policy" and ascan[3]["inScopeOnly"] == "true"
    inj = next(x for x in calls if x[2] == "setOptionTargetParamsInjectable")
    assert inj[3]["Integer"] == 27
    rep = next(x for x in calls if x[0] == "replacer" and x[2] == "addRule")
    assert rep[3]["matchType"] == "REQ_HEADER"
    oast = next(x for x in calls if x[0] == "oast")
    assert oast[2] == "setActiveScanServiceForOast" and oast[3]["name"] == "BOAST"


# ── graphql_tool: introspection parse + abuse signals ────────────
def test_graphql_endpoint_candidates_and_detection():
    cands = gql.endpoint_candidates("https://api.example.com/")
    assert "https://api.example.com/graphql" in cands
    assert gql.looks_like_graphql({"data": {"__typename": "Query"}})
    assert gql.looks_like_graphql({"errors": [{"message": "x"}]})
    assert not gql.looks_like_graphql({"random": 1})


def test_graphql_parse_schema_roots():
    resp = {"data": {"__schema": {
        "queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"},
        "subscriptionType": None,
        "types": [
            {"name": "Query", "fields": [{"name": "allLifts"}, {"name": "Lift"}]},
            {"name": "Mutation", "fields": [{"name": "setLiftStatus"}]},
            {"name": "__Type", "fields": []},
        ]}}}
    s = gql.parse_schema(resp)
    assert s["introspection"] and s["query_fields"] == ["allLifts", "Lift"]
    assert s["mutation_fields"] == ["setLiftStatus"] and s["type_count"] == 2


def test_graphql_abuse_signals():
    assert gql.detect_batching([{}, {}, {}], 3) and not gql.detect_batching({"data": {}}, 3)
    assert gql.detect_field_suggestion({"errors": [{"message": "Cannot query field x. Did you mean y?"}]})
    assert not gql.detect_field_suggestion({"errors": [{"message": "syntax error"}]})


def test_graphql_analyze_emits_findings():
    intro = {"data": {"__schema": {"queryType": {"name": "Query"}, "mutationType": None,
             "subscriptionType": None, "types": [{"name": "Query", "fields": [{"name": "me"}]}]}}}
    batch = [{"data": {}}] * 5
    f = gql.analyze("https://t/graphql", intro, batch, 5, {})
    keys = {x["title"] for x in f}
    assert "GraphQL introspection enabled" in keys
    assert "GraphQL request batching enabled" in keys
    # introspection disabled but suggestions leak -> low finding instead
    f2 = gql.analyze("https://t/graphql", {"errors": [{"message": "no"}]}, {"data": {}}, 5,
                     {"errors": [{"message": "Did you mean me?"}]})
    assert any(x["title"] == "GraphQL field suggestions leak schema" for x in f2)


# ── jwt_tool: decode, none, crack, forge ─────────────────────────
def test_jwt_decode_and_none():
    # {"alg":"none"} . {"user":"guest","admin":false} . (no sig)
    tok = jt.forge_none({"user": "guest", "admin": False})
    d = jt.decode_jwt(tok)
    assert d and d["header"]["alg"] == "none" and d["payload"]["user"] == "guest"
    res = jt.analyze(tok)
    assert any(f["title"].startswith("JWT signed with alg:none") for f in res["findings"])


def test_jwt_crack_and_forge_roundtrip():
    # forge a real HS256 token with a weak secret, then confirm the tool cracks it
    secret = "changeme"
    token = jt.forge_hs({"typ": "JWT"}, {"iss": "https://crapi.example", "sub": "a@x.com",
                                         "role": "user", "exp": 9999999999}, secret, "HS256")
    assert jt.verify_hs(token, secret)
    res = jt.analyze(token)
    assert res["cracked_secret"] == "changeme"
    # forged admin token must verify under the recovered secret and carry admin
    assert jt.verify_hs(res["forged_admin"], secret)
    assert jt.decode_jwt(res["forged_admin"])["payload"]["admin"] is True
    titles = {f["title"] for f in res["findings"]}
    assert "JWT signing secret is weak/crackable" in titles


def test_jwt_crack_derives_secret_from_issuer():
    # secret == issuer host root ("snowtooth") — must be found via candidate_secrets
    token = jt.forge_hs({}, {"iss": "https://snowtooth.example/"}, "snowtooth", "HS512")
    assert jt.crack_secret(token, jt.candidate_secrets(jt.decode_jwt(token)["payload"])) == "snowtooth"


def test_jwt_strong_secret_not_cracked():
    token = jt.forge_hs({}, {"sub": "x"}, "M9x!q2Zr7_Lp03Vw-uKf8Nb6Ty1Ce4A", "HS256")
    assert jt.analyze(token)["cracked_secret"] is None


# ── authz_tool: BFLA method testing + side-channel BOLA ──────────
def test_bfla_flags_write_method_not_public():
    mr = {"GET": {"status": 200, "length": 100}, "PUT": {"status": 200, "length": 50},
          "DELETE": {"status": 204, "length": 0}}
    anon = {"GET": {"status": 200, "length": 100}}   # GET is public; writes are not
    f = authz.analyze_methods("https://t/api/picture/2", mr, anon)
    titles = {x["title"] for x in f}
    assert "Broken function-level authorization (PUT)" in titles
    assert "Broken function-level authorization (DELETE)" in titles
    # a write method that is also public (anon 2xx) is NOT flagged
    f2 = authz.analyze_methods("https://t/x", {"POST": {"status": 200}}, {"POST": {"status": 200}})
    assert f2 == []


def test_bfla_admin_path_get():
    f = authz.analyze_methods("https://t/api/admin/find/user", {"GET": {"status": 200, "length": 80}}, {})
    assert any(x["title"] == "Admin endpoint reachable by non-admin token" for x in f)
    assert not authz.is_admin_path("https://t/api/user/2")


def test_side_channel_oracle():
    # nonexistent -> 404, existing-unauthorized -> 403  => distinguishable
    f = authz.analyze_side_channel({"status": 404, "length": 20}, {"status": 403, "length": 20})
    assert f and f[0]["title"].startswith("Side-channel BOLA")
    # both 404 => no oracle
    assert authz.analyze_side_channel({"status": 404, "length": 20}, {"status": 404, "length": 20}) == []


# ── race_tool: parallel-request race condition ───────────────────
def test_race_without_verify_is_conservative_candidate():
    # 3 of 10 accepted, but no state proof -> stays a candidate, NOT high/critical
    results = [{"status": 200, "length": 50}] * 3 + [{"status": 409, "length": 10}] * 7
    f = race.analyze_race("https://t/api/coupon/redeem", results, 10)
    assert f and f[0]["confidence"] == "candidate"
    assert f[0]["severity"] in ("low", "medium")
    assert f[0]["title"].endswith("candidate")


def test_race_confirmed_by_state_change():
    # same successes, but a verify request proves the balance jumped -> confirmed
    results = [{"status": 200, "length": 50}] * 3 + [{"status": 409}] * 7
    verify = race.verify_delta({"body": "balance: 500", "length": 12},
                               {"body": "balance: 2000", "length": 13})
    assert verify["changed"] and verify["max_numeric_jump"] == 1500
    f = race.analyze_race("https://t/transfer", results, 10, verify=verify)
    assert f[0]["confidence"] == "confirmed" and f[0]["severity"] == "critical"
    assert f[0]["title"] == "Race condition (TOCTOU)"   # no "candidate" suffix


def test_race_no_flag_on_single_success():
    results = [{"status": 200, "length": 50}] + [{"status": 409, "length": 10}] * 9
    assert race.analyze_race("https://t/x", results, 10) == []


def test_verify_delta_no_change():
    v = race.verify_delta({"body": "balance: 500", "length": 12},
                          {"body": "balance: 500", "length": 12})
    assert v["available"] and not v["changed"]


def test_race_best_round_picks_most_successes():
    r1 = [{"status": 200}] + [{"status": 409}] * 4
    r2 = [{"status": 200}] * 3 + [{"status": 409}] * 2   # best round
    r3 = [{"status": 409}] * 5
    best = race.best_round([r1, r2, r3])
    assert race.summarize(best)["successes"] == 3


# ── xss_tool: context detection + breakout exploitability ────────
def test_xss_context_detection():
    c = xt.CANARY
    assert xt.contexts_of(f"<p>hello {c} world</p>") == ["html"]
    assert xt.contexts_of(f'<input value="{c}">') == ["attr_dq"]
    assert xt.contexts_of(f"<input value='{c}'>") == ["attr_sq"]
    assert xt.contexts_of(f"<script>var x='{c}';</script>") == ["script"]
    assert xt.contexts_of(f"<!-- {c} -->") == ["comment"]


def test_xss_reflected_exploitable_needs_unescaped_breakout():
    body_vuln = f"<p>you searched {xt.BREAKOUTS['html']}</p>"
    assert xt.reflected_exploitable(body_vuln, "html")
    # same input HTML-escaped -> NOT exploitable (the whole point)
    body_safe = "<p>you searched &lt;bbhx7h&gt;</p>"
    assert not xt.reflected_exploitable(body_safe, "html")
    assert xt.reflected_exploitable(f'<input value="{xt.BREAKOUTS["attr_dq"]}">', "attr_dq")


def test_xss_set_param_and_fragment():
    out = xt.set_param("https://t/s?q=1&z=2", "q", "<x>")
    assert "q=%3Cx%3E" in out or "q=<x>" in out
    assert xt.set_fragment("https://t/p?a=1", "<img>").endswith("#<img>")


# ── codereview: secrets / sinks / comments / endpoints ───────────
def test_codereview_finds_secrets():
    # the exact hardcoded GitHub token from Bug Bounty Bootcamp Ch 22
    src = 'GITHUB_ACCESS_TOKEN = "0518fb3b4f52a1494576eee7ed7c75ae8948ce70"\n'
    types = {s["type"] for s in cr.scan_secrets(src)}
    assert any("GitHub" in t for t in types)
    # AWS key + generic assignment
    aws = cr.scan_secrets('const k = "AKIAIOSFODNN7EXAMPLE"; api_key: "s3cr3tValue123"')
    assert any(s["type"] == "AWS access key id" for s in aws)
    assert any("api_key" in s["type"] for s in aws)
    # placeholder must NOT be flagged
    assert cr.scan_secrets('password = "your_password_here"') == []
    # redaction: full secret not echoed
    assert all("0518fb3b4f52" not in s["match"] for s in cr.scan_secrets(src))


def test_codereview_finds_sinks_and_crypto():
    sinks = {s["sink"] for s in cr.scan_sinks("el.innerHTML = userInput; eval(x); unserialize($_COOKIE['d']);")}
    assert "innerHTML =" in sinks and "eval()" in sinks and "unserialize()" in sinks
    assert any(w["algorithm"] == "MD5" for w in cr.scan_weak_crypto("hash = md5(password)"))


def test_codereview_dev_comments_and_endpoints():
    c = cr.scan_comments("// todo: Implement CSRF protection on the change_password endpoint\ncode();")
    assert c and "csrf" in c[0]["comment"].lower()
    eps = cr.extract_endpoints('fetch("/api/v1/users"); var u="https://api.example.com/new_password";')
    assert "/api/v1/users" in eps and "https://api.example.com/new_password" in eps


def test_codereview_review_bundles_findings():
    src = ('const T="ghp_' + "a" * 36 + '"; el.innerHTML=x; // FIXME insecure hardcoded token\n'
           'fetch("/api/admin/delete");')
    res = cr.review(src, "https://t/app.js")
    titles = {f["title"] for f in res["findings"]}
    assert any("Hardcoded secret" in t for t in titles)
    assert any("Dangerous sink" in t for t in titles)
    assert "/api/admin/delete" in res["endpoints"]


# ── csrf_tool: form/token/SameSite analysis ──────────────────────
def test_csrf_parse_forms_and_token_detection():
    html = ('<form method="POST" action="/change_password">'
            '<input name="new_password"><input type="submit"></form>'
            '<form method="post" action="/send"><input name="csrf_token" value="x">'
            '<input name="msg"></form>')
    forms = csrf.parse_forms(html, "https://email.example.com/")
    pw = next(f for f in forms if "change_password" in f["action"])
    assert pw["method"] == "POST" and not pw["has_token"]
    send = next(f for f in forms if f["action"].endswith("/send"))
    assert send["has_token"]


def test_csrf_samesite_parse():
    assert csrf.parse_samesite("PHPSESSID=x; Secure; HttpOnly; SameSite=Strict") == "strict"
    assert csrf.parse_samesite("sid=x; SameSite=None") == "none"
    assert csrf.parse_samesite("sid=x; HttpOnly") == ""


def test_csrf_analyze_grades_by_samesite():
    forms = csrf.parse_forms('<form method="POST" action="/change_password"><input name="new_password"></form>',
                             "https://t/")
    # SameSite=None -> exploitable in all browsers -> high (sensitive action)
    high = csrf.analyze(forms, "sid=x; SameSite=None", "https://t/p")
    assert high and high[0]["severity"] == "high" and high[0]["cwe"] == "CWE-352"
    # token-protected form -> nothing
    ok = csrf.parse_forms('<form method="POST" action="/x"><input name="csrf_token"></form>', "https://t/")
    assert csrf.analyze(ok, "sid=x; SameSite=None", "https://t/p") == []
    # sensitive GET state change -> flagged even with strict cookie
    getf = csrf.parse_forms('<form method="GET" action="/password_change"><input name="new_password"></form>', "https://t/")
    g = csrf.analyze(getf, "sid=x; SameSite=Strict", "https://t/p")
    assert g and "GET" in g[0]["title"]


# ── fingerprint: headers / cookies / HTML signatures ─────────────
def test_fingerprint_headers_and_cookies():
    # the exact headers from Bug Bounty Bootcamp Ch 5
    techs = fp.fingerprint(
        {"Server": "Apache/2.0.6 (Ubuntu)", "X-Powered-By": "PHP/5.0.1", "X-Generator": "Drupal 8"},
        "PHPSESSID=abcde;", "")
    names = {t["name"] for t in techs}
    assert "Apache" in names and "PHP" in names
    apache = next(t for t in techs if t["name"] == "Apache")
    assert apache["version"] == "2.0.6"
    php = next(t for t in techs if t["name"] == "PHP")
    assert php["version"] == "5.0.1"
    # version disclosures surface for CVE lookup
    vd = {t["name"] for t in fp.version_disclosures(techs)}
    assert "Apache" in vd and "PHP" in vd


def test_fingerprint_body_signatures():
    techs = fp.fingerprint({}, "", '<meta name="generator" content="WordPress 6.1">'
                           '<script src="/js/jquery-3.6.0.min.js"></script><div class="wp-content">')
    names = {t["name"] for t in techs}
    assert "WordPress" in names and "jQuery" in names
    jq = next(t for t in techs if t["name"] == "jQuery")
    assert jq["version"] == "3.6.0"


def test_fingerprint_dedup_and_empty():
    assert fp.fingerprint({}, "", "") == []
    techs = fp.fingerprint({"Server": "nginx"}, "JSESSIONID=x", "")
    assert any(t["name"] == "Java/JSP" for t in techs) and any(t["name"] == "nginx" for t in techs)


def test_cymru_asn_parse():
    info = dns_recon.parse_cymru_asn('"32934 | 157.240.0.0/16 | US | arin | 2015-05-14"')
    assert info["asn"] == "32934" and info["prefix"] == "157.240.0.0/16" and info["country"] == "US"
    assert dns_recon.parse_cymru_asname('"32934 | US | arin | 2015 | FACEBOOK, US"') == "FACEBOOK, US"


# ── ssrf_tool: metadata reflection + blind port oracle ───────────
def test_ssrf_params_prefers_url_ish():
    ps = ssrf.ssrf_params("https://t/fetch?url=x&note=hi&image_url=y")
    assert ps == ["url", "image_url"]          # note is dropped, url-ish kept
    # no url-ish param -> fall back to every parameter
    assert ssrf.ssrf_params("https://t/a?q=1&z=2") == ["q", "z"]


def test_ssrf_reflection_detects_aws_metadata_not_echo():
    body = ('{"Code" : "Success", "AccessKeyId" : "ASIA...", "SecretAccessKey" : "x", '
            '"Token" : "y", "instance-id" : "i-0abc"}')
    hit = ssrf.analyze_reflection(body, "http://169.254.169.254/latest/meta-data/iam/security-credentials/")
    assert hit and hit["cloud"] == "AWS" and "AccessKeyId" in hit["matched"]


def test_ssrf_reflection_no_false_positive_on_echoed_url():
    # the app merely reflects the injected URL — must NOT be treated as a hit
    payload = "http://169.254.169.254/latest/meta-data/"
    assert ssrf.analyze_reflection(f"You requested: {payload} (blocked)", payload) is None
    assert ssrf.analyze_reflection("<html>normal page</html>", payload) is None


def test_ssrf_blind_status_and_connect_and_timing_oracles():
    # status differential
    s = ssrf.analyze_blind({"status": 200, "error": False, "elapsed": 0.1},
                           {"status": 502, "error": False, "elapsed": 0.1})
    assert s and s["kind"] == "status"
    # connect differential (open answers, closed errors)
    s = ssrf.analyze_blind({"status": 200, "error": False, "elapsed": 0.1},
                           {"status": 0, "error": True, "elapsed": 0.1})
    assert s and s["kind"] == "connect"
    # timing oracle (closed hangs to timeout)
    s = ssrf.analyze_blind({"status": 200, "error": False, "elapsed": 0.2},
                           {"status": 200, "error": False, "elapsed": 5.0})
    assert s and s["kind"] == "timing"
    # identical behavior -> no oracle (conservative)
    assert ssrf.analyze_blind({"status": 200, "error": False, "elapsed": 0.2},
                              {"status": 200, "error": False, "elapsed": 0.2}) is None


def test_ssrf_bypass_payloads_encode_loopback_and_metadata_ip():
    pl = ssrf.bypass_payloads()
    assert "http://2130706433/" in pl            # 127.0.0.1 as a dword
    assert "http://0x7f000001/" in pl            # 127.0.0.1 as hex
    assert "http://[::1]/" in pl                 # IPv6 loopback
    assert any("2852039166" in p for p in pl)    # 169.254.169.254 as a dword


def test_ssrf_findings_are_shaped_for_the_report():
    rf = ssrf.reflection_finding("https://t/fetch?url=x", "url",
                                 "http://169.254.169.254/latest/meta-data/", "AWS", ["AccessKeyId"])
    assert rf["severity"] == "critical" and rf["cwe"] == "CWE-918" and rf["confidence"] == "confirmed"
    assert "169.254.169.254" in rf["target"]
    bf = ssrf.blind_finding("https://t/fetch?url=x", "url", "http://127.0.0.1:80/",
                            "http://127.0.0.1:1/", {"reason": "r", "confidence": "confirmed"})
    assert bf["severity"] == "high" and "blind" in bf["tags"]


# ── deser_tool: serialized-object detection + sink confirmation ──
def test_deser_detects_php_java_pickle_dotnet_ruby():
    import base64, pickle
    assert deser.detect_format('O:4:"User":1:{s:4:"name";s:5:"admin";}')["format"] == "PHP"
    # Java ObjectInputStream -> base64 starts rO0AB
    java = base64.b64encode(b"\xac\xed\x00\x05stuff").decode()
    assert deser.detect_format(java)["format"] == "Java" and java.startswith("rO0")
    py = base64.b64encode(pickle.dumps({"user": "guest"})).decode()
    assert deser.detect_format(py)["format"] == "Python pickle"
    net = base64.b64encode(b"\x00\x01\x00\x00\x00\xff\xff\xff\xffmore").decode()
    assert deser.detect_format(net)["format"] == ".NET"
    ruby = base64.b64encode(b"\x04\x08{\x06").decode()
    assert deser.detect_format(ruby)["format"] == "Ruby Marshal"


def test_deser_ignores_plain_values():
    assert deser.detect_format("hello world") is None
    assert deser.detect_format("eyJhbGciOiJIUzI1NiJ9") is None   # a JWT header, not serialized
    assert deser.detect_format("12345") is None


def test_deser_find_inputs_across_query_and_cookies():
    import base64, pickle
    py = base64.b64encode(pickle.dumps([1, 2, 3])).decode()
    found = deser.find_serialized_inputs({"q": "x", "data": py}, {"sess": 'a:0:{}'})
    locs = {(f["location"], f["name"], f["format"]) for f in found}
    assert ("query", "data", "Python pickle") in locs
    assert ("cookie", "sess", "PHP") in locs


def test_deser_corrupt_changes_blob_and_stays_base64():
    import base64, pickle
    py = base64.b64encode(pickle.dumps({"a": 1})).decode()
    bad = deser.corrupt(py, {"encoding": "base64"})
    assert bad != py
    # a corrupted pickle must not re-load cleanly
    import pytest
    with pytest.raises(Exception):
        pickle.loads(base64.b64decode(bad + "=" * (-len(bad) % 4)))


def test_deser_error_signature_only_when_new():
    base = "welcome back"
    probe = "Traceback ... _pickle.UnpicklingError: pickle data was truncated"
    hits = deser.analyze_errors(base, probe, "Python pickle")
    assert any("Unpickling" in h for h in hits)
    # if the baseline already showed it, it is not a new signal
    assert deser.analyze_errors(probe, probe, "Python pickle") == []


# ── oauth_tool: SSO / OAuth redirect_uri + state + token leak ────
def test_oauth_parse_and_detect():
    info = oauth.parse_authorize("https://sso.t/oauth/authorize?client_id=abc&redirect_uri=https://c.t/cb&"
                                 "response_type=code&state=xyz")
    assert info["is_oauth"] and info["endpoint"] == "https://sso.t/oauth/authorize"
    assert info["redirect_uri"] == "https://c.t/cb" and info["state"] == "xyz"
    assert oauth.parse_authorize("https://t/home?x=1")["is_oauth"] is False


def test_oauth_redirect_variants_target_attacker():
    vs = oauth.redirect_uri_variants("https://client.t/callback")
    kinds = {v["name"] for v in vs}
    assert {"external host", "subdomain suffix", "@-userinfo", "open-redirect chain"} <= kinds
    assert all(oauth.EVIL_HOST in v["value"] for v in vs)


def test_oauth_analyze_redirect_host_vs_chain():
    host = oauth.analyze_redirect_response(302, f"https://{oauth.EVIL_HOST}/callback?code=AAA")
    assert host and host["accepted"] == "host"
    sub = oauth.analyze_redirect_response(302, f"https://client.t.{oauth.EVIL_HOST}/cb?code=AAA")
    assert sub and sub["accepted"] == "host"
    chain = oauth.analyze_redirect_response(302, f"https://client.t/redirect?url=https://{oauth.EVIL_HOST}/&code=A")
    assert chain and chain["accepted"] == "chain"
    # a proper server that redirects back to the legit client is not a hit
    assert oauth.analyze_redirect_response(302, "https://client.t/callback?code=AAA") is None
    assert oauth.analyze_redirect_response(400, "") is None


def test_oauth_state_and_token_oracles():
    assert oauth.analyze_state(302, "https://client.t/cb?code=AAA") is True
    assert oauth.analyze_state(302, "https://client.t/cb?error=invalid") is False
    assert oauth.analyze_token_leak(302, "https://client.t/cb#access_token=xyz&token_type=bearer") is True
    assert oauth.analyze_token_leak(302, "https://client.t/cb?code=AAA") is False


def test_oauth_findings_shape():
    f = oauth.redirect_finding("https://sso.t/authorize",
                               [{"name": "@-userinfo", "location": f"https://{oauth.EVIL_HOST}/cb?code=1"}])
    assert f["severity"] == "critical" and f["cwe"] == "CWE-601" and f["confidence"] == "confirmed"


# ── exposure_tool: information-disclosure file checks ────────────
def _check(path):
    return next(c for c in exp.EXPOSURE_CHECKS if c["path"] == path)


def test_exposure_confirms_git_config_by_signature():
    body = "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = git@x:y.git\n"
    f = exp.classify(_check(".git/config"), 200, body, "text/plain", "not found")
    assert f and f["family"] == "git_exposure" and f["cwe"] == "CWE-527" and f["confidence"] == "confirmed"


def test_exposure_confirms_dotenv_and_aws():
    env = exp.classify(_check(".env"), 200, "APP_KEY=base64:abc\nDB_PASSWORD=secret\n", "text/plain", "")
    assert env and env["severity"] == "critical"
    aws = exp.classify(_check(".aws/credentials"), 200,
                       "[default]\naws_access_key_id = AKIA...\naws_secret_access_key = x\n", "", "")
    assert aws and aws["family"] == "credential_exposure"


def test_exposure_no_false_positive_on_catchall_and_404():
    spa = "<!doctype html><title>App</title><div id=root></div>"
    # catch-all 200 returning the SPA for every path -> no signature -> no hit
    assert exp.classify(_check(".env"), 200, spa, "text/html", spa) is None
    assert exp.classify(_check(".git/config"), 200, spa, "text/html", "") is None
    # 404 with the real content is still not a positive
    assert exp.classify(_check(".git/config"), 404, "[core]", "text/plain", "") is None


def test_exposure_git_reconstruct_finding():
    f = exp.git_reconstruct_finding([".git/HEAD", ".git/config"])
    assert "source recoverable" in f["title"].lower() and f["cwe"] == "CWE-527"


# ── collaborator: native OOB token / correlation ────────────────
def test_collab_probe_url_path_vs_subdomain():
    os.environ.pop("BBH_OOB_DOMAIN", None)
    assert collab.probe_url("abc123", base_url="http://agent:8000") == "http://agent:8000/oob/abc123"
    os.environ["BBH_OOB_DOMAIN"] = "oast.bbh.test"
    try:
        assert collab.probe_url("abc123") == "http://abc123.oast.bbh.test/"
    finally:
        os.environ.pop("BBH_OOB_DOMAIN", None)


def test_collab_token_extraction_path_and_host():
    os.environ.pop("BBH_OOB_DOMAIN", None)
    assert collab.token_from_request("oob/deadbeef/x", "agent:8000") == "deadbeef"
    os.environ["BBH_OOB_DOMAIN"] = "oast.bbh.test"
    try:
        assert collab.token_from_request("/", "cafe1234.oast.bbh.test") == "cafe1234"
    finally:
        os.environ.pop("BBH_OOB_DOMAIN", None)


def test_collab_record_correlates_and_confirms():
    tok = collab.new_token()
    collab.register(tok)
    assert collab.hits(tok) == []
    known = collab.record(tok, {"source_ip": "203.0.113.9", "method": "GET"})
    assert known and len(collab.hits(tok)) == 1
    f = collab.oob_finding("https://t/fetch?url=x", "url", collab.probe_url(tok, "http://a"), collab.hits(tok))
    assert f["confidence"] == "confirmed" and f["cwe"] == "CWE-918" and "203.0.113.9" in f["evidence"]
    collab.clear(tok)
    assert collab.hits(tok) == []


def test_collab_enabled_follows_env():
    os.environ.pop("BBH_OOB_BASE", None)
    assert collab.enabled() is False
    os.environ["BBH_OOB_BASE"] = "http://agent:8000"
    try:
        assert collab.enabled() is True and collab.base() == "http://agent:8000"
    finally:
        os.environ.pop("BBH_OOB_BASE", None)


# ── xxe_tool: external-entity payloads + reflection analysis ─────
def test_xxe_inband_payload_declares_entity_and_reference():
    xml = xxe.build_inband_xml("file:///etc/passwd", '<?xml version="1.0"?>\n<user><name>bob</name></user>')
    assert '<!ENTITY xxe SYSTEM "file:///etc/passwd">' in xml
    assert "&xxe;" in xml and "<!DOCTYPE" in xml


def test_xxe_oob_payload_uses_parameter_entity():
    xml = xxe.build_oob_xml("http://agent:8000/oob/abc123")
    assert "http://agent:8000/oob/abc123" in xml and "% rem" in xml and "%rem;" in xml


def test_xxe_analyze_inband_detects_passwd_not_random():
    body = "<user><name>root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1</name></user>"
    hit = xxe.analyze_inband(body)
    assert hit and hit["file"] == "file:///etc/passwd"
    assert xxe.analyze_inband("<user><name>hello</name></user>") is None


def test_xxe_looks_like_xml():
    assert xxe.looks_like_xml("application/xml", "") is True
    assert xxe.looks_like_xml("application/soap+xml", "") is True
    assert xxe.looks_like_xml("", "<?xml version='1.0'?><a/>") is True
    assert xxe.looks_like_xml("application/json", '{"a":1}') is False


def test_xxe_finding_shapes():
    ib = xxe.inband_finding("https://t/api", "file:///etc/passwd", "root:x:0:0:")
    assert ib["severity"] == "critical" and ib["cwe"] == "CWE-611" and ib["confidence"] == "confirmed"
    ob = xxe.oob_finding("https://t/api", "http://a/oob/t", [{"source_ip": "198.51.100.7"}])
    assert ob["confidence"] == "confirmed" and "198.51.100.7" in ob["evidence"]


# ── github_recon: dork building + secret classification ──────────
def test_ghr_dorks_pair_domain_with_secret_indicators():
    d = ghr.build_dorks("acme.com", org="acme-inc")
    assert any("filename:.env" in q for q in d)
    assert any("aws_access_key_id" in q for q in d)
    assert any("org:acme-inc" in q for q in d)
    assert len(d) == len(set(d))          # deduped


def test_ghr_parse_code_search_extracts_fragments():
    data = {"items": [{"repository": {"full_name": "acme/app"}, "path": "config/.env",
                       "html_url": "https://github.com/acme/app/blob/main/config/.env",
                       "text_matches": [{"fragment": "AWS_KEY=AKIAIOSFODNN7EXAMPLE"}]}]}
    items = ghr.parse_code_search(data)
    assert items[0]["repo"] == "acme/app" and items[0]["fragments"][0].startswith("AWS_KEY=")


def test_ghr_classify_flags_secret_and_redacts():
    item = {"repo": "acme/app", "path": ".env", "url": "https://github.com/acme/app/blob/main/.env",
            "fragments": ["aws_access_key_id = AKIAIOSFODNN7EXAMPLE"]}
    f = ghr.classify_hit(item, "acme.com", '"acme.com" filename:.env')
    assert f and f["cwe"] == "CWE-540" and "github-recon" in f["tags"]
    assert "AKIAIOSFODNN7EXAMPLE" not in f["evidence"]        # redacted, not raw


def test_ghr_sensitive_file_is_a_lead_plain_mention_is_not():
    item = {"repo": "acme/app", "path": ".env", "url": "u", "fragments": ["DOMAIN=acme.com"]}
    assert ghr.classify_hit(item, "acme.com", '"acme.com" filename:.env')["severity"] == "low"
    plain = {"repo": "x/y", "path": "README.md", "url": "u", "fragments": ["see acme.com for info"]}
    assert ghr.classify_hit(plain, "acme.com", '"acme.com"') is None


# ── sqli_tool: error / boolean / time oracles ───────────────────
def test_sqli_error_signature_fingerprints_dbms_and_ignores_baseline():
    base = "<html>results for widget</html>"
    probe = "<html>You have an error in your SQL syntax; check the manual that corresponds to your MySQL</html>"
    hits = sqli.error_signatures(base, probe)
    assert hits and hits[0]["dbms"] == "MySQL"
    # the same signature already in the baseline is not a new signal
    assert sqli.error_signatures(probe, probe) == []


def test_sqli_boolean_true_tracks_baseline_false_diverges():
    base = "Product: Widget (in stock)"
    t = "Product: Widget (in stock)"
    f = "No results found"
    assert sqli.analyze_boolean(base, t, f) is True
    # a param that changes nothing (true==false) is not injectable
    assert sqli.analyze_boolean(base, base, base) is False


def test_sqli_time_oracle_needs_correlated_delay():
    assert sqli.analyze_time(0.2, 5.3, 5) is True         # control fast, sleep slow by ~5s
    assert sqli.analyze_time(0.2, 0.4, 5) is False        # both fast -> not injectable
    assert sqli.analyze_time(4.9, 5.1, 5) is False        # both slow (jitter) -> not correlated


def test_sqli_payloads_embed_value_and_controls():
    bp = sqli.boolean_payloads("7")
    assert any(p["true"].startswith("7") and "1=1" in p["true"] for p in bp)
    tp = sqli.time_payloads("7", 5)
    assert any("SLEEP(5)" in i["payload"] and "SLEEP(0)" in i["control"] for i in tp)
    assert any("pg_sleep(5)" in i["payload"] for i in tp)


def test_sqli_findings_shape():
    ef = sqli.error_finding("https://t/i?id=1", "id", "'", [{"dbms": "SQLite", "pattern": "x"}])
    assert ef["cwe"] == "CWE-89" and ef["confidence"] == "confirmed" and ef["severity"] == "high"
    tf = sqli.time_finding("https://t/i?id=1", "id",
                           {"dbms": "MySQL", "payload": "1' AND SLEEP(5)-- -"}, 0.2, 5.3, 5)
    assert tf["severity"] == "critical" and "time-blind" in tf["tags"]


# ── cmdi_tool: computed-output / time / OOB command injection ────
def test_cmdi_output_hit_only_on_execution_not_echo():
    # the payload contains the arithmetic, NOT the product -> echoing it back is safe
    payload = cmdi.output_payloads("8.8.8.8")[0]["payload"]
    assert cmdi.EXPECTED not in payload
    assert cmdi.analyze_output("ping stats", f"ping stats\n{cmdi.EXPECTED}\n") == \
        {"kind": "computed-echo", "match": cmdi.EXPECTED}
    # a server that just reflects the raw payload must NOT be flagged
    assert cmdi.analyze_output("x", f"you sent: {payload}") is None


def test_cmdi_output_detects_id_and_ignores_baseline():
    body = "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
    assert cmdi.analyze_output("home", body)["kind"] == "command-output"
    assert cmdi.analyze_output(body, body) is None       # already in baseline -> not new


def test_cmdi_time_oracle_correlates():
    assert cmdi.analyze_time(0.1, 5.2, 5) is True
    assert cmdi.analyze_time(0.1, 0.3, 5) is False
    assert cmdi.analyze_time(4.8, 5.0, 5) is False        # both slow (jitter)


def test_cmdi_payloads_cover_separators_and_oob():
    tp = cmdi.time_payloads("x", 5)
    assert any("; sleep 5" in i["payload"] for i in tp) and any("`sleep 5`" in i["payload"] for i in tp)
    assert any("ping -n 6" in i["payload"] for i in tp)   # windows
    oob = cmdi.oob_payloads("x", "http://c/oob/t")
    assert any("curl -s http://c/oob/t" in p for p in oob)


def test_cmdi_finding_shapes():
    of = cmdi.output_finding("https://t/p?host=1", "host", "1; id", {"kind": "command-output", "match": "uid=0"})
    assert of["cwe"] == "CWE-78" and of["severity"] == "critical" and "rce" in of["tags"]


# ── AI config resolution + credential preflight + secret safety ──
_AI_ENV = ("AI_PROVIDER", "AI_API_KEY", "AI_MODEL", "AI_BASE_URL", "OPENROUTER_API_KEY",
           "OPENROUTER_MODEL", "ANTHROPIC_API_KEY", "ANTHROPIC_MODEL")


def _env_snapshot():
    return {k: os.environ.get(k) for k in _AI_ENV}


def _env_restore(snap):
    for k, v in snap.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def test_resolve_ai_config_precedence_and_generic_fallback():
    import agent as agmod
    snap = _env_snapshot()
    try:
        for k in _AI_ENV:
            os.environ.pop(k, None)
        # the exact 500 scenario: OPENROUTER_API_KEY injected empty, generic set
        os.environ["AI_PROVIDER"] = "openrouter"
        os.environ["OPENROUTER_API_KEY"] = ""
        os.environ["AI_API_KEY"] = "sk-generic"
        os.environ["AI_MODEL"] = "vendor/model"
        c = agmod.resolve_ai_config()
        assert c["api_key"] == "sk-generic" and c["model"] == "vendor/model"
        assert c["base_url"] == "https://openrouter.ai/api/v1"
        # provider-specific wins over the generic alias
        os.environ["OPENROUTER_API_KEY"] = "sk-specific"
        os.environ["OPENROUTER_MODEL"] = "p/m"
        c = agmod.resolve_ai_config()
        assert c["api_key"] == "sk-specific" and c["model"] == "p/m"
        # default model when neither specific nor generic model is set
        os.environ.pop("OPENROUTER_MODEL"); os.environ.pop("AI_MODEL")
        assert agmod.resolve_ai_config()["model"] == agmod.DEFAULT_OPENROUTER_MODEL
    finally:
        _env_restore(snap)


def test_ai_status_is_secret_free_and_reports_readiness():
    import agent as agmod
    snap = _env_snapshot()
    try:
        for k in _AI_ENV:
            os.environ.pop(k, None)
        os.environ["AI_PROVIDER"] = "openrouter"
        os.environ["AI_API_KEY"] = "sk-SECRET-VALUE"
        st = agmod.ai_status()
        assert st["ready"] is True and st["key_source"] == "AI_API_KEY"
        assert "api_key" not in st and "sk-SECRET-VALUE" not in json.dumps(st)
        os.environ.pop("AI_API_KEY")
        st = agmod.ai_status()
        assert st["ready"] is False and "OPENROUTER_API_KEY" in st["hint"]
    finally:
        _env_restore(snap)


def test_config_endpoint_and_engage_preflight_422():
    import pytest
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    import main as mainmod
    snap = _env_snapshot()
    try:
        for k in _AI_ENV:
            os.environ.pop(k, None)
        os.environ["AI_PROVIDER"] = "openrouter"          # no key configured
        client = TestClient(mainmod.app)                   # no lifespan -> no DB needed here
        cfg = client.get("/config").json()
        assert cfg["ready"] is False and "api_key" not in cfg
        # an AI strategy still requires a credential -> 422 before any DB access
        r = client.post("/engage", json={"program_name": "P", "in_scope": ["x.com"], "strategy": "low_ai"})
        assert r.status_code == 422 and "OPENROUTER_API_KEY" in r.json()["detail"]
        # with a key present, /config reports ready and never echoes the secret
        os.environ["AI_API_KEY"] = "sk-DO-NOT-LEAK"
        cfg = client.get("/config").json()
        assert cfg["ready"] is True and "sk-DO-NOT-LEAK" not in json.dumps(cfg)
    finally:
        _env_restore(snap)


def test_report_markdown_csv_json_and_print_css():
    findings = [{"title": "SQLi", "severity": "critical", "target": "https://t/i?id=1", "cwe": "CWE-89",
                 "description": "d", "impact": "i", "reproduction_steps": ["a", "b"]}]
    scope = {"in_scope": ["t.com"]}
    md = report.generate_report("Prog", findings, scope)
    assert "# Security Assessment Report: Prog" in md and "SQLi" in md and "CWE-89" in md
    csv_out = report.findings_csv(findings)
    assert csv_out.splitlines()[0].startswith("title,severity,target") and "SQLi" in csv_out
    j = json.loads(report.findings_json("Prog", findings, scope))
    assert j["program"] == "Prog" and j["findings"][0]["title"] == "SQLi"
    html = report.generate_html_report("Prog", findings, scope)
    assert "@media print" in html and "Save as PDF" in html      # print-to-PDF ready


def test_rescan_parent_linkage_surfaces_in_list():
    d = tempfile.mkdtemp()
    db.init(os.path.join(d, "t.db"))
    db.create_mission("par", "P", "active", "o", {"in_scope": ["x"]}, {})
    db.create_mission("chi", "P", "full", "o", {"in_scope": ["x"]}, {"parent_id": "par"})
    ms = {m["id"]: m for m in db.list_missions()}
    assert ms["chi"]["parent_id"] == "par" and ms["par"]["parent_id"] is None


# ── recon cycles + scope import + report download + empty-header filter ──
def test_recon_cycles_clamp_and_directive():
    import agent as agmod
    from tools import ToolRegistry
    eng = scope_mod.ScopeEngine(); eng.load_manual(["*.x.com"], [], "P")
    a3 = agmod.BBHAgent(eng, ToolRegistry(eng), asyncio.Event(), recon_cycles=3)
    assert a3.recon_cycles == 3 and "3 recon cycles" in a3._recon_note()
    assert agmod.BBHAgent(eng, ToolRegistry(eng), asyncio.Event(), recon_cycles=9).recon_cycles == 3   # clamped
    a1 = agmod.BBHAgent(eng, ToolRegistry(eng), asyncio.Event(), recon_cycles=1)
    assert a1.recon_cycles == 1 and a1._recon_note() == ""        # default is unchanged behavior


def test_scope_generic_csv_and_hackerone_still_detected():
    g = scope_mod.parse_scope("endpoint,type\napi.x.com,url\n*.x.com,wildcard\n,url")
    assert g["format"] == "csv"
    ids = [e["identifier"] for e in g["in_scope"]]
    assert "api.x.com" in ids and "*.x.com" in ids and g["skipped"] >= 1     # empty row counted
    # a real HackerOne header (identifier + eligible_for_bounty) still routes correctly
    h = scope_mod.parse_scope("identifier,asset_type,eligible_for_bounty\napi.x.com,URL,true\nold.x.com,URL,false")
    assert h["format"] == "hackerone_csv" and len(h["out_of_scope"]) == 1


def test_scope_summary_report_download_and_empty_header_filter():
    import pytest
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    import main as mainmod
    import db as dbmod
    snap = _env_snapshot()
    try:
        for k in _AI_ENV:
            os.environ.pop(k, None)
        os.environ["AI_PROVIDER"] = "openrouter"; os.environ["AI_API_KEY"] = "sk-test"
        dbmod.DB_PATH = os.path.join(tempfile.mkdtemp(), "t.db")
        with TestClient(mainmod.app) as c:                 # lifespan runs db.init()
            # scope import returns a human summary + skipped count
            r = c.post("/scope/parse", data={"text": "endpoint,type\napi.z.com,url\n,url"})
            j = r.json()
            assert j["skipped"] >= 1 and "skipped" in j["summary"].lower() and "api.z.com" in j["web_in_scope"]
            # /engage drops empty-value auth headers (prefilled template) -> unauthenticated
            e = c.post("/engage", json={"program_name": "P", "in_scope": ["*.z.com"],
                                        "auth_headers": {"Authorization": "", "Cookie": ""}, "recon_cycles": 2})
            assert e.status_code == 200 and e.json()["authenticated"] is False
            sid = e.json()["session_id"]
            # HTML report download carries an attachment disposition; inline does not
            rd = c.get(f"/report/{sid}/html", params={"download": 1})
            assert rd.status_code == 200 and "attachment" in rd.headers.get("content-disposition", "").lower()
            ri = c.get(f"/report/{sid}/html")
            assert "content-disposition" not in {k.lower() for k in ri.headers}
    finally:
        _env_restore(snap)


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


class _StubTools:
    """Minimal tools stand-in exercising the gate without network/LLM."""
    def get_openai_tools(self): return []
    def get_claude_tools(self): return []
    async def execute(self, name, inp, sid):
        from tools import ToolResult
        return ToolResult(name, inp.get("url", ""), True, "ran", [])


def _make_agent(mode, auto_approve=False):
    import agent as agent_mod
    eng = scope_mod.ScopeEngine(); eng.load_manual(["*.example.com"], [], "P")
    return agent_mod.BBHAgent(eng, _StubTools(), asyncio.Event(),
                              mode=mode, auto_approve=auto_approve, mission_id=None)


def test_passive_mode_blocks_active_tool():
    async def go():
        a = _make_agent("passive")
        events = [ev async for ev in a._run_tool("run_httpx", {"targets": ["a.example.com"]}, "s")]
        return events
    events = _run(go())
    assert any(ev.get("type") == "scope_block" for ev in events)
    assert not any(ev.get("type") == "tool_call" for ev in events)


def test_auto_approve_skips_gate():
    async def go():
        a = _make_agent("full", auto_approve=True)
        events = [ev async for ev in a._run_tool("run_web_probes", {"url": "https://a.example.com/?id=1"}, "s")]
        return events, a
    events, a = _run(go())
    assert a.intrusive_state == "approved"
    assert any(ev.get("type") == "tool_call" for ev in events)
    assert not any(ev.get("type") == "approval_required" for ev in events)


def test_intrusive_gate_requires_and_denies():
    async def go():
        a = _make_agent("active")
        gen = a._run_tool("run_content_discovery", {"base_url": "https://a.example.com"}, "s")
        first = await gen.__anext__()          # phase event
        seen = [first]
        # pull until we hit approval_required, then deny
        while True:
            ev = await gen.__anext__()
            seen.append(ev)
            if ev.get("type") == "approval_required":
                a.resolve_approval(ev["approval_id"], False)
                break
        rest = [ev async for ev in gen]
        return seen + rest, a
    events, a = _run(go())
    assert a.intrusive_state == "denied"
    assert any(ev.get("type") == "approval_required" for ev in events)
    assert any(ev.get("type") == "scope_block" for ev in events)  # tool skipped after deny


# ── knowledge graph ──────────────────────────────────────────────
_G_RECON = {
    "live_hosts": [{"url": "https://api.example.com", "tech": ["nginx", "Django"]},
                   {"url": "https://www.example.com", "tech": ["nginx"]}],
    "subdomains": ["api.example.com", "www.example.com", "dev.example.com"],
}
_G_URLS = ["https://api.example.com/orders/1?id=1", "https://api.example.com/orders/2?id=2",
           "https://www.example.com/login", "https://api.example.com/orders/1?id=3"]
_G_FINDINGS = [
    {"id": "f1", "title": "IDOR on /orders", "severity": "high", "category": "Authorization",
     "target": "https://api.example.com/orders/1"},
    {"id": "f2", "title": "Missing security headers", "severity": "low", "category": "Config",
     "target": "https://www.example.com/login"},
]


def test_graph_build_typed_nodes_and_edges():
    g = graph_model.build_graph(_G_RECON, _G_URLS, _G_FINDINGS)
    kinds = {n["kind"] for n in g["nodes"]}
    assert {"domain", "host", "endpoint", "tech", "finding"} <= kinds
    # dev.example.com (subdomain-only, no url) is still a host node
    assert any(n["id"] == "host:dev.example.com" for n in g["nodes"])
    assert g["stats"]["findings"] == 2
    # duplicated (host,path) with different query collapses to ONE endpoint node
    orders1 = [n for n in g["nodes"] if n["id"] == "ep:api.example.com/orders/1"]
    assert len(orders1) == 1
    rels = {e["rel"] for e in g["edges"]}
    assert {"has_host", "serves", "runs", "found"} <= rels


def test_graph_neighbors_and_related_findings():
    g = graph_model.build_graph(_G_RECON, _G_URLS, _G_FINDINGS)
    hid = "host:api.example.com"
    nb = graph_model.neighbors(g, hid)
    assert "tech:Django" in nb and any(x.startswith("ep:api.example.com") for x in nb)
    rf = graph_model.related_findings(g, hid)          # host->endpoint->finding (2 hops)
    assert any("IDOR" in f["label"] for f in rf)
    # the www finding is NOT reachable from the api host
    assert not any("headers" in f["label"].lower() for f in rf)


def test_graph_edges_only_between_known_nodes():
    g = graph_model.build_graph(_G_RECON, _G_URLS, _G_FINDINGS)
    ids = {n["id"] for n in g["nodes"]}
    for e in g["edges"]:
        assert e["source"] in ids and e["target"] in ids


def test_graph_empty_inputs_safe():
    g = graph_model.build_graph({}, [], [])
    assert g["nodes"] == [] and g["edges"] == [] and g["stats"]["nodes"] == 0


# ── cross-session memory ─────────────────────────────────────────
def test_memory_target_key_stable_across_wildcards_and_order():
    a = memory_mod.target_key({"in_scope": ["*.example.com", "api.example.com"]})
    b = memory_mod.target_key({"in_scope": ["https://api.example.com:443/x", "www.example.com"]})
    assert a == b == "example.com"
    # two distinct roots sort deterministically
    c = memory_mod.target_key({"in_scope": ["b.com", "a.com"]})
    assert c == "a.com|b.com"


def test_memory_finding_fp_ignores_severity_and_wording():
    f1 = {"title": "IDOR here", "severity": "high", "category": "Authorization",
          "target": "https://api.example.com/orders/1"}
    f2 = {"title": "totally different words", "severity": "low", "category": "Authorization",
          "target": "https://api.example.com/orders/1?id=9"}
    assert memory_mod.finding_fp(f1) == memory_mod.finding_fp(f2)  # same class + location
    f3 = {"title": "IDOR here", "category": "Authorization",
          "target": "https://api.example.com/other"}
    assert memory_mod.finding_fp(f1) != memory_mod.finding_fp(f3)  # different path


def test_memory_snapshot_and_diff():
    snap = memory_mod.snapshot(_G_RECON, _G_URLS, _G_FINDINGS)
    assert "dev.example.com" in snap["subdomains"]
    assert snap["counts"]["findings"] == 2
    # dedup: /orders/1 appears twice in urls -> one endpoint
    assert snap["endpoints"].count("api.example.com/orders/1") == 1
    prior = {"hosts": ["api.example.com"], "subdomains": ["api.example.com", "www.example.com"],
             "endpoints": ["api.example.com/orders/1"], "tech": ["nginx"],
             "findings": [{"fp": memory_mod.finding_fp(_G_FINDINGS[0])}]}
    d = memory_mod.diff(prior, snap)
    assert d["has_prior"] is True
    assert "dev.example.com" in d["subdomains"]["added"]
    assert any(f["title"] == "Missing security headers" for f in d["findings"]["added"])
    assert d["findings"]["removed"] == []
    # no prior -> has_prior false, nothing "added" spuriously flagged as change vs empty
    d0 = memory_mod.diff({}, snap)
    assert d0["has_prior"] is False


def test_db_memory_roundtrip_assets_and_prior_snapshot():
    db.init(os.path.join(tempfile.mkdtemp(), "mem.db"))
    tk = memory_mod.target_key({"in_scope": ["*.example.com"]})
    s1 = memory_mod.snapshot(_G_RECON, _G_URLS, _G_FINDINGS)
    db.record_memory(tk, "m1", s1)
    assets = db.get_memory_assets(tk)
    assert len(assets["subdomains"]) == 3 and assets["tech"]
    # re-recording keeps assets unique (PK on target_key,kind,value) and bumps last_seen
    db.record_memory(tk, "m1b", s1)
    assert len(db.get_memory_assets(tk)["subdomains"]) == 3
    # a later mission's "prior" excludes itself and returns m1's snapshot
    s2 = memory_mod.snapshot(_G_RECON, _G_URLS + ["https://new.example.com/x"], _G_FINDINGS)
    db.record_memory(tk, "m2", s2)
    prior = db.get_prior_snapshot(tk, before_mission="m2")
    assert "new.example.com" not in prior["hosts"]
    assert db.get_snapshot("m2")["counts"]["endpoints"] > db.get_snapshot("m1")["counts"]["endpoints"]


def test_graph_and_memory_endpoints_via_testclient():
    import pytest
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    import main as mainmod
    import db as dbmod
    snap = _env_snapshot()
    try:
        for k in _AI_ENV:
            os.environ.pop(k, None)
        os.environ["AI_PROVIDER"] = "openrouter"; os.environ["AI_API_KEY"] = "sk-test"
        dbmod.DB_PATH = os.path.join(tempfile.mkdtemp(), "t.db")
        with TestClient(mainmod.app) as c:
            e = c.post("/engage", json={"program_name": "P", "in_scope": ["*.example.com"]})
            assert e.status_code == 200
            j = e.json()
            assert j["warm_start"] == {"seeded": False}       # first-ever scan: cold
            sid = j["session_id"]
            # graph endpoint responds even before the agent runs (empty but well-formed)
            g = c.get(f"/graph/{sid}").json()
            assert "nodes" in g and "edges" in g and "stats" in g
            # inject a live surface + finding, then re-query graph + diff
            tools = mainmod.sessions[sid]["tools"]
            tools.recon.update(_G_RECON)
            tools._add_urls(_G_URLS)
            for f in _G_FINDINGS:
                dbmod.add_finding(sid, dict(f))
            g2 = c.get(f"/graph/{sid}").json()
            assert g2["stats"]["findings"] == 2 and g2["stats"]["hosts"] >= 2
            d = c.get(f"/memory/{sid}/diff").json()
            assert d["diff"]["has_prior"] is False            # no prior mission yet
            assert d["current"]["findings"] == 2
            # record this mission's memory, then a SECOND mission warm-starts from it
            mainmod._record_memory(sid)
            e2 = c.post("/engage", json={"program_name": "P", "in_scope": ["*.example.com"]})
            ws2 = e2.json()["warm_start"]
            assert ws2["seeded"] is True and ws2["subdomains"] >= 1
            sid2 = e2.json()["session_id"]
            # the second agent carries a prior-intel note; surface is pre-seeded
            assert "PRIOR INTEL" in mainmod.sessions[sid2]["agent"].memory_note
            surf = c.get(f"/surface/{sid2}").json()
            assert surf["stats"]["endpoints"] >= 1
            # and the diff now sees a prior baseline
            d2 = c.get(f"/memory/{sid2}/diff").json()
            assert d2["diff"]["has_prior"] is True
    finally:
        _env_restore(snap)


# ── URL sanitisation (surface / memory / graph pollution) ────────
def test_clean_url_filters_html_extraction_artifacts():
    bad = ["https://x.com/%3C/a%3E", "https://x.com/)%3C/a%3E",
           "https://x.com/about%3C/a%3E%3C/span%3E", "https://x.com/users/delete/carlos%3C/a%3E&quot",
           "https://x.com/%5C", "https://x.com/)", "https://x.com/<script>",
           'https://x.com/a"b', "https://x.com/x&lt;y"]
    for u in bad:
        assert surface.clean_url(u) is False, u
    good = ["https://x.com/", "https://x.com/?ref=abc", "https://x.com/orders/1?id=1",
            "https://api.x.com/v2/users?limit=10", "https://x.com/a/b/c",
            "https://x.com/search?q=a%20b"]      # %20 (space) is legitimate, must pass
    for u in good:
        assert surface.clean_url(u) is True, u


def test_build_inventory_drops_artifacts():
    urls = ["https://x.com/orders/1?id=1", "https://x.com/%3C/a%3E",
            "https://x.com/about%3C/a%3E", "https://x.com/login"]
    inv = surface.build_inventory(urls)
    paths = {e["path"] for e in inv}
    assert "/orders/1" in paths and "/login" in paths
    assert not any("%3C" in p or "<" in p for p in paths)
    assert len(inv) == 2


# ── access-check false positive (public page must not flag) ──────
def test_access_verdict_public_page_not_flagged():
    # anonymous 200 with content, no roles, non-protected URL -> NO anomaly
    res = [{"role": "anonymous", "status": 200, "length": 4000, "is_anon": True, "is_owner": False}]
    v = replay.access_verdict(res, "https://x.com/?ref=homepage")
    assert v["anomaly"] is False and "Public resource" in v["verdict"]


def test_access_verdict_protected_path_flags_anon():
    res = [{"role": "anonymous", "status": 200, "length": 4000, "is_anon": True, "is_owner": False}]
    v = replay.access_verdict(res, "https://x.com/admin/users")
    assert v["anomaly"] is True and "anonymous" in v["flags"]
    # object-scoped resource also counts as protected-looking
    v2 = replay.access_verdict(res, "https://x.com/orders/1042")
    assert v2["anomaly"] is True


def test_access_verdict_owner_comparison_still_works():
    res = [
        {"role": "owner", "status": 200, "length": 5000, "is_owner": True, "is_anon": False},
        {"role": "userB", "status": 200, "length": 5000, "is_owner": False, "is_anon": False},
    ]
    v = replay.access_verdict(res, "https://x.com/account/orders/9")
    assert v["anomaly"] is True and "userB" in v["flags"]
    assert replay.looks_protected("https://x.com/admin") is True
    assert replay.looks_protected("https://x.com/") is False


# ── mission lifecycle: status owned by the background task ───────
class _LTools:
    def __init__(self):
        self.recon = {"target": "x.com", "domain": "x.com", "live_hosts": [], "subdomains": []}
        self.urls = []


class _LAgent:
    def __init__(self, runner):
        self._runner = runner

    def run(self, objective, sid):
        return self._runner(objective, sid)


def _life_session(runner):
    return {"scope": None, "agent": _LAgent(runner), "tools": _LTools(),
            "stop_event": asyncio.Event(), "objective": "o",
            "status": "created", "events": [], "task": None, "done": False}


def _life_setup():
    import pytest
    pytest.importorskip("fastapi")
    import main as mainmod
    import db as dbmod
    dbmod.init(os.path.join(tempfile.mkdtemp(), "life.db"))
    return mainmod, dbmod


def test_driver_marks_complete_stopped_and_failed():
    mainmod, dbmod = _life_setup()

    async def run_ok(o, sid):
        yield {"type": "phase", "phase": "recon"}
        yield {"type": "text", "content": "hi"}
        yield {"type": "complete", "content": "done"}

    async def run_boom(o, sid):
        yield {"type": "phase", "phase": "recon"}
        raise RuntimeError("kaboom")

    # complete
    dbmod.create_mission("lc1", "P", "full", "o", {"in_scope": ["x.com"]}, {})
    mainmod.sessions["lc1"] = _life_session(run_ok)
    _run(mainmod._drive_mission("lc1"))
    assert dbmod.get_mission("lc1")["status"] == "complete"
    assert mainmod.sessions["lc1"]["done"] is True
    assert any(e.get("type") == "complete" for e in mainmod.sessions["lc1"]["events"])

    # stopped (stop_event set -> terminal status is 'stopped', not 'complete')
    dbmod.create_mission("lc2", "P", "full", "o", {"in_scope": ["x.com"]}, {})
    sess = _life_session(run_ok); sess["stop_event"].set()
    mainmod.sessions["lc2"] = sess
    _run(mainmod._drive_mission("lc2"))
    assert dbmod.get_mission("lc2")["status"] == "stopped"

    # failed (exception in the agent loop)
    dbmod.create_mission("lc3", "P", "full", "o", {"in_scope": ["x.com"]}, {})
    mainmod.sessions["lc3"] = _life_session(run_boom)
    _run(mainmod._drive_mission("lc3"))
    assert dbmod.get_mission("lc3")["status"] == "failed"


def test_stream_disconnect_does_not_false_complete():
    """The regression Codex found: a client disconnect must NOT mark an unfinished
    run 'complete'. Status is owned solely by the background task."""
    mainmod, dbmod = _life_setup()

    async def run_hang(o, sid):
        yield {"type": "phase", "phase": "recon"}
        yield {"type": "text", "content": "working"}
        await asyncio.Event().wait()      # never completes

    dbmod.create_mission("ld1", "P", "full", "o", {"in_scope": ["x.com"]}, {})
    mainmod.sessions["ld1"] = _life_session(run_hang)

    async def go():
        mainmod._ensure_run_started("ld1")
        await asyncio.sleep(0.05)                     # let the driver emit a couple events
        resp = await mainmod.stream("ld1")            # a viewer attaches
        gen = resp.body_iterator
        chunk = await gen.__anext__()                 # receives first SSE event
        await gen.aclose()                            # viewer disconnects mid-run
        await asyncio.sleep(0.05)
        status = dbmod.get_mission("ld1")["status"]
        done = mainmod.sessions["ld1"]["done"]
        mainmod.sessions["ld1"]["task"].cancel()      # cleanup the hung task
        try:
            await mainmod.sessions["ld1"]["task"]
        except (asyncio.CancelledError, Exception):
            pass
        return chunk, status, done

    chunk, status, done = _run(go())
    assert "recon" in chunk                            # the viewer did get live data
    assert status == "running" and done is False       # ...but disconnect left it RUNNING


def test_ensure_playbook_fallback_generates_when_missing():
    """Full mode sometimes skips generate_playbook; the safety-net builds one from
    the deterministic guidance engine so Playbooks is never empty with surface."""
    mainmod, dbmod = _life_setup()
    dbmod.create_mission("pb1", "P", "full", "o", {"in_scope": ["x.com"]}, {})
    sess = _life_session(None)
    sess["tools"].urls = ["https://x.com/search?q=1", "https://x.com/product?id=1"]
    sess["tools"].recon["http"] = {"ok": True, "headers": {}, "final_url": "https://x.com/", "is_https": True}
    mainmod.sessions["pb1"] = sess
    assert not dbmod.get_mission("pb1")["context"].get("playbook")
    mainmod._ensure_playbook("pb1")
    ctx = dbmod.get_mission("pb1")["context"]
    assert ctx.get("playbook") and ctx.get("playbook_auto") is True
    # idempotent: a second call does not clobber an existing playbook
    n = len(ctx["playbook"])
    mainmod._ensure_playbook("pb1")
    assert len(dbmod.get_mission("pb1")["context"]["playbook"]) == n


def test_health_endpoint():
    import pytest
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    import main as mainmod
    snap = _env_snapshot()
    try:
        os.environ["AI_PROVIDER"] = "openrouter"; os.environ["AI_API_KEY"] = "sk-x"
        with TestClient(mainmod.app) as c:
            r = c.get("/health")
            assert r.status_code == 200 and r.json()["status"] == "ok"
    finally:
        _env_restore(snap)


# ── recon-cycle labels (only when >1 cycle configured) ───────────
def _cycle_agent(recon_cycles):
    import agent as agent_mod
    eng = scope_mod.ScopeEngine(); eng.load_manual(["*.example.com"], [], "P")
    # cycle labels via _run_tool are the AGENTIC-flow behavior (deterministic owns
    # its own cycle banners in _execute_plan, tested separately).
    return agent_mod.BBHAgent(eng, _StubTools(), asyncio.Event(), mode="active",
                              strategy="agentic", mission_id=None, recon_cycles=recon_cycles)


def _events(agent, tool):
    async def go():
        return [ev async for ev in agent._run_tool(tool, {"domain": "a.example.com", "url": "https://a.example.com/"}, "s")]
    return _run(go())


def test_recon_cycle_labels_emitted_on_reentry():
    a = _cycle_agent(3)
    e1 = _events(a, "run_subfinder")                 # init -> recon = cycle 1
    cyc = [e for e in e1 if e.get("type") == "cycle"]
    assert cyc and cyc[0]["cycle"] == 1 and cyc[0]["total"] == 3
    _events(a, "run_httpx")                           # recon -> enum (no cycle)
    e3 = _events(a, "run_crtsh")                      # enum -> recon = cycle 2
    cyc3 = [e for e in e3 if e.get("type") == "cycle"]
    assert cyc3 and cyc3[0]["cycle"] == 2


def test_no_cycle_labels_when_single_cycle():
    a = _cycle_agent(1)                               # default run: unchanged
    assert not any(e.get("type") == "cycle" for e in _events(a, "run_subfinder"))


# ── failed-run surfacing: report banner + error sanitisation ─────
def test_report_status_banner_on_failed_run():
    md = report.generate_report("P", [], {"in_scope": ["x.com"]}, status="failed")
    assert "FAILED" in md and "provider quota" in md.lower()
    html = report.generate_html_report("P", [], {"in_scope": ["x.com"]}, status="failed")
    assert "statusbar" in html and "FAILED" in html
    # a clean/complete run has no banner (unchanged behaviour)
    ok = report.generate_report("P", [], {"in_scope": ["x.com"]}, status="complete")
    assert "FAILED" not in ok and "No confirmed vulnerabilities" in ok


def test_sanitize_error_maps_quota_and_redacts_keys():
    import pytest
    pytest.importorskip("fastapi")
    import main as mainmod
    m429 = mainmod._sanitize_error(Exception("Error code: 429 - free-models-per-day limit"))
    assert "429" in m429 and "quota" in m429.lower() and "provider limit" in m429.lower()
    leak = mainmod._sanitize_error(Exception("boom with key sk-abcdef123456 inside"))
    assert "sk-abcdef123456" not in leak and "[redacted]" in leak


# ── blank-auth role rejection (access-check FP source) ───────────
def test_add_profile_rejects_blank_auth_role():
    import pytest
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    import main as mainmod
    import db as dbmod
    snap = _env_snapshot()
    try:
        os.environ["AI_PROVIDER"] = "openrouter"; os.environ["AI_API_KEY"] = "sk-x"
        dbmod.DB_PATH = os.path.join(tempfile.mkdtemp(), "t.db")
        with TestClient(mainmod.app) as c:
            sid = c.post("/engage", json={"program_name": "P", "in_scope": ["*.x.com"], "recon_cycles": 3}).json()["session_id"]
            # blank/whitespace headers -> 422, role not created
            r = c.post(f"/profiles/{sid}", json={"name": "ownerish", "headers": {"Authorization": "", "Cookie": "  "}, "is_owner": True})
            assert r.status_code == 422
            assert not c.get(f"/profiles/{sid}").json()["profiles"]
            # a real credential is accepted (empty template rows are dropped)
            r2 = c.post(f"/profiles/{sid}", json={"name": "userA", "headers": {"Cookie": "session=abc", "X-CSRF": ""}, "is_owner": True})
            assert r2.status_code == 200
            profs = c.get(f"/profiles/{sid}").json()["profiles"]
            assert len(profs) == 1 and profs[0]["name"] == "userA"
            # rescan surfaces the source recon_cycles
            md = c.get(f"/missions/{sid}").json()["mission"]
            assert md["recon_cycles"] == 3
    finally:
        _env_restore(snap)


async def _hang(objective, sid):
    yield {"type": "phase", "phase": "recon"}
    await asyncio.Event().wait()


def test_api_only_run_endpoint_starts_execution():
    """POST /run starts the background task for an API-only client (no SSE), so a
    session no longer sits at 'created' until something streams it."""
    import pytest
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    import main as mainmod
    import db as dbmod
    snap = _env_snapshot()
    try:
        os.environ["AI_PROVIDER"] = "openrouter"; os.environ["AI_API_KEY"] = "sk-x"
        dbmod.DB_PATH = os.path.join(tempfile.mkdtemp(), "t.db")
        with TestClient(mainmod.app) as c:
            sid = c.post("/engage", json={"program_name": "P", "in_scope": ["*.x.com"]}).json()["session_id"]
            assert c.get(f"/status/{sid}").json()["status"] == "created"   # not running yet
            mainmod.sessions[sid]["agent"] = _LAgent(_hang)                 # stub: no network
            r = c.post(f"/run/{sid}")
            assert r.status_code == 200 and r.json()["status"] == "running"
            assert c.get(f"/status/{sid}").json()["status"] == "running"
            assert mainmod.sessions[sid]["task"] is not None
            mainmod.sessions[sid]["task"].cancel()                          # cleanup
    finally:
        _env_restore(snap)


# ── deterministic planner (no AI) ────────────────────────────────
def test_planner_terminates_and_orders_phases():
    import planner
    state = {"mode": "full", "roots": ["ex.com"], "done": set(),
             "recon": {"subdomains": [], "live_hosts": []}, "urls": []}
    firsts, guard = [], 0
    while True:
        guard += 1
        assert guard < 200, "planner did not terminate"
        batch = planner.next_batch(state)
        if not batch:
            break
        firsts.append(batch[0]["tool"])
        for s in batch:
            state["done"].add(s["key"])
        if any(s["tool"] == "run_subfinder" for s in batch):
            state["recon"]["subdomains"] = ["api.ex.com", "ex.com"]
        if any(s["tool"] == "http_probe" for s in batch):
            state["recon"]["live_hosts"] = [{"url": "https://ex.com", "tech": ["Angular"]}]
            state["urls"] = ["https://ex.com/item?id=1", "https://ex.com/fetch?url=x", "https://ex.com/a.js"]
    # recon precedes probes precedes playbook
    assert firsts.index("run_subfinder") < firsts.index("generate_playbook")
    assert "run_httpx" in firsts and "generate_playbook" in firsts


def test_planner_no_duplicate_keys_within_a_batch():
    import planner
    # duplicate roots + a graphql url could emit run_graphql twice in one batch
    state = {"mode": "full", "roots": ["ex.com", "ex.com"], "done": set(),
             "recon": {"subdomains": [], "live_hosts": [{"url": "https://ex.com"}]},
             "urls": ["https://ex.com/graphql", "https://ex.com/x?id=1"]}
    for _ in range(12):
        batch = planner.next_batch(state)
        if not batch:
            break
        keys = [s["key"] for s in batch]
        assert len(keys) == len(set(keys)), f"duplicate keys in one batch: {keys}"
        for s in batch:
            state["done"].add(s["key"])


def test_planner_passive_mode_stays_passive():
    import planner
    st = {"mode": "passive", "roots": ["x.com"], "done": set(), "recon": {"subdomains": []}, "urls": []}
    tools, g = set(), 0
    while True:
        g += 1
        assert g < 60
        b = planner.next_batch(st)
        if not b:
            break
        for s in b:
            st["done"].add(s["key"]); tools.add(s["tool"])
    assert tools <= {"run_subfinder", "run_crtsh", "run_wayback", "run_dns", "run_asn",
                     "run_github_recon", "generate_playbook"}


def test_planner_estimate_scales_with_mode():
    import planner
    assert planner.estimate("passive", ["a.com"])["intrusive_steps"] == 0
    assert planner.estimate("full", ["a.com"])["intrusive_steps"] > 0
    assert planner.estimate("full", ["a.com", "b.com"])["passive_steps"] == 12


def test_agent_strategy_budget_defaults():
    import agent as agent_mod
    eng = scope_mod.ScopeEngine(); eng.load_manual(["*.x.com"], [], "P")
    mk = lambda strat, **kw: agent_mod.BBHAgent(eng, _StubTools(), asyncio.Event(),
                                                strategy=strat, mission_id=None, **kw)
    assert mk("deterministic").max_ai_calls == 0
    assert mk("manual").max_ai_calls == 0
    assert mk("low_ai").max_ai_calls == 2
    assert mk("agentic").max_ai_calls == 40
    assert mk("low_ai", max_ai_calls=5).max_ai_calls == 5   # explicit override


class _PlanTools:
    """Tool stand-in for a deterministic run: no network, records executed tools."""
    def __init__(self):
        self.recon = {"target": "example.com", "domain": "example.com", "subdomains": [], "live_hosts": []}
        self.urls = []

    async def execute(self, name, inp, sid):
        from tools import ToolResult
        tgt = inp.get("url") or inp.get("domain") or inp.get("target") or inp.get("base_url") or ""
        return ToolResult(name, tgt, True, "ran", [])


def test_deterministic_mode_runs_no_ai_end_to_end():
    import agent as agent_mod

    async def go():
        eng = scope_mod.ScopeEngine(); eng.load_manual(["*.example.com", "example.com"], [], "P")
        a = agent_mod.BBHAgent(eng, _PlanTools(), asyncio.Event(), mode="full",
                               strategy="deterministic", auto_approve=True, mission_id=None)
        evs = [ev async for ev in a.run("obj", "s")]
        return evs, a

    evs, a = _run(go())
    assert a.ai_calls == 0                                  # zero AI spend
    tools = [e["tool"] for e in evs if e.get("type") == "tool_call"]
    assert "run_subfinder" in tools and "generate_playbook" in tools
    assert any(e.get("type") == "complete" for e in evs)
    # a manual-mode agent runs nothing automated
    async def go2():
        eng = scope_mod.ScopeEngine(); eng.load_manual(["*.example.com"], [], "P")
        a2 = agent_mod.BBHAgent(eng, _PlanTools(), asyncio.Event(), strategy="manual", mission_id=None)
        return [ev async for ev in a2.run("obj", "s")], a2
    evs2, a2 = _run(go2())
    assert a2.ai_calls == 0 and not [e for e in evs2 if e.get("type") == "tool_call"]
    assert any(e.get("type") == "complete" for e in evs2)


class _GrowTools(_PlanTools):
    """Deterministic-run stub that DISCOVERS assets, so recon cycles have new
    surface to fold in on later passes."""
    async def execute(self, name, inp, sid):
        from tools import ToolResult
        if name == "run_subfinder" and "sub.example.com" not in self.recon["subdomains"]:
            self.recon["subdomains"].append("sub.example.com")
        if name == "http_probe":
            u = f"https://{inp.get('url','x').split('//')[-1].split('/')[0]}/found?id=1"
            if u not in self.urls:
                self.urls.append(u)
        return ToolResult(name, inp.get("url") or inp.get("domain") or "", True, "ran", [])


def test_deterministic_recon_cycles_are_honored():
    import agent as agent_mod

    async def go():
        eng = scope_mod.ScopeEngine(); eng.load_manual(["*.example.com", "example.com"], [], "P")
        a = agent_mod.BBHAgent(eng, _GrowTools(), asyncio.Event(), mode="active",
                               strategy="deterministic", recon_cycles=3, auto_approve=True, mission_id=None)
        return [ev async for ev in a.run("obj", "s")], a

    evs, a = _run(go())
    cyc = [e["cycle"] for e in evs if e.get("type") == "cycle"]
    assert 1 in cyc and 2 in cyc, f"deterministic run did not honor multiple recon cycles: {cyc}"
    assert a.ai_calls == 0


def test_guidance_consolidate_groups_and_caps():
    import guidance
    # emulate a wide surface: the same vuln class discovered across many hosts
    allg = []
    for h in range(8):
        recon = {"target": f"h{h}.com", "domain": f"h{h}.com",
                 "http": {"ok": True, "headers": {}, "final_url": f"https://h{h}.com/", "is_https": True},
                 "urls": [f"https://h{h}.com/a?id=1", f"https://h{h}.com/b?url=x"]}
        allg += guidance.build_guidance(recon)
    con = guidance.consolidate(allg, cap=20)
    assert len(con) < len(allg) and len(con) <= 20
    top = con[0]
    assert top.get("group_count", 0) >= 2 and len(top.get("grouped_surfaces", [])) >= 2
    # sorted most-severe first
    ranks = [guidance.SEVERITY_RANK.get(g["severity"], 0) for g in con]
    assert ranks == sorted(ranks, reverse=True)


class _FindTools(_PlanTools):
    """Deterministic-run stub whose run_sqli CONFIRMS a finding — proves the probe
    result is actually stored (not dropped) when no model drives the scan."""
    async def execute(self, name, inp, sid):
        from tools import ToolResult
        if name == "http_probe":
            u = "https://ex.com/item?id=1"
            if u not in self.urls:
                self.urls.append(u)
        if name == "run_sqli":
            return ToolResult("sqli", inp.get("url", ""), True, "1 confirmed SQLi",
                              [{"title": "SQL injection (error-based) in 'id'", "severity": "high",
                                "target": inp.get("url", ""), "description": "x", "confidence": "confirmed"}])
        if name == "run_xss":     # reflection only -> candidate -> LEAD, not a finding
            return ToolResult("xss", inp.get("url", ""), True, "reflected",
                              [{"title": "Reflected value in 'q'", "severity": "high",
                                "target": inp.get("url", ""), "confidence": "candidate"}])
        return ToolResult(name, inp.get("url") or inp.get("domain") or "", True, "ran", [])


def test_deterministic_auto_stores_confirmed_probe_findings():
    import agent as agent_mod

    async def go(strategy):
        eng = scope_mod.ScopeEngine(); eng.load_manual(["*.ex.com", "ex.com"], [], "P")
        a = agent_mod.BBHAgent(eng, _FindTools(), asyncio.Event(), mode="full",
                               strategy=strategy, auto_approve=True, mission_id=None)
        return [ev async for ev in a.run("obj", "s")], a

    evs, a = _run(go("deterministic"))
    finds = [e for e in evs if e.get("type") == "finding"]
    leads = [e for e in evs if e.get("type") == "lead"]
    # CONFIRMED sqli -> a finding; CANDIDATE xss reflection -> a lead (never a finding)
    assert finds and all("SQL injection" in f["finding"]["title"] for f in finds), \
        "confirmed probe finding missing / a candidate leaked into findings"
    assert not any("Reflected value" in f["finding"]["title"] for f in finds), \
        "candidate reflection was wrongly stored as a confirmed finding"
    assert leads and any("Reflected value" in l["lead"]["title"] for l in leads), \
        "candidate signal was not captured as a lead"
    assert len(a.findings) >= 1 and len(a.leads) >= 1
    titles = [f["finding"]["title"] for f in finds]
    assert len(titles) == len(set(titles)), "auto-store did not dedup by fingerprint"


def test_planner_full_mode_covers_lfi_and_cmdi():
    import planner
    state = {"mode": "full", "roots": ["ex.com"], "done": set(),
             "recon": {"subdomains": [], "live_hosts": [{"url": "https://ex.com"}]},
             "urls": ["https://ex.com/read?file=a.txt", "https://ex.com/ping?host=x&cmd=ls"]}
    tools = set()
    for _ in range(30):
        b = planner.next_batch(state)
        if not b:
            break
        for s in b:
            state["done"].add(s["key"]); tools.add(s["tool"])
    assert "run_web_probes" in tools, "LFI/traversal probe missing from deterministic plan"
    assert "run_cmdi" in tools, "command-injection probe missing for cmd-ish params"


def test_report_execution_note():
    det = report.generate_report("P", [], {"in_scope": ["x.com"]},
                                 execution={"strategy": "deterministic", "ai_note": "Deterministic (no-AI) coverage completed."})
    assert "Deterministic" in det and "no-AI" in det
    low = report.generate_html_report("P", [], {"in_scope": ["x.com"]},
                                      execution={"strategy": "low_ai", "ai_note": "AI wrap-up skipped (RateLimitError)."})
    assert "execbar" in low and "RateLimitError" in low


def test_report_includes_ai_summary():
    md = report.generate_report("P", [], {"in_scope": ["x.com"]}, ai_summary="Nothing confirmed. Top leads: check IDOR.")
    assert "Executive Summary" in md and "Top leads" in md
    html = report.generate_html_report("P", [], {"in_scope": ["x.com"]}, ai_summary="Exec line here.")
    assert "Executive Summary" in html and "aisum" in html


def test_estimate_endpoint():
    import pytest
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    import main as mainmod
    snap = _env_snapshot()
    try:
        os.environ["AI_PROVIDER"] = "openrouter"; os.environ["AI_API_KEY"] = "sk-x"
        with TestClient(mainmod.app) as c:
            j = c.post("/estimate", json={"in_scope": ["*.x.com"], "mode": "full", "strategy": "low_ai"}).json()
            assert j["estimated_ai_calls"] == 2 and j["deterministic_steps"]["intrusive_steps"] > 0
            jd = c.post("/estimate", json={"in_scope": ["x.com"], "mode": "passive", "strategy": "deterministic"}).json()
            assert jd["estimated_ai_calls"] == 0
    finally:
        _env_restore(snap)

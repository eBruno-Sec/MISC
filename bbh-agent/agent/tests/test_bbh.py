"""
Deterministic test suite for the BBH Agent platform engines.

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


# ── agent: async HITL gate + mode enforcement ────────────────────
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

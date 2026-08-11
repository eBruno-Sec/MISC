"""Session-lifecycle invalidation (CWE-613 — WSTG-SESS-06 / -07 / -11) — Q-001.

Three layers, because three different things can be wrong:

  1. the ANALYZER decides correctly over observed values (pure, no I/O);
  2. the MISSION-SAFETY carve-out actually holds as a FACT, not as a promise — this is the one that
     matters, because the engine deliberately ends a session and the scan's own session must survive it;
  3. the whole engine, driven over real HTTP against a PAIRED lab: the vulnerable behaviour must be
     confirmed AND the secure partner declined. An engine that only ever fires is indistinguishable
     from one that flags everything.

The lab is served in-process from the stdlib so layer 3 runs everywhere pytest does, with no docker and
no network. Its two mounts differ in exactly ONE server-side behaviour, so a difference in the verdict is
attributable to that behaviour and nothing else.
"""
import asyncio
import json
import re
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import personas as P
import session_lifecycle_tool as sl
from scope import ScopeEngine
from tools import ToolRegistry


# ── layer 1: the analyzer, over observed values ─────────────────────────────────────────────────

def test_an_anonymously_served_endpoint_is_refused_as_a_witness():
    """THE negative control, and the reason this engine can be trusted at all. If an endpoint answers
    200 to a cookie the server has never seen, it is not gating on the session — so "still 200 after
    logout" means nothing there. Refusing it is what stops a healthy app being reported vulnerable."""
    disc, why = sl.build_discriminator({"status": 200, "body": "<h1>welcome</h1>"},
                                       {"status": 200, "body": "<h1>welcome</h1>"})
    assert disc is None
    assert "served anonymously" in why


def test_a_rejected_invented_cookie_makes_the_endpoint_a_witness():
    disc, why = sl.build_discriminator({"status": 200, "body": "hello"}, {"status": 401, "body": "no"})
    assert disc["kind"] == "status" and disc["authed_status"] == 200
    assert "invented cookie is rejected" in why


def test_an_observed_identity_marker_is_the_strongest_witness():
    """The marker must be a value we OBSERVED on the account we created. A marker we invented could not
    appear in either response, so the engine would silently fall back to a weaker discriminator."""
    disc, _ = sl.build_discriminator({"status": 200, "body": "signed in as probe@apolaki-test.local"},
                                     {"status": 200, "body": "please log in"},
                                     ["probe@apolaki-test.local"])
    assert disc["kind"] == "marker" and disc["marker"] == "probe@apolaki-test.local"


def test_a_session_that_never_reached_the_endpoint_is_not_a_witness():
    disc, why = sl.build_discriminator({"status": 403, "body": ""}, {"status": 403, "body": ""})
    assert disc is None and "did not reach" in why


def test_a_login_wall_under_the_real_session_is_not_a_witness():
    """200 + "please log in" means the session is not in effect here, whatever the status says."""
    disc, why = sl.build_discriminator({"status": 200, "body": "Please log in to continue"},
                                       {"status": 401, "body": "no"})
    assert disc is None and "login wall" in why


def test_still_authenticated_reads_the_discriminator_that_was_proven():
    marker = {"kind": "marker", "marker": "probe@x.io", "authed_status": 200}
    assert sl.still_authenticated({"status": 200, "body": "hi probe@x.io"}, marker) is True
    assert sl.still_authenticated({"status": 200, "body": "hi stranger"}, marker) is False
    assert sl.still_authenticated({"status": 401, "body": "hi probe@x.io"}, marker) is False
    status = {"kind": "status", "authed_status": 200, "control_status": 401}
    assert sl.still_authenticated({"status": 200, "body": ""}, status) is True
    assert sl.still_authenticated({"status": 401, "body": ""}, status) is False


def test_invented_cookies_keep_the_name_and_shape_but_never_the_value():
    real = {"slsid": "a1b2c3d4e5f6", "theme": "dark"}
    fake = sl.invented_cookies(real)
    assert set(fake) == set(real), "the control must use the SAME names the server validates"
    assert all(fake[k] != real[k] for k in real), fake
    assert re.fullmatch(r"[0-9a-fA-F]+", fake["slsid"]), "a hex session id keeps its hex shape"
    assert len(fake["slsid"]) == len(real["slsid"])


def test_invented_headers_covers_bearer_tokens_too():
    fake = sl.invented_headers({"Authorization": "Bearer eyJhbGciOi.eyJzdWIi.c2ln", "Accept": "*/*"})
    assert fake["Authorization"].startswith("Bearer ") and "eyJhbGciOi" not in fake["Authorization"]
    assert fake["Authorization"].count(".") == 2, "a JWT-shaped token keeps its three segments"
    assert fake["Accept"] == "*/*", "non-credential headers are carried through unchanged"


def test_a_bare_200_is_never_accepted_as_a_processed_logout():
    """A 200 from a logout route is a DECLARATION. Without a byte-observable fact we cannot tell "the
    app ignored our request" from "the app failed to invalidate", so the engine must not proceed."""
    ok, why = sl.logout_accepted(200, {}, "<html>home</html>", ["slsid"])
    assert ok is False and "did not clear" in why


def test_a_cleared_session_cookie_proves_the_logout_was_processed():
    ok, why = sl.logout_accepted(200, {"Set-Cookie": "slsid=; Path=/; Max-Age=0"}, "", ["slsid"])
    assert ok is True and "CLEARS the session cookie" in why


def test_a_redirect_or_a_stated_confirmation_also_proves_it():
    assert sl.logout_accepted(302, {"Location": "/login"}, "", ["slsid"])[0] is True
    assert sl.logout_accepted(200, {}, "You have been logged out.", ["slsid"])[0] is True
    assert sl.logout_accepted(500, {}, "logged out", ["slsid"])[0] is False


def test_credential_rotation_is_proven_by_the_login_differential_not_by_a_200():
    assert sl.password_change_accepted(401, 200)[0] is True     # old refused, new accepted
    assert sl.password_change_accepted(200, 200)[0] is False    # old STILL works -> nothing rotated
    assert sl.password_change_accepted(401, 401)[0] is False    # neither works -> account broken


def test_declared_lifetime_reads_max_age_only():
    """Max-Age is relative, so it needs no clock agreement with the target; an Expires date would make
    the check depend on the target's clock being right."""
    assert sl.declared_lifetime("slsid=abc; Max-Age=900; Path=/", ["slsid"]) == 900
    assert sl.declared_lifetime("slsid=abc; Expires=Wed, 21 Oct 2099 07:28:00 GMT", ["slsid"]) is None
    assert sl.declared_lifetime("theme=dark; Max-Age=900", ["slsid"]) is None


def test_logout_candidates_prefer_what_the_surface_actually_showed_us():
    """The quarantine list is the point of un-blinding `_add_urls`: a discovered logout beats a guess."""
    cands = sl.logout_candidates("http://t:8080/vuln",
                                 ["http://t:8080/vuln/api/logout", "http://other:9/logout"])
    assert cands[0] == "http://t:8080/vuln/api/logout"
    assert "http://other:9/logout" not in cands, "another host's logout is not ours to send"
    assert "http://t:8080/vuln/logout" in cands, "the bounded fallback list still follows"


def test_the_marker_probe_is_never_pointed_at_a_session_killer():
    out = sl.marker_candidates("http://t:8080/a", ["http://t:8080/a/api/logout", "http://t:8080/a/profile"])
    assert not any("logout" in u for u in out)
    assert "http://t:8080/a/profile" in out


def test_the_findings_are_proof_shaped_with_a_consistent_cvss():
    """The declared score must be the one the vector actually computes to, and the severity band must
    follow from it — the two checks `report.check_report_honesty` runs on every finding. The inherited
    pair (6.5 against a vector computing 7.1, plus a 'low' on a medium band) failed both, which would
    have surfaced as a self-inconsistent report rather than as a test failure."""
    import blind_benchmark as bb
    from report import cvss31_base_score
    disc = {"kind": "status", "authed_status": 200, "control_status": 401}
    for f in (sl.logout_finding("http://t/me", "http://t/logout", disc, "c", "a", 200, "r"),
              sl.password_change_finding("http://t/me", "http://t/pw", disc, "c", "a", 200, "r"),
              sl.timeout_finding("http://t/me", 3, 5, disc, "c", 200, "r")):
        assert f["family"] == "session_lifecycle" and f["cwe"] == "CWE-613"
        assert bb._has_proof(f), f["title"]
        score = cvss31_base_score(f["cvss_vector"])
        assert abs(score - f["cvss_score"]) < 0.05, f["title"]
        band = ("critical" if score >= 9 else "high" if score >= 7 else
                "medium" if score >= 4 else "low")
        assert f["severity"] == band or str(f.get("cvss_rationale") or "").strip(), \
            "a severity off its CVSS band needs a written rationale: %s" % f["title"]
        assert f["wstg"] in ("WSTG-SESS-06", "WSTG-SESS-07", "WSTG-SESS-11")


# ── layer 2: the mission-safety carve-out, as a FACT ────────────────────────────────────────────

def _registry(session_headers=None):
    sc = ScopeEngine()
    sc.load_manual(["127.0.0.1:8080", "t:8080"], [], "test")
    return ToolRegistry(sc, lab_mode=True, session_headers=session_headers or {})


def test_a_session_killing_url_is_quarantined_not_dropped():
    """`_add_urls` used to DISCARD logout URLs, which kept the scanner alive and also meant nothing
    remembered where the endpoint was. Both halves must hold: out of the probe surface, into the list."""
    tr = _registry()
    tr._add_urls(["http://t:8080/api/logout", "http://t:8080/api/me"])
    assert "http://t:8080/api/logout" not in tr.urls, "a session killer must never reach the sweep"
    assert "http://t:8080/api/logout" in tr.session_kill_urls, "...but it must still be remembered"
    assert "http://t:8080/api/me" in tr.urls


def test_the_guard_refuses_to_log_out_the_running_scans_own_session():
    """The engineering risk of this whole ticket. If the destructive step ever carried the mission's
    cookie it would end the authenticated scan and silently destroy the rest of its coverage."""
    tr = _registry({"Cookie": "sid=THE-MISSION-SESSION"})
    safe, why = tr._session_kill_is_safe({"Cookie": "sid=THE-MISSION-SESSION"})
    assert safe is False and "kill the running scan" in why


def test_the_guard_refuses_a_session_shared_with_a_persona_under_test():
    tr = _registry()
    tr._sessions["user_a"] = {"Authorization": "Bearer MATRIX-TOKEN"}
    safe, why = tr._session_kill_is_safe({"Authorization": "Bearer MATRIX-TOKEN"})
    assert safe is False and "user_a" in why


def test_the_guard_admits_a_genuinely_disjoint_sacrificial_session():
    """A guard that refused everything would be just as broken — the engine would never run."""
    tr = _registry({"Cookie": "sid=THE-MISSION-SESSION"})
    tr._sessions["user_a"] = {"Authorization": "Bearer MATRIX-TOKEN"}
    safe, why = tr._session_kill_is_safe({"Cookie": "slsid=" + secrets.token_hex(8)})
    assert safe is True and "value-disjoint" in why


def test_the_guard_checks_the_value_not_the_header_name():
    """Same cookie NAME, different value, is a different session — refusing it would be a false
    refusal that silently disables the engine on every authenticated scan."""
    tr = _registry({"Cookie": "slsid=MISSION"})
    assert tr._session_kill_is_safe({"Cookie": "slsid=SACRIFICE"})[0] is True


def test_the_engines_own_client_never_carries_the_mission_session():
    """`_http` merges `self.session_headers` into every request; `_sl_req` must not, or the logout we
    send would carry the mission's cookie no matter what the guard concluded."""
    import inspect
    body = re.sub(r'""".*?"""', "", inspect.getsource(ToolRegistry._sl_req), flags=re.S)
    assert "session_headers" not in body, "the engine's client must not merge the mission session"
    sent = {}

    class _Client:
        def request(self, method, url, headers=None, json=None, data=None):
            sent.update(headers or {})
            return None

    _registry({"Cookie": "sid=MISSION"})._sl_req(_Client(), "POST", "http://t:8080/api/logout",
                                                 headers={"Cookie": "slsid=SACRIFICE"})
    assert sent.get("Cookie") == "slsid=SACRIFICE"
    assert "MISSION" not in json.dumps(sent)


# ── layer 2b: the persona half of the carve-out ─────────────────────────────────────────────────

def test_a_sacrificial_persona_is_hidden_from_every_consumer_that_would_test_with_it():
    pm = P.PersonaManager()
    pm.add(P.USER_A, identity="a@x", headers={"Cookie": "sid=A"})
    pm.add(P.USER_B, identity="b@x", headers={"Cookie": "sid=B"})
    pm.add(P.SESSION_PROBE, identity="probe@x", headers={"Cookie": "sid=S"})
    assert pm.get(P.SESSION_PROBE).sacrificial is True, "the role forces it, whatever the caller passes"
    assert P.SESSION_PROBE not in pm.session_roles()
    assert pm.same_privilege_pair() == (P.USER_A, P.USER_B)
    assert P.SESSION_PROBE not in [r["role"] for r in pm.matrix_roles()]
    assert pm.sacrificial_roles() == [P.SESSION_PROBE]


def test_bind_prunes_a_session_that_has_since_become_sacrificial():
    """REGRESSION. `bind()` skipping sacrificial personas is only HALF a carve-out: `_sessions` is also
    written directly by `acquire_session` and by `browser_login`'s promote_session, both of which take
    an arbitrary role name. A stale entry left behind makes `_session_kill_is_safe` refuse the engine's
    OWN session — the engine then reports inconclusive on every target and nothing looks broken.

    Verifying BOTH halves: never write it, AND remove it if something else did."""
    pm = P.PersonaManager()
    tr = _registry()
    tr._sessions[P.SESSION_PROBE] = {"Cookie": "sid=SACRIFICE"}      # e.g. via acquire_session
    pm.add(P.SESSION_PROBE, identity="probe@x", headers={"Cookie": "sid=SACRIFICE"})
    pm.bind(tr)
    assert P.SESSION_PROBE not in tr._sessions, "a sacrificial session must not survive in _sessions"
    assert tr._session_kill_is_safe({"Cookie": "sid=SACRIFICE"})[0] is True, \
        "and the guard must therefore allow the engine to end its own session"


def test_bind_still_projects_every_ordinary_persona():
    """NEGATIVE CONTROL for the prune: it must remove only the sacrificial ones."""
    pm = P.PersonaManager()
    tr = _registry()
    pm.add(P.USER_A, identity="a@x", headers={"Cookie": "sid=A"})
    pm.add(P.SESSION_PROBE, identity="p@x", headers={"Cookie": "sid=S"})
    pm.bind(tr)
    assert tr._sessions.get(P.USER_A) == {"Cookie": "sid=A"}
    assert P.SESSION_PROBE not in tr._sessions


# ── layer 3: the whole engine over real HTTP, against a PAIRED lab ──────────────────────────────
#
# Mirrors labs/sessionlife (docker, compose service `sessionlife`) in-process so this runs with no
# network. `logout_invalidates` is the ONLY difference between the two mounts.

class _Lab:
    """Two mounts, one behavioural difference. `/vuln` clears the client cookie on logout but keeps the
    server-side record; `/secure` deletes the record."""

    def __init__(self):
        self.users, self.sessions = {}, {}          # email -> pw ; sid -> (mount, email)

    def handle(self, mount, path, method, cookie, body):
        invalidates = (mount == "/secure")
        if path == "/api/register" and method == "POST":
            d = json.loads(body or "{}")
            if not d.get("email") or not d.get("password"):
                return 400, {}, '{"error":"bad"}'
            self.users[d["email"]] = d["password"]
            return 200, {"Content-Type": "application/json"}, json.dumps({"id": 1, "email": d["email"]})
        if path == "/api/login" and method == "POST":
            d = json.loads(body or "{}")
            email = d.get("email") or d.get("username")
            if self.users.get(email) != d.get("password"):
                return 401, {"Content-Type": "application/json"}, '{"error":"no"}'
            sid = secrets.token_hex(12)
            self.sessions[sid] = (mount, email)
            return (200, {"Content-Type": "application/json", "Set-Cookie": "slsid=%s; Path=/" % sid},
                    json.dumps({"ok": True}))
        if path == "/api/logout":
            sid = sl.parse_cookie_header(cookie).get("slsid")
            if invalidates:
                self.sessions.pop(sid, None)
            return 200, {"Set-Cookie": "slsid=; Path=/; Max-Age=0"}, "logged out"
        if path == "/api/me":
            sid = sl.parse_cookie_header(cookie).get("slsid")
            rec = self.sessions.get(sid)
            if not rec or rec[0] != mount:
                return 401, {"Content-Type": "application/json"}, '{"error":"not authenticated"}'
            return 200, {"Content-Type": "application/json"}, json.dumps({"email": rec[1]})
        return 200, {"Content-Type": "text/html"}, (
            '<html><body><a href="%s/api/me">me</a> <a href="%s/api/logout">out</a></body></html>'
            % (mount, mount))


@pytest.fixture(scope="module")
def lab():
    state = _Lab()

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, *a):
            pass

        def _go(self, method):
            mount = "/secure" if self.path.startswith("/secure") else "/vuln"
            path = self.path[len(mount):].split("?")[0] or "/"
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n).decode("utf8", "replace") if n else ""
            st, hdrs, out = state.handle(mount, path, method, self.headers.get("Cookie", ""), body)
            data = out.encode()
            self.send_response(st)
            for k, v in hdrs.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self._go("GET")

        def do_POST(self):
            self._go("POST")

        def do_PUT(self):
            self._go("PUT")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()


def _run(lab_url, mount):
    sc = ScopeEngine()
    sc.load_manual(["127.0.0.1:" + lab_url.rsplit(":", 1)[1]], [], "sessionlife")
    tr = ToolRegistry(sc, lab_mode=True)
    base = lab_url + mount
    tr._add_urls([base + "/", base + "/api/me", base + "/api/logout", base + "/api/register",
                  base + "/api/login"])
    res = asyncio.run(tr._run_session_lifecycle({"base_url": base}))
    return tr, res


def test_the_engine_confirms_the_vulnerable_mount_end_to_end(lab):
    """Recon quarantines the logout, the engine mints its own account, proves the marker, sends the
    app's own logout, and the pre-logout cookie still works. Every hop over real HTTP."""
    tr, res = _run(lab, "/vuln")
    assert res.success and not res.error, res.error
    assert tr.session_kill_urls, "the logout endpoint must have been quarantined by _add_urls"
    f = [x for x in res.findings if x["wstg"] == "WSTG-SESS-06"]
    assert f, res.output
    assert f[0]["confidence"] == "confirmed"
    assert "NEGATIVE CONTROL" in f[0]["evidence"]
    assert "CLEARS the session cookie" in f[0]["evidence"], "the logout must be PROVEN processed"


def test_the_engine_declines_the_secure_mount(lab):
    """The FPR half, and the reason the paired lab exists. Same engine, same oracle, one server-side
    behaviour changed — it must report nothing."""
    _tr, res = _run(lab, "/secure")
    assert res.success and not res.error, res.error
    assert res.findings == [], [f["title"] for f in res.findings]
    assert "correctly invalidated" in res.output, res.output


def test_the_engine_tests_a_target_once(lab):
    """One sacrificial account per mission: a second call must not create another."""
    tr, _res = _run(lab, "/vuln")
    again = asyncio.run(tr._run_session_lifecycle({"base_url": lab + "/vuln"}))
    assert again.findings == [] and "already tested" in again.output


def test_out_of_scope_targets_are_refused(lab):
    sc = ScopeEngine()
    sc.load_manual(["example.com"], [], "other")
    tr = ToolRegistry(sc, lab_mode=True)
    res = asyncio.run(tr._run_session_lifecycle({"base_url": lab + "/vuln"}))
    assert res.error == "SCOPE BLOCK" and not res.findings

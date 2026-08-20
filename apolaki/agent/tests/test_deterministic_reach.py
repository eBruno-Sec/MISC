"""Q-050 -- the detection engines a deterministic mission could never select.

Slice 1 (`run_mass_assign`) gave one of them a deterministic trigger. Slice 2 (`run_nosqlmap`)
took the opposite verdict on the evidence and DELETED one, because one fewer engine is better
than one more unreachable one. Both halves live here; the header below is slice 1's.

---

Q-050 -- `run_mass_assign` could never be selected by a deterministic mission.

MEASURED over 154 missions / 29,945 `tool_call` rows: 111 registered tools, 72 ever dispatched,
40 never. Of the 40, ten are named NOWHERE in `agent.py` or `planner.py`, and six of those ten are
real detection engines with a working `ToolRegistry._run_*` method. `run_mass_assign` is the one
with an ASVS objective (`asvs_model.py:179`, ATHZ-04, `"verifiable": True`) and a WSTG test
(`wstg_catalog.py:110`, WSTG-INPV-20) riding on it, so two control catalogues were claiming
coverage from an engine the deterministic planner structurally could not reach.

Pre-state, MEASURED at `0b991e9`::

    $ grep -c run_mass_assign agent/planner.py agent/agent.py
    agent/planner.py:0
    agent/agent.py:0

    $ grep -c run_sqli agent/planner.py agent/agent.py     # positive control, an engine that IS scheduled
    agent/planner.py:3
    agent/agent.py:11

THE IRONY THIS FILE EXISTS TO AVOID REPEATING. Q-011 found `run_mass_assignment` was a phantom NAME,
implemented the engine and fixed the spelling so it dispatches. Nobody ever put the correctly-spelled
engine into a scheduler. **The name was fixed and the wiring never existed.** So none of the
assertions below are "the name is in a table": every one drives `planner.next_batch` to exhaustion
over state built by the REAL graph projection (`_seed_and_project_graph` ->
`_project_spec_params` -> `_forms_from_graph` -> `_graph_primary_state`) and reads the step the
planner actually emitted.

The spec fixture is VAmPI's own, trimmed. MEASURED live against `apolaki-vampi-1:5000/openapi.json`
via `surface.operations_from_openapi` -- 14 operations, four of them JSON writes::

    POST /books/v1                     'application/json'  body=[book_title, secret]
    POST /users/v1/login               'application/json'  body=[password, username]
    POST /users/v1/register            'application/json'  body=[email, password, username]
    PUT  /users/v1/{username}/email    'application/json'  body=[email]
    (every other operation: content_type '' and no body parameters)
"""
from __future__ import annotations

import asyncio
import json

import pytest

import agent as agent_mod
import asset_graph as AG
import mass_assign_tool as ma
import planner
import scope as scope_mod

HOST = "vampi.local:5000"
BASE = "http://vampi.local:5000"


def _json_body(props):
    return {"requestBody": {"required": True,
                            "content": {"application/json": {"schema": {"type": "object",
                                                                        "properties": props}}}},
            "responses": {"200": {"description": "ok"}}}


_STR = {"type": "string"}

# VAmPI's spec, trimmed to the operations that matter. Shape is verbatim OpenAPI 3.
VAMPI_SPEC = {
    "openapi": "3.0.1",
    "servers": [{"url": ""}],
    "paths": {
        "/users/v1": {"get": {"responses": {"200": {"description": "ok"}}}},
        "/users/v1/_debug": {"get": {"responses": {"200": {"description": "ok"}}}},
        "/users/v1/{username}": {"get": {"responses": {"200": {"description": "ok"}}},
                                 "delete": {"responses": {"200": {"description": "ok"}}}},
        "/users/v1/register": {"post": _json_body({"email": _STR, "password": _STR,
                                                   "username": _STR})},
        "/users/v1/login": {"post": _json_body({"password": _STR, "username": _STR})},
        "/users/v1/{username}/email": {"put": _json_body({"email": _STR})},
        "/books/v1": {"get": {"responses": {"200": {"description": "ok"}}},
                      "post": _json_body({"book_title": _STR, "secret": _STR})},
    },
}

# A read-only JSON API: same media type nowhere, because there is no write at all.
READONLY_SPEC = {"openapi": "3.0.1", "servers": [{"url": ""}],
                 "paths": {"/users/v1": {"get": {"responses": {"200": {"description": "ok"}}}},
                           "/books/v1": {"get": {"responses": {"200": {"description": "ok"}}}}}}

# A JSON write whose schema is an unresolved `$ref` -- `operations_from_openapi` deliberately does
# NOT resolve refs, so it yields a content type and ZERO properties. This is a real spec shape, not
# a contrived one, and it is the case where a URL-only step would dispatch into `ran: False`.
REF_SPEC = {"openapi": "3.0.1", "servers": [{"url": ""}],
            "paths": {"/users/v1/register": {
                "post": {"requestBody": {"content": {"application/json": {
                    "schema": {"$ref": "#/components/schemas/User"}}}},
                    "responses": {"200": {"description": "ok"}}}}}}

# The HTML side of the world: a real POST form with real fields and NO media type, because a form
# posts `application/x-www-form-urlencoded`. This is the negative control that matters most -- it is
# the shape every non-API lab in the fleet presents.
HTML_FORMS = [
    {"action": BASE + "/register.php", "method": "POST",
     "fields": ["username", "password", "email"],
     "inputs": [{"name": "username", "type": "text"}, {"name": "password", "type": "password"},
                {"name": "email", "type": "text"}]},
    {"action": BASE + "/profile.php", "method": "POST", "fields": ["nickname"],
     "inputs": [{"name": "nickname", "type": "text"}]},
]

SPEC_URLS = [BASE + "/users/v1", BASE + "/users/v1/_debug", BASE + "/users/v1/1",
             BASE + "/users/v1/register", BASE + "/users/v1/login",
             BASE + "/users/v1/1/email", BASE + "/books/v1"]


class _Tools:
    def __init__(self, *, spec=None, forms=None, urls=None):
        self.graph = AG.AssetGraph("vampi")
        self.recon = {"subdomains": ["vampi.local"], "live_hosts": [{"url": BASE}],
                      "forms": list(forms or []), "target": "vampi.local",
                      "domain": "vampi.local"}
        if spec is not None:
            self.recon["openapi"] = {BASE: spec}
        self.urls = list(urls if urls is not None else SPEC_URLS)
        self.intensity = "standard"

    def _swallow(self, *a, **k):
        pass

    def get_openai_tools(self):
        return []

    def get_claude_tools(self):
        return []


def _agent(tools, mode="full"):
    eng = scope_mod.ScopeEngine()
    eng.load_manual([BASE + "/"], [], "P")
    return agent_mod.BBHAgent(eng, tools, asyncio.Event(), mode=mode, auto_approve=True,
                              strategy="deterministic", mission_id=None)


def _state(tools=None, mode="full", **kw):
    """The planner state a REAL deterministic mission hands `next_batch`, built the real way."""
    tools = tools or _Tools(spec=VAMPI_SPEC, **kw)
    a = _agent(tools, mode=mode)
    a.findings = []
    g = tools.graph
    from urllib.parse import urlparse
    for u in tools.urls:                      # what `_graph_add_url` writes during a live scan
        p = urlparse(u)
        eid = g.observe("endpoint", p.netloc + (p.path or "/"), label=p.path or "/",
                        source="live-recon")
        g.link(g.observe("host", p.netloc, source="live-recon"), eid, "serves", source="live-recon")
    a._seed_and_project_graph(g)
    assert a._graph_projection_error is None, a._graph_projection_error
    roots, eps, recon = a._graph_primary_state(g)
    return {"mode": mode, "roots": roots, "recon": recon, "urls": eps,
            "bases": a.scope.base_map(), "intensity": "standard"}


def _drive(state):
    """Every step the planner emits, driven to exhaustion exactly as the executor does."""
    done = set()
    state["done"] = done
    steps = []
    for _ in range(400):
        batch = planner.next_batch(state)
        if not batch:
            break
        for s in batch:
            done.add(s["key"])
            steps.append(s)
    return steps


def _mass_assign_steps(state):
    return [s for s in _drive(state) if s["tool"] == "run_mass_assign"]


# ── the capability: a deterministic mission DISPATCHES it ────────────────────────────


def test_a_json_write_endpoint_is_actually_scheduled():
    """THE CLAIM. Not "the name is in a dict" -- the planner, driven to exhaustion over graph-built
    state, emits the step. Pre-fix this list was empty for every possible input."""
    steps = _mass_assign_steps(_state())
    assert steps, "run_mass_assign is still unreachable from the deterministic planner"
    targets = sorted(s["input"]["url"] for s in steps)
    assert targets == [BASE + "/books/v1", BASE + "/users/v1/1/email",
                       BASE + "/users/v1/register"], targets


def test_the_step_carries_a_body_the_endpoint_will_actually_accept():
    """A step carrying only a URL WOULD dispatch -- and `_run_mass_assign` would return
    `ran: False, "no base body"`. That is reach on paper and nothing on the wire, which is the exact
    shape of defect this ticket is about, one level down. So the assertion is on the engine's own
    body builder, run against the params the planner actually put on the step."""
    step = next(s for s in _mass_assign_steps(_state())
                if s["input"]["url"].endswith("/users/v1/register"))
    body = ma.body_from_params(step["input"]["params"], "apolaki")
    assert sorted(body) == ["email", "password", "username"], body
    # ... and the API's own validation is honoured: an `email` field gets something that parses as
    # an e-mail, a `password` field something that clears a password policy.
    assert "@" in body["email"], body
    assert body["password"] != "apolaki_password", body


def test_the_offered_fields_are_excluded_from_the_privileged_candidates():
    """The typed params are also the list of fields that are NOT mass assignment. Handing the engine
    a body without them would make it re-post a field the endpoint openly offers and call the
    persistence a finding."""
    step = next(s for s in _mass_assign_steps(_state())
                if s["input"]["url"].endswith("/users/v1/register"))
    offered = sorted(p["name"] for p in step["input"]["params"])
    cands = [c["field"] for c in ma.privileged_candidates(offered_fields=offered)]
    assert cands, cands
    assert not (set(cands) & set(offered)), (cands, offered)


def test_the_read_paths_reach_the_view_that_can_answer():
    """`read_paths` must be observed paths, not invented ones, AND they must be able to produce a
    re-read view for the object -- otherwise the engine can only ever emit a lead. MEASURED on VAmPI
    (docs/handoff/massassign.md): `/users/v1/{username}` does NOT expose `admin`; `/users/v1/_debug`
    does. Both must survive `read_views`' ranking."""
    step = next(s for s in _mass_assign_steps(_state())
                if s["input"]["url"].endswith("/users/v1/register"))
    paths = step["input"]["read_paths"]
    # every path is one the mission put on the surface -- the spec-imported URLs plus the live-host
    # root the recon phase observed. Nothing is synthesised.
    observed = {planner._path(u) for u in SPEC_URLS} | {"/"}
    assert set(paths) <= observed, sorted(set(paths) - observed)
    # write endpoints are NOT read views: `_ma_views` is capped, so each one displaces a real one.
    assert "/users/v1/register" not in paths and "/users/v1/login" not in paths, paths
    views = ma.read_views("/users/v1/register", paths, key_field="username",
                          key_value="apolaki_x", object_id="")
    assert "/users/v1/_debug" in views, views
    assert "/users/v1" in views, views


# ── negative controls: the precondition must be able to say NO ───────────────────────


def test_an_html_form_target_never_gets_the_step():
    """THE PRIMARY NEGATIVE CONTROL. An engine wired to fire always is worse than one that never
    fires. A form posts urlencoded and records no media type, so a target whose entire write surface
    is HTML forms gets ZERO mass-assignment steps -- while still getting the form engines, which is
    what proves the forms were delivered and the branch simply declined them."""
    st = _state(_Tools(spec=None, forms=HTML_FORMS, urls=[BASE + "/", BASE + "/register.php",
                                                          BASE + "/profile.php"]))
    steps = _drive(st)
    assert not [s for s in steps if s["tool"] == "run_mass_assign"], \
        [s["input"]["url"] for s in steps if s["tool"] == "run_mass_assign"]
    # positive control for the apparatus: the forms WERE delivered to the planner on this same run.
    assert st["recon"]["forms"], st["recon"]
    assert [s for s in steps if s["tool"] == "run_csrf"], sorted({s["tool"] for s in steps})


def test_a_read_only_json_api_never_gets_the_step():
    st = _state(_Tools(spec=READONLY_SPEC, urls=[BASE + "/users/v1", BASE + "/books/v1"]))
    assert not _mass_assign_steps(st)


def test_a_json_write_with_no_typed_body_params_is_not_scheduled():
    """An unresolved `$ref` yields a JSON content type and zero properties. Scheduling on the media
    type alone would emit a step the engine cannot run."""
    st = _state(_Tools(spec=REF_SPEC, urls=[BASE + "/users/v1/register"]))
    assert not _mass_assign_steps(st)


def test_a_login_write_is_excluded_even_though_it_matches_on_paper():
    """`POST /users/v1/login` is a JSON write with two typed body params -- it satisfies every
    mechanical condition. It creates no object, so there is no re-read view and the engine could
    only ever emit a lead; excluding it is a named budget decision, and this test is what keeps it
    named instead of drifting back in."""
    urls = [s["input"]["url"] for s in _mass_assign_steps(_state())]
    assert not [u for u in urls if u.endswith("/login")], urls


def test_it_stays_out_of_active_mode():
    """`run_mass_assign` is INTRUSIVE: it writes objects. Reach must not have quietly widened the
    consent envelope -- an active mission must still not schedule it."""
    assert not _mass_assign_steps(_state(mode="active"))
    assert not _mass_assign_steps(_state(mode="passive"))


def test_an_empty_content_type_is_not_read_as_json():
    """The recorded falsy-default trap, at the one line where it would bite: `""` is a REAL
    observation (an HTML form records no media type) and must not fall through to a JSON default."""
    assert planner._is_json_ct("application/json")
    assert planner._is_json_ct("application/json; charset=utf-8")
    assert planner._is_json_ct("application/vnd.api+json")
    assert not planner._is_json_ct("")
    assert not planner._is_json_ct(None)
    assert not planner._is_json_ct("application/x-www-form-urlencoded")
    assert not planner._is_json_ct("multipart/form-data")
    assert not planner._is_json_ct("text/html")


# ── slice 2: `run_nosqlmap` DELETED, and the capability proved to survive it ──────────
#
# The question asked before any wiring was whether it was a distinct capability or a duplicate of
# the already-dispatched `run_nosqli`. It was a duplicate, and a strictly weaker one:
#
#   * the `nosqlmap` binary is absent from the shipped image (MEASURED: `command -v nosqlmap` ->
#     MISSING; no reference in agent/Dockerfile or docker-compose.yml), so `_cmd` could only ever
#     return `__MISSING__`. Wiring it buys a guaranteed-failing dispatch per parameterized URL.
#   * over 154 missions / 29,945 tool_call rows it dispatched 0 times, while the native pair
#     dispatched 1,046 (`run_nosqli` 342, `run_form_nosqli` 704). The 1,046 is the positive control:
#     the apparatus counts NoSQL engines fine, so the 0 is a real absence.
#   * its oracle was `re.search(r"injectable|vulnerable|payload", stdout)` emitting confidence
#     "lead" -- no baseline, no control request. `_run_nosqli` baselines, then compares an operator
#     probe against BOTH a non-matching-value control and a missing-param control before confirming.
#   * real NoSQLMap's one non-duplicate capability is unauthenticated Mongo/Couch port enumeration,
#     and `nosqlmap --url <url>` never reaches it -- the feroxbuster `--no-recursion` mistake again.


PARAM_URLS = [BASE + "/", BASE + "/books/v1?id=1", BASE + "/users/v1?q=a"]

LOGIN_FORMS = [{"action": BASE + "/login", "method": "POST",
                "fields": ["username", "password"],
                "inputs": [{"name": "username", "type": "text"},
                           {"name": "password", "type": "password"}]}]


def test_run_nosqlmap_is_removed_rather_than_left_unreachable():
    """Absence asserted rather than deleted silently -- the same guard Q-057 left on
    ferox/dirsearch/gobuster. Re-adding a NoSQL adapter now costs an argument."""
    import tools
    assert "run_nosqlmap" not in {s["name"] for s in tools.CLAUDE_TOOLS}
    assert "run_nosqlmap" not in tools.TOOL_PERMISSIONS
    assert not hasattr(tools.ToolRegistry, "_run_nosqlmap")
    # ... and the binary it shelled out to is still not in the image, which is why it went.
    import shutil
    assert shutil.which("nosqlmap") is None, "a binary appeared -- re-open the argument, do not re-add blind"


def test_the_nosql_capability_is_still_deterministically_dispatched():
    """THE HALF THAT MAKES THE DELETION SAFE, and an absence assertion alone would be the same
    'name in a dict' defect inverted. Driven to exhaustion on a parameterized-URL + login-form
    target: the deletion removed an adapter, not a capability."""
    st = _state(_Tools(spec=None, forms=LOGIN_FORMS, urls=PARAM_URLS))
    steps = _drive(st)
    tools_emitted = {s["tool"] for s in steps}
    assert "run_nosqli" in tools_emitted, sorted(tools_emitted)
    assert "run_form_nosqli" in tools_emitted, sorted(tools_emitted)
    # the query-string engine reached the parameterized endpoints specifically, not just the root
    nq = sorted(s["input"]["url"] for s in steps if s["tool"] == "run_nosqli")
    assert any("id=1" in u or "q=a" in u for u in nq), nq
    # and nothing re-emits the deleted name from any code path
    assert "run_nosqlmap" not in tools_emitted, sorted(tools_emitted)


# ── slice 3: `run_hash_id` given a deterministic trigger keyed on a DISCLOSED hash ────
#
# `wstg_catalog.PARTIAL["WSTG-CRYP-04"]` reads "run_hash_id flags weak primitives". It flagged
# nothing: 0 dispatches in 154 missions, selectable only if an LLM picked it out of CLAUDE_TOOLS.
# The measurement behind the precondition, and behind every fixture below, is in
# `docs/handoff/deterministic_reach.md` section 3.
#
# EVERY BODY IN THIS SECTION IS A REAL RECORDED BODY, copied out of the stored corpus rather than
# invented. That matters most for the negative controls: the DVWA `user_token` page is the shape
# that would have made a naive "a hash appeared" trigger 77% noise, and it is in the corpus already.

# Juice Shop's user table, leaked through /rest/memories. Rows like these hold the ONLY password
# hashes in 32.5 MB of captured traffic; the `bkimminich` row is the admin.
JUICE_LEAK = ('{"data":[{"id":8,"UserId":13,"User":{"id":13,"username":"","email":"bjoern@owasp.org",'
              '"password":"9283f1b2e9669749081963be0462e466","role":"deluxe",'
              '"deluxeToken":"efe2f1599e2d9344ab1ff2b3f9b9a1c0a0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5",'
              '"lastLoginIp":"","profileImage":"/assets/public/images/uploads/default.svg"}},'
              '{"id":9,"UserId":4,"User":{"id":4,"username":"bkimminich",'
              '"email":"bjoern.kimminich@gmail.com",'
              '"password":"6edd9d726cbdc873c539e41ae8757b8c","role":"admin"}}]}')

# DVWA's login page. `user_token` is an anti-CSRF nonce, MD5-shaped, and served on every page.
DVWA_LOGIN = ("<form action=\"login.php\" method=\"post\">\r\n\t<fieldset>\r\n\t\t"
              "<label for=\"user\">Username</label><input type=\"text\" class=\"loginInput\" "
              "size=\"20\" name=\"username\"><br />\r\n\t\t<p class=\"submit\">"
              "<input type=\"submit\" value=\"Login\"></p>\r\n\r\n\t</fieldset>\r\n\r\n\t"
              "<input type='hidden' name='user_token' value='e6b98aa6a65869394f0c5c8b0f2c1d3e' />"
              "\r\n\r\n\t</form>")

# security.txt, from the same corpus: a 40-hex PGP key fingerprint, SHA-1 shaped.
SECURITY_TXT = ('{"contact":"mailto:donotreply@owasp-juice.shop","encryption":'
                '"https://keybase.io/bkimminich/pgp_keys.asc?fingerprint='
                '19c01cb7157e4645cc06b1b0b0e9b3a1c5f7d8e9","acknowledgements":"/#/score-board"}')


def _hashes(bodies):
    return [h for h, _ in agent_mod._disclosed_hashes(
        [{"url": "http://lab/x", "response_body": b} for b in bodies])]


def test_the_precondition_admits_the_credential_store_and_declines_the_nonce():
    """THE DISCRIMINATOR, on real recorded bodies. It is not a property of the hash -- a 32-hex
    digest is MD5, NTLM and MD4 at once and `identify` says so. It is the key the app bound it to."""
    got = _hashes([JUICE_LEAK, DVWA_LOGIN, SECURITY_TXT])
    assert got == ["9283f1b2e9669749081963be0462e466",
                   "6edd9d726cbdc873c539e41ae8757b8c"], got
    # named one by one, because each is a MEASURED false positive of the naive version:
    assert "e6b98aa6a65869394f0c5c8b0f2c1d3e" not in got          # DVWA anti-CSRF nonce
    assert "19c01cb7157e4645cc06b1b0b0e9b3a1c5f7d8e9" not in got  # PGP key fingerprint
    assert not [h for h in got if h.startswith("efe2f159")]       # deluxeToken, same JSON object


def test_a_crypt_style_hash_needs_no_key_at_all():
    """Rule A. A /etc/shadow dump has no JSON key anywhere near the hash and does not need one:
    these formats are self-identifying, and their measured false-positive rate over the whole
    corpus is zero."""
    shadow = "root:$6$abcdefgh$" + "A1b2C3d4E5f6G7h8I9j0" * 4 + ":19000:0:99999:7:::"
    ldap = "dn: uid=jane\nuserPassword: {SSHA}0TT88S6Xn9tMvEHXVQdPjHknHtimyf9V\n"
    mysql = "| jane | *A4B6157319038724E3560894F7F932C8886EBFCF |"
    got = _hashes([shadow, ldap, mysql])
    assert len(got) == 3, got
    import hashid_tool as hid
    assert [hid.identify(h)[0]["name"] for h in got] == \
        ["sha512crypt (Unix)", "LDAP SHA/SSHA", "MySQL 4.1+ (SHA1(SHA1))"]


def test_a_jwt_is_left_to_the_engine_that_owns_it():
    """`run_jwt` holds WSTG-SESS-10 in `wstg_catalog.FULL` with a confirming oracle. A second engine
    that says "this is a JWT" and stops there is the `run_nosqlmap` mistake from slice 2."""
    jwt = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0."
           "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk")
    assert _hashes(['{"password":"%s"}' % jwt]) == []


def test_a_plaintext_password_is_not_copied_into_the_evidence():
    """A `password` key whose value is a real plaintext credential must not be taken -- `identify`
    is the final filter precisely so the engine's evidence blob can never carry one."""
    assert _hashes(['{"username":"admin","password":"SuperSecretPassword123"}']) == []
    assert _hashes(['{"password":"admin123"}']) == []


def test_a_request_body_is_not_a_disclosure():
    """A `password` in a REQUEST body is the mission's own probe value or a credential it already
    holds. Neither is the target disclosing anything, and neither belongs in a finding."""
    ex = [{"url": "http://lab/login", "request_body": JUICE_LEAK, "response_body": ""}]
    assert agent_mod._disclosed_hashes(ex) == []


# ── THE DISPATCH, through the real registry: the engine EXECUTES ─────────────────────


@pytest.fixture
def mission_db(tmp_path):
    """A real database, restored afterwards so this lane cannot move the process-wide connection
    out from under anything else in the suite."""
    import db
    prev = getattr(db, "_conn", None)
    db.init(str(tmp_path / "reach.db"))
    try:
        yield db
    finally:
        db._conn = prev


def _mission_agent(db, bodies):
    """A real mission, real exchanges stored through `db.add_exchange`, and a REAL `ToolRegistry`,
    so `_run_tool` -> `tools.execute` runs the shipped engine. `run_hash_id` is PASSIVE and offline,
    so nothing here is stubbed and nothing touches the network."""
    import tools as tools_mod
    mid = "q050reach"
    db.create_mission(mid, "P", "full", "obj", {"in_scope": [BASE + "/"]})
    for i, b in enumerate(bodies):
        db.add_exchange(mid, {"url": BASE + "/rest/memories?i=%d" % i, "method": "GET",
                              "status_code": 200, "request_headers": {}, "response_headers": {},
                              "request_body": "", "response_body": b})
    eng = scope_mod.ScopeEngine()
    eng.load_manual([BASE + "/"], [], "P")
    reg = tools_mod.ToolRegistry(eng, mission_id=mid, mission_mode="full")
    a = agent_mod.BBHAgent(eng, reg, asyncio.Event(), mode="full", auto_approve=True,
                           strategy="deterministic", mission_id=mid)
    a.findings, a.leads = [], []
    return a


def _drive_hash_id(a):
    async def go():
        return [ev async for ev in a._identify_dumped_hashes("s1")]
    return asyncio.run(go())


def test_the_agent_actually_executes_run_hash_id(mission_db):
    """THE CLAIM, and not a table lookup: the shipped engine RUNS, through `_run_tool` ->
    `tools.execute`, and returns a real result. Pre-fix, `run_hash_id` had 0 dispatches in 154
    missions because nothing outside an LLM could ever name it."""
    a = _mission_agent(mission_db, [JUICE_LEAK])
    evs = _drive_hash_id(a)
    res = [e for e in evs if e.get("type") == "tool_result"]
    assert res, [e.get("type") for e in evs]
    assert res[0].get("tool") == "run_hash_id", res[0]
    # the hashes it was handed are ones the TARGET disclosed -- never an invented value
    call = next(e for e in evs if e.get("type") == "tool_call")
    assert call["input"]["hashes"] == ["9283f1b2e9669749081963be0462e466",
                                       "6edd9d726cbdc873c539e41ae8757b8c"], call
    # BOTH HALVES. Dispatching is not the whole fix: without `run_hash_id` in `_AUTO_STORE_TOOLS`
    # the engine ran and its lead went nowhere. MEASURED while wiring this -- tool_call and
    # tool_result both appeared and `self.leads` was empty. So the assertion is on mission state.
    assert a.leads, [e.get("type") for e in evs]
    ev = str(a.leads[0].get("evidence") or "")
    assert "MD5" in ev and "NTLM" in ev, a.leads[0]         # the engine's own ranked output
    assert "9283f1b2" in ev, a.leads[0]
    assert "lead" in [e.get("type") for e in evs], [e.get("type") for e in evs]


def test_a_target_with_no_disclosed_hashes_gets_no_dispatch_at_all(mission_db):
    """THE NEGATIVE CONTROL, on the corpus's own commonest false positive. DVWA serves an MD5-shaped
    `user_token` on every page; a trigger that fired here would burn a dispatch and emit an `info`
    finding on every DVWA mission. Zero events -- and `test_the_agent_actually_executes_run_hash_id`
    is the positive control proving this apparatus does dispatch when there is something to say."""
    a = _mission_agent(mission_db, [DVWA_LOGIN, SECURITY_TXT, DVWA_LOGIN])
    assert _drive_hash_id(a) == []


def test_a_mission_with_no_exchanges_is_not_an_error(mission_db):
    a = _mission_agent(mission_db, [])
    assert _drive_hash_id(a) == []


# ── slice 4: `run_ws_hijack`, held OUT of the sweep on purpose until a measurement ────
#
# `tools.py:604` recorded the hold in the code itself: the engine was "implemented,
# permission-registered and reachable from NOTHING", and putting a brand-new confirming engine on
# every mission's always-on path is the move that produced Q-047's false positive, "so that step
# waits for a measurement". `docs/handoff/deterministic_reach.md` section 4 is that measurement.
#
# The short version, because it decides the shape of the trigger: driven live against four labs,
# `_run_ws_hijack({"url": <root>})` answered "no WebSocket endpoint advertised" on ALL FOUR --
# including Juice Shop, which genuinely speaks socket.io, because its index.html is an Angular
# shell and `main.js` holds 8 `socket.io` references and ZERO `ws://` literals. Page content is
# therefore the wrong signal. The mission already observes the endpoint by its HTTP long-polling
# URL, which is a fact about the target rather than a guess about it.

SIO = "/socket.io/?EIO=4&transport=polling&t=P-Q_HRn"
WS_URLS = [BASE + "/", BASE + SIO, BASE + "/socket.io/docs/v3/migrating-from-2-x-to-3-0",
           BASE + "/rest/products/search?q=a"]
# A target with no real-time transport anywhere. `/wsdl/service.wsdl` is here on purpose: a prefix
# match on "/ws" would take it, and a WSDL document is not a WebSocket.
NO_WS_URLS = [BASE + "/", BASE + "/login.php", BASE + "/vulnerabilities/xss_r/?name=a",
              BASE + "/wsdl/service.wsdl", BASE + "/wsimport"]


def _ws_steps(state):
    return [s for s in _drive(state) if s["tool"] == "run_ws_hijack"]


def test_an_observed_realtime_endpoint_is_actually_scheduled():
    """THE CLAIM: the planner, driven to exhaustion over graph-built state, emits the step. It also
    emits exactly ONE despite two observed `/socket.io/...` URLs, because the transport is the unit
    of work, not the URL."""
    steps = _ws_steps(_state(_Tools(spec=None, urls=WS_URLS)))
    assert len(steps) == 1, [s["input"] for s in steps]
    assert steps[0]["input"] == {
        "url": "http://vampi.local:5000/",
        "ws_urls": ["ws://vampi.local:5000/socket.io/?EIO=4&transport=websocket"]}, steps[0]


def test_the_transport_string_is_ws_tools_and_not_a_second_copy():
    """`ws_tool.COMMON_WS_PATHS` owns the knowledge that socket.io needs `?EIO=4&transport=websocket`.
    A duplicated literal in the planner would drift the day that protocol detail changes."""
    import ws_tool as wst
    got = _ws_steps(_state(_Tools(spec=None, urls=WS_URLS)))[0]["input"]["ws_urls"][0]
    assert got.replace("ws://vampi.local:5000", "") in wst.COMMON_WS_PATHS, got


def test_a_target_with_no_realtime_endpoint_gets_no_step():
    """THE NEGATIVE CONTROL. `/wsdl/service.wsdl` and `/wsimport` are in this list precisely because
    a prefix match on `/ws` would take both -- and a handshake against a WSDL document is a wasted
    request on every SOAP app in the world."""
    st = _state(_Tools(spec=None, urls=NO_WS_URLS))
    steps = _drive(st)
    assert not [s for s in steps if s["tool"] == "run_ws_hijack"], \
        [s["input"] for s in steps if s["tool"] == "run_ws_hijack"]
    # positive control for the apparatus: those URLs DID reach the planner on this same run.
    assert len({s["tool"] for s in steps}) > 10, sorted({s["tool"] for s in steps})
    assert [s for s in steps if s["tool"] == "run_xss"], sorted({s["tool"] for s in steps})


def test_the_candidate_builder_declines_everything_that_is_not_a_transport():
    """The precondition on its own, so a future reader can see the boundary without reading a plan."""
    assert planner._ws_candidate("http://h:3000/socket.io/?EIO=4&transport=polling") == \
        "ws://h:3000/socket.io/?EIO=4&transport=websocket"
    assert planner._ws_candidate("https://h/ws") == "wss://h/ws"          # scheme carries through
    assert planner._ws_candidate("http://h/cable") == "ws://h/cable"
    for not_a_transport in ("http://h/wsdl/service.wsdl", "http://h/wsimport", "http://h/",
                            "http://h/rest/products", "ws://h/ws", "", "not a url"):
        assert planner._ws_candidate(not_a_transport) == "", not_a_transport


def test_it_stays_out_of_passive_mode():
    """`run_ws_hijack` is ACTIVE: it opens a socket to the target. Reach must not widen consent."""
    assert not _ws_steps(_state(_Tools(spec=None, urls=WS_URLS), mode="passive"))
    assert _ws_steps(_state(_Tools(spec=None, urls=WS_URLS), mode="active"))

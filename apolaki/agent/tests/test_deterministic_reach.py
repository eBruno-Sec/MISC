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

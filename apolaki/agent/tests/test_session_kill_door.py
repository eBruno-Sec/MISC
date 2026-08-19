"""Q-080 -- the session-kill quarantine belongs at the DOOR, and the door was two doors wide.

MEASURED BEFORE THE FIX, driving the shipped path end to end against the running `sessionlife` lab
(raw output in docs/handoff/session_door.md). `tools._add_urls` quarantines a logout URL out of
`tools.urls` and into `tools.session_kill_urls`, where only `_run_session_lifecycle` may reach it
with a sacrificial session. Two other routes from discovered surface to a scheduled step overruled
that, both fed by the same response body::

    crawl -> planner, DRAINED to its fixpoint, on the graph-derived state the executor builds

    mode=full    113 steps,  6 at the logout URL: http_probe x2, run_csrf, run_race,
                             run_form_cmdi, run_stored_xss
    mode=active  103 steps,  3 at the logout URL: http_probe x2, run_csrf   <- the DEFAULT mode
    mode=passive  29 steps,  0

    ...and emptying `recon["forms"]` -- the door the ticket was filed for -- left FOUR standing:
    mode=full    109 steps,  4 at the logout URL: http_probe x2, run_form_cmdi, run_upload_test

    kill url in tools.urls (quarantined) : False
    kill url in state["urls"] (planner)  : True     <- the quarantine, overruled

The second door is in `agent.py`: `_project_form_params` mints the form ACTION as a graph endpoint
node, and `_graph_primary_state` promoted every endpoint node to a planner URL -- so the URL
re-entered as probe surface for every url-driven engine, not for the form loop's four.

Executing what the planner scheduled, with the mission session, on the mount that invalidates at
logout (`/secure`)::

    mode=full    steps=6  before=(200, True)  after=(401, False)   SESSION ALIVE=False
    mode=active  steps=3  before=(200, True)  after=(401, False)   SESSION ALIVE=False

and 6/6 in a per-engine census on freshly minted sessions, against 0/6 on the paired `/vuln` mount
whose ONLY difference is `logout_invalidates=False`. Every engine reported `success=True` and
`session_headers` kept the dead cookie, so every authenticated probe afterwards silently tested as
anonymous while the mission went on reporting.

EVERY FIXTURE BELOW IS COPIED FROM THAT RUN, not invented -- `_MEASURED_FORMS`, `_MEASURED_URLS`,
`_MEASURED_BASES` and `_MEASURED_ENDPOINT_KEYS` are the dicts the shipped code produced, pasted
verbatim. Four defects in this repository came from invented fixtures making vacuous tests pass.

`test_the_ordinary_form_is_still_probed_by_every_engine` is the NEGATIVE CONTROL and it is the point
of the file: a quarantine that also swallows an ordinary state-changing form has bought a false
negative with a capability loss, which is a trade this project has already paid for once.
"""
from __future__ import annotations

import asyncio

import agent as agent_mod
import planner
import scope as S
import tools
from asset_graph import AssetGraph

KILL = "http://sessionlife:8080/secure/api/logout"
ORDINARY = "http://sessionlife:8080/secure/api/change-password"

# ── copied verbatim from the shipped run (see module docstring) ──────────────────────────────────
_MEASURED_FORMS = [
    {"action": ORDINARY, "method": "POST",
     "fields": ["csrfmiddlewaretoken", "currentPassword", "newPassword"]},
    {"action": KILL, "method": "POST", "fields": ["csrfmiddlewaretoken"]},
]
_MEASURED_URLS = ["http://127.0.0.1:9113/", ORDINARY, KILL]
_MEASURED_ROOTS = ["127.0.0.1", "127.0.0.1:9113", "sessionlife", "sessionlife:8080"]
_MEASURED_BASES = {"sessionlife": "http://sessionlife:8080", "127.0.0.1": "http://127.0.0.1:9113"}
_MEASURED_ENDPOINT_KEYS = [
    "127.0.0.1:9113/", "http://127.0.0.1:9113/",
    "http://sessionlife:8080/secure/api/change-password",
    "sessionlife:8080/secure/api/change-password",
    "sessionlife:8080/secure/api/logout",
]
# the graph's body-parameter nodes, verbatim: (endpoint key, field name)
_MEASURED_BODY_PARAMS = [
    ("sessionlife:8080/secure/api/logout", "csrfmiddlewaretoken"),
    ("sessionlife:8080/secure/api/change-password", "csrfmiddlewaretoken"),
    ("sessionlife:8080/secure/api/change-password", "currentPassword"),
    ("sessionlife:8080/secure/api/change-password", "newPassword"),
]
# the engines the planner aimed at the logout form before the fix, measured (mode -> tools)
_MEASURED_AT_KILL = {
    "full": ["http_probe", "http_probe", "run_csrf", "run_form_cmdi", "run_race", "run_stored_xss"],
    "active": ["http_probe", "http_probe", "run_csrf"],
    "passive": [],
}


def _state(mode, forms=None, urls=None):
    return {"mode": mode, "roots": list(_MEASURED_ROOTS), "done": set(),
            "recon": {"forms": list(_MEASURED_FORMS if forms is None else forms),
                      "subdomains": list(_MEASURED_ROOTS), "live_hosts": []},
            "urls": list(_MEASURED_URLS if urls is None else urls),
            "bases": dict(_MEASURED_BASES), "auth_headers": {}, "intensity": "standard"}


def _drain(st, cap=40):
    """Every step a whole mission schedules.

    `next_batch` returns the EARLIEST INCOMPLETE phase, so ONE call returns phase A and nothing else
    -- reading a single batch reports zero form steps on a surface that has forms, which is the
    instrument error that first hid this defect from me. The executor marks each dispatched step
    `done` and re-plans; this drains the same way.
    """
    out, done, rounds = [], set(), 0
    while rounds < cap:
        st["done"] = done
        batch = planner.next_batch(st)
        if not batch:
            break
        out.extend(batch)
        for s in batch:
            done.add(s["key"])
        rounds += 1
    return out


# ── the predicate ────────────────────────────────────────────────────────────────────────────────

def test_is_session_kill_url_matches_the_real_shapes_and_only_those():
    for u in (KILL, "https://app.tld/logout", "https://app.tld/sign-out",
              "https://app.tld/account/signout", "https://app.tld/x?action=logout",
              "https://app.tld/session/log_off"):
        assert planner.is_session_kill_url(u) is True, u
    # POSITIVE CONTROL for the negative half: these must NOT match, or the quarantine eats the app.
    for u in (ORDINARY, "https://app.tld/login", "https://app.tld/products?id=1",
              "https://app.tld/logout-history-report", "https://app.tld/api/users"):
        assert planner.is_session_kill_url(u) is False, u
    assert planner.is_session_kill_url(None) is False
    assert planner.is_session_kill_url("") is False


def test_the_rule_has_ONE_definition():
    """The regex is imported from `tools`, never restated.

    A second copy of "this URL ends a session" is precisely how one URL came to sit under two
    contradictory policies -- quarantined by `_add_urls`, probe surface to `recon["forms"]`. If a
    later edit inlines its own pattern here, this fails.
    """
    assert planner._SESSION_KILL_RE is tools._SESSION_KILL_RE


def test_session_kill_target_reads_every_key_that_names_a_request_target():
    for key in ("url", "base_url", "target"):
        assert planner.session_kill_target({"tool": "run_x", "input": {key: KILL}}) == KILL
        assert planner.session_kill_target({"tool": "run_x", "input": {key: ORDINARY}}) == ""
    # the LIST form (run_js_review / run_saml fetch each entry)
    assert planner.session_kill_target(
        {"tool": "run_js_review", "input": {"urls": [ORDINARY, KILL]}}) == KILL
    assert planner.session_kill_target(
        {"tool": "run_js_review", "input": {"urls": [ORDINARY]}}) == ""


def test_the_entitled_engine_may_still_reach_a_quarantined_url():
    """`run_session_lifecycle` mints a sacrificial account and `tools._session_kill_is_safe`
    re-checks, as a fact, that the credential it destroys is disjoint from every live session.
    Blocking it would replace a false negative with a lost vulnerability class (CWE-613)."""
    assert "run_session_lifecycle" in planner._SESSION_KILL_ENTITLED
    assert planner.session_kill_target(
        {"tool": "run_session_lifecycle", "input": {"url": KILL}}) == ""


# ── door 1: recon["forms"] ───────────────────────────────────────────────────────────────────────

def test_planner_schedules_nothing_at_a_session_kill_url():
    for mode, before in _MEASURED_AT_KILL.items():
        steps = _drain(_state(mode))
        at_kill = [s["tool"] for s in steps if KILL in str(s.get("input"))]
        assert at_kill == [], (
            "mode=%s: %d step(s) still target the logout URL: %s (measured before the fix: %s)"
            % (mode, len(at_kill), at_kill, before))


def test_the_ordinary_form_is_still_probed_by_every_engine():
    """THE NEGATIVE CONTROL, and the one that will be skipped.

    A guard that drops the logout form by dropping FORMS costs the CSRF, race, body-cmdi and
    stored-XSS coverage of every state-changing form on the target -- it would trade a
    self-inflicted false negative for a much larger capability loss, and the suite would stay green
    because the only thing anybody asserts after a fix like this is that the bad thing stopped.

    The measured baseline is the same page's change-password form: 6 steps at `full`, 3 at `active`.
    """
    for mode, expect in (("full", {"http_probe", "run_csrf", "run_race",
                                   "run_form_cmdi", "run_stored_xss"}),
                         ("active", {"http_probe", "run_csrf"})):
        steps = _drain(_state(mode))
        at_ord = {s["tool"] for s in steps if ORDINARY in str(s.get("input"))}
        assert expect <= at_ord, (
            "mode=%s: the quarantine swallowed an ORDINARY form. missing=%s got=%s"
            % (mode, sorted(expect - at_ord), sorted(at_ord)))


def test_the_rest_of_the_plan_is_untouched():
    """Positive control: the guard removes the kill-URL steps and NOTHING else.

    Measured: full 113 -> 107 (exactly the 6 kill-URL steps), active 103 -> 100 (exactly 3),
    passive 29 -> 29. A guard that also quietly shrank the rest of the plan would pass every
    assertion above while gutting the scan.
    """
    for mode in ("full", "active", "passive"):
        with_kill = [s["key"] for s in _drain(_state(mode))]
        # the SAME surface with the session-killer never discovered at all
        clean = _state(mode, forms=[f for f in _MEASURED_FORMS if f["action"] != KILL],
                       urls=[u for u in _MEASURED_URLS if u != KILL])
        without = [s["key"] for s in _drain(clean)]
        assert with_kill == without, (
            "mode=%s: a plan built WITH the session-killer must now be step-for-step identical to "
            "one built without it ever being discovered. only-with=%s only-without=%s"
            % (mode, sorted(set(with_kill) - set(without))[:5],
               sorted(set(without) - set(with_kill))[:5]))
        # ...and the apparatus was looking at a real plan, not two empty lists
        assert len(with_kill) > 20, "mode=%s produced only %d steps" % (mode, len(with_kill))


# ── door 2: state["urls"], the one emptying recon["forms"] does not close ────────────────────────

def test_the_second_door_is_closed_too():
    """MEASURED: with `recon["forms"]` EMPTY, HEAD still scheduled 4 steps at the logout URL
    (http_probe x2, run_form_cmdi, run_upload_test) because the URL was also in `state["urls"]`.
    The guard is on the step's TARGET, not on the state field, which is what closes both."""
    for mode in ("full", "active"):
        steps = _drain(_state(mode, forms=[]))
        at_kill = [s["tool"] for s in steps if KILL in str(s.get("input"))]
        assert at_kill == [], "mode=%s: forms-door empty and %s still target the logout URL" % (
            mode, at_kill)
        # positive control: the apparatus is still producing steps at all
        assert len(steps) > 20, "mode=%s produced only %d steps -- the drain is broken" % (
            mode, len(steps))


# ── the agent-side state: it stopped contradicting itself ────────────────────────────────────────

def _agent():
    sc = S.ScopeEngine()
    sc.load_manual(["http://sessionlife:8080"], [], "q080")
    t = tools.ToolRegistry(sc, mission_id=None, lab_mode=True)
    a = agent_mod.BBHAgent(sc, t, asyncio.Event(), mode="full",
                           authenticated_scan=True, mission_id=None)
    return sc, t, a


def _graph_with_the_measured_nodes():
    g = AssetGraph()
    g.observe("host", "sessionlife:8080", label="sessionlife:8080", source="test")
    for key in _MEASURED_ENDPOINT_KEYS:
        if "sessionlife" not in key:
            continue
        g.observe("endpoint", key, label="/" + key.split("/", 1)[-1], source="form-capture")
    for ep_key, name in _MEASURED_BODY_PARAMS:
        g.observe_param(ep_key, name, location="body", method="POST", source="form-capture")
    return g


def test_graph_primary_state_does_not_promote_a_quarantined_endpoint_to_probe_surface():
    sc, t, a = _agent()
    g = _graph_with_the_measured_nodes()
    roots, urls, recon = a._graph_primary_state(g)
    assert not any(planner.is_session_kill_url(u) for u in urls), urls
    # POSITIVE CONTROL: the ordinary endpoint from the same crawl IS still promoted, so this is a
    # filter and not an empty list.
    assert any(u.endswith("/secure/api/change-password") for u in urls), urls


def test_the_refusal_is_recorded_rather_than_silent():
    """A silent drop would keep the worse half of the bug: the run's own state saying nothing about
    what it declined. `_swallow` is the established recorder in this exact function (Q-019)."""
    sc, t, a = _agent()
    a._graph_primary_state(_graph_with_the_measured_nodes())
    rows = [e for e in (t.swallowed or []) if "session_kill_quarantine" in str(e.get("where"))]
    assert rows, "the quarantine recorded nothing; tools.swallowed=%r" % (t.swallowed,)
    assert "logout" in str(rows[0].get("target"))


def test_the_world_model_still_holds_the_logout_endpoint():
    """Quarantine, not deletion -- the distinction `_add_urls` already makes.

    Dropping the node would blind the CWE-613 class the graph exists to reason about, which is the
    blindness the quarantine was invented to avoid. The asset stays; only its promotion to PROBE
    SURFACE is refused.
    """
    sc, t, a = _agent()
    g = _graph_with_the_measured_nodes()
    a._graph_primary_state(g)
    assert any("logout" in str(n.get("key")) for n in g.nodes("endpoint"))


def test_forms_from_graph_drops_the_session_killer_and_keeps_the_ordinary_form():
    sc, t, a = _agent()
    g = _graph_with_the_measured_nodes()
    forms = a._forms_from_graph(g, sc.base_map())
    acts = [f["action"] for f in forms]
    assert not any(planner.is_session_kill_url(x) for x in acts), acts
    # POSITIVE CONTROL + the capability half: the ordinary form survives WITH its fields, or the
    # body engines lose the parameter names that make their probes land.
    keep = [f for f in forms if f["action"].endswith("/secure/api/change-password")]
    assert keep, acts
    assert set(keep[0]["fields"]) == {"csrfmiddlewaretoken", "currentPassword", "newPassword"}


# ── door 3: the executor ingress, which the planner cannot see ───────────────────────────────────

def test_executor_ingress_refuses_a_step_the_planner_never_saw():
    """`_graph_action_steps` builds steps straight off the graph's ranked actions and never passes
    through `planner.fresh()`. A guard that lived only in the planner would leave that door open --
    the recorded failure shape here is a guard that checks the entrance someone already thought of.
    """
    sc, t, a = _agent()
    graph_step = {"tool": "http_probe", "input": {"url": KILL}, "key": "k",
                  "_action": {"action": "map_surface"}}
    assert a._reject_session_kill_step(graph_step) is True
    rows = [e for e in (t.swallowed or []) if "session_kill_step" in str(e.get("where"))]
    assert rows and rows[0]["target"] == KILL, t.swallowed
    assert "http_probe" in rows[0]["where"], rows[0]


def test_executor_ingress_lets_everything_else_through():
    """The negative control for the ingress guard. A guard that fails closed on ordinary steps is
    strictly worse than the hole it closes."""
    sc, t, a = _agent()
    for step in ({"tool": "http_probe", "input": {"url": ORDINARY}, "key": "a"},
                 {"tool": "run_sqli", "input": {"url": "http://sessionlife:8080/x?id=1"}, "key": "b"},
                 {"tool": "run_exposure", "input": {"base_url": "http://sessionlife:8080"}, "key": "c"},
                 {"tool": "generate_playbook", "input": {}, "key": "d"},
                 {"tool": "run_session_lifecycle", "input": {"url": KILL}, "key": "e"}):
        assert a._reject_session_kill_step(step) is False, step
    assert not [e for e in (t.swallowed or []) if "session_kill_step" in str(e.get("where"))]

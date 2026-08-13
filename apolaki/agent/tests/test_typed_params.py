"""Q-031 row 4 -- a body parameter had nowhere to live, so the planner could not name one.

MEASURED, VAmPI's published OpenAPI spec::

    SPEC DECLARES        operations 14 | query params 0 | BODY params 9
    endpoints_from_openapi RETURNS  urls 12 | query 0 | body 0 | methods 0

100% of that API's testable parameter surface was invisible. The same blindness explains U1's
result: all four of its ranked actions were `cross_user_test` on endpoints the tool planner
structurally never covers, because `run_bfla` is scheduled only for QUERY-parameterized endpoints.
Two lanes, one root cause -- the planner could only see parameters that live in a URL.

Two defects are fixed here and each has its own negative control.

1. NO PRODUCER. `param` nodes existed but could only ever mean a query parameter: the writers were
   `ingest_intel` (bare names, post-loop) and `build_from_engagement` (report-time, fed by
   `surface.build_inventory`, which unions query strings). No body parameter had ever reached the
   graph from any producer at any point in a mission -- even though `crawl.extract_forms` already
   returns each field's name, default value and input type into `tools.recon["forms"]`. The
   knowledge existed and was dropped, exactly as in D3.

2. THE HANDOFF DROPPED FORMS ENTIRELY. `_graph_primary_state` returned a recon dict whose keys were
   `subdomains / live_hosts / target / domain`. Every form-driven planner branch reads
   `state["recon"]["forms"]`, so in the deterministic executor it read `[]` regardless of what the
   crawl captured. MEASURED, 2 forms captured -> 0 delivered::

       run_stored_xss 0 | run_csrf 0 | run_race 0        (never fired at all)
       run_auth_sqli 8 | run_form_nosqli 8 | run_form_cmdi 3

   The three that survived did so only because unrelated fallback branches re-discover forms from
   login-ish paths and page URLs -- which is what masked the hole. A test asserting "form engines
   run" would have passed the whole time.
"""
from __future__ import annotations

import asyncio

import agent as agent_mod
import asset_graph as AG
import planner
import scope as scope_mod

HOST = "t.local:3000"
BASE = "http://t.local:3000"

LOGIN_FORM = {"action": BASE + "/login", "method": "POST",
              "fields": ["username", "password"],
              "inputs": [{"name": "username", "value": "", "type": "text"},
                         {"name": "password", "value": "", "type": "password"}]}
EXEC_FORM = {"action": BASE + "/exec", "method": "POST", "fields": ["cmd"],
             "inputs": [{"name": "cmd", "value": "", "type": "text"}]}
GET_FORM = {"action": BASE + "/search", "method": "GET", "fields": ["q"],
            "inputs": [{"name": "q", "value": "", "type": "text"}]}

FORM_DRIVEN = ("run_stored_xss", "run_csrf", "run_race")


class _Tools:
    def __init__(self, forms=None, urls=None):
        self.graph = AG.AssetGraph("t")
        self.recon = {"subdomains": ["t.local"], "live_hosts": [{"url": BASE}],
                      "forms": list(forms if forms is not None else [LOGIN_FORM, EXEC_FORM]),
                      "target": "t.local", "domain": "t.local"}
        self.urls = list(urls if urls is not None else [BASE + "/", BASE + "/login", BASE + "/exec"])
        self.intensity = "standard"

    def _swallow(self, *a, **k):
        pass

    def get_openai_tools(self):
        return []

    def get_claude_tools(self):
        return []


def _agent(tools):
    eng = scope_mod.ScopeEngine()
    eng.load_manual([BASE + "/"], [], "P")
    return agent_mod.BBHAgent(eng, tools, asyncio.Event(), mode="full", auto_approve=True,
                              strategy="deterministic", mission_id=None)


def _projected(tools=None):
    tools = tools or _Tools()
    a = _agent(tools)
    a.findings = []
    g = tools.graph
    from urllib.parse import urlparse
    for u in tools.urls:                      # what _graph_add_url writes during a live scan
        p = urlparse(u)
        eid = g.observe("endpoint", p.netloc + (p.path or "/"), label=p.path or "/", source="live-recon")
        g.link(g.observe("host", p.netloc, source="live-recon"), eid, "serves", source="live-recon")
    a._seed_and_project_graph(g)
    assert a._graph_projection_error is None, a._graph_projection_error
    return a, g


def _drive(state):
    done = set()
    state["done"] = done
    seen = []
    for _ in range(200):
        b = planner.next_batch(state)
        if not b:
            break
        for s in b:
            done.add(s["key"])
            seen.append(s["tool"])
    return seen


# ── defect 1: no producer ever wrote a body parameter ────────────────────────────────


def test_body_parameters_now_reach_the_graph_at_all():
    """NEGATIVE CONTROL for the producer. `params_at("body")` was empty BY CONSTRUCTION -- there was
    no writer anywhere in the codebase that could put a non-query parameter in the graph."""
    _a, g = _projected()
    body = g.params_at("body")
    assert body, "no body parameter reached the graph -- the producer is still missing"
    assert {n["label"] for n in body} == {"username", "password", "cmd"}
    # the declared type survives too: name-only would lose what makes a param testable
    types = {n["label"]: (n.get("props") or {}).get("ptype") for n in body}
    assert types["password"] == "password", types
    for n in body:
        assert (n.get("props") or {})["method"] == "POST"


def test_a_body_param_is_attached_to_its_endpoint_not_left_floating():
    _a, g = _projected()
    pid = next(n["id"] for n in g.params_at("body") if n["label"] == "cmd")
    owners = [g.node(x) for x in g.neighbors(pid, "has_param")]
    assert [o for o in owners if o["kind"] == "endpoint" and o["key"] == HOST + "/exec"], owners


def test_a_get_forms_fields_are_query_not_body():
    """Guard against the easy over-claim. A GET form's fields ride in the query string; calling them
    `body` would schedule body engines against a query surface and read as coverage that is not real."""
    _a, g = _projected(_Tools(forms=[GET_FORM], urls=[BASE + "/search"]))
    assert not g.params_at("body"), [n["key"] for n in g.params_at("body")]
    assert {n["label"] for n in g.params_at("query")} == {"q"}


def test_query_param_keys_did_not_move():
    """D12 guard: `build_from_engagement` has always minted `{host}{path}?{name}`. Routing it through
    the new writer must not change existing node identities under the report."""
    g = AG.build_from_engagement("t", urls=[BASE + "/x?id=1"], findings=[])
    assert [n["key"] for n in g.nodes("param")] == ["t.local:3000/x?id"], \
        [n["key"] for n in g.nodes("param")]


def test_body_params_are_observable_to_the_technique_planner():
    _a, g = _projected()
    assert "has_body_params" in g.to_observations()
    _a2, g2 = _projected(_Tools(forms=[GET_FORM], urls=[BASE + "/search"]))
    assert "has_body_params" not in g2.to_observations()


def test_param_role_is_shared_so_a_form_field_can_earn_a_role():
    """`param_role` was inline in `ingest_intel`, so a parameter learned anywhere else could never be
    classified -- and `to_observations` reads role, not location."""
    _a, g = _projected(_Tools(
        forms=[{"action": BASE + "/up", "method": "POST", "fields": ["file"],
                "inputs": [{"name": "file", "type": "file"}]}],
        urls=[BASE + "/up"]))
    assert "has_file_upload" in g.to_observations()


# ── defect 2: the graph -> planner handoff dropped forms ─────────────────────────────


def test_the_planner_state_carries_forms_again():
    """NEGATIVE CONTROL for the handoff. Pre-fix the recon dict had no `forms` KEY at all, so the
    assertion is on the delivered content, not merely on the key existing."""
    a, g = _projected()
    _roots, _eps, recon = a._graph_primary_state(g)
    assert "forms" in recon, sorted(recon)
    got = {f["action"]: sorted(f["fields"]) for f in recon["forms"]}
    assert got == {BASE + "/login": ["password", "username"], BASE + "/exec": ["cmd"]}, got


def test_the_three_engines_that_never_fired_now_fire():
    """The capability claim, and the one that would have been missed: `run_auth_sqli`,
    `run_form_nosqli` and `run_form_cmdi` fire EITHER WAY (fallback branches re-discover forms), so
    only these three distinguish a fixed handoff from a broken one."""
    a, g = _projected()
    _roots, eps, recon = a._graph_primary_state(g)
    state = {"mode": "full", "roots": _roots, "recon": recon, "urls": eps,
             "bases": a.scope.base_map(), "intensity": "standard"}
    seen = _drive(state)
    for tool in FORM_DRIVEN:
        assert seen.count(tool) > 0, "%s still never fires; emitted=%s" % (tool, sorted(set(seen)))

    starved = dict(recon)
    starved.pop("forms")                      # exactly the pre-fix dict
    before = _drive({"mode": "full", "roots": _roots, "recon": starved, "urls": eps,
                     "bases": a.scope.base_map(), "intensity": "standard"})
    for tool in FORM_DRIVEN:
        assert before.count(tool) == 0, (
            "%s fires even with forms removed, so this test cannot detect the defect" % tool)


def test_forms_are_graph_derived_not_passed_through():
    """The executor's contract is that the planner's world-state comes FROM the graph -- an empty
    graph must yield no actions. A pass-through of `tools.recon["forms"]` would break that, and would
    also mean an OpenAPI body parameter could never become schedulable through the same path."""
    tools = _Tools()
    a = _agent(tools)
    empty = AG.AssetGraph("empty")
    _roots, _eps, recon = a._graph_primary_state(empty)
    assert recon["forms"] == [], recon["forms"]


def test_a_form_with_no_host_yields_no_action():
    """Q-019: no host, no URL. A relative action must not be manufactured onto a bare scheme."""
    tools = _Tools(forms=[{"action": "/relative", "method": "POST", "fields": ["a"]}], urls=[BASE + "/"])
    a = _agent(tools)
    a.findings = []
    g = tools.graph
    a._seed_and_project_graph(g)
    _roots, _eps, recon = a._graph_primary_state(g)
    assert recon["forms"] == [], recon["forms"]


def test_projection_is_idempotent_and_deterministic():
    tools = _Tools()
    a = _agent(tools)
    a.findings = []
    g = tools.graph
    a._seed_and_project_graph(g)
    first = (g.stats()["nodes"], g.stats()["edges"], a._graph_primary_state(g)[2]["forms"])
    a._seed_and_project_graph(g)
    assert (g.stats()["nodes"], g.stats()["edges"], a._graph_primary_state(g)[2]["forms"]) == first

"""D5 + D13 (architecture.md 6.1) -- the live graph projected findings that recommended nothing.

MEASURED BEFORE THE FIX, driving the real `BBHAgent._seed_and_project_graph` over two CONFIRMED
findings (a SQL injection and a leaked AWS secret)::

    stats            : {'nodes': 6, 'edges': 0}
    finding.enables  : [[], []]
    chase candidates : 0
    next_best_actions: []

Two confirmed findings, zero recommended actions.

D5. `AssetGraph.next_best_actions` (`asset_graph.py:288`) builds the `chase_capability` tier by
iterating `f["enables"]` on every finding node. The live projector called `g.observe("finding", ...)`
with `family=` and no `enables=`, so that list was empty **by construction** and the highest-utility
tier could never fire during a scan. The mapping it needed already existed and was already tested --
`_FINDING_ENABLES` + `_content_enables` (`asset_graph.py:420-441`) -- and was used by the
report-time `build_from_engagement`. Only the live path skipped it, so the planner reasoned over a
strictly poorer world model than the report rendered.

D13. The same projector called `g.link` nowhere, so host, endpoint and finding landed unconnected.

Why the negative controls below are shaped the way they are: a test asserting "the finding node
carries enables" would have passed the moment `enables=` was added even if `next_best_actions` still
returned nothing, and a test asserting "edges exist" would pass on any unrelated edge. Both assert
the OLD observable -- an empty action list, an unconnected finding -- is gone.
"""
from __future__ import annotations

import asyncio

import agent as agent_mod
import asset_graph as AG
import scope as scope_mod

HOST = "t.local:3000"
BASE = "http://" + HOST


class _Tools:
    """Just enough registry for `_seed_and_project_graph`."""

    def __init__(self, urls=None, live_hosts=None, subdomains=None):
        self.graph = AG.AssetGraph("t")
        self.recon = {"subdomains": list(subdomains or ["t.local"]),
                      "live_hosts": list(live_hosts if live_hosts is not None else [{"url": BASE}]),
                      "forms": []}
        self.urls = list(urls if urls is not None else
                         [BASE + "/rest/basket/1", BASE + "/x?id=1"])
        self.intensity = "standard"

    def _swallow(self, exc, where, target=""):
        pass

    def get_openai_tools(self):
        return []

    def get_claude_tools(self):
        return []


SQLI = {"id": "f1", "title": "SQL injection in id parameter", "family": "sql_injection",
        "confidence": "confirmed", "severity": "high",
        "target": BASE + "/x?id=1", "evidence": "syntax error near"}
LEAK = {"id": "f2", "title": "Directory listing exposes backup", "family": "sensitive_exposure",
        "confidence": "confirmed", "severity": "medium",
        "target": BASE + "/rest/basket/1", "evidence": "AWS_SECRET_ACCESS_KEY=AKIA..."}


def _agent(tools, in_scope=(BASE + "/",)):
    eng = scope_mod.ScopeEngine()
    eng.load_manual(list(in_scope), [], "P")
    return agent_mod.BBHAgent(eng, tools, asyncio.Event(), strategy="deterministic", mission_id=None)


def _project(findings, tools=None):
    tools = tools or _Tools()
    a = _agent(tools)
    a.findings = list(findings)
    g = AG.AssetGraph("live")
    a._seed_and_project_graph(g)
    assert a._graph_projection_error is None, a._graph_projection_error
    return g


# ── D5: the tier that could never fire ───────────────────────────────────────────────


def test_the_chase_capability_candidate_list_is_no_longer_empty_by_construction():
    """NEGATIVE CONTROL for D5. Pre-fix this graph produced `next_best_actions() == []`.

    Asserting only that finding nodes carry `enables` is not enough -- that would pass while the
    action list stayed empty (a capability already held produces no action). The load-bearing
    assertion is that `chase_capability` is actually EMITTED.
    """
    g = _project([SQLI, LEAK])

    enables = [n["enables"] for n in g.nodes("finding")]
    assert enables and not all(e == [] for e in enables), (
        "every projected finding still has enables == [] -- D5 is not fixed: %r" % enables)

    acts = g.next_best_actions()
    assert acts, "the live graph still recommends nothing at all for two confirmed findings"
    chased = [a for a in acts if a["action"] == "chase_capability"]
    assert chased, ("chase_capability still never fires; actions produced were %r"
                    % sorted({a["action"] for a in acts}))
    assert {a["capability"] for a in chased} == {"database_read", "credential_material"}, chased


def test_enables_match_what_the_report_time_rebuild_computes():
    """No second mapping: the live path and `build_from_engagement` must agree, or the planner and
    the report disagree about what a finding unlocks."""
    live = {n["label"]: sorted(n["enables"]) for n in _project([SQLI, LEAK]).nodes("finding")}
    rebuilt = AG.build_from_engagement("t", urls=[SQLI["target"], LEAK["target"]],
                                       findings=[SQLI, LEAK])
    ref = {n["label"]: sorted(n["enables"]) for n in rebuilt.nodes("finding")}
    assert live == ref, "live projection and report-time rebuild disagree: %r vs %r" % (live, ref)


def test_the_content_signal_is_wired_not_only_the_family_table():
    """`_content_enables` upgrades a finding by its OWN text. A family with no table entry whose
    evidence leaks a secret must still unlock credential_material -- otherwise only half of the
    existing machinery was reused."""
    f = {"id": "f9", "title": "Verbose error page", "family": "misconfiguration",
         "confidence": "confirmed", "target": BASE + "/x?id=1",
         "evidence": "Authorization header: Bearer eyJ... api key leaked"}
    assert AG._FINDING_ENABLES.get("misconfiguration") is None, "fixture no longer isolates the signal"
    node = _project([f]).nodes("finding")[0]
    assert node["enables"] == ["credential_material"], node["enables"]


def test_a_capability_already_held_is_not_chased():
    """Guards against a chase_capability emitter that fires unconditionally: the tier is defined as
    'enables X and X is not achieved yet'."""
    g = _project([SQLI])
    assert [a for a in g.next_best_actions() if a["action"] == "chase_capability"]
    g.observe("capability", "database_read", label="database_read", tested=True)
    assert not [a for a in g.next_best_actions() if a["action"] == "chase_capability"]


# ── D13: nodes that landed unconnected ───────────────────────────────────────────────


def test_projected_nodes_are_no_longer_unconnected():
    """NEGATIVE CONTROL for D13. Pre-fix: `edges: 0`.

    `edges > 0` alone would pass on any unrelated edge, so the specific
    host -serves-> endpoint -found_on-> finding path is walked.
    """
    g = _project([SQLI])
    assert g.stats()["edges"] > 0, "the projector still writes no edges at all"

    fid = g.nodes("finding")[0]["id"]
    eps = [n for n in g.neighbors(fid, "found_on")]
    assert eps, "the finding is still unconnected to the asset it was found on"
    ep = g.node(eps[0])
    assert ep["kind"] == "endpoint" and ep["key"] == SQLI["target"], ep

    hosts = [g.node(n) for n in g.neighbors(ep["id"], "serves")]
    assert [h for h in hosts if h["kind"] == "host"], (
        "the endpoint is still unconnected to the host that serves it")


def test_every_projected_endpoint_is_attached_to_its_host():
    g = _project([])
    for ep in g.nodes("endpoint"):
        hosts = [g.node(n) for n in g.neighbors(ep["id"], "serves")]
        assert [h for h in hosts if h["kind"] == "host"], "orphan endpoint %s" % ep["key"]


def test_a_finding_anchors_to_an_endpoint_stored_under_the_other_key_convention():
    """`tools._graph_add_url` keys an endpoint `netloc+path`; this projector keys it by whole URL
    (D12). A finding must still find its endpoint when the live scan wrote the other one."""
    tools = _Tools(urls=[], live_hosts=[])
    a = _agent(tools)
    a.findings = [SQLI]
    g = AG.AssetGraph("live")
    g.observe("endpoint", HOST + "/x", label="/x", source="live-recon")   # _graph_add_url's shape
    g.observe("host", HOST, label=HOST, source="live-recon")
    a._seed_and_project_graph(g)
    fid = g.nodes("finding")[0]["id"]
    anchored = [g.node(n) for n in g.neighbors(fid, "found_on")]
    assert anchored and anchored[0]["key"] == HOST + "/x", anchored


def test_linking_mints_no_fourth_host_identity():
    """The graph already carries three host/endpoint identity conventions (D12). Attaching edges
    must not invent another one just so an edge has somewhere to land."""
    before = _project([SQLI, LEAK])
    kinds = before.stats()["by_kind"]
    assert kinds["host"] == 1, "projection created extra host nodes: %r" % kinds
    assert {n["key"] for n in before.nodes("host")} == {"t.local"}, before.nodes("host")


def test_a_finding_with_no_resolvable_target_is_still_projected():
    """Fail open on the EDGE, never on the NODE: an unanchorable finding must still be a node, or
    the fix would silently shrink the graph."""
    f = dict(SQLI, id="f3", target="")
    g = _project([f])
    assert [n for n in g.nodes("finding") if n["key"] == "f3"]
    assert g.nodes("finding")[0]["enables"] == ["database_read"]


def test_projection_stays_idempotent():
    """`_seed_and_project_graph` runs every planning iteration; re-running must not grow the graph."""
    tools = _Tools()
    a = _agent(tools)
    a.findings = [SQLI, LEAK]
    g = AG.AssetGraph("live")
    a._seed_and_project_graph(g)
    first = (g.stats()["nodes"], g.stats()["edges"])
    a._seed_and_project_graph(g)
    assert (g.stats()["nodes"], g.stats()["edges"]) == first

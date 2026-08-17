"""Q-060 -- an in-scope origin must be CARRIED out of the operator's scope, never rebuilt from it.

`ScopeEngine.load_manual` stores a BARE HOST: `_split_scope_entry("http://juice-shop:3000")` puts
`juice-shop` in `ScopeEntry.value` and parks the scheme+port in `ScopeEntry.base`. Three drivers in
`agent.py` read `scope.to_dict()["in_scope"]` -- the bare hosts -- and re-added a default scheme:

    u = s if "://" in s else "https://" + s.split("/")[0]

That INVENTS a port the operator never authorised (:443, or :80 for the http variant), and
`validate()` then correctly refuses the origin the driver itself built.

MEASURED on a live Juice Shop mission: `run_transport_posture` 1 call, 0 results, 1 scope block --
100% dead on the target. `run_header_trust` 6 calls / 5 results / 1 block, because it ALSO feeds
discovered URLs, which carry their own port; only its origin pass was dead, and it must not be
reported as a dead engine. Every Apolaki lab runs on a non-standard port, so this cost
`tls_posture`, `cookie_scope_posture`, `http_security_headers` and `http_methods_audit` across the
whole fleet.

A third caller carrying the identical line was found while fixing the two the ticket names:
`_browser_harvest_surface`, whose JS-rendered crawl seeds the frontier the same way and then drops
every seed on `self.scope.validate(u)[0]`.

THE SCOPE ENGINE'S REFUSAL IS CORRECT AND MUST STAY CORRECT. Half this module is negative controls
saying so: the fix carries the operator's own origin, it does not widen scope, and a genuinely
out-of-scope host is still refused at the same choke point afterwards.
"""
from __future__ import annotations

import asyncio
import os
import tempfile

import agent as agent_mod
import db as dbmod
import scope as scope_mod
import tools as tools_mod

LAB = "http://juice-shop:3000"          # the operator's entry: explicit scheme, non-standard port
EVIL = "https://evil.example/admin"     # never authorised, on any port


def _fresh(mid: str) -> None:
    dbmod.init(os.path.join(tempfile.mkdtemp(), "q060.db"))
    dbmod.create_mission(mid, "Q-060", "active", "o", {"in_scope": [LAB]}, {})


def _recorder(tool: str, seen: list, findings=()):
    """A leaf engine that records the URL it was actually handed.

    `execute()` resolves `getattr(self, "_" + tool_name)`, so binding this substitutes ONLY the
    engine body -- scope validation, dispatch and ledger writes all stay the real thing. `seen`
    therefore holds exactly the targets that survived scope enforcement, which is the measurement.
    """
    async def leaf(inp):
        u = inp.get("url") or inp.get("base_url") or ""
        seen.append(u)
        return tools_mod.ToolResult(tool, u, True, "audited %s" % u, [dict(f) for f in findings], None)
    return leaf


def _agent(in_scope, urls=(), **leaves):
    eng = scope_mod.ScopeEngine()
    eng.load_manual(list(in_scope), [], "q060")
    reg = tools_mod.ToolRegistry(eng, mission_id="q060")
    for name, fn in leaves.items():
        setattr(reg, "_" + name, fn)
    reg.urls = list(urls)
    ag = agent_mod.BBHAgent(eng, reg, asyncio.Event(), strategy="deterministic",
                            mission_id=None, auto_approve=True)
    ag.mode = "active"
    return ag


def _drain(agen) -> list:
    async def go():
        return [ev async for ev in agen]
    return asyncio.run(go())


def _rows(mid: str, kind: str, tool: str) -> list:
    return [l for l in dbmod.get_logs(mid, limit=200)
            if l.get("type") == kind and l.get("tool") == tool]


F_TLS = {"severity": "medium", "title": "TLS 1.0 offered", "confidence": "confirmed",
         "evidence": "handshake negotiated TLSv1.0", "family": "security_misconfig"}
F_HDR = {"severity": "high", "title": "authorization decided by X-Forwarded-For", "confidence": "lead",
         "evidence": "403 -> 200", "family": "broken_access_control"}


# ── THE DEFECT ───────────────────────────────────────────────────────────────
#
# Both FAIL before the fix: the engine is dispatched with an origin the scope engine refuses, so the
# leaf is never reached and `seen` is empty -- the live 1-call/0-result/1-scope-block row exactly.

def test_transport_posture_audits_the_port_the_operator_authorised():
    """The whole ticket in one assertion, on the engine that was 100% dead."""
    _fresh("q060a")
    seen = []
    ag = _agent([LAB], run_transport_posture=_recorder("run_transport_posture", seen, [F_TLS]))
    evs = _drain(ag._do_transport_posture("q060a"))

    assert seen == [LAB], (
        "transport posture was handed %r; the operator authorised %r. An origin rebuilt from a bare "
        "scope host invents :443 and the scope engine correctly refuses it, which is why this engine "
        "produced 0 results on every lab in the fleet." % (seen, LAB))
    assert not _rows("q060a", "scope_block", "run_transport_posture"), (
        "the driver blocked itself on its own invented origin")
    assert [e for e in evs if e.get("type") == "finding"], "an audited origin must be able to report"


def test_header_trust_audits_the_port_the_operator_authorised():
    """Same defect, other caller. The `http://` default is not the bug -- discarding :3000 is."""
    _fresh("q060b")
    seen = []
    ag = _agent([LAB], run_header_trust=_recorder("run_header_trust", seen, [F_HDR]))
    _drain(ag._do_header_trust("q060b"))

    assert LAB in seen, "header-trust never reached the operator's own origin: %r" % (seen,)
    assert not _rows("q060b", "scope_block", "run_header_trust")


def test_the_browser_harvest_seed_carries_the_port_too():
    """The third caller, found by auditing `agent.py` for the same shape rather than by the ticket.

    Asserted at the seed derivation rather than through the crawl, because the crawl needs a live
    CDP browser. A seed the scope engine refuses makes the whole JS-rendered harvest a no-op, and a
    no-op harvest is indistinguishable from an app with no client-rendered surface.
    """
    ag = _agent([LAB])
    seeds = ag._scope_origins()
    assert seeds == [LAB], seeds
    assert all(ag.scope.validate(s)[0] for s in seeds), (
        "a seed the driver built is refused by the driver's own scope check")


def test_a_bare_host_still_gets_an_origin():
    """Positive control on the apparatus AND on the fallback: the fix must not restrict the drivers
    to operators who happened to type a scheme. A bare host has no pinned port, so the default
    https origin is authorised and must still be produced."""
    _fresh("q060c")
    seen = []
    ag = _agent(["target.tld"], run_transport_posture=_recorder("run_transport_posture", seen))
    _drain(ag._do_transport_posture("q060c"))
    assert seen == ["https://target.tld"], seen


# ── NEGATIVE CONTROLS: the refusal is correct and stays correct ──────────────

def test_the_scope_engine_still_refuses_the_invented_port():
    """Pre-registered: the wrong fix is to teach `validate()` to ignore a pinned port. If either of
    these ever returns True the fix was made by widening scope, and the port pin (SEC-1) is gone."""
    eng = scope_mod.ScopeEngine()
    eng.load_manual([LAB], [], "q060")
    assert eng.validate("https://juice-shop")[0] is False   # the origin the old code built
    assert eng.validate("http://juice-shop")[0] is False    # ... and the header-trust variant
    assert eng.validate("http://juice-shop:3001")[0] is False
    assert eng.validate(LAB)[0] is True                     # positive control: the pin still admits


def test_an_out_of_scope_host_is_still_refused_by_header_trust():
    """The driver's OTHER input is discovered URLs, and it must not become a way around scope. An
    out-of-scope admin URL is dispatched (the driver does not pre-filter, so the refusal stays
    visible in the ledger) and must never reach the engine."""
    _fresh("q060d")
    seen = []
    ag = _agent([LAB], urls=[EVIL], run_header_trust=_recorder("run_header_trust", seen))
    _drain(ag._do_header_trust("q060d"))

    assert EVIL not in seen, "an out-of-scope host reached the engine"
    assert LAB in seen, "positive control: the in-scope origin still ran in the same pass"
    blocks = _rows("q060d", "scope_block", "run_header_trust")
    assert blocks, "the refusal left no trace -- a silent block is an invisible false negative"


def test_an_explicitly_out_of_scope_host_never_becomes_an_origin():
    """`base_urls()` is the new source of origins, so prove it cannot serve one the operator
    excluded, even when the same host also appears in-scope on another port."""
    eng = scope_mod.ScopeEngine()
    eng.load_manual([LAB], ["juice-shop"], "q060")
    ag = agent_mod.BBHAgent(eng, tools_mod.ToolRegistry(eng, mission_id="q060"),
                            asyncio.Event(), strategy="deterministic", mission_id=None)
    for o in ag._scope_origins():
        assert eng.validate(o)[0] is False, (
            "deny-overrides-allow must still win: %r was offered as an origin" % o)


def test_a_wildcard_asset_is_not_turned_into_a_hostname():
    """`https://*.example.com` is not a host. The old reconstruction produced exactly that and it
    passed `_matches` (`'*.example.com'.endswith('.example.com')`), so the drivers spent a dispatch
    on a name DNS can never resolve. A wildcard must contribute no origin."""
    ag = _agent(["*.example.com", LAB])
    assert ag._scope_origins() == [LAB]


def _scheme_concat_functions() -> list:
    """Every function in `agent.py` that reads a SCOPE ENTRY and builds a URL by concatenating a
    scheme onto it. That conjunction is the defect; neither half alone is.

    Deliberately not a line regex. The first version was, and it flagged
    `_url_from_graph_key`, which consults `scope.base_map()` FIRST and only falls back to a default
    for a host the scope has never heard of -- i.e. the CORRECT pattern, and itself a prior fix of
    this same class. A ratchet that fires on the fix is a ratchet that gets deleted.
    """
    import ast
    import inspect
    tree = ast.parse(inspect.getsource(agent_mod))
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = _code_only(node)
        if _reads_scope_entry(body) and _concats_a_scheme(body):
            out.append(node.name)
    return out


def _code_only(node) -> str:
    """The EXECUTABLE body of a function, docstrings stripped and quoting normalised.

    Docstrings must not count: `_scope_origins` quotes the old broken line verbatim to explain what
    it replaced, and a detector that reads prose would flag the fix as the defect. This repo has
    already been bitten by the mirror-image mistake -- `test_saml_wiring` matched a docstring that
    merely NAMED a call -- so the rule is the same in both directions: check code against code.
    """
    import ast
    import copy
    n = copy.deepcopy(node)
    for sub in ast.walk(n):
        b = getattr(sub, "body", None)
        if isinstance(b, list) and b and isinstance(b[0], ast.Expr) \
                and isinstance(getattr(b[0], "value", None), ast.Constant) \
                and isinstance(b[0].value.value, str):
            del b[0]
    return ast.unparse(n).replace("'", '"') if n.body else ""


def _reads_scope_entry(body: str) -> bool:
    return "scope.in_scope" in body or '"in_scope"' in body


def _concats_a_scheme(body: str) -> bool:
    return '"http://"' in body or '"https://"' in body


def test_no_driver_rebuilds_an_origin_from_a_bare_scope_host():
    """Class-level ratchet, paired with the behavioural tests above so it is not a guard that checks
    a declaration. Reading `to_dict()["in_scope"]` is legitimate on its own (host-level recon,
    prompt payloads); reading it and CONCATENATING a scheme is the defect, and it had appeared three
    times independently by the time anyone measured it."""
    assert _scheme_concat_functions() == [], (
        "a scope entry is being turned into a URL by string concatenation again -- the port the "
        "operator pinned is discarded there. Carry `self._scope_origins()` / `scope.base_urls()` "
        "instead: %s" % _scheme_concat_functions())


def test_the_ratchet_can_actually_see_the_defect():
    """Positive control for the ratchet. A guard that passes because it looks at nothing is the
    trap this codebase has hit four times, so the detector is run against the exact source shape it
    exists to catch and must report it."""
    import ast
    import textwrap
    mutant = ast.parse(textwrap.dedent('''
        def _do_transport_posture(self):
            """This docstring is the negative half: prose alone must NOT trip the detector."""
            for e in (self.scope.to_dict().get("in_scope") or []):
                s = str(e)
                u = s if "://" in s else "https://" + s.split("/")[0]
    ''')).body[0]
    body = _code_only(mutant)
    assert _reads_scope_entry(body) and _concats_a_scheme(body), (
        "the detector cannot see the defect it was written for")

    prose_only = ast.parse(textwrap.dedent('''
        def _explains_the_defect(self):
            """It read in_scope and built "https://" + host, which invented a port."""
            return self._scope_origins()
    ''')).body[0]
    pbody = _code_only(prose_only)
    assert not (_reads_scope_entry(pbody) and _concats_a_scheme(pbody)), (
        "the detector reads prose -- it would flag the comment that documents the fix")

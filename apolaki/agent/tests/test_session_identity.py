"""Q-032/033/034 — IDENTITY CONTAMINATION, measured at the wire.

`session_headers` is one raw dict on the registry, merged into EVERY request by `_http_send`:

    h = {"User-Agent": _UA, **(self.session_headers or {}), **(headers or {})}

The caller's headers win per-key, so a same-key collision (Cookie vs Cookie) is safe. Two shapes
are NOT safe, and both are oracle defects rather than tidiness defects:

  1. ANONYMOUS IS NOT ANONYMOUS. `_authz_matrix._headers_for` returns `{}` for rank 0 and hands it
     to `_http_send`, which merges the mission session straight back in. The anon control row of
     the authorization matrix is then authenticated. `authz.build_matrix` reads that row three ways
     (missing_authentication fires ON it, bfla and horizontal IDOR require it to be DENIED), so one
     contaminated row produces false POSITIVES in one gap type and false NEGATIVES in two others.
     This is the `x or DEFAULT` shape: an empty header dict is a real input meaning "as nobody",
     not a missing one meaning "as whoever the mission is".

  2. CROSS-SCHEME BLEED. A mission authenticated by Cookie and a persona authenticated by Bearer do
     not collide on a key, so BOTH ride the same request. The server picks; the oracle assumes it
     drove the persona.

WHY THE SUITE IS GREEN ON A REAL DEFECT: every existing authz/IDOR test monkeypatches
`reg._http_send` itself (see tests/test_authz_matrix_driver.py `_reg`/`protected`), which is the
exact function that performs the merge. The contaminating line is never executed under test. These
tests therefore patch BELOW it, at `tools._target_client`, and assert on the headers that actually
reach the wire.

Fixtures here are copied from reality: the registry is a real `ToolRegistry`, the responses are real
`httpx.Response` objects, and the persona/session shapes are the ones
tests/test_authz_matrix_driver.py and tests/test_session_lifecycle.py already use
({"Cookie": "s=A"}, {"Authorization": "Bearer ..."}).

STRUCTURAL-RATCHET SCOPE: the two AST controls below protect ToolRegistry's concrete identity merge
boundary in tools.py. They do not claim that every class in the repository with an attribute named
`_sessions` participates in that mechanism. Their detectors accept an explicit path so the rule can be
falsified against a planted sibling module without overstating the production scope.
"""
from __future__ import annotations

import asyncio
import contextlib

import httpx
import pytest

import scope as S
import tools


BASE = "http://target.tld"


def _registry(session_headers=None):
    """A real ToolRegistry, scoped like the existing authz-matrix driver test does."""
    sc = S.ScopeEngine()
    sc.load_manual(["target.tld"], [], "T")
    return tools.ToolRegistry(sc, lab_mode=True, session_headers=session_headers or {})


@contextlib.contextmanager
def _wiretap(monkeypatch, status=200, text="ok"):
    """Capture the headers that actually reach the transport.

    Patches `tools._target_client`, i.e. BELOW `_http_send`, so the session_headers merge under
    test still runs. Returns a list that receives one dict of real request headers per request.
    """
    seen: list = []

    class _Client:
        async def request(self, method, url, content=None):
            return httpx.Response(status, text=text, request=httpx.Request(method, url))

    class _Ctx:
        def __init__(self, headers):
            self._headers = dict(headers or {})

        async def __aenter__(self):
            seen.append(dict(self._headers))
            return _Client()

        async def __aexit__(self, *exc):
            return False

    def _fake(*args, headers=None, **kwargs):
        return _Ctx(headers)

    monkeypatch.setattr(tools, "_target_client", _fake)
    yield seen


def _send(reg, headers):
    return asyncio.new_event_loop().run_until_complete(
        reg._http_send("GET", BASE + "/api/orders/1", headers, None, True))


# ── shape 1: the anonymous control row ──────────────────────────────────────────────────────────

def test_an_anonymous_persona_request_carries_no_mission_session(monkeypatch):
    """The defect that matters. `_headers_for(role, rank=0)` declares 'as nobody'.

    If the mission session rides that request, the anon row of the authorization matrix is
    authenticated, and `authz.build_matrix` then reports missing_authentication on every protected
    endpoint the mission can reach while suppressing every bfla and horizontal-IDOR confirmation
    (all three read the anon row, `authz.py` lines 77-114 and tools.py's `_accessed(sn, bn)` gate).
    """
    reg = _registry({"Cookie": "sid=THE-MISSION-SESSION"})
    with _wiretap(monkeypatch) as seen:
        _send(reg, tools.Identity())        # exactly what _headers_for returns for rank 0
    wire = seen[0]
    assert "THE-MISSION-SESSION" not in str(wire), (
        "the anonymous control row carried the mission session; the matrix's anon baseline is "
        "authenticated, so missing_authentication over-fires and bfla/IDOR are suppressed: %r" % wire)


def test_the_real_authz_matrix_drives_a_genuinely_anonymous_control_row(monkeypatch):
    """End-to-end, through the REAL `_run_authz_matrix` on a REAL authenticated registry.

    This is the behavioural guard: it asserts the FACT (no request on the wire carried the mission
    session unless it was supposed to), not the declaration that `_headers_for` returns an Identity.
    Nothing here is monkeypatched above `_target_client`, so the merge under test really runs --
    unlike tests/test_authz_matrix_driver.py, which replaces `_http_send` itself and therefore
    cannot see this class of defect at all.
    """
    reg = _registry({"Cookie": "sid=THE-MISSION-SESSION"})
    reg._sessions["user_a"] = {"Cookie": "s=A"}
    reg._sessions["user_b"] = {"Cookie": "s=B"}
    roles = [{"role": "anonymous", "rank": 0}, {"role": "user_a", "rank": 1},
             {"role": "user_b", "rank": 1}]
    inp = {"base_url": BASE, "roles": roles,
           "operations": [{"request": "/basket/2", "path": "/basket/2"}],
           "pair": ("user_a", "user_b"), "owner_identity": "carlos@t.local"}
    with _wiretap(monkeypatch, status=401, text="unauthorized") as seen:
        asyncio.new_event_loop().run_until_complete(reg._run_authz_matrix(inp))

    assert seen, "the matrix made no requests at all -- this guard would pass vacuously"
    anon = [w for w in seen if "s=A" not in str(w) and "s=B" not in str(w)]
    assert anon, "no anonymous row was driven; expected one request carrying neither persona"
    for wire in anon:
        assert "THE-MISSION-SESSION" not in str(wire), (
            "the matrix's anonymous control row reached the wire carrying the mission session: %r" % wire)
    for wire in seen:
        assert not ("THE-MISSION-SESSION" in str(wire) and ("s=A" in str(wire) or "s=B" in str(wire))), (
            "a persona row carried the mission session alongside its own: %r" % wire)


def test_an_explicitly_anonymous_request_is_distinguishable_from_an_absent_one(monkeypatch):
    """Empty is a real input. `{}` must mean 'as nobody' and be honoured as such, while a caller
    that expresses no opinion still inherits the mission identity (today's behaviour, preserved)."""
    reg = _registry({"Cookie": "sid=THE-MISSION-SESSION"})
    with _wiretap(monkeypatch) as seen:
        _send(reg, None)                    # no opinion -> mission identity, unchanged
    assert "THE-MISSION-SESSION" in str(seen[0]), (
        "a caller expressing no identity must still inherit the mission session")


# ── shape 2: cross-scheme bleed between two live identities ─────────────────────────────────────

def test_a_bearer_persona_request_does_not_also_carry_the_missions_cookie(monkeypatch):
    """Cookie-mission + Bearer-persona do not collide on a key, so both ride the same request and
    the server chooses which identity served it. Every BOLA proof depends on that choice being ours."""
    reg = _registry({"Cookie": "sid=THE-MISSION-SESSION"})
    reg._sessions["attacker"] = {"Authorization": "Bearer ATTACKER-TOKEN"}
    with _wiretap(monkeypatch) as seen:
        _send(reg, reg._role_headers({"x_session": "attacker"}, "x"))
    wire = seen[0]
    assert "Bearer ATTACKER-TOKEN" in str(wire), "the persona's own credential must be present"
    assert "THE-MISSION-SESSION" not in str(wire), (
        "the attacker persona's request also carried the mission's cookie — two identities on one "
        "request, and the server picks: %r" % wire)


def test_every_persona_header_producer_returns_an_identity():
    """The three resolvers that turn a role name into headers must all mark the result, or the
    transport will quietly inherit the mission session into it."""
    reg = _registry({"Cookie": "sid=THE-MISSION-SESSION"})
    reg._sessions["r"] = {"Cookie": "s=R"}
    assert isinstance(reg._identity("r"), tools.Identity)
    assert isinstance(reg._resolve_headers({"session": "r"}), tools.Identity)
    assert isinstance(reg._role_headers({"o_session": "r"}, "o"), tools.Identity)


def test_an_unknown_persona_degrades_to_anonymous_never_to_the_mission():
    """A persona that failed to mint must become a control row that proves nothing, not a row that
    silently proves the wrong thing. `x or DEFAULT` where the default is the mission identity is
    exactly how a BOLA control stops running without anyone noticing."""
    reg = _registry({"Cookie": "sid=THE-MISSION-SESSION"})
    ident = reg._identity("never-minted")
    assert isinstance(ident, tools.Identity) and ident == {}


# ── the ratchet: a new raw-global reference must not appear ─────────────────────────────────────

def _toolregistry_identity_ast(path=None):
    import ast
    import pathlib
    src = pathlib.Path(path or tools.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    owner = {}
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for node in ast.walk(fn):
                owner.setdefault(node, fn.name)
    return src, tree, owner


def _raw_toolregistry_session_reads(path=None):
    """Raw per-role reads that bypass ToolRegistry._identity in one source module."""
    import ast
    _src, tree, owner = _toolregistry_identity_ast(path)

    def _is_sessions(n):
        return (isinstance(n, ast.Attribute) and n.attr == "_sessions"
                and isinstance(n.value, ast.Name) and n.value.id == "self")

    bad = []
    for node in ast.walk(tree):
        # The defect shape is EXTRACTING ONE ROLE'S HEADERS to send as a request:
        #   self._sessions[role]        (Load)      /  self._sessions.get(role)
        # A membership test (`role in self._sessions`) reveals no headers, and the whole-dict
        # `.items()` sweep in `_session_kill_is_safe` compares secrets rather than sending them --
        # neither can contaminate a request, so neither is flagged. Narrowing this to the real
        # shape matters: a rule broad enough to flag them would have been silenced as noise.
        hit = False
        if isinstance(node, ast.Subscript) and _is_sessions(node.value) \
                and isinstance(node.ctx, ast.Load):
            hit = True
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr == "get" and _is_sessions(node.func.value):
            hit = True
        if not hit:
            continue
        fn = owner.get(node, "<module>")
        if fn not in ("_identity",):
            bad.append("%s (line %d)" % (fn, node.lineno))
    return bad


def test_toolregistry_reads_self_sessions_through_exactly_one_accessor():
    """TOOLREGISTRY RATCHET. Reading `self._sessions` raw yields a plain dict, which the transport
    silently upgrades to the mission session. `_identity` is the only sanctioned read in tools.py;
    writes are unaffected. A new raw read fails here with the reason, not a diff.
    """
    bad = _raw_toolregistry_session_reads()
    assert not bad, (
        "raw read of self._sessions outside the _identity accessor: %s. Use self._identity(role) -- "
        "it returns an Identity, which the transport will not merge the mission session into. A "
        "plain dict from a raw read looks identical and is contaminated at the wire." % bad)


def _toolregistry_identity_merges(path=None):
    """Mission/caller identity merges outside ToolRegistry's sanctioned functions."""
    import ast
    src, tree, owner = _toolregistry_identity_ast(path)
    allowed = {"_merge_identity", "_run_race"}
    bad = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        unpacks = [i for i, k in enumerate(node.keys) if k is None]
        if len(unpacks) < 2:
            continue
        segs = [ast.get_source_segment(src, node.values[i]) or "" for i in unpacks]
        # a session_headers unpack followed by at least one further unpack = two identities merged
        for pos, seg in enumerate(segs[:-1]):
            if "session_headers" in seg:
                fn = owner.get(node, "<module>")
                if fn not in allowed:
                    bad.append("%s (line %d)" % (fn, node.lineno))
                break
    return bad


def test_toolregistry_merges_mission_identity_in_one_sanctioned_place():
    """TOOLREGISTRY RATCHET. `{**self.session_headers, **caller_headers}` can put two identities on
    one request. `_merge_identity` is the one place allowed to decide that because it honours
    `Identity`; `_run_race` is a mission-identity probe by construction and never resolves a persona.
    """
    allowed = {"_merge_identity", "_run_race"}
    bad = _toolregistry_identity_merges()
    assert not bad, (
        "the mission session is merged with caller-supplied headers outside %s: %s. Route the "
        "request through self._merge_identity(headers) so an Identity (including the empty, "
        "anonymous one) is honoured instead of being silently authenticated." % (sorted(allowed), bad))


def test_a_raw_identity_read_planted_in_an_unseen_module_is_rejected(tmp_path):
    """NEGATIVE CONTROL. This module is outside the old hard-coded tools.__file__ scope."""
    planted = tmp_path / "new_transport.py"
    planted.write_text(
        "class ToolRegistryExtension:\n"
        "    def leak(self, role):\n"
        "        return self._sessions.get(role)\n",
        encoding="utf8",
    )
    bad = _raw_toolregistry_session_reads(planted)
    assert bad == ["leak (line 3)"], (
        "the ToolRegistry identity detector did not reject the planted raw session read")


def test_an_identity_merge_planted_in_an_unseen_module_is_rejected(tmp_path):
    """NEGATIVE CONTROL for the second identity-bypass shape, outside tools.py."""
    planted = tmp_path / "new_transport.py"
    planted.write_text(
        "class ToolRegistryExtension:\n"
        "    def leak(self, caller_headers):\n"
        "        return {**self.session_headers, **caller_headers}\n",
        encoding="utf8",
    )
    bad = _toolregistry_identity_merges(planted)
    assert bad == ["leak (line 3)"], (
        "the ToolRegistry identity detector did not reject the planted two-identity merge")


def test_two_personas_do_not_contaminate_each_other(monkeypatch):
    """The owner/attacker pair the BOLA oracle drives. Each request must carry exactly one identity."""
    reg = _registry()
    reg._sessions["owner"] = {"Cookie": "s=OWNER"}
    reg._sessions["attacker"] = {"Authorization": "Bearer ATTACKER-TOKEN"}
    with _wiretap(monkeypatch) as seen:
        _send(reg, reg._role_headers({"o_session": "owner"}, "o"))
        _send(reg, reg._role_headers({"a_session": "attacker"}, "a"))
    owner_wire, atk_wire = str(seen[0]), str(seen[1])
    assert "OWNER" in owner_wire and "ATTACKER-TOKEN" not in owner_wire, owner_wire
    assert "ATTACKER-TOKEN" in atk_wire and "OWNER" not in atk_wire, atk_wire

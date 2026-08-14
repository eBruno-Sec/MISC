"""Q-021B, the cross-mission half - a TechnologyFact must outlive the mission that found it.

Oracle 3 from the ticket: a second mission on the same target warm-starts with the fact already
present. Without this, `first_seen` is a lie - every mission would rediscover the same nginx and
call it new, and the version history the whole Q-021 family needs would never accumulate.

Also here: the identity gate is applied to what gets PERSISTED as display technology. Six of the
thirteen `tech` rows in live memory were sentence fragments (`fingerprint._POWERED` capturing
prose), and a live run against Mutillidae reproduced a seventh - `'and that the database username'`.
Those are the strings a future feed lookup would send off as product names.
"""
import os
import tempfile

import db
import dependency_intel as di
import memory as memory_mod


def _fact(product, version, host, source="Server header", now=100.0):
    return di.make_tech_fact(product, version=version, source=source, host=host,
                             detector="fingerprint.headers",
                             evidence="Server: %s/%s" % (product, version),
                             location="http://%s/" % host, now=now)


def _recon(facts=None, display=None):
    return {"live_hosts": [{"url": "http://box:3000/", "tech": display or []}],
            "technology": facts or [], "technology_rejected": []}


# ── the snapshot carries the facts, not just the display strings ───────────────────────────────
def test_snapshot_persists_technology_facts():
    snap = memory_mod.snapshot(_recon([_fact("nginx", "1.18.0", "box:3000")]), [], [])
    assert len(snap["technology"]) == 1
    f = snap["technology"][0]
    assert f["product"] == "nginx" and f["version"] == "1.18.0"
    assert f["version_confidence"] == di.LOW
    assert f["source"] == "Server header"
    assert f["evidence"] == "Server: nginx/1.18.0"
    assert f["first_seen"] == 100.0


def test_snapshot_technology_is_json_serialisable():
    """`record_memory` json.dumps the whole snapshot; a fact that cannot serialise loses the
    mission's entire memory row, not just the technology."""
    import json
    snap = memory_mod.snapshot(_recon([_fact("nginx", "1.18.0", "box:3000")]), [], [])
    assert json.loads(json.dumps(snap))["technology"][0]["version"] == "1.18.0"


def test_a_mission_with_no_technology_snapshots_an_empty_list_not_a_missing_key():
    assert memory_mod.snapshot({}, [], [])["technology"] == []
    assert memory_mod.snapshot(_recon(), [], [])["technology"] == []


# ── the identity gate purges prose from the PERSISTED display list ─────────────────────────────
def test_prose_is_no_longer_persisted_as_technology():
    """The measured rows. `'and that the database username'` is live - Mutillidae's
    database-offline page produced it through `_POWERED` during the Q-021B live proof."""
    recon = _recon(display=["nginx", "PHP", "and that the database username",
                            "a MultiJuicer Kubernetes cluste", "in safety mode.", "on."])
    snap = memory_mod.snapshot(recon, [], [])
    assert snap["tech"] == ["PHP", "nginx"]


def test_real_product_names_survive_the_gate():
    recon = _recon(display=["nginx", "PHP", "jQuery", "ASP.NET", "Ruby on Rails",
                            "Express/Node.js", "Microsoft-IIS", "Next.js"])
    snap = memory_mod.snapshot(recon, [], [])
    assert set(snap["tech"]) == {"nginx", "PHP", "jQuery", "ASP.NET", "Ruby on Rails",
                                 "Express/Node.js", "Microsoft-IIS", "Next.js"}


def test_asset_pairs_still_yields_only_strings():
    """REGRESSION. `memory_assets` has a (target_key, kind, value) primary key and stores TEXT. A
    dict leaking in here would break the row model for every kind, not just technology."""
    snap = memory_mod.snapshot(_recon([_fact("nginx", "1.18.0", "box:3000")],
                                      display=["nginx"]), [], [])
    pairs = memory_mod.asset_pairs(snap)
    assert all(isinstance(k, str) and isinstance(v, str) for k, v in pairs)
    assert ("tech", "nginx") in pairs
    assert not any(k == "technology" for k, _ in pairs), \
        "facts live in the snapshot blob, never as memory_assets rows -- a row keyed on a JSON " \
        "blob containing last_seen would insert a new row on every single mission"


def test_diff_is_unchanged_and_does_not_choke_on_facts():
    """REGRESSION. `diff` set-differences every asset kind; handing it dicts would raise
    unhashable. Technology facts are deliberately not diffed here."""
    a = memory_mod.snapshot(_recon([_fact("nginx", "1.18.0", "h")], display=["nginx"]), [], [])
    b = memory_mod.snapshot(_recon([_fact("nginx", "1.25.0", "h")], display=["nginx", "PHP"]), [], [])
    d = memory_mod.diff(a, b)
    assert d["tech"] == {"added": ["PHP"], "removed": []}
    assert "technology" not in d


# ── the warm start: mission two begins knowing what mission one found ──────────────────────────
def _fresh_db():
    db.init(os.path.join(tempfile.mkdtemp(), "tech-mem.db"))


class _Agent:
    memory_note = ""


def _scope(hosts):
    import scope
    sc = scope.ScopeEngine()
    sc.load_manual(hosts, [], "T")
    return sc


def _tools(sc):
    import tools as tools_mod
    return tools_mod.ToolRegistry(sc, lab_mode=True)


def test_warm_start_reseeds_technology_from_the_prior_mission():
    """ORACLE 3. This is the assertion the ticket names."""
    import main as mainmod
    _fresh_db()
    sc = _scope(["box:3000"])
    tkey = memory_mod.target_key(sc.to_dict())
    snap = memory_mod.snapshot(_recon([_fact("nginx", "1.18.0", "box:3000")], display=["nginx"]),
                               ["http://box:3000/"], [])
    db.record_memory(tkey, "mission-1", snap)

    tools = _tools(sc)
    summary = mainmod._warm_start(sc, tools, _Agent())
    assert summary["technology"] == 1
    assert len(tools.recon["technology"]) == 1
    f = tools.recon["technology"][0]
    assert f["product"] == "nginx" and f["version"] == "1.18.0"
    assert f["version_confidence"] == di.LOW
    assert f["evidence"] == "Server: nginx/1.18.0"


def test_a_reseeded_fact_keeps_its_original_first_seen_when_re_observed():
    """The point of persisting `first_seen` at all: mission two must be able to say how long this
    technology has been there, not restart the clock."""
    import fingerprint as fp
    import main as mainmod
    _fresh_db()
    sc = _scope(["box:3000"])
    tkey = memory_mod.target_key(sc.to_dict())
    db.record_memory(tkey, "mission-1",
                     memory_mod.snapshot(_recon([_fact("nginx", "1.18.0", "box:3000", now=100.0)],
                                                display=["nginx"]), [], []))
    tools = _tools(sc)
    mainmod._warm_start(sc, tools, _Agent())
    fp.record_facts(tools.recon, "http://box:3000/", {"Server": "nginx/1.18.0"}, "", "", now=900.0)
    assert len(tools.recon["technology"]) == 1
    assert tools.recon["technology"][0]["first_seen"] == 100.0
    assert tools.recon["technology"][0]["last_seen"] == 900.0


def test_an_out_of_scope_fact_is_not_reseeded():
    """A since-narrowed scope must silently drop stale intel, exactly as it already does for
    subdomains and endpoints. A warm start is not a scope bypass."""
    import main as mainmod
    _fresh_db()
    sc = _scope(["box:3000"])
    tkey = memory_mod.target_key(sc.to_dict())
    snap = memory_mod.snapshot(_recon([_fact("nginx", "1.18.0", "box:3000"),
                                       _fact("apache", "2.4.7", "gone.example.com")],
                                      display=["nginx"]), [], [])
    db.record_memory(tkey, "mission-1", snap)
    tools = _tools(sc)
    mainmod._warm_start(sc, tools, _Agent())
    assert [f["host"] for f in tools.recon["technology"]] == ["box:3000"]


def test_warm_start_merges_into_recon_rather_than_replacing_it():
    """A warm start must never DESTROY a fact already in recon. Today `_warm_start` runs before any
    fingerprinting so recon is empty and assignment would look identical -- measured: the mutant that
    replaces the merge with an assignment survived the rest of this file. That makes it a latent
    trap, not a non-issue: anything that later warm-starts twice, or seeds after a first probe,
    would silently drop live observations."""
    import main as mainmod
    _fresh_db()
    sc = _scope(["box:3000"])
    tkey = memory_mod.target_key(sc.to_dict())
    db.record_memory(tkey, "mission-1",
                     memory_mod.snapshot(_recon([_fact("nginx", "1.18.0", "box:3000")]), [], []))
    tools = _tools(sc)
    tools.recon["technology"] = [_fact("php", "7.4.3", "box:3000", source="X-Powered-By", now=50.0)]
    mainmod._warm_start(sc, tools, _Agent())
    assert sorted(f["product"] for f in tools.recon["technology"]) == ["nginx", "php"], \
        "the already-observed php fact must survive the seed"


def test_warm_start_with_no_prior_technology_is_a_clean_zero():
    import main as mainmod
    _fresh_db()
    sc = _scope(["box:3000"])
    tools = _tools(sc)
    summary = mainmod._warm_start(sc, tools, _Agent())
    assert summary.get("technology", 0) == 0
    assert tools.recon["technology"] == []


def test_technology_alone_is_enough_to_warm_start():
    """A prior mission that found ONE technology and no subdomains/endpoints must not be discarded
    by the `if not assets: return` early exit - the falsy-default shape this codebase has been bitten
    by twice."""
    import main as mainmod
    _fresh_db()
    sc = _scope(["box:3000"])
    tkey = memory_mod.target_key(sc.to_dict())
    # no live_hosts at all, so the snapshot records no host / subdomain / endpoint -- only the fact
    snap = memory_mod.snapshot({"technology": [_fact("nginx", "1.18.0", "box:3000")]}, [], [])
    assert snap["hosts"] == [] and snap["subdomains"] == [] and snap["endpoints"] == []
    db.record_memory(tkey, "mission-1", snap)
    tools = _tools(sc)
    summary = mainmod._warm_start(sc, tools, _Agent())
    assert summary["technology"] == 1
    assert len(tools.recon["technology"]) == 1

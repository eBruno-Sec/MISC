"""Q-121 -- the live `tools.graph` was never persisted, so every live-graph defect was
un-postmortem-able.

Only the report-time `AssetGraph.build_from_engagement(...).save()` reconstruction ever reached
`/app/data/graph` -- a FRESH graph rebuilt from `tools.recon`/`tools.urls`/findings at teardown,
not the object `_seed_and_project_graph`/`_graph_primary_state` actually read and wrote to DURING
the mission. Q-109 needed a bespoke reproduction harness to see the live graph's state because
nothing on disk ever carried it (docs/handoff/q109_hostless_producer.md section 4, H7 -- scanned
491 persisted graph files, 26827 endpoint nodes, 0 hostless, because every one of them was the
report-time rebuild).

FIX: `AssetGraph.save`/`load` take an additive `suffix` (default "", every existing caller
unaffected) so the live graph can be persisted under its own filename without colliding with the
report-time one. `main._record_memory` -- the one teardown call site that already saves the
report-time graph -- now also best-effort-saves `tools.graph` with `suffix="_live"`.
"""
import os
import tempfile

from asset_graph import AssetGraph, build_from_engagement


def test_suffix_defaults_to_the_existing_filename_unchanged():
    """Every caller before this ticket used bare save()/load() -- must be byte-identical."""
    d = tempfile.mkdtemp()
    g = AssetGraph("m1")
    g.observe("endpoint", "https://x.com/a", source="crawl")
    path = g.save(base_dir=d)
    assert os.path.basename(path) == "m1.json"
    reloaded = AssetGraph.load("m1", base_dir=d)
    assert len(reloaded.nodes("endpoint")) == 1


def test_a_suffixed_save_does_not_collide_with_the_unsuffixed_one():
    d = tempfile.mkdtemp()
    report_time = build_from_engagement("m2", recon={}, urls=["https://x.com/report"], findings=[])
    report_time.save(base_dir=d)

    live = AssetGraph("m2")
    live.observe("endpoint", "https://x.com/live-only", source="crawl")
    live.save(base_dir=d, suffix="_live")

    assert sorted(os.listdir(d)) == ["m2.json", "m2_live.json"]
    # each file keeps its own content -- the live one is not the report-time rebuild
    reloaded_report = AssetGraph.load("m2", base_dir=d)
    reloaded_live = AssetGraph.load("m2", base_dir=d, suffix="_live")
    report_paths = {n.get("key") for n in reloaded_report.nodes("endpoint")}
    live_paths = {n.get("key") for n in reloaded_live.nodes("endpoint")}
    assert "/live-only" in str(live_paths) or any("live-only" in p for p in live_paths)
    assert live_paths != report_paths


def test_the_live_graph_carries_state_the_report_time_rebuild_never_would():
    """The whole point: a node type only the LIVE graph would ever see (no report-time producer
    projects it from recon/urls/findings alone) survives the round trip."""
    d = tempfile.mkdtemp()
    live = AssetGraph("m3")
    live.observe("capability", "database_read", source="planner")
    live.save(base_dir=d, suffix="_live")
    reloaded = AssetGraph.load("m3", base_dir=d, suffix="_live")
    assert any(n.get("kind") == "capability" for n in reloaded.nodes("capability"))


def test_record_memory_persists_the_live_graph_under_the_live_suffix(tmp_path, monkeypatch):
    """End-to-end through the actual teardown call site (`main._record_memory`), not just the
    library function -- this is where Q-109 needed the bespoke harness instead."""
    import pytest
    pytest.importorskip("fastapi")
    monkeypatch.setenv("BBH_DATA_DIR", str(tmp_path))
    import main as mainmod
    import db as dbmod
    import tempfile as _tf
    dbmod.init(os.path.join(_tf.mkdtemp(), "t.db"))

    class _FakeTools:
        def __init__(self):
            self.recon = {}
            self.urls = ["https://x.com/a"]
            self.graph = AssetGraph("sessX")
            self.graph.observe("endpoint", "https://x.com/live-marker", source="crawl")

        class _State:
            def to_dict(self):
                return {"capabilities": []}
        state = _State()

    session_id = "sessX"
    dbmod.create_mission(session_id, "P", "active", "o", {"in_scope": ["x.com"]}, {})
    mainmod.sessions[session_id] = {"tools": _FakeTools(), "agent": object()}
    try:
        mainmod._record_memory(session_id)
    finally:
        mainmod.sessions.pop(session_id, None)

    live_path = tmp_path / "graph" / "sessX_live.json"
    assert live_path.exists(), "the live graph must reach disk from the real teardown call site"
    reloaded = AssetGraph.load(session_id, base_dir=str(tmp_path / "graph"), suffix="_live")
    assert any("live-marker" in str(n.get("key", "")) for n in reloaded.nodes("endpoint"))

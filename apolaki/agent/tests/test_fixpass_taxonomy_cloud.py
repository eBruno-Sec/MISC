"""Fix-pass truth/standards tail: #12 WSTG cache_deception taxonomy, #13 run_cloud_probe orchestration."""
import asyncio

import agent as agent_mod
import scope as scope_mod
import techniques as T
from tools import ToolResult


# ── #12: cache_deception maps to WSTG-CONF-13 (Path Confusion), not the OAuth control ──
def test_cache_deception_maps_to_path_confusion_at_runtime():
    t = T.get("cache_deception")
    assert t["wstg"] == "WSTG-CONF-13"          # authoritative _WSTG map now carries it (was absent -> unmapped)
    assert t["wstg"] != "WSTG-ATHZ-05"          # not OAuth Weaknesses
    import wstg_catalog as wc
    assert wc.CATALOG["WSTG-CONF-13"] == "Path Confusion"   # the id it points to really is path confusion


# ── #13: run_cloud_probe is orchestrated (scheduled for discovered buckets) + auto-stored ──
class _BucketTools:
    def __init__(self):
        self.calls = []
        self.cloud_bucket_urls = ["http://app/backups"]   # discovered during harvest
        self.recon, self.urls, self.session_headers = {}, [], {}

    async def execute(self, name, inp, sid):
        self.calls.append((name, inp.get("url")))
        f = {"title": "Public bucket", "family": "sensitive_exposure", "confidence": "confirmed",
             "target": inp.get("url"), "severity": "high"}
        return ToolResult(name, inp.get("url"), True, "{}", [f])


def test_cloud_probe_is_scheduled_for_discovered_buckets():
    assert "run_cloud_probe" in agent_mod._AUTO_STORE_TOOLS      # confirmed-by-oracle -> auto-stored
    eng = scope_mod.ScopeEngine()
    eng.load_manual(["app"], [], "P")
    a = agent_mod.BBHAgent(eng, _BucketTools(), asyncio.Event(), mode="active",
                           strategy="deterministic", mission_id=None, auto_approve=True)
    evs = asyncio.run(_drain(a._probe_cloud_storage("s")))
    assert ("run_cloud_probe", "http://app/backups") in a.tools.calls   # the island is now fed
    fam = [e["finding"]["family"] for e in evs if e.get("type") == "finding"]
    assert "sensitive_exposure" in fam and a.findings                    # confirmed finding surfaced + kept


def test_cloud_probe_skipped_in_passive_mode():
    eng = scope_mod.ScopeEngine()
    eng.load_manual(["app"], [], "P")
    a = agent_mod.BBHAgent(eng, _BucketTools(), asyncio.Event(), mode="passive",
                           strategy="deterministic", mission_id=None)
    asyncio.run(_drain(a._probe_cloud_storage("s")))
    assert a.tools.calls == []                                   # ACTIVE tool blocked by _exec_internal in passive


async def _drain(agen):
    return [ev async for ev in agen]

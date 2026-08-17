"""Q-050(b) SOUNDNESS -- the islands lane's verdicts, as executable facts.

`test_engine_reachability.py` answers "can anything call this engine?". This file answers the
question that has to be settled BEFORE anything is allowed to call it: **is its oracle sound, and
what happens to what it produces?** An engine that has never run has never had its false-positive
behaviour measured, and wp1 is the precedent for what adding an unmeasured engine to the always-on
path costs.

Full write-up, with the live measurements these tests encode: `docs/handoff/islands.md`.

Two MEASURED defects are pinned here as STRICT xfails so they are executable evidence rather than
prose in a hand-off. When an owner fixes one, the xfail XPASSes, the suite goes red, and the marker
has to be retired deliberately -- the pattern `test_source_lane_breaker.py` established.

EVERY fixture in this file is copied from a real run. The `enumerate_ids` lead below is the exact
record emitted by `ToolRegistry._run_enumerate_ids` against `http://juice-shop:3000/api/Products/{id}`
on 2026-08-16; the EXIF case reads the real bytes off the running lab rather than inventing a JPEG.
"""
import asyncio

import pytest

import agent as agent_mod
import asvs_model
import tools
import workflow as wf
from scope import ScopeEngine


def _reg():
    sc = ScopeEngine()
    sc.load_manual(["juice-shop:3000"], [], "island-soundness")
    return tools.ToolRegistry(sc, lab_mode=True)


# The REAL lead, copied verbatim from a live run of _run_enumerate_ids against Juice Shop's
# /api/Products/{id} (ids 1..8). Not a shape invented for the test: 8 of 8 ids came back distinct
# from the nonexistent-id baseline, so the engine emitted exactly this.
REAL_ENUMERATE_IDS_LEAD = {
    "title": "Enumerable objects by id (8 in 1..8)",
    "severity": "medium",
    "target": "http://juice-shop:3000/api/Products/{id}",
    "family": "idor",
    "confidence": "lead",
    "tags": ["idor", "enumeration", "bola"],
    "description": ("Sequential object ids return distinct populated records. If these belong to "
                    "other users this is a bulk IDOR - confirm ownership with confirm_idor."),
    "evidence": "accessible ids: [1, 2, 3, 4, 5, 6, 7, 8]",
}


def _one_step_workflow():
    return {"id": "island-soundness-probe",
            "steps": [{"do": "enumerate_ids",
                       "url_template": "http://juice-shop:3000/api/Products/{id}",
                       "start": 1, "end": 8}]}


def _reg_with_stubbed_step(result_findings):
    """A REAL ToolRegistry with exactly one step method replaced, so workflow.run runs against the
    real state object / real substitution / real assertion path and only the transport is stubbed."""
    reg = _reg()

    async def _stub(inp):
        return tools.ToolResult("enumerate_ids", inp.get("url_template", ""), True,
                                '{"template": "x", "count": 8}', list(result_findings))

    reg._run_enumerate_ids = _stub
    return reg


def test_the_stubbed_step_really_does_emit_a_finding():
    """NEGATIVE CONTROL for the xfail below.

    If the stub ever stopped emitting a finding, the xfail would xfail for the wrong reason and this
    file would be pinning nothing. Assert the input to the experiment before asserting the output.
    """
    reg = _reg_with_stubbed_step([REAL_ENUMERATE_IDS_LEAD])
    res = asyncio.run(reg._run_enumerate_ids({"url_template": "http://juice-shop:3000/x/{id}"}))
    assert len(res.findings) == 1
    assert res.findings[0]["family"] == "idor"


def test_workflow_carries_its_steps_findings_out():
    """A workflow that runs an engine which found something must say so.

    This is the difference between 'the mission paid for the requests and reported nothing' and a
    finding. run_workflow executes REAL attacks -- acquire_session, confirm_idor, test_numeric_abuse
    -- so a silent return is the false-clean shape, not a missing nicety.
    """
    reg = _reg_with_stubbed_step([REAL_ENUMERATE_IDS_LEAD])
    res = asyncio.run(wf.run(reg, _one_step_workflow()))
    assert res["ran"] is True
    emitted = res.get("findings") or [f for e in res.get("log", []) for f in (e.get("findings") or [])]
    assert emitted, "workflow.run returned no findings although its only step emitted one"
    assert emitted[0]["family"] == "idor"


def test_run_workflow_tool_result_carries_them_too():
    """The other half of the same fix, at the boundary agent._run_tool actually reads.

    This test existed to make a PARTIAL fix visible: `workflow.run` could start returning findings
    and this would still be [] while tools.py hardcoded the empty list -- the 'verify BOTH halves of
    a fix' rule, which this codebase has broken before. Both halves landed under Q-054, so the pin is
    now inverted: it holds the FIX in place instead of the defect. If _run_workflow ever stops
    forwarding, this goes red rather than the mission quietly reporting clean.
    """
    reg = _reg_with_stubbed_step([REAL_ENUMERATE_IDS_LEAD])
    res = asyncio.run(reg._run_workflow({"workflow": _one_step_workflow()}))
    assert res.success is True
    assert len(res.findings) == 1, "tools._run_workflow stopped forwarding workflow.run's findings"
    assert res.findings[0]["family"] == "idor"
    assert res.findings[0]["engine"] == "enumerate_ids"   # provenance names the inner producer


def test_wiring_run_workflow_without_auto_store_would_still_drop_everything():
    """The THIRD sink, and the reason the fix was three edits and not one.

    agent.py auto-stores a dispatched tool's findings only when the tool name is in
    _AUTO_STORE_TOOLS. All three sinks are now closed under Q-054, so this pin is inverted: it holds
    the wiring in place rather than recording its absence. Removing run_workflow from that set would
    make a deterministic mission drop every finding the workflow produced and report the target
    clean, which is why this asserts membership rather than merely documenting it.
    """
    assert "confirm_idor" in agent_mod._AUTO_STORE_TOOLS
    assert "run_workflow" in agent_mod._AUTO_STORE_TOOLS, (
        "run_workflow lost auto-store; a deterministic mission will silently drop the findings "
        "workflow.run and tools._run_workflow now forward, and the run will look clean")


def test_island_lead_families_are_quarantined_from_the_asvs_model():
    """Why the sound-but-unpromotable islands cannot spuriously FAIL an objective.

    Character-for-character, against the model rather than against the page: `enumerate_ids` emits
    family 'idor' and `run_metadata` emits family 'exposure', and both strings ARE consumed -- so
    neither is invisible downstream, and neither is a near-miss spelling (the defect that made four
    objectives unfailable on `default_creds` vs `default_credentials`).
    """
    consumers = {f for o in asvs_model.OBJECTIVES for f in o["violated_by"]}
    assert "idor" in consumers
    assert "exposure" in consumers
    assert [o["cid"] for o in asvs_model.OBJECTIVES if "idor" in o["violated_by"]] == ["ATHZ-00", "ATHZ-01"]
    assert [o["cid"] for o in asvs_model.OBJECTIVES if "exposure" in o["violated_by"]] == ["COMM-03"]
    # ...and the content-discovery trio's family is consumed by NOTHING, so its lead is invisible
    # to the objective model however it is wired.
    assert "recon" not in consumers


# `run_ferox` was the third case here until Q-057 deleted it, its two siblings and their shared
# driver -- three specs advertising content discovery with no binary in the image. `run_dork_gen` is
# the surviving producer of a `recon` lead (tools.py:1299), so the routing rule is still exercised
# against a family that something actually emits. Naming a deleted engine in a test is the stale
# citation `test_cited_functions_exist.py` exists to catch, one file over.
@pytest.mark.parametrize("tool,family", [("enumerate_ids", "idor"),
                                         ("run_metadata", "exposure"),
                                         ("run_dork_gen", "recon")])
def test_island_leads_never_enter_the_confirmed_report(tool, family):
    """The quarantine that makes the above safe, asserted at the routing function itself.

    All three engines emit confidence 'lead'. agent._is_confirmed must route those to leads, never
    to findings -- report.py passes only CONFIRMED findings to asvs_model.assess, so this is the
    single check standing between an 'idor' lead on a PUBLIC product catalogue and a failed ATHZ-01.
    """
    ag = agent_mod.BBHAgent.__new__(agent_mod.BBHAgent)
    lead = {"confidence": "lead", "family": family, "severity": "medium", "evidence": "real evidence"}
    assert agent_mod.BBHAgent._is_confirmed(ag, tool, lead) is False


def test_external_surface_cannot_emit_a_finding_on_any_path():
    """run_external_surface's soundness argument in one line: it makes no claim.

    Every return in _run_external_surface passes a literal [] for findings, so there is no
    false-positive surface to measure. If a future change gives it a finding, that change needs its
    own oracle argument and this test is where it gets caught.
    """
    import inspect
    import re
    src = inspect.getsource(tools.ToolRegistry._run_external_surface)
    returns = re.findall(r"return ToolResult\((.*?)\)\n", src, re.S)
    assert returns, "could not read the returns; the scan would pass for free"
    for r in returns:
        assert re.search(r",\s*\[\]", r), (
            "run_external_surface now returns a non-empty findings list: %r" % r[:160])


# --------------------------------------------------------------------------------------------
# The metadata false negative. LAB-GATED on purpose: the only honest fixture is the file the
# target actually serves, and this lane will not invent a JPEG to make a test go red. When the
# lab is down there is no measurement, so it skips -- a skip here is an ABSENT measurement and is
# never evidence of a pass. `scripts/liveness.sh` is the gate that says whether the lab was up.
# --------------------------------------------------------------------------------------------
JUICE = "http://juice-shop:3000"
GEO_PHOTO = "/assets/public/images/uploads/magn(et)ificent!-1571814229653.jpg"


def _fetch_geo_photo():
    import urllib.parse

    import httpx
    url = JUICE + "/" + urllib.parse.quote(GEO_PHOTO.lstrip("/"))
    try:
        r = httpx.get(url, timeout=10, follow_redirects=True)
    except Exception as e:                                     # lab not up
        pytest.skip("juice-shop lab unreachable (%s); no measurement, not a pass" % e)
    if r.status_code != 200 or not r.content.startswith(b"\xff\xd8"):
        pytest.skip("juice-shop served no JPEG at the geo-stalking path; no measurement")
    return r.content


def _has_binary_gps_ifd(data: bytes) -> bool:
    """Ground truth, independent of Apolaki: walk to IFD0 and look for the GPS IFD pointer 0x8825."""
    import struct
    k = data.find(b"Exif\x00\x00")
    if k < 0:
        return False
    tiff = k + 6
    bo = "<" if data[tiff:tiff + 2] == b"II" else ">"
    off = struct.unpack(bo + "I", data[tiff + 4:tiff + 8])[0]
    p = tiff + off
    n = struct.unpack(bo + "H", data[p:p + 2])[0]
    return any(struct.unpack(bo + "H", data[p + 2 + j * 12:p + 4 + j * 12])[0] == 0x8825
               for j in range(n))


def test_the_geo_photo_really_does_carry_gps_metadata():
    """NEGATIVE CONTROL for the xfail below: assert the fixture before asserting the engine.

    FAILS rather than skips if the lab is up and the file no longer carries a GPS IFD -- an engine
    reporting clean on a clean file is correct, and the xfail below would be pinning nothing.
    """
    data = _fetch_geo_photo()
    assert _has_binary_gps_ifd(data), (
        "the Juice Shop geo-stalking photo no longer carries a binary GPS IFD; the false-negative "
        "xfail below has lost its positive case and must be re-aimed, not deleted")
    assert b"GPS" not in data, (
        "this file now contains the ASCII string 'GPS'; upload_tool's ASCII branch could fire on it "
        "and the xfail below would pass for the wrong reason")


def test_native_metadata_reader_sees_binary_exif_gps():
    """The native fallback is only a fallback if it can read the format it is a fallback for."""
    import upload_tool
    data = _fetch_geo_photo()
    meta = upload_tool.extract_metadata(data)
    assert any("gps" in k.lower() or "coord" in k.lower() for k in meta), (
        "extract_metadata returned %r for a file carrying a GPS IFD" % (meta,))

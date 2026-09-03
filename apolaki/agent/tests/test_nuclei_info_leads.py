"""Q-173. nuclei's yield is almost entirely `info`, and `info` was filtered out.

MEASURED against mutillidae, with the -jsonl flag fixed so the binary actually runs:

    tags tech,misconfig   severity low,medium,high,critical   ->   2 findings
    tags tech,misconfig   severity info,low,...,critical      ->  23 findings
    every template        severity low,medium,high,critical   ->   0 findings

The `tech` tag alone is 967 templates and is overwhelmingly info-severity, so the default tag set
asked for a body of templates the severity filter then discarded. Excluding info is right for a
REPORT and wrong for a SCAN: "this host runs WordPress with plugin X at version Y and xmlrpc.php is
reachable" is what makes the next probe targeted.

The whole change rests on the grading. 21 extra LEADS is intelligence; 21 extra CONFIRMED findings
would be a false-positive incident, which is the thing this platform exists not to do. Both
directions are pinned.
"""
import asyncio

import pytest

import scope as S
import tools


LINES = [
    '{"template-id":"wordpress-detect","host":"http://t.local","matched-at":"http://t.local",'
    '"info":{"name":"WordPress Detection","severity":"info"}}',
    '{"template-id":"phpinfo-files","host":"http://t.local","matched-at":"http://t.local/phpinfo.php",'
    '"info":{"name":"phpinfo exposed","severity":"low"}}',
    '{"template-id":"git-config","host":"http://t.local","matched-at":"http://t.local/.git/config",'
    '"info":{"name":"Git config exposed","severity":"high"}}',
]


def _run(monkeypatch, lines):
    sc = S.ScopeEngine()
    sc.load_manual(["t.local"], [], "T")
    reg = tools.ToolRegistry(sc, mission_id=None, lab_mode=True)

    async def _fake_cmd(cmd, timeout=None, **kw):
        _fake_cmd.argv = list(cmd)
        return tools.CmdResult("\n".join(lines), "", 0)

    monkeypatch.setattr(reg, "_cmd", _fake_cmd)
    res = asyncio.run(reg._run_nuclei({"target": "http://t.local"}))
    return res, _fake_cmd.argv


def test_info_severity_is_requested_from_the_binary(monkeypatch):
    """THE regression: the filter used to drop `info`, discarding most of the template set."""
    _res, argv = _run(monkeypatch, LINES)
    sev = argv[argv.index("-severity") + 1]
    assert "info" in sev.split(","), (
        "nuclei was asked for %r, which excludes the severity carrying most of its templates" % sev)


def test_an_info_detection_is_a_lead_not_a_confirmed_finding(monkeypatch):
    """The half that makes the change safe. A detection is not a vulnerability claim."""
    res, _argv = _run(monkeypatch, LINES)
    info = [f for f in res.findings if str(f.get("severity")).lower() == "info"]
    assert info, "the info record was dropped entirely: %r" % [f.get("template") for f in res.findings]
    for f in info:
        assert f.get("confidence") == "candidate", (
            "a technology DETECTION was graded %r -- 21 of these arriving as confirmed findings is "
            "a false-positive incident, not coverage" % f.get("confidence"))
        assert f.get("family") == "nuclei_info"


def test_a_real_severity_finding_is_not_downgraded(monkeypatch):
    """The negative control. Demoting everything would be a worse defect than the missing coverage."""
    res, _argv = _run(monkeypatch, LINES)
    high = [f for f in res.findings if str(f.get("severity")).lower() == "high"]
    assert high, "the high-severity record vanished"
    assert high[0].get("family") != "nuclei_info"
    assert high[0].get("confidence") != "candidate", (
        "an exposed .git/config is not a technology detection and must not be graded as one")


def test_every_record_survives_parsing(monkeypatch):
    res, _argv = _run(monkeypatch, LINES)
    assert len(res.findings) == len(LINES)
    assert res.success is True

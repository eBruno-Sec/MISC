"""Probe SHAPES for OS command injection, and the negative control for each.

The shipping payloads all APPEND to the observed value (`<v>; echo ...`). That shape assumes the
value lands inside a string a shell will parse. It is wrong for the other common sink:

    Runtime.exec(cmd)  /  execve(argv)      -- the string is tokenised and run as argv DIRECTLY

There is no shell there, so `;` is just another argv word and no metacharacter payload can ever
execute. The shape that works on an argv sink REPLACES the value with a bare command.

Every shape below is paired with the control that must NOT confirm it, because a probe shape without
a negative control is how this codebase previously shipped an oracle that confirmed on reflection.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cmdi_tool as cmdi  # noqa: E402


# ── argv-sink output payloads ────────────────────────────────────
def test_argv_payloads_replace_the_value_they_do_not_append():
    """The whole point of the shape: an argv sink is destroyed by a prefix."""
    for item in cmdi.argv_payloads("8.8.8.8"):
        assert not item["payload"].startswith("8.8.8.8"), item
        assert "8.8.8.8" not in item["payload"], item


def test_argv_payloads_are_read_only_commands():
    """No-DoS / non-destructive: the shape proves execution, it never changes state."""
    for item in cmdi.argv_payloads(""):
        head = item["payload"].split()[0]
        assert head in {"id", "cat", "uname"}, item


def test_argv_proof_strings_are_absent_from_the_payloads():
    """THE control that makes the shape reflection-immune.

    `id` proves execution through `uid=0(root) gid=0(root)`, which the payload `id` does not
    contain. An endpoint that merely echoes the payload therefore cannot satisfy the oracle -- the
    same property that makes the computed-echo marker safe."""
    for item in cmdi.argv_payloads("x"):
        assert cmdi.analyze_output("", item["payload"]) is None, item


def test_argv_output_confirms_only_on_real_command_output():
    body = "<p>Here is the standard output of the command:<br>uid=0(root) gid=0(root) groups=0(root)"
    assert cmdi.analyze_output("home page", body)["kind"] == "command-output"
    # already present in the baseline -> not caused by us -> not a finding
    assert cmdi.analyze_output(body, body) is None


def test_argv_bare_noncommand_is_the_negative_control():
    """A bare value that is not a command must produce nothing, however the app renders it."""
    for echoed in ("zqnotacmd", "you sent: zqnotacmd", "Cannot run program \"zqnotacmd\""):
        assert cmdi.analyze_output("baseline", echoed) is None


# ── argv-sink time payloads ──────────────────────────────────────
def test_argv_time_payloads_pair_every_probe_with_a_zero_delay_control():
    items = cmdi.argv_time_payloads(5)
    assert items, "argv time shape must exist"
    for item in items:
        assert "control" in item and "payload" in item
        # the control is the SAME command with the delay removed -- a trigger-removed differential
        assert item["control"] != item["payload"]
        assert not item["payload"].startswith(("&", ";", "|", "`", "$"))


def test_argv_time_control_is_the_same_command_with_the_delay_removed():
    for item in cmdi.argv_time_payloads(7):
        assert item["payload"].split()[0] == item["control"].split()[0]


def test_time_oracle_declines_a_uniformly_slow_endpoint():
    """An endpoint slow for EVERY input must not confirm -- the control is compared, not assumed."""
    assert cmdi.analyze_time(4.9, 5.1, 5) is False      # both slow: no differential
    assert cmdi.analyze_time(0.1, 0.4, 5) is False      # no delay at all
    assert cmdi.analyze_time(0.1, 5.3, 5) is True       # real injected delay


# ── argv-sink OOB payloads ───────────────────────────────────────
def test_argv_oob_payloads_are_bare_and_carry_the_probe_url():
    probe = "http://agent:8000/oob/deadbeef"
    payloads = cmdi.argv_oob_payloads(probe)
    assert payloads
    for p in payloads:
        assert p.startswith(("curl", "wget")), p
        assert probe in p
        # bare: no shell separator, because an argv sink never parses one
        assert not any(sep in p for sep in (";", "|", "`", "$(", "&"))


def test_argv_oob_payloads_do_not_prefix_an_observed_value():
    probe = "http://agent:8000/oob/deadbeef"
    for p in cmdi.argv_oob_payloads(probe):
        assert not p.startswith("8.8.8.8")


# ── the append shape must keep working; this is additive ─────────
def test_append_shape_is_unchanged():
    items = cmdi.output_payloads("8.8.8.8")
    assert all(i["payload"].startswith("8.8.8.8") for i in items)
    assert cmdi.EXPECTED not in "".join(i["payload"] for i in items)


# ── WIRING: the shape must be REACHED by the engine, not merely defined ──
# A registered payload that no code path sends is an island, and a guard that checks the declaration
# instead of the fact passes exactly the case it exists to catch. These drive the real engine.
def _run_form_cmdi(responder, fields=("host",)):
    """Drive the shipping _run_form_cmdi against a stubbed transport. `responder(value)` is the
    app: it receives the value the engine put in the field and returns the response body."""
    import asyncio
    from urllib.parse import parse_qsl

    import scope as scope_mod
    from tools import ToolRegistry

    eng = scope_mod.ScopeEngine()
    eng.load_manual(["host.local"], [], "P")
    reg = ToolRegistry(eng, mission_id=None, lab_mode=True)
    sent = []

    async def fake_http(url, method="GET", headers=None, body="", capture=False, **kw):
        val = dict(parse_qsl(body or "", keep_blank_values=True)).get(fields[0], "")
        if headers:
            for k, v in headers.items():
                if k.lower() not in ("content-type",):
                    val = v
        sent.append(val)
        return {"status": 200, "body": responder(val), "error": "", "final_url": url}

    reg._http = fake_http
    res = asyncio.new_event_loop().run_until_complete(
        reg._run_form_cmdi({"url": "http://host.local/exec", "fields": list(fields)}))
    return res, sent


def test_engine_reaches_the_argv_shape_on_a_sink_no_separator_can_touch():
    """An argv sink: it runs argv[0] and echoes anything it cannot run.

    The append payloads reflect and must NOT confirm; the bare argv payload must."""
    def argv_sink(value):
        if value.strip() == "id":
            return "<p>uid=0(root) gid=0(root) groups=0(root)</p>"
        return "<p>you sent: %s</p>" % value            # pure reflection for everything else

    res, sent = _run_form_cmdi(argv_sink)
    assert "id" in sent, "engine never sent a bare argv payload: the shape is an island"
    assert res.findings, "argv sink went undetected"
    f = res.findings[0]
    assert f["family"] == "cmdi" and f["confidence"] == "confirmed"
    assert "argv" in " ".join(f["tags"])


def test_engine_does_not_confirm_on_an_endpoint_that_only_reflects():
    """THE negative control for the whole shape. An app that echoes every value, including the bare
    commands, executes nothing -- and must produce no finding."""
    res, sent = _run_form_cmdi(lambda value: "<p>you sent: %s</p>" % value)
    assert "id" in sent, "control is vacuous unless the argv payload was actually sent"
    assert res.findings == [], "confirmed on reflection alone: %r" % (res.findings,)


def test_engine_still_confirms_the_shell_sink_through_the_append_shape():
    """Additive, not a replacement: a real shell sink must still be caught by the old shape."""
    def shell_sink(value):
        if "echo" in value and "$((" in value:
            return "<p>%s</p>" % cmdi.EXPECTED       # the shell computed the product
        return "<p>you sent: %s</p>" % value

    res, _ = _run_form_cmdi(shell_sink)
    assert res.findings and res.findings[0]["family"] == "cmdi"
    assert "argv" not in " ".join(res.findings[0]["tags"])


def test_findings_name_the_shape_that_proved_it():
    f = cmdi.argv_output_finding("https://t/p", "host", "id",
                                 {"kind": "command-output", "match": "uid=0(root) gid=0"})
    assert f["family"] == "cmdi"
    assert f["confidence"] == "confirmed"
    assert f["cwe"] == "CWE-78"
    assert "argv" in " ".join(f["tags"])

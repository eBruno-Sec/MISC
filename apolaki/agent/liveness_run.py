"""Runner for the engine-liveness gate. All the I/O lives here; liveness.py stays pure.

    python liveness_run.py              # run every check, compare to the committed baseline
    python liveness_run.py --update     # accept the current result AS the new baseline

`--update` only ever ADDS. A regression cannot be laundered by re-baselining: an engine that was live and
is not now still fails first, and the baseline is written only when the gate passes.
"""
from __future__ import annotations

import asyncio
import json
import os
import socket
import sys
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import liveness as lv                                          # noqa: E402

BASELINE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tests", "liveness_baseline.json")

# Lab -> (host, port) to test reachability. A lab that does not answer is SKIPPED, never passed.
_LAB_ADDR = {
    "conpot": ("conpot", 5020), "snmpd": ("snmpd", 161), "openldap": ("openldap", 389),
    "smb": ("smb", 445), "dvga": ("dvga", 5013), "domsource": ("domsource", 8080),
    "clientauthz": ("clientauthz", 8080),
}


def _reachable(lab: str, timeout: float = 3.0) -> bool:
    host, port = _LAB_ADDR.get(lab, (lab, 80))
    # snmpd is UDP-only; a TCP connect would always fail, so treat DNS resolution as the liveness signal.
    if lab == "snmpd":
        try:
            socket.gethostbyname(host)
            return True
        except Exception:
            return False
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except Exception:
        return False


def _scope_for(check: dict):
    from scope import ScopeEngine
    hosts = set()
    if check["kind"] == "tool":
        u = check["input"].get("url")
        hosts.add(urlparse(u).hostname if u else check["input"].get("host"))
    else:
        hosts.add(urlparse(check["kwargs"]["base"]).hostname)
    sc = ScopeEngine()
    sc.load_manual(sorted(h for h in hosts if h), [], "liveness")
    return sc


async def _run_one(check: dict) -> dict:
    if not _reachable(check["lab"]):
        return lv.verdict(check, [], lab_up=False)
    try:
        if check["kind"] == "tool":
            from tools import ToolRegistry
            tb = ToolRegistry(_scope_for(check), lab_mode=True)
            res = await getattr(tb, check["tool"])(check["input"])
            findings = list(getattr(res, "findings", []) or [])
        else:
            mod = __import__(check["module"])
            sc = _scope_for(check)
            fn = getattr(mod, check["func"])
            # OFF THE EVENT LOOP. run_persona_swap drives Playwright's SYNC api, which refuses to start
            # inside a running asyncio loop; it catches that itself and returns ran=False, so calling it
            # from here reported a perfectly healthy engine as DEAD. A liveness gate that cannot tell
            # "the engine is broken" from "the harness is broken" is worse than no gate.
            out = await asyncio.to_thread(
                lambda: fn(scope_ok=lambda u: sc.validate(u)[0], **check["kwargs"]))
            out = out or {}
            if out.get("ran") is False or out.get("note"):
                return lv.verdict(check, [], lab_up=True,
                                  error="engine did not run: %s" % (out.get("note") or "no reason given"))
            findings = list(out.get("findings") or [])
        return lv.verdict(check, findings, lab_up=True)
    except Exception as e:
        return lv.verdict(check, [], lab_up=True, error="%s: %s" % (type(e).__name__, e))


async def main(update: bool) -> int:
    results = []
    for check in lv.CHECKS:
        r = await _run_one(check)
        results.append(r)
        print("  [%-9s] %-32s %s" % (r["verdict"], r["technique"], r["detail"][:80]), flush=True)
    baseline = []
    if os.path.exists(BASELINE):
        with open(BASELINE, encoding="utf8") as fh:
            baseline = json.load(fh).get("live", [])
    ev = lv.evaluate(results, baseline)
    print()
    print(lv.report(ev))
    if update and ev["ok"]:
        with open(BASELINE, "w", encoding="utf8") as fh:
            json.dump({"live": ev["new_baseline"],
                       "note": "Engines proven end-to-end against a standing lab. Add by running "
                               "liveness_run.py --update; a REGRESSION fails before the file is written, "
                               "so this can only ratchet up."}, fh, indent=2)
        print("baseline updated: %d live engine(s)" % len(ev["new_baseline"]))
    return 0 if ev["ok"] else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main("--update" in sys.argv)))

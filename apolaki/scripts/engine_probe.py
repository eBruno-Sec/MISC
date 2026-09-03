#!/usr/bin/env python3
"""Call every SILENT engine BY HAND against a target chosen for the bug it hunts.

    docker exec -i apolaki-agent-1 python - < scripts/engine_probe.py

WHY THIS EXISTS, and why reading the engines' source instead would have found nothing.

`tool_ledger.py` says which engines have never produced. It cannot say WHY, because a zero has
three meanings that are identical at the ledger: the target is clean, the engine is broken, or the
engine was never handed a target it could act on. Every silent engine repaired in this project so
far turned out to be the THIRD:

    run_nuclei       a CLI flag removed upstream; the binary exited 2 before loading a template
    run_dalfox       the lab's database was offline, so every zero was correct
    run_sqlmap       the same outage
    run_form_cmdi    the vulnerable page was never crawled -- the engine was flawless
    run_upload_test  the same page
    service packs    a one-host list that never reached the non-web hosts

Not one had a defect in its own code. Source review would have shown correct code in all six, and
the one fix that WAS made by reading code (narrowing a weak-PRNG rule) broke a negative control
written to catch that exact over-correction.

So this batches the DIAGNOSIS, which is the part that generalises. Each engine is invoked directly
against a target picked for its vulnerability class, and the answer separates the three meanings:

    FIRED    produced a finding when handed a suitable target -> the engine works and the mission
             was STARVING it; the defect is upstream, in targeting
    SILENT   ran cleanly and produced nothing -> either the target lacks the bug or the engine is
             wrong, and only a target PROVEN vulnerable by hand tells those apart
    ERROR    raised or refused -> the one bucket where reading the engine is the right next step

A FIRED row is worth more than the others: it converts "this engine is dead" into "this engine is
fine and something upstream never gave it work" -- a different fix, in a different file.
"""
from __future__ import annotations

import asyncio
import sys

sys.path.insert(0, "/app")

# engine -> (input, why this target). Local authorized labs only. Chosen for the BUG each engine
# hunts, never for convenience: a silent engine aimed at a target without its bug teaches nothing,
# which is the mistake this file exists to stop repeating.
PROBES = {
    "run_cmdi": ({"url": "http://mutillidae/index.php?page=dns-lookup.php&target_host=127.0.0.1"},
                 "mutillidae dns-lookup runs nslookup on target_host"),
    "run_form_cmdi": ({"url": "http://mutillidae/index.php?page=dns-lookup.php"},
                      "the same injection, reached through the POST form"),
    "run_upload_test": ({"url": "http://mutillidae/index.php?page=upload-file.php"},
                        "mutillidae upload form"),
    "run_ssi": ({"url": "http://mutillidae/index.php?page=ssi-injection.php"},
                "mutillidae ships an SSI lab page"),
    "run_path_sqli": ({"url": "http://juice-shop:3000/rest/products/1/reviews"},
                      "juice-shop puts the id in the PATH"),
    "run_nosqli": ({"url": "http://juice-shop:3000/rest/products/search?q=a"},
                   "juice-shop search reaches MarsDB"),
    "run_nosqli_body": ({"url": "http://juice-shop:3000/rest/user/login"},
                        "a JSON body endpoint"),
    "run_stored_xss": ({"url": "http://mutillidae/index.php?page=add-to-your-blog.php"},
                       "mutillidae blog persists input"),
    "run_css_injection": ({"url": "http://mutillidae/index.php?page=set-background-color.php"},
                          "reflects a colour value into a style"),
    "run_sqli_structural": ({"url": "http://mutillidae/index.php?page=user-info.php&username=a&password=b"},
                            "a confirmed SQLi endpoint"),
    "run_session_token": ({"url": "http://mutillidae/"}, "PHPSESSID is issued here"),
    "run_session_fixation": ({"url": "http://mutillidae/index.php?page=login.php"},
                             "a login that may not rotate the session id"),
    "run_username_enum": ({"url": "http://mutillidae/index.php?page=login.php"},
                          "a login form with distinguishable failure text"),
    "run_jsonp": ({"url": "http://juice-shop:3000/rest/products/search?q=a&callback=cb"},
                  "a callback parameter"),
    "run_cache_poison": ({"url": "http://mutillidae/"}, "an unkeyed-header target"),
    "run_cache_deception": ({"url": "http://mutillidae/index.php?page=user-info.php"},
                            "an authenticated-looking page"),
    "run_saml": ({"url": "http://mutillidae/"}, "no SAML here; a clean SILENT is the right answer"),
    "run_llm_probe": ({"url": "http://juice-shop:3000/rest/chatbot/respond"},
                      "juice-shop ships a chatbot"),
    "check_takeover": ({"domain": "mutillidae"}, "no dangling CNAME; clean SILENT expected"),
    "run_github_recon": ({"domain": "mutillidae"}, "offline bench; clean SILENT expected"),
    "run_waf_bypass": ({"url": "http://mutillidae/index.php?page=user-info.php&username=a"},
                       "no WAF in front; clean SILENT expected"),
    "run_ffuf": ({"url": "http://mutillidae/"}, "content discovery on a rich app"),
    "run_service_pack": ({"host": "apolaki-smb-1", "port": 445, "service": "smb"},
                         "the SMB lab, proven to answer a null session"),
}

SCOPE = ["mutillidae", "juice-shop:3000", "juice-shop", "apolaki-smb-1",
         "apolaki-openldap-1", "dvwa", "bwapp"]


def probe(name, inp, timeout=90):
    import scope as S
    import tools as T
    sc = S.ScopeEngine()
    sc.load_manual(list(SCOPE), [], "probe")
    reg = T.ToolRegistry(sc, mission_id=None, lab_mode=True)
    reg.urls = [inp["url"]] if inp.get("url") else []
    fn = getattr(reg, "_" + name, None)
    if fn is None:
        return ("NO-DISPATCH", 0, "ToolRegistry has no _" + name)
    try:
        res = asyncio.run(asyncio.wait_for(fn(dict(inp)), timeout=timeout))
    except asyncio.TimeoutError:
        return ("ERROR", 0, "timed out after %ds" % timeout)
    except Exception as e:
        return ("ERROR", 0, "%s: %s" % (type(e).__name__, str(e)[:90]))
    n = len(getattr(res, "findings", None) or [])
    if not getattr(res, "success", True) and not n:
        return ("ERROR", 0, str(getattr(res, "error", ""))[:90])
    return (("FIRED" if n else "SILENT"), n, str(getattr(res, "output", ""))[:78])


def main():
    only = set(sys.argv[1:]) or None
    rows = []
    for name, (inp, why) in PROBES.items():
        if only and name not in only:
            continue
        verdict, n, note = probe(name, inp)
        rows.append((verdict, name, n, note, why))
        print("%-11s %-22s %-3s %s" % (verdict, name, n or "", note))
        sys.stdout.flush()
    print()
    for v in ("FIRED", "ERROR", "SILENT", "NO-DISPATCH"):
        got = [r for r in rows if r[0] == v]
        print("%-11s %d" % (v, len(got)))
        if v in ("FIRED", "ERROR"):
            for _v, name, n, note, why in got:
                print("      %-22s %s" % (name, why))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

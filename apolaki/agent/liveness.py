"""Engine liveness — does each engine STILL confirm, right now, against a lab that has the bug?

WHY THIS EXISTS. `techniques.validated_on` records that an engine was once proven. Nothing re-checks it.
In one night three engines were found silently dead with the whole suite green:

  * `_run_graphql` raised NameError on every call (a missing function-local `httpx` import), so the
    entire GraphQL tool returned nothing on any real endpoint;
  * `dom_trace` evaluated `dt.DOM_SCAN_JS`, which did not exist, inside a bare `except Exception: pass`
    — dom_link_manipulation and dom_data_manipulation became undetectable and the DOM-XSS payload pass
    never fired;
  * `_shape_response` called `poc.redact`, which did not exist, behind a `hasattr` guard, so bodies
    handed to the model were never redacted.

None of that failed a test, because the suite exercises PURE HELPERS and the wiring is untested by
construction. A unit test proves an oracle can decide; only an end-to-end run proves the engine still
reaches it. This module is the missing half.

THE RATCHET. `evaluate()` compares a run against a committed baseline: an engine that confirmed before
and does not now is a REGRESSION and fails the gate. New confirmations are welcome and raise the
baseline. The count may rise, never fall — the same shape as the dead-code gates.

WHAT THIS DELIBERATELY IS NOT. It is not a benchmark and does not score recall. It answers one question
per engine — "did the wiring carry a real target all the way to a confirmed finding" — and a lab that is
not running is reported as SKIPPED, never as a pass. Treating an absent lab as success is exactly the
declaration-instead-of-fact failure the project keeps hitting.

The CHECKS table and every scoring function here are pure; the runner does the I/O.
"""
from __future__ import annotations

# Each check: the technique it proves, the lab that must be up, how to invoke the SHIPPING code path,
# and what counts as proof. `kind` selects the runner:
#   "tool" -> a ToolRegistry coroutine, invoked with `input`
#   "call" -> a module-level function, invoked with `kwargs`
#   "recon" -> a ToolRegistry coroutine invoked with `input`, proof is `recon_key` in `tools.recon`
#              afterward rather than a confirmed finding (Q-126: some engines, like technology
#              detection, deliberately never emit one)
CHECKS = (
    # ── SURFACE DISCOVERY: can the product still REACH a target at all? ───────────────────────────
    # Five orchestration defects shipped while 1645 unit tests stayed green, because every one of them
    # tested an engine and none asserted that Apolaki can find anything to point an engine at:
    #   recon seeded the host root while scope pinned /benchmark  -> scope correctly refused it
    #   crawl.bfs_frontier's only caller was the AUTHENTICATED pass -> unauth scans never followed a link
    #   document-relative links were dropped                       -> could not crawl most of the web
    #   robots.txt / sitemap.xml were never read
    #   the browser sensor returned browser:False on every run
    # A mission against a 1415-vulnerability target returned ZERO findings in 40 seconds and reported
    # "coverage completed". This check is the missing guarantee: point the crawl at a lab whose app is
    # mounted on a SUBPATH and whose links are RELATIVE, and require the surface to actually grow.
    {"technique": "surface_discovery", "lab": "owaspbench", "kind": "surface",
     "seed": "https://owaspbench:8443/benchmark/", "min_urls": 8, "max_hostless": 0},

    # ── ICS / OT: read-only identity probes against a foreign protocol stack (Conpot) ──────────
    {"technique": "modbus_exposed", "lab": "conpot", "kind": "tool", "tool": "_run_service_pack",
     "input": {"host": "conpot", "port": 5020, "service": "modbus"}, "family": "modbus_exposed"},
    {"technique": "s7comm_exposed", "lab": "conpot", "kind": "tool", "tool": "_run_service_pack",
     "input": {"host": "conpot", "port": 10201, "service": "s7comm"}, "family": "ics_ot",
     "title": "S7comm"},
    {"technique": "enip_exposed", "lab": "conpot", "kind": "tool", "tool": "_run_service_pack",
     "input": {"host": "conpot", "port": 44818, "service": "enip"}, "family": "ics_ot",
     "title": "EtherNet/IP"},
    {"technique": "ipmi_rakp", "lab": "conpot", "kind": "tool", "tool": "_run_service_pack",
     "input": {"host": "conpot", "port": 6230, "service": "ipmi"}, "family": "ipmi_rakp"},
    # DNP3 needed its own foreign stack: Conpot speaks five ICS protocols but has no DNP3 outstation, so
    # this technique stayed unproven while its neighbours were validated. OpenFMB Adapter (opendnp3)
    # supplies a link-status reply whose CRC our parser verifies — their encoder, our decoder.
    {"technique": "dnp3_exposed", "lab": "dnp3", "kind": "tool", "tool": "_run_service_pack",
     "input": {"host": "dnp3-outstation", "port": 20000, "service": "dnp3"}, "family": "ics_ot",
     "title": "DNP3"},
    # ── beyond-web network services ───────────────────────────────────────────────────────────
    {"technique": "snmp_default_community", "lab": "snmpd", "kind": "tool", "tool": "_run_service_pack",
     "input": {"host": "snmpd", "port": 161, "service": "snmp"}, "family": "snmp_default_community"},
    {"technique": "ldap_anonymous_read", "lab": "openldap", "kind": "tool", "tool": "_run_service_pack",
     "input": {"host": "openldap", "port": 389, "service": "ldap"}, "family": "ldap_anonymous_read"},
    {"technique": "smb_null_session", "lab": "smb", "kind": "tool", "tool": "_run_service_pack",
     "input": {"host": "smb", "port": 445, "service": "smb"}, "family": "smb_null_session"},
    {"technique": "smb_signing_disabled", "lab": "smb", "kind": "tool", "tool": "_run_service_pack",
     "input": {"host": "smb", "port": 445, "service": "smb"}, "family": "smb_signing_disabled"},
    # ── GraphQL: the tool that was raising on every real endpoint ──────────────────────────────
    {"technique": "graphql_introspection", "lab": "dvga", "kind": "tool", "tool": "_run_graphql",
     "input": {"url": "http://dvga:5013/graphql"}, "family": "graphql",
     # title, not family alone: batching and field-suggestion are also family "graphql", and matching on
     # family let the BATCHING finding satisfy this check while introspection emitted no evidence at all.
     "title": "introspection enabled"},
    {"technique": "graphql_argument_injection", "lab": "dvga", "kind": "tool", "tool": "_run_graphql",
     "input": {"url": "http://dvga:5013/graphql"}, "family": "sqli"},
    # ── runtime DOM source→sink: the families the dead sink scan silently retired ──────────────
    {"technique": "dom_data_manipulation", "lab": "domsource", "kind": "tool", "tool": "_run_dom_trace",
     "input": {"url": "http://domsource:8080/hash"}, "family": "dom_data_manipulation"},
    {"technique": "dom_xss", "lab": "domsource", "kind": "tool", "tool": "_run_dom_trace",
     "input": {"url": "http://domsource:8080/hash"}, "family": "dom_xss"},
    # Q-148. Proves `passive_disclosure` fires through the REAL tool dispatch, not just in unit
    # tests. The lab serves the key as a BACKUP FILE, not inside <pre>: the first version wrapped
    # it for display and the engine correctly stayed silent, because a key in a display element is
    # a documentation page -- the exact false positive it exists to suppress.
    {"technique": "private_key_disclosed", "lab": "domsource", "kind": "tool",
     "tool": "_run_web_probes", "input": {"url": "http://domsource:8080/leak"},
     "family": "info_disclosure"},
    {"technique": "dom_link_manipulation", "lab": "domsource", "kind": "tool", "tool": "_run_dom_trace",
     "input": {"url": "http://domsource:8080/hashparam"}, "family": "dom_link_manipulation"},
    # ── browser-runtime access control (BIE) ──────────────────────────────────────────────────
    {"technique": "client_side_authz", "lab": "clientauthz", "kind": "call",
     "module": "bie", "func": "run_persona_swap", "cwe": "CWE-602",
     "kwargs": {"base": "http://clientauthz:8080",
                "owner_headers": {"Cookie": "sid=sess-bob"},
                "attacker_headers": {"Cookie": "sid=sess-alice"},
                "owner": "bob-admin", "attacker": "alice-user",
                "seed_paths": ["/panel"], "screenshots": False}},
    {"technique": "client_supplied_identity_param", "lab": "clientauthz", "kind": "call",
     "module": "bie", "func": "run_persona_swap", "cwe": "CWE-639",
     "kwargs": {"base": "http://clientauthz:8080",
                "owner_headers": {"Cookie": "sid=sess-bob"},
                "attacker_headers": {"Cookie": "sid=sess-alice"},
                "owner": "bob-admin", "attacker": "alice-user",
                "seed_paths": ["/panel"], "screenshots": False}},
    # ── Q-126: Q-021B's persistence half, proven live (recon, not a vulnerability) ─────────────
    # `dvwa` serves a plain `Server: Apache/2.4.25 (Debian)` banner -- a real target, not a fixture --
    # so this proves the producer -> recon["technology"] wiring is still carrying a version, evidence
    # and all, rather than merely that the unit tests still construct a TechnologyFact by hand.
    {"technique": "technology_detection", "lab": "dvwa", "kind": "recon",
     "tool": "_run_fingerprint", "input": {"url": "http://dvwa/"},
     "recon_key": "technology", "min_facts": 1},
    # Q-011: mass_assignment was declared live in three catalogs (engine_descriptor, asvs_model
    # ATHZ-04, wstg_catalog WSTG-INPV-20) with the engine, oracle and 96 unit tests all shipped, but
    # zero `run_mass_assign` tool_call rows had ever appeared in the live database and this table had
    # no entry -- exactly the island shape the ticket was filed to fix, just moved one layer down.
    # VAmPI's `/users/v1/register` is the standard fixture for this class: it binds the request body
    # straight onto the user model, and `/users/v1/_debug` is VAmPI's OWN declared endpoint that
    # re-exposes the privileged `admin` field a normal read never shows. The seed body's `username`/
    # `email` are personalized to a fresh unique marker by `mass_assign_tool.personalize()` on every
    # write (baseline, ignored-field control, and each injected attempt all get their own), so this
    # fixed seed is safe to reuse across repeated liveness runs without a collision.
    {"technique": "mass_assignment", "lab": "vampi", "kind": "tool", "tool": "_run_mass_assign",
     "input": {"url": "http://vampi:5000/users/v1/register", "method": "POST",
               "body": {"username": "apolaki_liveness_seed", "email": "apolaki_liveness_seed@apolaki.test",
                        "password": "Apolaki-Liveness-1!"},
               "read_paths": ["/users/v1/_debug"]},
     "family": "mass_assignment", "cwe": "CWE-915"},
)

# Verdicts a check can produce.
CONFIRMED, DEAD, SKIPPED, ERROR = "confirmed", "dead", "skipped", "error"


def _match(finding: dict, check: dict) -> bool:
    """Does this finding prove the check? Family (or cwe) plus an optional title fragment, and it must be
    CONFIRMED with real evidence. Pure. A 'lead' never satisfies a liveness check — the point is that the
    oracle still fires.

    `title` EXISTS BECAUSE FAMILY ALONE GAVE A FALSE PASS. Several engines share one family: GraphQL
    introspection, field-suggestion leakage and batching are all `family: "graphql"`. The
    graphql_introspection check was therefore satisfied by the BATCHING finding, and reported green while
    introspection was in fact emitting no evidence at all and being dropped by every proof filter. A gate
    that cannot tell two engines apart is not checking either of them."""
    f = finding or {}
    conf = str(f.get("confidence") or "").lower()
    if conf not in ("confirmed", "high") and not f.get("confirmed"):
        return False
    if len(str(f.get("evidence") or f.get("success_oracle") or "").strip()) < 12:
        return False
    want_title = str(check.get("title") or "").lower()
    if want_title and want_title not in str(f.get("title") or "").lower():
        return False
    if check.get("cwe"):
        return str(f.get("cwe") or "") == check["cwe"]
    fam = str(f.get("family") or f.get("vuln_class") or "")
    return fam == check.get("family")


def verdict(check: dict, findings, lab_up: bool, error: str = "") -> dict:
    """One check's outcome. Pure — the runner supplies the findings and whether the lab answered."""
    if error:
        return {"technique": check["technique"], "lab": check["lab"], "verdict": ERROR, "detail": error[:160]}
    if not lab_up:
        return {"technique": check["technique"], "lab": check["lab"], "verdict": SKIPPED,
                "detail": "lab %s is not reachable — NOT a pass" % check["lab"]}
    # A surface check asserts REACH, not a finding: the runner passes the discovered URLs as `findings`.
    # Kept in the same table and ratchet as the engines because "can we still reach a target" belongs in
    # exactly the gate that already refuses to treat an absent lab as success.
    if check.get("kind") == "surface":
        urls = list(findings or [])
        n, need = len(urls), int(check.get("min_urls") or 1)
        # Q-019: a big surface is not the same as a USABLE one. Mission 90cee81c discovered 2756 URLs
        # and probed 36, because `urljoin("https://", "/benchmark/x.html")` yields
        # `https:///benchmark/x.html` — scheme, EMPTY netloc — which ScopeEngine then correctly refuses.
        # Those hostless entries were the category index pages linking to all 2740 test cases, so the
        # crawl "succeeded" by count while losing the only pages that mattered. A reach check that
        # counts URLs without checking they are addressable would have passed that mission.
        from urllib.parse import urlparse
        hostless = [u for u in urls if not (urlparse(str(u)).netloc or "")]
        cap = check.get("max_hostless")
        if cap is not None and len(hostless) > int(cap):
            return {"technique": check["technique"], "lab": check["lab"], "verdict": DEAD,
                    "detail": "%d URL(s) on the surface have no host (e.g. %s) — scope will refuse every "
                              "one of them" % (len(hostless), str(hostless[0])[:60])}
        if n >= need:
            return {"technique": check["technique"], "lab": check["lab"], "verdict": CONFIRMED,
                    "detail": "surface grew to %d URL(s) (needed %d), all addressable" % (n, need)}
        return {"technique": check["technique"], "lab": check["lab"], "verdict": DEAD,
                "detail": "crawl reached only %d URL(s), needed %d — the product cannot see the target"
                          % (n, need)}
    # Q-126: a `recon` check proves a FACT reached persistence, not a confirmed vulnerability. Some
    # engines (Q-021B's technology detection) deliberately never emit a `confirmed`/`high`-confidence
    # finding — detection is not a vulnerability by that ticket's own design — so `_match()` would
    # reject every one of them and this gate could never prove that class of engine live at all. The
    # runner passes whatever the named `recon_key` held after the call as `findings`; still requires
    # real evidence per record, so an empty-shell dict landing in the list cannot count.
    if check.get("kind") == "recon":
        facts = [f for f in (findings or []) if isinstance(f, dict)]
        with_evidence = [f for f in facts if len(str(f.get("evidence") or "").strip()) >= 8]
        n, need = len(with_evidence), int(check.get("min_facts") or 1)
        if n >= need:
            return {"technique": check["technique"], "lab": check["lab"], "verdict": CONFIRMED,
                    "detail": "recon[%r] gained %d fact(s) with evidence (needed %d)"
                              % (check.get("recon_key"), n, need)}
        return {"technique": check["technique"], "lab": check["lab"], "verdict": DEAD,
                "detail": "recon[%r] has %d evidenced fact(s), needed %d — the wiring did not persist "
                          "a detection" % (check.get("recon_key"), n, need)}
    hit = next((f for f in (findings or []) if _match(f, check)), None)
    if hit:
        return {"technique": check["technique"], "lab": check["lab"], "verdict": CONFIRMED,
                "detail": str(hit.get("title") or "")[:120]}
    return {"technique": check["technique"], "lab": check["lab"], "verdict": DEAD,
            "detail": "engine ran but produced no confirmed %s finding"
                      % (check.get("cwe") or check.get("family"))}


def evaluate(results, baseline) -> dict:
    """THE RATCHET. Pure.

    A technique the baseline records as live, which is not confirmed now, is a REGRESSION and fails the
    gate. SKIPPED does not clear a regression and does not count as a pass — a lab that is not running
    means the question was not asked, which is the one thing this gate must never confuse with an answer.
    """
    base = set(baseline or [])
    by = {r["technique"]: r for r in (results or [])}
    confirmed = sorted(t for t, r in by.items() if r["verdict"] == CONFIRMED)
    dead = sorted(t for t, r in by.items() if r["verdict"] == DEAD)
    skipped = sorted(t for t, r in by.items() if r["verdict"] == SKIPPED)
    errored = sorted(t for t, r in by.items() if r["verdict"] == ERROR)
    regressions = sorted(t for t in base if t not in confirmed)
    gained = sorted(t for t in confirmed if t not in base)
    return {
        "checked": len(by), "confirmed": confirmed, "dead": dead, "skipped": skipped, "errors": errored,
        "regressions": regressions, "gained": gained,
        "baseline_size": len(base), "new_baseline": sorted(base | set(confirmed)),
        "ok": not regressions and not errored,
        "statement": ("%d engine(s) confirmed; no regression against a baseline of %d"
                      % (len(confirmed), len(base)) if not regressions else
                      "REGRESSION: %d engine(s) confirmed before and do not now: %s"
                      % (len(regressions), ", ".join(regressions))),
    }


def report(ev: dict) -> str:
    """Human-readable gate output."""
    lines = ["engine liveness: %d checked, %d confirmed, %d dead, %d skipped, %d error"
             % (ev["checked"], len(ev["confirmed"]), len(ev["dead"]), len(ev["skipped"]), len(ev["errors"]))]
    for key, label in (("regressions", "REGRESSION"), ("dead", "dead"), ("errors", "error"),
                       ("skipped", "skipped (lab down — NOT a pass)"), ("gained", "newly live")):
        for t in ev.get(key) or []:
            lines.append("  %-32s %s" % (label, t))
    lines.append(ev["statement"])
    return "\n".join(lines)

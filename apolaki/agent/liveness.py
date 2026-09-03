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
    # Titled since Q-164, when this family gained a second check: `test_liveness.py`'s table guard
    # requires any two checks sharing a family to be distinguishable, and it is right to. The engine
    # names the host it questioned in the finding title, so pinning that fragment makes each check
    # demand a finding from ITS OWN lab — a check that would otherwise be satisfied by its sibling's
    # answer now fails when pointed anywhere else.
    {"technique": "snmp_default_community", "lab": "snmpd", "kind": "tool", "tool": "_run_service_pack",
     "input": {"host": "snmpd", "port": 161, "service": "snmp"}, "family": "snmp_default_community",
     "title": "snmpd:161"},
    # Q-164. This technique's badge named TWO labs, conpot and snmpd, and only the snmpd half had a
    # check. The conpot half's entire backing was a membership assertion in test_ics_real_stack.py --
    # `assert "conpot" in ... validated_on` -- a literal pinned against a literal, replaying not one
    # SNMP byte, while its four neighbours in that same loop each have a recorded reply above them.
    #
    # THE REASON NOBODY NOTICED is a port. conpot's SNMP is published as `127.0.0.1:42162:16100/udp`
    # (docker-compose.yml), so the container listens on 16100, not the well-known 161. MEASURED
    # through this exact dispatch: `conpot:161` -> 0 findings, `conpot:16100` -> confirmed, family
    # snmp_default_community, sysDescr "Siemens, SIMATIC, S7-200". Anyone who had tried to re-earn
    # this badge at the obvious port would have concluded the engine was dead.
    #
    # This is also the first technique in the table with two checks; `evaluate()` groups per technique
    # for that reason, and the docstring there records what the ungrouped version did.
    {"technique": "snmp_default_community", "lab": "conpot", "kind": "tool", "tool": "_run_service_pack",
     "input": {"host": "conpot", "port": 16100, "service": "snmp"}, "family": "snmp_default_community",
     "title": "conpot:16100"},
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
    # Q-164. DVGA is this badge's own lab and `_run_graphql` is its shipping engine, but the only
    # thing pinning the claim was `assert "dvga" in ... validated_on` in test_local_import_guard.py.
    # test_validated_on.py had already demonstrated that this shape cannot fail on an addition.
    #
    # PINNED BY TITLE, and the trap runs both ways. MEASURED at this endpoint: introspection,
    # batching and argument-injection all come back from one call, and the first two share
    # `family: "graphql"`. The introspection entry above carries a title for exactly this reason --
    # matching on family alone let the BATCHING finding satisfy the INTROSPECTION check while
    # introspection emitted no evidence at all. Without a title here the reverse holds and this
    # check would report green on an engine that had stopped batching entirely.
    {"technique": "graphql_batching_enabled", "lab": "dvga", "kind": "tool", "tool": "_run_graphql",
     "input": {"url": "http://dvga:5013/graphql"}, "family": "graphql", "title": "batching"},
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
    # Q-147. The socket HOST comes from the fragment, so the payload chooses the endpoint. This is
    # also the regression guard for the structural fix: the check used to accept the canary
    # anywhere in the URL, which made an app's own `wss://app/live?room=<canary>` a finding.
    {"technique": "websocket_url_poisoning", "lab": "domsource", "kind": "tool",
     "tool": "_run_dom_trace", "input": {"url": "http://domsource:8080/wsock"},
     "family": "websocket_url_poisoning"},
    # Q-147. `classify` has read `ajax_headers` since this module was written and NOTHING EVER
    # PRODUCED IT -- reachable code, unreachable verdict. The hooks now record what the PAGE sets,
    # via both XHR and fetch, which is also the guard against the Referer trap.
    {"technique": "ajax_header_manipulation", "lab": "domsource", "kind": "tool",
     "tool": "_run_dom_trace", "input": {"url": "http://domsource:8080/ajaxhdr"},
     "family": "ajax_header_manipulation"},
    # Q-151, first of the zero-histogram tools to get a lab. `run_ssi` had 1333 dispatches across
    # every stored mission and NEVER ONE non-zero count -- which proves nothing on its own, because
    # a modern target has no mod_include and 0 is the right answer there. This lab has the bug, so
    # from here a zero means the engine, not the target.
    {"technique": "ssi_injection", "lab": "domsource", "kind": "tool", "tool": "_run_ssi",
     "input": {"url": "http://domsource:8080/ssi?q=hello"}, "family": "ssi_injection"},
    # Q-145. `security_misconfig` is shared by every header rule, so this case is pinned by TITLE.
    # Matching the family alone would pass with csp_audit dead -- the missing-frame-ancestors
    # finding from the plain header rules would satisfy it, and the case would prove nothing.
    {"technique": "csp_allows_untrusted_script", "lab": "domsource", "kind": "tool",
     "tool": "_run_transport_posture", "input": {"url": "http://domsource:8080/"},
     "family": "security_misconfig", "title": "CSP allows untrusted script execution"},
    # Q-149. The endpoint DECODES the token and never checks the signature, and it gates on the
    # token's presence -- so the three legs are 401 without a token, 200 with ours, 200 with the
    # signature mangled. That discrimination is the whole oracle: without it the honest verdict is
    # `not_tested`, which the uncontrolled version this replaced could never say (it reported
    # CRITICAL on any 2xx, and so fired on every unauthenticated endpoint in existence).
    {"technique": "jwt_signature_not_verified", "lab": "domsource", "kind": "tool",
     "tool": "_run_jwt",
     "input": {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsInJvbGUiOiJ1c2VyIn0.c2ln", "url": "http://domsource:8080/api/me"},
     "family": "jwt", "title": "JWT signature is not verified"},
    # Q-146. The lab EXECUTES the formula and echoes what it printed, so both of the probe's
    # independently-derived tokens can appear: the arithmetic product proves evaluation, and the
    # language-exclusive construct (`[::-1]`) is what allows the language to be NAMED. An echo
    # cannot produce either, which is the property the whole oracle rests on -- and the reason the
    # Q-126 `{{7*7}}`/"49" check raised CVSS 9.8 on a page that merely contained two digits.
    {"technique": "python_code_injection", "lab": "domsource", "kind": "tool",
     "tool": "_run_injection_probes",
     "input": {"url": "http://domsource:8080/calc?expr=1"},
     "family": "code_injection", "title": "Python code injection"},
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

    ONE TECHNIQUE MAY NOW CARRY SEVERAL CHECKS, and that is why the grouping below exists. Q-164 added a
    second `snmp_default_community` check because conpot publishes SNMP on 16100/udp while the original
    check drove snmpd:161 — so the first badge with two labs also became the first technique with two
    checks. This function used to read `by = {r["technique"]: r for r in results}`, which keeps only the
    LAST result per technique. MEASURED against that version, with hand-built results:

        CONFIRMED(snmpd) + SKIPPED(conpot)  ->  ok False, regressions ['snmp_default_community']
        the SAME two results, order reversed ->  ok True,  regressions []
        DEAD(conpot)     + CONFIRMED(snmpd) ->  ok True,  dead []

    The verdict depended on where a line was pasted into CHECKS, and a CONFIRMED sibling silently
    ERASED a dead engine — this module's own founding defect, moved up one layer into the scorer.
    """
    base = set(baseline or [])
    by: dict = {}
    for r in (results or []):
        by.setdefault(r["technique"], []).append(r)

    def _any(t: str, v: str) -> bool:
        return any(r["verdict"] == v for r in by[t])

    # A technique counts as live only if some check ANSWERED YES and no check ANSWERED NO. The
    # asymmetry between SKIPPED and DEAD is `verdict()`'s rule, applied here: an absent lab means the
    # question was never asked, so it cannot subtract from a confirmation made elsewhere; a DEAD check
    # means the question WAS asked and the engine did not confirm, so it must.
    confirmed = sorted(t for t in by if _any(t, CONFIRMED) and not _any(t, DEAD))
    dead = sorted(t for t in by if _any(t, DEAD))
    skipped = sorted(t for t in by if _any(t, SKIPPED) and t not in confirmed)
    errored = sorted(t for t in by if _any(t, ERROR))
    # Every check that did not run, named by the LAB it would have driven. Without this a technique
    # confirmed on one lab and skipped on another reports as a plain pass, and the fact that nobody
    # asked about the second lab disappears — which is the exact shape Q-164 was filed about.
    unasked = sorted("%s@%s" % (r["technique"], r["lab"]) for rs in by.values() for r in rs
                     if r["verdict"] == SKIPPED)
    regressions = sorted(t for t in base if t not in confirmed)
    gained = sorted(t for t in confirmed if t not in base)
    return {
        "checked": len(results or []), "confirmed": confirmed, "dead": dead, "skipped": skipped,
        "errors": errored, "unasked": unasked,
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
                       ("skipped", "skipped (lab down — NOT a pass)"),
                       ("unasked", "not asked (this lab's check did not run)"), ("gained", "newly live")):
        for t in ev.get(key) or []:
            lines.append("  %-32s %s" % (label, t))
    lines.append(ev["statement"])
    return "\n".join(lines)

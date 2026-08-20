"""OWASP WSTG coverage engine. The authoritative WSTG v4.2 active-test catalog (id -> title, sourced from
the RedCyber corpus's OWASP_WSTG_Complete table — factual taxonomy identifiers, not prose) mapped against
what Apolaki ACTUALLY has a confirming engine for. This powers an HONEST coverage statement: "Apolaki fully
tests N of 109 WSTG tests, partially M, and deliberately does NOT test K (with the reason)" — the same
truth-first discipline as the report's Coverage section. Marking is conservative: `full` only where a
deterministic confirming engine exists; `partial` where a related tool touches it but does not confirm the
specific WSTG scenario; `none` (with a reason) otherwise — including the tests we refuse on safety grounds.
"""
from __future__ import annotations

CATEGORIES = {
    "INFO": "Information Gathering", "CONF": "Configuration & Deployment", "IDNT": "Identity Management",
    "ATHN": "Authentication", "ATHZ": "Authorization", "SESS": "Session Management",
    "INPV": "Input Validation", "ERRH": "Error Handling", "CRYP": "Cryptography",
    "BUSL": "Business Logic", "CLNT": "Client-Side", "APIT": "API",
}

CATALOG = {
    "WSTG-APIT-01": "API Reconnaissance", "WSTG-APIT-02": "API Broken Object Level Authorization",
    "WSTG-APIT-99": "Testing GraphQL",
    "WSTG-ATHN-01": "Credentials Transported over an Encrypted Channel", "WSTG-ATHN-02": "Default Credentials",
    "WSTG-ATHN-03": "Weak Lock Out Mechanism", "WSTG-ATHN-04": "Bypassing Authentication Schema",
    "WSTG-ATHN-05": "Vulnerable Remember Password", "WSTG-ATHN-06": "Browser Cache Weakness",
    "WSTG-ATHN-07": "Weak Password Policy", "WSTG-ATHN-08": "Weak Security Question Answer",
    "WSTG-ATHN-09": "Weak Password Change or Reset Functionalities",
    "WSTG-ATHN-10": "Weaker Authentication in Alternative Channel", "WSTG-ATHN-11": "Multi-Factor Authentication",
    "WSTG-ATHZ-01": "Directory Traversal File Include", "WSTG-ATHZ-02": "Bypassing Authorization Schema",
    "WSTG-ATHZ-03": "Privilege Escalation", "WSTG-ATHZ-04": "Insecure Direct Object References",
    "WSTG-ATHZ-05": "OAuth Weaknesses",
    "WSTG-BUSL-01": "Business Logic Data Validation", "WSTG-BUSL-02": "Ability to Forge Requests",
    "WSTG-BUSL-03": "Integrity Checks", "WSTG-BUSL-04": "Process Timing",
    "WSTG-BUSL-05": "Number of Times a Function Can Be Used Limits", "WSTG-BUSL-06": "Circumvention of Work Flows",
    "WSTG-BUSL-07": "Defenses Against Application Misuse", "WSTG-BUSL-08": "Upload of Unexpected File Types",
    "WSTG-BUSL-09": "Upload of Malicious Files", "WSTG-BUSL-10": "Payment Functionality",
    "WSTG-CLNT-01": "DOM Based Cross Site Scripting", "WSTG-CLNT-02": "JavaScript Execution",
    "WSTG-CLNT-03": "HTML Injection", "WSTG-CLNT-04": "Client-Side URL Redirect",
    "WSTG-CLNT-05": "CSS Injection", "WSTG-CLNT-06": "Client-Side Resource Manipulation",
    "WSTG-CLNT-07": "Cross Origin Resource Sharing", "WSTG-CLNT-08": "Cross Site Flashing",
    "WSTG-CLNT-09": "Clickjacking", "WSTG-CLNT-10": "WebSockets", "WSTG-CLNT-11": "Web Messaging",
    "WSTG-CLNT-12": "Browser Storage", "WSTG-CLNT-13": "Cross Site Script Inclusion",
    "WSTG-CLNT-14": "Reverse Tabnabbing",
    "WSTG-CONF-01": "Network Infrastructure Configuration", "WSTG-CONF-02": "Application Platform Configuration",
    "WSTG-CONF-03": "File Extensions Handling for Sensitive Information",
    "WSTG-CONF-04": "Old Backup and Unreferenced Files", "WSTG-CONF-05": "Infrastructure and Application Admin Interfaces",
    "WSTG-CONF-06": "HTTP Methods", "WSTG-CONF-07": "HTTP Strict Transport Security",
    "WSTG-CONF-08": "RIA Cross Domain Policy", "WSTG-CONF-09": "File Permission",
    "WSTG-CONF-10": "Subdomain Takeover", "WSTG-CONF-11": "Cloud Storage",
    "WSTG-CONF-12": "Content Security Policy", "WSTG-CONF-13": "Path Confusion",
    "WSTG-CONF-14": "Other HTTP Security Header Misconfigurations",
    "WSTG-CRYP-01": "Weak Transport Layer Security", "WSTG-CRYP-02": "Padding Oracle",
    "WSTG-CRYP-03": "Sensitive Information Sent Via Unencrypted Channels", "WSTG-CRYP-04": "Weak Cryptographic Primitives",
    "WSTG-ERRH-01": "Improper Error Handling", "WSTG-ERRH-02": "Stack Traces",
    "WSTG-IDNT-01": "Role Definitions", "WSTG-IDNT-02": "User Registration Process",
    "WSTG-IDNT-03": "Account Provisioning Process", "WSTG-IDNT-04": "Account Enumeration and Guessable User Account",
    "WSTG-IDNT-05": "Weak or Unenforced Username Policy",
    "WSTG-INFO-01": "Search Engine Discovery Reconnaissance", "WSTG-INFO-02": "Fingerprint Web Server",
    "WSTG-INFO-03": "Review Webserver Metafiles", "WSTG-INFO-04": "Enumerate Applications on Webserver",
    "WSTG-INFO-05": "Review Webpage Content for Information Leakage", "WSTG-INFO-06": "Identify Application Entry Points",
    "WSTG-INFO-07": "Map Execution Paths Through Application", "WSTG-INFO-08": "Fingerprint Web Application Framework",
    "WSTG-INFO-09": "Fingerprint Web Application", "WSTG-INFO-10": "Map Application Architecture",
    "WSTG-INPV-01": "Reflected Cross Site Scripting", "WSTG-INPV-02": "Stored Cross Site Scripting",
    "WSTG-INPV-03": "HTTP Verb Tampering", "WSTG-INPV-04": "HTTP Parameter Pollution",
    "WSTG-INPV-05": "SQL Injection", "WSTG-INPV-06": "LDAP Injection", "WSTG-INPV-07": "XML Injection",
    "WSTG-INPV-08": "SSI Injection", "WSTG-INPV-09": "XPath Injection", "WSTG-INPV-10": "IMAP SMTP Injection",
    "WSTG-INPV-11": "Code Injection", "WSTG-INPV-12": "Command Injection", "WSTG-INPV-13": "Format String Injection",
    "WSTG-INPV-14": "Incubated Vulnerabilities", "WSTG-INPV-15": "HTTP Splitting Smuggling",
    "WSTG-INPV-16": "HTTP Incoming Requests", "WSTG-INPV-17": "Host Header Injection",
    "WSTG-INPV-18": "Server-Side Template Injection", "WSTG-INPV-19": "Server-Side Request Forgery",
    "WSTG-INPV-20": "Mass Assignment",
    "WSTG-SESS-01": "Session Management Schema", "WSTG-SESS-02": "Cookies Attributes",
    "WSTG-SESS-03": "Session Fixation", "WSTG-SESS-04": "Exposed Session Variables",
    "WSTG-SESS-05": "Cross Site Request Forgery", "WSTG-SESS-06": "Logout Functionality",
    "WSTG-SESS-07": "Session Timeout", "WSTG-SESS-08": "Session Puzzling",
    "WSTG-SESS-09": "Session Hijacking", "WSTG-SESS-10": "JSON Web Tokens", "WSTG-SESS-11": "Concurrent Sessions",
}

# `full` = a deterministic confirming engine exists (the Apolaki tool that owns it).
FULL = {
    "WSTG-APIT-01": "fetch_openapi + recon", "WSTG-APIT-02": "authz matrix + confirm_idor",
    "WSTG-APIT-99": "run_graphql", "WSTG-ATHN-04": "run_auth_sqli + authz matrix (forced browse)",
    "WSTG-ATHZ-01": "run_web_probes (path traversal)", "WSTG-ATHZ-02": "authz matrix + run_bfla",
    "WSTG-ATHZ-03": "run_bfla + authz matrix", "WSTG-ATHZ-04": "confirm_idor + authz matrix",
    "WSTG-ATHZ-05": "run_oauth", "WSTG-BUSL-08": "run_upload_test", "WSTG-BUSL-09": "run_upload_test",
    "WSTG-CLNT-01": "run_dom_audit + run_dom_trace", "WSTG-CLNT-02": "run_dom_audit",
    "WSTG-CLNT-03": "run_xss / run_form_xss", "WSTG-CLNT-04": "run_dom_trace (open redirect)",
    "WSTG-CLNT-05": "run_css_injection", "WSTG-CLNT-07": "run_injection_probes (CORS)",
    "WSTG-CLNT-09": "guidance (framing headers)",
    "WSTG-CONF-04": "run_exposure + run_dir_harvest", "WSTG-CONF-05": "run_content_discovery",
    "WSTG-CONF-06": "run_web_probes (dangerous methods)", "WSTG-CONF-07": "header analysis (HSTS)",
    "WSTG-CONF-10": "check_takeover", "WSTG-CONF-12": "header analysis (CSP)",
    "WSTG-CONF-08": "run_client_checks (crossdomain.xml / clientaccesspolicy wildcard)",
    "WSTG-CONF-13": "run_cache_deception (path confusion)", "WSTG-CONF-14": "header analysis",
    "WSTG-CLNT-14": "run_client_checks (reverse tabnabbing)",
    "WSTG-ERRH-01": "error-signature oracles (sqli/xpath/ldap)", "WSTG-ERRH-02": "stack-trace detection",
    "WSTG-IDNT-02": "create_account / registration engine",
    "WSTG-IDNT-04": "run_username_enum (login response-discrepancy oracle, no brute-force)",
    "WSTG-INFO-02": "run_fingerprint", "WSTG-INFO-03": "run_exposure (metafiles)",
    "WSTG-INFO-04": "recon + content discovery", "WSTG-INFO-05": "run_js_review + intel harvest",
    "WSTG-INFO-06": "crawl (entry points)", "WSTG-INFO-08": "run_fingerprint", "WSTG-INFO-09": "run_fingerprint",
    "WSTG-INPV-01": "run_xss", "WSTG-INPV-02": "run_stored_xss", "WSTG-INPV-03": "run_web_probes (verb)",
    "WSTG-INPV-05": "run_sqli / run_auth_sqli", "WSTG-INPV-06": "run_ldap", "WSTG-INPV-07": "run_xxe",
    "WSTG-INPV-08": "run_ssi", "WSTG-INPV-09": "run_xpath", "WSTG-INPV-12": "run_cmdi / run_form_cmdi",
    "WSTG-INPV-17": "run_injection_probes (host header)", "WSTG-INPV-18": "run_injection_probes (SSTI)",
    "WSTG-INPV-19": "run_ssrf",
    # Q-011. This used to read "mass_assignment (authz)" -- a TECHNIQUE id, not an engine, and the
    # engine it implied did not exist, so `FULL` claimed full coverage for a capability the product
    # did not have (Q-012 measured that as the over-report half of the same defect). It now names the
    # engine that actually runs, in the spelling that actually dispatches: `run_mass_assign`, not the
    # `run_mass_assignment` this catalog and asvs_model both guessed at.
    "WSTG-INPV-20": "run_mass_assign (privileged attribute persists on a SEPARATE re-read; "
                    "invented-attribute + baseline controls both recorded)",
    "WSTG-SESS-01": "run_session_token (predictability/meaningful analyzer)",
    "WSTG-SESS-02": "cookie/header analysis", "WSTG-SESS-05": "run_csrf", "WSTG-SESS-10": "run_jwt (+ key confusion)",
    "WSTG-SESS-03": "run_session_fixation (token-rotation-on-login oracle)",
    "WSTG-SESS-06": "run_session_lifecycle (replay after a PROVEN-processed logout, invented-cookie control)",
    "WSTG-SESS-07": "run_session_lifecycle (replay after the server's own declared Max-Age has elapsed)",
    "WSTG-SESS-11": "run_session_lifecycle (a concurrent session replayed after a proven credential rotation)",
}

# `partial` = a related tool touches it but does not confirm the specific WSTG scenario.
PARTIAL = {
    "WSTG-ATHN-01": "transport/header checks flag cleartext creds, no full channel test",
    "WSTG-ATHN-02": "run_default_creds confirms vendor-default admin interfaces (Tomcat/JBoss, single known value); app-form default logins not auto-tested",
    "WSTG-ATHN-09": "host-header reset poisoning covered; full reset-flow logic not",
    "WSTG-BUSL-01": "business-logic graph reasons about it; no generic confirm",
    "WSTG-BUSL-02": "request forgery reasoned via graph", "WSTG-BUSL-04": "run_race covers timing side of it",
    "WSTG-BUSL-05": "run_race covers single-use/limit races", "WSTG-BUSL-06": "workflow graph, no auto-confirm",
    "WSTG-CLNT-06": "run_dom_trace (request URL override) covers part", "WSTG-CLNT-12": "run_js_review inspects storage",
    "WSTG-CONF-01": "run_nmap covers network surface", "WSTG-CONF-02": "run_fingerprint + run_exposure",
    "WSTG-CONF-03": "run_content_discovery touches extensions", "WSTG-CONF-11": "cloud_iam + run_exposure (buckets)",
    "WSTG-CRYP-01": "TLS/header hygiene noted, no deep cipher audit", "WSTG-CRYP-03": "cleartext-channel hygiene",
    "WSTG-CRYP-04": "run_hash_id flags weak primitives", "WSTG-IDNT-01": "persona/authz roles",
    "WSTG-IDNT-03": "registration engine touches provisioning",
    "WSTG-INFO-01": "run_dork_gen (offline)",
    "WSTG-INFO-07": "crawl maps some paths", "WSTG-INFO-10": "canonical asset graph",
    "WSTG-INPV-11": "run_cmdi/SSTI cover code-exec subsets",
    "WSTG-SESS-04": "intel harvest flags exposed session vars",
    "WSTG-SESS-09": "session capture, no active hijack",
}

# deliberate `none` with a stated reason — safety exclusions and honest no-clean-oracle calls.
EXCLUDED = {
    "WSTG-ATHN-03": "lock-out testing requires repeated failed logins (brute) — excluded by the no-brute rule",
    "WSTG-ATHN-11": "MFA prompts PAUSE the engine (never bypassed), so it is not auto-tested",
    "WSTG-CRYP-02": "padding-oracle has no clean deterministic oracle for a general scanner — not faked",
    "WSTG-INPV-04": "HTTP parameter pollution is an enabler with no clean standalone confirm — would be FP-prone",
    "WSTG-INPV-15": "request SMUGGLING desync can affect OTHER users (no-collateral) — refused; CRLF/splitting via header_injection is covered",
}


def coverage() -> dict:
    """What Apolaki's CATALOG claims, per category and overall: full / partial / none, plus the id lists.
    `full`/`partial` come from the hand-verified maps above; anything else is `none` (excluded ones carry a
    reason).

    **This is a statement about the TOOL, not about any mission.** It returns the same numbers for a
    full-mode scan of Juice Shop, a passive scan of one static page, and a mission in which zero engines
    ran. Any caller rendering it must say so; `report.py` does.

    Q-084 removed a `techniques: list = None` parameter from this signature. It was never referenced in
    the body, so `coverage([])` -- an empty technique list, meaning nothing ran -- returned the same
    60 full / 25 partial as `coverage()`. Its docstring claimed the parameter "only enriches the `by`
    label"; it did not do that either. A parameter that cannot change the output is an island inside a
    signature, and this one did real damage: it made `report.py:343` calling `coverage()` bare look like
    an oversight a caller could fix, when in fact no argument would have helped. MEASURED unused at all
    three call sites (`report.py`, two in `tests/test_wstg_catalog.py`) plus the `/coverage/wstg`
    endpoint, none of which passed it.

    **An evidence-driven WSTG tally is NOT derivable from this module as written**, which is why Q-084
    corrected the sentence instead of the number. `FULL` and `PARTIAL` map an id to PROSE --
    `'fetch_openapi + recon'`, `'authz matrix + run_bfla'`, `'business-logic graph reasons about it; no
    generic confirm'`. Some name engines, some name concepts, some name no engine at all, and pulling
    engine names out of that with a regex is the "no regex on records" mistake this project has already
    paid for. Making this mission-sensitive means restructuring the maps to carry machine-readable engine
    references first. Until someone does that, do not add the parameter back.
    """
    cats = {}
    tally = {"full": 0, "partial": 0, "none": 0, "excluded": 0}
    for wid, title in CATALOG.items():
        prefix = wid.split("-")[1]
        c = cats.setdefault(prefix, {"category": CATEGORIES.get(prefix, prefix),
                                     "full": [], "partial": [], "none": []})
        if wid in FULL:
            c["full"].append({"id": wid, "title": title, "by": FULL[wid]}); tally["full"] += 1
        elif wid in PARTIAL:
            c["partial"].append({"id": wid, "title": title, "by": PARTIAL[wid]}); tally["partial"] += 1
        else:
            reason = EXCLUDED.get(wid, "not yet implemented")
            c["none"].append({"id": wid, "title": title, "reason": reason})
            tally["none"] += 1
            if wid in EXCLUDED:
                tally["excluded"] += 1
    total = len(CATALOG)
    return {
        "framework": "OWASP WSTG v4.2", "total_tests": total, "tally": tally,
        "full_pct": round(100.0 * tally["full"] / total, 1),
        "any_coverage_pct": round(100.0 * (tally["full"] + tally["partial"]) / total, 1),
        "categories": cats,
    }

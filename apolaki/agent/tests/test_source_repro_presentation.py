"""Q-082: the PRESENTER must not re-introduce DAST semantics the STORE refuses.

MEASURED on mission `2fb87a3a` (716 stored source-derived findings, the whole population of
`analysis=static-call-site` rows in a table of 1773 findings across 114 missions): the markdown
renderer gave **716 of 716** a `Reproduction (copy-paste)` block containing

    curl -i -sS -k --path-as-is 'java/org/owasp/benchmark/testcode/BenchmarkTest00325.java'

and the HTML renderer gave **4 of 4** cards the same thing (HTML groups by root cause, so the 716
findings collapse into four family cards -- 100% of what each renderer emits, in both).

`main._canonical_source_finding` FAILS CLOSED so a source result cannot enter reports under DAST
semantics. `report.finding_curl` then derived a request from `target` with no proof-kind check, so
the semantics the store refuses walked back in through the renderer. **A guard at the store does not
bind the presenter.**

EVERY FIXTURE HERE IS COPIED FROM THE REAL FINDINGS TABLE, byte for byte, not invented -- four
defects in this project came from invented fixtures making vacuous tests pass. Provenance of each is
stated at its definition.

WHAT EACH HALF GUARDS

1. The POSITIVE half asserts the false claim is gone: a `static-call-site` finding renders its FILE
   and LINE and no request to replay, in BOTH renderers.

2. The NEGATIVE CONTROLS are the point of the ticket. A fix that strips reproduction from
   everything trades a false claim for a useless report. A genuine DAST finding must KEEP its curl --
   both the kind that carries an explicit `curl` from its producer and the kind whose command is
   DERIVED from `target`, because it is the derivation path that was wrong and the derivation path
   that must survive.

3. The DISCRIMINATION tests prove the fix keys on the proof-kind PREDICATE and not on some proxy: a
   behavioural finding whose target merely looks like a file path still gets a command, and a
   source-derived finding whose target is a `.py` file (a shape mission 2fb87a3a does not contain)
   still gets none. A fix that pattern-matched `.java` would pass 1 and 2 and fail these.
"""
from __future__ import annotations

import pytest

import proof_schema
import report


# --- FIXTURES: copied verbatim from the findings table -------------------------------------------

# MEASURED: `select data from findings where mission_id='2fb87a3a'` row 0, in full. One of 716.
# `file` and `line` are present on all 716 rows, so the presenter always has real coordinates.
SOURCE_FINDING = {
    "title": "Trust boundary violation: request data written into the session",
    "severity": "medium",
    "target": "java/org/owasp/benchmark/testcode/BenchmarkTest00325.java",
    "confidence": "confirmed",
    "family": "trust_boundary",
    "cwe": "CWE-501",
    "line": 56,
    "provenance": "source-derived",
    "lane": "code-assisted",
    "analysis": "static-call-site",
    "description": ("HttpSession.putValue at java/org/owasp/benchmark/testcode/BenchmarkTest00325.java "
                    "line 56: a value read from the HTTP request (request.getHeaders()) reaches "
                    "HttpSession.putValue while still under the attacker's control -- untrusted data is "
                    "written into a trusted store"),
    "impact": ("An attacker chooses what the application stores as trusted state. Anything that later "
               "reads the session believes a value the client supplied."),
    "evidence": ("java/org/owasp/benchmark/testcode/BenchmarkTest00325.java:56  "
                 "HttpSession.putValue(HttpSession.putValue)  [value resolved from dataflow]"),
    "oracle": ("the value reaching HttpSession.putValue at line 56 is request-derived "
               "(request.getHeaders()); this is a dataflow conclusion, not a call-site match -- the same "
               "sink with a constant is not reported"),
    "remediation": ("Validate the value against an allow-list before it crosses into the session, and "
                    "never let a request-supplied string become a session ATTRIBUTE NAME."),
    "reproduction_steps": [
        "Open java/org/owasp/benchmark/testcode/BenchmarkTest00325.java at line 56",
        "Read the call site — no runtime observation is required",
    ],
    "tags": ["sast", "code-assisted", "dataflow", "trust-boundary"],
    "file": "java/org/owasp/benchmark/testcode/BenchmarkTest00325.java",
    "id": "89e2add24b4a",
}

# MEASURED: `select data from findings where mission_id='2810d5d9'` -- a genuine DAST finding whose
# producer wrote an explicit `curl`. Response body truncated (it is 2KB of Express error HTML); every
# other field is byte-for-byte the stored row.
DAST_EXPLICIT_CURL = {
    "title": "SQL injection (error-based) in 'q'",
    "severity": "high",
    "target": "http://juice-shop:3000/rest/products/search?q",
    "description": ("Injecting \"')\" into 'q' produced a SQLite SQL error absent from the baseline, so "
                    "the parameter is concatenated into a SQL statement."),
    "impact": ("Read or modify the database: dump credentials/PII, bypass authentication, and — "
               "depending on privileges — write files or execute commands on the DB host."),
    "reproduction_steps": [
        "Set 'q' to a value ending in \"')\"",
        "Observe a SQLite SQL error in the response",
        "Extract data with a UNION/error-based query (authorized testing only)",
    ],
    "evidence": "SQLite error triggered by \"')\"",
    "cwe": "CWE-89",
    "family": "sqli",
    "tags": ["sqli", "error-based"],
    "confidence": "confirmed",
    "request": "GET http://juice-shop:3000/rest/products/search?q=%27%29",
    "curl": "curl -i -sk 'http://juice-shop:3000/rest/products/search?q=%27%29'",
    "response": "HTTP 500\nError: SQLITE_ERROR: near \")\": syntax error",
    "id": "83f2a5cb022e",
    "owasp": "A03:2021 Injection",
    "analyst_notes": "METIS classification: CWE-89 / A03:2021 Injection",
}

# MEASURED: the same mission, one of the 35 rows carrying a `target` and NO `curl` -- the finding
# whose command is DERIVED. This is the population the defect lived in, so it is the one the negative
# control has to protect.
DAST_DERIVED_CURL = {
    "title": "Possible Broken access control — endpoint reachable with no authentication",
    "severity": "medium",
    "family": "access_control",
    "confidence": "lead",
    "cwe": "CWE-306",
    "target": "http://juice-shop:3000/products/owasp-juice-shop/794",
    "tags": ["access-control", "authentication", "needs-confirmation"],
    "description": ("An object endpoint returned data to an UNAUTHENTICATED request. This is a SIGNAL, "
                    "not proof — confirm it is not a legitimately public resource by comparing the "
                    "anonymous response to a per-user one. Roles involved: anonymous."),
    "evidence": ("reachable with NO authentication (anonymous) and returns the same data an "
                 "authenticated role sees — the endpoint does not require a session."),
    "remediation": "Require an authenticated session on this endpoint; deny anonymous access.",
    "id": "2b7af4990a87",
    "owasp": "A01:2021 Broken Access Control",
    "analyst_notes": "METIS classification: CWE-639 / A01:2021 Broken Access Control",
}

SCOPE = {"in_scope": ["https://owaspbench:8443/benchmark/"], "bases": [], "out_of_scope": []}


def _md(findings):
    return report.generate_report("Q-082", [dict(f) for f in findings], dict(SCOPE))


def _html(findings):
    return report.generate_html_report("Q-082", [dict(f) for f in findings], dict(SCOPE))


# --- 0. the fixtures are what this test thinks they are (apparatus check) ------------------------

def test_fixtures_carry_the_proof_kinds_the_rest_of_this_file_assumes():
    """Every zero below needs a positive control proving the apparatus was looking. If the fixtures
    were mis-typed, 'no curl on the source finding' would be trivially true for the wrong reason."""
    assert proof_schema.proof_kind(SOURCE_FINDING) == proof_schema.SOURCE_DERIVED
    assert proof_schema.control_status(SOURCE_FINDING) == proof_schema.CONTROL_NOT_APPLICABLE
    assert proof_schema.proof_kind(DAST_EXPLICIT_CURL) == proof_schema.BEHAVIOURAL
    assert proof_schema.proof_kind(DAST_DERIVED_CURL) == proof_schema.BEHAVIOURAL
    # and the DAST fixtures really do exercise BOTH curl paths
    assert DAST_EXPLICIT_CURL.get("curl"), "explicit-curl fixture lost its curl"
    assert not DAST_DERIVED_CURL.get("curl"), "derived-curl fixture must have no producer curl"
    assert DAST_DERIVED_CURL.get("target"), "derived-curl fixture needs a target to derive from"


# --- 1. POSITIVE: the false claim is gone ---------------------------------------------------------

def test_source_derived_finding_gets_no_curl_reproduction():
    assert report.finding_curl(dict(SOURCE_FINDING)) == "", (
        "a static call-site finding was given an HTTP reproduction command")


def test_source_derived_finding_renders_its_file_and_line_in_markdown():
    md = _md([SOURCE_FINDING])
    assert "--path-as-is" not in md, "markdown still fabricates a request for a source finding"
    assert "**Reproduction (copy-paste)**" not in md
    assert "**Where in the code**" in md, "markdown dropped the repro block without replacing it"
    assert "java/org/owasp/benchmark/testcode/BenchmarkTest00325.java:56" in md, (
        "the file:line the reader needs is not in the report")


def test_source_derived_finding_renders_its_file_and_line_in_html():
    html = _html([SOURCE_FINDING])
    assert "--path-as-is" not in html, "HTML still fabricates a request for a source finding"
    assert "<h4>Reproduction (copy-paste)</h4>" not in html
    assert "Where in the code" in html, "HTML dropped the repro block without replacing it"
    assert "java/org/owasp/benchmark/testcode/BenchmarkTest00325.java:56" in html


def test_source_derived_finding_never_says_run_the_command_below():
    """The steps fallback is a claim too. A source finding with no producer steps used to be told to
    'Send the reproduction command below' -- with no command below, once the block is gone."""
    bare = {k: v for k, v in SOURCE_FINDING.items() if k != "reproduction_steps"}
    md, html = _md([bare]), _html([bare])
    for blob, name in ((md, "markdown"), (html, "HTML")):
        low = blob.lower()
        assert "reproduction command below" not in low, "%s dangles a command that is not there" % name
        assert "request shown in the reproduction command" not in low
        assert "BenchmarkTest00325.java" in blob, "%s lost the file coordinate" % name


# --- 2. NEGATIVE CONTROLS: a genuine DAST finding KEEPS its curl ----------------------------------

def test_behavioural_finding_with_an_explicit_curl_keeps_it():
    assert report.finding_curl(dict(DAST_EXPLICIT_CURL)) == DAST_EXPLICIT_CURL["curl"]


def test_behavioural_finding_with_a_derived_curl_keeps_it():
    got = report.finding_curl(dict(DAST_DERIVED_CURL))
    assert got == ("curl -i -sS -k --path-as-is "
                   "'http://juice-shop:3000/products/owasp-juice-shop/794'"), got


def test_both_renderers_still_print_the_reproduction_for_dast_findings():
    dast = [DAST_EXPLICIT_CURL, DAST_DERIVED_CURL]
    md, html = _md(dast), _html(dast)
    assert md.count("**Reproduction (copy-paste)**") == 2, (
        "a DAST finding lost its reproduction block in markdown")
    assert "curl -i -sk 'http://juice-shop:3000/rest/products/search?q=%27%29'" in md
    assert "--path-as-is 'http://juice-shop:3000/products/owasp-juice-shop/794'" in md
    assert html.count("<h4>Reproduction (copy-paste)</h4>") == 2, (
        "a DAST finding lost its reproduction block in HTML")
    assert "Where in the code" not in html, "a behavioural finding was given a source-location block"
    assert "**Where in the code**" not in md


def test_a_mixed_report_keeps_dast_repro_and_drops_only_the_source_one():
    """The two halves in ONE report -- the shape a mission running both lanes produces."""
    md = _md([SOURCE_FINDING, DAST_EXPLICIT_CURL, DAST_DERIVED_CURL])
    assert md.count("**Reproduction (copy-paste)**") == 2
    assert md.count("**Where in the code**") == 1
    assert "--path-as-is 'java/" not in md


# --- 3. DISCRIMINATION: the fix keys on the predicate, not on a proxy for it ----------------------

def test_a_source_finding_that_is_not_java_also_gets_no_curl():
    """A `.py` source finding is a shape mission 2fb87a3a does not contain. A fix that pattern-matched
    the measured `java/` prefix (or `.java`) would pass every test above and fail here."""
    py = dict(SOURCE_FINDING, target="app/services/token.py", file="app/services/token.py", line=12,
              family="weak_random", cwe="CWE-330", reproduction_steps=None)
    assert report.finding_curl(py) == ""
    assert "app/services/token.py:12" in _md([py])


def test_a_behavioural_finding_whose_target_looks_like_a_path_keeps_its_command():
    """The mirror image: nothing about the fix may depend on the target looking like a URL. Findings
    stored with a bare path target (no scheme) are behavioural and must still get a command."""
    f = dict(DAST_DERIVED_CURL, target="/rest/products/search?q=x")
    assert report.finding_curl(f) == "curl -i -sS -k --path-as-is '/rest/products/search?q=x'"


def test_a_source_derived_finding_that_carries_a_producer_curl_still_wins():
    """The latent door `proof_schema.control_status` deliberately leaves open: a SAST lead later
    confirmed by a real probe. The presenter must not suppress an artifact that actually exists --
    that would be the store-side mistake pointed the other way."""
    confirmed_later = dict(SOURCE_FINDING, curl="curl -i -sk 'http://app:8080/x?p=1'")
    assert report.finding_curl(confirmed_later) == "curl -i -sk 'http://app:8080/x?p=1'"
    md = _md([confirmed_later])
    assert "**Reproduction (copy-paste)**" in md
    assert "http://app:8080/x?p=1" in md


# --- 4. THE SWEEP: the other two places the presenter asserted a request that never happened -----
#
# MEASURED on the same 716 rows, AFTER the curl fix landed:
#   proof_and_retest()['retest']  -> 716/716 "Operator-driven: re-run the original confirming request"
#   validation_line()             -> 716/716 "Re-run the exact reproduction above"
# Both are the Q-082 defect one section lower, and the first is a BOTH-HALVES failure inside a single
# function: `proof_and_retest` returns two claims, and only `negative_control` was proof-kind-aware.

def test_the_retest_half_of_proof_and_retest_is_bound_to_the_proof_kind_too():
    pr = report.proof_and_retest(dict(SOURCE_FINDING))
    assert "re-run the original confirming request" not in pr["retest"].lower(), (
        "the retest claim still asserts a confirming request that never existed")
    assert "no replayable http(s) target" not in pr["retest"], (
        "the retest reason still blames a missing replayable target rather than a missing request")
    assert "BenchmarkTest00325.java:56" in pr["retest"], "the retest lost the coordinate to re-read"
    # the OTHER half must be unchanged -- it was already correct
    assert "NOT APPLICABLE to this proof kind" in pr["negative_control"]


def test_validation_after_fix_does_not_tell_the_reader_to_re_run_a_request():
    v = report.validation_line(dict(SOURCE_FINDING))
    assert "Re-run the exact reproduction above" not in v
    assert "BenchmarkTest00325.java:56" in v


def test_a_source_derived_finding_in_a_dast_shaped_family_is_still_bound():
    """`_FAMILY_VALIDATION` is entirely request instructions. A source-derived finding whose family
    happens to be `sqli` must not be told to re-send a payload -- the proof-kind branch has to sit
    BEFORE the family map, not after it."""
    src_sqli = dict(SOURCE_FINDING, family="sqli", cwe="CWE-89")
    v = report.validation_line(src_sqli)
    assert "Re-send the confirming payloads" not in v, "the family map overrode the proof kind"
    assert "call site" in v


# NEGATIVE CONTROLS for the sweep: the behavioural texts must be byte-for-byte what they were.

def test_behavioural_findings_keep_their_request_based_retest_and_validation():
    for fx in (DAST_EXPLICIT_CURL, DAST_DERIVED_CURL):
        pr = report.proof_and_retest(dict(fx))
        low = pr["retest"].lower()
        assert ("re-request" in low or "re-run the original confirming request" in low), (
            "a DAST finding lost its request-based retest: %r" % pr["retest"])
        assert "derived by reading source" not in low
    assert report.validation_line(dict(DAST_EXPLICIT_CURL)).startswith(
        "Re-send the confirming payloads"), "the sqli family validation text changed"
    assert "Re-run the exact reproduction above" in report.validation_line(dict(DAST_DERIVED_CURL)), (
        "the generic behavioural validation text changed")


def test_a_producer_supplied_validation_still_wins_over_the_proof_kind_branch():
    """Same door as the producer `curl`: the presenter constrains what it INVENTS, never what a
    producer actually stated."""
    own = dict(SOURCE_FINDING, validation="Run `mvn verify -Pcrypto-lint` and assert zero findings.")
    assert report.validation_line(own) == "Run `mvn verify -Pcrypto-lint` and assert zero findings."


def test_each_source_marker_alone_is_enough_to_suppress_the_command():
    """`proof_schema._SOURCE_MARKERS` classifies on ANY ONE of the three markers, on purpose. The
    presenter must inherit that, not require all three -- a lane adopting part of the vocabulary
    would otherwise get a fabricated request back."""
    for key in ("provenance", "lane", "analysis"):
        partial = {k: v for k, v in SOURCE_FINDING.items()
                   if k not in {"provenance", "lane", "analysis"}}
        partial[key] = SOURCE_FINDING[key]
        assert proof_schema.proof_kind(partial) == proof_schema.SOURCE_DERIVED, key
        assert report.finding_curl(partial) == "", (
            "marker %r alone did not suppress the fabricated request" % key)

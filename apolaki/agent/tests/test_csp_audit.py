"""Q-145 -- granular CSP analysis, mined from Burp's published issue catalog.

Burp lists seven distinct CSP issues; Apolaki answered only "is the header present". Present-but-
useless is the common case on a real target: `script-src *` passes a presence check and stops
nothing.

EVERY CASE HERE IS GROUND TRUTH I CAN WRITE BY HAND, which is the whole reason CSP was picked first.
The lesson from this week is that a technique known perfectly still ships false positives on contact
with reality -- so the checks that go in first should be the ones whose correct answer is
constructible, not guessed.

THE FOUR CSP SEMANTICS THAT SEPARATE THIS FROM A GREP FOR 'unsafe-inline'. Each is a false positive
the naive version emits:

  1. A NONCE OR HASH NEUTRALISES 'unsafe-inline' (CSP2+). Flagging it accuses a site of using the
     RECOMMENDED pattern. This is the single most likely FP in the whole check.
  2. `frame-ancestors` and `form-action` DO NOT inherit from `default-src`. Missing them is a real
     gap even under a strict default-src -- and a checker that treats default-src as covering
     everything misses both.
  3. `script-src`/`style-src` DO inherit, so their absence is only a finding when default-src is
     also permissive.
  4. Report-Only enforces NOTHING, however good the policy reads.
"""
from __future__ import annotations

import csp_audit as csp


def _checks(enforced="", report_only=""):
    return {f["check"] for f in csp.analyze_csp(enforced, report_only)}


# ── the FP that matters most: a nonce means unsafe-inline is ignored ──────────

def test_a_nonce_neutralises_unsafe_inline():
    """CSP2+ browsers IGNORE 'unsafe-inline' when a nonce is present. This is the modern recommended
    pattern, and flagging it would accuse sites of doing the right thing."""
    got = _checks("default-src 'self'; script-src 'self' 'unsafe-inline' 'nonce-r4nd0m'; "
                  "frame-ancestors 'none'; form-action 'self'")
    assert "csp_untrusted_script" not in got, got


def test_a_hash_also_neutralises_unsafe_inline():
    got = _checks("script-src 'self' 'unsafe-inline' 'sha256-abc123='; "
                  "frame-ancestors 'none'; form-action 'self'")
    assert "csp_untrusted_script" not in got, got


def test_unsafe_inline_with_no_nonce_is_still_reported():
    """NON-VACUITY for the rule above. Without a nonce or hash, 'unsafe-inline' is exactly the hole
    it looks like."""
    got = _checks("script-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'")
    assert "csp_untrusted_script" in got, got


# ── the inheritance rules, which a naive checker gets backwards ───────────────

def test_frame_ancestors_does_not_inherit_from_default_src():
    """A strict default-src does NOT protect against framing. Treating it as covering
    frame-ancestors is the mistake that makes a checker miss real clickjacking exposure."""
    got = _checks("default-src 'none'; script-src 'self'; form-action 'self'")
    assert "csp_allows_clickjacking" in got, got


def test_form_action_does_not_inherit_from_default_src():
    got = _checks("default-src 'none'; script-src 'self'; frame-ancestors 'none'")
    assert "csp_allows_form_hijacking" in got, got


def test_script_src_DOES_inherit_from_default_src():
    """The other half of the same rule. A restrictive default-src genuinely does cover script-src,
    so reporting one here would be a false positive."""
    got = _checks("default-src 'self'; frame-ancestors 'none'; form-action 'self'")
    assert "csp_untrusted_script" not in got, got


def test_a_permissive_default_src_reaches_script_src():
    """Inheritance cuts both ways: if default-src is the wildcard, script-src inherits the hole."""
    got = _checks("default-src *; frame-ancestors 'none'; form-action 'self'")
    assert "csp_untrusted_script" in got, got


# ── the wildcard family ──────────────────────────────────────────────────────

def test_each_wildcard_source_is_caught():
    for src in ("*", "https:", "http:", "data:"):
        got = _checks("script-src 'self' %s; frame-ancestors 'none'; form-action 'self'" % src)
        assert "csp_untrusted_script" in got, (src, got)


def test_unsafe_eval_is_caught():
    got = _checks("script-src 'self' 'unsafe-eval'; frame-ancestors 'none'; form-action 'self'")
    assert "csp_untrusted_script" in got, got


def test_none_is_restrictive_not_permissive():
    """`'none'` contains the substring "none" and must never be mistaken for absence."""
    got = _checks("default-src 'none'; script-src 'none'; frame-ancestors 'none'; form-action 'none'")
    assert got == set(), got


# ── report-only, and the difference from no policy at all ────────────────────

def test_report_only_enforces_nothing():
    got = _checks("", "default-src 'none'; script-src 'none'")
    assert got == {"csp_not_enforced"}, got


def test_no_policy_at_all_is_silent_here():
    """Absence of any CSP is `transport_posture`'s existing finding, not this engine's. Reporting it
    twice under two names would inflate the count for one fact."""
    assert _checks("", "") == set()


def test_an_enforced_policy_beside_report_only_is_not_flagged_as_unenforced():
    got = _checks("default-src 'none'; frame-ancestors 'none'; form-action 'none'",
                  "default-src 'self'")
    assert "csp_not_enforced" not in got, got


# ── malformed ────────────────────────────────────────────────────────────────

def test_a_header_that_parses_to_nothing_is_malformed():
    assert "csp_malformed" in _checks(";;;")


def test_an_unparseable_directive_name_is_reported():
    got = _checks("default-src 'none'; 'self'; frame-ancestors 'none'; form-action 'none'")
    assert "csp_malformed" in got, got


# ── allowlisted bypassable hosts ─────────────────────────────────────────────

def test_a_known_bypassable_cdn_in_script_src_is_reported():
    got = _checks("script-src 'self' ajax.googleapis.com; frame-ancestors 'none'; form-action 'self'")
    assert "csp_allowlisted_script_resources" in got, got


def test_an_ordinary_first_party_host_is_not():
    """NEGATIVE CONTROL. Only hosts with a documented bypass path count, or every CSP on the
    internet becomes a finding."""
    got = _checks("script-src 'self' static.example.com; frame-ancestors 'none'; form-action 'self'")
    assert "csp_allowlisted_script_resources" not in got, got


# ── the parser ───────────────────────────────────────────────────────────────

def test_directive_names_are_case_insensitive_and_sources_are_not():
    """CSP matches directive names case-insensitively; a nonce is case-SENSITIVE and must survive."""
    p = csp.parse_csp("Script-SRC 'self' 'nonce-AbC123'")
    assert "script-src" in p
    assert "'nonce-AbC123'" in p["script-src"]


def test_a_duplicate_directive_keeps_the_first_per_spec():
    p = csp.parse_csp("script-src 'self'; script-src *")
    assert p["script-src"] == ["'self'"], p


def test_a_strict_modern_policy_produces_nothing():
    """THE CONTROL THAT KEEPS THIS USABLE. A site doing everything right must get a clean result, or
    the engine is noise on every target."""
    assert _checks("default-src 'self'; script-src 'self' 'nonce-abc'; style-src 'self'; "
                   "frame-ancestors 'none'; form-action 'self'; base-uri 'self'; "
                   "object-src 'none'") == set()


# ── NO ISLANDS: the analyzer must be reachable from the real engine ──────────
#
# A pure oracle nothing consults is the failure this repo keeps filing. `csp_audit` is only worth
# writing if `analyze_security_headers` actually calls it on every response it already fetches.

def _base_headers(**over):
    h = {"X-Frame-Options": "DENY", "Strict-Transport-Security": "x",
         "X-Content-Type-Options": "nosniff", "Referrer-Policy": "x", "Permissions-Policy": "x"}
    h.update(over)
    return h


def test_the_real_header_engine_emits_granular_csp_findings():
    import transport_posture as tp
    ids = [i["id"] for i in tp.analyze_security_headers(
        _base_headers(**{"Content-Security-Policy": "script-src * 'unsafe-inline'"}), is_https=True)]
    assert "csp_untrusted_script" in ids, ids


def test_a_strict_policy_produces_no_finding_through_the_real_engine():
    import transport_posture as tp
    ids = [i["id"] for i in tp.analyze_security_headers(
        _base_headers(**{"Content-Security-Policy":
                         "default-src 'self'; script-src 'self' 'nonce-a'; "
                         "frame-ancestors 'none'; form-action 'self'"}), is_https=True)]
    assert ids == [], ids


def test_a_missing_csp_is_reported_once_not_twice():
    """`header_missing_csp` and the granular checks must never both fire -- one fact, one finding.
    The granular branch is an `else` on purpose."""
    import transport_posture as tp
    ids = [i["id"] for i in tp.analyze_security_headers(_base_headers(), is_https=True)]
    assert ids == ["header_missing_csp"], ids


def test_every_granular_check_has_a_finding_code():
    """An id with no entry in `_CODES` renders without a CWE or a title. Pin all seven."""
    import transport_posture as tp
    for cid in ("csp_untrusted_script", "csp_untrusted_style", "csp_allows_clickjacking",
                "csp_allows_form_hijacking", "csp_allowlisted_script_resources",
                "csp_malformed", "csp_not_enforced"):
        assert cid in tp._FINDING_META, cid

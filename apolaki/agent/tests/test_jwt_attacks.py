"""Q-149 -- the JWT attack family, mined from Burp's published issue catalog.

EVERY CASE HERE IS GROUND TRUTH CONSTRUCTED BY HAND. The tokens are forged in the test with
obviously synthetic keys, and the responses are strings written in the test file, so the correct
answer is known before the code runs rather than read off the code's own output.

BOTH HALVES PER CHECK, because this week deleted ~330 false positives from oracles that were
technique-correct and reality-wrong:

    POSITIVE   the forgery is accepted, and the check confirms it
    NEGATIVE   a properly-validating server refuses it and NOTHING is reported; an AMBIGUOUS
               response yields `not_tested`, never `confirmed` and never a clean result

THE FOUR AMBIGUITIES THAT GET THEIR OWN NEGATIVE CONTROLS, because each is a CRITICAL that a
status-code check emits against a target with no bug at all:

  1. the unauthenticated endpoint (controls indistinguishable)
  2. the 200 login page (status says accept, body says refuse)
  3. the crashed verifier (HTTP 500)
  4. the third shape (a WAF block at 200 that matches neither control)
"""
from __future__ import annotations

import ast
import json
import pathlib

import jwt_attacks as ja
import jwt_tool


# =================================================================================================
# hand-forged fixtures. SYNTHETIC KEYS ONLY -- nothing here resembles a real credential.
# =================================================================================================

SYNTHETIC_SECRET = "not-a-real-secret-q149"       # a strong, unguessable string: NOT in any wordlist
WEAK_SECRET = "changeme"                           # deliberately IN jwt_tool.COMMON_SECRETS

CLAIMS = {"sub": "alice", "role": "user", "iss": "https://lab.invalid/", "exp": 4102444800}


def hs_token(claims=None, secret=SYNTHETIC_SECRET, alg="HS256"):
    return jwt_tool.forge_hs({"typ": "JWT"}, dict(claims or CLAIMS), secret, alg)


#: The three legs, written out. `AUTH_BODY` and `UNAUTH_BODY` share no alphabetic word, which is
#: what makes the body signal discriminate; the digits differ per capture on purpose, to prove the
#: normaliser erases them.
AUTH_BODY = '{"user":"alice","role":"admin","balance":1200,"csrf":"a1b2c3d4e5f6a7b8"}'
AUTH_BODY_SECOND_CAPTURE = '{"user":"alice","role":"admin","balance":1207,"csrf":"ffff0000ffff1111"}'
UNAUTH_BODY = '{"error":"unauthorized","detail":"missing or invalid token"}'

AUTH = ja.Response(200, AUTH_BODY)
UNAUTH = ja.Response(401, UNAUTH_BODY)
REFUSED = ja.Response(401, UNAUTH_BODY)


def controls(tampered=REFUSED, authenticated=AUTH, unauthenticated=UNAUTH):
    return ja.Controls(authenticated=authenticated, unauthenticated=unauthenticated,
                       tampered=tampered)


# =================================================================================================
# the module's own invariants: offline, and no silent-failure handlers
# =================================================================================================

_SOURCE = pathlib.Path(ja.__file__).with_suffix(".py")
_TREE = ast.parse(_SOURCE.read_text(encoding="utf8"))


def test_the_module_imports_no_http_client_at_all():
    """OFFLINE BY CONSTRUCTION. The weak-secret crack must never become an online attack, and the
    builders must never send anything. This is asserted at the AST level rather than trusted to a
    docstring, because an accidental `import requests` would be invisible to every other test."""
    forbidden = {"requests", "httpx", "aiohttp", "socket", "urllib", "http", "websockets",
                 "ftplib", "telnetlib", "asyncio", "subprocess"}
    imported = set()
    for node in ast.walk(_TREE):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert not (imported & forbidden), sorted(imported & forbidden)


def test_the_module_contains_no_exception_handler():
    """NO NEW SILENT-FAILURE HANDLERS (I-5). The caps in `test_silent_failure_invariant.py` are
    ratchets; this file adds zero seats to them, and this assertion is what keeps that true as the
    module grows. Shape validation (`jwt_tool.decode_jwt` returning None, `alg not in _HS_ALGS`)
    replaces every place a try/except would have gone."""
    handlers = [n for n in ast.walk(_TREE) if isinstance(n, ast.ExceptHandler)]
    assert handlers == [], [h.lineno for h in handlers]


# =================================================================================================
# THE CLASSIFIER -- the four false positives it exists to kill, each with its non-vacuity twin
# =================================================================================================

def test_positive_a_forged_response_matching_the_authenticated_control_is_accepted():
    """POSITIVE CONTROL for the classifier itself. Without this the three refusals below could all
    be produced by a classifier that says `not_tested` to everything."""
    got = ja.classify_acceptance(controls(), ja.Response(200, AUTH_BODY_SECOND_CAPTURE))
    assert got["verdict"] == ja.VERDICT_CONFIRMED, got


def test_negative_a_response_matching_the_unauthenticated_control_is_rejected():
    got = ja.classify_acceptance(controls(), ja.Response(401, UNAUTH_BODY))
    assert got["verdict"] == ja.VERDICT_REJECTED, got


def test_fp1_an_endpoint_that_answers_identically_with_and_without_a_token_is_not_tested():
    """THE UNAUTHENTICATED ENDPOINT. Point the naive `if 200 <= status < 300` check at a public
    page and it reports CRITICAL on every target in existence. Indistinguishable controls mean no
    acceptance test run here can mean anything."""
    public = ja.Controls(authenticated=ja.Response(200, "<h1>Welcome to the shop</h1>"),
                         unauthenticated=ja.Response(200, "<h1>Welcome to the shop</h1>"),
                         tampered=ja.Response(200, "<h1>Welcome to the shop</h1>"))
    usable, why = ja.controls_usable(public)
    assert usable is False and "does not gate" in why, why
    got = ja.classify_acceptance(public, ja.Response(200, "<h1>Welcome to the shop</h1>"))
    assert got["verdict"] == ja.VERDICT_NOT_TESTED, got


def test_fp2_the_login_page_rendered_at_200_is_a_rejection_not_an_acceptance():
    """THE 200 LOGIN PAGE. A SPA shell serves the login view at HTTP 200, so the status matches the
    authenticated control exactly. The body must outvote it."""
    spa = ja.Controls(authenticated=ja.Response(200, AUTH_BODY),
                      unauthenticated=ja.Response(200, UNAUTH_BODY),
                      tampered=ja.Response(200, UNAUTH_BODY))
    usable, _ = ja.controls_usable(spa)
    assert usable is True
    got = ja.classify_acceptance(spa, ja.Response(200, UNAUTH_BODY))
    assert got["verdict"] == ja.VERDICT_REJECTED, got


def test_fp3_a_crashed_verifier_is_neither_an_acceptance_nor_a_rejection():
    """THE CRASHED VERIFIER. A 500 with a stack trace is the MOST likely response to a malformed
    forged token, and it is inconclusive in both directions."""
    got = ja.classify_acceptance(controls(), ja.Response(500, "Traceback: JWSError at line 41"))
    assert got["verdict"] == ja.VERDICT_NOT_TESTED, got
    assert "crashed verifier" in got["reason"], got


def test_fp4_a_third_shape_at_the_authenticated_status_is_not_tested():
    """THE THIRD SHAPE. A WAF block page at HTTP 200 matches the authenticated control's STATUS and
    neither control's BODY. If the body signal were allowed to abstain here, every rate limit would
    become a CRITICAL authentication bypass."""
    got = ja.classify_acceptance(controls(), ja.Response(200, "Request blocked by security policy"))
    assert got["verdict"] == ja.VERDICT_NOT_TESTED, got
    assert "matches neither control" in got["reason"], got


def test_a_transport_failure_is_not_tested():
    got = ja.classify_acceptance(controls(), ja.Response(0, ""))
    assert got["verdict"] == ja.VERDICT_NOT_TESTED, got


def test_a_bodiless_api_is_classified_on_status_alone():
    """Both controls have EMPTY bodies, so the body signal cannot discriminate and stays silent.
    A 204/401 API must still be testable -- refusing here would make the module useless against
    every REST service that answers with no content."""
    api = ja.Controls(authenticated=ja.Response(204, ""), unauthenticated=ja.Response(401, ""),
                      tampered=ja.Response(401, ""))
    assert ja.controls_usable(api)[0] is True
    assert ja.classify_acceptance(api, ja.Response(204, ""))["verdict"] == ja.VERDICT_CONFIRMED
    assert ja.classify_acceptance(api, ja.Response(401, ""))["verdict"] == ja.VERDICT_REJECTED


def test_per_request_nonces_do_not_make_a_page_look_unlike_itself():
    """NON-VACUITY for the normaliser. Two captures of the same authenticated page differ in their
    CSRF token and their balance. If digits and hex runs were not erased, the second capture would
    match neither control and every check would degrade to `not_tested` on a live target."""
    assert ja.similarity(AUTH_BODY, AUTH_BODY_SECOND_CAPTURE) == 1.0


# =================================================================================================
# CHECK 1 -- Burp "JWT signature not verified"
# =================================================================================================

def test_signature_not_verified_positive_tampered_honoured_no_token_refused():
    """POSITIVE. The genuine token with one signature byte flipped authenticates; the same request
    with no token does not. That differential IS the finding."""
    got = ja.analyze_signature_verification(controls(tampered=ja.Response(200, AUTH_BODY)))
    assert got["verdict"] == ja.VERDICT_CONFIRMED, got
    assert got["check"] == ja.CHECK_SIGNATURE_NOT_VERIFIED


def test_signature_not_verified_negative_a_sound_verifier_reports_nothing():
    """NEGATIVE CONTROL. A verifier that refuses the tampered token yields `rejected`, and
    `finding_for` returns None -- nothing reaches the report."""
    got = ja.analyze_signature_verification(controls(tampered=REFUSED))
    assert got["verdict"] == ja.VERDICT_REJECTED, got
    assert ja.finding_for(got, "https://lab.invalid/me") is None


def test_signature_not_verified_on_an_ungated_endpoint_is_not_tested_not_confirmed():
    """THE VACUOUS CASE. The tampered token is honoured -- but so is the no-token request, because
    the endpoint is public. Reporting `signature not verified` here is the false positive."""
    public = ja.Controls(authenticated=ja.Response(200, "welcome to the shop"),
                         unauthenticated=ja.Response(200, "welcome to the shop"),
                         tampered=ja.Response(200, "welcome to the shop"))
    got = ja.analyze_signature_verification(public)
    assert got["verdict"] == ja.VERDICT_NOT_TESTED, got


def test_signature_not_verified_without_a_tampered_leg_is_not_tested():
    got = ja.analyze_signature_verification(
        ja.Controls(authenticated=AUTH, unauthenticated=UNAUTH, tampered=None))
    assert got["verdict"] == ja.VERDICT_NOT_TESTED, got
    assert "no signature-tampered control" in got["reason"], got


def test_the_payload_tamper_probe_keeps_the_original_signature_and_changes_the_claims():
    """GROUND TRUTH, checked byte by byte: same signature segment, different payload segment, and
    the resulting token does NOT verify under the real secret."""
    token = hs_token()
    forged = ja.forge_payload_tamper(token)
    assert forged.token.split(".")[2] == token.split(".")[2]
    assert forged.token.split(".")[1] != token.split(".")[1]
    assert json.loads(jwt_tool.b64url_decode(forged.token.split(".")[1]))["role"] == "admin"
    assert jwt_tool.verify_hs(forged.token, SYNTHETIC_SECRET) is False


def test_the_payload_tamper_probe_is_not_built_from_a_non_jwt():
    assert ja.forge_payload_tamper("not.a.jwt") is None
    assert ja.forge_payload_tamper("") is None


# =================================================================================================
# CHECK 2 -- Burp "JWT none algorithm supported"
# =================================================================================================

def test_none_variants_cover_the_casings_jwt_tool_does_not():
    """THE EXTENSION, stated as a measurement. `jwt_tool.forge_none` emits `alg:"none"` with a
    trailing dot -- one point on a surface. A library that blocklists the literal "none" with a
    case-sensitive compare is bypassed by "None", which jwt_tool never sends."""
    algs = set()
    for forged in ja.forge_none_variants(hs_token()):
        header = json.loads(jwt_tool.b64url_decode(forged.token.split(".")[0]))
        algs.add(header["alg"])
    assert {"none", "None", "NONE", "nOnE"} <= algs, algs
    assert json.loads(jwt_tool.b64url_decode(jwt_tool.forge_none({}).split(".")[0]))["alg"] == "none"


def test_none_variants_cover_the_three_signature_shapes_and_are_bounded():
    variants = ja.forge_none_variants(hs_token())
    shapes = {f.shape.split("/")[1] for f in variants}
    assert shapes == {"empty_signature", "no_signature_segment", "original_signature_retained"}
    assert len(variants) == 12, len(variants)
    assert len(ja.forge_none_variants(hs_token(), max_variants=3)) == 3


def test_none_variant_tokens_are_hand_checkable():
    """GROUND TRUTH. Every emitted token decodes to an escalated payload, and the empty-signature
    shape ends in a bare dot exactly as an unsigned JWS does."""
    by_shape = {f.shape: f for f in ja.forge_none_variants(hs_token())}
    empty = by_shape["none/empty_signature"]
    assert empty.token.endswith(".") and empty.token.count(".") == 2
    assert json.loads(jwt_tool.b64url_decode(empty.token.split(".")[1]))["role"] == "admin"
    assert by_shape["none/no_signature_segment"].token.count(".") == 1


def test_none_algorithm_positive_accepted_forgery_with_a_sound_verifier():
    got = ja.analyze_forgery(ja.CHECK_NONE_ALGORITHM, controls(),
                             ja.Response(200, AUTH_BODY_SECOND_CAPTURE), shape="none/empty")
    assert got["verdict"] == ja.VERDICT_CONFIRMED, got
    finding = ja.finding_for(got, "https://lab.invalid/me")
    assert finding["severity"] == "critical" and finding["cwe"] == "CWE-347"


def test_none_algorithm_negative_a_validating_server_reports_nothing():
    got = ja.analyze_forgery(ja.CHECK_NONE_ALGORITHM, controls(), REFUSED)
    assert got["verdict"] == ja.VERDICT_REJECTED, got
    assert ja.finding_for(got, "https://lab.invalid/me") is None


def test_an_accepted_forgery_is_not_attributed_when_the_verifier_honours_any_signature():
    """THE GATE, and the single most important negative control in this file. If a
    signature-tampered token is honoured, then an accepted alg:none token proves NOTHING ABOUT
    alg:none -- the server would have honoured a random string. Attributing it to the check is the
    over-claim; the verdict must be `not_tested` and the reason must name the real defect."""
    broken = controls(tampered=ja.Response(200, AUTH_BODY))
    got = ja.analyze_forgery(ja.CHECK_NONE_ALGORITHM, broken, ja.Response(200, AUTH_BODY))
    assert got["verdict"] == ja.VERDICT_NOT_TESTED, got
    assert "does not verify signatures at all" in got["reason"], got
    assert ja.finding_for(got, "https://lab.invalid/me") is None


# =================================================================================================
# CHECK 3 -- Burp "JWT weak HMAC secret". OFFLINE. A MISS IS NOT A CLEAN RESULT.
# =================================================================================================

def test_weak_hmac_positive_a_dictionary_secret_is_recovered_offline():
    got = ja.crack_hmac_secret(hs_token(secret=WEAK_SECRET))
    assert got["verdict"] == ja.VERDICT_CONFIRMED, got
    assert got["secret"] == WEAK_SECRET
    assert "recomputes exactly" in got["evidence"]


def test_weak_hmac_negative_a_strong_secret_is_NOT_TESTED_not_clean():
    """THE HONESTY HOLE `jwt_tool.crack_secret` leaves open. It returns None on a miss and
    `analyze()` emits nothing, so "21 words tried" is indistinguishable in the report from "never
    examined". A bounded dictionary miss is `not_tested`, and it carries the number tried."""
    got = ja.crack_hmac_secret(hs_token(secret=SYNTHETIC_SECRET))
    assert got["verdict"] == ja.VERDICT_NOT_TESTED, got
    assert got["secret"] is None and got["exhausted"] is True
    assert got["tried"] > 20, got
    assert "NOT evidence of a strong secret" in got["reason"]
    assert ja.finding_for(got, "https://lab.invalid/me") is None


def test_weak_hmac_refuses_an_asymmetric_token_instead_of_reporting_it_clean():
    rs = "%s.%s.c2ln" % (jwt_tool.b64url_encode('{"alg":"RS256"}'),
                         jwt_tool.b64url_encode('{"sub":"alice"}'))
    got = ja.crack_hmac_secret(rs)
    assert got["verdict"] == ja.VERDICT_NOT_TESTED, got
    assert "no symmetric secret to recover" in got["reason"]


def test_weak_hmac_refuses_a_non_jwt():
    got = ja.crack_hmac_secret("Bearer abc")
    assert got["verdict"] == ja.VERDICT_NOT_TESTED and got["tried"] == 0


def test_the_wordlist_budget_is_a_real_bound():
    got = ja.crack_hmac_secret(hs_token(secret=WEAK_SECRET),
                               words=["nope-1", "nope-2", WEAK_SECRET], max_words=2)
    assert got["verdict"] == ja.VERDICT_NOT_TESTED, got
    assert got["tried"] == 2, got


def test_the_wall_clock_budget_is_a_real_bound_and_reports_unfinished_not_clean():
    """The clock is INJECTED so the budget is testable without sleeping. An expired budget must
    report `exhausted=False` -- the search did not finish, and saying it did would be the lie."""
    ticks = iter([0.0, 0.0, 99.0])
    got = ja.crack_hmac_secret(hs_token(secret=WEAK_SECRET),
                               words=["nope-1", WEAK_SECRET], clock=lambda: next(ticks))
    assert got["verdict"] == ja.VERDICT_NOT_TESTED, got
    assert got["exhausted"] is False and got["tried"] == 1, got
    assert "budget expired" in got["reason"]


def test_the_wordlist_is_bounded_by_the_module_ceiling():
    words = ja.hmac_wordlist(hs_token(), extra=["w%d" % i for i in range(9000)])
    assert len(words) <= ja.MAX_CRACK_WORDS
    assert len(words) == len(set(words)), "the wordlist must be de-duplicated"


def test_forging_with_the_cracked_secret_produces_a_token_that_actually_verifies():
    """GROUND TRUTH for the impact half: the re-signed token verifies under the recovered secret
    and carries escalated claims, so it is indistinguishable from one the server issued."""
    token = hs_token(secret=WEAK_SECRET)
    forged = ja.forge_with_secret(token, WEAK_SECRET)
    assert jwt_tool.verify_hs(forged.token, WEAK_SECRET) is True
    assert json.loads(jwt_tool.b64url_decode(forged.token.split(".")[1]))["role"] == "admin"


def test_forging_with_a_secret_refuses_an_asymmetric_token():
    rs = "%s.%s.c2ln" % (jwt_tool.b64url_encode('{"alg":"RS256"}'),
                         jwt_tool.b64url_encode('{"sub":"alice"}'))
    assert ja.forge_with_secret(rs, "x") is None


# =================================================================================================
# the report boundary -- a finding is built ONLY from a confirmation, and coverage is surfaced
# =================================================================================================

def test_a_finding_is_never_built_from_a_non_confirmed_verdict():
    for verdict in (ja.VERDICT_REJECTED, ja.VERDICT_NOT_TESTED):
        row = {"check": ja.CHECK_NONE_ALGORITHM, "verdict": verdict, "evidence": "anything"}
        assert ja.finding_for(row, "https://lab.invalid/") is None, verdict


def test_a_confirmation_with_no_evidence_is_refused():
    """A `confirmed` row whose evidence string is empty cannot satisfy `proof_schema`, and
    emitting it would put an unprovable CRITICAL in the report."""
    row = {"check": ja.CHECK_NONE_ALGORITHM, "verdict": ja.VERDICT_CONFIRMED, "evidence": ""}
    assert ja.finding_for(row, "https://lab.invalid/") is None


def test_every_check_has_a_finding_spec_and_every_spec_passes_proof_schema():
    import proof_schema
    for check in ja.CHECKS:
        row = {"check": check, "verdict": ja.VERDICT_CONFIRMED, "shape": "s",
               "evidence": "HTTP request carrying the forged token -> accepted (HTTP 200)"}
        finding = ja.finding_for(row, "https://lab.invalid/me")
        assert finding is not None, check
        ok, missing = proof_schema.validate_confirmed(finding)
        assert ok, (check, missing)


def test_not_tested_checks_are_surfaced_rather_than_dropped():
    """A failed attempt must never be reported as a clean result. The findings list is empty, and
    `coverage_rows` is where the operator sees that the check ran and could not conclude."""
    verdicts = [
        ja.analyze_forgery(ja.CHECK_NONE_ALGORITHM, controls(tampered=None), REFUSED),
        ja.crack_hmac_secret(hs_token(secret=SYNTHETIC_SECRET)),
    ]
    assert [ja.finding_for(v, "u") for v in verdicts] == [None, None]
    rows = ja.coverage_rows(verdicts)
    assert len(rows) == 2
    assert all(r["verdict"] == ja.VERDICT_NOT_TESTED and r["reason"] for r in rows), rows

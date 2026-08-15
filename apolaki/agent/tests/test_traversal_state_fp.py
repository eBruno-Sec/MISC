"""A page that is DIFFERENT ON EVERY REQUEST must never confirm path traversal.

MEASURED false positive, wp2 seal `82f55903`
(`docs/benchmarks/wp2_q047_fixed_oracle_claims.json`), reproduced by this lane and written up in
`docs/handoff/fp42.md`:

    path_traversal | Path traversal in POST body field 'password'
                   | https://owaspbench:8443/benchmark/weakrand-00/BenchmarkTest00042

`BenchmarkTest00042` is a weakrand case, vulnerable to nothing.

Q-047 added the ORDER control: `exists` is sent a fourth time and a divergence counts only if it
survives the repeat. That control catches a FIRST-REQUEST artifact (session establishment, cache
miss). It cannot catch the complementary case -- an EVERY-REQUEST artifact -- because the repeat
diverges from the absent pair exactly as the original `exists` did, so `holds` is satisfied and the
reason even gains the words "it REPRODUCED".

What lets such a page through step (1), the determinism control, is that step (1) asks
`unexplained_divergence(absent_a, absent_b)` rather than asking whether the two bodies are equal.
`unexplained_divergence` has a `min_chars=3` floor, and `SequenceMatcher` chops two random 9-10 digit
integers into opcode chunks; 3.38% of the time (MEASURED over 5000 draws from a pool of 300 real
responses) every chunk holds fewer than 3 alphanumerics, the function returns None, and a page whose
300/300 responses were distinct is certified deterministic.

The bodies below are RECORDED verbatim from `https://owaspbench:8443/benchmark/weakrand-00/
BenchmarkTest00042` -- four real responses, each fetched on its own client, which is what
`ToolRegistry._http` does (it builds a new `httpx.AsyncClient` per request, so no cookie is carried
and every request is a first request). This exact quadruple makes the oracle answer `confirmed`, and
its "evidence" is `'574249'` -- a slice of the random integer belonging to an ABSENT probe.
"""
import web_security as ws


# ── recorded from the live lab; the ONLY thing that varies is `nextInt()` ────
_TAIL = "<br/>\nWeak Randomness Test java.security.SecureRandom.nextInt() executed\n"
_HEAD = "SafeIngrid00042 has been remembered with cookie: rememberMe00042 whose value is: "

WEAKRAND_EXISTS = _HEAD + "-1328856830" + _TAIL
WEAKRAND_ABSENT_A = _HEAD + "574249128" + _TAIL
WEAKRAND_ABSENT_B = _HEAD + "1878243161" + _TAIL
WEAKRAND_REPEAT = _HEAD + "-1486986136" + _TAIL


class _Twin:
    """The exact twin the differential built when the false positive was produced."""
    label = "posix"
    encoding = "raw"
    target = "etc/passwd"
    exists = "../../../../../../etc/passwd"
    absent_a = "../../../../../../9ad/39109a"
    absent_b = "../../../../../../598/6befb7"


def _r(body, status=200):
    return {"body": body, "status": status}


def _confirmed(verdict):
    """True only when the verdict is one the product would report as a real vulnerability."""
    if not verdict:
        return False
    return str(verdict.get("confidence") or "confirmed").lower() not in ws.UNPROVEN_TRAVERSAL_CONFIDENCE


def test_the_recorded_responses_really_are_all_different():
    """Negative control for the fixture itself.

    If these four bodies were ever equal the test below would pass for free and prove nothing.
    """
    bodies = {WEAKRAND_EXISTS, WEAKRAND_ABSENT_A, WEAKRAND_ABSENT_B, WEAKRAND_REPEAT}
    assert len(bodies) == 4
    # ...and the difference is nothing but the random integer.
    import re
    masked = {re.sub(r"-?\d{4,}", "N", b) for b in bodies}
    assert len(masked) == 1, masked


def test_every_request_different_page_does_not_confirm_traversal():
    """THE DEFECT. Four real responses from a case vulnerable to nothing -> `confirmed`.

    Fails against the shipped oracle; passes once the repeat is required to be IDENTICAL to the
    first `exists` after echo redaction, instead of merely still-divergent from the absent pair.
    """
    v = ws.analyze_traversal_differential(
        _r(WEAKRAND_EXISTS), _r(WEAKRAND_ABSENT_A), _r(WEAKRAND_ABSENT_B), _Twin,
        baseline=_r(WEAKRAND_EXISTS), exists_repeat=_r(WEAKRAND_REPEAT))
    assert not _confirmed(v), v


def test_the_evidence_it_offered_was_a_fragment_of_an_absent_probes_random_number():
    """Why the verdict was never evidence: the quoted snippet is text from `absent_a`.

    Kept as a separate assertion so that if the oracle is ever changed to report this shape again,
    the failure message says what the snippet actually was.
    """
    v = ws.analyze_traversal_differential(
        _r(WEAKRAND_EXISTS), _r(WEAKRAND_ABSENT_A), _r(WEAKRAND_ABSENT_B), _Twin,
        baseline=_r(WEAKRAND_EXISTS), exists_repeat=_r(WEAKRAND_REPEAT))
    if _confirmed(v):
        snippet = str(v.get("evidence") or "")
        assert snippet not in WEAKRAND_ABSENT_A, (
            "confirmed on a snippet lifted from the ABSENT response: %r" % snippet)


# ── the fix must not be a fix by amputation ──────────────────────────────────
def test_a_real_status_differential_still_confirms():
    """A genuine traversal: the present file answers 200, both absent twins answer 404, twice."""
    v = ws.analyze_traversal_differential(
        _r("root user file served", 200), _r("not found", 404), _r("not found", 404), _Twin,
        baseline=_r("home", 200), exists_repeat=_r("root user file served", 200))
    assert _confirmed(v), v


def test_a_real_body_differential_still_confirms():
    """A genuine traversal proved by body content the absent twins never produced, stable on repeat."""
    served = "Contents: PermitRootLogin yes ChallengeResponseAuthentication no"
    v = ws.analyze_traversal_differential(
        _r(served), _r("no such file"), _r("no such file"), _Twin,
        baseline=_r("home page"), exists_repeat=_r(served))
    assert _confirmed(v), v


def test_file_content_signature_still_confirms():
    """The shortcut oracle is untouched: the file's interior in the body is proof on its own."""
    v = ws.analyze_traversal_differential(
        _r("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"),
        _r("no such file"), _r("no such file"), _Twin,
        baseline=_r("home page"), exists_repeat=_r("root:x:0:0:root:/root:/bin/bash"))
    assert _confirmed(v), v
    assert v["oracle"] == "file-content-signature"


def test_missing_repeat_is_still_only_a_lead():
    """Q-047's guarantee is preserved: no fourth request, no confirmation."""
    served = "Contents: PermitRootLogin yes ChallengeResponseAuthentication no"
    v = ws.analyze_traversal_differential(
        _r(served), _r("no such file"), _r("no such file"), _Twin, baseline=_r("home page"))
    assert v and not _confirmed(v), v

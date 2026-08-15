"""The path-traversal oracle must confirm on TRAVERSAL, never on reflection.

MEASURED defect (docs/LEDGERS.md retraction, docs/CODEBASE_REVIEW.md V2): the oracle stamped
`confirmed` whenever the application echoed the probe back, so a page that echoes anything —
including a string that is not a filename and contains no `../` at all — produced a confirmed
path traversal. 22 clean `securecookie` cases carried one, and the whole 69.2% pathtraver score
rested on it.

Every test here is a negative control that FAILED before the fix, plus the two-sided evidence the
oracle now requires: content only the file system could have supplied, or a divergence between a
present-file target and an absent-file target of identical shape that the echoed parameter cannot
explain.
"""
import web_security as ws


def _r(body, status=200):
    return {"body": body, "status": status}


ECHO_BASE = _r("<html><body>You searched for: hello</body></html>")


def _echo(payload):
    return _r("<html><body>You searched for: %s</body></html>" % payload)


def _confirmed(verdict):
    """True only when the verdict is one the product would report as a real vulnerability."""
    if not verdict:
        return False
    return str(verdict.get("confidence") or "confirmed").lower() not in ws.UNPROVEN_TRAVERSAL_CONFIDENCE


# ── the three measured false positives, now regression tests ─────────────────
def test_reflected_traversal_payload_alone_is_not_a_confirmation():
    """`../bbh-canary.txt` echoed back proves the parameter reaches the page, not the file system."""
    v = ws.analyze_traversal_pair(ECHO_BASE, _echo("../bbh-canary.txt"), "../bbh-canary.txt",
                                  lab_mode=True)
    assert not _confirmed(v), v


def test_payload_with_no_traversal_sequence_is_not_a_confirmation():
    """No `../` anywhere in the payload — there is no traversal to confirm."""
    v = ws.analyze_traversal_pair(ECHO_BASE, _echo("bbh-canary.txt"), "bbh-canary.txt", lab_mode=True)
    assert not _confirmed(v), v


def test_payload_that_is_not_a_filename_is_not_a_confirmation():
    v = ws.analyze_traversal_pair(ECHO_BASE, _echo("APOLAKI-NOT-A-FILE-9182"),
                                  "APOLAKI-NOT-A-FILE-9182", lab_mode=True)
    assert not _confirmed(v), v


def test_a_parameter_that_merely_echoes_never_confirms_through_the_differential():
    """The strongest form of the control: an endpoint whose ONLY behaviour is to echo. The twin
    responses differ (different payloads), but every difference is the echo itself."""
    twin = ws.build_traversal_twins(nonces=["aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"])[0]
    v = ws.analyze_traversal_differential(
        _echo(twin.exists), _echo(twin.absent_a), _echo(twin.absent_b), twin, baseline=ECHO_BASE)
    assert not _confirmed(v), v


# ── what a real confirmation looks like ──────────────────────────────────────
def test_file_content_signature_confirms():
    v = ws.analyze_traversal_pair(ECHO_BASE, _r("root:x:0:0:root:/root:/bin/bash\n"),
                                  "../../../../etc/passwd", lab_mode=True)
    assert _confirmed(v), v


def test_content_signature_already_in_the_baseline_is_not_evidence():
    """A page that always shows /etc/passwd content did not traverse because we asked it to."""
    base = _r("root:x:0:0:root:/root:/bin/bash\n")
    v = ws.analyze_traversal_pair(base, _r("root:x:0:0:root:/root:/bin/bash\n"),
                                  "../../../../etc/passwd", lab_mode=True)
    assert not _confirmed(v), v


def test_existence_differential_confirms_on_a_real_file_system_oracle():
    """The shape OWASP Benchmark BenchmarkTest00040 actually returns: the app reports whether the
    resolved path exists. The echo is identical in structure; only the verdict sentence differs, and
    the parameter cannot have supplied that sentence."""
    twin = ws.build_traversal_twins(nonces=["aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"])[0]

    def page(payload, exists):
        return _r("Access to file: '%s' created.\n %s\n" % (
            payload.replace("/", "&#x2f;"),
            "And file already exists." if exists else "But file doesn't exist yet."))

    # The repeat is the order control (Q-047): a real file system answers the same way twice, so the
    # repeat looks exactly like the first `exists`. Passing it is not a formality -- without it this
    # same evidence is only a lead, which is what `test_..._without_the_repeat_is_only_a_lead` pins.
    v = ws.analyze_traversal_differential(
        page(twin.exists, True), page(twin.absent_a, False), page(twin.absent_b, False), twin,
        baseline=ECHO_BASE, exists_repeat=page(twin.exists, True))
    assert _confirmed(v), v
    assert "REPRODUCED" in v["reason"], v


def test_identical_responses_never_confirm():
    """The Benchmark's non-observable shape (BenchmarkTest00011): every payload gets the same page."""
    twin = ws.build_traversal_twins(nonces=["aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"])[0]
    same = _r("Nothing to see here.")
    v = ws.analyze_traversal_differential(same, same, same, twin, baseline=ECHO_BASE)
    assert not _confirmed(v), v


def test_a_nondeterministic_endpoint_cannot_confirm():
    """Two ABSENT targets already disagree, so any exists/absent difference is noise, not a file
    system. Without this control a page carrying a request id or a timestamp confirms every time."""
    twin = ws.build_traversal_twins(nonces=["aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"])[0]
    v = ws.analyze_traversal_differential(
        _r("request 111 done"), _r("request 222 done"), _r("request 333 done"), twin,
        baseline=ECHO_BASE)
    assert not _confirmed(v), v


def test_status_only_divergence_confirms_because_a_parameter_cannot_echo_a_status():
    twin = ws.build_traversal_twins(nonces=["aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"])[0]
    v = ws.analyze_traversal_differential(
        _r("", 200), _r("", 404), _r("", 404), twin, baseline=ECHO_BASE, exists_repeat=_r("", 200))
    assert _confirmed(v), v


# ── Q-047: the ORDER control ──────────────────────────────────────────────────
# MEASURED against the live lab on weakrand-00/BenchmarkTest00187, a case vulnerable to nothing.
# Sending `exists` first gave it the session-establishing body while both absent probes got the
# steady-state one; the absent pair agreed, the divergence was not the echoed payload, and the oracle
# confirmed. Reordering so an ABSENT payload went first moved the divergence and the finding vanished
# -- proof the verdict tracked REQUEST ORDER, not the file system.
_FIRST_REQUEST = "SafeIngrid00187 has been remembered with cookie: rememberMe00187"
_STEADY_STATE = "Welcome back: SafeIngrid00187"


def _stateful_first_request(twin):
    """The exact shape of the false positive: whoever goes first sees a different page."""
    return dict(exists_resp=_r(_FIRST_REQUEST), absent_a_resp=_r(_STEADY_STATE),
                absent_b_resp=_r(_STEADY_STATE), twin=twin)


def test_a_stateful_first_request_no_longer_confirms():
    """THE regression test for Q-047. The repeat sees the steady-state page, so the divergence does
    not reproduce and there is no finding at all."""
    twin = ws.build_traversal_twins(nonces=["aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"])[0]
    v = ws.analyze_traversal_differential(exists_repeat=_r(_STEADY_STATE),
                                          **_stateful_first_request(twin))
    assert v is None, v


def test_that_scenario_DID_confirm_without_the_repeat():
    """The precondition, asserted rather than asserted-about: with three requests this evidence is
    indistinguishable from a real file system. If this ever stops holding, the test above is passing
    for some other reason and stops being a control."""
    twin = ws.build_traversal_twins(nonces=["aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"])[0]
    v = ws.analyze_traversal_differential(**_stateful_first_request(twin))
    assert v is not None and v["oracle"] == "existence-differential", v


def test_a_divergence_without_the_repeat_is_only_a_lead():
    """A caller that runs no order control gets the weaker verdict, and the report says WHY rather
    than dropping the signal: no control was run, so nothing was established."""
    twin = ws.build_traversal_twins(nonces=["aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"])[0]
    v = ws.analyze_traversal_differential(**_stateful_first_request(twin))
    assert not _confirmed(v), v
    assert v["confidence"] == "lead" and "NOT REPEATED" in v["reason"], v


def test_a_status_divergence_that_does_not_reproduce_is_rejected_too():
    """The other confirmation path gets the same control -- one guarded branch and one unguarded one
    is how the FP survives its own fix."""
    twin = ws.build_traversal_twins(nonces=["aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"])[0]
    v = ws.analyze_traversal_differential(
        _r("", 200), _r("", 404), _r("", 404), twin, exists_repeat=_r("", 404))
    assert v is None, v


# ── the twins themselves must be shape-identical, or the differential is unsound ──
def test_twin_payloads_are_shape_identical_so_only_the_target_differs():
    """A response that is a function of the parameter's SHAPE (its length, its segment count, its
    encoding) must be identical across the twins — otherwise the oracle confirms on string length."""
    for twin in ws.build_traversal_twins(nonces=["0123456789abcdef", "fedcba9876543210"]):
        assert len(twin.exists) == len(twin.absent_a) == len(twin.absent_b), twin
        for other in (twin.absent_a, twin.absent_b):
            assert twin.exists.count("/") == other.count("/"), twin
            assert twin.exists.count("\\") == other.count("\\"), twin
            assert twin.exists.count("..") == other.count(".."), twin
        assert twin.absent_a != twin.absent_b
        assert ".." in twin.exists


def test_twin_absent_targets_are_unique_per_call():
    a = ws.build_traversal_twins()[0]
    b = ws.build_traversal_twins()[0]
    assert a.absent_a != b.absent_a


# ── the divergence primitive itself ──────────────────────────────────────────
def test_unexplained_divergence_ignores_pure_echo_and_catches_real_text():
    assert ws.unexplained_divergence("hello ../a/b there", "hello ../c/d there",
                                     ["../a/b", "../c/d"]) is None
    # HTML-escaped echo is still echo — the Benchmark escapes '/' as &#x2f;. The segments are long
    # enough here that only the redaction can discard them: this is the assertion that defends it.
    assert ws.unexplained_divergence("file '..&#x2f;etc&#x2f;passwd' ok",
                                     "file '..&#x2f;q7x9a1&#x2f;b2c3d4' ok",
                                     ["../etc/passwd", "../q7x9a1/b2c3d4"]) is None
    # ...and an app that echoes the RESOLVED path is still echoing, not proving.
    assert ws.unexplained_divergence("opened /var/data/etc/passwd", "opened /var/data/q7x9a1/b2c3d4",
                                     ["../etc/passwd", "../q7x9a1/b2c3d4"]) is None
    assert ws.unexplained_divergence("file exists", "file missing", ["../a/b", "../c/d"])

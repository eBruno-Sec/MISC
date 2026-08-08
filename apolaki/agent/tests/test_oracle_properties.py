"""Property-based tests over Apolaki's ORACLE INVARIANTS (#125, Robust Python Ch.23).

Example-based tests check the cases someone thought of. Ch.23's point is that the interesting failures are
the ones nobody thought of, and that a generator *"will find boundary values for you"*.

These state the invariants directly. The load-bearing one, in every oracle:

    NOTHING IS EVER 'confirmed' UNLESS ITS FULL EVIDENCE CONTRACT HOLDS.

Hypothesis then attacks that over arbitrary status codes and bodies, including the empty/whitespace/
identical/near-identical cases that hand-written examples routinely miss.
"""
import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings, strategies as st, HealthCheck  # noqa: E402

import bie  # noqa: E402
import transport_posture as tp  # noqa: E402

# Bodies deliberately include empty, whitespace and near-duplicates — the boundaries of "same body".
bodies = st.one_of(
    st.just(""), st.just("   "), st.just("{}"),
    st.text(min_size=0, max_size=80),
    st.sampled_from(['{"id":1,"owner":"a"}', '{"id":2,"owner":"b"}', "<html><app-root></app-root></html>"]),
)
statuses = st.sampled_from([0, 200, 201, 204, 301, 400, 401, 403, 404, 405, 500, 503])
SETTINGS = settings(max_examples=250, deadline=None,
                    suppress_health_check=[HealthCheck.too_slow])


def _ex(status, body):
    return bie.exchange("http://t/rest/basket/1", status, body)


# ── bie.judge — the persona-swap oracle ───────────────────────────────────────
@SETTINGS
@given(bs=statuses, bb=bodies, ms=statuses, mb=bodies, ans=statuses, ab=bodies,
       ns=statuses, nb=bodies)
def test_judge_confirms_only_when_the_entire_contract_holds(bs, bb, ms, mb, ans, ab, ns, nb):
    """THE invariant. A confirmation requires: the owner really had an object, the attacker got it
    byte-for-byte, and BOTH negative controls disagree. Hypothesis may not find a single counterexample."""
    v = bie.judge(_ex(bs, bb), _ex(ms, mb), anon=_ex(ans, ab), nonexistent=_ex(ns, nb))
    if v["verdict"] != "confirmed":
        return
    assert bs == 200 and len(bb.strip()) >= bie._MIN_BODY   # owner had a substantive object
    assert ms == 200 and mb == bb                           # attacker received exactly it
    assert not (ans == 200 and ab == bb)                    # anonymous did NOT also get it
    assert not (ns == 200 and nb == bb)                     # implausible id did NOT also get it


@SETTINGS
@given(bs=statuses, bb=bodies, ms=statuses, mb=bodies)
def test_judge_never_confirms_with_a_missing_control(bs, bb, ms, mb):
    """A missing control is missing evidence. No combination of inputs may promote it to proof."""
    for anon, nonex in ((None, _ex(404, "")), (_ex(401, ""), None), (None, None)):
        v = bie.judge(_ex(bs, bb), _ex(ms, mb), anon=anon, nonexistent=nonex)
        assert v["verdict"] != "confirmed", (v, anon is None, nonex is None)


@SETTINGS
@given(s=statuses, b=bodies)
def test_judge_is_total_and_never_raises(s, b):
    """An oracle that throws is an oracle that silently drops findings."""
    v = bie.judge(_ex(s, b), _ex(s, b), anon=_ex(s, b), nonexistent=_ex(s, b))
    assert v["verdict"] in ("confirmed", "rejected", "lead", "not_applicable")
    assert isinstance(v.get("reason"), str) and v["reason"]


# ── bie.judge_param_swap — identity-parameter tampering ───────────────────────
@SETTINGS
@given(ss=statuses, sb=bodies, os_=statuses, ob=bodies, ms=statuses, mb=bodies)
def test_param_swap_confirms_only_on_the_other_personas_baseline(ss, sb, os_, ob, ms, mb):
    v = bie.judge_param_swap(_ex(ss, sb), _ex(os_, ob), _ex(ms, mb), anon=_ex(401, ""))
    if v["verdict"] != "confirmed":
        return
    assert ss == 200 and os_ == 200 and ms == 200
    assert ob != sb            # the two personas must be distinguishable at all
    assert mb == ob            # the response became the OTHER persona's view
    assert mb != sb            # and is not merely the session's own answer (the SECURE case)


# ── bie.judge_client_side_authz — CWE-602 ─────────────────────────────────────
@SETTINGS
@given(ps=statuses, pb=bodies, ans=statuses, ab=bodies, shs=statuses, shb=bodies,
       visible=st.booleans(), disabled=st.booleans())
def test_client_side_authz_never_confirms_an_offered_control(ps, pb, ans, ab, shs, shb, visible, disabled):
    ctl = {"visible": visible, "disabled": disabled, "reason": "not-displayed"}
    v = bie.judge_client_side_authz(ctl, _ex(ps, pb), anon=_ex(ans, ab), shell=_ex(shs, shb))
    if v["verdict"] != "confirmed":
        return
    assert not (visible and not disabled)      # a control the UI OFFERS can never be "withheld"
    assert ps == 200 and len(pb.strip()) >= bie._MIN_BODY
    assert shb != pb                            # not the SPA shell
    assert not (ans == 200 and ab == pb)        # not public content


# ── transport_posture — protocol + method oracles ─────────────────────────────
@SETTINGS
@given(sup=st.dictionaries(
    st.sampled_from(["SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]),
    st.one_of(st.booleans(), st.none()), min_size=0, max_size=5))
def test_protocol_grading_never_reports_an_untested_version_as_supported(sup):
    g = tp.analyze_protocols(sup)
    for p in g["deprecated_supported"]:
        assert sup.get(p) is True, "reported %s as supported when it was %r" % (p, sup.get(p))
    assert set(g["deprecated_supported"]).isdisjoint(g["untestable"])


@SETTINGS
@given(sup=st.dictionaries(st.sampled_from(["SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]),
                           st.just(True), min_size=4, max_size=5))
def test_a_probe_that_accepts_everything_never_yields_a_tls_finding(sup):
    """If every pinned version 'succeeds' the probe is not discriminating; claiming anything is noise."""
    fs = tp.findings_for("https://t", protocols=sup)
    assert [f for f in fs if "tls" in f["tags"]] == []


@SETTINGS
@given(status=statuses, body=bodies, marker=st.text(min_size=1, max_size=20))
def test_trace_confirms_only_on_the_echoed_marker(status, body, marker):
    iss = tp.analyze_methods("", trace_status=status, trace_body=body, trace_marker=marker)
    if any(i["id"] == "methods_trace_enabled" for i in iss):
        assert status == 200 and marker in body


@SETTINGS
@given(name=st.text(min_size=1, max_size=24), secure=st.booleans(), httponly=st.booleans(),
       samesite=st.sampled_from(["", "lax", "strict", "none"]), https=st.booleans())
def test_cookie_findings_only_ever_concern_session_cookies(name, secure, httponly, samesite, https):
    hdr = "%s=v" % name + ("; Secure" if secure else "") + ("; HttpOnly" if httponly else "") + \
          ("; SameSite=%s" % samesite if samesite else "")
    for iss in tp.analyze_cookies([hdr], is_https=https):
        assert tp.is_session_cookie(name), "flagged a non-session cookie %r" % name
        if iss["id"] == "cookie_missing_secure":
            assert https and not secure     # never demanded on a plaintext origin

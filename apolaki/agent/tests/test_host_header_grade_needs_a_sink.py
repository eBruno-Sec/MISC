"""Q-114 - host-header injection was graded MEDIUM with no check that a sink exists.

THE DETECTION WAS RIGHT. This is the first Apolaki finding of the Shopify engagement to survive hand
verification, and the operator reproduced it himself:

    curl -is https://linkpop.com/054470-ee -H 'Host: bbh-evil.example'
    HTTP/1.1 301 Moved Permanently
    Location: https://bbh-evil.example/054470-ee/index.html?s=1
    Server: UploadServer

THE GRADE WAS NOT. He then probed both sinks and neither existed:

  * no shared cache -- no Age, no X-Cache, no CF-Cache-Status, no Via on any response, so nothing
    stores the poisoned redirect and no second visitor ever receives it;
  * X-Forwarded-Host ignored -- supplying it returned a Location pointing at the legitimate host, so
    the reverse-proxy route into the same primitive is absent too.

`Server: UploadServer` is a Google Cloud Storage bucket website, where building the redirect from the
supplied Host is stock platform behaviour rather than an application defect. The correct output was
INFORMATIONAL, and Apolaki said MEDIUM unconditionally.

This is the Q-106 lesson moved one layer out, from the ORACLE to the GRADE: the detection was sound
and the severity was asserted rather than measured. A MEDIUM sent to a mature program on this
evidence is closed N/A, and N/A closures cost the reporter signal on the platform.

THE NEGATIVE CONTROL IS THE HALF THAT KEEPS THIS AN ORACLE. The same redirect plus a cache indicator
must still grade MEDIUM. Without it, "downgrade everything" satisfies every other test in this file,
which is a blind spot wearing the costume of precision.
"""
import web_security as ws


EVIL = ws._EVIL_HOST
#: The operator's own response, verbatim in shape.
_LINKPOP_LOC = "https://%s/054470-ee/index.html?s=1" % EVIL
_LINKPOP_HEADERS = {"Content-Type": "text/html; charset=utf-8", "Location": _LINKPOP_LOC,
                    "Server": "UploadServer", "Content-Length": "0"}


# -- the field case ------------------------------------------------------------

def test_the_linkpop_shape_with_no_sink_grades_informational():
    """No cache headers, X-Forwarded-Host ignored (the Location comes back legitimate)."""
    got = ws.analyze_host_header("", _LINKPOP_LOC, resp_headers=_LINKPOP_HEADERS,
                                 xfh_location="https://linkpop.com/054470-ee/index.html?s=1")
    assert got and got["severity"] == "INFORMATIONAL", got
    assert got["sinks"] == [], got


def test_the_informational_detail_says_which_probes_came_back_empty():
    """A downgrade with no reason is indistinguishable from a missed finding. The reader has to be
    able to re-run the two probes and disagree."""
    got = ws.analyze_host_header("", _LINKPOP_LOC, resp_headers=_LINKPOP_HEADERS, xfh_location="")
    low = got["detail"].lower()
    assert "x-cache" in low and "x-forwarded-host" in low, got["detail"]


# -- the negative controls, i.e. the half that keeps this an oracle -------------

def test_a_cache_indicator_still_grades_medium():
    """THE ONE THAT MATTERS. `Age` + `X-Cache: HIT` means something STORED the poisoned redirect."""
    hdrs = dict(_LINKPOP_HEADERS, **{"Age": "0", "X-Cache": "HIT"})
    got = ws.analyze_host_header("", _LINKPOP_LOC, resp_headers=hdrs, xfh_location="")
    assert got["severity"] == "MEDIUM", got
    assert any("cache" in s for s in got["sinks"]), got


def test_an_honoured_x_forwarded_host_still_grades_medium():
    """The other sink, on its own. A reverse proxy that trusts XFH is a route into the same
    primitive even with no cache anywhere."""
    got = ws.analyze_host_header("", _LINKPOP_LOC, resp_headers=_LINKPOP_HEADERS,
                                 xfh_location="https://%s/anything" % EVIL)
    assert got["severity"] == "MEDIUM", got
    assert any("X-Forwarded-Host" in s for s in got["sinks"]), got


def test_a_shared_storage_cache_control_is_a_sink():
    """`s-maxage` is an instruction to a SHARED cache, which is the sink itself."""
    hdrs = dict(_LINKPOP_HEADERS, **{"Cache-Control": "public, s-maxage=600"})
    got = ws.analyze_host_header("", _LINKPOP_LOC, resp_headers=hdrs, xfh_location="")
    assert got["severity"] == "MEDIUM", got


def test_a_private_no_store_response_is_not_a_sink():
    """The inverse, so the Cache-Control branch cannot be satisfied by matching the header name."""
    hdrs = dict(_LINKPOP_HEADERS, **{"Cache-Control": "private, no-store"})
    got = ws.analyze_host_header("", _LINKPOP_LOC, resp_headers=hdrs, xfh_location="")
    assert got["severity"] == "INFORMATIONAL", got


# -- not supplied is not the same as supplied and empty ------------------------

def test_a_caller_that_did_not_probe_gets_the_unchanged_grade():
    """Q-103's rule. A caller with no sink evidence must not be silently credited with a NEGATIVE
    result - absence of evidence is not evidence of absence, and six other call sites and tests
    invoke this function with two arguments."""
    got = ws.analyze_host_header("", _LINKPOP_LOC)
    assert got["severity"] == "MEDIUM", got


# -- Q-106b must not regress ---------------------------------------------------

def test_an_open_redirect_parameter_is_still_not_a_host_header_finding():
    """The structural test that made this finding trustworthy in the first place. A grade change
    must not quietly reopen the substring oracle underneath it."""
    loc = "https://legit.example/login?next=https%%3A%%2F%%2F%s" % EVIL
    assert ws.analyze_host_header("", loc, resp_headers={"Age": "0"}, xfh_location="") is None


def test_a_relative_location_carries_no_host_and_is_silent():
    assert ws.analyze_host_header("", "/redir?to=" + EVIL, resp_headers={}, xfh_location="") is None


def test_the_body_reflection_branch_is_untouched_and_still_low():
    """The LOW body branch claims reflection, not a redirect primitive, so no sink applies to it."""
    got = ws.analyze_host_header("<a href='//%s/'>x</a>" % EVIL, "", resp_headers={}, xfh_location="")
    assert got and got["severity"] == "LOW", got


def test_a_clean_response_is_silent():
    assert ws.analyze_host_header("", "https://legit.example/", resp_headers={}, xfh_location="") is None
    assert ws.analyze_host_header("", "", resp_headers={}, xfh_location="") is None


# -- the sink helper on its own ------------------------------------------------

def test_every_cache_indicator_is_recognised_individually():
    """One vendor's header must not be the only one that counts. Each alone is a shared cache."""
    for h in ("Age", "X-Cache", "CF-Cache-Status", "Via", "X-Served-By", "X-Varnish"):
        assert ws.host_header_sinks({h: "1"}, "") , h


def test_no_headers_and_no_xfh_is_no_sink():
    assert ws.host_header_sinks({}, "") == []
    assert ws.host_header_sinks(None, None) == []

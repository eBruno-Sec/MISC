"""ONE contract for set_param, across every module that defines one.

Three modules define `set_param` and every injection engine probes through one of them:
`_run_sqli`, `_run_nosqli`, `_run_cmdi` and `_run_xss` via `xss_tool`, the SSRF engines via
`ssrf_tool`, the DOM engines via `dom_trace`. They disagreed about a MISSING parameter -- two
appended it, one returned the URL unchanged.

Why that is a silent false negative and not a cosmetic difference: when the engine is probing a
parameter it DISCOVERED rather than one already on the URL, a `set_param` that drops it returns the
baseline URL. The engine then sends the baseline, compares it against the baseline, finds no
difference, and reports the endpoint clean. The probe was never sent, and the result is shaped
exactly like a correct non-detection.

THE CONTRACT: setting a parameter always yields a URL in which that parameter carries that value.
Absent means appended, never dropped.

The load-bearing assertion is `test_setting_any_parameter_changes_the_url`: a probe that equals its
own baseline is not a probe. That is what would have caught the divergence, and it is what keeps any
future implementation honest.
"""
import os
import sys
from urllib.parse import parse_qsl, urlparse

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dom_trace  # noqa: E402
import ssrf_tool  # noqa: E402
import xss_tool  # noqa: E402

MODULES = [("xss_tool", xss_tool), ("ssrf_tool", ssrf_tool), ("dom_trace", dom_trace)]
BASE = "https://t.example/app?id=1&page=2"


def _q(url):
    return dict(parse_qsl(urlparse(url).query, keep_blank_values=True))


@pytest.mark.parametrize("name,mod", MODULES)
def test_setting_any_parameter_changes_the_url(name, mod):
    """THE NEGATIVE CONTROL. A probe URL identical to the baseline is not a probe -- the differential
    is zero by construction and the endpoint reports clean whatever it does."""
    for param in ("id", "page", "absent", "q"):
        out = mod.set_param(BASE, param, "PAYLOAD")
        assert out != BASE, "%s.set_param dropped %r: the probe IS the baseline" % (name, param)
        assert _q(out).get(param) == "PAYLOAD", "%s.set_param(%r) did not carry the value" % (name, param)


@pytest.mark.parametrize("name,mod", MODULES)
def test_missing_parameter_is_appended_not_dropped(name, mod):
    out = mod.set_param(BASE, "absent", "PAYLOAD")
    q = _q(out)
    assert q["absent"] == "PAYLOAD"
    assert q["id"] == "1" and q["page"] == "2", "siblings must survive"


@pytest.mark.parametrize("name,mod", MODULES)
def test_existing_parameter_is_replaced_and_siblings_untouched(name, mod):
    q = _q(mod.set_param(BASE, "id", "PAYLOAD"))
    assert q["id"] == "PAYLOAD" and q["page"] == "2"
    assert len(q) == 2, "replacing a parameter must not add one"


@pytest.mark.parametrize("name,mod", MODULES)
def test_works_on_a_url_with_no_query_at_all(name, mod):
    out = mod.set_param("https://t.example/app", "q", "PAYLOAD")
    assert _q(out).get("q") == "PAYLOAD"
    assert out != "https://t.example/app"


@pytest.mark.parametrize("name,mod", MODULES)
def test_all_modules_agree(name, mod):
    """Same input, same output -- the divergence itself is the defect."""
    for param in ("id", "absent"):
        assert mod.set_param(BASE, param, "X") == xss_tool.set_param(BASE, param, "X"), (
            "%s disagrees with xss_tool on %r" % (name, param))

"""CSS injection engine (CWE-74 / WSTG-CLNT-05). Confirms ONLY when input reflects into a CSS context with
the breakout chars unescaped — reflection alone (or HTML-encoded output) must NOT confirm."""
import blind_benchmark as bb
import css_injection_tool as css
from report import cvss31_base_score


def test_payload_carries_css_breakout():
    p = css.payload("dead")
    assert "apolcssdead" in p and "{" in p and "}" in p and ";" in p


def test_confirms_in_style_block_when_braces_survive():
    t = "dead"
    body = "<html><style> .x { color:blue } .%s;x{color:red} </style></html>" % ("apolcss" + t)
    ev = css.evaluate(body, t)
    assert ev["confirmed"] and ev["where"] == "style block"


def test_confirms_in_style_attribute():
    t = "beef"
    body = '<div style="width:10px; apolcss%s;x{color:red}">hi</div>' % t
    ev = css.evaluate(body, t)
    assert ev["confirmed"] and ev["where"] == "style attribute"


def test_does_not_confirm_outside_css_or_when_encoded():
    t = "cafe"
    # reflected in plain HTML body (not a CSS context) -> not CSS injection
    assert not css.evaluate("<p>apolcss%s;x{color:red}</p>" % t, t)["confirmed"]
    # reflected in a <style> block but HTML-entity-encoded -> safely encoded, not injectable
    enc = "<style>.a{} apolcss%s&#59;x&#123;color:red&#125; </style>" % t
    assert not css.evaluate(enc, t)["confirmed"]
    # not reflected at all
    assert not css.evaluate("<style>.a{color:red}</style>", t)["confirmed"]


def test_finding_is_proof_with_consistent_cvss():
    f = css.finding("https://x/p?q=1", "q", "style block", "braces unescaped")
    assert f["family"] == "css_injection" and f["cwe"] == "CWE-74" and bb._has_proof(f)
    assert abs(cvss31_base_score(f["cvss_vector"]) - f["cvss_score"]) < 0.05

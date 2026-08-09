"""CSS injection engine (CWE-74 / WSTG-CLNT-05). Confirms ONLY when input reflects into a CSS context with
the breakout chars unescaped — reflection alone (or HTML-encoded output) must NOT confirm."""
import asyncio
import html

import blind_benchmark as bb
import css_injection_tool as css
import pytest
import tools
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


def test_cssom_nonce_is_token_bound_and_sanitised():
    """The property/value carry the token, so nothing but OUR injection can satisfy the CSSOM read."""
    assert css.custom_property("d00d") == "--apolaki-d00d" and css.cssom_value("d00d") == "vd00d"
    assert css.custom_property("a b;}/*") == "--apolaki-ab"      # CSS-structural chars stripped
    assert css.custom_property("") == "--apolaki-probe"           # never degenerates to "--apolaki-"
    p = css.payload("d00d")
    assert "--apolaki-d00d:vd00d" in p and ":root{" in p


def _cssom_match(document: str, token: str, chrome: str) -> dict:
    """Ask a REAL Chromium whether it parsed the document as CSS and set our nonce custom property.

    This is Chromium's own CSS parser and CSSOM — Apolaki is not re-reading its own payload out of a
    string it wrote, which is the only way this fixture could prove anything.
    """
    async def _go():
        from playwright.async_api import async_playwright
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True, executable_path=chrome,
                args=["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"])
            page = await (await browser.new_context()).new_page()
            await page.set_content(document)
            hit = await css.read_cssom(page, token)
            await browser.close()
            return hit
    return asyncio.run(_go())


def test_cssom_probe_confirms_in_real_chromium_and_declines_both_safe_twins():
    """The precision half of the engine: _run_css_injection DISCARDS a reflection-oracle hit when Chromium
    is available and the CSSOM read does not match, so this negative control is what keeps that gate honest."""
    chrome = tools._chrome_path()
    if not chrome:
        pytest.skip("Chromium is required for the real CSSOM fixture")
    t = "d00d"
    injected = css.payload(t)

    # VULNERABLE: input lands inside a declaration list with the breakout chars intact, so the trailing
    # `:root{...}` rule becomes real CSS and the custom property reaches computed style.
    vulnerable = "<html><style>.a{color:blue;%s</style><p>x</p></html>" % injected
    hit = _cssom_match(vulnerable, t, chrome)
    assert hit["matched"] is True, hit
    assert hit["tag"] == "html", hit          # :root == documentElement

    # SAFE TWIN 1 — same bytes, HTML-escaped into a text context. Never a CSS context, never parsed.
    escaped = "<html><style>.a{color:blue}</style><p>%s</p></html>" % html.escape(injected)
    assert _cssom_match(escaped, t, chrome)["matched"] is False

    # SAFE TWIN 2 — reflected INSIDE <style> but entity-encoded. <style> is raw text, so the entities are
    # NOT decoded and the CSS parser sees garbage: the reflection is there, the injection is not.
    enc = injected.replace(";", "&#59;").replace("{", "&#123;").replace("}", "&#125;")
    assert _cssom_match("<html><style>.a{color:blue} %s</style></html>" % enc, t, chrome)["matched"] is False

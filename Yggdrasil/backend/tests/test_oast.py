"""Tests for the out-of-band (OAST) callback listener and OOB payload templating."""
import asyncio
import httpx

from core.oast import OASTListener
from core.payloads import oob_payloads, dom_payloads, DOM_MARKER


def test_url_for_and_token_shape():
    lis = OASTListener(host="10.0.0.5", port=1234)
    t = lis.new_token()
    assert t.startswith("ygg") and len(t) > 6
    assert lis.url_for(t) == f"http://10.0.0.5:1234/{t}"


def test_listener_records_and_correlates_callback():
    async def go():
        lis = await OASTListener(host="127.0.0.1").start()
        tok = lis.new_token()
        async with httpx.AsyncClient(trust_env=False, timeout=5) as c:
            await c.get(lis.url_for(tok))
        await asyncio.sleep(0.2)
        result = (lis.got(tok), lis.got("yggnope0000"))
        await lis.stop()
        return result
    hit, miss = asyncio.run(go())
    assert hit is True
    assert miss is False


def test_oob_payloads_embed_callback_url():
    url = "http://oast.example:9/tok"
    bundle = oob_payloads(url)
    assert url in bundle["ssrf"]
    assert any("curl " + url in p for p in bundle["cmdi"])
    assert any(url in p and "SYSTEM" in p for p in bundle["xxe"])


def test_dom_payloads_call_marker():
    pls = dom_payloads()
    assert any(DOM_MARKER in p and "onerror" in p for p in pls)
    assert any(p.startswith("javascript:") for p in pls)

"""Document-relative links must enter the scan surface.

Regression for the defect that made whole-product missions useless: _http_probe kept only links
starting with "http" or "/", so `cmdi-Index.html`, `./x` and `../y` were silently discarded. Apolaki
could not crawl any site that links relatively -- which is most of them. On the OWASP Benchmark it threw
away all 11 category indexes and with them every one of the 2740 test cases, then reported
"coverage completed".
"""
import asyncio

import scope
import tools

_PAGE = """<html><head>
<link rel=stylesheet href="/app/css/site.css">
<script src="js/app.js"></script>
</head><body>
<a href="cmdi-Index.html">cmdi</a>
<a href="./sqli-Index.html">sqli</a>
<a href="../parent.html">up</a>
<a href="https://target.tld/app/absolute.html">abs</a>
<a href="//target.tld/app/protocol-relative.html">protorel</a>
<a href="mailto:x@y.z">mail</a>
<a href="javascript:void(0)">js</a>
<a href="#frag">frag</a>
</body></html>"""


def _probe(page_url):
    sc = scope.ScopeEngine()
    sc.load_manual(["target.tld"], [], "T")
    reg = tools.ToolRegistry(sc, mission_id=None, lab_mode=True)

    async def _http(url, method="GET", *a, **kw):
        return {"status": 200, "headers": {}, "body": _PAGE, "final_url": page_url, "error": ""}

    reg._http = _http
    asyncio.run(reg._http_probe({"url": page_url}))
    return list(reg.urls or [])


def test_document_relative_links_are_followed():
    urls = _probe("https://target.tld/app/index.html")
    assert "https://target.tld/app/cmdi-Index.html" in urls, urls
    assert "https://target.tld/app/sqli-Index.html" in urls, urls
    assert "https://target.tld/parent.html" in urls, urls


def test_absolute_root_relative_and_protocol_relative_still_work():
    urls = _probe("https://target.tld/app/index.html")
    assert "https://target.tld/app/absolute.html" in urls
    assert "https://target.tld/app/css/site.css" in urls
    assert "https://target.tld/app/js/app.js" in urls
    # protocol-relative must resolve to ONE host, never scheme://host//host/x
    assert "https://target.tld/app/protocol-relative.html" in urls
    assert not any(u.count("target.tld") > 1 for u in urls), urls


def test_non_navigable_schemes_are_excluded():
    """mailto/javascript/fragments must never become scan targets."""
    urls = _probe("https://target.tld/app/index.html")
    assert not any(u.startswith(("mailto:", "javascript:")) for u in urls), urls
    assert all(u.startswith(("http://", "https://")) for u in urls), urls

"""General parameter discovery: JS-source harvest + batched reflection probe. These are the target-derived
candidate sources that let the reflected/DOM/request-override probes reach params that no crawl edge links
(e.g. /login?redirect=, /?url=). Pure logic tested here; HTTP transport lives in tools."""
import param_discovery as pd


def test_harvest_js_params_from_client_reads():
    js = """
      const p = new URLSearchParams(location.search);
      let r = p.get('redirect'); let u = getParameterByName("returnUrl");
      fetch('/api?postId=' + params['postId']);
    """
    names = pd.harvest_js_params(js)
    for expect in ("redirect", "returnUrl", "postId"):
        assert expect in names, (expect, names)
    assert "http" not in [n.lower() for n in names]


def test_harvest_bounded():
    js = " ".join("searchParams.get('p%d')" % i for i in range(50))
    assert len(pd.harvest_js_params(js, cap=8)) == 8


def test_probe_url_batches_unique_canaries_and_preserves_existing():
    u = "https://x/login?next=1"
    pu, tokens = pd.probe_url(u, ["redirect", "url", "search"])
    # each candidate gets a distinct token
    assert len(set(tokens.values())) == 3
    # existing param preserved, candidates added
    assert "next=1" in pu
    for n, t in tokens.items():
        assert ("%s=%s" % (n, t)) in pu


def test_reflected_reads_back_only_live_params():
    _, tokens = pd.probe_url("https://x/login", ["redirect", "url", "search"])
    # a body that echoes only the 'redirect' canary
    body = "<input name=redirect value=%s>" % tokens["redirect"]
    live = pd.reflected(body, tokens)
    assert live == ["redirect"]


def test_discover_orders_existing_then_js_then_wordlist():
    out = pd.discover("https://x/login?next=1",
                      js_sources=["let r = searchParams.get('redirect');"],
                      body="", cap=10)
    cands = out["candidates"]
    assert cands[0] == "next"                     # existing first
    assert "redirect" in cands                    # js-harvested included
    assert cands.index("redirect") < cands.index("q")  # js before generic wordlist
    # the probe URL never re-adds the existing param as a candidate token
    assert "redirect" in out["probe"]["tokens"] and "next" not in out["probe"]["tokens"]


def test_discover_probe_roundtrip():
    out = pd.discover("https://x/p", js_sources=[], body="", cap=12)
    tokens = out["probe"]["tokens"]
    # simulate a server reflecting the 'search' and 'q' params
    body = "%s and %s" % (tokens["search"], tokens["q"])
    assert set(pd.reflected(body, tokens)) == {"search", "q"}

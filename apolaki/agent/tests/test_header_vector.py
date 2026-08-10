"""Discovery of custom request-header inputs — a DELIVERY vector, not a vulnerability class.

An app that routes its value through a request header is invisible to any engine that only rewrites
URLs and bodies: the payload never arrives, the response never varies, and the endpoint reads clean.
Discovery must stay generic — keyed on how markup and XHR conventionally declare a header, never on
any particular application's naming.
"""
import header_vector as hv


def test_literal_setrequestheader_is_discovered():
    assert hv.discover_header_names('<script>xhr.setRequestHeader("X-Tenant-Id", v);</script>') == ["X-Tenant-Id"]
    # also when the script arrives separately from the HTML
    assert hv.discover_header_names("<html></html>", "xhr.setRequestHeader('X-Trace', t)") == ["X-Trace"]


def test_attribute_named_like_a_header_is_discovered():
    assert hv.discover_header_names('<div data-header-name="X-Api-Key"></div>') == ["X-Api-Key"]
    assert hv.discover_header_names("<div data-header='X-Role'></div>") == ["X-Role"]


def test_element_declaring_a_header_action_yields_its_token():
    """The dynamic case: setRequestHeader(tok, val) never puts the name in the script, so the only
    place it appears is the triggering element. Keyed on the word 'header' in an attribute VALUE."""
    html = '<input type="button" method="submitHeaderForm" testcase="Widget42" value="Go">'
    assert hv.discover_header_names(html) == ["Widget42"]


def test_hop_by_hop_and_auth_headers_are_never_probed():
    """Rewriting these changes the request's meaning rather than testing the app; Cookie has its own
    engine. A discovery that returned them would generate junk traffic on every page."""
    for bad in ("Content-Type", "Host", "Cookie", "Authorization", "Content-Length", "Connection"):
        assert hv.discover_header_names('<script>xhr.setRequestHeader("%s", v)</script>' % bad) == [], bad


def test_nothing_is_invented_from_ordinary_markup():
    """Negative control. An ordinary page must yield NO header names, or every scan grows a tail of
    pointless requests and the vector becomes noise."""
    assert hv.discover_header_names("") == []
    assert hv.discover_header_names("<html><form><input name=q><a href=/x>go</a></form></html>") == []
    assert hv.discover_header_names("<p>please set a header on your request</p>") == []   # prose only


def test_names_are_deduped_case_insensitively_and_validated():
    html = ('<script>xhr.setRequestHeader("X-Dup", a); xhr.setRequestHeader("x-dup", b)</script>'
            '<div data-header="X-Dup"></div>')
    assert hv.discover_header_names(html) == ["X-Dup"]
    # a value that is not a legal header token must not be emitted
    assert hv.discover_header_names('<div data-header="not a header"></div>') == []
    assert hv.discover_header_names('<div data-header="x"></div>') == []      # too short to be real

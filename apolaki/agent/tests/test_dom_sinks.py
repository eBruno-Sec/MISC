"""Q-147 ground truth for `dom_sinks` - the client-side sink families beyond `dom_trace`'s four.

EVERY case in this file has an answer I constructed by hand. That is the point: the week this
module was written deleted roughly 330 false positives from oracles that were technique-correct and
reality-wrong, and each of those oracles passed its own tests. So each sink here ships BOTH halves:

  POSITIVE          a genuine client-side flow fires, with the family's structural discriminator met
  NEGATIVE CONTROL  a server echo does not fire; a failed navigation does not fire; a clean render
                    is silent; and - the part that actually catches things - the SHAPE that looks
                    like the bug but is not it (a canary in a form action's query string, a canary
                    in the Referer header, the marker percent-encoded inside one parameter's value)

The two inherited rules are asserted directly, including their non-vacuity halves, because a gate
that suppresses everything satisfies every negative control and deletes the engine.
"""
import blind_benchmark as bb
import dom_sinks as ds
import dom_trace as dt
import proof_schema as ps


URL = "http://wpreach/shop?p=1&lang=x"
C = "domtr7168079a"          # the URL-source canary
PM = "dompm41c0ffee"         # the WEB MESSAGE canary - deliberately a different value
EVIL = "https://evilcab12cd34.example"


def _fams(sig, param="lang"):
    return {h["family"] for h in ds.classify(URL, param, C, sig)}


def _page_fams(sig):
    return {h["family"] for h in ds.classify_page(URL, sig)}


def _one(sig, param="lang"):
    hits = ds.classify(URL, param, C, sig)
    assert len(hits) == 1, [h["family"] for h in hits]
    return hits[0]


# ══════════════════════════════════════════════════════════════════════════════════════════════
# THE INHERITED RULES, ASSERTED FIRST
# ══════════════════════════════════════════════════════════════════════════════════════════════

def test_a_clean_render_reports_nothing():
    assert _fams({}) == set()
    assert _fams({"navigated": True, "server_reflected": False}) == set()
    assert _page_fams({}) == set()


def test_the_whole_wordpress_signal_shape_yields_nothing():
    """The Q-128 field case fed to THIS module: WordPress echoed the request URI into an href, a
    form action and the page text. Not one of these families may fire on it."""
    assert _fams({"in_href": "a[href]", "in_src": "img[src]", "in_attr": "title", "in_text": True,
                  "server_reflected": True, "navigated": True}) == set()


def test_the_chrome_error_page_shape_yields_nothing():
    """Q-129: the navigation never connected, so Chrome rendered its own error page with the
    requested URL - canary included - in it."""
    assert _fams({"in_text": True, "in_href": "a[href]", "navigated": False,
                  "server_reflected": False}) == set()
    assert _page_fams({"navigated": False, "prssi_relative_css": "css/app.css",
                       "prssi_path_tolerant": True, "prssi_quirks": True}) == set()


# ══════════════════════════════════════════════════════════════════════════════════════════════
# 1. HTML5 WEB MESSAGE MANIPULATION  (postMessage) - the highest-value sink on the list
# ══════════════════════════════════════════════════════════════════════════════════════════════

_PM_OK = {"pm_canary": PM, "pm_cross_origin": True, "pm_sink": "innerHTML",
          "pm_origin_checked": False}


def test_positive_a_cross_origin_message_reaching_a_sink_is_reported():
    assert _page_fams(_PM_OK) == {"web_message_manipulation"}


def test_positive_a_cross_origin_message_that_executes_is_web_message_xss():
    got = ds.classify_page(URL, {**_PM_OK, "pm_sink": "eval", "pm_executed": True})
    assert [h["family"] for h in got] == ["web_message_xss"]
    assert "FOREIGN origin" in got[0]["evidence"] and PM in got[0]["evidence"]


def test_negative_a_same_origin_probe_proves_nothing():
    """THE FALSE-POSITIVE TRAP FOR THIS FAMILY. A handler that correctly checks
    `event.origin === location.origin` ACCEPTS a same-origin probe and rejects the real attacker.
    Delivery from a foreign origin is the entire proof, so without it there is no finding."""
    assert _page_fams({**_PM_OK, "pm_cross_origin": False}) == set()


def test_negative_an_absent_cross_origin_flag_is_not_proof():
    """Unlike `navigated` and `server_reflected`, this signal has NO existing callers - so absent
    must mean "not proven", never "assume the good case". An engine that assumes its own premise
    reports the bug on every page with a message listener."""
    sig = dict(_PM_OK)
    del sig["pm_cross_origin"]
    assert _page_fams(sig) == set()


def test_negative_a_listener_that_reaches_no_sink_is_not_a_finding():
    """Most pages on the internet register a `message` listener. Having one is not a bug."""
    assert _page_fams({"pm_canary": PM, "pm_cross_origin": True, "pm_sink": ""}) == set()


def test_negative_a_message_with_no_canary_is_not_a_finding():
    assert _page_fams({"pm_cross_origin": True, "pm_sink": "eval", "pm_executed": True}) == set()


def test_an_origin_check_that_accepted_us_anyway_is_still_reported_and_said_so():
    got = ds.classify_page(URL, {**_PM_OK, "pm_origin_checked": True})
    assert got and "accepted the foreign origin anyway" in got[0]["evidence"]


def test_message_sink_attributes_only_hits_carrying_the_message_canary():
    """A single shared canary would attribute a URL-sourced sink hit to the message source and
    report a postMessage bug on a page whose handler never ran."""
    url_sourced = [{"sink": "eval", "value": "x=" + C}]
    assert ds.message_sink(url_sourced, PM) == ""
    assert ds.message_sink(url_sourced + [{"sink": "innerHTML", "value": PM}], PM) == "innerHTML"


def test_message_sink_prefers_the_most_dangerous_sink():
    hits = [{"sink": "innerHTML", "value": PM}, {"sink": "eval", "value": PM}]
    assert ds.message_sink(hits, PM) == "eval"


# ══════════════════════════════════════════════════════════════════════════════════════════════
# 2. DOCUMENT DOMAIN MANIPULATION
# ══════════════════════════════════════════════════════════════════════════════════════════════

def test_positive_document_domain_written_from_the_canary():
    h = _one({"doc_domain_write": C + ".example.com"})
    assert h["family"] == "document_domain_manipulation"
    assert "document.domain ->" in h["evidence"]


def test_negative_a_legitimate_document_domain_write_is_not_a_finding():
    """THE TRAP: plenty of applications set `document.domain = "example.com"` on every load. The
    setter running is not the bug; the setter running with ATTACKER-CHOSEN input is."""
    assert _fams({"doc_domain_write": "example.com"}) == set()


def test_negative_no_write_at_all():
    assert _fams({"doc_domain_write": ""}) == set()


# ══════════════════════════════════════════════════════════════════════════════════════════════
# 3. WEBSOCKET URL POISONING
# ══════════════════════════════════════════════════════════════════════════════════════════════

def test_negative_the_canary_merely_REACHING_the_socket_url_is_not_control():
    """THIS TEST USED TO ASSERT THE OPPOSITE, and that is the point of keeping it here.

    It read `wss://wpreach/live?room=<canary>` -- the application's OWN socket, with our value in a
    query parameter -- and required a `websocket_url_poisoning` hit whose text reads "the socket
    endpoint is chosen by the payload, not by the application." The endpoint there is chosen by the
    application; only the room name came from us. Any chat page echoing a room id into its socket
    URL was a CWE-918.

    The test did not miss the defect, it REQUIRED it: making the module structural failed this
    test, so the suite would have reported the fix as the regression."""
    assert _fams({"ws_url": "wss://wpreach/live?room=" + C}) == set()


def test_positive_the_canary_is_the_socket_HOST():
    """Control means the authority, which is what decides where the handshake goes."""
    h = _one({"ws_url": "wss://" + C + ".example/live"})
    assert h["family"] == "websocket_url_poisoning"
    assert "OPEN not observed" in h["evidence"]


def test_negative_a_canary_in_the_socket_USERINFO_is_not_control():
    """`wss://user:<canary>@wpreach/live` still connects to wpreach. Userinfo looks like the host
    to a substring test and changes nothing about the destination."""
    assert _fams({"ws_url": "wss://user:" + C + "@wpreach/live"}) == set()


def test_positive_the_socket_reached_the_attacker_host_and_opened():
    h = _one({"ws_url": "wss://evilcab12cd34.example/ws", "ws_opened": True})
    assert h["family"] == "websocket_url_poisoning"
    assert "reached OPEN" in h["evidence"]


def test_negative_the_applications_own_socket_is_not_a_finding():
    """Every page with live updates constructs a WebSocket. Only an attacker-controlled target
    counts."""
    assert _fams({"ws_url": "wss://wpreach/live", "ws_opened": True}) == set()


# ══════════════════════════════════════════════════════════════════════════════════════════════
# 4. FORM ACTION HIJACKING - the module's ONE deliberate `server_reflected` exception
# ══════════════════════════════════════════════════════════════════════════════════════════════

def test_positive_the_form_posts_to_the_attacker_host():
    h = _one({"form_action": EVIL + "/harvest", "form_password": True})
    assert h["family"] == "form_action_hijack"
    assert h["cvss"][1] == 6.1                      # a password field raises it
    assert "credentials" in h["evidence"]


def test_a_form_without_a_password_field_scores_lower():
    h = _one({"form_action": EVIL + "/harvest"})
    assert h["cvss"][1] == 4.7
    assert "every field the victim typed" in h["evidence"]


def test_negative_a_canary_in_the_action_query_string_is_not_hijacking():
    """THE 314-FALSE-POSITIVE SHAPE. WordPress echoes the request URI into its own form and link
    targets, so the canary IS in the action - but the action still points at the application. The
    discriminator is the resolved AUTHORITY, parsed, never a substring."""
    assert _fams({"form_action": "http://wpreach/shop?p=1&lang=" + C}) == set()
    assert _fams({"form_action": "http://wpreach/?next=" + EVIL + "/"}) == set()


def test_negative_a_lookalike_host_does_not_match():
    assert _fams({"form_action": "https://evilcab12cd34.example.attacker-owned.test/x"}) == set()


def test_form_action_hijack_is_NOT_suppressed_by_server_reflection():
    """THE DELIBERATE EXCEPTION, and the reason it is deliberate: gating this on `server_reflected`
    deletes "Form action hijacking (reflected)" - the server echoing `?next=https://evil/` into the
    action attribute so the victim's password is posted to the attacker. The server put it there.
    That IS the bug, and Q-147 asks for the reflected variant by name."""
    assert _fams({"form_action": EVIL + "/harvest", "server_reflected": True}) == {"form_action_hijack"}


def test_form_action_hijack_names_the_mechanism_from_server_reflected():
    """The other half of the exception: never CLAIM a DOM flow for a server echo."""
    srv = _one({"form_action": EVIL + "/h", "server_reflected": True})["evidence"]
    dom = _one({"form_action": EVIL + "/h", "server_reflected": False})["evidence"]
    assert "reflected form action hijacking" in srv and "DOM-based" not in srv
    assert "DOM-based form action hijacking" in dom and "the server reflected it" not in dom


def test_negative_form_action_on_a_page_that_never_loaded():
    """Q-129 still applies to this family even though Q-128 does not."""
    assert _fams({"form_action": EVIL + "/harvest", "navigated": False}) == set()


# ══════════════════════════════════════════════════════════════════════════════════════════════
# 5. HTML5 WEB STORAGE MANIPULATION  /  PERSISTENT DOM XSS VIA WEB STORAGE
# ══════════════════════════════════════════════════════════════════════════════════════════════

_WROTE = {"storage_writes": [{"store": "localStorage", "key": "recentSearch", "value": "q=" + C}]}


def test_positive_the_payload_survives_a_clean_reload():
    h = _one({**_WROTE, "storage_replayed": True})
    assert h["family"] == "dom_storage_manipulation"
    assert "recentSearch" in h["evidence"]


def test_positive_the_stored_payload_executes_on_a_later_load():
    h = _one({**_WROTE, "storage_replayed": True, "storage_replay_executed": True})
    assert h["family"] == "dom_storage_xss"
    assert "every later visit" in h["evidence"]


def test_negative_a_write_that_never_comes_back_is_not_a_finding():
    """Applications write the search term to localStorage all day. Persistence alone is not a bug -
    the value has to come back OUT into the page on a load that carries no payload."""
    assert _fams(_WROTE) == set()


def test_negative_a_write_that_does_not_carry_our_payload():
    assert _fams({"storage_writes": [{"store": "localStorage", "key": "theme", "value": "dark"}],
                  "storage_replayed": True}) == set()


def test_negative_the_server_stored_it_not_the_browser():
    """Q-128 one render later. The replay URL contains no canary at all, so a canary in the REPLAY
    response body means the SERVER stored it. That is server-side stored input, owned by another
    engine; calling it web-storage manipulation is a false claim about the mechanism."""
    assert _fams({**_WROTE, "storage_replayed": True,
                  "storage_replay_server_reflected": True}) == set()


def test_negative_the_replay_render_never_loaded():
    assert _fams({**_WROTE, "storage_replayed": True, "storage_replay_navigated": False}) == set()


def test_an_absent_replay_navigated_flag_is_treated_as_loaded():
    """NON-VACUITY for the replay gate."""
    assert _fams({**_WROTE, "storage_replayed": True}) == {"dom_storage_manipulation"}


def test_execution_is_a_behaviour_and_says_so_when_the_server_also_stored_it():
    """Behaviours are never gated - the browser DID execute. But the mechanism claim has to stay
    honest when there were two possible carriers."""
    h = _one({**_WROTE, "storage_replayed": True, "storage_replay_executed": True,
              "storage_replay_server_reflected": True})
    assert h["family"] == "dom_storage_xss"
    assert "the server stored it too" in h["evidence"]


# ══════════════════════════════════════════════════════════════════════════════════════════════
# 6. AJAX REQUEST HEADER MANIPULATION - and the Referer trap
# ══════════════════════════════════════════════════════════════════════════════════════════════

def test_positive_the_payload_controls_a_request_header_value():
    h = _one({"ajax_headers": [["X-Search-Term", "shoes " + C]]})
    assert h["family"] == "ajax_header_manipulation"
    assert h["cwe"] == "CWE-20" and h["cvss"][1] == 3.1


def test_positive_the_payload_controls_a_request_header_NAME():
    h = _one({"ajax_headers": [["X-" + C, "1"]]})
    assert h["cwe"] == "CWE-113" and h["cvss"][1] == 5.4
    assert "NAME" in h["evidence"]


def test_negative_the_referer_header_carries_the_probe_url_on_every_request():
    """THE TRAP THAT WOULD FIRE ON EVERY PAGE ON THE INTERNET. The browser puts the full requested
    URL - canary included - in `Referer` on every sub-resource request. An unfiltered "canary in a
    header" test reports Ajax header manipulation on any page that loads one image."""
    assert _fams({"ajax_headers": [["Referer", URL + "&lang=" + C]]}) == set()
    assert _fams({"ajax_headers": [["referer", "http://wpreach/?lang=" + C],
                                   ["Origin", "http://" + C + ".x"],
                                   ["Cookie", "sid=" + C],
                                   ["User-Agent", "Mozilla/" + C]]}) == set()


def test_negative_a_header_that_does_not_carry_the_payload():
    assert _fams({"ajax_headers": [["X-Requested-With", "XMLHttpRequest"]]}) == set()


# ══════════════════════════════════════════════════════════════════════════════════════════════
# 7. CLIENT-SIDE HTTP PARAMETER POLLUTION - structural, never a substring
# ══════════════════════════════════════════════════════════════════════════════════════════════

def test_positive_the_marker_became_its_own_query_key():
    h = _one({"hpp_request_urls": ["http://wpreach/api/search?q=shoes&%s=%s" % (ds.HPP_MARKER, C)]})
    assert h["family"] == "client_side_hpp"
    assert ds.HPP_MARKER in h["evidence"]


def test_negative_the_marker_encoded_inside_one_parameters_value():
    """THE SHAPE OF OUR OWN PROBE URL. `set_param` percent-encodes, so the navigation carries
    `%26apolakihpp%3D` INSIDE one value - one parameter, not two. A substring test reports the
    pollution it is testing for on every single probe."""
    encoded = "http://wpreach/api?q=%s%%26%s%%3D%s" % (C, ds.HPP_MARKER, C)
    assert _fams({"hpp_request_urls": [encoded]}) == set()


def test_negative_the_navigation_request_itself_is_never_the_evidence():
    here = dt.set_param(URL, "lang", C)
    assert _fams({"hpp_request_urls": [here]}) == set()


def test_negative_the_marker_key_carrying_someone_elses_value():
    assert _fams({"hpp_request_urls": ["http://wpreach/api?%s=unrelated" % ds.HPP_MARKER]}) == set()


def test_negative_a_request_with_no_pollution():
    assert _fams({"hpp_request_urls": ["http://wpreach/api/search?q=" + C]}) == set()


# ══════════════════════════════════════════════════════════════════════════════════════════════
# 8. CLIENT-SIDE JSON INJECTION - the marker must be a KEY, not a value
# ══════════════════════════════════════════════════════════════════════════════════════════════

def test_positive_the_payload_added_a_top_level_key():
    h = _one({"json_keys": ["q", ds.JSON_MARKER, "page"]})
    assert h["family"] == "client_json_injection"
    assert "top-level KEY" in h["evidence"]


def test_negative_the_payload_is_only_a_value():
    """Ordinary data flow: the app parsed JSON that happens to contain our canary. Nothing broke
    out of anything."""
    assert _fams({"json_keys": ["q", "page", "results"]}) == set()
    assert _fams({"json_keys": []}) == set()


# ══════════════════════════════════════════════════════════════════════════════════════════════
# 9. CLIENT-SIDE XPATH INJECTION - three facts, and any two of them are not injection
# ══════════════════════════════════════════════════════════════════════════════════════════════

_XP = {"xpath_exprs": ["//product[@name='%s']" % C], "xpath_error": True,
       "xpath_baseline_error": False}


def test_positive_the_quote_broke_the_expression_and_the_baseline_did_not():
    h = _one(_XP)
    assert h["family"] == "client_xpath_injection"
    assert "STRUCTURE" in h["evidence"]


def test_negative_the_parameter_reaches_the_expression_but_nothing_broke():
    """Reaching an XPath expression is data flow. Changing its structure is injection."""
    assert _fams({**_XP, "xpath_error": False}) == set()


def test_negative_the_expression_was_already_broken_without_our_quote():
    """Without the baseline control, any page whose own XPath throws is reported as injectable."""
    assert _fams({**_XP, "xpath_baseline_error": True}) == set()


def test_negative_an_error_in_an_expression_that_never_saw_our_payload():
    assert _fams({"xpath_exprs": ["//div[@id='nav']"], "xpath_error": True}) == set()


# ══════════════════════════════════════════════════════════════════════════════════════════════
# 10. DOM-BASED DENIAL OF SERVICE - a repeated differential or nothing
# ══════════════════════════════════════════════════════════════════════════════════════════════

def test_positive_every_probe_render_hung_and_no_baseline_did():
    h = _one({"dos_renders": 3, "dos_hangs": 3, "dos_baseline_hangs": 0})
    assert h["family"] == "client_side_dos"
    assert "3 of 3" in h["evidence"]


def test_negative_a_single_hang_is_a_flaky_container():
    assert _fams({"dos_renders": 1, "dos_hangs": 1, "dos_baseline_hangs": 0}) == set()


def test_negative_an_intermittent_hang_is_not_a_finding():
    assert _fams({"dos_renders": 3, "dos_hangs": 2, "dos_baseline_hangs": 0}) == set()


def test_negative_a_page_that_is_slow_without_the_payload_too():
    """No differential, no finding - the baseline hung as well, so the payload proved nothing."""
    assert _fams({"dos_renders": 3, "dos_hangs": 3, "dos_baseline_hangs": 1}) == set()


# ══════════════════════════════════════════════════════════════════════════════════════════════
# 11. LOCAL FILE PATH MANIPULATION - the module's second GATED-PRESENCE family
# ══════════════════════════════════════════════════════════════════════════════════════════════

_FILE = {"file_urls": ["file:///var/data/" + C + ".json"]}


def test_positive_the_payload_chooses_a_local_file_path():
    h = _one(_FILE)
    assert h["family"] == "local_file_path_manipulation"


def test_negative_a_server_reflected_file_reference_is_gated():
    """Q-128 in full for this family: what is claimed is a CLIENT-SIDE local file reference, so a
    server echo is not evidence of it."""
    assert _fams({**_FILE, "server_reflected": True}) == set()


def test_negative_a_file_reference_on_a_page_that_never_loaded():
    assert _fams({**_FILE, "navigated": False}) == set()


def test_negative_an_ordinary_http_url_is_not_a_local_file_path():
    """Structure carries the claim: the scheme must be `file:`, not merely 'the canary is in an
    href' - which is `dom_trace`'s already-gated dom_link_manipulation, not this."""
    assert _fams({"file_urls": ["http://wpreach/data/" + C + ".json"]}) == set()


def test_an_absent_navigated_flag_is_treated_as_loaded_for_presence_families():
    """NON-VACUITY for Q-129. Every existing caller omits the key; defaulting the other way
    silently disables every gated family in this module."""
    assert _fams(_FILE) == {"local_file_path_manipulation"}


# ══════════════════════════════════════════════════════════════════════════════════════════════
# 12. PATH-RELATIVE STYLE SHEET IMPORT - a three-signal conjunction
# ══════════════════════════════════════════════════════════════════════════════════════════════

_PRSSI = {"prssi_relative_css": "css/app.css", "prssi_path_tolerant": True, "prssi_quirks": True}


def test_positive_all_three_prssi_conditions_hold():
    got = ds.classify_page(URL, _PRSSI)
    assert [h["family"] for h in got] == ["prssi"]
    assert "quirks mode" in got[0]["evidence"]


def test_negative_each_missing_prssi_condition_suppresses():
    """Any one of the three alone is completely ordinary: most pages use relative stylesheet hrefs,
    plenty of servers tolerate extra path segments, and quirks mode by itself is a doctype bug."""
    for drop, value in (("prssi_relative_css", ""), ("prssi_path_tolerant", False),
                        ("prssi_quirks", False)):
        assert _page_fams({**_PRSSI, drop: value}) == set(), drop


def test_negative_an_absolute_stylesheet_href_is_immune():
    assert _page_fams({**_PRSSI, "prssi_relative_css": ""}) == set()


# ══════════════════════════════════════════════════════════════════════════════════════════════
# ORDERING, FINDING SHAPE, AND THE PROOF GATE
# ══════════════════════════════════════════════════════════════════════════════════════════════

def test_hits_come_back_most_severe_first():
    sig = {**_FILE, "ajax_headers": [["X-T", C]], "ws_url": "wss://" + C + ".example/"}
    fams = [h["family"] for h in ds.classify(URL, "lang", C, sig)]
    assert fams[0] == "websocket_url_poisoning"          # 5.4 > 4.3 > 3.1
    assert fams[-1] == "ajax_header_manipulation"


#: One POSITIVE signal set per family, so every family's real output is checked - not a hand-built
#: hit that could drift from what `classify` actually emits.
_POSITIVE = {
    "document_domain_manipulation": ({"doc_domain_write": C + ".example.com"}, False),
    "websocket_url_poisoning": ({"ws_url": "wss://" + C + ".example/live"}, False),
    "client_side_hpp": ({"hpp_request_urls": ["http://wpreach/a?%s=%s" % (ds.HPP_MARKER, C)]}, False),
    "client_json_injection": ({"json_keys": [ds.JSON_MARKER]}, False),
    "client_xpath_injection": (_XP, False),
    "ajax_header_manipulation": ({"ajax_headers": [["X-T", C]]}, False),
    "client_side_dos": ({"dos_renders": 2, "dos_hangs": 2, "dos_baseline_hangs": 0}, False),
    "dom_storage_xss": ({**_WROTE, "storage_replayed": True, "storage_replay_executed": True}, False),
    "dom_storage_manipulation": ({**_WROTE, "storage_replayed": True}, False),
    "local_file_path_manipulation": (_FILE, False),
    "form_action_hijack": ({"form_action": EVIL + "/h", "form_password": True}, False),
    "web_message_xss": ({**_PM_OK, "pm_executed": True}, True),
    "web_message_manipulation": (_PM_OK, True),
    "prssi": (_PRSSI, True),
}


def _findings():
    out = {}
    for fam, (sig, page) in _POSITIVE.items():
        hits = ds.classify_page(URL, sig) if page else ds.classify(URL, "lang", C, sig)
        match = [h for h in hits if h["family"] == fam]
        assert match, "%s produced no hit from its own positive signal set: %s" % (
            fam, [h["family"] for h in hits])
        out[fam] = ds.finding(match[0])
    return out


def test_every_family_has_a_positive_case_and_none_is_missing():
    """A family in the tables with no positive case is a family nobody proved can fire."""
    assert set(_POSITIVE) == set(ds._CVSS) == set(ds._CWE) == set(ds._TITLE) == set(ds._IMPACT)


def test_every_finding_is_well_formed():
    for fam, f in _findings().items():
        assert f["family"] == fam
        assert f["confidence"] == "confirmed", fam
        assert f["title"] and f["target"] and f["evidence"], fam
        assert f["cwe"].startswith("CWE-"), fam
        assert f["cvss_vector"].startswith("CVSS:3.1/") and f["cvss_score"], fam
        assert f["severity"] in ("low", "medium", "high"), fam
        assert len(f["reproduction_steps"]) >= 2, fam
        assert f["impact"], fam
        assert fam in f["tags"], fam


def test_every_finding_passes_the_proof_gate():
    """`proof_schema.validate_confirmed` is what demotes a confirmed finding that cannot back its
    claim. A family that only passes because nobody ran the gate on it is a future demotion."""
    for fam, f in _findings().items():
        ok, missing = ps.validate_confirmed(f)
        assert ok, "%s: %s" % (fam, missing)


def test_every_finding_counts_as_proof_for_the_benchmark():
    for fam, f in _findings().items():
        assert bb._has_proof(f), fam


def test_the_severity_of_a_score_is_one_rule():
    assert ds.severity_of(7.0) == "high"
    assert ds.severity_of(6.9) == "medium" and ds.severity_of(4.0) == "medium"
    assert ds.severity_of(3.9) == "low" and ds.severity_of(None) == "low"


def test_cvss_vectors_and_scores_are_paired_consistently():
    """Same vector must never carry two different numbers anywhere in the tables."""
    seen = {}
    for fam, (vec, score) in ds._CVSS.items():
        assert seen.setdefault(vec, score) == score, fam


# ══════════════════════════════════════════════════════════════════════════════════════════════
# THE PURE HELPERS - they must be TOTAL, because there is no exception handler behind them
# ══════════════════════════════════════════════════════════════════════════════════════════════

def test_host_of_is_total_and_parses_the_authority():
    assert ds._host_of("https://EVIL.example:8443/a?b#c") == "evil.example"
    assert ds._host_of("http://user:pw@host.test/x") == "host.test"
    assert ds._host_of("http://[::1]:80/x") == "[::1]"
    for junk in ("", None, "not a url", "://", "javascript:alert(1)", "//x", 7):
        ds._host_of(junk)


def test_scheme_of_is_total():
    assert ds._scheme_of("file:///etc/passwd") == "file"
    assert ds._scheme_of("HTTPS://x/") == "https"
    assert ds._scheme_of("/relative/path") == ""
    for junk in ("", None, ":x", "a b:c", 7):
        ds._scheme_of(junk)


def test_query_pairs_does_not_unquote():
    """The whole point: a percent-encoded separator inside a value stays one parameter."""
    assert ds._query_pairs("http://x/?a=1&b=2") == [("a", "1"), ("b", "2")]
    assert ds._query_pairs("http://x/?a=1%26b%3D2") == [("a", "1%26b%3D2")]
    assert ds._query_pairs("http://x/#frag") == []
    for junk in ("", None, "?", "http://x/?&&", 7):
        ds._query_pairs(junk)


def test_the_js_collectors_are_present_and_shaped_for_their_call_sites():
    """`dom_trace.DOM_SCAN_JS` was once referenced by a call site while missing from the module, and
    a bare `except` swallowed the AttributeError on EVERY render - three families collected nothing
    and looked present. Assert the constants exist and are the right SHAPE for how they are used:
    the hooks are an init script (a statement), the scan is an arrow function taking the canary."""
    assert ds.DOM_SINK_HOOKS_JS.strip().startswith("(() =>")
    assert "__apolaki_sinks" in ds.DOM_SINK_HOOKS_JS
    assert ds.DOM_SINK_SCAN_JS.strip().startswith("(c) =>")
    for key in ("doc_domain_write", "ws_url", "form_action", "file_urls", "prssi_quirks",
                "storage_writes", "json_keys", "xpath_exprs", "sink_hits"):
        assert key in ds.DOM_SINK_SCAN_JS, key

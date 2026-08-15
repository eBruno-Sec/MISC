"""Q-002 -- Cross-Site WebSocket Hijacking oracle (agent/ws_tool.py).

The tests that matter here are the ones that try to make the oracle WRONG:

  * a 101 with a wrong / missing / echoed accept must not count as an upgrade,
  * a public socket (control receives the same marker) must not be confirmed,
  * a socket with no authenticated data must be a lead, never a finding,
  * a token-only session must not be confirmed however permissive the handshake,
  * every confirmed finding must carry a control artifact `proof_schema` can actually read.

`test_juice_shop_measured_capture_is_a_lead_not_a_finding` replays bytes captured from the live
lab (docs/handoff/realtime.md section 2). It is the regression that stops this engine flagging
every socket.io deployment as vulnerable.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ws_tool as wst
import proof_schema


# -- RFC 6455 accept ----------------------------------------------------------------------------

def test_accept_matches_the_rfc6455_published_vector():
    """RFC 6455 section 1.3 states this exact pair. If our hash is wrong, every handshake we ever
    verify is wrong, and the engine would silently reject real upgrades."""
    assert wst.accept_for("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="


def test_new_key_is_16_random_bytes_and_never_repeats():
    import base64
    k1, k2 = wst.new_key(), wst.new_key()
    assert len(base64.b64decode(k1)) == 16
    assert k1 != k2                        # a fixed key would let a replayed response pass forever


def _head(status="101 Switching Protocols", accept=None, upgrade="websocket", key=None):
    lines = ["HTTP/1.1 " + status]
    if upgrade:
        lines.append("Upgrade: " + upgrade)
        lines.append("Connection: Upgrade")
    if accept is None and key is not None:
        accept = wst.accept_for(key)
    if accept:
        lines.append("Sec-WebSocket-Accept: " + accept)
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def test_handshake_accepted_on_a_correct_upgrade():
    key = wst.new_key()
    assert wst.handshake_accepted(wst.parse_handshake(_head(key=key)), key) is True


def test_a_101_with_a_wrong_accept_is_rejected():
    """THE central guard. A proxy, a captive portal or a catch-all route can answer 101; only the
    derived accept proves the server actually spoke WebSocket to OUR key."""
    key = wst.new_key()
    parsed = wst.parse_handshake(_head(accept=wst.accept_for("some-other-key")))
    assert parsed["status"] == 101                       # it really is a 101 ...
    assert wst.handshake_accepted(parsed, key) is False  # ... and it is still not an upgrade


def test_a_101_with_no_accept_header_is_rejected():
    key = wst.new_key()
    assert wst.handshake_accepted(wst.parse_handshake(_head(accept="")), key) is False


def test_a_101_that_echoes_our_key_verbatim_is_rejected():
    """A lazy mock (or a hostile server) that echoes the key instead of hashing it must fail."""
    key = wst.new_key()
    assert wst.handshake_accepted(wst.parse_handshake(_head(accept=key)), key) is False


def test_a_correct_accept_without_the_upgrade_header_is_rejected():
    key = wst.new_key()
    parsed = wst.parse_handshake(_head(key=key, upgrade=""))
    assert wst.handshake_accepted(parsed, key) is False


def test_non_101_status_with_a_valid_accept_is_rejected():
    key = wst.new_key()
    parsed = wst.parse_handshake(_head(status="200 OK", key=key))
    assert wst.handshake_accepted(parsed, key) is False


def test_empty_key_never_passes():
    """Empty is a real input: with no key we sent, there is nothing to verify against."""
    assert wst.handshake_accepted(wst.parse_handshake(_head(accept="")), "") is False
    assert wst.handshake_accepted(wst.parse_handshake(_head(accept=wst.accept_for(""))), "") is False


def test_parse_handshake_survives_garbage():
    for junk in (b"", b"not http at all", b"\x00\x01\x02", "HTTP/1.1 abc\r\n\r\n"):
        p = wst.parse_handshake(junk)
        assert isinstance(p, dict) and p["status"] in (0,)


# -- framing ------------------------------------------------------------------------------------

def _frame(payload: bytes, opcode=0x1, mask=None):
    body = payload
    header = bytes([0x80 | opcode])
    n = len(body)
    mbit = 0x80 if mask else 0
    if n < 126:
        header += bytes([mbit | n])
    elif n < 65536:
        header += bytes([mbit | 126]) + n.to_bytes(2, "big")
    else:
        header += bytes([mbit | 127]) + n.to_bytes(8, "big")
    if mask:
        header += mask
        body = bytes(b ^ mask[i % 4] for i, b in enumerate(body))
    return header + body


def test_decode_single_text_frame():
    f = wst.decode_frames(_frame(b'{"user":"alice@corp.example"}'))
    assert len(f) == 1 and f[0]["opcode"] == wst.OPCODE_TEXT
    assert f[0]["text"] == '{"user":"alice@corp.example"}'


def test_decode_extended_length_frames():
    for n in (200, 70000):
        payload = b"x" * n
        f = wst.decode_frames(_frame(payload))
        assert len(f) == 1 and f[0]["length"] == n


def test_decode_honours_a_mask_bit_even_though_servers_must_not_set_it():
    """A non-conforming server that masks would otherwise hand back scrambled bytes that fail every
    marker match -- an invisible false negative."""
    f = wst.decode_frames(_frame(b"alice@corp.example", mask=b"\x01\x02\x03\x04"))
    assert f[0]["text"] == "alice@corp.example"


def test_decode_stops_cleanly_on_a_truncated_frame():
    good = _frame(b"complete")
    truncated = _frame(b"this payload never arrives")[:6]
    f = wst.decode_frames(good + truncated)
    assert len(f) == 1 and f[0]["text"] == "complete"


def test_decode_is_bounded():
    many = b"".join(_frame(b"spam") for _ in range(200))
    assert len(wst.decode_frames(many, limit=8)) == 8


def test_frames_text_excludes_control_frames():
    """A close frame's reason string must never be mistaken for pushed application data."""
    buf = _frame(b"alice@corp.example", opcode=wst.OPCODE_CLOSE) + _frame(b"public")
    assert "alice@corp.example" not in wst.frames_text(wst.decode_frames(buf))
    assert "public" in wst.frames_text(wst.decode_frames(buf))


# -- discovery ----------------------------------------------------------------------------------

def test_discover_ws_literals_and_relative_constructor():
    html = """<script>
      var a = new WebSocket("wss://chat.example.com/socket");
      var b = new WebSocket('/live/feed');
    </script>"""
    urls = wst.discover_ws_urls(html, "https://app.example.com/dash")
    assert "wss://chat.example.com/socket" in urls
    assert "wss://app.example.com/live/feed" in urls


def test_discovery_on_empty_content_yields_nothing():
    """Empty is a real input -- it must produce no endpoints, not a guessed default."""
    assert wst.discover_ws_urls("", "https://app.example.com/") == []
    assert wst.discover_ws_urls("<html></html>", "") == []


def test_split_ws_url_keeps_a_stated_port_and_the_query():
    assert wst.split_ws_url("ws://host:3000/socket.io/?EIO=4&transport=websocket") == (
        "host", 3000, "/socket.io/?EIO=4&transport=websocket")
    assert wst.split_ws_url("wss://host/ws")[1] == 443
    assert wst.split_ws_url("ws://host/ws")[1] == 80


def test_http_origin_of_maps_scheme_correctly():
    assert wst.http_origin_of("wss://a.example/x") == "https://a.example"
    assert wst.http_origin_of("ws://a.example:3000/x") == "http://a.example:3000"


# -- the oracle ---------------------------------------------------------------------------------

MARK = ["alice@corp.example"]


def _side(accepted, payload=b""):
    return {"accepted": accepted, "frames": wst.decode_frames(_frame(payload)) if payload else []}


def test_confirmed_requires_all_four_halves():
    v = wst.evaluate(_side(True, b'{"inbox":3,"user":"alice@corp.example"}'),
                     _side(True, b'{"error":"unauthorized"}'), MARK, had_cookie=True)
    assert v["verdict"] == wst.CONFIRMED
    assert v["marker"] == "alice@corp.example"


def test_no_upgrade_is_clean():
    v = wst.evaluate(_side(False), _side(False), MARK, had_cookie=True)
    assert v["verdict"] == wst.CLEAN


def test_upgrade_without_authenticated_data_is_a_lead_not_a_finding():
    """(a) alone is NOT a vulnerability -- the ticket's central rule."""
    v = wst.evaluate(_side(True, b'{"type":"hello"}'), _side(True, b'{"type":"hello"}'),
                     MARK, had_cookie=True)
    assert v["verdict"] == wst.LEAD


def test_a_public_socket_is_clean_because_the_control_got_the_same_marker():
    """The FP guard: if the cookie-stripped control receives the marker, the data is public."""
    v = wst.evaluate(_side(True, b'{"user":"alice@corp.example"}'),
                     _side(True, b'{"user":"alice@corp.example"}'), MARK, had_cookie=True)
    assert v["verdict"] == wst.CLEAN
    assert "PUBLIC" in v["reason"]


def test_no_markers_available_is_a_lead_never_a_confirm_and_never_a_silent_clean():
    """An empty marker list is a real input: half (b) is UNTESTED, not failed."""
    for markers in (None, [], [""], ["ab"]):     # "ab" is under the 4-char floor
        v = wst.evaluate(_side(True, b'{"user":"alice@corp.example"}'),
                         _side(True, b""), markers, had_cookie=True)
        assert v["verdict"] == wst.LEAD, markers


def test_a_bearer_only_session_is_a_lead_not_a_confirm():
    """A browser does not attach Authorization to a cross-origin WebSocket, so a token-only session
    is not hijackable however permissive the handshake. Measured need: Juice Shop issues no cookie."""
    v = wst.evaluate(_side(True, b'{"user":"alice@corp.example"}'),
                     _side(True, b'{"error":"unauthorized"}'), MARK, had_cookie=False)
    assert v["verdict"] == wst.LEAD
    assert "not a cookie" in v["reason"]


def test_control_that_fails_to_upgrade_still_confirms():
    """A server that refuses the upgrade entirely without a cookie is the strongest control there is."""
    v = wst.evaluate(_side(True, b'{"user":"alice@corp.example"}'), _side(False),
                     MARK, had_cookie=True)
    assert v["verdict"] == wst.CONFIRMED


def test_short_markers_cannot_manufacture_a_confirm():
    v = wst.evaluate(_side(True, b'{"a":1}'), _side(True, b""), ["a"], had_cookie=True)
    assert v["verdict"] == wst.LEAD


def test_evaluate_tolerates_non_dict_input():
    assert wst.evaluate(None, None, MARK, had_cookie=True)["verdict"] == wst.CLEAN


# -- the measured live-lab capture --------------------------------------------------------------

# Captured from apolaki-juice-shop-bench-1 on network apolaki_default (docs/handoff/realtime.md
# section 2). The endpoint upgrades from Origin: http://evil.example WITH and WITHOUT credentials,
# and pushes the same public Engine.IO handshake frame either way.
JUICE_FRAME = (b'0{"sid":"fOcfpqZA9zEc6crMAAAA","upgrades":[],'
               b'"pingInterval":25000,"pingTimeout":5000}')
JUICE_CONTROL_FRAME = (b'0{"sid":"s3UsPOoUjURjjUUYAAAB","upgrades":[],'
                       b'"pingInterval":25000,"pingTimeout":5000}')


def test_juice_shop_measured_capture_is_a_lead_not_a_finding():
    """The regression that stops this engine flagging every socket.io deployment as vulnerable."""
    v = wst.evaluate(_side(True, JUICE_FRAME), _side(True, JUICE_CONTROL_FRAME),
                     ["admin@juice-sh.op"], had_cookie=False)
    assert v["verdict"] == wst.LEAD
    assert v["accepted"] is True                     # half (a) really did hold
    assert v["marker"] == ""                         # half (b) did not


def test_the_juice_shop_sid_is_never_mistaken_for_an_identity_marker():
    """A per-connection nonce trivially passes the control test -- the control CANNOT echo a token
    minted for the authed connection. Without `identity_markers` this exact input manufactures a
    confirmed CSWSH on a completely public endpoint. Measured sids, both real."""
    v = wst.evaluate(_side(True, JUICE_FRAME), _side(True, JUICE_CONTROL_FRAME),
                     ["fOcfpqZA9zEc6crMAAAA"], had_cookie=True)
    assert v["verdict"] == wst.LEAD
    assert v["marker"] == ""


def test_identity_markers_rejects_nonce_shapes():
    for nonce in ("fOcfpqZA9zEc6crMAAAA", "s3UsPOoUjURjjUUYAAAB",
                  "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9",
                  "a1B2c3D4e5F6g7H8i9J0"):
        assert wst.identity_markers([nonce]) == [], nonce


def test_identity_markers_keeps_real_identities():
    """THE NEGATIVE CONTROL for the filter. If it ate real identities it would silently disable the
    confirm path on every target and the engine would report clean forever."""
    real = ["alice@corp.example", "admin@juice-sh.op", "administrator", "alice1234",
            "AliceSmith2024", "bob.jones@a.io", "j_smith", "user-42"]
    assert wst.identity_markers(real) == real


def test_identity_markers_drops_short_and_blank_values():
    assert wst.identity_markers(["", "  ", "ab", "a", None]) == []


def test_identity_markers_dedupes_and_preserves_order():
    assert wst.identity_markers(["alice", "bob", "carol", "alice"]) == ["alice", "carol"]


# -- findings carry a control artifact -----------------------------------------------------------

def test_confirmed_finding_carries_a_control_proof_schema_can_read():
    """626 of 660 stored findings once printed a control claim that never ran. This engine's
    finding must carry the artifact, not the sentence."""
    v = wst.evaluate(_side(True, b'{"user":"alice@corp.example"}'), _side(False),
                     MARK, had_cookie=True)
    f = wst.cswsh_finding("ws://app.example/ws", v, wst.EVIL_ORIGIN,
                          "was refused (no upgrade)", marker_source="verified login")
    assert proof_schema.control_status(f) == proof_schema.CONTROL_RECORDED
    assert f["confidence"] == "confirmed" and f["cwe"] == "CWE-1385"
    assert f["negative_controls"][0]["result"] == "was refused (no upgrade)"


def test_lead_finding_is_a_lead_and_also_carries_its_control():
    v = wst.evaluate(_side(True, JUICE_FRAME), _side(True, JUICE_CONTROL_FRAME), [], had_cookie=False)
    f = wst.upgrade_lead("ws://app.example/ws", v, wst.EVIL_ORIGIN, "also upgraded")
    assert f["confidence"] == "lead" and f["severity"] == "info"
    assert proof_schema.control_status(f) == proof_schema.CONTROL_RECORDED


def test_finding_binds_the_marker_as_a_field_not_only_in_prose():
    """Bind the value, do not parse it back out of a rendered sentence."""
    v = wst.evaluate(_side(True, b'{"user":"alice@corp.example"}'), _side(False), MARK, had_cookie=True)
    assert v["marker"] == "alice@corp.example"
    assert v["authed_frame"].startswith('{"user"')


def test_cvss_vector_and_score_agree_within_the_report_honesty_tolerance():
    import cvss4
    f = wst.cswsh_finding("ws://a/ws", {"marker": "m", "authed_frame": ""}, wst.EVIL_ORIGIN, "x")
    assert f["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"
    assert abs(f["cvss_score"] - 6.5) < 0.01
    del cvss4                                   # imported only to assert the module is available


def test_build_handshake_omits_empty_headers_and_keeps_the_query():
    raw = wst.build_handshake("h", "/socket.io/?EIO=4", "KEY", origin="", cookie="",
                              port=3000).decode()
    assert "GET /socket.io/?EIO=4 HTTP/1.1" in raw
    assert "Host: h:3000" in raw
    assert "Origin:" not in raw and "Cookie:" not in raw
    assert "Sec-WebSocket-Key: KEY" in raw and "Sec-WebSocket-Version: 13" in raw


def test_build_handshake_includes_origin_and_cookie_when_given():
    raw = wst.build_handshake("h", "/ws", "K", origin="http://evil.test",
                              cookie="sid=abc").decode()
    assert "Origin: http://evil.test" in raw and "Cookie: sid=abc" in raw
    assert raw.endswith("\r\n\r\n")

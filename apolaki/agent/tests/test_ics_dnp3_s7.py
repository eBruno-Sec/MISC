"""#107 DNP3 + S7comm read-only engines. The safety rail is the point: these frames reach equipment
that moves physical things, so 'no write is constructible' is asserted, not assumed."""
import ics_dnp3_s7 as ics


# ── the safety rail ───────────────────────────────────────────────────────────
def test_no_builder_in_this_module_can_produce_a_write_frame():
    """The load-bearing test. Every frame this module can emit must pass is_write_frame as read-only."""
    frames = [
        ("dnp3", ics.dnp3_request_link_status()),
        ("dnp3", ics.dnp3_request_link_status(dest=7, src=100)),
        ("s7comm", ics.cotp_connection_request()),
        ("s7comm", ics.s7_setup_communication()),
        ("s7comm", ics.s7_read_szl()),
        ("s7comm", ics.s7_read_szl(szl_id=0x001C)),
    ]
    for proto, f in frames:
        assert ics.is_read_only(proto, f), "%s builder produced a frame classified as a write" % proto


def test_the_rail_is_strict_by_default():
    """An unrecognised frame must be REFUSED, not waved through — the failure mode has to be safe."""
    assert ics.is_write_frame("dnp3", b"\x00\x01\x02") is True
    assert ics.is_write_frame("s7comm", b"garbage") is True
    assert ics.is_write_frame("modbus", b"\x00" * 12) is True        # unknown protocol -> refuse
    assert ics.is_write_frame("dnp3", b"") is False                  # nothing to send is not a write


def test_dnp3_frames_carrying_an_application_layer_are_refused():
    """A link frame with user data could operate a point; only the bare status request is allowed."""
    ok = bytearray(ics.dnp3_request_link_status())
    ok[2] = 20                       # length now implies an application layer
    assert ics.is_write_frame("dnp3", bytes(ok)) is True


def test_dnp3_reset_link_states_is_classified_as_a_write():
    f = bytearray(ics.dnp3_request_link_status())
    f[3] = 0xC0 | 0            # RESET_LINK_STATES
    assert ics.is_write_frame("dnp3", bytes(f)) is True


def test_the_rail_actually_catches_a_real_write_frame():
    """Without this the rail could be vacuously true. Hand-build the frames this module refuses to build
    — S7 Write Var and S7 PLC Stop — and require the classifier to name them writes."""
    import struct

    def s7_job(func_byte):
        param = bytes([func_byte]) + b"\x00" * 7
        header = struct.pack(">BBHHHH", 0x32, 0x01, 0x0000, 0x0300, len(param), 0x0000)
        return ics.cotp_data(header + param)

    for func, name in ((0x05, "Write Var"), (0x29, "PLC Stop"), (0x28, "PLC Control"),
                       (0x1A, "Request download")):
        assert ics.is_write_frame("s7comm", s7_job(func)) is True, name
    # and a genuine read function on the same structure is allowed
    assert ics.is_write_frame("s7comm", s7_job(0x04)) is False      # Read Var


def test_the_write_catalogues_name_the_dangerous_operations():
    assert ics.DNP3_APP_WRITE_FCS[0x04] == "OPERATE"
    assert ics.DNP3_APP_WRITE_FCS[0x0D] == "COLD_RESTART"
    assert ics.S7_WRITE_FUNCS[0x29] == "PLC Stop"
    assert 0x05 in ics.S7_WRITE_FUNCS          # Write Var must never be a read func
    assert 0x05 not in ics.S7_READ_FUNCS


# ── DNP3 ──────────────────────────────────────────────────────────────────────
def test_dnp3_crc_bitwise_and_table_implementations_agree():
    """Verifying the CRC without trusting a memorised vector: two independent implementations of the
    IEEE 1815 parameters must produce identical output over varied input."""
    for data in (b"", b"\x05\x64\x05\xc9\x01\x00\x00\x04", bytes(range(64)), b"\xff" * 33):
        assert ics.dnp3_crc(data) == ics._dnp3_crc_table(data), data


def test_dnp3_request_link_status_shape():
    f = ics.dnp3_request_link_status(dest=4, src=1)
    assert f[:2] == b"\x05\x64"
    assert f[2] == 5                       # no application layer
    assert f[3] & 0x0F == ics.DNP3_LINK_REQUEST_LINK_STATUS
    assert f[3] & 0x40                     # PRM=1 (primary)
    assert len(f) == 10
    import struct
    assert struct.unpack("<H", f[4:6])[0] == 4 and struct.unpack("<H", f[6:8])[0] == 1


def test_dnp3_frame_round_trips_through_the_parser():
    f = ics.dnp3_request_link_status(dest=10, src=20)
    p = ics.parse_dnp3_link(f)
    assert p["valid"] and p["crc_ok"] and p["dest"] == 10 and p["src"] == 20
    assert p["has_application_layer"] is False


def test_parse_dnp3_rejects_junk_and_detects_a_link_status_reply():
    assert ics.parse_dnp3_link(b"nope")["valid"] is False
    reply = bytearray(ics.dnp3_request_link_status(dest=1, src=9))
    reply[3] = 0x0B                                  # link status (function 11)
    import struct
    reply[8:10] = struct.pack("<H", ics.dnp3_crc(bytes(reply[:8])))
    p = ics.parse_dnp3_link(bytes(reply))
    assert p["is_link_status"] is True and p["crc_ok"] is True and p["src"] == 9


def test_a_corrupted_dnp3_frame_fails_the_crc_check():
    f = bytearray(ics.dnp3_request_link_status())
    f[6] ^= 0xFF
    assert ics.parse_dnp3_link(bytes(f))["crc_ok"] is False


# ── S7comm ────────────────────────────────────────────────────────────────────
def test_tpkt_length_is_the_whole_packet():
    p = ics.tpkt(b"abcd")
    assert p[0] == 0x03 and len(p) == 8
    import struct
    assert struct.unpack(">H", p[2:4])[0] == len(p)


def test_cotp_connection_request_is_a_cr_with_both_tsaps():
    f = ics.cotp_connection_request()
    assert f[0] == 0x03 and f[5] == 0xe0            # TPKT then COTP CR
    assert b"\xc1\x02" in f and b"\xc2\x02" in f


def test_s7_frames_are_wrapped_in_cotp_data_and_carry_an_s7_header():
    for f in (ics.s7_setup_communication(), ics.s7_read_szl()):
        assert f[4:7] == b"\x02\xf0\x80"            # COTP DT
        assert b"\x32" in f                          # S7 protocol id


def test_s7_read_szl_asks_for_module_identification_by_default():
    f = ics.s7_read_szl()
    assert b"\x00\x11" in f                          # SZL-ID 0x0011


def test_parse_s7_szl_extracts_a_siemens_order_number():
    resp = b"\x03\x00\x00\x40\x02\xf0\x80\x32\x07\x00\x00" + b"\x00" * 8 + \
           b"6ES7 212-1AE40-0XB0 \x00\x00CPU 1212C DC/DC/DC\x00"
    p = ics.parse_s7_szl(resp)
    assert p["valid"] and p["module"].startswith("6ES7")
    assert any("CPU" in s for s in p["strings"])


def test_parse_s7_szl_is_defensive():
    assert ics.parse_s7_szl(b"")["valid"] is False
    assert ics.parse_s7_szl(b"\x00\x01\x02")["valid"] is False


# ── findings ──────────────────────────────────────────────────────────────────
def test_finding_states_that_apolaki_never_sends_control_frames():
    f = ics.finding("s7comm", "10.0.0.5", 102, {"module": "6ES7 212-1AE40-0XB0"})
    assert f["family"] == "ics_ot" and f["cwe"] == "CWE-306" and f["severity"] == "high"
    assert "never send a control or write frame" in f["impact"]
    assert "6ES7" in f["evidence"]


def test_dnp3_finding_uses_the_device_address_as_identity():
    f = ics.finding("dnp3", "10.0.0.9", 20000, {"src": 1024})
    assert "1024" in f["description"]


def test_ics_findings_satisfy_the_proof_contract():
    import proof_schema
    for f in (ics.finding("dnp3", "h", 20000, {"src": 3}),
              ics.finding("s7comm", "h", 102, {"module": "6ES7 x"})):
        ok, missing = proof_schema.validate_confirmed(f)
        assert ok, (f["title"], missing)

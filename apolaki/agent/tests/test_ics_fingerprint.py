"""ICS/OT read-only fingerprint (#107): protocol id, READ-ONLY frame safety self-check, identity parsers."""
import struct

import ics_fingerprint as I


def test_protocol_identification():
    assert I.identify_protocol(502) == "modbus"
    assert I.identify_protocol(44818) == "ethernetip"
    assert I.identify_protocol(0, "Siemens S7-1200") == "s7comm"
    assert I.identify_protocol(0, "Rockwell EtherNet/IP") == "ethernetip"
    assert I.identify_protocol(9999, "nginx") == ""


def test_builders_are_read_only_SAFETY():
    # the load-bearing safety rail: every frame this engine emits must be read-only
    mb = I.modbus_read_device_id()
    enip = I.ethernetip_list_identity()
    assert I.is_write_frame("modbus", mb) is False and I.is_read_only("modbus", mb)
    assert I.is_write_frame("ethernetip", enip) is False and I.is_read_only("ethernetip", enip)
    # the Modbus frame carries the Read-Device-ID function (0x2B), never a write function code
    assert mb[7] == 0x2B and mb[7] not in I._MODBUS_WRITE_FCS
    # and the engine correctly RECOGNISES a write frame as unsafe (so a driver can refuse it)
    write_coil = mb[:7] + bytes([0x05]) + mb[8:]        # swap in Write-Single-Coil (0x05)
    assert I.is_write_frame("modbus", write_coil) is True
    # EtherNet/IP: ListIdentity(0x63) is read-only; a SendRRData(0x6F) frame is flagged write
    assert I.is_write_frame("ethernetip", struct.pack("<H", 0x006F) + enip[2:]) is True


def test_modbus_read_device_id_frame_shape():
    mb = I.modbus_read_device_id(unit=1, transaction=7)
    txid, pid, length, unit = struct.unpack(">HHHB", mb[:7])
    assert txid == 7 and pid == 0 and unit == 1 and length == 5
    assert mb[7:] == bytes([0x2B, 0x0E, 0x01, 0x00])


def test_parse_modbus_device_id():
    # craft a valid Read-Device-ID response: MBAP + 0x2B 0x0E ... 2 objects (vendor, product_name)
    objs = bytes([0x00, 0x05]) + b"Acme\x00"[:5]        # obj 0 vendor "Acme\x00"
    objs += bytes([0x04, 0x03]) + b"PLC"                # obj 4 product_name "PLC"
    pdu = bytes([0x2B, 0x0E, 0x01, 0x81, 0x00, 0x00, 0x02]) + objs
    resp = struct.pack(">HHHB", 1, 0, len(pdu) + 1, 0) + pdu
    ident = I.parse_modbus_device_id(resp)
    assert ident.get("vendor", "").startswith("Acme") and ident.get("product_name") == "PLC"


def test_parse_ethernetip_identity():
    # minimal List Identity response: 24B header + CPF(count,type,len) + identity fields
    header = b"\x00" * 24
    body = struct.pack("<H", 1)                          # item count
    body += struct.pack("<H", 0x000C) + struct.pack("<H", 0)   # item type + len
    body += struct.pack("<H", 1)                         # encap protocol version
    body += b"\x00" * 16                                 # socket addr
    body += struct.pack("<H", 0x004D)                    # vendor id (77 = Rockwell)
    body += struct.pack("<H", 0x000C)                    # device type
    body += struct.pack("<H", 0x0036)                    # product code
    body += struct.pack("<H", 0x0101)                    # revision
    body += struct.pack("<H", 0)                         # status
    body += struct.pack("<I", 0xDEADBEEF)               # serial
    name = b"1756-L61/B LOGIX5561"
    body += bytes([len(name)]) + name
    ident = I.parse_ethernetip_identity(header + body)
    assert ident["vendor_id"] == 0x004D and ident["serial"] == 0xDEADBEEF
    assert ident["product_name"] == "1756-L61/B LOGIX5561"


def test_finding_is_readonly_exposure():
    f = I.finding("modbus", "10.0.0.5", 502, {"vendor": "Acme", "product_name": "PLC"})
    assert f["family"] == "ics_ot" and f["confidence"] == "confirmed" and f["cwe"] == "CWE-306"
    assert "read-only" in f["safety_note"].lower() and "read-only" in f["tags"]
    assert isinstance(f["reproduction_steps"], list)

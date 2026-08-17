"""Q-055 — `run_metadata` reported CLEAN on a file proven to leak GPS.

THE DEFECT, MEASURED on 2026-08-16 inside the shipped `apolaki-agent` image against the live lab:

    exiftool on PATH: None
    status=200 bytes=107952 jpeg=True
    b'GPS' in data      : False   <-- the fallback's ONLY JPEG branch
    IFD0 tags: [... '0x8769', '0x8825']   GPS IFD pointer 0x8825 present: True
    extract_metadata(): {}
    run_metadata -> output='No sensitive metadata (native)' findings=0

TWO INDEPENDENT CAUSES COMPOSED, and fixing either alone left it broken:

  1. `exiftool` was absent from the image, so `shutil.which("exiftool")` was always false and the
     engine ALWAYS took the native fallback. Fixed in `agent/Dockerfile` (+67.2 MB measured).
  2. The native fallback's only JPEG branch matched the ASCII substring `b"GPS"`, which real binary
     EXIF never contains. Fixed by `upload_tool.read_exif`, a real APP1/TIFF IFD parser.

THE NEGATIVE CONTROL MATTERS AS MUCH AS THE POSITIVE. The engine scored 0 false positives on 14
negative controls before this change; re-measured after it on 17 (the documented 14 plus three more
uploaded images), still 0 — see `docs/handoff/truthful.md`.

LAB-GATED ON PURPOSE, following `tests/test_island_soundness.py`: the only honest fixture for the
positive case is the file the target actually serves, and this lane will not invent a JPEG carrying
GPS. A SKIP here is an ABSENT measurement and is never evidence of a pass. The parser-robustness
tests below are lab-independent and DO construct byte strings — legitimately, because the property
under test is "malformed input must not raise", and malformed input is not copied from anywhere.
"""
from __future__ import annotations

import asyncio
import re
import struct
import urllib.parse

import pytest

import tools
import upload_tool
from scope import ScopeEngine

JUICE = "http://juice-shop:3000"
GEO_PHOTO = "/assets/public/images/uploads/magn(et)ificent!-1571814229653.jpg"
CLEAN_PHOTOS = ["/assets/public/images/products/apple_juice.jpg",
                "/assets/public/images/products/fan_hoodie.jpg",
                "/assets/public/images/products/holo_sticker.png",
                "/assets/public/images/products/carrot_juice.jpeg"]


def _fetch(path: str) -> bytes:
    import httpx
    url = JUICE + "/" + urllib.parse.quote(path.lstrip("/"), safe="/%")
    try:
        r = httpx.get(url, timeout=10, follow_redirects=True)
    except Exception as e:
        pytest.skip("juice-shop lab unreachable (%s); no measurement, not a pass" % e)
    if r.status_code != 200:
        pytest.skip("juice-shop served HTTP %s for %s; no measurement" % (r.status_code, path))
    return r.content


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _reg():
    sc = ScopeEngine()
    sc.load_manual(["juice-shop:3000"], [], "truthful-metadata")
    return tools.ToolRegistry(sc, lab_mode=True)


def _url(path: str) -> str:
    return JUICE + "/" + urllib.parse.quote(path.lstrip("/"), safe="/%")


# ---------------------------------------------------------------------------------------------
# POSITIVE CASE — the file the whole ticket is about
# ---------------------------------------------------------------------------------------------
def test_the_geo_photo_still_carries_a_binary_gps_ifd_and_no_ascii_GPS():
    """NEGATIVE CONTROL FOR THE TEST BELOW: assert the fixture before asserting the engine.

    FAILS rather than skips if the lab is up and the file changed. If it ever stopped carrying a
    GPS IFD the positive test would pass for the wrong reason; if it ever gained the ASCII string
    'GPS' the deleted substring branch would have been able to fire on it."""
    data = _fetch(GEO_PHOTO)
    assert data[:2] == b"\xff\xd8"
    k = data.find(b"Exif\x00\x00")
    tiff = k + 6
    bo = "<" if data[tiff:tiff + 2] == b"II" else ">"
    off = struct.unpack(bo + "I", data[tiff + 4:tiff + 8])[0]
    p = tiff + off
    n = struct.unpack(bo + "H", data[p:p + 2])[0]
    tags = [struct.unpack(bo + "H", data[p + 2 + j * 12:p + 4 + j * 12])[0] for j in range(n)]
    assert 0x8825 in tags, "the geo photo no longer carries a GPS IFD pointer"
    assert b"GPS" not in data, "the file now contains ASCII 'GPS'; re-aim this test"


def test_native_reader_decodes_the_real_gps_coordinates():
    """FAILS BEFORE THE FIX: `extract_metadata` returned {} on this exact file.

    The expected values were decoded by hand out of the GPS IFD before any code was written, and
    are independently confirmed by exiftool 12.57 (59.4211583333333 / 24.8012 — agreement to 6 dp
    between two independent readers)."""
    meta = upload_tool.extract_metadata(_fetch(GEO_PHOTO))
    assert meta.get("EXIF:GPSLatitude") == "59 deg 25' 16.17\" N"
    assert meta.get("EXIF:GPSLongitude") == "24 deg 48' 4.32\" E"
    assert meta.get("EXIF:GPSPosition") == "59.421158, 24.8012"


def test_native_reader_also_recovers_the_device_and_software_tags():
    """exiftool would have surfaced these; the fallback must not be a GPS-only special case."""
    meta = upload_tool.extract_metadata(_fetch(GEO_PHOTO))
    assert meta.get("EXIF:Make") == "Google"
    assert meta.get("EXIF:Model") == "Pixel 3 XL"
    assert meta.get("EXIF:Software") == "paint.net 4.2"


#: Ground truth for the Juice Shop geo-stalking photo, decoded by hand out of the GPS IFD before any
#: code was written and independently confirmed by exiftool 12.57. 59 deg 25' 16.17" N is
#: 59 + 25/60 + 16.17/3600 = 59.421158; 24 deg 48' 4.32" E is 24 + 48/60 + 4.32/3600 = 24.801200.
GEO_TRUTH_LAT, GEO_TRUTH_LON = 59.421158, 24.801200


def _decimal_coords(evidence: str):
    """Pull (lat, lon) in decimal degrees out of EITHER reader's formatting.

    `run_metadata` uses exiftool when it is installed and a native pure-python reader otherwise, and
    the two spell coordinates differently -- DMS (`59 deg 25' 16.17" N`) versus decimal
    (`GPSLatitude: 59.4211583333333`). BOTH ARE CORRECT AND BOTH NAME THE SAME POINT.

    This test used to assert the DMS substring, which pinned the native reader's spelling rather than
    the disclosure. It passed for weeks and then broke the moment `libimage-exiftool-perl` was baked
    into the image and the engine started preferring exiftool -- a green test going red on a change
    that improved the product. So the assertion now pins the POINT, to 4 decimal places (~11 m),
    which is a stronger claim than any substring: it would catch a reader that returned plausible
    numbers for the wrong location, and a substring match never could.
    """
    dms = re.findall(r"(\d+)\s*deg\s*(\d+)'\s*([\d.]+)\"\s*([NSEW])", evidence)
    if len(dms) >= 2:
        out = []
        for d, m, s, hemi in dms[:2]:
            v = int(d) + int(m) / 60.0 + float(s) / 3600.0
            out.append(-v if hemi in ("S", "W") else v)
        return out[0], out[1]
    lat = re.search(r"GPSLatitude:\s*(-?[\d.]+)", evidence)
    lon = re.search(r"GPSLongitude:\s*(-?[\d.]+)", evidence)
    if lat and lon:
        return float(lat.group(1)), float(lon.group(1))
    return None, None


def test_the_engine_now_reports_the_leak_end_to_end():
    """The whole point: `run_metadata` said 'No sensitive metadata' on this URL."""
    res = _run(_reg()._run_metadata({"url": _url(GEO_PHOTO)}))
    assert len(res.findings) == 1, res.output
    f = res.findings[0]
    assert f["family"] == "exposure" and f["confidence"] == "lead"
    assert f["severity"] == "medium", "a GPS disclosure must not be graded low"
    lat, lon = _decimal_coords(f["evidence"])
    assert lat is not None, (
        "no coordinates in either supported format; evidence was: %r" % f["evidence"])
    assert abs(lat - GEO_TRUTH_LAT) < 1e-4, "latitude %r is not the known leak %r" % (lat, GEO_TRUTH_LAT)
    assert abs(lon - GEO_TRUTH_LON) < 1e-4, "longitude %r is not the known leak %r" % (lon, GEO_TRUTH_LON)


def test_the_two_readers_agree_on_the_location_they_report():
    """Whichever reader the image ships with, the reported POINT must be the same.

    The environment decides which path runs, so without this the product can report a different
    evidence string on two installs and nothing would notice -- which for a deterministic-first tool
    is a defect in its own right (Q-068). Pins the native reader against the same ground truth the
    end-to-end test pins the engine against, so the two can never drift apart silently.
    """
    meta = upload_tool.extract_metadata(_fetch(GEO_PHOTO))
    lat, lon = _decimal_coords(
        "%s %s" % (meta.get("EXIF:GPSLatitude", ""), meta.get("EXIF:GPSLongitude", "")))
    assert lat is not None, "native reader produced no parseable coordinates"
    assert abs(lat - GEO_TRUTH_LAT) < 1e-4 and abs(lon - GEO_TRUTH_LON) < 1e-4


# ---------------------------------------------------------------------------------------------
# NEGATIVE CONTROLS — fixing the false negative must not buy a false positive
# ---------------------------------------------------------------------------------------------
@pytest.mark.parametrize("path", CLEAN_PHOTOS)
def test_images_without_exif_stay_clean(path):
    res = _run(_reg()._run_metadata({"url": _url(path)}))
    assert res.findings == [], "false positive on %s: %s" % (path, res.output)


def test_json_and_html_responses_stay_clean():
    for path in ("/", "/api/Products"):
        res = _run(_reg()._run_metadata({"url": _url(path)}))
        assert res.findings == [], "false positive on %s" % path


def test_read_exif_returns_empty_on_a_real_jpeg_without_exif():
    assert upload_tool.read_exif(_fetch(CLEAN_PHOTOS[0])) == {}


# ---------------------------------------------------------------------------------------------
# PARSER ROBUSTNESS — lab-independent. A raised exception here would be caught upstream and become
# an invisible false negative for the ENTIRE engine, which is the defect class this ticket is about.
# ---------------------------------------------------------------------------------------------
def _tiff(bo: str, entries: list, ifd_off: int = 8) -> bytes:
    """A byte-exact little/big-endian TIFF block. CONSTRUCTED, not copied — these tests are about
    structural handling of hostile input, which by definition has no real-world original."""
    e = struct.pack(bo + "H", len(entries))
    for tag, typ, n, payload in entries:
        e += struct.pack(bo + "HHI", tag, typ, n) + payload
    e += struct.pack(bo + "I", 0)
    head = (b"II" if bo == "<" else b"MM") + struct.pack(bo + "HI", 42, ifd_off)
    return head + b"\x00" * (ifd_off - 8) + e


def _jpeg(app1_payload: bytes, scan: bytes = b"") -> bytes:
    seg = b"Exif\x00\x00" + app1_payload
    return (b"\xff\xd8" + b"\xff\xe1" + struct.pack(">H", len(seg) + 2) + seg
            + b"\xff\xda" + struct.pack(">H", len(scan) + 2) + scan + b"\xff\xd9")


@pytest.mark.parametrize("data", [
    b"", b"not an image at all", b"\xff\xd8", b"\xff\xd8\xff\xd9",
    b"\xff\xd8\xff\xe1\x00\x02",                                   # APP1 with a length of 2
    b"\xff\xd8\xff\xe1\xff\xffExif\x00\x00II*\x00",                # length runs past EOF
    b"II*\x00\xff\xff\xff\xff",                                    # TIFF, IFD offset past EOF
    b"II\x2b\x00\x08\x00\x00\x00",                                 # BigTIFF magic 43, not 42
    b"MM\x00\x2a\x00\x00\x00\x08",                                 # valid header, no IFD bytes
    b"\x89PNG\r\n\x1a\n" + b"\x00" * 64,
    b"%PDF-1.4\n" + b"\x00" * 64,
])
def test_malformed_input_returns_a_dict_and_never_raises(data):
    assert upload_tool.read_exif(data) == {}
    assert isinstance(upload_tool.extract_metadata(data), dict)


def test_an_entry_pointing_outside_the_block_is_skipped_not_read():
    """A hostile offset must lose ONE tag, not the whole parse."""
    bo = "<"
    good = struct.pack(bo + "HHI", 0x0110, 2, 4) + b"X1\x00\x00"      # Model, inline
    bad = struct.pack(bo + "HHI", 0x010F, 2, 200) + struct.pack(bo + "I", 0xFFFFFF00)
    out = upload_tool.read_exif(_jpeg(_tiff(bo, [(0x0110, 2, 4, b"X1\x00\x00"),
                                                 (0x010F, 2, 200, struct.pack(bo + "I", 0xFFFFFF00))])))
    assert out == {"EXIF:Model": "X1"}, out
    assert good and bad                                              # payload shapes as asserted


def test_both_byte_orders_parse():
    for bo in ("<", ">"):
        out = upload_tool.read_exif(_jpeg(_tiff(bo, [(0x0110, 2, 4, b"X1\x00\x00")])))
        assert out == {"EXIF:Model": "X1"}, (bo, out)


def test_exif_marker_inside_scan_data_is_not_mistaken_for_a_segment():
    """The reason this walks the JPEG segment table instead of `data.find(b"Exif\\x00\\x00")`:
    a `find` can match inside compressed image data and hand the parser a bogus TIFF base."""
    fake = b"Exif\x00\x00" + _tiff("<", [(0x0110, 2, 4, b"X1\x00\x00")])
    data = b"\xff\xd8\xff\xda" + struct.pack(">H", len(fake) + 2) + fake + b"\xff\xd9"
    assert data.find(b"Exif\x00\x00") > 0                            # a naive find WOULD match
    assert upload_tool.read_exif(data) == {}                         # the segment walk does not


def test_a_gps_ifd_with_no_decodable_coordinates_says_exactly_that():
    """Honest degraded claim, keyed on the binary tag actually observed — never the old ASCII guess,
    and never an invented coordinate."""
    bo = "<"
    gps = struct.pack(bo + "H", 1) + struct.pack(bo + "HHI", 0x001D, 2, 5) + struct.pack(bo + "I", 200)
    body = _tiff(bo, [(0x8825, 4, 1, struct.pack(bo + "I", 300))])
    blob = body + b"\x00" * (300 - len(body)) + gps
    blob = blob[:200] + b"2020\x00" + blob[205:]
    out = upload_tool.read_exif(_jpeg(blob))
    assert "EXIF:GPSIFDPresent" in out, out
    assert not any(k.endswith("Latitude") or k.endswith("Longitude") for k in out)


@pytest.mark.parametrize("parts,ref,expect_dec", [
    ([59.0, 25.0, 16.17], "N", 59.421158),
    ([59.0, 25.0, 16.17], "S", -59.421158),
    ([24.0, 48.0, 4.32], "E", 24.8012),
    ([24.0, 48.0, 4.32], "W", -24.8012),
])
def test_hemisphere_ref_flips_the_sign(parts, ref, expect_dec):
    label, dec = upload_tool._dms(parts, ref)
    assert dec == expect_dec
    assert label.endswith(" " + ref)


def test_a_missing_hemisphere_ref_is_not_silently_defaulted_to_north():
    """An empty ref is a REAL input: the coordinate is ambiguous, and quietly calling it North is
    the `x or DEFAULT` shape this codebase has paid for four times."""
    label, dec = upload_tool._dms([59.0, 25.0, 16.17], "")
    assert "no hemisphere ref" in label
    assert dec == 59.421158


@pytest.mark.parametrize("parts", [None, [], [59.0], [59.0, 25.0], [200.0, 0.0, 0.0],
                                   [59.0, 61.0, 0.0], [59.0, 25.0, 99.0]])
def test_non_coordinates_report_nothing_rather_than_nonsense(parts):
    assert upload_tool._dms(parts, "N") == (None, None)


def test_the_deleted_ascii_branch_can_no_longer_fire():
    """The old branch flagged any JPEG containing the letters 'GPS' in its first 64KB as carrying a
    GPS IFD — a claim about a binary structure, made from a substring. It was a guaranteed false
    negative on real EXIF and a false-positive surface on comments; it is gone in BOTH directions."""
    jpeg_with_the_word = (b"\xff\xd8\xff\xfe" + struct.pack(">H", len(b"my GPS notes") + 2)
                          + b"my GPS notes" + b"\xff\xd9")
    assert b"GPS" in jpeg_with_the_word
    assert upload_tool.extract_metadata(jpeg_with_the_word) == {}


def test_xmp_and_binary_exif_are_namespaced_so_neither_hides_the_other():
    """The old code suppressed its EXIF branch whenever XMP had produced a GPSLatitude. Two sources
    reporting the same fact is not a defect; hiding one is."""
    xmp = (b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><exif:GPSLatitude>1,2.5N</exif:GPSLatitude>'
           b'</x:xmpmeta>')
    data = _jpeg(_tiff("<", [(0x0110, 2, 4, b"X1\x00\x00")]), scan=b"") + xmp
    meta = upload_tool.extract_metadata(data)
    assert meta.get("GPSLatitude") == "1,2.5N"          # XMP, bare key
    assert meta.get("EXIF:Model") == "X1"               # binary EXIF, namespaced

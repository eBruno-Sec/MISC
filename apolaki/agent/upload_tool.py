"""
File-upload abuse testing (CWE-434 unrestricted upload of a dangerous file type).

Non-destructive: every payload is a small, INERT canary — never real shell code
that could execute meaningfully if a filter is bypassed. The goal is proving the
FILTER can be bypassed, not achieving code execution.

Method (mirrors PortSwigger Academy's file-upload lab methodology):

  1. CONTROL — upload an obviously-blocked extension (.exe) with plain content.
     If the app has no filtering at all, this is accepted too (informational —
     "no upload restrictions observed" is itself worth flagging as a lead, not a
     confirmed bypass, since nothing was actually bypassed).

  2. BYPASS VARIANTS — a server-executable extension (.php/.asp/.jsp/.phtml)
     disguised via: double extension (shell.php.jpg), null byte (shell.php%00.jpg),
     case variation (shell.pHp), trailing semicolon (shell.php;.jpg), and a
     magic-byte prefix (GIF89a) so a naive image-signature check also passes.

  3. VERDICT — CONFIRMED only when the CONTROL was rejected (proving a filter
     exists) AND a BYPASS variant carrying a dangerous extension was accepted —
     that is a real, provable filter bypass. If the control is also accepted,
     there is no filter to bypass and this is downgraded to an informational
     lead ("no upload restriction observed"), never invented as a bypass.

Acceptance/rejection is read from the response: explicit success/failure
keywords, JSON status fields, a 2xx/3xx with a returned file URL, or a 4xx.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin


class _UploadFormParser(HTMLParser):
    """Finds <form> elements carrying a file <input> — a candidate upload
    endpoint. Mirrors csrf_tool._FormParser's style, but also tracks enctype
    and input `type` so a non-file field name (used as the multipart field to
    inject the payload under) can be picked correctly."""
    def __init__(self):
        super().__init__()
        self.forms = []
        self._cur = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._cur = {"method": a.get("method", "get").lower(), "action": a.get("action", ""),
                        "enctype": a.get("enctype", "").lower(), "file_field": None, "other_fields": []}
        elif tag == "input" and self._cur is not None and a.get("name"):
            if a.get("type", "text").lower() == "file":
                self._cur["file_field"] = a["name"]
            else:
                self._cur["other_fields"].append(a["name"])

    def handle_endtag(self, tag):
        if tag == "form" and self._cur is not None:
            if self._cur.get("file_field"):
                self.forms.append(self._cur)
            self._cur = None


def find_upload_forms(html: str, base_url: str = "") -> list:
    """Forms with a file input — {method, action, enctype, file_field, other_fields}."""
    p = _UploadFormParser()
    try:
        p.feed(html or "")
    except Exception:
        pass
    out = []
    for f in p.forms:
        action = urljoin(base_url, f["action"]) if (base_url and f["action"]) else (f["action"] or base_url)
        out.append({"method": (f["method"] or "post").upper(), "action": action,
                    "enctype": f["enctype"], "file_field": f["file_field"], "other_fields": f["other_fields"]})
    return out

# tiny inert payload — a comment only, never functional shell code
CANARY_BODY_TPL = "APOLAKI-UPLOAD-TEST-{token} (inert marker; safe non-executing content)"
GIF_MAGIC = b"GIF89a"  # 1x1 GIF header so a naive image-signature sniff passes

DANGEROUS_EXTS = ("php", "phtml", "php5", "php7", "pht", "asp", "aspx", "jsp", "jspx")
BLOCKED_CONTROL_EXT = "exe"

_REJECT_RE = re.compile(
    r"\b(?:not allowed|forbidden|invalid (?:file|type|extension)|unsupported (?:file|type)|"
    r"file type|extension is not|rejected|blocked|denied|disallowed)\b", re.IGNORECASE)
_ACCEPT_RE = re.compile(r'"(?:success|ok|uploaded)"\s*:\s*true|"status"\s*:\s*"(?:ok|success)"', re.IGNORECASE)
_URL_RE = re.compile(r'"(?:url|path|location|file(?:name|Url)?)"\s*:\s*"([^"]+)"', re.IGNORECASE)


def bypass_filenames(base: str = "apolaki") -> list:
    """(filename, ext_that_would_actually_execute) pairs, image-input field name
    hints excluded — these are FILENAMES only, the caller sets the multipart part."""
    out = []
    for ext in DANGEROUS_EXTS[:3]:                      # bounded — keep the probe fast
        out.append((f"{base}.{ext}.jpg", ext))           # double extension
        out.append((f"{base}.{ext.upper()[0]}{ext[1:]}", ext))  # case variation, e.g. .pHp
        out.append((f"{base}.{ext};.jpg", ext))           # trailing semicolon (legacy Apache)
    return out[:6]


def verdict(control_status: int, control_body: str,
           bypass_status: int, bypass_body: str) -> str:
    """'accepted' | 'rejected' for one upload attempt, from status + body signals."""
    body = bypass_body if bypass_status else control_body
    rejected_kw = bool(_REJECT_RE.search(bypass_body or ""))
    if bypass_status and bypass_status >= 400:
        return "rejected"
    if rejected_kw:
        return "rejected"
    if bypass_status in (200, 201, 202, 302) or _ACCEPT_RE.search(bypass_body or ""):
        return "accepted"
    return "rejected"


def extract_url(body: str) -> str:
    m = _URL_RE.search(body or "")
    return m.group(1) if m else ""


def multipart_body(file_field: str, filename: str, file_content: str,
                   other_fields: list = None, content_type: str = "image/gif") -> tuple:
    """(headers, body_str) for a manually-built multipart/form-data request — gives
    exact control over filename/Content-Type per part, which httpx's `files=` param
    does not expose as precisely when a filter check depends on both."""
    boundary = "ApolakiUploadBoundary7f3c9a"
    parts = []
    for name in (other_fields or []):
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n1\r\n')
    parts.append(
        f'--{boundary}\r\nContent-Disposition: form-data; name="{file_field}"; filename="{filename}"\r\n'
        f'Content-Type: {content_type}\r\n\r\n{file_content}\r\n')
    parts.append(f'--{boundary}--\r\n')
    body = "".join(parts)
    headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    return headers, body


def _base(field: str, filename: str, ext: str) -> dict:
    return {
        "title": f"Unrestricted file upload — extension-filter bypass ('{filename}')",
        "severity": "critical", "target": filename,
        "description": (f"The upload endpoint rejected a plainly-blocked file (.{BLOCKED_CONTROL_EXT}), proving a "
                        f"filter exists, but accepted '{filename}' — a filename crafted to disguise a "
                        f".{ext} (server-executable) extension. The filter can be bypassed."),
        "impact": ("An attacker can upload a server-side script (webshell) and, if it lands in a web-servable "
                   "directory and the server maps execution by any recognised extension in the filename, "
                   "achieve remote code execution on the host."),
        "reproduction_steps": [
            f"Confirm a plain .{BLOCKED_CONTROL_EXT} upload is rejected (baseline filter check)",
            f"Upload a file named '{filename}' with image-shaped content (GIF89a header)",
            "Observe the upload is ACCEPTED despite carrying a disguised server-executable extension",
            "If the returned path is web-servable, verify manually whether the extension is honoured for execution"],
        "evidence": f"Control (.{BLOCKED_CONTROL_EXT}) rejected; '{filename}' accepted",
        "cwe": "CWE-434", "family": "upload", "tags": ["upload", "cwe-434"],
        "confidence": "confirmed", "field": field,
    }


def bypass_finding(field: str, filename: str, ext: str, upload_url: str = "") -> dict:
    f = _base(field, filename, ext)
    if upload_url:
        f["description"] += f" The server returned a retrievable location: {upload_url}"
        f["reproduction_steps"].insert(3, f"Fetch the returned location ({upload_url}) to confirm it is served")
    return f


def no_restriction_lead(field: str) -> dict:
    """The blocked-extension CONTROL itself was accepted — there is no filter to
    bypass, so this is an observation (no confirmed bypass happened), not a finding."""
    return {
        "title": "No file-extension restriction observed on upload endpoint",
        "severity": "medium", "confidence": "candidate", "family": "upload",
        "description": (f"An upload with a plainly dangerous extension (.{BLOCKED_CONTROL_EXT}) was accepted "
                        "without any extension filtering being observed. This is a lead, not a confirmed "
                        "bypass — no filter was actually defeated because none was detected."),
        "field": field, "tags": ["upload", "cwe-434", "lead"],
    }


# ── Native metadata extraction (fallback when exiftool is absent) ────────────────
import re as _re
import struct as _struct

# ── Binary EXIF (Q-055) ──────────────────────────────────────────────────────────
# THE DEFECT THIS REPLACES. `extract_metadata`'s only JPEG branch was
#     if data[:2] == b"\xff\xd8" and b"GPS" in data[:65536]: ...
# an ASCII substring match. Real EXIF stores GPS as the BINARY IFD-pointer tag 0x8825; the
# characters "GPS" never appear. MEASURED on the Juice Shop geo-stalking photo, which provably
# leaks 59d25'16.17"N 24d48'4.32"E:
#     b"GPS" in data                     -> False
#     IFD0 tag 0x8825 (GPS IFD pointer)  -> present
#     extract_metadata(data)             -> {}
#     run_metadata                       -> "No sensitive metadata (native)", findings=0
# So the string match was BOTH a guaranteed false negative on every real EXIF GPS file and a
# false-positive surface on any JPEG that happens to contain the letters "GPS" in a comment. It
# is deleted rather than kept alongside: a parser supersedes it in both directions.
#
# TIFF/EXIF type -> bytes per component (TIFF 6.0 §2). Unknown types are skipped, never guessed.
_TIFF_TYPE_SIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8}

_IFD0_TAGS = {0x010F: "Make", 0x0110: "Model", 0x0131: "Software",
              0x013B: "Artist", 0x8298: "Copyright", 0x0132: "ModifyDate"}
_EXIF_SUB_TAGS = {0x9003: "DateTimeOriginal", 0xA430: "OwnerName",
                  0xA431: "BodySerialNumber", 0xA433: "LensMake", 0xA434: "LensModel"}
_GPS_TAGS = {0x0001: "GPSLatitudeRef", 0x0002: "GPSLatitude", 0x0003: "GPSLongitudeRef",
             0x0004: "GPSLongitude", 0x0006: "GPSAltitude", 0x001D: "GPSDateStamp"}
_EXIF_IFD_PTR, _GPS_IFD_PTR = 0x8769, 0x8825


def _jpeg_exif_block(data: bytes) -> bytes:
    """The TIFF block inside the APP1 'Exif\\x00\\x00' segment, found by WALKING the JPEG segment
    table — not by `data.find(b"Exif\\x00\\x00")`, which can match inside compressed image data and
    would hand the parser a bogus TIFF base. Returns b"" when there is no APP1/Exif segment."""
    if data[:2] != b"\xff\xd8":
        return b""
    i, n = 2, len(data)
    while i + 4 <= n:
        if data[i] != 0xFF:
            return b""                      # not a marker boundary: stop rather than resynchronise
        marker = data[i + 1]
        if marker == 0xFF:                  # fill byte, legal between markers
            i += 1
            continue
        if marker in (0x01, 0xD8) or 0xD0 <= marker <= 0xD7:
            i += 2                          # standalone markers carry no length
            continue
        if marker in (0xD9, 0xDA):
            return b""                      # EOI / start of entropy-coded scan: no more segments
        seglen = _struct.unpack(">H", data[i + 2:i + 4])[0]
        if seglen < 2 or i + 2 + seglen > n:
            return b""                      # truncated/garbage length: refuse, do not guess
        if marker == 0xE1 and data[i + 4:i + 10] == b"Exif\x00\x00":
            return data[i + 10:i + 2 + seglen]
        i += 2 + seglen
    return b""


def _tiff_block(data: bytes) -> bytes:
    """The TIFF/EXIF byte block for either container shape: a JPEG APP1 segment, or a bare TIFF
    file (which IS its own TIFF block)."""
    if data[:2] in (b"II", b"MM") and len(data) >= 8:
        return data
    return _jpeg_exif_block(data)


def _read_ifd(tiff: bytes, offset: int, bo: str, wanted: dict, ptrs: tuple = ()) -> tuple:
    """Read one IFD. Returns ({name: decoded_value}, {ptr_tag: sub_ifd_offset}).

    Every read is bounds-checked against `tiff`, so a truncated or hostile file yields fewer tags
    rather than an exception — this runs inside `run_metadata`, where a raised error would be
    caught upstream and become an invisible false negative for the whole engine (the exact defect
    class this ticket is about). Nothing here can raise on adversarial input, so nothing here needs
    a swallow."""
    vals, found_ptrs = {}, {}
    if offset < 2 or offset + 2 > len(tiff):
        return vals, found_ptrs
    count = _struct.unpack(bo + "H", tiff[offset:offset + 2])[0]
    if count > 512:                          # sane cap; real IFDs are tens of entries
        count = 512
    for j in range(count):
        e = offset + 2 + j * 12
        if e + 12 > len(tiff):
            break
        tag, typ, n = _struct.unpack(bo + "HHI", tiff[e:e + 8])
        if tag in ptrs:
            found_ptrs[tag] = _struct.unpack(bo + "I", tiff[e + 8:e + 12])[0]
            continue
        if tag not in wanted:
            continue
        unit = _TIFF_TYPE_SIZE.get(typ)
        if not unit or n == 0 or n > 4096:
            continue                         # unknown type / absurd count: skip, never guess
        size = unit * n
        if size <= 4:
            raw = tiff[e + 8:e + 8 + size]
        else:
            off = _struct.unpack(bo + "I", tiff[e + 8:e + 12])[0]
            if off + size > len(tiff):
                continue                     # points outside the block: skip
            raw = tiff[off:off + size]
        if len(raw) < size:
            continue
        val = _decode_tiff_value(raw, typ, n, bo)
        if val is not None:
            vals[wanted[tag]] = val
    return vals, found_ptrs


def _decode_tiff_value(raw: bytes, typ: int, n: int, bo: str):
    """ASCII -> str, RATIONAL/SRATIONAL -> float or [float], SHORT/LONG -> int or [int]."""
    if typ in (1, 2, 7):                                  # BYTE / ASCII / UNDEFINED
        s = raw.split(b"\x00")[0].decode("ascii", "replace").strip()
        return s or None
    if typ in (3, 4, 9):                                  # SHORT / LONG / SLONG
        code = {3: "H", 4: "I", 9: "i"}[typ]
        out = list(_struct.unpack(bo + code * n, raw))
        return out[0] if n == 1 else out
    if typ in (5, 10):                                    # RATIONAL / SRATIONAL
        code = "II" if typ == 5 else "ii"
        out = []
        for k in range(n):
            num, den = _struct.unpack(bo + code, raw[k * 8:(k + 1) * 8])
            out.append(float(num) / den if den else 0.0)
        return out[0] if n == 1 else out
    return None


def _dms(parts, ref: str) -> tuple:
    """[deg, min, sec] + N/S/E/W -> ("59 deg 25' 16.17\\" N", 59.421158) or (None, None).

    The ref is a REAL input even when absent: a coordinate with no hemisphere is ambiguous, so it
    is reported as-is rather than silently defaulting to the northern/eastern hemisphere."""
    if not isinstance(parts, list) or len(parts) < 3:
        return None, None
    d, m, s = (float(parts[0]), float(parts[1]), float(parts[2]))
    if not (0 <= d <= 180 and 0 <= m < 60 and 0 <= s < 60):
        return None, None                     # not a coordinate; report nothing rather than nonsense
    dec = d + m / 60.0 + s / 3600.0
    r = (ref or "").strip().upper()[:1]
    if r in ("S", "W"):
        dec = -dec
    def _n(x):
        return ("%g" % round(x, 6))
    label = "%s deg %s' %s\"" % (_n(d), _n(m), _n(s))
    return (label + " " + r if r else label + " (no hemisphere ref)"), round(dec, 6)


def read_exif(data: bytes) -> dict:
    """Binary EXIF reader for JPEG (APP1) and bare TIFF: GPS coordinates plus the device/authorship
    tags exiftool would surface. Flat {`EXIF:<Tag>`: value}; {} when the file carries no EXIF."""
    tiff = _tiff_block(data or b"")
    if len(tiff) < 8 or tiff[:2] not in (b"II", b"MM"):
        return {}
    bo = "<" if tiff[:2] == b"II" else ">"
    if _struct.unpack(bo + "H", tiff[2:4])[0] != 42:      # TIFF magic; anything else is not TIFF
        return {}
    ifd0_off = _struct.unpack(bo + "I", tiff[4:8])[0]
    vals, ptrs = _read_ifd(tiff, ifd0_off, bo, _IFD0_TAGS, (_EXIF_IFD_PTR, _GPS_IFD_PTR))
    out = {"EXIF:" + k: v for k, v in vals.items()}

    if _EXIF_IFD_PTR in ptrs:
        sub, _ = _read_ifd(tiff, ptrs[_EXIF_IFD_PTR], bo, _EXIF_SUB_TAGS)
        out.update({"EXIF:" + k: v for k, v in sub.items()})

    if _GPS_IFD_PTR in ptrs:
        gps, _ = _read_ifd(tiff, ptrs[_GPS_IFD_PTR], bo, _GPS_TAGS)
        lat, lat_dec = _dms(gps.get("GPSLatitude"), gps.get("GPSLatitudeRef") or "")
        lon, lon_dec = _dms(gps.get("GPSLongitude"), gps.get("GPSLongitudeRef") or "")
        if lat:
            out["EXIF:GPSLatitude"] = lat
        if lon:
            out["EXIF:GPSLongitude"] = lon
        if lat_dec is not None and lon_dec is not None:
            out["EXIF:GPSPosition"] = "%s, %s" % (lat_dec, lon_dec)
        if gps.get("GPSDateStamp"):
            out["EXIF:GPSDateStamp"] = gps["GPSDateStamp"]
        if not lat and not lon:
            # The pointer tag 0x8825 IS present but no coordinate decoded. Say exactly that, keyed
            # on the binary tag actually observed — an honest degraded claim, never the old ASCII
            # guess. `gps` keys are still namespaced so nothing is invented.
            out["EXIF:GPSIFDPresent"] = ("GPS IFD (tag 0x8825) present, coordinates not decodable "
                                         "from tags %s" % sorted(gps) or "[]")
    return out


def extract_metadata(data: bytes) -> dict:
    """Dependency-free metadata extraction used when exiftool is not installed. Pulls the
    XMP packet (images/PDF), the PDF info dictionary, and a REAL binary EXIF parse (Q-055 —
    this used to be an ASCII `b"GPS"` substring match that real EXIF never satisfies). Returns a
    flat {tag: value} dict. Best-effort and deterministic — exiftool is richer across container
    formats, but this carries the JPEG/TIFF EXIF capability on its own."""
    if not data:
        return {}
    out = {}
    text = data[:8_000_000].decode("latin-1", "replace")  # byte-preserving over binary
    m = _re.search(r"<x:xmpmeta.*?</x:xmpmeta>", text, _re.S)
    if m:
        xmp = m.group(0)
        for tag, rx in (
            ("Creator", r"<dc:creator>.*?<rdf:li[^>]*>([^<]+)"),
            ("CreatorTool", r'xmp:CreatorTool="([^"]+)"|<xmp:CreatorTool>([^<]+)'),
            ("Make", r'tiff:Make="([^"]+)"|<tiff:Make>([^<]+)'),
            ("Model", r'tiff:Model="([^"]+)"|<tiff:Model>([^<]+)'),
            ("Software", r'tiff:Software="([^"]+)"'),
            ("GPSLatitude", r'exif:GPSLatitude="([^"]+)"|<exif:GPSLatitude>([^<]+)'),
            ("GPSLongitude", r'exif:GPSLongitude="([^"]+)"|<exif:GPSLongitude>([^<]+)'),
        ):
            mm = _re.search(rx, xmp)
            if mm:
                out[tag] = next((g for g in mm.groups() if g), "").strip()
    for tag in ("Author", "Creator", "Producer", "Title", "CreationDate", "ModDate"):
        mm = _re.search(r"/%s\s*\(([^)]{1,200})\)" % tag, text)
        if mm:
            out["PDF:" + tag] = mm.group(1).strip()
    # Binary EXIF LAST and namespaced under `EXIF:`, so it can neither overwrite nor be overwritten
    # by the XMP values above. Two sources reporting the same fact is not a defect; hiding one is —
    # the old code suppressed its EXIF branch whenever XMP had already produced a GPSLatitude.
    out.update(read_exif(data))
    return out


# ── ONE canonical coordinate spelling (Q-068) ────────────────────────────────────
# THE DEFECT THIS FIXES. `run_metadata` prefers `exiftool` when it is installed and falls back to
# `extract_metadata` above. Both are correct and both recover the SAME point from the Juice Shop
# geo-stalking photo — they SPELL it differently. MEASURED on the same 107952 bytes inside the
# shipped image on 2026-08-17:
#     exiftool -j -n   GPSLatitude = 59.4211583333333        GPSPosition = '59.4211583333333 24.8012'
#     native           EXIF:GPSLatitude = "59 deg 25' 16.17\" N"   EXIF:GPSPosition = '59.421158, 24.8012'
# `_run_metadata` renders its evidence as "\n".join(f"{k}: {v}"), so BOTH spellings reach a
# client-facing finding and which one an operator gets depends on whether `libimage-exiftool-perl`
# was baked into their image. For a deterministic-first tool two installs must not report the same
# target differently, and nothing in the suite noticed until the bake flipped the preferred path.
#
# THE CANONICAL FORM: SIGNED DECIMAL DEGREES to exactly six decimal places, hemisphere carried in
# the sign, latitude first, ", " between the pair -> "59.421158, 24.801200". Decimal rather than DMS
# because both readers reach it losslessly from the same EXIF rationals
# (59 + 25/60 + 16.17/3600 = 59.42115833... and exiftool's 59.4211583333333 both give 59.421158),
# whereas going the other way would mean re-deriving seconds from a rounded decimal. Six decimals is
# ~0.11 m, finer than the source rationals carry, so nothing real is rounded away.
#
# SCOPE, stated so it is not quietly widened later: this normalises the coordinate VALUES, not the
# key namespace. `EXIF:` names the SOURCE a value came from, which is real information, and
# flattening it would re-open the Q-055 namespacing that stops XMP and binary EXIF hiding each
# other. exiftool also surfaces GPSDOP/GPSAltitude/GPSTimeStamp/ProfileCreator that the native reader
# genuinely cannot read, so byte-identical evidence between the two readers is impossible; the
# property that IS achievable, and is what the tests pin, is that the LOCATION is one string.
#
# A value that does not parse as a coordinate is LEFT EXACTLY AS IT WAS. Refusing beats inventing:
# an unrecognised spelling should look unrecognised in the report, not become a plausible number.
_CANON_FMT = "%.6f"
_CANON_LAT_KEYS = ("GPSLatitude", "GPSDestLatitude")
_CANON_LON_KEYS = ("GPSLongitude", "GPSDestLongitude")
_CANON_PAIR_KEYS = ("GPSPosition", "GPSCoordinates", "GPSDestPosition")

#: A trailing hemisphere letter. Anchored at the end so it cannot match the `N` inside a word — the
#: native reader's own "(no hemisphere ref)" label is the case that proves the anchor is needed.
_HEMI_RE = _re.compile(r"([NSEW])\s*$", _re.IGNORECASE)
_NUM_RE = _re.compile(r"-?\d+(?:\.\d+)?")


def _coord_value(raw):
    """One coordinate, in ANY spelling either reader emits -> signed decimal degrees, or None.

    Accepts: a number (exiftool `-n`); `59 deg 25' 16.17" N` (native reader, and exiftool without
    `-n`); a bare decimal string with or without a hemisphere letter; and the XMP `59,25.2695N`
    degrees-and-decimal-minutes form. Anything else returns None and the caller leaves the value
    alone."""
    if isinstance(raw, bool):
        return None                                  # True is not 1 degree
    if isinstance(raw, (int, float)):
        return float(raw)
    if not isinstance(raw, str) or not raw.strip():
        return None
    s = raw.strip()
    hemi = ""
    m = _HEMI_RE.search(s)
    if m:
        hemi = m.group(1).upper()
        s = s[:m.start()]
    nums = _NUM_RE.findall(s)
    if not 1 <= len(nums) <= 3:
        return None                                  # not a coordinate; report nothing rather than nonsense
    try:
        parts = [float(n) for n in nums]
    except ValueError:
        return None
    negative = parts[0] < 0 or hemi in ("S", "W")
    value = abs(parts[0])
    if len(parts) >= 2:
        if not 0 <= parts[1] < 60:
            return None
        value += parts[1] / 60.0
    if len(parts) == 3:
        if not 0 <= parts[2] < 60:
            return None
        value += parts[2] / 3600.0
    if value > 180:
        return None
    return -value if negative else value


def _coord_pair(raw):
    """A `GPSPosition`-style pair -> (lat, lon) in decimal degrees, or None.

    Split on a comma when that yields exactly two halves (`59.421158, 24.8012`), otherwise on
    whitespace (exiftool `-n` writes `59.4211583333333 24.8012`, and the XMP form is comma-bearing
    within each half so only the whitespace split can separate it)."""
    if not isinstance(raw, str):
        return None
    for parts in ([p for p in raw.split(",")], raw.split()):
        if len(parts) != 2:
            continue
        lat, lon = _coord_value(parts[0]), _coord_value(parts[1])
        if lat is not None and lon is not None and abs(lat) <= 90:
            return lat, lon
    return None


def _axis_keys(key: str) -> str:
    """"lat" | "lon" | "pair" | "" for a metadata key, ignoring any source namespace prefix."""
    base = key.rsplit(":", 1)[-1]
    if base in _CANON_LAT_KEYS:
        return "lat"
    if base in _CANON_LON_KEYS:
        return "lon"
    if base in _CANON_PAIR_KEYS:
        return "pair"
    return ""


def canonical_gps(meta: dict) -> dict:
    """A COPY of `meta` with every GPS coordinate value rewritten to the one canonical spelling.

    Keys, ordering and every non-coordinate value are untouched — including `GPSDOP`, `GPSAltitude`
    and the `...Ref` tags, which are not coordinates and must not be reformatted as if they were."""
    out = dict(meta or {})
    for key, raw in list(out.items()):
        axis = _axis_keys(key)
        if axis in ("lat", "lon"):
            value = _coord_value(raw)
            if value is not None and abs(value) <= (90.0 if axis == "lat" else 180.0):
                out[key] = _CANON_FMT % value
        elif axis == "pair":
            pair = _coord_pair(raw)
            if pair:
                out[key] = "%s, %s" % (_CANON_FMT % pair[0], _CANON_FMT % pair[1])
    return out


def canonical_position(meta: dict) -> str:
    """The ONE source-independent location statement for a metadata dict, or "".

    Keys are visited in SORTED order rather than insertion order so that a file carrying both an XMP
    and a binary-EXIF latitude resolves the same way every run — determinism is the whole point of
    this function, and inheriting dict ordering would have left it to whichever reader ran."""
    meta = meta or {}
    lat = lon = None
    for key in sorted(meta):
        axis = _axis_keys(key)
        value = _coord_value(meta[key]) if axis in ("lat", "lon") else None
        if axis == "lat" and lat is None and value is not None and abs(value) <= 90:
            lat = value
        elif axis == "lon" and lon is None and value is not None and abs(value) <= 180:
            lon = value
    if lat is None or lon is None:
        for key in sorted(meta):
            if _axis_keys(key) == "pair":
                pair = _coord_pair(meta[key])
                if pair:
                    lat, lon = pair
                    break
    if lat is None or lon is None:
        return ""
    return "%s, %s" % (_CANON_FMT % lat, _CANON_FMT % lon)

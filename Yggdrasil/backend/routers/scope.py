import csv
import io
import json
import re
from typing import Optional
from fastapi import APIRouter, UploadFile, File, Form, HTTPException

router = APIRouter()


# ── Line-level helpers ────────────────────────────────────────

def _extract_md_url(line: str) -> Optional[str]:
    """[label](https://domain.com/path) -> domain.com"""
    m = re.match(r'\[.*?\]\(https?://([^/)\s]+)', line)
    return m.group(1).lstrip("www.") if m else None


def _strip_platform_suffix(line: str):
    """'com.pkg.name (Android)' -> ('com.pkg.name', 'android')"""
    m = re.match(r'^(.+?)\s+\((Android|iOS|Apple|Google Play)\)\s*$', line, re.I)
    if m:
        kind = m.group(2).lower().replace("google play", "android").replace("apple", "ios")
        return m.group(1).strip(), kind
    return line.strip(), None


def _classify(identifier: str) -> str:
    i = identifier.strip()
    if i.startswith("/") and not i.startswith("//"):
        return "path"
    if re.match(r'^\d+$', i):
        return "ios_app_id"
    if re.match(r'^com\.[a-z]', i.lower()):
        return "android_package"
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}(/\d+)?$', i):
        return "ip"
    if re.match(r'^https?://', i, re.I):
        return "url"
    return "domain"


def _looks_like_scope_asset(identifier: str) -> bool:
    i = identifier.strip()
    if not i:
        return False
    if i.startswith("/") and not i.startswith("//"):
        return True
    if re.match(r'^https?://', i, re.I):
        return True
    if re.match(r'^\d+$', i):
        return True
    if re.match(r'^com\.[a-z]', i.lower()):
        return True
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}(/\d+)?$', i):
        return True
    host = i.split("/")[0].split(":")[0].lstrip("*.")
    return "." in host and " " not in host and "\t" not in host


def _parse_target(raw: str) -> Optional[dict]:
    line = raw.strip()
    if not line:
        return None

    # Markdown link
    md = _extract_md_url(line)
    if md:
        line = md

    # Strip inline comment (but not the # IN-SCOPE headers, those are gone before this runs)
    line = re.split(r'\s+#\s+', line)[0].strip()

    # Mobile platform suffix
    line, platform = _strip_platform_suffix(line)
    if not line:
        return None
    if not _looks_like_scope_asset(line):
        return None

    return {"identifier": line, "type": platform or _classify(line)}


# ── Format parsers ────────────────────────────────────────────

def _parse_sections(content: str) -> dict:
    """
    Handles:
      - Section headers:  # IN-SCOPE ...  /  # OUT-OF-SCOPE ...
      - Prefix style:     - domain.com (excluded)  /  + domain.com or bare line (included)
      - Markdown links:   [label](https://domain.com)
      - Mobile apps:      com.package (Android) / 123456 (iOS)
      - Plain list:       all lines treated as in-scope if no out-of-scope marker found
    """
    in_scope: list = []
    out_of_scope: list = []
    section = "in"

    for raw in content.splitlines():
        line = raw.strip()
        if not line:
            continue

        # Section header detection
        if line.startswith("#"):
            u = line.upper()
            if any(k in u for k in ("OUT-OF-SCOPE", "OUT OF SCOPE", "INELIGIBLE", "EXCLUDE", "NOT IN SCOPE")):
                section = "out"
            elif any(k in u for k in ("IN-SCOPE", "IN SCOPE", "ELIGIBLE", "INCLUDE")):
                section = "in"
            continue

        # Explicit prefix override
        if line.startswith("-"):
            entry = _parse_target(line[1:])
            if entry:
                out_of_scope.append(entry)
            continue
        if line.startswith("+"):
            entry = _parse_target(line[1:])
            if entry:
                in_scope.append(entry)
            continue

        # Follow current section
        entry = _parse_target(line)
        if entry:
            (in_scope if section == "in" else out_of_scope).append(entry)

    return {"in_scope": in_scope, "out_of_scope": out_of_scope, "format": "section_based"}


def _parse_hackerone_csv(content: str) -> dict:
    in_scope, out_of_scope = [], []
    reader = csv.DictReader(io.StringIO(content))
    hdrs = [h.lower().strip() for h in (reader.fieldnames or [])]
    id_col = next((h for h in hdrs if "identifier" in h or "target" in h), None)
    bounty_col = next((h for h in hdrs if "bounty" in h or "eligible" in h), None)
    type_col = next((h for h in hdrs if "type" in h), None)

    if not id_col:
        return _parse_sections(content)

    for row in reader:
        raw = (row.get(id_col) or "").strip()
        if not raw or raw.lower() in ("n/a", "none", "-", ""):
            continue
        entry = _parse_target(raw)
        if not entry:
            continue
        if type_col:
            entry["type"] = (row.get(type_col) or entry["type"]).strip().lower()
        eligible = (row.get(bounty_col) or "true").strip().lower()
        (in_scope if eligible in ("true", "yes", "1") else out_of_scope).append(entry)

    return {"in_scope": in_scope, "out_of_scope": out_of_scope, "format": "hackerone_csv"}


def _parse_bugcrowd_csv(content: str) -> dict:
    in_scope, out_of_scope = [], []
    reader = csv.DictReader(io.StringIO(content))
    hdrs = [h.lower().strip() for h in (reader.fieldnames or [])]
    target_col = next((h for h in hdrs if "target" in h), None)
    focus_col = next((h for h in hdrs if "focus" in h), None)

    if not target_col:
        return _parse_sections(content)

    for row in reader:
        raw = (row.get(target_col) or "").strip()
        if not raw:
            continue
        entry = _parse_target(raw)
        if not entry:
            continue
        focus = (row.get(focus_col) or "in").strip().lower()
        (out_of_scope if "out" in focus or "excluded" in focus else in_scope).append(entry)

    return {"in_scope": in_scope, "out_of_scope": out_of_scope, "format": "bugcrowd_csv"}


def _parse_burp_json(content: str) -> dict:
    """
    Burp Suite scope JSON formats:
      {"target": {"scope": {"include": [{"host": "..."}], "exclude": [...]}}}
      {"include": ["url"], "exclude": ["url"]}
    """
    data = json.loads(content)
    if "target" in data and "scope" in data.get("target", {}):
        data = data["target"]["scope"]

    def extract(items: list) -> list:
        result = []
        for item in (items or []):
            if isinstance(item, str):
                entry = _parse_target(item)
            elif isinstance(item, dict):
                raw = item.get("host") or item.get("url") or item.get("file") or ""
                entry = _parse_target(raw)
            else:
                entry = None
            if entry:
                result.append(entry)
        return result

    return {
        "in_scope": extract(data.get("include") or data.get("inclusions") or []),
        "out_of_scope": extract(data.get("exclude") or data.get("exclusions") or []),
        "format": "burp_json",
    }


# ── Auto-detect and dispatch ──────────────────────────────────

def _auto_parse(content: str) -> dict:
    content = content.strip()
    if not content:
        return {"in_scope": [], "out_of_scope": [], "format": "empty"}

    # JSON (Burp Suite project scope export)
    if content.startswith("{"):
        try:
            return _parse_burp_json(content)
        except Exception:
            pass

    first = content.splitlines()[0].lower().strip()

    # CSV format detection
    if "," in first and len(first.split(",")) >= 2:
        if "asset_identifier" in first or "eligible_for_bounty" in first:
            return _parse_hackerone_csv(content)
        if "target" in first and any(k in first for k in ("category", "severity", "focus")):
            return _parse_bugcrowd_csv(content)

    # Section-based, prefix-style, plain list, or markdown
    return _parse_sections(content)


# ── Endpoint ──────────────────────────────────────────────────

@router.post("/parse")
async def parse_scope(
    file: Optional[UploadFile] = File(None),
    text: Optional[str] = Form(None),
):
    if file:
        raw = await file.read()
        try:
            content = raw.decode("utf-8")
        except UnicodeDecodeError:
            content = raw.decode("latin-1")
    elif text:
        content = text
    else:
        raise HTTPException(400, "Provide a file upload or raw text")

    result = _auto_parse(content)
    return {
        "in_scope": result["in_scope"],
        "out_of_scope": result["out_of_scope"],
        "format_detected": result.get("format", "unknown"),
        "total_in": len(result["in_scope"]),
        "total_out": len(result["out_of_scope"]),
    }

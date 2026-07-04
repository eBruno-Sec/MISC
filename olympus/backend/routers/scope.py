import csv
import io
import re
from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from typing import Optional

router = APIRouter()


def _clean(val: str) -> str:
    return val.strip().lower().lstrip("*.")


def _classify(identifier: str) -> str:
    identifier = identifier.strip()
    if re.match(r"^\d+\.\d+\.\d+\.\d+(/\d+)?$", identifier):
        return "ip"
    if re.match(r"^\d+\.\d+\.\d+\.\d+-\d+\.\d+\.\d+\.\d+$", identifier):
        return "ip_range"
    if re.match(r"^https?://", identifier, re.IGNORECASE):
        return "url"
    if re.match(r"^[\w.-]+\.[a-z]{2,}$", identifier, re.IGNORECASE):
        return "domain"
    return "other"


def parse_hackerone(content: str) -> dict:
    """
    HackerOne scope CSV columns:
      asset_type, asset_identifier, eligible_for_bounty, instruction, max_severity
    """
    in_scope, out_of_scope = [], []
    reader = csv.DictReader(io.StringIO(content))
    headers = [h.lower().strip() for h in (reader.fieldnames or [])]

    id_col = next((h for h in headers if "identifier" in h or "target" in h or "asset" in h), None)
    bounty_col = next((h for h in headers if "bounty" in h or "eligible" in h), None)
    type_col = next((h for h in headers if "type" in h), None)

    if not id_col:
        return parse_generic(content)

    for row in reader:
        raw = (row.get(id_col) or "").strip()
        if not raw or raw.lower() in ("n/a", "none", "-"):
            continue
        eligible = (row.get(bounty_col) or "true").strip().lower()
        asset_type = (row.get(type_col) or _classify(raw)).strip().lower()
        entry = {"identifier": raw, "type": asset_type}
        if eligible in ("true", "yes", "1"):
            in_scope.append(entry)
        else:
            out_of_scope.append(entry)

    return {"in_scope": in_scope, "out_of_scope": out_of_scope, "format": "hackerone"}


def parse_bugcrowd(content: str) -> dict:
    """
    Bugcrowd scope CSV columns:
      Category, Target, Severity, Focus, Notes
    """
    in_scope, out_of_scope = [], []
    reader = csv.DictReader(io.StringIO(content))
    headers = [h.lower().strip() for h in (reader.fieldnames or [])]

    target_col = next((h for h in headers if "target" in h), None)
    cat_col = next((h for h in headers if "category" in h or "scope" in h), None)
    focus_col = next((h for h in headers if "focus" in h), None)

    if not target_col:
        return parse_generic(content)

    for row in reader:
        raw = (row.get(target_col) or "").strip()
        if not raw:
            continue
        focus = (row.get(focus_col) or "in").strip().lower()
        cat = (row.get(cat_col) or _classify(raw)).strip().lower()
        entry = {"identifier": raw, "type": cat}
        if "out" in focus or "excluded" in focus:
            out_of_scope.append(entry)
        else:
            in_scope.append(entry)

    return {"in_scope": in_scope, "out_of_scope": out_of_scope, "format": "bugcrowd"}


def parse_generic(content: str) -> dict:
    """
    Generic format: lines prefixed with + (in-scope) or - (out-of-scope),
    or just a plain list of domains/IPs (all treated as in-scope).
    Also handles CSV with two columns: scope, target
    """
    in_scope, out_of_scope = [], []

    # Try two-column CSV first
    lines = [l.strip() for l in content.splitlines() if l.strip()]
    if lines and "," in lines[0]:
        reader = csv.reader(io.StringIO(content))
        for row in reader:
            if len(row) < 2:
                continue
            scope_marker = row[0].strip().lower()
            target = row[1].strip()
            if not target:
                continue
            entry = {"identifier": target, "type": _classify(target)}
            if scope_marker in ("out", "exclude", "excluded", "false", "no", "-"):
                out_of_scope.append(entry)
            else:
                in_scope.append(entry)
    else:
        for line in lines:
            if line.startswith("#") or not line:
                continue
            if line.startswith("-"):
                raw = line[1:].strip()
                if raw:
                    out_of_scope.append({"identifier": raw, "type": _classify(raw)})
            else:
                raw = line.lstrip("+").strip()
                if raw:
                    in_scope.append({"identifier": raw, "type": _classify(raw)})

    return {"in_scope": in_scope, "out_of_scope": out_of_scope, "format": "generic"}


def auto_parse(content: str) -> dict:
    """Detect format and dispatch to the right parser."""
    first_line = content.splitlines()[0].lower() if content.strip() else ""
    if "asset_identifier" in first_line or "eligible_for_bounty" in first_line:
        return parse_hackerone(content)
    if "target" in first_line and ("category" in first_line or "severity" in first_line):
        return parse_bugcrowd(content)
    return parse_generic(content)


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
        raise HTTPException(400, "Provide a file or raw text")

    result = auto_parse(content.strip())
    return {
        "in_scope": result["in_scope"],
        "out_of_scope": result["out_of_scope"],
        "format_detected": result.get("format", "generic"),
        "total_in": len(result["in_scope"]),
        "total_out": len(result["out_of_scope"]),
    }

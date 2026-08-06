"""API protocol inventory beyond REST/OpenAPI/GraphQL (Codex cross-check Tier-2 #8): SOAP/WSDL + gRPC.

Apolaki is strong on REST/OpenAPI/GraphQL; SOAP/WSDL/gRPC were invisible to the planner. This adds INVENTORY
(not payloads): discover WSDL endpoints + operations, detect SOAP body-sink candidates, detect gRPC hints, and
record the protocol family so the planner can see the surface.

RAILS: inventory NEVER claims a vulnerability. A SOAP body candidate is a LEAD that (under existing safety
rules) routes to the XXE/XML check — it is not itself a finding. Off-scope service URLs found inside a WSDL
are rejected. Pure + offline (operates on already-fetched text/headers).
"""
from __future__ import annotations

import re
from xml.etree import ElementTree as ET

_WSDL_HINT = re.compile(r"""(?ix)
    (?:href|action|src|location)\s*=\s*['"]([^'"]*?(?:\?(?:single)?wsdl\b|\.wsdl)[^'"]*)['"]
""")
_SOAP_CT = ("application/soap+xml", "text/xml")
_GRPC_CT = ("application/grpc", "application/grpc-web", "application/grpc+proto", "application/grpc-web+proto")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def detect_wsdl_links(html: str, base_url: str = "") -> list:
    """WSDL URLs referenced from an HTML page (href/action/src with ?wsdl / ?singleWsdl / .wsdl). Relative
    links are joined onto base_url. Deduplicated, order-preserved."""
    from urllib.parse import urljoin
    out = []
    for m in _WSDL_HINT.finditer(html or ""):
        u = m.group(1).strip()
        u = urljoin(base_url, u) if base_url else u
        if u not in out:
            out.append(u)
    return out


def parse_wsdl(xml_text: str) -> dict:
    """Parse a WSDL document enough to SEED surface: service name, SOAP endpoint address(es), and operation
    names. Namespace-agnostic (WSDL 1.1/2.0, soap/soap12). Returns {} on unparseable input."""
    try:
        root = ET.fromstring(xml_text or "")
    except Exception:
        return {}
    service, endpoints, operations = None, [], []
    for el in root.iter():
        ln = _local(el.tag)
        if ln == "service" and el.get("name") and service is None:
            service = el.get("name")
        elif ln == "address":                                   # <soap:address location="..."/>
            loc = el.get("location")
            if loc and loc not in endpoints:
                endpoints.append(loc)
        elif ln == "endpoint" and el.get("address"):            # WSDL 2.0
            if el.get("address") not in endpoints:
                endpoints.append(el.get("address"))
        elif ln == "operation" and el.get("name"):
            if el.get("name") not in operations:
                operations.append(el.get("name"))
    if service is None and not endpoints and not operations:
        return {}
    return {"protocol": "soap", "service": service, "endpoints": endpoints, "operations": operations}


def detect_protocol(headers: dict = None, path: str = "", body: str = "", content_type: str = "") -> str:
    """Best-effort protocol family: 'grpc' | 'soap' | 'graphql' | 'rest'. Header/content-type/path/body hints
    only — never a probe."""
    h = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    ct = (content_type or h.get("content-type") or "").lower()
    p = (path or "").lower()
    b = (body or "")
    if any(ct.startswith(g) for g in _GRPC_CT) or "grpc" in h.get("te", "") or p.endswith(".proto"):
        return "grpc"
    if "soapaction" in h or "application/soap+xml" in ct or "envelope" in b.lower() and "soap" in b.lower():
        return "soap"
    if p.endswith("/graphql") or "graphql" in p or '"query"' in b and "{" in b:
        return "graphql"
    return "rest"


def soap_body_candidates(parsed: dict, in_scope=None) -> list:
    """SOAP endpoints -> XML body CANDIDATES (leads) that route to the existing XXE/XML check under existing
    safety rules. Off-scope endpoint URLs are rejected. Never a finding — candidate/requires-validation only."""
    out = []
    for url in (parsed or {}).get("endpoints", []) or []:
        if in_scope is not None and not in_scope(url):
            continue                                            # reject off-scope service URL from the WSDL
        out.append({
            "api_protocol": "soap", "target": url,
            "service": parsed.get("service"), "operations": parsed.get("operations", []),
            "confidence": "lead", "candidate": True, "requires_runtime_validation": True,
            "suggested_check": "xxe",
            "note": "SOAP XML body — candidate for the XXE/XML check under existing safety rules; not a finding.",
        })
    return out


def grpc_observation(headers: dict = None, url: str = "", content_type: str = "") -> dict:
    """A gRPC INVENTORY observation (no vuln claim). Returns None if no gRPC hint is present."""
    if detect_protocol(headers=headers, path=url, content_type=content_type) != "grpc":
        return None
    return {"api_protocol": "grpc", "target": url, "kind": "inventory_observation",
            "candidate": True, "requires_runtime_validation": True,
            "note": "gRPC surface observed (content-type/proto hint) — inventory only, no vulnerability claimed."}


def inventory(items: list) -> dict:
    """Aggregate protocol observations into a surface summary. Purely descriptive."""
    by_proto: dict = {}
    for it in items or []:
        proto = (it or {}).get("api_protocol") or "rest"
        by_proto.setdefault(proto, []).append((it or {}).get("target"))
    return {"protocols": sorted(by_proto.keys()), "by_protocol": by_proto,
            "count": sum(len(v) for v in by_proto.values()),
            "note": "API protocol inventory — surface only; no vulnerabilities are implied by inventory."}

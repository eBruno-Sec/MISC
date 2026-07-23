"""
Parse nmap NSE 'vuln'-category script output (XML) into truth-first leads.

The heavyweight NSE vuln scan runs the whole `vuln` script category (minus DoS),
which reports version- and behaviour-based weaknesses. Those are NOT exploit-
confirmed — an NSE "VULNERABLE" verdict is usually a version/heuristic match — so
every result is emitted as an advisory LEAD (candidate confidence), never a
confirmed finding. Same truth-first discipline Apolaki applies to ZAP alerts:
breadth without inflating the confirmed risk score.

Pure/deterministic and unit-tested; the tool wrapper does the subprocess.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

_STATE_RE = re.compile(r"State:\s*(LIKELY VULNERABLE|VULNERABLE|NOT VULNERABLE|UNKNOWN)", re.IGNORECASE)
_CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}", re.IGNORECASE)


def severity_for(output: str) -> str:
    """Map an NSE script's output to a severity, or '' when it is not a real vuln
    result (NOT VULNERABLE / no state / no CVE) so it is dropped rather than shown."""
    o = output or ""
    m = _STATE_RE.search(o)
    state = (m.group(1).upper() if m else "")
    if state == "VULNERABLE":
        return "high"
    if state == "LIKELY VULNERABLE":
        return "medium"
    if state == "NOT VULNERABLE" or state == "UNKNOWN":
        return ""                      # explicitly cleared — never a finding
    if _CVE_RE.search(o):              # names a CVE with no VULNERABLE state -> advisory
        return "low"
    return ""


def _state(output: str) -> str:
    m = _STATE_RE.search(output or "")
    return m.group(1).upper() if m else "REPORTED"


def _script_finding(script_el, target: str, where: str) -> dict:
    sid = script_el.get("id", "") or "nse"
    output = script_el.get("output", "") or ""
    sev = severity_for(output)
    if not sev:
        return None
    cves = sorted(set(c.upper() for c in _CVE_RE.findall(output)))
    state = _state(output)
    loc = f" ({where})" if where and where != "host" else ""
    return {
        "title": f"NSE {sid} — {state}{loc}",
        "severity": sev,
        # truth-first: NSE version/behaviour checks are advisory, so these are LEADS.
        "confidence": "candidate",
        "target": target,
        "evidence": output.strip()[:1500],
        "cve": ", ".join(cves),
        "cwe": "",
        "family": "nse_vuln",
        "tags": ["nmap", "nse", "vuln"] + cves,
        "description": (f"nmap NSE script '{sid}' reported {state} on {where or 'the target'} of {target}. "
                        "This is a version/behaviour-based network-vulnerability signal — confirm "
                        "exploitability before treating it as a real finding."),
        "impact": ("Depends on the specific CVE/weakness. NSE vuln checks can false-positive on a version "
                   "match alone, so validate the actual condition."),
        "reproduction_steps": [
            f"nmap -sV --script {sid} {target}",
            "Read the script output for the VULNERABLE state and any CVE ids",
            "Validate the underlying weakness manually before reporting"],
    }


def parse_nse_vuln(xml_text: str, target: str) -> list:
    """Return advisory leads from an nmap -oX NSE-vuln run (port + host scripts)."""
    out = []
    try:
        root = ET.fromstring(xml_text or "")
    except Exception:
        return out
    for host in root.findall(".//host"):
        for port in host.findall(".//port"):
            pid = port.get("portid", "")
            proto = port.get("protocol", "")
            svc = port.find("service")
            svcname = svc.get("name", "") if svc is not None else ""
            where = f"{pid}/{proto} {svcname}".strip()
            for scr in port.findall("script"):
                f = _script_finding(scr, target, where)
                if f:
                    out.append(f)
        for scr in host.findall("hostscript/script"):
            f = _script_finding(scr, target, "host")
            if f:
                out.append(f)
    return out

"""OT/ICS zone + process-impact modeling (Codex cross-check Tier-3 #12).

Apolaki already stays READ-ONLY for Modbus + EtherNet/IP. The missing layer is OT CONTEXT: Purdue level /
zone, asset role (engineering workstation / HMI / SCADA / PLC / historian), and process criticality — and
the discipline that process impact is POTENTIAL until an operator confirms the process context.

HARD SAFETY RAILS (enforced here):
  * No write coils/registers, no project upload/download, no firmware interaction, no unauthenticated state
    change, no physical process manipulation.
  * A service pack must DECLARE a safety_class; anything but "read_only" is rejected by default. Future OT
    protocols (DNP3 / OPC / Profinet / BACnet / S7) cannot be routed until a read-only safety class is
    declared for them.
  * Reported process impact stays "potential" unless the operator supplies confirmed process context.
Pure + offline.
"""
from __future__ import annotations

PURDUE = {
    0: "Level 0 — Physical Process",
    1: "Level 1 — Basic Control (PLC/RTU/IED)",
    2: "Level 2 — Supervisory Control (HMI/SCADA)",
    3: "Level 3 — Operations (Historian / Engineering Workstation)",
    4: "Level 4 — Enterprise / IT",
}

# port -> (asset role, purdue level, protocol)
_PORT_ROLE = {
    502: ("plc", 1, "modbus"), 44818: ("plc", 1, "enip"), 2222: ("plc", 1, "enip_io"),
    102: ("plc", 1, "s7"), 20000: ("plc", 1, "dnp3"), 47808: ("controller", 1, "bacnet"),
    34962: ("plc", 1, "profinet"), 4840: ("scada_server", 2, "opcua"), 789: ("plc", 1, "redlion"),
}
_ROLE_HINTS = (
    ("engineering_workstation", ("tia portal", "studio 5000", "rslogix", "unity pro", "engineering")),
    ("hmi", ("hmi", "wonderware", "factorytalk view", "wincc", "panelview")),
    ("scada_server", ("scada", "ignition", "clearscada", "opc")),
    ("historian", ("historian", "pi server", "osisoft")),
    ("plc", ("plc", "1756", "1769", "s7-", "modicon", "controllogix", "compactlogix")),
)

SAFETY_CLASSES = ("read_only", "ot_write", "state_change", "firmware")
# protocols with a DECLARED safety class Apolaki may route (read-only only)
# Kept in step with what service_router ACTUALLY routes. dnp3 and s7comm shipped as read-only engines
# (#107) but were never added here, so /intel/ot-context told an operator those protocols were not
# routeable while production service packs were routing them — the registry disagreeing with reality in
# the direction that understates what the tool touches, which is the worse direction for OT.
PROTOCOL_SAFETY = {"modbus": "read_only", "enip": "read_only",
                   "dnp3": "read_only", "s7comm": "read_only"}


def classify_asset(port: int = None, product_name: str = "", banner: str = "") -> dict:
    """Best-effort OT asset classification (role + Purdue level + zone). Read-only inference from port +
    product/banner hints; unknown is honestly unknown."""
    blob = ("%s %s" % (product_name or "", banner or "")).lower()
    role, level, protocol = None, None, None
    if port and int(port) in _PORT_ROLE:
        role, level, protocol = _PORT_ROLE[int(port)]
    for r, hints in _ROLE_HINTS:
        if any(h in blob for h in hints):
            role = r
            level = {"engineering_workstation": 3, "historian": 3, "hmi": 2, "scada_server": 2,
                     "plc": 1}.get(r, level)
            break
    if role is None:
        role, level = "unknown_ot_asset", None
    return {"role": role, "purdue_level": level, "zone": PURDUE.get(level, "unclassified OT zone"),
            "protocol": protocol}


def ot_asset_context(finding: dict) -> dict:
    """Turn a read-only ICS finding (Modbus/ENIP, family ics_ot) into OT asset context for the graph. Never
    asserts confirmed process impact."""
    f = finding or {}
    target = str(f.get("target") or "")
    port = None
    if ":" in target:
        try:
            port = int(target.rsplit(":", 1)[-1].split("/")[0])
        except Exception:
            port = None
    ctx = classify_asset(port=port, product_name=str(f.get("product") or ""),
                         banner=str(f.get("evidence") or ""))
    return {
        "ot_asset": target or f.get("id"), "role": ctx["role"], "purdue_level": ctx["purdue_level"],
        "zone": ctx["zone"], "protocol": ctx["protocol"], "criticality": "unknown",
        "process_context": "not_supplied",
        "note": "OT asset context inferred read-only; process criticality is unknown until an operator confirms.",
    }


def process_impact(asset_ctx: dict, operator_context: dict = None) -> dict:
    """Frame process impact. Without operator-confirmed process context it is POTENTIAL, never asserted."""
    ctx = asset_ctx or {}
    if operator_context and operator_context.get("confirmed"):
        return {"impact_class": "confirmed", "severity": operator_context.get("severity", "high"),
                "statement": "Confirmed process impact: %s" % operator_context.get("description", "operator-supplied"),
                "process": operator_context.get("process")}
    role = ctx.get("role", "OT asset")
    return {"impact_class": "potential", "severity": "high",
            "statement": ("Potential process impact: control-plane exposure on a %s (%s). Actual impact "
                          "depends on the physical process and stays POTENTIAL until an operator confirms "
                          "the process context." % (role, ctx.get("zone", "OT zone"))),
            "process": None}


def is_pack_allowed(pack: dict):
    """Gate an OT service pack by its DECLARED safety class. Undeclared or non-read-only (ot_write /
    state_change / firmware) is rejected by default. Returns (allowed: bool, reason: str)."""
    sc = (pack or {}).get("safety_class")
    if not sc:
        return False, "OT pack has no declared safety_class — rejected (must declare read_only)"
    if sc != "read_only":
        return False, "OT pack safety_class '%s' is not read_only — rejected by default (no writes to OT)" % sc
    return True, "read-only OT pack — allowed"


def can_route_protocol(protocol: str) -> bool:
    """A future OT protocol (DNP3/OPC/Profinet/...) can be routed only once a read-only safety class is
    declared for it in PROTOCOL_SAFETY."""
    return PROTOCOL_SAFETY.get((protocol or "").lower()) == "read_only"


def declare_protocol_safety(protocol: str, safety_class: str) -> bool:
    """Register a read-only safety class for an OT protocol so the planner may route it. Only 'read_only' is
    ever accepted."""
    if safety_class != "read_only":
        return False
    PROTOCOL_SAFETY[(protocol or "").lower()] = "read_only"
    return True

"""OT/ICS zone + process-impact modeling (Codex Tier-3 #12): ICS findings create OT asset context; impact is
POTENTIAL until operator-confirmed; ot_write packs rejected; future protocols need a declared safety class."""
import ot_context as O


def test_modbus_finding_creates_ot_asset_context():
    f = {"target": "modbus://10.0.0.5:502", "family": "ics_ot", "evidence": "Modicon PLC"}
    ctx = O.ot_asset_context(f)
    assert ctx["role"] == "plc" and ctx["purdue_level"] == 1
    assert "Level 1" in ctx["zone"] and ctx["criticality"] == "unknown"


def test_enip_finding_creates_ot_asset_context():
    f = {"target": "enip://10.0.0.6:44818", "family": "ics_ot", "product": "1756-EN2T ControlLogix"}
    ctx = O.ot_asset_context(f)
    assert ctx["role"] == "plc" and ctx["protocol"] == "enip"


def test_process_impact_is_potential_without_operator_context():
    ctx = O.ot_asset_context({"target": "modbus://10.0.0.5:502"})
    imp = O.process_impact(ctx)
    assert imp["impact_class"] == "potential" and "POTENTIAL" in imp["statement"]
    assert imp["process"] is None


def test_process_impact_confirmed_only_with_operator_context():
    ctx = O.ot_asset_context({"target": "modbus://10.0.0.5:502"})
    imp = O.process_impact(ctx, operator_context={"confirmed": True, "description": "boiler control",
                                                  "process": "boiler", "severity": "critical"})
    assert imp["impact_class"] == "confirmed" and imp["process"] == "boiler"


def test_ot_write_pack_is_rejected_by_default():
    ok, _ = O.is_pack_allowed({"name": "modbus_write_coil", "safety_class": "ot_write"})
    assert ok is False
    ok2, reason = O.is_pack_allowed({"name": "undeclared_pack"})
    assert ok2 is False and "declare" in reason.lower()
    ok3, _ = O.is_pack_allowed({"name": "modbus_read", "safety_class": "read_only"})
    assert ok3 is True


def test_future_protocol_needs_declared_safety_class_before_routing():
    """The GATE, tested with a protocol Apolaki does not route. This used dnp3 as its undeclared example
    and started failing the moment dnp3 was legitimately declared read-only — the test was coupled to
    which real protocols happen to be enabled rather than to the mechanism. `profinet` is a real
    industrial protocol with no engine here, so it stays undeclared and the gate stays testable.
    That dnp3/s7comm ARE now declared is asserted separately, in test_ics_real_stack."""
    assert O.can_route_protocol("modbus") is True and O.can_route_protocol("enip") is True
    assert O.can_route_protocol("profinet") is False           # no engine, so never routable
    assert O.declare_protocol_safety("profinet", "ot_write") is False   # only read_only is ever accepted
    assert O.declare_protocol_safety("profinet", "read_only") is True
    assert O.can_route_protocol("profinet") is True
    O.PROTOCOL_SAFETY.pop("profinet", None)                    # do not leak into other tests


def test_classify_asset_hints():
    assert O.classify_asset(product_name="Siemens WinCC HMI")["role"] == "hmi"
    assert O.classify_asset(product_name="OSIsoft PI Historian")["role"] == "historian"
    assert O.classify_asset(port=99999)["role"] == "unknown_ot_asset"

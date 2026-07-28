"""
Business-Logic Graph + logic-abuse test generator.

Scanners see routes and parameters; they do not see WORKFLOWS. This models the target's business
processes (checkout, refund, subscription) as ordered steps carrying properties — mandatory,
idempotent, monetary, terminal, prerequisites — and GENERATES the logic-abuse tests a human
consultant would try but a scanner can't derive:

  - replay a completed transaction / refund twice / apply a coupon twice   (non-idempotent money)
  - submit a negative amount or quantity                                    (monetary, client-trusted)
  - skip a mandatory step (payment, approval, verification)                 (server trusts UI order)
  - run steps out of order                                                 (unguarded state machine)

Deterministic: every test comes from the workflow STRUCTURE, so the same generator works on any
modelled or inferred workflow. `logic_tests` is pure + testable; `infer_workflows` maps discovered
routes to the built-in workflow templates so this runs black-box off recon output.
"""
from __future__ import annotations

_MONETARY = ("payment", "pay", "charge", "refund", "coupon", "discount", "wallet", "invoice",
             "order", "checkout", "transfer", "withdraw", "topup", "deluxe", "purchase")


# Built-in workflow templates — ordered steps with the properties that drive test generation.
WORKFLOWS = {
    "checkout": {"name": "Checkout / order placement", "steps": [
        {"id": "add_to_cart", "state": True},
        {"id": "apply_coupon", "monetary": True, "idempotent": False},
        {"id": "set_address", "mandatory": True},
        {"id": "payment", "mandatory": True, "monetary": True, "idempotent": False, "depends_on": ["set_address"]},
        {"id": "checkout", "terminal": True, "monetary": True, "idempotent": False, "depends_on": ["payment"]},
    ]},
    "refund": {"name": "Refund", "steps": [
        {"id": "request_refund", "monetary": True, "idempotent": False, "depends_on": ["order_completed"]},
        {"id": "approve_refund", "mandatory": True},
        {"id": "issue_refund", "terminal": True, "monetary": True, "idempotent": False, "depends_on": ["approve_refund"]},
    ]},
    "subscription": {"name": "Subscription / membership lifecycle", "steps": [
        {"id": "subscribe", "monetary": True, "idempotent": False},
        {"id": "cancel", "idempotent": False},
        {"id": "access_feature", "depends_on": ["subscribe"]},
    ]},
}

_HINTS = {
    "checkout": ("cart", "checkout", "order", "payment", "address", "coupon", "basket", "deliver"),
    "refund": ("refund", "chargeback", "return"),
    "subscription": ("subscri", "plan", "wallet", "deluxe", "membership", "billing", "invoice"),
}


def logic_tests(workflow: dict) -> list:
    """Generate abuse-test hypotheses from a workflow's structure. Each is a concrete thing to try
    plus WHY it works — not a confirmed finding."""
    steps = workflow.get("steps") or []
    ids = [s.get("id") for s in steps]
    out = []
    for s in steps:
        sid = s.get("id", "step")
        mon = bool(s.get("monetary")) or any(k in sid for k in _MONETARY)
        if s.get("idempotent") is False and (mon or s.get("state")):
            out.append({"kind": "replay_double_execute", "target": sid, "severity": "high",
                        "test": "Execute '%s' twice (replay the request) and check the effect applies more "
                                "than once." % sid,
                        "rationale": "A non-idempotent money/state action with no server-side guard lets an "
                                     "attacker double-refund, re-apply a coupon, or replay a completed order."})
        if mon:
            out.append({"kind": "negative_or_limit_value", "target": sid, "severity": "high",
                        "test": "Submit '%s' with a negative / out-of-range amount or quantity." % sid,
                        "rationale": "Monetary flows that trust a client value can be driven below zero (the "
                                     "shop pays you) or past intended limits."})
        if s.get("terminal"):
            out.append({"kind": "replay_completed", "target": sid, "severity": "medium",
                        "test": "Re-trigger '%s' after the workflow has already completed." % sid,
                        "rationale": "Replaying a completed terminal step can re-run fulfilment, re-charge or "
                                     "re-ship."})
        if s.get("mandatory"):
            out.append({"kind": "bypass_mandatory", "target": sid, "severity": "high",
                        "test": "Complete the workflow while skipping the mandatory step '%s'." % sid,
                        "rationale": "A mandatory control (payment, approval, verification) enforced only in "
                                     "the UI can be bypassed by calling the next step directly."})
        for dep in (s.get("depends_on") or []):
            out.append({"kind": "skip_prerequisite", "target": sid, "severity": "high",
                        "test": "Reach '%s' WITHOUT completing its prerequisite '%s'." % (sid, dep),
                        "rationale": "If the server re-checks state only on the client, the prerequisite step "
                                     "can be skipped."})
    if len([i for i in ids if i]) >= 2:
        out.append({"kind": "out_of_order", "target": ids[-1], "severity": "medium",
                    "test": "Invoke the steps out of order (e.g. '%s' before '%s')." % (ids[-1], ids[0]),
                    "rationale": "State machines that don't validate transition order let steps be jumped."})
    return out


def graph(workflow: dict) -> dict:
    """Nodes + edges for a single workflow (step -> step by order and by prerequisite)."""
    steps = workflow.get("steps") or []
    nodes = [{"id": s.get("id"), "props": [k for k in ("mandatory", "monetary", "terminal", "state")
                                           if s.get(k)] + (["non-idempotent"] if s.get("idempotent") is False else [])}
             for s in steps]
    edges = []
    for i in range(1, len(steps)):
        edges.append({"source": steps[i - 1].get("id"), "target": steps[i].get("id"), "rel": "then"})
    for s in steps:
        for dep in (s.get("depends_on") or []):
            edges.append({"source": dep, "target": s.get("id"), "rel": "requires"})
    return {"name": workflow.get("name"), "nodes": nodes, "edges": edges}


def infer_workflows(routes: list) -> list:
    """Map discovered routes/endpoints (from recon/harvest) to the built-in workflow templates that
    the target appears to implement — so this runs black-box off recon, no source needed."""
    joined = " ".join(str(r) for r in (routes or [])).lower()
    return [WORKFLOWS[k] for k, hints in _HINTS.items() if any(h in joined for h in hints)]


def analyze(routes: list) -> dict:
    """Full black-box pass: infer the workflows present, build their graphs, and generate the logic
    tests to run against each."""
    wfs = infer_workflows(routes)
    out = []
    for wf in wfs:
        out.append({"workflow": wf.get("name"), "graph": graph(wf), "tests": logic_tests(wf)})
    return {"workflows_detected": [w.get("name") for w in wfs], "detail": out,
            "test_count": sum(len(x["tests"]) for x in out)}

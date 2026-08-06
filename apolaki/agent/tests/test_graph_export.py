"""Sanitized OpenGraph export of the canonical AssetGraph (Codex Tier-2 #7): namespaced nodes, secrets as
refs only, topology edges are never attack paths, capability edges carry precondition + resulting capability."""
import json

import asset_graph as AG
import graph_export as GX


def _graph():
    g = AG.AssetGraph("test")
    h = g.observe("host", "10.0.0.1", label="10.0.0.1", tested=True)
    ep = g.observe("endpoint", "/admin", label="/admin", props={"reachable": "confirmed"})
    cap = g.observe("capability", "database_read", label="database_read")
    weakcap = g.observe("capability", "rce", label="rce")
    lead = g.observe("endpoint", "/maybe", label="/maybe")
    cred = g.observe("credential", "S3cr3t-Password-Value", label="admin:S3cr3t-Password-Value",
                     props={"secret": "S3cr3t-Password-Value"})
    pers = g.observe("persona", "admin", label="admin")
    g.link(h, ep, "exposes", confidence=0.6)              # topology
    g.link(ep, cap, "enables", confidence=0.95)           # capability, evidence-backed -> traversable
    g.link(lead, weakcap, "enables", confidence=0.3)      # capability, weak evidence -> NOT traversable
    g.link(pers, h, "authenticated_as", confidence=0.9)   # capability, temporary
    return g


def test_export_contains_namespaced_nodes_and_edges():
    ex = GX.export_graph(_graph(), scope="10.0.0.0/24", environment="lab")
    kinds = {n["kind"] for n in ex["nodes"]}
    assert {"Apolaki_Host", "Apolaki_Endpoint", "Apolaki_Capability", "Apolaki_Credential",
            "Apolaki_Persona"} <= kinds
    assert ex["scope"] == "10.0.0.0/24" and ex["environment"] == "lab"
    assert ex["format"] == "apolaki_opengraph/v1" and ex["edge_count"] == 4


def test_credential_node_is_hash_ref_only_and_no_secret_leaks():
    ex = GX.export_graph(_graph(), scope="s", environment="lab")
    cred = next(n for n in ex["nodes"] if n["kind"] == "Apolaki_Credential")
    assert cred["label"].startswith("ref:") and cred["properties"]["redacted"] is True
    assert cred["properties"]["ref"].startswith("ref:")
    # the raw secret value must appear NOWHERE in the whole export
    assert "S3cr3t-Password-Value" not in json.dumps(ex)


def test_topology_edges_are_not_attack_paths():
    ex = GX.export_graph(_graph(), scope="s")
    exposes = next(e for e in ex["edges"] if e["kind"] == "exposes")
    assert exposes["edge_class"] == "topology" and exposes["traversable"] is False


def test_capability_edges_carry_precondition_and_resulting_capability():
    ex = GX.export_graph(_graph(), scope="s")
    enables = [e for e in ex["edges"] if e["kind"] == "enables"]
    strong = next(e for e in enables if e["target"].endswith("database_read"))
    assert strong["edge_class"] == "capability" and strong["traversable"] is True
    assert strong["precondition"] and strong["resulting_capability"] == "database_read"


def test_weak_evidence_enables_is_capability_but_not_traversable():
    ex = GX.export_graph(_graph(), scope="s")
    weak = next(e for e in ex["edges"] if e["kind"] == "enables" and e["target"].endswith("rce"))
    assert weak["edge_class"] == "capability" and weak["traversable"] is False


def test_authenticated_as_is_temporary_capability_edge():
    ex = GX.export_graph(_graph(), scope="s")
    auth = next(e for e in ex["edges"] if e["kind"] == "authenticated_as")
    assert auth["edge_class"] == "capability" and auth["traversable"] is True
    assert auth.get("temporary") is True and "expires" in auth


def test_traversable_count_matches():
    ex = GX.export_graph(_graph(), scope="s")
    assert ex["traversable_edge_count"] == sum(1 for e in ex["edges"] if e["traversable"])
    assert ex["traversable_edge_count"] == 2          # strong enables + authenticated_as

"""Deterministic attack-graph pathfinding (§7, §8, §11)."""

from __future__ import annotations

from reasoning.attack_graph import AttackEdge, AttackGraph


def test_single_step_idor_path():
    g = AttackGraph()
    g.add_edge(
        AttackEdge(
            id="idor",
            technique="web.authorization.idor",
            requires=frozenset({"authenticated_user"}),
            provides=frozenset({"read_foreign_object"}),
            confidence=0.95,
            noise=1.0,
            risk=1.0,
        )
    )
    r = g.find_path({"authenticated_user"}, "read_foreign_object", strategy="shortest")
    assert r.found is True
    assert r.hops == 1
    assert r.technique_sequence == ["web.authorization.idor"]


def _two_path_graph() -> AttackGraph:
    g = AttackGraph()
    # Path A: one loud, low-confidence hop straight to admin.
    g.add_edge(
        AttackEdge(id="a_direct", technique="loud_direct", requires=frozenset({"u"}),
                   provides=frozenset({"admin"}), confidence=0.5, noise=10.0, risk=5.0, cost=1.0)
    )
    # Path B: two quiet, high-confidence hops to admin.
    g.add_edge(
        AttackEdge(id="b1", technique="quiet_token", requires=frozenset({"u"}),
                   provides=frozenset({"token"}), confidence=0.9, noise=1.0, risk=1.0, cost=1.0)
    )
    g.add_edge(
        AttackEdge(id="b2", technique="quiet_escalate", requires=frozenset({"token"}),
                   provides=frozenset({"admin"}), confidence=0.9, noise=1.0, risk=1.0, cost=1.0)
    )
    return g


def test_shortest_prefers_direct_hop():
    r = _two_path_graph().find_path({"u"}, "admin", strategy="shortest")
    assert r.found and r.hops == 1 and r.technique_sequence == ["loud_direct"]


def test_lowest_noise_prefers_quiet_two_hop():
    r = _two_path_graph().find_path({"u"}, "admin", strategy="lowest_noise")
    assert r.found and r.technique_sequence == ["quiet_token", "quiet_escalate"]
    assert r.total_noise == 2.0


def test_highest_confidence_prefers_quiet_path():
    r = _two_path_graph().find_path({"u"}, "admin", strategy="highest_confidence")
    assert r.found and r.technique_sequence == ["quiet_token", "quiet_escalate"]
    assert round(r.product_confidence, 3) == 0.81


def test_least_privilege_prefers_low_risk_path():
    r = _two_path_graph().find_path({"u"}, "admin", strategy="least_privilege")
    # Direct path risk 5.0 vs two-hop risk 2.0 -> two-hop wins.
    assert r.technique_sequence == ["quiet_token", "quiet_escalate"]
    assert r.total_risk == 2.0


def test_unreachable_goal():
    g = _two_path_graph()
    assert g.find_path({"u"}, "domain_admin", strategy="shortest").found is False


def test_goal_already_satisfied():
    r = _two_path_graph().find_path({"u", "admin"}, "admin", strategy="shortest")
    assert r.found is True and r.hops == 0


def test_unknown_strategy_raises():
    import pytest

    with pytest.raises(ValueError):
        _two_path_graph().find_path({"u"}, "admin", strategy="nope")

"""Tests for the bWAPP lab prover -- structure, lab wiring, and the generalized flip. No live bWAPP needed
(graceful degrade covers the network path)."""
from __future__ import annotations

import bwapp_solvers
import labs
import techniques as T


def test_prove_degrades_when_unreachable():
    r = bwapp_solvers.prove("http://127.0.0.1:1")     # nothing listening -> no oracle fires, never raises
    assert r["lab"] == "bwapp"
    assert r.get("confirmed") == [] or "error" in r


def test_probes_cover_the_generalizing_classes():
    classes = {p[0] for p in bwapp_solvers._PROBES}
    assert {"command_injection", "path_traversal", "reflected_xss", "sqli"} <= classes


def test_bwapp_registered_as_a_lab():
    assert "bwapp" in labs.list_labs()
    r = labs.solve("bwapp", "http://127.0.0.1:1")     # dispatches to the prover, graceful on unreachable
    assert r.get("lab") == "bwapp"


def test_bwapp_generalizes_command_injection_and_path_traversal():
    for tid in ("command_injection", "path_traversal", "reflected_xss"):
        assert "bwapp" in T.TECHNIQUES[tid]["validated_on"], tid
    # command_injection + path_traversal were DVWA-only; bWAPP is the 2nd lab -> generalized
    assert T.is_generalized(T.TECHNIQUES["command_injection"])
    assert T.is_generalized(T.TECHNIQUES["path_traversal"])

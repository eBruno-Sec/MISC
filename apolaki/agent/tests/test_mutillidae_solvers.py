"""Tests for the Mutillidae lab prover -- structure, lab wiring, and the open_redirect generalized flip.
No live Mutillidae needed (graceful degrade covers the network path)."""
from __future__ import annotations

import labs
import mutillidae_solvers
import techniques as T


def test_prove_degrades_when_unreachable():
    r = mutillidae_solvers.prove("http://127.0.0.1:1")
    assert r["lab"] == "mutillidae"
    assert r.get("confirmed") == [] or "error" in r


def test_probes_cover_the_target_classes():
    classes = {p[0] for p in mutillidae_solvers._PROBES}
    assert {"open_redirect", "path_traversal", "command_injection", "reflected_xss"} <= classes


def test_mutillidae_registered_as_a_lab():
    assert "mutillidae" in labs.list_labs()
    r = labs.solve("mutillidae", "http://127.0.0.1:1")
    assert r.get("lab") == "mutillidae"


def test_mutillidae_generalizes_open_redirect():
    assert "mutillidae" in T.TECHNIQUES["open_redirect"]["validated_on"]
    # open_redirect was Juice-Shop-only; Mutillidae is the 2nd lab -> generalized
    assert T.is_generalized(T.TECHNIQUES["open_redirect"])

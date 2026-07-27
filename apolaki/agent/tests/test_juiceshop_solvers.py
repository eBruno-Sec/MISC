"""Tests for the Juice Shop lab-mode solver pack (structure + safety + graceful degrade)."""
from __future__ import annotations

import inspect

import juiceshop_solvers as js
import labs


def test_module_exposes_solve_and_steps():
    assert callable(js.solve)
    for fn in ("_sqli_logins", "_known_cred_logins", "_registrations", "_resets",
               "_beacon_visits", "_uploads", "_basket_manipulate", "_feedback", "_reviews"):
        assert callable(getattr(js, fn))


def test_no_bruteforce_or_dos_in_pack():
    src = inspect.getsource(js)
    # single known values only — never iterate a password/answer LIST
    assert "for pw in" not in src and "wordlist" not in src.lower()
    # never trigger the DoS challenges
    assert "xxeDos" not in src and "Memory Bomb" not in src and "billion" not in src.lower()


def test_solve_graceful_on_unreachable_target():
    r = js.solve("http://127.0.0.1:1")     # connection refused → fast, no raise
    assert isinstance(r, dict)
    assert r.get("lab") == "juiceshop" or "error" in r


def test_labs_solve_dispatch():
    assert callable(labs.solve)
    unknown = labs.solve("nope", "http://x")
    assert "error" in unknown and "juiceshop" in unknown.get("available", [])

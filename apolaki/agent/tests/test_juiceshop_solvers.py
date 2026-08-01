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
    # DoS challenges may be CATALOGUED as deliberately skipped, but must never be SOLVED:
    # none of them may appear in the solve manifest, and none is actually exploited.
    dos = {n for n, b in js._REMAINING_BUCKET.items() if b == "dos"}
    assert dos, "expected the DoS challenges to be catalogued as deliberately skipped"
    assert not (dos & set(js.SOLVE_MANIFEST)), "a DoS challenge must never be in the solve manifest"
    assert "xxeDos" not in src and "billion" not in src.lower()


def test_manifest_and_writeup_cover_the_same_challenges():
    # every solved-challenge write-up has a matching one-line technique tag, and vice versa
    assert set(js.SOLVE_DETAIL) == set(js.SOLVE_MANIFEST)
    assert len(js.SOLVE_MANIFEST) >= 85            # ~89 challenges catalogued
    assert all(js.SOLVE_MANIFEST.values())         # no blank technique tag
    assert all(js.SOLVE_DETAIL.values())           # no blank write-up


def test_conquest_graceful_and_dispatch():
    r = js.conquest("http://127.0.0.1:1")          # unreachable → returns, never raises
    assert isinstance(r, dict) and ("error" in r or r.get("lab") == "juiceshop")
    assert callable(labs.conquest)
    assert "error" in labs.conquest("nope", "http://x")


def test_solve_graceful_on_unreachable_target():
    r = js.solve("http://127.0.0.1:1")     # connection refused → fast, no raise
    assert isinstance(r, dict)
    assert r.get("lab") == "juiceshop" or "error" in r


def test_labs_solve_dispatch():
    assert callable(labs.solve)
    unknown = labs.solve("nope", "http://x")
    assert "error" in unknown and "juiceshop" in unknown.get("available", [])


def test_forged_coupon_url_encodes_the_z85_coupon():
    # regression: the z85 coupon contains #{}/ etc.; it MUST be url-encoded in the PUT path or the
    # '#' truncates it as a fragment -> "Invalid coupon" -> the challenge never solves.
    import inspect
    src = inspect.getsource(js._forged_coupon)
    assert "urllib.parse.quote(coupon" in src and "/coupon/%s" in src

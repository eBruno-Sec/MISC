"""Tests for the bWAPP lab prover -- structure, lab wiring, and response-oracle behaviour. No live bWAPP
needed (graceful degrade covers the network path)."""
from __future__ import annotations

import bwapp_solvers
import httpx
import labs


_VULNERABLE_RESPONSES = {
    ("POST", "/commandi.php", (), (("form", "submit"), ("target", "127.0.0.1; id"))):
        "PING 127.0.0.1 followed by uid=33(www-data) gid=33(www-data)",
    ("GET", "/directory_traversal_1.php", (("page", "../../../../../../etc/passwd"),), ()):
        "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
    ("GET", "/xss_get.php",
     (("firstname", "<script>alert(1)</script>"), ("form", "submit"), ("lastname", "z")), ()):
        "Welcome <script>alert(1)</script> z",
    ("GET", "/sqli_1.php", (("action", "search"), ("title", "iron'")), ()):
        "You have an error in your SQL syntax near iron",
}


class _ResponseClient:
    def __init__(self, responses):
        self.responses = responses

    @staticmethod
    def _key(method, path, params=None, data=None):
        return method, path, tuple(sorted((params or {}).items())), tuple(sorted((data or {}).items()))

    def get(self, path, params=None, **_kwargs):
        text = self.responses.get(self._key("GET", path, params=params), "clean response")
        return type("Response", (), {"text": text})()

    def post(self, path, params=None, data=None, **_kwargs):
        text = self.responses.get(self._key("POST", path, params=params, data=data), "clean response")
        return type("Response", (), {"text": text})()

    def close(self):
        pass


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


def test_synthetic_vulnerable_responses_fire_each_oracle(monkeypatch):
    monkeypatch.setattr(httpx, "Client", lambda **_kwargs: _ResponseClient(_VULNERABLE_RESPONSES))
    result = bwapp_solvers.prove("http://bwapp.test")
    assert result["probes"] == {
        "command_injection": True,
        "path_traversal": True,
        "reflected_xss": True,
        "sqli": True,
    }
    assert result["confirmed"] == ["command_injection", "path_traversal", "reflected_xss", "sqli"]


def test_clean_responses_fire_no_oracle(monkeypatch):
    monkeypatch.setattr(httpx, "Client", lambda **_kwargs: _ResponseClient({}))
    result = bwapp_solvers.prove("http://bwapp.test")
    assert result["probes"] == {
        "command_injection": False,
        "path_traversal": False,
        "reflected_xss": False,
        "sqli": False,
    }
    assert result["confirmed"] == []

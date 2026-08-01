"""Browser-login token selection: promote a VALIDATED token (real XHR Bearer preferred over a
storage JWT), not just the first eyJ-looking value (CHAD review #4). Pure."""
from __future__ import annotations

import base64

import tools


def _jwt(payload: str) -> str:
    h = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    p = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
    return h + "." + p + ".sig"


def test_valid_jwt():
    assert tools._valid_jwt(_jwt('{"sub":"carlos","email":"c@x"}'))
    assert not tools._valid_jwt("not.a.jwt")
    assert not tools._valid_jwt("eyJ.only")                 # wrong part count
    assert not tools._valid_jwt("randomstring")
    assert not tools._valid_jwt(_jwt("not-json"))           # payload not JSON


def test_pick_session_token_prefers_real_xhr_bearer():
    storage_tok = _jwt('{"sub":"storage"}')
    xhr_tok = _jwt('{"sub":"real"}')
    assert tools._pick_session_token([storage_tok], ["Bearer " + xhr_tok]) == xhr_tok   # XHR wins
    assert tools._pick_session_token([storage_tok], []) == storage_tok                  # storage fallback
    assert tools._pick_session_token(["not-a-token", "12345"], []) is None              # junk ignored

"""Token-in-JSON (bearer) login extraction (auth artery fix): auth.login must recover a bearer/JWT token from
a JSON login response (Juice Shop {authentication:{token}}, {access_token}, {data:{token}}, ...), not just a
Set-Cookie. This is what unlocks authenticated scanning on modern SPA/REST APIs."""
import auth


def test_find_token_juiceshop_shape():
    tok = "a" * 40
    assert auth._find_token({"authentication": {"token": tok, "bid": 1, "umail": "x@y"}}) == tok


def test_find_token_common_shapes():
    tok = "b" * 30
    assert auth._find_token({"access_token": tok}) == tok
    assert auth._find_token({"data": {"token": tok}}) == tok
    assert auth._find_token({"result": {"jwt": tok}}) == tok
    assert auth._find_token({"accessToken": tok}) == tok          # camelCase normalizes
    assert auth._find_token({"id_token": tok}) == tok


def test_find_token_rejects_non_tokens():
    assert auth._find_token({"token": "short"}) is None            # too short to be a token
    assert auth._find_token({"user": {"email": "a@b.com"}}) is None
    assert auth._find_token({}) is None
    assert auth._find_token(None) is None
    assert auth._find_token({"nested": {"deep": {"deep2": {"deep3": {"deep4": {"token": "x" * 40}}}}}}) is None  # depth-capped


def test_find_token_bounded_and_safe():
    # a big list doesn't blow up; first plausible token wins
    tok = "c" * 50
    assert auth._find_token({"sessions": [{"token": tok}]}) == tok


def test_safe_json_never_raises():
    class _R:
        def json(self):
            raise ValueError("not json")
    assert auth._safe_json(_R()) is None

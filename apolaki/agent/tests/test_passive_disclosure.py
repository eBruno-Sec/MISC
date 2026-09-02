"""Q-148 -- passive content disclosure, mined from Burp's published issue catalog.

EVERY CHECK HERE SHIPS BOTH HALVES OF ITS GROUND TRUTH, constructed by hand: a POSITIVE that must
fire, and an ORDINARY-PAGE LOOKALIKE that must not. That pairing is the entire ticket, because
regex-shaped disclosure checks are the classic false-positive generator and this repo has just spent
a week deleting ~330 of them.

THE FIELD FAILURE THIS FAMILY IS WRITTEN AGAINST is in
`test_exposure_catchall_is_not_a_file.py`: a CRITICAL "Exposed .env file" against a WordPress
install with no .env, caused by `re.I` on a case-BEARING signature and `\\s` matching newlines.

NO FIXTURE HERE CONTAINS A REAL-LOOKING LIVE CREDENTIAL. `4111111111111111` is the industry test
PAN, `078-05-1120` is the SSN printed on the 1938 Woolworth specimen card and the standard example
ever since, and every key body is the literal base64 of ASCII text.
"""
from __future__ import annotations

import passive_disclosure as pd


# ═══════════════════════════════════════════════════════════════════════════════════════════════
# 1. PRIVATE KEY DISCLOSED
#
# `-----BEGIN ... PRIVATE KEY-----` is 30 characters of fixed uppercase text that no template
# engine emits by accident, so this is the near-zero-FP member of the family. The FP that DOES
# exist is documentation, which shows the armour with the key elided.

#: base64("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") repeated -- obviously synthetic, and >100 chars
#: of base64 alphabet so it clears the key-material floor.
_FAKE_KEY_BODY = "\n".join(["QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5"] * 3)


def _pem(kind="RSA ", body=None):
    body = _FAKE_KEY_BODY if body is None else body
    return ("-----BEGIN %sPRIVATE KEY-----\n%s\n-----END %sPRIVATE KEY-----\n"
            % (kind, body, kind))


def test_a_pem_private_key_block_is_critical():
    got = pd.find_private_keys("<html><body>oops\n%s</body></html>" % _pem())
    assert [f["check"] for f in got] == ["private_key_disclosed"], got
    assert got[0]["severity"] == "critical", got


def test_the_key_material_is_never_quoted_into_the_finding():
    """A finding that carries the key INTO THE REPORT is itself a disclosure -- the report then
    hands the key to everyone the report reaches."""
    got = pd.find_private_keys(_pem())
    assert got
    rendered = repr(got[0])
    assert _FAKE_KEY_BODY.split("\n")[0] not in rendered, rendered
    assert "<redacted:" in got[0]["evidence"], got[0]["evidence"]
    assert got[0]["location"]["line"] == 1, got[0]["location"]


def test_every_private_key_flavour_is_caught():
    for kind in ("RSA ", "EC ", "DSA ", "OPENSSH ", "", "ENCRYPTED "):
        assert pd.find_private_keys(_pem(kind)), kind


# -- negative controls ---------------------------------------------------------

def test_a_documentation_page_showing_the_armour_is_not_a_disclosure():
    """NEGATIVE CONTROL. Every PEM tutorial on the internet looks exactly like this."""
    doc = ("<h1>Configure TLS</h1><p>Paste your key:</p>"
           "-----BEGIN RSA PRIVATE KEY-----\n"
           "MIIEowIBAAKCAQEA... your private key goes here ...\n"
           "-----END RSA PRIVATE KEY-----")
    assert pd.find_private_keys(doc) == []


def test_a_public_key_or_certificate_is_not_a_private_key():
    """NEGATIVE CONTROL. Serving a public key or a certificate is the intended behaviour."""
    for kind in ("PUBLIC KEY", "CERTIFICATE", "CERTIFICATE REQUEST"):
        body = "-----BEGIN %s-----\n%s\n-----END %s-----" % (kind, _FAKE_KEY_BODY, kind)
        assert pd.find_private_keys(body) == [], kind


def test_armour_with_no_key_material_is_prose_not_a_key():
    """NEGATIVE CONTROL. A blog post naming the format, or a truncated snippet."""
    assert pd.find_private_keys("-----BEGIN RSA PRIVATE KEY-----\nQUJD\n-----END RSA PRIVATE KEY-----") == []
    assert pd.find_private_keys("we store the -----BEGIN RSA PRIVATE KEY----- header in the vault") == []


def test_a_templated_key_is_not_a_leaked_key():
    """NEGATIVE CONTROL. A rendered config template with the secret still unsubstituted."""
    for filler in ("${TLS_PRIVATE_KEY}", "{{ tls.key }}", "%PRIVATE_KEY%", "<REDACTED>"):
        body = "-----BEGIN PRIVATE KEY-----\n%s\n%s\n-----END PRIVATE KEY-----" % (
            _FAKE_KEY_BODY, filler)
        assert pd.find_private_keys(body) == [], filler


def test_the_placeholder_words_do_not_cause_false_negatives_inside_base64():
    """The FP control must not eat real keys: `paste` and `example` occur inside base64 by chance,
    so the word alternatives carry non-alphanumeric lookarounds. Without them this key is missed."""
    body = ("QUJDpasteRUZHSElKS0xNTk9QUVJTVFVWV1hZWjAxMjM0NTY3ODlleampleQUJDREVGR0hJSg"
            "RUZHSElKS0xNTk9QUVJTVFVWV1hZWjAxMjM0NTY3ODlpbnNlcnRQUVJTVFVWV1hZWg==")
    assert len(body) > 100
    assert pd.find_private_keys(_pem(body="\n".join([body]))) != []


# ═══════════════════════════════════════════════════════════════════════════════════════════════
# 2. JWK PRIVATE KEY / JWKS
#
# STRUCTURAL, NOT GREP. `"d"` appears in any JSON document. `"d"` carrying 20+ base64url characters
# inside the SAME OBJECT as `"kty"` is an RSA/EC private exponent and nothing else.

_PUB = '{"kty":"RSA","kid":"sig-1","alg":"RS256","use":"sig","n":"0vx7agoebGcQSuu","e":"AQAB"}'
_PRIV = ('{"kty":"RSA","kid":"sig-1","alg":"RS256","n":"0vx7agoebGcQSuu","e":"AQAB",'
         '"d":"X4cTteJY_gn4FYPsXB8rdXixQkRmzLmnpAtQGeeaSp"}')


def test_a_jwk_with_a_private_exponent_is_critical():
    got = pd.find_jwk_private_keys('{"keys":[%s]}' % _PRIV)
    assert [f["check"] for f in got] == ["jwt_private_key_disclosed"], got
    assert got[0]["severity"] == "critical", got
    assert "<redacted:42>" in got[0]["evidence"], got[0]["evidence"]


def test_an_oct_jwk_symmetric_key_counts_as_private():
    got = pd.find_jwk_private_keys('{"kty":"oct","kid":"hs","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMko"}')
    assert [f["check"] for f in got] == ["jwt_private_key_disclosed"], got


def test_a_public_jwks_is_informational_only():
    """NEGATIVE CONTROL, and the one that matters most: a JWKS of PUBLIC keys is published on
    purpose at a well-known URL. Calling it critical would flag every OIDC provider alive."""
    got = pd.find_jwk_private_keys('{"keys":[%s]}' % _PUB)
    assert got == [], got
    info = pd.find_jwks('{"keys":[%s]}' % _PUB)
    assert [f["check"] for f in info] == ["jwks_disclosed"], info
    assert info[0]["severity"] == "info" and info[0]["confidence"] == "informational", info


def test_a_private_jwks_does_not_also_emit_the_informational_row():
    """One document, one finding. The critical must not be diluted by an info row beside it."""
    assert pd.find_jwks('{"keys":[%s]}' % _PRIV) == []


def test_a_d_in_a_neighbouring_object_is_not_this_key_s_private_exponent():
    """THE ONE THAT SEPARATES A STRUCTURAL ORACLE FROM A GREP. A document-wide search for `"kty"`
    and `"d"` says yes here; walking to the enclosing object says no, correctly."""
    doc = ('{"keys":[%s],"debug":{"d":"X4cTteJY_gn4FYPsXB8rdXixQkRmzLmnpAtQGeeaSp"}}' % _PUB)
    assert '"kty"' in doc and '"d":' in doc
    assert pd.find_jwk_private_keys(doc) == []


def test_an_ordinary_json_document_with_a_d_field_is_not_a_jwk():
    """NEGATIVE CONTROL. `"d"` is a perfectly ordinary key name."""
    assert pd.find_jwk_private_keys(
        '{"path":{"d":"M150 0 L75 200 L225 200 Z_padding_padding"},"fill":"#fff"}') == []


def test_a_short_private_member_is_not_key_material():
    """NEGATIVE CONTROL. A real EC private scalar is 43 base64url characters; `"d":"1"` is a flag."""
    assert pd.find_jwk_private_keys('{"kty":"EC","crv":"P-256","d":"1","x":"aa","y":"bb"}') == []


def test_a_json_document_that_is_not_a_key_set_is_not_a_jwks():
    """NEGATIVE CONTROL for the informational check: `"keys"` alone is a common field name."""
    assert pd.find_jwks('{"keys":["alpha","beta"],"count":2}') == []


# ═══════════════════════════════════════════════════════════════════════════════════════════════
# 3. DATABASE CONNECTION STRING
#
# A connection string in a DOCS page is more common than one in a leak, and it is the same string
# minus a real credential. The placeholder vocabulary is the whole FP control.

def test_a_uri_connection_string_with_a_real_credential_is_reported():
    got = pd.find_connection_strings(
        "DATABASE_URL=postgres://svc_billing:Kj8sQ2vHn4Lp@db.internal:5432/billing")
    assert [f["check"] for f in got] == ["db_connection_string_disclosed"], got
    assert got[0]["severity"] == "high"
    assert "Kj8sQ2vHn4Lp" not in repr(got[0]), got[0]
    assert "svc_billing" in got[0]["evidence"], got[0]["evidence"]


def test_every_supported_dialect_is_caught():
    for uri in ("mysql://app:R3alPassw0rd@10.0.0.5/shop",
                "mongodb+srv://root:R3alPassw0rd@cluster0.example.net/db",
                "redis://default:R3alPassw0rd@cache.internal:6379",
                "jdbc:postgresql://app:R3alPassw0rd@pg.internal:5432/app",
                "amqps://svc:R3alPassw0rd@broker.internal:5671/%2f"):
        assert pd.find_connection_strings(uri), uri


def test_a_key_value_connection_string_with_a_real_credential_is_reported():
    got = pd.find_connection_strings(
        "Server=sql01.corp.local;Database=payments;User Id=app_rw;Password=Zx9qR2mLt;")
    assert [f["check"] for f in got] == ["db_connection_string_disclosed"], got
    assert "Zx9qR2mLt" not in repr(got[0]), got[0]


# -- negative controls ---------------------------------------------------------

def test_the_quickstart_connection_string_is_not_a_leak():
    """NEGATIVE CONTROL. This exact line is in every database quickstart ever written."""
    doc = ("<h2>Configure the database</h2><pre>DATABASE_URL=postgres://user:password@localhost:5432/mydb"
           "\nDATABASE_URL=mysql://root:pass@127.0.0.1/example</pre>")
    assert pd.find_connection_strings(doc) == []


def test_the_canonical_dotnet_documentation_string_is_not_a_leak():
    """NEGATIVE CONTROL. The connectionstrings.com canonical example, verbatim."""
    assert pd.find_connection_strings(
        "Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword;") == []


def test_an_unsubstituted_template_credential_is_not_a_leak():
    """NEGATIVE CONTROL. A rendered chart or compose file with the secret still a variable."""
    for filler in ("${DB_PASSWORD}", "{{db.password}}", "%DBPASS%", "changeme", "****"):
        assert pd.find_connection_strings(
            "postgres://app:%s@db.internal:5432/app" % filler) == [], filler


def test_a_password_field_with_no_server_beside_it_is_not_a_connection_string():
    """NEGATIVE CONTROL. `password=` on its own is a form field or a query parameter. The
    server/database key is REQUIRED, and that requirement is what stops this check from firing on
    every login page on the target."""
    assert pd.find_connection_strings("action=login&password=Zx9qR2mLt&remember=1") == []


def test_an_empty_or_trivial_credential_is_not_a_credential():
    assert pd.find_connection_strings("Server=db;Database=app;Password=;") == []
    assert pd.find_connection_strings("Server=db;Database=app;Password=x;") == []


def test_html_markup_naming_a_password_input_is_not_a_connection_string():
    """NEGATIVE CONTROL built from the shape that produced the .env false positive: ordinary
    markup that a loose `password.*=` pattern reads as a credential assignment."""
    markup = ('<form action="/login" method="post"><input name="password" type="password">'
              '<input name="database" value="primary"><button>Sign in</button></form>')
    assert pd.find_connection_strings(markup) == []


# =================================================================================================
# BREAKER REGRESSION -- three FALSE HIGHS/CRITICALS this module produced on ordinary pages.
#
# Every case below is the Breaker's own reported input, kept verbatim. A false CRITICAL is a false
# accusation: it costs HackerOne Signal, and Signal costs invitations. These are the exact bodies
# that fired, so a regression is caught by the input that caused it rather than by a paraphrase.
# =================================================================================================

def test_a_documentation_page_showing_an_example_private_key_is_not_a_disclosure():
    """FINDING 2. `display_spans`/`_inside` existed to suppress exactly this and had ZERO CALLERS --
    the FP control was written, tested, and never wired, so any docs page illustrating a PEM was a
    CRITICAL. Dead code is not a control."""
    docs = ('<h2>Generating a key</h2><p>Your key file will look like this:</p>'
            '<pre><code>-----BEGIN RSA PRIVATE KEY-----\n'
            'MIIEowIBAAKCAQEAx7Vn9kZ2mQ8jf0pL3sWqR5tYbNcE1hGvUxK4dP6aSzMlOiJr\n'
            'nQvT8yUeWfB2oGdHl5AqXsZ0iMcRyE9tKpLvNbXjWgFuD3hSaOe7YrCzQ1mItPkV\n'
            'uHgB4NxWZlQfSdE6TcOa9rYmJvKpX2iRbAzGnLwUe0MhDySqCtVjFoP5kNXBIu8g\n'
            '-----END RSA PRIVATE KEY-----</code></pre>'
            '<p>Never commit this file.</p>')
    assert [f["check"] for f in pd.find_private_keys(docs)] == []


def test_a_real_leaked_private_key_still_fires():
    """The other half of the same fix. Suppressing the docs page must not suppress the leak -- a
    control that silences both is not a control either."""
    leak = ('-----BEGIN RSA PRIVATE KEY-----\n'
            'MIIEowIBAAKCAQEAx7Vn9kZ2mQ8jf0pL3sWqR5tYbNcE1hGvUxK4dP6aSzMlOiJr\n'
            'nQvT8yUeWfB2oGdHl5AqXsZ0iMcRyE9tKpLvNbXjWgFuD3hSaOe7YrCzQ1mItPkV\n'
            'uHgB4NxWZlQfSdE6TcOa9rYmJvKpX2iRbAzGnLwUe0MhDySqCtVjFoP5kNXBIu8g\n'
            '-----END RSA PRIVATE KEY-----')
    assert [f["check"] for f in pd.find_private_keys(leak)] == ["private_key_disclosed"]


def test_a_public_jwks_containing_a_nested_d_member_is_not_a_private_key():
    """FINDING 3. The private-member search ran over the whole object SLICE, nested objects
    included, so any public JWKS carrying a nested `d` was a CRITICAL -- fired on
    `/.well-known/jwks.json`, which is public BY DESIGN. `d` at top level means private; `d`
    three braces down is somebody else's field."""
    public = ('{"keys":[{"kty":"RSA","kid":"a1","use":"sig","n":"0vx7ag","e":"AQAB",'
              '"x5c":["MIIDQ"],"meta":{"rotation":{"d":30,"unit":"days"}}}]}')
    assert [f["check"] for f in pd.find_jwk_private_keys(public)] == []


def test_a_genuinely_private_jwk_still_fires():
    """`d` as a TOP-LEVEL member of the key object is the RFC 7517 private exponent."""
    private = '{"kty":"RSA","kid":"a1","n":"0vx7ag","e":"AQAB","d":"X4cTteJY_gn4FYPsXB8rd"}'
    assert [f["check"] for f in pd.find_jwk_private_keys(private)] == ["jwt_private_key_disclosed"]


def test_host_and_password_on_different_lines_are_not_a_connection_string():
    """FINDING 4. The 200-char window crossed NEWLINES while the constant's own comment said `a
    .NET connection string is one line`. A settings panel with the two keys four HTML lines apart
    was reported HIGH. The comment was right; the code did not implement it."""
    # The keys sit ~70 characters apart -- WELL INSIDE the 200-char window -- and are separated
    # only by NEWLINES. The first version of this fixture used realistic long markup, which put
    # them 223 chars apart, so it passed on window LENGTH and survived the mutant that restored
    # the newline-crossing window. A control that passes for a reason other than the fix is not
    # a control.
    panel = ('<div>host=db.internal</div>\n'
             '<div>5432</div>\n'
             '<div>svcaccount</div>\n'
             '<input password=Winter2024>')
    assert pd.find_connection_strings(panel) == []


def test_a_url_query_string_carrying_a_password_is_not_a_connection_string():
    """FINDING 4, second half. A single anchor satisfied every other clause. A key-value DSN
    separates pairs with `;`; a query string uses `&`. That separator is the whole difference, and
    it is what distinguishes the two rather than a heuristic about how the page looks."""
    anchor = '<a href="/legacy/login.jsp?uid=jdoe&password=Winter2024">Legacy sign-in</a>'
    assert pd.find_connection_strings(anchor) == []


def test_a_real_one_line_dsn_still_fires():
    """The positive control that keeps the two fixes above honest."""
    dsn = "Server=db.internal;Database=prod;Uid=svc;Password=S3cretPw99;"
    assert [f["check"] for f in pd.find_connection_strings(dsn)] == ["db_connection_string_disclosed"]

"""Credentials parked in comments (#125) — found by walking OverTheWire Natas.

Natas level 0 serves the next level's password inside an HTML comment, in the shape reproduced below.
Apolaki fetched that page, ran scan_secrets and scan_comments, and reported nothing: the value has no
vendor prefix so the secret patterns miss it, and the comment carries no todo/fixme so the comment
scanner ignores it. Two scanners, one blind spot between them.

The token below is SYNTHETIC — the same shape (32 chars, mixed case, no vendor prefix) as the live one,
not the value itself. Committing a real third-party credential is the exact practice
`scan_comment_secrets` exists to flag, and publishing wargame answers spoils the level for everyone
else. Shape alone fully exercises the detector, so nothing is lost.
"""
import codereview as cr

NATAS0 = """<div id="content">
You can find the password for the next level on this page.

<!--The password for natas1 is K3pTaQ7vZmXr2NbYwLcE9dHsUgFj6Ai4 -->
</div>"""


def test_the_natas_case_is_detected():
    hits = cr.scan_comment_secrets(NATAS0)
    assert hits, "the exact live case that motivated this still slips through"
    assert hits[0]["value"] == "K3pTaQ7vZmXr2NbYwLcE9dHsUgFj6Ai4"
    assert hits[0]["severity"] == "high"


def test_neither_existing_scanner_catches_it():
    """Documents WHY this exists — if either of these starts passing, this engine is redundant."""
    assert cr.scan_secrets(NATAS0) == []
    assert cr.scan_comments(NATAS0) == []


def test_comment_styles_are_all_covered():
    for body in ('<!-- password: Sup3rSecretValue123 -->',
                 '/* api_key = ak_live_9f8e7d6c5b4a3f2e1d */',
                 '// token: ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123',
                 '# secret is my-production-secret-42'):
        assert cr.scan_comment_secrets(body), body


def test_placeholders_are_not_reported():
    """A documentation comment is not a leak. This is the false-positive guard."""
    for body in ('<!-- password: your-password-here -->',
                 '<!-- password: CHANGEME -->',
                 '// token: <YOUR_TOKEN>',
                 '# api_key = xxxxxxxxxxxxxxxx',
                 '/* password: ******** */',
                 '<!-- password: {{ secret }} -->',
                 '// password: placeholder'):
        assert cr.scan_comment_secrets(body) == [], body


def test_a_url_is_not_a_line_comment():
    """Found on the first live page tested: without a lookbehind, the // in http:// reads as a line
    comment and the rest of the line becomes a 'comment body', manufacturing findings out of markup."""
    page = ('<link rel="stylesheet" href="http://host.example/css/level.css">\n'
            '<script src="http://host.example/js/app.js?password=notreallyasecret"></script>')
    assert cr.scan_comment_secrets(page) == []


def test_a_hash_inside_a_url_fragment_is_not_a_comment():
    assert cr.scan_comment_secrets('<a href="/x#password=abcdefgh12345678">y</a>') == []


def test_short_values_and_prose_are_ignored():
    assert cr.scan_comment_secrets("<!-- password: abc -->") == []
    assert cr.scan_comment_secrets("<!-- remember to hash the password before storing -->") == []


def test_code_outside_a_comment_is_not_a_comment_finding():
    """Only COMMENT bodies — a password variable in live code is a different class."""
    assert cr.scan_comment_secrets('password = "RealLookingValue123"') == []


def test_results_are_deduped_and_bounded():
    many = "\n".join('<!-- password: uniqueSecretValue%03d -->' % i for i in range(40))
    hits = cr.scan_comment_secrets(many)
    assert 0 < len(hits) <= 15
    assert len({h["value"] for h in hits}) == len(hits)


def test_finding_is_emitted_by_the_analyzer():
    findings = cr.analyze(NATAS0, source="https://t/index.html") if hasattr(cr, "analyze") else None
    if findings is None:
        import pytest
        pytest.skip("analyzer entry point named differently")
    creds = [f for f in findings if f.get("cwe") == "CWE-615"]
    assert creds and creds[0]["confidence"] == "confirmed"
    assert "K3pTaQ" not in creds[0]["evidence"], "evidence must not restate the secret itself"

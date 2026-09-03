"""Q-170. A line comment ends at the end of the line.

THE DEFECT, measured on jquery.js as served by mutillidae. `_ANY_COMMENT` opens with `(?s)`, which
is DOTALL for the WHOLE pattern -- including the `//` branch's `(.*)$`. So `.` matched newlines
there too, and the greedy `.*` ran to the end of the file before backtracking to the last `$`.

One `//` comment therefore absorbed the following lines INCLUDING CODE, and a token sitting in that
code was reported as:

    Credential exposed in a source comment    HIGH    confidence=confirmed

against a vendored third-party library. Three harms out of one quantifier:

  1. a value in CODE attributed to a COMMENT -- the finding's central claim was false
  2. the wrong line number, so nobody could check it
  3. every later `//` comment silently never scanned as its own body -- a false NEGATIVE hiding
     behind the false positive

The negative direction is tested as hard as the positive one, because "find no comments at all"
would also make the false positive disappear.
"""
import codereview as cr


CODE_AFTER_COMMENT = "\n".join([
    "var a = 1;",
    "// A central reference to the root jQuery(document)",
    "rootjQuery,",
    "// The deferred used on DOM ready",
    "readyList,",
    "var config = { token: 'abcdefgh12345678' };",
])


def test_a_line_comment_does_not_swallow_the_code_beneath_it():
    """THE regression: the token lives in CODE, not in a comment."""
    found = cr.scan_comment_secrets(CODE_AFTER_COMMENT)
    assert found == [], (
        "a value in source CODE was reported as a credential parked in a comment: %r" % (found,))


def test_each_line_comment_is_scanned_as_its_own_body():
    """The false NEGATIVE half. A greedy match reports one comment where there are two."""
    bodies = []
    for m in cr._ANY_COMMENT.finditer(CODE_AFTER_COMMENT):
        body = next((g for g in m.groups() if g), "") or ""
        bodies.append((cr._line_of(CODE_AFTER_COMMENT, m.start()), body))
    assert len(bodies) == 2, "expected both line comments, got %r" % (bodies,)
    assert bodies[0] == (2, "A central reference to the root jQuery(document)")
    assert bodies[1] == (4, "The deferred used on DOM ready")
    for _line, body in bodies:
        assert "\n" not in body, "a line comment body must not span lines: %r" % body


def test_a_real_one_line_credential_is_still_caught():
    """Positive control. Narrowing the match must not blind the detector."""
    found = cr.scan_comment_secrets("// password: s3cr3tValue123\nvar x = 1;")
    assert [f["value"] for f in found] == ["s3cr3tValue123"]
    assert found[0]["line"] == 1


def test_block_and_html_comments_still_span_lines():
    """DOTALL is correct for these two: they really are multi-line constructs."""
    html = "<!--\n  password: hunter2seventeen\n  more text\n-->"
    assert [f["value"] for f in cr.scan_comment_secrets(html)] == ["hunter2seventeen"]
    block = "/*\n  api_key = ABCdef123456xyz\n*/"
    assert [f["value"] for f in cr.scan_comment_secrets(block)] == ["ABCdef123456xyz"]


def test_a_hash_comment_also_stops_at_the_line_end():
    src = "\n".join(["# a note about configuration",
                     "SECRET_TOKEN = 'realvalue12345678'"])
    assert cr.scan_comment_secrets(src) == [], (
        "the assignment is code on its own line, not part of the comment above it")

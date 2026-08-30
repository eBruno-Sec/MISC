"""Q-127 - a CRITICAL "Exposed .env file" against a WordPress install that has no .env.

Found on the reach lab, which is exactly what the lab is for: a target whose ground truth I can
check by hand. A stock `wordpress:6-apache` with five latest plugins produced 322 findings, and
number one was CRITICAL.

TWO INDEPENDENT DEFECTS, both measured, either one sufficient to cause it.

1. THE CATCH-ALL GUARD WAS EXACT EQUALITY. `classify` suppressed a hit when the body EQUALLED the
   randomised not-found baseline. Measured against the lab:

       /.env body                82506 chars
       randomised 404 baseline   82534 chars
       body == baseline_body     False      <- the guard passed
       _body_similarity          1.0        <- the same page

   Twenty-eight bytes: the requested path echoed into the <title> and the search form. A nonce, a
   timestamp, a CSRF token or the path itself defeats `==` on any dynamic application.
   `web_security.validate_sensitive_body` already used `_body_similarity >= 0.92` for this exact
   job -- the right tool was in the codebase and this call site used the wrong one.

2. `re.I` WAS APPLIED TO EVERY SIGNATURE, which is what actually fired. The dotenv pattern
   `^[A-Z][A-Z0-9_]{2,}\s*=` reads as "an uppercase KEY starting a line", which is what a dotenv
   line is. Under IGNORECASE it means "any word followed by =", and every tab-indented HTML
   attribute is that. It matched `class=` in WordPress's own markup.

   A third, smaller one rode along: `\s` matches newlines, so `^` bought nothing -- the match could
   start at one line and land arbitrarily deep in another. Now `[^\S\n]*`, and a VALUE is required
   after the `=`, because a dotenv line is `KEY=value` and never a bare `KEY=`.

THE LOAD-BEARING TEST IS `test_the_signature_alone_rejects_the_page_with_no_baseline_at_all`. Fixing
only the baseline guard would leave the tool one missing baseline away from the same CRITICAL, and a
scan of a host whose not-found probe failed is precisely when a baseline is missing.
"""
import exposure_tool as ex


def _check(path):
    return [c for c in ex.EXPOSURE_CHECKS if c["path"] == path][0]


#: WordPress's own markup, reduced to the shape that fired: tab-indented attributes at line starts.
_WP_MARKUP = (
    '<!DOCTYPE html>\n<html lang="en-US">\n<body>\n'
    '\t\t\t<div\n\t\t\t\tclass="wp-block-navigation"\n'
    '\t\t\t\tdata-wp-on--focusout="actions.handleMenuFocusout"\n'
    '\t\t\t\ttabindex="-1"\n\t\t\t>\n'
    '\t\t\t\t<span>Nothing found for <b>.env</b></span>\n\t\t\t</div>\n</body></html>\n'
)
_WP_BASELINE = _WP_MARKUP.replace(".env", "bbh-random-404-xyz")


# -- the field failure ---------------------------------------------------------

def test_a_catch_all_page_that_differs_by_the_echoed_path_is_not_an_exposed_file():
    """The exact shape: the two bodies differ only where the requested path is reflected."""
    assert _WP_MARKUP != _WP_BASELINE, "the fixture must differ, or it proves nothing about `==`"
    assert ex.classify(_check(".env"), 200, _WP_MARKUP, "", _WP_BASELINE) is None


def test_the_signature_alone_rejects_the_page_with_no_baseline_at_all():
    """THE ONE THAT MATTERS. Fixing only the baseline guard leaves the tool one missing baseline
    away from the same CRITICAL -- and a host whose not-found probe failed is exactly when the
    baseline is missing."""
    assert ex.classify(_check(".env"), 200, _WP_MARKUP) is None
    assert ex._matches(_check(".env")["sig"], _WP_MARKUP) == ""


def test_an_html_attribute_is_not_a_dotenv_key():
    """Stated on its own, because this is the whole substance of the signature fix."""
    assert ex._matches(_check(".env")["sig"], '\t\tclass="x"\n') == ""
    assert ex._matches(_check(".env")["sig"], '\t\ttabindex="-1"\n') == ""


def test_a_key_with_no_value_is_not_a_dotenv_line():
    """`KEY=` alone is a query string or an attribute; a dotenv line carries a value."""
    assert ex._matches(_check(".env")["sig"], "APP_ENV=\n") == ""


# -- non-vacuity: real files must still be caught ------------------------------

def test_a_real_dotenv_is_still_CRITICAL():
    """Without this, deleting the check satisfies every test above."""
    got = ex.classify(_check(".env"), 200, "APP_ENV=production\nDB_PASSWORD=hunter2\n", "", _WP_BASELINE)
    assert got and got["severity"] == "critical", got


def test_a_real_dotenv_is_caught_with_no_baseline_too():
    assert ex.classify(_check(".env"), 200, "DB_PASSWORD=hunter2\n") is not None


def test_the_other_checks_still_confirm_their_own_files():
    """The `re.I` removal touched EVERY signature, so every family needs its positive control or
    the fix silently disables a detector instead of tightening one."""
    for path, body in (
        (".git/HEAD", "ref: refs/heads/main\n"),
        (".git/config", "[core]\n\trepositoryformatversion = 0\n"),
        (".git/index", "DIRC\x00\x00\x00\x02"),
        (".DS_Store", "Bud1\x00\x00"),
        (".htpasswd", "admin:$apr1$abc$def\n"),
        (".aws/credentials", "[default]\naws_access_key_id = AKIA...\n"),
        ("docker-compose.yml", "services:\n  web:\n    image: nginx\n"),
        ("phpinfo.php", "<title>phpinfo()</title>"),
    ):
        assert ex.classify(_check(path), 200, body) is not None, path


def test_case_folding_is_kept_where_the_content_genuinely_varies():
    """`re.I` was not wrong everywhere -- it was wrong as a BLANKET. A SQL dump may be written in
    either case, so that signature keeps an inline `(?i)` while `DIRC` and `Bud1` do not."""
    assert ex.classify(_check("backup.sql"), 200, "insert into users values (1);") is not None
    assert ex.classify(_check("backup.sql"), 200, "INSERT INTO users VALUES (1);") is not None
    assert ex.classify(_check(".git/index"), 200, "dirc but lowercase") is None


# -- the guard itself ----------------------------------------------------------

def test_a_genuinely_different_body_still_passes_the_baseline_guard():
    """The guard must not become a blanket suppressor: a real file bears no resemblance to the
    site's 404 page, and that is the case the whole engine exists for."""
    assert ex.classify(_check(".env"), 200, "DB_PASSWORD=hunter2\n", "", _WP_BASELINE) is not None


def test_a_non_2xx_is_never_a_finding():
    assert ex.classify(_check(".env"), 404, "DB_PASSWORD=hunter2\n") is None
    assert ex.classify(_check(".env"), 301, "DB_PASSWORD=hunter2\n") is None

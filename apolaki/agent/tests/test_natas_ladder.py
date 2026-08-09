"""Natas ladder benchmark (#33) — the DISCIPLINE, not the score.

A benchmark's number is only worth what its rules are worth. These tests enforce the three that make the
result meaningful: no level-specific logic, no credentials in the repo, and an honest ceiling that does
not merge different kinds of failure into one percentage.
"""
import re

import natas_ladder as n


def test_the_module_contains_no_level_specific_logic():
    """THE rule. A level solved by logic written for that level is a lookup table, not a capability, and
    it inflates every future claim. Same discipline as the GinAndJuice blind run."""
    import inspect
    src = inspect.getsource(n)
    body = "\n".join(l for l in src.splitlines() if not l.strip().startswith("#"))
    for tell in ("s3cr3t", "files/users", "natas5.natas", "loggedin=1'"):
        assert tell not in body, "level-specific tell in the module: %s" % tell
    # A path that only matters on one level would show up as a hardcoded deep path.
    assert not re.search(r"[\"'][a-z0-9]+/[a-z0-9]+\.txt[\"']", body), "hardcoded deep path"


def test_general_recon_paths_are_generic():
    """robots.txt and .git/config are what a scanner checks on ANY target. A path that only pays off on
    one Natas level would not belong."""
    for p in n.GENERAL_RECON_PATHS:
        assert p in ("robots.txt", ".git/config", "sitemap.xml", ".well-known/security.txt"), p


def test_no_credential_is_embedded():
    """34 levels produce 34 live credentials, and one already leaked into git history on this project."""
    import inspect
    src = inspect.getsource(n)
    for m in n.PASSWORD_RE.finditer(src):
        raise AssertionError("32-char credential-shaped literal in the module: %s..." % m.group(1)[:6])


def test_the_password_shape_does_not_match_longer_blobs():
    """Anchored on word boundaries so a base64 blob or a hex digest is not mistaken for a password."""
    assert n.candidate_passwords("a" * 32) == ["a" * 32]
    assert n.candidate_passwords("a" * 40) == []
    assert n.candidate_passwords("short abc") == []


def test_known_passwords_are_excluded_from_candidates():
    pw = "b" * 32
    assert n.candidate_passwords("the value is " + pw, exclude=[pw]) == []


# ── the honest-ceiling contract ─────────────────────────────────────────────────────────────────

def test_levels_are_classified_so_failures_are_not_merged():
    """A scanner missing a hash-extension forgery is a different fact from one missing a SQL injection.
    One percentage covering both tells the reader nothing."""
    kinds = {n.classify(i) for i in range(n.FIRST_LEVEL, n.LAST_LEVEL + 1)}
    assert kinds == {"surface", "injection", "session_logic", "specialist"}


def test_summarise_separates_blocked_from_unsolved():
    """A level that could not be REACHED is not a level the engines failed on."""
    s = n.summarise([{"level": 0, "solved": True}, {"level": 1, "solved": False},
                     {"level": 2, "solved": False, "blocked": True}])
    assert s["solved"] == 1 and s["not_solved"] == 1 and s["blocked"] == 1
    assert s["rate"] == 33.3


def test_the_report_line_names_the_ceiling():
    s = n.summarise([{"level": 0, "solved": True}, {"level": 30, "solved": False}])
    line = n.report_line(s)
    assert "general engines" in line and "by class" in line
    assert "surface 1/1" in line and "specialist 0/1" in line


def test_summarise_is_pure_and_handles_nothing():
    assert n.summarise([])["attempted"] == 0
    assert n.summarise([]) == n.summarise([])


# ── the recon helpers are ordinary crawling ─────────────────────────────────────────────────────

def test_same_origin_refs_skips_offsite_and_pseudo_schemes():
    html = ('<img src="files/pixel.png"><a href="https://cdn.test/x.js">o</a>'
            '<a href="javascript:void(0)">j</a><a href="#top">t</a>')
    assert n.same_origin_refs(html) == ["files/pixel.png"]


def test_directories_of_finds_the_parent_index():
    """A page referencing `files/pixel.png` implies `files/` — the classic exposed-index check, and what
    `exposed_files_harvest` does on any target."""
    assert n.directories_of(["files/pixel.png", "a/b/c.js", "top.png"]) == ["files/", "a/b/"]


def test_robots_paths_reads_what_robots_advertises():
    assert n.robots_paths("User-agent: *\nDisallow: /hidden/\nDisallow: /\n") == ["hidden/"]


def test_retry_variants_reads_response_headers_not_just_the_body():
    """A Set-Cookie header is the ordinary place a server hands the client an authorization input.
    Reading only the body missed every one of them — a probe seeing half its own input surface."""
    labels = [l for l, _ in n.retry_variants("", "http://t.test", "/", "Set-Cookie: loggedin=0; path=/")]
    assert "cookie loggedin=1" in labels


def test_retry_variants_are_all_general_classes():
    """Header-trust and client-controlled-cookie are vulnerability CLASSES, not level solutions."""
    for label, headers in n.retry_variants("<p>x</p>", "http://t.test", "/", "Set-Cookie: admin=0"):
        assert isinstance(headers, dict) and headers
        assert any(k in label for k in ("Referer", "X-", "cookie")), label


# ── paths revealed as TEXT, not as links ────────────────────────────────────────────────────────

def test_content_paths_finds_a_path_named_only_in_prose():
    """`same_origin_refs` sees only href/src. A source-disclosure page, stack trace or config dump names
    files that are linked from nowhere — a general blind spot, not a Natas-specific one. Mirrors the path
    mining Apolaki already does on served blobs in agent.py and codeintel."""
    src = 'require("includes/secret.inc"); $cfg = "/etc/app/settings.conf";'
    got = n.content_paths(src)
    assert "includes/secret.inc" in got
    assert "etc/app/settings.conf" in got


def test_content_paths_skips_static_asset_noise():
    """Fetching an image proves nothing and burns the budget."""
    src = '"a/logo.png" "b/style.css" "c/font.woff2" "d/app.map" "e/data.json"'
    got = n.content_paths(src)
    assert got == ["e/data.json"], got


def test_content_paths_skips_absolute_urls():
    assert n.content_paths('src="http://cdn.test/x.js" and "www.test/y.js"') == []


def test_content_paths_is_bounded_and_pure():
    many = " ".join('dir%d/file%d.txt' % (i, i) for i in range(50))
    assert len(n.content_paths(many)) <= 20
    assert n.content_paths(many) == n.content_paths(many)


def test_recon_targets_includes_text_named_paths():
    html = '<p>include("lib/config.inc")</p><img src="assets/logo.png">'
    assert "lib/config.inc" in n.recon_targets(html)


# ── interaction: forms, parameters, decode chains ───────────────────────────────────────────────

def test_a_submit_button_is_carried_in_the_payload():
    """Server handlers routinely GATE on the submit button (`array_key_exists("submit", $_POST)`).
    Dropping it means the request is silently rejected no matter how right the other values are — the
    form was submitted and nothing happened, which reads as "the value was wrong"."""
    html = ('<form method="post"><input name="secret">'
            '<input type="submit" name="submit" value="Go"></form>')
    form = n.forms_in(html)[0]
    assert "submit" in form["fields"], "submit button must be in the payload"
    assert "submit" not in form["interesting"], "…but never varied — a tester does not control its meaning"


def test_hidden_fields_are_carried_unchanged():
    """Hidden inputs are usually state the server expects back."""
    html = '<form><input type="hidden" name="tok" value="abc"><input name="q"></form>'
    form = n.forms_in(html)[0]
    assert form["fields"]["tok"] == "abc"
    assert form["interesting"] == ["q"]


def test_one_field_is_varied_at_a_time():
    """A success must attribute to a single substitution, not a lucky combination."""
    html = '<form><input name="a"><input name="b"></form>'
    for _label, _form, payload in n.form_submissions(html, ["VALUE"]):
        assert list(payload.values()).count("VALUE") == 1


def test_absolute_paths_reads_what_the_target_discloses():
    """A hint, stack trace or config dump names where something lives. The target supplies the address."""
    got = n.absolute_paths("hint: the password is in /etc/natas_webpass/natas8 on this host")
    assert got == ["/etc/natas_webpass/natas8"]


def test_param_substitution_varies_one_parameter():
    subs = n.param_substitutions(["http://h/i.php?page=home&lang=en"], ["/etc/passwd"])
    assert any("page=%2Fetc%2Fpasswd" in u and "lang=en" in u for _l, u in subs)
    assert any("lang=%2Fetc%2Fpasswd" in u and "page=home" in u for _l, u in subs)


def test_param_substitution_ignores_urls_without_parameters():
    assert n.param_substitutions(["http://h/plain"], ["/etc/passwd"]) == []

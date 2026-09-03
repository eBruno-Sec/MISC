"""Q-173 - a browsable directory we ALREADY FETCHED is a list of real files.

Mission `bed9ffcd` scanned a local mutillidae lab with 61 tools and 2866 requests and never
reported `/passwords/accounts.txt`, a world-readable file publishing 23 working admin logins.

MEASURED root cause, and it is not a broken oracle. Every downstream stage already worked when
handed the listing by hand:

    GET /passwords/?C=N;O=D -> 200
    looks_like_listing : True
    parse_listing      : ['accounts.txt']
    is_harvestable     : True
    .txt in _HARVEST_EXT: True          <- the "static extension filter" hypothesis is DISPROVED

The engine's ONLY source of directories to harvest is `DIR_CANDIDATES`, sixteen names somebody
typed, and `passwords` is not one of them. The mission's own `exchanges` table has three rows for
`http://mutillidae/passwords/`, so the crawler walked the directory and the harvester was never
allowed to see it.

Two further defects fell out of measuring that one:

2. `parse_listing` returned raw hrefs and the caller joined them to the ORIGIN. A listing's hrefs
   are relative to the page they are on, and the two common styles differ exactly there:

       http://juice-shop:3000/ftp   href="ftp/acquisitions.md"  -> origin-join 200  (correct by luck)
       http://mutillidae/passwords/ href="accounts.txt"         -> origin-join 404  (wrong)

   Apache `mod_autoindex` emits bare file names, so every Apache autoindex this engine has ever
   harvested was requesting files from the web root. It only ever appeared to work because
   juice-shop's listing emits root-relative hrefs.

3. The content oracle was one substring regex including a bare `password`. MEASURED, it is unsound
   in BOTH directions: it fires on `robots.txt` (`Disallow: /passwords/`) on two of three labs, and
   the one true positive was luck -- the credential dump matches only because ten of its rows use
   the literal password "password". A dump with real secrets contains the substring nowhere.

The fix is general and name-free: harvest directories the engagement OBSERVED, resolve listing
links against the listing's own URL, and judge a file on the STRUCTURE of its content.

Fixtures below are synthetic. The real lab credentials are never committed.
"""
import exposure_tool as exp


# ── fixtures ────────────────────────────────────────────────────────────────────
# A credential store: many rows, one delimiter, near-unique identifier column, adjacent
# opaque token column. Shaped like the real thing, with invented values.
CRED_CSV = "\n".join(
    "%d,%s,%s,note %d,Admin" % (i, u, p, i) for i, (u, p) in enumerate(
        [("alice", "hunter2"), ("bob", "qx"), ("carol", "s3cr3t!"), ("dave", "letmein"),
         ("erin", "correcthorse"), ("frank", "tr0ub4dor"), ("grace", "zzzz9"),
         ("heidi", "p4ssphrase"), ("ivan", "monkey99"), ("judy", "9lives")], 1))

# Apache mod_autoindex: hrefs are BARE FILE NAMES, plus sort and parent links.
APACHE_INDEX = """<html><head><title>Index of /passwords</title></head><body>
<h1>Index of /passwords</h1><table>
<tr><th><a href="?C=N;O=D">Name</a></th><th><a href="?C=S;O=A">Size</a></th></tr>
<tr><td><a href="/">Parent Directory</a></td><td>-</td></tr>
<tr><td><a href="accounts.txt">accounts.txt</a></td><td>929</td></tr>
<tr><td><a href="notes.md">notes.md</a></td><td>12</td></tr>
<tr><td><a href="dump.sql">dump.sql</a></td><td>44</td></tr>
</table></body></html>"""

# The other common style: hrefs already relative to the web root.
ROOT_RELATIVE_INDEX = """<ul>
<li><a href="ftp/acquisitions.md">acquisitions.md</a></li>
<li><a href="ftp/legal.md">legal.md</a></li>
<li><a href="ftp/package.json.bak">package.json.bak</a></li>
</ul>"""

ROBOTS = ("User-agent: *\nDisallow: passwords/\nDisallow: config.inc\nDisallow: classes/\n"
          "Disallow: javascript/\nDisallow: documentation/\nDisallow: phpmyadmin/\n"
          "Disallow: includes/\nDisallow: images/\n")


# ── half 1: a directory we already walked is discovered surface ──────────────────
def test_observed_directory_becomes_a_harvest_candidate():
    """THE DEFECT. The directory was fetched by the mission and never harvested."""
    observed = ["http://mutillidae/index.php?page=home.php",
                "http://mutillidae/passwords/?C=N;O=D"]
    dirs = exp.observed_directories(observed, "http://mutillidae")
    assert "passwords" in dirs, (
        "a directory the engagement already fetched must be discovered surface; got %r" % dirs)
    # MUTANT "ignore files named by a directory listing" dies here: it makes this list empty.
    cands = exp.directory_candidates("http://mutillidae", observed)
    assert "passwords" in cands
    assert cands.index("passwords") < cands.index("ftp"), \
        "an observed FACT must be tried before a guessed name"


def test_a_url_without_a_trailing_slash_does_not_invent_a_directory():
    """`/.git/logs/HEAD` names two directories, not three. Guard against request inflation."""
    dirs = exp.observed_directories(["http://h/.git/logs/HEAD"], "http://h")
    assert dirs == [".git", ".git/logs"], dirs
    assert exp.observed_directories(["http://h/index.php"], "http://h") == []


def test_another_hosts_directory_is_not_this_hosts_surface():
    dirs = exp.observed_directories(
        ["http://a/secrets/", "http://b/public/"], "http://a")
    assert dirs == ["secrets"], dirs


def test_no_observed_surface_degrades_to_todays_behaviour():
    """The change can never make an existing run worse."""
    assert exp.directory_candidates("http://h", None)[:3] == exp.DIR_CANDIDATES[:3]


# ── half 2: a listing's links resolve against the listing, not the origin ────────
def test_apache_autoindex_links_resolve_into_their_directory():
    """THE DEFECT: bare hrefs were joined to the origin and 404'd."""
    got = exp.parse_listing(APACHE_INDEX, "http://mutillidae/passwords/")
    assert "passwords/accounts.txt" in got, got
    assert "accounts.txt" not in got, "a bare name joined to the origin requests the wrong URL"
    assert not any(g.startswith("?") for g in got), "sort links are not files"


def test_root_relative_listing_is_unchanged():
    """The one listing style that already worked must keep working."""
    got = exp.parse_listing(ROOT_RELATIVE_INDEX, "http://juice-shop:3000/ftp")
    assert "ftp/acquisitions.md" in got, got
    assert "ftp/ftp/acquisitions.md" not in got, "double-joined the directory"


def test_parse_listing_without_a_base_url_keeps_the_old_contract():
    assert exp.parse_listing(APACHE_INDEX) == ["accounts.txt", "notes.md", "dump.sql"]


def test_a_listing_linking_offsite_does_not_produce_offsite_paths():
    html = '<a href="accounts.txt">a</a><a href="https://evil.test/x.txt">b</a>'
    got = exp.parse_listing(html, "http://mutillidae/passwords/")
    assert got == ["passwords/accounts.txt"], got


# ── half 3: judge the file on its CONTENT, never on its name ────────────────────
def test_a_credential_table_is_recognised_by_shape_not_by_the_word_password():
    """The dump must be caught even when the substring 'password' never appears."""
    assert "password" not in CRED_CSV.lower()
    c = exp.classify_content(CRED_CSV)
    assert c and c["kind"] == "credential_table", c
    assert c["severity"] == "high" and c["cwe"] == "CWE-522"


def test_a_two_character_password_does_not_suppress_the_whole_table():
    """A per-value length floor vetoed the real dump over one 2-char password."""
    assert exp.credential_table(CRED_CSV)["rows"] == 10


def test_robots_txt_is_not_a_credential_exposure():
    """OVER-CORRECTION MUTANT ("treat every .txt as a credential exposure") DIES HERE.

    robots.txt is colon-delimited with two fields per line and says the word `passwords`.
    Only the near-uniqueness of the identifier column separates it from a login table:
    `Disallow` repeats on every row, a username does not."""
    assert exp.classify_content(ROBOTS) is None
    assert exp.credential_table(ROBOTS) is None


def test_a_plain_text_file_is_not_sensitive_by_virtue_of_being_text():
    assert exp.classify_content("hello world\nthis is a readme\nnothing to see\n") is None
    assert exp.classify_content("id,name,city\n1,alice,Boston\n2,bob,Denver\n3,cy,Reno\n") is None


def test_documentation_of_a_default_password_is_not_a_leaked_config():
    """A markdown code span is documentation; a bare token is a config value."""
    assert exp.classify_content("# Setup\n\n**Default password = `password`**\n") is None
    assert exp.classify_content("DB_PASSWORD=hunter2\nDB_HOST=db\n") is not None


def test_a_directory_index_is_a_table_of_contents_not_content():
    """An index that NAMES a sensitive file is not itself a sensitive file."""
    assert exp.classify_content(ROOT_RELATIVE_INDEX) is None


def test_key_material_and_dumps_are_recognised_structurally():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----\n"
    assert exp.classify_content(pem)["kind"] == "key_material"
    assert exp.classify_content("AKIAIOSFODNN7EXAMPLE is the id")["kind"] == "key_material"
    dump = "CREATE TABLE users (id int);\nINSERT INTO users VALUES (1);\n"
    assert exp.classify_content(dump)["kind"] == "db_dump"


# ── the finding the harvester emits ─────────────────────────────────────────────
def test_the_finding_states_the_claim_that_was_proven():
    f = exp.harvest_finding("http://h/passwords/accounts.txt", "passwords/accounts.txt",
                            False, CRED_CSV)
    assert f["family"] == "credential_exposure" and f["cwe"] == "CWE-522"
    assert "credential store" in f["title"]


def test_the_finding_never_copies_the_secrets_into_the_report():
    """Evidence used to be the raw body, so a credential dump put every plaintext password
    into the finding, the report and the database."""
    f = exp.harvest_finding("http://h/p/accounts.txt", "p/accounts.txt", False, CRED_CSV)
    for secret in ("hunter2", "s3cr3t!", "correcthorse", "tr0ub4dor"):
        assert secret not in f["evidence"], "leaked %r into the finding evidence" % secret
    assert "rows" in f["evidence"], "the evidence must describe the structure it claims"


def test_a_decode_artefact_never_reaches_the_evidence_string():
    """U+FFFD appears only when a decoder hit bytes it could not decode, so it is an artefact
    of our own reading, never content. MEASURED on a real harvested doc whose
    `--user=root --password=samurai` is mis-decoded, the evidence came out as
    "\ufffdpassword: <redacted>". This project already shipped a finding titled
    `Exposed application credentials for 'root\ufffd'`."""
    c = exp.classify_content("mysql \ufffduser=root \ufffdpassword=samurai \ufffdexecute=drop\n")
    assert c and c["kind"] == "secret_assignment"
    assert "\ufffd" not in c["evidence"], c["evidence"]
    assert "samurai" not in c["evidence"], "the secret's value must never be emitted"

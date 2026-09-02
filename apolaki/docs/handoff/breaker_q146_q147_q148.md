# BREAKER report -- Q-146 `code_injection`, Q-147 `dom_sinks`, Q-148 `passive_disclosure`

Adversarial audit of three unwired detection modules. The job was to make them WRONG, not to
review them. Every claim below is either MEASURED (command + real output reproduced in a throwaway
container) or explicitly marked UNVERIFIED.

Environment for every measurement:

    MSYS_NO_PATHCONV=1 docker run --rm --network apolaki_default \
      -v "<repo>/agent:/app:ro" -v "<scratch>:/scratch" -w /scratch apolaki-agent python <script>

Baseline before any mutation, on the shared tree, three files only:

    tests/test_dom_sinks.py tests/test_code_injection.py tests/test_passive_disclosure.py
    -> 109 passed   (72 + 37; the brief's "96 green" is now 109)

RANKING RULE used throughout: **would this produce a false finding against a real bug bounty
target?** That is the only severity in this file.

---

## SUMMARY TABLE

| # | Module | Finding | Status | Fires on a real target? |
|---|---|---|---|---|
| P-1 | passive_disclosure | PEM key shown inside `<pre>`/`<code>` reports CRITICAL; the documented FP control is dead code | CONFIRMED | **YES -- any docs page showing an example key** |
| P-2 | passive_disclosure | A PUBLIC JWK containing any NESTED object with a 20+ char `"d"`/`"k"`/`"p"`/`"q"` reports CRITICAL private-key disclosure | CONFIRMED | **YES -- JWKS with metadata** |
| P-3 | passive_disclosure | Redaction leak: a password containing `@` is printed CLEARTEXT into `detail` and `evidence` | CONFIRMED | YES (when it fires at all) |
| P-4 | passive_disclosure | `password=` + a host-ish key anywhere within 200 chars **across newlines** reports HIGH "database connection string" | CONFIRMED | **YES -- settings pages, minified bundles, login links** |
| P-5 | passive_disclosure | Module is 4 of its own 12 declared checks; 8 `_META` entries have no implementation, 4 helpers are dead | CONFIRMED | No (but a caller iterating `_META` will KeyError/no-op) |
| ... | | further findings appended as they are measured | | |

---

## Q-148 `passive_disclosure.py`

### Negative control FIRST (the check that matters most) -- PASSED

15 real pages fetched live from the local labs and fed to all four implemented checks.

    wpreach/ (82496 b), wpreach/?p=1, wpreach/wp-login.php, wpreach/wp-admin/install.php,
    wpreach/?s=test, wpreach jquery.min.js (87553 b), juice-shop:3000/ , juice-shop main.js
    (783793 b), juice-shop /rest/products/search?q=apple, /api/Products, /#/login,
    dvwa/login.php, mutillidae/, bwapp/login.php

    TOTAL FINDINGS ON REAL PAGES: 0

**Hypothesis "this module floods a stock WordPress like the 314-finding DOM oracle did" is
DISPROVED.** On stock pages it is silent. Every finding below needed a constructed shape -- but
all of the constructed shapes are ordinary web pages, not attacker-built ones.

### P-1 CONFIRMED -- a documentation page that DISPLAYS a key is reported as a leaked key (CRITICAL)

The module docstring states, as one of five named FP controls:

> A PAGE THAT DISPLAYS CODE is not a page that leaked code. Matches inside `<pre>`/`<code>`, and
> HTML-escaped `&lt;?php`, are excluded.

**That control does not exist in any code path.** `display_spans()` and `_inside()` are defined at
lines 127 and 132 and are called ZERO times:

    display_spans    occurrences of 'display_spans(' in the module: 1  (definition only)
    _inside          occurrences of '_inside(' in the module: 1  (definition only)

Exact input (a developer-docs page, the single most common place a PEM block legitimately appears):

    <html><head><title>Developer docs - signing keys</title></head><body>
    <h1>Example: generating a signing key</h1>
    <p>Your <code>id_rsa</code> will look like this:</p>
    <pre><code>-----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEAx7Vn9Z3kQ0pLmN4tRfGhYcWsD2bKjXeVuA1oPqZrTyUiOlEsHgFdCbNmXwJk
    ... (3 identical lines, 228 chars of base64 alphabet) ...
    -----END RSA PRIVATE KEY-----</code></pre>
    <p>Never commit this file.</p></body></html>

Observed output:

    FIRED private_keys  check=private_key_disclosed sev=critical
      detail: a RSA PRIVATE KEY block with 228 characters of key material is served in this
              response body; anyone who fetches this URL holds the key

Note the `_KEY_PLACEHOLDER` control does not save this: the docs page uses real-looking base64 (as
every "here is what a key looks like" page does), and the only placeholder tokens it recognises are
`...`, `<...>`, `{{`, `${`, `%WORD%` and a fixed English word list.

**Would it fire on a real target? Yes.** Any developer-portal, tutorial, blog post, or
`/docs/` route that renders an example key inside `<pre>` -- and RFC/test-vector keys are exactly
this shape -- produces a CRITICAL "private key disclosed". This is the `.env`-on-WordPress failure
repeated: a documented FP control that was never wired.

### P-2 CONFIRMED -- a PUBLIC JWKS with a nested metadata object reports a PRIVATE key (CRITICAL)

`enclosing_object()` finds the innermost `{...}` containing `"kty"`, then
`_JWK_PRIVATE_MEMBER.search(text[start:end])` searches **the whole slice, nested objects
included**. The existing test `test_a_d_in_a_neighbouring_object_is_not_this_key_s_private_exponent`
only pins the SIBLING case (a `"debug"` object outside the key), which the brace walk does exclude.
The NESTED case was never tested and is not excluded.

Exact input -- a public RSA JWK with one nested metadata object:

    {"keys":[{"kty":"RSA","kid":"sig-1","alg":"RS256","use":"sig",
      "n":"0vx7agoebGcQSuu","e":"AQAB",
      "x5c_meta":{"d":"MjAyNC0wMS0wMVQwMDowMDowMFoAAAAAAAAA"}}]}

Observed output:

    FIRED jwk_private  check=jwt_private_key_disclosed sev=critical
      detail: a JSON Web Key of type RSA exposes its PRIVATE member "d"; whoever fetches this URL
              can mint and sign tokens this application will accept

There is no private key in that document. The `"d"` is a base64 ISO date. The member names the
oracle treats as private are `d p q dp dq qi k` -- seven of the most common short JSON key names in
existence -- and the only thing standing between them and a CRITICAL is a brace walk that does not
descend.

**Would it fire on a real target? Yes.** `/.well-known/jwks.json` is a published, intentionally
public endpoint on every OIDC provider. Any vendor that decorates its keys with a nested object
(rotation metadata, `x5c` details, custom claims) earns a CRITICAL "attacker can mint tokens"
against a document that is public by design. This is the highest-embarrassment finding in this
report: it fires on the endpoint whose entire purpose is to be fetched by strangers.

Related, SUSPECTED, not reproduced with a real-world sample: the same walk explicitly does not
honour braces inside string literals, and it scans up to 8192 characters BACKWARD through arbitrary
page text. The docstring justifies this by saying JWK member values cannot contain a brace -- true
of the JWK, irrelevant to the 8 KB of HTML/CSS/JS the walk crosses to reach it. I built a page with
`<style>.hero:after{content:'}'}</style>` before an embedded JWKS; it stayed correctly at INFO, so
this particular construction did NOT break the walk. Hypothesis not confirmed; the structural risk
remains.

### P-3 CONFIRMED -- redaction leak: half a real password printed in cleartext

Check #6 of the brief. `_CONN_URI`'s password class is `[^\s/@"'<>]{1,128}` (excludes `@`) but its
HOST class is `[^\s/?#"'<>]{1,255}` (**does not exclude `@`**). A password containing `@` therefore
splits: the part before `@` is masked, the part after is captured as the "host" and printed raw.

Exact input:

    postgres://svc:Sup3rSecretPart@RestOfPassword@db.internal:5432/billing

Observed output:

    detail:   a postgres connection string with live credentials is served in this response body
              (user 'svc', host 'RestOfPassword@db.internal:5432'); ...
    evidence: postgres://svc:<redacted:15>@RestOfPassword@db.internal:5432
    LEAKED CLEARTEXT FRAGMENTS: ['RestOfPassword']

Second case, `mongodb://root:hunter2hunter2@extra@cluster.internal/app` -> `extra` leaked the same
way. The module's own contract is "Every finding here reports a MATCH LOCATION (byte offset + line)
and a MASKED form" -- violated.

Third case, `mysql://app:P@ssw0rd12345@10.0.0.5/shop` -> **silent**. The pre-`@` fragment `P` is 1
char, below `_MIN_CRED`, so it is discarded as a placeholder. A real leaked credential is missed.
The same defect produces both a redaction leak and a false negative depending on where the `@` sits.

### P-4 CONFIRMED -- "database connection string" HIGH from two ordinary page shapes

`_CONN_KV_HOST` is searched in `text[m.start()-200 : m.end()+200]`. The code comment justifying the
window says "A .NET connection string is one line." **The window is not line-scoped** -- it crosses
newlines freely. Measured:

    gap=0    fires=True
    gap=100  fires=True
    gap=199  fires=False        (window is ~200 chars, as documented)
    4 intervening HTML lines between host= and password=  -> fires=True

Firing input A -- an ordinary settings panel:

    <div class="settings-panel">
      <a href="/admin/db?host=sql01.corp.local">Database server</a>
      <p>Reset the account below.</p>
      <label>New password</label>
      <span class="hint">password=Tr0ub4dor3</span>
    </div>

    FIRED  check=db_connection_string_disclosed sev=high
      detail: a key-value database connection string with a live password is served in this
              response body, beside a server/database key; it grants direct database access,
              bypassing the application entirely

Firing input B -- one anchor tag, nothing else on the page:

    <a href="/legacy/login.jsp?uid=jdoe&amp;password=Winter2024">resume session</a>

    FIRED  check=db_connection_string_disclosed sev=high  (same detail)

`uid` is in the host-key vocabulary, so a single legacy login URL satisfies both halves. Note the
module *declares* a `password_in_url` check (medium, CWE-598) that would be the correct verdict --
it is one of the eight unimplemented ones (P-5). The right finding is missing and the wrong one at
HIGH fires in its place, claiming "direct database access".

Measured base rate on real bundles -- the value class `[^;\s"'<>&]{1,128}` accepts arbitrary code:

    juice-shop main.js  783793 bytes
      password/pwd= matches: 1   host-key matches: 22   findings: 0
      the one match:  group='password'  value='this.passwordControl.value,this.userService.login(this.user)'
                      _is_placeholder(value) = False        <- read as a "live password"
      nearest host-key match: 25927 chars away  (window 200) -> saved by distance only

A minified JS expression is being classified as a live credential; only the 200-char distance kept
this from being a HIGH against Juice Shop's production bundle. A bundle with different minifier
ordering fires.

**Would it fire on a real target? Yes**, on three independent shapes: admin/settings pages, legacy
login links, and minified bundles. This is a passive check that runs on every one of ~6345 crawled
URLs, so the exposure is the whole surface, not one page.

### P-5 CONFIRMED -- the module implements 4 of the 12 checks it declares

    _META declared: 12   implemented: 4
    MISSING: credit_card_disclosed, cross_domain_script_include, password_form_method_get,
             password_in_url, password_returned_in_response, session_token_in_url,
             source_code_disclosure, ssn_disclosed

The builder lane was killed mid-flight. The module docstring describes `find_card_numbers` and
`find_ssns` in detail (Luhn + IIN + brand length + digit boundaries + payment context; the
context-free SSN scan "REFUSED, in writing, in `find_ssns`'s docstring") -- **neither function
exists**. Four helpers written for the missing checks are dead: `mask_tail`, `mask_ssn`,
`display_spans`, `_inside`.

Consequence for the Coordinator wiring this: a call site that iterates `_META` to build a check
registry will register eight checks with no producer. `tests/test_passive_disclosure.py` has no
test for any of the eight, so the gate agrees with the module and neither says anything is missing.

### Checks that PASSED for this module (disproved hypotheses -- these are results too)

* **Check 4, case and whitespace.** No `re.I` on a case-bearing signature. `-----BEGIN` / PEM
  armour and `"kty":"RSA"` are matched case-exactly; the placeholder word list uses a scoped inline
  `(?i:...)` rather than folding the whole pattern; every horizontal-whitespace class is
  `[^\S\n]`. The specific `.env` defect is not present. The `_CONN_KV_HOST` **window** crosses
  newlines (P-4) but no regex `\s` does.
* **Check 7, silent failure.** `grep -c except passive_disclosure.py` -> 1 occurrence, and it is
  the word "except" in the docstring. Zero handlers. The claim in the header is true.
* **Redaction of PEM material and JWK members.** `mask_secret()` emits `<redacted:N>` only; the
  228-char key body never reaches the finding. Attempts to extract it failed. Only the `@`-in-URI
  path (P-3) leaks.
* **Public keys and certificates.** `-----BEGIN PUBLIC KEY-----` / `CERTIFICATE` cannot reach the
  private-key oracle; armour with prose (not base64) between it stays silent. Verified.

### Design hazard for the wiring (not a module defect) -- SELF-ECHO

A passive check that runs over responses the ACTIVE engines provoked will report the scanner's own
payloads. Measured:

    input:  <html><body>No results for <b>postgres://root:S3cretPassw0rd@10.1.1.9/prod</b></body></html>
    FIRED   db_connection_string_disclosed HIGH  "a postgres connection string with live
            credentials is served in this response body (user 'root', host '10.1.1.9')"

That is a search page echoing an attacker-supplied string. The module is pure and cannot know. If
`tools.py` feeds it bodies from probe responses rather than from clean crawl responses, every
reflected-input page becomes a HIGH. Recommend: passive_disclosure sees crawl responses only, or
the caller subtracts the request's own parameter values before calling.

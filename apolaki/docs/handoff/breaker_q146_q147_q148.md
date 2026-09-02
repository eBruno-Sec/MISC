# BREAKER report -- Q-146 `code_injection`, Q-147 `dom_sinks`, Q-148 `passive_disclosure`

Adversarial audit of three unwired detection modules. The job was to make them WRONG, not to
review them. Every claim below is MEASURED (command + real output reproduced in a throwaway
container) or explicitly marked SUSPECTED / UNVERIFIED.

Environment for every measurement:

    MSYS_NO_PATHCONV=1 docker run --rm --network {none|apolaki_default} \
      -v "<repo>/agent:/app:ro" -v "<scratch>:/scratch" -w /scratch apolaki-agent python <script>

Mutation ran against a COPY of the tree in scratch, never the shared tree. Every mutation printed
its file, line number, before-text and after-text, and re-read the file to prove the edit landed
before running pytest -- the "the pattern never matched" trap is explicitly guarded against.

Baseline, three test files only, unmutated shared tree:

    tests/test_dom_sinks.py tests/test_code_injection.py tests/test_passive_disclosure.py
    -> 109 passed  (72 + 13 + 25 -- the brief's "96 green" is now 109)

RANKING RULE: **would this produce a false finding against a real bug bounty target?** That is the
only severity in this file.

---

## RANKED FINDINGS

| Rank | Id | Module | Finding | Status | Fires on a real target? |
|---|---|---|---|---|---|
| 1 | CI-1 | code_injection | `el_replace`'s token is its own payload minus one hyphen -- five ordinary sanitizers turn a pure ECHO into `unidentified_code_injection` HIGH | CONFIRMED 50/50 | **YES. This is the SSTI failure repeated.** |
| 2 | PD-1 | passive_disclosure | PEM key shown inside `<pre>`/`<code>` -> CRITICAL. The documented `<pre>` control is dead code | CONFIRMED | **YES -- every docs page showing an example key** |
| 3 | PD-2 | passive_disclosure | Any NESTED object inside a PUBLIC JWK with a 20+ char `d/p/q/k` -> CRITICAL "attacker can mint tokens" | CONFIRMED | **YES -- `/.well-known/jwks.json` is public by design** |
| 4 | PD-4 | passive_disclosure | `password=` plus a host-ish key within 200 chars **across newlines** -> HIGH "direct database access" | CONFIRMED | **YES -- settings pages, login links, minified bundles** |
| 5 | DS-1 | dom_sinks | `websocket_url_poisoning` is a SUBSTRING oracle behind a STRUCTURAL claim, and is ungated on both flags | CONFIRMED | **YES -- any socket URL carrying the page URL** |
| 6 | CI-2 | code_injection | `analyze_code_injection` returns `None` for the object `build_url_probes` actually returns -- wiring it the obvious way yields a permanently silent engine | CONFIRMED | No FP; a dead engine |
| 7 | DS-2 | dom_sinks | The two headline "inherited rule" tests are VACUOUS: their fixtures contain no key the module reads; deleting all three presence gates leaves them green | CONFIRMED | No FP itself; it removes the guard |
| 8 | PD-3 | passive_disclosure | Redaction leak: a password containing `@` is printed CLEARTEXT into `detail` and `evidence` | CONFIRMED | Yes, whenever it fires |
| 9 | DS-3 | dom_sinks | `dom_storage_manipulation` (presence) is not gated on `navigated`; `client_json_injection` is not gated on `server_reflected` and claims the wrong mechanism | CONFIRMED | Low -- needs a rare page shape |
| 10 | DS-4 | dom_sinks | `evidence` copies live bearer tokens and session tokens out of WebSocket URLs and Ajax headers into the finding | CONFIRMED | Report-hygiene, not an FP |
| 11 | PD-5 | passive_disclosure | Module implements 4 of the 12 checks it declares; 4 helpers dead; the docstring describes two functions that do not exist | CONFIRMED | No |
| 12 | CI-3 | code_injection | `build_url_probes` silently probes only the first 2 of 5 parameters at defaults | CONFIRMED | No -- false negatives |
| 13 | CI-4 | code_injection | EL is a ONE-token oracle (eval == attr); `attributed=True` HIGH rests on one markerless integer | CONFIRMED (FP risk MEASURED AS ~0) | Measured 0 on the labs |
| -- | many | all three | 12 of 25 mutants killed; **13 survived** -- see the mutation table | CONFIRMED | -- |

---

# Q-146 `code_injection.py`

## CI-1 CONFIRMED -- RANK 1. `el_replace` is echo-satisfiable. This is Q-126 all over again.

The module's central claim, stated in its own header and in its test file:

> Neither is a substring of the payload, so an ECHO cannot produce either one.

**False for the `el_replace` shape.** Its token is the payload's marker and nonce with the single
separating hyphen deleted:

    payload:     ${"civwmk-bdfigbuc".replace("-","")}
    eval_token:  civwmkbdfigbuc
    attr_token:  ''                                  (unidentified BY DESIGN)
    eval_token in payload                       -> False   <- the runtime self-check passes
    eval_token in payload.replace("-", "")      -> True    <- one deleted character defeats it

The runtime self-check at line 468 is a literal substring test. It is blind to an edit distance of
one. Any application that deletes non-alphanumeric characters from a value it echoes reconstructs
the token exactly.

Measured -- 50 fresh probes per sanitizer, pure reflection, no code executed anywhere, baseline
`<h1>No results for </h1>`:

    strip hyphens (str_replace('-','',$x): phone / SKU / card normaliser)   50/50 findings
    alphanumeric-only filter (preg_replace('/[^a-z0-9]/i','',$x))           50/50 findings
    slug with no separator                                                  50/50 findings
    strip punctuation for a search index                                    50/50 findings
    identifier normaliser (drop -, _, spaces)                               50/50 findings
    CONTROL: raw echo, untouched                                             0/50 findings
    CONTROL: html-escape                                                     0/50 findings

Example finding produced by a reflection:

    body:    <h1>No results for citefjcpngoaeyreplace</h1>
    finding: unidentified_code_injection   severity=HIGH   confidence=confirmed

Negative control -- the other five languages are immune, so this is specific to `el_replace` and
not a flaw in the two-token design generally:

    php  0   python  0   ruby  0   perl  0   javascript  0   findings from pure reflection
    el   250 findings, by shape: {'el_replace': 250}

The choice of a hyphen is what creates the hole, and the module documents the choice while missing
the consequence:

> MEASURED: Java's `String.replace` is GLOBAL, so the separator must be a character the
> alphanumeric marker and nonce cannot contain. A hyphen cannot.

A hyphen is also the character that hundreds of sanitizers delete. A separator the payload can
survive would have to be one the target cannot remove -- which does not exist -- so the correct fix
is a token that is not a deletion-image of the payload at all (e.g. `${"A".concat("B")}` where the
token is `BA`, or reuse the `hashCode` device).

**Coverage: `el_replace` is exercised by ZERO tests.**

    default shapes_per_language=1 -> el shapes shipped: ['el_hashcode']
    'shapes_per_language' appears in tests/test_code_injection.py:  0 times
    'el_replace'         appears in tests/test_code_injection.py:  0 times

So `el_replace` only ships when the caller raises `shapes_per_language` to 3 or more. **That makes
this a landmine rather than a live bug today** -- but the shape is reachable from one integer in the
`tools.py` call site the Coordinator is writing right now, and nothing in the suite would notice.

Confirmed again independently with a forced palindromic nonce (`abcddcba`) across every language and
shape and three echo forms: exactly one finding, and it was `el_replace`.

## CI-2 CONFIRMED -- RANK 6. The analyser rejects the object the builder returns.

`build_url_probes()` returns `WebCodeProbe`. `analyze_code_injection()` reads `eval_token`,
`attr_token`, `language`, `shape` and `eval_ambiguity` off the probe by `getattr`. `WebCodeProbe`
proxies only `payload` and `family`:

    build_url_probes -> WebCodeProbe
    attributes: ['family', 'original_value', 'parameter', 'payload', 'probe', 'url']
      getattr(WebCodeProbe, 'eval_token')     = <ABSENT>
      getattr(WebCodeProbe, 'attr_token')     = <ABSENT>
      getattr(WebCodeProbe, 'language')       = <ABSENT>
      getattr(WebCodeProbe, 'shape')          = <ABSENT>
      getattr(WebCodeProbe, 'eval_ambiguity') = <ABSENT>

    analyze_code_injection("clean", <body containing BOTH tokens>, web_probe) -> None
    analyze_code_injection("clean", <same body>,          web_probe.probe)    -> php_code_injection

`analyze_code_injection` opens with `if not eval_token: return None`, so the failure is a silent,
total, permanent `None`. A wiring that passes the object `build_url_probes` handed it -- the obvious
wiring -- produces an engine that reports clean on a vulnerable target forever.

`build_url_probes` and `WebCodeProbe` have **zero callers anywhere in the repo, tests included**
(`grep -rn "build_url_probes\|WebCodeProbe" --include=*.py .` -> definitions only). This is the
zero-histogram / dead-engine shape the repo has already been bitten by twice. Either add the five
proxy properties or have the call site pass `.probe`.

## CI-3 CONFIRMED -- RANK 12. Two of five parameters get probed.

    url = http://t/x?a=1&b=2&c=3&d=4&e=5   (default max_probes=12, 6 languages)
    probes per parameter: {'a': 6, 'b': 6}
    parameters NEVER probed: ['c', 'd', 'e']

`max_probes` returns from inside the parameter loop, so the budget is spent left-to-right. Not a
false positive; it is a silent coverage claim. The docstring argues at length against a parameter
hint list "used as a FILTER" because it "silently skips the interesting case" -- the positional
budget does the same thing, deterministically.

Also measured, minor: `_replace_query_value` re-encodes the untouched parameters.

    in : http://t/x?path=%2Fetc%2Fpasswd&next=a%20b&q=1
    out: http://t/x?path=%2Fetc%2Fpasswd&next=a+b&q=PAYLOAD

`next` changed from `%20` to `+`. The probe request is therefore not a minimal delta from the
baseline; on a signed or path-sensitive URL that difference is attributable to the wrong cause.

## CI-4 CONFIRMED, but the FP risk MEASURED AS ~0 -- RANK 13.

The header's standing rule is "ATTRIBUTION COMES FROM THE ATTRIBUTION TOKEN ONLY. Arithmetic alone
is NEVER attributed to a language." For EL the two tokens are the SAME value, so attribution rests
on one markerless integer appearing in the body:

    shape=el_hashcode payload=${"cojjfwmk".hashCode()} eval=-691035429 attr=-691035429 same=True
    a page carrying ONLY that bare integer -> check=expression_language_injection
                                              attributed=True  severity=HIGH

I expected this to be exploitable by coincidence and it is not. Measured token length over 20000
draws: `{6:3, 7:49, 8:465, 9:4523, 10:9553, 11:5407}` -- zero tokens of five characters or fewer, so
the "96354" class of small hash does not occur for an 8-char nonce. And the differential gate holds:
two consecutive fetches of seven live lab pages produced **zero** 6-11 digit integers present in the
second fetch and absent from the first.

    wpreach/ ints:10 new:0   wpreach/?p=1 ints:12 new:0   juice-shop/ ints:56 new:0
    juice-shop/main.js ints:60 new:0   /api/Products ints:2 new:0   mutillidae/ 0   dvwa 0

**Hypothesis "the EL hashCode token collides with page integers" is DISPROVED on this evidence.**
The structural point stands and is worth a comment in the file: EL is a one-token oracle and the
standing rule does not apply to it.

## Q-146 mutation results

    SURVIVED  CI-M1  delete the runtime self-check (gate 2, 'token is a substring of its own payload')
    SURVIVED  CI-M2  re-introduce the MEASURED perl trap: `scalar reverse` -> `reverse`
    SURVIVED  CI-M3  drop the DIGIT BOUNDARY on numeric tokens (the EL / timestamp control)
    KILLED    CI-M4  POSITIVE CONTROL: make the JS attr token a literal substring of its payload
                     -> test_no_token_is_ever_a_substring_of_its_own_payload
                     -> test_each_language_is_attributed_when_its_exclusive_construct_evaluates
    KILLED    CI-M5  delete the BASELINE gate -> test_a_token_already_in_the_baseline_is_not_ours
    SURVIVED  CI-M6  operands 1000-9999 -> 1-9 (the Q-126 'product must be 7-8 digits' control)
    SURVIVED  CI-M7  _MARK_RANDOM 4 -> 0 (every probe shares the marker "ci")
    SURVIVED  CI-M8  nonce palindrome guard removed

Reading of each survivor:

* **CI-M1 matters.** Gate 2 is described as "the structural guarantee, asserted at RUNTIME and not
  merely in a test". Nothing tests it. It is the last line of defence against a mis-built payload,
  and CI-1 shows a payload can be mis-built in a way this gate cannot see anyway.
* **CI-M2 matters.** The Perl `scalar reverse` list-context trap cost a real measurement to find and
  is documented at length in the header. Reverting it kills zero tests, so it can silently return.
* **CI-M3 matters.** The digit boundary is the entire defence for the one markerless token in the
  module (CI-4). Replacing it with a plain substring test kills nothing.
* **CI-M7 matters, and exposes a VACUOUS TEST.** With `_MARK_RANDOM = 0` every probe on a page
  shares the marker `ci` -- the exact condition the module warns about ("Two parameters on one page
  must never share a token, or one stray value convicts both").
  `test_tokens_are_random_per_probe` asserts 25 draws give >= 20 distinct eval_tokens and still
  passes, because the *operands* are random. The test cannot tell marker randomness from operand
  randomness; it claims the first and measures the second.
* **CI-M6, CI-M8 do not matter.** I could not construct a case where a 1-digit operand product or a
  palindromic nonce satisfies the oracle: the marker carries the uniqueness and every shape
  separates the marker from the nonce with quotes and operators. The header's "operands are four
  digits so the product is at least seven" and the palindrome guard are both belt-and-braces, not
  load-bearing. Recording this as a **disproved hypothesis**, not a defect.

## Q-146 checks that PASSED

* **Check 3, echo attacks.** 60 rounds x every shape x 18 transformations (raw, in `<title>`, in an
  HTML comment, HTML-escaped, URL-encoded, DOUBLE URL-encoded, JSON string, double-encoded JSON,
  base64, uppercased, reversed, whitespace-collapsed, WAF operator deletion, doubled) -- **the only
  satisfied case in the whole battery was `el_replace`** (CI-1). Every other shape is echo-immune
  as claimed.
* **An application that really does the arithmetic is still not a finding.** 200 responses that
  echoed the payload *and* printed the computed product beside it: 0 findings. 200 responses that
  actually evaluated `print("mark".(a*b))`: 200 findings. The oracle discriminates evaluation of the
  *concatenation*, exactly as designed.
* **Check 4, case and whitespace.** `re.I` occurrences in `code_injection.py`: **0**. `\s` in a
  regex literal: **0**. The `.env` defect class is absent.
* **Check 7, silent failure.** Zero `except` handlers (AST count over the module: 0).

---

# Q-147 `dom_sinks.py`

## Realistic negative input -- PASSED, including the exact Q-128 field case

Signals derived from LIVE lab HTML the way `DOM_SINK_SCAN_JS` derives them (first form action
carrying the canary, `file:` hrefs carrying the canary, first path-relative stylesheet, quirks mode
from the doctype), canary actually injected as `?lang=<canary>`, with `prssi_path_tolerant` GRANTED
(the worst case for us):

    http://wpreach/?lang=CANARY            reflected=True  -> classify: SILENT  classify_page: SILENT
    http://wpreach/?p=1&lang=CANARY        reflected=True  -> SILENT / SILENT
    http://wpreach/wp-login.php?lang=...   forms=1         -> SILENT / SILENT
    http://juice-shop:3000/?lang=...       rel_css=styles.css               -> SILENT / SILENT
    http://mutillidae/?lang=...            rel_css=./styles/global-styles.css -> SILENT / SILENT
    http://dvwa/login.php?lang=...         rel_css=dvwa/css/login.css       -> SILENT / SILENT

    TOTAL dom_sinks FINDINGS FROM REAL PAGES: 0

And the literal Q-128 shape, reproduced against live WordPress:

    form actions on the page:             ['http://wpreach/wp-comments-post.php']
    actions containing the canary:        []
    href/src attributes containing the canary: 1
       -> '/?p=1&#038;lang=domtr7168079a#respond'      <- the comment-reply link, the 314-FP source
    dom_sinks.classify with ALL of that (server_reflected=True): []

**The 314-false-positive flood does not reproduce.** `local_file_path_manipulation` requires the
`file:` scheme, `form_action_hijack` requires the parsed authority to be the injected attacker host,
and both hold. Three of six pages carry a path-relative stylesheet but none renders in quirks mode,
so the PRSSI conjunction does real work. This is the strongest positive result in the audit.

## DS-1 CONFIRMED -- RANK 5. `websocket_url_poisoning`: a substring behind a structural claim, ungated.

    wu = _s(s, "ws_url")
    if wu and (canary in wu or dt.is_evil_host(wu)):

`canary in wu` is a plain substring over the whole socket URL. The finding and its impact make an
AUTHORITY claim:

> "%s controls the target of a WebSocket handshake request the page opened"
> impact: "The attacker chooses the WebSocket endpoint the page connects to, so the whole duplex
> channel ... belongs to the attacker."

Measured -- all three of these produce `websocket_url_poisoning` with that impact text, with
`navigated=False` and `server_reflected=True` both set:

    wss://wpreach/live?room=CANARY                                        -> FIRES
    wss://analytics.vendor.example/s?page=http%3A%2F%2F...%3Fq%3DCANARY   -> FIRES
    wss://wpreach/live#CANARY                                             -> FIRES
    wss://wpreach/live                                                    -> silent (correct)

In the first three the endpoint is the application's own (or a third party's own) host. The canary
reached a query parameter or a fragment. Nothing about the endpoint is attacker-chosen. This is
character-for-character the CRLF / host-header defect the repo deleted 17 findings for: a substring
match standing in for a structural claim. Contrast `form_action_hijack` in the same file, which gets
this right and says so at length -- "the discriminator is not WHO wrote the value, it is WHAT the
value controls: the resolved action's AUTHORITY must be the attacker host we injected, parsed --
never a substring."

It is also the module's **ungated presence family** (the answer to check #5). It is described under
"BEHAVIOURS (ungated)", but `ws_url` is a recorded string, not something the browser did -- the
family fires on `constructed; OPEN not observed`, i.e. with no handshake at all. Neither
`server_reflected` nor `navigated` is consulted.

The test file **locks the defect in**. Mutation DS-M3, making the oracle structural
(`if wu and dt.is_evil_host(wu)`), was KILLED by five tests, headed by
`test_positive_the_canary_reaches_the_websocket_url`, whose own fixture is
`wss://wpreach/live?room=<canary>`. The suite requires the substring behaviour.

**Would it fire on a real target? Yes.** Session-replay, live-chat, analytics and dev-HMR sockets
routinely embed the page URL or a page parameter in the socket URL. Every one of those becomes a
MEDIUM (CVSS 5.4, CWE-918) claiming the attacker owns the channel.

Recommended shape, matching the family's own sibling: fire only when the canary reaches the
socket URL's **authority** (`_host_of(wu)`), or when `dt.is_evil_host(wu)`. A canary in the query
is at most an informational "parameter reaches a WebSocket URL".

## DS-2 CONFIRMED -- RANK 7. The two headline "inherited rule" tests are vacuous.

The file's first two named assertions are the Q-128 and Q-129 postmortems:

    test_the_whole_wordpress_signal_shape_yields_nothing
    test_the_chrome_error_page_shape_yields_nothing

Their fixtures use `in_href`, `in_src`, `in_attr`, `in_text` -- **`dom_trace` signal names.
`dom_sinks` reads none of them.** Instrumented with a read-recording dict:

    keys dom_sinks.classify() reads (16):
      ajax_headers, doc_domain_write, dos_baseline_hangs, dos_hangs, dos_renders, file_urls,
      form_action, hpp_request_urls, json_keys, navigated, server_reflected,
      storage_replay_navigated, storage_replay_server_reflected, storage_writes, ws_url, xpath_exprs

    test_the_whole_wordpress_signal_shape_yields_nothing
      fixture keys: in_attr, in_href, in_src, in_text, navigated, server_reflected
      EVIDENCE keys it supplies: NONE -> the assertion cannot discriminate

    test_the_chrome_error_page_shape_yields_nothing (classify half)
      fixture keys: in_href, in_text, navigated, server_reflected
      EVIDENCE keys it supplies: NONE

    test_a_clean_render_reports_nothing (2nd assert)
      fixture keys: navigated, server_reflected
      EVIDENCE keys it supplies: NONE

Confirmed by mutation DS-M4 -- all three presence gates deleted at once (`loaded = True`,
`if True:` for local_file_path, `if fa:` for form_action_hijack), verified applied, then those two
tests only:

    RESULT: ..  [100%]  -> *** MUTANT SURVIVED ***

**The two tests that carry the module's central claim would pass with every gate removed.** The
gates ARE implemented and other tests do kill gate mutations (DS-M1, DS-M2), so this is a false
sense of coverage rather than a missing gate -- but it is precisely "a test whose fixture cannot
discriminate", and it is guarding the exact rule that cost 314 findings. Fix: rebuild both fixtures
out of this module's own evidence keys (`form_action`, `file_urls`, `storage_writes`, `ws_url`).

Methodological note against myself: my FIRST version of this instrument reported "keys read: []"
because `_s`/`_list`/`_int` all do `(sig or {})` and an EMPTY dict is falsy, so the spy's `.get` was
never called. I nearly published a vacuous measurement inside a finding about vacuity. The numbers
above come from a spy pre-seeded with one dummy key.

## DS-3 CONFIRMED -- RANK 9. Two presence families that are not gated as the module's rule requires.

Check #5 of the brief, answered by direct behaviour probe:

    dom_storage_manipulation (a PRESENCE family):
      navigated=True  -> ['dom_storage_manipulation']
      navigated=False -> ['dom_storage_manipulation']     <- NOT gated on `navigated`

    local_file_path_manipulation (the correctly gated comparison):
      navigated=True  -> ['local_file_path_manipulation']
      navigated=False -> []

    client_json_injection:
      server_reflected=False -> ['client_json_injection']
      server_reflected=True  -> ['client_json_injection'] <- NOT gated on `server_reflected`

`dom_storage_manipulation` gates on `storage_replay_navigated` (the replay render) but never on the
`navigated` of the render where the write happened. In practice the hooks cannot record a
`setItem` on a Chrome error page, so this is low-risk -- but it is the stated rule not being
applied, and `test_negative_the_replay_render_never_loaded` covers only the replay half.

`client_json_injection`'s structural discriminator is strong (the marker must become a KEY of a
parsed object, which needs a break-out of a JSON string literal), so this is not a phantom
vulnerability. What is wrong is the **mechanism claim**: the evidence says "the page concatenates
and parses at runtime" and the family is "Client-side JSON injection" (CWE-74). If the SERVER
echoed the raw parameter into a JSON document the page then fetched and parsed, the same signal
appears and the claim names the wrong side of the wire. This is the Q-128 rule -- "must name the
real mechanism from `server_reflected` instead" -- applied everywhere except here. The cheap fix is
the one `form_action_hijack` already uses: keep the family ungated, let `server_reflected` choose
the wording.

`document_domain_manipulation` is ungated on both flags. Measured:

    {}                          -> ['document_domain_manipulation']
    {'navigated': False}        -> ['document_domain_manipulation']
    {'server_reflected': True}  -> ['document_domain_manipulation']

That is defensible (the setter firing is a behaviour) with one caveat, UNVERIFIED in a browser: the
hook records the written value BEFORE delegating to the real setter --
`set: function (v) { B.doc_domain_write = String(v); return d.set.call(this, v); }` -- so a value
the browser REJECTS with a SecurityError (anything that is not a suffix of the current domain, i.e.
every attacker-chosen value) is still recorded, and the finding still says "the payload chooses the
document's origin for same-origin-policy purposes". Suggest recording success, not attempt.

## DS-4 CONFIRMED -- RANK 10. Live secrets copied into findings.

    ws_url = wss://app.example/live?token=eyJhbGciOiJIUzI1NiJ9.SECRETSESSION.sig&r=<canary>
      evidence: "... a WebSocket handshake request the page opened:
                 wss://app.example/live?token=eyJhbGciOiJIUzI1NiJ9.SECRETSESSION.sig&r=..."
      SECRETSESSION present in the finding: True

    ajax_headers = [["Authorization", "Bearer eyJ0LIVEBEARERTOKEN9.<canary>"]]
      evidence: "... controls the VALUE of the request header `Authorization` that the page sets at
                 runtime (`Bearer eyJ0LIVEBEARERTOKEN9....`)."
      LIVEBEARERTOKEN present in the finding: True

`wu[:140]` and `value[:100]` are copied verbatim. WebSocket URLs commonly carry a session token in
the query and `Authorization` is deliberately NOT in `BROWSER_HEADERS`. Not a false positive, but
`passive_disclosure` in the same batch has a whole redaction convention (`mask_secret`) that this
module does not use. A report carrying the victim's bearer token is itself a disclosure.

## Q-147 mutation results -- the gates are real and well covered

    KILLED    DS-M1  POSITIVE CONTROL: drop server_reflected from local_file_path_manipulation
                     -> test_negative_a_server_reflected_file_reference_is_gated
    KILLED    DS-M2  drop `navigated` from form_action_hijack
                     -> test_negative_form_action_on_a_page_that_never_loaded
    KILLED    DS-M3  make websocket_url_poisoning STRUCTURAL  (5 tests -- see DS-1: the suite
                     REQUIRES the substring behaviour)
    SURVIVED  DS-M4  delete ALL THREE presence gates, run only the two inherited-rule tests
    KILLED    DS-M5  drop the BROWSER_HEADERS filter
                     -> test_negative_the_referer_header_carries_the_probe_url_on_every_request
    KILLED    DS-M6  make client_side_hpp a substring test
                     -> test_negative_the_marker_encoded_inside_one_parameters_value
    KILLED    DS-M7  drop the xpath BASELINE differential
                     -> test_negative_the_expression_was_already_broken_without_our_quote
    KILLED    DS-M8  weaken the DoS differential from 'every render' to 'any render'
                     -> test_negative_a_single_hang_is_a_flaky_container (+1)

7 of 8 killed. The structural discriminators (HPP query-key, XPath three-fact differential, DoS
repeated differential, Referer filter, form-action authority) are all genuinely defended. This is
the best-tested of the three modules.

## Q-147 checks that PASSED

* **Check 4.** `re.I` occurrences in `dom_sinks.py`: **0**. `\s` in a regex literal: **0**. The one
  case-insensitive comparison (`name.strip().lower() in BROWSER_HEADERS`) is correct -- HTTP header
  names are case-insensitive.
* **Check 7.** Zero Python `except` handlers. NOTE: `DOM_SINK_HOOKS_JS` contains **11 `catch (e) {}`
  blocks that discard**. They are JavaScript inside a string literal, so the census cannot see them.
  They cannot cause a false positive, but each one silently disables a collector: if
  `Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML')` fails under a page's own
  polyfill, `innerHTML` records nothing on every render and the family looks silent-because-clean.
  That is exactly the `DOM_SCAN_JS` failure named in this module's own comment at line 610.
  UNVERIFIED in a browser; flagged for the wiring.
* **`BROWSER_HEADERS` completeness.** I checked the omitted client-hint and fetch-metadata headers
  (`sec-ch-ua-arch`, `sec-ch-ua-model`, `device-memory`, `dpr`, `viewport-width`, `downlink`, `ect`,
  `rtt`, `save-data`, `dnt`, `x-requested-with`, `sec-purpose`). None can carry a URL, so none can
  carry the canary. **Hypothesis "the header allowlist is incomplete enough to leak the Referer
  trap" is DISPROVED.**
* Minor, false-NEGATIVE only, not chased further: `DOM_SINK_SCAN_JS` takes the FIRST form whose
  action contains the canary and `break`s. On WordPress the canary lands in benign link/form targets
  first, so a genuinely hijacked form later in the document would never be reported.

---

# Q-148 `passive_disclosure.py`

## Realistic negative input -- PASSED

15 live pages, all four implemented checks:

    wpreach/ (82496 b), wpreach/?p=1, wp-login.php, wp-admin/install.php, wpreach/?s=test,
    jquery.min.js (87553 b), juice-shop:3000/, juice-shop main.js (783793 b),
    /rest/products/search?q=apple, /api/Products, /#/login, dvwa/login.php, mutillidae/,
    bwapp/login.php

    TOTAL FINDINGS ON REAL PAGES: 0

**Hypothesis "this module floods stock WordPress like the 314-finding DOM oracle" is DISPROVED.**
Every finding below needed a constructed input -- but all of the constructed inputs are ordinary
web pages, not attacker-built ones.

## PD-1 CONFIRMED -- RANK 2. A docs page that DISPLAYS a key is reported as a leaked key (CRITICAL).

The docstring names five FP controls. This is one of them:

> A PAGE THAT DISPLAYS CODE is not a page that leaked code. Matches inside `<pre>`/`<code>`, and
> HTML-escaped `&lt;?php`, are excluded.

**The control is not in any code path.** `display_spans()` (line 127) and `_inside()` (line 132)
have zero callers:

    display_spans   occurrences of 'display_spans(' in the module: 1  (definition only)
    _inside         occurrences of '_inside('       in the module: 1  (definition only)

Input -- a developer-docs page, the commonest legitimate home of a PEM block:

    <html><head><title>Developer docs - signing keys</title></head><body>
    <h1>Example: generating a signing key</h1>
    <p>Your <code>id_rsa</code> will look like this:</p>
    <pre><code>-----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEAx7Vn9Z3kQ0pLmN4tRfGhYcWsD2bKjXeVuA1oPqZrTyUiOlEsHgFdCbNmXwJk
    (3 identical lines -- 228 chars of base64 alphabet, clears _MIN_PEM_BODY=100)
    -----END RSA PRIVATE KEY-----</code></pre>
    <p>Never commit this file.</p></body></html>

Output:

    FIRED  check=private_key_disclosed  sev=critical
      detail: a RSA PRIVATE KEY block with 228 characters of key material is served in this
              response body; anyone who fetches this URL holds the key

`_KEY_PLACEHOLDER` does not save it: a "here is what a key looks like" page shows real-looking
base64, and the only recognised placeholders are `...`, `<...>`, `{{`, `${`, `%WORD%` and a fixed
English word list.

**Fires on a real target: YES.** Any developer portal, tutorial, `/docs/` route, or page reproducing
an RFC test-vector key. Same shape as the `.env`-on-WordPress CRITICAL: a documented FP control that
was never wired.

## PD-2 CONFIRMED -- RANK 3. A public JWKS with nested metadata reports a PRIVATE key (CRITICAL).

`enclosing_object()` finds the innermost `{...}` containing `"kty"`, then searches the WHOLE SLICE
-- nested objects included -- for a private member. The existing test only pins the SIBLING case
(`"debug"` outside the key object), which the walk does exclude. The NESTED case is untested and
unexcluded.

Input -- a public RSA JWK with one nested metadata object:

    {"keys":[{"kty":"RSA","kid":"sig-1","alg":"RS256","use":"sig",
      "n":"0vx7agoebGcQSuu","e":"AQAB",
      "x5c_meta":{"d":"MjAyNC0wMS0wMVQwMDowMDowMFoAAAAAAAAA"}}]}

Output:

    FIRED  check=jwt_private_key_disclosed  sev=critical
      detail: a JSON Web Key of type RSA exposes its PRIVATE member "d"; whoever fetches this URL
              can mint and sign tokens this application will accept

There is no private key in that document. The `"d"` is a base64 ISO date. The "private" member names
are `d p q dp dq qi k` -- seven of the commonest short JSON key names in existence -- and the only
thing between them and a CRITICAL is a brace walk that does not descend.

**Fires on a real target: YES, on the one endpoint whose purpose is to be fetched by strangers.**
`/.well-known/jwks.json` is public by design; any vendor that decorates keys with a nested object
earns a CRITICAL "attacker can mint tokens".

Mutation PD-M10 confirms the member list is unprotected: widening `"(d|p|q|dp|dq|qi|k)"` to
`"([a-z]{1,2})"` -- i.e. ANY one- or two-letter key -- **killed zero tests**. The negative control
`test_an_ordinary_json_document_with_a_d_field_is_not_a_jwk` uses
`{"path":{"d":"M150 0 ..."},"fill":"#fff"}`, which has no `"kty"` at all and therefore cannot
discriminate the member list from anything.

Related, NOT CONFIRMED: the walk explicitly ignores braces inside string literals while scanning up
to 8192 characters BACKWARD through arbitrary page text. I built a page with
`<style>.hero:after{content:'}'}</style>` and `var tpl = "{{ user.name }}";` before an embedded
public JWKS; it stayed correctly at `jwks_disclosed` INFO. **Hypothesis not confirmed.** Mutation
PD-M9 (`_OBJECT_WINDOW` 8192 -> 100000) killed zero tests, so the bound itself is untested.

## PD-3 CONFIRMED -- RANK 8. Redaction leak: half a real password printed in cleartext.

`_CONN_URI`'s password class is `[^\s/@"'<>]{1,128}` (excludes `@`); its HOST class is
`[^\s/?#"'<>]{1,255}` (**does not exclude `@`**). A password containing `@` splits -- the head is
masked, the tail is captured as "host" and printed raw.

    input:    postgres://svc:Sup3rSecretPart@RestOfPassword@db.internal:5432/billing
    detail:   ... (user 'svc', host 'RestOfPassword@db.internal:5432'); ...
    evidence: postgres://svc:<redacted:15>@RestOfPassword@db.internal:5432
    LEAKED CLEARTEXT FRAGMENTS: ['RestOfPassword']

    input:    mongodb://root:hunter2hunter2@extra@cluster.internal/app
    LEAKED CLEARTEXT FRAGMENTS: ['extra']

    input:    mysql://app:P@ssw0rd12345@10.0.0.5/shop
    -> SILENT.  The pre-@ fragment "P" is 1 char, below _MIN_CRED, so it is discarded as a
       placeholder: the same defect also produces a FALSE NEGATIVE on a genuine leaked credential.

Violates the module's own contract ("Every finding here reports a MATCH LOCATION and a MASKED
form"). All other redaction attempts failed: `mask_secret` emits `<redacted:N>` only, and the
228-char PEM body never reaches the finding.

## PD-4 CONFIRMED -- RANK 4. "Database connection string" HIGH from two ordinary page shapes.

`_CONN_KV_HOST` is searched in `text[m.start()-200 : m.end()+200]`. The comment justifying it says
"A .NET connection string is one line." **The window is not line-scoped.** Measured:

    gap=0 fires=True    gap=100 fires=True    gap=199 fires=False    gap=300 fires=False
    4 intervening HTML lines between host= and password= -> fires=True

Firing input A, an ordinary settings panel:

    <div class="settings-panel">
      <a href="/admin/db?host=sql01.corp.local">Database server</a>
      <p>Reset the account below.</p>
      <label>New password</label>
      <span class="hint">password=Tr0ub4dor3</span>
    </div>
    -> db_connection_string_disclosed  HIGH
       "...beside a server/database key; it grants direct database access, bypassing the
        application entirely"

Firing input B, a single anchor tag and nothing else (`uid` is in the host-key vocabulary):

    <a href="/legacy/login.jsp?uid=jdoe&amp;password=Winter2024">resume session</a>
    -> db_connection_string_disclosed  HIGH  (same detail)

Input B is doubly wrong: the module *declares* a `password_in_url` check (medium, CWE-598) that is
the correct verdict for it -- and that check is one of the eight unimplemented ones (PD-5). The
right finding is missing and a wrong one at HIGH fires in its place.

Measured base rate on a real production bundle -- the value class `[^;\s"'<>&]{1,128}` accepts
arbitrary code:

    juice-shop main.js  783793 bytes
      password/pwd= matches: 1     host-key matches: 22     findings: 0
      the match: group='password'
                 value='this.passwordControl.value,this.userService.login(this.user)'
                 _is_placeholder(value) = False      <- read as a live credential
      nearest host-key match: 25927 chars away (window 200) -> saved by distance alone

A minified JS expression is being classified as a live password. Only the 200-char distance kept
this off Juice Shop's own bundle; different minifier ordering fires it.

Mutation PD-M5 (`_CONN_KV_WINDOW` 200 -> 100000) **killed zero tests** -- the proximity bound, the
single control separating this check from "any page with the word password on it", is untested.

**Fires on a real target: YES**, on three independent shapes (admin/settings pages, legacy login
links, minified bundles), and this is a passive check that runs on every crawled URL -- the last
mission crawled 6345 -- so the exposure is the whole surface.

## PD-5 CONFIRMED -- RANK 11. Four of twelve declared checks exist.

    _META declared: 12    implemented: 4
    MISSING: credit_card_disclosed, cross_domain_script_include, password_form_method_get,
             password_in_url, password_returned_in_response, session_token_in_url,
             source_code_disclosure, ssn_disclosed

The lane was killed mid-flight. The docstring describes `find_card_numbers` and `find_ssns` in
detail (Luhn + IIN + brand length + digit boundaries + payment context; the context-free SSN scan
"REFUSED, in writing, in `find_ssns`'s docstring") -- **neither function exists**. Four helpers
written for the missing checks are dead: `mask_tail`, `mask_ssn`, `display_spans`, `_inside`.

`tests/test_passive_disclosure.py` has no test for any of the eight, so module and gate agree and
neither reports the gap. A call site that iterates `_META` to build a registry will register eight
checks with no producer.

## Q-148 mutation results

    KILLED    PD-M1  POSITIVE CONTROL: _MIN_PEM_BODY 100 -> 0
    KILLED    PD-M2  drop the documentation-placeholder control on PEM blocks
    SURVIVED  PD-M3  THE .env DEFECT re-introduced: re.I on the case-BEARING PEM armour
    SURVIVED  PD-M4  THE .env DEFECT other half: [^\S\n] -> \s in _KTY
    SURVIVED  PD-M5  _CONN_KV_WINDOW 200 -> 100000
    KILLED    PD-M6  drop the placeholder control on credentials (4 tests)
    KILLED    PD-M7  drop the enclosing-object walk (search the whole document)
    KILLED    PD-M8  drop the host-key requirement beside a key-value password
    SURVIVED  PD-M9  _OBJECT_WINDOW 8192 -> 100000
    SURVIVED  PD-M10 _JWK_PRIVATE_MEMBER widened to ANY 1-2 letter key
    KILLED    PD-M11 drop the placeholder control on the URI branch

**PD-M3 and PD-M4 are the important survivors.** This module was written specifically against the
`.env` false positive, and its docstring devotes its longest section to the two defects that caused
it: `re.I` on a case-bearing signature, and `\s` matching newlines. Both defects can be
re-introduced -- into the PEM armour and into `_KTY` respectively -- **without failing a single
test.** The module gets the rule right and nothing holds it there. No fixture in the file contains
lowercase `-----begin rsa private key-----` or a newline between `"kty"` and its colon.

## Q-148 checks that PASSED

* **Check 4, case and whitespace, as SHIPPED.** No `re.I` on any case-bearing signature. PEM armour
  and `"kty":"RSA"` are matched case-exactly; the placeholder word list uses a scoped inline
  `(?i:...)` rather than folding the whole pattern; every horizontal-whitespace class is `[^\S\n]`.
  The `.env` defect is genuinely absent from the code -- it is only absent from the tests (PD-M3/M4).
  The `_CONN_KV_HOST` *window* crosses newlines (PD-4) but no regex `\s` does.
* **Check 7, silent failure.** Zero `except` handlers; the module's "NO `except` HANDLER ANYWHERE IN
  THIS FILE" claim is true (the one grep hit is the word "except" in prose).
* **Check 6, redaction, for PEM and JWK.** `mask_secret` emits `<redacted:N>`; the key body and the
  JWK private member never reach the finding. Only the `@`-in-URI path leaks (PD-3).
* **Public keys and certificates.** `-----BEGIN PUBLIC KEY-----` / `CERTIFICATE` /
  `CERTIFICATE REQUEST` cannot reach the private-key oracle; armour with prose between it stays
  silent. Verified.
* A phpinfo-style table (`mysqli.default_host` / `host=<input>` / `password=<input>`) stays silent.

## Design hazard for the wiring (not a module defect) -- SELF-ECHO

A passive check running over responses the ACTIVE engines provoked reports the scanner's own
payloads:

    input:  <html><body>No results for
            <b>postgres://root:S3cretPassw0rd@10.1.1.9/prod</b></body></html>
    FIRED   db_connection_string_disclosed HIGH
            "a postgres connection string with live credentials is served in this response body
             (user 'root', host '10.1.1.9')"

That is a search page echoing attacker-supplied input. The module is pure and cannot know.
Recommendation: feed it crawl responses only, or have the caller subtract the request's own
parameter values before calling.

---

# CHECK 7 -- SILENT-FAILURE CENSUS (as the brief asked, numbers reported)

    docker run ... apolaki-agent python -m pytest tests/test_silent_failure_invariant.py -q
    -> 1 failed, 12 passed

The single failure is the module-count line the brief said to ignore:

    assert len(trees) == 181   ->  AssertionError: assert 185 == 181

185 production modules are now parsed; the file asserts 181. Four modules landed mid-cycle. All
three modules under audit ARE inside the census.

The ratchets, extracted directly:

    MAIN CENSUS (except handlers): {'optional': 387, 'control-plane': 78}
      caps: optional <= 387   control-plane <= 78     -> BOTH EXACTLY AT CAP, not exceeded
    LITERAL-RETURN CENSUS: cap optional <= 61         -> test passed, under cap

    per-module handler counts for the three new modules:
      code_injection.py       except handlers: 0
      dom_sinks.py            except handlers: 0
      passive_disclosure.py   except handlers: 0

**None of the three modules adds a silent-failure handler.** All twelve non-module-count assertions
in the census pass. The one uncensused discard set is the 11 `catch (e) {}` blocks inside
`dom_sinks.DOM_SINK_HOOKS_JS` -- JavaScript in a string literal, invisible to an AST census, and
each one able to silently disable a collector (see Q-147 checks-that-passed).

---

# WHAT I COULD NOT BREAK

Recorded because a disproved hypothesis is a result.

1. **`code_injection`'s two-token echo immunity, for five of six languages.** 60 rounds x every
   shape x 18 transformations including double-URL-encoding, double-encoded JSON, base64,
   whitespace collapse and WAF operator deletion. Only `el_replace` fell.
2. **An application that genuinely computes the arithmetic.** 200 calculator-style responses that
   echoed the payload and printed the product beside it: 0 findings. The oracle requires the
   concatenation, not the product.
3. **`dom_sinks` against real pages.** 0 findings from live-HTML-derived signals across six lab
   pages, including the literal Q-128 comment-reply-link shape with `server_reflected=True`.
4. **`dom_sinks` structural discriminators.** 7 of 8 gate mutations killed. HPP query-key, XPath
   three-fact differential, DoS repeated differential, the Referer header filter and the form-action
   authority parse are all genuinely defended.
5. **`passive_disclosure` against real pages.** 0 findings across 15 live pages including an 82 KB
   stock WordPress index and a 784 KB Angular bundle.
6. **The `BROWSER_HEADERS` allowlist.** Every omitted client-hint / fetch-metadata header is
   incapable of carrying a URL, so none can leak the Referer trap.
7. **The EL `hashCode` chance collision.** 0 new 6-11 digit integers across two fetches of seven
   live pages; 0 of 20000 tokens shorter than six digits.
8. **The brace-walk-through-CSS attack on `enclosing_object`.** Constructed and did not fire.
9. **`code_injection`'s operand width and nonce palindrome guard.** Both mutable without
   consequence -- they are belt-and-braces, and the marker carries the uniqueness. Not defects.

---

# MUTATION SCOREBOARD

25 mutations attempted, 25 applied and verified (1 initially failed to apply -- pattern occurred
twice -- and was re-run with a unique context). **12 killed, 13 survived.**

| Survived | Why it matters |
|---|---|
| CI-M1 delete the runtime self-check | last defence against a mis-built payload; untested |
| CI-M2 revert `scalar reverse` -> `reverse` | the trap that cost a real measurement can silently return |
| CI-M3 drop the numeric digit boundary | the only defence for the module's one markerless token |
| CI-M6 operands 1000-9999 -> 1-9 | NOT a defect (marker carries uniqueness) |
| CI-M7 `_MARK_RANDOM` 4 -> 0 | **vacuous test**: randomness test is satisfied by the operands |
| CI-M8 nonce palindrome guard | NOT a defect (no shape adjoins marker and nonce) |
| DS-M4 delete all three presence gates | **the two headline tests cannot discriminate** |
| PD-M3 `re.I` on the PEM armour | **the .env defect, re-introducible, zero tests fail** |
| PD-M4 `[^\S\n]` -> `\s` in `_KTY` | **the .env defect's other half, same** |
| PD-M5 proximity window 200 -> 100000 | the only control separating PD-4 from "any page with password" |
| PD-M9 `_OBJECT_WINDOW` 8192 -> 100000 | the brace walk's bound is untested |
| PD-M10 private-member list -> any 1-2 letter key | the "structural not grep" claim rests on an untested allowlist |

---

# RECOMMENDED ORDER OF WORK FOR THE COORDINATOR

1. **Do not ship `el_replace`** (or ship it only with a token that is not a deletion-image of its
   payload). If `shapes_per_language` is ever set above 2 in `tools.py`, this is a live HIGH
   false-positive generator on any target with an alphanumeric-only filter.
2. **Wire `display_spans` into `find_private_keys`, or delete the claim from the docstring.** Today
   the docstring promises an FP control that does not run.
3. **Make the JWK member search non-descending** (reject a match inside a nested object), and add
   the nested negative control.
4. **Line-scope the `_CONN_KV_HOST` window**, and drop `uid` from the host-key vocabulary or require
   two host-keys. Then implement `password_in_url` so the right check owns input B.
5. **Add the five proxy properties to `WebCodeProbe`**, or pass `.probe` at the call site.
6. **Rebuild the two `dom_sinks` inherited-rule fixtures out of this module's own evidence keys.**
7. Make `websocket_url_poisoning` structural on the authority; keep a low-severity informational
   variant for a canary in the query.
8. Exclude the URI host class from swallowing `@`, and re-mask.
9. Add the two negative controls the `.env` lesson needs: lowercase PEM armour, and a newline
   between `"kty"` and its colon.

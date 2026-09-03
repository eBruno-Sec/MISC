# Q-176 (reopened) - Host header injection is graded by REFLECTION, not by LANDING SITE

Builder lane. Owner of `agent/web_security.py`, `agent/tests/test_host_header_landing.py`, this file.
`agent/tools.py` is owned by another lane - producer changes are a DIFF at the bottom, not an edit.

## 0. The claim under test

`agent/web_security.py::analyze_host_header`, body branch (pre-fix):

```python
    if _EVIL_HOST in (body or "").lower():
        return {"severity": "LOW", "detail": "spoofed Host reflected in response body"}
```

Producer `success_oracle` (tools.py, verbatim): "the injected host appears in the response body
or redirect target, so the app trusts the Host header".

I withdrew this ticket once, on the reasoning "the reflection is genuine so the grade is
defensible". That reasoning was about DETECTION. The Breaker measured LANDING SITE, which is what
the grade is actually a claim about, and the two are not the same question. Its evidence is better
than mine and reopens the ticket.

## 1. MEASURED - the landing sites, reproduced independently

Not a replay of the Breaker's numbers - my own fetches, own probe host `evil.apolaki.test`, own
throwaway container. `Host` and `X-Forwarded-Host` sent SEPARATELY, because the mission's combined
request cannot say which header the app honoured.

```
MSYS_NO_PATHCONV=1 docker run --rm --network apolaki_default apolaki-agent python -c "..."
```

| target | hdr | code | occ | in ServerSignature | landing |
|---|---|---|---|---|---|
| `/javascript/jQuery/?C=N;O=D` | Host | 200 | 1 | 1 | `<address>` only |
| `/javascript/jQuery/?C=N;O=D` | XFH  | 200 | 0 | 0 | nothing |
| `/nope-404-page`              | Host | 404 | 1 | 1 | `<address>` only |
| `/nope-404-page`              | XFH  | 404 | 0 | 0 | nothing |
| `/webservices/soap/ws-user-account.php?wsdl` | Host | 200 | 1 | 0 | `soap:address location=` |
| `/webservices/soap/ws-user-account.php?wsdl` | XFH  | 200 | 0 | 0 | nothing |
| `/index.php`, `/`             | Host | 200 | 0 | 0 | **nothing** |
| `/phpmyadmin/server_databases.php`, `/querywindow.php`, `/import.php`, `/chk_rel.php` | Host | 200 | 1 | 0 | `parent.document.title = '...'` |
| `/phpmyadmin/main.php`        | Host | 200 | 2 | 0 | document.title AND `<a href="http://EVIL/...">` |
| `/phpmyadmin/db_structure.php`, `/tbl_change.php` | Host | 302 | 0 | 0 | `Location:` header |

Verbatim contexts:

```
<address>Apache/2.4.7 (Ubuntu) Server at evil.apolaki.test Port 80</address>
<soap:address location="http://evil.apolaki.test/webservices/soap/ws-user-account.php"/>
parent.document.title = 'evil.apolaki.test / 127.0.0.1 | phpMyAdmin 3.5.
<a href="http://evil.apolaki.test/phpmyadmin/chk_rel.php?lang=e
Location: http://evil.apolaki.test/phpmyadmin/main.php?lang=en&collation_connection=utf8_g
```

Three decisive facts:

1. **The application under test does not reflect Host at all.** `/index.php` and `/` - the actual
   Mutillidae app - return occ=0. Only Apache-generated documents (404, mod_autoindex) and the
   vendored phpMyAdmin do. The claimed oracle "the app trusts the Host header" is FALSE on 40 of 65.
2. **`X-Forwarded-Host` alone is honoured NOWHERE on this host** - occ=0 on every single target
   including the ones where `Host` reflects. The producer's evidence string names a header that did
   nothing.
3. **The classes are structurally separable.** ServerSignature is `<address>...Server at HOST Port
   N</address>`; the actionable ones put HOST in the AUTHORITY position of an absolute URL
   (`//HOST/`); the inert ones are bare text in a title or a JS string. Two regexes split them.

## 2. The rule I shipped

Grade by what a client can be made to do from where the host landed, extending the Q-114
MEDIUM/INFORMATIONAL vocabulary rather than inventing a new one. Detection is UNCHANGED - every
body reflection that fired before still fires; only the severity and the evidence move.

* **URL authority** - `(?:https?:)?//HOST` followed by a URL delimiter, i.e. the host is the
  authority a client would resolve: `href`/`src`/`action`, a WSDL `soap:address location=`, a
  `meta refresh`, a JS absolute-URL string, a password-reset link. -> **grade UNCHANGED (LOW)**, and
  the detail names the sink.
* **ServerSignature only** - every occurrence of the host is inside `<address>...Server at HOST Port
  N</address>`. -> **INFORMATIONAL**, and the detail says SERVER-GENERATED explicitly: this is
  Apache's `UseCanonicalName Off` default echoing into its own error/index footer, a property of the
  web server, not of the application under test.
* **Inert text** - reflected, but not as a URL authority. -> **INFORMATIONAL**, detail names the
  landing site (`<title>`, `document.title`, or a bare text node).

`Location:` branch untouched: Q-114 already grades it MEDIUM-with-sink / INFORMATIONAL-without, and
the Breaker measured that half as CORRECT.

### Why NOT the Breaker's proposed regex

Its patch used an attribute-name whitelist:

```
(?:href|src|action|location)\s*=\s*["\']?https?://HOST
```

It fails two ways I measured:

* It does not match a PROTOCOL-RELATIVE URL, and
  `test_host_header_oracle_is_structural.py::test_body_reflection_is_unchanged_and_still_LOW` feeds
  exactly `<a href='//HOST/x'>` and requires LOW. The proposed patch turns a real, existing,
  passing oracle test RED. Verified before writing any code.
* It misses `pma_absolute_uri = 'http://HOST/phpmyadmin/'` on `/phpmyadmin/` - a JS variable that
  phpMyAdmin builds its own navigation URLs from - because the name is not in the whitelist.

The authority test `(?:https?:)?//HOST(?=[/:?#"'\s\\<>&]|$)` is both more general and shorter: it
does not enumerate sink names, it asks the one structural question that decides the claim.

## 3. MEASURED - mutation results, both directions

Five mutants, each applied to a COPY of the tree in the scratchpad (the shared working tree is never
mutated), run against
`tests/test_host_header_landing.py` + the two pre-existing host-header oracle files.

```
BASELINE (unmutated): rc=0, 46 passed
M1  old unconditional LOW on any body reflection      KILLED  (17 failing)
M2  over-correction: every landing -> INFORMATIONAL   KILLED  (12 failing)
M3  signature branch drops the `sig == occ` equality  KILLED  (1 failing)
M4  authority test loses its delimiter lookahead      KILLED  (1 failing)
M5  `server_generated` hardcoded True                 KILLED  (2 failing)
```

The two the ticket named, killed by the intended assertion:

* **M1 - restores the defect.** Killed first by
  `test_the_apache_autoindex_signature_is_informational_not_low` and
  `test_the_apache_404_signature_is_informational_not_low`. It is ALSO killed by
  `test_THE_WSDL_SOAP_ADDRESS_IS_STILL_LOW`, which is the interesting one: M1 grades the WSDL LOW,
  the same as the fix, and still dies - because the evidence no longer names `soap:address`. A
  correct grade carrying a false claim is still a failure.
* **M2 - the over-correction, and the more dangerous defect of the two.** Killed by
  `test_THE_WSDL_SOAP_ADDRESS_IS_STILL_LOW`, `test_the_phpmyadmin_page_that_has_BOTH_stays_low`,
  `test_a_javascript_absolute_url_variable_is_actionable`, the form-action / password-reset /
  meta-refresh / script-src / unnamed-sink cases, AND both pre-existing oracle tests
  (`test_body_reflection_is_unchanged_and_still_LOW`,
  `test_the_body_reflection_branch_is_untouched_and_still_low`). Silencing the 4 real rows is caught
  by 12 assertions, not by one.

M3, M4 and M5 each die by exactly ONE intended assertion, which is what says the test file is
discriminating rather than merely large.

### A mutation run that lied, and how it was caught

The first pass reported all five KILLED. M4's kill list was byte-identical to M3's, which is not
what an independent mutant looks like. Cause: the applier printed `ANCHOR-MISSING` for M4 because
the hardcoded anchor string had mangled escaping, exited without writing, and left M3's mutation in
place - so "M4" was scored against M3's file. The guard missed it because the container emitted a
`SyntaxWarning` line ahead of the marker and the shell tested only the FIRST line of output.

Two fixes, both kept: M4 is now applied by a regex over the pristine text instead of a hand-escaped
literal, and the runner asserts every mutant actually CHANGES THE FILE (`diff` against pristine)
before any verdict is trusted. That self-check is what turns "5 killed" into evidence. This is the
`instrumentation-changes-what-it-measures` failure mode: the measurement apparatus was broken in a
direction that produced the answer I wanted.

## 4. NOT MINE - dead-code gate red in the shared tree

A full unscoped `pytest tests/` was red on 4 `tests/test_deadcode_gate.py` cases. MEASURED cause:

```
UNACCOUNTED -- flagged in this tree and in NEITHER recorded measurement:
  exposure_tool.directory_candidates
```

`exposure_tool.py` belongs to another lane, which is mid-edit. Neither `web_security` nor
`host_header_landing` appears anywhere in the flagged set - the new function is correctly seen as
WIRED, not as an island. Not my defect, not my file; recorded and moved past.

A second shared-tree artefact, recorded so nobody chases it: one scoped run hit
`Interrupted: 5 errors during collection` on `test_auto_store_reach.py`, `test_autonomy_loop.py`,
`test_backoff_ledger.py` and two others. Re-running the same command minutes later collected and
passed all of them with no change from me. That is a torn read of a tree another lane is writing,
not a failure - which is exactly why the full unscoped suite is the wrong instrument here. My three
host-header files plus `test_bbh.py` (290 tests) were green throughout.

## 5. MEASURED - the reclassification census

I could not read mission `bed9ffcd`'s 65 URLs (no ledger on disk), so I rebuilt an equivalent target
set the way the mission's own content discovery did: crawl `mod_autoindex` listings from `/.git/`,
`/javascript/`, `/documentation/`, `/passwords/`, `/images/`, plus the three SOAP WSDLs, the
phpMyAdmin scripts, Apache 404s, and the application's own pages. 67 targets, of which 62 make the
oracle fire - the same order as the mission's 65.

```
targets fetched: 67   rows where the oracle fires: 62
X-Forwarded-Host alone honoured on: 0 of 67

OLD grade distribution:                          NEW grade distribution:
   LOW                                    56        INFORMATIONAL (server_signature)   40
   MEDIUM/INFORMATIONAL (Location, Q-114)  6        INFORMATIONAL (inert)              10
                                                    LOW (url_authority)                 6
                                                    INFORMATIONAL (location)            6

RECLASSIFIED LOW -> INFORMATIONAL: 50       LOW kept as LOW: 6
```

The six that KEPT the grade - the ones an over-correction would have silenced:

```
/webservices/soap/ws-hello-world.php?wsdl          LOW -> LOW (url_authority)
/webservices/soap/ws-lookup-dns-record.php?wsdl    LOW -> LOW (url_authority)
/webservices/soap/ws-user-account.php?wsdl         LOW -> LOW (url_authority)
/phpmyadmin/ , /phpmyadmin/index.php               LOW -> LOW (url_authority)   pma_absolute_uri
/phpmyadmin/main.php                               LOW -> LOW (url_authority)   <a href="http://HOST/...">
```

All 3 WSDLs survive. The `server_signature` count is **40, the same number the Breaker measured
independently** - two different target sets, two different probe hosts, same figure, which is what
makes it a property of the host rather than of either replay.

**`X-Forwarded-Host` alone was honoured on 0 of 67 targets.** That is a producer defect, not an
oracle one: the emitted `evidence` string names XFH as having come back when it did nothing.

## 6. PRODUCER DIFF for the tools.py owner - NOT APPLIED BY ME

`agent/tools.py` is another lane's file. The oracle now returns `landing` and `server_generated`, and
nothing reads them yet. Three defects live in the producer, all of them wrong CLAIMS rather than
wrong grades:

1. `success_oracle` is a hardcoded constant that says "so the app trusts the Host header". MEASURED
   false on 40 of 62 - the application never ran. It must come from the finding, not from a literal.
2. `evidence` says "an attacker-supplied Host/X-Forwarded-Host came back". MEASURED: XFH was honoured
   on 0 of 67 targets. It names a header that did nothing.
3. One `ServerSignature On` produces one row PER URL. 40 rows, one fact.

```diff
--- a/agent/tools.py
+++ b/agent/tools.py
@@ -8470,7 +8470,12 @@
                     if v:
-                        findings.append({"title": "Host header injection", "severity": v["severity"].lower(),
+                        # Q-176. The TITLE has to carry the landing class or a triager opens 40
+                        # identical rows before reaching the one that matters.
+                        _t = {"server_signature": "Host reflected in the web server's ServerSignature "
+                                                  "footer (server-generated page)",
+                              "inert": "Host reflected into an inert sink",
+                              "url_authority": "Host header injection into an absolute URL"}
+                        findings.append({"title": _t.get(v.get("landing"), "Host header injection"),
+                                         "severity": v["severity"].lower(),
                                          "target": url, "description": v["detail"],
                                          "confidence": "confirmed", "cwe": "CWE-644",
-                                         "evidence": "an attacker-supplied Host/X-Forwarded-Host (%s) came "
-                                                     "back in the response or its Location: %s"
-                                                     % (ws._EVIL_HOST, v["detail"]),
-                                         "success_oracle": "the injected host appears in the response body "
-                                                           "or redirect target, so the app trusts the Host header",
+                                         # Name ONLY the header that was actually honoured. MEASURED on
+                                         # mutillidae: X-Forwarded-Host alone came back on 0 of 67 targets,
+                                         # so the old string credited a header that did nothing.
+                                         "evidence": "an attacker-supplied Host: %s came back in the "
+                                                     "response or its Location -- %s"
+                                                     % (ws._EVIL_HOST, v["detail"]),
+                                         "success_oracle": v["detail"],
+                                         "landing": v.get("landing"),
+                                         "server_generated": bool(v.get("server_generated")),
                                          "family": "host_header", "tags": ["hostheader"]})
```

Plus a dedup rule wherever `family=host_header` rows are collapsed: key on
`(host, landing, server_generated)` rather than the full URL, carrying the affected-URL list on the
single surviving row. On this census that turns 62 rows into 4: one `server_signature`, one `inert`,
one `url_authority`, one `location`.

**A note for that lane on the gate at line 8464.** `if ws.analyze_host_header(hh.text, ...)` still
guards the second XFH request, and my change keeps every previous reflection truthy, so that gate
behaves exactly as before - no extra requests, no lost ones. I deliberately did NOT add an
`xfh_body=` parameter: no caller could pass it until this diff lands, and an unwired parameter is an
island wearing the costume of thoroughness.

## 7. What I did NOT change, and why

* **Detection.** Every body reflection that fired before still fires. The ticket is about the claim
  attached to the finding, not about whether to look.
* **The `Location` branch.** Q-114's MEDIUM-with-sink / INFORMATIONAL-without split was measured
  CORRECT by the Breaker and my census reproduces it (6 rows, all INFORMATIONAL, no cache indicator
  and XFH not honoured anywhere on this host).
* **Upgrading the WSDL rows.** The Breaker called them "TRUE, under-graded". They may well be, but
  the ticket said keep the current grade for actionable sinks, and moving a severity UP on the same
  evidence that just proved severities were asserted rather than measured would repeat the defect
  facing the other way. Left at LOW; the evidence now says why it matters.

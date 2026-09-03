# Breaker v16 - hand-verified FP triage of mission `bed9ffcd` (target: local mutillidae lab)

Lane: BREAKER. Written as I go. Every row is MEASURED (command + real output pasted) or UNVERIFIED.
Mission `bed9ffcd`, 113 findings, target `http://mutillidae` (compose hostname, reachable only from
inside `apolaki-agent-1`). All reproductions were run read-only via
`docker exec -i apolaki-agent-1 python - <<PY ... PY` with `httpx`.

Rule used for the verdicts:
- FALSE = the oracle's stated claim does not hold structurally. The mechanism named in the finding is
  not the mechanism that produced the observation.
- OVERGRADED = the observation is real, but the severity/confidence/title overstates what was proven.
- TRUE = I can show the mechanism.

---

## 1. DISPROVED FINDINGS (write these down first - this is the part I would most regret losing)

### 1.1 FALSE - `LDAP injection in form field 'new_db'` (HIGH, CVSS 8.2, confidence=confirmed)

Finding id `27dc7c5a377b`, target `http://mutillidae/phpmyadmin/db_create.php`, engine `ldap`,
dispatch `run_ldap`.

Claimed evidence, verbatim:

> The form field 'new_db' is concatenated into an LDAP search filter. an LDAP boolean differential
> changed only one filter assertion from universally true to an impossible value; the true predicate
> returned a strict record-set superset (102%, 112%, 122%, 132%) while the contradiction did not

**MEASURED. The claim is false on three independent counts.**

Command:

```
docker exec -i apolaki-agent-1 python - <<'PY'
import httpx
c = httpx.Client(timeout=25, follow_redirects=False)
url="http://mutillidae/phpmyadmin/db_create.php"
def post(label, data):
    r=c.post(url, data=data)
    print("### %s -> HTTP %s len=%d" % (label, r.status_code, len(r.text)))
    return r
b=post("BASELINE new_db=testdb", {"new_db":"testdb"})
t=post("PROBE  tautology  new_db=*)(objectClass=*", {"new_db":"*)(objectClass=*"})
f=post("NEGCTRL contradiction", {"new_db":"*)(objectClass=zzqq"})
n=post("NEGCTRL nonsense", {"new_db":"zzqqnonsense"})
print("identical taut vs contradiction:", t.text==f.text)
print("identical nonsense vs taut:", n.text==t.text)
PY
```

Real output:

```
### BASELINE new_db=testdb -> HTTP 200 len=1160
### PROBE  tautology  new_db=*)(objectClass=* -> HTTP 200 len=1107
### NEGCTRL contradiction new_db=*)(objectClass=zzqq -> HTTP 200 len=1107
### NEGCTRL nonsense    new_db=zzqqnonsense -> HTTP 200 len=1107
identical taut vs contradiction: True
identical nonsense vs taut: True
```

**(a) The negative control is byte-identical to the probe.** The "universally true" filter assertion
and its "deliberately impossible" twin return the SAME 1107 bytes. There is no differential at this
endpoint at all. Re-measured 3x each for stability: tautology `[1107, 1107, 1107]`, contradiction
`[1107, 1107, 1107]`. Not a dynamic page, not a flake.

**(b) The application never processed the field.** Stripping tags from the 1107-byte body:

```
VISIBLE TEXT of tautology response:
phpMyAdmin db_create.php: Missing parameter: new_db

VISIBLE TEXT of baseline response:
phpMyAdmin db_create.php: Missing parameter: new_db
```

The app literally answers `Missing parameter: new_db` while the finding asserts `new_db` is
"concatenated into an LDAP search filter". A bare `GET /phpmyadmin/db_create.php` returns the same
1107 bytes. I also retried with a live phpMyAdmin session cookie jar and a `token` field
(`follow_redirects=True`, token harvested from `/phpmyadmin/`) - identical result, all three variants
`HTTP 200 len=1107 :: phpMyAdmin db_create.php: Missing parameter: new_db`. So this is not a
"we forgot the CSRF token" artefact either.

**(c) phpMyAdmin 3.x/4.x `db_create.php` issues a MySQL `CREATE DATABASE`. There is no directory
server in this stack.** The finding names CWE-90 and an LDAP filter on a page whose only backend is
MySQL.

**(d) The "record-set superset (102%, 112%, 122%, 132%)" is phpMyAdmin's font-size dropdown.**
Located:

```
docker exec -i apolaki-agent-1 python - <<'PY'
import httpx, re
c=httpx.Client(timeout=25, follow_redirects=True)
t=c.get("http://mutillidae/phpmyadmin/main.php").text
i=t.find("102%"); print(re.sub(r"\s+"," ",t[i-260:i+90]))
PY
```

Real output:

```
n value="82%" selected="selected">82%</option> <option value="83%">83%</option> <option
value="84%">84%</option> ... <option value="92%">92%</option> <option value="102%">102%</option>
<option value="112%">112%</option> <option value="122%">122%</option>
```

Those four "records" are `<option>` entries in the phpMyAdmin appearance/font-size `<select>` on
`main.php`. They are not directory objects, and they are not on `db_create.php`.

#### Oracle defect (a) - `agent/semantic_differential.py::_SemanticHTML.handle_starttag`

```python
if tag in _RECORD_TAGS:
    record_id = next((_norm(ad[k]) for k in _RECORD_ID_ATTRS if ad.get(k)), "")
    recordish = bool(record_id or _RECORD_CLASSES.search(ad.get("class", "")))
    if tag == "option" and ad.get("value"):
        record_id, recordish = _norm(ad["value"]), True     # <-- every <option value> is a "record"
```

**Asserts:** "a strict record-set superset" - i.e. the true predicate made the directory return
directory entries the contradiction did not.
**Actually checks:** that the set of `<option value=...>` strings (plus any element containing a
`<td>`) in body A is a proper superset of the set in body B. A UI `<select>` - font size, language,
collation, rows-per-page, timezone - is indistinguishable from a directory record set under this
rule. Any two responses where one renders a settings page and the other renders an error page satisfy
`yes["records"] > no["records"]`.

#### Oracle defect (b) - `agent/semantic_differential.py::evaluate` has no same-page precondition

```python
def evaluate(true_body, false_body, true_payload="", false_payload=""):
    yes = snapshot(true_body, payloads)
    no  = snapshot(false_body, payloads)
    ...
    if yes["records"] and yes["records"] > no["records"]:
        return {"confirmed": True, "signal": "record_set", ...}
```

`evaluate` never checks that the two bodies are the same page, the same status, or even that the
payload was accepted. It does not check that the parameter was echoed, that the endpoint acknowledged
it, or that the sets are disjoint from static UI chrome. A superset relation between two
differently-rendered pages is accepted as a boolean-injection proof. This is the generic form of the
defect and it is shared by every caller of `sd.evaluate` (`ldap_tool.evaluate_boolean` is one of
them; grep `agent/` for `semantic_differential` before trusting any other boolean-differential
family).

#### Oracle defect (c) - `agent/ldap_tool.py::evaluate_boolean` adds an LDAP claim it did not test

```python
def evaluate_boolean(true_body, false_body, true_payload, false_payload):
    ev = sd.evaluate(true_body, false_body, true_payload, false_payload)
    if not ev["confirmed"]:
        return {"confirmed": False, "oracle": ""}
    return {"confirmed": True,
            "oracle": ("an LDAP boolean differential changed only one filter assertion from "
                       "universally true to an impossible value; %s" % ev["oracle"])}
```

`sd.evaluate` is protocol-agnostic. `evaluate_boolean` wraps its generic verdict in the sentence
"an LDAP boolean differential ... filter assertion", and `ldap_tool.finding()` then hardcodes
`"confidence": "confirmed"`, `"severity": "high"`, `"cvss_score": 8.2`, `"cwe": "CWE-90"`. Nothing
anywhere on this path required a single piece of LDAP-specific evidence. The module's own docstring
says confirmation is "LDAP-SPECIFIC" and that "Status, response size, and error text do not
participate" - the error-signature path (`ldap_tool.evaluate`, `LDAP_ERRORS`) genuinely is specific;
the boolean path is not, and it is the one that fired.

**This is the single most dangerous defect in the mission.** It manufactures a `confirmed` HIGH
(CVSS 8.2) naming a protocol the target does not speak, on a parameter the target says is missing,
with a negative control that is byte-identical to the probe.

#### Proposed patch (NOT applied - I do not own these files)

```diff
--- a/agent/semantic_differential.py
+++ b/agent/semantic_differential.py
@@
 def evaluate(true_body: str, false_body: str, true_payload: str = "", false_payload: str = "") -> dict:
     """Confirm only a semantic true/contradiction split, never transport or presentation noise."""
     payloads = (true_payload, false_payload)
     yes = snapshot(true_body, payloads)
     no = snapshot(false_body, payloads)
+    # NEGATIVE CONTROL, structural: identical bodies can never carry a differential. A record-set
+    # split is only meaningful when BOTH sides rendered the same page; a settings page vs an error
+    # page trivially satisfies the superset relation without any injection having occurred.
+    if _norm(true_body) == _norm(false_body):
+        return {"confirmed": False, "signal": "", "oracle": ""}
     if yes["auth"] == "authenticated" and no["auth"] == "unauthenticated":
@@
-    if yes["records"] and yes["records"] > no["records"]:
+    # A record set that is entirely static UI chrome (a <select> of font sizes, collations, page
+    # sizes) is not a directory/DB record set. Require the gained identities to be absent from a
+    # third, payload-free control render of the same URL before believing them.
+    if yes["records"] and yes["records"] > no["records"] and not _looks_like_ui_chrome(yes["records"] - no["records"]):
         gained = sorted(yes["records"] - no["records"])
```

```diff
--- a/agent/ldap_tool.py
+++ b/agent/ldap_tool.py
@@ def evaluate_boolean(...)
     ev = sd.evaluate(true_body, false_body, true_payload, false_payload)
     if not ev["confirmed"]:
         return {"confirmed": False, "oracle": ""}
+    # The boolean path proves "input changes the query", not "the query is LDAP". Emitting CWE-90 at
+    # CVSS 8.2 requires at least one LDAP-specific corroborator; otherwise degrade the family.
+    if not (ldap_error(true_body) or ldap_error(false_body)):
+        return {"confirmed": False, "oracle": ""}
     return {"confirmed": True, ...}
```

A cheaper, strictly-correct alternative if the boolean path must stay: keep it, but emit it as
`family="boolean_differential"`, `severity="low"`, `confidence="candidate"` with a title that does
not name LDAP.

---

### 1.2 Recall check on the ground truth - see section 4. The mission MISSED the real RCE.

---

## 2. VERIFIED TRUE POSITIVES

### 2.1 TRUE - `Path traversal in query parameter 'page'` (HIGH)

Finding id `d9939395d5c5`, engine `web_probes`.

**MEASURED.** Baseline / probe / negative control:

```
### BASELINE page=add-to-your-blog.php -> HTTP 200 len=71158
    contains 'root:x:0:0'  : False
### PROBE page=../../../../../../etc/passwd -> HTTP 200 len=44344
    contains 'root:x:0:0'  : True
    contains 'daemon:x:'   : True
    contains 'sbin/nologin': True
### NEGCTRL page=../../../../../../etc/NOSUCHFILE_zzqq -> HTTP 200 len=44655
    contains 'root:x:0:0'  : False
    contains 'daemon:x:'   : False
    traversal match line: root:x:0:0:root:/root:/bin/bash
```

The mechanism is shown: `/etc/passwd` content appears only for the real path, and a structurally
identical traversal to a nonexistent file does not produce it. Verdict TRUE, severity HIGH is right.

**Reporting defect (not a false positive, but it would waste a triager's time on a live programme):**
the finding's `target`, `request` and `curl` fields all record the BASELINE URL
(`http://mutillidae/?page=add-to-your-blog.php&popUpNotificationCode=SUD1&uniqid=`), not the probe.
Running the `curl` line as printed reproduces nothing. The traversal payload appears only inside the
free-text `evidence` string. On Shopify this ships a HIGH whose own repro command returns a clean
page.

Proposed patch shape: `web_probes` should set `target`/`request`/`curl` from the probe request, and
put the baseline in a separate `baseline_request` field.

### 2.2 TRUE - SQL injection (error-based), 4 findings (HIGH)

`5cf8cb52541e` (`username`), `478cb661b2f2` (`level1HintIncludeFile`), `3a3cadf17058` (`pagename`),
`573c9525263c` (`blog_entry`). Engine `sqli`.

The stored `response` field on three of the four contains the server's own MySQL error naming the
concatenated query, e.g. for `username`:

```
"error: You have an error in your SQL syntax; ... near ''adrian''' at line 3"
... ) Query: SELECT username, mysignature FROM accounts WHERE username='adrian''
#2 /app/webservices/rest/ws-user-account.php(64):
   SQLQueryHandler->getNonSensitiveAccountInformation('adrian'')
```

That is the mechanism in full: the value lands inside a quoted literal in a real statement. A
negative-control record is present in the finding
(`unmodified-baseline-signature-absence`: the MySQL signature is absent from the baseline). Verdict
TRUE for all four. `blog_entry` is recorded with a truncated body (see section 5, UNVERIFIED items) -
listed TRUE on the strength of the same engine + negative control, flagged for re-measurement.

### 2.3 TRUE - all 6 `XSS confirmed` criticals

`68b58e17f129`, `bbc988594978`, `02c7ff56115e` (query `page`), `4a73a39c1384` (`username`),
`590222d00b58` (`level1HintIncludeFile`), `33f2d1a17a36` (`pagename`). Engine `xss`.

**MEASURED, with a structural oracle (the payload must become an ELEMENT, not text) and a negative
control on every one.** Command feeds `"><img src=x onerror=alert(/bbhx7/)>` and parses the response
with `html.parser`, counting `img` elements that carry an `onerror` attribute; the negative control
replaces the payload with `zzqqnonsense`.

```
A root ?page=          img[onerror] elements in parsed DOM: 6  [{'src': 'x', 'onerror': 'alert(/bbhx7/)'}]
                       NEGCTRL img[onerror] elements: 0
B index.php ?page=     img[onerror] elements in parsed DOM: 6  [{'src': 'x', 'onerror': 'alert(/bbhx7/)'}]
                       NEGCTRL img[onerror] elements: 0
C ws-user-account      img[onerror] elements in parsed DOM: 1  [{'src': 'x', 'onerror': 'alert(/bbhx7/)'}]
                       NEGCTRL img[onerror] elements: 0
D hints-page-wrapper   img[onerror] elements in parsed DOM: 1  [{'src': 'x', 'onerror': 'alert(/bbhx7/)'}]
                       NEGCTRL img[onerror] elements: 0
E pop-up-help          img[onerror] elements in parsed DOM: 1  [{'src': 'x', 'onerror': 'alert(/bbhx7/)'}]
                       NEGCTRL img[onerror] elements: 0
```

All five distinct injection points return `Content-Type: text/html` and reflect the payload RAW (no
HTML entity encoding), and the injected `<img onerror>` exists as a real element in the parsed
document. Landing contexts, measured:

- `page` : `<td><a href="index.php?do=toggle-hints&page="><img src=x onerror=...>">Toggle Hints</a>` - breaks out of an `href` attribute.
- `username` : `Result: {User '"><img src=x onerror=...>' does not exist}` (68-byte `text/html` response).
- `pagename` : `<div class="help-text-header"> Page "><img src=x onerror=...> does not have any help`.
- `level1HintIncludeFile` : raw inside the rendered MySQL error message.

Verdict TRUE, CRITICAL is defensible. **Caveat: 6 rows for 4 distinct injection points.** `page` is
reported three times (`/?page=`, `/index.php?page=` and a third "promoted from candidate lead" row,
`02c7ff56115e`, whose target is byte-identical to `68b58e17f129`). On a live programme that is three
reports for one bug. Dedup key should be (host, path-normalised-endpoint, param, family), not the
full URL with its incidental extra query parameters.

---

## 3. OVERGRADED / MIS-CLASSIFIED

### 3.1 OVERGRADED - 62 of 65 `Host header injection` rows (LOW x62, informational x3)

Engine `injection_probes` -> `agent/web_security.py::analyze_host_header`.

Claimed `success_oracle`, verbatim:

> the injected host appears in the response body or redirect target, so the app trusts the Host header

**MEASURED.** I replayed all 65 recorded targets with `Host: bbh-evil.example` and classified where
the reflection actually lands (Apache `ServerSignature` footer / a URL-valued attribute / other body
text / the `Location` header):

```
APACHE-SIGNATURE-ONLY          40
OTHER-BODY-TEXT                18
URL-CONTEXT(href/src/action)    4
LOCATION-HEADER                 3
```

**The 40 `APACHE-SIGNATURE-ONLY` rows are OVERGRADED and their stated claim is false.** The only
occurrence of the spoofed host anywhere in those responses is Apache's own footer:

```
### PROBE Host: bbh-evil.example   (http://mutillidae/documentation/index.php?page=...)
    HTTP 404 len=302
    ctx: <address>Apache/2.4.7 (Ubuntu) Server at bbh-evil.example Port 80</address>
```

Decisive negative control - **the application does not reflect the Host at all**:

```
app page (PHP 200)     HTTP 200 body=False Location=False
app root               HTTP 200 body=False Location=False
apache 404             HTTP 404 body=True  only-in-<address>=True
autoindex listing      HTTP 200 body=True  only-in-<address>=True
```

`mutillidae/index.php` and `/` - the actual application - never emit the spoofed host. Only
Apache-generated documents do: the 404 error page and `mod_autoindex` listings. So "the app trusts
the Host header" is contradicted by measurement; what trusts it is `ServerSignature On`, a web-server
default, in an inert `<address>` text node. This matches the ground truth already established by
hand. The right grade for those 40 is INFORMATIONAL at most, as one finding, not 40.

Also measured: `X-Forwarded-Host` alone is NOT honoured (`body=False`), so the evidence string
"an attacker-supplied Host/X-Forwarded-Host ... came back" names a header that did nothing.

**Dedup:** one server-level configuration fact produced 40 rows. 18 more are one phpMyAdmin behaviour
(`parent.document.title = 'bbh-evil.example / 127.0.0.1 | phpMyAdmin 3.5.2.2';` - a JS string
assigning the document title, also inert) repeated across 18 phpMyAdmin scripts.

**The 4 + 3 that ARE real are buried.** These deserved to be the output:

```
URL-CONTEXT  http://mutillidae/webservices/soap/ws-hello-world.php?wsdl
URL-CONTEXT  http://mutillidae/webservices/soap/ws-lookup-dns-record.php?wsdl
URL-CONTEXT  http://mutillidae/webservices/soap/ws-user-account.php?wsdl
     <soap:address location="http://bbh-evil.example/webservices/soap/ws-hello-world.php"/>
```

A WSDL whose `soap:address` is built from the request Host redirects every SOAP client that fetches
it to the attacker. And the three `Location`-header cases:

```
severity=informational HTTP 302  Location: http://bbh-evil.example/phpmyadmin/
severity=informational HTTP 302  Location: http://bbh-evil.example/phpmyadmin/main.php?token=ce78260ea94e...&reload=1
severity=informational HTTP 302  Location: http://bbh-evil.example/phpmyadmin/main.php?token=ce78260ea94e...&message=%231065...
```

Note the second and third leak a phpMyAdmin CSRF `token` to the attacker host in the redirect target.

To be fair to the engine: the `informational` grade on those three is CORRECT and well-earned. The
`Location` branch (Q-114) probes for a shared-cache indicator and for `X-Forwarded-Host` honouring,
finds neither, and downgrades. That half of the oracle is sound. **It is the body branch that is
broken.**

#### Oracle defect - `agent/web_security.py::analyze_host_header`, body branch (line ~903)

```python
    if _EVIL_HOST in (body or "").lower():
        return {"severity": "LOW", "detail": "spoofed Host reflected in response body"}
    return None
```

**Asserts:** "the app trusts the Host header".
**Actually checks:** the literal string `bbh-evil.example` occurs anywhere in the bytes, including in
the web server's own default footer, including in a JS `document.title` assignment, including on a
404 error page the application never generated.

The docstring defends this as acceptable because "it is already LOW ... and a host string in HTML has
no structure to parse". Both halves are wrong in practice. LOW x62 on a single host is not cheap - it
is the bulk of the report, and `report.py:2481` already records the same shape reaching a live
Shopify run ("SEVEN `Host header injection` rows"). And the reflection *does* have parseable
structure: the classification above separated 40/18/4 cleanly with two regexes.

#### Proposed patch (NOT applied)

```diff
--- a/agent/web_security.py
+++ b/agent/web_security.py
@@
-    if _EVIL_HOST in (body or "").lower():
-        return {"severity": "LOW", "detail": "spoofed Host reflected in response body"}
-    return None
+    b = (body or "")
+    if _EVIL_HOST not in b.lower():
+        return None
+    # NEGATIVE CONTROL, structural. A host string in HTML DOES have structure to parse, and the
+    # three contexts carry three different claims:
+    #   1. the web server's own ServerSignature footer  -> the APPLICATION never saw the Host
+    #   2. a URL-valued attribute / WSDL soap:address    -> a real client-redirection primitive
+    #   3. inert body text (a JS document.title, a label) -> reflection, no primitive
+    # MEASURED on mutillidae: 40 of 65 rows were case 1 -- Apache's <address> on 404 and autoindex
+    # pages -- while the application's own PHP pages did not reflect the Host at all.
+    occ = len(re.findall(re.escape(_EVIL_HOST), b, re.I))
+    sig = len(re.findall(r"<address>[^<]*Server at " + re.escape(_EVIL_HOST) + r" Port \d+</address>", b, re.I))
+    if sig and sig == occ:
+        return {"severity": "INFORMATIONAL", "server_signature": True,
+                "detail": "the spoofed Host appears ONLY in the web server's ServerSignature footer "
+                          "(<address>...Server at HOST Port N</address>) on a server-generated error/index "
+                          "document. The application did not reflect it. This is `ServerSignature On`, "
+                          "not an application defect, and it is one server-level fact per host, not per URL"}
+    if re.search(r'(?:href|src|action|location)\s*=\s*["\']?https?://' + re.escape(_EVIL_HOST), b, re.I):
+        return {"severity": "LOW", "url_context": True,
+                "detail": "spoofed Host became a URL in a link/resource/service-endpoint attribute -- "
+                          "clients following it are directed to the attacker host"}
+    return {"severity": "INFORMATIONAL",
+            "detail": "spoofed Host reflected into inert body text (no URL context, no redirect target)"}
```

Plus a dedup rule in the caller: collapse `family=host_header` rows that share
(host, landing-class, detail) into ONE finding carrying the affected-URL list.

### 3.2 OVERGRADED / MIS-TITLED - 4 `DOM-based XSS` rows (MEDIUM)

`aa4eb22263e5` (`page`), `26b1a6a8e01b` (`page`), `e58261c6ab85` (`level1HintIncludeFile`),
`c9dbdb197f04` (`pagename`). Engine `dom_trace`.

The underlying vulnerability is real - these are the SAME four injection points already confirmed
TRUE in 2.3. Two problems:

**(a) They are not DOM-based.** MEASURED: the payload is present in the RAW server response, fetched
with `httpx`, which runs no JavaScript at all (section 2.3, "RAW payload present: True" on every
case). A DOM-based XSS is one where client-side script copies a DOM source into a sink; here the
server emits the payload in its own HTML. The title sends a triager to look for a JS source->sink
flow that does not exist.

`agent/dom_trace.py` makes this choice knowingly - the `Q-128` comment block says the `executed`
family is "DELIBERATELY NOT GATED" on `server_reflected`, reasoning "Server-side reflection that also
executes is still DOM XSS". The engineering trade (don't suppress a real bug) is right; the **title**
is what is wrong:

```python
_TITLE = {"dom_xss": "DOM-based XSS", ...}
```

Proposed patch: title from the gate, not the family.

```diff
--- a/agent/dom_trace.py
+++ b/agent/dom_trace.py
@@
     if s.get("executed"):
         hits.append({"family": "dom_xss", "param": param, "source": source,
+                     # The payload executing does not say WHO put it in the page. When the server
+                     # already emitted it, this is classic reflected XSS and calling it "DOM-based"
+                     # sends the triager hunting a client-side source->sink flow that is not there.
+                     "server_reflected": bool(s.get("server_reflected")),
+                     "title_override": ("Reflected XSS (payload executed in a real browser)"
+                                        if s.get("server_reflected") else "DOM-based XSS"),
                      "target": s.get("xss_target") or here,
```

**(b) They duplicate the `xss` engine.** All four params already have a CRITICAL from `run_xss`.
Reporting the same injection point twice at two severities (CRITICAL and MEDIUM) is a cross-engine
dedup gap, not a second bug.

### 3.3 OVERGRADED - `Security value from a disclosed non-cryptographic PRNG (Math.random)` (MEDIUM, CVSS 5.9)

Finding `c059af635fd9`, target `http://mutillidae/phpmyadmin/js/functions.js?ts=1526333067`.

**MEASURED.** The file is real and `Math.random` is genuinely in it, twice:

```
HTTP 200 len=47858 ct=application/javascript
MATCH: $.ajaxPrefilter(function(a,b){var c=(new Date).getTime()+""+Math.floor(Math.random()*1E6);
       if(typeof a.data=="string")a.data+="&_nocache="+c;
MATCH: ...b.value+="abcdefhjmnpqrstuvwxyz23456789ABCDEFGHJKLMNPQRSTUVWYXZ".charAt(
       Math.floor(Math.random()*53));a.text_pma_pw.value=b.value;a.text_pma_pw2.value=b.value;
```

So the substance is not invented. But three parts of the grade are not supported by that evidence:

1. **It is vendored third-party code, not the application.** `/phpmyadmin/js/functions.js` is
   phpMyAdmin 3.5.2.2's own bundled JS (version string measured in section 3.1:
   `phpMyAdmin 3.5.2.2`). Under the same rule that excludes `/javascript/jQuery/` and
   `/phpmyadmin/js/jquery/`, this is a bundled component, not mutillidae's code. Nothing in the
   finding says so.
2. **The `Math.random` use is a client-side password *suggestion* box, not a token/session
   generator.** `a.text_pma_pw.value` is phpMyAdmin's "Generate password" helper: it fills a form
   field the operator can overwrite. The finding's impact text claims "A token, session id or secret
   ... An attacker who observes a handful of values can recover the generator state ... enabling
   session hijacking or password-reset abuse." No session id or reset token was shown to come from
   this generator. The other match is a cache-buster (`_nocache`), which is not security-relevant at all.
3. **CWE-209 is wrong.** The impact says "The disclosure itself (CWE-209) is what makes this
   observable without source access." CWE-209 is information exposure through an *error message*.
   This is a static `.js` asset served by design, with `Content-Type: application/javascript`. There
   is no error and no disclosure; a scanner read a public file.

Oracle defect: `web_probes`' weak-random check treats "the string `Math.random` appears in a
JS response that also contains a security-ish word" as "the application states a security value comes
from a predictable source". It does not check whether the file is first-party, and it does not trace
the generated value to a sink. Correct grade: LOW/INFORMATIONAL, attributed to the third-party
component with its version.

---

## 4. MORE DISPROVED FINDINGS

### 4.1 FALSE - `Exposed application credentials for 'root<U+FFFD>'` (MEDIUM, candidate)

Finding `8dda7f6b9397`, target `http://mutillidae/login`. Emitted by `agent/agent.py::_do_scan_auth`.

The stored username is literally `root` followed by U+FFFD REPLACEMENT CHARACTER. Confirmed in the
raw log row (the U+FFFD byte is written here as `<U+FFFD>` to keep this file ASCII; in the database
it is the literal replacement character):

```
credentials for 'root<U+FFFD>'", "severity": "medium", "family": "broken_auth",
"confidence": "candidate", "target": "http://mutillidae/login", ...
```

MEASURED codepoints, read straight out of the finding record:

```
docker exec -i apolaki-agent-1 python - <<'PY'
import sqlite3, json
c=sqlite3.connect('/app/data/bbh.db')
for (d,) in c.execute("SELECT data FROM findings WHERE mission_id='bed9ffcd'"):
    o=json.loads(d)
    if o.get("id")=="8dda7f6b9397":
        u=o["title"].split("for '")[1].rstrip("'")
        print("username codepoints:", [hex(ord(ch)) for ch in u])
        print("target:", o["target"])
PY
```

Real output:

```
username codepoints: ['0x72', '0x6f', '0x6f', '0x74', '0xfffd']
target: http://mutillidae/login
```

`0xfffd` is U+FFFD REPLACEMENT CHARACTER, emitted only by a decoder that hit bytes it could not
decode. It cannot be part of a real account name.

**MEASURED - three independent reasons this is false:**

**(a) The endpoint it tested does not exist.**

```
  /login                     HTTP 404 len=278
  /index.php?page=login.php  HTTP 200 len=54989
```

`http://mutillidae/login` is Apache's 278-byte default 404. The finding's own description blames
"a single verification login did not yield a session (form/flow mismatch)". That explanation is
wrong: there is no form to mismatch. The verification POST went to a 404 page.

**(b) The URL came from a falsy default.** `agent/agent.py:1928`:

```python
login_url = prior_login or self._discover_login_url(base) or base.rstrip("/") + "/login"
```

`_discover_login_url` returned falsy for mutillidae, whose login lives at
`/index.php?page=login.php`, and the `or` fell through to a guessed `/login`. This is the
falsy-default shape: the guess is indistinguishable downstream from a discovered URL, and
`verified=False` is then attributed to the credential rather than to the URL.

**(c) A username cannot contain U+FFFD.** U+FFFD is produced only when a decoder hits bytes it cannot
decode. The value is a decode artefact, not an account name.

**UNVERIFIED:** I could not reproduce the harvest. Running the agent's own
`intel.harvest_credentials` over all seven pages `_probe_for_creds` fetches
(`/vulnerabilities`, `/`, `/login`, `/readme`, `/README.md`, `/help`, `/about`) yields ZERO
credentials today:

```
/vulnerabilities HTTP-body len=288     creds=[]
/                HTTP-body len=52757   creds=[]
/login           HTTP-body len=278     creds=[]
...
```

and re-running it over every stored `exchanges` row for the mission produced no `root*` credential
either. So the exact source text is UNVERIFIED - I am recording that as a disproved hypothesis
rather than guessing.

The likely oracle defect is in `agent/intel.py::harvest_credentials`. `_CRED` is:

```python
_CRED = re.compile(r"(?i)\buser(?:name)?\b[\s:=]{0,4}(.{1,100}?)\bpass(?:word)?\b[\s:=]{0,4}(.{1,100}?)"
                   r"(?=\b(?:path|technolog|difficult|vulnerab|host|url|email|account)\b|[\r\n]|$)")
...
u = re.sub(r"\s+", "", m.group(1))
```

`(.{1,100}?)` will span arbitrary prose between the words "user" and "password", and then
`re.sub(r"\s+", "", ...)` collapses that whole span into a single token that is then presented as a
username. Any page that says "user ... password ..." within 100 characters can yield a
sentence-shaped "credential". That is consistent with a mojibake username, but I did not reproduce
it, so it stays UNVERIFIED.

**Proposed patch (NOT applied):**

```diff
--- a/agent/agent.py
+++ b/agent/agent.py
@@
-        login_url = prior_login or self._discover_login_url(base) or base.rstrip("/") + "/login"
+        # FALSY DEFAULT: a GUESSED /login is not a discovered login. When discovery fails, the
+        # verification result is a fact about the URL, not about the credential -- reporting an
+        # unverifiable credential lead against a 404 is worse than reporting nothing.
+        # MEASURED on mutillidae: /login is a 278-byte Apache 404; the real login is
+        # /index.php?page=login.php, and the finding blamed a "form/flow mismatch".
+        login_url = prior_login or self._discover_login_url(base)
+        if not login_url:
+            return events
```

```diff
--- a/agent/intel.py
+++ b/agent/intel.py
@@
         u = re.sub(r"\s+", "", m.group(1))
         p = re.sub(r"\s+", "", m.group(2))
-        if 2 <= len(u) <= 40 and 2 <= len(p) <= 60 and u.lower() not in _CRED_STOP and u != p:
+        # A credential is a TOKEN, not a collapsed sentence, and never a decode artefact. Reject any
+        # candidate whose captured span contained whitespace/punctuation runs (i.e. was prose) or
+        # carries U+FFFD, which only appears when bytes failed to decode.
+        if chr(0xFFFD) in u or chr(0xFFFD) in p:   # decode artefact, never a real credential
+            continue
+        if re.search(r"\s", m.group(1).strip()) or re.search(r"\s", m.group(2).strip()):
+            continue
+        if 2 <= len(u) <= 40 and 2 <= len(p) <= 60 and u.lower() not in _CRED_STOP and u != p:
```

---

## 5. REMAINING TRUE POSITIVES (verified, but note the duplication)

### 5.1 TRUE - git exposure. **7 HIGH rows for ONE fact.**

`3b4890b2cc50` (Git repository exposed (.git/HEAD)), `bab699066f8a` (Git config exposed) from engine
`content_discovery`; `3feaa53857ea` (.git/config), `84d29f686397` (.git/HEAD), `c32c72cf1bab`
(.git/logs/HEAD), `8b00fbd602e1` (.git/index), `bc5022e46c9a` (full source recoverable) from engine
`exposure`.

**MEASURED, and the strongest claim ("full source recoverable") is justified** - I reconstructed a
real blob out of the exposed object store:

```
  /.git/HEAD             HTTP 200 len=23     head='ref: refs/heads/master\n'
  /.git/config           HTTP 200 len=272    head='[core]\n\trepositoryformatversion = 0\n...'
  /.git/index            HTTP 200 len=394    head='DIRC\x00\x00\x00\x02\x00\x00\x00\x05...'
  /.git/refs/heads/master HTTP 200 len=41    '15ca375e54f056a576905b41a417b413c57df6eb\n'
  object 09/432cab87 HTTP 200 -> b'blob 96\x00hello-world-lamp\n================\n\n
      Hello world application to test LAMP deployments (PHP+MySQL)\n'
  NEGCTRL /zzqq-no-such-path -> HTTP 404 len=290
```

zlib-decompressing a loose object returned real git blob content, so the repository genuinely is
walkable. Verdict TRUE, HIGH correct. **But two engines report the same exposure and one of them
(`exposure`) emits a row per file plus a summary row.** Seven HIGH rows for one issue. Additionally,
22 of the 65 Host-header rows are `.git/**/?C=N;O=D` autoindex listings of this same directory - so
one misconfiguration accounts for 29 of 113 findings (26%).

Also note a mis-mapping: the five `exposure`-engine git rows carry
`analyst_notes: METIS classification: CWE-78 / A03:2021 Injection` and `owasp: A03:2021 Injection`
while their own `cwe` field says `CWE-527`. CWE-78 is OS Command Injection. The METIS classifier
disagrees with the finding's own CWE on every one of these rows, and it is the METIS value that
reaches the report's OWASP grouping.

### 5.2 TRUE - `Exposed phpinfo()` (MEDIUM). `ac7c6408c1c7`.

```
  /phpinfo.php  HTTP 200 len=81547  head='\r\n<style>\n<!--\n\tdiv.phpinfodisplay table...'
  NEGCTRL /zzqq-no-such-path -> HTTP 404 len=290
```

Matches the ground truth. TRUE, MEDIUM correct.

### 5.3 TRUE - 12 `Cookie set without the Secure attribute` rows + posture cookie/header rows

MEASURED by reading the raw headers, which is exactly what these oracles claim to do:

```
http://mutillidae/?page=add-to-your-blog.php...
   Set-Cookie: PHPSESSID=tvee9fd120bg8uasku76g9hr60; path=/
   Set-Cookie: showhints=1
http://mutillidae/phpmyadmin/prefs_manage.php
   Set-Cookie: phpMyAdmin=lsbu400ao84dugto7j9folgvv62f69mu; path=/phpmyadmin/; HttpOnly
   Set-Cookie: pma_lang=en; expires=...; Max-Age=2592000; path=/phpmyadmin/; httponly
   Set-Cookie: pma_collation_connection=utf8_general_ci; ...; httponly
```

`PHPSESSID` has no `Secure`, no `HttpOnly`, no `SameSite`; the phpMyAdmin cookies have `HttpOnly` but
no `Secure`. Every one of these findings states exactly that and nothing more. These oracles read the
header field itself and their evidence strings are accurate. Verdict TRUE.

Posture headers, MEASURED on `/`:

```
  content-security-policy      None
  x-frame-options              None
  x-content-type-options       None
  referrer-policy              None
  permissions-policy           None
```

All five posture findings are TRUE and honestly worded ("the response headers the server sent, read
directly").

**Dedup note:** 12 cookie rows describe 2 distinct cookie sets (mutillidae's `PHPSESSID`/`showhints`,
phpMyAdmin's three). One row per URL visited.

### 5.4 TRUE - `Path-relative style sheet import` (LOW). `664b30a9665d`.

This one surprised me - I expected it to be false, and it is not. I verified the **whole exploit
chain**, not just the claim:

```
victim page http://mutillidae/hints-page-wrapper.php/aaa/?level1HintIncludeFile
  HTTP 200 len=2410
  starts with DOCTYPE: False
  head: '<fieldset>\r\n\t\t\t<legend>Error Message</legend>...'      <- quirks mode (BackCompat)
  imports ./styles/global-styles.css: True
  its relative sheet -> HTTP 200 ct=text/html len=528 (served as HTML, not CSS)
```

and the padded path really does return the page rather than 404:

```
padded page    /hints-page-wrapper.php/aaa/            HTTP 200 len=528
resolved sheet /hints-page-wrapper.php/aaa/styles/global-styles.css HTTP 200 len=528 ct=text/html
   sheet body == page body: True
NEGCTRL /zzqq-nope.php/aaa/styles/global-styles.css -> HTTP 404 len=315
```

Every element of the finding's claim holds: the server accepts extra path segments on the PHP script
(`AcceptPathInfo`), the document imports its stylesheet path-relatively, the document has no DOCTYPE
so it renders in quirks mode, and the resolved stylesheet URL returns the page's own HTML body. The
negative control 404s. TRUE, LOW correct.

### 5.5 TRUE - `Reverse tabnabbing` (LOW). `4272c86b38f1`.

MEASURED on `/`:

```
  target=_blank links: 44 | without rel=noopener: 44 | cross-origin: 36
     <a href="https://www.owasp.org/images/7/72/OWASP_Top_10-2017_%28en%29.pdf.pdf" target="_blank">
```

The finding claims 10 cross-origin links; I count 36 occurrences (10 is plausibly the deduplicated
href count). Direction and mechanism are right, and the remediation text already notes modern
browsers default to `noopener`, so the LOW is honest. TRUE.

---

## 6. RECALL GAPS - what the mission MISSED

This is the other half of the cost. 113 findings, and the two most severe issues on the target are
not among them.

### 6.1 MISSED (critical) - OS command injection / RCE on `dns-lookup.php`

**MEASURED with baseline, probe and negative control:**

```
BASELINE 127.0.0.1        -> HTTP 200 len=52280  uid= present: False
PROBE   127.0.0.1;id      -> HTTP 200 len=52337  match: uid=33(www-data) gid=33(www-data) groups=33(www-data)
NEGCTRL 127.0.0.1;zzqq... -> HTTP 200 len=52294  uid= present: False
```

Command:

```
POST http://mutillidae/index.php?page=dns-lookup.php
     target_host=127.0.0.1;id&dns-lookup-php-submit-button=Lookup+DNS
```

Arbitrary command execution as `www-data`. The mission reported **zero** command-injection findings -
searching all 113 finding records for `dns-lookup`, `command inject` and `cmdi` returns False for
each. Meanwhile it emitted 62 LOW rows for a web-server footer.

This is the headline recall failure: the most severe bug on the host was missed, and the finding
count was dominated by one benign server default.

### 6.2 MISSED (high) - `/passwords/accounts.txt` is world-readable with 23 plaintext logins

Found while chasing the false credential finding in 4.1.

```
/passwords/ -> 200  ['/', 'accounts.txt']
accounts.txt HTTP 200 len=929
1,admin,adminpass,g0t r00t?,Admin
2,adrian,somepassword,Zombie Films Rock!,Admin
3,john,monkey,I like the smell of confunk,Admin
... 23 rows, every one marked Admin
```

**And the credentials work.** One verification login each, with two negative controls, fresh client
per attempt:

```
PUBLISHED admin/adminpass      -> len=53248  'Logged In Admin: '   Not-Logged-In marker: absent
PUBLISHED adrian/somepassword  -> len=53264  auth_error: False
NEGCTRL   admin/zzqq-wrong     -> len=54988  'Not Logged In'
NEGCTRL   zzqquser/adminpass   -> len=54988  'Not Logged In'
```

Clean structural split: valid logins render `Logged In Admin: ` and drop the `Not Logged In` marker;
both negative controls (wrong password, wrong username) render `Not Logged In` at an identical 54988
bytes. So a real, working admin credential is published on the target's own surface.

The mission's credential engine produced a mangled `root<U+FFFD>` against a 404 instead. The engine
does not fetch `/passwords/`, even though the mission's own content discovery reached that directory
- `http://mutillidae/passwords/?C=N;O=D` appears as one of the 65 Host-header targets, so the
crawler saw the autoindex listing and no engine read the file it linked to.

### 6.3 NOT a recall gap - Host header reflection

The ground truth notes the Apache `ServerSignature` reflection is real. The mission DID report it,
62 times. Section 3.1 is the grading verdict: real reflection, wrong claim, wrong multiplicity.

---

## 7. SCOREBOARD

| Finding | Sev | Verdict | Deciding measurement |
|---|---|---|---|
| XSS confirmed (`page` x3, `username`, `level1HintIncludeFile`, `pagename`) | critical x6 | **TRUE** (4 distinct bugs, 6 rows) | payload parses as a real `img[onerror]` element in the response DOM; negctrl `zzqqnonsense` -> 0 elements |
| SQL injection error-based (`username`, `level1HintIncludeFile`, `pagename`) | high x3 | **TRUE** | server returns the concatenated query and MySQL errno 1064 naming the injected quote |
| SQL injection error-based (`blog_entry`) | high | **TRUE (re-measure)** | same engine + negative control; stored response body truncated before the error, see 8.1 |
| Path traversal in `page` | high | **TRUE** | `/etc/passwd` -> `root:x:0:0:root:/root:/bin/bash`; negctrl nonexistent file -> absent. But `curl`/`target` record the BASELINE URL |
| Exposed .git (x5 `exposure`) + Git repo/config exposed (x2 `content_discovery`) | high x7 | **TRUE, 7 rows for 1 fact** | zlib-decompressed a real blob from the exposed object store; negctrl 404 |
| **LDAP injection in `new_db`** | **high** | **FALSE** | tautology and contradiction byte-identical (1107 == 1107); app answers `Missing parameter: new_db`; "records" were phpMyAdmin's font-size `<option>` values |
| Exposed phpinfo() | medium | **TRUE** | 81547-byte phpinfo page; negctrl 404 |
| DOM-based XSS (`page` x2, `level1HintIncludeFile`, `pagename`) | medium x4 | **OVERGRADED / mis-titled** | payload present in the raw non-JS response -> server-reflected, not DOM-based; duplicates the criticals |
| **Exposed application credentials for `root<U+FFFD>`** | **medium** | **FALSE** | `/login` is a 278-byte Apache 404; username contains U+FFFD; harvest not reproducible |
| Security value from disclosed PRNG (Math.random) | medium | **OVERGRADED** | real `Math.random`, but in vendored phpMyAdmin 3.5.2.2 JS, feeding a password-*suggestion* box; CWE-209 wrong |
| Cookie without Secure (x12) | medium x5 / low x7 | **TRUE, 12 rows for 2 cookie sets** | raw `Set-Cookie` headers read directly, evidence accurate |
| Session cookie without HttpOnly / SameSite / plaintext-reachable | medium x2 / low | **TRUE** | `Set-Cookie: PHPSESSID=...; path=/` - no Secure, HttpOnly or SameSite |
| Page can be framed by any origin | medium | **TRUE** | no `x-frame-options`, no CSP |
| **Host header injection (Apache signature only)** | **low x40** | **OVERGRADED, claim false** | reflection is ONLY `<address>...Server at HOST Port 80</address>` on server-generated 404/autoindex; the app's own PHP pages do not reflect Host at all |
| Host header injection (phpMyAdmin document.title) | low x18 | **OVERGRADED** | lands in `parent.document.title = '...'` - inert, and one behaviour x18 rows |
| Host header injection (WSDL `soap:address`, phpMyAdmin href) | low x4 | **TRUE, under-graded** | `<soap:address location="http://bbh-evil.example/..."/>` redirects SOAP clients |
| Host header injection (302 `Location`) | informational x3 | **TRUE, correctly graded** | `Location: http://bbh-evil.example/phpmyadmin/main.php?token=...`; no cache header, XFH not honoured -> informational is right |
| Path-relative style sheet import | low | **TRUE** | full chain verified: padded path 200, no DOCTYPE (quirks), sheet URL returns the page body as `text/html`; negctrl 404 |
| Reverse tabnabbing | low | **TRUE** | 36 cross-origin `target=_blank` without `rel=noopener` |
| No CSP / MIME sniffing / Referrer-Policy / Permissions-Policy | low + info x4 | **TRUE** | all five headers absent, read directly |

**Totals: 113 findings triaged. 2 FALSE (1 HIGH, 1 MEDIUM). 63 OVERGRADED (58 Host-header + 4
DOM-XSS + 1 PRNG). 48 TRUE.** Arithmetic check against the mission: 113 rows = 6 critical + 13 high
+ 15 medium + 73 low + 6 info/informational; the 65 Host-header rows split 40 + 18 + 4 + 3 by
measured landing class. Of the 48 TRUE, dedup would collapse them to roughly 20 distinct issues
(6 XSS rows -> 4 bugs; 7 git rows -> 1; 12 cookie rows -> 2).

And **2 critical/high issues missed entirely** (RCE, published working admin credentials).

---

## 8. UNVERIFIED / open

### 8.1 `SQL injection (error-based) in 'blog_entry'` - listed TRUE, needs one re-measurement

The stored `response` for `573c9525263c` is the page header, truncated before any error text, and its
`request`/`curl` fields are malformed:

```
curl: curl -i -sk 'http://mutillidae/index.php?page=add-to-your-blog.php [POST blog_entry]'
```

That is not a runnable command - the POST body is embedded in the URL string as prose. The other
three SQLi rows carry a real MySQL error in `response`; this one does not. I did not re-run it (the
blog form is authenticated/stateful and posting to it writes a row on a shared lab, which the house
rules put out of bounds for a read-only pass). Recorded TRUE on the engine's negative control, flagged
UNVERIFIED for the body evidence.

### 8.2 Source of the `root<U+FFFD>` harvest - UNVERIFIED

See 4.1. Not reproducible from the seven documented probe pages or from any stored exchange. The
`_CRED` prose-spanning regex is the leading hypothesis, not a proven cause.

### 8.3 METIS classification disagrees with findings' own CWE

Observed but not fully characterised: the five `exposure`-engine git rows say `cwe: CWE-527` while
`analyst_notes` says `METIS classification: CWE-78 / A03:2021 Injection`, and the METIS value is what
populates the `owasp` field. Same shape on the `transport_posture` HttpOnly row: `cwe: CWE-1004`,
METIS says `CWE-79`. Worth a separate pass - it mis-buckets findings in the report's OWASP grouping.

---

## 9. THE ONE THING TO FIX FIRST

`agent/semantic_differential.py::evaluate` accepts a superset relation between two arbitrary response
bodies as proof of a boolean injection, with no check that the two bodies are the same page, that the
parameter was accepted, or that the "records" are anything but static UI chrome. On this mission it
manufactured a `confirmed` HIGH at CVSS 8.2 naming LDAP - a protocol the target does not speak - on a
parameter the target reports as missing, with a negative control byte-identical to the probe.

Every caller of `sd.evaluate` inherits that. Grep `agent/` for `semantic_differential` and re-check
each boolean-differential family before the Shopify run.

The runner-up is the volume problem: one Apache default (`ServerSignature On`) produced 40 findings
and one `.git` exposure produced 29 across two engines. 69 of 113 rows (61%) trace to two facts,
while a live `;id` RCE and a published working admin password went unreported.


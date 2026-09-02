# Q-158 - every FORM engine is blind on a single-page app

Lane A (Builder). Deliverable: `agent/rendered_forms.py` + `agent/tests/test_rendered_forms.py`.
Every claim below is marked MEASURED (command + real output) or UNVERIFIED.

## 1. Restating the defect in one line

`form_xss.parse_forms` answers the question "what forms does this DOCUMENT declare?".
On an SPA the answer is "none", and that answer is correct - it is the question that is wrong.
The question this module asks instead is **"what request does this application actually send when a
human fills its controls?"**, which has an answer on an SPA and needs no `action`, no `method` and
no `name=`.

## 2. Measurements taken BEFORE writing any code

### 2.1 The lab form has no `action` and no `method` (the DoD's requirement)

MEASURED - playwright chromium in a throwaway container against `juice-shop:3000`, reading every
rendered `input`/`textarea` and its owning `el.form`:

```
route #/login
  input name=email    id=email    form=login-form  action=null  method=null  visible=true
  input name=password id=password form=login-form  action=null  method=null  visible=true
  input type=checkbox id=rememberMe-input          form=login-form
```

`el.form` is non-null (Angular renders a real `<form>` element) but it carries neither attribute,
so `parse_forms`'s `method != "post" -> continue` drops it before it reads a single field. This is
the shape the ticket describes, confirmed on the target.

### 2.2 The injection oracle and its negative control are BOTH in the same form

MEASURED - direct HTTP to the endpoint the login form drives
(`POST /rest/user/login`, JSON body):

```
baseline    {"email":"a@b.co","password":"Aa1!aaaa"}  -> 401  Invalid email or password.
email + '   {"email":"a'","password":"Aa1!aaaa"}      -> 500  Express stacktrace (sqlite/query.js)
password+ ' {"email":"a@b.co","password":"a'"}        -> 401  Invalid email or password.
bypass      {"email":"' OR 1=1--","password":"x"}     -> 200  {"authentication":{"token":"eyJ0eXAi...
```

Two results matter:

* the **email** field is concatenated into the SQL statement -> injectable;
* the **password** field is `security.hash()`ed before it reaches the statement, so the identical
  payload is inert -> **the negative control is a real field of the same form, not a synthetic
  fixture**. A form whose field is correctly neutralised stays silent, as the ticket demands.

### 2.3 A disproved hypothesis (recorded, per house rules)

HYPOTHESIS: the 500 would carry a DBMS error string, so `sqli_tool.error_signatures` would confirm.
MEASURED - it does not. Juice Shop's 500 page is a bare Express stacktrace; `error_signatures`
returned `[]` for both the injected and the control body. `sqli_tool.quote_break_recovers` also
does not apply here: it requires a 2xx/3xx baseline and this baseline is a 401.
The oracle that DOES fire is `sqli_tool.auth_bypass_confirmed` (401 + no token -> 200 + JWT).
Recorded so nobody re-derives it: **do not reach for the error-string oracle on this endpoint.**

### 2.4 A CORRECTION to 2.3 -- the app's own request gets a different answer

MEASURED, and this is the single most important result in the ticket. The SAME endpoint, the SAME
payload, answered twice:

```
urllib POST (a request we composed)   -> 500, bare Express HTML stacktrace, no DBMS text
the app's own XHR (intercepted)       -> 500, {"error":{"message":"SQLITE_ERROR: unrecognized
                                                token: \"8cbf5f1b50b6b959250081a52429676b\"" ...
```

`sqli_tool.error_signatures` returns `[]` for the first and `[{"dbms":"SQLite"}]` for the second.
Juice Shop content-negotiates its error handler, so the answer depends on the `Accept` header the
application's own client sends. **Driving the app's request is not a purity preference; it is what
makes the oracle fire.** 2.3 stands as written for a composed request and is superseded for the
real one.

## 3. What was built

`agent/rendered_forms.py`. The design decision, stated once:

> `parse_forms` asks "what forms does this DOCUMENT declare?". On an SPA the answer is "none" and
> that answer is correct. This module asks **"what request does this application send when a human
> fills its controls?"** The endpoint, the verb, the encoding and the parameter names are not
> parsed out of attributes -- they are OBSERVED, by filling every rendered control with its own
> unique marker, letting the app's JavaScript build and send the request, and reading back where
> each marker landed.

`wire_form()` is that observation and it is the artifact that replaces `parse_forms`'s output:

```
{"observed": true, "url": "http://juice-shop:3000/rest/user/login", "method": "POST",
 "carrier": "json", "params": {"#email": "email", "#password": "password"}, "unmapped": []}
```

MEASURED live. Note `unmapped`: a control whose value never appears in the request is REPORTED,
not silently counted as probed. "We thought we probed that field" is the failure mode this exists
to prevent.

Layering follows the house convention (`bie.py`): **the oracle is pure, the driver is dumb.**

* Pure (no browser, 32 unit tests): `field_identity`, `shaped_value`, `baseline_plan`,
  `locate_marker`, `wire_form`, `probe_plans`, `judge_error`, `judge_auth_bypass`,
  `judge_reflection`, `judge_probe`, `finding`.
* Driver: `read_forms`, `clear_obstruction`, `fill_and_submit`, `_open_route`, `probe_form`, `run`.
  It navigates, fills, clicks and records. It never decides anything.

Oracles are REUSED, not re-invented: `sqli_tool.error_signatures`,
`sqli_tool.auth_bypass_confirmed`, `sqli_tool.looks_like_login`, `sqli_tool.error_finding`,
`sqli_tool.auth_bypass_finding`, `xss_tool.contexts_of` / `reflected_exploitable` /
`markup_executable` / `BREAKOUTS`. This module contributes the CARRIER -- a control the
application really submits -- not a fourth opinion about what an injection looks like.

Two-stage planning, on purpose: the auth-bypass payload is only planned for an endpoint the app
actually posts credentials to, and the reflection payload only for a response a browser parses as
markup. Neither is knowable before the baseline submission, and guessing either is how a probe
becomes noise.

## 4. The live acceptance run (the definition of done)

MEASURED. `rf.run("http://juice-shop:3000", ["#/login"])`, 4.3 s wall clock, 9 real form
submissions:

```
route=#/login container=form#login-form action=None method_attr=None
wire {"observed": true, "url": ".../rest/user/login", "method": "POST", "carrier": "json",
      "params": {"#email": "email", "#password": "password"}, "unmapped": []}

probe #email     sqli         "apolakirft1581f0@example.test'"   500  verdict=True
probe #email     auth_bypass  "' OR 1=1--"                       200  verdict=True
probe #email     xss          '...@example.test<bbhx7h>"><...'   500  verdict=False
                              reason: reflected into an application/json response, which a
                                      browser does not parse as markup
probe #password  sqli         "Aa1!apolakirft1581f1'"            401  verdict=False
                              reason: no DBMS error signature appeared that the baseline lacked
probe #password  auth_bypass  "' OR 1=1--"                       401  verdict=False
                              reason: no session was issued that the benign invalid credential
                                      did not also get
probe #password  xss          'Aa1!...<bbhx7h>"><bbhx7a>'        401  verdict=False
                              reason: the value does not reflect

2 findings, both confirmed, both on #email, both pass proof_schema.validate_confirmed
```

Every clause of the DoD is in that output: a form with `action=None method=None`, an injection
confirmed through a control the app actually submits, and **the negative control is the other real
field of the same real form** -- three payloads, three refusals, three different stated reasons.

## 5. Adversarial checks (what I tried to break)

| # | Attack on the result | Outcome |
|---|---|---|
| M1 | Drop the baseline from the error differential (`error_signatures("", probe)`) | SURVIVED the suite as first written -- juice-shop's benign baseline is clean, so every existing test still passed. Killed by a new test (`test_error_oracle_refuses_when_the_baseline_ALREADY_carries_the_error`) that feeds a baseline already carrying the SQL error. |
| M2 | Judge a submission that never happened | Killed: `_comparable` refuses, 4 oracles asserted. |
| M3 | Judge a 429/503 | Killed: refuses both sides. The live false HIGH in `quote_break_recovers`'s docstring is the precedent. |
| M4 | Disable `clear_obstruction` in `run()` | SURVIVED -- see 5.1. Not a defect; an explained non-trigger. |
| M5 | Confirm on an encoded reflection / a JSON body | Killed by two asserts in the reflection test. |

### 5.1 A hypothesis that was disproved, then restored, by measurement

HYPOTHESIS: juice-shop's welcome modal covers the submit button, so `clear_obstruction` is what
makes the form submittable.

MEASURED, run through `run()`: disabling the clearer changed NOTHING (same 2 findings, same 4.3 s).
Instrumenting the click showed `covered: false` every time. Cause: `bie._new_persona` boots the app
at `/`, then `_open_route` navigates to `#/login`, and the route change tears the dialog down.
Dialog count went 2 -> 2 -> 1 and `app-welcome-banner` disappeared across those navigations.

RESTORED, by testing the case that actually meets the obstruction -- a COLD context whose first
navigation is the form route:

```
covered_before: {"covered": true, "layer": "mat-dialog-container#mat-mdc-dialog-0"}

WITHOUT clearing:  6.2 s   submitted_by=enter:#password
                   reason: click on #loginButton did not produce a request carrying our value
                           (Page.click: Timeout 6000ms exceeded)
WITH    clearing:  0.3 s   submitted_by=click:#loginButton
                   obstruction: "cleared by escape, dismiss:dismiss, dismiss:dismiss"
```

So the clearer is load-bearing (20x, and it uses the intended control instead of a fallback), it
just does not trigger on the route ordering `run()` happens to use. Both halves are recorded
because "it made no difference" and "it can make no difference" are different claims.

A defect found by the same measurement: the first click candidate had been juice-shop's
"Button to display the password" toggle, costing a whole 6 s timeout on a control that can never
submit. Fixed by only spending a click budget on rank<=1 controls (`type=submit`, or submit-ish
text); the Enter fallback still covers a form with no button at all.

### 5.2 No fixed sleeps

Three waits, all bounded conditions:
`_open_route` waits for the form's first control to be VISIBLE (then `bie.settle`);
`fill_and_submit` registers `expect_response` on "a request carrying our payload" BEFORE the click,
so a fast answer cannot be missed; `clear_obstruction` loops on `elementFromPoint` until the button
is uncovered or a deadline passes. `grep -n "wait_for_timeout\|sleep(" agent/rendered_forms.py`
returns nothing.

## 6. Honest limitations

* `#/contact` (the feedback form) is discovered and mapped but cannot be submitted: its CAPTCHA
  control has an answer the module has no way to compute, so the submit button never enables and
  the baseline records `observed: false` with a reason. That is the correct behaviour -- it reports
  a form it could not probe rather than a form with no findings.
* `clear_obstruction`'s dismiss vocabulary is generic web wording (`dismiss`, `accept`, `close`,
  `got it`, ...) on purpose. A target-specific button label there would be a benchmark signature.
* Only `<form>`-rooted and dialog-rooted groups are probed, plus any ancestor that owns a button
  and does NOT contain site chrome. The chrome clause is not cosmetic: without it the group
  degenerates to `<body>` and the "form" becomes the navbar (MEASURED -- fields = the header
  search box, submits = `menu` / `search` / `Your Basket`).
* The navbar search box is deliberately NOT probed here. It is Q-163's lane (a param-bearing SPA
  route reached by typing), and two lanes driving the same control would collide.

## 7. Status

- [x] Read `docs/QUEUE.md` Q-158, `agent/bie.py`, `agent/form_xss.py`, `agent/sqli_tool.py`
- [x] Measurements 2.1-2.3
- [ ] `agent/rendered_forms.py` pure layer + tests
- [ ] Browser driver + live confirmation on juice-shop
- [ ] Wiring patch for the Coordinator

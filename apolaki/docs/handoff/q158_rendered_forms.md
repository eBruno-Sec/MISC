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

## 3. Status

- [x] Read `docs/QUEUE.md` Q-158, `agent/bie.py`, `agent/form_xss.py`, `agent/sqli_tool.py`
- [x] Measurements 2.1-2.3
- [ ] `agent/rendered_forms.py` pure layer + tests
- [ ] Browser driver + live confirmation on juice-shop
- [ ] Wiring patch for the Coordinator

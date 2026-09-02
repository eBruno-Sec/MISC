# Q-155 - NoSQL injection in JSON request bodies (Lane B)

Status: IN PROGRESS. This file is written as work lands, not at the end.

Owner: Lane B (Builder). Write set: `agent/nosqli_body.py`, `agent/tests/test_nosqli_body.py`,
this file. Nothing else is touched - the wiring patch for `tools.py` / `agent.py` / `planner.py`
is a code block at the bottom for the Coordinator to apply.

---

## 1. What the ticket says, and what I confirmed before writing a line

The ticket's claim is that `_run_nosqli` is CORRECT and merely blind: it appends an operator to a
parameter NAME on a query string (`id[$ne]=`), which is one of the two carriers, and never builds
the operator as a real nested object inside a JSON request body (`{"id": {"$ne": -1}}`).

Read first, no edits: `agent/nosqli_tool.py` (350 lines), `ToolRegistry._run_nosqli`
(`agent/tools.py:9559`), `ToolRegistry._run_form_nosqli` (`agent/tools.py:9671`).

MEASURED - the carrier inventory is exactly two, and neither is the shape the ticket describes:

| carrier | where | payload shape | oracle |
|---|---|---|---|
| `_run_nosqli` | query string | `id[$ne]=<garbage>` appended to the param NAME | boolean broadening + driver error |
| `_run_form_nosqli` | JSON body | `{"email": {"$ne": null}, "password": {"$ne": null}}` | auth-bypass (token issued / 401->200) |

`_run_form_nosqli` DOES send a JSON body, so a reader skimming the tool list would conclude the
gap is already closed. It is not, for two independent reasons, and both matter:

1. It is scoped to LOGIN fields. `cred_fields` is filtered by `ns.LOGIN_FIELD_HINTS`
   (`email/username/user/login/userid/user_name/account/password`) and falls back to the invented
   pair `["email", "username"]`. A body field named `id`, `productId` or `filter.category` is
   never probed by it.
2. It uses a DIFFERENT oracle. `ns.auth_bypass_confirmed` looks for an issued session/JWT or a
   401->200 flip. A search/list endpoint that broadens its result set issues no token and was
   already 200, so that oracle is structurally incapable of seeing it.

So the boolean-broadening oracle - the one that actually detects a Mongo filter reached by user
input - exists ONLY on the query-string carrier. That is the gap, and it is a carrier gap exactly
as filed.

MEASURED - `_run_form_nosqli` also violates the project's own "probe with observed values" rule:

```python
benign = "bbh_" + os.urandom(4).hex() + "@test.invalid"          # tools.py:9686
base_body = _json.dumps({field: benign, pw_field: "bbh_" + os.urandom(3).hex()})
```

The baseline credential is INVENTED. That is survivable there only because its oracle is
"a token appeared where none had", which does not depend on the baseline matching anything.
It is not survivable for a broadening oracle, and `agent/nosqli_body.py` must not copy it.
(Recorded here as an observation about a file I am not allowed to edit. NOT a defect in
`_run_form_nosqli` - its oracle tolerates it. Do not "fix" it on the strength of this note.)

---

## 2. Ground truth on juice-shop - MEASURED, and it is not what the ticket assumes

The ticket names `PATCH /rest/products/reviews` as the injectable body endpoint. Both facts below
were measured from a throwaway container on `apolaki_default`, no shared container touched.

**Fact 1 - reviews really are the Mongo-style store.**

```
$ docker run --rm --network apolaki_default curlimages/curl -s \
    "http://juice-shop:3000/rest/products/1/reviews"
{"status":"success","data":[{"message":"One of my favorites!","author":"admin@juice-sh.op",
 "product":1,"likesCount":0,"likedBy":[],"_id":"YxAfD6AN5Bk3h3Zeo","liked":true}, ...]}
```

`_id` is a MarsDB/Mongo-style document id, confirming the store behind reviews.

**Fact 2 - the endpoint is behind authentication, so an unauthenticated mission never reaches it.**

```
$ docker run --rm --network apolaki_default curlimages/curl -s -i -X PATCH \
    -H "Content-Type: application/json" \
    -d '{"id":"YxAfD6AN5Bk3h3Zeo_bbh_nomatch","message":"bbh probe"}' \
    "http://juice-shop:3000/rest/products/reviews"
HTTP/1.1 401 Unauthorized
<title>UnauthorizedError: No Authorization header was found</title>
```

(That probe body carries a deliberately NON-MATCHING id, so it could not have modified a review
even if it had been authorized. It is the control request, not the operator request.)

This is a second, independent reason the 12 dispatches found nothing, and it is worth recording
because it changes what "fixing Q-155" means: building the carrier is necessary and NOT
sufficient. Without a session, the shape that carries the bug answers 401 to every probe.

**Fact 3 - and this is the one that constrains the design.**

`PATCH /rest/products/reviews` is a BULK-WRITE endpoint. The canonical Juice Shop payload
`{"id": {"$ne": -1}, "message": "..."}` is famous precisely because it overwrites EVERY review in
the store. A broadening operator on a mutating method does not read extra rows, it mutates extra
rows. juice-shop is shared with the Coordinator's scans and with Lane C, and the house rules
forbid restarting it, so I did not send that request and Apolaki must not send it by default
either. See section 4 for how the module handles this rather than pretending the problem is not
there.

---

## 3. Design - the CARRIER changes, the ORACLE does not

`analyze_boolean(baseline, operator_body, control_body, missing_body, baseline_samples=...)` in
`agent/nosqli_tool.py` is reused verbatim. `nosqli_body.py` imports it and adds no oracle of its
own. Everything below is about producing the three bodies that oracle consumes.

```
observed request        {"id": "YxAfD6AN5Bk3h3Zeo", "product": 1}
                                  |
                        the OBSERVED value, never an invented one
                                  |
   baseline    {"id": "YxAfD6AN5Bk3h3Zeo"}                  -> the rows the app really returns
   control     {"id": "YxAfD6AN5Bk3h3Zeo_bbh_a1b2"}         -> plain, non-matching  -> no rows
   operator    {"id": {"$ne": "YxAfD6AN5Bk3h3Zeo_bbh_a1b2"}} -> matches everything BUT that
   omit        {}                                            -> the "field was ignored" FP control
```

The operator's `$ne` argument is the SAME string as the control's plain value. That is what makes
the pair a differential and not two unrelated requests: the only difference between the control
body and the operator body is one level of JSON nesting.

Why the control value is derived from the observed one and not generated:

> "PROBE WITH OBSERVED VALUES, NEVER INVENTED ONES" - this project's three prior misses were all
> engines whose baseline and probe failed identically, so the differential was 0 on a vulnerable
> field. `nonmatching_value("YxAfD6AN5Bk3h3Zeo")` returns `"YxAfD6AN5Bk3h3Zeo_bbh_<tag>"`, which
> still carries the observed value as a prefix and is asserted to do so in the test suite.

`omit` is the JSON-body analogue of `_run_nosqli`'s `missing_param_url`: if the operator response
looks like the response with the field REMOVED, the app is discarding a non-string value rather
than evaluating an operator, and that must not be reported. Passed through to `analyze_boolean`
as `missing_body`.

---

## 4. The mutating-method gate (read this before calling the engine over-cautious)

TBD - filled in with the slice that lands it.

---

## 5. Wiring patch for the Coordinator

TBD - filled in once the module and its tests are green.

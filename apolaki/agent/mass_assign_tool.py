"""Mass assignment -- CWE-915, OWASP API3:2023 (BOPLA), WSTG-INPV-20 / WSTG-ATHZ-04.

The application binds request parameters straight onto a model, so a client can set a field it was
never offered: `role`, `isAdmin`, `verified`, `balance`. Q-011: this technique was declared live in
`engine_descriptor.PRECONDITIONS`, `asvs_model` ATHZ-04 and `wstg_catalog.FULL["WSTG-INPV-20"]`, and
the only code in the tree that ever over-posted a privileged attribute was the Juice Shop lab
SOLVER. Two published catalogs claimed a capability the product did not have. This module is the
capability.

WHAT THIS MODULE REFUSES TO CALL A FINDING, and why each guard exists:

  * **A 200 is not the vulnerability.** Every framework worth the name accepts a JSON body carrying
    attributes it does not bind and answers 200. Confirming on the write response would flag every
    JSON API alive. `evaluate` demands the field hold the injected value in a SEPARATE re-read.
    The re-read is the whole oracle.

  * **A field that already held the value is not a finding.** `role: "user"` that was always
    `"user"` proves nothing, and an object CREATED with the value you were about to inject is the
    classic false positive of this class -- you confirm the server's own default. So the BASELINE
    control is mandatory: the same object shape, created without the injection, read through the
    same view. A baseline that did not RUN caps the verdict at a lead.

  * **An endpoint that echoes arbitrary attributes proves nothing.** Some APIs round-trip whatever
    JSON you hand them (a document store, a `PATCH` that merges blindly into a blob, a debug view
    that renders the raw request). Persistence of `role` on such an endpoint is not privilege
    binding. So the IGNORED-FIELD control is mandatory: the identical write carrying
    `apolaki_probe_<nonce>` -- a name that CANNOT pre-exist on the server. If that name comes back
    at all, the verdict is `clean`, whatever the privileged field did.

  * **A field the endpoint OFFERS is not mass assignment.** Setting a documented parameter is the
    API working as designed. `privileged_candidates` subtracts the fields the write already accepts
    (from the OpenAPI operation, or learned from a sample object), so a `role` the spec declares is
    never reported.

  * **A view that does not expose the field is UNTESTED, never clean.** MEASURED on VAmPI:
    `GET /users/v1/{username}` returns `{username, email}` and never shows `admin`, while
    `GET /users/v1/_debug` -- an endpoint VAmPI's OWN OpenAPI spec declares -- shows it. Reporting
    `clean` from a view that structurally cannot answer the question is a false negative wearing a
    verdict. `UNTESTED` is a fourth value so the driver can count it instead of hiding it.

  * **The read view is chosen against the BASELINE object, before any injected value exists.**
    Picking the view that happens to show `role: admin` would be result-shopping; picking the view
    that exposes the field on an object created with no injection cannot be.

Non-destructive by construction: every object the driver writes to is one it created. It never
escalates a pre-existing account. When it does set a privileged field, the finding names the object
plainly so an operator can undo it.

Pure logic only -- candidate selection, body assembly, response location, and the verdict. The HTTP
lives in `tools.ToolRegistry._run_mass_assignment`.
"""
from __future__ import annotations

import json
import secrets


# -- the general privileged-field list ----------------------------------------------------------
#
# GENERAL, and that is the requirement: these are the attribute names application frameworks bind by
# convention (RBAC role fields, boolean privilege/verification flags, account-tier and balance
# fields). Not one of them is read from a benchmark's answer key, a lab's endpoint list or a solver.
# The two labs this engine was validated on are covered by `admin` and `role`, which any API tester
# would try first.
#
# Ordered by signal, because the driver caps how many it sends: a `role` or `isAdmin` that binds is
# an unambiguous privilege escalation; `isActive` is usually already true and normally dies on the
# baseline control; `balance` changes a number and is sent last.
#
# (name, value, what setting it would mean)
PRIVILEGED_FIELDS = (
    ("role",           "admin", "the conventional RBAC role field"),
    ("isAdmin",        True,    "the conventional administrator boolean"),
    ("is_admin",       True,    "the snake_case administrator boolean"),
    ("admin",          True,    "the bare administrator boolean"),
    ("userRole",       "admin", "role under a namespaced name"),
    ("user_role",      "admin", "role under a namespaced snake_case name"),
    ("isVerified",     True,    "identity/e-mail verification bypass"),
    ("verified",       True,    "identity/e-mail verification bypass"),
    ("emailVerified",  True,    "e-mail verification bypass"),
    ("accountType",    "admin", "account tier / privilege class"),
    ("account_type",   "admin", "account tier / privilege class"),
    ("userType",       "admin", "account tier / privilege class"),
    ("privilege",      "admin", "explicit privilege attribute"),
    ("permissions",    "admin", "explicit permission attribute"),
    ("group",          "admin", "group membership drives authorization"),
    ("isActive",       True,    "activation / approval bypass"),
    ("active",         True,    "activation / approval bypass"),
    ("balance",        999999,  "account balance bound from the request"),
    ("credit",         999999,  "account credit bound from the request"),
)

#: The prefix of the invented attribute used by the ignored-field control. A name the server cannot
#: possibly already know, so its presence in a re-read is proof of echo and nothing else.
CONTROL_PREFIX = "apolaki_probe_"
#: The value carried by that attribute. Distinctive so it is greppable in a captured response.
CONTROL_VALUE = "apolaki_control_value"


def new_nonce() -> str:
    """A fresh nonce for one endpoint's control attribute. Random per endpoint ON PURPOSE: a fixed
    name could, in principle, be a field some application really has, and would also let one
    endpoint's echo be mistaken for another's."""
    return secrets.token_hex(5)


def control_field(nonce: str) -> str:
    """The invented attribute name for `nonce`. An EMPTY nonce is a real input and still yields a
    usable name -- the caller gets `apolaki_probe_`, which no application defines either -- rather
    than silently substituting a default that would collide across endpoints."""
    return CONTROL_PREFIX + str(nonce or "")


def new_marker() -> str:
    """A unique value stamped into a field we control, so a re-read can prove it located OUR object
    and not merely 'an' object of the right shape."""
    return "apolaki_ma_%s" % secrets.token_hex(6)


# -- candidate selection ------------------------------------------------------------------------

def _norm(name) -> str:
    """Fold a field name for comparison: lower-cased, separators dropped. `is_admin`, `isAdmin` and
    `IsAdmin` are the same field to an application and must be the same field here."""
    return "".join(ch for ch in str(name or "").lower() if ch.isalnum())


def privileged_candidates(offered_fields=None, limit: int = 6, extra=None) -> list:
    """The privileged attributes worth injecting into a write that OFFERS `offered_fields`. Pure.

    Returns [{"field", "value", "why"}], order preserved from `PRIVILEGED_FIELDS`, capped at `limit`.

    A field the endpoint already offers is REMOVED, not merely deprioritised: setting a documented
    parameter is the API behaving as designed, and reporting it would be a guaranteed false positive
    on every API whose spec declares `role`. Comparison is on `_norm`, so a spec offering `is_admin`
    also suppresses `isAdmin`.

    `offered_fields` EMPTY is a real input meaning "the mission observed no declared body fields for
    this write" -- it yields the full candidate list with nothing subtracted, which is correct, and
    is NOT the same as a missing argument being replaced by a default. `limit <= 0` likewise means
    "no candidates", and returns [] rather than expanding to everything.
    """
    if limit is None or int(limit) <= 0:
        return []
    blocked = {_norm(f) for f in (offered_fields or []) if _norm(f)}
    pool = list(PRIVILEGED_FIELDS) + [tuple(e) for e in (extra or []) if len(tuple(e)) == 3]
    out, seen = [], set()
    for name, value, why in pool:
        key = _norm(name)
        if not key or key in blocked or key in seen:
            continue
        seen.add(key)
        out.append({"field": name, "value": value, "why": why})
        if len(out) >= int(limit):
            break
    return out


def body_with(base_body, field: str, value):
    """`base_body` plus exactly ONE extra attribute, as a JSON string. Pure.

    One variable at a time is the discipline this whole engine rests on: two injected attributes in
    one request make it impossible to say which one bound, and a server that rejects the request
    because of the second hides the first as a false negative.

    `base_body` may be a dict or a JSON string. A body that does not parse as a JSON OBJECT returns
    "" -- an unparseable body is a real input and must not be silently replaced with `{field: value}`
    alone, which would send a request the endpoint never asked for and read its 400 as a clean.
    """
    if isinstance(base_body, str):
        try:
            base = json.loads(base_body or "")
        except Exception:
            return ""
    else:
        base = base_body
    if not isinstance(base, dict):
        return ""
    if not str(field or ""):
        return ""
    out = dict(base)
    out[str(field)] = value
    return json.dumps(out)


#: Value shapes an API's own validation will reject if we ignore them. A registration endpoint that
#: 400s on `email: "apolaki_email"` yields no object at all, and the engine would report a clean
#: through a false negative. General field-name conventions, not any target's schema.
_EMAIL_HINTS = ("email", "mail")
_PASSWORD_HINTS = ("password", "passwd", "pwd", "secret")
#: Clears the common password policies out of the box (length + upper + lower + digit + symbol),
#: same reasoning as `register.adapt_password`.
_PASSWORD_VALUE = "Apolaki-Test-1!"
_EMAIL_DOMAIN = "apolaki-test.local"


def _string_value(name: str, marker: str) -> str:
    """A string that satisfies the validation a field of this NAME usually carries. Pure."""
    low = _norm(name)
    mk = marker or "apolaki"
    if any(h in low for h in _PASSWORD_HINTS):
        return _PASSWORD_VALUE
    if any(h in low for h in _EMAIL_HINTS):
        return "%s@%s" % (mk, _EMAIL_DOMAIN)
    return "%s_%s" % (mk, name)


def body_from_params(params, marker: str = "") -> dict:
    """A minimally-valid JSON body from an OpenAPI operation's typed BODY parameters (Q-031). Pure.

    `params` is `surface.operations_from_openapi(...)["params"]`. Only `location == "body"` entries
    are used; query/path/header parameters do not belong in a body. Types are honoured so the API's
    own validation passes: integer/number -> 1, boolean -> False, array -> [], object -> {}, string
    -> a marker-derived value shaped by the field NAME (an `email` field gets something that parses
    as an e-mail, a `password` field gets something that clears a password policy). A body the API
    rejects yields no object, and no object means the engine reports clean through a false negative.

    Returns {} when the operation declares no body parameters. That is a real answer -- the caller
    must then learn the shape from a sample object rather than invent one.
    """
    out = {}
    for p in (params or []):
        if not isinstance(p, dict) or str(p.get("location") or "").lower() != "body":
            continue
        name = str(p.get("name") or "")
        if not name:
            continue
        t = str(p.get("type") or "").lower()
        if t in ("integer", "number"):
            out[name] = 1
        elif t == "boolean":
            out[name] = False
        elif t == "array":
            out[name] = []
        elif t == "object":
            out[name] = {}
        else:
            out[name] = _string_value(name, marker)
    return out


#: Fields an API commonly keys an object by, so a re-read can be matched back to the object we
#: wrote. Ordered by how identifying they are. General REST/JSON conventions.
NATURAL_KEY_FIELDS = ("username", "email", "login", "handle", "user_name", "slug", "book_title",
                      "title", "name", "code", "label")


def object_key(body) -> tuple:
    """(field, value) that identifies the object this body creates, or ("", ""). Pure.

    Prefers a natural key (`username`, `email`, `title`, ...), falls back to the LONGEST string
    value, which is the field most likely to carry our marker. Password-ish fields are excluded --
    they are not returned by any sane read view, and matching on one would mean matching on a
    credential.

    Returns ("", "") for a body with no usable string field. That is a real answer: without a key we
    cannot prove a re-read found OUR object, and `locate_object` refuses to guess.
    """
    if isinstance(body, str):
        try:
            body = json.loads(body or "")
        except Exception:
            return "", ""
    if not isinstance(body, dict):
        return "", ""
    usable = {k: v for k, v in body.items()
              if isinstance(v, str) and v and not any(h in _norm(k) for h in _PASSWORD_HINTS)}
    if not usable:
        return "", ""
    for nat in NATURAL_KEY_FIELDS:
        for k in usable:
            if _norm(k) == _norm(nat):
                return k, usable[k]
    best = max(usable.items(), key=lambda kv: len(kv[1]))
    return best[0], best[1]


def personalize(base_body, marker: str) -> tuple:
    """(body, key_field, key_value) -- `base_body` made unique to `marker`. Pure.

    THE RE-READ CANNOT WORK WITHOUT THIS, and getting it wrong is silent. Every attempt sends its own
    write, so every attempt must produce a DISTINGUISHABLE object. Without a unique key the re-read
    either locates nothing (every verdict degrades to a lead, and the engine reports clean on a
    vulnerable target) or locates a PREVIOUS attempt's object -- which reads back the previous
    attempt's injected value, a false positive carrying a real, replayable-looking artifact.

    Only two classes of field are rewritten, each for a stated reason:
      * the object's natural key (`object_key`) -- that is what `locate_object` matches on;
      * any e-mail-ish field -- registration endpoints almost always require it to be unique, so
        leaving it fixed makes the SECOND attempt fail with "already registered".
    Everything else is left exactly as the caller supplied it: which values the endpoint's validation
    accepts is knowledge we do not have and must not overwrite.

    Deterministic in (`base_body`, `marker`), so a body already built by `body_from_params` with the
    same marker passes through unchanged.

    An empty body, or one with no field that can identify the object, yields an empty key -- a real
    answer, and the driver must decline rather than write blind into something it cannot re-read.
    """
    if isinstance(base_body, str):
        try:
            base_body = json.loads(base_body or "")
        except Exception:
            return {}, "", ""
    if not isinstance(base_body, dict) or not base_body:
        return {}, "", ""
    body = dict(base_body)
    key_field, _ = object_key(body)
    for name in list(body):
        if not isinstance(body[name], str):
            continue
        if name == key_field or any(h in _norm(name) for h in _EMAIL_HINTS):
            body[name] = _string_value(name, marker)
    if not key_field:
        return body, "", ""
    return body, key_field, str(body[key_field])


# -- ranking the re-read views --------------------------------------------------------------------

_ID_PLACEHOLDERS = ("id", "_id", "uuid", "pk", "objectid", "object_id")


def _segments(path: str) -> list:
    return [s for s in str(path or "").split("/") if s]


def _shared_prefix(a: str, b: str) -> int:
    sa, sb = _segments(a), _segments(b)
    n = 0
    for x, y in zip(sa, sb):
        if x.lower() != y.lower():
            break
        n += 1
    return n


def _fill_template(path: str, key_field: str, key_value: str, object_id: str):
    """`/users/v1/{username}` -> `/users/v1/<our username>`, or None when the placeholder names
    something we cannot supply. Pure.

    Refusing to fill is deliberate: guessing a value for `{book_title}` burns a request on a view
    that can only ever locate nothing, and a view that locates nothing is indistinguishable from a
    view that proves the object is gone.
    """
    import re
    out, filled = path, False
    for m in re.finditer(r"\{([^}]+)\}", str(path or "")):
        ph = _norm(m.group(1))
        if key_field and key_value and ph == _norm(key_field):
            val = str(key_value)
        elif object_id and (ph in _ID_PLACEHOLDERS or ph.endswith("id")):
            val = str(object_id)
        else:
            return None
        out = out.replace(m.group(0), val)
        filled = True
    return out if (filled or "{" not in str(path or "")) else None


def read_views(write_path: str, get_paths, key_field: str = "", key_value: str = "",
               object_id: str = "", limit: int = 5) -> list:
    """Ranked candidate re-read PATHS for an object created by a write at `write_path`. Pure.

    `get_paths` are GET operations the mission OBSERVED (from the API's own spec / crawl). Only
    paths sharing a leading path segment with the write are kept -- a `/books` view can never hold a
    `/users` object, and probing it is pure cost. Ranked: most path segments shared with the write
    first (the closest relative), then a filled template (which identifies exactly our object) ahead
    of a collection listing, then the longer path first.

    That last tie-break is what reaches VAmPI's `/users/v1/_debug` alongside `/users/v1` -- both
    share two segments, and BOTH are tried, because which of them exposes the field is decided later
    against the baseline object, never against a result.

    An empty `get_paths` is a real input and yields [] -- the driver then falls back to the REST
    convention (`<write path>/<id>`), which it constructs itself.
    """
    if not str(write_path or "") or limit is None or int(limit) <= 0:
        return []
    scored = []
    for p in (get_paths or []):
        p = str(p or "")
        if not p.startswith("/"):
            continue
        share = _shared_prefix(write_path, p)
        if share < 1:
            continue
        filled = _fill_template(p, key_field, key_value, object_id)
        if filled is None:
            continue
        scored.append((-share, 0 if "{" in p else 1, -len(_segments(p)), filled))
    out = []
    for _, _, _, path in sorted(scored):
        if path not in out:
            out.append(path)
        if len(out) >= int(limit):
            break
    return out


# -- locating our object in a re-read ------------------------------------------------------------

_ENVELOPES = ("data", "result", "object", "item", "user", "record")


def _candidate_objects(payload, limit: int = 400) -> list:
    """Every dict a re-read response could plausibly BE our object. Pure and bounded.

    Handles the four shapes an API actually returns: a bare object, an enveloped object
    (`{"data": {...}}`), a bare list, and a keyed collection (`{"users": [...]}` -- MEASURED, that is
    exactly what VAmPI's `_debug` view returns). Nested one level only: deeper recursion starts
    matching unrelated sub-objects, and a wrong object is worse than no object.
    """
    if isinstance(payload, str):
        try:
            payload = json.loads(payload or "")
        except Exception:
            return []
    out = []
    if isinstance(payload, list):
        out += [o for o in payload if isinstance(o, dict)]
    elif isinstance(payload, dict):
        out.append(payload)
        for key in _ENVELOPES:
            if isinstance(payload.get(key), dict):
                out.append(payload[key])
            elif isinstance(payload.get(key), list):
                out += [o for o in payload[key] if isinstance(o, dict)]
        for v in payload.values():
            if isinstance(v, list):
                out += [o for o in v if isinstance(o, dict)]
    return out[:limit]


def read_field(obj, field: str) -> tuple:
    """(found, value) for `field` in `obj`, matched on `_norm`. Pure.

    `found` is returned SEPARATELY from `value` because a field holding `False`, `0` or `""` is a
    real observation and `if value:` would erase it -- which is precisely the reading a baseline of
    `admin: false` needs to survive.
    """
    if not isinstance(obj, dict):
        return False, None
    want = _norm(field)
    if not want:
        return False, None
    for k, v in obj.items():
        if _norm(k) == want:
            return True, v
    return False, None


def locate_object(payload, key_field: str, key_value) -> dict:
    """The object in a re-read whose `key_field` equals `key_value`, or None. Pure.

    An EMPTY `key_field` or `key_value` returns None rather than falling back to "the first object in
    the response". Without a key we cannot prove the object we read is the one we wrote, and a
    finding built on "an" object is not a finding.
    """
    if not str(key_field or "") or key_value in (None, "", []):
        return None
    want = str(key_value).strip().lower()
    for obj in _candidate_objects(payload):
        found, got = read_field(obj, key_field)
        if found and str(got).strip().lower() == want:
            return obj
    return None


def exposed_fields(obj, fields) -> dict:
    """{field: value} for the candidate `fields` this object actually exposes. Pure.

    Used on the BASELINE object to decide, per field, which read view can answer the question at all
    -- before any injected value exists anywhere. A field absent here is untestable through this
    view, not absent from the model.
    """
    out = {}
    for f in (fields or []):
        found, val = read_field(obj, f)
        if found:
            out[str(f)] = val
    return out


# -- value comparison ----------------------------------------------------------------------------

_TRUE = {"true", "1", "yes", "y", "t", "on"}
_FALSE = {"false", "0", "no", "n", "f", "off"}


def same_value(sent, observed) -> bool:
    """Did the server store the value we sent? Pure.

    A BOOLEAN we sent is compared across its storage forms, because an ORM over SQLite hands back
    `1` for `True` and a form-encoded API hands back `"true"`. That widening applies ONLY when the
    value we sent is a bool -- otherwise an integer field we set to `1` would match a boolean `True`
    somewhere else in the object and manufacture a confirmation out of a type coincidence.

    Strings compare case-insensitively (`"Admin"` and `"admin"` are the same role) and are stripped.
    Everything else compares on its exact string form.
    """
    if isinstance(sent, bool):
        o = str(observed).strip().lower() if not isinstance(observed, bool) else ("true" if observed else "false")
        return o in (_TRUE if sent else _FALSE)
    if isinstance(observed, bool):
        return False                       # a non-bool send never matches a stored boolean
    return str(sent).strip().lower() == str(observed).strip().lower()


# -- the oracle ----------------------------------------------------------------------------------

CONFIRMED, LEAD, CLEAN, UNTESTED = "confirmed", "lead", "clean", "untested"


def evaluate(*, field: str, sent_value, baseline: dict, after: dict, control: dict,
             reread_ran: bool, write_accepted: bool) -> dict:
    """The mass-assignment verdict for ONE injected field. Pure, and the only place the halves meet.

    `baseline`   -- {"ran": bool, "found": bool, "value": any}: the field's state on an object of the
                    same shape created/read WITHOUT the injection, through the SAME view.
    `after`      -- {"found": bool, "value": any}: the field on the object we injected into, read
                    back in a SEPARATE request.
    `control`    -- {"ran": bool, "field": str, "found": bool}: the ignored-field probe. `found` is
                    whether the invented attribute came back at all.
    `reread_ran` -- whether the separate re-read actually located our object.
    `write_accepted` -- whether the write carrying the extra attribute got a 2xx. REQUIRED, with no
                    default: a rejected write and an unverified write are opposite results (one is a
                    correctly-validating API, the other is an untested one) and a default would
                    silently pick one of them for every caller that forgot.

    CONFIRMED requires all six:
      (a) the write carrying the extra attribute was ACCEPTED, AND
      (b) the re-read located our object, AND
      (c) the ignored-field control RAN and the invented attribute did NOT come back, AND
      (d) the baseline RAN, AND
      (e) the baseline did not already hold the injected value, AND
      (f) the re-read shows the field holding the injected value.

    Everything weaker degrades explicitly:
      * the write was rejected                        -> CLEAN  (the API validates unknown fields)
      * no re-read / no control run / no baseline run  -> LEAD   (untested, never silently clean)
      * the invented attribute came back               -> CLEAN  (the endpoint echoes anything)
      * the baseline already held the value            -> CLEAN  (the server's own default)
      * the field is exposed and does not hold it      -> CLEAN  (accepted and ignored)
      * the field is exposed by neither read           -> UNTESTED (this view cannot answer)
    """
    baseline = baseline if isinstance(baseline, dict) else {}
    after = after if isinstance(after, dict) else {}
    control = control if isinstance(control, dict) else {}
    out = {"verdict": CLEAN, "field": str(field or ""), "sent": sent_value,
           "baseline_found": bool(baseline.get("found")), "baseline_value": baseline.get("value"),
           "observed_found": bool(after.get("found")), "observed_value": after.get("value"),
           "control_field": str(control.get("field") or ""),
           "control_reflected": bool(control.get("found")), "reason": ""}

    if not write_accepted:
        out.update(verdict=CLEAN, reason=(
            "the endpoint REJECTED the write carrying the extra attribute %r, so the attribute is "
            "not bound -- the API validates the properties it accepts" % out["field"]))
        return out

    if not reread_ran:
        out.update(verdict=LEAD, reason=(
            "the write was sent but the object could not be re-read, so persistence of %r was never "
            "observed -- an accepted request is not proof that the attribute bound" % out["field"]))
        return out

    if not control.get("ran"):
        out.update(verdict=LEAD, reason=(
            "the ignored-field control did not run, so an endpoint that simply echoes every "
            "attribute it is handed cannot be ruled out"))
        return out

    # The control name cannot pre-exist on the server. Its presence ALONE -- not merely its value --
    # is proof the endpoint round-trips arbitrary input, so nothing this endpoint persists is
    # evidence of privilege binding.
    if control.get("found"):
        out.update(verdict=CLEAN, reason=(
            "the endpoint ECHOES arbitrary attributes: the invented control attribute %r came back "
            "on the re-read, so persistence of %r proves nothing about privilege binding"
            % (out["control_field"], out["field"])))
        return out

    if not baseline.get("ran"):
        out.update(verdict=LEAD, reason=(
            "no baseline was established for %r, so the field may already have held this value "
            "before the write" % out["field"]))
        return out

    if baseline.get("found") and same_value(sent_value, baseline.get("value")):
        out.update(verdict=CLEAN, reason=(
            "%r already held %r on an object created WITHOUT the injection, so this is the "
            "application's own default and not an attribute we set"
            % (out["field"], baseline.get("value"))))
        return out

    if not after.get("found"):
        if not baseline.get("found"):
            out.update(verdict=UNTESTED, reason=(
                "this read view exposes no %r field on either the baseline or the injected object, "
                "so it cannot answer whether the attribute bound" % out["field"]))
        else:
            out.update(verdict=CLEAN, reason=(
                "the read view exposes %r (the baseline showed %r) and the injected object does not "
                "carry it, so the extra attribute was accepted and discarded"
                % (out["field"], baseline.get("value"))))
        return out

    if not same_value(sent_value, after.get("value")):
        out.update(verdict=CLEAN, reason=(
            "%r came back as %r, not the injected %r -- the write was accepted and the attribute "
            "was not bound" % (out["field"], after.get("value"), sent_value)))
        return out

    out.update(verdict=CONFIRMED, reason=(
        "%r was not offered by the endpoint, was %s on the baseline object, and reads back as %r "
        "after a write that added it -- the request binds straight onto the model"
        % (out["field"],
           ("%r" % (baseline.get("value"),)) if baseline.get("found") else "absent",
           after.get("value"))))
    return out


# -- findings --------------------------------------------------------------------------------------

# CVSS v3.1: network, low complexity, PR:L (the write normally needs a session -- a self-registration
# endpoint is really PR:N, and scoring the harder case is the conservative direction), no user
# interaction, scope unchanged. C:H/I:H because binding `role`/`isAdmin` grants the privileges the
# application gates on it and lets the attacker write as that role. A:N -- this engine never proves
# an availability effect. Vector and score are kept adjacent and pinned by a test that recomputes
# the v3.1 base score from the vector, because nothing in the report pipeline does: `ws_tool` and
# `session_lifecycle_tool` both cite a `report.check_report_honesty` that does not exist in the tree
# (MEASURED -- `grep -rn check_report_honesty agent/` matches only those two comments and this one),
# so the arithmetic is defended here or nowhere.
_CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
_CVSS_SCORE = 8.1

_BASE_TAGS = ["mass-assignment", "cwe-915", "access-control", "api", "wstg-inpv-20"]

_REMEDIATION = (
    "Do not bind request bodies straight onto persistence models. Accept an explicit ALLOWLIST of "
    "client-writable fields per endpoint (a DTO / serializer / `pick()`), and drop everything else "
    "before the object is constructed -- a denylist is bypassed by the next field somebody adds. "
    "Server-controlled attributes (role, privilege flags, verification state, balances, owner ids) "
    "must be set only by server-side logic after an authorization check, never from the request. "
    "Where the framework offers it, mark those model attributes non-fillable/read-only and reject "
    "unknown properties outright instead of ignoring them."
)


def _control_records(verdict: dict, control_evidence: str, baseline_evidence: str) -> list:
    """The two negative controls, as ARTIFACTS. Written to `negative_controls` -- one of
    `proof_schema.CONTROL_KEYS` -- so `report.control_ran` reads a recorded result rather than a
    sentence the engine merely printed. This codebase measured 626 of 660 stored findings printing a
    control claim that never ran; nothing here prints a claim without this field."""
    return [
        {"kind": "ignored-field control",
         "description": ("the identical write carrying an invented attribute %r that cannot "
                         "pre-exist on the server" % verdict.get("control_field", "")),
         "result": control_evidence,
         "rules_out": "an endpoint that round-trips every attribute it is handed"},
        {"kind": "baseline control",
         "description": ("the same object shape created WITHOUT the injected attribute and read "
                         "through the same view"),
         "result": baseline_evidence,
         "rules_out": "a field that already held the injected value (the application's own default)"},
    ]


def mass_assignment_finding(*, target: str, method: str, verdict: dict, why: str,
                            read_url: str, control_evidence: str, baseline_evidence: str,
                            object_key: str = "", object_value: str = "",
                            offered_fields=None) -> dict:
    """A CONFIRMED mass assignment.

    Every value the report needs is a FIELD on this dict -- `param`, `observed_value`,
    `baseline_value`, `object_id` -- and never something a consumer has to parse back out of the
    title or the evidence prose. Three separate defects in this codebase came from recovering a
    value from a rendered sentence.
    """
    field = verdict.get("field", "")
    ev = (
        "Mass assignment at %s %s. The endpoint accepted an attribute %r it does not offer%s, and a "
        "SEPARATE re-read of the object at %s shows it holding the injected value %r (baseline: %s) "
        "-- HTTP request parameters are bound straight onto the model, so the client chooses a "
        "server-controlled, privileged attribute. %s "
        "NEGATIVE CONTROL 1 (ignored-field) -- %s "
        "NEGATIVE CONTROL 2 (baseline) -- %s"
        % (method or "POST", target, field,
           (" (declared body fields: %s)" % ", ".join(sorted(str(f) for f in offered_fields)))
           if offered_fields else "",
           read_url, verdict.get("observed_value"),
           ("%r" % (verdict.get("baseline_value"),)) if verdict.get("baseline_found") else "absent",
           verdict.get("reason", ""), control_evidence, baseline_evidence))
    return {
        "title": "Mass assignment -- the request body binds the privileged attribute %r" % field,
        "severity": "high", "family": "mass_assignment", "confidence": "confirmed",
        "target": target, "cwe": "CWE-915",
        "cvss_vector": _CVSS_VECTOR, "cvss_score": _CVSS_SCORE,
        "param": field,
        "method": (method or "POST").upper(),
        "injected_value": verdict.get("sent"),
        "observed_value": verdict.get("observed_value"),
        "baseline_value": verdict.get("baseline_value") if verdict.get("baseline_found") else None,
        "baseline_present": bool(verdict.get("baseline_found")),
        "read_url": read_url,
        "object_key": object_key, "object_value": object_value,
        "evidence": ev,
        "success_oracle": ("the privileged attribute holds the injected value on a SEPARATE re-read "
                           "of the object, while the invented control attribute does not come back "
                           "and the baseline object does not already hold that value"),
        "negative_controls": _control_records(verdict, control_evidence, baseline_evidence),
        "reproduction_steps": [
            "Send %s %s with a valid body PLUS the single extra attribute %r = %r."
            % ((method or "POST").upper(), target, field, verdict.get("sent")),
            "Re-read the object in a separate request: GET %s." % read_url,
            "Observe %r = %r in the response -- the attribute persisted."
            % (field, verdict.get("observed_value")),
            "Repeat the write with the invented attribute %r instead: it does not come back, so the "
            "endpoint is not simply echoing input." % verdict.get("control_field", ""),
            "Repeat the write with no extra attribute at all: %r reads back as %s, so the value "
            "above was set by the request."
            % (field, ("%r" % (verdict.get("baseline_value"),))
               if verdict.get("baseline_found") else "absent"),
        ],
        "impact": ("A client can set a server-controlled attribute (%s) simply by naming it in the "
                   "request body. Where that attribute drives authorization, any user who can reach "
                   "this endpoint grants themselves the privilege -- privilege escalation with a "
                   "single extra JSON key, needing no other flaw."
                   % (why or "a privileged field")),
        "remediation": _REMEDIATION,
        "tags": list(_BASE_TAGS) + ["field-%s" % str(field).lower()],
        "wstg": "WSTG-INPV-20",
        # Plainly recorded so an operator can undo the state this engine created. The engine only
        # ever writes to an object it created itself, so this is always a test object.
        "state_created": ("Apolaki created the object %s=%s at %s and set %r on it; delete that "
                          "object to undo." % (object_key or "?", object_value or "?", target,
                                               field)),
    }


def unverified_lead(*, target: str, method: str, verdict: dict, read_url: str,
                    control_evidence: str, baseline_evidence: str) -> dict:
    """A LEAD: the write was sent, and the oracle's other half could not be established.

    Deliberately not a finding. A write that was accepted, an object that could not be re-read, or a
    control that did not run are all the NORMAL state of a well-built API, and emitting any of them
    as `confirmed` is exactly the defect Q-011 exists to fix rather than repeat.
    """
    field = verdict.get("field", "")
    return {
        "title": "Possible mass assignment at %s (extra attribute %r accepted, persistence NOT proven)"
                 % (target, field),
        "severity": "info", "family": "mass_assignment", "confidence": "lead",
        "target": target, "cwe": "CWE-915",
        "param": field,
        "method": (method or "POST").upper(),
        "injected_value": verdict.get("sent"),
        "read_url": read_url,
        "evidence": ("%s %s accepted a request body carrying the extra attribute %r, but this is NOT "
                     "confirmed as mass assignment: %s. An accepted write is not proof -- APIs "
                     "routinely accept and ignore unknown fields. "
                     "NEGATIVE CONTROL 1 (ignored-field) -- %s "
                     "NEGATIVE CONTROL 2 (baseline) -- %s"
                     % ((method or "POST").upper(), target, field, verdict.get("reason", ""),
                        control_evidence, baseline_evidence)),
        "success_oracle": ("persistence of the injected attribute on a SEPARATE re-read was NOT "
                           "observed, so this is reported as a lead and never as a confirmation"),
        "negative_controls": _control_records(verdict, control_evidence, baseline_evidence),
        "impact": ("Not established. If the attribute does bind, a client could set a "
                   "server-controlled field; Apolaki could not observe the object after the write, "
                   "so this is recorded for manual review, not as a vulnerability."),
        "remediation": _REMEDIATION,
        "tags": list(_BASE_TAGS) + ["unconfirmed"],
        "wstg": "WSTG-INPV-20",
    }

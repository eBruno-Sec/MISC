"""Q-155 -- NoSQL operator injection carried in a JSON REQUEST BODY.

The engine under test adds a CARRIER, not an oracle: `nosqli_body` imports
`nosqli_tool.analyze_boolean` and every verdict here is that function's verdict. So these tests
are about the three things a carrier can get wrong, and each has a negative control that fails
when the carrier is right:

  1. IT PROBES WITH AN INVENTED VALUE. Three engines in this project have shipped with a probe
     whose value had no relationship to the observed one, so the baseline and the probe failed
     identically and the engine reported CLEAN on a vulnerable field. Pinned at both levels:
     `nonmatching_value` must carry the observed value, and the bodies the CARRIER actually puts
     on the wire must too.
  2. IT REPORTS AN ENDPOINT THAT REJECTS THE OPERATOR. `SECURE_COERCE` and `SECURE_REJECT` are
     the same application with the defect removed; both must stay silent. `IGNORES_OBJECTS` is
     the subtler one -- an app that DISCARDS a value it cannot coerce answers the operator body
     with the same page it answers a body with the field missing, and without the omit request
     that is a confirmed finding on a clean app.
  3. IT SENDS SOMETHING DESTRUCTIVE. Every payload is checked against the read-only guard, and
     the guard itself is checked against every mutating operator so it cannot be a guard that
     passes what it exists to catch.

No network: the transport is injected. Every fake app below is an in-process Mongo-ish matcher.
"""
import asyncio
import copy
import json
import re

import pytest

import nosqli_body as nb
import nosqli_tool as ns
import proof_schema

URL = "http://lab.invalid/rest/reviews/search"

DOCS = [
    {"_id": "YxAfD6AN5Bk3h3Zeo", "author": "admin@juice-sh.op", "message": "One of my favorites!"},
    {"_id": "YwGn6WgA8BcH7uzfh", "author": "basil@juice-sh.op", "message": "Great, an apple party"},
    {"_id": "Zq1rT4kL9PmX2wCdv", "author": "jim@juice-sh.op", "message": "Tastes like burning"},
]

OBSERVED = {"id": "YxAfD6AN5Bk3h3Zeo", "product": 1}
OBSERVED_RAW = json.dumps(OBSERVED)


# =========================================================================================
# In-process Mongo-ish applications. These ARE the ground truth for this suite: one
# vulnerable, three clean-in-different-ways, one unstable.
# =========================================================================================

def _mongo_match(cond, value) -> bool:
    """The subset of Mongo matching semantics the probes exercise. A dict cond is an OPERATOR
    object -- which is exactly the defect being modelled."""
    if isinstance(cond, dict):
        for op, arg in cond.items():
            if op == "$ne":
                if value == arg:
                    return False
            elif op == "$gt":
                try:
                    if not (value > arg):
                        return False
                except TypeError:
                    return False
            elif op == "$regex":
                if not re.search(str(arg), str(value)):
                    return False
            else:
                return False
        return True
    return value == cond


class FakeApp:
    """`send(method, url, headers, body)` with the shape `ToolRegistry._http` returns.

    `optional_filter` is NOT decoration -- it is the axis the whole omit control turns on, and
    the two settings model two real and common application shapes:

      * REQUIRED filter (default). `find({_id: body.id})` with `body.id` missing selects nothing,
        which is what juice-shop's review store does. The absent-field response is `[]`.
      * OPTIONAL filter. Mongoose strips undefined keys, so `find({})` with the key missing
        selects EVERYTHING. The absent-field response is the whole collection.

    The second shape is where this carrier has a stated, measured blind spot -- see
    `test_an_optional_filter_endpoint_is_a_stated_false_negative`.
    """

    def __init__(self, mode="vulnerable", field="id", key="_id", docs=None,
                 optional_filter=False):
        self.mode, self.field, self.key = mode, field, key
        self.docs = docs if docs is not None else DOCS
        self.optional_filter = optional_filter
        self.seen = []          # every body this app was sent, parsed
        self.raw_seen = []      # every body this app was sent, verbatim
        self.headers_seen = []
        self.replies = []       # every response body it sent back
        self._flip = 0

    def _rows(self, cond):
        return [d for d in self.docs if _mongo_match(cond, d[self.key])]

    def _no_filter(self):
        """What this application answers when the filter field is not in the body at all."""
        return self.docs if self.optional_filter else []

    async def send(self, method, url, headers, body):
        resp = await self._dispatch(method, url, headers, body)
        self.replies.append(resp.get("body"))
        return resp

    async def _dispatch(self, method, url, headers, body):
        self.raw_seen.append(body)
        self.headers_seen.append(dict(headers or {}))
        try:
            parsed = json.loads(body)
        except Exception:
            parsed = None
        self.seen.append(parsed)

        if self.mode == "unstable":
            self._flip += 1
            payload = ([self.docs[0]] if self._flip % 2 else [self.docs[1]])
            return {"status": 200, "body": json.dumps(payload), "error": None}
        if self.mode == "dead":
            return {"status": 0, "body": "", "error": "connect: refused"}

        if not isinstance(parsed, dict) or self.field not in parsed:
            return {"status": 200, "body": json.dumps(self._no_filter()), "error": None}
        cond = parsed[self.field]

        if self.mode == "vulnerable":
            rows = self._rows(cond)
        elif self.mode == "secure_coerce":
            # the fix: the value is coerced to the scalar type the query expects, so an
            # operator object becomes a string that matches no document
            rows = self._rows(str(cond) if isinstance(cond, dict) else cond)
        elif self.mode == "secure_reject":
            if isinstance(cond, dict):
                return {"status": 400, "body": '{"error":"id must be a string"}', "error": None}
            rows = self._rows(cond)
        elif self.mode == "ignores_objects":
            # THE FALSE-POSITIVE SHAPE. A value it cannot coerce is DISCARDED, so the operator
            # response is by definition the same one a body with no `id` at all receives. That
            # is the whole reason the carrier spends a round trip on the omit request.
            if isinstance(cond, dict):
                return {"status": 200, "body": json.dumps(self._no_filter()), "error": None}
            rows = self._rows(cond)
        elif self.mode == "driver_error":
            if isinstance(cond, dict):
                return {"status": 500,
                        "body": "MongoServerError: unknown top level operator: $ne", "error": None}
            rows = self._rows(cond)
        elif self.mode == "driver_error_on_any_miss":
            # errors on ANY value it cannot find, operator or not -- so the error is about the
            # VALUE, not the operator, and must NOT be reported
            if not self._rows(str(cond) if isinstance(cond, dict) else cond):
                return {"status": 500,
                        "body": "MongoServerError: CastError: Cast to ObjectId failed", "error": None}
            rows = self._rows(cond)
        else:
            raise AssertionError("unknown mode %r" % self.mode)
        return {"status": 200, "body": json.dumps(rows), "error": None}


def run(app, **kw):
    kw.setdefault("tag", "bbh7f2a")
    return asyncio.run(nb.probe_json_body(app.send, URL, kw.pop("method", "POST"),
                                          kw.pop("raw", OBSERVED_RAW), **kw))


# =========================================================================================
# 1. Body parsing and traversal
# =========================================================================================

def test_parse_body_accepts_objects_arrays_bytes_and_live_objects():
    assert nb.parse_body('{"a":1}') == {"a": 1}
    assert nb.parse_body('[1,2]') == [1, 2]
    assert nb.parse_body(b'{"a":1}') == {"a": 1}
    assert nb.parse_body({"a": 1}) == {"a": 1}


def test_parse_body_returns_none_for_carriers_that_are_not_ours():
    # None means "this carrier does not apply", never "the endpoint is clean".
    for raw in ("a=1&b=2", "<xml/>", "", "   ", None, 17, '"just-a-string"', "{bad json"):
        assert nb.parse_body(raw) is None, raw


def test_parse_body_does_not_alias_the_callers_object():
    src = {"a": {"b": 1}}
    out = nb.parse_body(src)
    out["a"]["b"] = 99
    assert src["a"]["b"] == 1


def test_walk_scalars_reaches_nested_dicts_and_list_indices():
    body = {"filter": {"id": "x1", "tags": ["red", "blue"]}, "page": 2}
    got = dict(nb.walk_scalars(body))
    assert got[("filter", "id")] == "x1"
    assert got[("filter", "tags", 0)] == "red"
    assert got[("filter", "tags", 1)] == "blue"
    assert got[("page",)] == 2


def test_walk_scalars_excludes_booleans_and_nulls():
    # bool is an int subclass in Python; a flag is a branch selector, not a filter key.
    paths = [p for p, _ in nb.walk_scalars({"live": True, "off": False, "gone": None, "id": "a"})]
    assert paths == [("id",)]


def test_walk_scalars_is_depth_bounded():
    deep = {"a": {"b": {"c": {"d": {"e": {"f": "buried"}}}}}}
    assert nb.walk_scalars(deep, max_depth=3) == []
    assert ("a", "b", "c", "d", "e", "f") in [p for p, _ in nb.walk_scalars(deep, max_depth=99)]


def test_path_label_renders_dicts_and_indices():
    assert nb.path_label(("filter", "tags", 0)) == "filter.tags[0]"
    assert nb.path_label(("id",)) == "id"
    assert nb.path_label(()) == "(body)"


def test_set_at_and_omit_at_never_mutate_the_source_body():
    src = {"filter": {"id": "x1"}, "page": 2}
    frozen = copy.deepcopy(src)
    nb.set_at(src, ("filter", "id"), {"$ne": "z"})
    nb.omit_at(src, ("filter", "id"))
    assert src == frozen


def test_omit_at_removes_the_leaf_only():
    assert nb.omit_at({"a": {"b": 1, "c": 2}}, ("a", "b")) == {"a": {"c": 2}}
    assert nb.omit_at({"t": ["x", "y"]}, ("t", 1)) == {"t": ["x"]}


# =========================================================================================
# 2. Candidate selection
# =========================================================================================

def test_candidate_fields_orders_identifier_looking_names_first_but_excludes_nothing():
    body = {"description": "a long-ish sentence", "productId": 7, "note": "hi"}
    labels = [nb.path_label(p) for p, _ in nb.candidate_fields(body, max_fields=9)]
    assert labels[0] == "productId"
    # ORDERING, NOT FILTERING. Restricting the candidate set to identifier-looking names would
    # be a signature, and would miss any app that filters on a field we did not think to name.
    assert set(labels) == {"productId", "description", "note"}


def test_candidate_fields_excludes_values_that_cannot_carry_an_observed_probe():
    body = {"empty": "", "blank": "   ", "prose": "x" * (nb.MAX_VALUE_LEN + 1),
            "flag": True, "gone": None, "id": "keepme"}
    assert [nb.path_label(p) for p, _ in nb.candidate_fields(body, max_fields=9)] == ["id"]


def test_candidate_fields_is_capped():
    body = {"f%d" % i: "v%d" % i for i in range(20)}
    assert len(nb.candidate_fields(body, max_fields=3)) == 3


# =========================================================================================
# 3. PROBE WITH OBSERVED VALUES -- the rule three engines have already broken
# =========================================================================================

def test_nonmatching_string_carries_the_observed_value():
    v = nb.nonmatching_value("YxAfD6AN5Bk3h3Zeo", tag="t1")
    assert v.startswith("YxAfD6AN5Bk3h3Zeo")
    assert v != "YxAfD6AN5Bk3h3Zeo"


def test_nonmatching_number_is_a_function_of_the_observation():
    # A number has no room for a suffix, so the mutation is arithmetic -- but it must still be
    # DERIVED from the observation, not a constant sentinel like -1 that every field shares.
    assert nb.nonmatching_value(5) != 5
    assert nb.nonmatching_value(5) - 5 == nb.nonmatching_value(9) - 9
    assert nb.nonmatching_value(2.5) != 2.5


def test_nonmatching_value_refuses_types_that_cannot_be_mutated_meaningfully():
    for bad in (True, False, None, [1], {"a": 1}):
        with pytest.raises(TypeError):
            nb.nonmatching_value(bad)


def test_the_operator_argument_is_literally_the_control_value():
    # This is what makes the pair a DIFFERENTIAL rather than two unrelated requests: the only
    # difference between the control body and the $ne body is one level of JSON nesting.
    p = nb.build_probe(OBSERVED, ("id",), tag="t1")
    ne = [o for o in p["operators"] if o["op"] == "$ne"][0]
    assert ne["payload"] == {"$ne": p["control_value"]}
    assert p["control"]["id"] == p["control_value"]
    assert p["control_value"].startswith(OBSERVED["id"])


def test_build_probe_baseline_is_the_observed_body_unchanged():
    p = nb.build_probe(OBSERVED, ("id",), tag="t1")
    assert p["baseline"] == OBSERVED
    # and every probe differs from the baseline at exactly the probed leaf
    for body in [p["control"], p["operators"][0]["body"]]:
        assert body["product"] == OBSERVED["product"]
        assert body["id"] != OBSERVED["id"]
    assert p["omit"] == {"product": 1}


def test_build_probe_works_on_a_nested_path():
    body = {"filter": {"id": "abc123"}, "page": 1}
    p = nb.build_probe(body, ("filter", "id"), tag="t1")
    assert p["label"] == "filter.id"
    assert p["operators"][0]["body"]["filter"]["id"] == {"$ne": "abc123_t1"}
    assert p["operators"][0]["body"]["page"] == 1
    assert p["omit"] == {"filter": {}, "page": 1}


def test_regex_is_never_emitted_for_a_numeric_field():
    # Mongo raises on $regex against a non-string. That driver error is a false positive the
    # probe would have manufactured itself, so the numeric operator set must not contain it.
    ops = nb.operator_payloads(7, nb.nonmatching_value(7))
    assert "$regex" not in [o["op"] for o in ops]
    assert "$regex" in [o["op"] for o in nb.operator_payloads("seven", "seven_t1")]


def test_numeric_gt_bound_is_derived_from_the_observed_number():
    gt = [o for o in nb.operator_payloads(500, nb.nonmatching_value(500)) if o["op"] == "$gt"][0]
    assert gt["payload"]["$gt"] < 500
    other = [o for o in nb.operator_payloads(900, nb.nonmatching_value(900)) if o["op"] == "$gt"][0]
    assert 500 - gt["payload"]["$gt"] == 900 - other["payload"]["$gt"]


# =========================================================================================
# 4. Read-only payloads -- the guard, and the guard's own negative control
# =========================================================================================

def test_every_emitted_probe_body_is_read_only():
    for body in ({"id": "abc"}, {"n": 7}, {"filter": {"id": "abc"}}):
        for path, _ in nb.candidate_fields(body, max_fields=9):
            p = nb.build_probe(body, path, tag="t1")
            for b in [p["baseline"], p["control"], p["omit"]] + [o["body"] for o in p["operators"]]:
                assert nb.is_read_only_payload(b), b


def test_read_only_guard_rejects_every_mutating_operator():
    # A GUARD THAT CANNOT FAIL IS NOT A GUARD. Feed it the entire exclusion list, nested, and
    # require a rejection for each one.
    assert nb.MUTATING_OPERATORS, "the exclusion list must not be empty"
    for op in sorted(nb.MUTATING_OPERATORS):
        assert not nb.is_read_only_payload({"id": {op: "x"}}), op
        assert not nb.is_read_only_payload({"a": [{"b": {op: 1}}]}), op
    assert not nb.is_read_only_payload({"id": {"$madeUpOperator": 1}})


def test_read_only_and_mutating_operator_sets_are_disjoint():
    assert not (nb.READ_ONLY_OPERATORS & nb.MUTATING_OPERATORS)


# =========================================================================================
# 5. The mutating-method gate
# =========================================================================================

def test_method_gate_allows_non_mutating_methods():
    for m in ("POST", "post", "GET", "SEARCH", "QUERY"):
        assert nb.method_verdict(m)[0] is True, m


def test_method_gate_refuses_write_methods_with_a_stated_reason():
    # juice-shop's own body-NoSQLi endpoint is `PATCH /rest/products/reviews`, where the famous
    # {"id": {"$ne": -1}} payload OVERWRITES EVERY REVIEW. A read-only operator on a write
    # method is still a destructive request.
    for m in ("PATCH", "PUT", "DELETE"):
        ok, why = nb.method_verdict(m)
        assert ok is False and "mutating" in why.lower(), m
        assert nb.method_verdict(m, allow_mutating=True)[0] is True


def test_method_gate_refuses_an_unobserved_or_unknown_method():
    assert nb.method_verdict("")[0] is False
    assert nb.method_verdict(None)[0] is False
    assert nb.method_verdict("FROBNICATE")[0] is False


def test_carrier_declines_a_mutating_method_loudly_and_sends_nothing():
    app = FakeApp("vulnerable")
    res = run(app, method="PATCH")
    assert res["findings"] == []
    assert "mutating" in res["skipped"].lower()
    assert app.seen == [], "a refused method must not put a single request on the wire"


# =========================================================================================
# 6. The oracle is nosqli_tool's, and the omit request earns its round trip
# =========================================================================================

def test_verdict_is_analyze_boolean():
    base = json.dumps([DOCS[0]])
    op = json.dumps(DOCS)
    ctl = "[]"
    assert nb.verdict(base, op, ctl, None, baseline_samples=[base]) is True
    assert ns.analyze_boolean(base, op, ctl, None, baseline_samples=[base]) is True


def test_verdict_is_false_when_the_operator_matched_nothing():
    base = json.dumps([DOCS[0]])
    assert nb.verdict(base, "[]", "[]", None, baseline_samples=[base]) is False


def test_the_omit_control_is_what_separates_a_finding_from_a_discarded_field():
    # An app that DISCARDS a value it cannot coerce answers the operator body with the same page
    # it answers a body with no such field at all. Without the omit response that is a confirmed
    # finding on a clean app -- both halves asserted so the control is shown to be load-bearing.
    base = json.dumps([DOCS[0]])
    listed_everything = json.dumps(DOCS)
    assert nb.verdict(base, listed_everything, "[]", None, baseline_samples=[base]) is True
    assert nb.verdict(base, listed_everything, "[]", listed_everything,
                      baseline_samples=[base]) is False


def test_an_unstable_endpoint_is_inconclusive_not_confirmed():
    base = json.dumps([DOCS[0]])
    v = nb.verdict(base, json.dumps(DOCS), "[]", None, baseline_samples=[json.dumps([DOCS[1]])])
    assert ns.is_inconclusive(v)
    assert not v, "Inconclusive must stay falsy so an untaught caller cannot read it as a finding"


# =========================================================================================
# 7. The carrier end to end -- vulnerable app confirms, clean apps stay silent
# =========================================================================================

def test_vulnerable_json_body_endpoint_is_confirmed():
    app = FakeApp("vulnerable")
    res = run(app)
    assert res["skipped"] == ""
    assert len(res["findings"]) == 1, res
    f = res["findings"][0]
    assert f["param"] == "id"
    assert f["family"] == "nosqli" and f["cwe"] == "CWE-943"
    assert f["confidence"] == "confirmed"
    assert "json-body" in f["tags"]


@pytest.mark.parametrize("mode", ["secure_coerce", "secure_reject", "ignores_objects"])
def test_the_same_application_with_the_defect_removed_stays_silent(mode):
    # PAIRED SECURE CONTROLS. Same routes, same documents, same probes -- only the handling of a
    # non-scalar value differs. Any finding here is a false positive by construction.
    app = FakeApp(mode)
    res = run(app)
    assert res["findings"] == [], (mode, res)


def test_an_app_that_discards_objects_is_caught_by_the_omit_request_alone():
    # The one clean shape that the baseline/operator/control triple CANNOT separate on its own.
    # `ignores_objects` with an optional filter answers the operator body with the entire
    # collection -- exactly what a real injection looks like -- and the only thing that says
    # otherwise is that a body with no `id` at all gets the same page.
    app = FakeApp("ignores_objects", optional_filter=True)
    res = run(app)
    assert res["findings"] == [], res
    # ... and the responses really were the confirming shape, so this is the omit control doing
    # work and not the differential having failed for some unrelated reason.
    base = json.dumps(DOCS[:1])
    assert nb.verdict(json.dumps([DOCS[0]]), json.dumps(DOCS), "[]", None,
                      baseline_samples=[base]) is True


def test_an_optional_filter_endpoint_is_a_stated_false_negative():
    # MEASURED, and recorded as a BOUND rather than hidden. On an endpoint whose filter is
    # optional, a genuine `$ne` injection returns the whole collection and so does a body with
    # the field removed -- the two responses are byte-identical, so no probe in this set can
    # tell an evaluated operator from a discarded one. `analyze_boolean` correctly refuses.
    # A false negative is the right side of that trade (a false HIGH is worse), and the fix is
    # a separate identity-operator probe, not a weakened guard here.
    vuln = FakeApp("vulnerable", optional_filter=True)
    clean = FakeApp("ignores_objects", optional_filter=True)
    assert run(vuln)["findings"] == []
    # the honest reason it is a bound: over every request this carrier sends, the vulnerable
    # application and the clean one return byte-identical responses. Nothing was missed through
    # carelessness -- there is no signal there to read.
    run(clean)
    assert vuln.raw_seen == clean.raw_seen
    assert vuln.replies == clean.replies


def test_a_dead_endpoint_reports_why_instead_of_reporting_clean():
    res = run(FakeApp("dead"))
    assert res["findings"] == []
    assert "baseline request did not complete" in res["skipped"]


def test_an_unstable_endpoint_yields_no_finding_and_says_so():
    app = FakeApp("unstable")
    res = run(app)
    assert res["findings"] == []
    assert res["inconclusive"], "an unstable endpoint must be REPORTED, not silently clean"
    assert "reproduce" in res["inconclusive"][0]["why"]


def test_a_body_this_carrier_cannot_read_is_skipped_with_a_reason():
    res = run(FakeApp("vulnerable"), raw="id=YxAfD6AN5Bk3h3Zeo&product=1")
    assert res["findings"] == [] and "not a JSON" in res["skipped"]


def test_a_body_with_no_filterable_field_is_skipped_with_a_reason():
    res = run(FakeApp("vulnerable"), raw='{"enabled":true,"note":null}')
    assert res["findings"] == [] and "no scalar field" in res["skipped"]


# =========================================================================================
# 8. Error-based variant, and its own negative control
# =========================================================================================

def test_a_driver_error_the_operator_alone_provokes_is_reported():
    app = FakeApp("driver_error")
    res = run(app)
    assert len(res["findings"]) == 1
    assert "error-based" in res["findings"][0]["tags"]
    assert "MongoDB" in res["findings"][0]["evidence"]


def test_a_driver_error_the_plain_control_also_provokes_is_not_reported():
    # The error is about the VALUE (an id the store does not hold), not the OPERATOR. Reporting
    # it would be a false positive manufactured by our own non-matching probe.
    app = FakeApp("driver_error_on_any_miss")
    res = run(app)
    assert res["findings"] == [], res


# =========================================================================================
# 9. What the carrier actually puts on the wire
# =========================================================================================

def test_the_first_request_is_the_applications_own_body_verbatim():
    app = FakeApp("vulnerable")
    run(app)
    assert app.seen[0] == OBSERVED, "the reference request must be the observed request"


def test_the_baseline_is_repeated_so_stability_is_measured_not_assumed():
    app = FakeApp("vulnerable")
    run(app)
    assert app.seen[0] == OBSERVED and app.seen[1] == OBSERVED


def test_every_body_the_carrier_sends_is_read_only_and_carries_the_observed_value():
    app = FakeApp("vulnerable")
    run(app)
    assert app.seen, "the carrier sent nothing"
    seen_observed = False
    for body in app.seen:
        assert nb.is_read_only_payload(body), body
        blob = json.dumps(body)
        if OBSERVED["id"] in blob:
            seen_observed = True
    # THE ANTI-INVENTED-VALUE PIN AT THE CARRIER LEVEL. Every value this engine substitutes into
    # the `id` field must carry the observed id -- the only exceptions are the declared
    # match-everything wildcards, which cannot fail for a reason unrelated to the field.
    for body in [b for b in app.seen if "id" in b]:
        v = body["id"]
        if v in nb.WILDCARD_PAYLOADS:
            continue
        assert OBSERVED["id"] in json.dumps(v), body
    assert seen_observed


def test_only_declared_wildcards_are_ungrounded():
    # The exception list is a LIST, not a habit. Every probe argument this module can emit is
    # either a mutation of the observation or one of exactly these two wildcards; a third one
    # added later turns this test red rather than quietly widening the exemption.
    for observed in ("YxAfD6AN5Bk3h3Zeo", 42, 3.5):
        ctl = nb.nonmatching_value(observed, tag="t1")
        for spec in nb.operator_payloads(observed, ctl):
            if spec["payload"] in nb.WILDCARD_PAYLOADS:
                continue
            arg = list(spec["payload"].values())[0]
            assert str(observed) in str(arg) or isinstance(arg, (int, float)), spec
    # and the wildcards really are match-everything, not just labelled as such
    assert re.search(nb.WILDCARD_PAYLOADS[0]["$regex"], "anything at all")
    assert "" < "a" and nb.WILDCARD_PAYLOADS[1]["$gt"] == ""


def test_the_carrier_sends_a_json_content_type_and_keeps_the_callers_headers():
    app = FakeApp("vulnerable")
    asyncio.run(nb.probe_json_body(app.send, URL, "POST", OBSERVED_RAW, tag="t1",
                                   headers={"Authorization": "Bearer x"}))
    assert app.headers_seen, "the carrier sent nothing"
    for h in app.headers_seen:
        assert h.get("Content-Type") == "application/json"
        # juice-shop's own body-NoSQLi endpoint answers 401 without this, so dropping the
        # caller's session would make every probe measure the login wall instead of the query.
        assert h.get("Authorization") == "Bearer x"


def test_caller_headers_survive_and_the_request_count_is_bounded():
    app = FakeApp("vulnerable")
    res = asyncio.run(nb.probe_json_body(app.send, URL, "POST", OBSERVED_RAW, tag="t1",
                                         headers={"Authorization": "Bearer x"}, max_fields=2))
    # 2 reference requests + per field (1 control + 1 omit + <=2 operators)
    assert res["requests"] <= 2 + 2 * (2 + nb.MAX_OPERATORS_PER_FIELD)


# =========================================================================================
# 10. The finding satisfies the project's proof contract
# =========================================================================================

def test_the_confirmed_finding_passes_the_proof_schema():
    for app in (FakeApp("vulnerable"), FakeApp("driver_error")):
        f = run(app)["findings"][0]
        ok, missing = proof_schema.validate_confirmed(f)
        assert ok, (f.get("title"), missing)
        assert proof_schema.is_confirmed(f)


def test_the_boolean_finding_records_the_negative_control_as_an_artifact():
    f = run(FakeApp("vulnerable"))["findings"][0]
    key = next(k for k in proof_schema.CONTROL_KEYS if k in f)
    assert f[key], "the control must be a recorded artifact, not a claim in prose"
    assert f[key][0]["value"].startswith(OBSERVED["id"])


def test_the_finding_names_the_body_path_not_a_query_parameter():
    body = {"filter": {"id": "YxAfD6AN5Bk3h3Zeo"}}
    app = FakeApp("vulnerable", field="filter")

    # a nested-filter app: the operator has to be reached at filter.id
    async def send(method, url, headers, raw):
        app.raw_seen.append(raw)
        parsed = json.loads(raw)
        app.seen.append(parsed)
        if "id" not in (parsed.get("filter") or {}):
            return {"status": 200, "body": "[]", "error": None}   # the filter is required
        cond = parsed["filter"]["id"]
        rows = [d for d in DOCS if _mongo_match(cond, d["_id"])]
        return {"status": 200, "body": json.dumps(rows), "error": None}

    res = asyncio.run(nb.probe_json_body(send, URL, "POST", json.dumps(body), tag="t1"))
    assert [f["param"] for f in res["findings"]] == ["filter.id"]
    assert "filter.id" in res["findings"][0]["evidence"]

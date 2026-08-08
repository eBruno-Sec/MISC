"""GraphQL argument extraction + injection wiring (#125, Black Hat GraphQL Ch.8).

parse_schema already reported that introspection is enabled. Ch.8's point is that the arguments are the
injection entry points — and Apolaki's injection engines only look at query strings and form fields, so
without an argument list they cannot reach a GraphQL sink at all.
"""
import graphql_tool as gq

INTROSPECTION = {"data": {"__schema": {
    "queryType": {"name": "Query"},
    "mutationType": {"name": "Mutation"},
    "types": [
        {"name": "Query", "kind": "OBJECT", "fields": [
            {"name": "user", "args": [{"name": "id", "type": {"kind": "SCALAR", "name": "ID"}}, {"name": "locale", "type": {"kind": "SCALAR", "name": "String"}}]},
            {"name": "search", "args": [{"name": "term", "type": {"kind": "SCALAR", "name": "String"}}, {"name": "limit", "type": {"kind": "SCALAR", "name": "Int"}}]},
            {"name": "health", "args": []},
        ]},
        {"name": "Mutation", "kind": "OBJECT", "fields": [
            {"name": "updateEmail", "args": [{"name": "userId", "type": {"kind": "SCALAR", "name": "ID"}}, {"name": "email", "type": {"kind": "SCALAR", "name": "String"}}]},
        ]},
        {"name": "User", "kind": "OBJECT", "fields": [{"name": "name", "args": []}]},
    ]}}}


def test_operations_cover_queries_and_mutations_only():
    ops = gq.schema_operations(INTROSPECTION)
    assert {o["operation"] for o in ops} == {"user", "search", "health", "updateEmail"}
    assert {o["kind"] for o in ops} == {"query", "mutation"}
    # a plain object type is not an operation
    assert not any(o["operation"] == "name" for o in ops)


def test_arguments_are_extracted_with_their_types():
    ops = {o["operation"]: o for o in gq.schema_operations(INTROSPECTION)}
    assert [a["name"] for a in ops["user"]["args"]] == ["id", "locale"]
    assert [a["type"] for a in ops["search"]["args"]] == ["String", "Int"]
    assert ops["health"]["args"] == []


def test_non_textual_arguments_are_marked_uninjectable():
    """Learned live on DVGA: a payload sent to an Int argument is rejected by the type system before it
    reaches any sink — the request is wasted and proves nothing."""
    inj = {i["arg"]: i for i in gq.injectable_arguments(gq.schema_operations(INTROSPECTION))}
    assert inj["term"]["injectable"] is True and inj["term"]["type"] == "String"
    assert inj["limit"]["injectable"] is False and inj["limit"]["type"] == "Int"
    # injectable ones sort ahead of the rest
    order = [i["arg"] for i in gq.injectable_arguments(gq.schema_operations(INTROSPECTION))]
    assert order.index("term") < order.index("limit")


def test_mutations_are_excluded_from_auto_fire():
    """Also learned live: the first candidate DVGA offered was deletePaste(id:). Mutations change state
    and must never be speculatively injected — they are operator-gated, not automatic."""
    auto = gq.injectable_arguments(gq.schema_operations(INTROSPECTION))
    assert all(i["kind"] == "query" for i in auto), [i for i in auto if i["kind"] != "query"]
    assert "email" not in [i["arg"] for i in auto]

    gated = gq.injectable_arguments(gq.schema_operations(INTROSPECTION), include_mutations=True)
    m = [i for i in gated if i["arg"] == "email"]
    assert m and m[0]["state_changing"] is True


def test_injectable_arguments_rank_interesting_names_first():
    inj = gq.injectable_arguments(gq.schema_operations(INTROSPECTION))
    assert inj and inj[0]["interesting"] is True
    names = [i["arg"] for i in inj]
    assert "id" in names and "term" in names
    assert names.index("locale") > names.index("id")


def test_operations_are_empty_without_introspection():
    assert gq.schema_operations({"errors": [{"message": "introspection disabled"}]}) == []
    assert gq.schema_operations({}) == []
    assert gq.schema_operations(None) == []


def test_build_query_shapes_a_minimal_operation():
    q = gq.build_query("user", "query", "id", "1")
    assert q.startswith("query {") and "user(id: \"1\")" in q and "__typename" in q
    m = gq.build_query("updateEmail", "mutation", "email", "a@b.c")
    assert m.startswith("mutation {")


def test_a_payload_cannot_restructure_the_document():
    """Safety, not hygiene: an unescaped payload could close the string and append a far heavier query —
    which on GraphQL means accidentally sending the resource-exhaustion request Apolaki refuses to send.

    The property is containment, not the absence of scary words: whatever the payload contains, it must
    round-trip out of the document as EXACTLY the value we put in, meaning it never became structure."""
    import json
    import re
    for nasty in ('") { __typename } } query Heavy { __schema { types { name } } } #',
                  '"}]}{"query":"query E { __typename }"',
                  'a" b \\" c'):
        q = gq.build_query("search", "query", "term", nasty)
        m = re.match(r'^query \{ search\(term: (".*")\) \{ __typename \} \}$', q, re.S)
        assert m, "document shape broken by payload %r -> %s" % (nasty, q)
        assert json.loads(m.group(1)) == nasty, "payload did not round-trip as a value"


def test_build_query_survives_quotes_and_newlines():
    for payload in ("' OR 1=1 --", '<script>alert(1)</script>', "a\nb", '"', "\\"):
        q = gq.build_query("search", "query", "term", payload)
        assert q.startswith("query {") and q.endswith("} }")

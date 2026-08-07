"""General create-object-IDOR endpoint discovery (target-agnostic BOLA): discover REST object collections
from the surface + derive a create-spec from a sample object, so BOLA is confirmed on ANY REST API."""
import json

import create_object_idor as C


def test_discover_collection_endpoints():
    urls = ["http://app/api/Feedbacks", "http://app/api/Feedbacks/3", "http://app/rest/basket",
            "http://app/products", "http://app/api/Products?q=1", "http://app/api/Feedbacks"]
    got = C.discover_collection_endpoints(urls)
    assert "/api/Feedbacks" in got and "/rest/basket" in got and "/api/Products" in got
    assert "/api/Feedbacks/3" not in got          # already carries an id — not a collection
    assert "/products" not in got                 # not under an api-ish root
    assert got.count("/api/Feedbacks") == 1       # deduped


def test_build_spec_from_sample_stamps_marker_and_drops_server_fields():
    sample = {"id": 1, "comment": "a fairly long feedback comment", "rating": 5,
              "UserId": 2, "createdAt": "2020", "captcha": "x"}
    spec = C.build_spec_from_sample("/api/Feedbacks", sample, "MARKER123")
    body = json.loads(spec["create"]["body"])
    assert "id" not in body and "UserId" not in body and "createdAt" not in body   # server-assigned dropped
    assert body["comment"] == "MARKER123"          # marker in the longest string field
    assert body["rating"] == 5                     # numeric preserved
    assert spec["read"] == "/api/Feedbacks/{id}" and spec["create"]["method"] == "POST"
    assert spec["marker_field"] == "comment" and spec["derived"] is True


def test_build_spec_none_without_string_field():
    assert C.build_spec_from_sample("/api/Nums", {"id": 1, "count": 5}, "M") is None
    assert C.build_spec_from_sample("/api/x", "not a dict", "M") is None


def test_derived_spec_defaults_to_marker_placeholder():
    """Defect #3 regression: a derived spec (no explicit marker) must carry the literal ``{marker}``
    PLACEHOLDER — NOT a concrete value baked at derivation time. The live driver stamps one fresh marker
    per attempt via body.replace("{marker}", live), so the verdict always checks the marker actually sent.
    A concrete baked marker never matched the driver's freshly-generated one => confirmed reads went silently
    missing (false negative)."""
    sample = {"id": 7, "book_title": "some long-enough title", "secret": "s"}
    spec = C.build_spec_from_sample("/books/v1", sample)          # no marker arg -> default placeholder
    body = json.loads(spec["create"]["body"])
    assert spec["marker_field"] == "book_title" and spec["natural_key"] is True
    assert body["book_title"] == "{marker}"                       # placeholder, not a concrete marker
    # the driver's substitution reaches a real value the verdict can then match
    live = C.new_marker()
    sent = spec["create"]["body"].replace("{marker}", live)
    assert live in sent and "{marker}" not in sent

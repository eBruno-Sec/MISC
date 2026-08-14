"""Q-021B - the fingerprinter must PERSIST what it detects, and must refuse prose while doing it.

Two separate defects, both reproduced against live code before this suite existed:

  1. `fingerprint()` returns {name, version, source, category}; `tools._run_fingerprint` keeps
     `[t["name"] for t in techs]` and drops the rest one line later. The version is computed and
     thrown away.
  2. `_POWERED` admits sentence fragments as product names -
     `'a MultiJuicer Kubernetes cluste'` (31 chars: the {2,30} bound plus its leading character)
     and `'nothing on.'`. Persisting those would send them to a CVE feed as products.

The fix for (2) is an admission GATE on the persistence path, not a narrower `_POWERED`:
`fingerprint()` itself is unchanged, so `live_hosts[i]["tech"]` - which the UI and the report delta
section read - keeps its exact shape.
"""
import dependency_intel as di
import fingerprint as fp


HDRS = {"Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.4.3"}
PROSE = ("This deployment is running a MultiJuicer Kubernetes cluster in safety mode. "
         "powered by nothing on.")


# ── the detector's own output is untouched (regression) ────────────────────────────────────────
def test_fingerprint_return_shape_is_unchanged():
    """The display path must not move. Anything that renders `tech` reads these four keys."""
    techs = fp.fingerprint(HDRS, "PHPSESSID=x", "")
    assert [t["name"] for t in techs] == ["nginx", "PHP"]
    assert all(set(t) == {"name", "version", "source", "category"} for t in techs)


def test_prose_still_reaches_the_display_path_unchanged():
    """`_POWERED` is deliberately NOT narrowed - narrowing it would change `fingerprint()`'s output
    for every existing caller. The gate lives on the persistence path instead."""
    assert [t["name"] for t in fp.fingerprint({}, "", PROSE)] == \
        ["a MultiJuicer Kubernetes cluste", "nothing on."]


# ── the identity gate ──────────────────────────────────────────────────────────────────────────
def test_real_product_names_are_admitted():
    for name, src in [("nginx", "Server header"), ("PHP", "X-Powered-By"),
                      ("ASP.NET", "x-aspnet-version"), ("Ruby on Rails", "Set-Cookie"),
                      ("Express/Node.js", "Set-Cookie"), ("Next.js", "HTML signature"),
                      ("jQuery", "script src"), ("Microsoft-IIS", "Server header"),
                      ("WordPress", "meta generator"), ("Java/JSP", "Set-Cookie")]:
        assert fp.name_rejection(name, src) == "", "%s from %s must be admitted" % (name, src)


def test_the_measured_prose_fragments_are_refused_with_a_named_reason():
    """CONTROL (a). These are the exact strings the live detector produced. `MultiJuicer` is caught
    by the leading article - it is also four tokens and 31 characters (the {2,30} bound plus its
    leading character), so three independent rules refuse it and the first one wins."""
    assert fp.name_rejection("a MultiJuicer Kubernetes cluste", "powered-by text") == "prose_leading_stopword"
    assert fp.name_rejection("nothing on.", "powered-by text") == "trailing_sentence_punctuation"
    assert fp.name_rejection("in safety mode.", "powered-by text") == "trailing_sentence_punctuation"


def test_a_long_phrase_without_a_leading_stopword_is_still_refused():
    """Isolates the token-count rule from the stopword rule: no product name any detection table
    emits is longer than `Ruby on Rails`."""
    assert fp.name_rejection("Acme Super Fast Server", "Server header") == "too_many_tokens"
    assert fp.name_rejection("Open Source Content Management", "meta generator") == "too_many_tokens"


def test_prose_source_requires_a_known_product():
    """A free-text 'powered by X' hit is the weakest signal the detector has, so X must be a product
    the detection tables already name. An unknown token there is a sentence, not a vendor."""
    assert fp.name_rejection("Wordpress", "powered-by text") == ""
    assert fp.name_rejection("Bakery", "powered-by text") == "prose_not_a_known_product"
    assert fp.name_rejection("Bakery", "Server header") == "", \
        "a structured header is allowed to name a product no table knows"


def test_gate_refuses_junk_shapes():
    assert fp.name_rejection("", "Server header") == "empty"
    assert fp.name_rejection("   ", "Server header") == "empty"
    assert fp.name_rejection("cache-lax1-LAX, cache-fra1-FRA", "x-served-by") == "bad_shape"
    assert fp.name_rejection("9lives", "Server header") == "bad_shape"
    assert fp.name_rejection("x" * 60, "Server header") == "too_long"
    assert fp.name_rejection("the Cloud", "Server header") == "prose_leading_stopword"


# ── facts carry the version and the source, end to end ─────────────────────────────────────────
def test_tech_facts_keep_the_version_that_fingerprint_computed():
    """ORACLE 1. The version survives, with the byte that proved it."""
    facts, rejected = fp.tech_facts(HDRS, "", "", url="http://box:3000/")
    assert rejected == []
    by = {f["product"]: f for f in facts}
    assert by["nginx"]["version"] == "1.18.0"
    assert by["nginx"]["source"] == "Server header"
    assert by["nginx"]["detector"] == "fingerprint.headers"
    assert by["nginx"]["evidence"] == "Server: nginx/1.18.0"
    assert by["nginx"]["host"] == "box:3000"
    assert by["nginx"]["category"] == "server"
    assert by["php"]["version"] == "7.4.3"
    assert by["php"]["evidence"] == "X-Powered-By: PHP/7.4.3"


def test_a_spoofed_ancient_banner_is_recorded_but_never_cve_eligible():
    """CONTROL. `Server: Apache/1.3.9` on a modern box is the classic decoy. The fact records the
    claim verbatim as EVIDENCE; the ladder refuses to let it pull CVEs."""
    facts, _ = fp.tech_facts({"Server": "Apache/1.3.9"}, "", "", url="http://box/")
    assert len(facts) == 1
    f = facts[0]
    assert f["version"] == "1.3.9" and f["evidence"] == "Server: Apache/1.3.9"
    assert f["version_confidence"] == di.LOW
    assert di.cve_eligible(f) is False
    assert f["component_status"] == di.POTENTIALLY_AFFECTED
    assert f["proof_state"] == di.VERSION_SUSPECTED


def test_a_versionless_detection_is_a_legal_fact_at_low_confidence():
    """CONTROL (b)."""
    facts, _ = fp.tech_facts({"Server": "nginx"}, "", "", url="http://box/")
    assert [f["product"] for f in facts] == ["nginx"]
    assert facts[0]["version"] == ""
    assert facts[0]["version_confidence"] == di.LOW
    assert di.cve_eligible(facts[0]) is False
    assert facts[0]["proof_state"] == di.DETECTED_TECHNOLOGY


def test_a_versioned_script_filename_is_high_and_cve_eligible():
    body = '<script src="/assets/jquery-3.4.1.min.js"></script>'
    facts, _ = fp.tech_facts({}, "", body, url="http://box/")
    jq = [f for f in facts if f["product"] == "jquery"][0]
    assert jq["version"] == "3.4.1"
    assert jq["version_confidence"] == di.HIGH
    assert di.cve_eligible(jq) is True


def test_cookie_evidence_never_carries_the_cookie_value():
    """A Set-Cookie header carries a LIVE SESSION TOKEN. Evidence is quoted into reports and stored
    across missions, so only the matched cookie NAME may be recorded."""
    secret = "s%3ADEADBEEFCAFE1234567890"
    facts, _ = fp.tech_facts({}, "connect.sid=" + secret + "; HttpOnly", "", url="http://box/")
    assert [f["product"] for f in facts] == ["express/node.js"]
    assert facts[0]["evidence"] == "Set-Cookie: connect.sid"
    assert secret not in facts[0]["evidence"]


def test_authentication_state_is_carried_onto_every_fact():
    facts, _ = fp.tech_facts(HDRS, "", "", url="http://box/", authenticated=True)
    assert facts and all(f["authenticated"] is True for f in facts)


# ── refusals are RECORDED, never silently dropped ──────────────────────────────────────────────
def test_prose_produces_zero_facts_and_a_named_rejection():
    """CONTROL (a), the whole of it. A fix that merely stops STORING prose without recording the
    refusal has moved the blindness, not removed it - the same reason `_swallow` exists."""
    facts, rejected = fp.tech_facts({}, "", PROSE, url="http://box/")
    assert facts == []
    assert len(rejected) == 2
    assert {r["name"] for r in rejected} == {"a MultiJuicer Kubernetes cluste", "nothing on."}
    assert {r["reason"] for r in rejected} == {"prose_leading_stopword", "trailing_sentence_punctuation"}
    assert all(r["detector"] == "fingerprint.body.prose" for r in rejected), \
        "the rejection names the detector that produced it"
    assert all(r["source"] == "powered-by text" for r in rejected)


def test_empty_target_produces_zero_facts_zero_rejections_and_no_error():
    """CONTROL (c). A real zero must be distinguishable from a broken detector."""
    assert fp.tech_facts({}, "", "", url="http://box/") == ([], [])
    assert fp.tech_facts(None, None, None) == ([], [])


# ── the persistence path: recon, not a return value ────────────────────────────────────────────
def test_record_facts_writes_into_recon():
    """ORACLE 1, end to end. `recon` is what survives the tool call; a return value is exactly what
    was being thrown away."""
    recon = {"live_hosts": []}
    fp.record_facts(recon, "http://box:3000/", HDRS, "", "", now=100.0)
    assert len(recon["technology"]) == 2
    nginx = [f for f in recon["technology"] if f["product"] == "nginx"][0]
    assert nginx["version"] == "1.18.0"
    assert nginx["source"] == "Server header"
    assert nginx["first_seen"] == 100.0


def test_record_facts_records_refusals_into_recon():
    recon = {}
    fp.record_facts(recon, "http://box/", {}, "", PROSE, now=1.0)
    assert recon["technology"] == []
    assert len(recon["technology_rejected"]) == 2


def test_a_second_observation_updates_last_seen_rather_than_duplicating():
    """ORACLE 3's local half: re-fingerprinting one host is one fact, not two."""
    recon = {}
    fp.record_facts(recon, "http://box:3000/", HDRS, "", "", now=100.0)
    fp.record_facts(recon, "http://box:3000/", HDRS, "", "", now=500.0)
    assert len(recon["technology"]) == 2
    nginx = [f for f in recon["technology"] if f["product"] == "nginx"][0]
    assert nginx["first_seen"] == 100.0 and nginx["last_seen"] == 500.0


def test_two_hosts_are_two_facts():
    recon = {}
    fp.record_facts(recon, "http://a/", {"Server": "nginx/1.18.0"}, "", "", now=1.0)
    fp.record_facts(recon, "http://b/", {"Server": "nginx/1.25.0"}, "", "", now=1.0)
    assert sorted(f["host"] for f in recon["technology"]) == ["a", "b"]


def test_record_facts_accepts_precomputed_techs_without_refingerprinting():
    """The producer patch reuses the `techs` it already computed - the caller must not pay for a
    second regex pass over the body."""
    recon = {}
    techs = fp.fingerprint(HDRS, "", "")
    fp.record_facts(recon, "http://box/", {}, "", "", techs=techs, now=1.0)
    assert {f["product"] for f in recon["technology"]} == {"nginx", "php"}


def test_rejection_list_is_bounded():
    """The `_swallow` discipline: a pathological body must not grow recon without limit."""
    recon = {}
    for i in range(fp.MAX_REJECTIONS + 50):
        fp.record_facts(recon, "http://box/", {"Server": "bad name %d." % i}, "", "", now=1.0)
    assert len(recon["technology_rejected"]) == fp.MAX_REJECTIONS


def test_record_facts_leaves_the_display_list_alone():
    """REGRESSION. `live_hosts[i]["tech"]` is `tools._run_fingerprint`'s business and must keep the
    bare-string shape the report delta section reads."""
    recon = {"live_hosts": [{"url": "http://box/", "tech": ["nginx"]}]}
    fp.record_facts(recon, "http://box/", HDRS, "", "", now=1.0)
    assert recon["live_hosts"] == [{"url": "http://box/", "tech": ["nginx"]}]

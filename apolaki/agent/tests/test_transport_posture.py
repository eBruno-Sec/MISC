"""Transport + web posture family (#103, WAHH-seeded). The pure layer: every oracle and every refusal."""
import datetime

import transport_posture as tp

NOW = datetime.datetime(2026, 8, 8, tzinfo=datetime.timezone.utc)


def _cert(subject="example.com", issuer="Real CA", not_after="Jun  1 12:00:00 2027 GMT",
          not_before="Jun  1 12:00:00 2025 GMT", sans=("example.com",)):
    return {"subject": ((("commonName", subject),),),
            "issuer": ((("commonName", issuer),),),
            "notAfter": not_after, "notBefore": not_before,
            "subjectAltName": tuple(("DNS", s) for s in sans)}


# ── certificates ──────────────────────────────────────────────────────────────
def test_healthy_certificate_yields_nothing():
    assert tp.analyze_certificate(_cert(), "example.com", now=NOW) == []


def test_expired_and_expiring_are_distinguished():
    exp = tp.analyze_certificate(_cert(not_after="Jun  1 12:00:00 2026 GMT"), "example.com", now=NOW)
    assert [i["id"] for i in exp] == ["cert_expired"]
    soon = tp.analyze_certificate(_cert(not_after="Aug 20 12:00:00 2026 GMT"), "example.com", now=NOW)
    assert [i["id"] for i in soon] == ["cert_expiring"] and soon[0]["severity"] == "low"


def test_self_signed_detected_by_subject_equals_issuer():
    ids = [i["id"] for i in tp.analyze_certificate(_cert(issuer="example.com"), "example.com", now=NOW)]
    assert "cert_self_signed" in ids


def test_hostname_mismatch_and_wildcard_rules():
    # the CN counts as a name too, so a genuine mismatch needs BOTH to be wrong
    bad = _cert(subject="other.com", sans=("other.com",))
    ids = [i["id"] for i in tp.analyze_certificate(bad, "example.com", now=NOW)]
    assert "cert_hostname_mismatch" in ids
    # a SAN that matches is enough even when the CN does not
    assert tp.analyze_certificate(_cert(subject="legacy", sans=("example.com",)),
                                  "example.com", now=NOW) == []
    # a single leftmost wildcard matches one label only
    assert tp.hostname_matches("a.example.com", ["*.example.com"]) is True
    assert tp.hostname_matches("a.b.example.com", ["*.example.com"]) is False
    assert tp.hostname_matches("example.com", ["*.example.com"]) is False


def test_weak_key_flagged_only_below_the_minimum():
    assert [i["id"] for i in tp.analyze_certificate(_cert(), "example.com", now=NOW, key_bits=1024)] \
        == ["cert_weak_key"]
    assert tp.analyze_certificate(_cert(), "example.com", now=NOW, key_bits=2048) == []


# ── protocols + ciphers ───────────────────────────────────────────────────────
def test_deprecated_protocols_reported_only_when_the_handshake_completed():
    g = tp.analyze_protocols({"SSLv3": False, "TLSv1": True, "TLSv1.1": False,
                              "TLSv1.2": True, "TLSv1.3": True})
    assert g["deprecated_supported"] == ["TLSv1"] and g["discriminating"] is True
    assert g["no_modern_support"] is False


def test_an_untestable_version_is_unknown_never_absent():
    """A version this OpenSSL cannot speak, or was not tested at all, is UNKNOWN. Reporting it as
    'not supported' would let an insecure server look secure because of our own client's limits."""
    g = tp.analyze_protocols({"SSLv3": None, "TLSv1": None, "TLSv1.2": True})
    assert g["untestable"] == ["SSLv3", "TLSv1", "TLSv1.1"]   # TLSv1.1 absent => also unknown
    assert g["deprecated_supported"] == []          # unknown must never become a finding


def test_a_probe_that_accepts_everything_is_not_trusted():
    """If every pinned version 'succeeds' the probe is not discriminating; reporting it would be noise."""
    g = tp.analyze_protocols({"SSLv3": True, "TLSv1": True, "TLSv1.1": True, "TLSv1.2": True,
                              "TLSv1.3": True})
    assert g["discriminating"] is False
    fs = tp.findings_for("t", protocols={"SSLv3": True, "TLSv1": True, "TLSv1.1": True,
                                         "TLSv1.2": True, "TLSv1.3": True})
    assert [f for f in fs if f["tags"][1] == "tls"] == []      # no TLS claim from a useless probe


def test_no_modern_support_is_high():
    g = tp.analyze_protocols({"TLSv1": True, "TLSv1.2": False, "TLSv1.3": False})
    assert g["no_modern_support"] is True


def test_weak_cipher_tokens():
    assert tp.weak_cipher("ECDHE-RSA-RC4-SHA") == "RC4"
    assert tp.weak_cipher("DES-CBC3-SHA") in ("DES-CBC3", "3DES", "DES")
    assert tp.weak_cipher("TLS_AES_256_GCM_SHA384") == ""


# ── cookies ───────────────────────────────────────────────────────────────────
def test_session_cookie_attribute_gaps():
    iss = tp.analyze_cookies(["sessionid=abc; Path=/"], is_https=True)
    ids = {i["id"] for i in iss}
    assert ids == {"cookie_missing_secure", "cookie_missing_httponly", "cookie_missing_samesite"}


def test_a_fully_attributed_cookie_is_clean():
    assert tp.analyze_cookies(["sessionid=abc; Secure; HttpOnly; SameSite=Lax"], is_https=True) == []


def test_non_session_cookies_are_ignored():
    """Flagging theme=dark for missing HttpOnly is noise, not a finding."""
    assert tp.analyze_cookies(["theme=dark; Path=/"], is_https=True) == []


def test_secure_is_not_demanded_on_a_plaintext_origin():
    ids = {i["id"] for i in tp.analyze_cookies(["sid=x; HttpOnly; SameSite=Lax"], is_https=False)}
    assert "cookie_missing_secure" not in ids


def test_samesite_none_is_worse_than_unset():
    a = tp.analyze_cookies(["sid=x; Secure; HttpOnly; SameSite=None"], is_https=True)
    assert a[0]["severity"] == "medium"


def test_parse_set_cookie_shape():
    c = tp.parse_set_cookie("JSESSIONID=abc123; Path=/; Secure; HttpOnly; SameSite=Strict")
    assert c["name"] == "JSESSIONID" and c["secure"] and c["httponly"] and c["samesite"] == "strict"


# ── protective headers ────────────────────────────────────────────────────────
def test_framing_control_satisfied_by_either_mechanism():
    assert not any(i["id"] == "header_missing_framing_control"
                   for i in tp.analyze_security_headers({"X-Frame-Options": "DENY"}, is_https=True))
    assert not any(i["id"] == "header_missing_framing_control"
                   for i in tp.analyze_security_headers(
                       {"Content-Security-Policy": "frame-ancestors 'none'"}, is_https=True))
    assert any(i["id"] == "header_missing_framing_control"
               for i in tp.analyze_security_headers({}, is_https=True))


def test_hsts_is_not_demanded_on_plaintext():
    ids = {i["id"] for i in tp.analyze_security_headers({}, is_https=False)}
    assert "header_missing_strict_transport_security" not in ids
    assert "header_missing_strict_transport_security" in {
        i["id"] for i in tp.analyze_security_headers({}, is_https=True)}


def test_hygiene_headers_are_graded_info_not_inflated():
    iss = {i["id"]: i["severity"] for i in tp.analyze_security_headers({}, is_https=True)}
    assert iss["header_missing_permissions_policy"] == "info"
    assert iss["header_missing_referrer_policy"] == "info"
    assert iss["header_missing_framing_control"] == "medium"


# ── HTTP methods ──────────────────────────────────────────────────────────────
def test_advertised_methods_are_a_lead_never_a_confirmation():
    iss = tp.analyze_methods("GET, POST, PUT, DELETE, OPTIONS")
    assert len(iss) == 1 and iss[0]["confidence"] == "lead"
    assert "NOT tested" in iss[0]["detail"]


def test_trace_confirmed_only_by_the_echoed_marker():
    m = "Apolaki-Trace-deadbeef"
    ok = tp.analyze_methods("", trace_status=200, trace_body="TRACE / HTTP/1.1\n" + m, trace_marker=m)
    assert [i["id"] for i in ok] == ["methods_trace_enabled"] and ok[0]["confidence"] == "confirmed"
    # a 200 that does NOT echo the marker proves nothing
    assert tp.analyze_methods("", trace_status=200, trace_body="hello", trace_marker=m) == []
    assert tp.analyze_methods("", trace_status=405, trace_body=m, trace_marker=m) == []


def test_trace_marker_is_unguessable_and_unique():
    a, b = tp.trace_marker(), tp.trace_marker()
    assert a != b and a.startswith("Apolaki-Trace-") and len(a) > 20


# ── findings ──────────────────────────────────────────────────────────────────
def test_findings_carry_cwe_impact_and_oracle():
    fs = tp.findings_for("https://t", protocols={"TLSv1": True, "TLSv1.2": True, "TLSv1.3": True,
                                                 "SSLv3": False, "TLSv1.1": False},
                         cipher="ECDHE-RSA-RC4-SHA", cert=_cert(issuer="example.com"),
                         hostname="example.com", set_cookies=["sid=x"], headers={}, is_https=True,
                         allow_header="GET, PUT", now=NOW)
    by = {f["cwe"] for f in fs}
    assert "CWE-327" in by and "CWE-295" in by and "CWE-614" in by and "CWE-650" in by
    for f in fs:
        assert f["impact"] and f["oracle"] and f["target"] == "https://t"
        assert f["found_by"] == "transport_posture"


def test_confirmed_posture_findings_satisfy_the_proof_contract():
    import proof_schema
    fs = tp.findings_for("https://t", cert=_cert(not_after="Jun  1 12:00:00 2026 GMT"),
                         hostname="example.com", set_cookies=["sid=x"], is_https=True, now=NOW)
    assert fs
    for f in fs:
        if f["confidence"] == "confirmed":
            ok, missing = proof_schema.validate_confirmed(f)
            assert ok, (f["title"], missing)


def test_a_clean_target_produces_no_findings():
    fs = tp.findings_for("https://t", protocols={"SSLv3": False, "TLSv1": False, "TLSv1.1": False,
                                                 "TLSv1.2": True, "TLSv1.3": True},
                         cipher="TLS_AES_256_GCM_SHA384", cert=_cert(), hostname="example.com",
                         key_bits=2048, set_cookies=["sid=x; Secure; HttpOnly; SameSite=Lax"],
                         headers={"Content-Security-Policy": "frame-ancestors 'none'",
                                  "Strict-Transport-Security": "max-age=63072000",
                                  "X-Content-Type-Options": "nosniff",
                                  "Referrer-Policy": "no-referrer",
                                  "Permissions-Policy": "geolocation=()"},
                         is_https=True, allow_header="GET, POST, OPTIONS", now=NOW)
    assert fs == [], [f["title"] for f in fs]


def test_probe_tls_degrades_cleanly_on_a_dead_host():
    r = tp.probe_tls("127.0.0.1", 1, timeout=1.0)
    assert r["reachable"] is False and r["protocols"] == {} and r["note"]

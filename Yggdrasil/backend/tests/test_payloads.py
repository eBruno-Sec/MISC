"""Tests for core.payloads — the deep-fuzz payload plan and differential detectors."""
from core.payloads import (
    probe_families, evaluate, family_description, boolean_verdict,
    CANARY, SSTI_EXPECT, SQLI_BOOL_PAIRS,
)


def test_probe_plan_covers_all_classes():
    fams = {f for f, _ in probe_families(include_time=True)}
    assert {"sqli_error", "xss", "ssti", "cmdi", "traversal", "crlf",
            "sqli_time", "cmdi_time"} <= fams
    # time probes are droppable
    assert not any(f.endswith("_time") for f, _ in probe_families(include_time=False))


# ── SQLi (error-based), differential ─────────────────────────────
def test_sqli_error_hit_and_differential():
    err = "You have an error in your SQL syntax; check the manual"
    assert evaluate("sqli_error", "'", err, base_text="normal page") is not None
    # already present in baseline -> not attributable to our payload
    assert evaluate("sqli_error", "'", err, base_text=err) is None
    assert evaluate("sqli_error", "'", "totally normal page", base_text="normal") is None


def test_sqli_time_needs_delay_delta():
    assert evaluate("sqli_time", "' OR SLEEP(6)-- -", "", elapsed=6.3, base_elapsed=0.2) is not None
    assert evaluate("sqli_time", "' OR SLEEP(6)-- -", "", elapsed=0.5, base_elapsed=0.2) is None


# ── XSS: verbatim (unencoded) reflection only ────────────────────
def test_xss_unencoded_reflection_hits_encoded_does_not():
    pl = f"<{CANARY}>"
    assert evaluate("xss", pl, f"<div>{pl}</div>") is not None
    assert evaluate("xss", pl, f"<div>&lt;{CANARY}&gt;</div>") is None


# ── SSTI: math evaluated, but literal reflection is NOT SSTI ──────
def test_ssti_evaluated_hit():
    assert evaluate("ssti", "{{41*43}}", f"total {SSTI_EXPECT} items", base_text="total 0 items") is not None


def test_ssti_literal_reflection_is_not_ssti():
    # payload echoed back verbatim (and no product) => template not evaluated
    assert evaluate("ssti", "{{41*43}}", "you typed {{41*43}}") is None


# ── OS command injection ─────────────────────────────────────────
def test_cmdi_id_output_hit():
    out = "uid=0(root) gid=0(root) groups=0(root)"
    assert evaluate("cmdi", ";id", out) is not None
    assert evaluate("cmdi", ";id", "no command ran here") is None


def test_cmdi_time_delta():
    assert evaluate("cmdi_time", ";sleep 6", "", elapsed=6.1, base_elapsed=0.3) is not None


# ── Path traversal ───────────────────────────────────────────────
def test_traversal_passwd_hit_differential():
    passwd = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:"
    assert evaluate("traversal", "../../etc/passwd", passwd, base_text="not found") is not None
    assert evaluate("traversal", "../../etc/passwd", passwd, base_text=passwd) is None


# ── CRLF / response splitting ─────────────────────────────────────
def test_crlf_injected_header_hit():
    hit = evaluate("crlf", f"%0d%0aX-Ygg-Inj:{CANARY}", "body",
                   resp_headers={"X-Ygg-Inj": CANARY})
    assert hit is not None
    assert evaluate("crlf", f"%0d%0aX-Ygg-Inj:{CANARY}", "body", resp_headers={}) is None


def test_every_family_has_a_description():
    for fam in ("sqli_error", "sqli_time", "xss", "ssti", "cmdi", "cmdi_time", "traversal", "crlf"):
        assert family_description(fam)


def test_verdict_carries_severity_and_remediation():
    v = evaluate("cmdi", "$(id)", "uid=33(www-data) gid=33(www-data) groups=33")
    assert v["severity"] == "critical" and v["cvss"] >= 9 and v["remediation"]


# ── sub-types added later: boolean-blind SQLi, LFI wrappers, Windows cmdi ──
def test_probe_plan_includes_lfi_and_windows_blind():
    plan = probe_families(include_time=True)
    assert any(f == "lfi_wrapper" for f, _ in plan)
    assert any(f == "cmdi_time" and "ping -n 6" in p for f, p in plan)  # Windows blind cmdi


def test_bool_pairs_are_true_false_shaped():
    assert SQLI_BOOL_PAIRS and all(len(pair) == 2 for pair in SQLI_BOOL_PAIRS)


def test_boolean_blind_true_matches_false_differs():
    base = "<html>" + "product row " * 300 + "</html>"
    assert boolean_verdict(base, base, "<html>no results</html>") is not None


def test_boolean_blind_no_flag_when_all_identical():
    page = "same content " * 80
    assert boolean_verdict(page, page, page) is None


def test_boolean_blind_no_flag_when_true_also_differs():
    base = "aaaa " * 200
    other = "bbbb " * 200
    assert boolean_verdict(base, other, other) is None   # TRUE not ~ baseline


def test_lfi_wrapper_detects_php_source_leak_differential():
    leak = "PD9waHAgZWNobyAiaGkiOw=="   # base64 of '<?php echo "hi";'
    pl = "php://filter/convert.base64-encode/resource=index"
    assert evaluate("lfi_wrapper", pl, leak) is not None
    assert evaluate("lfi_wrapper", pl, "just a normal page") is None
    assert evaluate("lfi_wrapper", pl, leak, base_text=leak) is None   # already in baseline


def test_xss_attribute_handler_context_detected():
    pl = f"\" autofocus onfocus={CANARY} x=\""
    assert evaluate("xss", pl, f"<input value=\"{pl}\">") is not None


# ── UNION-based SQLi: marker returned as a row, not raw reflection ──
def test_union_marker_returned_as_row_hits():
    from core.payloads import UNION_MARKER
    pl = f"' UNION SELECT '{UNION_MARKER}'-- -"
    # DB echoes only the SELECTed marker value (payload itself not reflected) -> UNION SQLi
    assert evaluate("sqli_union", pl, f"<td>{UNION_MARKER}</td>", base_text="<td>ygg1</td>") is not None


def test_union_raw_reflection_is_not_union():
    from core.payloads import UNION_MARKER
    pl = f"' UNION SELECT '{UNION_MARKER}'-- -"
    # whole payload reflected verbatim => reflection, not data extraction
    assert evaluate("sqli_union", pl, f"you searched for {pl}") is None


def test_union_in_probe_plan():
    assert any(f == "sqli_union" for f, _ in probe_families(include_time=False))

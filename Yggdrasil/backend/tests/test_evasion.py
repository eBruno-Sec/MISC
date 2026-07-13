"""Tests for core.evasion (WAF-evasion payloads + block detection) and the
hardened LLM JSON extractor used by MIMIR triage."""
from core.evasion import (
    BROWSER_USER_AGENT, SQLMAP_TAMPER, SQLMAP_TAMPER_AGGRESSIVE,
    payload_variants, expand_payloads, looks_waf_blocked,
)
from agents.athena import _extract_json


# ── payload variants ─────────────────────────────────────────────
def test_variants_always_include_original_first():
    assert payload_variants("' OR 1=1-- -", "sql")[0] == "' OR 1=1-- -"
    assert payload_variants("<olymxss7z>", "xss")[0] == "<olymxss7z>"


def test_variants_respect_max_and_dedupe():
    v = payload_variants("' OR 1=1-- -", "sql", max_variants=4)
    assert len(v) <= 4
    assert len(v) == len(set(v))  # no dupes


def test_sql_variants_obfuscate_spaces_and_case():
    v = payload_variants("' OR 1=1-- -", "sql", max_variants=6)
    assert any("/**/" in x for x in v)              # space2comment style
    assert any(x != "' OR 1=1-- -" and x.lower() == "' or 1=1-- -" for x in v)  # case-swap


def test_xss_variants_encode_angle_brackets():
    v = payload_variants("<olymxss7z>", "xss", max_variants=6)
    assert any("%3C" in x and "%3E" in x for x in v)


def test_traversal_variants_encode_slashes():
    v = payload_variants("../../etc/passwd", "traversal", max_variants=6)
    assert any("..%2f" in x for x in v)


def test_expand_payloads_dedupes_and_preserves_order():
    out = expand_payloads(["'", "'"], "sql", max_variants=2)
    assert out[0] == "'"
    assert len(out) == len(set(out))


# ── WAF/block detection ──────────────────────────────────────────
def test_block_statuses_flagged():
    for code in (403, 406, 429, 503):
        assert looks_waf_blocked(code, {}, "anything") is True


def test_clean_200_not_flagged():
    assert looks_waf_blocked(200, {"server": "nginx"}, "<html>welcome</html>") is False


def test_cloudflare_fronted_200_is_not_a_block():
    # Being behind a CDN is not the same as being blocked by it.
    assert looks_waf_blocked(200, {"server": "cloudflare", "cf-ray": "abc"}, "normal page") is False


def test_block_body_signature_flagged_even_on_200():
    assert looks_waf_blocked(200, {}, "Request blocked by ModSecurity") is True


def test_looks_waf_blocked_tolerates_bad_status():
    assert looks_waf_blocked(None, {}, "") is False


# ── constants ────────────────────────────────────────────────────
def test_browser_ua_looks_like_a_browser():
    assert "Mozilla/5.0" in BROWSER_USER_AGENT and "sqlmap" not in BROWSER_USER_AGENT.lower()


def test_tamper_chains_are_comma_lists():
    assert "space2comment" in SQLMAP_TAMPER
    assert "charencode" in SQLMAP_TAMPER_AGGRESSIVE
    # structural rewrite comes before encoder in the aggressive chain
    parts = SQLMAP_TAMPER_AGGRESSIVE.split(",")
    assert parts.index("space2comment") < parts.index("charencode")


# ── MIMIR JSON extractor robustness ──────────────────────────────
def test_extract_plain_and_fenced():
    assert _extract_json('{"a": 1}') == {"a": 1}
    assert _extract_json('```json\n{"a": 1}\n```') == {"a": 1}


def test_extract_from_surrounding_prose():
    assert _extract_json('Sure! Here you go: {"a": 1, "b": 2} — done.') == {"a": 1, "b": 2}


def test_extract_tolerates_trailing_comma():
    assert _extract_json('{"a": 1, "b": [1, 2,],}') == {"a": 1, "b": [1, 2]}


def test_extract_tolerates_raw_newline_in_string():
    # LLMs often emit a literal newline inside a "narrative" value.
    assert _extract_json('{"a": "line1\nline2"}') == {"a": "line1\nline2"}


def test_extract_salvages_truncated_object():
    # Cut off by a token cap mid-array — should close the open structures.
    out = _extract_json('{"a": 1, "b": [10, 20')
    assert out["a"] == 1 and out["b"] == [10, 20]

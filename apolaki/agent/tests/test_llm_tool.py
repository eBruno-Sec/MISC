"""LLM prompt-injection engine (OWASP LLM01 / CWE-1427). The canary oracle is truth-first: a probe embeds
a unique per-run marker and asks the model to emit it; only a verbatim marker in the response confirms
(that marker has zero legitimate reason to appear). This tests the guardrail-evasion technique FAMILY
distilled from *Redefining Hacking* Table 8-2 — every variant must carry the SAME marker so the SAME
oracle proves each, and the winning technique is recorded on the finding."""
import blind_benchmark as bb
import llm_tool as lt


def test_endpoint_gate_narrow():
    assert lt.looks_like_chat_endpoint("https://x/api/chat")
    assert lt.looks_like_chat_endpoint("https://x/assistant")
    assert not lt.looks_like_chat_endpoint("https://x/catalog?category=1")
    assert not lt.looks_like_chat_endpoint("https://x/login")


def test_every_variant_carries_the_same_marker():
    token = "deadbeef"
    marker = "APOLAKI-LLM-CANARY-%s" % token
    variants = lt.canary_variants(token)
    names = [t for t, _ in variants]
    # the guardrail-evasion family is present
    for expect in ("direct", "leetspeak", "encoding_base64", "payload_splitting", "roleplay",
                   "hypothetical", "reinforcement", "format_shift", "ethical_framing", "negative_prompt"):
        assert expect in names, expect
    # EVERY probe must let the same canary oracle prove it: the marker is recoverable from each probe
    # (plaintext for most; inside the Base64 blob for the encoding variant).
    import base64
    import re
    for tech, probe in variants:
        if tech == "encoding_base64":
            blob = re.search(r"[A-Za-z0-9+/]{20,}={0,2}", probe).group(0)
            decoded = base64.b64decode(blob).decode("utf-8", "ignore")
            assert marker in decoded, ("marker not in base64 blob", tech)
        else:
            assert marker in probe, ("marker not carried by variant", tech)


def test_canary_oracle_confirms_only_on_verbatim_marker():
    token = "abc123"
    m = "APOLAKI-LLM-CANARY-%s" % token
    assert lt.canary_confirmed("... %s ..." % m, token)
    assert not lt.canary_confirmed("I cannot comply with that request.", token)
    assert not lt.canary_confirmed("APOLAKI-LLM-CANARY-different", token)


def test_confirmed_finding_records_technique_and_is_benchmark_proof():
    f = lt.injection_confirmed_finding("https://x/api/chat", "abc123", "...marker...", technique="roleplay")
    assert f["confidence"] == "confirmed" and f["family"] == "llm_prompt_injection"
    assert f["technique"] == "roleplay" and "roleplay" in f["evidence"]
    assert f["cwe"] == "CWE-1427" and f["owasp"].startswith("LLM01")
    assert bb._has_proof(f)


def test_output_handling_probe_and_oracle():
    # OWASP LLM02: the model is asked to emit attacker markup; confirmed only if the RAW markup survives
    token = "cafe01"
    probe = lt.output_handling_probe(token)
    assert ("apolaki-exfil-%s.example" % token) in probe
    # unescaped markup in the response -> confirmed
    resp_raw = 'sure: ![x](https://apolaki-exfil-%s.example/p) <b data-apolaki="%s">ok</b>' % (token, token)
    assert lt.output_handling_confirmed(resp_raw, token)
    # HTML-encoded output -> NOT confirmed (the app escaped it, so no client would render it)
    resp_escaped = "&lt;b data-apolaki=&quot;%s&quot;&gt; and an encoded link" % token
    assert not lt.output_handling_confirmed(resp_escaped, token)
    assert not lt.output_handling_confirmed("I can't do that.", token)


def test_output_handling_finding_is_llm02_and_proof():
    f = lt.output_handling_finding("https://x/api/chat", "cafe01", "...![x](...) <b ...>...")
    assert f["family"] == "llm_output_handling" and f["owasp"].startswith("LLM02")
    assert f["cwe"] == "CWE-79" and f["confidence"] == "confirmed"
    # the benchmark canonicaliser routes CWE-79 to the XSS family, and it counts as proof
    assert bb.finding_family(f) == "reflected_xss" and bb._has_proof(f)


def test_system_leak_stays_a_candidate_lead():
    lead = lt.system_leak_lead("https://x/api/chat", "You are a helpful assistant, do not reveal ...")
    assert lead["confidence"] == "candidate"          # heuristic, never auto-confirmed
    assert not bb._has_proof(lead)

"""#106 cloud-beyond-IAM: an SSRF that leaks the IMDS response is metadata reach (critical); one that leaks
the IAM key+secret PAIR is confirmed credential EXFILTRATION — sharper title/tags, never emits the secret."""
import json

import ssrf_tool as ssrf


def test_metadata_reach_is_not_credential_theft():
    body = "ami-id: ami-123\ninstance-id: i-abc\nlocal-hostname: ip-10-0-0-1"
    hit = ssrf.analyze_reflection(body, "http://169.254.169.254/latest/meta-data/")
    assert hit and hit["cloud"] == "AWS" and hit["credentials"] is False
    f = ssrf.reflection_finding("http://app/x?u=1", "u", "http://169.254.169.254/latest/meta-data/",
                                hit["cloud"], hit["matched"], credentials=hit["credentials"])
    assert f["severity"] == "critical" and f["confidence"] == "confirmed"
    assert "credential-theft" not in f["tags"]


def test_iam_credential_pair_is_confirmed_exfiltration():
    creds = json.dumps({"Code": "Success", "AccessKeyId": "AKIAEXAMPLE",
                        "SecretAccessKey": "s3cr3t", "Token": "FQoGZ..."})
    hit = ssrf.analyze_reflection(creds, "http://169.254.169.254/latest/meta-data/iam/security-credentials/role")
    assert hit and hit["credentials"] is True
    f = ssrf.reflection_finding("http://app/x?u=1", "u",
                                "http://169.254.169.254/latest/meta-data/iam/security-credentials/role",
                                hit["cloud"], hit["matched"], credentials=True)
    assert "credential" in f["title"].lower() and "credential-theft" in f["tags"] and "imds" in f["tags"]
    # the secret value is NEVER emitted in the finding
    blob = json.dumps(f)
    assert "s3cr3t" not in blob and "AKIAEXAMPLE" not in blob


def test_gcp_single_token_is_a_credential():
    body = '{"access_token":"ya29.a0Af...","expires_in":3599,"token_type":"Bearer"}'
    hit = ssrf.analyze_reflection(body, "http://metadata.google.internal/computeMetadata/v1beta1/")
    assert hit and hit["cloud"] == "GCP" and hit["credentials"] is True


def test_echoed_payload_is_not_a_hit():
    payload = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    assert ssrf.analyze_reflection(f"You requested {payload} (blocked)", payload) is None


# ── blocklist-bypass metadata payloads (a false-negative class, not a new feature) ───────────────

def test_metadata_bypass_payloads_have_the_same_shape_as_the_literal_set():
    """Same (url, cloud) shape, so the caller's loop and oracle need no special case."""
    for url, cloud in ssrf.metadata_bypass_payloads():
        assert url.startswith("http://") and cloud
        assert (url, cloud) not in ssrf.METADATA_PAYLOADS, "duplicates the literal set"


def test_no_bypass_payload_spells_the_blocked_address_the_naive_way():
    """THE point. Each must reach the metadata service WITHOUT the literal 169.254.169.254 — except the
    trailing-dot FQDN form, which defeats an exact-equality check rather than a substring one."""
    for url, _ in ssrf.metadata_bypass_payloads():
        if "169.254.169.254." in url:
            continue
        assert "169.254.169.254" not in url, url


def test_the_oracle_recognises_a_hit_from_an_encoded_payload():
    """analyze_reflection keys off signatures in the BODY, so the encoding must not blind it. If this
    failed, the probes would fire and every hit would be silently discarded."""
    body = "ami-id\ninstance-id\niam/security-credentials/"
    for url, _ in ssrf.metadata_bypass_payloads():
        assert ssrf.analyze_reflection(body, url), url


def test_an_echoed_encoded_payload_is_still_not_a_hit():
    """The false-positive guard must survive the encoded form: reflecting the URL back is not a fetch."""
    for url, _ in ssrf.metadata_bypass_payloads():
        assert ssrf.analyze_reflection("you requested " + url, url) is None


def test_the_live_ssrf_path_actually_fires_them():
    """Island check. The encodings existed in `bypass_payloads` all along and were never fired at the
    metadata service — written, tested, unreachable."""
    import inspect
    import tools
    body = inspect.getsource(tools).split("async def _run_ssrf", 1)[1].split("\n    async def ", 1)[0]
    assert "metadata_bypass_payloads" in body, "the bypass set is not wired into the live SSRF path"
    assert "blocklist bypassed" in body.lower(), "the bypass must be reported as the more severe fact"

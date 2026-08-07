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

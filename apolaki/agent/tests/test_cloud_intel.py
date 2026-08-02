"""Cloud provider + storage fingerprinting (pure) + feeding the asset graph (CHAD review #8)."""
from __future__ import annotations

import asset_graph as AG
import cloud_intel as CI


def test_fingerprint_from_headers():
    assert CI.fingerprint_provider({"X-Amz-Cf-Id": "abc", "Server": "AmazonS3"}) == "aws"
    assert CI.fingerprint_provider({"CF-Ray": "x", "Server": "cloudflare"}) == "cloudflare"
    assert CI.fingerprint_provider({"x-ms-request-id": "y"}) == "azure"
    assert CI.fingerprint_provider({"X-Goog-Generation": "1"}) == "gcp"
    assert CI.fingerprint_provider({"Server": "nginx"}) == "unknown"


def test_fingerprint_from_cname():
    assert CI.fingerprint_provider({}, cname="d123.cloudfront.net") == "aws"
    assert CI.fingerprint_provider({}, cname="app.azurewebsites.net") == "azure"
    assert CI.fingerprint_provider({}, ip_org="Google LLC") == "gcp"


def test_storage_bucket_detection():
    assert CI.storage_bucket("https://backups.s3.amazonaws.com/db.sql") == "backups.s3.amazonaws.com"
    assert CI.storage_bucket("https://acct.blob.core.windows.net/x") == "acct.blob.core.windows.net"
    assert CI.storage_bucket("https://example.com/normal") is None


def test_analyze_and_graph_facts():
    v = CI.analyze(url="https://data.s3.amazonaws.com/x", headers={"X-Amz-Request-Id": "1"})
    assert v["is_cloud"] and v["provider"] == "aws" and v["storage_bucket"] == "data.s3.amazonaws.com"
    g = AG.AssetGraph("m")
    CI.to_graph_facts(g, "app.example.com", v)
    assert g.node("cloud_account:aws") is not None
    assert "cloud_account:aws" in g.neighbors("host:app.example.com", rel="belongs_to")
    # the public bucket is recorded as an object that could unlock file read
    obj = g.nodes("object")
    assert obj and "arbitrary_file_read" in obj[0]["enables"]


def test_non_cloud_is_noop_on_graph():
    g = AG.AssetGraph("m")
    CI.to_graph_facts(g, "host", CI.analyze(headers={"Server": "nginx"}))
    assert g.stats()["nodes"] == 0


def test_cloud_fingerprint_runs_during_harvest():
    # cloud_intel is actually WIRED: a harvested response with cloud headers records a cloud asset
    # into the registry's live graph (not just a standalone module).
    import scope
    import tools
    sc = scope.ScopeEngine()
    sc.load_manual(["app.example"], [], "T")
    reg = tools.ToolRegistry(sc, lab_mode=True)

    class _R:
        headers = {"CF-Ray": "abc123", "Server": "cloudflare"}
        text = "ok"

    reg._harvest_response("https://app.example/page", _R())
    assert reg.graph.node("cloud_account:cloudflare") is not None
    assert "cloud_account:cloudflare" in reg.graph.neighbors("host:app.example", rel="belongs_to")

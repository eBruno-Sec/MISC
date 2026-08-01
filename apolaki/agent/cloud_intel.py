"""
Cloud provider + storage fingerprinting (deterministic) — the first slice of the cloud engine.

Identifies AWS / Azure / GCP / Cloudflare / Fastly from response headers, CNAMEs, and IP-org hints,
and recognizes public object-storage URLs (S3 / Azure Blob / GCS / R2), so cloud assets enter the
SAME canonical asset graph with provenance. Pure: no cloud API calls, no credentials — the actual
authorized cloud tests are routed from these facts later. This makes cloud a first-class recon
signal instead of a report decoration (CHAD review #8, foundation).
"""
from __future__ import annotations

import re

# response-header substrings that identify a provider (checked case-insensitively as "k: v")
_HEADER_SIGNS = [
    ("aws", ("x-amz-", "x-amzn-", "server: amazons3", "x-amz-request-id", "x-amz-cf-id")),
    ("cloudflare", ("cf-ray", "cf-cache-status", "server: cloudflare")),
    ("azure", ("x-azure-", "x-ms-request-id", "x-msedge-ref", "server: microsoft-azure")),
    ("gcp", ("x-goog-", "server: gse", "via: 1.1 google", "x-cloud-trace-context")),
    ("fastly", ("x-served-by", "x-fastly-request-id")),
]

# CNAME / IP-org substrings that identify a provider
_CNAME_SIGNS = [
    ("aws", ("amazonaws.com", "cloudfront.net", "elasticbeanstalk.com", "awsglobalaccelerator.com", "amazon")),
    ("azure", ("azurewebsites.net", "azureedge.net", "blob.core.windows.net", "cloudapp.azure.com",
               "trafficmanager.net", "microsoft")),
    ("gcp", ("googleusercontent.com", "appspot.com", "storage.googleapis.com", "run.app", "google")),
    ("cloudflare", ("cloudflare.net", "cdn.cloudflare.net", "cloudflare")),
]

# public object-storage URL shapes
_STORAGE_RX = re.compile(
    r"(?:https?://)?("
    r"[a-z0-9.-]+\.s3[.-][a-z0-9-]*\.amazonaws\.com"      # bucket.s3-region.amazonaws.com
    r"|[a-z0-9.-]+\.s3\.amazonaws\.com"                    # bucket.s3.amazonaws.com
    r"|s3[.-][a-z0-9-]*\.amazonaws\.com/[a-z0-9._-]+"      # s3.amazonaws.com/bucket
    r"|[a-z0-9-]+\.blob\.core\.windows\.net"               # account.blob.core.windows.net
    r"|storage\.googleapis\.com/[a-z0-9._-]+"              # GCS
    r"|[a-z0-9.-]+\.r2\.cloudflarestorage\.com"            # Cloudflare R2
    r")", re.I)

_PROVIDERS = {"aws", "azure", "gcp", "cloudflare", "fastly"}


def fingerprint_provider(headers: dict = None, cname: str = "", ip_org: str = "") -> str:
    """Best cloud-provider guess from headers (strongest), then CNAME / IP-org. 'unknown' if none."""
    blob = " ".join("%s: %s" % (str(k).lower(), str(v).lower()) for k, v in (headers or {}).items())
    for prov, signs in _HEADER_SIGNS:
        if any(s in blob for s in signs):
            return prov
    low = (cname or "").lower() + " " + (ip_org or "").lower()
    for prov, signs in _CNAME_SIGNS:
        if any(s in low for s in signs):
            return prov
    return "unknown"


def storage_bucket(url: str) -> str:
    """Return the public object-storage host/path if the URL is one (S3/Blob/GCS/R2), else None."""
    m = _STORAGE_RX.search(url or "")
    return m.group(1) if m else None


def analyze(url: str = "", headers: dict = None, cname: str = "", ip_org: str = "") -> dict:
    """One deterministic cloud verdict for a host: {provider, is_cloud, storage_bucket, signals}."""
    provider = fingerprint_provider(headers, cname, ip_org)
    bucket = storage_bucket(url) or storage_bucket(cname)
    return {"provider": provider, "is_cloud": provider in _PROVIDERS or bool(bucket),
            "storage_bucket": bucket,
            "signals": [s for s in ("headers" if headers else "", "cname" if cname else "") if s]}


def to_graph_facts(graph, host: str, verdict: dict, source: str = "cloud_intel") -> None:
    """Record a cloud verdict into the canonical asset graph: a cloud_account node (provider) linked
    to the host, and a public storage bucket node when found (flagged as exposure to investigate)."""
    try:
        if not host or not (verdict or {}).get("is_cloud"):
            return
        prov = verdict.get("provider") or "unknown"
        hid = graph.observe("host", host, source=source)
        cid = graph.observe("cloud_account", prov, label=prov, source=source, provider=prov)
        graph.link(hid, cid, "belongs_to", source=source)
        if verdict.get("storage_bucket"):
            bid = graph.observe("object", verdict["storage_bucket"], label="cloud-storage",
                                source=source, enables=["arbitrary_file_read"])
            graph.link(cid, bid, "exposes", source=source)
    except Exception:
        pass

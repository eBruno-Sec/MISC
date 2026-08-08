"""Deterministic external-recon primitives (#114): favicon hashing + subdomain permutation/recursion.

Pure + offline: these GENERATE candidates and pivot queries; they do NOT resolve, probe, or call any
external service (that stays gated behind the intel-source allowlist). A permuted subdomain is an
UNVERIFIED candidate until a live check proves it; a favicon hash is a pivot key an operator can feed to
a (gated, key-authorized) Shodan/Censys query. No network here.
"""
from __future__ import annotations

import base64

# ── favicon hash (Shodan/Censys pivot key) ──
def _mmh3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86 32-bit, returned SIGNED (the form Shodan's http.favicon.hash uses). Pure."""
    c1, c2 = 0xcc9e2d51, 0x1b873593
    length = len(data)
    h1 = seed & 0xffffffff
    rounded = length & ~3
    for i in range(0, rounded, 4):
        k1 = data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24)
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xffffffff
        h1 = (h1 * 5 + 0xe6546b64) & 0xffffffff
    k1 = 0
    tail = length & 3
    if tail >= 3:
        k1 ^= data[rounded + 2] << 16
    if tail >= 2:
        k1 ^= data[rounded + 1] << 8
    if tail >= 1:
        k1 ^= data[rounded]
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85ebca6b) & 0xffffffff
    h1 ^= h1 >> 13
    h1 = (h1 * 0xc2b2ae35) & 0xffffffff
    h1 ^= h1 >> 16
    return h1 - 0x100000000 if h1 & 0x80000000 else h1


def favicon_hash(favicon_bytes: bytes) -> int:
    """The Shodan-style favicon hash: mmh3 over base64.encodebytes(favicon). Uses the mmh3 library when
    present (authoritative); the pure _mmh3_32 fallback is proven byte-identical to it. Deterministic."""
    b = base64.encodebytes(favicon_bytes or b"")
    try:
        import mmh3
        return mmh3.hash(b)
    except ImportError:
        return _mmh3_32(b)


def favicon_pivot_queries(h: int) -> dict:
    """Pivot QUERIES (strings) to find same-favicon hosts — run only via the gated, key-authorized
    Tier-2 adapters. Returning the query is offline + safe; executing it is not done here."""
    return {"shodan": "http.favicon.hash:%d" % h, "censys": "services.http.response.favicons.md5_hash"}


# ── subdomain permutation / recursion ──
_DEFAULT_WORDS = ("www", "api", "dev", "staging", "stage", "test", "qa", "uat", "admin", "internal",
                  "portal", "app", "beta", "vpn", "mail", "git", "ci", "jenkins", "grafana", "kibana",
                  "prod", "preprod", "sandbox", "demo", "auth", "sso", "gateway", "edge", "cdn")


def _root(domain: str) -> str:
    h = (domain or "").strip().lower().strip(".")
    return h.split("/")[0]


def permute(domain: str, words=None, *, max_out: int = 300) -> list:
    """Deterministic candidate subdomains for a root domain: word.root, root-word patterns, and a
    single recursion over the domain's own leftmost label. Returns sorted unique candidates (UNVERIFIED
    — never resolved here). Pure."""
    root = _root(domain)
    if not root or "." not in root:
        return []
    parts = root.split(".")
    base = ".".join(parts[-2:]) if len(parts) >= 2 else root
    lead = parts[0] if len(parts) > 2 else ""
    words = list(dict.fromkeys(list(words or ()) + list(_DEFAULT_WORDS)))
    out = set()
    for w in words:
        out.add("%s.%s" % (w, base))
        if lead:
            out.add("%s-%s.%s" % (lead, w, base))       # recursion over the existing label
            out.add("%s.%s.%s" % (w, lead, base))
    out.discard(base)
    return sorted(out)[:max_out]


# ── certificate-transparency harvest ──
def parse_ct_names(rows, root: str) -> list:
    """crt.sh JSON -> candidate subdomains of `root`. Pure: no network, no resolution.

    A CT entry proves a certificate was ISSUED for a name, which is not proof the name resolves, is live,
    or is in scope — every result is a CANDIDATE. Wildcards are unfolded to the bare root rather than
    emitted as '*.x', and anything outside the authorized root is dropped even if the certificate
    mentioned it (a shared cert routinely names other people's domains)."""
    r = _root(root)
    out = set()
    for row in (rows or []):
        blob = ""
        if isinstance(row, dict):
            blob = "%s\n%s" % (row.get("name_value") or "", row.get("common_name") or "")
        else:
            blob = str(row)
        for name in blob.replace(",", "\n").split("\n"):
            n = name.strip().lower().strip(".")
            if not n:
                continue
            if n.startswith("*."):
                n = n[2:]
            if not n or " " in n or "@" in n:
                continue
            if r and (n == r or n.endswith("." + r)):     # authorized root only
                out.add(n)
    return sorted(out)


def ct_query_url(root: str) -> str:
    """The crt.sh query for a root domain. Returned as a STRING — executing it is the caller's job and
    stays behind the gated intel-source allowlist (ct_logs / CT_LOGS_ENABLED)."""
    r = _root(root)
    return "https://crt.sh/?q=%%25.%s&output=json" % r if r else ""


def seed_candidates(graph, domain: str, subs, *, scope_asset: str = "") -> int:
    """Seed permuted subdomains into the engagement graph as UNVERIFIED candidates (never resolved/probed
    here). They earn a real host node only after a live reachability check. Returns count seeded."""
    n0 = graph.stats()["nodes"]
    for s in subs or []:
        graph.observe("subdomain", str(s), label=str(s), source="permutation", confidence=0.2,
                      scope_asset=scope_asset, reachable="unverified", provenance_kind="generated")
    return graph.stats()["nodes"] - n0

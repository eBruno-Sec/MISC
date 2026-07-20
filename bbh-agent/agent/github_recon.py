"""
GitHub reconnaissance — leaked-secret hunting on PUBLIC GitHub.

From Bug Bounty Bootcamp (Li, Ch 5, "GitHub Recon"). Passive against the target:
it queries github.com's code-search API (never the target) for the org's domain,
name, and employee terms combined with secret dorks, then scans the returned code
fragments for hardcoded credentials with the same detector used by run_js_review
(codereview.scan_secrets), so matches are consistent across the platform.

Authentication is the OPERATOR's own read-only Personal Access Token
(BBH_GITHUB_TOKEN), used only to lift GitHub's rate limit — not the target's. No
scopes are required (public read). Secret samples are redacted in our output.

The dork builder, response parser, and hit classifier are pure/deterministic and
unit-tested; tools._run_github_recon does the authenticated fetch + pacing.
"""
from __future__ import annotations

_SEV_RANK = {"info": 0, "informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def build_dorks(domain: str, org: str = "", extra: list = None) -> list:
    """GitHub code-search queries pairing the target with secret indicators."""
    domain = (domain or "").lstrip("*.").strip()
    org = (org or domain.split(".")[0]).strip()
    dorks = [
        f'"{domain}" password', f'"{domain}" api_key', f'"{domain}" secret',
        f'"{domain}" aws_access_key_id', f'"{domain}" filename:.env',
        f'"{domain}" filename:.git-credentials', f'"{domain}" extension:sql',
        f'"{domain}" BEGIN RSA PRIVATE KEY', f'"{domain}" authorization bearer',
        f'"{domain}" jdbc:', f'"{domain}" filename:.npmrc _auth',
    ]
    if org and org.lower() != domain.lower():
        dorks += [f'org:{org} password', f'"{org}" filename:.env']
    for t in (extra or []):
        dorks.append(f'"{domain}" {t}')
    return list(dict.fromkeys(dorks))


# dork qualifiers that mark a hit as a sensitive file even without a secret match
_SENSITIVE_Q = ("filename:.env", "filename:.git", "extension:sql", "private key",
                "filename:config", "filename:.npmrc", "jdbc:", "aws_access_key_id")


def parse_code_search(data: dict) -> list:
    """Turn a GitHub /search/code response into items with text-match fragments."""
    out = []
    for it in (data or {}).get("items", []):
        frags = [tm["fragment"] for tm in (it.get("text_matches") or []) if tm.get("fragment")]
        out.append({
            "repo": (it.get("repository") or {}).get("full_name", "") or "",
            "path": it.get("path", "") or "",
            "url": it.get("html_url", "") or "",
            "fragments": frags,
        })
    return out


def classify_hit(item: dict, domain: str, query: str) -> dict | None:
    """A finding when a fragment carries a secret, or the hit is in a sensitive
    file; otherwise None (a bare domain mention is not a finding)."""
    import codereview as cr
    secrets = []
    for frag in item.get("fragments", []):
        secrets += cr.scan_secrets(frag)
    if secrets:
        return secret_finding(item, domain, secrets)
    if any(q in (query or "").lower() for q in _SENSITIVE_Q):
        return lead_finding(item, domain, query)
    return None


def secret_finding(item: dict, domain: str, secrets: list) -> dict:
    worst = max(secrets, key=lambda s: _SEV_RANK.get(s["severity"], 0))
    kinds = ", ".join(sorted({s["type"] for s in secrets}))
    where = f"{item['repo']}/{item['path']}".strip("/")
    return {
        "title": f"Leaked secret on public GitHub ({worst['type']})",
        "severity": worst["severity"], "target": item.get("url") or f"github:{where}",
        "description": (f"A public GitHub file referencing {domain} appears to contain a secret ({kinds}) in "
                        f"{where}. Redacted sample: {worst['match']}."),
        "impact": "Exposed credentials/keys granting access to the org's systems, cloud, or third-party services.",
        "reproduction_steps": [f"Open {item.get('url') or where}",
                               f"Locate the {worst['type']} ({worst['match']})",
                               "Verify the secret is active and belongs to the target before reporting; do not use it without authorization"],
        "evidence": f"{where} — {kinds}: {worst['match']}", "cwe": "CWE-540",
        "family": "info_disclosure", "tags": ["github-recon", "secret-leak"], "confidence": "candidate",
    }


def lead_finding(item: dict, domain: str, query: str) -> dict:
    where = f"{item['repo']}/{item['path']}".strip("/")
    return {
        "title": f"Sensitive file referencing {domain} on public GitHub",
        "severity": "low", "target": item.get("url") or f"github:{where}",
        "description": (f"A sensitive file ({item['path']}) in the public repo {item['repo']} references {domain} "
                        f"(dork: {query}). Review it for hardcoded config, internal hostnames, or credentials."),
        "impact": "Potential disclosure of internal configuration, endpoints, or credentials.",
        "reproduction_steps": [f"Open {item.get('url') or where}", "Review the file for secrets / internal detail"],
        "evidence": f"{where} (dork: {query})", "cwe": "CWE-200",
        "family": "info_disclosure", "tags": ["github-recon"], "confidence": "candidate",
    }

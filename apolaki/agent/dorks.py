"""
Passive Google-dork (search-operator) query generation.

100% offline and PASSIVE: this module only *builds* operator-ready search queries a
human can paste into a search engine. It NEVER contacts a search engine or scrapes
results — automated scraping would violate most engines' terms, so the deliverable is
the query text, not the results. Deterministic, no AI, no network.

Queries are grouped by intent (exposure, files, secrets, subdomains, tech, code) so the
operator can pick what fits the engagement. The target is only ever placed inside a
`site:` operator, so a generated query is always scoped to the authorized domain.
"""
from __future__ import annotations

import re

# label -> list of (title, query-template). {t} is replaced by the bare target host.
_DORKS = {
    "Exposed files & directories": [
        ("Directory listing", 'site:{t} intitle:"index of"'),
        ("Config / env files", 'site:{t} ext:env | ext:ini | ext:conf | ext:cfg | ext:yaml | ext:yml'),
        ("Backup & archive files", 'site:{t} ext:bak | ext:old | ext:backup | ext:zip | ext:tar | ext:sql | ext:gz'),
        ("Log files", 'site:{t} ext:log'),
        ("Database dumps", 'site:{t} ext:sql | ext:dbf | ext:mdb'),
        ("Office / PDF documents", 'site:{t} ext:pdf | ext:doc | ext:docx | ext:xls | ext:xlsx | ext:csv'),
    ],
    "Secrets & credentials": [
        ("Password / secret keywords", 'site:{t} intext:"password" | intext:"passwd" | intext:"api_key" | intext:"secret"'),
        ("API keys & tokens in text", 'site:{t} intext:"BEGIN RSA PRIVATE KEY" | intext:"aws_access_key_id"'),
        ("Exposed .git", 'site:{t} inurl:".git"'),
        ("Environment / credentials files", 'site:{t} (inurl:".env" | inurl:"credentials" | inurl:"config")'),
    ],
    "Login & admin surfaces": [
        ("Login pages", 'site:{t} (inurl:login | inurl:signin | inurl:admin | intitle:"login")'),
        ("Admin panels", 'site:{t} (inurl:admin | inurl:administrator | inurl:cpanel | inurl:dashboard)'),
        ("Password reset flows", 'site:{t} (inurl:reset | inurl:forgot | inurl:recover)'),
    ],
    "Application surface": [
        ("API endpoints", 'site:{t} (inurl:api | inurl:rest | inurl:graphql | inurl:v1 | inurl:v2)'),
        ("Parameters worth testing", 'site:{t} (inurl:id= | inurl:redirect= | inurl:url= | inurl:file= | inurl:page=)'),
        ("OpenAPI / Swagger docs", 'site:{t} (inurl:swagger | inurl:openapi | inurl:api-docs | filetype:json inurl:swagger)'),
        ("Upload endpoints", 'site:{t} (inurl:upload | inurl:file | intitle:"upload")'),
    ],
    "Errors & disclosure": [
        ("Verbose errors / stack traces", 'site:{t} (intext:"stack trace" | intext:"SQL syntax" | intext:"Fatal error" | intext:"Warning:")'),
        ("phpinfo / debug pages", 'site:{t} (intitle:"phpinfo()" | inurl:phpinfo | inurl:debug)'),
    ],
    "Broader recon (subdomains, code, cache)": [
        ("Subdomains (exclude www)", 'site:*.{t} -site:www.{t}'),
        ("Source code leaks (GitHub)", 'site:github.com "{t}"'),
        ("Pastebin leaks", 'site:pastebin.com "{t}"'),
        ("Cached / archived", 'site:web.archive.org "{t}"'),
    ],
}

_HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$")


def _clean_host(target: str) -> str:
    """Reduce a URL/host/scope entry to a bare registrable host for `site:`."""
    t = re.sub(r"^\w+://", "", (target or "").strip()).split("/")[0]
    t = t.split(":")[0].lstrip("*.").lower()
    return t


def generate(target: str) -> dict:
    """Return {'target', 'groups': [{'label', 'queries': [{'title','query'}]}], 'flat': [...]}.
    Only builds text; performs no network I/O. Non-host input yields an empty result."""
    host = _clean_host(target)
    if not host or not _HOST_RE.match(host):
        return {"target": host, "groups": [], "flat": []}
    groups, flat = [], []
    for label, items in _DORKS.items():
        qs = []
        for title, tmpl in items:
            q = tmpl.format(t=host)
            qs.append({"title": title, "query": q})
            flat.append(q)
        groups.append({"label": label, "queries": qs})
    return {"target": host, "groups": groups, "flat": flat}


def as_markdown(target: str) -> str:
    """Operator-ready markdown block of dork queries for the report / notes."""
    d = generate(target)
    if not d["groups"]:
        return ""
    out = [f"### Passive search-operator queries for `{d['target']}`", "",
           "_Paste into a search engine manually. Apolaki does not auto-scrape results "
           "(that would violate most engines' terms). Authorized recon only._", ""]
    for g in d["groups"]:
        out.append(f"**{g['label']}**")
        out += [f"- {q['title']}: `{q['query']}`" for q in g["queries"]]
        out.append("")
    return "\n".join(out)

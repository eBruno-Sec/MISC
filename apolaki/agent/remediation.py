"""
Remediation Playbook catalog.

For each vulnerability class, returns a developer-facing fix: a short summary
plus copy-paste, language-specific secure-code snippets. Ported from Round Table
core/remediation.py.
"""
from typing import Any, Optional

CATALOG: dict = {
    "sqli": {
        "summary": "Never build SQL by string concatenation. Use parameterized queries / prepared statements and a least-privilege DB account.",
        "fixes": [
            {"label": "Python (psycopg / DB-API)", "lang": "python",
             "code": "cur.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))"},
            {"label": "Node.js (pg)", "lang": "javascript",
             "code": "await pool.query('SELECT * FROM users WHERE id = $1', [userId]);"},
            {"label": "Java (JDBC PreparedStatement)", "lang": "java",
             "code": "PreparedStatement ps = con.prepareStatement(\"SELECT * FROM users WHERE id = ?\");\nps.setInt(1, userId);"},
            {"label": "PHP (PDO)", "lang": "php",
             "code": "$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');\n$stmt->execute([$id]);"},
        ],
    },
    "xss": {
        "summary": "Context-encode all output, prefer framework auto-escaping, and add a strict Content-Security-Policy. Never build HTML from raw input.",
        "fixes": [
            {"label": "Encode on output (server)", "lang": "python",
             "code": "from markupsafe import escape\nreturn f\"<div>{escape(user_input)}</div>\""},
            {"label": "React (safe by default)", "lang": "javascript",
             "code": "// Render as text, NOT dangerouslySetInnerHTML\nreturn <div>{userInput}</div>;"},
            {"label": "Strict CSP header", "lang": "nginx",
             "code": "add_header Content-Security-Policy \"default-src 'self'; object-src 'none'; base-uri 'self'\" always;"},
        ],
    },
    "open_redirect": {
        "summary": "Do not redirect to user-supplied absolute URLs. Allow-list relative paths or known hosts only.",
        "fixes": [
            {"label": "Allow-list relative paths (Python)", "lang": "python",
             "code": "from urllib.parse import urlparse\nnxt = request.args.get('next', '/')\nif urlparse(nxt).netloc:      # absolute/external -> reject\n    nxt = '/'\nreturn redirect(nxt)"},
        ],
    },
    "ssrf": {
        "summary": "Validate and allow-list outbound destinations, resolve+pin the IP, block RFC1918/link-local/metadata ranges, and disable unused URL schemes.",
        "fixes": [
            {"label": "Block internal ranges (Python)", "lang": "python",
             "code": "import ipaddress, socket\nip = ipaddress.ip_address(socket.gethostbyname(host))\nif ip.is_private or ip.is_loopback or ip.is_link_local:\n    raise ValueError('destination not allowed')"},
            {"label": "Disable AWS IMDSv1", "lang": "bash",
             "code": "aws ec2 modify-instance-metadata-options --instance-id i-xxxx --http-tokens required --http-endpoint enabled"},
        ],
    },
    "lfi": {
        "summary": "Never pass user input to file APIs. Map to an allow-list of IDs, then canonicalize and confirm the path stays inside the base directory.",
        "fixes": [
            {"label": "Canonicalize + contain (Python)", "lang": "python",
             "code": "import os\nbase = '/srv/files'\npath = os.path.realpath(os.path.join(base, user_name))\nif not path.startswith(base + os.sep):\n    raise ValueError('path traversal')"},
        ],
    },
    "cors": {
        "summary": "Reflect only an explicit allow-list of origins; never combine Access-Control-Allow-Origin: * with credentials.",
        "fixes": [
            {"label": "Strict allow-list (Express)", "lang": "javascript",
             "code": "const allowed = new Set(['https://app.example.com']);\napp.use((req,res,next)=>{\n  const o = req.headers.origin;\n  if (allowed.has(o)) { res.set('Access-Control-Allow-Origin', o); res.set('Vary','Origin'); }\n  next();\n});"},
        ],
    },
    "csrf": {
        "summary": "Use anti-CSRF tokens (synchronizer or double-submit) and SameSite cookies on all state-changing requests.",
        "fixes": [
            {"label": "SameSite + Secure cookie", "lang": "python",
             "code": "resp.set_cookie('session', val, secure=True, httponly=True, samesite='Lax')"},
        ],
    },
    "clickjacking": {
        "summary": "Deny framing with CSP frame-ancestors (and X-Frame-Options for old browsers).",
        "fixes": [
            {"label": "Anti-framing headers", "lang": "nginx",
             "code": "add_header Content-Security-Policy \"frame-ancestors 'none'\" always;\nadd_header X-Frame-Options \"DENY\" always;"},
        ],
    },
    "cookies": {
        "summary": "Set HttpOnly, Secure, and SameSite on every session cookie.",
        "fixes": [
            {"label": "Hardened cookie (Node)", "lang": "javascript",
             "code": "res.cookie('sid', id, { httpOnly: true, secure: true, sameSite: 'lax' });"},
        ],
    },
    "hsts": {
        "summary": "Serve HSTS over HTTPS so browsers refuse to downgrade.",
        "fixes": [
            {"label": "HSTS header", "lang": "nginx",
             "code": "add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\" always;"},
        ],
    },
    "headers": {
        "summary": "Add the standard security header set at the edge (proxy) so it applies everywhere.",
        "fixes": [
            {"label": "Baseline headers", "lang": "nginx",
             "code": "add_header X-Content-Type-Options \"nosniff\" always;\nadd_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\nadd_header Content-Security-Policy \"default-src 'self'\" always;"},
        ],
    },
    "host_header": {
        "summary": "Never trust the Host / X-Forwarded-Host header. Pin an allow-list of expected hostnames and build absolute URLs from config.",
        "fixes": [
            {"label": "Allowed hosts (Django)", "lang": "python",
             "code": "ALLOWED_HOSTS = ['app.example.com', 'www.example.com']"},
        ],
    },
    "idor": {
        "summary": "Enforce object-level authorization on every request: check the current user owns/may access the referenced object server-side.",
        "fixes": [
            {"label": "Ownership check", "lang": "python",
             "code": "obj = Invoice.query.get_or_404(invoice_id)\nif obj.user_id != current_user.id:\n    abort(403)"},
        ],
    },
    "vcs": {
        "summary": "Remove version-control and backup artifacts from the web root and block dotfiles at the server.",
        "fixes": [
            {"label": "Block dotfiles (nginx)", "lang": "nginx",
             "code": "location ~ /\\.(git|svn|hg|env) { deny all; return 404; }"},
        ],
    },
    "secrets": {
        "summary": "Never ship secrets in the web root. Rotate any exposed key immediately, load config from a secrets manager, and keep .env out of the image.",
        "fixes": [
            {"label": "Exclude from build", "lang": "bash",
             "code": "echo '.env' >> .dockerignore && echo '.env' >> .gitignore"},
        ],
    },
    "email": {
        "summary": "Publish SPF, DKIM, and an enforcing DMARC policy to stop domain spoofing.",
        "fixes": [
            {"label": "DMARC record (DNS TXT at _dmarc)", "lang": "dns",
             "code": "_dmarc.example.com  TXT  \"v=DMARC1; p=reject; rua=mailto:dmarc@example.com; adkim=s; aspf=s\""},
        ],
    },
    "graphql": {
        "summary": "Disable introspection in production, enforce per-field authorization, add query depth/complexity limits, and rate-limit.",
        "fixes": [
            {"label": "Disable introspection (Apollo)", "lang": "javascript",
             "code": "new ApolloServer({ schema, introspection: false });"},
        ],
    },
    "actuator": {
        "summary": "Restrict Spring Boot Actuator to a management port behind auth, and expose only health.",
        "fixes": [
            {"label": "application.properties", "lang": "properties",
             "code": "management.endpoints.web.exposure.include=health\nmanagement.endpoint.health.show-details=never"},
        ],
    },
    "redis": {
        "summary": "Never expose Redis to the internet. Bind to localhost, require a strong password, and enable protected-mode/ACLs.",
        "fixes": [
            {"label": "redis.conf", "lang": "conf",
             "code": "bind 127.0.0.1 ::1\nprotected-mode yes\nrequirepass <long-random-secret>"},
        ],
    },
    "mongo": {
        "summary": "Enable authentication/authorization and bind MongoDB to a private interface only.",
        "fixes": [
            {"label": "mongod.conf", "lang": "yaml",
             "code": "security:\n  authorization: enabled\nnet:\n  bindIp: 127.0.0.1"},
        ],
    },
    "elastic": {
        "summary": "Enable the security features and never expose Elasticsearch unauthenticated.",
        "fixes": [
            {"label": "elasticsearch.yml", "lang": "yaml",
             "code": "xpack.security.enabled: true\nnetwork.host: 127.0.0.1"},
        ],
    },
    "docker": {
        "summary": "Never expose the Docker daemon TCP socket. Use the local unix socket and mTLS if remote access is truly required.",
        "fixes": [
            {"label": "Do not publish 2375/2376", "lang": "bash",
             "code": "# remove `-H tcp://0.0.0.0:2375` from dockerd; use /var/run/docker.sock"},
        ],
    },
    "wordpress": {
        "summary": "Keep core/plugins/themes patched, block user enumeration, disable xmlrpc if unused, and enforce MFA on wp-admin.",
        "fixes": [
            {"label": "Disable xmlrpc (nginx)", "lang": "nginx",
             "code": "location = /xmlrpc.php { deny all; return 403; }"},
        ],
    },
    "fingerprint": {
        "summary": "Suppress version banners and keep the component patched against known CVEs.",
        "fixes": [
            {"label": "Hide nginx version", "lang": "nginx", "code": "server_tokens off;"},
        ],
    },
    "caa": {
        "summary": "Publish a CAA record so only your chosen CA can issue certificates for the domain.",
        "fixes": [
            {"label": "CAA record (DNS)", "lang": "dns",
             "code": "example.com  CAA  0 issue \"letsencrypt.org\""},
        ],
    },
    "takeover": {
        "summary": "Remove dangling DNS records that point at unclaimed provider resources; claim or delete the CNAME target.",
        "fixes": [
            {"label": "Audit + delete dangling CNAME", "lang": "bash",
             "code": "dig +short CNAME sub.example.com   # if target is unclaimed, remove the record"},
        ],
    },
}

_KEY_HINTS = [
    ("sqli", "sqli"), ("xss", "xss"), ("csp-missing", "xss"), ("clickjacking", "clickjacking"),
    ("hsts", "hsts"), ("cookie", "cookies"), ("redirect", "open_redirect"), ("ssrf", "ssrf"),
    ("lfi", "lfi"), ("cors", "cors"), ("csrf", "csrf"), ("host-header", "host_header"),
    ("idor", "idor"), ("vcs", "vcs"), ("backup", "vcs"), ("secrets", "secrets"),
    ("email", "email"), ("graphql", "graphql"), ("actuator", "actuator"), ("swagger", "graphql"),
    ("wordpress", "wordpress"), ("server-version", "fingerprint"), ("caa", "caa"),
    ("takeover", "takeover"), ("redis", "redis"), ("mongo", "mongo"), ("elastic", "elastic"),
    ("docker", "docker"), ("admin", "idor"), ("status", "headers"), ("phpinfo", "secrets"),
]


def remediation_for(finding: dict) -> Optional[dict]:
    key = (finding.get("key") or "").lower()
    tags = " ".join(finding.get("tags") or []).lower()
    hay = key + " " + tags
    for hint, cat in _KEY_HINTS:
        if hint in hay:
            return CATALOG.get(cat)
    return None


def remediation_text(finding: dict) -> str:
    """Flatten a remediation entry to a plain-text summary for reports/PoC."""
    entry = remediation_for(finding)
    if not entry:
        return ""
    return entry.get("summary", "")


# ── Fix Now / Fix If / Strengthen — action-priority layer ALONGSIDE technical severity (CVSS/CWE) ──
# A remediation-PRIORITY lens (competitor-inspired) that answers "what should the team do FIRST", derived
# deterministically from the fields Apolaki already emits — it never replaces the technical severity, it adds a
# triage action a developer can act on:
#   * fix_now    — a CONFIRMED, exploitable-now high/critical: an attacker can use it today.
#   * fix_if     — a CONFIRMED medium, OR a strong-but-UNCONFIRMED high/critical lead (verify, then fix if real),
#                  OR a confirmed issue that only bites under a stated precondition (conditional weakness).
#   * strengthen — hardening / defense-in-depth: confirmed low/info, missing-header/cookie-flag/transport
#                  hygiene, or a weak unconfirmed lead. Best-practice, not an open door.
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "": 0}
# families that are hardening / defense-in-depth by nature -> Strengthen regardless of a scanner's severity label
_HARDENING_FAMILIES = {"cookie_flags", "security_headers", "header", "headers", "cleartext_transport",
                       "clickjacking", "csp", "cors", "cache_control", "info_leak", "verbose_error",
                       "tls_config", "permissions_policy"}
_CONDITIONAL_TAGS = {"needs-confirmation", "conditional", "requires-precondition", "context-dependent"}


def fix_priority(finding: dict) -> dict:
    """Return {tier, label, reason} where tier ∈ {fix_now, fix_if, strengthen}. Pure; deterministic over
    (confidence, severity, family, tags). Adds a triage ACTION next to CVSS/CWE — does not replace them."""
    f = finding or {}
    fam = str(f.get("family") or f.get("vuln_class") or "").strip().lower()
    sev = str(f.get("severity") or "info").strip().lower()
    conf = str(f.get("confidence") or "").strip().lower()
    confirmed = conf == "confirmed"
    rank = _SEV_RANK.get(sev, 0)
    tags = {str(t).strip().lower() for t in (f.get("tags") or [])}
    conditional = bool(tags & _CONDITIONAL_TAGS)

    def out(tier, reason):
        label = {"fix_now": "Fix Now", "fix_if": "Fix If", "strengthen": "Strengthen"}[tier]
        return {"tier": tier, "label": label, "reason": reason}

    if fam in _HARDENING_FAMILIES:
        return out("strengthen", "defense-in-depth / hardening (%s) — best practice, not an open door" % (fam or "config"))
    if confirmed and rank >= 3:                 # confirmed high/critical
        if conditional:
            return out("fix_if", "confirmed %s but only exploitable under a stated precondition" % sev)
        return out("fix_now", "confirmed %s severity — exploitable now" % sev)
    if confirmed and rank == 2:                 # confirmed medium
        return out("fix_if", "confirmed medium — fix in the normal cycle unless it composes into a chain")
    if confirmed and rank <= 1:                 # confirmed low/info
        return out("strengthen", "confirmed but low impact — hardening")
    # unconfirmed leads
    if rank >= 3:
        return out("fix_if", "strong unconfirmed %s lead — verify, then fix if real" % sev)
    return out("strengthen", "weak/unconfirmed signal — hardening or dismiss after review")


_TIER_ORDER = {"fix_now": 0, "fix_if": 1, "strengthen": 2}


def fix_priority_summary(findings: list, leads: list = None) -> dict:
    """Group findings (+ optional leads) by fix tier for the report header. Returns
    {counts:{fix_now,fix_if,strengthen}, order:[...]}. Pure."""
    counts = {"fix_now": 0, "fix_if": 0, "strengthen": 0}
    for f in list(findings or []) + list(leads or []):
        counts[fix_priority(f)["tier"]] += 1
    return {"counts": counts, "order": ["fix_now", "fix_if", "strengthen"]}

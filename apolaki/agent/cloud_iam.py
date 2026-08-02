"""
Cloud IAM analysis engine (CHAD capability A) — the DETERMINISTIC brain.

Full live enumeration of an AWS/Azure/GCP account requires operator cloud CREDENTIALS + explicit
scope, which is an external prerequisite this lab environment does not have — so live account/role
discovery is a declared BLOCKER (see `live_enumeration_supported`). Everything that does NOT need a
live account is built and unit-tested here:

  - normalize Infrastructure-as-Code (Terraform plan JSON / CloudFormation) into an IAM model
  - build the IAM relationship graph: principal -> role -> policy -> permission -> resource
  - role / permission analysis: wildcard actions, public resources, and privilege-escalation paths
    (iam:PassRole + compute, iam:* , wildcard AssumeRole, policy self-attachment)
  - proof-first findings: every finding carries the exact offending statement as evidence + a fix
  - graph projection into the canonical asset graph; credentials are vault refs, never raw

This is the analysis engine an authorized live collector would feed; wiring a real boto3/az/gcloud
collector behind `live_enumeration_supported()` is the remaining, credential-gated step.
"""
from __future__ import annotations

# Actions that grant broad control or enable privilege escalation when combined.
_ADMIN_ACTIONS = ("*", "iam:*", "iam:createpolicyversion", "iam:putrolepolicy", "iam:attachrolepolicy",
                  "iam:passrole", "sts:assumerole", "lambda:createfunction", "lambda:invokefunction",
                  "ec2:runinstances", "iam:createaccesskey", "iam:updateassumerolepolicy")
_ESCALATION_PAIRS = [
    ({"iam:passrole"}, {"lambda:createfunction", "ec2:runinstances", "glue:createdevendpoint"},
     "iam:PassRole with a compute-create action lets a role hand its privileges to attacker-run code"),
    ({"iam:createpolicyversion"}, set(),
     "iam:CreatePolicyVersion lets a principal rewrite its OWN policy to admin"),
    ({"iam:attachrolepolicy", "iam:putrolepolicy"}, set(),
     "iam:AttachRolePolicy / PutRolePolicy lets a principal grant itself AdministratorAccess"),
    ({"iam:createaccesskey"}, set(),
     "iam:CreateAccessKey lets a principal mint long-lived credentials for a more-privileged user"),
]


def live_enumeration_supported() -> dict:
    """Whether a LIVE cloud collector can run. False here: no operator cloud credentials/scope in this
    environment. The analysis engine below runs on IaC regardless. Honest, machine-readable blocker."""
    import os
    _providers = (("aws", "AWS_ACCESS_KEY_ID"), ("azure", "AZURE_CLIENT_ID"),
                  ("gcp", "GOOGLE_APPLICATION_CREDENTIALS"), ("linode", "LINODE_TOKEN"))
    ready = [p for p, k in _providers if os.environ.get(k)]
    # linode has a real live read-only collector; aws/azure/gcp live SDK wiring is still gated.
    return {"supported": bool(ready),
            "reason": "" if ready else "no operator cloud credentials in scope — live account/role "
                                       "enumeration is credential-gated; IaC analysis runs regardless",
            "providers_ready": ready, "live_collector_implemented": ["linode"]}


def _stmt_list(policy: dict) -> list:
    s = (policy or {}).get("Statement") or (policy or {}).get("statement") or []
    return s if isinstance(s, list) else [s]


def _as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def normalize_iac(doc: dict) -> dict:
    """Normalize a Terraform-plan-style or CloudFormation-style doc into
    {roles:[{name, assume, policies:[{effect, actions[], resources[]}]}], resources:[{type,name,public}]}.
    Tolerant: unknown shapes yield empty lists rather than raising."""
    roles, resources = [], []
    doc = doc or {}
    # CloudFormation: Resources: {Name: {Type, Properties}}
    cfn = doc.get("Resources")
    if isinstance(cfn, dict):
        for name, r in cfn.items():
            rtype = (r or {}).get("Type", "")
            props = (r or {}).get("Properties", {}) or {}
            if rtype == "AWS::IAM::Role":
                pols = []
                for p in _as_list(props.get("Policies")):
                    pd = (p or {}).get("PolicyDocument", {})
                    for st in _stmt_list(pd):
                        pols.append({"effect": st.get("Effect", "Allow"),
                                     "actions": [a.lower() for a in _as_list(st.get("Action"))],
                                     "resources": _as_list(st.get("Resource"))})
                roles.append({"name": name, "assume": props.get("AssumeRolePolicyDocument", {}), "policies": pols})
            else:
                pub = _detect_public(rtype, props)
                resources.append({"type": rtype, "name": name, "public": pub})
        return {"roles": roles, "resources": resources}
    # Terraform plan JSON: planned_values.root_module.resources: [{type, name, values}]
    tf = (((doc.get("planned_values") or {}).get("root_module") or {}).get("resources")) or doc.get("resources")
    if isinstance(tf, list):
        for r in tf:
            rtype = r.get("type", "")
            vals = r.get("values", r) or {}
            if rtype == "aws_iam_role_policy" or rtype == "aws_iam_policy":
                pd = vals.get("policy")
                import json as _j
                try:
                    pd = _j.loads(pd) if isinstance(pd, str) else (pd or {})
                except Exception:
                    pd = {}
                pols = [{"effect": st.get("Effect", "Allow"),
                         "actions": [a.lower() for a in _as_list(st.get("Action"))],
                         "resources": _as_list(st.get("Resource"))} for st in _stmt_list(pd)]
                roles.append({"name": vals.get("name") or r.get("name", ""), "assume": {}, "policies": pols})
            else:
                resources.append({"type": rtype, "name": r.get("name", ""), "public": _detect_public(rtype, vals)})
        return {"roles": roles, "resources": resources}
    return {"roles": roles, "resources": resources}


def normalize_azure(doc: dict) -> dict:
    """Normalize Azure role-assignment / ARM-ish JSON into the common IAM model. Accepts
    {roleAssignments:[{principalId, roleName, permissions:[{actions[],notActions[]}], scope}],
    resources:[{type, name, properties}]}. Azure wildcard action is '*'."""
    roles, resources = [], []
    doc = doc or {}
    for ra in (doc.get("roleAssignments") or []):
        pols = []
        for perm in _as_list(ra.get("permissions")):
            pols.append({"effect": "Allow",
                         "actions": [a.lower() for a in _as_list(perm.get("actions"))],
                         "resources": _as_list(ra.get("scope") or "*")})
        roles.append({"name": ra.get("roleName") or ra.get("principalId", "azure-role"),
                      "assume": {"principal": ra.get("principalId")}, "policies": pols})
    for r in (doc.get("resources") or []):
        props = r.get("properties", r) or {}
        pub = str(props.get("allowBlobPublicAccess") or props.get("publicNetworkAccess") or "").lower() in ("true", "enabled")
        resources.append({"type": r.get("type", ""), "name": r.get("name", ""), "public": pub})
    return {"roles": roles, "resources": resources, "provider": "azure"}


def normalize_gcp(doc: dict) -> dict:
    """Normalize a GCP IAM policy (getIamPolicy shape) into the common model:
    {bindings:[{role, members[]}], resources:[{type,name,public}]}. A binding to allUsers /
    allAuthenticatedUsers marks the bound resource PUBLIC; primitive roles (owner/editor) are broad."""
    roles, resources = [], []
    doc = doc or {}
    public_via_iam = False
    for b in (doc.get("bindings") or []):
        role = b.get("role", "")
        members = _as_list(b.get("members"))
        if any(m in ("allUsers", "allAuthenticatedUsers") for m in members):
            public_via_iam = True
        # GCP primitive roles map to broad action grants in the common model
        acts = ["*"] if role in ("roles/owner", "roles/editor") else [role.lower()]
        roles.append({"name": role or "gcp-binding", "assume": {"members": members},
                      "policies": [{"effect": "Allow", "actions": acts, "resources": ["*"]}]})
    for r in (doc.get("resources") or []):
        resources.append({"type": r.get("type", ""), "name": r.get("name", ""),
                          "public": bool(r.get("public")) or public_via_iam})
    if public_via_iam and not resources:
        resources.append({"type": "gcp_iam_policy", "name": doc.get("resource", "policy"), "public": True})
    return {"roles": roles, "resources": resources, "provider": "gcp"}


# Ports that must NOT be reachable from the whole internet (0.0.0.0/0). SSH/RDP + database/admin.
_SENSITIVE_PORTS = {22, 23, 3389, 3306, 5432, 6379, 27017, 9200, 5601, 11211, 1433, 5900, 2375, 2379}
_ANY_CIDR = ("0.0.0.0/0", "::/0", "0.0.0.0", "*")


def _ports_in(spec) -> set:
    """Parse a Linode firewall port spec ('22', '80,443', '8000-8080') into a set of ints."""
    out = set()
    for part in str(spec or "").split(","):
        part = part.strip()
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                out |= set(range(int(a), min(int(b), int(a) + 1024) + 1))
            except Exception:
                pass
        elif part.isdigit():
            out.add(int(part))
    return out


def normalize_linode(doc: dict) -> dict:
    """Normalize Linode (Akamai Connected Cloud) API v4 read-only responses into the common model.
    Accepts {users:[{username,tfa_enabled}], grants:{user:{global:{...}}}, firewalls:[{label,rules}],
    buckets:[{label,acl}], instances:[{label,ipv4}], databases:[{label,allow_list,engine}]}. Maps
    account users+grants -> roles, storage/db/instances -> resources (public flags), and keeps
    firewalls for the open-to-internet check. Tolerant of missing keys."""
    doc = doc or {}
    roles, resources = [], []
    grants = doc.get("grants") or {}
    for u in (doc.get("users") or []):
        uname = u.get("username") or u.get("email") or "linode-user"
        g = (grants.get(uname) or {}).get("global") or {}
        acts = []
        if str(g.get("account_access") or "").lower() in ("read_write", "readwrite"):
            acts.append("*")            # full account read/write == broad admin
        for k, v in g.items():
            if k != "account_access" and v:
                acts.append(("linode:%s" % k).lower())
        roles.append({"name": uname, "assume": {"tfa": u.get("tfa_enabled")},
                      "policies": [{"effect": "Allow", "actions": acts or ["linode:read"], "resources": ["*"]}]})
    for b in (doc.get("buckets") or []):
        acl = str(b.get("acl") or b.get("acl_type") or "").lower()
        resources.append({"type": "linode_object_storage_bucket", "name": b.get("label", "bucket"),
                          "public": acl in ("public-read", "public-read-write", "authenticated-read") or bool(b.get("public"))})
    for d in (doc.get("databases") or []):
        allow = [str(a) for a in (d.get("allow_list") or [])]
        resources.append({"type": "linode_managed_database:%s" % (d.get("engine") or "db"),
                          "name": d.get("label", "database"),
                          "public": any(a in _ANY_CIDR for a in allow)})
    for i in (doc.get("instances") or []):
        resources.append({"type": "linode_instance", "name": i.get("label", "instance"),
                          "public": False, "ipv4": i.get("ipv4") or []})
    return {"roles": roles, "resources": resources, "firewalls": doc.get("firewalls") or [],
            "provider": "linode"}


def normalize(provider: str, doc: dict) -> dict:
    """Provider-dispatched normalization into the common IAM model."""
    p = (provider or "").lower()
    if p == "azure":
        return normalize_azure(doc)
    if p == "gcp":
        return normalize_gcp(doc)
    if p == "linode":
        return normalize_linode(doc)
    return normalize_iac(doc)


def _linode_get(path: str, token: str, timeout: int = 20, retries: int = 3):
    """One READ-ONLY GET vs the Linode API v4 with bounded retry/backoff on 429 + transient 5xx.
    Returns (ok, json_or_None, status). The token is sent in the Authorization header only and is
    NEVER logged or returned. Never raises — the caller records completeness from the (ok,status)."""
    import json as _j
    import time
    import urllib.error
    import urllib.request
    url = "https://api.linode.com/v4" + path
    for attempt in range(max(1, retries)):
        try:
            req = urllib.request.Request(url, headers={"Authorization": "Bearer " + token,
                                                       "User-Agent": "apolaki-cloud"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return True, _j.loads(r.read().decode("utf-8", "replace")), r.getcode()
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 504) and attempt < retries - 1:
                time.sleep(min(2 ** attempt, 8))
                continue
            return False, None, e.code
        except Exception:
            if attempt < retries - 1:
                time.sleep(min(2 ** attempt, 8))
                continue
            return False, None, 0
    return False, None, 0


_PAGE_CAP = 100


def _linode_paged(path: str, token: str, manifest: dict):
    """Fetch ALL pages of a Linode collection. Records every request in the manifest and returns
    (items, complete). complete=False if any page FAILED, if the API advertised MORE pages than the
    cap (truncated — CHAD edge bug: must NOT be marked complete), or if the collected count does not
    match the advertised total (inconsistent collection). Truncation/mismatch is recorded explicitly
    so a truncated collection is never mistaken for a full one."""
    items, page, pages, advertised = [], 1, 1, None
    while page <= pages and page <= _PAGE_CAP:
        sep = "&" if "?" in path else "?"
        ok, data, status = _linode_get("%s%spage=%d&page_size=100" % (path, sep, page), token)
        manifest["requests"] += 1
        if not ok or not isinstance(data, dict):
            manifest["failed"].append({"path": path, "page": page, "status": status})
            return items, False
        manifest["succeeded"] += 1
        items += data.get("data", []) or []
        pages = int(data.get("pages", 1) or 1)
        advertised = int(data.get("results", len(items)) or len(items))
        manifest["advertised"][path] = advertised
        page += 1
    # The API advertised MORE pages than we fetched -> the collection is TRUNCATED, not complete.
    if pages > _PAGE_CAP:
        manifest["truncated"].append({"path": path, "advertised_pages": pages, "page_cap": _PAGE_CAP})
        return items, False
    # Collected count must reconcile with the advertised total (else the account changed mid-collection
    # or a page was short) -> treat as incomplete rather than silently under-report.
    if advertised is not None and len(items) != advertised:
        manifest["truncated"].append({"path": path, "collected": len(items), "advertised": advertised})
        return items, False
    return items, True


def collect_linode_live(token: str) -> dict:
    """LIVE, strictly READ-ONLY Linode (Akamai Connected Cloud) posture collection with COMPLETENESS
    tracking. GET-only over users+grants, cloud firewalls+rules, object-storage buckets, managed
    databases, instances (all pages), then the deterministic analyzer. A hardening review of the
    operator's OWN account — no writes/exploitation. Token is auth-only, never stored.

    CRITICAL (CHAD #2): an incomplete or failed collection is NEVER reported as a clean posture. If a
    required endpoint fails, the result is marked partial/blocked with a manifest of what was and was
    not collected, so zero findings on a broken collection cannot be mistaken for a secure account."""
    from urllib.parse import quote
    manifest = {"requests": 0, "succeeded": 0, "failed": [], "truncated": [], "advertised": {},
                "counts": {}, "complete": True}
    doc = {"users": [], "grants": {}, "firewalls": [], "buckets": [], "instances": [], "databases": []}
    required = {"users": "/account/users", "firewalls": "/networking/firewalls",
                "buckets": "/object-storage/buckets", "instances": "/linode/instances",
                "databases": "/databases/instances"}
    for key, path in required.items():
        items, ok = _linode_paged(path, token, manifest)
        doc[key] = items
        if not ok:
            manifest["complete"] = False
    # per-user grants — username URL-encoded (CHAD #6) so odd characters can't break the path
    for u in doc["users"]:
        un = u.get("username")
        if not un:
            continue
        ok, data, status = _linode_get("/account/users/%s/grants" % quote(str(un), safe=""), token)
        manifest["requests"] += 1
        if ok:
            manifest["succeeded"] += 1
            doc["grants"][un] = data
        else:
            manifest["failed"].append({"path": "grants:%s" % un, "status": status})
            manifest["complete"] = False
    # each firewall's inbound rule set
    for fw in doc["firewalls"]:
        if fw.get("id") and "rules" not in fw:
            ok, data, status = _linode_get("/networking/firewalls/%s/rules" % quote(str(fw["id"]), safe=""), token)
            manifest["requests"] += 1
            if ok:
                manifest["succeeded"] += 1
                fw["rules"] = data
            else:
                manifest["failed"].append({"path": "fwrules:%s" % fw["id"], "status": status})
                manifest["complete"] = False
    manifest["counts"] = {k: len(v) for k, v in doc.items() if isinstance(v, list)}
    model = normalize_linode(doc)
    findings = analyze(model)
    complete = manifest["complete"]
    # A collection that got NOTHING usable (e.g. a bad/expired token or every required endpoint failing)
    # is BLOCKED, not clean. Any partial failure is surfaced so 0 findings is never read as "secure".
    total_failed_required = manifest["succeeded"] == 0
    if total_failed_required:
        return {"provider": "linode", "blocked": True, "partial": True,
                "reason": "Linode collection FAILED (bad token or all required endpoints errored) — "
                          "this is NOT a clean posture; check the token/scope and retry",
                "manifest": manifest, "model": model, "findings": findings, "counts": manifest["counts"]}
    return {"provider": "linode", "blocked": False, "partial": not complete,
            "reason": "" if complete else "collection PARTIAL — some endpoints failed (see manifest.failed); "
                                          "findings are INCOMPLETE and 0 findings must NOT be read as secure",
            "manifest": manifest, "model": model, "findings": findings, "counts": manifest["counts"]}


def collect(provider: str, *, fixture: dict = None, token: str = None) -> dict:
    """Provider collector. With a `fixture` it normalizes + analyzes offline (unit-testable). For
    `linode` with a token (arg or LINODE_TOKEN env) it runs a LIVE, read-only posture collection. AWS/
    Azure/GCP live SDK wiring stays credential-gated. Returns {provider, blocked, model?, findings?}."""
    import os
    p = (provider or "").lower()
    if fixture is not None:
        model = normalize(p, fixture)
        return {"provider": p, "blocked": False, "model": model, "findings": analyze(model)}
    if p == "linode":
        tok = token or os.environ.get("LINODE_TOKEN", "")
        if not tok:
            return {"provider": p, "blocked": True,
                    "reason": "set LINODE_TOKEN (a READ-ONLY Linode API token) to run the live posture review",
                    "model": {"roles": [], "resources": []}, "findings": []}
        try:
            return collect_linode_live(tok)
        except Exception as e:
            return {"provider": p, "blocked": True, "reason": "live linode collect failed: %s" % e,
                    "model": {"roles": [], "resources": []}, "findings": []}
    st = live_enumeration_supported()
    if p not in st.get("providers_ready", []):
        return {"provider": p, "blocked": True,
                "reason": "live %s enumeration needs credentials in scope (%s)" % (p, st["reason"]),
                "model": {"roles": [], "resources": []}, "findings": []}
    return {"provider": p, "blocked": True,
            "reason": "live %s SDK wiring not enabled in this build — credentials present; enable in collect()" % p,
            "model": {"roles": [], "resources": []}, "findings": []}


def _detect_public(rtype: str, props: dict) -> bool:
    rt = (rtype or "").lower()
    props = props or {}
    if "s3" in rt and "bucket" in rt:
        acl = str(props.get("AccessControl") or props.get("acl") or "").lower()
        if acl in ("publicread", "public-read", "publicreadwrite", "public-read-write"):
            return True
    if str(props.get("PubliclyAccessible") or props.get("publicly_accessible") or "").lower() == "true":
        return True
    return False


def analyze(model: dict) -> list:
    """Return proof-first findings from a normalized IAM model. Each carries the exact offending
    statement as evidence. Confidence 'confirmed' only for unambiguous IaC facts (a wildcard action
    IS in the policy); escalation PATHS are high-severity leads pending live confirmation."""
    findings = []
    for role in (model or {}).get("roles", []):
        rname = role.get("name", "role")
        granted = set()
        for pol in role.get("policies", []):
            if str(pol.get("effect", "Allow")).lower() != "allow":
                continue
            acts = set(pol.get("actions", []))
            granted |= acts
            res = pol.get("resources", [])
            if "*" in acts or any(a in ("iam:*",) for a in acts):
                findings.append(_f(rname, "critical", "confirmed", "cloud_iam_wildcard_action",
                    "Role '%s' grants a wildcard/admin action" % rname,
                    "Effect=Allow Action=%s Resource=%s" % (sorted(acts), res),
                    "Scope the policy to the specific actions + resources actually required."))
            elif "*" in res and (acts & set(_ADMIN_ACTIONS)):
                findings.append(_f(rname, "high", "lead", "cloud_iam_wildcard_resource",
                    "Role '%s' grants a sensitive action on Resource '*'" % rname,
                    "Effect=Allow Action=%s Resource=*" % sorted(acts & set(_ADMIN_ACTIONS)),
                    "Restrict Resource to specific ARNs."))
        # privilege-escalation paths from the union of granted actions
        for need, companion, why in _ESCALATION_PAIRS:
            if need <= granted and (not companion or (granted & companion)):
                findings.append(_f(rname, "high", "lead", "cloud_iam_privilege_escalation",
                    "Role '%s' has a privilege-escalation path" % rname,
                    "granted actions include %s — %s" % (sorted(need | (granted & companion)), why),
                    "Remove the escalation primitive or add a permissions boundary."))
    for r in (model or {}).get("resources", []):
        if r.get("public"):
            findings.append(_f(r.get("name", ""), "high", "confirmed", "cloud_public_resource",
                "Resource '%s' (%s) is publicly accessible" % (r.get("name"), r.get("type")),
                "IaC declares this %s public" % r.get("type"),
                "Make the resource private; block public ACLs/exposure."))
    # Cloud firewalls open to the whole internet on a sensitive port (SSH/RDP/DB/admin) — the single
    # most common cloud-infra misconfig. Deterministic from the firewall's own inbound rules.
    for fw in (model or {}).get("firewalls", []):
        label = fw.get("label", "firewall")
        for rule in ((fw.get("rules") or {}).get("inbound") or []):
            if str(rule.get("action", "ACCEPT")).upper() != "ACCEPT":
                continue
            addrs = (rule.get("addresses") or {})
            wide = any(a in _ANY_CIDR for a in (list(addrs.get("ipv4") or []) + list(addrs.get("ipv6") or [])))
            hit = _ports_in(rule.get("ports")) & _SENSITIVE_PORTS
            if wide and hit:
                findings.append(_f(label, "high", "confirmed", "cloud_firewall_open_to_internet",
                    "Firewall '%s' allows the whole internet (0.0.0.0/0) to sensitive port(s) %s"
                    % (label, sorted(hit)),
                    "inbound ACCEPT ports=%s addresses=%s" % (rule.get("ports"), addrs),
                    "Restrict the inbound rule to known admin IPs / a bastion; never expose SSH/RDP/DB to 0.0.0.0/0."))
    # A user without 2FA who holds broad account access is an account-takeover risk.
    for role in (model or {}).get("roles", []):
        if role.get("assume", {}).get("tfa") is False and "*" in {a for p in role.get("policies", []) for a in p.get("actions", [])}:
            findings.append(_f(role.get("name", ""), "high", "lead", "cloud_admin_without_2fa",
                "Account-admin user '%s' has no 2FA enabled" % role.get("name"),
                "user holds full account access and tfa_enabled=false",
                "Enforce 2FA for every user with account write access."))
    return findings


def _f(target, sev, conf, cat, title, evidence, remediation):
    return {"title": title, "severity": sev, "confidence": conf, "family": "cloud_misconfig",
            "cwe": "CWE-732", "target": target, "tags": ["cloud", "iam", cat],
            "description": title + ".", "impact": "Excess cloud privilege / exposure enabling escalation or data access.",
            "evidence": evidence, "provenance": "iac-analysis", "remediation": remediation}


def to_graph(graph, model: dict, account: str = "iac", source: str = "cloud_iam") -> int:
    """Project the IAM model into the canonical asset graph: account -> role -> (permissions) and
    account -> resource. Credentials never appear here; only role/permission/resource identity."""
    n = 0
    try:
        acc = graph.observe("cloud_account", account, label=account, source=source)
        for role in (model or {}).get("roles", []):
            rid = graph.observe("role", "%s/%s" % (account, role.get("name")), label=role.get("name"),
                                source=source, tested=False)
            graph.link(acc, rid, "has_role", source=source)
            n += 1
            perms = sorted({a for p in role.get("policies", []) for a in p.get("actions", [])})
            if perms:
                pid = graph.observe("permission", "%s/%s/perms" % (account, role.get("name")),
                                    label=",".join(perms[:8]), source=source, actions=perms)
                graph.link(rid, pid, "grants", source=source)
        for r in (model or {}).get("resources", []):
            rid = graph.observe("cloud_resource", "%s/%s" % (account, r.get("name")), label=r.get("name"),
                                source=source, resource_type=r.get("type"), public=bool(r.get("public")))
            graph.link(acc, rid, "owns", source=source)
            n += 1
    except Exception:
        pass
    return n

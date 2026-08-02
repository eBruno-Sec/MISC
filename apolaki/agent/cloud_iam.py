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
    have = any(os.environ.get(k) for k in ("AWS_ACCESS_KEY_ID", "AZURE_CLIENT_ID", "GOOGLE_APPLICATION_CREDENTIALS"))
    return {"supported": bool(have),
            "reason": "" if have else "no operator cloud credentials in scope — live account/role "
                                      "enumeration is credential-gated; IaC analysis runs regardless",
            "providers_ready": [p for p, k in (("aws", "AWS_ACCESS_KEY_ID"), ("azure", "AZURE_CLIENT_ID"),
                                               ("gcp", "GOOGLE_APPLICATION_CREDENTIALS")) if os.environ.get(k)]}


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


def normalize(provider: str, doc: dict) -> dict:
    """Provider-dispatched normalization into the common IAM model."""
    p = (provider or "").lower()
    if p == "azure":
        return normalize_azure(doc)
    if p == "gcp":
        return normalize_gcp(doc)
    return normalize_iac(doc)


def collect(provider: str, *, fixture: dict = None) -> dict:
    """Provider collector. With a `fixture` (a raw provider IAM doc) it normalizes + analyzes it —
    the credential-independent path, unit-testable now. A LIVE collect (fixture=None) requires cloud
    credentials and returns a BLOCKED result rather than pretending: the SDK wiring (boto3 / azure-
    identity / google-auth) is the only piece gated on external access. Returns
    {provider, blocked, reason?, model?, findings?}."""
    p = (provider or "").lower()
    if fixture is not None:
        model = normalize(p, fixture)
        return {"provider": p, "blocked": False, "model": model, "findings": analyze(model)}
    st = live_enumeration_supported()
    ready = p in st.get("providers_ready", [])
    if not ready:
        return {"provider": p, "blocked": True,
                "reason": "live %s enumeration needs credentials in scope (%s)" % (p, st["reason"]),
                "model": {"roles": [], "resources": []}, "findings": []}
    # Credentials ARE present -> a real collector would run here. Kept explicit so enabling it is a
    # single, reviewable step (import the SDK, list roles/policies/resources, feed normalize()).
    return {"provider": p, "blocked": True,
            "reason": "live collector SDK wiring intentionally not enabled in this build — "
                      "credentials present; enable in collect() to go live",
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

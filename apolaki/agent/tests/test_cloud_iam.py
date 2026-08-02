"""Cloud IAM analysis engine: IaC normalization, proof-first risk findings, privilege-escalation
paths, graph projection, and the honest credential-gated live-enumeration blocker (CHAD capability A)."""
from __future__ import annotations

import json

import cloud_iam as CI
import asset_graph as AG


_CFN = {"Resources": {
    "AdminRole": {"Type": "AWS::IAM::Role", "Properties": {"Policies": [
        {"PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}]}},
    "PublicBucket": {"Type": "AWS::S3::Bucket", "Properties": {"AccessControl": "PublicRead"}},
}}

_TF = {"planned_values": {"root_module": {"resources": [
    {"type": "aws_iam_role_policy", "name": "escalate", "values": {"name": "escalate", "policy": json.dumps(
        {"Statement": [{"Effect": "Allow", "Action": ["iam:PassRole", "lambda:CreateFunction"], "Resource": "*"}]})}},
]}}}


def test_live_enumeration_is_honestly_blocked(monkeypatch):
    for k in ("AWS_ACCESS_KEY_ID", "AZURE_CLIENT_ID", "GOOGLE_APPLICATION_CREDENTIALS"):
        monkeypatch.delenv(k, raising=False)
    st = CI.live_enumeration_supported()
    assert st["supported"] is False and st["reason"] and st["providers_ready"] == []
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIA_test")
    assert CI.live_enumeration_supported()["supported"] is True


def test_cfn_wildcard_admin_and_public_bucket_are_confirmed():
    model = CI.normalize_iac(_CFN)
    assert any(r["name"] == "AdminRole" for r in model["roles"])
    assert any(r["public"] for r in model["resources"])
    findings = CI.analyze(model)
    cats = {t for f in findings for t in f["tags"]}
    assert "cloud_iam_wildcard_action" in cats and "cloud_public_resource" in cats
    # proof-first: every finding carries evidence, and the wildcard/public ones are confirmed facts
    assert all(f.get("evidence") for f in findings)
    wild = next(f for f in findings if "cloud_iam_wildcard_action" in f["tags"])
    assert wild["confidence"] == "confirmed" and wild["severity"] == "critical"


def test_terraform_privilege_escalation_path_detected():
    model = CI.normalize_iac(_TF)
    findings = CI.analyze(model)
    esc = [f for f in findings if "cloud_iam_privilege_escalation" in f["tags"]]
    assert esc and "passrole" in esc[0]["evidence"].lower()
    assert esc[0]["confidence"] == "lead"      # a path is a lead pending live confirmation


def test_iam_model_projects_into_asset_graph():
    g = AG.AssetGraph("m")
    n = CI.to_graph(g, CI.normalize_iac(_CFN), account="acct-1")
    assert n >= 1
    kinds = g.stats()["by_kind"]
    assert kinds.get("cloud_account") == 1 and kinds.get("role", 0) >= 1
    assert kinds.get("cloud_resource", 0) >= 1
    # role is reachable from the account, permissions from the role
    assert any(e["rel"] == "has_role" for e in g.edges())
    assert "password" not in str(g.to_dict())      # no secrets projected


def test_unknown_iac_shape_is_tolerated():
    assert CI.normalize_iac({}) == {"roles": [], "resources": []}
    assert CI.analyze({"roles": [], "resources": []}) == []


_AZURE = {"roleAssignments": [
    {"principalId": "p1", "roleName": "Owner", "scope": "/sub/x",
     "permissions": [{"actions": ["*"], "notActions": []}]}],
    "resources": [{"type": "Microsoft.Storage/storageAccounts", "name": "stor1",
                   "properties": {"allowBlobPublicAccess": "true"}}]}

_GCP = {"bindings": [
    {"role": "roles/owner", "members": ["user:admin@x"]},
    {"role": "roles/storage.objectViewer", "members": ["allUsers"]}],
    "resources": [{"type": "storage.bucket", "name": "b1"}]}


def test_azure_wildcard_and_public_storage():
    model = CI.normalize_azure(_AZURE)
    assert model["provider"] == "azure"
    findings = CI.analyze(model)
    cats = {t for f in findings for t in f["tags"]}
    assert "cloud_iam_wildcard_action" in cats and "cloud_public_resource" in cats


def test_gcp_allusers_binding_is_public_and_owner_is_wildcard():
    model = CI.normalize_gcp(_GCP)
    assert model["provider"] == "gcp"
    findings = CI.analyze(model)
    cats = {t for f in findings for t in f["tags"]}
    assert "cloud_public_resource" in cats     # allUsers binding -> public
    assert "cloud_iam_wildcard_action" in cats  # roles/owner -> broad


def test_collect_with_fixture_analyzes_each_provider():
    for prov, doc in (("aws", _CFN), ("azure", _AZURE), ("gcp", _GCP)):
        res = CI.collect(prov, fixture=doc)
        assert res["provider"] == prov and res["blocked"] is False
        assert res["model"]["roles"] and isinstance(res["findings"], list)


def test_collect_live_is_blocked_without_credentials(monkeypatch):
    for k in ("AWS_ACCESS_KEY_ID", "AZURE_CLIENT_ID", "GOOGLE_APPLICATION_CREDENTIALS"):
        monkeypatch.delenv(k, raising=False)
    for prov in ("aws", "azure", "gcp"):
        res = CI.collect(prov)
        assert res["blocked"] is True and "credential" in res["reason"].lower()


_LINODE = {
  "users": [{"username": "student", "tfa_enabled": False}],
  "grants": {"student": {"global": {"account_access": "read_write", "add_linodes": True}}},
  "firewalls": [{"id": 1, "label": "web-fw", "rules": {"inbound": [
      {"action": "ACCEPT", "ports": "22", "addresses": {"ipv4": ["0.0.0.0/0"]}},
      {"action": "ACCEPT", "ports": "443", "addresses": {"ipv4": ["0.0.0.0/0"]}}]}}],
  "buckets": [{"label": "backups", "acl": "public-read"}],
  "databases": [{"label": "appdb", "engine": "mysql", "allow_list": ["0.0.0.0/0"]}],
  "instances": [{"label": "web-1", "ipv4": ["203.0.113.9"]}],
}


def test_linode_normalize_and_misconfig_findings():
    model = CI.normalize_linode(_LINODE)
    assert model["provider"] == "linode"
    findings = CI.analyze(model)
    cats = {t for f in findings for t in f["tags"]}
    assert "cloud_firewall_open_to_internet" in cats   # SSH 22 open to 0.0.0.0/0
    assert "cloud_public_resource" in cats             # public bucket + public db
    assert "cloud_admin_without_2fa" in cats           # read_write account access, tfa off
    # port 443 open to the world is NOT flagged (not a sensitive/admin port)
    fw = next(f for f in findings if "cloud_firewall_open_to_internet" in f["tags"])
    assert "22" in fw["evidence"] and "443" not in fw["title"]
    # every finding carries proof + a fix
    assert all(f.get("evidence") and f.get("remediation") for f in findings)


def test_linode_collect_fixture_and_blocked_without_token(monkeypatch):
    res = CI.collect("linode", fixture=_LINODE)
    assert res["blocked"] is False and res["provider"] == "linode" and res["findings"]
    monkeypatch.delenv("LINODE_TOKEN", raising=False)
    blocked = CI.collect("linode")
    assert blocked["blocked"] is True and "LINODE_TOKEN" in blocked["reason"]


def test_linode_token_never_appears_in_output():
    # the token is auth-only; a fixture collect carries no token, and the model/findings never store it
    res = CI.collect("linode", fixture=_LINODE)
    assert "secrettoken" not in str(res).lower() and "authorization" not in str(res).lower()


def test_linode_is_a_ready_provider_with_env_token(monkeypatch):
    monkeypatch.setenv("LINODE_TOKEN", "x")
    st = CI.live_enumeration_supported()
    assert "linode" in st["providers_ready"] and "linode" in st["live_collector_implemented"]


def _linode_router(fail=(), pages2=()):
    """Fake cloud_iam._linode_get: (ok,data,status) keyed by base path; `fail` paths error 500,
    `pages2` paths return two pages to exercise pagination."""
    responses = {
        "/account/users": {"data": [{"username": "student", "tfa_enabled": False}], "pages": 1, "results": 1},
        "/account/users/student/grants": {"global": {"account_access": "read_write"}},
        "/networking/firewalls": {"data": [{"id": 1, "label": "fw"}], "pages": 1, "results": 1},
        "/networking/firewalls/1/rules": {"inbound": [
            {"action": "ACCEPT", "ports": "22", "addresses": {"ipv4": ["0.0.0.0/0"]}}]},
        "/object-storage/buckets": {"data": [{"label": "b", "acl": "public-read"}], "pages": 1, "results": 1},
        "/linode/instances": {"data": [{"label": "web", "ipv4": ["203.0.113.9"]}], "pages": 1, "results": 1},
        "/databases/instances": {"data": [], "pages": 1, "results": 0},
    }

    def _get(path, token, timeout=20, retries=3):
        base = path.split("?")[0]
        if base in fail:
            return (False, None, 500)
        if base in pages2:
            page = 1
            if "page=2" in path:
                page = 2
            return (True, {"data": [{"label": "extra-%d" % page}], "pages": 2, "results": 2}, 200)
        return (True, responses.get(base, {"data": [], "pages": 1, "results": 0}), 200)
    return _get


def test_linode_live_complete_collection_reports_findings(monkeypatch):
    monkeypatch.setattr(CI, "_linode_get", _linode_router())
    res = CI.collect_linode_live("tok")
    assert res["blocked"] is False and res["partial"] is False
    assert res["manifest"]["complete"] is True and not res["manifest"]["failed"]
    cats = {t for f in res["findings"] for t in f["tags"]}
    assert "cloud_firewall_open_to_internet" in cats and "cloud_public_resource" in cats


def test_linode_partial_collection_is_never_reported_clean(monkeypatch):
    # a required endpoint fails -> the collection is PARTIAL; 0-or-fewer findings must not read as clean
    monkeypatch.setattr(CI, "_linode_get", _linode_router(fail=("/databases/instances",)))
    res = CI.collect_linode_live("tok")
    assert res["blocked"] is False and res["partial"] is True
    assert any(x["path"] == "/databases/instances" for x in res["manifest"]["failed"])
    assert "PARTIAL" in res["reason"] and "NOT be read as secure" in res["reason"]


def test_linode_total_failure_is_blocked_not_clean(monkeypatch):
    allreq = ("/account/users", "/networking/firewalls", "/object-storage/buckets",
              "/linode/instances", "/databases/instances")
    monkeypatch.setattr(CI, "_linode_get", _linode_router(fail=allreq))
    res = CI.collect_linode_live("tok")
    assert res["blocked"] is True and res["partial"] is True
    assert "NOT a clean posture" in res["reason"] and res["manifest"]["succeeded"] == 0


def test_linode_pagination_follows_all_pages(monkeypatch):
    monkeypatch.setattr(CI, "_linode_get", _linode_router(pages2=("/linode/instances",)))
    res = CI.collect_linode_live("tok")
    # two instance pages collected (extra-1 + extra-2)
    assert res["counts"]["instances"] == 2 and res["blocked"] is False


def test_linode_over_100_pages_is_not_complete(monkeypatch):
    # the API advertises 101 pages -> the cap is hit and the collection MUST be marked truncated,
    # never complete (CHAD edge bug).
    def _get(path, token, timeout=20, retries=3):
        base = path.split("?")[0]
        if base == "/linode/instances":
            return (True, {"data": [{"label": "i"}], "pages": 101, "results": 200}, 200)
        return (True, {"data": [], "pages": 1, "results": 0}, 200)
    monkeypatch.setattr(CI, "_linode_get", _get)
    res = CI.collect_linode_live("tok")
    assert res["partial"] is True and res["manifest"]["complete"] is False
    assert any(t.get("path") == "/linode/instances" and t.get("advertised_pages") == 101
               for t in res["manifest"]["truncated"])


def test_linode_advertised_count_mismatch_is_not_complete(monkeypatch):
    # API says results=5 for buckets but returns only 1 -> inconsistent -> NOT complete.
    def _get(path, token, timeout=20, retries=3):
        base = path.split("?")[0]
        if base == "/object-storage/buckets":
            return (True, {"data": [{"label": "b", "acl": "private"}], "pages": 1, "results": 5}, 200)
        return (True, {"data": [], "pages": 1, "results": 0}, 200)
    monkeypatch.setattr(CI, "_linode_get", _get)
    res = CI.collect_linode_live("tok")
    assert res["partial"] is True
    assert any(t.get("path") == "/object-storage/buckets" and t.get("advertised") == 5
               for t in res["manifest"]["truncated"])

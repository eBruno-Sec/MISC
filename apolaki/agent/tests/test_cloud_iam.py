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

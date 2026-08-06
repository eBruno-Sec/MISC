"""Cloud provider-policy gate (Codex Tier-1 #4): mutating/active cloud actions are default-denied, prohibited
wins over allowed, notification-required blocks, provider/region scope enforced — while the authorized
read-only inventory flow (Linode) keeps working under the default policy."""
import cloud_policy as C


def test_default_policy_allows_read_only_inventory():
    # the authorized Linode read-only posture must not regress
    d = C.gate("linode", "read_inventory")
    assert d["allowed"] is True and d["requires_approval"] is False
    assert C.gate("aws", "read_iam")["allowed"] is True


def test_mutating_actions_default_denied():
    # no explicit policy -> every write/active/destructive action is blocked by default
    assert C.gate("aws", "destructive_write")["allowed"] is False
    assert C.gate("aws", "delete")["allowed"] is False
    assert C.gate("gcp", "dos")["allowed"] is False
    assert C.gate("azure", "credential_bruteforce")["allowed"] is False


def test_prohibited_wins_over_allowed():
    pol = {"provider": "any", "allowed_actions": ["read_inventory", "write"],
           "prohibited_actions": ["write"], "requires_approval": [],
           "provider_notification": {"required": False}, "source": "test"}
    d = C.gate("aws", "write", policy=pol)
    assert d["allowed"] is False and "PROHIBITED" in d["reason"]


def test_requires_approval_blocks_without_and_allows_with_approval():
    d1 = C.gate("aws", "active_probe")
    assert d1["allowed"] is False and d1["requires_approval"] is True
    d2 = C.gate("aws", "active_probe", approval="ticket-123")
    assert d2["allowed"] is True and d2["requires_approval"] is True and d2["approval_id"] == "ticket-123"


def test_provider_scope_enforced():
    pol = {"provider": "aws", "allowed_actions": ["read_inventory"], "prohibited_actions": [],
           "requires_approval": [], "provider_notification": {"required": False}, "source": "test"}
    assert C.gate("aws", "read_inventory", policy=pol)["allowed"] is True
    d = C.gate("gcp", "read_inventory", policy=pol)
    assert d["allowed"] is False and "provider" in d["reason"]


def test_region_scope_enforced():
    pol = {"provider": "any", "regions": ["us-east-1"], "allowed_actions": ["read_inventory"],
           "prohibited_actions": [], "requires_approval": [],
           "provider_notification": {"required": False}, "source": "test"}
    assert C.gate("aws", "read_inventory", policy=pol, region="us-east-1")["allowed"] is True
    assert C.gate("aws", "read_inventory", policy=pol, region="eu-west-1")["allowed"] is False


def test_notification_required_blocks_until_provided():
    pol = {"provider": "any", "allowed_actions": ["read_inventory"], "prohibited_actions": [],
           "requires_approval": [], "provider_notification": {"required": True, "status": "missing"},
           "source": "test"}
    assert C.gate("aws", "read_inventory", policy=pol)["allowed"] is False
    pol2 = dict(pol, provider_notification={"required": True, "status": "provided"})
    assert C.gate("aws", "read_inventory", policy=pol2)["allowed"] is True


def test_default_is_not_in_allowed_denied():
    # an action nobody granted (and that isn't a known read-only action) is default-denied
    d = C.gate("aws", "some_novel_action")
    assert d["allowed"] is False and "default-deny" in d["reason"]


def test_collect_live_path_is_gated_but_fixture_is_not(monkeypatch):
    import cloud_iam
    # fixture (offline analysis) is NOT a live action -> never gated
    r = cloud_iam.collect("aws", fixture={"resources": []})
    assert r["blocked"] is False
    # force an explicit policy that prohibits read_inventory -> live linode collect is blocked by the gate
    pol = {"provider": "any", "allowed_actions": [], "prohibited_actions": ["read_inventory"],
           "requires_approval": [], "provider_notification": {"required": False}, "source": "test"}
    monkeypatch.setattr(C, "effective_policy", lambda provider=None: pol)
    r2 = cloud_iam.collect("linode", token="dummy")
    assert r2["blocked"] is True and "cloud-policy gate" in r2["reason"]

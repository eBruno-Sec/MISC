"""API inventory drift + version governance (Codex Tier-2 #10): runtime-only -> observation, spec-only ->
coverage gap (not vuln), version coexistence -> observation, off-scope archived not imported as live."""
import api_inventory as I


def _types(obs):
    return {o["type"] for o in obs}


def test_runtime_only_endpoint_becomes_observation():
    obs = I.reconcile(runtime=["/api/users", "/api/secret-admin"], documented=["/api/users"])
    undoc = [o for o in obs if o["type"] == "undocumented_runtime_endpoint"]
    assert undoc and undoc[0]["endpoint"] == "/api/secret-admin"
    assert undoc[0]["family"] == "api_inventory"        # inventory, not a vuln family


def test_spec_only_endpoint_is_coverage_gap_not_vuln():
    obs = I.reconcile(runtime=["/api/users"], documented=["/api/users", "/api/legacy-thing"])
    dead = [o for o in obs if o["type"] == "documented_dead_endpoint"]
    assert dead and dead[0]["confidence"] == "coverage_gap"


def test_v1_v2_coexistence_creates_versioning_observation():
    obs = I.reconcile(runtime=["/v1/orders", "/v2/orders"], documented=[])
    multi = [o for o in obs if o["type"] == "multiple_versions_exposed"]
    assert multi and multi[0]["endpoint"] == "/orders"
    assert "v1" in _types_join(multi[0]) and "v2" in _types_join(multi[0])


def _types_join(o):
    return o["note"]


def test_deprecated_version_flagged():
    obs = I.reconcile(runtime=["/v1/orders"], documented=["/v1/orders"])
    dep = [o for o in obs if o["type"] == "deprecated_version_exposed"]
    assert dep and dep[0]["confidence"] == "lead"


def test_off_scope_archived_not_imported_as_live():
    in_scope = lambda p: True                            # path-level scope always ok here...
    # archived endpoint filtered by an in_scope predicate that rejects it
    obs = I.reconcile(runtime=["/api/a"], documented=["/api/a"],
                      archived=["/api/evil"], in_scope=lambda p: "evil" not in p)
    assert all("evil" not in o["endpoint"] for o in obs)


def test_schema_drift():
    d = I.schema_drift(observed_fields=["id", "name", "is_admin"], spec_fields=["id", "name"], endpoint="/u")
    assert d["type"] == "schema_drift" and "is_admin" in d["extra_fields"]
    assert I.schema_drift(["id"], ["id"]) is None        # matching schema -> no drift


def test_third_party_dependency_apis():
    out = I.third_party_dependency_apis(["https://api.stripe.com/v1/charge", "https://app.local/x"],
                                        target_hosts=["app.local"])
    hosts = {o["endpoint"] for o in out}
    assert "api.stripe.com" in hosts and "app.local" not in hosts
    assert all(o["type"] == "third_party_dependency_api" for o in out)

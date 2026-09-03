"""Q-168. The gate that kept `run_cmdi` from ever being dispatched.

MEASURED before the fix, over the whole recorded corpus -- 6,193 query-string requests, 792
distinct param-bearing endpoints, 557 distinct parameter names:

    exact name match (the old rule)      1 endpoint   (0.1%)
    raw substring on the path          280 endpoints  (35.4%)   -- noise, not a rule
    anchored whole path segments         0 endpoints  (0.0%)
    token match on the NAME (the fix)    1 endpoint   (0.1%)

`run_cmdi` was dispatched zero times in 175 missions. An engine that claims RCE could not run, and
its false-positive oracle was hardened twice by someone who never checked that it executes.

The token rule costs the same 0.1% on that corpus while reaching `target_host`, which is what a
real application calls the parameter. These tests pin BOTH directions, because a gate that widens
until everything matches is not an improvement -- it is a different defect.
"""
import planner


def test_it_selects_the_name_a_real_application_actually_uses():
    assert planner.cmd_param_hit(["target_host"]), (
        "mutillidae's command-injection parameter is target_host; the old exact-match rule "
        "missed it, which is why run_cmdi was never dispatched")
    assert planner.cmd_param_hit(["cmd"])
    assert planner.cmd_param_hit(["host_name"])
    assert planner.cmd_param_hit(["ping_target"])
    assert planner.cmd_param_hit(["id", "dns_server"]), "any one parameter is enough"


def test_it_still_rejects_the_names_a_substring_rule_would_swallow():
    """The negative half. 'ip' lives inside recipient/description/zipcode, 'run' inside almost
    anything -- a substring rule would fire run_cmdi on a third of the internet."""
    for name in ["description", "recipient", "zipcode", "page", "username", "product_id",
                 "category", "prices", "current", "searchterm", "format", "email"]:
        assert not planner.cmd_param_hit([name]), (
            "%r must not select a command-injection probe" % name)


def test_an_empty_or_absent_parameter_list_selects_nothing():
    assert not planner.cmd_param_hit([])
    assert not planner.cmd_param_hit(None)


def test_the_rule_is_case_and_separator_insensitive():
    assert planner.cmd_param_hit(["Target-Host"])
    assert planner.cmd_param_hit(["TARGET_HOST"])
    assert planner.cmd_param_hit(["target.host"])


# --- the call site, not just the helper -------------------------------------------------------
# A mutant that reverted the planner to the old `p in _CMD_PARAM` SURVIVED the tests above: they
# pin the pure rule, and the pure rule can be perfect while nothing calls it. That is the same
# shape as a fix proven in isolation that does nothing in a mission. These drive the real planner.

def _state(urls):
    return {"mode": "full", "roots": ["t.local"], "done": set(),
            "recon": {"subdomains": ["t.local"],
                      "live_hosts": [{"url": "http://t.local:3000"}]},
            "urls": list(urls),
            "bases": {"t.local": "http://t.local:3000"},
            "intensity": "standard"}


def _tools_emitted(urls):
    import planner as _p
    state = _state(urls)
    done = state["done"]
    tools = []
    for _ in range(200):
        batch = _p.next_batch(state)
        if not batch:
            break
        for s in batch:
            done.add(s["key"])
            tools.append(s["tool"])
    return tools


def test_the_planner_actually_emits_run_cmdi_for_a_real_world_parameter_name():
    tools = _tools_emitted(["http://t.local:3000/index.php?page=dns-lookup.php&target_host=x"])
    assert "run_cmdi" in tools, (
        "the planner never scheduled run_cmdi for target_host -- this is the defect that left "
        "run_cmdi dispatched ZERO times in 175 missions")


def test_the_planner_does_not_emit_run_cmdi_for_ordinary_parameters():
    tools = _tools_emitted(["http://t.local:3000/shop?category=books&productId=7&searchTerm=hat"])
    assert "run_cmdi" not in tools, (
        "run_cmdi claims RCE; scheduling it on every ordinary parameter is a different defect")

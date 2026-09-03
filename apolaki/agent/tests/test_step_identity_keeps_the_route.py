"""Q-185. A step key that drops the query turns N distinct pages into one step.

THIS EXACT BUG HAS NOW APPEARED FOUR TIMES, in four different loops, and each fix looked complete:

    Q-172  surface.build_inventory keyed on (host, path)          45 pages -> 1 inventory entry
    Q-174  the form-discovery loop deduped on _abs(u)             45 pages -> 1 dedup slot
    Q-174  ...and its STEP KEY dropped the query as well          45 pages -> 1 step
    Q-185  the FORM-CAPTURE loop did both again                   38 pages -> 1 http_probe

The fourth is why mutillidae's command injection survived the first three. The page was crawled,
the planner's form-action dispatch works, and `_http_probe` captures that form perfectly when
called by hand:

    {"action": ".../index.php?page=dns-lookup.php", "method": "POST",
     "fields": ["target_host", "dns-lookup-php-submit-button"]}

The form engines were never told the form existed, because the page that declares it was
deduplicated away before anything fetched it.

`_abs` is `base + _path(u)` and `_path` discards the query. That is correct for normalising a
scheme and port, and wrong as an IDENTITY. So this is a general guard rather than a fifth
one-off: drive the real planner with route URLs that differ ONLY in their route value, and assert
that no tool receives them under a shared step key. A future loop that reaches for `_abs` or
`_path` to build an identity fails here instead of in a mission.
"""
import collections

import planner


ROUTES = ["dns-lookup.php", "upload-file.php", "login.php", "credits.php",
          "user-info.php", "add-to-your-blog.php"]


def _drive(urls):
    state = {"mode": "full", "roots": ["t.local"], "done": set(),
             "recon": {"subdomains": ["t.local"], "live_hosts": [{"url": "http://t.local"}]},
             "urls": list(urls), "bases": {"t.local": "http://t.local"},
             "intensity": "standard"}
    done, steps = state["done"], []
    for _ in range(400):
        batch = planner.next_batch(state)
        if not batch:
            break
        for s in batch:
            done.add(s["key"])
            steps.append(s)
    return steps


ROUTED = ["http://t.local/index.php?page=" + p for p in ROUTES]


def test_no_tool_collapses_distinct_route_pages_onto_one_step_key():
    """THE general guard. Two different pages must never share a step identity."""
    per_key = collections.defaultdict(set)
    for s in _drive(ROUTED):
        u = (s.get("input") or {}).get("url")
        if isinstance(u, str) and "?page=" in u:
            per_key[s["key"]].add(u)
    collisions = {k: sorted(v) for k, v in per_key.items() if len(v) > 1}
    assert not collisions, (
        "these step keys carry MORE THAN ONE distinct route page, so only one of them is ever "
        "executed: %r" % collisions)


def test_the_form_capture_probe_reaches_every_route_page():
    """The specific regression: a form is invisible until the page declaring it is fetched."""
    probed = {(s.get("input") or {}).get("url") for s in _drive(ROUTED)
              if s["tool"] == "http_probe"}
    probed = {u for u in probed if isinstance(u, str) and "?page=" in u}
    missing = [p for p in ROUTES if not any(p in u for u in probed)]
    assert not missing, (
        "these route pages are never http_probed, so their forms never reach recon['forms'] and "
        "the body-injection engines cannot see them: %r" % missing)


def test_a_shared_path_with_different_routes_yields_different_steps():
    """Stated as the property rather than the symptom: same path, different route -> two steps."""
    steps = _drive(["http://t.local/index.php?page=a.php", "http://t.local/index.php?page=b.php"])
    keys = {s["key"] for s in steps
            if isinstance((s.get("input") or {}).get("url"), str)
            and "?page=" in s["input"]["url"]}
    assert len(keys) >= 2, "two distinct route pages produced %d step key(s)" % len(keys)

"""Q-104 — phase A fed itself, and starved every later phase.

Found in the field. The operator's 2026-08-27 Shopify engagement, two snapshots of ONE mission:

    22:10 UTC   12 tools dispatched, run_transport_posture had run,  67 calls per recon tool
    03:49 UTC    7 tools dispatched, ALL passive recon,             286 calls per recon tool
                 1000 tool invocations, 6 of 9 in-scope targets never probed, 0 active engines

`_graph_primary_state` makes a recon root out of EVERY host node in the graph. Phase A runs seven
passive tools per root, and what those tools discover becomes more host nodes. Phase A also ends with
`if a: return a`, so while a single fresh recon step exists NO LATER PHASE RUNS. Every other phase in
`planner.py` had a cap; this one, the only self-feeding one, had none.

Q-100 did not cause this, it UNMASKED it: before Q-100 a regex-only scope produced an empty
`in_scope`, the graph was never seeded, and phase A had nothing to expand.

THE TEST THAT MATTERS IS `test_a_growing_graph_still_reaches_a_later_phase`. Capping the fan-out is
only half the point -- the reason the cap exists is that the mission has to get past recon and
actually attack something.
"""
import planner


OPERATOR = ["shopify.com", "shop.app"]


def _state(hosts, **kw):
    st = {"mode": "active", "roots": list(hosts), "done": set(), "recon": {},
          "urls": [], "bases": {}, "scope_roots": list(OPERATOR)}
    st.update(kw)
    return st


def _recon_targets(batch):
    return {s["input"].get("domain") for s in batch
            if s["tool"] in ("run_subfinder", "run_crtsh", "run_wayback",
                             "run_dns", "run_asn", "run_github_recon")}


# A LITERAL, deliberately not `planner.CAP_RECON_ROOTS`. My first version of this file asserted
# against the constant it was testing, so raising the constant raised the assertion with it and a
# mutant that removed the cap entirely survived all four tests. A bound that tracks the thing it
# bounds is not a bound.
MAX_REASONABLE_RECON_ROOTS = 40


def test_the_recon_fanout_is_capped():
    """41 roots is what the field mission reached. Unbounded, that is 41 x 7 tools per cycle."""
    hosts = ["h%02d.example.com" % i for i in range(41)] + OPERATOR
    targets = _recon_targets(planner.next_batch(_state(hosts)))
    assert len(targets) <= MAX_REASONABLE_RECON_ROOTS, len(targets)


def test_the_operators_own_assets_are_never_the_ones_trimmed():
    """The cap must trim DISCOVERED hosts. An operator asset crowded out by a CDN's subdomains would
    be a worse bug than the fan-out: the mission would skip the thing it was pointed at."""
    hosts = ["z%03d.cdn.example.com" % i for i in range(200)] + OPERATOR
    targets = _recon_targets(planner.next_batch(_state(hosts)))
    for asset in OPERATOR:
        assert asset in targets, "operator asset %r was trimmed: %r" % (asset, sorted(targets)[:5])


def test_a_small_engagement_is_not_capped_at_all():
    """Non-vacuity. If the cap bit at normal sizes it would be silently shrinking ordinary missions,
    and every other assertion here would still pass."""
    hosts = ["a.example.com", "b.example.com"] + OPERATOR
    targets = _recon_targets(planner.next_batch(_state(hosts)))
    assert targets == set(hosts), targets


def test_a_growing_graph_still_reaches_a_later_phase():
    """THE POINT. Phase A returns early while it has fresh work, so an ever-growing root set meant
    the mission never attacked anything -- fourteen hours of passive recon and zero active engines.

    With the fan-out bounded, marking phase A's steps done must let the planner move on. If this ever
    fails, the mission is stuck in recon again no matter what the cap says.

    THE GRAPH MUST GROW BETWEEN BATCHES, and my first version of this test did not do that. It
    marked one whole batch done at once, which drains even with NO cap, so the mutant survived. The
    real mission's roots grew as recon discovered hosts, and that feedback IS the defect -- a test
    that holds the root set still is testing a mission that never existed.
    """
    hosts = list(OPERATOR)
    done, discovered = set(), 0
    for _ in range(12):                      # bounded: a fixed budget, not "until it works"
        batch = planner.next_batch(_state(hosts, done=done,
                                          urls=["https://shopify.com/search?q=apple"]))
        if not batch:
            break
        if not _recon_targets(batch):        # a non-recon batch: phase A has drained
            return
        done |= {s["key"] for s in batch}
        # Recon "finds" 30 more hosts per round, exactly as subfinder/crtsh did on the real run.
        hosts += ["d%04d.example.com" % (discovered + i) for i in range(30)]
        discovered += 30
    raise AssertionError(
        "phase A never drained after %d discovered hosts -- the planner cannot reach an active "
        "phase, which is the fourteen-hour Shopify mission" % discovered)

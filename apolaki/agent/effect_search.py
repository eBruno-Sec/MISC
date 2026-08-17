"""
Forward search over engine effects (T8) — the half of planning Apolaki did not have.

The existing planner answers "what is applicable RIGHT NOW": it filters techniques whose preconditions the
current observations already satisfy. That is one of the three things *Automated Planning* §4.2 says a
planner needs. The other two — a goal test, and a successor function that says what state an action
PRODUCES — had no representation at all, because effects were never declared. `engine_descriptor` declares
them; this module searches over them.

The concrete difference, in Apolaki's own vocabulary:

    filter:  observations={has_login}          -> [sqli_auth_bypass, csrf, weak_password_reset, ...]
    search:  observations={has_login}, goal=authenticated
             -> sqli_auth_bypass ESTABLISHES authenticated, so a path exists, and its length is 1

The filter can never produce the second answer. It cannot say "this goal is two steps away", cannot say
"nothing you can reach makes this goal achievable", and cannot warn that the step you are about to take
destroys a condition a later step needs.

**Negative effects are the reason this is not just a graph walk.** §4.4's Sussman anomaly is the standing
counterexample: achieving two goals independently and concatenating the plans does not work when the second
plan deletes what the first established. `plan()` applies `invalidates` when it expands a state, so a path
through `weak_password_reset` genuinely loses `authenticated` rather than silently keeping it.

**Additive by construction.** Nothing here is called by the existing precondition path; `plan_techniques`
is untouched. This adds an answer Apolaki could not previously give, and cannot change an answer it already
gives. Pure and deterministic throughout — same inputs, same plan, so a scan stays replayable.

**Known limit, stated rather than hidden.** An ALWAYS-ON engine declares no observations in
`_PRECONDITIONS`, because the thing that reaches it — the persona artery, the sweep, a tool-level gate —
is not an observation. The search therefore treats it as applicable in every state, so a plan routed
through one is conditional on that path's own requirements (configured credentials, a reachable browser)
which live outside the observation vocabulary entirely. `plan()` marks those steps so a consumer can see
the assumption instead of inheriting it silently.
"""
from __future__ import annotations

from collections import deque

# A search over 82 engines is tiny, but a bound keeps a pathological registry from hanging a request.
MAX_EXPANSIONS = 20000


def _actions(descriptors):
    """Only engines that actually change the state are search operators. An engine with no effects is a
    leaf: worth running for its findings, never worth running to reach something else. Pure."""
    return sorted((d for d in descriptors.values() if d["establishes"] or d["invalidates"]),
                  key=lambda d: d["id"])


def applicable(descriptors, observations) -> list:
    """Engine ids whose preconditions hold in this state — the existing filter, restated over descriptors
    so search and filter cannot disagree. Pure."""
    obs = set(observations or ())
    return sorted(d["id"] for d in descriptors.values()
                  if d["requires"] and all(r in obs for r in d["requires"]))


def successor(descriptors, observations, technique_id) -> frozenset:
    """The state after running `technique_id`. Adds `establishes`, then removes `invalidates`.

    Removal comes SECOND and deliberately: a technique that both establishes and invalidates the same
    observation (`weak_password_reset` rotates the credential it just used) must end without it. Getting
    this order wrong is precisely the deleted-condition bug §4.4 warns about, and it would be invisible —
    the planner would simply produce plans that fail in the field. Pure."""
    d = descriptors.get(technique_id)
    if not d:
        return frozenset(observations or ())
    obs = set(observations or ())
    obs.update(d["establishes"])
    obs.difference_update(d["invalidates"])
    return frozenset(obs)


def _routing(descriptors, steps):
    """({step: [engine, ...]}, [unroutable step, ...]) for a plan's steps.

    Q-066/Q-065. A step names a TECHNIQUE; an executor needs an ENGINE, and until the descriptor
    carried `engines` there was no route between the two — which is how a mission's autonomy loop came
    to recommend a capability it had no way to dispatch.

    A descriptor with no `engines` KEY AT ALL is reported as neither routed nor unroutable: absence of
    a measurement is not a negative result, and the synthetic descriptors the algorithm tests are built
    from legitimately have no routing. Only an `engines` key that is present and EMPTY means "this
    technique has no engine". Pure."""
    eng, unroutable = {}, []
    for s in steps:
        d = descriptors.get(s) or {}
        if "engines" not in d:
            continue
        e = list(d.get("engines") or [])
        eng[s] = e
        if not e:
            unroutable.append(s)
    return eng, sorted(set(unroutable))


def plan(descriptors, observations, goal, *, max_depth: int = 6) -> dict:
    """Shortest engine sequence to `goal`, annotated with whether its steps can actually be DISPATCHED.

    `_plan_core` answers the planning question; this wrapper answers the execution one. A plan that is
    `reachable` but not `dispatchable` is the honest statement of Q-065's symptom: the search found a
    real path and the platform has no engine for one of its steps. Silently returning such a plan is
    what let a ranked capability look actionable when nothing could run it. Pure."""
    r = _plan_core(descriptors, observations, goal, max_depth=max_depth)
    eng, unroutable = _routing(descriptors, r["plan"])
    r["engines"] = eng
    r["unroutable"] = unroutable
    r["dispatchable"] = bool(r["reachable"]) and not unroutable
    return r


def _plan_core(descriptors, observations, goal, *, max_depth: int = 6) -> dict:
    """Shortest sequence of engines that reaches `goal` from `observations`, or an honest failure.

    Breadth-first, so the first path found is the shortest — Automated Planning §4.2's forward search with
    the trivial admissible heuristic. Ties break on technique id so the plan is reproducible.

    Returns {reachable, plan, depth, reason, assumes}. An unreachable goal is a RESULT, not an error: "no
    sequence of engines can establish this" is exactly the honest exhausted-path answer the existing planner
    already gives when the evidence supports nothing.

    `assumes` lists steps that are always-on rather than evidence-gated — their real requirements are not
    observations, so the plan holds only if those paths are actually available. Pure."""
    start = frozenset(observations or ())
    if goal in start:
        return {"reachable": True, "plan": [], "depth": 0, "reason": "already established", "assumes": []}

    def _assumes(steps):
        return sorted({s for s in steps if not descriptors[s]["requires"]})

    acts = _actions(descriptors)
    seen, queue, expansions = {start}, deque([(start, [])]), 0
    best, limit = None, max_depth
    while queue:
        state, path = queue.popleft()
        if len(path) >= limit:
            continue
        for a in acts:
            if expansions >= MAX_EXPANSIONS:
                # Do not throw away a plan already found. Hitting the bound means the search may not have
                # proven this one OPTIMAL, but reporting "unreachable" when a valid sequence is in hand
                # would be a false negative — the worst answer a planner can give.
                if best:
                    _, _, step = best
                    return {"reachable": True, "plan": step, "depth": len(step),
                            "assumes": _assumes(step),
                            "reason": "%s establishes %s (search bound reached; may not be shortest)"
                                      % (step[-1], goal)}
                return {"reachable": False, "plan": [], "depth": 0, "assumes": [],
                        "reason": "search bound reached (%d expansions)" % MAX_EXPANSIONS}
            # An action is only available where its own preconditions hold in THIS state.
            if a["requires"] and not all(r in state for r in a["requires"]):
                continue
            expansions += 1
            nxt = successor(descriptors, state, a["id"])
            if nxt == state:
                continue
            step = path + [a["id"]]
            if goal in nxt:
                # Do NOT return on the first hit. Among plans of the SAME length, one routed through an
                # always-on engine is weaker than a fully evidence-gated one: it silently depends on
                # configured credentials or a reachable browser. Keep the shortest, then the least-assuming
                # — otherwise the search recommends the weaker plan whenever it happens to sort first.
                cand = (len(step), len(_assumes(step)), step)
                if best is None or cand < best:
                    best, limit = cand, len(step)   # never look deeper than the best found
                continue
            if nxt in seen:
                continue
            seen.add(nxt)
            queue.append((nxt, step))
    if best:
        _, _, step = best
        return {"reachable": True, "plan": step, "depth": len(step),
                "reason": "%s establishes %s" % (step[-1], goal), "assumes": _assumes(step)}
    return {"reachable": False, "plan": [], "depth": 0, "assumes": [],
            "reason": "no engine sequence establishes '%s' from the current evidence" % goal}


def unlocks(descriptors, observations, technique_id) -> list:
    """Engine ids that become applicable BECAUSE this one confirmed — the planner's argument for running a
    technique that finds nothing directly. Pure."""
    before = set(applicable(descriptors, observations))
    after = set(applicable(descriptors, successor(descriptors, observations, technique_id)))
    return sorted(after - before)


def breaks(descriptors, observations, technique_id) -> list:
    """Engine ids that STOP being applicable because this one ran. The §4.4 warning, per action: if this is
    non-empty, run those engines first or accept losing them.

    Excludes the technique itself. An engine that deletes its own precondition — `weak_password_reset`
    consumes the login it just used — always appears in its own `before - after`, which is arithmetically
    true and useless for ordering: "run rotate before rotate" is not advice. Reporting it would bury the
    real conflicts in self-references. Pure."""
    before = set(applicable(descriptors, observations))
    after = set(applicable(descriptors, successor(descriptors, observations, technique_id)))
    return sorted((before - after) - {technique_id})


def frontier(descriptors, observations) -> dict:
    """Everything the effects model can say about the current state, in one pass — what is runnable now,
    what each runnable engine would unlock or break, and which observations are reachable at all.

    This is the shape a planner consumer wants: not a single plan, but the decision surface. Pure."""
    obs = frozenset(observations or ())
    now = applicable(descriptors, obs)
    goals = sorted({g for d in descriptors.values() for g in d["establishes"]} - set(obs))
    _, unroutable_now = _routing(descriptors, now)
    return {
        "observations": sorted(obs),
        "applicable_now": now,
        # Applicable but not dispatchable. The decision surface must show this or a consumer reads
        # "runnable now" and finds nothing to run — the Q-065 symptom, one layer up.
        "unroutable_now": unroutable_now,
        "reachable_goals": {g: plan(descriptors, obs, g) for g in goals},
        "consequences": {t: {"unlocks": unlocks(descriptors, obs, t), "breaks": breaks(descriptors, obs, t)}
                         for t in now if descriptors[t]["establishes"] or descriptors[t]["invalidates"]},
    }

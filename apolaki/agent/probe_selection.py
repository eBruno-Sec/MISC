"""
Probe selection — a budget that can be argued SAFE (T3).

*practical model-based testing* §4.2.3 and *Automated Planning* §4.2.1 together name the problem with how
Apolaki currently bounds its probe space. Engines take the first N of something — `params[:8]`,
`max_candidates=3`, `max_probes=12`. A first-N cut is not a criterion: it cannot say what it covered, it
silently drops whole regions, and its coverage depends on dictionary ordering rather than on anything about
the target.

Automated Planning §4.2.1 gives the vocabulary. A pruning technique is **safe** when it is guaranteed not
to prune every solution, and **strongly safe** when at least one optimal solution survives. "The first 12"
is neither, and cannot be shown to be either.

**Pairwise** (practical MBT §4.2.3) is the replacement. Instead of every combination of
parameter × payload × encoding — which is unaffordable, and MBT §8.1.1's point that full path coverage
"will ruin your company" applies exactly here — cover every PAIR of values at least once. That is a stated
criterion, it is checkable after the fact, and empirically most defects are triggered by one factor or the
interaction of two.

What this module does NOT claim: pairwise is not exhaustive, so it is not *safe* in the strict sense for
a defect that needs three specific factors at once. It is a declared, measurable budget instead of an
arbitrary one, and `describe()` states which it is so a coverage report can be honest about the difference.

Pure and deterministic — same inputs, same order out, so a scan stays replayable.
"""
from __future__ import annotations

from itertools import combinations, product


def full_grid(factors: dict) -> list:
    """Every combination. Present so the cost pairwise avoids is visible and testable. Pure."""
    if not factors:
        return []
    names = list(factors)
    return [dict(zip(names, combo)) for combo in product(*(factors[n] for n in names))]


def pairwise(factors: dict, *, max_cases: int = 0) -> list:
    """A set of cases covering every PAIR of values across every pair of factors, at least once.

    Greedy set-cover: repeatedly take the candidate case that covers the most still-uncovered pairs. Not
    the minimal set (that is NP-hard) but deterministic, close, and — unlike a first-N cut — it can state
    exactly what it covers. Pure.

    A single factor has no pairs, so its values are returned as individual cases rather than nothing."""
    names = [n for n in factors if factors[n]]
    if not names:
        return []
    if len(names) == 1:
        n = names[0]
        return [{n: v} for v in factors[n]]

    # Every (factor_a, value_a, factor_b, value_b) that must appear together at least once.
    # MUST go through _pair_key: combinations() yields factors in declaration order while _pair_key
    # normalises lexicographically, so building with raw tuples and discarding with normalised ones
    # removes nothing and the loop never terminates.
    required = set()
    for a, b in combinations(names, 2):
        for va, vb in product(factors[a], factors[b]):
            required.add(_pair_key(a, va, b, vb))

    cases = []
    while required:
        # SEED from one still-uncovered pair. This is what guarantees progress: the seed pair is by
        # definition uncovered, so every iteration removes at least one and the loop must terminate.
        a, va, b, vb = sorted(required, key=lambda t: (t[0], str(t[1]), t[2], str(t[3])))[0]
        case = {a: va, b: vb}
        # Fill the remaining factors greedily: take the value closing the most pairs against what is
        # already assigned in this case.
        for n in names:
            if n in case:
                continue
            pick, pick_cover = factors[n][0], -1
            for v in factors[n]:
                cover = sum(1 for m, val in case.items() if _pair_key(n, v, m, val) in required)
                if cover > pick_cover:
                    pick, pick_cover = v, cover
            case[n] = pick
        cases.append(case)
        for x, y in combinations(sorted(case), 2):
            required.discard(_pair_key(x, case[x], y, case[y]))
        if max_cases and len(cases) >= max_cases:
            break
    return cases


def _pair_key(fa, va, fb, vb):
    """Order-independent key for a factor-value pair. Pure."""
    return (fa, va, fb, vb) if fa <= fb else (fb, vb, fa, va)


def coverage(factors: dict, cases: list) -> dict:
    """What a selection actually covered — the number a first-N cut can never produce. Pure."""
    names = [n for n in factors if factors[n]]
    required = set()
    for a, b in combinations(names, 2):
        for va, vb in product(factors[a], factors[b]):
            required.add(_pair_key(a, va, b, vb))
    seen: set = set()
    for c in cases or []:
        for x, y in combinations(sorted(k for k in c if k in factors), 2):
            seen.add(_pair_key(x, c[x], y, c[y]))
    total = len(required)
    hit = len(required & seen)
    return {"pairs_total": total, "pairs_covered": hit,
            "pair_coverage_pct": round(100.0 * hit / total, 1) if total else 100.0,
            "cases": len(cases or []), "full_grid_cases": len(full_grid(factors))}


def describe(factors: dict, cases: list) -> str:
    """A sentence the coverage report can print. States the criterion AND its limit — an unstated cutoff
    is the coverage-debt problem this module exists to remove.

    The Automated Planning §4.2.1 label is included rather than left to the reader: "12 of 48 cases" reads
    like a shortfall, when the honest statement is that the pruning is DECLARED — it covers every value
    pair and misses only 3-way interactions. Naming the safety class is the difference between a budget
    that can be argued and one that merely sounds small."""
    c = coverage(factors, cases)
    return ("pairwise selection: %d cases cover %d/%d value pairs (%.1f%%) versus %d for the full grid. "
            "Every pair of factor values is exercised at least once; combinations requiring THREE specific "
            "values simultaneously are not, so this is a declared budget, not exhaustive coverage. "
            "Pruning class: %s."
            % (c["cases"], c["pairs_covered"], c["pairs_total"], c["pair_coverage_pct"],
               c["full_grid_cases"], safety_label("pairwise")))


def safety_label(strategy: str) -> str:
    """Automated Planning §4.2.1 vocabulary, applied to a selection strategy. Pure."""
    return {
        "pairwise": "declared — every value pair is covered; 3-way interactions are not",
        "full_grid": "safe — nothing is pruned",
        "first_n": "NOT safe — an arbitrary prefix; coverage depends on input ordering and is unstated",
    }.get(strategy, "unknown")

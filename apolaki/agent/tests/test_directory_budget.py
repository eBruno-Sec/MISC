"""Q-184. One exposed tree must not spend the whole directory budget.

MEASURED on a real mission's 549-URL surface. `directory_candidates` returned its full 40 and
TWENTY-ONE of them were `.git` internals:

    .git/branches  .git/hooks  .git/info  .git/logs  .git/logs/refs  .git/logs/refs/heads
    .git/objects/09  .git/objects/15  .git/objects/37  .git/objects/3e  .git/objects/6a ...

Those hold binary blobs and nothing harvestable, and they sort early, so `passwords` was not merely
ranked low -- it was ABSENT. `/passwords/accounts.txt`, which publishes 23 working logins, went
unharvested on a mission that had already fetched that very directory listing three times.

The engine was right every time it reported one file. Same shape as every other budget defect in
this project: the work was starved, not broken.

Breadth-first is the general answer. Every distinct top-level area contributes one directory before
any area contributes a second, so depth costs a tree its OWN slots instead of everyone else's.
"""
import exposure_tool as exp


def _git_flood():
    """A real .git tree as served by an exposed repository, plus ordinary app directories."""
    deep = ["http://t.local/.git/objects/%02x/x" % i for i in range(24)]
    deep += ["http://t.local/.git/%s/x" % s for s in
             ("branches", "hooks", "info", "logs", "refs", "logs/refs", "refs/heads")]
    app = ["http://t.local/documentation/a", "http://t.local/passwords/a",
           "http://t.local/classes/a", "http://t.local/javascript/a",
           "http://t.local/phpmyadmin/a", "http://t.local/includes/a"]
    return deep + app


def test_one_deep_tree_cannot_crowd_out_the_application():
    """THE regression: `passwords` must survive an exposed .git repository."""
    got = exp.directory_candidates("http://t.local", _git_flood())
    assert "passwords" in got, (
        "an exposed .git tree spent the budget and the app's own directories were dropped: %r"
        % got[:20])


def test_the_flooding_tree_is_still_represented():
    """Negative control. Starving the tree instead would be the opposite defect -- `.git` is a real
    finding and must still be reachable."""
    got = exp.directory_candidates("http://t.local", _git_flood())
    assert any(d.startswith(".git") for d in got), got[:20]


def test_no_single_area_takes_more_than_its_share():
    got = exp.directory_candidates("http://t.local", _git_flood())
    git = [d for d in got if d.startswith(".git")]
    assert len(git) < len(got) // 2, (
        "one area holds %d of %d slots" % (len(git), len(got)))


def test_every_observed_area_appears_before_any_area_repeats():
    """The breadth-first property itself, stated directly."""
    got = exp.directory_candidates("http://t.local", _git_flood())
    areas, first_repeat = [], None
    for i, d in enumerate(got):
        a = d.split("/", 1)[0]
        if a in areas and first_repeat is None:
            first_repeat = i
        areas.append(a)
    distinct_before_repeat = len(set(areas[:first_repeat])) if first_repeat else len(set(areas))
    assert distinct_before_repeat >= 6, (
        "only %d distinct areas were reached before one repeated: %r"
        % (distinct_before_repeat, got[:12]))


def test_the_limit_is_still_respected():
    got = exp.directory_candidates("http://t.local", _git_flood(), limit=9)
    assert len(got) == 9, len(got)


def test_no_observed_urls_degrades_to_the_guess_list():
    """Backward compatibility: passing nothing must behave exactly as before."""
    got = exp.directory_candidates("http://t.local", None)
    assert got[:4] == [d.strip("/") for d in list(exp.DIR_CANDIDATES)[:4]], got[:4]


def test_no_duplicates():
    got = exp.directory_candidates("http://t.local", _git_flood() + _git_flood())
    assert len(got) == len({d.lower() for d in got}), got


def test_breadth_first_still_spends_the_whole_budget():
    """The other half, and a mutant that only ever took ONE directory per area survived without it.

    Breadth-first must not become breadth-ONLY: once every area has contributed, the remaining
    budget goes to depth. A version that stops after the first round returns as many candidates as
    there are areas -- on a two-area surface that is 2 instead of 40, which would starve the
    harvester far worse than the flood it replaced.
    """
    urls = (["http://t.local/docs/%d/x" % i for i in range(30)]
            + ["http://t.local/app/%d/x" % i for i in range(30)])
    got = exp.directory_candidates("http://t.local", urls, limit=40)
    assert len(got) == 40, (
        "only %d candidates from a 60-directory surface with a budget of 40 -- breadth-first "
        "became breadth-only and the depth was dropped: %r" % (len(got), got))
    docs = [d for d in got if d.startswith("docs")]
    assert len(docs) > 1, "no area was ever revisited, so the budget went unspent: %r" % got[:12]

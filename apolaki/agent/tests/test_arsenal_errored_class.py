"""Q-063 - the Arsenal SUMMARY must not merge "ran and errored" into "ran and found nothing".

In the four-way classification of engine outcomes, **"ran and errored" is the most valuable class**:
a broken engine is an invisible false negative, and the reader has no way to know the target was
never actually tested. **"Ran and found nothing" is the class that means "nothing to see here."**
The Arsenal-coverage summary buried the former inside the latter, so a client reading the summary -
which exists precisely so they do not have to read the 46-row table - was told a broken engine had
delivered a clean result.

Same merge-two-classes defect as the `blocked_by_mode` one fixed a level down: two classes with
OPPOSITE fixes (fix the engine / nothing to fix) reported as one number.

THE FIXTURE IS NOT INVENTED. `tool_ledger_57cc3b49.json` is the verbatim output of
`main._tool_ledger("57cc3b49")` read out of the live mission DB - the same `mode=active`,
`strategy=deterministic` Juice Shop mission measured in `docs/handoff/arsenal2.md`. Three defects in
one session came from invented fixtures making vacuous tests pass, including a tool-ledger fixture
with the mode string in the wrong key, so a guard never fired in a single real report while every
test stayed green. Everything asserted here is asserted against a ledger the product actually
produced.

MEASURED on that ledger, before the fix:
    {'dispatched': 46, 'silent': 33, 'not_dispatched': 66, 'blocked_by_mode': 31}
    failed  tools counted as SILENT: ['fetch_openapi']            <- status: "failed", 10/10 calls
    skipped tools counted as SILENT: ['run_github_recon',         <- BBH_GITHUB_TOKEN unset
                                      'run_transport_posture']    <- every target out of scope
and after:
    silent 30, errored 1, skipped 2   -- a RE-PARTITION, not a re-count; the sum is unchanged.
"""
import json
import os

import report

_FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tool_ledger_57cc3b49.json")


def _real_ledger():
    with open(_FIXTURE, encoding="utf-8") as fh:
        return json.load(fh)


def _row(led, tool):
    return next(t for t in led["tools"] if t["tool"] == tool)


# ── positive control: the apparatus is looking at something real ─────────────
def test_the_fixture_really_is_a_mission_ledger_with_all_three_statuses():
    """Every zero below needs an apparatus proven to be looking. If the fixture had no failed row,
    a passing `errored` assertion would prove nothing at all."""
    led = _real_ledger()
    statuses = {}
    for t in led["tools"]:
        statuses[t["status"]] = statuses.get(t["status"], 0) + 1
    assert statuses == {"executed": 42, "skipped": 3, "failed": 1}, statuses
    assert led["mode"] == "active" and led["strategy"] == "deterministic"
    assert _row(led, "fetch_openapi")["status"] == "failed"
    assert _row(led, "fetch_openapi")["calls"] == 10
    assert _row(led, "fetch_openapi")["findings"] == 0
    # ...and the producer's own words for why, so the class is not a guess.
    assert "not valid JSON" in _row(led, "fetch_openapi")["note"]


# ── THE defect ───────────────────────────────────────────────────────────────
def test_an_engine_that_ERRORED_is_not_reported_as_ran_and_found_nothing():
    """THE assertion. `fetch_openapi` failed on 10 of 10 dispatches and the summary called it clean.

    `arsenal_gap()` defined silence as `calls > 0 and findings == 0`, which is equally true of a
    clean engine, a broken engine and a skipped one. It never read `status`, which the producer has
    always emitted.
    """
    gap = report.arsenal_gap(_real_ledger())
    assert "fetch_openapi" not in gap["silent"], (
        "an engine whose ledger status is `failed` is being counted as a clean result -- "
        "the single most valuable class merged into the one that means 'nothing to see here'")
    assert "errored" in gap, "arsenal_gap() reports no errored class at all"
    assert gap["errored"] == ["fetch_openapi"], gap["errored"]


def test_a_dispatched_engine_that_TESTED_NOTHING_is_not_a_clean_result_either():
    """Same shape, different class. `run_github_recon` skipped for a missing token and
    `run_transport_posture` had every target refused by scope. Neither tested anything, and both
    were counted as coverage. Their fixes differ from each other AND from a clean result."""
    gap = report.arsenal_gap(_real_ledger())
    assert gap["skipped"] == ["codeintel.review_source_tree", "run_github_recon",
                              "run_transport_posture"], gap["skipped"]
    for name in ("run_github_recon", "run_transport_posture"):
        assert name not in gap["silent"], name


# ── negative controls ────────────────────────────────────────────────────────
def test_an_engine_that_GENUINELY_RAN_CLEAN_is_still_reported_as_silent():
    """The negative control that stops this fix from being a blanket re-label. `run_dom_trace` made
    20 calls, returned on all of them and found nothing -- that is a RESULT and must still read as
    one. A fix that empties the silent class would be worse than the defect."""
    gap = report.arsenal_gap(_real_ledger())
    for clean in ("run_dom_trace", "run_dom_audit", "run_sqli", "run_xpath", "check_takeover"):
        assert clean in gap["silent"], clean
        assert clean not in gap["errored"] and clean not in gap["skipped"], clean
    assert len(gap["silent"]) == 30, gap["silent"]


def test_an_engine_that_PRODUCED_FINDINGS_is_in_none_of_the_three():
    """`run_katana` produced 67 findings. It is neither silent, nor errored, nor skipped."""
    gap = report.arsenal_gap(_real_ledger())
    for productive in ("run_katana", "run_authz_matrix", "http_probe", "run_xss"):
        assert productive not in gap["silent"], productive
        assert productive not in gap["errored"], productive
        assert productive not in gap["skipped"], productive


def test_a_ledger_row_with_NO_status_is_not_retro_labelled_broken():
    """Archived ledgers predate the `status` field. A missing status is not evidence of failure, so
    such a row keeps the old classification. Retro-labelling silence as error would manufacture
    exactly the false alarm this ticket exists to remove, in the opposite direction."""
    legacy = {"mode": "active", "strategy": "deterministic",
              "tools": [{"tool": "run_sqli", "calls": 12, "findings": 0}]}
    gap = report.arsenal_gap(legacy)
    assert gap["silent"] == ["run_sqli"]
    assert gap["errored"] == [] and gap["skipped"] == []


# ── the class-sum invariant the arsenal lane asserts on every run ────────────
def test_the_classes_still_sum_to_the_REGISTRY_DENOMINATOR():
    """The arsenal lane asserts the classes sum to the registered-engine denominator on every run
    (111 when this was written; 110 since Q-050 deleted `run_nosqlmap`). This fix is a RE-PARTITION
    of the dispatched set, so the sum must track the registry: three engines moved out of `silent`
    and nothing else changed.

    A double-count or a dropped row breaks this even though every per-engine assertion above would
    still pass, which is why it is asserted as an arithmetic identity and not as a list.
    """
    import tools as _t
    registered = set(_t.TOOL_PERMISSIONS)
    gap = report.arsenal_gap(_real_ledger())
    assert not gap["error"], gap["error"]

    blocked = set(gap["blocked_by_mode"])
    never = set(gap["not_dispatched"]) - blocked
    silent = set(gap["silent"]) & registered
    errored = set(gap["errored"]) & registered
    skipped = set(gap["skipped"]) & registered

    # the three dispatched classes must be disjoint, or the sum lies while looking right
    assert not (silent & errored) and not (silent & skipped) and not (errored & skipped)

    dispatched_reg = registered & set(gap["dispatched"])
    assert dispatched_reg | set(gap["not_dispatched"]) == registered, (
        "precondition: every registered engine is either dispatched or not-dispatched")
    productive = dispatched_reg - (silent | errored | skipped)

    # summed as LENGTHS, not as a union -- a double-count has to be caught, not absorbed
    total = (len(blocked) + len(never) + len(silent) + len(errored)
             + len(skipped) + len(productive))
    assert total == len(registered), (
        "classes sum to %d, registry denominator is %d" % (total, len(registered)))
    # the measured split on this mission, so a silent drift in any one class is visible
    assert (len(blocked), len(never), len(silent), len(errored), len(skipped), len(productive)) == \
           (13, 54, 30, 1, 2, 12)
    # never 52 -> 54: cycle 20 registers two engines that did not exist on the recorded
    # mission, `run_rendered_forms` (Q-158) and `run_nosqli_body` (Q-155). They land in
    # `never` because that mission predates them, which is the honest class for an engine
    # the run never had. Every other class is unchanged, which is the point of pinning the
    # split rather than only the sum.
    # Q-052 moved 25 engines INTRUSIVE -> ACTIVE, so 18 of them left `blocked` and arrived in
    # `never` on this mission: 31->13 and 35->53. THE SUM IS THE INVARIANT this test exists for --
    # the split is pinned underneath it so a silent drift in any one class stays visible, and
    # re-aiming it is the deliberate cost of a taxonomy change.
    #
    # Q-050 re-aimed it a second time, and this is a DENOMINATOR change rather than a re-partition:
    # `run_nosqlmap` was DELETED (no binary in the image, 0 dispatches in 154 missions, a bare
    # stdout regex duplicating run_nosqli's baseline-and-two-controls oracle). It lived in `never`,
    # so the denominator went 111 -> 110 and `never` went 53 -> 52, one engine, in one class. Every
    # other class is byte-identical, which is what makes the delta accountable rather than asserted.


# ── both renderers, or it is a half fix ──────────────────────────────────────
def _both():
    led = _real_ledger()
    return (report.generate_report("P", [], {"in_scope": ["x"]}, tool_ledger=led),
            report.generate_html_report("P", [], {"in_scope": ["x"]}, tool_ledger=led))


def test_BOTH_renderers_state_the_errored_count_distinctly():
    """HTML is the CLIENT-FACING renderer. These sections were once wired into markdown and absent
    from HTML, so a markdown-only fix is a half fix and the reader who matters never sees it."""
    md, html = _both()
    assert "Ran and ERRORED:** 1" in md, "the MARKDOWN summary does not state the errored count"
    assert "fetch_openapi" in md
    assert "Ran and errored:</b> 1" in html, "the HTML summary does not state the errored count"
    assert "fetch_openapi" in html


def test_BOTH_renderers_still_report_the_clean_engines_as_a_RESULT():
    """The negative control on the renderers: the silent count must survive, at its new value, in
    both. A summary that reports only what broke is a different lie."""
    md, html = _both()
    assert "Ran and found nothing:** 30" in md, md[md.find("Arsenal coverage"):][:600]
    assert "Ran and found nothing:</b> 30" in html


def test_BOTH_renderers_name_the_tested_nothing_class():
    """3, not 2: the renderers count LEDGER ROWS (the same basis as `Dispatched: 46`), and the
    ledger's third skipped row is `codeintel.review_source_tree`, a lane label rather than a
    registered engine. The class-sum test above restricts to the registry and therefore sees 2.
    Both numbers are right for their own denominator -- which is why each states it."""
    md, html = _both()
    assert "tested nothing:** 3" in md
    assert "tested nothing:</b> 3" in html
    assert "run_github_recon" in md and "run_transport_posture" in md
    assert "run_github_recon" in html and "run_transport_posture" in html


def test_the_summary_reconciles_with_its_own_Dispatched_total():
    """The property that makes the summary trustworthy without the table: the sub-classes it prints
    add up to the number of engines it says were dispatched. 46 = 30 silent + 1 errored + 3 skipped
    + 12 productive. If they did not add up, a reader could not tell which number to believe."""
    gap = report.arsenal_gap(_real_ledger())
    accounted = len(gap["silent"]) + len(gap["errored"]) + len(gap["skipped"])
    productive = [t["tool"] for t in _real_ledger()["tools"] if int(t["findings"] or 0)]
    assert accounted + len(productive) == len(gap["dispatched"]), (
        accounted, len(productive), len(gap["dispatched"]))

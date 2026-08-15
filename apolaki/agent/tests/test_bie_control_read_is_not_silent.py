"""Q-016 - a control-surface read that CRASHED must not report as a clean zero.

`_read_controls` was `except Exception: return []`. Every consumer then saw a well-formed empty
result: `classify_controls([])` -> `counts.total = 0` -> `probe_targets` returns nothing -> phase 2
(CWE-602 client-side authz) emits zero probes and zero findings, and the report prints
`control_surface.counts.total: 0`. A `page.evaluate` that threw was byte-identical to a page that
genuinely renders no controls -- a confident statement about the application, produced by a crash.

Fourth instance of this shape (DOM_SCAN_JS, the traversal import, the service sweep), so the test is
written against the DISTINCTION rather than against the exception: same empty return, different
recorded facts.
"""
import bie


class _Boom:
    """A page whose control-surface read always throws."""

    url = "https://app.example/dash"

    def evaluate(self, _js):
        raise RuntimeError("Execution context was destroyed")


class _Empty:
    """A page that genuinely renders no controls."""

    url = "https://app.example/dash"

    def evaluate(self, _js):
        return []


def test_a_crashed_read_records_why_and_still_returns_a_list():
    errors = []
    assert bie._read_controls(_Boom(), errors) == []
    assert len(errors) == 1
    assert "RuntimeError" in errors[0] and "Execution context" in errors[0]


def test_a_genuinely_empty_page_records_NOTHING():
    """The control that gives the test its meaning: if both cases recorded an error, the diagnostic
    would be noise and 'degraded' would be permanently true."""
    errors = []
    assert bie._read_controls(_Empty(), errors) == []
    assert errors == []


def test_the_two_cases_are_distinguishable_which_is_the_whole_point():
    crashed, empty = [], []
    bie._read_controls(_Boom(), crashed)
    bie._read_controls(_Empty(), empty)
    assert (crashed == []) != (empty == []), "a crash and an empty page must not look identical"


def test_the_error_list_is_bounded():
    """A pathological page must not grow this without limit -- the same bound `_swallow` uses."""
    errors = []
    for _ in range(50):
        bie._read_controls(_Boom(), errors)
    assert len(errors) == 20


def test_the_caller_may_omit_the_recorder_without_crashing():
    """Back-compatible: the signature change must not break a caller that passes one argument."""
    assert bie._read_controls(_Boom()) == []

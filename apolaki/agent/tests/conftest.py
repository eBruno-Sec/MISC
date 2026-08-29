import os
import re
import sys

import pytest

# Make the flat agent/ modules importable from tests/.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# Q-094. `test_island_soundness.py`, `test_observed_param_value_delivery.py` and
# `test_truthful_metadata.py` each reach the live lab by compose DNS name (`juice-shop:3000`) and
# `pytest.skip("juice-shop lab unreachable (...)")` when the name will not resolve or the connection
# fails -- the documented container command omits `--network apolaki_default`, so that skip fires on
# EVERY run made the documented way, and ten real assertions silently become skips. That is a
# DIFFERENT shape from "the lab answered but this fixture is not there" (wrong HTTP status, no JPEG
# at a path), which is a legitimate skip regardless of network and must NOT trip this gate -- tripping
# on that shape too would be exactly the guard-that-cannot-fail trap this project keeps finding.
_LAB_UNREACHABLE_RE = re.compile(r"lab unreachable")


def _report_is_lab_unreachable(report) -> bool:
    """Pure predicate, isolated so it is unit-testable without a nested pytest session: True only for
    the DNS/connection-failure skip shape, never the content-gap shape."""
    if not getattr(report, "skipped", False):
        return False
    return bool(_LAB_UNREACHABLE_RE.search(str(getattr(report, "longrepr", "") or "")))


_lab_unreachable_nodeids = []


def pytest_runtest_logreport(report):
    if _report_is_lab_unreachable(report):
        _lab_unreachable_nodeids.append(report.nodeid)


@pytest.fixture(scope="session", autouse=True)
def _q094_lab_reachability_gate():
    """SKIPPED is never a pass. A networkless run does not merely fail more, it TESTS LESS -- this
    turns the silent shrink into a hard failure instead of a quietly smaller green suite. Clear it
    with `--network apolaki_default` on the docker run (see avengers-assemble SKILL.md)."""
    yield
    if _lab_unreachable_nodeids:
        pytest.fail(
            "Q-094: %d test(s) skipped because the lab was unreachable (not a content gap) -- this "
            "run tested LESS than it reports. Re-run the container with "
            "'--network apolaki_default'. Affected:\n  %s"
            % (len(_lab_unreachable_nodeids), "\n  ".join(_lab_unreachable_nodeids)),
            pytrace=False,
        )

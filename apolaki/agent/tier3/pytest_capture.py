"""Small pytest plugin used by the Tier-3 runner for semantic outcomes."""
from __future__ import annotations

import json
import os


_STATE = {}


def pytest_addoption(parser):
    group = parser.getgroup("apolaki-tier3")
    group.addoption("--tier3-capture", action="store", default="")


def pytest_configure(config):
    _STATE.clear()
    _STATE.update({"collected": [], "reports": {}, "collection_errors": []})


def pytest_collection_modifyitems(session, config, items):
    _STATE["collected"] = [item.nodeid for item in items]


def pytest_collectreport(report):
    if report.failed:
        _STATE["collection_errors"].append({
            "nodeid": report.nodeid,
            "detail": str(report.longrepr)[:2000],
        })


def pytest_runtest_logreport(report):
    row = {
        "nodeid": report.nodeid,
        "when": report.when,
        "outcome": report.outcome,
        "duration": round(float(getattr(report, "duration", 0.0)), 6),
        "wasxfail": str(getattr(report, "wasxfail", "") or ""),
        "detail": str(report.longrepr)[:2000] if report.failed else "",
    }
    _STATE["reports"].setdefault(report.nodeid, []).append(row)


def pytest_sessionfinish(session, exitstatus):
    path = session.config.getoption("--tier3-capture")
    if not path:
        return
    _STATE["exitstatus"] = int(exitstatus)
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf8") as fh:
        json.dump(_STATE, fh, sort_keys=True, separators=(",", ":"))
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)

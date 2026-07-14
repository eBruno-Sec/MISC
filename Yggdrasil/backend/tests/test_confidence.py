"""Tests for the Aang confidence dimension: every finding is reported and
labeled by how sure we are, so nothing is hidden and nothing is over-claimed."""
import importlib.util
import unittest

HAS_SQLALCHEMY = importlib.util.find_spec("sqlalchemy") is not None


@unittest.skipUnless(HAS_SQLALCHEMY, "SQLAlchemy not available")
class ConfidenceInferTests(unittest.TestCase):
    def test_infer_from_severity(self):
        from core.models import Confidence
        self.assertEqual(Confidence.infer("critical"), "high")
        self.assertEqual(Confidence.infer("high"), "high")
        self.assertEqual(Confidence.infer("medium"), "medium")
        self.assertEqual(Confidence.infer("low"), "low")
        self.assertEqual(Confidence.infer("info"), "low")
        self.assertEqual(Confidence.infer(None), "low")


if HAS_SQLALCHEMY:
    class FakeSession:
        def __init__(self):
            self.added = []

        def add(self, o):
            self.added.append(o)

        async def commit(self):
            pass

    from agents.base import BaseAgent

    class _Agent(BaseAgent):
        async def execute(self, target, context=None):
            return {}


@unittest.skipUnless(HAS_SQLALCHEMY, "SQLAlchemy not available")
class AddFindingConfidenceTests(unittest.IsolatedAsyncioTestCase):
    def _agent(self):
        return _Agent(FakeSession(), "m-conf")

    async def test_explicit_confidence_stored(self):
        from core.models import Finding
        a = self._agent()
        await a.add_finding("X", "high", "d", confidence="confirmed")
        f = [o for o in a.session.added if isinstance(o, Finding)][0]
        self.assertEqual(f.confidence, "confirmed")

    async def test_confidence_inferred_when_missing(self):
        from core.models import Finding
        a = self._agent()
        await a.add_finding("Low sev thing", "low", "d")   # no confidence passed
        f = [o for o in a.session.added if isinstance(o, Finding)][0]
        self.assertEqual(f.confidence, "low")

    async def test_medium_severity_infers_medium(self):
        from core.models import Finding
        a = self._agent()
        await a.add_finding("Header missing", "medium", "d")
        f = [o for o in a.session.added if isinstance(o, Finding)][0]
        self.assertEqual(f.confidence, "medium")


@unittest.skipUnless(HAS_SQLALCHEMY, "SQLAlchemy not available")
class FindingDictTests(unittest.TestCase):
    def test_finding_dict_exposes_confidence(self):
        from datetime import datetime
        from core.models import Finding
        from routers.missions import _finding_dict
        f = Finding(id="1", mission_id="m", title="t", severity="high",
                    confidence="confirmed", timestamp=datetime.utcnow())
        d = _finding_dict(f)
        self.assertEqual(d["confidence"], "confirmed")

    def test_finding_dict_defaults_confidence(self):
        from datetime import datetime
        from core.models import Finding
        from routers.missions import _finding_dict
        f = Finding(id="1", mission_id="m", title="t", severity="low",
                    confidence=None, timestamp=datetime.utcnow())
        self.assertEqual(_finding_dict(f)["confidence"], "medium")


if __name__ == "__main__":
    unittest.main()

"""Harvest -> consume: workflows seed a reserved harvest_* namespace from the intel store,
so techniques use TARGET-DERIVED fixtures (not hardcoded answers)."""
from __future__ import annotations

import json

import intel
import packs
import workflow


class _FakeReg:
    def __init__(self, store):
        self.intel = store


def test_seed_harvest_exposes_candidates_as_vars():
    s = intel.IntelStore()
    s.add("object_id", "1", "api"); s.add("object_id", "13", "api")
    s.add("email", "admin@host", "api")
    variables = {}
    workflow._seed_harvest(variables, _FakeReg(s))
    assert variables["harvest_object_id"] == ["1", "13"]
    assert variables["harvest_object_id_first"] == "1"
    assert variables["harvest_email_first"] == "admin@host"


def test_seed_harvest_does_not_override_explicit_inputs():
    s = intel.IntelStore(); s.add("object_id", "99", "api")
    variables = {"harvest_object_id_first": "7"}   # explicit input wins
    workflow._seed_harvest(variables, _FakeReg(s))
    assert variables["harvest_object_id_first"] == "7"


def test_seed_harvest_survives_missing_store():
    variables = {}
    workflow._seed_harvest(variables, object())    # object() has no .intel
    assert variables == {}


def test_subst_resolves_harvested_var_into_url():
    variables = {"base": "http://t", "harvest_object_id_first": "42"}
    out = workflow._subst({"url": "{base}/api/x/{harvest_object_id_first}"}, variables)
    assert out["url"] == "http://t/api/x/42"


def test_harvested_pack_exists_and_references_harvest_namespace():
    p = packs.get("harvested_object_read")
    assert p is not None
    assert "harvest_object_id_first" in json.dumps(p)

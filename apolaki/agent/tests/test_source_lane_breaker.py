"""Breaker: the negative controls the code-assisted lane's own test file does not have.

Written by the verification agent, not by the lane's author. Two jobs:

1. Pin three MEASURED defects as strict xfails so they are executable evidence rather than prose
   in a hand-off document. When the owner fixes one, the xfail XPASSes, the suite goes red, and
   the marker has to be removed deliberately. A defect recorded only in a markdown file is a
   defect that gets re-introduced.

2. Lock down the receiver shapes the lane was never tested against. This is the part that
   matters. `test_python_system_random_is_a_csprng_not_a_weak_generator` only covers the INLINE
   spelling `random.SystemRandom().getrandbits(32)`. The four indirect spellings below -- an
   instance bound to a module-level name, a class attribute, a factory function, and an alias --
   are all clean today and all of them are one careless "improvement" away from being flagged.

   That is not hypothetical. The obvious fix for DEFECT 1 (below) is to resolve names bound to
   the `random` module and treat them as receivers. Done without care, that fix starts reporting
   `_RNG = random.SystemRandom()` call sites as CWE-330 -- which is precisely the M2 mutant that
   costs 113 false positives and takes weakrand from 100.0% to 50.2% on the real suite. These
   tests are the guard rail for that fix.

All behaviour below was measured against the committed tree before the tests were written.
"""
import pytest

import codereview as cr


# ══════════════════════════════════════════════════════════════════════════════════
# The receiver decides the verdict -- indirect spellings, none of them previously tested
# ══════════════════════════════════════════════════════════════════════════════════
# `random.getrandbits(32)` is a Mersenne Twister; `random.SystemRandom().getrandbits(32)` reads
# os.urandom. 113 of the suite's 326 weakrand cases are the second line. The existing suite proves
# that only for the inline spelling.

def test_a_system_random_instance_bound_to_a_name_is_still_a_csprng():
    """The generator is constructed once at module level and reused. There is no
    `random.<method>(` anywhere in the file -- the weak-looking call is on `_RNG`."""
    src = ("import random\n"
           "_RNG = random.SystemRandom()\n"
           "def token():\n"
           "    return _RNG.getrandbits(32)\n")
    assert cr.scan_python_random(src) == []


def test_a_class_attribute_holding_a_system_random_is_still_a_csprng():
    src = ("import random\n"
           "class Tokens:\n"
           "    rng = random.SystemRandom()\n"
           "    def make(self):\n"
           "        return self.rng.getrandbits(32)\n")
    assert cr.scan_python_random(src) == []


def test_a_factory_returning_a_system_random_is_still_a_csprng():
    src = ("import random\n"
           "def make_rng():\n"
           "    return random.SystemRandom()\n"
           "def token():\n"
           "    return make_rng().getrandbits(32)\n")
    assert cr.scan_python_random(src) == []


def test_system_random_reached_through_an_aliased_module_is_still_a_csprng():
    """`import random as r` then `r.SystemRandom()`. Clean today because the alias is invisible
    (see DEFECT 1); it must stay clean once the alias IS resolved."""
    assert cr.scan_python_random("import random as r\nt = r.SystemRandom().getrandbits(32)\n") == []


def test_a_csprng_aliased_to_the_name_of_the_weak_class_is_not_flagged():
    """`from random import SystemRandom as Random` binds a CSPRNG to the name of the weak class.
    A rule that reads the LOCAL name instead of the imported symbol reports it as CWE-330."""
    assert cr.scan_python_random("from random import SystemRandom as Random\n"
                                 "t = Random().getrandbits(32)\n") == []


def test_the_inverse_alias_is_still_caught():
    """Negative control for the test above: `from random import Random as SystemRandom` is a WEAK
    generator wearing the safe name, and must still be reported. Without this, a rule could pass
    the previous test by special-casing the string 'SystemRandom'."""
    hits = cr.scan_python_random("from random import Random as SystemRandom\n"
                                 "t = SystemRandom().getrandbits(32)\n")
    assert [h["construct"] for h in hits] == ["random.Random()"]


def test_an_attribute_named_random_is_not_the_random_module():
    """`self.random` is an injected collaborator, not the stdlib module."""
    src = ("class C:\n"
           "    def __init__(self, rng):\n"
           "        self.random = rng\n"
           "    def token(self):\n"
           "        return self.random.getrandbits(32)\n")
    assert cr.scan_python_random(src) == []


def test_indirect_weak_generators_are_still_reported_at_their_construction_site():
    """The mirror of the four CSPRNG tests: the same indirect shapes built on `random.Random()`
    must NOT go quiet. Without this, a rule could pass every test above by reporting nothing."""
    for src in (
        "import random\n_RNG = random.Random()\ndef t():\n    return _RNG.getrandbits(32)\n",
        "import random\nclass T:\n    rng = random.Random()\n    def m(self):\n"
        "        return self.rng.getrandbits(32)\n",
        "import random\ndef mk():\n    return random.Random()\ndef t():\n"
        "    return mk().getrandbits(32)\n",
    ):
        hits = cr.scan_python_random(src)
        assert [h["construct"] for h in hits] == ["random.Random()"], src


def test_a_bare_from_import_of_a_weak_method_is_reported():
    """`from random import getrandbits` used with no receiver at all."""
    hits = cr.scan_python_random("from random import getrandbits\nt = getrandbits(32)\n")
    assert [h["construct"] for h in hits] == ["random.getrandbits()"]


# ══════════════════════════════════════════════════════════════════════════════════
# usedforsecurity=False -- the spellings the lane's own test does not cover
# ══════════════════════════════════════════════════════════════════════════════════

def test_usedforsecurity_false_is_honoured_on_hashlib_new_and_across_lines():
    assert cr.scan_python_hash("import hashlib\n"
                               "d = hashlib.new('md5', b, usedforsecurity=False)\n") == []
    assert cr.scan_python_hash("import hashlib\n"
                               "d = hashlib.md5(\n    b,\n    usedforsecurity=False,\n)\n") == []


def test_usedforsecurity_false_does_not_excuse_a_second_call_on_the_same_line():
    """The kwarg is scoped to ONE call's argument span. A guard implemented as a line-level or
    file-level search would silence the unguarded call next to it."""
    hits = cr.scan_python_hash(
        "import hashlib\n"
        "x = hashlib.md5(a).hexdigest() + hashlib.md5(b, usedforsecurity=False).hexdigest()\n")
    assert len(hits) == 1 and hits[0]["algorithm"] == "MD5"


# ══════════════════════════════════════════════════════════════════════════════════
# MEASURED DEFECTS -- strict xfail. Remove the marker when the owner fixes the rule.
# ══════════════════════════════════════════════════════════════════════════════════

@pytest.mark.xfail(strict=True, reason=(
    "DEFECT 1 (Breaker session 3): an aliased MODULE import is invisible. _py_imports() computes "
    "modules['r'] = 'random' and the binding is then thrown away -- _py_binds_module can only "
    "SUPPRESS a name, never resolve one, and _PY_RANDOM_CALL hard-codes the literal receiver "
    "`random`. The `from X import Y as Z` half is handled correctly. Costs the benchmark nothing "
    "(0 aliased imports in the suite); it is a generality hole."))
def test_an_aliased_random_module_import_is_still_the_stdlib_generator():
    hits = cr.scan_python_random("import random as r\ndef token():\n    return r.getrandbits(32)\n")
    assert hits, "r.getrandbits(32) after `import random as r` is a Mersenne Twister"


@pytest.mark.xfail(strict=True, reason=(
    "DEFECT 1, hash half: _PY_HASHLIB_CALL hard-codes the receiver `hashlib`, so "
    "`import hashlib as hl; hl.md5(d)` is never seen."))
def test_an_aliased_hashlib_import_is_still_the_stdlib_digest():
    hits = cr.scan_python_hash("import hashlib as hl\ndef h(d):\n    return hl.md5(d).hexdigest()\n")
    assert hits, "hl.md5(d) after `import hashlib as hl` is hashlib.md5"


@pytest.mark.xfail(strict=True, reason=(
    "DEFECT 2 (Breaker session 3): _PY_CLOCK_TOKEN fires on any identifier merely CONTAINING a "
    "security word when a clock read appears within 90 characters, so an audit or expiry "
    "timestamp is reported as CWE-337 'a security value derived from the clock'. Confirmed in "
    "the wild: the single CWE-337 in 5139 files of the container's stdlib is this bug firing on "
    "the keyword argument `token=` in anthropic/lib/credentials/_workload.py:346. Costs the "
    "benchmark nothing (0 occurrences of the shape in the suite)."))
def test_a_timestamp_named_after_a_session_is_not_weak_randomness():
    assert cr.scan_python_random("import time\ndef begin():\n"
                                 "    session_start = time.time()\n    return session_start\n") == []


@pytest.mark.xfail(strict=True, reason="DEFECT 2, expiry spelling. See the test above.")
def test_a_token_expiry_timestamp_is_not_weak_randomness():
    assert cr.scan_python_random("import time\ndef issue():\n"
                                 "    token_expiry = time.time() + 3600\n"
                                 "    return token_expiry\n") == []


def test_a_security_value_actually_derived_from_the_clock_is_still_reported():
    """Negative control for the two xfails above: DEFECT 2 must be fixed by narrowing the rule,
    not by deleting it. A token whose VALUE is the clock is a real CWE-337."""
    hits = cr.scan_python_random("import time\ndef issue():\n    token = str(time.time())\n"
                                 "    return token\n")
    assert [h["cwe"] for h in hits] == ["CWE-337"]

"""Q-058 item 3 — `run_hash_crack` advertised a `hash_type` parameter and never read it.

THE DEFECT, as measured before the fix: the token `hash_type` occurred EXACTLY ONCE in all 10,052
lines of `agent/tools.py`, on the `input_schema` line, described to the model as *"optional;
auto-identified if omitted"* — a phrase that promises supplying it does something. `_run_hash_crack`
ran `cands = hid.identify(h)` unconditionally and never looked at `inp["hash_type"]`.

WHY IT IS NOT COSMETIC. `hashid_tool.identify()` returns a RANKED list, and for a bare 32-hex digest
that list is MD5, NTLM, MD4 — one string, three hashcat modes, genuinely indistinguishable by
inspection. Auto-identification takes the first. An NTLM hash cracked under mode 0 does not error: it
finds nothing and reports "Not cracked", a wrong answer wearing a right one's clothes. The fix
HONOURS the parameter rather than dropping it, because the code was the half that was wrong.

The load-bearing test in this file is the last one: it asserts the pin changes the ARGUMENT VECTOR
actually handed to hashcat. A test that only checked the returned candidate ordering would pass on an
implementation that pinned the wrong thing and still cracked at mode 0.
"""
import asyncio

import scope as scope_mod
import tools


# The real output of `hashid_tool.identify("0192023a7bbd73250516f069df18b500")` — a 32-hex digest.
# Not invented: this is the ambiguity the parameter exists to resolve, and it is asserted to still be
# the real ranking in `test_the_ambiguity_this_parameter_resolves_is_real`.
_MD5_SHAPED = "0192023a7bbd73250516f069df18b500"


def test_the_ambiguity_this_parameter_resolves_is_real():
    """POSITIVE CONTROL for every assertion below. If `identify` ever stops returning more than one
    candidate for a 32-hex digest, the pin has nothing to choose between and these tests go vacuous
    without failing — so the premise is asserted, not assumed."""
    import hashid_tool as hid
    names = [c["name"] for c in hid.identify(_MD5_SHAPED)]
    assert names[0] == "MD5", names          # auto-identification's answer
    assert "NTLM" in names[1:], names        # ...and the one an operator may need to override it with
    assert len(names) >= 3, names


# ── the resolver ─────────────────────────────────────────────────────────────

def test_pin_selects_a_lower_ranked_candidate_over_the_auto_identified_first():
    import hashid_tool as hid
    cands = hid.identify(_MD5_SHAPED)
    assert tools._pick_hash_candidate(cands, "NTLM")["hashcat"] == "1000"
    assert cands[0]["name"] == "MD5", "the resolver must not mutate the list it was handed"


def test_pin_accepts_a_raw_hashcat_mode_because_that_is_what_an_operator_holds():
    import hashid_tool as hid
    cands = hid.identify(_MD5_SHAPED)
    assert tools._pick_hash_candidate(cands, "1000")["name"] == "NTLM"
    assert tools._pick_hash_candidate(cands, "0")["name"] == "MD5"


def test_pin_accepts_a_john_format_name():
    import hashid_tool as hid
    cands = hid.identify(_MD5_SHAPED)
    assert tools._pick_hash_candidate(cands, "nt")["name"] == "NTLM"
    assert tools._pick_hash_candidate(cands, "raw-md4")["name"] == "MD4"


def test_pin_ignores_case_and_punctuation():
    import hashid_tool as hid
    cands = hid.identify("a" * 64)
    for spelling in ("SHA-256", "sha256", "Sha 256", "sha-256"):
        assert tools._pick_hash_candidate(cands, spelling)["name"] == "SHA-256", spelling


def test_an_exact_match_anywhere_beats_a_prefix_match_earlier_in_the_list():
    """Pass 1 runs over EVERY candidate before pass 2 runs over any. Ordering the two passes the
    other way round would answer `hash_type="MD5"` with `md5crypt (Unix)` — a different hashcat mode
    (500 vs 0) — whenever the crypt variant happened to rank first."""
    cands = [{"name": "md5crypt (Unix)", "hashcat": "500", "john": "md5crypt"},
             {"name": "MD5", "hashcat": "0", "john": "raw-md5"}]
    assert tools._pick_hash_candidate(cands, "MD5")["hashcat"] == "0"
    assert tools._pick_hash_candidate(cands, "md5crypt")["hashcat"] == "500"


def test_pin_returns_none_when_the_hash_cannot_be_that_type():
    import hashid_tool as hid
    assert tools._pick_hash_candidate(hid.identify(_MD5_SHAPED), "bcrypt") is None
    assert tools._pick_hash_candidate([], "MD5") is None


def test_a_fragment_too_short_to_identify_anything_selects_nothing():
    """`hash_type="md"` must not silently select MD5. Exact matches are exempt from the guard, or a
    two-character John format would become unusable."""
    import hashid_tool as hid
    cands = hid.identify(_MD5_SHAPED)
    assert tools._pick_hash_candidate(cands, "md") is None
    assert tools._pick_hash_candidate(cands, "") is None
    assert tools._pick_hash_candidate(cands, "   ") is None
    assert tools._pick_hash_candidate(cands, "nt")["name"] == "NTLM"    # exact, 2 chars, still works


# ── the engine ───────────────────────────────────────────────────────────────

def _registry():
    eng = scope_mod.ScopeEngine()
    eng.load_manual(["host.local"], [], "P")
    return tools.ToolRegistry(eng, mission_id=None)


def _run(coro):
    """The suite has no pytest-asyncio (verified: `import pytest_asyncio` -> ModuleNotFoundError), so
    async engines are driven with `asyncio.run`, matching test_bbh / test_autonomy_loop. The loop is
    restored afterwards because `asyncio.run` closes the one it made, and older tests still reach for
    `asyncio.get_event_loop()`."""
    try:
        return asyncio.run(coro)
    finally:
        asyncio.set_event_loop(asyncio.new_event_loop())


def test_a_hash_type_the_hash_cannot_be_is_reported_not_ignored():
    """Silently cracking under a type the operator did not ask for is the same defect one layer
    down. The disagreement is surfaced, and the message names what WAS identified so the operator can
    act on it."""
    res = _run(_registry()._run_hash_crack({"hash": _MD5_SHAPED, "hash_type": "bcrypt"}))
    assert res.success is False
    assert "bcrypt" in res.error and "MD5" in res.error


def test_an_empty_hash_type_still_auto_identifies():
    """The schema says "auto-identified if omitted", and a falsy value is omission. This codebase has
    been bitten three times by `x or DEFAULT` treating an empty string as a real input; here the
    empty string must reach the auto path, not the mismatch path."""
    for omitted in ({}, {"hash_type": ""}, {"hash_type": "   "}):
        inp = dict({"hash": _MD5_SHAPED}, **omitted)
        res = _run(_registry()._run_hash_crack(inp))
        assert res.error is None or "does not match" not in (res.error or ""), omitted


def test_the_pin_reaches_the_hashcat_argument_vector(monkeypatch):
    """THE ONE THAT MATTERS. Not "the resolver returned NTLM" but "hashcat was invoked with -m 1000".

    hashcat and John are both absent from the agent image (`shutil.which` returns None for each), so
    the engine's real path here is its graceful skip. `which` is faked and `_cmd` is replaced with a
    recorder, which is the only way to observe the argv this parameter is supposed to change. The
    baseline in the same test is the same hash with NO `hash_type`, so the assertion is a DIFFERENCE
    between two observed vectors rather than a hardcoded expectation.
    """
    calls = []

    async def _record(self, cmd, timeout=None, **kw):
        calls.append(list(cmd))
        return "", ""

    monkeypatch.setattr(tools.shutil, "which", lambda b: "/usr/bin/" + b if b == "hashcat" else None)
    monkeypatch.setattr(tools.ToolRegistry, "_cmd", _record)

    _run(_registry()._run_hash_crack({"hash": _MD5_SHAPED}))
    assert calls, "positive control: the recorder saw no hashcat invocation at all"
    baseline = calls[0]
    assert baseline[0] == "hashcat" and baseline[baseline.index("-m") + 1] == "0", baseline

    calls.clear()
    _run(_registry()._run_hash_crack({"hash": _MD5_SHAPED, "hash_type": "NTLM"}))
    assert calls, "positive control: the recorder saw no hashcat invocation at all"
    pinned = calls[0]
    assert pinned[pinned.index("-m") + 1] == "1000", pinned
    assert pinned != baseline, "the pin changed nothing about the command that runs"

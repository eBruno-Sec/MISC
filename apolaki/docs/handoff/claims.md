# claims lane (Builder) -- Q-058: four claims in `agent/tools.py` that did not match behaviour

Files owned by this lane: `agent/tools.py`, `agent/tests/test_description_gate.py`, new tests written
by this lane, this file. Nothing else was written.

The standing rule for the whole ticket: **a description is the claim under test.** Where the claim
and the code disagreed, this lane fixed the half that was actually wrong, and recorded which half
that was for each item. No claim was softened to make a flag stop firing.

---

## STATUS

| item | what it was | state | commit |
|---|---|---|---|
| 1 | `_confirm_create_object_idor` docstring opened `ACTIVE:`, registered `INTRUSIVE` | see below | see below |
| 2 | `_run_external_surface` docstring opened `PASSIVE/ACTIVE-light`, registered `ACTIVE` | see below | see below |
| 3 | `run_hash_crack` advertises `hash_type`, never reads it | see below | see below |
| 4 | 4 engines declare no tier at all | see below | see below |

Rows are filled in only under the section that carries the command and its real output. Nothing is
marked done above the evidence.

---

## POSITIVE CONTROL FOR EVERY ZERO IN THIS FILE

Every "0 flags" below is paired with the number of engines the audit actually read. A gate that
parsed nothing would also report zero.

```
$ docker run --rm -v ".../apolaki/agent:/app" -w /app apolaki-agent python -c "
  import description_gate as dg; src=open('tools.py',encoding='utf-8').read()
  print('permissions:',len(dg.analyse(src).permissions)); [print('FLAG',v) for v in dg.audit(src)]"
```

BEFORE this lane (tree at `a577af7`):

```
permissions: 111
FLAG [undeclared_tier] confirm_create_object_idor: registered INTRUSIVE but its docstring declares ACTIVE - 'ACTIVE:'
FLAG [undeclared_tier] run_external_surface: registered ACTIVE but its docstring declares PASSIVE - 'PASSIVE/ACTIVE-light external attack-surface expansion (#114):'
```

111 is the number the ticket predicted, so the apparatus was looking at the whole registry, and the
two flags are exactly the two `KNOWN_OPEN` entries. MEASURED.

---

## ITEM 1 and ITEM 2 -- the two tier docstrings (one commit, with the ratchet)

### Verified against the code before touching it

MEASURED, item 1. `TOOL_PERMISSIONS["confirm_create_object_idor"] = PermissionLevel.INTRUSIVE`
(`agent/tools.py:249`, with the comment `creates+deletes an owned object (bounded, cleaned up)`), and
the `CLAUDE_TOOLS` spec description also opens `INTRUSIVE (bounded + self-cleaning)`. Only the
implementation docstring opened `ACTIVE:`. The ticket's claim that enforcement is correct holds:
`_run_tool` gates on `TOOL_PERMISSIONS`, not on the docstring, so this was never a live exposure.
**Wrong half: the docstring.** Two of three surfaces already said INTRUSIVE.

MEASURED, item 2. `run_external_surface` is registered `ACTIVE` (`agent/tools.py:253`) and its spec
description opens `ACTIVE:`. The docstring opened `PASSIVE/ACTIVE-light`. Reading the body confirms
ACTIVE is the correct registration: step 2 of the engine issues
`await self._http_send("GET", "%s://%s/favicon.ico" % (scheme, authority or host), ...)` against the
in-scope target itself. **Wrong half: the docstring.**

### A third thing found while verifying item 2, fixed in the same edit

The old docstring also asserted **"The CT fetch is the only outbound call"**. That is false in the
same file, four lines above the sentence: the favicon GET is outbound, and the ASN step calls
`dns_recon.ip_intel(host)`. This is the same defect family as the ticket items (a claim that does not
match behaviour) and it is the direction that matters, because the sentence understates target
contact. The claim was the wrong half here too, and correcting it makes the docstring stricter, not
softer. The replacement names both outbound calls and the delegated one.

### Fix

Both docstrings now open with the registered tier as a **bare token**, with the nuance in prose
AFTER the token, never inside it:

* `_confirm_create_object_idor`: `INTRUSIVE (bounded, self-cleaning): CREATE-OBJECT IDOR (CHAD C). ...`
* `_run_external_surface`: `ACTIVE: external attack-surface expansion (#114): ...`

No registration was changed. `agent/tools.py` no longer contains the string `ACTIVE-light` anywhere.

### The ratchet, in the same commit

`KNOWN_OPEN` in `agent/tests/test_description_gate.py` is now **empty**, with the two removed entries
kept in a comment recording what each was and why it left.

One structural change was needed to make an empty set safe. The ratchet test was
`@pytest.mark.parametrize("engine", sorted(KNOWN_OPEN))`, and `parametrize` over an empty set does
not run zero assertions: pytest emits **one SKIPPED test** with reason "got empty parameter set". A
skip that reads as a pass is exactly what this file exists to refuse, and it would also have moved
the suite's skip count. The test is now a single non-parametrized test asserting
`KNOWN_OPEN - live == set()`. Same assertion, same failure condition, no skip-shaped hole. It is
strictly harder to pass than the version it replaces.

### Tests

Added to `agent/tests/test_description_gate.py`:

* `test_q058_the_two_recorded_tier_defects_are_fixed_in_the_live_tree` (parametrized, 2 cases) --
  asserts on the LIVE tree that (a) the registration is UNCHANGED, so a "fix" that re-registered the
  engine at a softer tier fails here, (b) the docstring declares exactly the registered tier as a
  bare token, (c) the docstring opens with the exact expected phrase.
* `test_q058_no_hyphen_softened_tier_survives_anywhere_in_tools_py` -- whole-file check that no
  `TIER-qualifier` hedge exists in `tools.py` at all. Rule B only inspects the leading declaration
  phrase, so a hedge further down a docstring is invisible to it while still being read by the next
  engineer. Carries its own positive control (`len(source) > 100_000`).

FAILS BEFORE THE FIX. MEASURED against `git show HEAD:apolaki/agent/tools.py` (the pre-fix file,
10052 lines), audited by the same apparatus:

```
PRE-FIX permissions: 111 (positive control: the apparatus read the pre-fix file)
run_external_surface
   permissions == ACTIVE
   declared_tiers == ['PASSIVE'] -> assert == ['ACTIVE'] FAILS
   startswith('ACTIVE:') == False FAILS
confirm_create_object_idor
   permissions == INTRUSIVE
   declared_tiers == ['ACTIVE'] -> assert == ['INTRUSIVE'] FAILS
   startswith('INTRUSIVE (bounded, self-cleaning):') == False FAILS
```

PASSES AFTER. MEASURED:

```
$ ... python -c "import description_gate as dg; src=open('tools.py',encoding='utf-8').read()
                 print('permissions:',len(dg.analyse(src).permissions))
                 flags=dg.audit(src); print('flags:',len(flags)); [print('FLAG',v) for v in flags]"
permissions: 111
flags: 0
```

111 read, 0 flagged. The positive control is the same number as before the fix, so the zero is a
zero and not a parse failure.

```
$ ... python -m pytest tests/test_description_gate.py -p no:cacheprovider -q
................                                                         [100%]
16 tests, 0 failed, 0 skipped
```

Targeted regression set (every test file that mentions either engine):

```
$ ... python -m pytest tests/test_description_gate.py tests/test_benchmark_assert.py \
      tests/test_create_object_discovery.py tests/test_create_object_idor.py \
      tests/test_engine_reachability.py tests/test_island_soundness.py \
      tests/test_safety_gates.py -p no:cacheprovider -q
..................................................................       [100%]
66 tests, 0 failed, 0 skipped
```

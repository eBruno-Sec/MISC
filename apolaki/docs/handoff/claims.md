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

Committed as `6e16197`.

**A process note that belongs in the record, not buried.** The commit message of `6e16197` has a
malformed subject line: the literal `@`, on its own, above the real subject. The body is intact. The
cause was PowerShell here-string syntax (`-m @'...'@`) passed to the Bash tool, which does not parse
it. Worse, the `git commit --amend` intended to fix it landed on the WRONG COMMIT: another lane
committed `676923a` in the seconds between this lane's commit and its amend, so the amend rewrote
THEIR message with this lane's. It was detected immediately from `git show --stat` (the stat listed
`findings_57cc3b49.json` and `provenance2.md`, files this lane never touched) and repaired with
`git reset --soft 676923a` after verifying `3e9dd8a^{tree} == 676923a^{tree}` and
`3e9dd8a^ == 676923a^`, i.e. that the amend had changed the message and nothing else. `676923a` is
restored byte-for-byte at its original hash; no working-tree or index state was touched (`--soft`,
never `--hard`, with other lanes holding uncommitted changes in the same tree). The malformed subject
on `6e16197` was left as-is: fixing it needs a rebase, which would rewrite a sibling lane's commit
hash while that lane is still working. A cosmetic subject line is not worth that.

**Standing correction for every lane in this repo: `git commit --amend` is not safe here.** HEAD is
shared and moves under you between two commands.

---

## ITEM 3 -- `run_hash_crack` advertised `hash_type` and never read it

### Verified against the code before touching it

MEASURED, on the tree as this lane received it:

```
$ grep -n "hash_type" agent/tools.py
964:  "hash": {"type": "string"}, "hash_type": {"type": "string", "description": "optional; auto-identified if omitted"},
$ grep -c "hash_type" agent/tools.py
1
```

Exactly one occurrence in 10,052 lines, on the schema line, while `_run_hash_crack` ran
`cands = hid.identify(h)` unconditionally. The ticket's detail is correct as written.

**Wrong half: the CODE.** The schema describes the parameter as *"optional; auto-identified if
omitted"*, which promises that supplying it does something. Dropping the property was the offered
alternative and it was rejected, because the parameter is not decoration:
`hashid_tool.identify("0192023a7bbd73250516f069df18b500")` returns **MD5, NTLM, MD4** -- one string,
three hashcat modes, indistinguishable by inspection. Auto-identification takes the first. An NTLM
hash cracked at mode 0 does not error; it reports **"Not cracked"**, which is a wrong answer wearing
a right one's clothes. An operator holding a SAM dump has to be able to say so.

### Fix

`_pick_hash_candidate(cands, want)` (module level, beside the other resolvers) plus six lines in
`_run_hash_crack`. `hash_type` is a PIN over the ranked auto-identification:

* pass 1 matches EXACTLY against every candidate's name, hashcat mode and John format, across ALL
  candidates before any loose match is tried. It therefore also accepts a raw hashcat mode number
  (`"1000"`), which is what a pentester actually holds.
* pass 2 is a name-prefix match (`"md5crypt"` -> `"md5crypt (Unix)"`), length-guarded so a
  two-character fragment cannot silently select a family.
* a type the hash CANNOT be returns `None`, and the engine then returns a FAILED `ToolResult` naming
  both the request and what was identified. Proceeding under a type the operator did not ask for is
  the same defect one layer down.

The schema description was extended to state the pin semantics. That is not the forbidden edit: the
forbidden edit softens a claim so a defect stops firing, and the old text was already true of the new
code -- this makes it more specific about behaviour that now exists and is tested.

### KNOWN CEILING, recorded rather than hidden

When `identify()` recognises nothing (an unusual shape), ANY `hash_type` now fails with
`auto-identified: unrecognised` instead of proceeding. Honouring a pin in that case needs a
name-to-mode table, which lives in `hashid_tool.py` -- a file this lane does not own. **Patch wanted**
(see the bottom of this file). Before the fix the parameter was ignored in that case too, so nothing
regressed; the difference is that the tool now says so.

### Tests -- `agent/tests/test_hash_type_pin.py`, 11 new

Includes a premise control (`test_the_ambiguity_this_parameter_resolves_is_real`) asserting that
`identify` really does return >= 3 candidates ranked MD5-first for a 32-hex digest. Without it, a
future change to `identify` would make every other test in the file vacuous without failing.

The load-bearing test is `test_the_pin_reaches_the_hashcat_argument_vector`: it fakes
`shutil.which("hashcat")` (absent from the image: `python -c "import shutil; print(shutil.which('hashcat'), shutil.which('john'))"` -> `None None`),
records the argv through a patched `_cmd`, and asserts a DIFFERENCE between two observed vectors --
mode `0` with no `hash_type`, mode `1000` with `hash_type="NTLM"` -- rather than a hardcoded
expectation. A test that only checked the resolver's return value would pass an implementation that
resolved the pin correctly and then cracked at mode 0 anyway.

FAILS BEFORE THE FIX. MEASURED by mounting `git show 6e16197:apolaki/agent/tools.py` (the same tree
minus this item; `grep -c hash_type` on it = **1**) over `/app/tools.py` and running the new file:

```
9 failed, 2 passed
FAILED test_pin_selects_a_lower_ranked_candidate_over_the_auto_identified_first
FAILED test_pin_accepts_a_raw_hashcat_mode_because_that_is_what_an_operator_holds
FAILED test_pin_accepts_a_john_format_name
FAILED test_pin_ignores_case_and_punctuation
FAILED test_an_exact_match_anywhere_beats_a_prefix_match_earlier_in_the_list
FAILED test_pin_returns_none_when_the_hash_cannot_be_that_type
FAILED test_a_fragment_too_short_to_identify_anything_selects_nothing
FAILED test_a_hash_type_the_hash_cannot_be_is_reported_not_ignored
FAILED test_the_pin_reaches_the_hashcat_argument_vector      # E - 1000 / E + 0
```

The 2 that pass pre-fix are the two that MUST pass on both sides: the premise control, and
`test_an_empty_hash_type_still_auto_identifies`.

### Mutation testing -- 3 mutants, each VERIFIED APPLIED, all 3 killed

Each mutant was written to a separate file, read back off disk and asserted to contain the new text
and not the old, then grepped again INSIDE the container that ran the tests (marker count printed as
`1` each time). A mutation that silently fails to apply produces a green run that proves nothing.

| mutant | the defect it simulates | killed by |
|---|---|---|
| A `cands = [picked] + [...]` -> `cands = list(cands)` | pin resolved, then thrown away (computed-but-unused) | `test_the_pin_reaches_the_hashcat_argument_vector` (`- 1000` / `+ 0`) |
| B resolver's final `return None` -> `return (cands or [None])[0]` | resolver can never say no; a mismatched type silently becomes the top guess | `test_pin_returns_none_when_the_hash_cannot_be_that_type`, `test_a_hash_type_the_hash_cannot_be_is_reported_not_ignored` |
| C pass 1 `== wn` -> `.startswith(wn)` | exact matching degrades to prefix matching, so a collision earlier in the list wins | `test_an_exact_match_anywhere_beats_a_prefix_match_earlier_in_the_list`, `test_a_fragment_too_short_to_identify_anything_selects_nothing` |

### Regression

```
$ ... python -m pytest tests/test_hash_type_pin.py tests/test_bbh.py \
      tests/test_description_gate.py -p no:cacheprovider -p no:warnings
271 passed in 108.85s
```

`test_bbh.py` is the only other file in the suite that mentions `hash_crack` or `hashid`
(`grep -rln "hash_crack\|hashid" agent/tests/*.py` -> those two files).

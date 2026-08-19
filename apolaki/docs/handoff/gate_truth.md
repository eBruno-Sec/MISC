# Q-077 - a COMMENT mentioning a function makes it look alive to the dead-code gate

Lane: gate-truth (Builder). Files owned: `agent/deadcode_gate.py`,
`agent/tests/test_deadcode_gate.py`, this file. Written as the work happens.
Every claim is MEASURED (command + real output) or UNVERIFIED.

## 0. The environment, stated once

HEAD at lane start: `e66f4ca0772d4ebb8ee4a1408e283cb505a65e9a`.
`git status --porcelain -- apolaki/agent` was EMPTY, so the worktree `agent/` equalled HEAD and the
snapshot below is the same bytes the shared tree had.

Isolated snapshot (never the shared tree; two other lanes are live):

    cd /c/Users/voice/Desktop/GitHub/MISC && git archive HEAD apolaki | tar -x -C "$SP/snap"
    -> 179 .py files under snap/apolaki/agent

Every measurement in this file runs in a throwaway container over that snapshot:

    MSYS_NO_PATHCONV=1 docker run --rm --network apolaki_default \
      -v "<snap>/apolaki/agent:/app" -w /app apolaki-agent python -c ...

## 1. BASELINE BEFORE ANY CHANGE - measured, not read off the constants

MEASURED on the HEAD snapshot with the regex-based gate as it shipped:

    QUAL count 35  baseline 37  ok True
    QUAL newly []  resolved []
    METH count 13  baseline 14  ok True  examined 399
    METH newly []  resolved []

Both recorded sets are EXACT against the snapshot - `newly_dead` and `resolved` are both empty for
both scans, so `QUALIFIED_BASELINE_SET` (35) and `METHOD_BASELINE_SET` (13) are true measurements of
HEAD under the OLD resolver. That matters: any delta after the AST rewrite is attributable to the
rewrite alone, not to pre-existing drift.

Slack before the change: qualified 37-35 = **2**, method 14-13 = **1**.
`test_the_baseline_is_not_slack` allows at most 3.

The 35 qualified entries and 13 method entries are exactly the two frozensets already in the file, so
they are not repeated here.

## 2. THE FIX - references read off the AST

`_ast_refs(tree)` returns four sets per module: bare `Name` ids, `(receiver-path, attribute)` pairs,
every attribute name, and every WHOLE string-constant value. `_dotted()` reduces a pure Name/Attribute
chain to `a.b.c` and returns None for anything else, which is what the old `(?<![\w.])` lookbehind was
doing by hand.

Three rules changed, and each is attributed separately below:

  R1. own-module reference: `f in names` instead of a regex over the module's raw text
  R2. cross-module alias: `(alias, f) in qualified` instead of matching the text `alias.f`
  R3. from-import: the local name must appear as an `ast.Name`. The old rule regex-searched the raw
      source for the bare local name, which **matched the import statement it had just read** - so
      `from x import y` cleared `y` whether or not anything used it.

`scan_methods` keeps its string-dispatch rule (`getattr(self, "_" + tool_name)`), but now matches WHOLE
string-constant values rather than a substring of raw text, and keeps its self-exclusion verbatim.

## 3. RE-MEASURED - the count rises, and by far more than the ticket expected

Same snapshot, same container, AST resolver:

    QUAL count 62  baseline 37  ok False   (was 35, +27)
    METH count 14  baseline 14  ok True    (was 13, +1)   examined 399
    QUAL resolved 0   METH resolved 0

`resolved` is 0 for both: **nothing that was flagged before is cleared now.** The change is purely
additive, which is the first evidence that it did not break resolution.

### 3.1 Attribution - which rule change produced the +27 (MEASURED)

Re-ran the resolver with one rule at a time reverted:

    AST strict                       : 62
    + R3 reverted (from-import counts): 61   delta ['sqli_tool.is_inconclusive']

So **R3 accounts for exactly 1 entry**, and it is a true one: `nosqli_tool.py` does
`from sqli_tool import is_inconclusive` and never uses the name (MEASURED: `used as name: False`).
The other **26 come from R1/R2 - prose in the defining module.**

### 3.2 What actually cleared each of the 27 under the OLD resolver

For each newly-visible entry, the first old own-module regex hit was located in the ORIGINAL source and
classified by `tokenize` (COMMENT / STRING / CODE):

    TALLY: STRING 22, COMMENT 5, CODE 0

**CODE 0 is the headline.** Not one of the 27 was cleared by a real reference. 20 of the 22 STRING hits
are DOCSTRING prose; the remaining two are data strings that merely contain the name:

    bench_all.bench          bench_all.py:105   "program_name": "bench-%s" % key,
    tool_provenance.argv_hash tool_provenance.py:61  "argv_hash": _hash(redacted_argv),

Representative prose hits (the name is being DISCUSSED, not called):

    capability_matrix.state_rank  capability_matrix.py:13  `state_rank` orders them; a capability is ...
    fingerprint.fingerprint       fingerprint.py:139       # The four keys `fingerprint()` has always ...
    techniques.classes            techniques.py:38         # Permission classes mirror the wrapper-level ...
    exposure_tool.paths           exposure_tool.py:158     """Extract file paths (with extensions) ..."""

The last one is the systematic shape: **a function named after a common English noun is cleared by its
own docstring.** `paths`, `plan`, `finding`, `inventory`, `classes`, `observe`, `harvest`, `request`,
`response`, `audit`, `hypotheses` all self-cleared this way.

### 3.3 The gate exonerated itself

Three of the 27 are `deadcode_gate.scan`, `deadcode_gate.scan_qualified` and
`deadcode_gate.scan_methods`. They have no caller in `agent/*.py` (importers=NONE - they are invoked by
tests and by `scripts/liveness.sh`, neither of which the qualified scan reads). They read as ALIVE only
because the module's own docstring at `deadcode_gate.py:18` and `:28` and a comment at `:361` discuss
them by name. **The instrument built to detect declaration-instead-of-fact was clearing its own three
entry points with a declaration about itself.**

### 3.4 The method delta - an English full stop is an attribute access

The +1 is `vault.py::Vault.is_encrypted`. MEASURED, on the real prose line:

    vault.py:19  'pretends to be encrypted. is_encrypted() reports the true protection level.'
      OLD rule  self\s*\.\s*is_encrypted     -> no match
      OLD rule  \.\s*is_encrypted            -> '. is_encrypted'      <-- cleared it
      OLD rule  ["']_?is_encrypted["']       -> no match

The `.` is the end of the previous SENTENCE. `\.\s*name` cannot tell a full stop from an attribute
access, so any method whose name follows a period in prose reads as called.

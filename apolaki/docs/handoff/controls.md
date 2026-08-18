# controls lane -- Q-071: the report says "no negative control" on the only findings that have one

Written as the work happened. Every row is MEASURED (command + real output) or UNVERIFIED.
Status words are `in progress` until the evidence exists; an unmeasured row is never a number.

## The apparatus (and the trap that cost the Coordinator a wrong zero)

The findings live in the named volume `apolaki_bbh_data`, NOT in the tree. A container mounting only
`agent:/app` sees an empty `/app/data` and every count comes back 0. Mount both:

```
MSYS_NO_PATHCONV=1 docker run --rm -i \
  -v "<repo>/apolaki/agent:/app" -v "apolaki_bbh_data:/data" -w /app apolaki-agent python -
```
then `db.init('/data/bbh.db')` and `db._query("SELECT id, mission_id, data FROM findings")`.

**My own first probe was wrong and I nearly recorded its output.** `db._query` returns a list of
**dicts**, not tuples. `for fid, mid, data in rows` therefore unpacked each row's *key names*, so
`json.loads("data")` raised on every row and my `except: continue` swallowed it. The run printed
`total 1057 / browser_evidence 0 / control_status {}` -- a clean-looking all-zero that was pure
instrument failure. The fix was `row["data"]` plus a `parsed` / `unparsed` counter printed on every
run, which is the positive control that would have caught it: `parsed 1057, unparsed 0`.

## MEASURED -- the population, re-measured independently of the ticket

Probe: parse all 1057 stored findings, then walk **every** nesting level of each one looking for any
`proof_schema.CONTROL_KEYS` name holding a non-empty value, and record the JSON path.

```
POSITIVE CONTROL total stored findings: 1057
parsed as dict: 1057  unparsed: 0
carry a TOP-LEVEL control key (non-empty): 0
control_status() -> {'not_recorded': 1057}
findings with a non-empty browser_evidence dict: 3

EVERY path at ANY depth holding a non-empty CONTROL_KEY:
  browser_evidence.negative_controls          type=dict n=3  example id=53112c58f032 family=bola
  browser_evidence.negative_controls.control  type=dict n=3  example id=53112c58f032 family=bola
```

The ticket's three numbers reproduce **exactly**: 1057 stored, 3 nested controls, 0 top-level, 0
RECORDED. Q-022's "34 findings carry a control" does not reproduce; against this database it is 3.

Two results the ticket did not have, both of which change the fix:

**(a) The exhaustive walk found exactly ONE real nested location, plus one decoy.**
`browser_evidence.negative_controls.control` is not a second producer shape -- it is BIE's *inner*
probe label `control` (the attacker's own object) sitting inside the controls dict, matched because
`control` is itself a `CONTROL_KEY`. A fix that deep-scans for CONTROL_KEYS at any depth would count
it, and worse (see (c) below) would count a completely different thing under the same name.

**(b) The top-level shape is NOT fictional in source -- it has simply never run.** Census of the
producers, by grep over `agent/*.py`:

| producer | site | where it writes the control |
|---|---|---|
| `bie.py` | `:373` persona-swap BOLA | nested `browser_evidence.negative_controls` (dict) |
| `bie.py` | `:917` param tamper | nested `browser_evidence.negative_controls` (dict) |
| `bie.py` | `:1160` client-side authz | nested `browser_evidence.negative_controls` (dict) |
| `mass_assign_tool.py` | `:719`, `:776` | **top-level** `negative_controls` (list) |
| `ws_tool.py` | `:481`, `:527` | **top-level** `negative_controls` (list) |

Stored-finding census by family, same 1057 rows:
`mass_assignment 0`, `cswsh 0`, `bola 3`. So both top-level producers are real and neither has ever
stored a finding here. The precise statement is therefore *not* "no producer emits the top-level
shape" but "**the only shape any producer has ever actually stored is the nested one, and that is
the one the reader is told does not exist**". The top-level branch must keep working: it is the only
shape mass-assignment and CSWSH will ever emit.

**(c) `browser_evidence.control` means something else entirely, and a naive deep scan would lie.**
BIE phase 3 (`bie.py:1157`) writes, inside the same `browser_evidence` dict, a key literally named
`control` holding the *DOM element* the interface withheld -- tag, text, href, visible, disabled.
That is the thing under test, not an experiment that ruled out a benign explanation. Any fix that
treats "a CONTROL_KEY name anywhere below the finding" as an artifact stamps RECORDED on a phase-3
finding whose `negative_controls` is empty -- i.e. it produces exactly the false RECORDED that DoD 3
forbids. The fix reads **one declared key inside declared containers**, never a blind deep scan.

## MEASURED -- the defect, on real committed data

`agent/tests/findings_57cc3b49.json` already holds the **verbatim** findings rows of mission
57cc3b49 (its own `_provenance` header: read read-only out of the live volume, not hand-written, not
trimmed). One of its 2 findings is BIE finding `ef918650c9bb` -- the same row the live-DB walk found.
So the fixture this ticket demands already exists in the repo; it did not need to be written, only
*read*, which is the whole lesson of Q-071.

Reproduced in the agent image, no DB mount needed:

```
findings in fixture file: 2 ; with browser_evidence: 1 ; id: ef918650c9bb
be keys: [... negative_controls ...]      nc keys: ['anon', 'control', 'nonexistent']
proof_schema.control_status -> not_recorded
report.control_ran           -> False
claim heading                -> False-positive safety: NOT ESTABLISHED for this finding
```

Three real controls -- anonymous 401/972B, implausible id, attacker's own object -- rendered in the
table by `report.browser_evidence_html`, beside the sentence "NO NEGATIVE CONTROL WAS RECORDED".

Grepped for secrets before using it: the only hits for
`authorization|bearer|eyJ|token|cookie|password|secret|api[-_]key` are (1) the literal Juice Shop 401
error page "No Authorization header was found", (2) `"secrets": "[REDACTED -- held server-side]"`,
(3) the replay script's `$1` placeholders. No credential material. The file is already committed.

## Status

| slice | state |
| --- | --- |
| population + producer census re-measured | MEASURED, above |
| fixture identified (real, already committed) | MEASURED, above |
| failing test | in progress |
| fix in `report.py` | in progress |
| mutation test | in progress |
| full suite | in progress |

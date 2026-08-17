# provenance lane, run 2 - cycle 9, 2026-08-17

Ticket: **Q-064** (`ledger_finding_disagreement()` raises a FALSE integrity alarm).
Run 1 closed Q-060 (`3dca74c`) and did not start Q-064; `docs/handoff/provenance.md` records it as
"Not started", which matches the tree.

Files this lane may WRITE: `agent/agent.py`, `agent/report.py`, new tests under `agent/tests/`,
this file. Patches for anything else are recorded at the bottom, not applied.

Written as I go. A row with no commit hash is `in progress`, never a claim.

---

## Q-064 - the two records of one mission use two vocabularies

### The false alarm, REPRODUCED on the live records (MEASURED)

Not a fixture. The real ledger (`agent/tests/tool_ledger_57cc3b49.json`, 46 rows) and the real
findings table for the SAME mission, both read read-only out of the `apolaki_bbh_data` volume:

```
$ docker run --rm --network apolaki_default -v apolaki_bbh_data:/data:ro \
    -v .../agent:/app -w /app apolaki-agent python /scratch/measure_live2.py 57cc3b49
real findings: [('browser_persona_bola', 'Cross-user object read confirmed in the '),
                ('xss', "Reflected XSS (html) in 'sort'")]
ledger rows: 46
productive           : []
produced_but_unlogged: ['browser_persona_bola', 'xss']
WARNING RENDERS: True
    > (warn) **Ledger disagreement:** `browser_persona_bola`, `xss` produced findings but the tool
      ledger has no record of running them. ...
```

Both halves are wrong, and the second half is the one nobody has been quoting:

- `produced_but_unlogged` names TWO engines that both plainly ran. The ledger has
  `confirm_browser_persona_bola` (calls 1, findings 1) and `run_xss`.
- `productive` is **empty** on a mission that produced two findings from two engines. The useful
  half of the function - the honest complement to `arsenal_gap()["silent"]` - reports zero, always.
  A check that cries wolf ALSO stopped answering the question it was built for.

### How wide it is: 95 of 111 (MEASURED)

The ticket reads like one engine's quirk. It is the normal case. AST over `tools.py`, first string
argument of every `ToolResult(...)` inside each `_<dispatch_name>` method, against
`TOOL_PERMISSIONS`:

```
registered tools: 111
engines whose ToolResult name == dispatch name : 15
engines with NO literal ToolResult in own body : 1
engines whose ToolResult name DIFFERS          : 95
```

So the warning is not "sometimes wrong": for 95 of 111 engines it fires on every finding they ever
produce, and `productive` can only ever name the other 15.

### Why prefix-stripping was never available, with the counterexample

The ticket forbids normalising in the checker. The measurement shows it would also not WORK:

```
   dispatch=run_path_sqli                     ToolResult=sqli
   dispatch=run_sqli                          ToolResult=sqli
   dispatch=run_sqli_structural               ToolResult=sqli
   dispatch=run_default_creds                 ToolResult=default_credentials
   dispatch=run_username_enum                 ToolResult=username_enumeration
   dispatch=check_takeover                    ToolResult=takeover
   dispatch=test_numeric_abuse                ToolResult=numeric_abuse
```

- The map is **many-to-one**: three distinct dispatches emit `sqli`. A finding stamped `sqli` cannot
  be resolved back to the row that produced it, so any normaliser has to guess, and a guess in an
  integrity check is the thing the check exists to detect.
- Stripping `run_` from `run_path_sqli` yields `path_sqli`, which is not `sqli`. Stripping the
  prefix does not even close the instance that motivated it.
- Three different prefixes are in use (`run_`, `confirm_`, `check_`, `test_`) and two names are
  expansions rather than truncations (`default_creds` -> `default_credentials`).

### The fix

_(in progress - nothing claimed here until it has a commit)_

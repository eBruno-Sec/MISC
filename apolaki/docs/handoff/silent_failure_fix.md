# I-5 silent-failure residue: fixing the 15 load-bearing literal-return handlers

Lane opened 2026-08-21 from HEAD `66a7012` (verified green 3519 passed / 11 skipped /
12 xfailed / 0 failed).

## The defect this lane fixes

`_swallowed()` in `agent/tests/test_silent_failure_invariant.py` applies `_constant()`
to its **Assign** branch but not to its **Return** branch. A handler ending `out = []`
is classified; a handler ending `return []` is classified into no category at all and
is therefore constrained by no ceiling. The guard was repaired in a previous lane to
census and CAP those handlers (`_literal_return_swallow`, ceilings at the bottom of the
file). Capping is not fixing. The handlers themselves still swallow.

Fix shape (the one `tools.py` already uses elsewhere): record the swallow, then return
the same empty value. **The return value and the control flow do not change.** The only
change is that the failure becomes visible in the swallow ledger instead of being
indistinguishable from a clean result.

---

## DELIVERABLE 1 - the 15 load-bearing literal-return handlers (MEASURED)

Derived with the guard's own machinery, not a new predicate:
`_partition(predicate=_literal_return_swallow)` with the shipped `_load_call` /
`load_shaped` classification, run against the imported modules inside a throwaway
`apolaki-agent` container.

Command:

    MSYS_NO_PATHCONV=1 docker run --rm -i \
      -v "C:/Users/voice/Desktop/GitHub/MISC/apolaki/agent:/app" -w /app \
      apolaki-agent python - < derive.py

Real output (header line):

    TOTAL 89 {'optional': 61, 'load-bearing': 15, 'control-plane': 13}

which reproduces the shipped ceilings exactly (`optional <= 61`,
`control-plane <= 13`, `load-bearing <= 15`). The 15, as `module:line:function`:

| # | module:line:function |
|---|----------------------|
| 1 | `bie.py:1401:session_fingerprint` |
| 2 | `dns_recon.py:130:doh` |
| 3 | `enip_audit_tool.py:84:_list_identity_tcp` |
| 4 | `tools.py:2457:_fetch` |
| 5 | `tools.py:2874:_get` |
| 6 | `tools.py:3409:_socket_service_probe` |
| 7 | `tools.py:3425:_socket_service_probe` |
| 8 | `tools.py:3608:_send` |
| 9 | `tools.py:4773:_discover_params` |
| 10 | `tools.py:5472:_form_xss_browser_confirm` |
| 11 | `tools.py:5678:_send` |
| 12 | `tools.py:6586:send` |
| 13 | `tools.py:7582:read_state` |
| 14 | `tools.py:7608:worker` |
| 15 | `tools.py:8416:q` |

Ownership check against this lane's write boundary: **none of the 15 live in
`deadcode_gate.py` or `exposure_tool.py`** (both owned by another live lane), so none
has to be deferred as a patch-in-doc. Modules touched: `tools.py` (12), `bie.py` (1),
`dns_recon.py` (1), `enip_audit_tool.py` (1).

Line numbers are as of the working tree at lane open; they shift as fixes land above
them. The `module:function` pair is the stable key - `tools.py` has two distinct
`_send` and the two `_socket_service_probe` rows are two handlers in one function.

---

## Progress log

(appended as each slice lands)

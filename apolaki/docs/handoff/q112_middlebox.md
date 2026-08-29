# Q-112 - a middlebox eating our own payloads is indistinguishable from a clean target

Lane B (Builder). Ticket #123. Written as the work happens; if this lane dies, this file is the
contribution.

## The measurement handed to this lane (NOT re-derived here)

The operator scanned Shopify (his own authorized program scope). Mid-scan he opened his ISP
gateway's app and found his own router IPS dropping Apolaki's probes OUTBOUND, before they left
his network:

```
16:50  HTTP URI Comment Characters SQL Injection was blocked
16:50  HTTP URI 1=1 SQL Injection was blocked
16:50  HTTP URI Equal To SQL Injection was blocked
16:54  HTTP URI Union Select SQL Injection was blocked
17:08  (the same three again)      17:12  Union Select again
```

Those strings are `sqli_tool`'s payloads. The report for the same run said:

```
run_sqli            | executed | 70 | 0 | tested 3 param(s), 0 confirmed SQLi
run_sqli_structural | executed | 69 | 0 | 0 structural SQLi finding(s)
run_xpath / run_ldap / run_ssi / run_css_injection | 69 each | 0
```

Every one of those zeros is a blocked request, not a tested parameter. Enabling WireGuard bypassed
the ISP IPS and roughly tripled the sweep rate, so the drops also cost wall-clock time (a dropped
request sits until its timeout).

Defect class: the same sentence as Q-092 (`_cmd` discarded an exit code), Q-093 (`_http` discarded
a transport outcome) and Q-097 (an empty header dict from a dead socket read as a clean response) -
**a failed attempt must not be reported as a clean result**. What is new here is that the failure
happens on OUR side of the wire, so no error ever reaches the process: the request is answered by
the middlebox or times out, and the engine records a legitimate-looking zero.

## Design decision: a differential, never a vendor fingerprint

The general, target-agnostic signal, all three clauses required:

1. a benign request to the same host succeeds, AND
2. every payload-bearing request to that host fails at the transport (no response at all), AND
3. the pattern holds across UNRELATED hosts (different registrable domains).

Clause 3 is the entire discriminator. ONE host behaving this way is a WAF on the target, which is a
finding about the target. The SAME behaviour across unrelated hosts is a middlebox on our side,
which is a fact about the run and voids every injection result in it.

Deliberately NOT implemented, and why:

- No IPS/WAF vendor signatures, no block-page body matching. The oracle is transport-level only.
- A 4xx/403 "blocked" response counts as `ok` (a response was received). A target WAF that answers
  403 to payloads is indistinguishable from the app's own refusal without fingerprinting, and it is
  a fact about the target either way. UNVERIFIED extension noted at the bottom.

## Files

- `agent/middlebox.py` (new) - pure. No HTTP, no I/O, no imports beyond stdlib. A ledger of
  recorded per-request outcomes plus `assess()`, a pure function over the ledger's stats.
- `agent/tools.py` - feeds the ledger and reads the verdict.
- `agent/tests/test_middlebox_is_not_a_clean_result.py` - the gate + both negative controls.

## Status

- [x] Understand existing DEGRADED mechanism (Q-110) - MEASURED, see below
- [x] `agent/middlebox.py` written
- [x] wiring into `tools.py`
- [x] tests + gate
- [x] committed

## MEASURED: the Q-110 DEGRADED mechanism this reuses

`agent/tools.py` `_run_sqli` (line ~8774), `_run_nosqli` (~9074), `_run_cmdi` (~9236) each end:

```python
_trunc = (" -- DEGRADED: call budget of %ds exhausted, sweep TRUNCATED ..." ) if _budget_hit else ""
return ToolResult("sqli", url, not _budget_hit, f"tested ... , {len(findings)} confirmed SQLi" + _trunc, findings)
```

so `ToolResult.success` is the `ran` flag the execution ledger reads. Q-112 reuses exactly this:
the middlebox verdict ANDs into that same `success` argument and appends its own `DEGRADED:` line.

MEASURED: the choke points the ledger is fed from.

- `_run_sqli` / `_run_nosqli` / `_run_cmdi` each own a local `async def get(c, target)` that already
  swallows the transport exception and returns `None`. That is the exact line where a dropped probe
  became a clean zero. One edit each.
- `_run_xpath` / `_run_ldap` / `_run_ssi` reach GET query parameters through `self._http`, which
  since Q-093 has the ONE place a transport failure is known (`status == 0`). One edit covers all
  three plus every other `_http` caller.

# Q-148 -- passive content disclosure (LANE C, Builder)

Module: `agent/passive_disclosure.py`. Tests: `agent/tests/test_passive_disclosure.py`.
PURE: no network, no state, no `except` handler anywhere in the module (see "silent-failure" below).

Status legend: MEASURED = a command was run and its output is quoted. UNVERIFIED = claimed, not run.

## THE PROBLEM THIS TICKET IS

Burp's passive-disclosure family is regex-shaped, and regex-shaped disclosure checks are the classic
false-positive generator. `test_exposure_catchall_is_not_a_file.py` documents a CRITICAL "Exposed
.env file" raised against a WordPress install with no .env, from exactly two mistakes:
`re.I` on a case-BEARING signature, and `\s` matching newlines so `^` bought nothing.

Every check below therefore ships with BOTH halves of its ground truth: a positive that must fire and
an ordinary-page lookalike that must NOT. Where a check could not be made non-noisy, it is REFUSED
and the refusal is recorded here as the result.

## SHIPPED / REFUSED (filled in as each slice lands)

See "Per-check ledger" below.

## Wiring patch for the Coordinator (I do not own tools.py)

Recorded at the bottom of this file once the module is green.

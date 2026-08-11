# Throughput lane - hand-off

## Status: slice 3a landed (91d4d16). One test HELD BACK, deliberately.

`agent/tests/test_dom_audit_concurrency.py::test_probe_renders_actually_overlap` is **uncommitted and
failing**, and it is not committed because **its own author determined it was wrong** immediately
before being killed:

> "My early-exit test was wrong - confirming `proto` unlocks the gadget pass, so more confirmations
> can cost more renders. Let me isolate it properly."

So the assertion counts renders as a proxy for overlap, while the number of renders is itself a
function of how many probes confirm. A confirmation unlocks the gadget pass, which costs MORE
renders - so a faster, more-concurrent run can legitimately render more, and the test fails on
success. That is a broken oracle, not a broken feature.

**Do not "fix" this by relaxing the assertion.** Measure overlap directly - wall-clock of N probes
against N x single-probe latency, or timestamped start/end spans - so the metric cannot be moved by
how many probes happened to confirm.

The rest of the lane's work is committed and green (1908 passed with this one test excluded).

## Still open on this lane
- The diagnosis was never completed: WHERE the ~8.5s per tool call goes is still unmeasured.
  Candidates untested: network latency, per-call browser startup, sequential awaits, retry backoff,
  the intercept proxy, TLS handshake per request.
- Recall is 1.6% and bounded by wall-clock, not detection. This lane is still the top ticket.

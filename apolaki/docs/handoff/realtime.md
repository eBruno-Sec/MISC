# REALTIME lane -- Q-002: Cross-Site WebSocket Hijacking (CWE-1385 / CWE-346, WSTG-CLNT-10)

Ticket: build the smallest general engine that CONFIRMS CSWSH with deterministic proof.
Owner files: `agent/ws_tool.py` (new), `agent/tools.py`, `agent/engine_descriptor.py`,
`agent/wstg_catalog.py`, `agent/tests/test_ws_tool.py` (new), this file.

Every claim below is MEASURED (command + real output) or UNVERIFIED.

---

## 1. The zero-engine claim, re-measured

MEASURED:

```
$ grep -rn "Sec-WebSocket\|websocket\|WebSocket" --include=*.py agent/
agent/report.py:778:    "request_url_override": "Never build a client-side fetch/XHR/WebSocket target ..."
agent/wstg_catalog.py:39:    "WSTG-CLNT-10": "WebSockets",
```

Two hits, both prose. No handshake, no frame decoder, no oracle. `WSTG-CLNT-10` was in neither
`FULL` nor `PARTIAL` nor `EXCLUDED`, so `coverage()` reported it `none / not yet implemented`.
Confirmed genuine zero-engine class.

MEASURED -- there IS an existing WebSocket discovery source that fed nothing:
`agent/browser_engine.py:238` collects `ws://` / `wss://` request URLs into `runtime_ws`, and the
ONLY consumer (`browser_engine.py:498`) folds it into the `has_api` observation. The URLs themselves
were discarded. That is the seam this engine plugs into.

---

## 2. Ground truth on the live lab, taken BEFORE writing the oracle

Juice Shop (`apolaki-juice-shop-bench-1`, network `apolaki_default`) exposes socket.io.
Probe: raw `asyncio.open_connection` HTTP/1.1 Upgrade, attacker `Origin: http://evil.example`,
with and without the session credential.

MEASURED:

```
LOGIN ok token=eyJ0eXAiOiJKV1QiLCJhbGciO... cookie=

== /socket.io/?EIO=4&transport=websocket EVIL-ORIGIN+COOKIE ==
  status: HTTP/1.1 101 Switching Protocols
  accept-valid: True (got m2fqLhy5PGq8 want m2fqLhy5PGq8)
  frames: [(1, b'0{"sid":"fOcfpqZA9zEc6crMAAAA","upgrades":[],"pingInterval":25000,"pingTimeout":5000}')]

== /socket.io/?EIO=4&transport=websocket EVIL-ORIGIN+NOCOOKIE ==
  status: HTTP/1.1 101 Switching Protocols
  accept-valid: True (got OrpmjQd4ZgLC want OrpmjQd4ZgLC)
  frames: [(1, b'0{"sid":"s3UsPOoUjURjjUUYAAAB","upgrades":[],"pingInterval":25000,"pingTimeout":5000}')]
```

Three results, all load-bearing:

1. **Half (a) holds on Juice Shop.** The server completes a cross-origin upgrade: `101` plus a
   `Sec-WebSocket-Accept` that verifies against the key we sent. No `Origin` check at all.
2. **Half (b) does NOT hold.** The first pushed frame is the Engine.IO handshake `0{"sid":...}`.
   That `sid` is a fresh socket id minted for this connection -- it is not the identity the HTTP
   session proved.
3. **The negative control is IDENTICAL.** Cookie stripped, the server still answers 101 and still
   pushes the same frame shape. So the data is public, not authenticated.

**Juice Shop is therefore a LEAD, not a confirmed CSWSH, and the engine must say so.** An engine
that reported (a) as a finding would report Juice Shop as vulnerable, which it is not on this class.
This measurement is the single most useful negative control available on the lab estate and it is
wired into the test suite as a recorded fixture.

MEASURED and load-bearing for correctness: Juice Shop's login returns **no cookie** (`cookie=` is
empty); the session is a `Authorization: Bearer` header. That drives a design rule in section 3.

---

## 3. Design rules the measurements forced

**R1. A Bearer token is not a hijackable ambient credential.** CSWSH works because the *browser*
attaches the cookie to a cross-origin `new WebSocket()` automatically. A Bearer header is set by
JavaScript, and attacker-origin JavaScript cannot read or set it for another origin. So a session
that carries only `Authorization` can NEVER be confirmed CSWSH, regardless of what the handshake
returns. The engine requires a Cookie in `session_headers` and caps everything else at a lead.
Without this rule the engine would have promoted Juice Shop on a token the attack cannot use.

**R2. `101` alone is not half (a).** Many servers upgrade and then reject at the application layer.
The engine computes `base64(sha1(key + 258EAFA5-E914-47DA-95CA-C5AB0DC85B11))` from the key it
actually sent and compares. Status, `Upgrade: websocket`, and the derived accept must ALL hold.

**R3. The marker must be an OBSERVED identity value, never an invented one.** Same discipline as
`session_lifecycle_tool.build_discriminator` ("Never an invented string"). The engine reuses
`ToolRegistry._known_account()`, the existing helper that returns the scan's verified login or a
persona identity. An invented marker could not appear in either frame, and the engine would report
clean on a genuinely vulnerable endpoint.

**R4. The control failing is not enough -- the control CARRYING the marker kills the finding.** If
the cookie-stripped handshake pushes the same marker, the data is public. That path returns `clean`,
not `confirmed`. This is what demotes Juice Shop.

**R5. Empty is a real input.** An empty marker list, an empty cookie, an absent `Origin` and an empty
accept header are each handled explicitly and each cap the verdict at `lead` or `clean`. No
`x or DEFAULT`.

---

## 3a. A defect my own test found, and the guard it forced

Writing the Juice Shop regression exposed a real false-positive in the first draft of the oracle.

The oracle asks "did the cookie-stripped control receive this same marker?". A marker that is a
**per-connection nonce** passes that test trivially, because the control cannot echo a token minted
for the authed connection. Feed the engine Juice Shop's socket id and the first draft returned
`confirmed` on a completely public endpoint:

```
MEASURED (before the fix):
  evaluate(authed=sid fOcfpqZA9zEc6crMAAAA, control=sid s3UsPOoUjURjjUUYAAAB,
           markers=["fOcfpqZA9zEc6crMAAAA"], had_cookie=True)
  -> AssertionError: assert 'confirmed' != 'confirmed'
```

Fix: `ws_tool.identity_markers()` drops nonce-shaped values (>=16 chars, alphanumeric-only, mixing
upper AND lower AND digits) before any matching. A marker must be an account identity -- the thing
the HTTP session actually proved -- not an opaque token.

REJECTED ALTERNATIVE, recorded because it looks better than it is: comparing the two frames'
normalised SHAPE instead. `{"user":"alice1234"}` vs `{"user":"anonymous"}` normalises identically
and is a genuine confirm, so a shape rule trades this false positive for a false negative. Rejecting
nonce-shaped markers costs nothing real; `test_identity_markers_keeps_real_identities` is the
negative control that pins it (8 real identities, none dropped).

## 3b. Mutation test -- the tests are non-vacuous

Each mutation was applied to a copy of `ws_tool.py` and had to be KILLED by the exactly-intended
test. MEASURED, 7 of 7 killed:

| Mutation | Killed by |
| --- | --- |
| `handshake_accepted` trusts the 101, skips the RFC 6455 accept check | `test_a_101_with_a_wrong_accept_is_rejected` (+2 more) |
| `evaluate` confirms on the upgrade alone (half (a) only) | `test_upgrade_without_authenticated_data_is_a_lead_not_a_finding`, `test_juice_shop_measured_capture_is_a_lead_not_a_finding` |
| `evaluate` drops the negative-control check | `test_a_public_socket_is_clean_because_the_control_got_the_same_marker` |
| `evaluate` drops the cookie (ambient-credential) gate | `test_a_bearer_only_session_is_a_lead_not_a_confirm` |
| `identity_markers` drops the nonce filter | `test_the_juice_shop_sid_is_never_mistaken_for_an_identity_marker`, `test_identity_markers_rejects_nonce_shapes` |
| `decode_frames` ignores the mask bit | `test_decode_honours_a_mask_bit_even_though_servers_must_not_set_it` |
| `frames_text` includes control frames | `test_frames_text_excludes_control_frames` |

No mutant survived.

## 4. Status log

- [x] Ground-truth probe of the live lab (section 2). MEASURED.
- [x] Oracle + tests committed BEFORE any wiring.
- [x] Local paired vulnerable/secure WS server, confirm path proven end to end.
- [x] Wiring: dispatcher, CLAUDE_TOOLS, permission, engine_descriptor, wstg_catalog.
- [x] Full regression.

---

## 5. PATCH FOR ANOTHER OWNER -- `agent/agent.py` (I do not own this file)

The engine is dispatched from `ToolRegistry._run_client_checks`, which `agent.py` already fires on
every HTML page (see section 7 for the proof it runs). That is a real always-on path and needs no
agent.py change to work.

One OPTIONAL improvement I could not make, recorded so it is not lost. `agent/browser_engine.py:498`
throws away the `runtime_ws` URL list after folding it into `has_api`:

```python
    if obs.get("runtime_ws"):
        out.add("has_api")
```

The browser sensor is the only component that sees WebSocket endpoints opened by JS at runtime that
never appear in the page HTML. Persisting those URLs onto the tool state (e.g.
`tools.state.ws_endpoints`) would let `_run_ws_hijack` test runtime-discovered endpoints too, not
only ones it can find in HTML/JS text. The engine already accepts an explicit `ws_urls` input for
exactly this, so the patch is additive and needs no change in `ws_tool.py`.

---

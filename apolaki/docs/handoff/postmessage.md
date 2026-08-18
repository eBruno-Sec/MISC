# Q-003 -- `postMessage` as a DOM-XSS source (CWE-346 -> CWE-79), WSTG-CLNT-11

Lane: postMessage (Builder). Written as the work happens. Every claim is MEASURED (command + real
output) or UNVERIFIED.

## 1. Ground truth BEFORE building -- is the ticket real?

The ticket's root cause claims `postMessage|MessageEvent|onmessage` appears nowhere in `agent/`.

MEASURED:

    $ grep -rn "postMessage\|MessageEvent\|onmessage" agent/ --include=*.py | wc -l
    0

Positive control that the apparatus was looking (the same grep with a token that MUST exist):

    $ grep -rn "addEventListener" agent/ --include=*.py
    agent/tests/test_client_request_source.py:16: ...addEventListener("submit", ...)

So the zero is a real zero, not a broken probe. **Q-003 is CONFIRMED OPEN.** `message` is not a
tracked source anywhere in the codebase.

Existing DOM sources, MEASURED by reading `agent/dom_tool.py:build_probes` and
`agent/dom_trace.py`:

| engine | sources it drives |
|---|---|
| `run_dom_audit` (`dom_tool.py`) | URL fragment (`location.hash`), query parameters |
| `run_dom_trace` (`dom_trace.py`) | query parameters, URL fragment |

Neither reaches a `message` handler, and no handle-obtaining context (iframe / `window.open`) is
constructed anywhere in the product.

## 2. Where the capability goes -- and why it is NOT a new engine

Q-003 says "adding a SOURCE to a working confirmation engine, not a new engine". That is also the
NO-ISLANDS answer: `run_dom_audit` is already in `TOOL_PERMISSIONS` (ACTIVE), already dispatchable
via `getattr(self, "_run_dom_audit")`, and already advertised in `CLAUDE_TOOLS`. Extending it adds
zero registration risk. This project has 32 engines that never executed across 151 missions; this
lane does not add the 33rd.

## 3. Real-world fixture material (COPIED, NEVER INVENTED)

Sweep of every running local lab for a window `message` listener:

    $ for p in 42080 42084 42088 42089 42091 42092 42093 42094 42001 42097; do ...; done
    -> no lab root HTML registers a `message` listener

    $ curl -s http://127.0.0.1:42000/main.js | grep -c 'addEventListener("message"'
    0
    $ curl -s http://127.0.0.1:42000/main.js | grep -c 'onmessage'
    1

**The one Juice Shop hit is a FALSE POSITIVE TRAP, and it is the most valuable fixture found.**
Extracted verbatim from the live bundle:

    ...this.ws.onopen=function(){a.onOpen()},this.ws.onclose=function(){a.onClose()},
    this.ws.onmessage=function(e){a.onData(e.data)},this.ws.onerror=...

That is socket.io's WebSocket transport -- `ws.onmessage`, NOT `window.onmessage`. A naive regex on
`onmessage` reports a web-message vulnerability on Juice Shop that does not exist. This shape is
carried into the tests as a real, copied negative fixture.

## 4. Status

- [x] Ground measured; ticket confirmed open
- [ ] Slice 1: pure detection + origin grading in `dom_tool.py` + tests
- [ ] Slice 2: browser confirmation phase in `tools.py`
- [ ] Slice 3: live measurement + honest ceilings

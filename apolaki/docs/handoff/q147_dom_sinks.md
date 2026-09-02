# Q-147 - the DOM sink family (`agent/dom_sinks.py`)

LANE B (Builder). Status: IN PROGRESS. Every claim below is MEASURED (command + real output) or
UNVERIFIED.

`agent/dom_sinks.py` is a PURE classifier. It takes the runtime signals a render collected and
returns finding dicts, in exactly the shape `dom_trace.classify` / `dom_trace.finding` return. It
drives no browser, opens no socket and holds no state.

Files I own and may write: `agent/dom_sinks.py`, `agent/tests/test_dom_sinks.py`,
`docs/handoff/q147_dom_sinks.md`. `agent/tools.py` and `agent/dom_trace.py` are NOT touched - the
wiring patch is at the bottom of this file for the Coordinator to apply.

---

## 1. Why this order

The ticket said to prioritise by real bounty value. Mine, and the reasoning:

| # | Sink | Why here |
|---|------|----------|
| 1 | postMessage (`web_message_*`) | The only class on the list that is BOTH common in modern SPAs and almost never tested. Every OAuth/SSO/embedded-widget flow ships a `message` listener, most skip the `event.origin` check, and the payload usually lands in `innerHTML` or `eval`. It is a full XSS with no reflected parameter anywhere, so no request/response engine can see it. Highest expected value by a wide margin. |
| 2 | `document.domain` write | A one-line write that hands the whole SOP boundary to any sibling subdomain. Cheap to detect (hook the setter), and the finding is unambiguous: either attacker input reached the assignment or it did not. Burp rates it Medium; the real-world chain (one XSS on any subdomain -> full account takeover on the parent) is worth more than that. |
| 3 | WebSocket URL poisoning | Same class as `request_url_override`, which Apolaki already proves, but WebSockets bypass every fetch/XHR hook the existing engine installs, so today the connection is invisible. Attacker-chosen WS endpoint = the session's whole duplex channel goes to the attacker. |
| 4 | Form action hijacking | The highest-impact PRESENCE sink: the form posts the victim's credentials to the attacker. Burp lists reflected AND stored variants, so this one cannot be gated the way the others are - see section 3, it is the one deliberate exception in this module and it has its own test. |
| 5 | HTML5 storage manipulation | Real value only in the STORED shape (poison storage, reload clean, the payload comes back). That is a two-render oracle, which is also what makes it honest: the replay URL carries no canary at all. |
| 6 | Client-side HPP / JSON / XPath injection | One structural oracle each, ~8 lines apiece. Cheap, and each has a real structural discriminator (a distinct query key, a parsed object key, a broken expression) rather than a substring. |
| 7 | Ajax request header manipulation | Genuine but narrow: header VALUE control is usually harmless, header NAME control is the bug. Severity split accordingly. |
| 8 | DOM-based DoS | Implemented as a repeated differential only. Timeouts are the noisiest signal on this list; one hang is a flaky lab, not a finding. |
| 9 | Local file path manipulation | Near-zero yield against a browser (an `http:` page cannot navigate to `file:`), but it is 6 lines and it shares the Q-128 gate, so it is the module's second gated-presence family and doubles as the gate's generalisation test. |
| 10 | PRSSI | Kept last on purpose. The XSS half of PRSSI needs IE CSS expressions, which no shipping browser has. What remains is a real but low finding, so it is a three-signal conjunction at LOW severity and nothing else. |

### Judged NOT worth automating

- **Client-side SQL injection (WebSQL).** DELIBERATELY NOT IMPLEMENTED. The API it needs
  (`openDatabase` / `executeSql`) was removed from Chromium; the whole Web SQL Database feature was
  taken out in Chrome 123, having been removed from insecure contexts in 119. Apolaki drives headless
  Chromium. An engine for it could never fire once, in any target, on this browser - that is exactly
  the zero-histogram dead engine shape (`dalfox 0/171`, `nuclei 0/155`). Shipping a family whose
  detector is structurally incapable of firing adds a line to the taxonomy and zero recall, and it
  makes the next dead-engine census dirtier. If a target is ever driven under an old Chromium or an
  Electron shell, revisit.
- **The stored variants of WebSocket URL poisoning and local file path manipulation.** Not a
  separate detector: "stored" is a property of how the input got there, not of the sink. The storage
  replay pass (`storage_manipulation`) already covers "the payload survives a clean reload", and it
  reports which side stored it. Two more families would report the same event twice.

---

## 2. The two hard rules, and how each family answers them

**Q-128 - presence in the DOM is not a DOM flow.** **Q-129 - a page that never loaded is not a page.**

The governing principle I implemented, stated once:

> A presence signal must be gated on `server_reflected` when the finding's CLAIM is "client-side code
> did this". It need not be gated when the claim is STRUCTURAL and true no matter who wrote the value
> - but then the finding must not claim a DOM flow, and must name the real mechanism (reflected /
> stored / DOM) from `server_reflected` instead.

| Family | Kind | `server_reflected` gate | `navigated` gate |
|---|---|---|---|
| `web_message_xss` | behaviour (a dialog fired) | no | no |
| `web_message_manipulation` | behaviour (a sink received the message) | no | no |
| `document_domain_manipulation` | behaviour (the setter ran) | no | no |
| `websocket_url_poisoning` | behaviour (a socket was constructed) | no | no |
| `client_side_hpp` | behaviour (a request went out) | no | no |
| `client_json_injection` | behaviour (`JSON.parse` returned the key) | no | no |
| `client_xpath_injection` | behaviour (the expression broke) | no | no |
| `ajax_header_manipulation` | behaviour (`setRequestHeader` ran) | no | no |
| `client_side_dos` | behaviour (repeated differential hang) | no | no |
| `storage_manipulation` | behaviour + presence on the REPLAY render | YES (on the replay) | YES |
| `local_file_path_manipulation` | presence | YES | YES |
| `form_action_hijack` | presence, structural | NO - documented exception, section 3 | YES |
| `prssi` | page property, no canary | n/a (no canary to reflect) | YES |

Behaviours follow `dom_trace` exactly: they are ungated on BOTH flags, because `navigated` is set
only after `goto` returns and a partially-rendered page that timed out can still have fired a real
behaviour. Suppressing a fired dialog because the load was slow is the wrong trade, and `dom_trace`
already made that call for `dom_xss` / `open_redirect` / `request_url_override`.

---

## 3. The one deliberate exception: `form_action_hijack`

Gating this family on `server_reflected` would DELETE the variant Burp calls "Form action hijacking
(reflected)", which is a genuine credential-theft bug and which the ticket's own sink list asks for:
the server echoes `?next=https://evil/` into `<form action="https://evil/">` and the victim's
password is posted to the attacker. The server put it there. That is the bug.

So the discriminator is not WHO wrote the value, it is WHAT the value controls:

- the finding fires only when the form's RESOLVED action AUTHORITY is the attacker host we injected
  (`dom_trace.is_evil_host` on the host component, parsed - not a substring search);
- a canary that merely appears somewhere in the action's query string is NOT a finding, which is
  precisely the WordPress shape that produced the 314 false positives (WordPress echoes the request
  URI into its own form and link targets);
- `server_reflected` still decides the WORDING: `reflected` when the server emitted it, `DOM-based`
  when client-side code built it. The module never claims a DOM flow for a server echo.

Both halves are pinned by tests (`test_a_canary_in_the_action_query_string_is_not_hijacking`,
`test_form_action_hijack_names_the_mechanism_from_server_reflected`).

---

## 4. Signals the render must collect (the handoff contract)

FILLED IN BELOW AS EACH SLICE LANDS.

## 5. Wiring patch for the Coordinator

FILLED IN BELOW WHEN THE MODULE IS COMPLETE.

## 6. Mutants killed

FILLED IN BELOW AS EACH SLICE LANDS.

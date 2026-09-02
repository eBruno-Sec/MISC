# Q-146 - language-specific server-side code injection

LANE A (Builder). Ticket: Burp lists 7 code-injection checks; Apolaki had ZERO.
`agent/cmdi_tool.py` does OS command injection (shell/argv shape) and nothing else.

Deliverable: `agent/code_injection.py` - PURE, no network, no state. Transport stays in
`tools.py`, which this lane does NOT touch. The wiring patch is at the bottom of this file
for the Coordinator to apply.

STATUS: design measured, module written, tests green. See "Slices landed".

---

## 1. The oracle problem, stated precisely

The SSTI postmortem (`agent/tests/test_ssti_marker_is_not_a_coincidence.py`) fixed a
coincidence detector (`"49"` from `{{7*7}}`) by making the marker the PRODUCT of RANDOM
operands. That device proves EVALUATION.

It does NOT prove WHICH LANGUAGE evaluated it. `4831*7219` is `34874989` in PHP, Python,
Ruby, Perl, Node and SpEL alike. Attribution needs a second, independent token.

So every probe here carries TWO tokens:

| token | proves | built from |
| --- | --- | --- |
| `eval_token` | that the server EVALUATED something | random marker + product of random operands |
| `attr_token` | WHICH language did it | a language-EXCLUSIVE builtin applied to a random nonce |

STANDING RULE, and it is what makes Burp's 7th bucket load-bearing rather than leftover:

    ATTRIBUTION COMES FROM THE ATTRIBUTION TOKEN ONLY.
    The arithmetic alone is NEVER attributed. It reports `unidentified_code_injection`.

This is not caution for its own sake. `print(A*B)` is valid PHP *and* Python. `#{A*B}`
is Ruby interpolation *and* JSF/SpEL EL. `${A*B}` is EL, SpEL, Freemarker, Velocity,
Thymeleaf and Angular. Naming a language off shared syntax is the same class of error as
naming RCE off two digits.

### Why a marker prefix and not the bare product

`web_security.analyze_ssti` matches a bare 7-8 digit product. A page carrying an
epoch-millisecond timestamp (13 digits) contains ~6 distinct 8-digit substrings, so the
bare product is not FP-free, only FP-rare. Every token here is `mark + value` where
`mark` is `ci` + 4 random lowercase letters, built by the payload's own string
concatenation. `ciqzmw34874989` cannot occur by chance and cannot be echoed, because the
digits are absent from the payload.

The one exception is the EL `hashCode` shape, whose output is necessarily a bare integer.
That token alone is matched with DIGIT BOUNDARIES (`(?<![\d-])...(?!\d)`) so it cannot
match inside a longer digit run - which is exactly the timestamp vector above.

### Time-based oracles: deliberately NOT shipped

The ticket names them a last resort. This module ships none, and the reason is recorded
rather than assumed: the operator's targets are Cloudflare-fronted and routinely take
seconds, `run_sqli` already carries a 240 s call budget for that reason, and a sleep
oracle on such a target is a slow-target detector. Every check here is output-based.

---

## 2. Ground truth - MEASURED, not recalled

Every payload below was run in a real interpreter in a throwaway `--network none`
container. Nonce `kqxzwmbd`, operands `4831*7219` (= `34874989`), reverse `dbmwzxqk`.

| lang | interpreter | command | output |
| --- | --- | --- | --- |
| PHP | `wordpress:cli` (PHP 8) | `php -r 'print(strrev("kqxzwmbd").(4831*7219));'` | `dbmwzxqk34874989` |
| PHP | same | `php -r 'print(bin2hex("kqxzwmbd"));'` | `6b71787a776d6264` |
| Node | `node:20-alpine` | `node -e 'console.log(String.fromCharCode(107,113,120,122,119,109,98,100))'` | `kqxzwmbd` |
| Python | `python:3.12` | `python -c 'print("kqxzwmbd"[::-1])'` | `dbmwzxqk` |
| Ruby | `apolaki-agent` (ruby 3.1.2) | `ruby -e 'puts %q(kqxzwmbd).reverse'` | `dbmwzxqk` |
| Perl | `wordpress:6-apache` (perl 5.40) | `perl -e 'print "@{[scalar reverse(q(kqxzwmbd))]}"'` | `dbmwzxqk` |
| Java | `zaproxy:stable` (JDK 17) | `"kqxzwmbd".hashCode()` | `-1737333632` |

### Two traps found by MEASURING instead of recalling

1. **Perl `reverse` in list context does not reverse a string.**
   `perl -e 'print "@{[reverse(q(kqxzwmbd))]}"'` printed `kqxzwmbd` - UNREVERSED. The
   `@{[...]}` baby-cart imposes LIST context, so `reverse` reversed a one-element list.
   `scalar reverse` is mandatory. Had I shipped the obvious form, the Perl attribution
   token would have equalled the nonce, which IS in the payload, and the structural
   echo-immunity would have been silently void. MEASURED.

2. **Java `String.replace` is global, so a separator inside the nonce corrupts the token.**
   `"ciqzmwxkqxzwmbd".replace("x","")` returned `ciqzmwkqzwmbd`, not `ciqzmwkqxzwmbd` -
   the `x` inside the nonce `kqxzwmbd` was eaten too. The separator is now a HYPHEN, which
   the alphanumeric marker and nonce cannot contain. MEASURED.

### Cross-language exclusivity of each attribution token

| token construct | exclusive because |
| --- | --- |
| `strrev(s)` | PHP builtin. Perl/Python/Ruby/JS have no such name. |
| `s[::-1]` | Python slice-with-step. MEASURED as a **syntax error in Ruby** (`unexpected tUMINUS_NUM`). |
| `s.reverse` | Ruby `String#reverse`. Python `str` has no `.reverse`; JS `"x".reverse` is `undefined`; PHP/Perl have no method call on a literal. |
| `@{[scalar reverse(s)]}` | Perl baby-cart. No other language parses `@{[ ]}`. |
| `String.fromCharCode(...)` | JS. The payload carries decimal CODES, so the letters it emits are absent from the payload. |
| `s.hashCode()` | Java's hash algorithm (`h = 31h + c`). Validated against the published constants `"abc"` = 96354 and `"Hello"` = 69609650, both reproduced by the JDK 17 run above and by this module's pure re-implementation. |

UNVERIFIED: no JSP/SpEL/Freemarker container is available locally, so the EL shapes are
verified only at the level of "the JVM computes this hashCode". Whether a given EL
implementation permits `.hashCode()` on a string literal is untested. A blocked method is
a FALSE NEGATIVE, never a false positive, so this is safe to ship un-tuned.

---

## 3. The EL / SSTI collision, resolved explicitly

The ticket flagged that `${A*B}` collides with SSTI. It does, and
`web_security._ssti_payload` ALREADY sends `{{A*B}}${A*B}`. Emitting another bare
`${A*B}` here would duplicate a live probe and manufacture the ambiguity.

Resolution - the EL probes never send bare `${A*B}`:

* `el_hashcode` (`${"NONCE".hashCode()}` and the JSF `#{...}` sigil) - the token is
  Java's own hash algorithm, so a hit is Java-side expression evaluation. Reported as
  `expression_language_injection`, CWE-917.
* `el_replace` (`${"MARK-NONCE".replace("-","")}`) - strong alpha token, but `.replace`
  exists in Python and JS and `${...}` is shared with several template engines, so this
  shape carries NO attribution token and reports `unidentified_code_injection` by design.

Anything that evaluates arithmetic but fails its attribution token lands in the same
`unidentified_code_injection` bucket, with the detail naming the plausible evaluators.

---

## 4. Slices landed

(updated as each commit lands)

---

## 5. WIRING PATCH FOR THE COORDINATOR - do not apply from this lane

`agent/tools.py` is owned by another lane this cycle. The call site below mirrors the
SSTI block at `tools.py:8019-8043` exactly (same client, same scope gate, same finding
shape). Insert it immediately AFTER the SSTI block.

```diff
--- a/apolaki/agent/tools.py
+++ b/apolaki/agent/tools.py
@@ after the SSTI loop that ends with the `_apolaki_swallowed_7230` handler
                     except Exception as _apolaki_swallowed_7230:
                         self._swallow(_apolaki_swallowed_7230, 'tools:_run_injection_probes:7230', "")
                         pass
+                # Q-146: language-specific SERVER-SIDE CODE injection (PHP/Python/Ruby/Perl/
+                # Node/EL). Distinct from SSTI above (template evaluation) and from
+                # _run_cmdi (OS command execution). Attribution comes from a
+                # language-EXCLUSIVE token; arithmetic alone reports "unidentified".
+                for wp in _codeinj.build_url_probes(url):
+                    if not self.scope.validate(wp.url)[0]:
+                        continue
+                    try:
+                        cir = await c.get(wp.url)
+                        v = _codeinj.analyze_code_injection(base_body, cir.text, wp.probe)
+                        if v:
+                            findings.append(_codeinj.code_injection_finding(
+                                wp.url, wp.parameter, wp.probe, v))
+                            break
+                    except Exception as _apolaki_swallowed_7146:
+                        self._swallow(_apolaki_swallowed_7146, 'tools:_run_injection_probes:7146', "")
+                        pass
```

and at the import site used by `_run_injection_probes`:

```diff
+import code_injection as _codeinj
```

`code_injection_finding` returns the complete finding dict (title/severity/target/
description/evidence/success_oracle/cwe/family/tags/confidence), so the call site stays
one line and the vocabulary stays in this lane's file.

NOTE for the Coordinator: `build_url_probes` yields 6 probes by default (one shape per
language) against the first parameter it can rewrite. That is 6 extra GETs per URL. If
the budget is tight, pass `languages=("php", "python", "javascript")` - those three cover
the overwhelming majority of real server-side eval sinks.

"""Language-specific SERVER-SIDE CODE injection -- seven Burp Scanner checks in one pure engine.

MINED FROM Burp's published issue catalog (portswigger.net/burp/documentation/scanner/
vulnerabilities-list), which lists these as SEVEN DISTINCT issues:

    PHP code injection                      Ruby code injection
    Server-side JavaScript code injection   Python code injection
    Perl code injection                     Expression Language injection
                                            Unidentified code injection

Apolaki had ZERO of them. `cmdi_tool.py` detects OS command injection -- a shell or an argv
launcher running `ping`/`id`. Getting an interpreter to evaluate `strrev(...)` inside an `eval()`,
a `preg_replace /e`, a `pickle` sink or a JSP expression is a DIFFERENT vulnerability with a
DIFFERENT oracle, and `web_security.analyze_ssti` covers only the template-engine case.

PURE. No network, no state, no clock. Builders make probes; analysers read bodies. Transport lives
in `tools.py`.

================================================================================================
THE ORACLE -- two tokens, because one is not enough
================================================================================================

The SSTI postmortem (`tests/test_ssti_marker_is_not_a_coincidence.py`) is the direct ancestor of
this file. That oracle used `_SSTI_MARKER = "49"` from `{{7*7}}` and raised CVSS 9.8 against
admin.shopify.com because a signup page contained the digits `49`. The fix was RANDOM OPERANDS:
`{{4831*7219}}` yields `34874989`, which is NOT a substring of the payload, so an echo of the
literal expression cannot produce it.

That device proves EVALUATION. It does NOT prove WHICH LANGUAGE evaluated it -- `4831*7219` is
`34874989` in PHP, Python, Ruby, Perl, Node and SpEL alike. Attribution therefore needs a SECOND,
INDEPENDENT token, and every probe here carries both:

    eval_token   marker + product of random operands      -> the server EVALUATED something
    attr_token   marker + a LANGUAGE-EXCLUSIVE builtin    -> which language did it
                 applied to a random nonce

STANDING RULE, and it is what makes Burp's seventh bucket load-bearing rather than leftover:

    ATTRIBUTION COMES FROM THE ATTRIBUTION TOKEN ONLY.
    Arithmetic alone is NEVER attributed to a language. It reports "unidentified code injection".

This is not caution for its own sake -- naming a language off shared syntax is the same class of
error as naming RCE off two digits:

  * `print(A*B)` is valid PHP *and* valid Python.
  * `#{A*B}` is Ruby string interpolation *and* JSF / Spring SpEL expression syntax.
  * `${A*B}` is EL, SpEL, Freemarker, Velocity, Thymeleaf and Angular.

WHY A MARKER PREFIX AND NOT THE BARE PRODUCT. `analyze_ssti` matches a bare 7-8 digit product; a
page carrying an epoch-millisecond timestamp (13 digits) contains six distinct 8-digit substrings,
so the bare product is not false-positive-FREE, only false-positive-RARE. Every token here is
`mark + value`, where `mark` is `ci` + four random lowercase letters CONCATENATED BY THE PAYLOAD
ITSELF. `ciqzmw34874989` cannot occur by chance and cannot be echoed: the payload contains the
marker and the operands, never their concatenation with the product.

The single exception is the EL `hashCode` shape, whose output is necessarily a bare integer. That
token is matched with DIGIT BOUNDARIES so it cannot match inside a longer digit run -- which is
precisely the timestamp vector above.

TIME-BASED ORACLES ARE DELIBERATELY ABSENT. The operator's targets are Cloudflare-fronted and
routinely take seconds; `run_sqli` already carries a 240 s call budget because of it. A sleep
oracle on such a target is a slow-target detector. Every check here is output-based.

================================================================================================
GROUND TRUTH -- MEASURED IN REAL INTERPRETERS, NOT RECALLED
================================================================================================

Nonce `kqxzwmbd`, operands `4831*7219` (= 34874989), reverse `dbmwzxqk`. Each run in a throwaway
`--network none` container:

    PHP 8      wordpress:cli        print(strrev("kqxzwmbd").(4831*7219))  -> dbmwzxqk34874989
    Node 20    node:20-alpine       String.fromCharCode(107,113,...,100)   -> kqxzwmbd
    Python     python:3.12          "kqxzwmbd"[::-1]                       -> dbmwzxqk
    Ruby 3.1   apolaki-agent        %q(kqxzwmbd).reverse                   -> dbmwzxqk
    Perl 5.40  wordpress:6-apache   "@{[scalar reverse(q(kqxzwmbd))]}"     -> dbmwzxqk
    Java 17    zaproxy:stable       "kqxzwmbd".hashCode()                  -> -1737333632

TWO TRAPS THAT MEASURING CAUGHT AND RECALLING WOULD NOT HAVE:

  1. PERL `reverse` IN LIST CONTEXT DOES NOT REVERSE A STRING. `"@{[reverse(q(kqxzwmbd))]}"`
     printed `kqxzwmbd` -- UNREVERSED. The `@{[...]}` baby-cart imposes LIST context, so `reverse`
     reversed a one-element list. `scalar reverse` is mandatory. The obvious form would have made
     the Perl attribution token EQUAL to the nonce, which IS in the payload, silently voiding the
     structural echo-immunity this whole file rests on.

  2. JAVA `String.replace` IS GLOBAL. `"ciqzmwxkqxzwmbd".replace("x","")` returned
     `ciqzmwkqzwmbd`, not `ciqzmwkqxzwmbd` -- the `x` inside the nonce was eaten too. The
     separator is a HYPHEN, which an alphanumeric marker and nonce cannot contain.

EXCLUSIVITY OF EACH ATTRIBUTION TOKEN:

    strrev(s)                     PHP builtin; no such name in Perl/Python/Ruby/JS.
    s[::-1]                       Python slice-with-step. MEASURED as a SYNTAX ERROR in Ruby.
    s.reverse                     Ruby String#reverse. Python str has none; JS `"x".reverse` is
                                  `undefined`; PHP and Perl cannot call a method on a literal.
    @{[scalar reverse(s)]}        Perl baby-cart. Nothing else parses `@{[ ]}`.
    String.fromCharCode(...)      JS. The payload carries decimal CODES, so the letters it emits
                                  are absent from the payload.
    s.hashCode()                  Java's hash algorithm (h = 31h + c). This module re-implements
                                  it purely and the tests pin it to the published constants
                                  "abc" = 96354 and "Hello" = 69609650.

================================================================================================
THE EL / SSTI COLLISION, RESOLVED RATHER THAN INHERITED
================================================================================================

`${A*B}` is EL syntax AND template syntax, and `web_security._ssti_payload` ALREADY sends
`{{A*B}}${A*B}` on every injection sweep. Emitting another bare `${A*B}` here would duplicate a
live probe and manufacture the ambiguity. So the EL probes NEVER send bare `${A*B}`:

  * `el_hashcode`  -- `${"NONCE".hashCode()}`, plus the JSF `#{...}` sigil. The token is Java's
    own hash algorithm, so a hit is Java-side expression evaluation: reported as
    `expression_language_injection`, CWE-917.
  * `el_replace`   -- `${"MARK-NONCE".replace("-","")}`. Strong alphabetic token, but `.replace`
    exists in Python and JS too and `${...}` is shared with several template engines, so this
    shape carries NO attribution token and reports `unidentified_code_injection` BY DESIGN.

Anything that evaluates the arithmetic but fails its attribution token lands in that same
`unidentified_code_injection` bucket, with the detail naming the plausible evaluators.
"""
from __future__ import annotations

import re
import secrets
import string
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

#: `ci` keeps the marker greppable in a report the way `cmdi_tool.MARKER` ("cmi") does; the four
#: random letters are what make it unforgeable.
_MARK_PREFIX = "ci"
_MARK_RANDOM = 4
_NONCE_LEN = 8

#: Operands are four digits so the product is at least seven, exactly as the Q-126 SSTI fix
#: requires. The product is never a substring of the payload: the payload's longest digit run is
#: four characters.
_OPERAND_LO, _OPERAND_HI = 1000, 9999

#: A token that is nothing but digits (optionally signed) is matched with DIGIT BOUNDARIES, so it
#: cannot match inside a longer run. Only the EL hashCode shape produces one.
_NUMERIC_TOKEN = re.compile(r"^-?\d+$")

#: Burp's seven buckets. `unidentified` is a first-class verdict here, not a leftover.
CHECKS = {
    "php": "php_code_injection",
    "javascript": "server_side_javascript_code_injection",
    "perl": "perl_code_injection",
    "ruby": "ruby_code_injection",
    "python": "python_code_injection",
    "el": "expression_language_injection",
}
UNIDENTIFIED_CHECK = "unidentified_code_injection"

LANGUAGES = ("php", "python", "ruby", "perl", "javascript", "el")

#: CWE-917 is "Expression Language Injection"; everything else is CWE-94 "Code Injection".
_CWE = {"el": "CWE-917"}
_DEFAULT_CWE = "CWE-94"

_LANGUAGE_LABEL = {
    "php": "PHP", "python": "Python", "ruby": "Ruby", "perl": "Perl",
    "javascript": "server-side JavaScript", "el": "Expression Language",
}


# ---------------------------------------------------------------------------------------------
# randomness -- the whole file's echo-immunity rests on these three helpers
# ---------------------------------------------------------------------------------------------

def _operand() -> int:
    return _OPERAND_LO + secrets.randbelow(_OPERAND_HI - _OPERAND_LO + 1)


def _mark() -> str:
    return _MARK_PREFIX + "".join(secrets.choice(string.ascii_lowercase) for _ in range(_MARK_RANDOM))


def _nonce(length: int = _NONCE_LEN) -> str:
    """A random lowercase nonce whose REVERSE is guaranteed to differ from itself.

    A palindromic nonce would make the reversal attribution token equal to the nonce, which IS in
    the payload -- an echo would then satisfy the oracle. The first and last characters are drawn
    to differ, which rules that out by construction rather than by luck. `secrets` is used rather
    than `random` for the same reason `web_security` uses `os.urandom`: two parameters on one page
    must never share a token.
    """
    n = max(4, int(length))
    first = secrets.choice(string.ascii_lowercase)
    last = secrets.choice(string.ascii_lowercase.replace(first, ""))
    middle = "".join(secrets.choice(string.ascii_lowercase) for _ in range(n - 2))
    return first + middle + last


def java_string_hash(text: str) -> int:
    """Java's `String.hashCode()`, reimplemented purely: h = 31*h + c over UTF-16 code units.

    Pinned by the tests to the published constants "abc" = 96354 and "Hello" = 69609650, both of
    which a JDK 17 run reproduced. This is what makes the EL token computable without a JVM.
    """
    h = 0
    for ch in str(text or ""):
        h = (h * 31 + ord(ch)) & 0xFFFFFFFF
    return h - 0x100000000 if h >= 0x80000000 else h


# ---------------------------------------------------------------------------------------------
# the probe
# ---------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class CodeProbe:
    """One language, one sink shape, and the two tokens its evaluation must produce.

    `eval_ambiguity` is the honest sentence printed when the arithmetic evaluated but the
    attribution token did not: it NAMES what else could have produced the eval token, so the
    reader of an `unidentified_code_injection` finding can see why the language is unclaimed.
    """
    language: str
    shape: str
    payload: str
    eval_token: str
    attr_token: str
    eval_ambiguity: str



# ---------------------------------------------------------------------------------------------
# payload construction, one builder per language
#
# Each builder returns shapes ordered PRIMARY FIRST. The primary shape REPLACES the parameter
# value (an eval sink's value IS the expression); the `string_break` shapes PREFIX the observed
# value and then escape out of the literal they landed in. That is the same replace-vs-append
# distinction `cmdi_tool` documents for argv sinks versus shell sinks, and for the same reason:
# appending to a value that lands in an expression position produces a syntax error, and a
# syntax error is indistinguishable from "not injectable".
# ---------------------------------------------------------------------------------------------

def _php(m: str, a: int, b: int, n: str, value: str) -> list:
    ev, at = "%s%d" % (m, a * b), m + n[::-1]
    amb = ("any interpreter offering print() and string concatenation -- PHP and Python both "
           "match this shape")
    core = 'print("%s".(%d*%d));print("%s".strrev("%s"));' % (m, a, b, m, n)
    return [
        CodeProbe("php", "statement", core, ev, at, amb),
        # preg_replace/e, assert(), create_function: the value is an EXPRESSION, not a statement.
        CodeProbe("php", "expression", '"%s".(%d*%d)."%s".strrev("%s")' % (m, a, b, m, n),
                  ev, at, amb),
        # eval("$x = '<value>';") -- close the literal, run, comment out the remainder.
        CodeProbe("php", "string_break_single", "%s';%s//" % (value, core), ev, at, amb),
        CodeProbe("php", "string_break_double", '%s";%s//' % (value, core), ev, at, amb),
    ]


def _python(m: str, a: int, b: int, n: str, value: str) -> list:
    ev, at = "%s%d" % (m, a * b), m + n[::-1]
    amb = ("any interpreter offering print() and string concatenation -- PHP and Python both "
           "match this shape")
    # No imports, no sleeps, no side effects: `[::-1]` is a pure slice. A sleep oracle is
    # explicitly rejected in this module's header.
    core = 'print("%s"+str(%d*%d));print("%s"+"%s"[::-1])' % (m, a, b, m, n)
    return [
        CodeProbe("python", "statement", core, ev, at, amb),
        CodeProbe("python", "expression", '"%s"+str(%d*%d)+"%s"+"%s"[::-1]' % (m, a, b, m, n),
                  ev, at, amb),
        CodeProbe("python", "string_break_single",
                  '%s\'+"%s"+str(%d*%d)+"%s"+"%s"[::-1]+\'' % (value, m, a, b, m, n), ev, at, amb),
    ]


def _ruby(m: str, a: int, b: int, n: str, value: str) -> list:
    ev, at = "%s%d" % (m, a * b), m + n[::-1]
    amb = ("Ruby string interpolation shares the `#{...}` sigil with JSF and Spring SpEL, so the "
           "arithmetic alone does not name the evaluator")
    return [
        # A Ruby double-quoted-string sink needs no escape: `#{...}` evaluates in place.
        CodeProbe("ruby", "interpolation",
                  '%s#{"%s"+(%d*%d).to_s}#{"%s"+"%s".reverse}' % (value, m, a, b, m, n),
                  ev, at, amb),
        CodeProbe("ruby", "statement",
                  'puts("%s"+(%d*%d).to_s);puts("%s"+"%s".reverse)' % (m, a, b, m, n), ev, at, amb),
        CodeProbe("ruby", "expression",
                  '"%s"+(%d*%d).to_s+"%s"+"%s".reverse' % (m, a, b, m, n), ev, at, amb),
    ]


def _perl(m: str, a: int, b: int, n: str, value: str) -> list:
    ev, at = "%s%d" % (m, a * b), m + n[::-1]
    amb = "an interpolating language that evaluates arithmetic inside a string"
    # MEASURED: `@{[reverse(...)]}` returns the string UNREVERSED because the baby-cart imposes
    # LIST context. `scalar` is load-bearing, not decoration.
    return [
        CodeProbe("perl", "interpolation",
                  '%s%s@{[%d*%d]}%s@{[scalar reverse("%s")]}' % (value, m, a, b, m, n),
                  ev, at, amb),
        CodeProbe("perl", "statement",
                  'print "%s".(%d*%d); print "%s".scalar(reverse("%s"));' % (m, a, b, m, n),
                  ev, at, amb),
        CodeProbe("perl", "string_break_double",
                  '%s";print "%s".(%d*%d); print "%s".scalar(reverse("%s"));#'
                  % (value, m, a, b, m, n), ev, at, amb),
    ]


def _javascript(m: str, a: int, b: int, n: str, value: str) -> list:
    ev, at = "%s%d" % (m, a * b), m + n
    amb = ("any language whose `+` concatenates a string with an integer -- JS, Python and SpEL "
           "all do")
    # The payload carries decimal CHARACTER CODES; the letters they produce are absent from it,
    # so an echo cannot satisfy the attribution token.
    codes = ",".join(str(ord(c)) for c in n)
    fcc = "String.fromCharCode(%s)" % codes
    return [
        CodeProbe("javascript", "expression",
                  '"%s"+(%d*%d)+"%s"+%s' % (m, a, b, m, fcc), ev, at, amb),
        CodeProbe("javascript", "statement",
                  'console.log("%s"+(%d*%d));console.log("%s"+%s)' % (m, a, b, m, fcc),
                  ev, at, amb),
        # A template literal's `${...}` shares its sigil with EL. The CONTENT is JS-exclusive, so
        # attribution stays safe; if only the arithmetic lands, the verdict is "unidentified",
        # which is the correct answer for a shared sigil.
        CodeProbe("javascript", "template_literal",
                  '%s${"%s"+(%d*%d)}${"%s"+%s}' % (value, m, a, b, m, fcc), ev, at, amb),
        CodeProbe("javascript", "string_break_double",
                  '%s"+("%s"+(%d*%d)+"%s"+%s)+"' % (value, m, a, b, m, fcc), ev, at, amb),
    ]


def _el(m: str, a: int, b: int, n: str, value: str) -> list:
    # NOTE the deliberate absence of a bare `${%d*%d}`: `web_security.build_ssti_probes` already
    # sends exactly that on every sweep, and duplicating it here would manufacture the very
    # EL/SSTI ambiguity this module exists to resolve. `a` and `b` are accepted so the signature
    # matches every other builder and neither is mistaken for the other.
    java_tok = str(java_string_hash(n))
    amb_hash = "no other language computes Java's h = 31h + c hash"
    # MEASURED: Java's String.replace is GLOBAL, so the separator must be a character the
    # alphanumeric marker and nonce cannot contain. A hyphen cannot.
    replace_tok = m + n
    amb_replace = ("`.replace()` exists in Python and JavaScript, and `${...}` is shared by EL, "
                   "SpEL, Freemarker, Velocity, Thymeleaf and Angular, so this shape names no "
                   "language by design")
    return [
        CodeProbe("el", "el_hashcode", '${"%s".hashCode()}' % n, java_tok, java_tok, amb_hash),
        # JSF and Spring use `#{...}` for the same grammar.
        CodeProbe("el", "el_hashcode_jsf", '#{"%s".hashCode()}' % n, java_tok, java_tok, amb_hash),
        CodeProbe("el", "el_replace", '${"%s-%s".replace("-","")}' % (m, n),
                  replace_tok, "", amb_replace),
    ]


_ECHO_REDRAWS = 5


def _echo_satisfiable(token: str, payload: str) -> bool:
    """True when TOKEN can be produced from PAYLOAD by DELETING characters.

    BREAKER FINDING. The module's self-check asked whether the token was a SUBSTRING of its own
    payload, and `el_replace` passed it: payload `${"MARK-NONCE".replace("-","")}` against token
    `MARKNONCE`, which differs by exactly one deleted hyphen. Substring says no; a sanitizer that
    strips punctuation from a reflected value says yes, and the echo becomes a confirmed HIGH.

    Deletion is the right closure because that is what sanitizers, encoders and template filters
    actually do to a reflected payload. Subsequence is decided in one pass over the payload.
    """
    if not token:
        return False
    rest = iter(payload)
    return all(ch in rest for ch in token)


_BUILDERS = {"php": _php, "python": _python, "ruby": _ruby, "perl": _perl,
             "javascript": _javascript, "el": _el}


def build_probes(value: str = "", languages=None, shapes_per_language: int = 1) -> list:
    """Fresh probes with FRESH RANDOMNESS PER PROBE.

    Every probe draws its own marker, operands and nonce. Two parameters on one page must never
    share a token, or one stray value convicts both -- that is the generalisation of the Q-126
    finding, where a fixed `49` convicted whatever page happened to contain it.

    `shapes_per_language` selects how many sink shapes to emit, primary first. The default of 1
    keeps a sweep to one request per language.
    """
    langs = tuple(languages) if languages else LANGUAGES
    per = max(1, int(shapes_per_language))
    out: list = []
    for lang in langs:
        builder = _BUILDERS.get(lang)
        if builder is None:
            continue
        # Fresh draw PER LANGUAGE so a hit on one language's token cannot be produced by another
        # language's payload sitting in the same response.
        # Redraw rather than emit an echo-satisfiable probe. A random operand product can collide
        # with its own payload by chance, and a fresh draw clears that; a shape that is
        # STRUCTURALLY echo-satisfiable (el_replace) never comes back clean and is dropped here
        # for good. One mechanism covers the accident and the design defect both.
        shapes: list = []
        for _ in range(_ECHO_REDRAWS):
            m, a, b, n = _mark(), _operand(), _operand(), _nonce()
            shapes = [p for p in builder(m, a, b, n, str(value or ""))[:per]
                      if not _echo_satisfiable(p.eval_token, p.payload)]
            if len(shapes) == per:
                break
        out.extend(shapes)
    return out


# ---------------------------------------------------------------------------------------------
# URL binding -- pure string rewriting, kept local so this module imports no sibling engine
# ---------------------------------------------------------------------------------------------


# ---------------------------------------------------------------------------------------------
# the analyser
# ---------------------------------------------------------------------------------------------

def _token_present(body: str, token: str) -> bool:
    """Substring for a marked token; DIGIT-BOUNDED for a purely numeric one.

    The boundary is what stops the EL hashCode token matching inside an epoch timestamp or a
    build number -- the failure mode that made a bare 7-8 digit product only false-positive-RARE
    rather than false-positive-FREE.
    """
    if not token:
        return False
    text = body or ""
    if _NUMERIC_TOKEN.match(token):
        return re.search(r"(?<![\d-])%s(?!\d)" % re.escape(token), text) is not None
    return token in text


def analyze_code_injection(baseline_body: str, probe_body: str, probe) -> dict | None:
    """Flag server-side code injection, and name the language ONLY when a language-exclusive
    token evaluated.

    Four gates, every one of them a false positive this would otherwise emit:

      1. NO PROBE, NO VERDICT. A caller that cannot say what it sent cannot say what came back.
         The fixed `49` marker WAS a default verdict, and it convicted a real company.
      2. SELF-CHECK: if the token is a SUBSTRING OF ITS OWN PAYLOAD, refuse. That can only happen
         if a payload builder was written wrongly -- the Perl `scalar reverse` trap is exactly
         this bug -- and it makes the whole engine fail SAFE rather than fail LOUD against a
         target that merely echoes input.
      3. BASELINE: a token already present before we touched anything is not ours.
      4. ATTRIBUTION: the arithmetic alone NEVER names a language.
    """
    eval_token = getattr(probe, "eval_token", "") or ""
    payload = getattr(probe, "payload", "") or ""
    if not eval_token:
        return None

    # (2) the structural guarantee, asserted at RUNTIME and not merely in a test: an echo of the
    # payload must be incapable of satisfying this oracle.
    if eval_token in payload:
        return None

    base, body = baseline_body or "", probe_body or ""
    if _token_present(base, eval_token):          # (3) it was there before we arrived
        return None
    if not _token_present(body, eval_token):
        return None

    language = getattr(probe, "language", "") or ""
    attr_token = getattr(probe, "attr_token", "") or ""
    attributed = bool(attr_token) and attr_token not in payload \
        and not _token_present(base, attr_token) and _token_present(body, attr_token)

    if attributed:
        return {
            "check": CHECKS.get(language, UNIDENTIFIED_CHECK),
            "language": language,
            "severity": "HIGH",
            "cwe": _CWE.get(language, _DEFAULT_CWE),
            "attributed": True,
            "eval_token": eval_token,
            "attr_token": attr_token,
            "shape": getattr(probe, "shape", ""),
            "detail": ("%s code was EXECUTED server-side: the probe's own arithmetic produced %s "
                       "and the %s-exclusive construct in the same payload produced %s. Neither "
                       "value appears in the payload, so an echo cannot produce them, and neither "
                       "was in the baseline response"
                       % (_LANGUAGE_LABEL.get(language, language), eval_token,
                          _LANGUAGE_LABEL.get(language, language), attr_token)),
        }

    return {
        "check": UNIDENTIFIED_CHECK,
        "language": "",
        "severity": "HIGH",
        "cwe": _DEFAULT_CWE,
        "attributed": False,
        "eval_token": eval_token,
        "attr_token": "",
        "shape": getattr(probe, "shape", ""),
        "detail": ("server-side code was EVALUATED: the probe's own arithmetic produced %s, which "
                   "appears nowhere in the payload and nowhere in the baseline response. The "
                   "language is NOT claimed -- the %s-exclusive construct in the same payload did "
                   "not evaluate, and the arithmetic alone is ambiguous (%s)"
                   % (eval_token, _LANGUAGE_LABEL.get(language, language) or "language",
                      getattr(probe, "eval_ambiguity", "") or "shared across interpreters")),
    }


# ---------------------------------------------------------------------------------------------
# finding builder -- keeps the report vocabulary in this file so the tools.py call site is one line
# ---------------------------------------------------------------------------------------------

def code_injection_finding(url: str, parameter: str, probe, verdict: dict) -> dict:
    lang = verdict.get("language") or ""
    label = _LANGUAGE_LABEL.get(lang, "")
    title = ("%s code injection in '%s'" % (label, parameter) if label
             else "Unidentified server-side code injection in '%s'" % parameter)
    tags = ["code_injection", "rce"]
    if lang:
        tags.append(lang)
    else:
        tags.append("unidentified")
    return {
        "title": title,
        "param": parameter,
        "severity": verdict.get("severity", "HIGH").lower(),
        "target": url,
        "description": verdict.get("detail", ""),
        "impact": ("Arbitrary code runs inside the application's own interpreter, with its "
                   "credentials, its database handles and its filesystem access: full "
                   "application compromise, and usually full host compromise from there."),
        "evidence": "evaluated token %s%s" % (
            verdict.get("eval_token", ""),
            (" plus language-exclusive token %s" % verdict["attr_token"])
            if verdict.get("attr_token") else ""),
        "success_oracle": ("the arithmetic result and the language-exclusive construct in the "
                           "probe both appear in the response and in neither the payload nor the "
                           "baseline, so the server evaluated them"
                           if verdict.get("attributed") else
                           "the probe's own arithmetic result appears in the response and in "
                           "neither the payload nor the baseline, so the server evaluated it; no "
                           "language is claimed because no language-exclusive token evaluated"),
        "reproduction_steps": [
            "Set '%s' to %r" % (parameter, getattr(probe, "payload", "")),
            "Observe %s in the response body" % verdict.get("eval_token", ""),
            "Confirm the same value is absent from the unmodified request's response",
        ],
        "cwe": verdict.get("cwe", _DEFAULT_CWE),
        "family": "code_injection",
        "tags": tags,
        "confidence": "confirmed",
    }

"""
Static source review (SAST-lite) + JS secret/endpoint mining.

From Bug Bounty Bootcamp (Li, Ch 22). Black-box hunters routinely pull JS bundles
and leaked source; this turns that into signal: dangerous sinks (RCE / injection
/ XSS / deserialization), hardcoded secrets, weak crypto, revealing developer
comments, debug endpoints, and API endpoints/paths that seed the attack surface.

All analyzers are pure and operate on text — unit-tested here; tools._run_js_review
fetches in-scope JS (or takes pasted source) and runs them.
"""
from __future__ import annotations

import math
import re

# ── Hardcoded secrets ────────────────────────────────────────────
_SECRET_PATTERNS = [
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "high"),
    ("AWS secret access key", re.compile(r"(?i)aws.{0,20}?(secret|key).{0,5}['\"]([A-Za-z0-9/+=]{40})['\"]"), "critical"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "high"),
    ("Google OAuth token", re.compile(r"\bya29\.[0-9A-Za-z\-_]{20,}"), "high"),
    ("GitHub token", re.compile(r"\bgh[posru]_[0-9A-Za-z]{36,}\b"), "critical"),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "high"),
    ("Stripe live secret key", re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b"), "critical"),
    ("Twilio API key", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), "high"),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "critical"),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "medium"),
    ("GitHub legacy token (40-hex)", re.compile(r"(?i)(?:github|gh|token|access[_-]?token).{0,20}?\b([a-f0-9]{40})\b"), "high"),
]
# generic KEY = "value" assignments
_ASSIGN = re.compile(
    r"(?i)\b(api[_-]?key|secret[_-]?key|secret|password|passwd|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)\b"
    r"\s*[:=]\s*['\"]([^'\"]{8,})['\"]")
_PLACEHOLDER = re.compile(r"(?i)(your|example|changeme|placeholder|xxxx|<[^>]+>|\{\{|\}\}|test|dummy|sample|redacted|\.\.\.)")


def _redact(s: str) -> str:
    return s if len(s) <= 8 else f"{s[:4]}…{s[-4:]}"


def _line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def scan_secrets(text: str) -> list:
    out, seen = [], set()
    for name, rx, sev in _SECRET_PATTERNS:
        for m in rx.finditer(text or ""):
            val = m.group(len(m.groups())) if m.groups() else m.group(0)
            key = (name, val)
            if key in seen:
                continue
            seen.add(key)
            out.append({"type": name, "severity": sev, "match": _redact(val),
                        "line": _line_of(text, m.start())})
    for m in _ASSIGN.finditer(text or ""):
        keyname, val = m.group(1), m.group(2)
        if _PLACEHOLDER.search(val) or val.isdigit():
            continue
        key = ("assignment:" + keyname.lower(), val)
        if key in seen:
            continue
        seen.add(key)
        out.append({"type": f"Hardcoded {keyname}", "severity": "high",
                    "match": _redact(val), "line": _line_of(text, m.start())})
    return out


# ── Dangerous sinks (RCE / injection / XSS / deserialization) ────
_SINKS = [
    (re.compile(r"\beval\s*\("), "eval()", "code injection / RCE", "high"),
    (re.compile(r"\bnew\s+Function\s*\("), "new Function()", "code injection", "medium"),
    (re.compile(r"\bdocument\.write(?:ln)?\s*\("), "document.write()", "DOM XSS", "medium"),
    (re.compile(r"\.innerHTML\s*="), "innerHTML =", "DOM XSS", "medium"),
    (re.compile(r"\.outerHTML\s*="), "outerHTML =", "DOM XSS", "medium"),
    (re.compile(r"\.insertAdjacentHTML\s*\("), "insertAdjacentHTML()", "DOM XSS", "medium"),
    (re.compile(r"\$\([^)]*\)\.html\s*\("), "jQuery .html()", "DOM XSS", "medium"),
    (re.compile(r"\bset(?:Timeout|Interval)\s*\(\s*['\"]"), "setTimeout/Interval(string)", "code injection", "low"),
    (re.compile(r"\b(?:location|document\.location)\s*(?:\.href|\.assign\s*\(|\.replace\s*\()?\s*[=(][^;\n]*(?:hash|search|location|referrer|\bname\b)"),
     "location <- URL source", "DOM open redirect / DOM XSS", "medium"),
    # client-side prototype pollution — the deparam gadget + unsafe deep-merge/
    # __proto__ writes (ginandjuice's /blog vector is deparam.js).
    (re.compile(r"\bdeparam\s*\("), "deparam()", "client-side prototype pollution (deparam gadget)", "medium"),
    (re.compile(r"(?:\$|jQuery)\.extend\s*\(\s*true\b"), "$.extend(true, ...)", "client-side prototype pollution", "medium"),
    (re.compile(r"__proto__|constructor\s*\[\s*['\"]prototype|\bprototype\s*\[\s*[^\]]+\]\s*="), "__proto__ / prototype write", "client-side prototype pollution", "medium"),
    # client-side template injection surface (AngularJS evaluates {{ }} in the DOM)
    (re.compile(r"\bng-app\b|angular\.bootstrap\s*\(|\[ng-app\]"), "AngularJS ng-app", "client-side template injection (CSTI)", "medium"),
    (re.compile(r"child_process|\.execSync?\s*\(|\.spawn\s*\("), "child_process/exec()", "command injection / RCE", "high"),
    (re.compile(r"\bunserialize\s*\("), "unserialize()", "insecure deserialization", "high"),
    (re.compile(r"\b(?:system|shell_exec|passthru|popen|assert)\s*\("), "PHP system/shell_exec()", "RCE", "high"),
    (re.compile(r"\bpickle\.loads?\s*\(|\byaml\.load\s*\((?![^)]*Safe)"), "pickle/yaml.load()", "insecure deserialization", "high"),
    (re.compile(r"\bos\.system\s*\(|\bsubprocess\.(?:call|Popen|run)\s*\([^)]*shell\s*=\s*True"), "os.system/shell=True", "command injection", "high"),
    (re.compile(r"\bMarshal\.load\s*\("), "Marshal.load()", "insecure deserialization", "high"),
]


def scan_sinks(text: str) -> list:
    out = []
    for rx, name, vuln, sev in _SINKS:
        m = rx.search(text or "")
        if m:
            out.append({"sink": name, "vuln": vuln, "severity": sev, "line": _line_of(text, m.start())})
    return out


# ── Weak crypto ──────────────────────────────────────────────────
_WEAK = [
    (re.compile(r"(?i)\bMD5\b|createHash\(['\"]md5"), "MD5"),
    (re.compile(r"(?i)\bMD4\b"), "MD4"),
    (re.compile(r"(?i)\bSHA-?1\b|createHash\(['\"]sha1"), "SHA-1"),
    (re.compile(r"(?i)\bDES\b(?!C)"), "DES"),
    (re.compile(r"(?i)\bRC4\b"), "RC4"),
    (re.compile(r"(?i)\bECB\b|['\"]aes-\d+-ecb"), "ECB mode"),
    (re.compile(r"Math\.random\s*\("), "Math.random() (non-crypto)"),
]


def scan_weak_crypto(text: str) -> list:
    out = []
    for rx, name in _WEAK:
        m = rx.search(text or "")
        if m:
            out.append({"algorithm": name, "line": _line_of(text, m.start())})
    return out


# ══════════════════════════════════════════════════════════════════════════════════════════════
# CODE-ASSISTED (SAST) LANE — call-site analysis of operator-supplied source
# ══════════════════════════════════════════════════════════════════════════════════════════════
# The scanners above are LEAD generators: a substring hit is a place to go look. That is the right
# trade for a mined JS bundle and the wrong one here, because these rules are asked to produce a
# SCORE. `scan_weak_crypto` would report MD5 on a comment that merely says "we dropped MD5", and on
# the line `println("... MessageDigest.getInstance(java.lang.String) ...")`. Both are text. Neither
# is a call.
#
# So this section works on a MASKED SKELETON: comment bodies and string-literal bodies are blanked
# out at the same offsets, structure is matched against the skeleton, and a literal is only ever
# read back when it sits in an ARGUMENT POSITION of a call the skeleton actually contains. That one
# discipline is what separates a detector from a signature.
#
# The oracle here is definitional rather than behavioural — `Cipher.getInstance("DES")` IS weak
# crypto, there is nothing to observe at runtime — which is exactly why this lane can be
# deterministic where HTTP cannot. It is still SAST, and every finding says so: `provenance:
# source-derived`, `lane: code-assisted`. It must never be folded into a DAST figure.

_FILL = "\x01"          # stands in for a masked literal body; matches nothing a rule looks for
_ESC = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "0": "\0",
        "\\": "\\", "'": "'", '"': '"'}


def _unescape(raw: str) -> str:
    """Java escapes inside a literal. `"DE\\u0053"` is the string DES, and a rule that cannot see
    that is trivially evaded."""
    if "\\" not in raw:
        return raw
    out, i, n = [], 0, len(raw)
    while i < n:
        if raw[i] != "\\" or i + 1 >= n:
            out.append(raw[i]); i += 1; continue
        c = raw[i + 1]
        if c == "u":
            j = i + 2
            while j < n and raw[j] == "u":
                j += 1
            hexs = raw[j:j + 4]
            if len(hexs) == 4 and all(h in "0123456789abcdefABCDEF" for h in hexs):
                out.append(chr(int(hexs, 16))); i = j + 4; continue
        out.append(_ESC.get(c, c)); i += 2
    return "".join(out)


def mask_source(text: str):
    """Blank comment bodies and string/char literal bodies, preserving LENGTH and newlines.

    Returns `(skeleton, literals)`. The skeleton is character-for-character the same size as the
    input, so any offset found in it maps straight back to a real line number. `literals` maps the
    index of an opening quote to that literal's decoded content, which is how a rule reads an
    argument after matching the call around it.

    Pure. Language-agnostic enough for the C family (Java/JS/C#/Go): `//`, `/* */`, `"..."`,
    `'...'`, and Java text blocks.
    """
    src = text or ""
    n = len(src)
    out = list(src)
    lits: dict = {}
    i = 0
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            j = src.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif c == "/" and i + 1 < n and src[i + 1] == "*":
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        elif src.startswith('"""', i):                      # Java text block
            j = src.find('"""', i + 3)
            j = n if j < 0 else j + 3
            lits[i] = _unescape(src[i + 3:max(i + 3, j - 3)])
            for k in range(i + 3, max(i + 3, j - 3)):
                if out[k] != "\n":
                    out[k] = _FILL
            i = j
        elif c in ('"', "'"):
            j, buf = i + 1, []
            while j < n:
                if src[j] == "\\" and j + 1 < n:
                    buf.append(src[j:j + 2]); j += 2; continue
                if src[j] == c or src[j] == "\n":
                    break                                    # a newline ends it: never swallow the file
                buf.append(src[j]); j += 1
            end = min(j, n)
            for k in range(i + 1, end):
                out[k] = _FILL
            lits[i] = _unescape("".join(buf))
            i = end + 1 if end < n and src[end] == c else end
        else:
            i += 1
    return "".join(out), lits


def _arg_span(skel: str, open_idx: int):
    """(start, end) of the argument list whose `(` is at `open_idx`. Parentheses inside literals and
    comments are already masked away, so the depth count is trustworthy."""
    depth = 0
    for k in range(open_idx, len(skel)):
        if skel[k] == "(":
            depth += 1
        elif skel[k] == ")":
            depth -= 1
            if depth == 0:
                return open_idx + 1, k
    return open_idx + 1, len(skel)


def _split_args(skel: str, s: int, e: int) -> list:
    """Top-level comma split of an argument list."""
    out, depth, start = [], 0, s
    for k in range(s, e):
        ch = skel[k]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            out.append((start, k)); start = k + 1
    out.append((start, e))
    return out


def _stmt_end(skel: str, start: int) -> int:
    depth = 0
    for k in range(start, len(skel)):
        ch = skel[k]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == ";" and depth <= 0:
            return k
    return len(skel)


_IDENT = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
# Externalized configuration. `getProperty(key, default)` is the single most common way a Java
# codebase names an algorithm, and the DEFAULT IS A FALLBACK, NOT THE ANSWER — reading it as the
# answer is how a reviewer gets the verdict exactly backwards on a config-driven codebase.
_GETPROP = re.compile(r"\.\s*get(?:Property|String)\s*\(")


class _Dialect(object):
    """The two things value-resolution needs from a language, and the only two.

    Everything else in this section — masking, argument spans, literal recovery — is already shared,
    because the DISCIPLINE is shared: match structure against a skeleton, read a literal back only
    from an argument position. What differs per language is where externalized configuration is
    fetched from and where a statement ends (`;` in Java, a newline in Python).
    """
    __slots__ = ("getprop", "stmt_end")

    def __init__(self, getprop, stmt_end):
        self.getprop, self.stmt_end = getprop, stmt_end


_JAVA_DIALECT = _Dialect(_GETPROP, _stmt_end)


def _expr_values(text: str, skel: str, lits: dict, s: int, e: int, props, depth: int = 0,
                 dialect=None) -> list:
    """Strings an expression can evaluate to, as [(value, origin)].

    Three shapes, in order of authority:
      1. a config lookup -> the DEPLOYED value from the properties file, else the default literal;
      2. literals appearing in the expression;
      3. a bare identifier -> resolved from its assignments in the same file.
    """
    if depth > 3:
        return []
    dialect = dialect or _JAVA_DIALECT
    gp = dialect.getprop.search(skel, s, e)
    if gp:
        gs, ge = _arg_span(skel, gp.end() - 1)
        parts = _split_args(skel, gs, ge)
        keys = [v for k, v in sorted(lits.items()) if parts[0][0] <= k < parts[0][1]]
        key = keys[0] if keys else None
        if props and key is not None and key in props:
            return [(props[key], "properties-file")]
        if len(parts) > 1:
            dflt = [v for k, v in sorted(lits.items()) if parts[1][0] <= k < parts[1][1]]
            if dflt:
                return [(dflt[0], "default-literal")]
        return []
    inline = [(v, "literal") for k, v in sorted(lits.items()) if s <= k < e]
    if inline:
        return inline
    name = skel[s:e].strip()
    if _IDENT.fullmatch(name):
        return _var_values(name, text, skel, lits, props, depth + 1, dialect)
    return []


def _var_values(name: str, text: str, skel: str, lits: dict, props, depth: int = 0,
                dialect=None) -> list:
    """Values assigned to a local anywhere in the file. Flow-insensitive on purpose: a single
    analysis pass over one file, no CFG. Every assignment is a candidate, which is the conservative
    reading and the one that does not miss."""
    if depth > 3:
        return []
    dialect = dialect or _JAVA_DIALECT
    out = []
    rx = re.compile(r"(?<![\w.$])" + re.escape(name) + r"\s*=(?!=)")
    for m in rx.finditer(skel):
        st = m.end()
        out += _expr_values(text, skel, lits, st, dialect.stmt_end(skel, st), props, depth, dialect)
    seen, uniq = set(), []
    for v, origin in out:
        if v not in seen:
            seen.add(v); uniq.append((v, origin))
    return uniq


def _norm_alg(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "", s or "").upper()


# Ciphers that are broken or deprecated as a matter of record, not of opinion. Each is a published
# break or a key/block size below any current floor -- there is no configuration that rescues them.
_WEAK_CIPHERS = {
    "DES": "DES — 56-bit key, exhaustively breakable",
    "DESEDE": "Triple DES — 64-bit block, SWEET32 birthday attack",
    "TRIPLEDES": "Triple DES — 64-bit block, SWEET32 birthday attack",
    "3DES": "Triple DES — 64-bit block, SWEET32 birthday attack",
    "RC2": "RC2 — related-key and differential attacks",
    "RC4": "RC4 — biased keystream, prohibited by RFC 7465",
    "ARCFOUR": "RC4 — biased keystream, prohibited by RFC 7465",
    "ARC4": "RC4 — biased keystream, prohibited by RFC 7465",
    "BLOWFISH": "Blowfish — 64-bit block, SWEET32 birthday attack",
    "IDEA": "IDEA — 64-bit block, superseded",
    "SKIPJACK": "SKIPJACK — 80-bit key, withdrawn",
    "TEA": "TEA — equivalent-key weakness",
    "XTEA": "XTEA — superseded, not a modern primitive",
}
# Block ciphers whose Java transformation defaults to ECB when no mode is written. `Cipher
# .getInstance("AES")` is AES/ECB/PKCS5Padding on SunJCE -- the omission IS the weakness.
_BLOCK_CIPHERS = {"AES", "DES", "DESEDE", "BLOWFISH", "RC2", "IDEA", "CAMELLIA", "SEED", "ARIA"}
_TRANSFORM_OK = re.compile(r"[A-Za-z0-9/_+.-]{1,80}")


def _cipher_weakness(spec: str, needs_mode: bool):
    """(label, why) when this transformation string is weak, else None."""
    if not spec or not _TRANSFORM_OK.fullmatch(spec):
        return None                                   # prose, not a transformation
    parts = spec.split("/")
    alg, mode = _norm_alg(parts[0]), _norm_alg(parts[1]) if len(parts) > 1 else ""
    if alg in _WEAK_CIPHERS:
        return (alg if not mode else "%s/%s" % (alg, mode), _WEAK_CIPHERS[alg])
    if mode == "ECB":
        return ("%s/ECB" % alg, "ECB mode — equal plaintext blocks yield equal ciphertext blocks")
    if needs_mode and not mode and alg in _BLOCK_CIPHERS:
        return ("%s (no mode)" % alg,
                "no mode specified — the JCE default is ECB, which leaks plaintext structure")
    return None


# site regex -> (which argument names the algorithm, whether an omitted mode means ECB)
_CRYPTO_SITES = [
    (re.compile(r"(?<![\w.$])(?:javax\.crypto\.)?Cipher\s*\.\s*getInstance\s*\("), 0, True,
     "Cipher.getInstance"),
    (re.compile(r"(?<![\w.$])(?:javax\.crypto\.)?(?:KeyGenerator|KeyPairGenerator|SecretKeyFactory|"
                r"AlgorithmParameters)\s*\.\s*getInstance\s*\("), 0, False, "KeyGenerator.getInstance"),
    (re.compile(r"(?<![\w.$])new\s+(?:javax\.crypto\.spec\.)?SecretKeySpec\s*\("), -1, False,
     "new SecretKeySpec"),
]


def scan_java_crypto(text: str, props: dict = None) -> list:
    """Weak or broken CIPHER selected at a real call site (CWE-327).

    Call-site only. A comment naming DES, a log line quoting `Cipher.getInstance(java.lang.String)`,
    and a variable merely TYPED as a weak class are all text, and none of them is a call.
    """
    src = text or ""
    skel, lits = mask_source(src)
    out, seen = [], set()
    for rx, argno, needs_mode, api in _CRYPTO_SITES:
        for m in rx.finditer(skel):
            s, e = _arg_span(skel, m.end() - 1)
            args = _split_args(skel, s, e)
            if not args:
                continue
            span = args[argno] if -len(args) <= argno < len(args) else args[0]
            for value, origin in _expr_values(src, skel, lits, span[0], span[1], props):
                weak = _cipher_weakness(value, needs_mode)
                if not weak:
                    continue
                line = _line_of(src, m.start())
                key = (weak[0], line, api)
                if key in seen:
                    continue
                seen.add(key)
                out.append({"algorithm": weak[0], "why": weak[1], "api": api, "line": line,
                            "spec": value, "resolved_from": origin, "cwe": "CWE-327"})
    return out


# Digests with a published collision or preimage break. SHA-1 is here on the strength of SHAttered
# (2017) and the SHA-1 is a Shambles chosen-prefix collision (2020).
_WEAK_DIGESTS = {
    "MD2": "MD2 — preimage attack, withdrawn",
    "MD4": "MD4 — collisions found in seconds",
    "MD5": "MD5 — practical chosen-prefix collisions",
    "SHA0": "SHA-0 — withdrawn, collisions found",
    "SHA1": "SHA-1 — practical chosen-prefix collisions (SHAttered / Shambles)",
    "RIPEMD": "RIPEMD (original) — collisions found",
    "RIPEMD128": "RIPEMD-128 — below any current collision-resistance floor",
}
# For a MAC, only the digests with a PREIMAGE-class break matter. HMAC-SHA1 has no practical attack
# and calling it broken would be a false positive wearing a security costume.
_WEAK_MAC_DIGESTS = {"MD2", "MD4", "MD5"}


def _digest_weakness(spec: str, mac: bool = False):
    n = _norm_alg(spec)
    if not n or len(n) > 40:
        return None
    if n.startswith("HMAC"):
        n, mac = n[4:], True
    n = n.split("WITH")[0] if "WITH" in n else n         # "MD5withRSA" -> MD5
    if mac:
        return (n, _WEAK_DIGESTS[n]) if n in _WEAK_MAC_DIGESTS else None
    return (n, _WEAK_DIGESTS[n]) if n in _WEAK_DIGESTS else None


# (site, argument naming the digest, is-a-MAC, api label)
_HASH_SITES = [
    (re.compile(r"(?<![\w.$])(?:java\.security\.)?MessageDigest\s*\.\s*getInstance\s*\("), 0, False,
     "MessageDigest.getInstance"),
    (re.compile(r"(?<![\w.$])(?:javax\.crypto\.)?Mac\s*\.\s*getInstance\s*\("), 0, True,
     "Mac.getInstance"),
    (re.compile(r"(?<![\w.$])(?:java\.security\.)?Signature\s*\.\s*getInstance\s*\("), 0, False,
     "Signature.getInstance"),
]
# Convenience wrappers name the algorithm in the METHOD, not in an argument.
_HASH_METHODS = re.compile(
    r"(?<![\w.$])(?:DigestUtils|Hashing|MessageDigestAlgorithms)\s*\.\s*"
    r"(md2|md4|md5|sha1|sha)\s*(?:Hex|Crypt)?\s*\(", re.I)


def scan_java_hash(text: str, props: dict = None) -> list:
    """Broken message digest selected at a real call site (CWE-328).

    Deliberately narrow about WHERE it looks. `SecureRandom.getInstance("SHA1PRNG")` names SHA-1 and
    is a CSPRNG, not a digest — 275 of the suite's weakrand cases are exactly that line, and a rule
    that greps for "SHA1" instead of for a digest call site reports every one of them.
    """
    src = text or ""
    skel, lits = mask_source(src)
    out, seen = [], set()
    for rx, argno, mac, api in _HASH_SITES:
        for m in rx.finditer(skel):
            s, e = _arg_span(skel, m.end() - 1)
            args = _split_args(skel, s, e)
            if not args:
                continue
            for value, origin in _expr_values(src, skel, lits, args[argno][0], args[argno][1], props):
                weak = _digest_weakness(value, mac)
                if not weak:
                    continue
                line = _line_of(src, m.start())
                if (weak[0], line) in seen:
                    continue
                seen.add((weak[0], line))
                out.append({"algorithm": weak[0], "why": weak[1], "api": api, "line": line,
                            "spec": value, "resolved_from": origin, "cwe": "CWE-328"})
    for m in _HASH_METHODS.finditer(skel):
        weak = _digest_weakness(m.group(1))
        if not weak:
            continue
        line = _line_of(src, m.start())
        if (weak[0], line) in seen:
            continue
        seen.add((weak[0], line))
        out.append({"algorithm": weak[0], "why": weak[1], "api": m.group(0).strip("( "),
                    "line": line, "spec": m.group(1), "resolved_from": "method-name",
                    "cwe": "CWE-328"})
    return out


# ── weak randomness (CWE-330) ────────────────────────────────────
# INSTANTIATION, not declaration. `java.util.Random numGen = SecureRandom.getInstance("SHA1PRNG")`
# is a CSPRNG behind a supertype reference, and `void f(java.util.Random g)` is a parameter type.
# Both contain the weak class name; neither creates a weak generator.
_RANDOM_SITES = [
    (re.compile(r"(?<![\w.$])new\s+(?:java\.util\.)?Random\s*\("),
     "new java.util.Random()", "java.util.Random is a linear congruential generator; its output is "
                               "reproducible from ~2 observed values"),
    (re.compile(r"(?<![\w.$])(?:java\.lang\.)?Math\s*\.\s*random\s*\(\s*\)"),
     "Math.random()", "Math.random() delegates to a shared java.util.Random — same predictability"),
    (re.compile(r"(?<![\w.$])(?:java\.util\.concurrent\.)?ThreadLocalRandom\s*\.\s*current\s*\(\s*\)"),
     "ThreadLocalRandom.current()", "ThreadLocalRandom is not a cryptographic generator"),
    (re.compile(r"(?<![\w.$])(?:org\.apache\.commons\.lang3?\.)?RandomStringUtils\s*\.\s*random"
                r"(?:Alphanumeric|Alphabetic|Ascii|Numeric|Graph|Print)?\s*\("),
     "RandomStringUtils.random*()", "RandomStringUtils uses java.util.Random unless a SecureRandom "
                                    "is passed explicitly"),
]
# The clock is public knowledge. Seeding from it, or minting a security value out of it, makes the
# result derivable by anyone who knows roughly when it happened.
_CLOCK = r"(?:java\.lang\.)?System\s*\.\s*(?:currentTimeMillis|nanoTime)\s*\(\s*\)"
_CLOCK_SEED = re.compile(r"(?<![\w.$])(?:new\s+(?:java\.util\.)?Random\s*\(\s*%s|\.\s*setSeed\s*\(\s*%s)"
                         % (_CLOCK, _CLOCK))
_CLOCK_TOKEN = re.compile(
    r"(?<![\w.$])(\w*(?:token|session|nonce|otp|secret|salt|apikey|password|guid|uuid)\w*)"
    r"\s*=[^;\n]{0,90}?" + _CLOCK, re.I)


def scan_java_random(text: str) -> list:
    """Predictable randomness reaching a security value (CWE-330/CWE-338)."""
    src = text or ""
    skel, _ = mask_source(src)
    out, seen = [], set()

    def _add(construct, why, idx, cwe="CWE-330"):
        line = _line_of(src, idx)
        if (construct, line) in seen:
            return
        seen.add((construct, line))
        out.append({"construct": construct, "why": why, "api": construct, "line": line,
                    "spec": construct, "resolved_from": "literal", "cwe": cwe})

    for m in _CLOCK_SEED.finditer(skel):
        _add("Random(System.currentTimeMillis())",
             "seeded from the wall clock — the seed is guessable to within a few thousand values",
             m.start(), "CWE-337")
    for rx, construct, why in _RANDOM_SITES:
        for m in rx.finditer(skel):
            _add(construct, why, m.start())
    for m in _CLOCK_TOKEN.finditer(skel):
        _add("System.currentTimeMillis() -> %s" % m.group(1),
             "a security value derived from the clock is derivable by anyone who knows when it was "
             "issued", m.start(), "CWE-337")
    return out


# ── assemble the code-assisted findings for one source file ──────
_JAVA_MARKER = re.compile(r"(?m)^\s*(?:package\s+[\w.]+\s*;|import\s+(?:static\s+)?(?:java|javax)\.)")


def looks_like_java(text: str, source: str = "") -> bool:
    return str(source or "").lower().endswith(".java") or bool(_JAVA_MARKER.search(text or ""))


def _source_finding(source: str, family: str, cwe: str, title: str, hit: dict,
                    impact: str, remediation: str, oracle: str, tags: list) -> dict:
    """One finding from the CODE-ASSISTED lane.

    `provenance` and `lane` are not decoration. This number cannot be quoted next to a DAST figure,
    and a marker that travels with the finding is the only thing that survives a copy/paste into a
    report. The ledger already carries one retraction for a mislabelled number.
    """
    return {
        "title": title, "severity": "medium", "target": source, "confidence": "confirmed",
        "family": family, "cwe": cwe, "line": hit["line"],
        "provenance": "source-derived", "lane": "code-assisted", "analysis": "static-call-site",
        "description": "%s at %s line %s: %s" % (hit.get("api") or "call site", source,
                                                 hit["line"], hit.get("why") or ""),
        "impact": impact,
        "evidence": "%s:%s  %s(%s)%s" % (
            source, hit["line"], hit.get("api") or "", hit.get("spec") or hit.get("construct") or "",
            "" if hit.get("resolved_from") in (None, "literal")
            else "  [value resolved from %s]" % hit["resolved_from"]),
        "oracle": oracle,
        "remediation": remediation,
        "reproduction_steps": ["Open %s at line %s" % (source, hit["line"]),
                               "Read the call site — no runtime observation is required"],
        "tags": ["sast", "code-assisted"] + list(tags),
    }


def review_java(text: str, source: str, props: dict = None) -> list:
    """CODE-ASSISTED (SAST) review of one Java source file. Findings are SOURCE-DERIVED."""
    out = []
    for h in scan_java_crypto(text, props):
        out.append(_source_finding(
            source, "weak_crypto", "CWE-327", "Weak cryptographic algorithm: %s" % h["algorithm"], h,
            "Data encrypted with this algorithm does not have the confidentiality it appears to have.",
            "Use AES-256 in an AEAD mode (GCM or CCM) with a random per-message IV.",
            "the source selects the algorithm %r at a %s call site — definitionally CWE-327, no "
            "runtime behaviour is in question" % (h.get("spec"), h.get("api")),
            ["crypto"]))
    for h in scan_java_hash(text, props):
        out.append(_source_finding(
            source, "weak_hash", "CWE-328", "Broken hash function: %s" % h["algorithm"], h,
            "A digest with practical collisions cannot support integrity, signatures or password "
            "storage.",
            "Use SHA-256 or SHA-3 for integrity; use bcrypt, scrypt or Argon2 for passwords.",
            "the source selects the digest %r at a %s call site — definitionally CWE-328"
            % (h.get("spec"), h.get("api")),
            ["crypto", "hash"]))
    for h in scan_java_random(text):
        out.append(_source_finding(
            source, "weak_random", h["cwe"], "Predictable randomness: %s" % h["construct"], h,
            "Any token, key, session id or nonce from this generator is reproducible by an attacker "
            "who observes a few outputs.",
            "Use java.security.SecureRandom for every security-relevant value.",
            "the source instantiates %s — a non-cryptographic generator, observed at the call site "
            "and not merely named in a declaration" % h["construct"],
            ["randomness"]))
    return out


# ══════════════════════════════════════════════════════════════════════════════════════════════
# PYTHON — the same call-site discipline, a different set of traps
# ══════════════════════════════════════════════════════════════════════════════════════════════
# The rules above are Java's. NOTHING here changes them: they measure 100% TPR / 0% FPR on the
# suite's crypto, hash and weakrand categories and the whole point of this section is that a
# second language costs the first one nothing.
#
# Python moves every trap. `//` is FLOOR DIVISION, not a comment, and carrying the C-family masker
# over blanks the rest of any line containing an integer division — then reports a clean file. `#`
# starts a comment. A docstring is a multi-line string literal. An f-string is half literal and
# half CODE, so blanking it whole hides real call sites and keeping it whole reads prose as code.
#
# And the single most important discriminator in the Python suite is a RECEIVER, not a name:
#
#     random.getrandbits(32)                  <- predictable, CWE-330
#     random.SystemRandom().getrandbits(32)   <- reads os.urandom, a CSPRNG
#
# Same module, same method name, opposite verdict. 113 of the suite's 326 weakrand cases are the
# second line; a rule that matches on the METHOD reports every one of them as vulnerable. That is
# the Python twin of `java.util.Random numGen = SecureRandom.getInstance("SHA1PRNG")`, and it is
# why this lane matches a qualified call and not an identifier.

_PY_STR_PREFIX = set("rbufRBUF")


def _py_unescape(raw: str, is_raw: bool) -> str:
    """Python escapes inside a literal. A raw string has none: `r"\\d"` is two characters."""
    if is_raw or "\\" not in raw:
        return raw
    out, i, n = [], 0, len(raw)
    while i < n:
        if raw[i] != "\\" or i + 1 >= n:
            out.append(raw[i]); i += 1; continue
        c = raw[i + 1]
        if c in ("x", "u", "U"):
            width = {"x": 2, "u": 4, "U": 8}[c]
            hexs = raw[i + 2:i + 2 + width]
            if len(hexs) == width and all(h in "0123456789abcdefABCDEF" for h in hexs):
                try:
                    out.append(chr(int(hexs, 16)))
                except ValueError:
                    out.append(c)
                i += 2 + width
                continue
        out.append(_ESC.get(c, c)); i += 2
    return "".join(out)


def _py_prefix(src: str, i: int) -> str:
    """The string prefix immediately before the quote at `i` (`r`, `f`, `b`, `rb`, ...), or ""."""
    k = i
    while k > 0 and src[k - 1].isalpha():
        k -= 1
    pre = src[k:i]
    if not pre or len(pre) > 2 or any(ch not in _PY_STR_PREFIX for ch in pre):
        return ""
    if k > 0 and (src[k - 1].isdigit() or src[k - 1] == "_"):
        return ""                                    # part of a longer identifier, not a prefix
    return pre


def _py_str_end(src: str, i: int, quote: str, triple: bool, is_f: bool):
    """(index of the closing quote, index just past it) for the literal opening at `i`.

    A newline ends a single-quoted literal even when the quote never closes — an unterminated
    string must cost one line, never the rest of the file.
    """
    n = len(src)
    j = i + (3 if triple else 1)
    depth = 0
    while j < n:
        ch = src[j]
        if ch == "\\" and j + 1 < n:
            j += 2
            continue
        if is_f:
            if ch == "{":
                if j + 1 < n and src[j + 1] == "{":
                    j += 2; continue                 # `{{` is a literal brace
                depth += 1; j += 1; continue
            if ch == "}":
                if depth == 0:
                    j += 2 if (j + 1 < n and src[j + 1] == "}") else 1
                    continue
                depth -= 1; j += 1; continue
        if depth == 0:
            if triple:
                if src.startswith(quote * 3, j):
                    return j, j + 3
            else:
                if ch == quote:
                    return j, j + 1
                if ch == "\n":
                    return j, j
        j += 1
    return n, n


def _py_brace_end(src: str, k: int, limit: int) -> int:
    """Index of the `}` closing the f-string interpolation whose `{` is at `k`."""
    depth, j = 0, k
    while j < limit:
        ch = src[j]
        if ch == "\\":
            j += 2; continue
        if ch in ('"', "'"):
            trip = src.startswith(ch * 3, j)
            _, j = _py_str_end(src, j, ch, trip, False)
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return j
        j += 1
    return limit


def mask_python_source(text: str):
    """Blank comment bodies and string-literal bodies, preserving LENGTH and newlines.

    Same contract as `mask_source`: `(skeleton, literals)`, the skeleton character-for-character
    the same size as the input so any offset maps straight back to a real line, and `literals`
    keyed by the index of the opening quote.

    Three Python-specific rules:
      - `#` starts a comment; `//` does NOT (it is floor division);
      - `'''`/`\"\"\"` literals span lines, and prefixes (`r`, `b`, `f`, `rb`, ...) are honoured;
      - inside an f-string, `{...}` is CODE and stays in the skeleton (masked recursively, so a
        nested literal in there is still a literal), while the prose around it is blanked.

    Pure.
    """
    src = text or ""
    n = len(src)
    out = list(src)
    lits: dict = {}
    i = 0
    while i < n:
        c = src[i]
        if c == "#":
            j = src.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif c in ('"', "'"):
            pre = _py_prefix(src, i)
            is_raw, is_f = "r" in pre.lower(), "f" in pre.lower()
            triple = src.startswith(c * 3, i)
            bstart = i + (3 if triple else 1)
            bend, after = _py_str_end(src, i, c, triple, is_f)
            bend = max(bstart, bend)
            lits[i] = _py_mask_body(src, out, lits, bstart, bend, is_raw, is_f)
            i = max(after, i + 1)
        else:
            i += 1
    return "".join(out), lits


def _py_mask_body(src: str, out: list, lits: dict, bstart: int, bend: int, is_raw: bool,
                  is_f: bool) -> str:
    """Blank a literal body in place; return its decoded content. For an f-string, the `{...}`
    interpolations are left in the skeleton AS CODE (masked recursively) — a weak call written
    inside an f-string is still a call."""
    if not is_f:
        for k in range(bstart, bend):
            if out[k] != "\n":
                out[k] = _FILL
        return _py_unescape(src[bstart:bend], is_raw)
    parts, k = [], bstart
    while k < bend:
        ch = src[k]
        if ch in "{}" and k + 1 < bend and src[k + 1] == ch:
            out[k] = out[k + 1] = _FILL
            parts.append(ch); k += 2; continue
        if ch == "{":
            end = _py_brace_end(src, k, bend)
            sub_skel, sub_lits = mask_python_source(src[k + 1:end])
            for off, ch2 in enumerate(sub_skel):
                out[k + 1 + off] = ch2
            for key, val in sub_lits.items():
                lits[k + 1 + key] = val
            k = end + 1 if end < bend else bend
            continue
        if ch != "\n":
            out[k] = _FILL
        parts.append(ch)
        k += 1
    return _py_unescape("".join(parts), is_raw)


# Externalized configuration, Python edition. `os.environ.get(key, default)` is what `getProperty`
# is in Java, and the default is a FALLBACK, not the answer.
_PY_GETENV = re.compile(r"(?:os\s*\.\s*environ\s*\.\s*get|os\s*\.\s*getenv)\s*\(")


def _py_stmt_end(skel: str, start: int) -> int:
    """A Python statement ends at a newline outside brackets (or at a `;`)."""
    depth = 0
    for k in range(start, len(skel)):
        ch = skel[k]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth < 0:
                return k
        elif ch in ("\n", ";") and depth <= 0:
            return k
    return len(skel)


_PY_DIALECT = _Dialect(_PY_GETENV, _py_stmt_end)

_PY_IMPORT = re.compile(r"(?m)^[ \t]*import[ \t]+([^\n]+)")
_PY_FROM = re.compile(r"(?m)^[ \t]*from[ \t]+([\w.]+)[ \t]+import[ \t]+([^\n]+)")


def _py_imports(skel: str):
    """What each name in this module is BOUND to.

    Returns `(modules, symbols)`:
      modules  {local name -> dotted module path}     from `import X` / `import X as Y`
      symbols  {local name -> (module, original)}     from `from X import Y [as Z]`

    This is what separates `import random` from `from numpy import random`. Both make the name
    `random` callable; only one of them is the predictable stdlib generator, and a rule that reads
    the name without reading the binding reports numpy as CWE-330.
    """
    modules, symbols = {}, {}
    for m in _PY_IMPORT.finditer(skel):
        for part in m.group(1).split(","):
            bits = part.split()
            if not bits:
                continue
            if len(bits) >= 3 and bits[1] == "as":
                modules[bits[2]] = bits[0]
            else:
                modules[bits[0]] = bits[0]
                modules.setdefault(bits[0].split(".")[0], bits[0].split(".")[0])
    for m in _PY_FROM.finditer(skel):
        module = m.group(1)
        for part in m.group(2).replace("(", " ").replace(")", " ").split(","):
            bits = part.split()
            if not bits or bits[0] == "*":
                continue
            local = bits[2] if len(bits) >= 3 and bits[1] == "as" else bits[0]
            symbols[local] = (module, bits[0])
    return modules, symbols


def _py_binds_module(modules: dict, symbols: dict, name: str) -> bool:
    """False when `name` is demonstrably bound to something OTHER than the stdlib module of that
    name. Absent any import at all this returns True: a qualified `random.random()` that executes
    at all must have `random` bound in the module, and being permissive there costs no precision."""
    if name in symbols:
        return False
    return modules.get(name, name) == name


def _py_shadowed(skel: str, name: str) -> bool:
    """A local `def`/`class` of the same name shadows the import — `md5` is then the operator's
    own function and calling it is not a call to hashlib."""
    return bool(re.search(r"(?m)^[ \t]*(?:def|class)[ \t]+%s[ \t]*[(:]" % re.escape(name), skel))


# ── Python weak hash (CWE-328) ───────────────────────────────────
# `usedforsecurity=False` is the caller stating, in the API's own vocabulary, that this digest is a
# cache key or a bucket index. Flagging it is a false positive the language explicitly ruled out.
_PY_USEDFORSEC = re.compile(r"(?<![\w.])usedforsecurity\s*=\s*False\b")
_PY_HASHLIB_CALL = re.compile(r"(?<![\w.])hashlib\s*\.\s*([A-Za-z0-9_]+)\s*\(")
_PY_HMAC_CALL = re.compile(r"(?<![\w.])hmac\s*\.\s*(?:new|HMAC)\s*\(")
_PY_CRYPTO_HASH = re.compile(r"(?<![\w.])(?:Crypto|Cryptodome)\s*\.\s*Hash\s*\.\s*"
                             r"([A-Za-z0-9_]+)\s*\.\s*new\s*\(")
_PY_HASH_MODULES = ("Crypto.Hash", "Cryptodome.Hash")


def scan_python_hash(text: str, props: dict = None) -> list:
    """Broken message digest selected at a real Python call site (CWE-328).

    Call-site only, and BINDING-aware. `md5(...)` is only the stdlib digest when `md5` was imported
    from hashlib and not shadowed by a local `def md5`; otherwise it is the operator's own function
    and has nothing to do with cryptography.
    """
    src = text or ""
    skel, lits = mask_python_source(src)
    _modules, symbols = _py_imports(skel)
    out, seen = [], set()

    def _add(alg, why, api, idx, spec, origin):
        line = _line_of(src, idx)
        if (alg, line, api) in seen:
            return
        seen.add((alg, line, api))
        out.append({"algorithm": alg, "why": why, "api": api, "line": line, "spec": spec,
                    "resolved_from": origin, "cwe": "CWE-328"})

    def _digest_call(name, api, idx, s, e, origin="method-name"):
        if _PY_USEDFORSEC.search(skel, s, e):
            return                                   # explicitly a non-security digest
        if name == "new":
            args = _split_args(skel, s, e)
            for value, origin2 in _expr_values(src, skel, lits, args[0][0], args[0][1], props,
                                               0, _PY_DIALECT):
                weak = _digest_weakness(value)
                if weak:
                    _add(weak[0], weak[1], api, idx, value, origin2)
            return
        weak = _digest_weakness(name)
        if weak:
            _add(weak[0], weak[1], api, idx, name, origin)

    for m in _PY_HASHLIB_CALL.finditer(skel):
        s, e = _arg_span(skel, m.end() - 1)
        _digest_call(m.group(1), "hashlib.%s" % m.group(1), m.start(), s, e)

    for local, (module, orig) in symbols.items():
        if _py_shadowed(skel, local):
            continue
        if module == "hashlib":
            for m in re.finditer(r"(?<![\w.])%s\s*\(" % re.escape(local), skel):
                s, e = _arg_span(skel, m.end() - 1)
                _digest_call(orig, "hashlib.%s" % orig, m.start(), s, e, "import-alias")
        elif module.startswith(_PY_HASH_MODULES):
            weak = _digest_weakness(orig)
            if not weak:
                continue
            for m in re.finditer(r"(?<![\w.])%s\s*\.\s*new\s*\(" % re.escape(local), skel):
                _add(weak[0], weak[1], "%s.%s.new" % (module, orig), m.start(), orig, "import-alias")

    for m in _PY_CRYPTO_HASH.finditer(skel):
        weak = _digest_weakness(m.group(1))
        if weak:
            _add(weak[0], weak[1], "Crypto.Hash.%s.new" % m.group(1), m.start(), m.group(1),
                 "module-name")

    # A MAC is judged by the PREIMAGE-class breaks only, exactly as the Java side judges
    # Mac.getInstance: HMAC-SHA1 has no practical attack and calling it broken would be a false
    # positive wearing a security costume.
    for m in _PY_HMAC_CALL.finditer(skel):
        s, e = _arg_span(skel, m.end() - 1)
        for a0, a1 in _split_args(skel, s, e):
            frag = skel[a0:a1].strip()
            if frag.startswith("digestmod"):
                frag = frag.split("=", 1)[-1].strip()
            named = re.fullmatch(r"(?:hashlib\s*\.\s*)?([A-Za-z0-9_]+)", frag)
            cands = [named.group(1)] if named else []
            cands += [v for k, v in sorted(lits.items()) if a0 <= k < a1]
            for cand in cands:
                weak = _digest_weakness(cand, mac=True)
                if weak:
                    _add(weak[0], weak[1], "hmac.new", m.start(), cand, "literal")
    return out


# ── Python weak randomness (CWE-330) ─────────────────────────────
# The `random` module is a Mersenne Twister: observing 624 outputs recovers the whole state, and
# for the values these functions are actually used for (tokens, session ids, coupon codes) far
# fewer are needed. `secrets`, `os.urandom` and `random.SystemRandom` read the OS CSPRNG and are
# never flagged — they are the fix, not the bug.
_PY_RANDOM_METHODS = ("random|randint|randrange|randbytes|choices|choice|sample|shuffle|uniform|"
                      "triangular|getrandbits|seed|normalvariate|gauss|lognormvariate|"
                      "expovariate|vonmisesvariate|gammavariate|betavariate|paretovariate|"
                      "weibullvariate")
_PY_RANDOM_SET = set(_PY_RANDOM_METHODS.split("|")) | {"Random"}
_PY_RANDOM_CALL = re.compile(r"(?<![\w.])random\s*\.\s*(%s)\s*\(" % _PY_RANDOM_METHODS)
_PY_RANDOM_CTOR = re.compile(r"(?<![\w.])random\s*\.\s*Random\s*\(")
_PY_CLOCK = (r"(?:time\s*\.\s*(?:time|time_ns|monotonic|perf_counter)\s*\(\s*\)"
             r"|datetime\s*\.\s*(?:datetime\s*\.\s*)?now\s*\(|os\s*\.\s*getpid\s*\(\s*\))")
_PY_CLOCK_SEED = re.compile(r"(?<![\w.])(?:random\s*\.\s*seed|\.\s*seed|Random)\s*\(\s*%s" % _PY_CLOCK)
_PY_CLOCK_TOKEN = re.compile(
    r"(?<![\w.])(\w*(?:token|session|nonce|otp|secret|salt|apikey|password|guid|uuid)\w*)"
    r"\s*=[^\n]{0,90}?" + _PY_CLOCK, re.I)
_PY_RANDOM_WHY = ("the `random` module is a Mersenne Twister, not a cryptographic generator; its "
                  "output is reproducible from a short run of observed values")


def scan_python_random(text: str) -> list:
    """Predictable randomness reaching a security value (CWE-330/CWE-337).

    The receiver decides the verdict, not the method name: `random.getrandbits(32)` is a Mersenne
    Twister and `random.SystemRandom().getrandbits(32)` is os.urandom behind the same method name.
    """
    src = text or ""
    skel, _lits = mask_python_source(src)
    modules, symbols = _py_imports(skel)
    out, seen, clock_lines = [], set(), set()

    def _add(construct, why, idx, cwe="CWE-330"):
        line = _line_of(src, idx)
        if (construct, line) in seen:
            return
        seen.add((construct, line))
        out.append({"construct": construct, "why": why, "api": construct, "line": line,
                    "spec": construct, "resolved_from": "literal", "cwe": cwe})

    for m in _PY_CLOCK_SEED.finditer(skel):
        clock_lines.add(_line_of(src, m.start()))
        _add("random.seed(<clock>)",
             "seeded from the wall clock — the seed is guessable to within a few thousand values",
             m.start(), "CWE-337")
    stdlib = _py_binds_module(modules, symbols, "random")
    if stdlib:
        for m in _PY_RANDOM_CALL.finditer(skel):
            if m.group(1) == "seed" and _line_of(src, m.start()) in clock_lines:
                continue                             # already reported as the stronger CWE-337
            _add("random.%s()" % m.group(1), _PY_RANDOM_WHY, m.start())
        for m in _PY_RANDOM_CTOR.finditer(skel):
            _add("random.Random()", _PY_RANDOM_WHY, m.start())
    for local, (module, orig) in symbols.items():
        if module != "random" or orig not in _PY_RANDOM_SET or _py_shadowed(skel, local):
            continue
        for m in re.finditer(r"(?<![\w.])%s\s*\(" % re.escape(local), skel):
            if orig == "seed" and _line_of(src, m.start()) in clock_lines:
                continue
            _add("random.%s()" % orig, _PY_RANDOM_WHY, m.start())
    for m in _PY_CLOCK_TOKEN.finditer(skel):
        _add("clock -> %s" % m.group(1),
             "a security value derived from the clock is derivable by anyone who knows when it "
             "was issued", m.start(), "CWE-337")
    return out


# ── Python weak crypto (CWE-327) ─────────────────────────────────
# pycryptodome and `cryptography` name the primitive in the MODULE, not in a transformation string,
# so the call site is `DES.new(...)` / `algorithms.TripleDES(...)` rather than a literal to resolve.
_PY_CIPHER_ALIAS = {"DES3": "DESEDE", "TRIPLEDES": "DESEDE", "ARC4": "RC4", "ARC2": "RC2"}
_PY_CIPHER_MODULES = ("Crypto.Cipher", "Cryptodome.Cipher")
_PY_CIPHER_DIRECT = re.compile(r"(?<![\w.])(?:Crypto|Cryptodome)\s*\.\s*Cipher\s*\.\s*"
                               r"([A-Za-z0-9_]+)\s*\.\s*new\s*\(")
_PY_CRYPTOGRAPHY_ALG = re.compile(r"(?<![\w.])algorithms\s*\.\s*([A-Za-z0-9_]+)\s*\(")
# `MODE_ECB` is normally reached through the cipher module (`AES.MODE_ECB`), so the qualifier dot
# must NOT be excluded here the way it is for a call receiver.
_PY_MODE_ECB = re.compile(r"(?<!\w)MODE_ECB\b|(?<![\w.])modes\s*\.\s*ECB\s*\(")
_PY_ECB_WHY = "ECB mode — equal plaintext blocks yield equal ciphertext blocks"


def _py_cipher_weakness(alg: str):
    n = _norm_alg(alg)
    n = _PY_CIPHER_ALIAS.get(n, n)
    return (n, _WEAK_CIPHERS[n]) if n in _WEAK_CIPHERS else None


def scan_python_crypto(text: str, props: dict = None) -> list:
    """Weak or broken CIPHER selected at a real Python call site (CWE-327)."""
    src = text or ""
    skel, _lits = mask_python_source(src)
    _modules, symbols = _py_imports(skel)
    out, seen = [], set()

    def _add(alg, why, api, idx, spec):
        line = _line_of(src, idx)
        if (alg, line) in seen:
            return
        seen.add((alg, line))
        out.append({"algorithm": alg, "why": why, "api": api, "line": line, "spec": spec,
                    "resolved_from": "module-name", "cwe": "CWE-327"})

    def _cipher_new(alg, api, idx, s, e):
        weak = _py_cipher_weakness(alg)
        if weak:
            _add(weak[0], weak[1], api, idx, alg)
        elif _PY_MODE_ECB.search(skel, s, e):
            _add("%s/ECB" % _norm_alg(alg), _PY_ECB_WHY, api, idx, alg)

    for m in _PY_CIPHER_DIRECT.finditer(skel):
        s, e = _arg_span(skel, m.end() - 1)
        _cipher_new(m.group(1), "Crypto.Cipher.%s.new" % m.group(1), m.start(), s, e)
    for local, (module, orig) in symbols.items():
        if not module.startswith(_PY_CIPHER_MODULES):
            continue
        for m in re.finditer(r"(?<![\w.])%s\s*\.\s*new\s*\(" % re.escape(local), skel):
            s, e = _arg_span(skel, m.end() - 1)
            _cipher_new(orig, "%s.%s.new" % (module, orig), m.start(), s, e)
    for m in _PY_CRYPTOGRAPHY_ALG.finditer(skel):
        weak = _py_cipher_weakness(m.group(1))
        if weak:
            _add(weak[0], weak[1], "algorithms.%s" % m.group(1), m.start(), m.group(1))
    for m in _PY_MODE_ECB.finditer(skel):
        if m.group(0).startswith("modes"):
            _add("ECB", _PY_ECB_WHY, "modes.ECB", m.start(), "ECB")
    return out


# ── assemble the code-assisted findings for one PYTHON source file ──
_PY_MARKER = re.compile(
    r"(?m)^#!.*python"
    r"|^[ \t]*def[ \t]+\w+[ \t]*\("
    r"|^[ \t]*class[ \t]+\w+[ \t]*[(:]"
    r"|^[ \t]*from[ \t]+[\w.]+[ \t]+import[ \t]"
    r"|^[ \t]*import[ \t]+[\w.]+[ \t]*(?:,[ \t]*[\w.]+[ \t]*)*$"
    r"|^[ \t]*(?:elif|except)\b"
    r"|^[ \t]*if[ \t]+__name__[ \t]*==")


def looks_like_python(text: str, source: str = "") -> bool:
    if str(source or "").lower().endswith((".py", ".pyw", ".pyi")):
        return True
    return bool(_PY_MARKER.search(text or ""))


def review_python(text: str, source: str, props: dict = None) -> list:
    """CODE-ASSISTED (SAST) review of one Python source file. Findings are SOURCE-DERIVED.

    Deliberately the same three families and the same finding shape as `review_java`: a consumer of
    this lane must not be able to tell which language produced a finding, only which lane did.
    """
    out = []
    for h in scan_python_crypto(text, props):
        out.append(_source_finding(
            source, "weak_crypto", "CWE-327", "Weak cryptographic algorithm: %s" % h["algorithm"], h,
            "Data encrypted with this algorithm does not have the confidentiality it appears to have.",
            "Use AES-256 in an AEAD mode (GCM) via `cryptography`, with a random per-message nonce.",
            "the source selects the algorithm %r at a %s call site — definitionally CWE-327, no "
            "runtime behaviour is in question" % (h.get("spec"), h.get("api")),
            ["crypto"]))
    for h in scan_python_hash(text, props):
        out.append(_source_finding(
            source, "weak_hash", "CWE-328", "Broken hash function: %s" % h["algorithm"], h,
            "A digest with practical collisions cannot support integrity, signatures or password "
            "storage.",
            "Use hashlib.sha256 or SHA-3 for integrity; use bcrypt, scrypt or Argon2 for passwords. "
            "If the digest is not security-relevant, say so with usedforsecurity=False.",
            "the source selects the digest %r at a %s call site — definitionally CWE-328"
            % (h.get("spec"), h.get("api")),
            ["crypto", "hash"]))
    for h in scan_python_random(text):
        out.append(_source_finding(
            source, "weak_random", h["cwe"], "Predictable randomness: %s" % h["construct"], h,
            "Any token, key, session id or nonce from this generator is reproducible by an attacker "
            "who observes a few outputs.",
            "Use the `secrets` module (or random.SystemRandom) for every security-relevant value.",
            "the source calls %s on the stdlib `random` module — a Mersenne Twister, observed at "
            "the call site and not merely named" % h["construct"],
            ["randomness"]))
    return out


# LANGUAGE DISPATCH. One entry point, so a caller never has to know which analyzer to reach for --
# and so adding the next language is a row here rather than a second walk of the tree.
def review_source(text: str, source: str, props: dict = None) -> list:
    """CODE-ASSISTED (SAST) review of one source file, whatever language it is written in."""
    if looks_like_java(text, source):
        return review_java(text, source, props)
    if looks_like_python(text, source):
        return review_python(text, source, props)
    return []


# ── Revealing developer comments ─────────────────────────────────
_COMMENT = re.compile(r"(?m)(?://|#|/\*|<!--)\s*(.*?(?:todo|fixme|hack|xxx|bug|insecure|not secure|"
                      r"vuln|hardcoded|backdoor|do not ship|remove this|temporary|debug|csrf|"
                      r"disable|bypass).*)$", re.I)


def scan_comments(text: str) -> list:
    out = []
    for m in _COMMENT.finditer(text or ""):
        out.append({"comment": m.group(1).strip()[:160], "line": _line_of(text, m.start())})
    return out[:25]


# Any comment, not just a suspicious-keyword one — comments are where credentials get parked.
# The `//` branch must NOT fire inside a URL: without the lookbehind, `href="http://host/..."` reads as a
# line comment and the whole rest of the line becomes a "comment body". That produced a false positive on
# the very first live page this was tested against.
_ANY_COMMENT = re.compile(
    r"(?s)(?:<!--(.*?)-->"          # HTML
    r"|/\*(.*?)\*/"                 # block
    r"|(?m:(?<![:/])//[ \t]*(.*)$)"  # line comment, not the // in a scheme
    r"|(?m:^[ \t]*\#[ \t]*(.*)$))")  # shell/python comment at line start only

# Credential-shaped text a developer leaves in prose, which the structured _SECRET_PATTERNS miss because
# it has no vendor prefix: "the password for X is <32 hex-ish chars>", "password: hunter2".
_COMMENT_CRED = [
    ("credential in comment", re.compile(
        r"(?i)\b(?:pass(?:word|wd)?|pwd|secret|api[_-]?key|token|credential)s?\b[^A-Za-z0-9\r\n]{0,20}"
        r"(?:for\s+\S{1,32}\s+)?(?:is|=|:)?[^A-Za-z0-9\r\n]{0,6}([A-Za-z0-9!@#$%^&*_\-+.]{8,64})"),
     "high"),
]

# Words that make a "credential" a placeholder rather than a secret.
_PLACEHOLDER_WORD = re.compile(
    r"(?i)^(your|my|the|a|an|some|example|sample|changeme|change|placeholder|xxx+|todo|fixme|none|null|"
    r"true|false|password|passwd|pwd|secret|token|apikey|key|value|string|here|goes|redacted|hidden|"
    r"insert|enter|set|put|real|actual|test|dummy|foo|bar|baz)$")


def _is_placeholder(val: str) -> bool:
    """A documentation placeholder, not a leak. Token-aware, because the common form is hyphen-joined
    prose — `your-password-here` is three placeholder words, while `my-production-secret-42` is not
    (production and 42 carry real information)."""
    v = val.strip()
    if not v or re.fullmatch(r"[*.\-_x]+", v, re.I):        # masks
        return True
    if re.fullmatch(r"<.*>|\{.*\}|\[.*\]|\$\{.*\}", v):     # template slots
        return True
    tokens = [t for t in re.split(r"[-_.\s]+", v) if t]
    return bool(tokens) and all(_PLACEHOLDER_WORD.match(t) for t in tokens)


def scan_comment_secrets(text: str) -> list:
    """Credentials parked in COMMENTS — the class `scan_secrets` cannot see.

    Two blind spots meet here and neither alone catches it. `scan_secrets` matches vendor-shaped tokens
    (AKIA…, AIza…) and a password written in prose has no such shape. `scan_comments` only surfaces
    comments containing todo/fixme/hack, and a comment that simply states a password contains none of
    those words.

    Proven live on OverTheWire Natas level 0, whose served HTML carries the next level's password as a
    bare 32-character value inside an HTML comment (`<!--The password for natas1 is ... -->`). Apolaki
    read that page, ran both scanners, and reported nothing. The value itself is deliberately not
    reproduced here — writing a live credential into source is the practice this function exists to
    flag.

    Placeholders are filtered, because `<!-- password: your-password-here -->` is documentation, not a
    leak. Pure."""
    out, seen = [], set()
    for m in _ANY_COMMENT.finditer(text or ""):
        body = next((g for g in m.groups() if g), "") or ""
        if not body.strip():
            continue
        for name, rx, sev in _COMMENT_CRED:
            for cm in rx.finditer(body):
                val = cm.group(1).strip()
                if len(val) < 8 or _is_placeholder(val) or val in seen:
                    continue
                # a run of identical characters is a mask, not a credential
                if len(set(val)) <= 2:
                    continue
                seen.add(val)
                out.append({"kind": name, "severity": sev, "value": val,
                            "comment": body.strip()[:160], "line": _line_of(text, m.start())})
    return out[:15]


# ── Endpoint / path extraction (seed the surface) ────────────────
_FULL_URL = re.compile(r"https?://[^\s'\"<>()\\]{4,}")
_PATH = re.compile(r"['\"](/[A-Za-z0-9_\-/.]{2,}(?:\?[^'\"]*)?)['\"]")
_FETCH = re.compile(r"(?:fetch|axios(?:\.\w+)?|\.open)\s*\(\s*['\"]([^'\"]+)['\"]")
# Modern SPA bundles write API routes as TEMPLATE LITERALS with ${...} interpolation:
#   `${this.hostServer}/rest/basket/${e}`   this.hostServer+"/api/BasketItems"
# _PATH only matches a single/double-quoted literal that is ENTIRELY a leading-slash
# path, so every interpolated REST route (basket, ftp, Users, SecurityQuestions,
# reviews, 2fa, …) is invisible and never gets probed — the single biggest attack-surface
# gap on Angular/React targets. Match a known API subtree wherever it occurs (allowing
# ${...} path segments), plus well-known standalone sensitive paths, and normalise the
# interpolations to {id} so the endpoint seeds the access-control / exposure probes.
_API_TREE = re.compile(
    r"/(?:rest|api|graphql|socket\.io|b2b)(?:/(?:[A-Za-z0-9_\-.]+|\$\{[^}]*\}))+", re.I)
_API_STD = re.compile(
    r"/(?:ftp|metrics|snippets|encryptionkeys|redirect|support|profile|swagger|"
    r"video|dataerasure|\.well-known)(?:/[A-Za-z0-9_\-.]*)?", re.I)


def _norm_tmpl(p: str) -> str:
    # ${expr} -> {id}; collapse a trailing partial segment left by an interpolation
    # (e.g. /ftp/order_{id}.pdf stays, /ftp/order_ -> /ftp/) so it is fetchable.
    p = re.sub(r"\$\{[^}]*\}", "{id}", p)
    p = re.sub(r"/[A-Za-z0-9_\-.]*_$", "/", p)
    return p


def extract_endpoints(text: str) -> list:
    found = []
    for m in _FULL_URL.finditer(text or ""):
        found.append(m.group(0).rstrip(".,;"))
    for m in _FETCH.finditer(text or ""):
        found.append(m.group(1))
    for m in _PATH.finditer(text or ""):
        p = m.group(1)
        if "/api" in p or re.search(r"\.(json|php|aspx?|jsp|do|action)$", p) or p.count("/") >= 2:
            found.append(p)
    for rx in (_API_TREE, _API_STD):
        for m in rx.finditer(text or ""):
            found.append(_norm_tmpl(m.group(0)))
    return list(dict.fromkeys(found))[:400]


# ── High-entropy scan (TruffleHog-style, catches unformatted secrets) ──
def _shannon(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in freq.values())


_TOKEN = re.compile(r"[A-Za-z0-9/+_=\-]{20,}")


def scan_entropy(text: str, threshold: float = 4.3) -> list:
    out, seen = [], set()
    for m in _TOKEN.finditer(text or ""):
        tok = m.group(0)
        if tok in seen or _PLACEHOLDER.search(tok):
            continue
        if _shannon(tok) >= threshold:
            seen.add(tok)
            out.append({"match": _redact(tok), "entropy": round(_shannon(tok), 2),
                        "line": _line_of(text, m.start())})
    return out[:20]


# ── Assemble findings for one source ─────────────────────────────
def review(text: str, source: str) -> dict:
    findings = []
    for s in scan_secrets(text):
        findings.append({
            "title": f"Hardcoded secret in JS/source: {s['type']}", "severity": s["severity"],
            "target": source, "description": f"{s['type']} found in {source} (line {s['line']}): {s['match']}",
            "impact": "Leaked credentials allow direct access to the associated service/account.",
            "reproduction_steps": [f"Open {source}", f"See {s['type']} at line {s['line']}"],
            "evidence": f"line {s['line']}: {s['match']}", "cwe": "CWE-798",
            "family": "code-review", "tags": ["secrets", "disclosure"], "confidence": "candidate"})
    for s in scan_sinks(text):
        findings.append({
            "title": f"Security-sensitive sink: {s['sink']} ({s['vuln']})", "severity": s["severity"],
            "target": source, "description": f"{s['sink']} at line {s['line']} in {source} — potential {s['vuln']} "
                                             "if it reaches user-controlled input.",
            "impact": f"Possible {s['vuln']}.", "reproduction_steps": [f"Review {source} line {s['line']}",
                                                                       "Trace whether user input reaches this sink"],
            "cwe": "CWE-94", "family": "code-review", "tags": ["sink", s["vuln"].split("/")[0].strip()],
            "confidence": "candidate"})
    for w in scan_weak_crypto(text):
        findings.append({
            "title": f"Weak cryptography: {w['algorithm']}", "severity": "low", "target": source,
            "description": f"{w['algorithm']} referenced at line {w['line']} in {source}.",
            "impact": "Weak/insecure algorithm; impact depends on where it protects data.",
            "reproduction_steps": [f"Review {source} line {w['line']}"], "cwe": "CWE-327",
            "family": "code-review", "tags": ["crypto"], "confidence": "candidate"})
    # Credentials parked in comments — a distinct class from "revealing comments" (no todo/fixme keyword)
    # and from scan_secrets (no vendor-shaped token). Confirmed live on Natas level 0.
    for cs in scan_comment_secrets(text):
        findings.append({
            "title": "Credential exposed in a source comment",
            "severity": cs["severity"], "target": source, "confidence": "confirmed",
            "family": "sensitive_exposure", "cwe": "CWE-615",
            "description": ("A comment in %s states a credential in plain text: %r. Comments are served "
                            "to every client; this is readable by anyone who views the source."
                            % (source, cs["comment"])),
            "impact": "The credential is disclosed to anyone who fetches the page or file.",
            "evidence": "GET %s -> comment at line %s contains a credential-shaped value"
                        % (source, cs["line"]),
            "oracle": ("a comment body matches a credential statement and the value is not a placeholder "
                       "or mask"),
            "remediation": "Remove the credential from the source and rotate it.",
            "tags": ["secrets", "comment", "source-disclosure"],
        })

    # CODE-ASSISTED lane. Fires on Java and Python source, so a mined JS bundle behaves exactly as
    # before; these rules are call-site analyses of specific stdlib APIs and have nothing to say
    # about a language whose APIs they do not name.
    findings.extend(review_source(text, source))

    comments = scan_comments(text)
    if comments:
        joined = "; ".join(f"L{c['line']}: {c['comment']}" for c in comments[:6])
        findings.append({
            "title": f"Revealing developer comments ({len(comments)})", "severity": "info", "target": source,
            "description": f"Comments in {source} hint at gaps/TODOs: {joined}",
            "impact": "May reveal incomplete controls (e.g. missing CSRF), debug hooks, or hidden endpoints.",
            "reproduction_steps": [f"Grep {source} for TODO/FIXME/CSRF/debug"], "cwe": "CWE-615",
            "family": "code-review", "tags": ["disclosure"], "confidence": "candidate"})
    return {"findings": findings, "endpoints": extract_endpoints(text),
            "entropy_hits": scan_entropy(text)}

"""Code-assisted (SAST) lane, JavaScript/Node dialect -- B-020.

TIER 3 (adversarial controls). There is NO Node ground-truth corpus in the estate, so there is no
denominator and this file may never produce an accuracy percentage. What it asserts is
control-by-control behaviour across the eight control kinds, and nothing more.

Java and Python reached 100% TPR / 0.0% FPR on their mapped categories by two rules, and both are
carried forward here rather than re-derived:

  THE RECEIVER DECIDES THE VERDICT, NOT THE METHOD NAME
      crypto.randomBytes(32)         is a CSPRNG
      crypto.pseudoRandomBytes(32)   is not, and says so in its own name
  BIND THE VALUE, DO NOT PATTERN-MATCH THE IDENTIFIER
      const c = require('crypto'); c.createHash('md5')   must resolve through the alias

That last control is Q-041's lesson applied as a PRECONDITION. The aliased-module hole was shipped
in Python and found later by the Breaker; here it is a control written before the rule exists.

The masker is where this dialect is won or lost, and its trap is the REGEX LITERAL: `/md5/` is a
pattern, `a / b / c` is arithmetic, and reading one as the other blanks the rest of a line -- the
same failure shape as treating Python's `//` (floor division) as a comment.
"""
import codereview as cr


def _algs(hits):
    return sorted(h["algorithm"] for h in hits)


def _constructs(hits):
    return sorted(h["construct"] for h in hits)


# ════════════════════════════════════════════════ VULNERABLE (the rule must fire)

def test_weak_digest_at_a_node_call_site():
    assert _algs(cr.scan_js_hash("const crypto = require('crypto');\n"
                                 "const h = crypto.createHash('md5').update(x).digest('hex');\n")) == ["MD5"]
    assert _algs(cr.scan_js_hash("const crypto = require('crypto');\n"
                                 "const h = crypto.createHash('sha1');\n")) == ["SHA1"]


def test_weak_cipher_and_explicit_ecb_mode():
    assert _algs(cr.scan_js_crypto("const crypto = require('crypto');\n"
                                   "const c = crypto.createCipheriv('des-ede3-cbc', k, iv);\n")) == ["des-ede3-cbc"]
    assert _algs(cr.scan_js_crypto("const crypto = require('crypto');\n"
                                   "const c = crypto.createCipheriv('rc4', k, iv);\n")) == ["rc4"]
    assert _algs(cr.scan_js_crypto("const crypto = require('crypto');\n"
                                   "const c = crypto.createCipheriv('aes-128-ecb', k, iv);\n")) == ["aes-128-ecb"]


def test_math_random_and_pseudo_random_bytes():
    assert _constructs(cr.scan_js_random("const t = Math.random().toString(36);\n")) == ["Math.random()"]
    assert _constructs(cr.scan_js_random(
        "const crypto = require('crypto');\nconst t = crypto.pseudoRandomBytes(32);\n")) == \
        ["crypto.pseudoRandomBytes()"]


def test_the_legacy_createCipher_is_weak_whatever_cipher_it_names():
    """`createCipher` derives its key with one unsalted MD5 round, so the defect is the API, not
    the algorithm -- `aes-256-cbc` through it is still wrong."""
    hits = cr.scan_js_crypto("const crypto = require('crypto');\n"
                             "const c = crypto.createCipher('aes-256-cbc', password);\n")
    assert len(hits) == 1 and "MD5" in hits[0]["why"]


# ════════════════════════════════════════════════ SAFE (the fix must NOT flag)

def test_crypto_randomBytes_and_getRandomValues_are_not_weak():
    for safe in ("const crypto = require('crypto');\nconst t = crypto.randomBytes(32);\n",
                 "const crypto = require('crypto');\nconst t = crypto.randomUUID();\n",
                 "const crypto = require('crypto');\nconst t = crypto.randomInt(1, 100);\n",
                 "const b = new Uint8Array(32);\ncrypto.getRandomValues(b);\n",
                 "const crypto = require('crypto');\ncrypto.webcrypto.getRandomValues(b);\n"):
        assert cr.scan_js_random(safe) == [], safe


def test_createHash_sha256_is_not_weak():
    for safe in ("sha256", "sha384", "sha512", "sha3-256", "blake2b512"):
        src = "const crypto = require('crypto');\nconst h = crypto.createHash('%s');\n" % safe
        assert cr.scan_js_hash(src) == [], safe


def test_a_modern_aead_cipher_is_not_weak():
    for safe in ("aes-256-gcm", "aes-128-gcm", "chacha20-poly1305", "aes-256-cbc"):
        src = "const crypto = require('crypto');\nconst c = crypto.createCipheriv('%s', k, iv);\n" % safe
        assert cr.scan_js_crypto(src) == [], safe


def test_hmac_sha1_is_not_reported_as_broken():
    """Same judgement as the Java and Python sides: HMAC-SHA1 has no practical attack, and calling
    it broken would be a false positive wearing a security costume. HMAC-MD5 still is."""
    assert cr.scan_js_hash("const crypto = require('crypto');\n"
                           "const m = crypto.createHmac('sha1', key);\n") == []
    assert _algs(cr.scan_js_hash("const crypto = require('crypto');\n"
                                 "const m = crypto.createHmac('md5', key);\n")) == ["MD5"]


# ════════════════════════════════════════════════ NOISE / LOOKALIKE (text is not a call)

def test_md5_named_only_in_a_comment_or_string_is_not_a_call_site():
    for noise in ("// we dropped md5 in 2019\nconst crypto = require('crypto');\n",
                  "/* migrate createHash('md5') -> sha256 */\n",
                  "console.log('using createHash(md5) is forbidden');\n",
                  "const msg = `do not use crypto.createHash('md5')`;\n"):
        assert cr.scan_js_hash(noise) == [], noise


def test_random_named_only_in_a_comment_or_string_is_not_a_call_site():
    for noise in ("// never use Math.random() for tokens\n",
                  "const warn = 'Math.random() is not a CSPRNG';\n",
                  "/** @deprecated use crypto.randomBytes not Math.random() */\n"):
        assert cr.scan_js_random(noise) == [], noise


def test_a_regex_literal_is_not_a_call_and_does_not_swallow_the_line():
    """THE JS TRAP. `/md5/` is a pattern. And a regex must not eat the rest of the file the way a
    misparsed comment would -- the call AFTER it still has to be seen."""
    src = ("const crypto = require('crypto');\n"
           "if (/md5|sha1/.test(name)) { report(name); }\n"
           "const h = crypto.createHash('md5');\n")
    hits = cr.scan_js_hash(src)
    assert _algs(hits) == ["MD5"]
    assert hits[0]["line"] == 3, "the regex on line 2 must not be the finding"


def test_division_is_not_a_regex():
    """The mirror of the trap. Reading `a / b / c` as a regex blanks real code between the
    slashes, which is how a masker reports a vulnerable file clean."""
    src = ("const crypto = require('crypto');\n"
           "const ratio = total / count / 2;\n"
           "const h = crypto.createHash('md5');\n")
    assert _algs(cr.scan_js_hash(src)) == ["MD5"]
    skel, _lits = cr.mask_js_source(src)
    assert "ratio" in skel and "count" in skel


def test_a_template_literal_keeps_its_interpolation_as_code():
    """An f-string's JS twin: the text is masked, the `${...}` half is CODE and a weak call inside
    one is still a call."""
    src = ("const crypto = require('crypto');\n"
           "const out = `digest=${crypto.createHash('md5').update(x).digest('hex')}`;\n")
    assert _algs(cr.scan_js_hash(src)) == ["MD5"]


def test_a_template_literal_body_is_not_code():
    assert cr.scan_js_hash("const t = `crypto.createHash('md5')`;\n") == []


# ════════════════════════════════════════════════ AMBIGUOUS (the binding decides)

def test_an_aliased_require_must_resolve():
    """Q-041 APPLIED AS A PRECONDITION. This is the control that was missing in Python until the
    Breaker found it; here it ships with the rule."""
    assert _algs(cr.scan_js_hash("const c = require('crypto');\n"
                                 "const h = c.createHash('md5');\n")) == ["MD5"]
    assert _algs(cr.scan_js_hash("const c = require('node:crypto');\n"
                                 "const h = c.createHash('md5');\n")) == ["MD5"]
    assert _constructs(cr.scan_js_random("const c = require('crypto');\n"
                                         "const t = c.pseudoRandomBytes(8);\n")) == \
        ["crypto.pseudoRandomBytes()"]


def test_a_destructured_require_must_resolve():
    assert _algs(cr.scan_js_hash("const { createHash } = require('crypto');\n"
                                 "const h = createHash('md5');\n")) == ["MD5"]
    assert _algs(cr.scan_js_hash("const { createHash: mk } = require('crypto');\n"
                                 "const h = mk('md5');\n")) == ["MD5"]


def test_esm_imports_resolve_the_same_way():
    assert _algs(cr.scan_js_hash("import crypto from 'crypto';\n"
                                 "const h = crypto.createHash('md5');\n")) == ["MD5"]
    assert _algs(cr.scan_js_hash("import * as c from 'node:crypto';\n"
                                 "const h = c.createHash('md5');\n")) == ["MD5"]
    assert _algs(cr.scan_js_hash("import { createHash } from 'crypto';\n"
                                 "const h = createHash('md5');\n")) == ["MD5"]


def test_a_user_defined_md5_is_not_a_library_digest():
    """The mandatory control. A local function named `md5` is the operator's own code; the rules
    fire on a BINDING to a digest, never on a name that merely reads like one."""
    assert cr.scan_js_hash("function md5(s) { return fold(s); }\n"
                           "const h = md5(data);\n") == []
    # ...and the binding is exactly what makes the real npm digest a finding
    assert _algs(cr.scan_js_hash("const md5 = require('md5');\n"
                                 "const h = md5(data);\n")) == ["MD5"]
    # a local `function md5` shadowing the require is the operator's function again
    assert cr.scan_js_hash("const md5 = require('md5');\n"
                           "function md5(s) { return fold(s); }\n"
                           "const h = md5(data);\n") == []


def test_a_foreign_crypto_module_is_not_node_crypto():
    """`crypto-js` is a different library with a different API. Resolving an alias must not make
    the rule credulous -- the same discipline as `from numpy import random` in Python."""
    assert cr.scan_js_hash("const crypto = require('crypto-js');\n"
                           "const h = crypto.createHash('md5');\n") == []


def test_the_algorithm_can_come_from_a_local_constant():
    """Bind the value: the algorithm is resolved from the variable, not required to be inline."""
    assert _algs(cr.scan_js_hash("const crypto = require('crypto');\n"
                                 "const ALG = 'md5';\n"
                                 "const h = crypto.createHash(ALG);\n")) == ["MD5"]


# ════════════════════════════════════════════════ FILTERED / UNSUPPORTED

def test_a_bare_aes_argument_is_not_inferred_to_be_ecb():
    """The Juliet bare-`AES` disagreement does NOT transfer. Java's `Cipher.getInstance("AES")`
    silently means ECB; Node requires an explicit mode and throws without one, so there is no
    implicit-ECB inference to make and none is made."""
    assert cr.scan_js_crypto("const crypto = require('crypto');\n"
                             "const c = crypto.createCipheriv('aes', k, iv);\n") == []


def test_a_non_javascript_file_produces_nothing_from_the_js_rules():
    assert cr.scan_js_hash("SELECT md5(password) FROM users;\n") == []


# ════════════════════════════════════════════════ REGRESSION (the other dialects are untouched)

def test_the_java_and_python_analyzers_are_unaffected():
    """A third language must cost the first two nothing. These are the exact shapes the other two
    lanes measure at 100% / 0.0% FPR."""
    java = 'javax.crypto.Cipher.getInstance("DES");'
    assert [h["algorithm"] for h in cr.scan_java_crypto(java)] == ["DES"]
    assert cr.scan_java_crypto('Cipher.getInstance("AES/GCM/NoPadding");') == []
    py = "import hashlib\nh = hashlib.md5(b'x')\n"
    assert [h["algorithm"] for h in cr.scan_python_hash(py)] == ["MD5"]
    assert cr.scan_python_random("import random\nx = random.SystemRandom().getrandbits(32)\n") == []


def test_dispatch_routes_js_without_stealing_java_or_python():
    assert cr.looks_like_js("const c = require('crypto');\n", "a.js")
    assert not cr.looks_like_js("", "Handler.java")
    assert not cr.looks_like_java("const c = require('crypto');\n", "a.js")
    fams = [f["family"] for f in cr.review_source(
        "const crypto = require('crypto');\nconst h = crypto.createHash('md5');\n", "a.js")]
    assert fams == ["weak_hash"]
    # a Java file still routes to the Java rules
    jfams = [f["family"] for f in cr.review_source(
        'package a;\nimport java.security.*;\nclass C { void f() { '
        'MessageDigest.getInstance("MD5"); } }', "C.java")]
    assert jfams == ["weak_hash"]


def test_findings_carry_the_lane_markers():
    f = cr.review_source("const crypto = require('crypto');\n"
                         "const h = crypto.createHash('md5');\n", "a.js")[0]
    assert f["lane"] == "code-assisted"
    assert f["provenance"] == "source-derived"
    assert f["confidence"] == "confirmed"
    assert f["cwe"] == "CWE-328"


def test_clock_derived_secrets_use_the_same_head_noun_rule_as_q042():
    """The Q-042 fix is dialect-independent: a timestamp is not a secret, and a keyword argument
    is not an assignment."""
    assert cr.scan_js_random("const tokenExpiry = Date.now() + 3600;\n") == []
    assert cr.scan_js_random("const sessionStart = Date.now();\n") == []
    assert cr.scan_js_random("fetch(url, { token: t, issuedAt: Date.now() });\n") == []
    hits = cr.scan_js_random("const token = String(Date.now());\n")
    assert [h["cwe"] for h in hits] == ["CWE-337"]


def test_an_unterminated_literal_costs_one_line_not_the_file():
    """A masker that swallows the rest of the file on a broken literal reports everything after it
    clean. One line is the correct blast radius."""
    src = ("const bad = 'unterminated\n"
           "const crypto = require('crypto');\n"
           "const h = crypto.createHash('md5');\n")
    assert _algs(cr.scan_js_hash(src)) == ["MD5"]

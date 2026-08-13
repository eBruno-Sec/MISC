"""Code-assisted (SAST) lane: call-site analysis of operator-supplied source.

DECLARED LANE. Everything these functions produce is source-derived, carries a provenance marker,
and must never be folded into a DAST figure. The reason this lane can be deterministic where HTTP
cannot is that the oracle is definitional: `Cipher.getInstance("DES")` IS weak crypto, there is no
behaviour to observe.

The whole ticket lives or dies on the negative controls, so they are first-class tests, not
afterthoughts. A substring matcher passes the positive cases and fails every one of these:

  - `AES/GCM/NoPadding` is not weak crypto
  - `SHA-256` / `SHA-512` are not weak hashes
  - `SecureRandom` is not weak randomness
  - "MD5" inside a COMMENT or inside a STRING LITERAL is not a call site

The last one is not hypothetical. Every OWASP Benchmark crypto case carries the line
`println("Crypto Test javax.crypto.Cipher.getInstance(java.lang.String) executed")` -- a perfect
fake call site inside a string -- and every weakrand case declares
`java.util.Random numGen = java.security.SecureRandom.getInstance("SHA1PRNG");`, where the *declared
type* is the weak class but the object is a CSPRNG. A regex over raw text scores both wrong.
"""
import os

import codeintel
import codereview as cr
import owasp_bench as ob


# ── masking: the primitive every rule depends on ─────────────────
def test_mask_blanks_comments_and_literal_bodies_but_keeps_offsets():
    src = 'int a; // Cipher.getInstance("DES")\nString s = "DES";\n/* MD5 */ int b;\n'
    skel, lits = cr.mask_source(src)
    assert len(skel) == len(src)                    # offsets survive, so line numbers stay true
    assert skel.count("\n") == src.count("\n")
    assert "Cipher.getInstance" not in skel         # the comment is gone
    assert "MD5" not in skel                        # the block comment is gone
    assert '"' in skel and "DES" not in skel        # the literal's quotes stay, its body does not
    assert "DES" in lits.values()                   # ...but the body is recoverable as an argument


def test_mask_recovers_escaped_literal_content():
    skel, lits = cr.mask_source(r'x("DES");')
    assert "DES" in lits.values()


# ── crypto: weak cipher at a real call site (CWE-327) ────────────
def test_weak_cipher_literal_is_flagged():
    hits = cr.scan_java_crypto('javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("DES/CBC/PKCS5Padding");')
    assert hits and hits[0]["cwe"] == "CWE-327"
    assert "DES" in hits[0]["algorithm"]
    assert hits[0]["line"] == 1


def test_ecb_mode_is_flagged_even_with_a_strong_cipher():
    hits = cr.scan_java_crypto('Cipher.getInstance("AES/ECB/PKCS5Padding");')
    assert hits and "ECB" in hits[0]["algorithm"]


def test_weak_key_generator_is_flagged():
    hits = cr.scan_java_crypto('javax.crypto.KeyGenerator.getInstance("DES").generateKey();')
    assert hits and "DES" in hits[0]["algorithm"]


def test_multiline_call_site_is_flagged():
    hits = cr.scan_java_crypto('javax.crypto.Cipher.getInstance(\n    "DES/CBC/PKCS5PADDING",'
                               ' java.security.Security.getProvider("SunJCE"));')
    assert hits and "DES" in hits[0]["algorithm"]


# NEGATIVE CONTROL 1 — strong AEAD must not be flagged
def test_aes_gcm_is_not_flagged():
    assert cr.scan_java_crypto('Cipher.getInstance("AES/GCM/NoPadding");') == []
    assert cr.scan_java_crypto('Cipher.getInstance("AES/CCM/NoPadding", provider);') == []
    assert cr.scan_java_crypto('KeyGenerator.getInstance("AES").generateKey();') == []


# NEGATIVE CONTROL 2 — a comment is not a call site
def test_algorithm_named_only_in_a_comment_is_not_flagged():
    assert cr.scan_java_crypto('// javax.crypto.Cipher.getInstance("DES/CBC/PKCS5Padding");') == []
    assert cr.scan_java_crypto('/* we used to call Cipher.getInstance("RC4") here */') == []


# NEGATIVE CONTROL 3 — a string literal is not a call site
def test_algorithm_named_only_inside_a_string_literal_is_not_flagged():
    # the exact shape every Benchmark crypto case prints in its catch block
    src = ('response.getWriter().println("Problem executing crypto - '
           'javax.crypto.Cipher.getInstance(java.lang.String,java.security.Provider) Test Case");')
    assert cr.scan_java_crypto(src) == []
    assert cr.scan_java_crypto('String note = "DES is banned in this codebase";') == []
    # a log line quoting a whole call, weak literal and all, is still one string
    assert cr.scan_java_crypto(r'log.info("never call Cipher.getInstance(\"DES\") again");') == []


def test_a_user_defined_factory_is_not_a_jca_call_site():
    """`getInstance` is not a keyword. Widening the site match to any `X.getInstance("...")` turns
    every registry lookup whose key happens to name an algorithm into a finding."""
    assert cr.scan_java_crypto('AlgorithmRegistry.getInstance("DES");') == []
    assert cr.scan_java_hash('AlgorithmRegistry.getInstance("MD5");') == []
    assert cr.scan_java_hash('ConfigCache.getInstance("SHA1");') == []


# ── externalized configuration: resolve the variable, not the default ──
def test_algorithm_variable_resolves_through_the_properties_file():
    src = ('String algorithm = benchmarkprops.getProperty("cryptoAlg1", "AES/GCM/NoPadding");\n'
           'javax.crypto.Cipher c = javax.crypto.Cipher.getInstance(algorithm);')
    # The DEFAULT literal is strong; the DEPLOYED value is weak. A reviewer answers "what actually
    # runs", so the properties file wins -- and a matched clean twin in the same shape must stay clean.
    assert cr.scan_java_crypto(src, props={"cryptoAlg1": "DES/ECB/PKCS5Padding"})
    assert cr.scan_java_crypto(src, props={"cryptoAlg1": "AES/GCM/NoPadding"}) == []


def test_algorithm_variable_falls_back_to_the_default_literal_when_unresolvable():
    src = ('String algorithm = props.getProperty("cipher", "DESede/ECB/PKCS5Padding");\n'
           'Cipher.getInstance(algorithm);')
    hits = cr.scan_java_crypto(src)
    assert hits and hits[0]["resolved_from"] == "default-literal"


def test_plain_local_variable_is_resolved():
    hits = cr.scan_java_crypto('String alg = "Blowfish";\nCipher.getInstance(alg);')
    assert hits and "BLOWFISH" in hits[0]["algorithm"].upper()


# ── hash: weak digest at a real call site (CWE-328) ──────────────
def test_md5_digest_is_flagged():
    hits = cr.scan_java_hash('java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");')
    assert hits and hits[0]["cwe"] == "CWE-328" and hits[0]["algorithm"] == "MD5"


def test_sha1_digest_is_flagged_in_every_spelling():
    for spec in ('"SHA1"', '"SHA-1"', '"sha1"'):
        assert cr.scan_java_hash("MessageDigest.getInstance(%s, \"SUN\");" % spec), spec


def test_hmac_md5_is_flagged_but_hmac_sha1_is_not():
    # precision matters more than volume: HMAC-SHA1 is not broken as a MAC, and claiming it is
    # would be a false positive dressed up as thoroughness
    assert cr.scan_java_hash('javax.crypto.Mac.getInstance("HmacMD5");')
    assert cr.scan_java_hash('javax.crypto.Mac.getInstance("HmacSHA1");') == []


# NEGATIVE CONTROL — modern SHA-2 must not be flagged
def test_sha256_and_sha512_are_not_flagged():
    assert cr.scan_java_hash('MessageDigest.getInstance("SHA-256");') == []
    assert cr.scan_java_hash('MessageDigest.getInstance("SHA-512", "SUN");') == []
    assert cr.scan_java_hash('MessageDigest.getInstance("sha-384", provider[0]);') == []


# NEGATIVE CONTROL — the trap the whole ticket lives on
def test_md5_mentioned_in_a_comment_or_literal_is_not_flagged():
    assert cr.scan_java_hash('// TODO: we still use MessageDigest.getInstance("MD5") somewhere') == []
    assert cr.scan_java_hash('/* MD5 was removed in 2019 */ int x;') == []
    assert cr.scan_java_hash('println("Problem executing hash - TestCase '
                             'java.security.MessageDigest.getInstance(java.lang.String)");') == []


def test_sha1prng_is_a_csprng_not_a_weak_digest():
    # `SecureRandom.getInstance("SHA1PRNG")` appears in 275 of the suite's 493 weakrand cases and is
    # the SAFE construct. A rule that greps for "SHA1" reports every one of them as a weak hash.
    src = 'java.util.Random numGen = java.security.SecureRandom.getInstance("SHA1PRNG");'
    assert cr.scan_java_hash(src) == []
    assert cr.scan_java_random(src) == []


def test_hash_algorithm_resolves_through_the_properties_file():
    src = ('String algorithm = benchmarkprops.getProperty("hashAlg1", "SHA512");\n'
           'java.security.MessageDigest md = java.security.MessageDigest.getInstance(algorithm);')
    # the in-code default says SHA512; the deployed configuration says MD5. The deployed value wins.
    assert cr.scan_java_hash(src, props={"hashAlg1": "MD5"})
    assert cr.scan_java_hash(src, props={"hashAlg1": "SHA-256"}) == []


# ── weakrand: predictable generator at a real call site (CWE-330) ──
def test_new_java_util_random_is_flagged():
    hits = cr.scan_java_random("long l = new java.util.Random().nextLong();")
    assert hits and hits[0]["cwe"] == "CWE-330"


def test_math_random_is_flagged_qualified_or_not():
    assert cr.scan_java_random("double value = java.lang.Math.random();")
    assert cr.scan_java_random("double value = Math.random();")


def test_seeding_from_the_clock_is_flagged():
    assert cr.scan_java_random("new Random(System.currentTimeMillis());")


# NEGATIVE CONTROL — SecureRandom must not be flagged
def test_secure_random_is_not_flagged():
    assert cr.scan_java_random("java.security.SecureRandom r = new java.security.SecureRandom();") == []
    assert cr.scan_java_random('int n = java.security.SecureRandom.getInstance("SHA1PRNG").nextInt(99);') == []


def test_a_variable_merely_typed_as_random_is_not_flagged():
    # DECLARED TYPE IS NOT INSTANTIATION. This exact line is the safe twin in 52 suite cases; a
    # substring rule for "java.util.Random" reports every one of them as vulnerable.
    assert cr.scan_java_random(
        'java.util.Random numGen = java.security.SecureRandom.getInstance("SHA1PRNG");') == []
    assert cr.scan_java_random("void getNextNumber(java.util.Random generator, byte[] b) {") == []
    assert cr.scan_java_random("double getNextNumber(java.util.Random generator) {") == []


def test_random_named_only_in_a_comment_is_not_flagged():
    assert cr.scan_java_random("// replaced new java.util.Random() with SecureRandom") == []
    assert cr.scan_java_random('println("Problem executing SecureRandom.nextDouble() - TestCase");') == []
    # a weak construct spelled out INSIDE a string is still a string
    assert cr.scan_java_random('println("we replaced Math.random() with SecureRandom");') == []
    assert cr.scan_java_random('String s = "new java.util.Random() is banned";') == []


# ── provenance: this lane is never mistakable for DAST ───────────
def test_every_source_finding_is_marked_source_derived():
    out = cr.review_java('Cipher.getInstance("DES");', "Foo.java")
    assert out and all(f["provenance"] == "source-derived" for f in out)
    assert all(f["lane"] == "code-assisted" for f in out)
    assert all(f["target"] == "Foo.java" for f in out)


def test_review_routes_java_source_into_the_code_assisted_lane():
    # composition, not an island: the product's own entry point picks the lane up
    res = cr.review('package a.b;\nimport java.security.MessageDigest;\n'
                    'class C { void f(){ MessageDigest.getInstance("MD5"); } }', "C.java")
    assert any(f.get("lane") == "code-assisted" for f in res["findings"])


def test_review_leaves_javascript_untouched_by_the_java_rules():
    res = cr.review('var x = 1; el.innerHTML = y;', "app.js")
    assert not any(f.get("lane") == "code-assisted" for f in res["findings"])


# ── tree lane: source is an EXPLICIT operator input ──────────────
def _tree(tmp_path, files):
    for name, body in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf8")
    return str(tmp_path)


def test_absent_source_is_reported_not_returned_as_clean():
    """A missing input is not a clean bill of health. Reporting one as the other is how a lane that
    never ran gets read as a lane that found nothing."""
    for bad in (None, "", "/nonexistent/path/xyz"):
        res = codeintel.review_source_tree(bad)
        assert "no source provided" in res["error"]
        assert res["findings"] == [] and res["files_scanned"] == 0


def test_tree_resolves_an_algorithm_across_files(tmp_path):
    root = _tree(tmp_path, {
        "src/App.java": ('package x;\nimport java.security.MessageDigest;\n'
                         'class App { void f() throws Exception {\n'
                         '  String algorithm = props.getProperty("hashAlg1", "SHA512");\n'
                         '  MessageDigest.getInstance(algorithm);\n} }\n'),
        "src/resources/benchmark.properties": "# comment\nhashAlg1=MD5\nhashAlg2=SHA-256\n",
    })
    res = codeintel.review_source_tree(root)
    assert res["properties_resolved"] >= 2
    assert any(f["family"] == "weak_hash" and f["cwe"] == "CWE-328" for f in res["findings"])
    assert all(f["provenance"] == "source-derived" for f in res["findings"])
    assert res["lane"] == "code-assisted"
    assert "App.java" in {os.path.basename(f["file"]) for f in res["findings"]}


def test_tree_keeps_the_matched_clean_twin_clean(tmp_path):
    root = _tree(tmp_path, {
        "src/Safe.java": ('package x;\nimport java.security.MessageDigest;\n'
                          'class Safe { void f() throws Exception {\n'
                          '  String algorithm = props.getProperty("hashAlg2", "SHA5");\n'
                          '  MessageDigest.getInstance(algorithm);\n'
                          '  javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");\n'
                          '  java.util.Random g = java.security.SecureRandom.getInstance("SHA1PRNG");\n'
                          '} }\n'),
        "src/resources/benchmark.properties": "hashAlg1=MD5\nhashAlg2=SHA-256\n",
    })
    res = codeintel.review_source_tree(root)
    assert res["files_scanned"] == 1
    assert res["findings"] == []


def test_tree_lists_every_file_it_read_so_a_missing_case_is_visible(tmp_path):
    root = _tree(tmp_path, {"a/One.java": "class One {}", "b/Two.java": "class Two {}"})
    res = codeintel.review_source_tree(root)
    assert {os.path.basename(p) for p in res["files"]} == {"One.java", "Two.java"}


# ── benchmark wiring: the lane must be impossible to misread ─────
def _row(test, cat, fam, lane="code-assisted", error=""):
    return {"test": test, "category": cat, "families": [fam] if fam else [],
            "conf": ["confirmed"] if fam else [], "lane": lane, "error": error}


def test_the_source_categories_have_a_family_mapping():
    for cat, fam in (("crypto", "weak_crypto"), ("hash", "weak_hash"), ("weakrand", "weak_random")):
        assert fam in ob.FAMILIES[cat]


def test_trustbound_is_mapped_only_because_a_detector_now_ships_for_it():
    """This assertion used to read `assert not ob.FAMILIES.get("trustbound")`, and it was right to.
    A mapping with no detector behind it is a claim, and the category scored an honest 0 rather
    than a fabricated number.

    What changed is not the standard, it is the evidence. A dataflow analysis now separates the
    clean twins, measured sealed at **0.0% FPR on both suites** (Java 67 TP / 0 FP / 43 TN,
    Python 18 TP / 0 FP / 19 TN). The bar was never "somebody mapped it"; it was "the clean twins
    survive it".

    So the invariant this test pins is inverted but not weakened: the mapping may exist ONLY while
    the detector that earns it exists. If `scan_trust_boundary` is ever removed, this fails, and
    the honest response is to unmap the category again rather than to delete this test.
    """
    assert ob.FAMILIES.get("trustbound") == {"trust_boundary"}
    assert hasattr(cr, "scan_trust_boundary")
    # and the detector has to actually discriminate, not merely exist
    sink = ('request.getSession().setAttribute("userid", bar);')
    tainted = ('String param = request.getParameter("p"); String bar = param;')
    constant = ('String bar = "constant";')
    wrap = ("import javax.servlet.http.*;\npublic class C extends HttpServlet {\n"
            "  public void doPost(HttpServletRequest request, HttpServletResponse response) {\n"
            "    %s\n    %s\n  }\n}\n")
    assert len(cr.scan_trust_boundary(wrap % (tainted, sink), "C.java")) == 1
    assert cr.scan_trust_boundary(wrap % (constant, sink), "C.java") == []


def test_a_code_assisted_run_is_scored_and_labelled_as_such():
    run = {"target": "java", "results": [_row("T1", "crypto", "weak_crypto"),
                                         _row("T2", "crypto", None)]}
    key = {"T1": ("crypto", True), "T2": ("crypto", False)}
    s = ob.score(run, key)
    assert s["per_category"]["crypto"]["tp"] == 1 and s["per_category"]["crypto"]["tn"] == 1
    assert s["lanes"] == ["code-assisted"]
    text = ob.report(s)
    assert "CODE-ASSISTED" in text and "SOURCE-DERIVED" in text
    assert "not a dast" in text.lower()


def test_a_mixed_lane_run_is_called_out_rather_than_averaged_quietly():
    """Two lanes in one number is the mislabelling the ledger already carries a retraction for."""
    run = {"target": "java", "results": [_row("T1", "crypto", "weak_crypto"),
                                         _row("T2", "sqli", "sqli", lane="dast")]}
    key = {"T1": ("crypto", True), "T2": ("sqli", True)}
    text = ob.report(ob.score(run, key))
    assert "MIXED" in text


def test_a_case_with_no_source_is_unscored_not_counted_as_a_miss():
    run = {"target": "java",
           "results": [_row("T1", "crypto", None, error="no source provided"),
                       _row("T2", "crypto", "weak_crypto")]}
    key = {"T1": ("crypto", True), "T2": ("crypto", True)}
    s = ob.score(run, key)
    assert "T1" in s["unscored"]
    assert s["per_category"]["crypto"]["tp"] == 1 and s["per_category"]["crypto"]["fn"] == 0


def test_dast_reports_are_unchanged_by_the_lane_labelling():
    run = {"target": "java", "results": [_row("T1", "sqli", "sqli", lane="dast")]}
    text = ob.report(ob.score(run, {"T1": ("sqli", True)}))
    assert "CODE-ASSISTED" not in text


# ══════════════════════════════════════════════════════════════════════════════════
# PYTHON — the same lane, dispatched by language rather than gated to *.java
# ══════════════════════════════════════════════════════════════════════════════════
# The Java rules above measure 100/100/100 and are untouched. What follows is the SAME
# discipline applied to Python call sites: mask the comments and literal bodies first, then
# match structure against the skeleton and only read a literal back when it sits in an argument
# position of a call the skeleton actually contains.
#
# Python moves the traps around. `#` starts a comment where `//` is FLOOR DIVISION; a docstring
# is a string literal that spans lines; an f-string is part literal and part CODE; and the single
# most important discriminator in the whole suite is a RECEIVER, not a name --
# `random.getrandbits(32)` is predictable while `random.SystemRandom().getrandbits(32)` is a
# CSPRNG, and a rule that greps for `getrandbits` reports 113 clean twins as vulnerable.


# ── masking: the Python primitive every Python rule depends on ───
def test_python_mask_blanks_hash_comments_and_literal_bodies_but_keeps_offsets():
    src = "x = 1  # hashlib.md5(b'')\ns = 'md5'\nh = hashlib.sha1(b)\n"
    skel, lits = cr.mask_python_source(src)
    assert len(skel) == len(src)                    # offsets survive, so line numbers stay true
    assert skel.count("\n") == src.count("\n")
    assert "hashlib.md5" not in skel                # the comment is gone
    assert "'" in skel and "md5" not in skel        # the literal's quotes stay, its body does not
    assert "md5" in lits.values()                   # ...but the body is recoverable as an argument
    assert "hashlib.sha1(" in skel                  # and real code is untouched


def test_python_mask_does_not_treat_floor_division_as_a_comment():
    """`//` is a COMMENT in Java and an OPERATOR in Python. A masker that carries the Java rule
    over blanks the rest of every line containing an integer division -- and then reports a clean
    result for the weak call sitting after it."""
    src = "half = n // 2\nh = hashlib.md5(b'x')\n"
    skel, _ = cr.mask_python_source(src)
    assert "n // 2" in skel
    assert cr.scan_python_hash(src)


def test_python_mask_blanks_a_docstring_without_swallowing_the_module():
    src = ('"""Module doc: we used to call hashlib.md5() here."""\n'
           "import hashlib\n"
           "def f(b):\n"
           "    return hashlib.sha1(b)\n")
    skel, _ = cr.mask_python_source(src)
    assert "hashlib.md5" not in skel and "hashlib.sha1(b)" in skel
    hits = cr.scan_python_hash(src)
    assert [h["algorithm"] for h in hits] == ["SHA1"] and hits[0]["line"] == 4


def test_python_mask_keeps_f_string_interpolations_as_code():
    """An f-string is half literal and half expression. Blanking the whole thing hides a real call
    site; leaving the whole thing hides nothing but reads the prose as code. Only `{...}` is code."""
    src = "import hashlib\nmsg = f'digest md5 = {hashlib.md5(b).hexdigest()}'\n"
    skel, _ = cr.mask_python_source(src)
    assert "digest md5 =" not in skel               # the prose half is a literal
    assert "hashlib.md5(b)" in skel                 # the interpolated half is code
    assert cr.scan_python_hash(src)


# ── hash: broken digest at a real Python call site (CWE-328) ─────
def test_python_hashlib_md5_and_sha1_are_flagged():
    for src, alg in (("import hashlib\nh = hashlib.md5(data)\n", "MD5"),
                     ("import hashlib\nh = hashlib.sha1(data)\n", "SHA1")):
        hits = cr.scan_python_hash(src)
        assert hits and hits[0]["cwe"] == "CWE-328" and hits[0]["algorithm"] == alg, src
        assert hits[0]["line"] == 2


def test_python_hashlib_new_with_a_literal_is_flagged():
    for spec in ("'md5'", '"MD5"', "'sha1'", '"SHA-1"'):
        assert cr.scan_python_hash("import hashlib\nh = hashlib.new(%s)\n" % spec), spec


def test_python_hashlib_new_resolves_a_variable():
    src = "import hashlib\nalg = 'md5'\nh = hashlib.new(alg)\n"
    hits = cr.scan_python_hash(src)
    assert hits and hits[0]["algorithm"] == "MD5"


def test_python_hashlib_new_resolves_an_environment_default():
    src = ("import hashlib, os\n"
           "alg = os.environ.get('HASH_ALG', 'md5')\n"
           "h = hashlib.new(alg)\n")
    hits = cr.scan_python_hash(src)
    assert hits and hits[0]["resolved_from"] == "default-literal"


def test_python_from_hashlib_import_md5_is_flagged():
    assert cr.scan_python_hash("from hashlib import md5\nd = md5(b'x').hexdigest()\n")
    assert cr.scan_python_hash("from hashlib import sha1 as h\nd = h(b'x')\n")


def test_python_pycryptodome_md5_is_flagged():
    assert cr.scan_python_hash("from Crypto.Hash import MD5\nh = MD5.new(data)\n")
    assert cr.scan_python_hash("import Crypto\nh = Crypto.Hash.MD5.new(data)\n")
    assert cr.scan_python_hash("from Crypto.Hash import SHA256\nh = SHA256.new(data)\n") == []


def test_python_hmac_with_md5_is_flagged_but_hmac_sha1_is_not():
    # same precision the Java side keeps: HMAC-SHA1 has no practical break and calling it broken
    # would be a false positive wearing a security costume
    assert cr.scan_python_hash("import hmac, hashlib\nm = hmac.new(k, msg, hashlib.md5)\n")
    assert cr.scan_python_hash("import hmac, hashlib\nm = hmac.new(k, msg, hashlib.sha1)\n") == []


# NEGATIVE CONTROL 1 — modern SHA-2 must not be flagged
def test_python_sha256_and_sha512_are_not_flagged():
    assert cr.scan_python_hash("import hashlib\nh = hashlib.sha256(data)\n") == []
    assert cr.scan_python_hash("import hashlib\nh = hashlib.sha512(data)\n") == []
    assert cr.scan_python_hash("import hashlib\nh = hashlib.sha3_256(data)\n") == []
    assert cr.scan_python_hash("import hashlib\nh = hashlib.new('sha384')\n") == []
    assert cr.scan_python_hash("import hashlib\nh = hashlib.blake2b(data)\n") == []


# NEGATIVE CONTROL 2 — usedforsecurity=False is an explicit non-security use
def test_python_usedforsecurity_false_is_not_flagged():
    assert cr.scan_python_hash("import hashlib\nh = hashlib.md5(data, usedforsecurity=False)\n") == []
    assert cr.scan_python_hash("import hashlib\nh = hashlib.new('md5', usedforsecurity=False)\n") == []
    # ...and the kwarg only exculpates when it is actually False
    assert cr.scan_python_hash("import hashlib\nh = hashlib.md5(data, usedforsecurity=True)\n")


# NEGATIVE CONTROL 4 — a comment or a string containing "md5" is not a call site
def test_python_md5_named_only_in_a_comment_or_string_is_not_flagged():
    assert cr.scan_python_hash("import hashlib\n# TODO: hashlib.md5(x) was removed in 2019\n") == []
    assert cr.scan_python_hash("import hashlib\nADVICE = 'md5 and sha1 are broken, use sha256'\n") == []
    assert cr.scan_python_hash("import hashlib\nprint('never call hashlib.md5() again')\n") == []
    assert cr.scan_python_hash('"""Runbook:\n  hashlib.new("md5")\n"""\n') == []
    assert cr.scan_python_hash("import hashlib\nAPI = 'hashlib.new'\nALG = 'md5'\n") == []


# NEGATIVE CONTROL 5 — a user-defined md5() is not the stdlib call
def test_python_a_user_defined_md5_is_not_the_stdlib_call():
    assert cr.scan_python_hash("def md5(x):\n    return x\n\nd = md5(payload)\n") == []
    assert cr.scan_python_hash("d = self.md5(payload)\n") == []
    assert cr.scan_python_hash("d = crypto_registry.md5(payload)\n") == []
    # even WITH the import present, a local definition shadows it
    assert cr.scan_python_hash("from hashlib import md5\n\ndef md5(x):\n    return x\n"
                               "d = md5(payload)\n") == []


# ── weakrand: predictable generator at a real Python call site (CWE-330) ──
def test_python_random_module_calls_are_flagged():
    for call in ("random.random()", "random.randint(0, 2**32)", "random.getrandbits(32)",
                 "random.randbytes(32)", "random.normalvariate()", "random.choice(seq)",
                 "random.Random().random()", "random.seed(1)"):
        src = "import random\nvalue = %s\n" % call
        hits = cr.scan_python_random(src)
        assert hits and hits[0]["cwe"] in ("CWE-330", "CWE-337"), call


def test_python_random_seeded_from_the_clock_is_flagged():
    hits = cr.scan_python_random("import random, time\nrandom.seed(time.time())\n")
    assert hits and any(h["cwe"] == "CWE-337" for h in hits)


def test_python_from_random_import_randint_is_flagged():
    assert cr.scan_python_random("from random import randint\nv = randint(0, 99)\n")
    assert cr.scan_python_random("from random import choice as pick\nv = pick(seq)\n")


# NEGATIVE CONTROL 3 — the CSPRNGs must not be flagged
def test_python_secrets_and_os_urandom_are_not_flagged():
    assert cr.scan_python_random("import secrets\nv = secrets.token_bytes(32)\n") == []
    assert cr.scan_python_random("import secrets\nv = secrets.token_urlsafe(32)\n") == []
    assert cr.scan_python_random("import secrets\nv = secrets.randbelow(2**32)\n") == []
    assert cr.scan_python_random("import secrets\nv = secrets.randbits(32)\n") == []
    assert cr.scan_python_random("import os\nv = os.urandom(32)\n") == []
    assert cr.scan_python_random("import uuid\nv = uuid.uuid4().hex\n") == []


def test_python_system_random_is_a_csprng_not_a_weak_generator():
    """THE discriminator. `random.SystemRandom` reads from os.urandom; it lives in the `random`
    module and its methods have the same names as the weak ones. 113 of the suite's weakrand cases
    are exactly this line, and a rule that matches on the METHOD reports every one of them."""
    for call in ("random.SystemRandom().getrandbits(32)", "random.SystemRandom().random()",
                 "random.SystemRandom().randint(0, 99)", "random.SystemRandom().choice(seq)"):
        assert cr.scan_python_random("import random\nvalue = %s\n" % call) == [], call
    assert cr.scan_python_random("from random import SystemRandom\nv = SystemRandom().random()\n") == []


def test_python_a_foreign_random_module_is_not_the_stdlib_one():
    """`numpy.random.random()` contains the substring `random.random(`, and `from numpy import
    random` rebinds the name entirely. Neither is `import random`."""
    assert cr.scan_python_random("import numpy\nv = numpy.random.random()\n") == []
    assert cr.scan_python_random("from numpy import random\nv = random.random()\n") == []
    assert cr.scan_python_random("v = self.random.randint(0, 9)\n") == []


def test_python_random_named_only_in_a_comment_or_string_is_not_flagged():
    assert cr.scan_python_random("import random\n# replaced random.random() with secrets\n") == []
    assert cr.scan_python_random("import random\nNOTE = 'random.randint() is banned here'\n") == []
    assert cr.scan_python_random("import random\nprint('do not use random.random() for tokens')\n") == []


# ── crypto: broken cipher at a real Python call site (CWE-327) ───
def test_python_weak_ciphers_and_ecb_are_flagged():
    assert cr.scan_python_crypto("from Crypto.Cipher import DES\nc = DES.new(key, DES.MODE_CBC)\n")
    assert cr.scan_python_crypto("from Crypto.Cipher import ARC4\nc = ARC4.new(key)\n")
    assert cr.scan_python_crypto("from Crypto.Cipher import AES\nc = AES.new(key, AES.MODE_ECB)\n")
    assert cr.scan_python_crypto(
        "from cryptography.hazmat.primitives.ciphers import algorithms\n"
        "a = algorithms.TripleDES(key)\n")


def test_python_aes_gcm_is_not_flagged():
    assert cr.scan_python_crypto("from Crypto.Cipher import AES\nc = AES.new(key, AES.MODE_GCM)\n") == []
    assert cr.scan_python_crypto("from Crypto.Cipher import ChaCha20\nc = ChaCha20.new(key=k)\n") == []
    assert cr.scan_python_crypto("# we removed DES.new(key, DES.MODE_ECB) in 2019\n") == []
    assert cr.scan_python_crypto("BANNED = 'DES/ECB'\n") == []


# ── dispatch: the lane is language-general, and Java is unchanged ─
def test_review_routes_python_source_into_the_code_assisted_lane():
    res = cr.review("import hashlib\n\ndef f(b):\n    return hashlib.md5(b).digest()\n", "app.py")
    assert any(f.get("lane") == "code-assisted" and f["cwe"] == "CWE-328"
               for f in res["findings"])


def test_review_still_leaves_javascript_out_of_the_python_lane():
    res = cr.review("import x from 'y';\nvar r = Math.random();\nel.innerHTML = r;\n", "app.js")
    assert not any(f.get("lane") == "code-assisted" for f in res["findings"])


def test_every_python_source_finding_is_marked_source_derived():
    out = cr.review_python("import hashlib, random\nh = hashlib.md5(b)\nv = random.random()\n",
                           "svc.py")
    assert out and all(f["provenance"] == "source-derived" for f in out)
    assert all(f["lane"] == "code-assisted" and f["analysis"] == "static-call-site" for f in out)
    assert {f["family"] for f in out} == {"weak_hash", "weak_random"}


PY_WEAK = '''"""Legacy billing helpers. We dropped hashlib.md5 from the token path in 2019."""
import hashlib
import random


def fingerprint(pan: str) -> str:
    # historical note: hashlib.new("md5") used to live here
    return hashlib.sha1(pan.encode()).hexdigest()


def remember_me_cookie() -> str:
    return str(random.getrandbits(32))
'''

PY_SAFE = '''"""Matched clean twin of the module above. Every construct is the strong one."""
import hashlib
import random
import secrets


def fingerprint(pan: str) -> str:
    # historical note: hashlib.new("md5") used to live here
    return hashlib.sha512(pan.encode()).hexdigest()


def checksum(blob: bytes) -> str:
    return hashlib.md5(blob, usedforsecurity=False).hexdigest()


def remember_me_cookie() -> str:
    return str(random.SystemRandom().getrandbits(32))


def api_key() -> str:
    return secrets.token_urlsafe(32)
'''


def test_tree_scans_python_as_well_as_java(tmp_path):
    root = _tree(tmp_path, {"svc/Legacy.java": 'class L { void f() throws Exception {'
                                               ' javax.crypto.Cipher.getInstance("DES"); } }\n',
                            "svc/billing.py": PY_WEAK})
    res = codeintel.review_source_tree(root)
    assert res["files_scanned"] == 2
    assert {os.path.basename(p) for p in res["files"]} == {"Legacy.java", "billing.py"}
    cwes = {f["cwe"] for f in res["findings"]}
    assert cwes == {"CWE-327", "CWE-328", "CWE-330"}, cwes
    assert all(f["provenance"] == "source-derived" for f in res["findings"])


def test_tree_keeps_the_python_clean_twin_clean(tmp_path):
    root = _tree(tmp_path, {"svc/safe.py": PY_SAFE})
    res = codeintel.review_source_tree(root)
    assert res["files_scanned"] == 1
    assert res["findings"] == []


def test_python_dispatch_does_not_disturb_the_java_lane(tmp_path):
    """Java measures 100/100/100. Adding a second language must change nothing about it."""
    java = ('package x;\nimport java.security.MessageDigest;\n'
            'class App { void f() throws Exception {\n'
            '  MessageDigest.getInstance("MD5");\n'
            '  javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");\n'
            '  java.util.Random g = java.security.SecureRandom.getInstance("SHA1PRNG");\n} }\n')
    root = _tree(tmp_path, {"src/App.java": java, "src/other.py": PY_SAFE})
    res = codeintel.review_source_tree(root)
    assert [(f["cwe"], os.path.basename(f["file"])) for f in res["findings"]] \
        == [("CWE-328", "App.java")]

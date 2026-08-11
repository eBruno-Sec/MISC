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

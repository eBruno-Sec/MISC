"""The code-assisted (SAST) lane must work on Java that is not OWASP Benchmark, and must stay
silent on the four constructs a naive implementation flags.

A detector that only works on `BenchmarkTest*.java` is a signature, not a capability. Every fixture
in this file is hand-written application code -- a Spring @Service, an Android helper, Apache
Commons wrappers -- with package names, class names and method names that appear nowhere in the
suite. MEASURED (docs/handoff/breaker.md, SESSION 2 TARGET 3): the same rules score 100.0% TPR /
0.0% FPR on the suite's crypto, hash and weakrand categories AND find every construct below, while
reporting nothing at all in the negative-control file.

The four mandatory negative controls are `test_negative_control_*`. The parser traps in
`test_inert_text_is_never_a_call_site` are the ones that actually kill naive implementations: a
weak algorithm named in a comment, in a string literal, in a commented-out call, in a Java 15 text
block, or in a log line is text, and text is not a call.
"""
from __future__ import annotations

import os
import tempfile

import codeintel

# ── negative controls: modern crypto, and weak names that are only ever text ───
SAFE = '''package com.acme.billing;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;

/**
 * Historical note: this service used to call Cipher.getInstance("DES") and
 * MessageDigest.getInstance("MD5"). Both were removed in 2019.
 */
public class CryptoConfig {

    // CONTROL 1 - modern AEAD ciphers must never be CWE-327
    public Cipher aead() throws Exception { return Cipher.getInstance("AES/GCM/NoPadding"); }
    public Cipher ccm() throws Exception { return Cipher.getInstance("AES/CCM/NoPadding"); }
    public KeyGenerator keys() throws Exception { return KeyGenerator.getInstance("AES"); }

    // CONTROL 2 - modern digests must never be CWE-328 (HMAC-SHA1 has no practical break)
    public MessageDigest sha256() throws Exception { return MessageDigest.getInstance("SHA-256"); }
    public MessageDigest sha512() throws Exception { return MessageDigest.getInstance("SHA-512"); }
    public MessageDigest sha3() throws Exception { return MessageDigest.getInstance("SHA3-256"); }
    public Mac hmacSha1() throws Exception { return Mac.getInstance("HmacSHA1"); }
    public Signature sig() throws Exception { return Signature.getInstance("SHA256withRSA"); }

    // CONTROL 3 - SecureRandom must never be CWE-330, including behind a supertype reference
    private final SecureRandom csprng = new SecureRandom();
    public SecureRandom prng() throws Exception { return SecureRandom.getInstance("SHA1PRNG"); }
    public java.util.Random behindSupertype() throws Exception {
        java.util.Random numGen = SecureRandom.getInstance("SHA1PRNG");
        return numGen;
    }
    public int roll(java.util.Random generator) { return generator.nextInt(6); }
    private java.util.Random declaredNeverInstantiated;

    // CONTROL 4 - MD5/DES named ONLY in a comment or a string literal
    // TODO: we finally dropped MD5 in favour of SHA-256; do not reintroduce MD5 here.
    // MessageDigest.getInstance("MD5");
    // Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");
    private static final String ADVICE = "MD5 and SHA1 are broken; use SHA-256";
    private static final String BANNED = "AES/ECB/PKCS5Padding";
    public void logIt() {
        System.out.println("Problem executing hash - MessageDigest.getInstance(java.lang.String)");
        System.out.println("Legacy deployments used DES/ECB/PKCS5Padding and new Random()");
        System.out.println("Do not call Math.random() for tokens");
    }
    public String advice() { return ADVICE + BANNED + csprng.toString(); }
}
'''

# ── parser traps: escaped quotes, apostrophes in comments, URLs, char literals, text blocks ───
TRAPS = '''package com.acme.traps;

import javax.crypto.Cipher;
import java.security.MessageDigest;

public class Traps {
    String t1 = "he said \\"Cipher.getInstance(\\\\\\"DES\\\\\\")\\" and left";
    /* don't use "DES" here, it isn't safe; MessageDigest.getInstance("MD5") is worse */
    String t3 = "https://example.com/docs/DES?alg=MD5#Cipher.getInstance(\\"RC4\\")";
    char t4 = '"';
    char t5 = '\\\\';
    String t5b = "Cipher.getInstance(\\"Blowfish\\")";
    String t6 = """
        Legacy runbook:
          Cipher.getInstance("DES/ECB/PKCS5Padding");
          MessageDigest.getInstance("MD5");
          new java.util.Random();
        """;
    @SuppressWarnings("MD5")
    void t7() {}
    void migrateFromMd5ToSha256() {}
    static final String API = "MessageDigest.getInstance";
    static final String ALG = "MD5";
    String t10 = "// Cipher.getInstance(\\"DES\\")";
    /**
     * {@code Cipher.getInstance("DES")} was removed.
     * @see java.util.Random
     */
    void t11() {}
}
'''

# ── real weak constructs, in shapes that appear nowhere in OWASP Benchmark ────
SPRING = '''package com.acme.billing;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.Random;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.stereotype.Service;

@Service
public class LegacyVaultService {
    private final Random jitter = new Random();
    private Random seeded = new Random(System.currentTimeMillis());

    public byte[] sealCardNumber(byte[] pan, byte[] key) throws Exception {
        Cipher c = Cipher.getInstance("DES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DES"));
        return c.doFinal(pan);
    }
    public byte[] sealLedger(byte[] blob) throws Exception {
        return Cipher.getInstance("AES").doFinal(blob);
    }
    public byte[] sealArchive(byte[] blob) throws Exception {
        String transformation = "Blowfish/ECB/PKCS5Padding";
        return Cipher.getInstance(transformation).doFinal(blob);
    }
    public String fingerprint(String s) throws Exception {
        return new String(MessageDigest.getInstance("MD5").digest(s.getBytes()));
    }
    public String commonsFingerprint(String s) { return DigestUtils.md5Hex(s); }
    public Mac legacyMac() throws Exception { return Mac.getInstance("HmacMD5"); }
    public Signature legacySig() throws Exception { return Signature.getInstance("MD5withRSA"); }
    public String newSessionToken() { return RandomStringUtils.randomAlphanumeric(32); }
    public long couponCode() { return Math.round(Math.random() * 1000000L); }
    public String csrfNonce() { return Long.toHexString(System.currentTimeMillis()); }
    public int jitterMs() { return jitter.nextInt(50) + seeded.nextInt(10); }
}
'''

ANDROID = '''package com.acme.android;

import javax.crypto.Cipher;
import java.security.MessageDigest;
import java.util.concurrent.ThreadLocalRandom;

public final class DeviceKeyStore {
    public static byte[] deviceId(String serial) throws Exception {
        return MessageDigest.getInstance("SHA1").digest(serial.getBytes());
    }
    public static Cipher legacy() throws Exception { return Cipher.getInstance("RC4"); }
    public static int pin() { return ThreadLocalRandom.current().nextInt(1000, 9999); }
}
'''


def _tree(**files) -> str:
    d = tempfile.mkdtemp()
    sub = os.path.join(d, "src", "main", "java")
    os.makedirs(sub)
    for name, body in files.items():
        with open(os.path.join(sub, name), "w", encoding="utf-8") as fh:
            fh.write(body)
    return d


def _findings(**files) -> list:
    r = codeintel.review_source_tree(_tree(**files))
    assert r["error"] == "" and r["files_scanned"] == len(files)
    return r["findings"]


# ── the four mandatory negative controls ──────────────────────────────────────
def test_negative_control_aead_cipher_is_not_weak_crypto():
    hits = [f for f in _findings(**{"CryptoConfig.java": SAFE}) if f["cwe"] == "CWE-327"]
    assert hits == [], hits


def test_negative_control_sha256_and_sha512_are_not_weak_hashes():
    hits = [f for f in _findings(**{"CryptoConfig.java": SAFE}) if f["cwe"] == "CWE-328"]
    assert hits == [], hits


def test_negative_control_securerandom_is_not_weak_randomness():
    hits = [f for f in _findings(**{"CryptoConfig.java": SAFE})
            if f["cwe"] in ("CWE-330", "CWE-337")]
    assert hits == [], hits


def test_negative_control_md5_named_only_in_a_comment_or_string_is_not_a_finding():
    """The one that kills a naive implementation. This file names MD5, SHA1, DES, ECB,
    `new Random()` and `Math.random()` in comments, commented-out calls, string constants and log
    lines, and contains no weak call site at all."""
    assert _findings(**{"CryptoConfig.java": SAFE}) == []


def test_inert_text_is_never_a_call_site():
    """Escaped quotes, an apostrophe inside a block comment, a URL whose // is not a comment, char
    literals holding a quote and a backslash, a Java 15 text block, an annotation argument, a method
    name, and javadoc {@code}. Every one of them spells out a weak construct; none of them is one."""
    assert _findings(**{"Traps.java": TRAPS}) == []


def test_the_masker_does_not_swallow_the_code_that_follows_a_trap():
    """The mirror image, and the reason the trap test above is not enough on its own: a masker that
    mis-parses a text block or an escaped quote would blank the rest of the file and report a clean
    result for a file full of weak crypto."""
    after = TRAPS.replace("    void t11() {}",
                          '    Cipher real1() throws Exception { return Cipher.getInstance("DES"); }\n'
                          '    MessageDigest real2() throws Exception { return MessageDigest.getInstance("MD5"); }\n'
                          '    java.util.Random real3() { return new java.util.Random(); }')
    cwes = sorted({f["cwe"] for f in _findings(**{"Traps.java": after})})
    assert cwes == ["CWE-327", "CWE-328", "CWE-330"], cwes


# ── generality: the same rules on Java that is nothing like the suite ─────────
def test_finds_weak_crypto_in_a_spring_service_and_an_android_helper():
    found = _findings(**{"LegacyVaultService.java": SPRING, "DeviceKeyStore.java": ANDROID})
    algs = {f["title"].split(": ", 1)[1] for f in found}
    # cipher selection, including the JCE no-mode-means-ECB default and a value held in a variable
    assert {"DES/CBC", "DES", "AES (no mode)", "BLOWFISH/ECB", "RC4"} <= algs, algs
    # digests: direct call site, Apache Commons method-name form, a MAC, and a signature suite
    assert "MD5" in algs and "SHA1" in algs
    apis = {f["evidence"].split("  ", 1)[1].split("(")[0] for f in found}
    assert "DigestUtils.md5Hex" in apis, apis
    # randomness: constructor, clock seed, Math.random, RandomStringUtils, ThreadLocalRandom
    constructs = {f["title"].split(": ", 1)[1] for f in found if f["cwe"] in ("CWE-330", "CWE-337")}
    assert {"new java.util.Random()", "Random(System.currentTimeMillis())", "Math.random()",
            "RandomStringUtils.random*()", "ThreadLocalRandom.current()"} <= constructs, constructs


def test_every_code_assisted_finding_carries_its_lane_marker():
    """A percentage travels; the sentence explaining it does not. If the marker is not on the
    finding, a source-derived number can be pasted next to a DAST score with nothing to stop it."""
    for f in _findings(**{"LegacyVaultService.java": SPRING}):
        assert f["provenance"] == "source-derived" and f["lane"] == "code-assisted"
        assert f["analysis"] == "static-call-site" and "sast" in f["tags"]


def test_absent_source_is_reported_as_absent_not_as_clean():
    for root in ("", "/no/such/tree/anywhere"):
        r = codeintel.review_source_tree(root)
        assert r["findings"] == [] and "no source provided" in r["error"], root

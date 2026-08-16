"""Q-053 GAP-3: `family` is a property of the FINDING, not of the module.

sqli_tool proves several different things. Five of its oracles prove "this parameter is
concatenated into a SQL statement" (family `sqli`). One of them -- the auth-bypass oracle --
proves something strictly stronger and CATEGORICALLY different: that authentication was
bypassed. Stamping both with `sqli` made the confirmed bypass indistinguishable, BY FAMILY,
from an ordinary SQLi in a search box, and left ASVS AUTHN-02 ("authentication cannot be
bypassed") unfailable in every possible run because no engine emitted the family it declares.

These tests pin BOTH directions, because a family that is too narrow is as wrong as one too
broad: the bypass earns `auth_bypass`, and every other oracle keeps `sqli`.
"""
import asvs_model
import proof_schema
import sqli_tool as sqli


# ── GAP-3: the auth-bypass oracle earns its own family ────────────────────────
def test_auth_bypass_finding_emits_auth_bypass_family():
    f = sqli.auth_bypass_finding("https://t/rest/user/login", "email", "' OR 1=1--",
                                 "session/JWT token issued for an invalid credential")
    assert f["family"] == "auth_bypass", (
        "a CONFIRMED authentication bypass must not be labelled `sqli` -- ASVS AUTHN-02 "
        "declares violated_by=auth_bypass and cannot fail without a producer")
    # The MECHANISM is still SQL injection: CWE-89 and the `sqli` tag are load-bearing for the
    # CWE-keyed consumers (benchmark._canon_class, main.py) and the tag-keyed one (remediation).
    assert f["cwe"] == "CWE-89"
    assert "sqli" in f["tags"] and "auth-bypass" in f["tags"]
    assert f["severity"] == "critical" and f["confidence"] == "confirmed"


def test_auth_bypass_finding_fails_authn02_and_not_val01():
    """The whole point of the family: it moves the finding onto the objective it violates."""
    f = sqli.auth_bypass_finding("https://t/rest/user/login", "email", "' OR 1=1--",
                                 "session/JWT token issued for an invalid credential")
    rows = {o["cid"]: o for o in asvs_model.assess([f])["objectives"]}
    assert rows["AUTHN-02"]["status"] == "failed", "the objective this finding exists to fail"
    # and it must NOT drag the generic SQLi objective with it -- that objective has its own producers
    assert rows["VAL-01"]["status"] != "failed", (
        "a login bypass is not evidence about every query parameter in the app")


def test_auth_bypass_evidence_satisfies_the_proof_gate():
    """A `confirmed` finding must carry replayable proof. Before this change the evidence was a
    bare prose signal that carried no request, no verb and no outcome, so validate_confirmed
    REJECTED it (`evidence_signal:union`) -- a confirmed finding failing its own proof contract."""
    f = sqli.auth_bypass_finding("https://t/rest/user/login", "email", "' OR 1=1--",
                                 "session/JWT token issued for an invalid credential")
    ok, missing = proof_schema.validate_confirmed(f)
    assert ok, "confirmed auth-bypass must carry its proof; missing=%r" % (missing,)
    ev = f["evidence"]
    assert "->" in ev and "POST" in ev            # a replayable exchange, not a sentence
    assert "' OR 1=1--" in ev                     # the exact payload that did it
    assert "rest/user/login" in ev                # against the exact endpoint


# ── the other direction: nothing else in this module may claim auth_bypass ────
def test_every_other_oracle_keeps_the_sqli_family():
    """NEGATIVE CONTROL for over-broadening. Only the auth-bypass builder changes."""
    others = [
        sqli.error_finding("https://t/p?id=1", "id", "'", [{"dbms": "MySQL", "pattern": "x"}]),
        sqli.boolean_finding("https://t/p?id=1", "id",
                             {"ctx": "numeric", "true": "1 AND 1=1", "false": "1 AND 1=2"}),
        sqli.time_finding("https://t/p?id=1", "id", {"dbms": "MySQL", "payload": "1 AND SLEEP(5)"},
                          0.2, 5.3, 5),
        sqli.quote_recovery_finding("https://t/p?id=1", "id", 200, 500, 200),
        sqli.structural_finding("https://t/p?sort=a", "sort", [{"dbms": "MySQL", "pattern": "x"}]),
        sqli.union_finding("https://t/p?id=1", "id", 3, "'", ["users"],
                           ["a@b.c:5f4dcc3b5aa765d61d8327deb882cf99"]),
    ]
    for f in others:
        assert f["family"] == "sqli", "%s must stay sqli" % f["title"]
    rows = {o["cid"]: o for o in asvs_model.assess(others)["objectives"]}
    assert rows["VAL-01"]["status"] == "failed"
    assert rows["AUTHN-02"]["status"] != "failed", (
        "an ordinary SQLi must NEVER fail 'authentication cannot be bypassed' -- a spurious "
        "FAIL is a defect too (this is exactly why Q-048 refused to re-point AUTHN-02 at sqli)")

"""Retest / closure loop (#117, Picus discipline): re-fire a finding's oracle -> OPEN/CLOSED/
INCONCLUSIVE. Deterministic verdict logic; never a false closure. Pure (no network)."""
import retest


def test_plan_only_safe_get_oracle_families_are_retestable():
    assert retest.plan({"family": "exposure", "target": "http://h/_debug"})["retestable"] is True
    # a state-changing / non-idempotent family is NOT auto-retested (honest, avoids re-performing writes)
    p = retest.plan({"family": "sqli", "target": "http://h/login"})
    assert p["retestable"] is False and "operator-approved" in p["reason"]
    # no replayable URL -> not retestable
    assert retest.plan({"family": "exposure"})["retestable"] is False


def test_reachable_oracle_open_when_still_served_closed_when_gone():
    f = {"family": "exposure", "target": "http://h/users/v1/_debug"}
    assert retest.evaluate(f, 200, body='{"users":[{"password":"x"}]}')["verdict"] == "open"
    assert retest.evaluate(f, 404, body="not found")["verdict"] == "closed"
    assert retest.evaluate(f, 200, body="   ")["verdict"] == "closed"     # served but empty -> gone
    assert retest.evaluate(f, None)["verdict"] == "inconclusive"          # unreachable -> honest unknown


def test_offsite_redirect_oracle():
    f = {"family": "open_redirect", "target": "http://h/go?next=//evil.com"}
    op = retest.evaluate(f, 302, headers={"Location": "https://evil.com/"})
    assert op["verdict"] == "open" and "evil.com" in op["detail"]
    # redirect back to the same host = fixed
    cl = retest.evaluate(f, 302, headers={"Location": "http://h/home"})
    assert cl["verdict"] == "closed"


def test_reflects_oracle_uses_url_borne_payload():
    f = {"family": "reflected_xss", "target": "http://h/s?q=<script>zz9</script>"}
    op = retest.evaluate(f, 200, body="results for <script>zz9</script> ...")
    assert op["verdict"] == "open"
    cl = retest.evaluate(f, 200, body="results for &lt;script&gt;zz9&lt;/script&gt; (encoded)")
    assert cl["verdict"] == "closed"
    # no crafted payload recoverable -> honest inconclusive, never a false closed
    assert retest.evaluate({"family": "xss", "target": "http://h/page"}, 200, body="x")["verdict"] == "inconclusive"


def test_chain_outcome_mapping():
    assert retest.chain_outcome("open") == "confirmed"
    assert retest.chain_outcome("closed") == "dismissed"
    assert retest.chain_outcome("inconclusive") == "attempted"

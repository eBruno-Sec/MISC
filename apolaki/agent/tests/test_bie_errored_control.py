"""REGRESSION (Q-00A) — a negative control that ERRORED is not a negative control that PASSED.

The live producer never returns None on failure. `_FETCH_JS` catches its own exception and returns
`{status: 0, body: '', headers: {}, ms: ..., error: '...'}`; the python wrapper `_fetch` turns that into
an `exchange(url, 0, "")` and, when `page.evaluate` itself raises, into that same exchange plus an
`error` key. Every oracle in bie.py tested only `if control is None`, so BOTH of those dicts satisfied
`is not None` and an errored control was scored as a satisfied control.

Two halves, and the second is the one a naive fix misses:

  half 1 — `judge()`: the mandatory-control gate accepted the dead dict, so `missing` was empty and the
           oracle walked on to `confirmed`.
  half 2 — `judge_client_side_authz` / `judge_param_swap`: the PUBLIC-resource rejection is written
           `if anon is not None and _s(anon) == 200 and ...`. A dead anon control has status 0, so it
           already failed the `== 200` test, never fired the rejection, and fell straight through to
           `confirmed`. Tightening `is not None` to `_control_ran(...)` on that line alone changes
           nothing at all — the public question has to be ANSWERED, not merely not-answered-negatively.

Each test below therefore asserts the pair: the dead-control case is a `lead`, and the same scenario
with a LIVE control is still `confirmed`. A gate that also kills the true positive is not a fix.
"""
import bie


def _ex(status, body, url="http://t/rest/basket/1"):
    return bie.exchange(url, status, body)


OBJ = '{"id":1,"owner":"alice","items":[{"sku":"A-1","qty":2}]}'
SHELL = "<html><body><app-root></app-root></body></html>"
ADMIN_PAGE = '{"users":[{"id":1,"email":"a@t"},{"id":2,"email":"b@t"}],"roles":["admin","user"]}'
MINE = '{"user":"alice","orders":[{"id":1,"total":10}]}'
THEIRS = '{"user":"bob","orders":[{"id":2,"total":99}]}'


def _ctl(**kw):
    base = {"tag": "a", "text": "Admin panel", "href": "/admin/users", "resolved": "http://t/admin/users",
            "routerlink": "", "id": "", "name": "", "visible": False, "disabled": False,
            "reason": "not-displayed"}
    return {**base, **kw}


# The two shapes the live producer actually emits for a failed control. Built through the real
# constructors, not hand-written, so a change to `exchange()` cannot make these tests lie.
def _js_caught(url="http://t/rest/basket/1"):
    """_FETCH_JS caught the fetch exception -> _fetch() -> exchange(url, 0, "") . No `error` key
    survives the wrapper, so `status == 0` is the ONLY signal that this probe never happened."""
    return bie.exchange(url, 0, "")


def _evaluate_raised(url="http://t/rest/basket/1"):
    """page.evaluate itself raised (context destroyed, navigation, timeout) -> exchange | {"error": ...}."""
    return bie.exchange(url, 0, "") | {"error": "TimeoutError: page.evaluate timed out"}


# ── the liveness predicate itself ─────────────────────────────────────────────
def test_control_ran_rejects_every_shape_the_producer_emits_on_failure():
    assert bie._control_ran(_js_caught()) is False, "status 0 is a probe that never reached the server"
    assert bie._control_ran(_evaluate_raised()) is False
    assert bie._control_ran(None) is False
    assert bie._control_ran({}) is False
    assert bie._control_ran("401") is False, "a non-dict is not a control"
    # a status that arrived but carries a transport error is still not a control
    assert bie._control_ran({"status": 200, "body": "x", "error": "aborted"}) is False


def test_control_ran_accepts_a_control_that_really_answered():
    assert bie._control_ran(_ex(401, "")) is True, "401 with an empty body IS a control: it ran and denied"
    assert bie._control_ran(_ex(404, "")) is True
    assert bie._control_ran(_ex(200, OBJ)) is True


def test_the_live_fetch_wrapper_really_produces_a_dead_control_dict():
    """Close the loop from producer to oracle: feed `_fetch` exactly what `_FETCH_JS` returns on a
    caught exception and confirm the resulting dict is one `_control_ran` refuses. Without this the
    oracle tests are only asserting against a shape I invented."""
    class _Page:
        def evaluate(self, js, arg):
            return {"status": 0, "body": "", "headers": {}, "ms": 3.0,
                    "error": "TypeError: Failed to fetch"}

    class _RaisingPage:
        def evaluate(self, js, arg):
            raise RuntimeError("Execution context was destroyed")

    dead = bie._fetch(_Page(), "http://t/rest/basket/1", {}, "anonymous")
    assert dead is not None, "the producer returns a dict, never None -- that is the whole defect"
    assert bie._control_ran(dead) is False
    raised = bie._fetch(_RaisingPage(), "http://t/rest/basket/1", {}, "anonymous")
    assert raised is not None and bie._control_ran(raised) is False


# ── half 1: judge() — the mandatory-control gate ──────────────────────────────
def test_judge_treats_an_errored_anonymous_control_as_missing():
    """BEFORE: confirmed (the dead dict was `is not None`, so the gate passed and the PUBLIC test at
    `_s(anon) == 200` could never fire on a status of 0). AFTER: lead."""
    v = bie.judge(_ex(200, OBJ), _ex(200, OBJ), anon=_js_caught(), nonexistent=_ex(404, ""))
    assert v["verdict"] == "lead", v
    assert "anonymous" in v["reason"] and "did not run" in v["reason"]


def test_judge_treats_an_errored_implausible_id_control_as_missing():
    v = bie.judge(_ex(200, OBJ), _ex(200, OBJ), anon=_ex(401, ""), nonexistent=_evaluate_raised())
    assert v["verdict"] == "lead", v
    assert "implausible-id" in v["reason"]


def test_judge_names_both_controls_when_both_died():
    v = bie.judge(_ex(200, OBJ), _ex(200, OBJ), anon=_js_caught(), nonexistent=_js_caught())
    assert v["verdict"] == "lead"
    assert "anonymous" in v["reason"] and "implausible-id" in v["reason"]


def test_judge_still_confirms_a_real_cross_user_read_with_live_controls():
    """The other half. A gate that also kills the true positive is not a fix, it is a mute button."""
    v = bie.judge(_ex(200, OBJ), _ex(200, OBJ), anon=_ex(401, ""), nonexistent=_ex(404, ""))
    assert v["verdict"] == "confirmed", v


# ── half 2: judge_client_side_authz — the fall-through the naive fix misses ───
def test_client_side_authz_errored_anon_control_cannot_clear_a_resource_of_being_public():
    """BEFORE: confirmed. The dead anon has status 0, so `_s(anon) == 200` was already False and the
    PUBLIC rejection never fired — the row fell through to `confirmed` with the public question never
    asked. AFTER: lead."""
    v = bie.judge_client_side_authz(_ctl(), _ex(200, ADMIN_PAGE), anon=_js_caught(),
                                    shell=_ex(200, SHELL))
    assert v["verdict"] == "lead", v
    assert "anonymous" in v["reason"] and "PUBLIC" in v["reason"]


def test_client_side_authz_errored_shell_control_is_a_lead():
    """BEFORE: confirmed. `if shell is None` let the dead dict through, and the dead body ("") does not
    equal the persona's body, so the SPA-shell rejection could not fire either."""
    v = bie.judge_client_side_authz(_ctl(), _ex(200, ADMIN_PAGE), anon=_ex(401, ""),
                                    shell=_evaluate_raised())
    assert v["verdict"] == "lead", v
    assert "SPA-shell" in v["reason"] or "shell" in v["reason"]


def test_client_side_authz_still_confirms_with_live_controls():
    v = bie.judge_client_side_authz(_ctl(), _ex(200, ADMIN_PAGE), anon=_ex(401, ""), shell=_ex(200, SHELL))
    assert v["verdict"] == "confirmed", v


def test_client_side_authz_keeps_rejecting_the_genuinely_public_resource():
    """Negative control on the fix itself: a LIVE anon control that receives the same body must still
    reject, not become a lead. The new gate must sit AFTER the PUBLIC test, not in front of it."""
    v = bie.judge_client_side_authz(_ctl(), _ex(200, ADMIN_PAGE), anon=_ex(200, ADMIN_PAGE),
                                    shell=_ex(200, SHELL))
    assert v["verdict"] == "rejected" and "PUBLIC" in v["reason"]


# ── half 2: judge_param_swap ──────────────────────────────────────────────────
def test_param_swap_errored_anon_control_is_a_lead_not_a_confirmation():
    """BEFORE: confirmed, for the identical fall-through reason."""
    v = bie.judge_param_swap(_ex(200, MINE), _ex(200, THEIRS), _ex(200, THEIRS), anon=_js_caught())
    assert v["verdict"] == "lead", v
    assert "anonymous" in v["reason"] and "PUBLIC" in v["reason"]


def test_param_swap_still_confirms_with_a_live_anon_control():
    v = bie.judge_param_swap(_ex(200, MINE), _ex(200, THEIRS), _ex(200, THEIRS), anon=_ex(401, ""))
    assert v["verdict"] == "confirmed", v


def test_param_swap_keeps_rejecting_public_content_with_a_live_control():
    v = bie.judge_param_swap(_ex(200, MINE), _ex(200, THEIRS), _ex(200, THEIRS), anon=_ex(200, THEIRS))
    assert v["verdict"] == "rejected" and "PUBLIC" in v["reason"]


def test_param_swap_keeps_rejecting_the_secure_server_before_asking_about_controls():
    """Ordering guard: the SECURE case (server ignored the client-supplied parameter) must still reject
    even when the anon control is dead — a dead control must never convert a proven-secure result into
    a lead, which would manufacture noise on a hardened target."""
    v = bie.judge_param_swap(_ex(200, MINE), _ex(200, THEIRS), _ex(200, MINE), anon=_js_caught())
    assert v["verdict"] == "rejected" and "SECURE" in v["reason"]


# ── generalisation: an unseen shape of the same class ─────────────────────────
def test_the_gate_generalises_to_an_unseen_stack_and_shape():
    """Same class (dead negative control), different everything else: a GraphQL-ish POST-shaped body on
    a username-keyed route, a 503 from an upstream proxy on the anon leg rather than a browser fetch
    error, and a control dict that carries a status but an `error` marker. If the fix only recognises
    `status == 0` on a `/rest/basket/{id}` JSON body it is a signature, not a capability."""
    gql_owner = '{"data":{"me":{"handle":"alice","email":"alice@t","token":"eyJhbGciOi"}}}'
    url = "http://shop.internal/graphql/user/alice/profile"
    owner = bie.exchange(url, 200, gql_owner)
    attacker = bie.exchange(url, 200, gql_owner)
    # anon leg: the request reached a proxy but the body never came back; the wrapper marked it errored
    anon_dead = bie.exchange(url, 200, "") | {"error": "net::ERR_INCOMPLETE_CHUNKED_ENCODING"}
    v = bie.judge(owner, attacker, anon=anon_dead, nonexistent=bie.exchange(url, 404, ""))
    assert v["verdict"] == "lead", v
    # and the same unseen shape with a control that genuinely ran still confirms
    v2 = bie.judge(owner, attacker, anon=bie.exchange(url, 302, ""),
                   nonexistent=bie.exchange(url, 404, ""))
    assert v2["verdict"] == "confirmed", v2

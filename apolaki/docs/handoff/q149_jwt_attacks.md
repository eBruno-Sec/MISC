# Q-149 -- the JWT attack family (`agent/jwt_attacks.py`)

LANE D (Builder). Every claim below is MEASURED (command + real output) or marked UNVERIFIED.

Landed: `bd7021b` (handoff), `57dfc31` (slice 1), `3d740ec` (slice 2).

## Scope, measured before writing anything

Burp's published catalog lists six JWT attack checks plus two disclosure checks. MEASURED against
`agent/jwt_tool.py` (335 lines, read in full):

| Burp check | present in `jwt_tool.py` before Q-149 | action |
|---|---|---|
| JWT signature not verified | NO | SHIPPED |
| JWT none algorithm supported | PARTIAL -- `forge_none()` builds ONE variant (`alg:"none"`, empty signature) | EXTENDED to 12 |
| JWT self-signed JWK header supported | NO | SHIPPED (+ its `x5c` sibling) |
| JWT weak HMAC secret | PARTIAL -- `crack_secret()` over 21 words, unbounded, and a MISS reports nothing | EXTENDED + honesty hole closed |
| JWT arbitrary jku header supported | NO | SHIPPED, OOB-gated |
| JWT arbitrary x5u header supported | NO | SHIPPED, OOB-gated |
| Json Web Key Set disclosed | already `jwt_tool.jwks_candidate_urls()` + `first_rsa_pem()` | SKIPPED, already covered |
| JWT private key disclosed | not in the tree | REFUSED -- see below |

Already in `jwt_tool.py` and deliberately NOT duplicated: algorithm confusion RS->HS
(`forge_key_confusion`, `pubkey_secret_variants`, `key_confusion_finding`), the `kid` injection
lead, expired-`exp` replay. `jwt_attacks.py` IMPORTS `jwt_tool` for `b64url_encode`,
`b64url_decode`, `decode_jwt`, `sign_hs`, `verify_hs`, `forge_hs`, `escalate_payload` and
`candidate_secrets` rather than restating them. It also round-trips its own forgeries back through
`jwt_tool.first_rsa_pem` and `jwt_tool.x5c_to_pem`, so the documents it builds are proven readable
by the tree's own consumers rather than only by itself.

## The oracle problem, which is what actually makes this lane hard

A JWT check is an ACCEPTANCE test: forge, send, ask "did the server honour it". Three response
shapes collapse into one if you look only at the status code:

  * a 200 because the forgery worked
  * a 200 because the endpoint never required authentication in the first place
  * a 200 that IS the login page, rendered at 200 by a SPA shell

### DEFECT FOUND IN THE LIVE PATH -- not mine to fix, the ticket forbids touching `tools.py`

`agent/tools.py:5282-5298`, inside `_run_jwt`:

```python
for label, forged in (("alg:none", res.get("forged_none")),
                      ("cracked-secret admin", res.get("forged_admin"))):
    if not forged:
        continue
    r = await self._http(url, headers={hname: wrap(forged)}, capture=True)
    if 200 <= r.get("status", 0) < 300:
        findings.append({"title": f"Forged JWT accepted ({label})", "severity": "critical", ...})
```

There is NO positive control and NO negative control. Any 2xx on the probed URL emits a CRITICAL
`Forged JWT accepted`. Pointed at an unauthenticated endpoint it fires on every target in the
world. The RS->HS block thirty lines below it (`tools.py:5312`) gets this RIGHT -- it requires a
signature-tampered token to be REJECTED before it will believe an acceptance -- so the correct
pattern was already in the file, applied to one of the three send sites.
`jwt_attacks.classify_acceptance()` is that pattern extracted, given a third leg, and made
unit-testable against responses written by hand. The wiring patch below replaces the naive block.

### The three-leg control set

`Controls(authenticated, unauthenticated, tampered)`, all three captured from the SAME endpoint:

  * `authenticated` -- POSITIVE control, the genuine token. What success looks like.
  * `unauthenticated` -- NEGATIVE control, no token at all. What failure looks like.
  * `tampered` -- the genuine token with one signature byte flipped
    (`jwt_tool.tamper_signature`). A sound verifier MUST reject it.

`tampered` does double duty, and that is the design's one real idea:

  * it is the SANITY GATE for every other check. If a mangled signature is honoured, an
    "acceptance" of an alg:none / JWK / jku forgery proves nothing about alg:none, JWK or jku --
    the server would have honoured a random string. `analyze_forgery()` returns `not_tested` there
    and names the real defect.
  * when it is honoured while the no-token control is REFUSED, that IS Burp's
    `jwt_signature_not_verified`, confirmed by a differential rather than inferred from a status.

Without all three legs the verdict is `not_tested`. **Never `not_vulnerable`.** `rejected` is a
statement about ONE probe and is never rendered as a finding; `finding_for()` returns `None` for
anything that is not `confirmed`, and `coverage_rows()` exists so a not-tested check is visible in
the report instead of being indistinguishable from a clean one.

### How a response is compared

Not by equality (a real authenticated page carries a CSRF token, a request id and a timestamp, so
two captures of the SAME page are never byte-equal) and not by status alone. Two signals vote, and
each votes ONLY when it can discriminate:

  * **status** discriminates iff the two controls' statuses differ.
  * **body** discriminates iff the two controls' bodies differ -- Jaccard over alphabetic word
    tokens, with hex runs then digit runs erased so per-request nonces cannot make one page look
    unlike itself.

A signal that cannot discriminate stays silent, which is how a bodiless 204/401 API is classified
on status alone and a two-200 SPA on body alone. If any discriminating signal returns UNKNOWN, or
the two contradict, the verdict is `not_tested`. HTTP 5xx and status 0 are `not_tested`
UNCONDITIONALLY, before scoring runs.

Four false positives, one negative-control test each:

| # | the case | what a status check reports | what this reports |
|---|---|---|---|
| 1 | the endpoint is public (controls indistinguishable) | CRITICAL on every target | `not_tested`, "this endpoint does not gate on the token" |
| 2 | the login page rendered at HTTP 200 | CRITICAL | `rejected` -- body outvotes status |
| 3 | the verifier crashed (HTTP 500 + stack trace) | nothing, or CRITICAL if 5xx were misread | `not_tested`, "a crashed verifier is neither" |
| 4 | a WAF block at 200 matching neither control | CRITICAL | `not_tested`, "a third shape is inconclusive" |

## Checks shipped

**1. `jwt_signature_not_verified`** (CWE-347, critical), TWO shapes that fail independently:

  * `signature_byte_flipped` -- the `tampered` control leg (`jwt_tool.tamper_signature`). Claims
    untouched, one signature byte wrong. Catches a verifier that never looks at the signature.
  * `payload_rewritten_signature_kept` -- `forge_payload_tamper()`. A REAL signature, just not over
    these claims. Catches a verifier that checks the signature's SHAPE, or verifies it against a
    stale signing input, or reads the claims from an unverified copy -- all of which PASS shape one.
    This shape needs no tampered leg: a rewritten payload accepted while a no-token request is
    refused is already the whole differential.

CAUGHT DURING THE BUILD: `forge_payload_tamper()` initially built a probe no analyser could
consume. Routing it through `analyze_forgery()` would have been wrong, because that function GATES
on the signature oracle being SOUND and the premise of this check is that it is not.
`analyze_signature_verification(controls, payload_tampered=...)` is the correct consumer.
CONTROLS: positive = either shape honoured while no-token refused, CONFIRMED. Negative = both
refused -> `rejected`, `finding_for` returns None. Third = honoured AND no-token honoured (a public
endpoint) -> `not_tested`, because that is not a signature defect.

**2. `jwt_none_algorithm_supported`** (CWE-347, critical). 12 variants: 4 casings
(`none`/`None`/`NONE`/`nOnE`) x 3 signature shapes (empty / no third segment / original signature
retained). MEASURED: `jwt_tool.forge_none()` emits exactly one of these. The extension is not
decoration -- a library that blocklists the literal `"none"` with a case-sensitive compare is
bypassed by `"None"`, which `jwt_tool` never sends; one that only rejects an empty signature is
bypassed by the retained-signature shape.
CONTROLS: positive = accepted forgery under a SOUND signature oracle. Negative = refused -> no
finding. Third = accepted forgery under a BROKEN verifier -> `not_tested`, not attributed.

**3. `jwt_self_signed_jwk_header_supported`** (CWE-347, critical), two shapes:
`jwk_embedded` and `x5c_embedded`. A verifier can reject `jwk` and still trust `x5c`, so they are
separate probes. `kid` is the RFC 7638 thumbprint of the generated key, so the token header and any
served JWKS agree by construction. Certificate validity is a PINNED LITERAL (2020-01-01 ..
2035-01-01), not a clock, so a forged certificate is reproducible across processes.
GROUND TRUTH is not "the token has three segments": the test reconstructs the public key through
`jwt_tool.first_rsa_pem` / `jwt_tool.x5c_to_pem` and VERIFIES the RS256 signature.

**4. `jwt_weak_hmac_secret`** (CWE-326, high). OFFLINE and bounded: `MAX_CRACK_WORDS = 5000` and a
10 s wall-clock budget with an INJECTABLE clock so the budget itself is testable without sleeping.
Wordlist = `jwt_tool.candidate_secrets` (common secrets + words derived from the token's own
`iss`/`aud`) then `wordlists.get_words("passwords-common")`, de-duplicated.
THE HONESTY HOLE THIS CLOSES: `jwt_tool.crack_secret()` returns `None` on a miss and `analyze()`
then emits nothing, so "21 words tried, none worked" is indistinguishable in the report from "this
token was never examined". Here a miss is `not_tested`, carries `tried` and `exhausted`, and says
in words that a bounded dictionary miss is NOT evidence of a strong secret.
`forge_with_secret()` is the impact half: a token that genuinely verifies under the recovered
secret.

**5/6. `jwt_arbitrary_jku_header_supported` / `..._x5u_...`** (CWE-347, critical) plus
`jwt_jku_url_fetched` / `jwt_x5u_url_fetched` (CWE-918, medium). Builders ship the token AND the
side-channel document that must be served at the URL (a JWKS for `jku`, a PEM certificate for
`x5u`), with `requires_oob=True`. `analyze_remote_key_header()` is a ladder that refuses to
conflate two different facts, exactly as `code_injection.py` refuses to name a language off shared
arithmetic:

| observation | verdict |
|---|---|
| no reachable collaborator | `not_tested` -- "there is no in-band oracle for it, so this check did not run" |
| correlated callback AND acceptance | CONFIRMED `jwt_arbitrary_jku_header_supported`, critical |
| correlated callback, no acceptance | CONFIRMED `jwt_jku_url_fetched`, medium. The fetch is proven; TRUST IS NOT. Never upgraded. |
| acceptance, NO callback | `not_tested` -- a contradiction. If the server never fetched our key it cannot have verified with it. |
| neither | `rejected`, with the reason stating that a missing callback inside the poll window is not proof of refusal |

`correlated_interactions()` re-checks the OOB token against each interaction's path/host, because a
collaborator shared across a mission holds callbacks from every probe and confirming a jku forgery
on someone else's callback would be a fabricated finding.

## Checks refused, and why that is a result

**`JWT private key disclosed` -- NOT SHIPPED.** It is a passive content check (a PEM private key or
a JWK with a `d` member in a response body), not a JWT forgery check. It belongs in the passive
disclosure engine, not here, and another lane is landing `agent/passive_disclosure.py` this cycle
which is where it should go. Shipping a second, JWT-flavoured PEM scanner would put two producers
of the same finding in the tree. RECOMMENDATION: route it to that lane.

**No in-band oracle was invented for `jku`/`x5u`.** With `oob_available=False` the verdict is
`not_tested` and no probe should be sent at all. This is the honest ceiling and it is the verdict
that will actually fire off-lab today -- see the open item below.

## KNOWN OPEN ITEM (not mine to fix, flagged as instructed)

`agent/collaborator.py:base()` reads `BBH_OOB_BASE`, which defaults to a Docker-internal hostname.
`collaborator.reachable_from(target)` correctly returns **False for every external target** in that
configuration (an in-network collaborator is reachable only by an in-network target). So `jku` and
`x5u` are structurally `not_tested` against anything outside the compose network until an operator
publishes a real public base URL or a wildcard `BBH_OOB_DOMAIN`. That is the right behaviour --
`reachable_from` exists precisely to stop a false-capability claim -- but it means shipping these
two checks buys nothing off-lab until the OOB base is fixed. **`jwt_attacks.py` does not import
`collaborator`** (it would make a pure module stateful and env-dependent); the caller passes
`oob_available` and `oob_interactions` in.

## Wiring patch for the Coordinator

`jwt_attacks.py` is a pure module with NO caller today. Two patches are required.

### (a) `agent/tests/test_silent_failure_invariant.py` -- the module counter

MEASURED: `assert len(trees) == 181` now fails with `185 == 181` because four lanes each added a
production module this cycle (`code_injection.py`, `dom_sinks.py`, `passive_disclosure.py`,
`jwt_attacks.py`). **`jwt_attacks.py` contributes +1 to that count and ZERO to every cap** -- it
contains no `except` handler at all, which `test_jwt_attacks.py` asserts at the AST level as a
ratchet on itself. `counts["optional"] <= 387` and `counts["control-plane"] <= 78` both still pass.
Bump the equality by one per landed module; do not touch the caps for this lane.

### (b) `agent/tools.py::_run_jwt` -- replace the uncontrolled acceptance block

Replace `tools.py:5282-5298` (the `for label, forged in (...)` loop shown above) with:

```python
            import jwt_attacks as ja

            async def _resp(tok):
                """One captured response as a jwt_attacks.Response. status 0 == transport failure,
                which _http already reports honestly and jwt_attacks treats as `not_tested`."""
                r = await self._http(url, headers=({hname: wrap(tok)} if tok else {}),
                                     capture=True)
                return ja.Response(r.get("status", 0), r.get("body", "") or "")

            # THE THREE LEGS. Without all three there is no oracle, and the correct output is
            # "not tested" -- never "not vulnerable", never a 2xx read as an acceptance.
            ctrl = ja.Controls(authenticated=await _resp(token),
                               unauthenticated=await _resp(""),
                               tampered=await _resp(jt.tamper_signature(token)))

            # `signature_not_verified` takes the payload-rewrite response DIRECTLY -- it must NOT
            # go through analyze_forgery, which gates on the signature oracle being SOUND.
            rewritten = ja.forge_payload_tamper(token)
            verdicts = [ja.analyze_signature_verification(
                ctrl, payload_tampered=(await _resp(rewritten.token)) if rewritten else None)]

            for probe in ja.forge_none_variants(token, max_variants=6):
                verdicts.append(ja.analyze_forgery(probe.check, ctrl, await _resp(probe.token),
                                                   shape=probe.shape, payload=probe.token))

            crack = ja.crack_hmac_secret(token, extra_secrets_or_None)
            verdicts.append(crack)
            if crack["verdict"] == ja.VERDICT_CONFIRMED:
                resigned = ja.forge_with_secret(token, crack["secret"])
                if resigned is not None:
                    verdicts.append(ja.analyze_forgery(
                        resigned.check, ctrl, await _resp(resigned.token),
                        shape=resigned.shape, payload=resigned.token))

            key = ja.generate_key()
            for build in (ja.forge_self_signed_jwk, ja.forge_self_signed_x5c):
                probe = build(token, key)
                if probe is None:
                    continue
                verdicts.append(ja.analyze_forgery(probe.check, ctrl, await _resp(probe.token),
                                                   shape=probe.shape, payload=probe.token))

            findings += [f for f in (ja.finding_for(v, url) for v in verdicts) if f]
            self.recon.setdefault("jwt_coverage", []).extend(ja.coverage_rows(verdicts))
```

Notes for whoever applies it:

  * `extra_secrets_or_None` is `inp.get("extra_secrets")`; pass it as the `extra` argument of
    `ja.hmac_wordlist(token, extra=...)` if a custom list is wanted, otherwise omit and let
    `crack_hmac_secret` build the bounded default.
  * `jt.tamper_signature` is the existing `jwt_tool` helper; keep the `import jwt_tool as jt` that
    is already at the top of `_run_jwt`.
  * `crack_hmac_secret` REPLACES the `res["cracked_secret"]` path only for the acceptance test.
    `jt.analyze()` still runs and still emits its own weak-secret finding; if both are kept the
    report will carry two rows for one fact, so prefer dropping the `analyze()` weak-secret finding
    or keeping the `jwt_attacks` one. UNVERIFIED which the Coordinator prefers -- flagging, not
    deciding.
  * `self.recon["jwt_coverage"]` is where the `not_tested` rows land so the report can show what
    ran and could not conclude. Nothing in the tree reads that key yet.

### (c) `jku` / `x5u` wiring -- ONLY when OOB is genuinely reachable

```python
            import collaborator
            if collaborator.enabled() and collaborator.reachable_from(url):
                oob = collaborator.new_token()
                collaborator.register(oob)
                for build, name in ((ja.forge_jku, "jwks.json"), (ja.forge_x5u, "cert.pem")):
                    probe_url = "%s/%s" % (collaborator.probe_url(oob).rstrip("/"), name)
                    probe = build(token, probe_url, key)
                    if probe is None:
                        continue
                    # probe.side_channel MUST be served at probe.side_channel_url before sending.
                    # The agent's /oob catch-all currently RECORDS but does not SERVE a body, so
                    # this is BLOCKED until it can return probe.side_channel for that path.
                    resp = await _resp(probe.token)
                    verdicts.append(ja.analyze_remote_key_header(
                        probe.check, ctrl, resp, oob_available=True,
                        oob_interactions=collaborator.hits(oob), oob_token=oob,
                        shape=probe.shape, payload=probe.token))
            else:
                verdicts.append(ja.analyze_remote_key_header(
                    ja.CHECK_ARBITRARY_JKU, ctrl, ja.Response(0, ""),
                    oob_available=False, oob_interactions=[]))
```

**BLOCKER, stated plainly so nobody wires it half-way.** Confirming `jku`/`x5u` needs the
collaborator to SERVE the key document, not merely record the hit. `collaborator.record()` logs an
inbound request; `main.py`'s `/oob` catch-all returns its own response, not a caller-supplied body.
Until an endpoint can return `probe.side_channel` for `probe.side_channel_url`, the only reachable
verdict is `jwt_jku_url_fetched` (the fetch is proven, trust is not) -- which is still a real
CWE-918 finding and is exactly what the ladder is built to report. The full-forgery branch is
correct code with no way to fire yet. That is a RESULT, recorded here rather than papered over.

## Measurements

```
$ docker run --rm --network apolaki_default -v ".../agent:/app" -w /app apolaki-agent \
    python -m pytest tests/test_jwt_attacks.py -p no:cacheprovider -q -rfE
..........................................................               [100%]
58 passed
```

Adjacent JWT tests, unaffected:

```
$ ... python -m pytest tests/test_jwt_key_confusion.py tests/test_planner_jwt_gate.py \
      tests/test_jwt_attacks.py -p no:cacheprovider -q
63 passed
```

Repository gates, MEASURED with this module present:

  * `tests/test_silent_failure_invariant.py` -- 11 of 12 pass. The one failure is the module
    counter (`assert len(trees) == 181` -> `185 == 181`), see patch (a). **Both handler caps still
    pass**, because this module contributes zero handlers.
  * `tests/test_deadcode_gate.py` -- fails, and MEASURED NOT BECAUSE OF THIS MODULE:
    `deadcode_gate.scan()` reports 4 unused functions and **0 of them are in `jwt_attacks`**
    (`python -c "import deadcode_gate as dg; [x for x in dg.scan()['unused'] if 'jwt_attacks' in
    str(x)]"` -> `[]`). Every public function in this module is referenced by
    `tests/test_jwt_attacks.py`, so it is not an unreferenced island; it is an UNWIRED one, which
    patch (b) resolves.
  * `tests/test_island_soundness.py::test_external_surface_cannot_emit_a_finding_on_any_path` --
    fails on `tools.ToolRegistry._run_external_surface`, a function this lane never touched.
    Belongs to whoever is editing `tools.py` this cycle.

Mutation run (`scratchpad/q149_mutate.py`, plants one mutant, runs the suite, restores and
verifies the sha256):

```
BASELINE GREEN
... 25 mutants ...
25/25 killed, survivors: 0  (restore verified, sha256 unchanged)
```

MUTANT S2-9 CAUGHT ONE OF MY OWN TESTS BEING VACUOUS, which is the point of running them.
`test_the_certificate_is_clock_free...` originally asserted only that two calls in one process
produce the same PEM. That stays true with `datetime.now()` as the default, because a module-level
default is evaluated ONCE at import -- the test could not fail. It now asserts against the literal
pinned instant (`not_valid_before_utc == 2020-01-01Z`), and the mutant dies.

The 25 mutants, all killed:

| id | mutant | test that kills it |
|---|---|---|
| S1-1 | the body UNKNOWN vote abstains instead of forcing `not_tested` | `test_fp4_a_third_shape_...` |
| S1-2 | 5xx is scored instead of refused | `test_fp3_a_crashed_verifier_...` |
| S1-3 | `controls_usable` stops checking the controls differ | `test_fp1_an_endpoint_that_answers_identically_...` |
| S1-4 | `analyze_forgery` drops the signature-oracle gate | `test_an_accepted_forgery_is_not_attributed_...` |
| S1-5 | a dictionary miss is reported as a rejection | `test_weak_hmac_negative_a_strong_secret_is_NOT_TESTED_not_clean` |
| S1-6 | the body normaliser stops erasing digits and hex | `test_per_request_nonces_do_not_make_a_page_look_unlike_itself` |
| S1-7 | the wall-clock budget is never checked | `test_the_wall_clock_budget_is_a_real_bound...` |
| S1-8 | `finding_for` builds a finding from any verdict | `test_a_finding_is_never_built_from_a_non_confirmed_verdict` |
| S1-9 | alg:none collapses to jwt_tool's single lowercase casing | `test_none_variants_cover_the_casings_jwt_tool_does_not` |
| S1-10 | a MISSING tampered leg is called SOUND | `test_signature_not_verified_without_a_tampered_leg_is_not_tested` |
| S1-11 | the word-count bound is ignored | `test_the_wordlist_budget_is_a_real_bound` |
| S1-12 | a confirmation with no evidence is emitted | `test_a_confirmation_with_no_evidence_is_refused` |
| S1-13 | the payload-rewrite probe is ignored entirely | `test_the_payload_rewrite_shape_confirms_where_the_byte_flip_does_not` |
| S1-14 | the payload-rewrite branch confirms regardless of the acceptance verdict | `test_the_payload_rewrite_shape_reports_nothing_against_a_sound_verifier` |
| S2-1 | the forged header carries the SERVER's own kid forward | `test_the_forged_header_does_not_carry_the_servers_own_kid_forward` |
| S2-2 | a fetch is UPGRADED to a forgery | `test_jku_fetched_but_refused_is_reported_as_a_FETCH_not_a_forgery` |
| S2-3 | `correlated_interactions` ignores the token | `test_another_probes_callback_cannot_confirm_this_one` |
| S2-4 | the missing-collaborator refusal is dropped | `test_without_a_collaborator_jku_is_NOT_TESTED_and_says_so` |
| S2-5 | accepted-without-a-fetch is confirmed | `test_jku_accepted_with_no_fetch_is_a_contradiction...` |
| S2-6 | the kid stops being the RFC 7638 thumbprint | `test_the_kid_is_the_rfc7638_thumbprint...` |
| S2-7 | the served JWKS omits the kid the header names | `test_the_jku_token_ships_the_jwks_it_needs...` |
| S2-8 | RS256 signs with the wrong digest | `test_the_self_signed_jwk_token_actually_verifies...` |
| S2-9 | certificate validity becomes clock-derived | `test_the_certificate_is_clock_free...` (rewritten) |
| S2-10 | an unsupported algorithm silently signs with RS256 | `test_an_unsupported_signing_algorithm_is_a_value_not_an_exception` |
| S2-11 | `forge_jku` accepts an empty URL | `test_the_asymmetric_builders_refuse_a_non_jwt` |

## House-rule compliance

  * NO NEW SILENT-FAILURE HANDLERS: `jwt_attacks.py` contains **zero** `except` handlers, asserted
    at AST level by `test_the_module_contains_no_exception_handler` as a ratchet. Every place one
    would have gone is validation instead -- `jwt_tool.decode_jwt()` returning `None`,
    `alg not in _HS_ALGS`, `_RS_ALGS.get(alg)` returning a falsy name.
  * OFFLINE: `test_the_module_imports_no_http_client_at_all` AST-asserts that none of
    `requests / httpx / aiohttp / socket / urllib / http / websockets / asyncio / subprocess` is
    imported. The weak-HMAC crack cannot become an online attack by accident.
  * NO REAL-LOOKING CREDENTIALS: every fixture key is generated in-process or is the literal
    `"not-a-real-secret-q149"` / `"changeme"`.
  * FILES TOUCHED: `agent/jwt_attacks.py`, `agent/tests/test_jwt_attacks.py`,
    `docs/handoff/q149_jwt_attacks.md`. `tools.py` and `jwt_tool.py` were READ ONLY.

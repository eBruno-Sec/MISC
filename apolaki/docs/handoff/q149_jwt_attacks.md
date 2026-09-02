# Q-149 -- the JWT attack family (`agent/jwt_attacks.py`)

LANE D (Builder). Status written AS I GO. If this lane is killed, this file is the contribution.

## Scope, measured before writing anything

Burp's published catalog lists six JWT attack checks plus two disclosure checks. MEASURED against
`agent/jwt_tool.py` (335 lines, read in full):

| Burp check | present in `jwt_tool.py` before Q-149 | verdict |
|---|---|---|
| JWT signature not verified | NO | ship |
| JWT none algorithm supported | PARTIAL -- `forge_none()` builds ONE variant (`alg:"none"`, trailing dot) | extend |
| JWT self-signed JWK header supported | NO | ship |
| JWT weak HMAC secret | PARTIAL -- `crack_secret()` over a 21-word `COMMON_SECRETS` list, unbounded, and a MISS is reported as nothing | extend + fix the honesty hole |
| JWT arbitrary jku header supported | NO | ship builder, OOB-gated analyser |
| JWT arbitrary x5u header supported | NO | ship builder, OOB-gated analyser |
| Json Web Key Set disclosed | already `jwt_tool.jwks_candidate_urls()` + `first_rsa_pem()` | SKIP, already covered |
| JWT private key disclosed | not shipped | SKIP -- see "refused" below |

Also already in `jwt_tool.py` and NOT duplicated here: algorithm confusion RS->HS
(`forge_key_confusion`, `pubkey_secret_variants`, `key_confusion_finding`), `kid` injection (a lead
in `analyze()`), expired-`exp` replay. `jwt_attacks.py` IMPORTS `jwt_tool` for `b64url_encode`,
`b64url_decode`, `sign_hs`, `verify_hs`, `decode_jwt`, `tamper_signature` and
`candidate_secrets` rather than restating them.

## The oracle problem, which is what actually makes this lane hard

A JWT check is an ACCEPTANCE test: forge, send, ask "did the server honour it". Three response
shapes collapse into one if you look only at the status code:

  * a 200 because the forgery worked
  * a 200 because the endpoint was never authenticated in the first place
  * a 200 that is the login page, rendered at 200 by a SPA shell

**DEFECT FOUND IN THE LIVE PATH (not mine to fix, ticket forbids touching `tools.py`).**
`agent/tools.py:5290` in `_run_jwt`:

```python
r = await self._http(url, headers={hname: wrap(forged)}, capture=True)
if 200 <= r.get("status", 0) < 300:
    findings.append({"title": f"Forged JWT accepted ({label})", "severity": "critical", ...})
```

There is NO positive control and NO negative control. Any 2xx on the probed URL emits a CRITICAL
`Forged JWT accepted`. Point that at an unauthenticated endpoint and it fires on every target in
the world. The RS->HS block 30 lines below it gets this RIGHT (it requires a tampered-signature
token to be REJECTED first), so the correct pattern is already in the file, applied to one of the
three send sites. `jwt_attacks.classify_acceptance()` is that pattern extracted, hardened with a
third leg, and made unit-testable. Wiring patch below replaces the naive block.

### The three-leg control set

`Controls(authenticated, unauthenticated, tampered)`, all three captured from the SAME endpoint:

  * `authenticated` -- POSITIVE control, the genuine token. Establishes what success looks like.
  * `unauthenticated` -- NEGATIVE control, no token. Establishes what failure looks like.
  * `tampered` -- the genuine token with one signature byte flipped (`jwt_tool.tamper_signature`).
    A sound verifier MUST reject it.

`tampered` does double duty. It is the sanity gate for every other check (if a bad signature is
honoured, an "acceptance" of a forgery proves nothing), AND when it is honoured while
`unauthenticated` is rejected, that IS Burp's `jwt_signature_not_verified` -- confirmed, not
inferred.

Without all three legs the verdict is `not_tested`. **Never `not_vulnerable`.** There is no
"rejected, therefore safe" finding emitted anywhere in this module.

## Checks shipped

(filled in per slice, below)

## Checks refused

(filled in per slice, below)

## Wiring patch for the Coordinator

(exact diff, below)

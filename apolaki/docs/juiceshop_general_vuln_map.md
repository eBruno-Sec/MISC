# Juice Shop → General-TTP Vulnerability Map (2026-08-06)

**Question (Erwin):** of Juice Shop's 113 "challenges", which are *actual vulnerabilities* that belong in
Apolaki's **general** techniques / workflow / TTP — versus lab-specific scavenger-hunt trivia — and does the
general checklist already cover them?

**Method:** pulled the authoritative challenge manifest live from `GET /api/Challenges` (category / key /
difficulty / description for all 113) and cross-referenced against the Apolaki technique registry
(`techniques.py`, 65 techniques across ~37 vuln classes).

## Headline

- **~58 of 113 are genuine general vulnerability classes** — Erwin's "50+" is correct.
- **Apolaki's registry already has a technique for essentially every one of those classes.** The checklist
  is complete *at the class level*. The gap is **not the techniques** — it is **reach + confirmation**:
  - **~⅔ of the general vulns live behind authentication** (basket/order/review IDOR, mass-assignment,
    business-logic, JWT-for-a-user, stored XSS in authed views). In the live general run the **auth artery
    established zero personas**, so that entire half was never tested. **Fixing auth is the unlock.**
  - Unauth pass is **leads-by-design** (confirmation needs the authed/exploitation pass).
  - **Reliability**: the heavy run DoS'd the single-process lab; the paced run hung. Fragile execution caps
    the ceiling regardless of technique quality.

## The general vuln classes (belong in general TTP) — and Apolaki coverage

| Class | Juice Shop challenges (examples) | Auth needed? | Apolaki technique class |
|---|---|---|---|
| SQL injection | loginAdmin, dbSchema, loginBender/Jim, unionSql, ephemeralAccountant, oauthUserPassword, christmasSpecial | no (login) | `sql_injection` ✅ |
| NoSQL injection | noSqlReviews, noSqlOrders, noSqlCommand | mixed | `nosql_injection` ✅ |
| SSTI / RCE | ssti, rce, rceOccupy | yes | `template_injection`, `command_injection`, `deserialization` ✅ |
| XSS (reflected/stored/DOM/CSP) | local/reflected/restful/persistedUser/Feedback/username/httpHeader/video Xss | mixed | `xss` ×3, `client_side`, `css_injection` ✅ |
| IDOR / BOLA / broken object authz | basketAccess, basketManipulate, forgedFeedback, forgedReview, dataExport, changeProduct, feedback | **yes** | `access_control` ×5 ✅ |
| Forced browse / admin | adminSection, ghostLogin | partial | `access_control` ✅ |
| CSRF | csrf, changePasswordBender | yes | `csrf` ✅ |
| SSRF | ssrf | yes | `ssrf` ✅ |
| XXE | xxeFileDisclosure | yes (B2B) | `xxe` ✅ |
| Open redirect | redirect, redirectCryptoCurrency | no | `redirect` ✅ |
| JWT (alg:none / key confusion) | jwtUnsigned, jwtForged | no | `broken_auth` / `crypto_authz` ✅ |
| Path traversal / LFI / file write | nullByte, lfr, fileWrite | no | `path_traversal` ×2 ✅ |
| Sensitive file / secret exposure | directoryListing, forgottenDev/SalesBackup, retrieveBlueprint, exposedCredentials, leakedApiKey | no | `sensitive_exposure` ×3 ✅ |
| Excessive data exposure (field-level) | passwordHashLeak | yes | **`field_authz` (Codex #9, new)** ✅ |
| Vulnerable component (known CVE) | knownVulnerableComponent | no | `vuln_component` ✅ |
| Security misconfig / error handling | errorHandling, deprecatedInterface, svgInjection | no | `misconfiguration` ✅ |
| Observability exposure | exposedMetrics, accessLogDisclosure | no | `sensitive_exposure` (content discovery) ✅ |
| Business logic | negativeOrder, freeDeluxe, zeroStars | yes | `business_logic` ×2 ✅ |
| Weak crypto | weirdCrypto | no | `crypto_authz` / hash-id ✅ |
| LLM prompt injection | chatbotPromptInjection/Greedy, systemPromptExtraction | env-gated (needs local LLM) | `llm_prompt_injection`, `llm_output_handling` ✅ |

### Real class-level GAPS (re-verified — smaller than first claimed)
- **Mass assignment** (`registerAdmin`): **NOT a gap** — `mass_assignment` (CWE-915) already exists in the
  registry, mapped to "Admin Registration", with a `has_api` planner precondition. (Original claim corrected.)
- **File-upload restriction bypass** (`uploadType`, `uploadSize`): the `run_upload_test` engine already exists
  and runs in the probe sweep — it only lacked a first-class **catalog technique**. Added
  `unrestricted_file_upload` (CWE-434) + `has_file_upload` planner precondition. Now closed.
- Everything else already has a technique.

## The lab-specific / non-general ~55 (do NOT belong in general TTP)

- **Forgot-password via known security-answer (OSINT/social):** resetPassword Jim / Bender / Bjoern /
  BjoernOwasp / Morty / Uvogin (6) — require knowing the person's actual security answer.
- **"Log in with X's *original* credentials" (specific password / OSINT):** loginAmy, loginRapper,
  loginSupport (creds in a CI config), dlpPasswordSpraying — need a specific secret, not a scan finding.
- **Web3 / NFT / crypto puzzles:** web3Sandbox, web3Wallet, nftMint, nftUnlock, tokenSale, forgedCoupon,
  continueCode, premiumPaywall (~8).
- **Scavenger hunt / OSINT / forensic:** scoreBoard, privacyPolicy(+Proof), hiddenImage, geoStalking
  (Meta/Visual — EXIF), dlpPastebinDataLeak, easterEgg L1/L2, missingEncoding, typosquatting Npm/Angular,
  supplyChainAttack, csaf (~14) — "find the specific hidden thing / report a specific package".
- **DoS / anti-automation (policy-excluded by Apolaki):** captchaBypass, timingAttack, xxeDos, yamlBomb,
  noSqlCommand(sleep) (~5) — Apolaki refuses brute/DoS by rail.
- **UI / trivia:** closeNotifications, securityPolicy, weakPassword (credential-guessing, no-brute rail).

## Conclusion / next action

The experiment Erwin proposed answered itself: **the general checklist already covers the vuln classes** —
so the path to "general mode finds 50+" is **not** adding techniques, it is:
1. **Fix the auth artery** so it actually establishes a session on Juice Shop (SQLi-bypass admin OR
   auto-register) and re-crawls authenticated → unlocks the ~⅔ auth-gated general vulns. *(highest leverage)*
2. **Reliability**: pace the scan so it doesn't crash the single-process lab; fix the hang.
3. Add the two small class gaps (mass-assignment, file-upload-restriction).
4. Then re-measure *confirmed findings* (not the scoreboard) on a clean, authenticated, paced run.

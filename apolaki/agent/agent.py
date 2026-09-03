import asyncio
import json
import os
import re
import time
import uuid
from typing import AsyncGenerator

import db
import triage as triage_mod
from scope import ScopeEngine, PermissionLevel
from tools import ToolRegistry, TOOL_PERMISSIONS

APPROVAL_TIMEOUT = int(os.getenv("BBH_APPROVAL_TIMEOUT", "0"))  # 0 = wait forever


def _zap_configured() -> bool:
    """True when a ZAP daemon is configured (ZAP_ADDR set), so the deterministic
    planner schedules a real DAST pass in Full mode. Read fresh (env can change);
    best-effort so a missing/partial zap_client never breaks planning."""
    try:
        import zap_client
        return zap_client.configured()
    except Exception:
        return False

DEFAULT_OPENROUTER_MODEL = "meta-llama/llama-3.3-70b-instruct:free"
DEFAULT_OPENROUTER_BASE = "https://openrouter.ai/api/v1"
DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-4-6"


def resolve_ai_config() -> dict:
    """Resolve the effective AI provider/key/model/base_url.

    Precedence for every field: provider-specific var > generic AI_* alias >
    default. This keeps the original OPENROUTER_* / ANTHROPIC_* vars working while
    also accepting the generic AI_API_KEY / AI_MODEL / AI_BASE_URL format. Empty
    provider vars (e.g. OPENROUTER_API_KEY="" injected by compose) fall through to
    the generic alias, which is the fix for the empty-key 500. Read fresh each call
    so it reflects the current environment; the api_key is never logged."""
    provider = os.getenv("AI_PROVIDER", "openrouter").lower()
    g_key = os.getenv("AI_API_KEY", "").strip()
    g_model = os.getenv("AI_MODEL", "").strip()
    g_base = os.getenv("AI_BASE_URL", "").strip()
    if provider == "anthropic":
        key = os.getenv("ANTHROPIC_API_KEY", "").strip() or g_key
        model = os.getenv("ANTHROPIC_MODEL", "").strip() or g_model or DEFAULT_ANTHROPIC_MODEL
        base = g_base  # empty -> the anthropic SDK uses its own default endpoint
        key_var = "ANTHROPIC_API_KEY"
    else:
        provider = "openrouter"
        key = os.getenv("OPENROUTER_API_KEY", "").strip() or g_key
        model = os.getenv("OPENROUTER_MODEL", "").strip() or g_model or DEFAULT_OPENROUTER_MODEL
        base = g_base or DEFAULT_OPENROUTER_BASE
        key_var = "OPENROUTER_API_KEY"
    return {"provider": provider, "api_key": key, "model": model,
            "base_url": base, "key_var": key_var}


def ai_status() -> dict:
    """Secret-free view of the effective AI config for /config and the /engage
    preflight. Reports readiness and where the key came from, but never the key."""
    c = resolve_ai_config()
    ready = bool(c["api_key"])
    if ready:
        source = c["key_var"] if os.getenv(c["key_var"], "").strip() else "AI_API_KEY"
    else:
        source = ""
    hint = "" if ready else f"{c['key_var']} is missing — set it (or AI_API_KEY) with your {c['provider']} API key."
    return {"provider": c["provider"], "model": c["model"], "base_url": c["base_url"],
            "ready": ready, "key_var": c["key_var"], "key_source": source, "hint": hint}

# tool -> assessment phase (drives the phase status bar in the UI)
PHASE_OF = {
    "run_subfinder": "recon", "run_crtsh": "recon", "run_wayback": "recon", "run_dns": "recon",
    "run_asn": "recon", "run_github_recon": "recon",
    "run_httpx": "enum", "http_probe": "enum", "run_whatweb": "enum", "run_fingerprint": "enum",
    "run_katana": "enum", "fetch_openapi": "enum", "check_takeover": "enum",
    "run_graphql": "enum", "run_jwt": "enum", "run_xss": "probe", "run_dom_audit": "probe", "run_js_review": "enum",
    "run_csrf": "enum", "run_oauth": "enum",
    "run_nmap": "scan", "run_nmap_vuln": "scan", "run_nuclei": "scan", "run_zap": "scan",
    "run_content_discovery": "probe", "run_ffuf": "probe", "run_web_probes": "probe",
    "run_injection_probes": "probe", "run_bfla": "probe", "run_race": "probe",
    "run_ssrf": "probe", "run_deserialization": "probe", "run_exposure": "probe",
    "run_xxe": "probe", "run_sqli": "probe", "run_auth_sqli": "probe", "run_cmdi": "probe",
    "run_form_cmdi": "probe", "run_nosqli": "probe", "run_form_nosqli": "probe", "run_upload_test": "probe",
    "run_cache_poison": "probe", "run_llm_probe": "probe", "run_stored_xss": "probe",
    "run_param_mine": "scan", "run_anomaly_scan": "scan", "run_dalfox": "probe", "run_sqlmap": "probe",
    "generate_playbook": "guidance", "store_finding": "report",
}
PHASES = ["recon", "enum", "scan", "probe", "guidance", "report"]

# Tools whose confirmed, finding-shaped results should be auto-stored when no model
# is driving (deterministic / low_ai). These native probes only emit CONFIRMED
# vulns; without auto-store a deterministic scan would confirm and then drop them.
_AUTO_STORE_TOOLS = {
    "run_sqli", "run_auth_sqli", "run_form_cmdi", "run_nosqli", "run_nosqli_body", "run_form_nosqli", "run_upload_test",
    "run_cache_poison", "run_cache_deception", "run_client_checks", "run_css_injection", "run_waf_bypass", "run_sqli_structural", "run_session_token", "run_username_enum", "run_session_fixation", "run_default_creds", "run_ssh_audit", "run_ldap_enum", "run_smb_enum", "run_snmp_audit", "run_modbus_audit", "run_vnc_audit", "run_rsync_audit", "run_ntp_audit", "run_ipmi_audit", "run_rdp_audit", "run_path_sqli", "run_llm_probe", "run_cmdi", "run_ssrf", "run_xss", "run_form_xss", "run_xpath", "run_ldap", "run_ssi", "run_stored_xss", "run_dom_audit", "run_dom_trace", "run_rendered_forms", "run_encoded_cookie", "run_xxe", "run_deserialization",
    "run_injection_probes", "run_web_probes", "run_exposure", "run_bfla", "run_race",
    "run_nuclei", "run_zap", "check_takeover", "run_oauth", "run_jwt", "run_csrf",
    "run_dalfox", "run_sqlmap", "run_graphql", "run_js_review",
    "run_content_discovery", "run_ffuf", "run_nmap_vuln", "run_param_mine", "run_anomaly_scan",
    # investigative + exploitation tools (their confirmed findings must persist too)
    "run_dir_harvest", "confirm_idor", "run_metadata", "run_sourcemap", "test_numeric_abuse",
    # Q-050, and it is the SECOND HALF of giving run_hash_id a deterministic trigger. Dispatching it
    # without this line executes the engine and drops its lead on the floor -- reach with no effect,
    # which is the same defect as a step that dispatches into `ran: False`, one level over. MEASURED
    # while wiring it: the tool_call and tool_result events both appeared and `self.leads` stayed
    # empty, so a WSTG-CRYP-04 observation would never have reached the report.
    "run_hash_id",
    # Q-050, the SAME both-halves gap twice more, found by auditing the line above rather than by a
    # failure. The lane that wired these two spotted `run_ws_hijack` as it was killed and never
    # reached `run_mass_assign` at all. MEASURED at HEAD: `_AUTO_STORE_TOOLS` held 69 entries and
    # neither name was among them, while both engines BUILD a findings list and append
    # `self._attach_poc(...)` to it -- 4 findings-bearing lines each, against 0 for an engine that
    # genuinely returns none. `_auto_store` is the only store path (one guard site,
    # `if not result.error and tool_name in _AUTO_STORE_TOOLS`), so every one of those findings was
    # discarded at dispatch.
    #
    # `run_mass_assign` is the severe one and it is worth naming why. It CHANGES STATE, it is the
    # engine `asvs_model.py:179` declares verifiable and `wstg_catalog.py:110` rides WSTG-INPV-20 on,
    # and Q-050 had just given it a deterministic trigger. Without this line a mission sends the
    # write, confirms the privileged attribute persisted on a separate re-read, and reports CLEAN --
    # the false-clean shape, arriving through the second half of a fix whose first half shipped.
    "run_mass_assign", "run_ws_hijack",
    # Q-087: these four can be dispatched directly, not through a parent that forwards their findings.
    # Without membership here their tool_call/tool_result rows land while their candidate findings do
    # not, producing a false-clean mission. run_service_pack has both paths: _run_service_packs
    # forwards its internal calls, while graph-directed execution goes through _run_tool here.
    "run_fingerprint", "run_github_recon", "run_service_pack", "run_whatweb",
    "run_cloud_probe",   # public-bucket listing is confirmed-by-oracle; auto-store it (#13, was an island)
    # Q-054, the THIRD sink. workflow.run and tools._run_workflow now both FORWARD their steps'
    # findings (measured: a confirmed CWE-639 survives the live idor_read pack end to end). Without
    # this line a deterministic mission drops them again at dispatch and the run looks CLEAN -- the
    # false-clean shape, not a missing nicety, because run_workflow executes real attacks.
    # Routing needs no other change: _is_confirmed keys off f["confidence"] BEFORE the tool-name
    # fallback, so a forwarded confirm_idor finding goes to /findings and a forwarded enumerate_ids
    # lead goes to Leads.
    "run_workflow",
}
# Confirmatory tools that emit no per-finding confidence grade — their results are
# confirmed by construction (a template/active-scan/fingerprint match). Everything
# else must carry confidence=="confirmed" to enter the report.
_CONFIRMED_BY_TOOL = {"run_nuclei", "run_zap", "check_takeover", "run_sqlmap", "run_dalfox"}

SYSTEM_PROMPT = """You are a professional bug bounty hunter operating exclusively within provided scope.

CURRENT PHASE: Tier 1 — HackerOne/Bugcrowd public programs.
PRIORITY VULN CLASSES: IDOR/BOLA, broken access control, business-logic flaws, API authorization, subdomain takeovers, exposed sensitive endpoints, injection (SQLi/XSS/SSRF/SSTI/traversal).

HARD RULES:
1. Never test any asset not explicitly listed in scope. A scope block means stop — do not retry.
2. Passive recon before active scanning. Enumeration before fingerprinting. Fingerprinting before nuclei. Nuclei before intrusive probing.
3. Start nuclei with safe tags only (tech, misconfig, exposed-panels, takeovers). Escalate to cve tags only on targets with confirmed vulnerable versions.
4. Never brute-force credentials.
5. Call store_finding only when: evidence is real, the PoC is reproducible, impact is clearly articulated, and you have exact reproduction steps a triage reviewer can follow.
6. Do not store theoretical or speculative findings.
7. INTRUSIVE tools (content discovery, web probes, ffuf, dalfox, sqlmap) require operator approval unless the run is pre-authorized. If a probe is denied, continue with passive/active work.
8. SEVERITY DISCIPLINE — be consistent between what you say and what you store. Missing SPF/DMARC/DKIM, missing CAA, and missing security headers (CSP/HSTS/X-Frame-Options) are LOW or INFORMATIONAL email/transport-hygiene observations — never "Critical". Do not narrate an issue as a "Critical finding" unless you also store_finding it with that severity and reproducible evidence. If you choose not to store something, present it as an observation/recommendation, not a confirmed finding, so the report and your summary never disagree.
9. Before you finish, ALWAYS call generate_playbook once the surface is populated (any mode), so the operator gets cURL-ready manual tests even if you ran out of active/intrusive budget.
10. CLOSING SUMMARY — when you have no further tool to run, end with a short, CONCLUSIVE wrap-up: what was covered, what was confirmed (or that nothing reproducible was), and where the operator should look next (point at the playbook). Do NOT end on an open-ended "we need to continue testing…" — the run is finishing, so the final message must read as a conclusion, not a cliffhanger.

RECOMMENDED METHODOLOGY:
1. Subdomain enumeration: run_subfinder + run_crtsh on every in-scope root domain. run_wayback to seed historical URLs. run_dns for SPF/DMARC/CAA/vendor intel. run_asn to map the org's IP range (scope expansion). run_github_recon to hunt leaked secrets in public repos (passive, uses the operator's own PAT).
2. Live host probe: run_httpx on discovered subdomains. check_takeover on subdomains to catch dangling-CNAME hijacks.
3. Enrich: http_probe interesting hosts (captures evidence, reads security headers, seeds the surface). run_fingerprint to identify the tech stack (server/language/framework/CMS + versions). fetch_openapi on any /swagger or /openapi.json. run_graphql on any /graphql endpoint (introspection + batching abuse). run_jwt on any JWT/Bearer token you capture (alg:none, weak-secret crack, forged-admin). run_oauth on any OAuth authorization URL (/oauth/authorize with client_id/redirect_uri — redirect_uri bypass, missing-state CSRF, implicit-flow token leak). run_js_review on discovered .js bundles (hardcoded secrets, dangerous sinks, hidden endpoints).
4. Surface scan: run_nuclei with safe tags on live hosts. run_nmap on unusual fingerprints. If the ZAP daemon is available, run_zap for a full DAST pass on a primary in-scope web app (spider + AJAX spider + active scan, scope-fenced).
5. Plan: call generate_playbook to get a rule-based, per-surface test playbook (what/how/payloads/confidence/cURL). Use it to target the next step.
6. Targeted probing (INTRUSIVE): run_content_discovery for sensitive paths (body-validated), run_exposure for exposed .git/.env/backup/credential files (signature-confirmed, source-recoverable escalation), run_web_probes for traversal/IDOR, run_injection_probes for CORS/open-redirect/host-header/SSTI on parameterized URLs, run_bfla for broken function-level authorization (write methods / admin paths with a low-priv token) + side-channel BOLA, run_race on single-use actions (coupon/transfer/vote) for race conditions, run_ssrf on URL-taking parameters (fetch/redirect/proxy/image/webhook) for server-side request forgery (cloud-metadata reflection + internal port oracle), run_deserialization on requests carrying serialized blobs in params/cookies (PHP/Java/pickle/.NET/Ruby — corrupt-and-watch-for-parser-error confirmation), run_xxe on endpoints that accept XML (in-band file read + OOB blind confirmation via the native collaborator), run_sqli on parameterized URLs (error/boolean/time oracles, baseline-confirmed, native — no binary needed), run_nosqli on parameterized URLs for MongoDB-style operator injection (id[$ne]=/[$regex]= — boolean/error oracles), run_auth_sqli and run_form_nosqli on login-style POST/JSON bodies for auth-bypass (SQL OR-payloads / NoSQL operator objects — the class query-string probes can't reach), run_form_cmdi on captured forms for POST-body command injection, run_upload_test on pages with a file-upload form for extension-filter bypass (CWE-434, non-destructive canary payloads), run_cache_poison on live host roots for unkeyed-header cache poisoning (X-Forwarded-Host/Scheme, X-Original-URL — confirmed only when a clean re-request still receives the injected canary), run_llm_probe on any discovered URL that looks like a chat/AI endpoint for prompt injection (instruction-override probe with a unique marker — confirmed only on exact marker compliance), run_cmdi on params that feed OS commands (ping/host/filename/exec — computed-output + time + OOB oracles), run_xss on reflected parameters and pages with client-side sinks (browser-confirmed, catches DOM XSS).
7. Correlate. Store every confirmed reportable vulnerability with store_finding.

INVESTIGATIVE TESTING (you are an operator, not just a scanner runner):
The canned scanners are your floor, not your ceiling. For access-control, authorization, auth/token, and business-logic classes the scanners cannot fully judge, DRIVE THE LOOP yourself with the request primitives:
  - acquire_session{login_url, username/email, password, role} — log in ONCE and store a reusable session under a role name. Acquire TWO roles (e.g. a victim account and an attacker account you register) so you can test cross-user access. Then pass session="<role>" to the primitives below to act as that identity. (Single-credential auth only — never iterate passwords.)
  - http_read{method:GET/HEAD/OPTIONS, url, headers} — send a scope-guarded read with custom headers (e.g. an Authorization token you acquired) and read the response.
  - http_diff{a,b} — send two reads and get a DETERMINISTIC differential (status, length delta, body_similarity, distinct_objects). This is your CONFIRMATION ORACLE.
  - http_request{method, url, headers, body} — a scope-guarded state-changing request (INTRUSIVE, gated). Use for write tests.
  - confirm_idor{owned_url, target_url, headers} — the IDOR/BOLA ORACLE: pass your own object + another id + your session; it deterministically confirms (and stores) cross-object access. Prefer this over storing an IDOR by hand.
  - enumerate_ids{url_template (with {id}), start, end, headers} — bounded object-id enumeration to find accessible objects at scale (then confirm ownership with confirm_idor).
  - browser_navigate{url, steps:[{action:goto|click|fill|press|wait,...}], session} — drive a real headless browser for authenticated SPA flows and to capture client-side state (localStorage/sessionStorage tokens, XHR/fetch API calls, scripts, DOM). Declarative steps only, no arbitrary JS.
  - test_numeric_abuse{url, param, body, session} — business-logic probe: does the server accept out-of-range numeric values (negative/zero/huge) for a quantity/price/amount field? Then verify the downstream effect (negative total etc.) with http_read. Never finalize a payment.
LOOP: DISCOVER a suspicious endpoint/flow (object id in path, role/authz boundary, token, price/quantity, multi-step sequence) → HYPOTHESIZE one vuln class → TEST by crafting requests → COMPARE with http_diff or a control request → ADAPT (change one thing, retry, bounded) → CONFIRM only when the oracle is unambiguous → CHAIN a confirmed primitive (a token, an id, a leaked value) into the next hypothesis.
ORACLE DISCIPLINE (truth-first, non-negotiable): never store_finding on a hunch. Confirm with EVIDENCE:
  - IDOR/BOLA: acquire a session, http_read another object's id, and http_diff against your own object — confirmed only when both are 200 and distinct_objects is true (you read data that is not yours). Include the two requests + responses as evidence.
  - Broken auth / token: forge/modify a token, http_read a protected endpoint with it — confirmed only when it authenticates (200 + your injected identity reflected).
  - Business logic: establish the invariant (e.g. server total == sum of item prices), attempt a BOUNDED violation with http_request, and re-read state — confirmed only when the invariant provably broke. Do NOT finalize payments or perform destructive/irreversible actions; inspect the outgoing request and stop at that boundary, recording the manual step.
GENERALIZE, never hardcode: discover identities/ids/values at runtime (enumerate /api/Users, read a source map, parse an error) — do not assume target-specific strings. The same loop works on any object endpoint, any REST API, any SPA.
STOP when: evidence is inadequate (record it as a lead + the exact manual repro), impact would be unsafe/irreversible, approval is required, or budget is spent.

HIGH-VALUE SIGNALS:
- Subdomains pointing to unclaimed cloud resources (S3, GitHub Pages, Heroku, Fastly)
- Admin panels with default or no credentials
- API endpoints returning PII or internal data without authorization
- Exposed .git/.env/backup/config files (only when the body confirms it)
- Dev/staging subdomains with weaker auth
- Mismatched CORS on authenticated API endpoints"""

MODE_NOTES = {
    "passive": "\n\nASSESSMENT MODE: PASSIVE. Only passive tools are permitted (subfinder, crtsh, wayback, dns, asn, github_recon, generate_playbook). Active and intrusive tools are disabled. Produce a recon picture and a test playbook the operator can execute by hand.",
    "active": "\n\nASSESSMENT MODE: ACTIVE. Passive + active tools auto-run. Intrusive probing requires one operator approval.",
    "full": "\n\nASSESSMENT MODE: FULL. Passive + active auto-run; intrusive probing requires approval. Go deep: content discovery, web probes, and confirmation on every promising surface.",
}


def _is_generic_objective(objective: str) -> bool:
    """True when the objective is the default template (adds no steering signal)."""
    o = (objective or "").strip().lower()
    return (not o) or o.startswith("perform comprehensive bug bounty recon")


# Deterministic-sweep budgets. MEASURED on the OWASP Benchmark lab, 2026-08-10 (Q-019), one URL through
# the ten sweep engines: the eight HTTP-only engines cost **1.1 s per URL between them**, while the two
# browser-backed confirmers cost **~19 s per URL** (run_xss 10 s, run_dom_trace 9 s) — 95% of the wall
# clock for 20% of the engines. A single cap for both is why it had to be 20: twenty endpoints against a
# 2756-URL surface, all twenty inside one directory. Budget the two tiers separately and the same wall
# clock buys an order of magnitude more coverage. Both are env-tunable; neither is unbounded.
#
# RE-MEASURED over a FULL mission, 2026-08-14 (selection lane) — per-dispatch wall clock, not a
# single-URL sample, and the 2026-08-10 figures were optimistic:
#   eight HTTP engines   680.8 s over 400 targets = **1.70 s per URL** between them
#     run_sqli 0.65  run_ldap 0.39  run_xpath 0.35  run_waf_bypass 0.09
#     run_sqli_structural 0.07  run_ssi 0.06  run_injection_probes 0.05  run_css_injection 0.03
#   two browser engines  run_xss **13.5 s** per call, run_dom_trace 3.95 s
# So ONE browser target costs ~33 HTTP targets, and the browser trio (run_xss, run_dom_trace,
# run_dom_audit) is 3.1% of the mission's dispatches for 58.5% of its tool-seconds. That ratio is
# the reason the two tiers have separate budgets, and it is now a measurement rather than a sample.
# RAISED 400 -> 700 on 2026-08-15, and the number is a MEASUREMENT, not a preference (Q-049).
#
# 400 kept 14.5% of a 2762-URL surface. Because a truncated round-robin is the water-filling optimum
# `min(size, level)`, every shape drew the same ~38, and the sqli class -- 456 of 2524 query-bearing
# candidates -- had nine true positives sitting at class indices 38-58, just past the cut. They were
# never probed by anything, and that WAS the entire `sqli 21 -> 11` regression. Reallocating cannot
# reach them (proportional splits break complete coverage of the small classes, worth 34.1% vs 17.8%
# macro reachable recall), so the budget itself was the lever. 605 is the modelled boundary; 700 is
# the first round number above it with margin.
#
# MEASURED end to end, sealed before the key (docs/benchmarks/wp3_raised_cap_claims.json, seal
# 951dc0a0), against conditions registered in advance (docs/benchmarks/wp3_precondition.md):
#   cases probed 373 -> 645 | sqli findings 11 -> 20 | 8 of the 9 named cases recovered
#   26 TP / 1 FP / 27 claimed, precision 96.3%, recall 1.84% -- the baseline's exact score
#   elapsed 2576 s vs the baseline's 5329 s, so the same result in 48% of the time
# The single FP is 00494, the long-known baseline false positive, not a new one.
#
# The cost prediction was WRONG in the good direction: +22% elapsed, not the +57% predicted from a
# linear per-URL model. Per-URL cost is evidently sublinear in target count, which is worth
# understanding before the next budget change is priced.
#
# CORRECTION 2026-08-17: this comment used to end "-- 00438, the ninth case, is still unprobed".
# That was FALSE and it sat in product source for days. MEASURED against mission ebd96f45: 00438
# was probed by EIGHT engines (run_sqli, run_sqli_structural, run_injection_probes, run_xpath,
# run_ldap, run_ssi, run_css_injection, run_waf_bypass) and produced a CONFIRMED sqli finding --
# identically to the other eight cases. Negative control: the paired mission 90cee81c shows 0 log
# rows and 0 findings for it. The selection model picks it at index 58 with the cap at 700, i.e.
# with 12 slots to spare, so raising the cap could never have been the fix for a case the cap
# already covered.
#
# The claim came from reading the wp3 SEAL, which has 0 mentions of 00438 -- but that seal's keys
# carry CLAIMS ONLY and no probed-cases list, so "unprobed" was an inference from "no claim".
# Absence of a claim is not evidence of absence of a probe.
# Q-113 · 700 IS NOT A BOUND, IT IS A NUMBER LARGER THAN ANY SURFACE WE HAVE MET.
#
# MEASURED on the operator's authorised Shopify engagement: the sweep reached endpoint 69 of 465 in
# roughly seven hours — ~6 minutes per endpoint against a Cloudflare-fronted target where every
# request is slow. The remaining 396 needed ANOTHER ~46 HOURS. Nothing was stalling: Q-110's
# per-call budget (`tools._PROBE_CALL_BUDGET_S`) never fired (TRUNCATED count 0) and the mission
# heartbeat advanced normally. 465 endpoints x 8 HTTP engines is simply more work than an engagement
# has. He killed it at 15% holding exactly the findings he already had at 5%.
#
# MEASURED baseline of this constant at 700, synthetic 465-endpoint surface
# (tests/test_injection_sweep_is_bounded.py): 465 candidates -> 465 selected -> 465 endpoints swept
# -> 3816 injection dispatches, and the announcement said "probing 465" with no statement that
# anything had been declined, because nothing was. At the measured per-endpoint cost that is 46.5 h.
#
# A COVERAGE GUARANTEE WITH NO TIME BOUND IS NOT A GUARANTEE, IT IS A PROMISE THE RUN CANNOT KEEP.
# Every other phase is capped (`planner.CAP_HOSTS` 30, `CAP_ENDPOINTS` 25, `CAP_JS` 40, `CAP_ZAP` 3,
# Q-104's `CAP_RECON_ROOTS` 25); this one opted out. 40 is inside the ticket's 25-50 band and just
# above `planner.CAP_ENDPOINTS`, so the sweep still out-covers the planner it exists to backstop.
#
# THE NUMBER IS THE SMALL HALF OF THE FIX. `select_sweep_targets` ranks by observable security value
# and operator-declared assets BEFORE it truncates: Q-104b bounded phase A correctly and then spent
# the whole budget on wildcard-DNS junk because the order underneath the cap was lexical.
#
# Q-113, COORDINATOR DECISION, and it reverses the lane's own first answer. Lane A shipped this at
# 40 to bound the operator's engagement, and the collision that produced was not a nuisance: at 40,
# `test_whole_product_reach.py` fails its `MIN_TARGETS = 100` floor. That floor is not a goalpost —
# its own docstring calls it "far above the broken numbers and far below the measured post-fix ones
# (250 / 400), so they catch a collapse without becoming a moving goalpost". Selecting 40 of 2524 on
# the lab IS the collapse that test exists to catch, and the proposed workaround — run the capability
# test with `BBH_SWEEP_TARGETS=700` — means running the oracle against a configuration the product
# does not ship. Q-019's `SWEEP_TARGET_CAP >= 200` says the same thing from the other side.
#
# So the COUNT stays a volume ceiling and the WALL CLOCK below is the engagement bound. The lane's own
# comment already argued this: a wall-clock budget "is the bound that is correct for both, because it
# is denominated in the thing that actually ran out". On the operator's target 4 h at ~6 min each
# stops at ~40 endpoints, which is the number the cap of 40 was reaching for anyway — reached by
# measuring the constraint instead of guessing it. On a fast target nothing is thrown away.
#
# The ranking Lane A built matters MORE under this arrangement, not less: with the count no longer
# truncating, ordering is the only thing deciding which endpoints get tested before the clock stops.
#
# COST, STATED PLAINLY: `docs/benchmarks/wp3_precondition.md` raised this to 700 on a pre-registered
# OWASP whole-product experiment (the dominant class draws 38 slots at cap 400 and 59 at 605, and
# nine sqli true positives sit at class indices 38-58), and 700 is what ships.
SWEEP_TARGET_CAP = max(1, int(os.getenv("BBH_SWEEP_TARGETS", "700") or 700))
# Q-113, THE SECOND BOUND, AND THE ONE THE TICKET IS ACTUALLY NAMED AFTER.
#
# A COUNT IS ONLY A TIME BOUND IF EVERY ENDPOINT COSTS THE SAME, AND THEY DO NOT. MEASURED: the eight
# HTTP engines total 1.1 s per URL on a local lab and ~6 MINUTES per endpoint on the operator's
# Cloudflare-fronted target. That is a 300x spread, so ANY single count is simultaneously too small
# for a fast target and too large for a slow one — which is exactly the collision this ticket ran
# into: 40 is right for the engagement and wrong for the OWASP whole-product benchmark, where the
# same 465-endpoint scale costs minutes rather than days.
#
# A wall-clock budget is the bound that is correct for both, because it is denominated in the thing
# that actually ran out. At the measured costs, 4 h buys ~40 endpoints on the slow target and all
# 2524 candidates on the lab, where it never fires at all.
#
# 0 disables it. THIS IS THE ENGAGEMENT BOUND. `SWEEP_TARGET_CAP` above is a volume ceiling that a
# real surface rarely reaches; this is what stops a run that cannot finish. Exhausting either one is
# REPORTED, never silent.
SWEEP_WALL_BUDGET_S = max(0, int(os.getenv("BBH_SWEEP_BUDGET_S", "14400") or 0))
#: Q-133. How many untested endpoints the mission RECORDS when a budget fires. Bounded so a huge
#: surface cannot bloat the mission row, and the overflow is reported rather than silently dropped.
_PENDING_KEEP = max(1, int(os.getenv("BBH_PENDING_KEEP", "200") or 200))
#: Indirection so the deadline is testable with a fake clock instead of a four-hour test.
_sweep_clock = time.monotonic
# targets that additionally get the browser-backed confirmers, taken off the FRONT of the shape-spread
# order so they are representatives of the whole site rather than the first N of one directory.
SWEEP_BROWSER_CAP = max(0, int(os.getenv("BBH_SWEEP_BROWSER_TARGETS", "30") or 30))
# the split itself. HTTP-only engines are cheap enough to run on every selected target; the two that
# drive a real browser are not, and pretending otherwise is what capped coverage at twenty endpoints.
#
# `run_web_probes` JOINED THIS TIER 2026-08-14 (selection lane). `_inject_sweep_surface` promises
# that "a discovered query input is ALWAYS tested even if the graph-authoritative planner did not
# select it". MEASURED on a full whole-product mission, that promise covered SQLi, XPath, LDAP and
# SSI and covered NOTHING for path traversal, IDOR, cookie flags or PRNG disclosure -- the four
# classes `run_web_probes` owns, and the engine `owasp_bench.ENGINES` names as the owner of
# `pathtraver`, `securecookie` and `weakrand`.
#
# It was not merely under-scheduled. **It ran ZERO times in the whole mission**, and the reason is a
# second gate, not this tuple: `planner._ALLOWED["active"] = {PASSIVE, ACTIVE}`, and `fresh()` drops
# any step whose tool is not `_allowed(tool, mode)`. `run_web_probes` is INTRUSIVE, so in the
# DEFAULT `active` mode the planner cannot schedule it at all -- nor `run_cmdi`, `run_nosqli`,
# `run_ssrf`, `run_bfla`, `run_content_discovery` or `run_ffuf`. The sweep dispatches through
# `_run_tool`, which applies the intrusive HITL gate (pre-authorised on an autonomous run) instead
# of the planner's mode filter, so THIS TUPLE IS THE ONLY PATH to intrusive injection coverage in an
# active-mode mission. A class absent from it is a class the mission never tests.
#
# MEASURED consequence on the OWASP Benchmark: of 220 vulnerable cases the mission actually probed,
# 56 (weakrand 18, pathtraver 16, securecookie 22) had `run_web_probes` as their owning engine and
# never received it, and were then booked as a DETECTION shortfall.
#
# It belongs in THIS tier and not the browser tier: HTTP-only (no CDP, no page render), and
# INTRUSIVE exactly like `run_sqli` and `run_injection_probes` already here, so the sweep's
# permission surface is unchanged.
_SWEEP_HTTP_ENGINES = ("run_sqli", "run_sqli_structural", "run_xpath", "run_ldap", "run_ssi",
                       "run_css_injection", "run_waf_bypass", "run_injection_probes")
# `run_web_probes` was ADDED here on 2026-08-14 and REMOVED the same day, by a revert condition
# registered BEFORE the measurement rather than argued after it. Both halves are recorded because the
# coverage argument below is still correct and still unaddressed -- this tuple covers no traversal,
# IDOR, cookie-flag or PRNG class -- while the engine that would cover them is not yet sound enough
# to be trusted with a confirmed verdict.
#
# MEASURED, whole-product mission, seal e6674d6d (docs/benchmarks/wp1_web_probes_sweep_claims.json):
# 30 TP / 1 FP / 31 claimed, 96.8% precision in 2103 s against the baseline's 96.3% in 5329 s. It
# looked like the first recall gain this suite has ever produced. Then the claims were read by class:
# of 12 confirmed `path_traversal` findings, only FIVE are on cases whose actual class is traversal.
# The rest landed on `cmdi-00` and `weakrand-00` endpoints and scored TP only because those cases
# happen to be vulnerable to something else -- and the single FP, `weakrand-00/BenchmarkTest00187`,
# is the same behaviour on a case that is vulnerable to nothing. Same engine, same carrier, same
# "POST body field" pattern: the verdict tracks the endpoint being reflective, not traversable.
#
# So the score was right and the reason was wrong, which is why the condition was written down in
# advance. See Q-047. Restoring this entry needs a traversal oracle that fails on 00187, not a better
# number.
def _dom_sweep_key(u: str) -> str:
    """What counts as "the same page" for the DOM sweep's dedup.

    Q-159. The path alone is wrong for a hash-routed SPA: every route shares the path "/", so one
    render of the base page marks the whole application as swept. The fragment IS the route there,
    so it belongs in the key -- and on an ordinary URL the fragment is empty and this is exactly
    the old behaviour.
    """
    from urllib.parse import urlparse as _up          # imported per-function throughout this file
    p = _up(u)
    return p.path + ("#" + p.fragment if p.fragment else "")


_SWEEP_BROWSER_ENGINES = ("run_xss", "run_dom_trace")

_SHAPE_DIGITS = re.compile(r"\d+")
_SHAPE_HEXID = re.compile(r"\b[0-9a-f]{8,}\b", re.I)


def target_shape(url: str) -> str:
    """The STRUCTURAL shape of a URL — its path with identifier-looking segments collapsed, plus its
    sorted parameter names. `/benchmark/sqli-04/BenchmarkTest01234.html?BenchmarkTest01234=x` and
    `/benchmark/sqli-09/BenchmarkTest02345.html?BenchmarkTest02345=y` share a shape; `/benchmark/xss-00/…`
    does not.

    This is NOT a deduplication key — two URLs of the same shape can hit completely different sinks, and
    collapsing them would be exactly the kind of case-specific cheating this project forbids. It is an
    ORDERING key: when a budget forces a truncation, spend it round-robin across shapes so the cut
    spans the whole application instead of exhausting itself in the first directory it walked into.
    MEASURED: the old selection's twenty targets were twenty consecutive files in one category folder.
    """
    from urllib.parse import urlparse, parse_qs

    def _norm(s: str) -> str:
        return _SHAPE_DIGITS.sub("#", _SHAPE_HEXID.sub("#", s))

    pr = urlparse(url or "")
    segs = [_norm(s) for s in (pr.path or "/").split("/") if s]
    # PARAMETER NAMES ARE NORMALIZED TOO. A framework that names the parameter after the page
    # (`?BenchmarkTest00006=…`, `?item_4711=…`) gives every endpoint a unique parameter, so shaping the
    # path alone leaves one shape per URL and the round-robin degenerates back into discovery order —
    # which is the bug, wearing the fix's clothes.
    params = sorted({_norm(k) for k in parse_qs(pr.query).keys()})
    return "/".join(segs) + "|" + ",".join(params)


_HIGH_VALUE_ROUTE = re.compile(
    r"/(?:admin|manage|internal|private|account|profile|users?|auth|login|session|execute|exec|"
    r"command|upload|import|export|graphql|api|rest|debug|config|backup)(?:/|$)", re.I)
_HIGH_VALUE_PARAM = re.compile(
    r"^(?:id|uid|user|account|role|admin|cmd|command|exec|code|file|path|page|template|url|uri|"
    r"redirect|next|return|target|callback|webhook|query|search|filter|sort|order)$", re.I)


def target_security_value(url: str) -> int:
    """Observable security value used only when a budget forces a cut.

    Inputs are target-owned URL facts, never a benchmark label, response, or expected result. Ties
    retain discovery order because Python's sort is stable.
    """
    raw = str(url or "").split("#", 1)[0]
    before_query, marker, query = raw.partition("?")
    params = [part.partition("=")[0] for part in query.split("&") if part] if marker else []
    path = before_query.split("://", 1)[-1]
    path = "/" + path.partition("/")[2] if "/" in path else "/"
    score = 1 if params else 0
    score += 4 * sum(bool(_HIGH_VALUE_PARAM.search(name)) for name in params)
    score += 3 if _HIGH_VALUE_ROUTE.search(path) else 0
    return score


def operator_roots(scope) -> list:
    """The hosts the OPERATOR declared, lower-cased and de-wildcarded.

    Q-113. This derivation already existed inline at the planner-state call site; naming it once is
    what lets the injection sweep rank by the same fact the recon phase does, instead of restating
    it and drifting.

    NO HANDLER, deliberately. This shipped with `except Exception: return []` and pushed the
    `test_silent_failure_invariant` optional-swallow census from 61 to 62 -- a ratchet, so that is a
    regression rather than a budget item. Returning `[]` would also be the worst possible failure
    here: an empty root set silently disables operator-asset ranking, so the sweep would quietly
    stop preferring the hosts the operator actually declared and nothing would say so. That is the
    `x or DEFAULT` failure mode this codebase has already been bitten by twice.

    The two realistic shapes are both handled without a handler: a scope with no `in_scope` yields
    `[]` through the `getattr` default, and an entry that is a plain string rather than a value
    object is filtered by `getattr(e, "value", None)`. Anything else is a broken scope object, which
    is a real error and belongs on the caller's floor, not swallowed here."""
    return [str(e.value).lower().lstrip("*.") for e in (getattr(scope, "in_scope", None) or [])
            if getattr(e, "value", None)]


def _is_operator_asset(url: str, roots: set) -> bool:
    """True when the URL's host IS a declared root or a subdomain of one."""
    if not roots:
        return False
    host = str(url or "").split("://", 1)[-1].split("/", 1)[0].split("@")[-1]
    host = host.split(":")[0].lower()
    return bool(host) and any(host == r or host.endswith("." + r) for r in roots)


def rank_targets_for_budget(targets, scope_roots=()) -> list:
    """Highest observable security value first; equal-value work stays in discovery order.

    Q-113 · OPERATOR ASSETS OUTRANK DISCOVERED HOSTS, which is Q-104's pattern
    (`planner._rank_recon_roots`, `_rank_live_hosts`) applied to the injection budget. A wildcard
    resolver or an over-broad crawl can put thousands of hosts on the surface that the operator
    never declared; when a budget forces a cut, the cut must fall on those and never on an asset
    that is actually in the engagement. `scope_roots` defaults empty, so every existing caller keeps
    pure value ranking and this is additive.

    Two stable sorts, applied value-first then asset-first, so asset membership is the PRIMARY key
    and security value orders within each tier.
    """
    ranked = sorted(list(targets or []), key=target_security_value, reverse=True)
    roots = {str(r).lower().lstrip("*.") for r in (scope_roots or []) if r}
    if not roots:
        return ranked
    return sorted(ranked, key=lambda u: _is_operator_asset(u, roots), reverse=True)


def _spread_by_shape(targets: list) -> list:
    """Round-robin the targets across their structural shapes, preserving first-seen order inside each
    shape. Deterministic: same input, same output, so a re-run probes the same endpoints."""
    groups: dict = {}
    for t in targets:
        groups.setdefault(target_shape(t), []).append(t)
    out, order = [], list(groups)
    while len(out) < len(targets):
        for k in order:
            g = groups[k]
            if g:
                out.append(g.pop(0))
    return out


def select_sweep_targets(candidates, limit: int = SWEEP_TARGET_CAP, scope_roots=()) -> list:
    """Apply the sweep's BUDGET to an already-built candidate list.

    Q-113 split this out of `sweep_targets` for one reason: the mission must be able to say how many
    endpoints it DECLINED, and a function that returns only the survivors cannot be asked. The caller
    now holds both numbers — `len(candidates)` and `len(selection)` — and the difference is a fact it
    reports rather than an inference nobody can make from a log line.

    UNDER BUDGET, NOTHING MOVES. Reordering is a truncation strategy, not a behaviour change: an
    ordinary engagement that fits must come back in discovery order, untouched and unshrunk.
    """
    candidates = list(candidates or [])
    if len(candidates) <= limit:
        return candidates
    # Shape spreading prevents one large route family consuming the budget. Security-value ranking
    # before that spread also prevents an early collection of low-value shapes consuming every slot,
    # and operator-declared assets outrank discovered hosts inside that (Q-113/Q-104b).
    return _spread_by_shape(rank_targets_for_budget(candidates, scope_roots))[:limit]


def sweep_candidates(urls, forms, in_scope) -> list:
    """The FULL parameterized surface the sweep could probe, in discovery order, before any budget.

    Q-113. This is the denominator of every claim the sweep makes. "0 confirmed across 465 endpoints"
    and "0 confirmed across the 40 we chose" are different claims about the target and only one of
    them is evidence; the mission cannot tell them apart without this number.
    """
    return _sweep_candidate_set(urls, forms, in_scope)


def sweep_targets(urls, forms, in_scope, scope_roots=(), limit: int = SWEEP_TARGET_CAP) -> list:
    """`sweep_candidates` composed with `select_sweep_targets` — the exact composition the mission
    call site runs, kept callable in one step for the many tests that drive the selection directly.

    `scope_roots` sits BEFORE `limit` on purpose: `limit` must stay the LAST default so the call site
    and the module budget remain pinned to each other (Q-019), and every caller passes `limit` by
    keyword.
    """
    return select_sweep_targets(sweep_candidates(urls, forms, in_scope), limit, scope_roots)


def _sweep_candidate_set(urls, forms, in_scope) -> list:
    """Endpoints the deterministic injection sweep will probe.

    Query-bearing URLs, one representative per (path, param-signature) — PLUS the page that carries each
    captured POST form. That second half is the point: the selection used to keep only URLs containing
    "?", so a page whose only injectable input is a form body was never handed to ANY injection engine,
    however capable that engine was. sqli and path traversal now have POST form passes and would still
    have gone unused, because nothing ever scheduled them against such a page.

    A form contributes its `page` (the document the form was parsed out of) and NOT its `action`: the
    engines re-parse the page to rebuild the form, and fetching a bare action usually returns a handler
    response with no <form> in it. Pure and order-stable so a re-run picks the same surface.

    THE CAP IS A BUDGET, AND THE ORDER MATTERS MORE THAN THE NUMBER (Q-019). `limit` defaulted to 20 and
    the mission call site never passed one, so twenty was the real bound on a 2756-URL surface — and
    because candidates were emitted in discovery order, all twenty landed in the first category folder
    the crawl walked. The candidate set is now built in full and then round-robined across structural
    shapes before truncation, so whatever the budget is, it is spent across the whole application.

    Q-113: this function now builds the FULL candidate set and applies NO budget. `select_sweep_targets`
    owns the cut, so the caller can hold both the numerator and the denominator.
    """
    from urllib.parse import urlparse, parse_qs
    import planner as _planner                  # Q-080 — one predicate, imported not restated
    seen_sig, seen_paths, targets = set(), set(), []
    for u in (urls or []):
        if "?" not in u or not in_scope(u):
            continue
        pr = urlparse(u)
        sig = (pr.path, tuple(sorted(parse_qs(pr.query).keys())))
        if sig in seen_sig:
            continue
        seen_sig.add(sig)
        seen_paths.add(pr.path)
        targets.append(u)
    for fm in (forms or []):
        page = (fm or {}).get("page") or (fm or {}).get("action")
        if not page or not in_scope(page):
            continue
        # Q-080. THE SWEEP IS PLANNER-INDEPENDENT, SO THE PLANNER'S QUARANTINE DOES NOT REACH IT.
        # The `page` fallback is not hypothetical: the forms `tools._http_probe` produces carry
        # exactly {action, method, fields} and NO `page` key (MEASURED), so every form here resolves
        # to its ACTION -- and a logout form's action, swept with the mission session, ends the scan's
        # own session. MEASURED before this line existed: sweep_targets(urls, the crawl's real forms)
        # returned the logout URL as a target. The engines this sweep dispatches (run_path_sqli,
        # run_encoded_cookie, run_xss, run_dom_trace, run_default_creds) all carry `session_headers`.
        if _planner.is_session_kill_url(page):
            continue
        # Dedupe form pages BY PATH, including against the query targets above: the engines run their
        # form pass on whatever page they are given, so if this path is already scheduled the form is
        # already going to be parsed there. Adding it twice only spends the budget.
        path = urlparse(page).path
        if path not in seen_paths:
            seen_paths.add(path)
            targets.append(page)
        # THE PAGE'S QUERY, REPLAYED AGAINST THE FORM'S ACTION. A page is often a static wrapper whose
        # own query string is meant for the endpoint its form posts to -- the wrapper ignores the
        # parameter entirely, so probing it there reads clean while the SAME parameter on the action is
        # injectable. Without this the engines test a document instead of a handler.
        action = (fm or {}).get("action") or ""
        pq = urlparse(page).query
        # Q-080: `page` and `action` are two different URLs whenever a producer records both, so the
        # guard above does not cover this branch. A form whose PAGE is ordinary and whose ACTION is
        # the logout endpoint is the exact shape of a nav-bar logout form.
        if action and _planner.is_session_kill_url(action):
            action = ""
        if action and pq and in_scope(action):
            merged = action + ("&" if urlparse(action).query else "?") + pq
            sig = (urlparse(action).path, tuple(sorted(parse_qs(pq).keys())))
            if sig not in seen_sig:
                seen_sig.add(sig)
                seen_paths.add(urlparse(action).path)
                targets.append(merged)
    return targets


# ── Q-050 · the observation that gives `run_hash_id` a deterministic trigger ─────────────────
#
# MEASURED over the whole stored corpus (154 missions), scanning 32.5 MB of captured exchange
# bodies + 1,773 findings with `hashid_tool.identify`, with a positive control that finds a planted
# bcrypt / sha512crypt / MySQL / MD5 / SHA-1 in the same pass:
#
#   * ZERO crypt-style prefixed hashes ($2b$, $6$, {SSHA}, *HEX) appear anywhere in the corpus.
#     Their false-positive rate on real traffic is therefore a measured zero, and they are
#     self-identifying -- no surrounding context is needed to know what they are.
#   * SEVENTEEN raw hex tokens appear, and hand-inspecting every one of them is what stopped this
#     from being wired wrong. Only THREE are password hashes (Juice Shop's `"password":"<md5>"`
#     user table, dumped through a confirmed SQLi -- one of them the `admin` row). TEN are DVWA's
#     `user_token` anti-CSRF nonce, and the rest are a PGP fingerprint in a security.txt, a
#     `deluxeToken`, and a csaf advisory digest.
#
# So a trigger keyed on "a hash-shaped string appeared" would have been 77% anti-CSRF nonces --
# noise on every DVWA page, on an engine whose whole output is severity `info`. The discriminator is
# not a property of the hash, which is genuinely ambiguous by construction (a 32-hex digest is MD5,
# NTLM and MD4 at once, and `identify` says so): it is the KEY THE APP ITSELF BOUND IT TO.
#
# JWTs are excluded on purpose. `run_jwt` owns them with a confirming oracle and holds WSTG-SESS-10
# in `wstg_catalog.FULL`; adding a second engine that says "this is a JWT" and stops there is the
# `run_nosqlmap` mistake -- a weaker restatement of a dispatched engine.
_HASH_KEY = re.compile(r"""["'\s,{]\s*["']?([A-Za-z_][A-Za-z0-9_]{0,30})["']?\s*[:=]\s*["']"""
                       r"""([A-Za-z0-9$./*{}+=_-]{16,4096}?)["']""")
# `passw` covers password / passwordHash / password_hash / user_password; `pwd` covers pwd/pwdHash.
# NOT `token`, NOT `hash`, NOT `secret` -- `user_token` is the exact false positive measured above,
# and the other two are broad enough to re-admit it under another name.
_CRED_KEY = re.compile(r"(?i)passw|pwd")
# Self-identifying formats, matched as WHOLE TOKENS rather than key-bound: `identify` rates these
# "high" from the prefix alone, so no surrounding key is needed -- which is the point, because the
# case they exist for is a `/etc/shadow`-shaped dump (`root:$6$...:19000:...`) that has no JSON key
# anywhere near it. JWT is also rated high and is deliberately not in this set.
_SELF_ID_TOKEN = re.compile(
    r"(?<![A-Za-z0-9$./*])("
    r"\$(?:1|2[aby]|5|6|argon2[a-z]*|pbkdf2[a-zA-Z0-9-]*)\$[A-Za-z0-9$./=+,-]{8,300}"
    r"|\{S?SHA\}[A-Za-z0-9+/=]{16,120}"
    r"|\*[0-9A-Fa-f]{40}"
    r")(?![A-Za-z0-9$./])")


def _disclosed_hashes(exchanges: list, cap: int = 50) -> list:
    """Hash material a target's own RESPONSES disclosed, as [(hash, why)], de-duplicated.

    RESPONSE bodies only. A request body's `password` field is either the mission's own probe value
    or a plaintext credential it already holds -- neither is a disclosure by the target, and neither
    should be copied into a finding's evidence.

    Two admission rules, both grounded in the measurement above:
      A. the token is a self-identifying crypt-style hash, standalone (measured FP rate: zero);
      B. the token is hash-shaped AND the app bound it to a password-ish KEY.
    `hashid_tool.identify` is the final filter in both, so a plaintext password sitting in a
    `password` field ("admin123") is dropped for not being hash-shaped -- which is also what keeps a
    real credential out of the evidence blob."""
    import hashid_tool as hid
    out, seen = [], set()

    def take(val, key, src):
        if val in seen:
            return False
        cands = hid.identify(val)
        if not cands or cands[0]["name"].startswith("JWT"):
            return False
        seen.add(val)
        out.append((val, "%s disclosed `%s` as %s" % (src or "response", key, cands[0]["name"])))
        return len(out) >= cap

    for ex in (exchanges or []):
        if not isinstance(ex, dict):
            continue
        body = ex.get("response_body") or ""
        if not isinstance(body, str) or not body:
            continue
        src = str(ex.get("url") or "")
        for m in _SELF_ID_TOKEN.finditer(body):            # rule A
            if take(m.group(1), "a crypt-style hash", src):
                return out
        for m in _HASH_KEY.finditer(body):                 # rule B
            key, val = m.group(1), m.group(2)
            if not _CRED_KEY.search(key):
                continue
            if take(val, key, src):
                return out
    return out


def _gate_refusal(res) -> str:
    """The reason a GATED dispatch refused to run, or "" when it did not refuse.

    `_exec_internal` reports a passive-mode or intrusive-HITL refusal as a `{"ran": false,
    "blocked": ...}` carrier rather than raising, so that callers keep their `.findings` handling.
    That design has a trap: a caller which only inspects `.findings` cannot tell "the gate said no"
    from "the engine ran and found nothing", and will book a refusal as a clean dismissal.

    A false negative manufactured by a safety gate is worse than the unsafe dispatch it replaced,
    because it is invisible. Every caller that routes a validator through the gate must ask this.
    """
    try:
        d = json.loads(str(getattr(res, "output", "") or "") or "{}")
    except Exception:
        return ""
    if isinstance(d, dict) and d.get("ran") is False:
        return str(d.get("blocked") or "gate refused the dispatch")
    return ""


class BBHAgent:
    # execution strategies (how tools are chosen), orthogonal to `mode` (which
    # tiers of tool are allowed). Default budgets: manual/deterministic use no AI,
    # low_ai spends at most 2 calls, agentic caps the ReAct loop.
    _DEFAULT_BUDGET = {"manual": 0, "deterministic": 0, "low_ai": 2, "agentic": 40}

    def __init__(self, scope: ScopeEngine, tools: ToolRegistry, stop_event: asyncio.Event,
                 mode: str = "active", auto_approve: bool = False, mission_id: str = None,
                 recon_cycles: int = 1, strategy: str = "low_ai", max_ai_calls: int = None,
                 exclude_categories=None,
                 enable_zap: bool = False, zap_policy: str = "safe_active",
                 zap_speed: str = "normal", zap_aggression: str = "normal",
                 enable_nmap_vuln: bool = False, enable_nuclei_heavy: bool = False,
                 authenticated_scan: bool = False):
        self.scope = scope
        # opt-in: reuse credentials the scan/prior-scan DISCOVERED to run authenticated (HITL — the UI
        # prompts for this on the next scan once a prior scan has gathered creds). Off = discover + report
        # the exposed creds, but scan unauthenticated.
        self.authenticated_scan = bool(authenticated_scan)
        # structured proof of the authentication artery — {"ran": False} until _do_persona_authz
        # actually mints/reacquires personas + runs the matrix. Lets a correctness check tell
        # "artery did not run" apart from "ran and produced no personas" (both differ from a smoke test).
        self._auth_artery = {"ran": False}
        self._graph_projection_error = None
        self._degraded = None                # structured degraded/failure state (e.g. graph projection halt)
        self._candidate_assurance = []       # per-candidate validation ledger (candidate->validator->result->evidence)
        self._candidate_validation_counts = {}
        self.tools = tools
        self.stop_event = stop_event
        self.tools.stop_event = stop_event   # let long ZAP polls honor a user stop
        # ZAP DAST is opt-in per scan: it runs only when the user enabled it (and
        # only in Full mode via the planner's INTRUSIVE gate). Policy chooses
        # passive / safe-active / thorough-active. Stored on the tool registry so
        # _run_zap can read the policy without threading it through every call.
        self.enable_zap = bool(enable_zap)
        self.zap_policy = zap_policy if zap_policy in ("passive", "safe_active", "thorough_active") else "safe_active"
        self.zap_speed = zap_speed if zap_speed in ("turtle", "normal", "fast") else "normal"
        self.zap_aggression = zap_aggression if zap_aggression in ("low", "normal", "demon") else "normal"
        self.tools.zap_policy = self.zap_policy
        self.tools.zap_speed = self.zap_speed
        self.tools.zap_aggression = self.zap_aggression
        # heavyweight nmap NSE vuln scan — opt-in, Full-mode only (INTRUSIVE gate)
        self.enable_nmap_vuln = bool(enable_nmap_vuln)
        # heavy nuclei (full vuln template set) — opt-in, Full mode only
        self.enable_nuclei_heavy = bool(enable_nuclei_heavy)
        # Q-079. Normalisation now lives in the `mode` SETTER (below), which also writes the value
        # through to `self.tools.mission_mode` — so this assignment binds the dispatcher's
        # permission context as a side effect, and so does every later `agent.mode = ...`.
        self.mode = mode
        # The live authorization read for the dispatcher backstop. A BOUND METHOD, not a bool: the
        # HITL state mutates mid-mission (None -> approved/denied), and a snapshot taken here would
        # answer with state from before the operator answered the gate.
        self.tools.intrusive_authorized = self._intrusive_authorized
        self.auto_approve = auto_approve
        self.mission_id = mission_id
        self.recon_cycles = max(1, min(int(recon_cycles or 1), 3))
        # Operator scoping (#34). Resolved ONCE to concrete technique ids so every planner call gates on
        # the same set -- resolving per call would let a later caller silently disagree about the scope.
        self.exclude_categories = list(exclude_categories or [])
        self.skip_technique_ids = []
        if self.exclude_categories:
            try:
                import scan_scope as _ss, techniques as _T
                self.skip_technique_ids = _ss.resolve(
                    self.exclude_categories,
                    [_T.get(t["id"]) for t in _T.list_techniques()])["skipped_technique_ids"]
            except Exception:
                self.skip_technique_ids = []
        self.strategy = strategy if strategy in self._DEFAULT_BUDGET else "low_ai"
        self.ai_calls = 0
        self.ai_degraded = False
        self.ai_note = ""   # human-readable AI-usage outcome for the report
        self.max_ai_calls = (max(0, int(max_ai_calls)) if max_ai_calls is not None
                             else self._DEFAULT_BUDGET[self.strategy])
        # Warm-start directive from cross-session memory (set by /engage when a
        # prior mission on the same target left intel). Empty by default so a
        # first-ever scan behaves exactly as before.
        self.memory_note = ""
        self.findings: list = []
        self.leads: list = []           # unconfirmed candidate/static signals (not report findings)
        self._advisor_recs: list = []   # technique-advisor picks for this run (report orchestration view)
        self._codeintel_summary: dict = {}   # what code-intelligence recon fed the scan (orchestration view)
        self._stored_fps: set = set()   # CONFIRMED-finding fingerprints (auto-store dedup)
        self._lead_fps: set = set()      # lead fingerprints (deduped separately; never block a confirmed)
        # share the dedup set with the tool registry so the model's store_finding tool
        # deduplicates against what auto-store already recorded (AI stays additive).
        try:
            self.tools._stored_fps = self._stored_fps
        except Exception:
            pass
        self.current_phase = "init"
        self._recon_passes = 0   # counts entries into the recon phase (cycle labels)

        # HITL gate state (one session-level intrusive authorization)
        self.intrusive_state = None  # None | "approved" | "denied"
        self.pending_approval: dict = None
        self._approval_event = asyncio.Event()
        self._approval_result = None

        cfg = resolve_ai_config()
        self.provider = cfg["provider"]
        self.model = cfg["model"]
        self._has_key = bool(cfg["api_key"])
        # Client construction is best-effort: deterministic/manual strategies run
        # with NO AI at all, so a missing key must never stop the agent from being
        # built. low_ai/agentic get a credential preflight in /engage.
        self.client = None
        try:
            if cfg["provider"] == "openrouter":
                from openai import AsyncOpenAI
                self.client = AsyncOpenAI(base_url=cfg["base_url"] or DEFAULT_OPENROUTER_BASE,
                                          api_key=cfg["api_key"] or "missing")
            else:
                import anthropic
                kwargs = {}
                if cfg["api_key"]:
                    kwargs["api_key"] = cfg["api_key"]
                if cfg["base_url"]:
                    kwargs["base_url"] = cfg["base_url"]
                self.client = anthropic.AsyncAnthropic(**kwargs)
        except Exception:
            self.client = None

    # ── Q-079: the mission mode, bound to the dispatcher it governs ──────────
    #
    # WHY A PROPERTY. `ToolRegistry.execute` had no permission check of any kind because the
    # registry never received the mission mode -- a missing parameter, not an oversight. The mode
    # could not simply become a constructor argument: REQUIRED breaks 89 test construction sites,
    # DEFAULTED leaves the guard opt-in at every call site, and an opt-in guard is the
    # declaration-not-fact pattern this codebase has hit eleven times.
    #
    # The third option is the one taken: the registry LEARNS the mode from the object that already
    # knows it. `main.py` builds a `ToolRegistry` and hands it to `BBHAgent(..., mode=req.mode)`
    # three lines later, and this class ALREADY pushes mission configuration onto that registry
    # (`self.tools.stop_event`, `self.tools.zap_policy/zap_speed/zap_aggression` above). This is the
    # same push, so every product mission is bound without one call site changing.
    #
    # It is a PROPERTY rather than one line in `__init__` because `agent.mode` is REASSIGNED after
    # construction -- several helpers in `tests/test_permission_tiers.py` do exactly that -- and a
    # snapshot taken in `__init__` would then describe a mission the agent is no longer running.
    # A stale permission context is worse than none: it would refuse or admit on the wrong answer.
    # One writer, so it cannot be forgotten.
    @property
    def mode(self) -> str:
        return getattr(self, "_mode", "active")

    @mode.setter
    def mode(self, value: str) -> None:
        self._mode = value if value in ("passive", "active", "full") else "active"
        reg = getattr(self, "tools", None)
        if reg is not None:
            try:
                reg.mission_mode = self._mode
            except Exception:
                pass          # a registry stand-in that refuses attributes must not break a scan

    def _intrusive_authorized(self) -> bool:
        """Does this mission carry an operator authorization for STATE-CHANGING engines?

        ONE definition of the rule, read live. It is `_exec_internal`'s existing expression verbatim
        -- HITL approved, OR `auto_approve` (which `_run_tool`/`_exec_internal` convert into
        `intrusive_state = "approved"` before dispatching), OR `authenticated_scan`, the operator's
        explicit opt-in to state-changing AUTHENTICATED testing. Two copies of one policy is how one
        URL came to sit under two contradictory rules in Q-080, so `_exec_internal` calls this
        instead of restating it, and so does the dispatcher backstop in `ToolRegistry`.

        NOT `_run_tool`'s rule, which is narrower (approved gate only, no `authenticated_scan`
        clause). `_run_tool` keeps its own stricter check: widening a gate is as much a defect as
        narrowing one, and the dispatcher backstop must be the UNION of what the wrappers permit or
        it would refuse dispatches a wrapper legitimately made.
        """
        return (getattr(self, "intrusive_state", None) == "approved"
                or bool(getattr(self, "authenticated_scan", False)))

    # ── HITL approval API (called by main.py) ────────────────────
    def resolve_approval(self, approval_id: str, approved: bool) -> bool:
        if not self.pending_approval or self.pending_approval.get("id") != approval_id:
            return False
        self._approval_result = "approved" if approved else "denied"
        self._approval_event.set()
        return True

    async def _await_gate(self, tool_name: str, tool_input: dict):
        """Yield an approval_required event, block until the operator resolves it."""
        approval_id = uuid.uuid4().hex[:8]
        self.pending_approval = {"id": approval_id, "tool": tool_name, "input": tool_input}
        self._approval_event.clear()
        self._approval_result = None
        yield {"type": "approval_required", "approval_id": approval_id, "tool": tool_name,
               "input": tool_input, "phase": "probe",
               "prompt": f"Authorize INTRUSIVE probing for this engagement? First request: {tool_name}",
               "content": f"Awaiting operator authorization for INTRUSIVE probing (first request: {tool_name}). "
                          "Approve or deny in the gate modal — the run is paused until you do."}
        try:
            if APPROVAL_TIMEOUT > 0:
                await asyncio.wait_for(self._approval_event.wait(), timeout=APPROVAL_TIMEOUT)
            else:
                await self._approval_event.wait()
        except asyncio.TimeoutError:
            self._approval_result = "denied"
        self.intrusive_state = self._approval_result or "denied"
        self.pending_approval = None
        yield {"type": "approval_resolved", "approval_id": approval_id,
               "resolution": self.intrusive_state,
               "content": f"Intrusive gate {self.intrusive_state} — "
                          + ("resuming intrusive probes." if self.intrusive_state == "approved"
                             else "intrusive probes skipped; continuing with passive/active work.")}

    def _set_phase(self, tool_name: str):
        ph = PHASE_OF.get(tool_name)
        if ph and ph != self.current_phase:
            self.current_phase = ph
            return ph
        return None

    # ── shared tool handling (mode gate + HITL + execution) ──────
    async def _run_tool(self, tool_name: str, tool_input: dict, session_id: str):
        """Async generator: yields UI events, then a final {'_content': str} the
        caller feeds back to the model as the tool result."""
        perm = TOOL_PERMISSIONS.get(tool_name, PermissionLevel.ACTIVE)

        ph = self._set_phase(tool_name)
        if ph:
            yield {"type": "phase", "phase": ph}
            # Explicit recon-cycle label each time the run (re-)enters the recon
            # phase, so iterative recon reads as "cycle 1 → 2 → 3" instead of an
            # opaque phase bounce. Only when >1 cycle is configured (default run
            # is unchanged and emits none).
            # Only the agentic ReAct flow emits cycle banners here on recon re-entry;
            # deterministic/low_ai own their cycle banners in _execute_plan (avoids
            # a duplicate "Recon cycle 1" message).
            if ph == "recon" and self.recon_cycles > 1 and self.strategy == "agentic":
                self._recon_passes += 1
                n = min(self._recon_passes, self.recon_cycles)
                yield {"type": "cycle", "cycle": n, "total": self.recon_cycles,
                       "content": f"Recon cycle {n} of {self.recon_cycles}: enumerate, then learn "
                                  "from newly discovered in-scope assets before the next pass."}

        # Mode enforcement: passive mode forbids active + intrusive.
        if self.mode == "passive" and perm != PermissionLevel.PASSIVE:
            msg = f"{tool_name} blocked: PASSIVE mode permits passive tools only."
            yield {"type": "scope_block", "tool": tool_name, "error": msg}
            yield {"_content": json.dumps({"success": False, "error": msg})}
            return

        # HITL gate for intrusive tools.
        if perm == PermissionLevel.INTRUSIVE:
            if self.auto_approve and self.intrusive_state is None:
                self.intrusive_state = "approved"
                yield {"type": "info", "content": "Intrusive phase pre-authorized (autonomous run)."}
            if self.intrusive_state is None:
                async for ev in self._await_gate(tool_name, tool_input):
                    yield ev
            if self.intrusive_state == "denied":
                msg = f"{tool_name} skipped: operator denied intrusive probing."
                yield {"type": "scope_block", "tool": tool_name, "error": msg}
                yield {"_content": json.dumps({"success": False, "error": msg})}
                return

        # `logged_at_dispatch` (Q-061): from here on the events describe a dispatch that
        # `ToolRegistry.execute` records itself, at the one place the dispatch is known. They are
        # still yielded -- the live UI feed is built from them -- but `main._drive_mission` does NOT
        # persist a tagged event, or every tool that goes through this wrapper would be counted
        # twice in the per-tool ledger. The gate refusals ABOVE carry no tag: `execute` is never
        # reached for those, so this wrapper is their only possible witness.
        yield {"type": "tool_call", "tool": tool_name, "input": tool_input, "permission": perm.value,
               "logged_at_dispatch": True}
        result = await self.tools.execute(tool_name, tool_input, session_id)
        self._stamp_dispatch(tool_name, result)

        if result.error:
            etype = "scope_block" if "SCOPE BLOCK" in result.error else "tool_error"
            yield {"type": etype, "tool": tool_name, "error": result.error,
                   "logged_at_dispatch": True}
        else:
            # Count real results only: some tools (e.g. run_sqlmap on a no-confirmation
            # pass) return a severity-less data-carrier {"vulnerable": False, log_tail...}
            # purely to preserve the tool log. It is explicitly NOT a finding, so it must
            # not inflate the ledger's findings count (that produced the "9 findings /
            # No SQLi confirmed" contradiction the integrity check now guards against).
            _real = sum(1 for f in result.findings
                        if not (isinstance(f, dict) and f.get("vulnerable") is False))
            yield {"type": "tool_result", "tool": tool_name, "output": result.output,
                   "count": _real, "logged_at_dispatch": True}

        if tool_name == "store_finding" and not result.error:
            # A model-authored finding (agentic). Dedup by fingerprint against what
            # auto-store already recorded so the AI layer is purely ADDITIVE — it can
            # add business-logic findings but never double-count a proof-based one that
            # auto-store already landed (tools._store_finding skips the DB write for a dup).
            import memory as memory_mod
            fin = result.findings[0] if result.findings else dict(tool_input)
            fp = memory_mod.finding_fp(fin)
            if fp not in self._stored_fps:
                self._stored_fps.add(fp)
                self.findings.append(fin)
                yield {"type": "finding", "finding": fin}

        # ALWAYS auto-store confirmed findings from the proof-based probes — regardless of
        # strategy. Confirmation is a deterministic oracle (proof), never the model's
        # opinion, so these MUST land even in agentic mode: relying on the model to store
        # them made agentic silently UNDERCOUNT (a run confirmed a SQLi + 19 leads but the
        # report showed neither because the model never called store_finding). The model's
        # own store_finding stays additive and is deduped against the same fingerprint set.
        if not result.error and tool_name in _AUTO_STORE_TOOLS:
            async for ev in self._auto_store(result):
                yield ev

        content = json.dumps({
            "success": result.success, "output": result.output,
            "findings": result.findings[:25], "error": result.error,
        })[:3500]
        yield {"_content": content}

    async def _exec_internal(self, tool_name: str, tool_input: dict, session_id: str):
        """Central GATED dispatch for the internal (non-model) tool calls the auth artery + service sweep
        make directly. Enforces the SAME passive-mode + intrusive-HITL gates as _run_tool so an internal
        caller can NEVER bypass them (#2 — previously these called self.tools.execute() straight through,
        skipping both gates). Scope is enforced inside tools.execute(). A blocked call returns a
        ran:false ToolResult with no findings (never raises), so callers keep their .findings handling."""
        import tools as _tm
        perm = TOOL_PERMISSIONS.get(tool_name, PermissionLevel.ACTIVE)
        # passive mode forbids any non-passive LIVE contact
        if self.mode == "passive" and perm != PermissionLevel.PASSIVE:
            return _tm.ToolResult(tool_name, "", True,
                                  json.dumps({"ran": False, "blocked": "passive mode: %s not permitted" % tool_name}), [])
        # intrusive (state-changing) tools require an explicit operator authorization, which is ANY of:
        #   * the intrusive HITL gate was approved (operator said yes in the modal),
        #   * auto_approve (an autonomous run pre-authorizes the intrusive phase), or
        #   * authenticated_scan — the operator's explicit opt-in to state-changing AUTHENTICATED testing,
        #     which the artery's bounded, self-cleaning writes (create-object / authz-write) fall under
        #     (per the call-site design contract). This is authorization, NOT a bypass: passive mode + scope
        #     are still enforced above/inside, so an intrusive tool can never fire in passive or off-scope.
        if perm == PermissionLevel.INTRUSIVE:
            if self.intrusive_state is None and self.auto_approve:
                self.intrusive_state = "approved"
            # Q-079: the same expression this line always was, named once in `_intrusive_authorized`
            # so the dispatcher backstop and this wrapper cannot drift into two different rules.
            authorized = self._intrusive_authorized()
            if not authorized:
                return _tm.ToolResult(tool_name, "", True,
                                      json.dumps({"ran": False, "blocked": "intrusive tool not authorized (HITL)"}), [])
        # LOGGING MOVED TO THE DISPATCH ITSELF (Q-061). This method used to write its own tool_call /
        # tool_result / tool_error rows, because at the time `_run_tool` was the only producer and all
        # TWELVE internally-dispatched engines were invisible in the report's "tools executed" section
        # (verified live: header-trust executed against 6 targets on mission 5ebd704d and appeared
        # nowhere in the ledger). That fixed one wrapper and left the other ten `tools.execute` call
        # sites unlogged, which is how a mission that acquired and VERIFIED two persona sessions still
        # reported `acquire_session` as never dispatched.
        #
        # `ToolRegistry.execute` now records every dispatch, so writing here as well would double-count
        # exactly the engines this comment was added to make visible. The gates above stay: a call this
        # method REFUSES never reaches execute and correctly leaves no row, because it made no dispatch.
        res = await self.tools.execute(tool_name, tool_input, session_id)
        self._stamp_dispatch(tool_name, res)
        return res

    @staticmethod
    def _stamp_dispatch(tool_name: str, result) -> None:
        """Q-064: BIND THE DISPATCH NAME onto every finding, here, at the boundary that knows it.

        THE DEFECT. Two records describe one mission and they were written in two vocabularies. The
        tool ledger keys on the DISPATCH name (`ToolRegistry.execute`'s `tool_name`, e.g.
        `confirm_browser_persona_bola`); a finding carries the ENGINE name, bound by
        `ToolResult.__post_init__` from the name the engine gives itself (`browser_persona_bola`).
        MEASURED over `TOOL_PERMISSIONS`: only 15 of 111 engines use the same string for both, so
        `report.ledger_finding_disagreement()` accused 95 engines of producing findings the ledger
        never recorded -- on missions where they plainly ran -- and its useful half, `productive`,
        could only ever name the other 15. On the live mission 57cc3b49 it flagged BOTH findings and
        reported `productive: []`.

        WHY NOT NORMALISE IN THE CHECKER. Besides being the forbidden move (loosening a check to
        stop it complaining masks the real `produced_but_unlogged` case), it cannot work: the map is
        many-to-one. `run_sqli`, `run_path_sqli` and `run_sqli_structural` ALL emit `sqli`, so no
        rule recovers the ledger row from the finding. `run_default_creds` ->
        `default_credentials` is an expansion, not a truncation. A hardcoded table would be a third
        vocabulary that rots like the two it joins.

        WHY HERE. Same argument as the `engine` stamp one layer in, pointed the other way. `engine`
        must be bound in the ToolResult constructor because engines call each other directly and the
        INNERMOST producer is the honest answer. `dispatch` is the opposite: only the OUTERMOST call
        is what the ledger recorded, and the two agent-side wrappers (`_run_tool`, `_exec_internal`)
        are where a dispatch name exists. Every one of the 13 sites in `agent.py` that persists a
        `ToolResult`'s findings reads them off a result that came through one of these two, so one
        stamp at the boundary covers all of them -- and a 14th site added later inherits it instead
        of being a 14th chance to forget.

        THE RULES, each with a negative control in tests/test_dispatch_provenance.py:
          * A blank/None dispatch name stamps NOTHING. `x or DEFAULT` where empty is a real input
            has bitten this codebase repeatedly; `dispatch: ""` would read as a dispatch that is not
            in any ledger, i.e. it would MANUFACTURE the alarm this ticket removes.
          * A finding that already names a dispatch KEEPS it -- the first dispatch that produced it
            is the one the ledger recorded, and a later carrier must not overwrite that.
          * Non-dict entries are skipped, never coerced: several engines put raw URLs in `findings`.
        """
        name = tool_name.strip() if isinstance(tool_name, str) else ""
        if not name or result is None:
            return                                    # "" is a real input -- record nothing, not a lie
        for f in (getattr(result, "findings", None) or []):
            if not isinstance(f, dict):
                continue
            existing = f.get("dispatch")
            if isinstance(existing, str) and existing.strip():
                continue
            f["dispatch"] = name

    def _is_confirmed(self, tool: str, f: dict) -> bool:
        """A finding is report-worthy CONFIRMED only when the probe says so. The
        native tools grade every finding (confirmed / candidate / possible /
        probable); we trust that grade. A tool that confirms by construction but
        emits no grade (nuclei/zap/takeover) is treated as confirmed; anything
        graded weaker — reflection candidates, IDOR signals, static JS review — is
        a LEAD, never a confirmed report finding.

        HARD GUARD: a native-graded "confirmed" with NO proof at all (no evidence,
        reason, or detail) is downgraded to a lead. Evidence is what makes a
        confirmed finding trustworthy; a proofless "confirmed" is the exact shape
        of the round-9 reflected-XSS false positive, so we refuse to promote it."""
        c = str(f.get("confidence", "")).strip().lower()
        if c == "confirmed":
            proof = f.get("evidence") or f.get("reason") or f.get("detail")
            return bool(str(proof).strip()) if proof is not None else False
        if c:                                 # candidate / possible / probable
            return False
        return tool in _CONFIRMED_BY_TOOL      # no grade + confirmatory tool

    async def _auto_store(self, result):
        """Route finding-shaped probe results (deterministic/low_ai) when no model
        drives the scan: CONFIRMED → /findings + report; weaker signals → Leads.
        Deduped by fingerprint. `severity` is the finding discriminator; the title
        is derived from whichever label key the tool used."""
        import memory as memory_mod
        for f in (result.findings or []):
            if not isinstance(f, dict) or not f.get("severity"):
                continue                      # data item, not a finding
            title = (f.get("title") or f.get("name") or f.get("issue")
                     or f.get("type") or f.get("detail") or f"{result.tool} finding")
            f = dict(f)
            f["title"] = str(title)[:140]
            f["target"] = f.get("target") or f.get("url") or result.target or ""
            f["severity"] = str(f.get("severity") or "info").lower()
            fp = memory_mod.finding_fp(f)
            if fp in self._stored_fps:
                continue
            if self._is_confirmed(result.tool, f):
                # only a CONFIRMED finding claims the fingerprint slot — a non-confirmed lead must NEVER
                # block a later confirmed finding of the same fp (that silently dropped real findings).
                self._stored_fps.add(fp)
                if self.mission_id:
                    f["id"] = db.add_finding(self.mission_id, f)
                self.findings.append(f)
                yield {"type": "finding", "finding": f}
            else:
                if fp in self._lead_fps:
                    continue
                self._lead_fps.add(fp)
                f.setdefault("confidence", "candidate")
                self.leads.append(f)
                yield {"type": "lead", "lead": f}

    async def _promote_leads(self, session_id: str):
        """Convert candidate leads to CONFIRMED findings by re-testing them with a
        confirmatory oracle they didn't already get. Currently: XSS-class candidate
        leads (reflection/dalfox/js-review signals) are replayed through the headless
        browser executor — a lead that now fires alert() becomes a browser-confirmed
        finding (with PoC). Truth-first: promotion requires real execution, never the
        signal alone; nothing is promoted when no browser is available."""
        import tools as _t
        from urllib.parse import urlparse, parse_qs
        if not self.leads or _t.xss_confirm_status() is False:
            return
        # one representative parameterized target per path among XSS-class leads
        targets = {}
        for lead in self.leads:
            cwe, ttl = str(lead.get("cwe") or ""), str(lead.get("title") or "").lower()
            if not ("79" in cwe or "xss" in ttl or "cross-site script" in ttl):
                continue
            tgt = str(lead.get("target") or "")
            if tgt and "?" in tgt and self.scope.validate(tgt)[0]:
                targets.setdefault(urlparse(tgt).path, tgt)
        if not targets:
            return
        promoted_paths = set()
        for tgt in rank_targets_for_budget(list(targets.values()))[:15]:  # bounded browser sweep
            if self.stop_event.is_set():
                break
            params = list(parse_qs(urlparse(tgt).query).keys())
            if not params:
                continue
            try:
                confs = await self.tools._xss_execute(tgt, params)
            except Exception:
                confs = []
            for f in confs:
                f.setdefault("found_by", "promoted from candidate lead (browser-confirmed)")
                if self.mission_id:
                    f["id"] = db.add_finding(self.mission_id, f)
                self.findings.append(f)
                promoted_paths.add(urlparse(str(f.get("target") or tgt)).path)
                yield {"type": "finding", "finding": f}
        # drop the now-redundant XSS-class leads on any promoted path
        if promoted_paths:
            before = len(self.leads)
            self.leads = [l for l in self.leads if not (
                ("79" in str(l.get("cwe") or "") or "xss" in str(l.get("title") or "").lower())
                and urlparse(str(l.get("target") or "")).path in promoted_paths)]
            dropped = before - len(self.leads)
            if dropped:
                yield {"type": "info", "content": f"Lead promotion: {dropped} candidate lead(s) "
                       "browser-confirmed and promoted to findings."}

    async def _identify_dumped_hashes(self, session_id: str):
        """Q-050 · WSTG-CRYP-04. `run_hash_id` had NO deterministic trigger: 0 dispatches in 154
        missions, selectable only if an LLM picked it out of `CLAUDE_TOOLS`, while
        `wstg_catalog.PARTIAL` said "run_hash_id flags weak primitives". It flagged nothing.

        The trigger is an OBSERVED value, never an invented one: hash material the target's own
        responses disclosed, read out of the mission's captured exchanges. The precondition is
        deliberately narrow, and it is narrow because it was MEASURED rather than guessed --
        see `docs/handoff/deterministic_reach.md` §3."""
        if not self.mission_id:
            return
        try:
            exchanges = db.get_exchanges(self.mission_id)
        except Exception as e:
            self.tools._swallow(e, "hash_id.get_exchanges", str(self.mission_id))
            return
        hits = _disclosed_hashes(exchanges)
        if not hits:
            return
        async for ev in self._run_tool("run_hash_id", {"hashes": [h for h, _ in hits]}, session_id):
            if "_content" not in ev:
                yield ev

    @staticmethod
    def _dom_class_match(family: str, finding: dict) -> bool:
        blob = (str(finding.get("title") or "") + " " + str(finding.get("family") or "")
                + " " + " ".join(str(x) for x in (finding.get("tags") or []))).lower()
        if family == "prototype_pollution":
            return "prototype pollution" in blob or "proto" in blob
        if family == "csti":
            return "template injection" in blob or "csti" in blob or "angular" in blob
        if family in ("dom_xss", "eval_sink"):
            return ("dom" in blob and "xss" in blob) or "dom-based" in blob or "client-side" in blob and "xss" in blob
        return False

    async def _validate_candidates(self, session_id: str):
        """Safety wrapper: a validator bug must NEVER fail the mission — candidate validation is a
        late enhancement pass, so any unexpected error degrades to a visible note and the run
        completes (findings/leads already gathered are preserved)."""
        try:
            async for ev in self._validate_candidates_impl(session_id):
                yield ev
        except Exception as _e:
            yield {"type": "info", "content": "Candidate validation degraded (%s) — mission continues; "
                   "leads preserved." % str(_e)[:100]}

    async def _validate_candidates_impl(self, session_id: str):
        """General, target-agnostic candidate-validation pipeline. Normalizes every remaining
        testable lead, routes it to a real validator, and finishes it in an EXPLICIT terminal
        state with a per-candidate assurance record {candidate, family, validator, attempted,
        oracle, result, evidence}. False-finding guard: DOM-class leads found only in library
        source are retested against the APPLICATION PAGES and confirmed ONLY by a runtime canary."""
        import candidate_pipeline as cp
        import tools as _t
        recs = self._candidate_assurance
        # record the reflected-XSS leads the promoter already browser-confirmed (one table for all)
        for f in self.findings:
            if "promoted from candidate lead" in str(f.get("found_by") or ""):
                recs.append({"candidate": f.get("title"), "family": "reflected_xss", "validator": "run_xss",
                             "attempted": True, "oracle": "browser alert() executed",
                             "result": cp.CONFIRMED, "evidence": str(f.get("evidence") or "")[:160],
                             "target": f.get("target")})
        if not self.leads:
            if recs:
                yield {"type": "info", "content": "Candidate validation: %d confirmed via promotion." % len(recs)}
            return
        app_pages = rank_targets_for_budget(
            cp.application_pages(getattr(self.tools, "urls", []) or []))[:8]
        browser_ok = _t.xss_confirm_status() is not False and bool(getattr(_t, "_chrome_path", lambda: None)())

        # ── one browser DOM audit sweep over the application pages, reused by every DOM family ──
        dom_findings, dom_ran = [], False
        dom_needed = any(cp.canonical_family(l) in ("prototype_pollution", "csti", "dom_xss", "eval_sink") for l in self.leads)
        if dom_needed and app_pages and browser_ok and not self.stop_event.is_set():
            for page in app_pages:
                if self.stop_event.is_set():
                    break
                try:
                    r = await self.tools.execute("run_dom_audit", {"url": page}, session_id)
                except Exception as _apolaki_swallowed_1127:
                    self.tools._swallow(_apolaki_swallowed_1127, 'agent:_validate_candidates_impl:1127', "")
                    continue
                # Q-064: the THIRD store path, found by the ratchet in tests/test_dispatch_provenance.py
                # rather than by the ticket. This is the one dispatch in agent.py that neither wrapper
                # covers, and its findings are persisted below as promoted candidates -- so without
                # this line a promoted DOM finding reaches the report carrying `engine: dom_audit`
                # against a ledger row keyed `run_dom_audit`, and the false alarm survives the fix in
                # exactly the place nobody would look for it.
                self._stamp_dispatch("run_dom_audit", r)
                dom_ran = True
                for f in (r.findings or []):
                    f.setdefault("target", page)
                    dom_findings.append(f)

        counts = {cp.CONFIRMED: 0, cp.DISMISSED: 0, cp.BLOCKED: 0, cp.SCHEDULED: 0, cp.UNSUPPORTED: 0}
        keep, confirmed_titles = [], set()
        for lead in list(self.leads):
            if self.stop_event.is_set():
                keep.append(lead); continue
            n = cp.normalize(lead)
            fam, validator = n["family"], n["validator"]
            rec = {"candidate": lead.get("title"), "family": fam, "validator": validator,
                   "attempted": False, "oracle": n["oracle"], "result": None, "evidence": "",
                   "target": n["raw_target"], "missing_prerequisite": None}
            state, promoted = None, None

            # dedupe: a generic advisor lead ("Technique to test — X") whose vuln a scan probe
            # ALREADY confirmed is CONFIRMED-by-dedupe, never re-dismissed.
            already = next((f for f in self.findings if str(f.get("confidence")) == "confirmed"
                            and (cp.canonical_family(f) == fam
                                 or (fam not in ("unknown", "") and fam in str(f.get("family") or "").lower()))), None)
            if already:
                # DEDUPLICATED, not independently executed: this lead's vulnerability is already
                # confirmed by a primary probe's finding. Reference that finding + its REAL oracle so
                # the row can never read "validator empty / no validator implemented yet / confirmed"
                # (the self-contradiction CHAD final-audit defect #4 flagged).
                _ref = str(already.get("title") or "")[:100]
                _orc = str(already.get("success_oracle") or "").strip()
                rec["deduplicated"] = True
                rec["attempted"] = False   # confirmed by the owning finding, NOT re-run as its own candidate
                state = cp.CONFIRMED
                rec["result_ref"] = _ref
                rec["validator"] = "deduplicated → primary finding"
                rec["oracle"] = ("confirmed by finding '%s'%s" %
                                 (_ref, (" via its success oracle: " + _orc) if _orc else ""))
                rec["evidence"] = ("deduplicated: the same vulnerability is already confirmed by finding '%s' "
                                   "(not re-executed as an independent candidate)." % _ref)
            elif fam in ("prototype_pollution", "csti", "dom_xss", "eval_sink"):
                if not browser_ok:
                    state, rec["missing_prerequisite"] = cp.BLOCKED, "headless browser (Chromium) unavailable"
                elif not app_pages:
                    state, rec["missing_prerequisite"] = cp.BLOCKED, "no in-scope application page to test the library against"
                else:
                    rec["attempted"] = True
                    hit = next((f for f in dom_findings if self._dom_class_match(fam, f)), None)
                    if hit:
                        promoted = dict(hit); state = cp.CONFIRMED
                        rec["evidence"] = "runtime canary fired on %s: %s" % (hit.get("target"), str(hit.get("evidence") or hit.get("title"))[:120])
                    else:
                        state = cp.DISMISSED
                        rec["evidence"] = "canary never fired across %d application page(s) — library-only match, not a runtime app vuln" % len(app_pages)

            elif fam == "reflected_xss":
                # parameterized reflected XSS is browser-confirmed earlier by _promote_leads; here we
                # confirm a lead that carries its own parameterized point, else dismiss after that sweep.
                rec["attempted"] = True
                if not browser_ok:
                    state, rec["missing_prerequisite"] = cp.BLOCKED, "headless browser (Chromium) unavailable"
                else:
                    from urllib.parse import urlparse as _up, parse_qs as _pq
                    confs = []
                    if "?" in n["raw_target"]:
                        try:
                            confs = await self.tools._xss_execute(n["raw_target"], list(_pq(_up(n["raw_target"]).query).keys()))
                        except Exception:
                            confs = []
                    if confs:
                        promoted = confs[0]; state = cp.CONFIRMED
                        rec["evidence"] = "browser alert() executed on " + str(n["raw_target"])[:80]
                    else:
                        state = cp.DISMISSED
                        rec["evidence"] = "browser XSS sweep found no reflected execution on a parameterized point"

            elif fam == "exposed_credentials":
                cred_f = next((f for f in self.findings if "credential" in str(f.get("title") or "").lower()
                               and str(f.get("severity")) in ("high", "critical")), None)
                rec["attempted"] = True
                if cred_f:
                    state = cp.CONFIRMED; rec["result_ref"] = cred_f.get("title")
                    rec["evidence"] = "harvested credential yielded a valid session (see: %s)" % str(cred_f.get("title"))[:80]
                else:
                    state = cp.DISMISSED
                    rec["evidence"] = "harvested value did not produce an authenticated session"

            elif fam == "exposed_files":
                rec["attempted"] = True
                try:
                    r = await self._exec_internal("run_exposure", {"base_url": n["raw_target"] or self._primary_base()}, session_id)  # gated (#2)
                    if r.findings:
                        promoted = r.findings[0]; state = cp.CONFIRMED
                        rec["evidence"] = "content/type signature matched: " + str(r.output or "")[:120]
                    elif "SCOPE BLOCK" in str(r.error or ""):
                        state, rec["missing_prerequisite"] = cp.BLOCKED, "target out of scope"
                    else:
                        state = cp.DISMISSED; rec["evidence"] = "no signature match (soft 200/404, not a real exposed file)"
                except Exception as e:
                    state = cp.DISMISSED; rec["evidence"] = "validator error: %s" % str(e)[:80]

            elif fam == "stored_xss":
                if not browser_ok:
                    state, rec["missing_prerequisite"] = cp.BLOCKED, "headless browser (Chromium) unavailable"
                else:
                    rec["attempted"] = True
                    try:
                        r = await self._exec_internal("run_stored_xss", {"url": n["raw_target"] or self._primary_base()}, session_id)  # gated (#2)
                        if r.findings:
                            promoted = r.findings[0]; state = cp.CONFIRMED
                            rec["evidence"] = "canary stored + re-read + executed: " + str(r.output or "")[:100]
                        else:
                            state = cp.DISMISSED; rec["evidence"] = "canary not reflected/executed on any display surface"
                    except Exception as e:
                        state = cp.DISMISSED; rec["evidence"] = "validator error: %s" % str(e)[:80]

            elif fam == "bfla":
                has_session = bool(getattr(self.tools, "session_headers", None)) or bool(getattr(self, "_auth_artery", {}).get("ran"))
                if not has_session:
                    state, rec["missing_prerequisite"] = cp.BLOCKED, "authenticated low-privilege session (run authenticated scan)"
                else:
                    rec["attempted"] = True
                    try:
                        r = await self._exec_internal("run_bfla", {"url": n["raw_target"] or self._primary_base()}, session_id)  # gated (#2)
                        if r.findings:
                            promoted = r.findings[0]; state = cp.CONFIRMED
                            rec["evidence"] = "low-priv session performed a prohibited action: " + str(r.output or "")[:100]
                        else:
                            state = cp.DISMISSED; rec["evidence"] = "privileged control correctly denied the low-priv session"
                    except Exception as e:
                        state = cp.DISMISSED; rec["evidence"] = "validator error: %s" % str(e)[:80]

            elif fam == "jsonp":
                rec["attempted"] = True
                try:
                    # GATED (#2 / Q-052). This was the ONE branch in this chain still calling
                    # `self.tools.execute` directly. That path enforces scope and nothing else -- no
                    # passive-mode check, no intrusive HITL -- so a PASSIVE mission fetched a live
                    # callback endpoint, which is exactly the contact `agent.py`'s passive branch
                    # refuses served-JS harvesting to avoid. Its three siblings above (run_exposure,
                    # run_stored_xss, run_bfla) were already routed through `_exec_internal`; this
                    # one was missed, and nothing in the suite could see the difference.
                    r = await self._exec_internal("run_jsonp", {"url": n["raw_target"] or self._primary_base()}, session_id)
                    _refused = _gate_refusal(r)
                    if r.findings:
                        promoted = r.findings[0]; state = cp.CONFIRMED
                        rec["evidence"] = str(r.output or "")[:120]
                    elif "SCOPE BLOCK" in str(r.error or ""):
                        state, rec["missing_prerequisite"] = cp.BLOCKED, "target out of scope"
                    elif _refused:
                        # The gate refused, so this candidate was never tested. Booking it DISMISSED
                        # would convert the safety gate into a silent false negative.
                        rec["attempted"] = False
                        state, rec["missing_prerequisite"] = cp.BLOCKED, _refused
                    else:
                        state = cp.DISMISSED; rec["evidence"] = str(r.output or "no executable JSONP wrapper with sensitive data")[:120]
                except Exception as e:
                    state = cp.DISMISSED; rec["evidence"] = "validator error: %s" % str(e)[:80]

            elif fam == "weak_random":
                blob = (str(lead.get("evidence") or "") + " " + str(lead.get("title") or "")
                        + " " + " ".join(str(x) for x in (lead.get("tags") or []))).lower()
                rec["attempted"] = True
                if any(k in blob for k in ("token", "session", "csrf", "password", "reset", "secret", "nonce", "otp", "id=")):
                    state, rec["missing_prerequisite"] = cp.BLOCKED, "manual trace: confirm the random output controls the named security value"
                    rec["evidence"] = "security-relevant sink suspected — needs runtime trace to confirm impact"
                else:
                    state = cp.DISMISSED
                    rec["evidence"] = "downgraded to informational — Math.random with no security-relevant sink is not a weakness"

            elif fam == "dev_comments":
                import re as _re
                blob = str(lead.get("evidence") or "") + " " + str(lead.get("target") or "")
                base = self._primary_base()
                paths = rank_targets_for_budget(
                    sorted(set(_re.findall(r"/[A-Za-z0-9_\-/.]{2,60}", blob))))[:8]
                rec["attempted"] = True
                state = cp.DISMISSED
                added = 0
                urls = getattr(self.tools, "urls", None)
                for p in paths:
                    if base and isinstance(urls, list):
                        url = base.rstrip("/") + p
                        if self.scope.validate(url)[0] and url not in urls:
                            urls.append(url)       # CONSUMED: folds into surface -> graph/report/memory + next-scan warm-start
                            added += 1
                rec["evidence"] = ("comment is not itself a vulnerability; %d derived in-scope route(s) folded into the "
                                   "surface (graph + memory) for validation" % added) if added else \
                                  "comment carried no new in-scope derived route"

            elif fam in cp.PRIMARY_HANDLED:
                # not unsupported: a dedicated primary-scan probe OWNS this family's confirmation and
                # ran this engagement — the candidate lead is deferred to it, not left untested.
                rec["attempted"] = True
                state = cp.DISMISSED
                rec["evidence"] = ("deferred to %s — that dedicated primary-scan probe owns this family's "
                                   "confirmation and ran this engagement; the candidate pipeline does not "
                                   "re-run it" % cp.PRIMARY_HANDLED[fam])

            else:
                state = cp.UNSUPPORTED
                rec["evidence"] = "no validator implemented for family '%s' yet (explicit coverage debt)" % fam

            rec["result"] = state
            counts[state] = counts.get(state, 0) + 1
            recs.append(rec)
            if state == cp.CONFIRMED and promoted:
                promoted.setdefault("found_by", "candidate-validation pipeline (%s, %s)" % (validator, rec["oracle"]))
                promoted.setdefault("confidence", "confirmed")
                if self.mission_id:
                    try:
                        promoted["id"] = db.add_finding(self.mission_id, promoted)
                    except Exception as _apolaki_swallowed_1345:
                        self.tools._swallow(_apolaki_swallowed_1345, 'agent:_validate_candidates_impl:1345', "")
                        pass
                self.findings.append(promoted)
                confirmed_titles.add(str(lead.get("title")))
                yield {"type": "finding", "finding": promoted}
            elif state in (cp.CONFIRMED, cp.DISMISSED):
                pass                                   # terminal, non-promoting -> drop the lead
            else:
                keep.append(lead)                      # blocked / scheduled / unsupported -> keep visible
        self.leads = keep
        self._candidate_validation_counts = counts
        yield {"type": "info", "content": (
            "Candidate validation: %d confirmed, %d dismissed, %d blocked, %d unsupported "
            "(every testable lead reached a terminal state)."
            % (counts[cp.CONFIRMED], counts[cp.DISMISSED], counts[cp.BLOCKED], counts[cp.UNSUPPORTED]))}

    async def _ai_business_logic_leads(self, session_id: str):
        """Additive AI enhancement layer: when an AI strategy is selected, run ONE bounded
        end-of-scan pass over the surface + confirmed findings and propose BUSINESS-LOGIC
        test hypotheses (workflow/step-skipping, price/quantity manipulation, IDOR/BOLA id
        sequences, coupon/referral abuse, auth-flow gaps, mass-assignment, races) that the
        deterministic probes can't reason about. Truth-first: these are candidate LEADS the
        operator must verify — the model hunts and hypothesizes, it never confirms. No-op in
        deterministic mode (AI is an opt-in enhancement, never the engine)."""
        if self.strategy not in ("low_ai", "agentic") or not self._ai_usable() or not self._budget_left():
            return
        import surface as surface_mod
        _surface_urls = getattr(self.tools, "urls", []) or []
        inv = surface_mod.build_inventory(_surface_urls, cap=max(1000, len(_surface_urls)))
        inv = sorted(inv, key=lambda ep: target_security_value(
            ep.get("example") or ("https://" + ep.get("host", "") + ep.get("path", "/"))),
                     reverse=True)[:40]
        if not inv:
            return
        surf = "\n".join(f"- {e['host']}{e['path']}"
                         + (f"  params={','.join(e.get('params') or [])}" if e.get("params") else "")
                         for e in inv)
        finds = "; ".join(f.get("title", "") for f in self.findings[:15]) or "none confirmed yet"
        system = ("You are a senior web/API pentester. From the attack surface and confirmed findings, propose "
                  "concrete BUSINESS-LOGIC test hypotheses a human should try that automated scanners miss — "
                  "workflow/step-skipping, price/quantity/negative-value manipulation, IDOR/BOLA id sequences, "
                  "coupon/referral/loyalty abuse, auth-flow and password-reset gaps, mass-assignment, race "
                  "conditions. Output 3-8 lines, each EXACTLY: '<endpoint or flow> | <hypothesis> | <how to test>'. "
                  "Hypotheses only — never claim anything is confirmed.")
        user = f"Attack surface:\n{surf}\n\nConfirmed findings: {finds}"
        try:
            txt = await self._ai_text(system, user, max_tokens=650)
        except Exception:
            return
        tgt0 = (getattr(self.tools, "recon", {}) or {}).get("target") or ""
        n = 0
        for raw in (txt or "").splitlines():
            line = raw.strip().lstrip("-*0123456789.) ")
            if line.count("|") < 1 or len(line) < 16:
                continue
            parts = [p.strip() for p in line.split("|")]
            where, hyp = parts[0][:80], (parts[1] if len(parts) > 1 else "")
            how = parts[2] if len(parts) > 2 else (parts[1] if len(parts) > 1 else "")
            lead = {"severity": "info", "confidence": "candidate", "family": "business_logic",
                    "tags": ["business-logic", "ai-hypothesis"], "cwe": "CWE-840",
                    "target": where if where.startswith("http") else tgt0,
                    "title": f"Business-logic hypothesis — {(hyp or where)[:90]}",
                    "evidence": f"{where}: {hyp}".strip(": "),
                    "reproduction_steps": [how] if how else [],
                    "analyst_notes": "AI-proposed hunt lead (business logic) — verify manually; not a confirmed vulnerability."}
            self.leads.append(lead)
            yield {"type": "lead", "lead": lead}
            n += 1
            if n >= 8:
                break

    def _primary_base(self) -> str:
        try:
            b = self.scope.base_urls()
            return b[0] if b else ""
        except Exception:
            return ""

    async def _recon_code_intelligence(self, session_id: str):
        """Deterministic code-intelligence recon. Black-box harvest the primary target's served JS,
        fold the mined API endpoints into the scan SURFACE (so the planner actually probes them), and
        raise the unlinked/sensitive routes + business-logic hypotheses as LEADS. Runs for EVERY
        strategy, before the scan, so the harvest drives the run instead of sitting in a dashboard."""
        import asyncio
        import codeintel
        if self.mode == "passive":     # SAFETY (#1): harvesting served JS is LIVE target contact — never in passive
            return
        base = self._primary_base()
        if not base:
            return
        try:
            h = await asyncio.to_thread(codeintel.harvest, base)
        except Exception:
            return
        if not isinstance(h, dict):
            return
        # 1) fold mined endpoints into the surface the planner probes
        # Q-118. THE BYPASS IS GONE. This built its own append loop and then retrofitted ONE of
        # `_add_urls`'s guarantees (the session-kill quarantine), leaving the other three off: no
        # `clean_url`, no `scope.validate`, and -- once Q-122 landed -- no entity-split repair. A
        # mined endpoint therefore entered the surface every other reader treats as quarantine-clean
        # without ever being checked against the operator's scope, which on a bug-bounty engagement
        # is the one guarantee that matters most.
        #
        # The local session-kill check is dropped rather than kept: `_add_urls` handles that case
        # BETTER, quarantining the URL into `session_kill_urls` where `_run_session_lifecycle` can
        # still use it, where this loop discarded it outright. The cost is the `_swallow` row that
        # named code-intelligence as the source; the guarantee is worth more than the attribution.
        _mined = [(base.rstrip("/") + ep if str(ep).startswith("/") else str(ep))
                  for ep in (h.get("endpoints") or [])]
        before = len(getattr(self.tools, "urls", []) or [])
        if _mined:
            self.tools._add_urls(_mined)
        added = len(getattr(self.tools, "urls", []) or []) - before
        # 2) sensitive / unlinked routes -> attack-surface leads
        ns = 0
        for r in (h.get("sensitive_routes") or [])[:12]:
            lead = {"severity": "info", "confidence": "candidate", "family": "attack_surface",
                    "tags": ["code-intel", "unlinked-route"], "cwe": "CWE-200", "target": base,
                    "title": "Unlinked/sensitive route mined from JS — %s" % str(r)[:80],
                    "evidence": "Code-intelligence harvest found client route '%s' in a served JS bundle." % r,
                    "reproduction_steps": ["Probe '%s' on %s for privileged functionality or missing authorization." % (r, base)],
                    "analyst_notes": "Code-intelligence recon lead — sensitive surface to test for access control."}
            self.leads.append(lead)
            yield {"type": "lead", "lead": lead}
            ns += 1
        # 3) business-logic hypotheses (derived from the mined routes) -> leads
        nl = 0
        for wf in ((h.get("logic") or {}).get("detail") or []):
            for t in (wf.get("tests") or []):
                lead = {"severity": "info", "confidence": "candidate", "family": "business_logic",
                        "tags": ["code-intel", "business-logic", t.get("kind", "logic")], "cwe": "CWE-840",
                        "target": base,
                        "title": "Business-logic hypothesis (%s) — %s" % (wf.get("workflow", "flow"), t.get("kind", "")),
                        "evidence": t.get("test", ""),
                        "reproduction_steps": [t.get("test", "")] if t.get("test") else [],
                        "analyst_notes": (t.get("rationale", "") + " Derived from routes mined by code intelligence; verify manually.").strip()}
                self.leads.append(lead)
                yield {"type": "lead", "lead": lead}
                nl += 1
                if nl >= 12:
                    break
            if nl >= 12:
                break
        self._codeintel_summary = {"endpoints": len(h.get("endpoints") or []), "added_to_surface": added,
                                   "sensitive_routes": ns, "logic_hypotheses": nl}
        yield {"type": "info", "content": "Code intelligence: mined %d endpoints (%d new to surface), "
               "raised %d sensitive-route + %d business-logic leads." % (len(h.get("endpoints") or []), added, ns, nl)}

    async def _technique_advisor(self, session_id: str):
        """Consult the first-class Technique knowledge model for the highest-priority techniques to
        test given the surface + confirmed findings, and raise them as prioritized (relevance + KEV +
        confidence ranked) leads. Deterministic; makes the technique registry a test GENERATOR rather
        than a static library. Runs for every strategy."""
        try:
            import techniques as T
            import technique_model
            import technique_advisor as adv
            import intel_feeds
        except Exception:
            return
        try:
            snaps = intel_feeds.load()
            kev = intel_feeds.known_exploited_cwes(snaps)
            enr = intel_feeds.enrich_techniques(
                [{"id": t["id"], "cwe": t.get("cwe")} for t in T.TECHNIQUES.values()], snaps) if snaps else {}
        except Exception:
            kev, enr = set(), {}
        try_map = getattr(T, "_TRY", {})
        canon = []
        for rec in T.TECHNIQUES.values():
            e = enr.get(rec["id"], {})
            canon.append(technique_model.from_registry(
                rec, try_it=try_map.get(rec["id"]), known_exploited=e.get("known_exploited", False),
                kev_cves=e.get("kev_cves"), capec=e.get("capec")))
        # Build vuln-class SIGNALS from EVERYTHING recon gathered, so the advisor is driven by all
        # intel (not just confirmed findings). This is the orchestration contract: gathered info -> intel.
        signals = set()
        for l in (self.leads or []):                       # code-intel + harvest-derived leads
            f = str(l.get("family") or "").strip().lower()
            if f:
                signals.add(f)
        try:                                               # the harvested intel store (versions/ids/coupons/...)
            by_kind = (self.tools.intel.to_dict(redact_secrets=True) or {}).get("by_kind", {})
            _K = {"object_id": "access_control", "version": "vulnerable_component", "coupon": "business_logic",
                  "email": "broken_auth", "username": "broken_auth", "secret": "sensitive_exposure",
                  "encoded": "crypto", "route": "access_control"}
            for kind, family in _K.items():
                if by_kind.get(kind):
                    signals.add(family)
        except Exception:
            pass
        recs = adv.recommend(self.findings, canon, kev_cwes=kev, signals=signals, top=8)
        if not recs:
            return
        base = self._primary_base()
        self._advisor_recs = [{"id": r["technique"]["id"], "name": r["technique"].get("name"),
                               "score": r["score"], "reasons": r["reasons"]} for r in recs]
        for lead in adv.as_leads(recs, base):
            self.leads.append(lead)
            yield {"type": "lead", "lead": lead}
        yield {"type": "info", "content": "Technique advisor: %d techniques recommended from the "
               "knowledge model (relevance + KEV + confidence ranked)." % len(recs)}

    async def _close_autonomy_loop(self, session_id: str):
        """Close CHAD's deterministic autonomy loop (Execution -> Evidence -> State -> Next-Best-Action).
        Records THIS engagement's confirmed findings (and attempted lead classes) into the per-target
        attack-chain memory, then runs the SAME evidence-driven technique planner that powers /plan --
        precondition-gated, KEV-ranked, learning-reweighted, chain-annotated -- to emit the ranked
        next-best actions. So real scans FEED the autonomy memory (not just manual confirm/dismiss), and
        the planner + learning get smarter every engagement. Zero-token, fully best-effort (never breaks a
        scan). This is the missing wire: the autonomy engine was a dashboard; now the scan drives + feeds it."""
        base = self._primary_base()
        if not base:
            return
        recorded, nxt = 0, []
        try:
            import attack_chain
            import technique_planner as TP
            # 1) Evidence -> State: confirmed findings + attempted lead classes into per-target memory.
            for f in (self.findings or []):
                fam = str(f.get("family") or f.get("vuln_class") or f.get("type") or "").strip()
                if not fam:
                    continue
                try:
                    attack_chain.record(f.get("target") or base, fam, "confirmed",
                                        evidence=str(f.get("title", ""))[:200], session=session_id)
                    recorded += 1
                except Exception:
                    pass
            for l in (self.leads or []):
                fam = str(l.get("family") or "").strip()
                if fam:
                    try:
                        attack_chain.record(l.get("target") or base, fam, "attempted",
                                            evidence=str(l.get("title", ""))[:120], session=session_id)
                    except Exception:
                        pass
            # 2) Next-Best-Action: the SAME planner /plan uses, now fed by the memory this scan just wrote.
            try:
                harvest = self.tools.intel.to_dict(redact_secrets=True) if getattr(self.tools, "intel", None) else {}
            except Exception:
                harvest = {}
            kev = set()
            try:
                import intel_feeds
                snaps = intel_feeds.load()
                kev = intel_feeds.known_exploited_cwes(snaps) if snaps else set()
            except Exception:
                pass
            # feed ALL gathered intel + findings INTO the live graph first, so the planner reads a
            # complete world model FROM the graph (graph-as-brain), not just flat lists.
            _g = getattr(self.tools, "graph", None)
            if _g is not None:
                try:
                    _g.ingest_intel(self.tools.intel.to_dict() if hasattr(self.tools.intel, "to_dict") else {})
                    for _f in self.findings:
                        _g.observe("finding", str(_f.get("id") or _f.get("title", "")[:40]),
                                   label=_f.get("title", "finding"), source="scan", family=(_f.get("family") or ""))
                except Exception:
                    pass
            # GRAPH-AUTHORITATIVE planning (CHAD capability B): the live graph already ingested ALL
            # recon/intel/findings (graph-as-brain slice 1), so the graph — not flat recon — is the
            # authority. plan_graph_authoritative derives observations SOLELY from the graph; an empty
            # graph could not be driven by recon alone. Flat derive_observations is merged only as a
            # backward-compat projection (a subset of what the graph already holds).
            _seed = TP.registry_seed()
            gplan = TP.plan_graph_authoritative(_g, _seed, kev_cwes=kev)
            self._graph_plan = gplan
            obs = set(gplan["observations"])
            obs |= TP.derive_observations(surface=list(self.tools.urls or []), harvest=harvest,
                                          findings=self.findings, leads=self.leads,
                                          authenticated=bool(getattr(self.tools, "_sessions", None)),
                                          graph=_g)   # compatibility projection
            try:
                import proxy as _proxy
                obs |= _proxy.to_observations()
            except Exception:
                pass
            # getattr, not attribute access: this method is also invoked unbound on lighter agent objects,
            # and a hard dependency here turned the whole autonomy loop into a silent no-op. An agent
            # without the attribute simply has no exclusions.
            p = TP.plan(obs, _seed, kev_cwes=kev, skip_ids=getattr(self, "skip_technique_ids", None))
            try:
                import learning
                rel = learning.reliability()
                for a in p:
                    w = learning.class_weight(a.get("family"), rel)
                    if w:
                        a["score"] = round(a["score"] + w, 1)
                p.sort(key=lambda x: x.get("score", 0), reverse=True)
            except Exception:
                pass
            try:
                p = attack_chain.annotate_plan(base, p)
            except Exception:
                pass
            nxt = p[:6]
            self._next_best = nxt
        except Exception:
            return
        if recorded or nxt:
            try:
                import attack_chain
                key = attack_chain.target_key(base)
            except Exception:
                key = base
            top = ", ".join(a.get("id", "") for a in nxt[:3]) or "none (evidence exhausts the gated techniques)"
            yield {"type": "info", "content": "Autonomy loop closed — %d confirmed finding(s) recorded to "
                   "engagement memory for %s; next-best actions: %s." % (recorded, key, top)}

    async def _acquire_scan_auth(self, session_id: str):
        """AUTHENTICATED SCANNING, autonomous + deterministic. Discover credentials the TARGET itself
        exposes -- harvested by recon this engagement, INHERITED from a prior engagement's memory, or found
        by a small bounded probe of likely credential-disclosure pages -- then log in ONCE and set
        self.tools.session_headers so the WHOLE scan runs AUTHENTICATED (all probe types inherit it). A
        single DISCOVERED value is used; passwords are never guessed/iterated. Exposed creds are recorded as
        a finding, and the discovery is stashed into target memory so the NEXT scan authenticates itself.
        Fully best-effort -- any missing attribute/error degrades to a no-op, never breaking a scan."""
        try:
            events = await self._do_scan_auth(session_id)
        except Exception as e:
            events = [{"type": "info", "content": "scan-auth artery error: %s: %s"
                       % (type(e).__name__, str(e)[:180])}]
        for e in (events or []):
            yield e
        # Second half of the artery: mint same-privilege personas + run the two-user authorization
        # matrix. Best-effort; a failure here never breaks the scan — but it is now SURFACED (a silently
        # swallowed artery error is invisible and undebuggable, which is exactly how a persona-flow failure
        # on a versioned/JSON API went unnoticed).
        try:
            pevents = await self._do_persona_authz(session_id)
        except Exception as e:
            import traceback
            pevents = [{"type": "info", "content": "persona/authz artery error: %s: %s | %s"
                        % (type(e).__name__, str(e)[:160], traceback.format_exc().splitlines()[-2][:120])}]
        for e in (pevents or []):
            yield e
        # Third leg: session LIFECYCLE (CWE-613). It runs LAST on purpose — it is the only engine that
        # deliberately ends a session, so the authorization matrix has already finished with the personas
        # it needs before anything is destroyed. It never touches those personas anyway (it mints its own
        # sacrificial account and `_session_kill_is_safe` re-checks that as a fact), but ordering it after
        # the matrix means a future bug in that guard costs nothing already gathered.
        try:
            sevents = await self._do_session_lifecycle(session_id)
        except Exception as e:
            sevents = [{"type": "info", "content": "session-lifecycle artery error: %s: %s"
                        % (type(e).__name__, str(e)[:180])}]
        for e in (sevents or []):
            yield e

    async def _do_scan_auth(self, session_id: str) -> list:
        events: list = []
        base = self._primary_base()
        sh = getattr(self.tools, "session_headers", None) or {}
        if not base or self.mode == "passive" or sh.get("Cookie") or sh.get("Authorization"):
            return events
        intel = getattr(self.tools, "intel", None)
        if intel is None:
            return events
        # 1) discovered creds: this engagement's harvest -> a prior engagement's memory -> a bounded probe.
        creds = list((intel.with_sources("credential") or {}).keys())
        prior_login, from_prior = None, False
        if not creds:
            try:
                import memory as _mem
                prior = db.get_prior_snapshot(_mem.target_key(self.scope.to_dict()), self.mission_id) or {}
                pc, plogin = self._creds_from_prior(prior)
                if pc:
                    creds = [pc]
                    prior_login = plogin
                    from_prior = True
            except Exception:
                pass
        if not creds:
            creds = await self._probe_for_creds(base)
        creds = [c for c in creds if ":" in c and c.split(":", 1)[0].lower() not in ("user", "username")
                 and "<redacted>" not in c]
        if not creds:
            return events
        user, pw = creds[0].split(":", 1)
        # Q-174. FALSY DEFAULT. This used to end in `or base.rstrip("/") + "/login"`, and
        # `_discover_login_url` manufactured the same guess internally, so a target whose login
        # lives anywhere else got a credential probe fired at a URL that does not exist. On
        # mutillidae that meant a POST to a 278-byte Apache 404, reported as
        # "a single verification login did not yield a session (form/flow mismatch)" -- a claim
        # about the credential, when the fact was about the URL. A probe that cannot succeed
        # reports clean and is indistinguishable from a correct negative.
        #
        # Now: discovery only (no guess), and the candidate must be shown to be a real login
        # surface before anything is fired at it. If neither holds, the credential is NOT
        # TESTED and says so. Discovery of the exposed credential is still reported -- that
        # finding never depended on the login URL.
        login_url = prior_login or self._discover_login_url(base, allow_guess=False)
        if login_url and not await self._login_surface(login_url):
            login_url = None
        login_tested = bool(login_url)
        # 2) DISCOVERY is unconditional: exposed creds are a FINDING (password redacted) and are stashed to
        #    target memory so the NEXT scan can OFFER an authenticated run. Authenticating is a separate,
        #    opted-in step (HITL) -- a scan never silently logs in.
        self._scan_credential = "%s:%s" % (user, pw)     # reuse channel (persisted to target memory; redacted in reports)
        self._scan_login_url = login_url or ""
        self.tools._enum_known_username = user            # ground truth for the username-enumeration differential
        self.tools._fixation_credential = (user, pw)      # known-good login for the session-fixation rotation check (never emitted)
        # 2) VERIFY the discovered credential ACTUALLY WORKS with a single login (anti-brute capped) --
        #    a found credential is only a real finding once it authenticates. This does NOT run the scan
        #    authenticated; it just confirms validity + obtains a session. The FULL authenticated scan
        #    stays opt-in (the rescan prompt).
        # Q-174. The probe runs ONLY against a login surface that was discovered and shown to
        # exist. With no such URL there is nothing to verify against, and firing at a guess
        # would manufacture a negative result that reads exactly like a real one.
        if login_tested:
            try:
                await self.tools.execute("acquire_session",
                                         {"login_url": login_url, "username": user, "password": pw,
                                          "role": "__scan__"}, session_id)
            except Exception as _apolaki_swallowed_1747:
                self.tools._swallow(_apolaki_swallowed_1747, 'agent:_do_scan_auth:1747', "")
                pass
        sess = (getattr(self.tools, "_sessions", None) or {}).get("__scan__") if login_tested else None
        verified = bool(sess)
        self._creds_verified = verified
        _src = "inherited from a prior scan of this target" if from_prior else "harvested from the target's own client-reachable surface"
        # A REAL, redacted authentication reproduction (method + content-type + required fields), then a
        # follow-up authenticated request — NOT a bogus GET page-load. The password is NEVER emitted; the
        # real value lives only in the encrypted vault (CHAD final-audit defect #2). Built from the EXACT
        # winning login shape captured by acquire_session.
        _shape = (getattr(self.tools, "_session_shapes", None) or {}).get("__scan__") or {}
        _auth_curl = ""
        if verified:
            _m = (_shape.get("method") or "POST").upper()
            _act = _shape.get("action") or login_url
            _ct = _shape.get("content_type") or "application/x-www-form-urlencoded"
            _uf, _pf = _shape.get("user_field") or "username", _shape.get("pass_field") or "password"
            _body = ('{"%s":"%s","%s":"<REDACTED_PASSWORD>"}' % (_uf, user, _pf)) if "json" in _ct \
                else ("%s=%s&%s=<REDACTED_PASSWORD>" % (_uf, user, _pf))
            _replay = ("-H 'Authorization: Bearer <TOKEN_FROM_STEP_1>'"
                       if _shape.get("auth_kind") == "bearer" else "-b 'session=<SESSION_COOKIE_FROM_STEP_1>'")
            _auth_curl = "\n".join([
                "# 1) Authenticate with the exposed credential (real secret redacted — held only in the vault)",
                "curl -i -sS -k -X %s '%s' \\" % (_m, _act),
                "  -H 'Content-Type: %s' \\" % _ct,
                "  --data '%s'" % _body,
                "# 2) Replay the issued session on an authenticated-only resource (expect 200 as '%s', not the login view)" % user,
                "curl -i -sS -k %s '%s'" % (_replay, base.rstrip("/") + "/my-account"),
            ])
        # Q-174. NEVER record a URL that was not actually used. `target` used to be the guessed
        # `/login`, so the finding pointed a triager at a 404.
        _probe_target = login_url or base
        f = {"title": "%s application credentials for '%s'"
                      % ("Confirmed working" if verified else "Exposed", user),
             "severity": "high" if verified else "medium",
             "family": "broken_auth",
             "confidence": "confirmed" if verified else "candidate",
             "target": _probe_target, "method": "POST", "curl": _auth_curl,
             "credential_verification": ("verified" if verified
                                         else "failed" if login_tested else "not_tested"),
             # mappings supported by the actual evidence: a real, usable credential exposed to attackers
             "cwe": "CWE-522", "capec": "CAPEC-560", "owasp": "A07:2021",
             # CVSS reflects single-user-account compromise via a no-effort known credential (network,
             # low complexity, no privileges/interaction). Elevate I to High if the account holds
             # privileged/admin functions. N/A only if verification could not run — see evidence.
             "cvss_vector": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N" if verified else ""),
             "cvss_score": (8.2 if verified else None),
             "description": ("A valid, working login for the account '%s' is exposed to attackers (%s). Anyone who "
                             "reads the target's own surface obtains it — no guessing or brute force. Apolaki verified "
                             "the credential authenticates and issues a live session." % (user, _src)) if verified else
                            ("A candidate login for '%s' was %s, but a single verification login did not yield a "
                             "session (form/flow mismatch) — treat as an unconfirmed lead." % (user, _src)
                             if login_tested else
                             "A candidate login for '%s' was %s. It was NOT TESTED: no login endpoint was "
                             "discovered on this target, so there was nothing to verify the credential "
                             "against. This says nothing about whether the credential is valid — treat as "
                             "an untested lead and confirm the login surface by hand." % (user, _src)),
             "impact": ("An attacker logs in as '%s' and gains that user's full account access — reads and modifies "
                        "the account's data and can invoke every function that account is authorised for, and pivot "
                        "from there. Because the credential is exposed on the target itself, exploitation needs no "
                        "guessing, brute force, or user interaction." % user) if verified else
                       ("If valid, an attacker would gain '%s' account access with no brute force." % user),
             "evidence": ("Verified working: a login to %s as '%s' (password redacted) returned a valid "
                          "authenticated session (session cookie/token issued). Raw credential stored redacted in "
                          "the vault, never in this report." % (login_url, user)) if verified else
                         ("Discovered '%s:<redacted>' for the login at %s; a verification login did not return a "
                          "session." % (user, login_url) if login_tested else
                          "Discovered '%s:<redacted>' on the target's own surface. No login endpoint was "
                          "discovered, so NO verification login was attempted and no conclusion about the "
                          "credential's validity is claimed." % user),
             "reproduction_steps": [
                 "POST %s  (form/JSON) with username='%s' and password=<the redacted discovered value>" % (login_url, user),
                 "Success oracle: the response issues a session cookie or bearer token; then a GET to an "
                 "authenticated-only page/identity endpoint returns 200 as '%s' (not the anonymous/login view)." % user,
             ] if verified else (
                 ["POST %s with '%s' and the discovered value; observe whether a session is issued."
                  % (login_url, user)] if login_tested else
                 ["Locate the application's login endpoint by hand (automated discovery found none "
                  "on this target)",
                  "POST it with '%s' and the discovered value; observe whether a session is issued." % user]),
             "success_oracle": ("A session cookie/token is issued AND a subsequent authenticated-only request "
                                "loads as '%s'." % user) if verified else "A session is issued for the account.",
             "remediation": "Rotate/disable the '%s' account credential immediately and remove the exposed value from "
                            "all client-reachable content; enforce unique, secret, non-published credentials." % user,
             "validation": "Replay the exact login above with the OLD credential — it MUST now fail (401 / invalid "
                           "credentials) and issue no session; confirm the value no longer appears in any "
                           "client-reachable response."}
        if self.mission_id:
            try:
                f["id"] = db.add_finding(self.mission_id, f)
            except Exception as _apolaki_swallowed_1817:
                self.tools._swallow(_apolaki_swallowed_1817, 'agent:_do_scan_auth:1817', "")
                pass
        self.findings.append(f)
        events.append({"type": "finding", "finding": f})
        # 3) APPLY the session (whole scan runs authenticated) ONLY when the operator opted in -- the UI
        #    offers this on a rescan whose target has prior discovered creds. Otherwise: verified + saved,
        #    but the scan stays unauthenticated until the user chooses.
        if self.authenticated_scan and verified:
            self.tools.session_headers = {**sh, **sess}
            events.append({"type": "info", "content": "Authenticated as '%s' from %s credentials — the remaining "
                           "probes run logged-in (session applied across all probe types)."
                           % (user, "prior-scan" if from_prior else "discovered")})
        elif self.authenticated_scan and not verified:
            events.append({"type": "info", "content": "Could not authenticate as '%s' — the verification login "
                           "did not yield a session (form/flow mismatch); continuing unauthenticated." % user})
        elif verified:
            events.append({"type": "info", "content": "Verified WORKING credentials for '%s' (a valid session was "
                           "obtained) — recorded as a finding and saved. This scan runs UNAUTHENTICATED; re-run "
                           "with 'authenticated scan' to test the logged-in surface with these credentials." % user})
        else:
            events.append({"type": "info", "content": "Discovered a credential lead for '%s' (could not verify) — "
                           "recorded and saved." % user})
        return events

    def _creds_from_prior(self, prior: dict):
        """Recover a discovered credential from a prior scan's snapshot for reacquisition. Prefers the
        encrypted vault reference (scan_auth_ref); falls back to a legacy plaintext scan_auth for
        snapshots written before the vault. Returns (user:pw or None, login_url or None) — this is the
        'load the login recipe, acquire a fresh session' step of the session lifecycle."""
        prior = prior or {}
        ref = prior.get("scan_auth_ref")
        if ref:
            try:
                import vault as _vault
                sec = _vault.default().get(ref) or {}
                if sec.get("username") and sec.get("password"):
                    login = (sec.get("recipe") or {}).get("login_url") or prior.get("scan_login_url")
                    return "%s:%s" % (sec["username"], sec["password"]), login
            except Exception:
                pass
        sa = prior.get("scan_auth")   # legacy plaintext snapshot (pre-vault)
        if sa and ":" in sa:
            return sa, prior.get("scan_login_url")
        return None, None

    def _discover_register_url(self, base: str):
        """Pick an in-scope registration/signup endpoint from the harvested surface, else a common
        default. Mirrors _discover_login_url but hunts register/signup/join surfaces."""
        import re as _re
        cands = []
        try:
            for u in (self.tools.urls or []):
                if _re.search(r"/(register|signup|sign-up|join|create-account|users?)\b", str(u), _re.I):
                    cands.append(str(u))
        except Exception:
            pass
        for kind in ("route", "endpoint", "url"):
            try:
                for v in self.tools.intel.get(kind):
                    s = str(v)
                    if _re.search(r"regist|signup|sign-up|create.?account", s, _re.I):
                        cands.append(s if s.startswith("http") else base.rstrip("/") + "/" + s.lstrip("/"))
            except Exception:
                pass
        cands += [base.rstrip("/") + "/register", base.rstrip("/") + "/api/Users"]  # Juice-Shop-style default
        for u in cands:
            try:
                if self.scope.validate(u)[0]:
                    return u
            except Exception:
                pass
        return None

    def _register_candidates(self, base: str) -> list:
        """Ordered registration-endpoint candidates. API/JSON registration paths first (so a real
        signup API like Juice Shop /api/Users wins before an SPA /register route that returns 200
        index.html without creating anything), then the discovered URL, then form defaults. Deduped
        + scope-valid."""
        b = base.rstrip("/")
        cands = [b + p for p in ("/api/Users", "/api/register", "/api/auth/register", "/api/signup", "/api/users",
                                 "/users/v1/register", "/api/v1/register", "/api/v1/users", "/v1/users/register",
                                 "/auth/v1/register", "/register/v1")]
        d = self._discover_register_url(base)
        if d:
            cands.append(d)
        cands += [b + p for p in ("/register", "/signup", "/users")]
        seen, out = set(), []
        for u in cands:
            if u in seen:
                continue
            seen.add(u)
            try:
                if self.scope.validate(u)[0]:
                    out.append(u)
            except Exception:
                pass
        return out[:10]

    async def _run_service_packs(self, session_id: str) -> list:
        """Beyond-web: DISCOVER non-web services on the target, classify them, and RUN each matching
        technique pack. Self-contained — it does a bounded socket port-scan of common service ports
        ITSELF (so it no longer depends on the model having run nmap first; CHAD review #1), in
        addition to any ports a prior nmap already reported. Scope-gated, bounded, best-effort."""
        import asyncio as _aio
        import service_router as _sr
        from urllib.parse import urlparse as _up
        events = []
        if self.mode == "passive":     # SAFETY (#1): socket scan + service packs are LIVE contact — never in passive
            return events
        recon = getattr(self.tools, "recon", {}) or {}
        base = self._primary_base()
        # Q-182. SWEEP EVERY IN-SCOPE HOST, not just the web one.
        #
        # This derived ONE host from the primary web base, so every non-web service living on any
        # OTHER in-scope host was never contacted -- which is every real engagement, and this whole
        # bench. MEASURED by an audit lane that called the packs by hand across the bench: SMB
        # null-session (high) and SMB signing not required (medium) on smb:445, unauthenticated
        # DNP3 (high) on dnp3-outstation:20000, LDAP anonymous read (medium) on openldap:389 --
        # four findings from engines with ZERO lifetime dispatches across 188 missions.
        #
        # 15 engines, 13.4% of the registry, were STARVED: not broken, not dispatched wrongly, just
        # never handed a host they could act on. That is the same shape as the crawl gap that hid a
        # command injection -- the engine was right every time it reported nothing.
        #
        # `live_hosts` carries either bare names or {"url": ...} records depending on the producer,
        # so both are accepted. Every scope and HITL gate stays exactly where it was; this changes
        # only WHICH in-scope hosts are swept.
        def _hostname(v):
            if isinstance(v, dict):
                v = v.get("url") or v.get("host") or v.get("value") or ""
            v = str(v or "")
            return (_up(v).hostname or v.split("/")[0].split(":")[0]) if v else ""

        hosts = []
        for cand in ([_up(base).hostname if base else ""]
                     + [_hostname(h) for h in (recon.get("live_hosts") or [])]
                     + [recon.get("target"), recon.get("domain")]):
            h = str(cand or "").strip()
            if h and h not in hosts and self.scope.validate(h)[0]:
                hosts.append(h)
        if not hosts:
            return events
        host = hosts[0]                      # the primary, for callers below that name one host
        services = []
        for _h in hosts:
            services += _sr.parse_nmap_ports((recon.get("nmap") or {}).get("open_ports") or [], _h)
        known = {s["port"] for s in services}
        # ICS/OT PORTS BELONG HERE TOO. This sweep is documented as self-contained — it exists so the
        # service packs still run when nmap did not — but it omitted every industrial port, so
        # modbus_exposed / s7comm_exposed / enip_exposed / dnp3_exposed were reachable ONLY if nmap
        # happened to run and seed them first. Four engines with a validated_on entry each, silently
        # unreachable on the fallback path they were supposed to be guaranteed by.
        # Read-only identify frames only; the safety rail in each engine is unchanged.
        probe = [p for p in (21, 22, 23, 25, 53, 102, 110, 143, 389, 445, 502, 873, 1433, 1521, 2049,
                             2375, 3306, 3389, 5432, 5900, 5985, 6379, 9200, 11211, 20000, 27017,
                             44818, 47808) if p not in known]

        # Q-182: bounded across hosts x ports, so a wide scope cannot open thousands of sockets.
        _sweep_sem = _aio.Semaphore(64)

        async def _open(h, p):
            async with _sweep_sem:
                try:
                    r, w = await _aio.wait_for(_aio.open_connection(h, p), timeout=1.5)
                    w.close()
                    return (h, p)
                except Exception:
                    return None
        _pairs = [(h, p) for h in hosts for p in probe]
        for hit in await _aio.gather(*[_open(h, p) for h, p in _pairs]):
            if not hit:
                continue
            _h, p = hit
            svc = _sr.fingerprint(p)
            services.append({"host": _h, "port": p, "service": svc, "banner": ""})
            self.tools.recon.setdefault("nmap", {}).setdefault("open_ports", []).append(
                "%d/tcp open %s" % (p, svc))
        # PARALLEL beyond-web execution (Strix-borrow #110, done the safe way): each non-web service pack is an
        # INDEPENDENT host:port probe (ssh/ldap/smb/snmp/modbus/vnc/rsync/ntp/ipmi/rdp), so run them CONCURRENTLY
        # under a bounded semaphore instead of one-at-a-time — a large wall-clock cut on multi-host engagements.
        # Findings are stored SERIALLY afterwards so the graph/db writes never interleave; scope/HITL gates stay
        # inside tools.execute(); the graph is still the single source of truth (workers don't talk to each other).
        _targets = [s for s in services
                    if not (_sr.is_web(s["service"]) or s["service"] == "unknown" or not s.get("host"))]
        # D6 (architecture.md 6.1): write the discovered service into the LIVE graph HERE, at
        # fingerprint time, UNTESTED — before its pack runs.
        #
        # MEASURED before this: with ssh:22 and redis:6379 discovered, the graph held ZERO service
        # nodes at dispatch and `untested("service")` was [] — so the `run_service_pack` tier in
        # `AssetGraph.next_best_actions` (asset_graph.py:300, which reads exactly that set) could
        # never fire. The audit reads the cause as `tools.py:2810-2812` marking the node tested "two
        # lines later"; the sharper reading is that the block sits at the END of `_run_service_pack`,
        # AFTER the pack has executed. The node was not marked tested too early — it was CREATED too
        # late, and so never existed in the state the planner consults.
        #
        # `tools.py` needs no change and is not touched: `observe` is idempotent by (kind, key) and
        # its merge branch never clears `tested`, so the existing observe + mark_tested at the end of
        # `_run_service_pack` correctly transitions THIS node to tested when the pack completes. A
        # pack that is gated off, errors, or never runs now leaves an untested service behind — which
        # is precisely the fact the tier exists to report.
        #
        # `enables` comes from the same `service_router.route` the report-time
        # `build_from_engagement` uses, so the tier's impact ranking matches the report instead of
        # falling back to the default.
        try:
            for _r in _sr.route(_targets):
                self.tools.graph.observe(
                    "service", "%s:%s" % (_r.get("host", ""), _r.get("port")),
                    label=_r["service"], source="fingerprint", scope_asset=_r.get("host", ""),
                    enables=sorted({e for c in _r["checks"] for e in c.get("enables", [])}),
                    service=_r["service"], port=_r.get("port"))
        except Exception as _e:
            self.tools._swallow(_e, "service_graph_seed", host)
        _sem = _aio.Semaphore(6)

        async def _run_pack(s):
            async with _sem:
                try:
                    return await self._exec_internal("run_service_pack",       # gated (#2)
                                                     {"host": s["host"], "port": s["port"],
                                                      "service": s["service"]}, session_id)
                except Exception as _apolaki_swallowed_1998:
                    self.tools._swallow(_apolaki_swallowed_1998, 'agent:_run_pack:1998', "")
                    return None
        ran = 0
        for res in await _aio.gather(*[_run_pack(s) for s in _targets]):   # concurrent probes, serial storage
            if res is None:
                continue
            ran += 1
            for f in (res.findings or []):
                if self.mission_id:
                    try:
                        f["id"] = db.add_finding(self.mission_id, f)
                    except Exception as _apolaki_swallowed_2009:
                        self.tools._swallow(_apolaki_swallowed_2009, 'agent:_run_service_packs:2009', "")
                        pass
                self.findings.append(f)
                events.append({"type": "finding", "finding": f})
        if ran:
            events.append({"type": "info", "content": "Ran %d network service pack(s) from the port "
                           "scan (beyond-web execution)." % ran})
        return events

    async def _probe_cloud_storage(self, session_id: str):
        """#13: for every object-storage URL the scan discovered (tools.cloud_bucket_urls, populated during
        response harvest), actively run the public-listing oracle (run_cloud_probe) through the gated
        dispatch. A confirmed public bucket becomes a real finding + graph node. Scope-gated, read-only GET,
        no credentials; skipped in passive mode (run_cloud_probe is ACTIVE, so _exec_internal blocks it)."""
        buckets = rank_targets_for_budget(list(dict.fromkeys(
            getattr(self.tools, "cloud_bucket_urls", []) or [])))
        probed = 0
        seen = set()
        for url in buckets[:8]:
            if url in seen or not self.scope.validate(url)[0]:
                continue
            seen.add(url)
            res = await self._exec_internal("run_cloud_probe", {"url": url}, session_id)
            probed += 1
            for f in (res.findings or []):
                if self.mission_id:
                    try:
                        f["id"] = db.add_finding(self.mission_id, f)
                    except Exception as _apolaki_swallowed_2036:
                        self.tools._swallow(_apolaki_swallowed_2036, 'agent:_probe_cloud_storage:2036', "")
                        pass
                self.findings.append(f)
                yield {"type": "finding", "finding": f}
        if probed:
            yield {"type": "info", "content": "Probed %d discovered cloud-storage URL(s) for public "
                   "listing (run_cloud_probe)." % probed}

    async def _surface_crawl(self, session_id, base: str = "") -> int:
        """Breadth-first surface discovery for EVERY mode, authenticated or not.

        The pieces already existed and nothing drove them: `_http_probe` extracts href/src/action and
        seeds them, `crawl.bfs_frontier` picks the next level. But bfs_frontier's only caller was
        `_authenticated_recrawl`, so an UNAUTHENTICATED mission fetched its seeds, mined served JS and
        never followed a single link. Against the OWASP Benchmark that meant reaching /benchmark/ and
        never walking to any of the 2740 test cases -- the default scanning mode had no surface
        discovery at all.

        BOUNDED BY A PAGE BUDGET, NOT BY A PER-ROUND FRONTIER (Q-019). The old bound was
        `depth(2) x frontier(30)`, and MEASURED against a 2740-case lab it fetched **12 pages** —
        because a BFS round's frontier is chosen from what is already known when the round starts, so
        round 2 could only ever see the 11 links round 1 had found. Everything round 2 discovered (all
        2740 cases) arrived after the last frontier was picked and was therefore never fetched. Since
        `sweep_targets` and the form store only ever see pages that WERE fetched, the entire mission's
        coverage was arithmetic on those 12 pages.

        `http_probe` is the cheapest thing the platform does — MEASURED 13 ms for a small page, 0.43 s
        for a 32 KB index — so the honest bound is a total page budget (BBH_SURFACE_PAGES, default 250
        ≈ a few seconds) spread over BBH_SURFACE_DEPTH levels, rather than a frontier so tight that the
        crawl stops one level above the application. `_authenticated_recrawl` keeps its own
        BBH_CRAWL_DEPTH bound untouched: that pass fetches as several personas and its cost is not this
        pass's cost. Same scope gate on every visit, so this widens reach without widening risk.
        """
        import os as _os

        import crawl as _crawl
        depth = max(1, min(int(_os.environ.get("BBH_SURFACE_DEPTH", "4") or 4), 8))
        budget = max(1, min(int(_os.environ.get("BBH_SURFACE_PAGES", "250") or 250), 5000))
        seen, visited = set(), 0

        # robots.txt and sitemap.xml FIRST — the owner's own index of the site, and of the paths they
        # would rather you did not visit. Free, passive, and standard for every mature scanner; Apolaki
        # read neither in a general scan (they appeared only in a noise-exclusion list and the Natas
        # solver). A Disallow is treated as recon, not as an instruction we are following.
        try:
            from urllib.parse import urljoin
            _origin = base or (getattr(self.tools, "urls", None) or [""])[0]
            if _origin:
                for _doc, _parse in (("robots.txt", _crawl.parse_robots),
                                     ("sitemap.xml", _crawl.parse_sitemap)):
                    _du = urljoin(_origin, "/" + _doc)
                    if not self.scope.validate(_du)[0]:
                        continue
                    _r = await self.tools._http(_du, "GET", capture=False)
                    if _r.get("error") or int(_r.get("status") or 0) != 200:
                        continue
                    _got = _parse(_r.get("body", "") or "", _du)
                    _new = [u for u in _got.get("urls", []) if self.scope.validate(u)[0]]
                    if _new:
                        self.tools._add_urls(_new)
        except Exception as e:
            self.tools._swallow(e, "surface_crawl.robots_sitemap", base or "")
        for _round in range(depth):
            if visited >= budget:
                break
            cands = rank_targets_for_budget(
                [u for u in (getattr(self.tools, "urls", None) or []) if u not in seen])
            if not cands:
                break
            # the frontier is whatever the remaining page budget can still afford. A single number
            # bounds the whole crawl, so a deep site is walked to its budget instead of being cut off
            # one level above its content by an arbitrary per-round 30.
            frontier = _crawl.bfs_frontier(cands, base or cands[0], seen, limit=budget - visited)
            if not frontier:
                break
            for u in frontier:
                seen.add(u)
                if self.stop_event.is_set() or visited >= budget:
                    return visited
                if not self.scope.validate(u)[0]:
                    continue
                try:
                    await self.tools.execute("http_probe", {"url": u}, session_id)
                    visited += 1
                except Exception as e:
                    self.tools._swallow(e, "surface_crawl.http_probe", u)
        return visited

    async def _authenticated_recrawl(self, roles, base, session_id) -> list:
        """Per-persona authenticated pass. For EACH session persona, GET a set of common authed routes
        (harvesting object ids + endpoints into the surface/intel/LIVE graph) and, when a headless
        browser is available, load the base page to capture SPA routes + XHR/fetch APIs. Returns the
        newly-discovered in-scope URLs. Now a bounded DEPTH-2 BFS (CHAD capability D): the fixed-route +
        browser pass seeds depth-1, then crawl.bfs_frontier follows the newly-discovered authed
        links/XHR one level deeper. HONEST SCOPE: depth is capped at 2 and the frontier at 30 URLs;
        deeper recursion, form submission, and CSRF/MFA-resume recipes remain. Bounded + best-effort."""
        before = set(self.tools.urls or [])
        routes = ["", "/profile", "/account", "/me", "/dashboard", "/settings", "/api/users",
                  "/rest/user/whoami", "/api/orders", "/rest/basket", "/api/basket", "/orders",
                  "/api/user", "/graphql"]
        b = base.rstrip("/")
        for role in (roles or []):
            for r in routes:
                url = b + r
                try:
                    if self.scope.validate(url)[0]:
                        await self.tools.execute("http_read", {"url": url, "session": role}, session_id)
                except Exception as _apolaki_swallowed_2142:
                    self.tools._swallow(_apolaki_swallowed_2142, 'agent:_authenticated_recrawl:2142', "")
                    pass
            # authenticated browser pass AS this persona: captures SPA routes + XHR APIs (seed _add_urls)
            try:
                await self.tools.execute("browser_navigate",
                                         {"url": base, "session": role,
                                          "steps": [{"action": "wait", "ms": 1200}]}, session_id)
            except Exception as _apolaki_swallowed_2149:
                self.tools._swallow(_apolaki_swallowed_2149, 'agent:_authenticated_recrawl:2149', "")
                pass
        # Depth-2 BFS (CHAD capability D): the fixed-route + browser pass just discovered new authed
        # links/XHR endpoints. Follow that frontier ONE more level AS the first persona (bounded) so
        # authenticated-only deep endpoints enter the surface + graph — a real recursive step, not a
        # fixed list. Pure crawl.bfs_frontier picks the frontier; the visits are scope-gated + budgeted.
        try:
            import crawl as _crawl
            import os as _os
            # configurable recursion depth (CHAD capability D): default 2, capped at 4. Each round
            # follows the newly-discovered authed frontier one level deeper AND extracts FORMS from
            # the fetched pages (action + method + fields), feeding form targets back into the surface.
            max_depth = max(1, min(int(_os.environ.get("BBH_CRAWL_DEPTH", "2") or 2), 4))
            deep_role = (roles or [None])[0]
            seen = set(before)
            for _round in range(max_depth - 1):     # depth-1 (routes + browser) already done above
                discovered = rank_targets_for_budget(
                    [u for u in (self.tools.urls or []) if u not in seen])
                frontier = _crawl.bfs_frontier(discovered, base, seen, limit=30)
                if not frontier:
                    break
                for u in frontier:
                    seen.add(u)
                    if not self.scope.validate(u)[0]:
                        continue
                    try:
                        res = await self.tools.execute("http_read", {"url": u, "session": deep_role}, session_id)
                        body = getattr(res, "output", "") if isinstance(getattr(res, "output", None), str) else ""
                        if "<form" in body.lower():
                            for fm in _crawl.extract_forms(body, u):
                                if fm.get("action") and self.scope.validate(fm["action"])[0]:
                                    self.tools._add_urls([fm["action"]])
                    except Exception as _apolaki_swallowed_2180:
                        self.tools._swallow(_apolaki_swallowed_2180, 'agent:_authenticated_recrawl:2180', "")
                        pass
        except Exception as _apolaki_swallowed_2182:
            self.tools._swallow(_apolaki_swallowed_2182, 'agent:_authenticated_recrawl:2182', "")
            pass
        return [u for u in (self.tools.urls or []) if u not in before]

    async def _reacquire_personas(self, prior, pm, session_id) -> list:
        """Restore personas from a PRIOR scan: load each persona's vaulted account + login recipe and
        re-login to obtain a FRESH session (CHAD review #5 — reacquire complete persona recipes, not
        just the single discovered credential). Returns the roles restored. Best-effort."""
        import vault as _vault
        refs = (prior or {}).get("persona_refs") or {}
        restored = []
        for role, ref in refs.items():
            try:
                sec = _vault.default().get(ref) or {}
            except Exception:
                sec = {}
            recipe = sec.get("recipe") or {}
            login_url = recipe.get("login_url")
            user = sec.get("email") or sec.get("username")
            pw = sec.get("password")
            if not (login_url and user and pw):
                continue
            try:
                await self.tools.execute("acquire_session",
                                         {"login_url": login_url, "username": user, "password": pw,
                                          "role": role}, session_id)
            except Exception as _apolaki_swallowed_2208:
                self.tools._swallow(_apolaki_swallowed_2208, 'agent:_reacquire_personas:2208', "")
                pass
            hdr = (getattr(self.tools, "_sessions", None) or {}).get(role) or {}
            if hdr:
                pm.add(role, identity=user, method="reacquired", headers=hdr, account={"identity_ref": ref})
                self._persona_refs[role] = ref
                restored.append(role)
        return restored

    async def _do_session_lifecycle(self, session_id: str) -> list:
        """The artery's third leg: session-lifecycle invalidation (CWE-613 — WSTG-SESS-06/07/11), the
        mirror of session fixation. Fixation asks whether the identifier is regenerated when a session is
        CREATED; this asks whether it is destroyed when the session ENDS.

        Gated on `authenticated_scan` for exactly the reason persona minting is: it creates an account
        through the target's own signup, which is state-changing. It is also the ONLY engine that ends a
        session, so it runs after the matrix and only ever against an identity it minted itself.

        The sacrificial identity is recorded in the persona manager under the SESSION_PROBE role, so the
        engagement can see the account it created and cleaned up — `Persona.sacrificial` is what keeps
        every other consumer (the matrix pair, the authenticated re-crawl, `_sessions`) from picking up a
        session that is about to be destroyed."""
        events: list = []
        if not self.authenticated_scan or self.mode == "passive":
            return events
        base = self._primary_base()
        if not base:
            return events
        res = await self._exec_internal("run_session_lifecycle",       # gated (#2)
                                        {"base_url": base,
                                         "register_urls": self._register_candidates(base),
                                         "login_urls": self._login_candidates(base)}, session_id)
        for f in (res.findings or []):
            if self.mission_id:
                try:
                    f["id"] = db.add_finding(self.mission_id, f)
                except Exception as _apolaki_swallowed_2244:
                    self.tools._swallow(_apolaki_swallowed_2244, 'agent:_do_session_lifecycle:2244', "")
                    pass
            self.findings.append(f)
            events.append({"type": "finding", "finding": f})
        ident = getattr(self.tools, "_sesslife_identity", "")
        pm = getattr(self, "_persona_manager", None)
        if ident and pm is not None:
            try:
                import personas as _p
                pm.add(_p.SESSION_PROBE, identity=ident, method="registered", sacrificial=True)
            except Exception:
                pass
        self._session_lifecycle_result = {
            # Q-108: `ToolResult` has `success`, never `ran`. This read `res.ran`, so every mission
            # raised AttributeError here, the artery handler caught it, and the WHOLE
            # session-lifecycle leg (CWE-613) was lost on every run -- visible in the operator's live
            # log only as one line: "session-lifecycle artery error: AttributeError: 'ToolResult'
            # object has no attribute 'ran'". The engine ran; nothing it produced ever landed.
            "ran": bool(res.success), "confirmed": len(res.findings or []),
            "sacrificial_identity": ident or None,
            "session_kill_endpoints_quarantined": len(getattr(self.tools, "session_kill_urls", []) or []),
            "detail": (res.output or "")[:400],
        }
        events.append({"type": "info", "content": "Session lifecycle (CWE-613): %s%s"
                       % (res.output or res.error or "no result",
                          " — sacrificial identity %s" % ident if ident else "")})
        return events

    async def _do_persona_authz(self, session_id: str) -> list:
        """The artery's second half: mint TWO same-privilege personas via the target's own signup,
        re-crawl authenticated, then run the two-user AUTHORIZATION MATRIX and record confirmed
        access-control findings. Account creation is state-changing, so this is gated on an explicit
        authenticated_scan opt-in (active/full only). Secrets go to the encrypted vault; only role
        names and vault refs travel further. Best-effort — any error degrades to a no-op."""
        events: list = []
        if not self.authenticated_scan or self.mode == "passive":
            return events
        base = self._primary_base()
        if not base:
            return events
        import personas as _p
        import register as _reg
        import vault as _vault
        import authz as _authz
        import authz_matrix as _am
        from urllib.parse import urlparse as _up
        pm = _p.PersonaManager()
        vlt = _vault.default()
        mid = self.mission_id or "default"
        self._persona_refs = {}

        # 0) reacquire personas from a PRIOR scan (fresh sessions from vaulted login recipes) before
        #    minting new ones — so future scans restore full personas, not just the scan credential.
        try:
            import memory as _mem
            prior = db.get_prior_snapshot(_mem.target_key(self.scope.to_dict()), self.mission_id) or {}
        except Exception:
            prior = {}
        restored = await self._reacquire_personas(prior, pm, session_id)
        if restored:
            pm.bind(self.tools)
            events.append({"type": "info", "content": "Reacquired %d persona(s) from a prior scan "
                           "(fresh sessions from vaulted login recipes): %s."
                           % (len(restored), ", ".join(restored))})

        # 1) mint any MISSING same-privilege personas through the signup flow (bounded). Probe an
        #    API-first candidate list so a real registration API (e.g. Juice Shop /api/Users) wins over
        #    an SPA /register route that would 200 without creating anything.
        reg_cands = self._register_candidates(base)
        minted, stop = list(restored), False
        for label, role in (("user_a", _p.USER_A), ("user_b", _p.USER_B)):
            if stop or role in minted:      # already restored from a prior scan — don't re-register
                continue
            res, reg_url = None, None
            for cand in reg_cands:
                try:
                    r = await _reg.register(cand, label=label)
                except Exception:
                    r = {"created": False, "headers": {}, "blocked": []}
                if r.get("blocked"):
                    events.append({"type": "info", "content": "Registration needs a manual step (%s) at %s — "
                                   "skipping autonomous account creation; supply operator accounts to test "
                                   "access control." % (", ".join(r["blocked"]), cand)})
                    stop = True
                    break
                if r.get("created"):
                    res, reg_url = r, cand
                    break
            if res is None:
                continue
            acct = res.get("account") or {}
            hdr = res.get("headers") or {}
            login_url = None
            if not hdr and acct.get("password"):
                # API-style signup doesn't auto-login — log in with the freshly-created account.
                # Probe a short ordered candidate list (one KNOWN credential, never a password list)
                # and stop at the first that yields a session.
                # APIs authenticate by EITHER email or username — try both identifiers per login URL so the
                # persona logs in whether the app is email-login (Juice Shop) or username-login (VAmPI).
                _idents = [i for i in (acct.get("email"), acct.get("username")) if i]
                for lu in self._login_candidates(base):
                    for _ident in _idents:
                        try:
                            await self.tools.execute("acquire_session",
                                                     {"login_url": lu, "username": _ident,
                                                      "password": acct.get("password"), "role": role}, session_id)
                        except Exception as _apolaki_swallowed_2345:
                            self.tools._swallow(_apolaki_swallowed_2345, 'agent:_do_persona_authz:2345', "")
                            pass
                        hdr = (getattr(self.tools, "_sessions", None) or {}).get(role) or {}
                        if hdr:
                            login_url = lu
                            break
                    if hdr:
                        break
            if not hdr and acct.get("password"):
                # browser-driven fallback (CHAD 1): API/form login didn't yield a session (SPA login,
                # client-side token, JS-gated form) — drive a real headless login through the UI and
                # promote the token from web storage / cookies into the persona's session.
                login_page = self._discover_login_url(base) or base
                steps = [
                    {"action": "goto", "url": login_page},
                    {"action": "fill", "selector": "input[type=email], input[name=email], input[name=username], #email",
                     "value": acct.get("email") or acct.get("username")},
                    {"action": "fill", "selector": "input[type=password], input[name=password], #password",
                     "value": acct.get("password")},
                    {"action": "click", "selector": "button[type=submit], button#loginButton, button, input[type=submit]"},
                    {"action": "wait", "ms": 1500},
                ]
                try:
                    await self.tools.execute("browser_navigate",
                                             {"url": login_page, "steps": steps, "promote_session": role}, session_id)
                except Exception as _apolaki_swallowed_2370:
                    self.tools._swallow(_apolaki_swallowed_2370, 'agent:_do_persona_authz:2370', "")
                    pass
                hdr = (getattr(self.tools, "_sessions", None) or {}).get(role) or {}
                if hdr:
                    login_url = login_page
            if not hdr:
                continue  # created but no session — cannot test as this persona
            ref = vlt.put(mid, role, {"username": acct.get("username"), "email": acct.get("email"),
                                      "password": acct.get("password"), "headers": hdr,
                                      "recipe": {"register_url": reg_url, "login_url": login_url,
                                                 "mode": "registration", "success_oracle": "session-cookie-present"}})
            pm.add(role, identity=res.get("identity") or acct.get("email", ""), method="registered",
                   headers=hdr, account={"identity_ref": ref})
            minted.append(role)
            self._persona_refs[role] = ref     # so the NEXT scan can reacquire this persona
            try:
                import audit as _audit
                _audit.record("account_created", actor="apolaki", mission=mid, target=role,
                              method="registered", identity_ref=ref)
            except Exception:
                pass
            events.append({"type": "info", "content": "Created test persona '%s' (%s) via signup — session "
                           "captured, secret vaulted (%s)." % (role, res.get("identity"), ref)})

        # 2) fall back to the verified single discovered credential as one persona
        scan_sess = (getattr(self.tools, "_sessions", None) or {}).get("__scan__")
        if scan_sess and _p.USER_A not in minted:
            pm.add(_p.USER_A, identity="(discovered credential)", method="discovered", headers=scan_sess)
            minted.append(_p.USER_A)
        if not pm.session_roles():
            # Observability (this was a silent dead-end): say WHY no persona was established so a
            # register-ok-but-login-failed case on a versioned/JSON API is visible, not invisible.
            events.append({"type": "info", "content":
                           "Authorization matrix: no personas established (minted=%d, register candidates=%d) "
                           "— account creation and/or login did not yield a session; supply operator accounts "
                           "to test access control." % (len(minted), len(reg_cands))})
            return events
        pm.bind(self.tools)   # project persona sessions onto the live registry (_sessions + identities)

        # 3) REAL per-persona authenticated re-crawl: crawl authed routes AS EACH persona (not a single
        #    GET-root) so the logged-in surface — object ids, authed-only endpoints, SPA XHR APIs —
        #    enters the inventory + LIVE graph, which the planner now reads (CHAD review #1/#7).
        new_urls = await self._authenticated_recrawl(pm.session_roles(), base, session_id)
        events.append({"type": "info", "content": "Authenticated re-crawl as %s — %d new endpoint(s) "
                       "merged into the surface + live graph before the authorization matrix."
                       % (", ".join(pm.session_roles()), len(new_urls))})

        # 4) build the operation set from the (now authenticated) surface + intel
        urls = [str(u) for u in (self.tools.urls or [])]
        for kind in ("endpoint", "route", "url"):
            try:
                for v in self.tools.intel.get(kind):
                    s = str(v)
                    urls.append(s if s.startswith("http") else base.rstrip("/") + "/" + s.lstrip("/"))
            except Exception:
                pass
        operations = _am.candidate_operations(rank_targets_for_budget(urls))
        for u in urls:                                  # + privileged-looking paths for the vertical (BFLA) check
            try:
                p = _up(u).path
            except Exception:
                p = ""
            if p and _authz._looks_privileged(p) and not any(o["path"] == p for o in operations):
                operations.append({"request": p, "path": p})
        if not operations:
            events.append({"type": "info", "content": "Authorization matrix: no object-bearing endpoints "
                           "discovered to compare across personas."})
            return events

        # 5) run the matrix through the scoped + captured transport
        roles = [{"role": r["role"], "rank": r["rank"], "tenant": r["tenant"]} for r in pm.matrix_roles()]
        pair = pm.same_privilege_pair()
        owner_identity = ""
        if pair and pm.get(pair[0]):
            p0 = pm.get(pair[0])
            owner_identity = p0.identity or (p0.account or {}).get("email", "")
        res = await self._exec_internal("run_authz_matrix",       # gated (#2)
                                        {"base_url": base, "roles": roles, "operations": operations,
                                         "pair": list(pair) if pair else None,
                                         "owner_identity": owner_identity}, session_id)
        # real per-persona transport counters from the matrix (CHAD #2) — attempted/succeeded auth
        # requests, status distribution, endpoints touched. Stored in _auth_artery below as PROOF.
        try:
            self._authz_request_stats = json.loads(res.output or "{}").get("auth_requests", {})
        except Exception:
            self._authz_request_stats = {}
        for f in (res.findings or []):
            if self.mission_id:
                try:
                    f["id"] = db.add_finding(self.mission_id, f)
                except Exception as _apolaki_swallowed_2460:
                    self.tools._swallow(_apolaki_swallowed_2460, 'agent:_do_persona_authz:2460', "")
                    pass
            self.findings.append(f)
            events.append({"type": "finding", "finding": f})

        # 5b) horizontal WRITE test — Full mode only (state-changing), on objects already proven
        #     cross-user READABLE, using the same persona pair. Bounded + restore-capable.
        if self.mode == "full" and pair:
            read_idor = rank_targets_for_budget(list(dict.fromkeys(
                f["target"] for f in (res.findings or [])
                if f.get("family") == "idor" and "write" not in (f.get("tags") or []))))
            for tgt in read_idor[:5]:
                try:
                    wr = await self._exec_internal("confirm_authz_write",       # gated INTRUSIVE (#2)
                                                   {"target_url": tgt, "owner_session": pair[0],
                                                    "attacker_session": pair[1]}, session_id)
                except Exception as _apolaki_swallowed_2475:
                    self.tools._swallow(_apolaki_swallowed_2475, 'agent:_do_persona_authz:2475', "")
                    continue
                for f in (wr.findings or []):
                    if self.mission_id:
                        try:
                            f["id"] = db.add_finding(self.mission_id, f)
                        except Exception as _apolaki_swallowed_2481:
                            self.tools._swallow(_apolaki_swallowed_2481, 'agent:_do_persona_authz:2481', "")
                            pass
                    self.findings.append(f)
                    events.append({"type": "finding", "finding": f})

        # 5c) CREATE-OBJECT IDOR (CHAD C): the strongest cross-user proof — create a uniquely-owned
        #     object as the owner persona, then access it as the attacker. Ownership is definitive
        #     (we made it with a private marker). Bounded + self-cleaning; runs on the same pair.
        if pair:
            app = "juiceshop" if "juice" in base.lower() else ""
            try:
                # The bounded, self-cleaning, uniquely-marked object-create is the ONLY way to get a
                # DEFINITIVE cross-user BOLA proof. authenticated_scan is already the opt-in that authorizes
                # state-changing account creation, so the same opt-in authorizes this bounded object-create —
                # enabling confirmed BOLA in active mode without the heavy full-mode tooling that can overload
                # a fragile single-process target.
                cres = await self._exec_internal("confirm_create_object_idor",   # gated INTRUSIVE (#2)
                                                 {"base_url": base, "owner": pair[0], "attacker": pair[1],
                                                  "app": app,
                                                  "allow_write": (self.mode == "full" or self.authenticated_scan)},
                                                 session_id)
                for f in (cres.findings or []):
                    if self.mission_id:
                        try:
                            f["id"] = db.add_finding(self.mission_id, f)
                        except Exception as _apolaki_swallowed_2506:
                            self.tools._swallow(_apolaki_swallowed_2506, 'agent:_do_persona_authz:2506', "")
                            pass
                    self.findings.append(f)
                    events.append({"type": "finding", "finding": f})
                if cres.findings:
                    events.append({"type": "info", "content": "Create-object IDOR: %d confirmed cross-user "
                                   "object access(es) proven via owned-object creation." % len(cres.findings)})
                # record that C actually FIRED (attempts + confirmed), so the artifact proves the
                # owner-create -> attacker-access flow ran live, even when the target enforces authz
                # correctly (0 confirmed = no false positive, still a real executed test).
                try:
                    self._create_object_result = {**json.loads(cres.output or "{}"),
                                                  "confirmed": len(cres.findings)}
                except Exception:
                    self._create_object_result = {"ran": True, "confirmed": len(cres.findings)}
            except Exception as _apolaki_swallowed_2521:
                self.tools._swallow(_apolaki_swallowed_2521, 'agent:_do_persona_authz:2521', "")
                pass

        # 5d) READ-ONLY cross-user BOLA (general, no writes): ownership differential over per-user
        #     collections — confirms cross-user READ on PRE-EXISTING / auto-created objects that the
        #     create-object test cannot reach. Definitive + zero-FP.
        if pair:
            try:
                _atk = pm.get(pair[1])
                _acct = (getattr(_atk, "account", {}) or {}) if _atk else {}
                # pass ALL known reader identifiers (email + username + identity) so the owner-attribution
                # oracle only confirms a provably-different principal (no numeric-owner-vs-email false positive)
                _atk_ids = [x for x in ((_atk.identity if _atk else ""), _acct.get("email"),
                                        _acct.get("username")) if x]
                rres = await self._exec_internal("confirm_read_object_idor",     # gated (#2)
                                                 {"base_url": base, "owner": pair[0], "attacker": pair[1],
                                                  "attacker_identities": _atk_ids},
                                                 session_id)
                for f in (rres.findings or []):
                    if self.mission_id:
                        try:
                            f["id"] = db.add_finding(self.mission_id, f)
                        except Exception as _apolaki_swallowed_2543:
                            self.tools._swallow(_apolaki_swallowed_2543, 'agent:_do_persona_authz:2543', "")
                            pass
                    self.findings.append(f)
                    events.append({"type": "finding", "finding": f})
                if rres.findings:
                    events.append({"type": "info", "content": "Read-object BOLA: %d confirmed cross-user "
                                   "read(s) via ownership differential." % len(rres.findings)})
            except Exception as _apolaki_swallowed_2550:
                self.tools._swallow(_apolaki_swallowed_2550, 'agent:_do_persona_authz:2550', "")
                pass

        # 5e) BROWSER INTELLIGENCE ENGINE (#124): the RUNTIME cross-user proof. 5c/5d prove BOLA over the
        #     HTTP transport; this proves it the way a client can watch it happen — two real logged-in
        #     browser contexts, the object request the SPA itself makes, one variable changed, three
        #     negative controls, and an evidence-derived PoC bundle (screenshots + exact/mutated request +
        #     controls + replay script) frozen from the run. Read-only GETs; no-ops without a browser.
        if pair:
            try:
                # feed it the objects the earlier phases already proved the owner owns, plus the app's own
                # authenticated routes, so the browser starts from evidence rather than guessing.
                owned = rank_targets_for_budget(list(dict.fromkeys(
                    f.get("target") for f in (self.findings or [])
                    if f.get("family") in ("idor", "bola") and f.get("target"))))[:5]
                bres = await self._exec_internal("confirm_browser_persona_bola",
                                                 {"base_url": base, "owner": pair[0], "attacker": pair[1],
                                                  "owner_object_urls": owned,
                                                  "seed_paths": self._runtime_seed_paths()}, session_id)
                for f in (bres.findings or []):
                    if self.mission_id:
                        try:
                            f["id"] = db.add_finding(self.mission_id, f)
                        except Exception as _apolaki_swallowed_2572:
                            self.tools._swallow(_apolaki_swallowed_2572, 'agent:_do_persona_authz:2572', "")
                            pass
                    self.findings.append(f)
                    events.append({"type": "finding", "finding": f})
                try:
                    self._bie_result = {**json.loads(bres.output or "{}")}
                except Exception:
                    self._bie_result = {"ran": True, "confirmed": len(bres.findings or [])}
                if bres.findings:
                    events.append({"type": "info", "content": "Browser Intelligence Engine: %d cross-user "
                                   "read(s) CONFIRMED in the browser runtime via persona-swap contexts "
                                   "(evidence-derived PoC bundle attached)." % len(bres.findings)})
                elif (self._bie_result or {}).get("ran"):
                    events.append({"type": "info", "content": "Browser Intelligence Engine ran: %d runtime "
                                   "object hypothes(es) tested, 0 confirmed (authorization held)."
                                   % len((self._bie_result or {}).get("candidates") or [])})
            except Exception as _apolaki_swallowed_2588:
                self.tools._swallow(_apolaki_swallowed_2588, 'agent:_do_persona_authz:2588', "")
                pass

        # 6) record the capabilities this phase unlocked (feeds the planner + attack graph)
        caps = pm.capabilities() + (["authenticated_surface_mapped"] if pm.session_roles() else [])
        for cap in caps:
            try:
                self.tools.state.add_capability(cap, "persona authz phase")
            except Exception:
                pass
        events.append({"type": "info", "content": "Authorization matrix complete: %d persona(s), %d "
                       "operation(s), %d confirmed access-control finding(s). Capabilities: %s."
                       % (len(pm.session_roles()), len(operations), len(res.findings or []),
                          ", ".join(caps) or "none")})
        self._persona_manager = pm
        # Structured PROOF the artery actually fired — persisted to mission context + report so it is
        # queryable, not trapped in the event stream. Personas carry role/rank/method/identity only
        # (pm.to_dict() never emits secrets). auth_success = personas that obtained a live session. This
        # is what a correctness benchmark asserts on (auth_success>=2, matrix ran) instead of a smoke test.
        try:
            plist = (pm.to_dict() or {}).get("personas", [])
            areq = getattr(self, "_authz_request_stats", {}) or {}
            by_role = areq.get("by_role", {}) or {}
            # PROOF (not inference): real authenticated requests happened AND succeeded from BOTH
            # same-privilege personas — the strongest evidence the sessions are genuinely usable.
            both_ok = bool(pair) and all((by_role.get(r, {}).get("succeeded", 0) > 0) for r in (pair or []))
            self._auth_artery = {
                "ran": True,
                "personas": plist,
                "persona_count": len(pm.session_roles()),
                "auth_success": sum(1 for r in pm.session_roles() if pm.get(r) and pm.get(r).has_session()),
                "reacquired": list(restored),
                "recrawl_new_endpoints": len(new_urls),
                "matrix": {"operations": len(operations),
                           "findings": len(res.findings or []),
                           "pair": list(pair) if pair else None,
                           "ran": True},
                # REAL transport evidence (CHAD #2): counted at the wire, not matrix_ops*personas
                "authenticated_requests": {
                    "attempted": areq.get("attempted", 0),
                    "succeeded": areq.get("succeeded", 0),
                    "by_role": by_role,
                    "status_dist": areq.get("status_dist", {}),
                    "endpoints_touched": areq.get("endpoints_touched", 0),
                    "with_auth_material": areq.get("with_auth_material", 0),
                    "both_personas_succeeded": both_ok,
                },
                # PROOF capability C (create-object IDOR) executed live: {ran, attempts, confirmed}
                "create_object_idor": getattr(self, "_create_object_result", {"ran": False}),
                # PROOF the Browser Intelligence Engine's runtime persona swap executed live (#124)
                "browser_persona_bola": getattr(self, "_bie_result", {"ran": False}),
                "capabilities": caps,
            }
        except Exception:
            self._auth_artery = {"ran": True, "note": "artery ran; evidence capture degraded"}
        return events

    def _observed_bases(self) -> dict:
        """host -> base URL, preferring the scheme we MEASURED over the one we assumed.

        Q-130. `ScopeEngine.base_map` falls back to `https://{host}` for any host the operator did
        not declare with a scheme. For an HTTP-only host that is a guess, and it is wrong: on the
        WordPress reach lab every guessed API path was probed over `https://` against a port with no
        TLS listener, so the navigations could not connect. Before Q-129 that manufactured findings
        from the browser's own error page; now it just wastes the budget silently.

        THE PRECEDENCE IS THE POINT, and it is three-tier rather than "prefer http":
          1. an operator-DECLARED base wins outright -- they said so, and flipping the default to
             http for everyone would be a security regression for the sake of a lab;
          2. otherwise a base we OBSERVED answering, because a measurement beats an assumption;
          3. otherwise the https default, which is correct for the internet.
        """
        from urllib.parse import urlparse          # module-local, as elsewhere in this file
        bases = dict(self.scope.base_map() or {})
        declared = {e.value for e in self.scope._addressable() if getattr(e, "base", None)}
        for row in (self.tools.recon.get("live_hosts") or []):
            u = row.get("url") if isinstance(row, dict) else str(row or "")
            if not u or "://" not in u:
                continue
            host = urlparse(u).hostname or ""
            if host and host not in declared and host in bases:
                bases[host] = u.rstrip("/")
        return bases

    def _scope_origins(self) -> list:
        """The in-scope origins to audit, CARRYING the scheme and port the operator authorised.

        Q-060. Three drivers used to rebuild an origin out of `scope.to_dict()["in_scope"]`:

            u = s if "://" in s else "https://" + s.split("/")[0]

        `in_scope` holds BARE HOSTS — `scope._split_scope_entry` strips the scheme and port before
        the entry is stored, parking them in `ScopeEntry.base`. So re-adding a default scheme
        INVENTS a port nobody authorised (`http://juice-shop:3000` -> `juice-shop` ->
        `https://juice-shop`, i.e. :443), and `validate()` then correctly refuses the origin the
        driver itself built. MEASURED live: `run_transport_posture` 1 call, 0 results, 1 scope
        block — 100% dead — while `run_header_trust` survived only on the discovered URLs, which
        carry their own port. Every Apolaki lab runs on a non-standard port, so the whole fleet was
        unauditable for `tls_posture` / `cookie_scope_posture` / `http_security_headers` /
        `http_methods_audit`.

        The refusal was right and the INPUT to it was wrong, so the fix is here and not in scope:
        `ScopeEngine.base_urls()` returns the operator's own `scheme://host:port` and only falls
        back to a default for a host they wrote bare. It is already the source of truth for
        `_primary_base`, the API sweep and the model's TARGET BASE URLS block; these drivers were
        the ones deriving their own.

        Wildcards contribute nothing: `*.example.com` is not a hostname, and the old
        reconstruction spent a real dispatch on `https://*.example.com` — which `_matches` accepts
        (`'*.example.com'.endswith('.example.com')`) and DNS can never resolve.
        """
        from urllib.parse import urlsplit as _us
        origins, seen = [], set()
        for b in (self.scope.base_urls() or []):
            p = _us(str(b))
            if not (p.scheme and p.netloc):
                continue
            o = "%s://%s" % (p.scheme, p.netloc)
            if o not in seen:
                seen.add(o)
                origins.append(o)
        return origins

    async def _do_transport_posture(self, session_id: str):
        """#103: run the transport + web posture family on each in-scope origin. Read-only (TLS
        handshakes, GET/OPTIONS/TRACE). Best-effort — any failure degrades to a no-op, never a
        broken scan."""
        origins = self._scope_origins()
        total = 0
        for o in origins[:3]:
            try:
                res = await self._exec_internal("run_transport_posture", {"url": o}, session_id)
            except Exception as _apolaki_swallowed_2693:
                self.tools._swallow(_apolaki_swallowed_2693, 'agent:_do_transport_posture:2693', "")
                continue
            for f in (res.findings or []):
                if self.mission_id:
                    try:
                        f["id"] = db.add_finding(self.mission_id, f)
                    except Exception as _apolaki_swallowed_2699:
                        self.tools._swallow(_apolaki_swallowed_2699, 'agent:_do_transport_posture:2699', "")
                        pass
                self.findings.append(f)
                yield {"type": "finding", "finding": f}
                total += 1
        if origins:
            yield {"type": "info", "content": "Transport posture: audited %d origin(s) — TLS protocol + "
                   "certificate, session-cookie attributes, protective headers, HTTP methods. %d "
                   "finding(s)." % (min(len(origins), 3), total)}

    async def _do_header_trust(self, session_id: str):
        """T1: authorization decided by a client-controlled header, on each in-scope origin plus any path
        the scan actually met a 401/403 on.

        WHY THIS EXISTS AS A SEPARATE PASS. `run_header_trust` was registered in the permission map and
        fully implemented, but its name was never passed to `execute`/`_exec_internal`, and it was absent
        from the CLAUDE_TOOLS spec — so neither the deterministic path nor the agentic path could reach
        it. Its ALWAYS_ON reason claimed it ran "on every in-scope origin". That claim is now true.

        Read-only: safe GETs replaying a denied request behind an override header. Best-effort — any
        failure degrades to a no-op rather than a broken scan, matching `_do_transport_posture`.

        Q-060: the origin pass reads `_scope_origins()` — the operator's own scheme+port — rather
        than rebuilding `http://` + a bare scope host, which discarded the pinned port and had this
        pass refused on every non-standard-port target. Only the origin half was affected; the
        discovered-URL half below always carried its port, which is why this engine measured
        6 calls / 5 results / 1 scope block instead of dying outright."""
        targets = self._scope_origins()
        seen = set(targets)
        # Sensitive routes the scan actually discovered are the high-value targets: a header that flips
        # their denial into a grant IS the finding. No separate denied-path tracker is invented here —
        # `_run_header_trust` establishes its own baseline per URL and recognises a denial itself, so
        # feeding it discovered routes is sufficient and avoids a second source of truth.
        for u in (getattr(self.tools, "urls", None) or []):
            s = str(u)
            if s in seen:
                continue
            if any(w in s.lower() for w in ("admin", "manage", "internal", "console", "dashboard",
                                            "config", "private", "staff")):
                seen.add(s)
                targets.append(s)

        total, ran, first_error = 0, 0, ""
        for t in rank_targets_for_budget(targets)[:6]:
            try:
                res = await self._exec_internal("run_header_trust", {"url": t}, session_id)
                ran += 1
            except Exception as e:
                # Record WHY, once. A bare `except: continue` here hid a total failure behind a summary
                # line that counted TARGETS rather than EXECUTIONS: the first live run reported "tested 6
                # target(s)" while zero calls had actually reached the tool. Silence plus an optimistic
                # count reads exactly like success.
                first_error = first_error or "%s: %s" % (type(e).__name__, str(e)[:120])
                continue
            for f in (res.findings or []):
                if self.mission_id:
                    try:
                        f["id"] = db.add_finding(self.mission_id, f)
                    except Exception as _apolaki_swallowed_2757:
                        self.tools._swallow(_apolaki_swallowed_2757, 'agent:_do_header_trust:2757', "")
                        pass
                self.findings.append(f)
                yield {"type": "finding", "finding": f}
                total += 1
        if targets:
            # Report what RAN, not what was queued, and never hide a total failure.
            if ran:
                yield {"type": "info", "content": "Header-trust: tested %d of %d target(s) for "
                       "authorization decided by a client-controlled header (Referer / X-Forwarded-* / "
                       "X-Original-URL). %d finding(s)." % (ran, min(len(targets), 6), total)}
            else:
                yield {"type": "info", "content": "Header-trust: DID NOT RUN on any of %d target(s) — %s. "
                       "Treat this class as untested, not as clean."
                       % (min(len(targets), 6), first_error or "no reason captured")}

    async def _do_saml(self, session_id: str):
        """SAML assertion posture, where the surface actually shows SSO.

        Gated on the SAME signal the planner uses (`saml_sso_detected`: a `saml` / `/sso` / `/acs` /
        `simplesaml` / `/adfs` path), so it stays silent on the overwhelming majority of targets rather
        than logging a no-op everywhere. Passive: `run_saml` issues no request, it reads the surface the
        scan already has."""
        urls = [str(u) for u in (getattr(self.tools, "urls", None) or [])]
        if not any(w in u.lower() for u in urls
                   for w in ("saml", "/sso", "/acs", "simplesaml", "/adfs")):
            return
        try:
            res = await self._exec_internal("run_saml", {"urls": urls}, session_id)
        except Exception as e:
            yield {"type": "info", "content": "SAML posture check did not run (%s: %s). Treat SAML "
                   "assertion handling as untested, not as clean." % (type(e).__name__, str(e)[:100])}
            return
        for f in (res.findings or []):
            if self.mission_id:
                try:
                    f["id"] = db.add_finding(self.mission_id, f)
                except Exception as _apolaki_swallowed_2794:
                    self.tools._swallow(_apolaki_swallowed_2794, 'agent:_do_saml:2794', "")
                    pass
            self.findings.append(f)
            yield {"type": "lead", "lead": f}
        yield {"type": "info", "content": "SAML: %s" % (res.output or "checked")}

    def _runtime_seed_paths(self, limit: int = 6) -> list:
        """The authenticated app routes worth RENDERING so the SPA fetches the logged-in user's own
        objects (which is what gives the Browser Intelligence Engine real cross-user hypotheses).
        Target-agnostic: prefer routes actually discovered on this target, and fall back to the common
        per-user areas every application has. Client-side (#/) routes are included because a SPA's object
        pages usually live there."""
        import re as _re
        _WANT = ("basket", "cart", "order", "profile", "account", "invoice", "dashboard", "my",
                 "settings", "wallet", "address")
        out = []
        try:
            for u in (self.tools.urls or []):
                s = str(u)
                if any(w in s.lower() for w in _WANT) and _re.search(r"/(#/)?[a-z]", s, _re.I):
                    from urllib.parse import urlsplit as _us
                    parts = _us(s)
                    p = parts.path + (("?" + parts.query) if parts.query else "")
                    if p and p not in out:
                        out.append(p)
        except Exception:
            pass
        for p in ("/#/basket", "/#/order-history", "/#/profile", "/#/address/saved"):
            if p not in out:
                out.append(p)
        return out[:limit]

    def _discover_login_url(self, base: str, allow_guess: bool = True):
        """Pick an in-scope login endpoint from the harvested surface, else a common default.

        Q-174. `allow_guess=False` returns ONLY endpoints actually seen on this target. The
        default is unchanged, so every existing caller keeps its behaviour.

        This is where the falsy default really lives. A triage report placed it at the call
        site (`prior_login or self._discover_login_url(base) or base + "/login"`), but MEASURED
        with an empty URL surface this function returns `'http://mutillidae/login'` itself --
        it appends the guess to its own candidate list -- so it is never falsy for an in-scope
        base and that trailing `or` is dead code. Removing the `or` would have changed nothing.
        The guess has to stop being manufactured HERE.

        The distinction matters because a guessed URL is indistinguishable downstream from a
        discovered one: `http://mutillidae/login` is a 278-byte Apache 404 with zero forms,
        while the real login is `/index.php?page=login.php` with a password input. A credential
        probe fired at the guess reports "the credential did not authenticate" when the truth
        is "there was nothing there to authenticate against".
        """
        import re as _re
        cands = []
        try:
            for u in (self.tools.urls or []):
                if _re.search(r"/(login|signin|sign-in|session|auth)\b", str(u), _re.I):
                    cands.append(str(u))
        except Exception:
            pass
        for kind in ("route", "endpoint", "url"):
            try:
                for v in self.tools.intel.get(kind):
                    s = str(v)
                    if _re.search(r"login|signin|auth", s, _re.I):
                        cands.append(s if s.startswith("http") else base.rstrip("/") + "/" + s.lstrip("/"))
            except Exception:
                pass
        if allow_guess:
            cands.append(base.rstrip("/") + "/login")
        for u in cands:
            try:
                if self.scope.validate(u)[0]:
                    return u
            except Exception:
                pass
        return None

    async def _login_surface(self, url: str) -> bool:
        """Is this URL something that could actually authenticate a credential?

        Q-174. A name-shaped login URL is not a login endpoint, in exactly the way a
        name-shaped `accounts.txt` is not a credential file: both decisions were being made on
        the string instead of on what the response contains. MEASURED on the three login-ish
        URLs the mission actually crawled -- one is a 404 and another renders with zero
        password inputs -- so recognising more URL shapes would only have produced a different
        unprobeable target.

        Deliberately permissive about JSON/API logins, which answer a GET with 401/405 and
        carry no HTML form; the only thing being excluded is a URL that demonstrably cannot
        accept a login.
        """
        if not url:
            return False
        try:
            if not self.scope.validate(url)[0]:
                return False
        except Exception as _apolaki_swallowed_3189:
            # RECORDED, not silent. This handler's silence is read by the caller as "this URL is
            # not a login surface", which is a verdict about the TARGET; a scope-engine fault is a
            # fact about US. Unrecorded, the two are the same `return False`, and that is exactly
            # what the silent-failure invariant counts -- it moved the partition 407 -> 408 and the
            # gate went red. Its sibling twelve lines below already records; this one did not.
            self.tools._swallow(_apolaki_swallowed_3189, 'agent:_login_surface:3189', url)
            return False
        import browser_engine as _browser_engine
        import httpx
        try:
            async with _browser_engine.rate_limited_async_client(
                    httpx, verify=False, follow_redirects=True, timeout=12,
                    headers={"User-Agent": "apolaki-recon"}) as c:
                r = await c.get(url)
        except Exception as _apolaki_swallowed_2174:
            self.tools._swallow(_apolaki_swallowed_2174, 'agent:_login_surface:2174', url)
            return False
        # EXCLUDE ONLY ON POSITIVE EVIDENCE THAT THIS CANNOT AUTHENTICATE. A GET is not the
        # method a login endpoint answers, so an error status is not evidence of absence.
        # MEASURED: juice-shop's real API login answers a GET with
        #   HTTP 500  <title>Error: Unexpected path: /rest/user/login</title>
        # Treating a 500 or a non-form body as "not a login" would refuse a genuine endpoint.
        # The two things that ARE evidence: nothing is served here at all, or a page rendered
        # perfectly well and is not a login form.
        if r.status_code in (404, 410):
            return False
        ct = (r.headers.get("content-type") or "").lower()
        if "html" in ct and r.status_code < 400:
            body = (r.text or "").lower()
            return ('type="password"' in body or "type='password'" in body
                    or "type=password" in body)
        return True

    def _login_candidates(self, base: str) -> list:
        """Ordered login-endpoint candidates for logging in a freshly-created account. API/JSON login
        paths first (so a real token login wins before an SPA /login route can hand back a bare
        tracking cookie), then the discovered login URL, then form defaults. Deduped + scope-valid.
        One KNOWN credential is tried against each until a session is obtained — endpoint discovery,
        never a password list."""
        b = base.rstrip("/")
        cands = [b + p for p in ("/rest/user/login", "/api/login", "/api/auth/login", "/auth/login",
                                 "/users/v1/login", "/api/v1/login", "/v1/users/login", "/auth/v1/login",
                                 "/login/v1")]
        d = self._discover_login_url(base)
        if d:
            cands.append(d)
        cands += [b + p for p in ("/login", "/user/login", "/api/sessions")]
        seen, out = set(), []
        for u in cands:
            if u in seen:
                continue
            seen.add(u)
            try:
                if self.scope.validate(u)[0]:
                    out.append(u)
            except Exception:
                pass
        return out[:10]  # bounded endpoint discovery (distinct-password anti-brute cap applies per endpoint)

    async def _probe_for_creds(self, base: str) -> list:
        """Bounded, polite fetch of the login page + common credential-disclosure pages, harvesting any
        exposed creds into the intel store. Small fixed page set -- never a crawl/brute."""
        import browser_engine as _browser_engine
        import httpx
        for p in ("/vulnerabilities", "/", "/login", "/readme", "/README.md", "/help", "/about"):
            u = base.rstrip("/") + p
            try:
                if not self.scope.validate(u)[0]:
                    continue
                async with _browser_engine.rate_limited_async_client(
                        httpx, verify=False, follow_redirects=True, timeout=12,
                        headers={"User-Agent": "apolaki-recon"}) as c:
                    self.tools._harvest_body(u, {}, (await c.get(u)).text)
            except Exception as _apolaki_swallowed_2893:
                self.tools._swallow(_apolaki_swallowed_2893, 'agent:_probe_for_creds:2893', "")
                continue
        return list((self.tools.intel.with_sources("credential") or {}).keys())

    # ── AI-call budget helpers ───────────────────────────────────
    def _ai_usable(self) -> bool:
        return bool(self.client) and self._has_key

    def _budget_left(self) -> bool:
        return self.ai_calls < self.max_ai_calls

    def _budget_event(self) -> dict:
        return {"type": "ai_budget", "used": self.ai_calls, "max": self.max_ai_calls,
                "strategy": self.strategy}

    async def _ai_text(self, system: str, user: str, max_tokens: int = 800) -> str:
        """One plain (no-tool) LLM completion; counts against the budget."""
        self.ai_calls += 1
        if self.provider == "openrouter":
            r = await self.client.chat.completions.create(
                model=self.model, max_tokens=max_tokens,
                messages=[{"role": "system", "content": system}, {"role": "user", "content": user}])
            return (r.choices[0].message.content or "").strip()
        r = await self.client.messages.create(
            model=self.model, max_tokens=max_tokens, system=system,
            messages=[{"role": "user", "content": user}])
        return "".join(getattr(b, "text", "") for b in r.content).strip()

    # ── entry ────────────────────────────────────────────────────
    async def run(self, objective: str, session_id: str) -> AsyncGenerator[dict, None]:
        yield {"type": "phase", "phase": "recon"}
        # SEED THE SCOPED PATH, NOT JUST THE HOST. An app mounted on a subpath -- example.com/app/,
        # or the OWASP Benchmark on /benchmark/ -- has a host root that 404s. Recon started there,
        # scope CORRECTLY refused it ("host is in scope, but the request path is outside the pinned
        # scope path"), the crawl found nothing, the planner had nothing to schedule, and the mission
        # completed in 40 seconds with ZERO findings against a target carrying 1415 real ones.
        # Scope already records the pinned path; nothing was seeding a URL that satisfies it.
        _seeded = []
        for _e in (self.scope.in_scope or []):
            _b, _p = (getattr(_e, "base", "") or ""), (getattr(_e, "path", "") or "")
            if _b and _p and _p != "/":
                _u = _b.rstrip("/") + "/" + _p.strip("/") + "/"
                if self.scope.validate(_u)[0]:
                    _seeded.append(_u)
        if _seeded:
            self.tools._add_urls(_seeded)
            yield {"type": "info", "content": "Seeded %d scoped base URL(s) whose path is pinned: %s — the "
                   "host root is out of scope for these, so nothing else would have reached the app."
                   % (len(_seeded), ", ".join(_seeded[:3]))}
        if self.recon_cycles > 1:
            yield {"type": "info", "content": f"Iterative recon enabled: up to {self.recon_cycles} cycles "
                   "(refine from discovered assets each pass; intrusive tools are not looped)."}
        # Be honest when the browser XSS confirmer is dead: reflected XSS in
        # script/DOM contexts can then only ever be advisory leads.
        import tools as _tools_mod
        if _tools_mod.xss_confirm_status() is False:
            yield {"type": "info", "content": "Headless-browser XSS confirmer unavailable — reflected XSS in "
                   "script/DOM contexts will stay advisory leads (HTML/attribute-context reflections still confirm)."}
        yield self._budget_event()

        # Deterministic code-intelligence recon: mine the target's served JS, seed the scan surface,
        # and raise sensitive-route + business-logic leads BEFORE the scan runs (every strategy).
        # SAFETY (#1): both this (fetches served JS) and the service-pack sweep (socket scan + packs) make
        # LIVE target contact, so they are skipped in PASSIVE mode — passive = OSINT only, no direct contact.
        if self.mode == "passive":
            yield {"type": "info", "content": "PASSIVE mode: skipping served-JS code-intelligence and the "
                   "network service-pack sweep (both make live target contact)."}
        else:
            # Walk the site BEFORE code-intelligence and the planner, so both see the real surface
            # rather than only the seed URLs the operator typed.
            _before_urls = len(getattr(self.tools, "urls", None) or [])
            _visited = await self._surface_crawl(session_id, base=(_seeded[0] if _seeded else ""))
            _gained = len(getattr(self.tools, "urls", None) or []) - _before_urls
            if _visited:
                yield {"type": "info", "content": "Surface crawl: probed %d page(s), surface %d -> %d URL(s). "
                       "This runs for unauthenticated scans too; previously only authenticated missions "
                       "followed links at all." % (_visited, _before_urls, _before_urls + _gained)}

            async for ev in self._recon_code_intelligence(session_id):
                yield ev

            # Beyond-web: turn the port scan into service-pack EXECUTION (nmap -> classify -> run pack).
            try:
                for ev in await self._run_service_packs(session_id):
                    yield ev
            except Exception:
                pass

            # Transport + web posture (#103): TLS protocol/certificate, session-cookie attributes,
            # protective headers and HTTP methods for every in-scope origin. Read-only.
            async for ev in self._do_transport_posture(session_id):
                yield ev

            # Header-trust (T1): authorization decided by a client-controlled header. Read-only GETs on
            # each in-scope origin plus any path the scan met a 401/403 on.
            async for ev in self._do_header_trust(session_id):
                yield ev

            # SAML assertion posture: harvest + analyze only, no request of its own. Fires only where the
            # surface actually shows SSO, so it stays silent on the vast majority of targets.
            async for ev in self._do_saml(session_id):
                yield ev

        # Authenticated scanning: discover credentials the target exposes (or inherit them from a prior
        # scan) and log in, so the whole assessment runs as a real user (every strategy, active/full only).
        async for ev in self._acquire_scan_auth(session_id):
            yield ev

        strat = self.strategy
        # Degrade to deterministic when AI is needed but unusable (missing key /
        # exhausted quota) — the platform stays useful without AI (item 4).
        if strat in ("low_ai", "agentic") and not self._ai_usable():
            self.ai_degraded = True
            self.ai_note = f"AI unavailable (no usable credential) — {strat} degraded to deterministic coverage."
            yield {"type": "info", "content": "AI unavailable — completing with deterministic coverage."}
            strat = "deterministic"

        if strat == "manual":
            yield {"type": "complete", "content": "Manual mode: no automated run. Drive testing yourself "
                   "with the cURL Console, Workbench, and Access Check."}
            return
        if strat == "deterministic":
            async for ev in self._run_deterministic(session_id):
                yield ev
        elif strat == "low_ai":
            async for ev in self._run_low_ai(objective, session_id):
                yield ev
        else:
            # QUAL-1: an agentic run must never fall below deterministic coverage.
            # Previously the ReAct loop ran alone, so a model that decided "analysis
            # complete" after a couple of calls could silently under-scan (observed:
            # 2 tools / 0 findings where deterministic found 6 on the same target).
            # Run the deterministic plan as a COVERAGE FLOOR first, then let the ReAct
            # loop augment on the already-mapped surface — AI adds, never replaces.
            yield {"type": "info", "content": "Agentic: establishing a deterministic coverage floor, "
                   "then the AI augments on the mapped surface."}
            # mark the floor so _run_tool auto-stores its confirmed findings (no model
            # is driving during the floor); the ReAct phase below stores its own.
            self._in_floor = True
            try:
                async for ev in self._execute_plan(session_id):
                    yield ev
            finally:
                self._in_floor = False
            floor_steps = getattr(self, "_plan_steps", 0)
            # ReAct augmentation. A RUNTIME provider failure (e.g. a 429 free-tier
            # quota hit) can't be seen by the credential pre-check; since the floor
            # already produced full coverage, catch it and finalize gracefully
            # instead of failing the run.
            gen = self._run_openrouter(objective, session_id) if self.provider == "openrouter" \
                else self._run_anthropic(objective, session_id)
            try:
                async for event in gen:
                    yield event
            except Exception as ex:
                low = str(ex).lower()
                ai_err = any(k in low for k in ("429", "quota", "rate limit", "rate-limit",
                                                "timeout", "timed out", "401", "unauthorized",
                                                "authentication", "insufficient"))
                self.ai_degraded = True
                self.ai_note = (f"Agentic AI unavailable ({type(ex).__name__}) — deterministic "
                                f"coverage floor completed ({floor_steps} step(s)).")
                yield {"type": "info", "content": ("AI rate-limited/unavailable" if ai_err
                       else f"AI augmentation error ({type(ex).__name__})") +
                       " — the deterministic coverage floor already completed for this run."}
                yield {"type": "complete", "content": f"Agentic run completed on the deterministic "
                       f"coverage floor ({floor_steps} step(s)). See Playbooks and the report."}
        # #13: actively probe every object-storage URL discovered during the scan for a public listing
        # (run_cloud_probe) — turns cloud fingerprinting into confirmed cloud exposure (was an island).
        async for ev in self._probe_cloud_storage(session_id):
            yield ev
        # Deterministic technique advisor: consult the knowledge model for the top applicable
        # techniques given the surface + confirmed findings, raised as prioritized leads (every strategy).
        async for ev in self._technique_advisor(session_id):
            yield ev
        # Close CHAD's deterministic autonomy loop: record this engagement's evidence into per-target
        # memory and emit the ranked next-best-action from the SAME planner that powers /plan (every strategy).
        async for ev in self._close_autonomy_loop(session_id):
            yield ev
        # GENERAL candidate-validation pipeline (runs for EVERY strategy, LATE — after the technique
        # advisor + autonomy loop have contributed their leads). Every remaining testable lead is
        # normalized, routed to a real validator, and driven to an EXPLICIT terminal state
        # (confirmed / dismissed / blocked-with-named-prereq / unsupported), with a per-candidate
        # assurance record. No testable lead is left sitting; "no browser" is a visible BLOCKED row.
        async for ev in self._validate_candidates(session_id):
            yield ev
        # advisory triage pass (METIS) over persisted findings
        async for ev in self._triage():
            yield ev

    # ── deterministic executor (planner-driven, no AI) ───────────
    @staticmethod
    def _graph_host_node(g, url: str) -> str:
        """The id of the host node serving `url`, or "" — WITHOUT creating one.

        Three host identities coexist in this graph (D12): `tools._graph_add_url` and
        `asset_graph.build_from_engagement` key a host by netloc (WITH port), while this projector
        keys it by BARE hostname (scope entries and recon subdomains are stored that way). Try the
        most specific first, fall back to the bare name, and observe NOTHING when neither exists —
        minting a fourth identity here to make an edge attach would make D12 worse, not better.
        """
        import asset_graph as _ag
        from urllib.parse import urlparse as _up
        try:
            netloc = (_up(str(url or "")).netloc or "").lower()
        except Exception:
            return ""
        if not netloc:
            return ""
        for key in (netloc, netloc.split(":")[0]):
            if g.node(_ag._nid("host", key)):
                return _ag._nid("host", key)
        return ""

    @classmethod
    def _graph_finding_anchor(cls, g, target: str) -> str:
        """The endpoint (preferred) or host node a finding was found on, or "" — never creating one.

        Same three-identity problem as `_graph_host_node`, one layer down: this projector keys an
        endpoint by the WHOLE URL, `_graph_add_url` keys it by `netloc+path`. A finding's `target`
        may also carry the probe's query string rather than the discovered one, so the bare
        scheme+netloc+path form is tried last before falling back to the host.
        """
        import asset_graph as _ag
        from urllib.parse import urlparse as _up, urlunparse as _uup
        s = str(target or "").strip()
        if not s:
            return ""
        cands = [s]
        try:
            p = _up(s)
            if p.netloc:
                cands.append(p.netloc + (p.path or "/"))
                cands.append(_uup((p.scheme, p.netloc, p.path, "", "", "")))
        except Exception:
            pass
        for k in cands:
            if g.node(_ag._nid("endpoint", k)):
                return _ag._nid("endpoint", k)
        return cls._graph_host_node(g, s)

    def _project_spec_params(self, g) -> None:
        """Project a fetched OpenAPI/Swagger spec's TYPED parameters into the graph.

        Q-031, the API half. `_fetch_openapi` now keeps the parsed spec in `recon["openapi"]` instead
        of garbage-collecting it, so the declared parameters survive the tool call for the first time.
        MEASURED on VAmPI before this: 14 operations, 9 body parameters, 0 of them anywhere in the
        graph -- 100% of that API's testable parameter surface invisible to the planner.

        Deliberately the SAME node/edge vocabulary and the same `observe_param` writer the form
        producer uses, so `_forms_from_graph` makes these schedulable through the path already built
        and tested. No second code path, which is the whole point of putting location on the param.
        """
        import surface as _surface
        from urllib.parse import urlparse as _up
        for base_url, spec in (self.tools.recon.get("openapi") or {}).items():
            try:
                ops = _surface.operations_from_openapi(spec, str(base_url))
            except Exception as _e:
                self.tools._swallow(_e, "project_spec_params", str(base_url))
                continue
            for op in ops:
                if not op.get("params"):
                    continue
                u = op["url"]
                try:
                    p = _up(u)
                except Exception:
                    continue
                if not p.netloc or not self.scope.validate(u)[0]:
                    continue
                ep_key = p.netloc + (p.path or "/")
                eid = g.observe("endpoint", ep_key, label=(p.path or "/"), source="openapi")
                hid = self._graph_host_node(g, u)
                if hid:
                    g.link(hid, eid, "serves", source="openapi")
                for prm in op["params"]:
                    pid = g.observe_param(ep_key, prm["name"], location=prm["location"],
                                          ptype=prm.get("type") or "",
                                          required=prm.get("required"),
                                          method=op["method"],
                                          content_type=op.get("content_type") or "",
                                          source="openapi")
                    g.link(eid, pid, "has_param", source="openapi")

    def _project_body_params(self, g) -> None:
        """Project captured FORM fields into the graph as typed `body` parameter nodes.

        Q-031 row 4. Until this, a `param` node could only ever mean a QUERY parameter: the only
        writers were `ingest_intel` (bare names, post-loop) and `build_from_engagement` (report-time,
        fed by `surface.build_inventory`, which unions query strings). **No body parameter had ever
        reached the graph from any producer, at any point in a mission.** The knowledge was not
        missing -- `crawl.extract_forms` already returns each field's name, default value AND input
        type, and it lands in `tools.recon["forms"]` -- it simply had nowhere to be recorded, which is
        the same drop-at-a-handoff shape as D3.

        The endpoint is keyed `netloc+path` to match `_graph_add_url`, so a form on an already-known
        endpoint attaches to that node rather than minting a second identity for it.
        """
        from urllib.parse import urlparse as _up
        self._project_spec_params(g)
        for fm in (self.tools.recon.get("forms") or []):
            act = str((fm or {}).get("action") or "").strip()
            if not act:
                continue
            try:
                p = _up(act)
            except Exception:
                continue
            if not p.netloc:
                continue
            ep_key = p.netloc + (p.path or "/")
            eid = g.observe("endpoint", ep_key, label=(p.path or "/"), source="form-capture")
            hid = self._graph_host_node(g, act)
            if hid:
                g.link(hid, eid, "serves", source="form-capture")
            method = str(fm.get("method") or "GET").upper()
            # `inputs` carries the declared type; `fields` is names only. Prefer inputs, fall back to
            # fields, so a producer that only ever wrote names still yields parameters.
            typed = {str(i.get("name")): str(i.get("type") or "")
                     for i in (fm.get("inputs") or []) if isinstance(i, dict) and i.get("name")}
            for name in (fm.get("fields") or []):
                if not name:
                    continue
                # A GET form's fields arrive in the query string, a POST form's in the body. Claiming
                # `body` for both would tell the planner to schedule body engines on a query surface.
                loc = "body" if method != "GET" else "query"
                pid = g.observe_param(ep_key, name, location=loc, ptype=typed.get(str(name), ""),
                                      method=method, source="form-capture")
                g.link(eid, pid, "has_param", source="form-capture")

    def _seed_and_project_graph(self, g) -> None:
        """Project ALL current engagement state into the mission graph so the graph is the single
        source the primary planner reads (CHAD: graph-authoritative execution). Seeds the in-scope
        roots as host nodes (bootstrap) and folds recon subdomains/live-hosts, discovered URLs, and
        findings into the graph. Idempotent (observe merges); best-effort.

        D5 + D13 (architecture.md 6.1). This function used to observe findings with `family=` and NO
        `enables=`, and to call `g.link` nowhere at all. MEASURED on two confirmed findings (a SQLi
        and a credential leak): `finding.enables: [[], []]`, `edges: 0`, and
        `next_best_actions(): []` — the graph recommended NOTHING, because `next_best_actions`
        (`asset_graph.py:288`) iterates `f["enables"]`, so the `chase_capability` tier had an empty
        candidate list BY CONSTRUCTION. The capability was written, registered and dead.

        The mapping already existed and was already tested — `_FINDING_ENABLES` + `_content_enables`
        (`asset_graph.py:420-441`), used by the report-time `build_from_engagement`. Only the LIVE
        path skipped it, so the planner reasoned over a strictly poorer world model than the report
        rendered. Both paths now compute `enables` from the same two helpers and use the same
        `serves` / `found_on` edge vocabulary.
        """
        try:
            import asset_graph as _ag
            for e in self.scope.in_scope:
                v = (getattr(e, "value", "") or "").lower().lstrip("*.")
                if v:
                    g.observe("host", v, label=v, source="scope")
            for s in (self.tools.recon.get("subdomains") or []):
                s = str(s).lower()
                if s:
                    g.observe("host", s, label=s, source="recon")
            eps = {}
            for h in (self.tools.recon.get("live_hosts") or []):
                u = h.get("url") if isinstance(h, dict) else str(h)
                if u:
                    eps[str(u)] = g.observe("endpoint", u, label=u, source="recon")
            for u in (self.tools.urls or []):
                if u:
                    eps[str(u)] = g.observe("endpoint", str(u), label=str(u), source="recon")
            # D13: hosts and endpoints are observed above and used to be left unconnected, so nothing
            # downstream could walk from an asset to what it serves. Same `serves` relation
            # build_from_engagement uses, so the two projections agree.
            for u, eid in eps.items():
                hid = self._graph_host_node(g, u)
                if hid:
                    g.link(hid, eid, "serves", source="recon")
            self._project_body_params(g)
            # Q-120. `ingest_intel` used to fire exactly ONCE, in `_close_autonomy_loop`, AFTER the
            # primary planning loop's last `_graph_primary_state` read (MEASURED across a full
            # mission: `graph_primary_state x14` then `ingest_intel x1`) -- so everything the harvest
            # contributes (has_login/has_api/has_sensitive_route/has_object_id, and every `route`
            # candidate) could only enrich the FINAL report/next-scan advisory, never steer the
            # mission that produced it. Re-ingesting here, every iteration this projector runs, closes
            # that gap; `ingest_intel`'s own `observe()` calls merge by key (idempotent, like every
            # other write in this function), so re-running it on a growing intel store each cycle is
            # cheap and safe. The post-loop call stays -- it feeds the separate next-scan advisory.
            _intel_store = getattr(self.tools, "intel", None)
            if _intel_store is not None:
                g.ingest_intel(_intel_store.to_dict() if hasattr(_intel_store, "to_dict") else {})
            for f in (self.findings or []):
                fam = (f.get("family") or "")
                # D5: the capability a confirmed finding unlocks — the input the chase_capability
                # tier reads and never received. Same computation as build_from_engagement.
                enables = sorted(set(_ag._FINDING_ENABLES.get(fam.lower(), []))
                                 | set(_ag._content_enables(f)))
                fid = g.observe("finding", str(f.get("id") or (f.get("title", "")[:40])),
                                label=f.get("title", "finding"), source="scan", family=fam,
                                enables=enables)
                # D13: attach the finding to the asset it was found on.
                anchor = self._graph_finding_anchor(g, f.get("target") or "")
                if anchor:
                    g.link(anchor, fid, "found_on", source="scan")
            self._graph_projection_error = None
        except Exception as e:
            # do NOT swallow silently (CHAD): a projection failure means the graph is stale, which
            # directly affects primary action selection — record it so the executor can surface it.
            self._graph_projection_error = str(e)

    @staticmethod
    def _endpoint_url(key: str, bases: dict) -> str:
        """Resolve ONE graph endpoint node to an absolute, probeable URL — or "" when the graph never
        recorded a host for it.

        MEASURED (mission 90cee81c, Q-019). The graph carries the same asset under two identities:
        `tools._graph_add_url` keys an endpoint by `host+path` but LABELS it with the bare `path`,
        while `_seed_and_project_graph` keys and labels it with the whole URL. This function's caller
        used to read the LABEL, so the planner received a host-less `/benchmark/cmdi-Index.html`, and
        `planner._b("")` concatenated that onto `https://` to produce `https:///benchmark/…` — scheme,
        EMPTY netloc. `ScopeEngine.validate()` refused every one, correctly: ten `scope_block` events
        per mission aimed at exactly the category index pages that link the whole test corpus. The
        scope engine was right; the producer handed it garbage and nothing named the producer.

        Read the KEY (the node's identity, which carries the host) and rebuild scheme+port from the
        scope's base map. Returns "" rather than a host-less string: a URL with no host is not a
        target, and manufacturing one out of an empty host is precisely how the defect happened.
        """
        from urllib.parse import urlparse as _up
        s = str(key or "").strip()
        if not s:
            return ""
        if "://" in s:
            return s if _up(s).netloc else ""
        host, sep, rest = s.partition("/")
        if not host:                     # a bare path — no host was ever recorded for this node
            return ""
        b = (bases or {})
        base = b.get(host) or b.get(host.split(":")[0]) or ("https://" + host)
        return base.rstrip("/") + (sep + rest if sep else "/")

    def _graph_primary_state(self, g):
        """Derive the planner's ASSET-SELECTION world-state FROM THE GRAPH only. roots = graph host
        labels; urls = graph endpoint identities resolved to ABSOLUTE URLs; live_hosts = the
        tool-discovered detail for hosts the GRAPH holds. An empty graph yields empty roots+urls, so
        flat recon can NEVER independently select a primary action (that is the graph-authoritative
        guarantee). Returns (roots, urls, recon)."""
        from urllib.parse import urlparse
        try:
            bases = self.scope.base_map() or {}
        except Exception:
            bases = {}
        hosts = sorted({n.get("label") for n in g.nodes("host") if n.get("label")})
        hostset = set(hosts)
        # ABSOLUTE URLs ONLY (Q-019). See _endpoint_url for why reading the label produced
        # `https:///path`. Anything that cannot be resolved to a host is DROPPED and RECORDED naming
        # the producer — a silently dropped bad URL is the same invisible failure that hid this for
        # weeks, so `_swallow` carries the count and the first offenders into the mission record.
        eps, _seen, _unresolved, _quarantined = [], set(), [], []
        import planner as _planner
        for n in g.nodes("endpoint"):
            u = self._endpoint_url(n.get("key"), bases)
            if not u:
                _unresolved.append(str(n.get("key") or n.get("label") or "")[:120])
                continue
            if u in _seen:
                continue
            # Q-080. THE GRAPH MAY KNOW A LOGOUT ENDPOINT; THE PROBE SURFACE MAY NOT CONTAIN IT.
            #
            # `tools._add_urls` keeps a session-destroying URL out of `tools.urls` and parks it in
            # `session_kill_urls`. `_project_form_params` then mints that same URL as an endpoint
            # NODE from the form action, and this loop turned every endpoint node into a planner
            # URL -- so `kill url in tools.urls` read False while `kill url in state["urls"]` read
            # True, and the planner aimed http_probe, run_form_cmdi and run_upload_test at it.
            # MEASURED: emptying `recon["forms"]` (the door Q-080 was filed for) left FOUR steps on
            # the logout URL standing, all of them arriving through here.
            #
            # The node STAYS in the graph. It is a real asset and the world model should hold it --
            # `run_session_lifecycle` needs a logout URL to exist, and dropping the node would be
            # the blindness `_add_urls` deliberately avoided when it chose quarantine over discard.
            # What is refused is its promotion to PROBE SURFACE.
            if _planner.is_session_kill_url(u):
                _quarantined.append(u)
                continue
            _seen.add(u)
            eps.append(u)
        if _quarantined:
            try:
                self.tools._swallow(
                    ValueError("%d graph endpoint node(s) name a session-destroying action and were "
                               "NOT promoted to the planner's probe surface (Q-080: probing them with "
                               "the mission session logs the scan out and every later authenticated "
                               "probe then silently tests as anonymous). First: %s"
                               % (len(_quarantined), ", ".join(_quarantined[:3]))),
                    "graph_primary_state.session_kill_quarantine", _quarantined[0])
            except Exception:
                pass
        if _unresolved:
            try:
                self.tools._swallow(
                    ValueError("%d graph endpoint node(s) carry no host, so no absolute URL exists for "
                               "them; they cannot be probed and were NOT faked onto a bare scheme. "
                               "First: %s" % (len(_unresolved), ", ".join(_unresolved[:3]))),
                    "graph_primary_state.hostless_endpoint", _unresolved[0])
            except Exception:
                pass
        # The graph stores endpoints by PATH (canonical asset identity), which DROPS the query string —
        # so the planner would probe a bare /catalog with NO parameter to inject, and every query-param
        # vuln (SQLi/reflected-XSS/header-injection/base64/DOM-data on ?category=/?searchTerm=/?productId=)
        # is unreachable. Re-attach the live surface's PARAMETERIZED URLs for endpoints the graph already
        # holds, so the injection probes actually reach the inputs. Graph-faithful (path must be a known
        # endpoint) and additive (bare-path endpoints stay in the set).
        _gp = {urlparse(u).path for u in eps}
        for _u in (self.tools.urls or []):
            if "?" not in _u:
                continue
            try:
                if urlparse(_u).path in _gp and _u not in _seen and self.scope.validate(_u)[0]:
                    _seen.add(_u)
                    eps.append(_u)
            except Exception:
                pass

        def _host_of(u):
            try:
                return urlparse(u).netloc or u
            except Exception:
                return u
        live = [h for h in (self.tools.recon.get("live_hosts") or [])
                if isinstance(h, dict) and (_host_of(h.get("url", "")) in hostset or h.get("url") in eps)]
        recon = {"subdomains": hosts, "live_hosts": live,
                 "target": self.tools.recon.get("target"), "domain": self.tools.recon.get("domain"),
                 "forms": self._forms_from_graph(g, bases)}
        return hosts, eps, recon

    def _forms_from_graph(self, g, bases: dict) -> list:
        """The planner's `recon["forms"]` list, REBUILT FROM THE GRAPH's parameter nodes.

        MEASURED defect this closes: `_graph_primary_state` returned a recon dict whose keys were
        exactly `subdomains / live_hosts / target / domain`. Every form-driven branch in the planner
        reads `state["recon"]["forms"]`, so in the deterministic executor that read `[]` no matter how
        many forms the crawl had captured -- 2 captured, 0 delivered. `run_stored_xss`, `run_csrf` and
        `run_race` therefore never fired at all; `run_auth_sqli`, `run_form_nosqli` and
        `run_form_cmdi` survived only because unrelated fallback branches re-discover forms from
        login-ish paths and page URLs, which masked the hole.

        Rebuilt from the graph rather than passed through from `tools.recon`, because the executor's
        whole contract is that the planner's world-state is graph-derived (an empty graph must yield
        no actions). That also means this is the ONE place a body parameter becomes schedulable
        surface, whatever taught it to the graph -- an HTML form today, an OpenAPI `requestBody` the
        moment a producer records one, with no second code path.
        """
        by_ep = {}
        for pnode in g.params_at("body"):
            props = pnode.get("props") or {}
            key = str(pnode.get("key") or "")
            ep_key = key.split("#", 1)[0]
            if not ep_key:
                continue
            slot = by_ep.setdefault(ep_key, {"fields": [], "method": props.get("method") or "POST",
                                             "content_type": "", "body_params": []})
            # Q-050. The MEDIA TYPE is what separates a JSON write endpoint from an HTML form, and
            # until now it was learned by `observe_param` and then dropped at this handoff. Only the
            # spec producer records one (an HTML form posts urlencoded and `_project_form_params`
            # writes none), so an absent content type is a real answer and is left absent rather
            # than defaulted to JSON -- `run_mass_assign` would then be scheduled against every
            # captured form, which is the always-fires failure mode, not reach.
            if not slot["content_type"] and props.get("content_type"):
                slot["content_type"] = str(props["content_type"])
            nm = pnode.get("label")
            if nm and nm not in slot["fields"]:
                slot["fields"].append(nm)
                # The typed parameter, in the exact shape `surface.operations_from_openapi` emits
                # and `mass_assign_tool.body_from_params` reads. A name alone cannot build a body
                # the API will accept, and a body the API rejects yields no object -- which the
                # engine reports as a clean, i.e. a false negative.
                slot["body_params"].append({"name": nm, "location": "body",
                                            "type": props.get("ptype") or "",
                                            "required": props.get("required")})
        import planner as _planner
        out = []
        for ep_key, slot in sorted(by_ep.items()):
            action = self._endpoint_url(ep_key, bases)
            if not action:            # no host recorded -> not a target (Q-019)
                continue
            # Q-080: this list IS the probe surface for run_csrf / run_race / run_form_cmdi /
            # run_stored_xss / run_auth_sqli / run_form_nosqli / run_xxe, every one of which sends
            # its requests carrying `session_headers`. A logout form's action is a real form and a
            # real body-parameter set -- and probing it ends the mission session (MEASURED: 4/4 on
            # the mount that invalidates at logout, 0/4 on the paired mount that does not). It is
            # quarantined here rather than filtered in each consumer, for the same reason the guard
            # in `planner.fresh()` is at the door: the seventh consumer must inherit it.
            if _planner.is_session_kill_url(action):
                continue
            out.append({"action": action, "method": slot["method"], "fields": slot["fields"],
                        # Q-050: additive keys. Every existing consumer reads action/method/fields
                        # and is unaffected; `planner`'s mass-assignment branch is the first reader
                        # that needs to know the media type and the DECLARED TYPE of each field.
                        "content_type": slot["content_type"], "body_params": slot["body_params"]})
        return out

    # U1 (architecture.md 6.3): the graph's ranked action -> a concrete tool.
    #
    # `AssetGraph.next_best_actions` was complete, deterministic and tested, and NOTHING executed it:
    # `plan_next()` and `apply_result()` had no non-test callers, and `_close_autonomy_loop` — which
    # reads the ranking — runs AFTER the execution loop finishes. The producer existed; the consumer
    # did not. This map is the consumer, and it is deliberately small: one tool per action, each one
    # already registered, already scoped, already permission-tiered. A capability with no entry
    # produces no step and is RECORDED as unmapped rather than silently dropped.
    # Each value is (tool, url_arg). The ARG IS PART OF THE MAPPING, not an assumption: `run_exposure`
    # reads `inp["base_url"]` while every other tool here reads `inp["url"]`, and a map that named the
    # right tool with the wrong key raised KeyError mid-scan on the first real run. A tool named is not
    # a tool invocable. `base_url` also means the origin, not the endpoint — an exposure sweep is a
    # host-level probe — so the arg selects the target shape too.
    _GRAPH_ACTION_TOOLS = {
        "cross_user_test": ("run_bfla", "url"),   # object endpoint, never compared across personas
        "run_service_pack": ("run_service_pack", None),
    }
    # chase_capability dispatches on the capability, not the action name
    _GRAPH_CAPABILITY_TOOLS = {
        "database_read": ("run_sqlmap", "url"),   # INTRUSIVE — _run_tool's HITL gate still applies
        "foreign_object_read": ("run_bfla", "url"),
        "internal_request": ("run_ssrf", "url"),
        "arbitrary_file_read": ("run_web_probes", "url"),
        "file_upload": ("run_upload_test", "url"),
        "credential_material": ("run_exposure", "base_url"),
    }
    # Per-mission ceiling on graph-directed dispatches. The point of U1 is to USE the ranking, not to
    # remove the ceiling: the list is ranked, so a budget cut-off drops the least valuable actions
    # first. Same spirit as planner.CAP_* — do not invent a second cap vocabulary.
    CAP_GRAPH_ACTIONS = 24

    def _graph_action_target(self, g, act: dict, bases: dict) -> str:
        """The absolute URL a ranked action should be aimed at, or "" when the graph cannot address it.

        Resolves from the emitting node's KEY (which carries the host), never from `target`, which is
        a LABEL — reading a label is exactly what produced `https:///benchmark/...` in Q-019. For a
        finding there is no URL on the node at all, so this walks the `found_on` edge D13 added back
        to the endpoint it was found on. That edge is why chase_capability is addressable.
        """
        n = g.node(act.get("node") or "")
        if not n:
            return ""
        if n["kind"] in ("endpoint", "object"):
            return self._endpoint_url(n["key"], bases)
        if n["kind"] == "finding":
            for nb in g.neighbors(n["id"], "found_on"):
                other = g.node(nb)
                if other and other["kind"] in ("endpoint", "object"):
                    u = self._endpoint_url(other["key"], bases)
                    if u:
                        return u
            for nb in g.neighbors(n["id"], "found_on"):
                other = g.node(nb)
                if other and other["kind"] == "host":
                    return self._endpoint_url(other["key"] + "/", bases)
        return ""

    def _graph_action_step(self, g, act: dict, bases: dict):
        """One ranked action -> one executable step dict, or None when it is not addressable.

        The step's KEY is deliberately in the PLANNER's namespace (`run_bfla:{host}{path}`) wherever a
        planner step could have covered the same ground, so `done` dedups a graph action against work
        the tool planner already did instead of re-probing it. That is the D2 lesson applied forward:
        a second producer with its own key namespace is how 8 probes got scheduled for 5 URLs.
        """
        from urllib.parse import urlparse as _up
        action = act.get("action")
        if action == "run_service_pack":
            n = g.node(act.get("node") or "")
            if not n:
                return None
            host, _, port = str(n["key"]).rpartition(":")
            if not host or not port.isdigit():
                return None
            return {"tool": "run_service_pack",
                    "input": {"host": host, "port": int(port),
                              "service": n.get("props", {}).get("service") or n["label"]},
                    "key": "run_service_pack:%s" % n["key"], "_action": act}
        if action == "chase_capability":
            entry = self._GRAPH_CAPABILITY_TOOLS.get(act.get("capability") or "")
            if not entry:
                try:
                    self.tools._swallow(
                        ValueError("graph ranked chase_capability for %r with no tool mapping; the "
                                   "action was produced and could not be executed"
                                   % act.get("capability")),
                        "graph_action.unmapped_capability", act.get("target") or "")
                except Exception:
                    pass
                return None
        else:
            entry = self._GRAPH_ACTION_TOOLS.get(action or "")
        if not entry:
            return None
        tool, arg = entry
        url = self._graph_action_target(g, act, bases)
        if not url:
            return None
        p = _up(url)
        if arg == "base_url":
            # a host-level sweep: the origin, never the endpoint path
            inp = {"base_url": "%s://%s" % (p.scheme, p.netloc)}
            key = "%s:%s" % (tool, p.netloc)
        else:
            inp = {"url": url}
            key = "%s:%s%s" % (tool, p.netloc, p.path)
        if tool == "run_bfla":
            inp["allow_delete"] = False          # SAFE methods only, as the planner schedules it
        if tool == "run_sqlmap":
            inp["intensity"] = getattr(self.tools, "intensity", "standard")
        return {"tool": tool, "input": inp, "key": key, "_action": act}

    def _graph_action_steps(self, g, done) -> list:
        """The ranked actions the graph recommends, as executable steps, bounded and deduped.

        Ranked order is preserved so a budget cut-off loses the least valuable actions — but the loop
        DRAINS the set rather than taking the top one, so the finding set does not depend on the
        ranking being stable to the millisecond (`decayed_confidence` moves with wall-clock for
        untested nodes). Order is a preference here; membership is not.
        """
        try:
            bases = self.scope.base_map() or {}
        except Exception:
            bases = {}
        budget = self.CAP_GRAPH_ACTIONS - getattr(self, "_graph_actions_run", 0)
        if budget <= 0:
            return []
        out, seen = [], set()
        for act in g.next_best_actions(limit=self.CAP_GRAPH_ACTIONS):
            step = self._graph_action_step(g, act, bases)
            if not step or step["key"] in done or step["key"] in seen:
                continue
            seen.add(step["key"])
            out.append(step)
            if len(out) >= budget:
                break
        return out

    def _reject_hostless_step(self, step: dict) -> bool:
        """Ingress guard on the planner→executor boundary: refuse a step whose target carries a scheme
        but an EMPTY netloc (`https:///x`), and RECORD it naming the producing tool.

        This is deliberately a guard *and* a recorder. Q-019's real cost was not the ten wasted probes;
        it was that the failure was invisible — the scope engine refused each one correctly, the mission
        logged a generic `scope_block`, and nothing anywhere said which component had built the broken
        URL. A guard that silently drops the bad value would reproduce that exact blindness, so the
        drop goes through `_swallow` with the tool name attached. Returns True when the step is refused.
        """
        from urllib.parse import urlparse as _up
        inp = step.get("input") or {}
        for k in ("url", "base_url", "target"):
            v = inp.get(k)
            if not isinstance(v, str) or "://" not in v:
                continue
            if _up(v).netloc:
                continue
            try:
                self.tools._swallow(
                    ValueError("planner step %r built a host-less URL %r (scheme present, netloc empty); "
                               "refused at the executor ingress rather than handed to scope"
                               % (step.get("tool"), v[:160])),
                    "execute_plan.hostless_step:%s" % step.get("tool"), v)
            except Exception:
                pass
            return True
        return False

    def _reject_session_kill_step(self, step: dict) -> bool:
        """Ingress guard on the planner→executor boundary: refuse a step aimed at a session-destroying
        URL, and RECORD it. Returns True when the step is refused.

        Q-080. `planner.fresh()` already declines to SCHEDULE one, but not every step reaching this
        loop came from the planner: `_graph_action_steps` builds steps straight off the mission
        graph's ranked actions and never passes through `fresh()`. A guard that lived only in the
        planner would close the two measured doors and leave that third one open — and this project's
        recorded failure shape is exactly a guard that checks the entrance someone already thought of.

        It is a guard *and* a recorder, for the reason `_reject_hostless_step` gives: the cost of this
        defect was never the wasted request, it was that nothing anywhere said the session had died.
        A silent drop here would keep that half of the bug. The refusal goes through `_swallow` with
        the producing tool attached.

        `run_session_lifecycle` is entitled to a quarantined URL and is exempt — the entitlement lives
        in `planner._SESSION_KILL_ENTITLED`, one list, consulted by both guards.
        """
        import planner as _planner
        u = _planner.session_kill_target(step)
        if not u:
            return False
        try:
            self.tools._swallow(
                ValueError("planner step %r targets the session-destroying URL %r; refused at the "
                           "executor ingress (Q-080: it carries the mission session, so running it "
                           "logs the scan out and every later authenticated probe silently tests as "
                           "anonymous while still reporting success)"
                           % (step.get("tool"), u[:160])),
                "execute_plan.session_kill_step:%s" % step.get("tool"), u)
        except Exception:
            pass
        return True

    async def _execute_plan(self, session_id: str):
        """Drive the planner through the SAME scoped, HITL-gated tool pipeline — but GRAPH-FIRST
        (CHAD): each step projects engagement state into the mission graph, then derives the planner's
        asset-selection world-state FROM the graph and gates on it (empty graph => no primary action).
        recon_cycles are honored; dedup + a hard step cap guarantee it ends."""
        import planner
        base_roots = [e.value.lower().lstrip("*.") for e in self.scope.in_scope]
        done, steps = set(), 0
        MAX_STEPS = 220
        cycles = self.recon_cycles
        for cyc in range(1, cycles + 1):
            if self.stop_event.is_set() or steps >= MAX_STEPS:
                break
            if cycles > 1:
                yield {"type": "cycle", "cycle": cyc, "total": cycles,
                       "content": f"Deterministic recon cycle {cyc} of {cycles} — folding in newly "
                                  "discovered in-scope assets."}
            before = self._surface_size()
            # a fresh playbook each cycle reflects everything found so far
            done.discard("generate_playbook")
            while steps < MAX_STEPS:
                if self.stop_event.is_set():
                    self._plan_steps = steps
                    return
                # GRAPH-AUTHORITATIVE primary execution (CHAD major #1): project everything into the
                # mission graph, then derive the planner's asset-selection world-state FROM the graph.
                # Flat recon populates the graph but never selects actions directly; an EMPTY graph
                # yields no roots/urls => no primary action.
                g = getattr(self.tools, "graph", None)
                if g is None:
                    # FAIL-CLOSED (CHAD): with no mission graph there is no asset-selection authority —
                    # halt primary execution rather than silently falling back to flat recon.
                    yield {"type": "info", "content": "No mission graph — primary execution halted "
                           "(the graph is the asset-selection authority; no flat-recon fallback)."}
                    break
                self._seed_and_project_graph(g)
                if getattr(self, "_graph_projection_error", None):
                    # HALT the primary planning cycle (CHAD): a projection failure means the graph is
                    # stale/partial, so the planner must NOT keep selecting actions off it. Emit + persist
                    # a structured degraded event so it shows in mission status + report.
                    self._degraded = {"reason": "graph_projection_failed",
                                      "detail": str(self._graph_projection_error)}
                    yield {"type": "degraded", "reason": "graph_projection_failed",
                           "content": "Primary execution HALTED — mission graph projection failed: %s"
                                      % self._graph_projection_error}
                    self._plan_steps = steps
                    return
                g_roots, g_urls, g_recon = self._graph_primary_state(g)
                if not g_roots and not g_urls:
                    break
                state = {"mode": self.mode, "roots": g_roots, "done": done,
                         # Q-104: the OPERATOR's declared assets, distinct from `roots`, which is
                         # every host the graph has learned about. Phase A caps its recon fan-out and
                         # ranks these first, so the cap trims discovered hosts and never an asset the
                         # operator actually put in scope.
                         "scope_roots": base_roots,
                         "recon": g_recon, "urls": g_urls,
                         "bases": self._observed_bases(),
                         # Q-065, second cause. `planner.py:641` gates run_jwt on
                         # `state["auth_headers"]` and this dict never carried that key, so the JWT
                         # blob was always `{}` plus recon cookies: only a COOKIE-borne JWT could
                         # ever schedule run_jwt, and a Bearer token -- the normal carrier, and what
                         # every SPA holding its token in localStorage uses -- never could.
                         # `auth_headers` is the API REQUEST field name (main.py:59); main.py:554
                         # immediately renames it to `session_headers`, which is what the registry
                         # holds (tools.py:1155). Producer and consumer named the same thing
                         # differently and never met -- the fifth instance of that shape here.
                         # Bound from the registry, the one place the mission's identity lives.
                         "auth_headers": getattr(self.tools, "session_headers", {}) or {},
                         # ZAP runs only when the user enabled it for this scan (and
                         # a daemon is configured); the planner's INTRUSIVE gate keeps
                         # it to Full mode. Policy rides along to the run_zap step.
                         "zap": self.enable_zap and _zap_configured(),
                         "zap_policy": self.zap_policy,
                         "zap_speed": self.zap_speed, "zap_aggression": self.zap_aggression,
                         "nmap_vuln": self.enable_nmap_vuln,
                         "nuclei_heavy": self.enable_nuclei_heavy,
                         # intensity dial (on the tool registry) rides to the planner so
                         # deep/insane can schedule the heavy sqlmap pass alongside run_sqli.
                         "intensity": getattr(self.tools, "intensity", "standard")}
                batch = planner.next_batch(state)
                if not batch:
                    # U1: the TOOL planner is at its fixpoint. Before ending the cycle, ask the GRAPH
                    # what it recommends and execute the ranked actions through this same executor.
                    # Until now `next_best_actions()` was computed and discarded — a complete,
                    # deterministic, tested producer with no consumer, and `_close_autonomy_loop`
                    # reads it only AFTER the loop has finished. Graph steps run through the identical
                    # dedup (`done`), hostless guard, budget (MAX_STEPS) and gates (`_run_tool`'s
                    # passive/HITL checks) as planner steps; nothing here bypasses a control.
                    batch = self._graph_action_steps(g, done)
                    if not batch:
                        break
                    yield {"type": "info",
                           "content": "Graph-directed execution — the world model ranked %d action(s) "
                                      "the tool planner does not schedule: %s."
                                      % (len(batch), ", ".join(
                                          "%s->%s" % (s["_action"]["action"], s["tool"]) for s in batch[:4]))}
                for step in batch:
                    if self.stop_event.is_set():
                        self._plan_steps = steps
                        return
                    done.add(step["key"])
                    if self._reject_hostless_step(step):
                        continue
                    if self._reject_session_kill_step(step):     # Q-080 — incl. graph-directed steps
                        continue
                    steps += 1
                    _act, _found = step.get("_action"), 0
                    async for ev in self._run_tool(step["tool"], step["input"], session_id):
                        if ev.get("type") == "tool_result":
                            _found = ev.get("count") or 0
                        if "_content" not in ev:      # no model to feed; drop the tool-result payload
                            yield ev
                    if _act is not None:
                        # CLOSE THE LOOP: fold the result back so the next plan_next() reflects it.
                        # `apply_result` had no non-test caller either; this is that caller. A gained
                        # capability is recorded ONLY on evidence (the tool actually confirmed
                        # something) — claiming it on a dispatch would make the graph assert a
                        # capability the run never demonstrated.
                        self._graph_actions_run = getattr(self, "_graph_actions_run", 0) + 1
                        try:
                            g.apply_result(_act, tested_ok=bool(_found),
                                           gained_capability=(_act.get("capability") if _found else None))
                        except Exception as _e:
                            self.tools._swallow(_e, "graph_action.apply_result", step["key"])
                        yield {"type": "graph_action", "action": _act["action"], "tool": step["tool"],
                               "target": step["input"].get("url") or step["input"].get("host") or "",
                               "capability": _act.get("capability"), "utility": _act.get("utility"),
                               "findings": _found,
                               "content": "Graph-directed %s -> %s on %s: %d finding(s)."
                                          % (_act["action"], step["tool"],
                                             step["input"].get("url") or step["input"].get("host") or "",
                                             _found)}
            # stop early once a cycle stops finding new surface
            if cyc < cycles and self._surface_size() <= before:
                yield {"type": "info", "content": f"Recon cycle {cyc} found no new in-scope assets — "
                       "stopping early."}
                break
        # promotion pass: re-test high-signal candidate leads with a confirmatory oracle
        async for ev in self._promote_leads(session_id):
            yield ev
        # Q-050: offline hash-type identification of credential material the TARGET disclosed during
        # this mission (WSTG-CRYP-04). PASSIVE and offline -- it reads exchanges already captured and
        # sends nothing. Placed here, after the deterministic loop, because the observation it keys
        # on lives in RESPONSE BODIES, which `planner.next_batch` state has never carried.
        async for ev in self._identify_dumped_hashes(session_id):
            yield ev
        # additive AI enhancement: business-logic hypotheses -> leads (no-op unless an AI
        # strategy is selected and usable). The model hunts; deterministic oracles confirm.
        async for ev in self._ai_business_logic_leads(session_id):
            yield ev
        # NOTE: the general candidate-validation pipeline runs LATE in the main scan flow (after the
        # technique advisor + autonomy loop have added their leads) so EVERY lead is validated, not
        # only the ones known at deterministic-pass time. See _run_scan.
        self._plan_steps = steps

    async def _browser_harvest_surface(self, session_id: str) -> int:
        """JS-RENDERED CRAWL (general technique): most modern apps (SPAs, React/Angular, GinAndJuice)
        build their navigation, product links and search/param forms in JavaScript, which the HTTP
        crawler never sees — so the injection probes have nothing to test. Render the app with the
        headless browser, one level deep, and harvest the CLIENT-RENDERED links + form params into the
        injectable surface (self.tools.urls + recon['forms']). Target-agnostic; no-ops with no browser.
        Returns the count of new parameter-bearing endpoints surfaced."""
        import os as _os
        if not _os.environ.get("CDP_BROWSER_URL"):
            return 0
        import browser_engine as _be
        from urllib.parse import urljoin
        # Q-060, third instance of the same shape — found by auditing agent.py for it rather than
        # by the ticket, which named only the two posture drivers. This seeded the frontier from
        # bare scope hosts + a default scheme, and the very next loop drops any seed that fails
        # `self.scope.validate(u)[0]` — so on every non-standard-port target the JS-rendered
        # harvest started with an empty frontier and returned 0, which is indistinguishable from an
        # app that has no client-rendered surface.
        seeds = self._scope_origins()[:2]
        from urllib.parse import urlparse as _up, parse_qs as _pq
        seen, frontier, before = set(), list(seeds), set(self.tools.urls or [])
        sig_seen = set()                           # (path, sorted-param-names) already surfaced ONCE
        for _depth in range(2):                    # homepage + one level of rendered links
            nxt, links = [], []
            for u in rank_targets_for_budget(frontier)[:10]:
                u = u.split("#")[0]
                if u in seen or not self.scope.validate(u)[0]:
                    continue
                seen.add(u)
                try:
                    obs = await asyncio.to_thread(_be.observe, u)
                except Exception:
                    continue
                if not obs or obs.get("browser") is False:
                    continue
                base = obs.get("target") or u
                for href in (obs.get("links") or []):
                    absu = urljoin(base, str(href)).split("#")[0]
                    if not absu.startswith("http") or not self.scope.validate(absu)[0]:
                        continue
                    nxt.append(absu)               # follow every distinct link for the crawl frontier
                    # but surface only ONE representative per (path, param-signature) so 18 productId
                    # VALUE-variants can't crowd the injectable category/searchTerm out of the probe cap
                    pr = _up(absu)
                    sig = (pr.path, tuple(sorted(_pq(pr.query).keys())))
                    if sig in sig_seen:
                        continue
                    sig_seen.add(sig)
                    links.append(absu)
                self._harvest_rendered_forms(obs.get("forms") or [], base)
            if links:
                self.tools._add_urls(links)
            frontier = list(dict.fromkeys(nxt))
        new_params = [u for u in (self.tools.urls or []) if u not in before and "?" in u]
        return len(new_params)

    def _harvest_rendered_forms(self, forms: list, page_url: str) -> None:
        """Turn browser-rendered forms into injectable surface, mirroring http_probe: a GET form becomes a
        parameterized URL (action?field=1&…) so query-injection probes reach it; a POST form is stored so
        the planner can reach POST-body sinks (e.g. GinAndJuice's XML stock-check → run_xxe)."""
        from urllib.parse import urljoin
        store = self.tools.recon.setdefault("forms", [])
        seen_actions = {f.get("action") for f in store}
        synth = []
        for fm in forms or []:
            action = urljoin(page_url, str(fm.get("action") or page_url)).split("#")[0]
            if not self.scope.validate(action)[0]:
                continue
            method = str(fm.get("method") or "get").upper()
            names = [n for n in (fm.get("inputs") or []) if n]
            if method == "POST":
                if action not in seen_actions:
                    # `page` is what the injection sweep schedules: the engines re-parse the document to
                    # rebuild the form, and a bare action usually answers without a <form> in it.
                    store.append({"action": action, "method": "POST", "fields": names, "page": page_url})
                    seen_actions.add(action)
            elif names:
                sep = "&" if "?" in action else "?"
                synth.append(action + sep + "&".join("%s=1" % n for n in names[:12]))
        if synth:
            self.tools._add_urls(synth)

    async def _inject_sweep_surface(self, session_id: str):
        """Deterministic coverage guarantee: directly run the injection probes on EVERY distinct
        parameterized endpoint on the live surface (one representative per path + param-signature), so a
        discovered query input is ALWAYS tested even if the graph-authoritative planner did not select
        it. Reuses _run_tool, so findings auto-store through the same scope/HITL-gated path. Bounded."""
        from urllib.parse import urlparse, parse_qs
        # API-FIRST SEEDING (before targets are gathered): a linkless JSON API or a GraphQL host yields nothing
        # to an HTML crawl, so its whole surface is invisible. Auto-fetch the OpenAPI spec (fetch_openapi seeds
        # every documented endpoint into self.tools.urls via _add_urls) and probe GraphQL (run_graphql
        # auto-discovers /graphql + introspection). Cheap: a few GETs per distinct base host; both self-skip a
        # non-API/non-GraphQL host. This is what lets the injection/authz engines below reach an API target.
        _bases = list(self._scope_origins())
        # derive base hosts from the crawl AND the scope's target roots — a linkless JSON API leaves the crawl
        # empty, so the scope roots are what let the API sweep start at all (this was the vampi 0% root cause).
        for u in (list(self.tools.urls or []) + list(self.scope.base_urls() or [])):
            pr = urlparse(u)
            b = "%s://%s" % (pr.scheme, pr.netloc)
            if b and pr.scheme and b not in _bases and self.scope.validate(b)[0]:
                _bases.append(b)
        for b in _bases[:6]:
            if self.stop_event.is_set():
                return
            for _spec in ("/openapi.json", "/swagger.json", "/v3/api-docs", "/api-docs", "/swagger/v1/swagger.json"):
                try:
                    async for ev in self._run_tool("fetch_openapi", {"url": b + _spec}, session_id):
                        if "_content" not in ev:
                            yield ev
                except Exception as _e:
                    self.tools._swallow(_e, "sweep.fetch_openapi", b + _spec)
            try:
                async for ev in self._run_tool("run_graphql", {"url": b}, session_id):
                    if "_content" not in ev:
                        yield ev
            except Exception as _e:
                self.tools._swallow(_e, "sweep.run_graphql", b)
        # PATH-PARAMETER SQLi on REST endpoints: an OpenAPI-seeded /users/v1/{id} carries its id in the PATH,
        # which the query-string injection sweep below never touches. Fuzz the id segment of each distinct
        # numeric-path endpoint (the API half's flagship injection vector). Bounded + deduped by path shape.
        _seen_psig = set()
        for u in rank_targets_for_budget(list(dict.fromkeys(self.tools.urls or []))):
            if self.stop_event.is_set():
                return
            pr = urlparse(u)
            if pr.query or not self.scope.validate(u)[0]:
                continue
            psig = tuple("#" if s.isdigit() else s for s in pr.path.split("/"))
            if "#" not in psig or psig in _seen_psig:
                continue
            _seen_psig.add(psig)
            try:
                async for ev in self._run_tool("run_path_sqli", {"url": u}, session_id):
                    if "_content" not in ev:
                        yield ev
            except Exception as _e:
                self.tools._swallow(_e, "sweep.run_path_sqli", u)
            if len(_seen_psig) >= 25:
                break
        # THE BUDGET IS PASSED EXPLICITLY (Q-019). The call site used to omit `limit`, so the function
        # signature's default — 20 — was the real bound on the whole sweep, and nothing at the call site
        # said so. Naming it here makes the budget visible where the cost is paid.
        # Q-113. THE DENOMINATOR IS BUILT FIRST AND KEPT. `sweep_targets` returns only the survivors,
        # so a mission that used it could never say how much surface it had walked away from — and
        # "0 confirmed across 465 endpoints" and "0 confirmed across the 40 we chose" are different
        # claims about the target, only one of which is evidence.
        _candidates = sweep_candidates(self.tools.urls, self.tools.recon.get("forms"),
                                       lambda u: self.scope.validate(u)[0])
        targets = select_sweep_targets(_candidates, SWEEP_TARGET_CAP,
                                       scope_roots=operator_roots(self.scope))
        _declined = len(_candidates) - len(targets)
        # A COUNTED FACT, NOT A FORMATTED STRING. Q-110 made its truncation countable for the same
        # reason: a number that exists only inside a log line cannot be read by the report, and the
        # report is where "we tested 40 of 465" has to survive to.
        self._sweep_budget = {"candidates": len(_candidates), "selected": len(targets),
                              "declined": _declined, "cap": SWEEP_TARGET_CAP}
        # Q-159. THE DEDUP KEY MUST INCLUDE THE FRAGMENT, or every route of a single-page app is
        # the same endpoint. `urlparse("http://h/#/contact").path` is "/", so #/contact, #/login,
        # #/about and the bare page all collapse to one key -- the base page claims it and every
        # discovered SPA route is then declared already swept. Q-157 put five routes on the surface
        # and this line silently discarded four of them and the fifth as duplicates of "/".
        swept_paths = {_dom_sweep_key(t) for t in targets}  # what the param sweep already DOM-traced
        if not targets:
            return
        # EXHAUSTION IS REPORTED, NEVER SILENT (Q-093, Q-110). The declined count is stated in the same
        # breath as the coverage claim, so the claim cannot be read as whole-surface coverage.
        _budget_note = (
            "BUDGET: %d of %d candidate endpoint(s) selected by security value + operator scope; "
            "%d DECLINED and NOT tested, so a clean result here is a claim about the %d probed and "
            "not about the %d discovered (raise BBH_SWEEP_TARGETS to widen)."
            % (len(targets), len(_candidates), _declined, len(targets), len(_candidates))
            if _declined else
            "BUDGET: the full candidate surface of %d endpoint(s) was selected, 0 declined."
            % len(_candidates))
        yield {"type": "info", "content": "Deterministic injection sweep: directly probing %d "
               "parameterized endpoint(s) for SQLi / reflected-XSS / header-injection / open-redirect + "
               "runtime DOM source-to-sink (coverage guarantee, planner-independent). The %d "
               "browser-backed confirmer(s) at the front of the shape-spread order additionally get "
               "run_xss + run_dom_trace (~19 s each, measured). %s"
               % (len(targets), min(SWEEP_BROWSER_CAP, len(targets)), _budget_note)}
        # encoded-cookie/param injection once per distinct host base (cookies are host-wide)
        _cookie_origins = list(self._scope_origins())
        for t in targets:
            _p = urlparse(t)
            _origin = "%s://%s" % (_p.scheme, _p.netloc)
            if _origin not in _cookie_origins:
                _cookie_origins.append(_origin)
        for hb in _cookie_origins[:6]:
            try:
                async for ev in self._run_tool("run_encoded_cookie", {"url": hb}, session_id):
                    if "_content" not in ev:
                        yield ev
            except Exception as _e:
                self.tools._swallow(_e, "sweep.run_encoded_cookie", hb)
        # default-credentials check on any discovered KNOWN admin interface (Tomcat Manager / JBoss jmx-console).
        # Planner-independent coverage guarantee; the tool self-skips non-product paths + tries ONE vendor default.
        import default_creds_tool as _dc
        for u in list(dict.fromkeys(self.tools.urls or [])):
            if self.stop_event.is_set():
                return
            if not self.scope.validate(u)[0] or not _dc.match(urlparse(u).path):
                continue
            try:
                async for ev in self._run_tool("run_default_creds", {"url": u}, session_id):
                    if "_content" not in ev:
                        yield ev
            except Exception as _e:
                self.tools._swallow(_e, "sweep.run_default_creds", u)
        # TWO TIERS, TWO BUDGETS (Q-019). MEASURED per URL on a live lab: the eight HTTP-only engines
        # below total 1.1 s, run_xss 10 s and run_dom_trace 9 s. Running all ten on every target made
        # the sweep 20x more expensive than its evidence justified, which is what forced the cap to 20.
        # Every selected target still gets the full deterministic HTTP battery; the browser-backed pair
        # runs on the leading SWEEP_BROWSER_CAP shape-representatives.
        # Q-113 · THE WALL-CLOCK BOUND. Checked BETWEEN endpoints, never mid-endpoint: a half-probed
        # endpoint is the same "failed attempt reported as a clean result" that Q-093 forbids, so the
        # sweep finishes the target it is on and then stops.
        _sweep_started = _sweep_clock()
        for _i, u in enumerate(targets):
            if SWEEP_WALL_BUDGET_S and _i and (_sweep_clock() - _sweep_started) > SWEEP_WALL_BUDGET_S:
                _left = len(targets) - _i
                self._sweep_budget["timed_out"] = _left
                self._sweep_budget["declined"] += _left
                self._sweep_budget["selected"] = _i
                # Q-133 · THE PENDING QUEUE. "505 declined" tells the operator how much was skipped
                # and nothing about WHICH, so the only way to cover it was to re-run the whole scan
                # and spend the same budget on the same first 49 endpoints. The untested targets are
                # in hand right here; not persisting them was the difference between a bounded scan
                # and a resumable one. Capped so a 10k-endpoint surface cannot bloat the mission
                # record, and the cap is REPORTED rather than silently truncating.
                self._sweep_budget["pending"] = list(targets[_i:_i + _PENDING_KEEP])
                self._sweep_budget["pending_truncated"] = max(0, _left - _PENDING_KEEP)
                self._sweep_budget["resume"] = (
                    "re-run with BBH_SWEEP_BUDGET_S raised (0 disables the bound), or scope the "
                    "next mission to the %d pending endpoint(s) recorded on this one" % _left)
                # DEGRADED, NOT DONE. The remaining endpoints were never probed and their absence
                # from the findings is a fact about this run's clock, not about the target.
                yield {"type": "degraded", "reason": "sweep_wall_budget_exhausted",
                       "content": "DEGRADED: injection sweep wall-clock budget of %d s exhausted "
                                  "after %d of %d selected endpoint(s); %d further endpoint(s) "
                                  "DECLINED and NOT tested. A clean result covers the %d probed "
                                  "only (raise BBH_SWEEP_BUDGET_S, or 0 to disable)."
                                  % (SWEEP_WALL_BUDGET_S, _i, len(targets), _left, _i)}
                break
            for tool in (_SWEEP_HTTP_ENGINES + (_SWEEP_BROWSER_ENGINES if _i < SWEEP_BROWSER_CAP else ())):
                if self.stop_event.is_set():
                    return
                try:
                    async for ev in self._run_tool(tool, {"url": u}, session_id):
                        if "_content" not in ev:
                            yield ev
                except Exception as _e:
                    # THE 92% SITE (Q-052). MEASURED on a whole-product mission this loop is 3350 of
                    # 4059 dispatches, so a bare `pass` here made most of the product's engine
                    # failures indistinguishable from a clean target. The handler still swallows --
                    # one broken engine must not abort a mission -- but the failure is now RECORDED.
                    self.tools._swallow(_e, "sweep.%s" % tool, u)
        # HTML-PAGE coverage guarantee: many injection points live on pages with NO query string — a POST
        # form (login username -> reflected XSS), or a client param the page reads that no crawl edge links
        # (/login?redirect, /catalog?category -> DOM data / CSTI). The parameterized sweep above skips them.
        # Run the DOM/form engines (which do their OWN param discovery) on distinct crawled HTML pages so
        # these are ALWAYS reached, not left to the planner. Bounded; deduped by path.
        seen_paths, cand = set(), []
        # crawler noise (feeds/ads/well-known/image-proxy/api-doc echoes) pollutes the surface and would
        # push the real app pages past the cap — drop it so /login, /catalog, /blog etc. are actually reached.
        _NOISE = ("/image/", "/api/", "/feed", "/feeds", "/atom", "/ads", "/app-ads", "/favicon",
                  "/.well-known", "/robots", "/sitemap", "//")
        _HIVALUE = ("login", "register", "signin", "sign-in", "signup", "sign-up", "account", "profile",
                    "contact", "feedback", "search", "subscribe", "comment", "reset", "forgot")
        for u in (self.tools.urls or []):
            if not self.scope.validate(u)[0]:
                continue
            pth = urlparse(u).path or "/"
            if pth in seen_paths:
                continue
            low = pth.lower()
            if any(low.endswith(x) for x in (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                                             ".woff", ".woff2", ".ttf", ".map", ".pdf", ".json", ".xml", ".txt")):
                continue
            if any(n in low for n in _NOISE):
                continue
            seen_paths.add(pth)
            # priority: auth/form pages first (a login/register form is the reflected-XSS/dom hot spot),
            # then shallow top-level sections — so the cap keeps the high-value pages, not deep noise.
            pri = (100 if any(h in low for h in _HIVALUE) else 0) + max(0, 8 - low.count("/"))
            cand.append((-pri, pth, u.split("?")[0] if "?" in u else u))
        cand.sort()
        pages = [u for _, _, u in cand][:12]
        if pages:
            yield {"type": "info", "content": "HTML-page sweep: POST-form-XSS + source-to-sink on %d distinct "
                   "app page(s); CSTI/proto DOM audit on the ones with discoverable params (reaches unlinked "
                   "params like /catalog?category + form fields like /login username)." % len(pages)}
            for _pi, u in enumerate(pages):
                if self.stop_event.is_set():
                    return
                # Q-113. THE DEADLINE GOVERNS THE WHOLE PHASE, not just the parameterized half. On a
                # target where an endpoint costs ~6 min these twelve pages are hours of their own, so
                # a bound that stopped at the loop above would leave the phase still unable to finish.
                if SWEEP_WALL_BUDGET_S and _pi and (_sweep_clock() - _sweep_started) > SWEEP_WALL_BUDGET_S:
                    self._sweep_budget["html_pages_declined"] = len(pages) - _pi
                    # Q-133: the HTML pass has a pending queue too. 11 of 12 pages went untested on
                    # the operator's run and the report named none of them.
                    self._sweep_budget["pending_pages"] = list(pages[_pi:_pi + _PENDING_KEEP])
                    yield {"type": "degraded", "reason": "sweep_wall_budget_exhausted",
                           "content": "DEGRADED: injection sweep wall-clock budget of %d s exhausted "
                                      "during the HTML-page pass; %d of %d app page(s) DECLINED and "
                                      "NOT tested for form-XSS / source-to-sink / CSTI."
                                      % (SWEEP_WALL_BUDGET_S, len(pages) - _pi, len(pages))}
                    return
                # form-XSS + XPath-injection run on every app page (both self-skip pages with no form; an
                # XML-backed login form is the classic XPath surface). DOM source-to-sink trace runs only
                # where the parameterized sweep did NOT already cover this path — otherwise it re-reports the
                # same DOM link/data twice (the /blog search over-report doubling).
                # session-token predictability sampling (16 fresh GETs) runs ONLY on session-issuing pages
                # (root / login / account), never on every HTML page — otherwise it's 16xN wasted requests.
                _sess_page = urlparse(u).path in ("", "/") or any(k in u.lower() for k in ("login", "signin", "account", "home"))
                # username-enumeration differential runs ONLY on a login-style page AND only when we already
                # hold a known-existing account (verified login / persona) to be the ground-truth 'present'
                # probe — otherwise it self-skips. Never a password guess.
                _login_page = any(k in u.lower() for k in ("login", "signin", "sign-in", "log-in", "sign_in"))
                _have_known = bool(getattr(self.tools, "_enum_known_username", "")
                                   or (getattr(self.tools.state, "identities", {}) or {}))
                # session fixation needs a VERIFIED working credential (to drive a real successful login) — only
                # available on an authenticated scan; runs once per mission (the tool self-guards).
                _have_cred = bool(getattr(self.tools, "_fixation_credential", None))
                _htools = ["run_form_xss", "run_xpath", "run_ldap", "run_ssi", "run_client_checks"] \
                    + (["run_session_token"] if _sess_page else []) \
                    + (["run_username_enum"] if (_login_page and _have_known) else []) \
                    + (["run_session_fixation"] if (_login_page and _have_cred) else []) \
                    + (["run_dom_trace"] if _dom_sweep_key(u) not in swept_paths else [])
                # web cache deception needs an authenticated session to have a private page to leak — only
                # add it on an authed scan (it self-skips otherwise, but this avoids a pointless call/page).
                if getattr(self.tools, "session_headers", None):
                    _htools.append("run_cache_deception")
                for tool in _htools:
                    try:
                        async for ev in self._run_tool(tool, {"url": u}, session_id):
                            if "_content" not in ev:
                                yield ev
                    except Exception as _e:
                        self.tools._swallow(_e, "sweep.html.%s" % tool, u)
                # the CSTI/prototype-pollution/gadget DOM audit is browser-heavy — run it only where param
                # discovery found a reflecting/JS-read param (a real DOM/CSTI candidate), so it stays bounded.
                try:
                    disc = await self.tools._discover_params(u)
                except Exception as _e:
                    # A crash here does not merely lose one engine: `disc` falling back to [] SKIPS
                    # run_dom_audit entirely, so the CSTI/prototype-pollution class goes untested and
                    # the run reports clean. Recording it is what tells those two cases apart.
                    self.tools._swallow(_e, "sweep.discover_params", u)
                    disc = []
                if disc:
                    try:
                        async for ev in self._run_tool("run_dom_audit", {"url": u}, session_id):
                            if "_content" not in ev:
                                yield ev
                    except Exception as _e:
                        self.tools._swallow(_e, "sweep.run_dom_audit", u)

    async def _run_deterministic(self, session_id: str):
        yield {"type": "info", "content": f"Deterministic scan planner engaged ({self.mode} mode, no AI) — "
               "recon → live hosts → fingerprint → enrich → surface probes → nuclei → playbook."}
        # JS-rendered crawl FIRST: seed the injectable surface with client-rendered links + form params
        # (SPAs hide these from the HTTP crawler), so the injection probes have real inputs to test.
        try:
            _u0 = len(self.tools.urls or [])
            _np = await self._browser_harvest_surface(session_id)
            _u1 = len(self.tools.urls or [])
            yield {"type": "info", "content": "JS-rendered crawl: %d client-rendered parameterized "
                   "endpoint(s) surfaced (surface %d→%d URLs)." % (_np, _u0, _u1)}
        except Exception as _e:
            yield {"type": "info", "content": "JS-rendered crawl skipped (%s: %s)." % (type(_e).__name__, str(_e)[:80])}
        async for ev in self._execute_plan(session_id):
            yield ev
        # COVERAGE GUARANTEE: directly probe every distinct parameterized endpoint on the surface, so a
        # discovered query input is ALWAYS tested even if the graph-authoritative planner did not select
        # it. This is the reliable "endpoint -> technique -> validator" path CHAD requires.
        try:
            async for ev in self._inject_sweep_surface(session_id):
                yield ev
        except Exception as _e:
            yield {"type": "info", "content": "Injection sweep skipped (%s)." % type(_e).__name__}
        note = " AI was unavailable; deterministic coverage completed." if self.ai_degraded else ""
        if not self.ai_note:
            self.ai_note = ("Deterministic (no-AI) coverage completed." if not self.ai_degraded
                            else self.ai_note)
        yield {"type": "complete", "content":
               f"Deterministic scan complete — {getattr(self, '_plan_steps', 0)} step(s).{note} "
               "See Playbooks for cURL-ready leads and the report."}

    # ── low-AI executor (planner + ≤2 targeted AI calls) ─────────
    async def _run_low_ai(self, objective: str, session_id: str):
        # AI call #1 (optional): only when there IS a specific objective and budget
        # allows — a generic objective adds no signal, so we save the call for #2.
        if self._budget_left() and objective and not _is_generic_objective(objective):
            try:
                pri = await self._ai_text(
                    "You are a lead penetration tester. Given the objective and scope, list 3-6 concise, "
                    "weighted testing priorities (most important first) as short bullet lines. No preamble.",
                    f"OBJECTIVE:\n{objective}\n\nSCOPE:\n{json.dumps(self.scope.to_dict())}")
                if pri:
                    yield {"type": "text", "content": "Testing priorities (AI):\n" + pri}
                yield self._budget_event()
            except Exception as e:
                yield {"type": "info", "content": f"AI prioritization skipped ({type(e).__name__})."}
                yield self._budget_event()   # the attempt counted; keep the chip in sync

        yield {"type": "info", "content": f"Low-AI scan — deterministic planner ({self.mode} mode) with an "
               "AI wrap-up. Budget: " + f"{self.ai_calls}/{self.max_ai_calls} calls used."}
        async for ev in self._execute_plan(session_id):
            yield ev

        # AI call #2 (the high-value one): summarize evidence + prioritize leads.
        wrapped = False
        if self._budget_left():
            try:
                async for ev in self._ai_wrapup(session_id):
                    yield ev
                wrapped = True
            except Exception as e:
                self.ai_note = f"Low-AI: deterministic scan completed; AI wrap-up skipped ({type(e).__name__})."
                yield {"type": "info", "content": f"AI wrap-up skipped ({type(e).__name__})."}
                yield self._budget_event()   # the attempt counted; keep the chip in sync
        if not self.ai_note:
            self.ai_note = (f"Low-AI: deterministic scan + AI wrap-up ({self.ai_calls} AI call(s))."
                            if wrapped else f"Low-AI: deterministic scan ({self.ai_calls} AI call(s)).")
        yield {"type": "complete", "content":
               f"Low-AI scan complete — {getattr(self, '_plan_steps', 0)} step(s), "
               f"{self.ai_calls}/{self.max_ai_calls} AI call(s). See Playbooks and the report."}

    async def _ai_wrapup(self, session_id: str):
        """AI call #2: turn the deterministic evidence into an executive summary +
        prioritized next leads, stored on the mission for the report."""
        inv = self.tools.surface_inventory()
        # GATED: this list is asserted to the model as "confirmed findings", so a proof-demoted lead
        # reaching it would put an unproven claim into the executive summary a human reads first.
        findings = db.get_findings_gated(self.mission_id) if self.mission_id else []
        findings = [f for f in findings
                    if str((f or {}).get("confidence") or "confirmed").lower() != "lead"]
        pb = []
        if self.mission_id:
            m = db.get_mission(self.mission_id)
            pb = [g.get("title") for g in ((m or {}).get("context", {}).get("playbook") or [])][:15]
        payload = {"scope": self.scope.to_dict().get("in_scope", []),
                   "surface": inv.get("stats", {}),
                   "findings": [{"title": f.get("title"), "severity": f.get("severity"),
                                 "target": f.get("target")} for f in findings],
                   "playbook_leads": pb}
        summary = await self._ai_text(
            "You are a lead penetration tester writing the executive summary of an authorized assessment. "
            "Given the surface stats, any confirmed findings, and the rule-based playbook leads, write: "
            "(1) a 2-4 sentence honest summary (if nothing was confirmed, say so plainly), then "
            "(2) 'Top leads to test next:' with 3-6 prioritized bullets referencing the playbook. Be specific.",
            json.dumps(payload), max_tokens=900)
        yield self._budget_event()
        if summary:
            yield {"type": "summary", "content": summary}
            if self.mission_id:
                m = db.get_mission(self.mission_id)
                ctx = dict((m or {}).get("context", {}))
                ctx["ai_summary"] = summary
                db.update_mission(self.mission_id, context=ctx)

    async def _triage(self):
        if not self.mission_id:
            return
        findings = db.get_findings(self.mission_id)
        if not findings:
            return
        self.current_phase = "report"
        yield {"type": "phase", "phase": "report"}
        result = triage_mod.triage(findings)
        # Q-090-D. `verdict` and `chains` were computed from `findings` BEFORE any write. Writing an
        # annotation back re-evaluates the finding gate, and two of its four outcomes mean the row is
        # not carrying the edit: a TRUTH (#7) reroute DELETES the row and appends it to the leads
        # list, and a SCOPE (#8) refusal leaves the stored row untouched. So the reported set is
        # rebuilt from what the writes actually did, never from the pre-write list.
        in_table, left_table, write_refused = [], [], []
        for f in findings:
            ann = result["annotations"].get(f.get("id"))
            if not ann:
                in_table.append(f)
                continue
            f["cwe"] = f.get("cwe") or ann["cwe"]
            f["owasp"] = ann["owasp"]
            existing = f.get("analyst_notes", "")
            f["analyst_notes"] = (existing + " | " + ann["analyst_notes"]).strip(" |") if existing else ann["analyst_notes"]
            # scoped to (mission, id) — tenant isolation (#10). READ THE VERDICT, NEVER THE BOOL:
            # `bool(FindingUpdateResult)` is True for a reroute that DELETED the row, exactly as it is
            # for a real in-place update, and that ambiguity is the whole defect.
            written = db.update_finding(self.mission_id, f["id"], f)
            if written.verdict in (db.UPDATE_REROUTED, db.UPDATE_MISSING):
                left_table.append({"id": f.get("id"), "verdict": written.verdict})
                continue                                    # no row remains: it is not in the report
            if written.verdict == db.UPDATE_REFUSED:
                write_refused.append({"id": f.get("id"), "verdict": written.verdict})
            in_table.append(f)                              # the row is still there, annotated or not
        if left_table:
            result = triage_mod.triage(in_table)            # the count/chains the table can back
        m = db.get_mission(self.mission_id)
        ctx = (m or {}).get("context", {})
        ctx["chains"] = result["chains"]
        db.update_mission(self.mission_id, context=ctx)
        event = {"type": "triage", "verdict": result["verdict"], "chains": result["chains"]}
        if left_table or write_refused:
            # `main.py` persists every streamed event under its own type, so naming the gap here
            # makes it durable instead of a line that scrolled past once.
            event["annotation_gap"] = {"left_the_table": left_table, "write_refused": write_refused}
        yield event

    def _recon_note(self) -> str:
        """Iterative-recon directive. Empty at 1 cycle (default = unchanged)."""
        n = self.recon_cycles
        if n <= 1:
            return ""
        return (
            f"\n\nITERATIVE RECON: Perform up to {n} recon cycles before active/intrusive testing. "
            "After each recon pass, review the newly discovered in-scope subdomains, live hosts, URLs, "
            "technologies, and OpenAPI/GraphQL hints, then run passive/active recon again ONLY on assets you "
            "have not yet covered, to deepen the surface. Deduplicate — never re-run the same tool against a "
            "target already covered, and do not repeat intrusive tools across cycles. Every discovered target "
            "is still scope-validated. Stop early and proceed to the next phase once a cycle yields no new "
            "in-scope assets.")

    def _system(self) -> str:
        # Surface any non-default target base (explicit scheme/port, e.g. a local app
        # on http://host:42000) so the model probes it instead of assuming https:443.
        nonstd = [u for u in self.scope.base_urls()
                  if not (u.startswith("https://") and u.count(":") == 1)]
        seed = ("\n\nTARGET BASE URLS — probe these EXACT scheme+port (do NOT assume https on 443):\n"
                + "\n".join(f"- {u}" for u in sorted(nonstd))) if nonstd else ""
        return (SYSTEM_PROMPT + MODE_NOTES.get(self.mode, "") + self._recon_note()
                + (self.memory_note or "")
                + f"\n\nSCOPE:\n{json.dumps(self.scope.to_dict(), indent=2)}" + seed)

    # ── ReAct loop guards (dedup + no-progress + budget) ─────────
    def _surface_size(self) -> int:
        return (len(self.tools.urls) + len(self.tools.recon.get("subdomains", []))
                + len(self.tools.recon.get("live_hosts", [])) + len(self.findings))

    @staticmethod
    def _tool_sig(name: str, inp: dict) -> str:
        try:
            return name + ":" + json.dumps(inp, sort_keys=True)[:200]
        except Exception:
            return name + ":?"

    async def _react_finish(self, session_id: str, reason: str):
        """Deterministic wrap-up when the ReAct loop hits its budget or stalls —
        guarantees a playbook and a clean completion instead of burning calls."""
        yield {"type": "info", "content": f"Wrapping up ({reason}) — generating the deterministic playbook."}
        m = db.get_mission(self.mission_id) if self.mission_id else None
        if not ((m or {}).get("context", {}).get("playbook")):
            async for ev in self._run_tool("generate_playbook", {}, session_id):
                if "_content" not in ev:
                    yield ev
        yield {"type": "complete", "content": f"Analysis complete ({reason}). See Playbooks and the report."}

    # ── OpenRouter / OpenAI ──────────────────────────────────────
    async def _run_openrouter(self, objective: str, session_id: str):
        messages = [{"role": "system", "content": self._system()},
                    {"role": "user", "content": objective}]
        openai_tools = self.tools.get_openai_tools()
        called, stall, last = set(), 0, self._surface_size()

        while True:
            if self.stop_event.is_set():
                yield {"type": "complete", "content": "Hunt stopped by user."}
                return
            if not self._budget_left():
                async for ev in self._react_finish(session_id, f"AI budget reached ({self.max_ai_calls} calls)"):
                    yield ev
                return
            self.ai_calls += 1
            yield self._budget_event()
            response = await self.client.chat.completions.create(
                model=self.model, messages=messages, tools=openai_tools, max_tokens=4096)
            msg = response.choices[0].message
            if msg.content:
                yield {"type": "text", "content": msg.content}
            if not msg.tool_calls:
                yield {"type": "complete", "content": "Analysis complete. Check the report for findings."}
                return
            messages.append({"role": "assistant", "content": msg.content,
                             "tool_calls": [{"id": tc.id, "type": "function",
                                             "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                                            for tc in msg.tool_calls]})
            for tc in msg.tool_calls:
                try:
                    tool_input = json.loads(tc.function.arguments)
                except json.JSONDecodeError:
                    tool_input = {}
                sig = self._tool_sig(tc.function.name, tool_input)
                # dedup: an identical earlier scanner call is skipped (loop guard). The
                # investigative primitives are EXEMPT — the same request legitimately runs
                # again across a state change (before/after auth, mutation, role swap), so
                # deduping them would break stateful retesting.
                _repeatable = ("generate_playbook", "store_finding", "http_read", "http_request",
                               "http_diff", "confirm_idor", "enumerate_ids", "acquire_session",
                               "browser_navigate", "test_numeric_abuse")
                if sig in called and tc.function.name not in _repeatable:
                    yield {"type": "info", "content": f"Skipped duplicate {tc.function.name} (loop guard)."}
                    messages.append({"role": "tool", "tool_call_id": tc.id,
                                     "content": json.dumps({"success": True,
                                     "note": "deduplicated: identical call already executed this run"})})
                    continue
                called.add(sig)
                content = "{}"
                async for ev in self._run_tool(tc.function.name, tool_input, session_id):
                    if "_content" in ev:
                        content = ev["_content"]
                    else:
                        yield ev
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": content})
            # no-progress guard. PROGRESS IS MORE THAN NEW URLS: a real investigation makes
            # progress by confirming findings, acquiring sessions/capabilities, or changing
            # state — not only by discovering surface. Count all of them, so the loop is not
            # killed mid-investigation just because it stopped finding new endpoints.
            cur = (self._surface_size()
                   + len(getattr(self, "_stored_fps", ()) or ())          # findings confirmed/stored
                   + len(getattr(self.tools, "_sessions", {}) or {})       # identities acquired
                   + int(getattr(self.tools, "_login_attempts", 0) or 0))  # auth/state actions taken
            stall = stall + 1 if cur <= last else 0
            last = cur
            if stall >= 4:
                async for ev in self._react_finish(session_id, "no further progress (surface, findings, or sessions)"):
                    yield ev
                return

    # ── Anthropic ────────────────────────────────────────────────
    async def _run_anthropic(self, objective: str, session_id: str):
        messages = [{"role": "user", "content": objective}]
        tool_defs = self.tools.get_claude_tools()
        called, stall, last = set(), 0, self._surface_size()

        while True:
            if self.stop_event.is_set():
                yield {"type": "complete", "content": "Hunt stopped by user."}
                return
            if not self._budget_left():
                async for ev in self._react_finish(session_id, f"AI budget reached ({self.max_ai_calls} calls)"):
                    yield ev
                return
            self.ai_calls += 1
            yield self._budget_event()
            response = await self.client.messages.create(
                model=self.model, max_tokens=4096, system=self._system(),
                tools=tool_defs, messages=messages)
            for block in response.content:
                if getattr(block, "text", None):
                    yield {"type": "text", "content": block.text}
            tool_calls = [b for b in response.content if b.type == "tool_use"]
            if not tool_calls or response.stop_reason == "end_turn":
                yield {"type": "complete", "content": "Analysis complete. Check the report for findings."}
                return
            tool_results = []
            for call in tool_calls:
                sig = self._tool_sig(call.name, call.input)
                if sig in called and call.name not in ("generate_playbook", "store_finding"):
                    yield {"type": "info", "content": f"Skipped duplicate {call.name} (loop guard)."}
                    tool_results.append({"type": "tool_result", "tool_use_id": call.id,
                                         "content": json.dumps({"success": True,
                                         "note": "deduplicated: identical call already executed this run"})})
                    continue
                called.add(sig)
                content = "{}"
                async for ev in self._run_tool(call.name, call.input, session_id):
                    if "_content" in ev:
                        content = ev["_content"]
                    else:
                        yield ev
                tool_results.append({"type": "tool_result", "tool_use_id": call.id, "content": content})
            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user", "content": tool_results})
            cur = self._surface_size()
            stall = stall + 1 if cur <= last else 0
            last = cur
            if stall >= 3:
                async for ev in self._react_finish(session_id, "no new surface discovered"):
                    yield ev
                return

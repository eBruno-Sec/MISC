# Threat Model — IDOR Differential Slice

## Scope

This threat model covers the §37 vertical slice: the BOLA/IDOR differential
assessment workflow against a lab target (OWASP Juice Shop).

Components in scope:
- Engagement lifecycle (API → Temporal workflow)
- Scope compilation and firewall
- Policy engine + signed action envelope
- Identity bootstrap (credential creation + session management)
- IDOR differential module (`web.authorization.idor.differential`)
- Evidence capture (MinIO) + finding emission
- Capability registry (proven-only)

## Assets

| Asset | Sensitivity | Location |
|-------|------------|----------|
| Test identity JWTs | High — grants target access | Secret store (reference only) |
| Evidence request/response bodies | High — may contain PII/data | MinIO (immutable) |
| Engagement authorization record | High — controls what is in scope | PostgreSQL (immutable) |
| Signing key | Critical — forging enables arbitrary actions | Environment (SIGNING_KEY) |
| Audit log | High — tampered log obscures actions | PostgreSQL (append-only) |
| Report artifacts | Medium — confirms vulnerabilities | MinIO (immutable) |

## Trust Boundaries

```
Internet ──────────────────────────────────────────────────┐
  (lab-only: juice-shop:3000 inside compose network)        │
                                                            │
  Worker activity (tool_sdk) ──→ scope firewall ──→ target │
       ↑ signed envelope from API                           │
       │ re-verified in executor before any request         │
       └──────────────────────────────────────────────────┘

Operator ──→ API (authenticated) ──→ Command handlers ──→ Temporal
                                              ↓
                                    Policy engine (8 layers)
                                              ↓
                                    Signed envelope (expiry, budget)
                                              ↓
                                    Approval gate (HITL for R2)
                                              ↓
                                    Activity executor (re-verifies)
```

## Threats and Mitigations

### T1: SSRF via target_locator injection

**Threat:** Attacker-controlled `target_locator` redirects requests to internal
services (metadata endpoints, internal APIs, RFC1918 addresses).

**Mitigations:**
- `packages/scope/ScopeFirewall` enforces allow-list + deny-overrides-allow
- DNS resolution is pinned at scope-compilation time; rebinding rejected
- RFC1918 and link-local blocks (169.254.169.254, 10.0.0.0/8, etc.)
- Redirects re-checked against firewall before following
- Scope ambiguity → deny (fail-closed)
- Tests: `tests/unit/test_firewall.py`, `tests/unit/test_scope_security.py`

### T2: Envelope forgery / replay attack

**Threat:** Attacker forges or replays a signed action envelope to execute
unauthorized actions or re-execute an approved action with modified parameters.

**Mitigations:**
- HMAC-SHA256 over canonical JSON (keyed, not just hash)
- Expiry field — short TTL (5 minutes default), rejected after expiry
- `idempotency_key` per envelope — duplicate detection in executor
- `revision_id` field — stale envelope rejected if scope/policy revised
- `approval_ref` binding — envelope only valid with its specific approval
- Generic `approved=true` rejected at API layer (§13.6)
- Tests: `tests/unit/test_envelope.py`

### T3: AI prompt injection changing policy decisions

**Threat:** Malicious content in target responses injected into AI prompts
causes AI to produce proposals that bypass policy, expand scope, or fabricate evidence.

**Mitigations:**
- AI is advisory-only in all planner paths; deterministic layers 1-5, 7-8 run first
- AI ranking operates on already-eligible candidates only (cannot add/remove)
- AI output never touches policy engine, scope firewall, or signing path
- AI prompts use structured output schemas with post-validation; malformed → quarantine
- Raw evidence never sent to AI (fingerprints only, per redaction rules)
- AI failure falls back to deterministic scoring (never bypasses policy)
- Tests: `tests/unit/test_ai_gateway.py`

### T4: Capability inflation — capability emitted without confirmed finding

**Threat:** A capability (e.g. `read_foreign_object`) is emitted without a
deterministically confirmed finding and verified evidence, inflating the
attack graph and enabling unjustified chain steps.

**Mitigations:**
- `CapabilityRegistry.record()` requires `evidence_digest` (sha256) + `finding_id`
- Only findings in `confirmed` state can produce capabilities
- Module `confirm()` is deterministic (no AI, no IO); 5-rule gate for IDOR
- `output_schema.json` validates confirmed results require sha256 evidence_digest
- Module output validated against versioned schema before capability emission
- Tests: `tests/unit/test_capability.py`, `tests/contract/test_module_output_contracts.py`

### T5: Tenant data isolation failure

**Threat:** One tenant's engagement data is visible to or writable by another
tenant's session, enabling data exfiltration or cross-tenant evidence tampering.

**Mitigations:**
- PostgreSQL Row Level Security (RLS) on every table with `tenant_id`
- Application layer: all repository queries carry `tenant_id` filter
- Engagement, finding, capability, evidence all scoped by `tenant_id`
- `authorization_record` verified before any engagement reads/writes
- Tests: `tests/unit/test_api.py` (tenant isolation assertions)

### T6: Immutability bypass — evidence or finding modified after creation

**Threat:** Attacker or buggy code modifies captured evidence or confirmed
findings, invalidating the audit trail or fabricating results.

**Mitigations:**
- PostgreSQL immutability trigger: UPDATE/DELETE on evidence, finding, capability
  tables rejected at DB level
- Application command handlers have no UPDATE path for immutable tables
- MinIO versioning: objects are versioned; prior versions always accessible
- Audit log is append-only; every state change written as a new event
- Tests: `tests/unit/test_evidence_domain.py`, `tests/unit/test_findings.py`

### T7: Secret leakage in logs, AI prompts, or evidence

**Threat:** JWT tokens or other credentials appear in log lines, AI context,
stored evidence, or report output, enabling token theft.

**Mitigations:**
- JWTs fetched from secret store by URI at call time; never returned to caller
- Evidence stores fingerprints only (sha256 of token), never raw token
- AI gateway redacts `Authorization` headers from prompts by default
- `AI_REDACT_PROMPTS` and `AI_SEND_RAW_*` env flags control redaction
- Log format strips `Authorization` and `X-Auth-Token` headers
- Tests: `tests/unit/test_secrets.py`

## Residual Risks (accepted for dev/lab profile)

| Risk | Acceptance rationale |
|------|---------------------|
| HMAC-SHA256 signing (not asymmetric) | Dev/lab profile only; ADR#0004 documents prod upgrade path to KMS |
| Local secret store (not Vault) | Dev/lab profile only; ADR#0006 documents Vault integration path |
| MinIO versioning (not object-lock) | Dev/lab profile only; ADR#0005 documents S3 object-lock for prod |
| Single-node Compose (not K8s) | Dev/lab only; ADR#0003 documents K8s deployment path |
| Juice Shop at 127.0.0.1:42000 | Lab target — explicit scope, not reachable from open internet in compose |

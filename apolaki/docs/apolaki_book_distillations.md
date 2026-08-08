# Apolaki — Book Distillations (genuine read, evidenced)

**Directive (#103):** read all ~21 substantial books in `resources/` cover-to-cover and distill every
concrete, target-agnostic, transferable method into an Apolaki engine (existing or new-candidate). This
is a real read, not a claim. Progress is tracked honestly below: only chunks I have actually read are
recorded, with the method → engine mapping.

**Discipline:** a book "read" only when every substantial chapter is actually streamed and distilled.
A method only becomes an engine entry when it is target-agnostic METHODOLOGY (payloads/creds/ids stay
lab fixtures). Confidence for each mapping: `have` (already an engine), `gap` (new-engine candidate),
`n/a` (conceptual/process, not an engine).

---

## Progress ledger

| # | Book | Lines | Status | Chunks read |
|---|------|-------|--------|-------------|
| 1 | Redefining Hacking (Red Team + BBH in AI world) | 13939 | **READ (full)** | 1–13939 ✓ |
| 2 | The Web Application Hacker's Handbook 2nd Ed | 18844 | **READ** | 1–15381 full content (Ch.1–21 + methodology); 15390–18844 = index back-matter |
| 3 | Advanced Penetration Testing (Allsopp — APT/C2/red-team) | 9644 | reading | 1–1080 (front-matter + intro + Ch.1 start); low Apolaki-yield (offensive-implant tradecraft, mostly n/a) |

Total substantial books: ~21. Books fully read: **2** (Redefining Hacking ✓, WAHH 2nd Ed ✓). Net build-worthy
candidates surfaced so far: **~31** (7 from Book 1 + ~24 from Book 2, consolidating into 6 engine families —
web/transport-posture, session-security, injection-completions [xxe/soap/ldap/xpath/smtp/hpp], server-posture,
encoding-canonicalization evasion amplifier, auth/cred-posture). Top single build seed: `tls_posture` (Book 2
§12.3 confirms it). All guardrail-safe: deterministic-first, oracle+negative-control, scope+HITL, no-DoS,
no-brute.

---

## Book 1 — Redefining Hacking: Red Teaming and Bug Bounty Hunting in an AI-driven World
*(Santos, Lazzara, Thurner — Addison-Wesley)*

### Ch.1 Evolution of pentest / red team / bug bounty — *conceptual*
- Triad model: pentest (find+verify max vulns, scoped) / red team (objective-driven, evade detection,
  people+process+tech) / bug bounty (crowd, responsible disclosure). Feedback loop between the three.
- **Transferable → `n/a` (framing):** the "candidate → verify → confirmed" lifecycle Apolaki already
  runs is the pentest half; red-team framing = objective-based scoring (which Apolaki's mission/objective
  model already encodes).

### Ch.1 opener — AI/ML supply-chain red-team (concrete)
- **Method:** attack the ML pipeline, not the app. Vectors seen: (a) malicious model on a public AI/ML
  hub (watering-hole) with **Keras Lambda-layer arbitrary-code exec** as the payload carrier → C2 stager;
  (b) **training-data poisoning** — locate the (often one-time, snapshot) training dataset, verify write
  access, perturb inputs (e.g. shift competitor prices 1–10%) to bias model output; (c) org-confusion
  persona on an unverified platform (no identity verification = impersonate the org).
- **Transferable → `gap` (ML/AI supply-chain engine candidate):** an Apolaki engine that, when it
  fingerprints an ML surface (Jupyter/`/notebooks`, model registry, `*.h5`/`*.pkl`/`SavedModel`,
  `mlflow`, HuggingFace endpoints), flags: unsafe-deserialization model formats (pickle/Keras-Lambda),
  writable training-data stores, and unverified model provenance. READ-ONLY detection only (never exec a
  loaded model). Distinct from existing web engines. **Note as candidate — do not build until more books
  corroborate the surface is worth a first-class engine.**

### Ch.2 Introduction to Red Teaming — *conceptual/process*
- Red team vs pentest distinction; importance (find critical vulns holistically, challenge assumptions,
  emulate industry-specific threats — e.g. MFA-bypass via social eng even when MFA "theoretically" holds).
- **Frameworks:** MITRE ATT&CK (TTP catalog, Enterprise/ICS/Mobile matrices), Unified Kill Chain
  (end-to-end lifecycle tying technical actions → strategic goals), TIBER-EU + CBEST (intel-led,
  financial-sector, 3rd-party red team + threat-intel required; CBEST "golden thread" = traceable link
  threat→mitigation).
- **Engagement types:** full-scope / objective-based / adversary-emulation (scenario) / purple /
  tabletop. Each with benefit/drawback trade.
- **Transferable → `have` (ATT&CK mapping) + `n/a`:** Apolaki already maps techniques to WSTG/CWE/OWASP;
  ATT&CK technique-id mapping on findings would strengthen the report's threat-narrative (minor, the
  technique registry already carries `maps_to`). CBEST "golden thread" ≈ Apolaki's evidence chain
  (observation→technique→confirmed→remediation) — already the core model. No new engine.

### Ch.3 Red Team Infrastructure — *out of Apolaki scope by design*
- C2 (Mythic/Cobalt Strike/Sliver/Havoc), redirectors (socat→iptables→reverse-proxy→CDN-fronting with
  rewrites), DoH C2 channels, callback jitter, SOCKS5 pivoting, ATT&CK task-mapping in Mythic reports.
- **Transferable → `n/a` (by design):** Apolaki is a scanner/pentest tool, not a C2 operator — it does
  not deploy implants, redirectors, or beacons. Deliberately excluded. The one carry-over already in the
  registry: ATT&CK-style technique→tactic mapping on findings (report already maps WSTG/CWE/OWASP).

### Ch.4 Modern Methodology — Recon (through password spraying)
- ASN → netblock enumeration; Certificate Transparency (crt.sh); subfinder/dnsx/httpx passive
  subdomain→DNS→HTTP probing. **→ `have`** (#114 external attack-surface: ASN→prefix, CT logs, favicon
  hash, sub permutation/recursion).
- **o365 `getuserrealm` Managed-vs-Federated classifier (concrete, READ-ONLY, deterministic):** GET
  `login.microsoftonline.com/getuserrealm.srf?login=user@<domain>&xml=1` → `NameSpaceType` =
  Managed / Federated / Unknown; Federated responses leak the IdP `AuthURL` (Okta/ADFS/etc.) + federation
  brand. Zero-intrusion identity-posture recon oracle. **→ `gap` (TOP candidate this book):** an Apolaki
  recon engine `identity_posture` that, given an in-scope domain, classifies M365 tenancy + extracts the
  federation provider. High-signal, deterministic, no auth, no brute. Build-worthy.
- Metadata harvest (pymeta/PowerMeta — username schema/versions/hostnames from public PDF/Office docs).
  **→ `gap` (low priority):** needs search-engine scraping (external, non-deterministic surface).
- Teams/OneDrive user-enum (KnockKnock — Teams `externalsearchv3` 403=valid/200+JSON=valid/200-empty=
  invalid). **→ `gap` but auth-gated** (needs a Teams bearer token) — narrower; note only.
- Password spraying (validate-users→2h-between→rotate-IP). **→ `n/a` (policy-excluded):** Apolaki
  forbids credential-brute loops by design; single known/discovered values only. This is the anti-pattern
  we deliberately do NOT implement.

### Ch.4 — Initial access → lateral movement → reporting (lines 1951–2807)
Mostly **out of Apolaki scope by policy/design** — recorded honestly so the "read" is real:
- MDM/M365 spraying (TeamFiltration), **MFASweep** (10× auth attempts to find single-factor endpoints),
  KnockKnock user-enum. **→ `n/a` (policy-excluded):** all are credential-brute / multi-auth loops
  Apolaki forbids. Single known/discovered value only.
- Payload/loader tradecraft (ScareCrow+Mangle EDR-unhook, PE bloat, MotW bypass), persistence (.lnk /
  schtasks / Registry-run / COM hijack), C2 SOCKS pivoting, phishing infra (Evilginx3 MiTM, phone
  pretext). **→ `n/a` (out of scope):** Apolaki is a scanner, not an implant/C2/social-eng operator.
- **AD detection gaps that ARE read-only and in-policy (real yield):**
  - **ADCS ESC misconfiguration audit (ESC1…):** read-only LDAP/CSRA enumeration of vulnerable cert
    templates — `EnrolleeSuppliesSubject` + `ClientAuthentication` + `RequiresManagerApproval:False` +
    Domain-Users enrollment = ESC1. Pure detection oracle (Certipy `find -vulnerable` is read-only).
    **→ `gap` (build-worthy):** `adcs_esc_audit` engine, fits the existing AD read-only tranche (#105).
    Flag as candidate/lead — never request/forge certs (that's the exploit half we exclude).
  - **Kerberoastable / AS-REP-roastable account detection:** enumerate users with SPNs set (or
    `DONT_REQUIRE_PREAUTH`) via LDAP. **→ `gap`/partial:** detection is read-only (candidate only); the
    TGS-crack (hashcat) is credential-brute → excluded. Aligns with the spawned Kerberos chip — report
    as a *candidate*, not confirmed. No cracking.
  - SCCM abuse (PXE creds, NAA, NTLM-coercion→MSSQL/SMB relay): **→ `n/a` mostly** (relay/coercion is
    intrusive), but *SCCM presence fingerprint* (SCCMHunter passive site discovery) is a read-only recon
    signal — minor `gap`, low priority.
- Report structure (timestamps, IOCs, attack-scenarios separated, findings+root-cause, artifact list):
  **→ `have`** — Apolaki's report already carries evidence chains, root-cause, per-finding provenance.

### Ch.5 Social Engineering & Physical (lines 2824–3250, partial) — *out of scope*
- Phone pretext, spear-phish infra (aged/categorized domains, Azure CDN fronting, Evilginx3 phishlets/
  lures/redirectors/OpenGraph, force_post for Remember-Me, MFA-cookie theft). **→ `n/a` (out of scope):**
  social-engineering operator tradecraft; Apolaki does not phish, spoof calls, or run MiTM phishlets.

### Ch.5-rest Physical (badge cloning, lockpick bypasses) — *out of scope* (`n/a`)
### Ch.6 Advanced Post-Exploitation (lines 3868–4650+) — *offensive-operator, out of scope*
Web shells / backdoors / reverse+bind shells / binary patching / code obfuscation / trojanized binaries /
LOTL / Meterpreter / supply-chain backdoors. **→ `n/a` (out of scope):** Apolaki plants nothing, runs no
implants/shells, obfuscates no malware. Two carry-overs already covered: (a) the `?cmd=whoami` command-exec
pattern = **command-injection detection → `have`**; (b) SecLists wordlists/web-shell lists → `have` (#10).
Blue-team framing (assume-compromise, PAM, XDR, MITRE-mapping) is defensive context, not an Apolaki engine.

### Ch.6-rest (lines 4650–5880): kernel/firmware backdoors, C2 covert channels, LOTL, priv-esc, stego
**→ `n/a` (out of scope):** rootkits/bootkits/BadUSB, DNS/HTTP/ICMP tunneling C2, cloud-service C2
(Dropbox/Drive/X), GTFOBins/LOLBAS local-priv-esc, PowerSploit/Empire/Mimikatz, steganography exfil,
track-covering. All require a shell/implant Apolaki never establishes. **Carry-overs already covered:**
- **BloodHound graph-theory AD attack paths** → conceptually `have`: Apolaki's canonical AssetGraph +
  utility-scored attack-path ranking (#116) is the same idea (asset/edge graph → shortest path to crown
  jewels). No new engine; possible enhancement = AD-specific edge types if Apolaki ever ingests SharpHound.
- Network-segmentation / post-ex port-scanning → `have` (nmap tranche, #105/#108).

### Ch.7 Active Directory & Linux (lines 5895+) — *read-only AD detection = real yield*
AD architecture (forest/domain/OU/schema/global-catalog/trusts), "identity is the new perimeter",
SSO single-point-of-failure. The **read-only enumeration/detection** half maps directly to Apolaki's AD
tranche (#105). Consolidated **AD detection-engine candidates** (all read-only, candidate/lead only —
never the crack/forge/relay exploit half):
- **`adcs_esc_audit`** — vulnerable cert-template detection (ESC1: EnrolleeSuppliesSubject + ClientAuth +
  no-manager-approval + Domain-Users enroll). `gap`, build-worthy.
- **Kerberoastable / AS-REP-roastable account detection** — LDAP users with SPN set / `DONT_REQUIRE_PREAUTH`.
  `gap`/partial (detection only, no TGS crack).
- **GPP cpassword in SYSVOL** — `Get-GPPPassword`: Groups.xml `cpassword` is AES-encrypted with a
  Microsoft-published static key → decryptable = a real read-only credential-exposure finding. `gap`
  (needs authenticated SYSVOL read; strong signal when in-scope + creds available).
- **Unconstrained/constrained delegation + two-way transitive trust mapping** — read-only LDAP signals for
  the attack-path graph. `gap`/partial (feeds #116 ranking).
These are one coherent **AD read-only detection tranche** to build as a batch (fits #105), gated on
authenticated_scan + scope, candidate-only, zero brute/crack/forge.

### Ch.7 depth (lines 6050–7450): AD attack methodology — read-only detection tranche (CONSOLIDATED)
The chapter walks GOAD end-to-end. The **read-only, in-policy** half is a coherent build-batch (all gated
on authenticated_scan + scope; candidate/lead only; **never** the crack/relay/forge/dump exploit half):

1. **`smb_posture`** (single SMB/RPC read via the existing SMB pack): flag **SMB signing disabled**
   (`signing:False` = NTLM-relay-vulnerable), **SMBv1 enabled**, **null-session / anonymous / guest**
   access allowed, **weak domain password policy** (`--pass-pol`: complexity flags 0, low min-length, no
   lockout threshold). All read-only findings. `gap`/verify-vs-#105.
2. **`ad_ldap_roast_detect`** (LDAP read): **Kerberoastable** = `(&(objectClass=user)(servicePrincipalName=*)
   (!(cn=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))`; **ASREPRoastable** =
   `(userAccountControl:1.2.840.113556.1.4.803:=4194304)` (DONT_REQ_PREAUTH). Report as **candidates**
   (no TGS/AS-REP crack). `gap`/partial.
3. **`adcs_esc_audit`** (LDAP/CSRA read, Certipy-`find`-style): vulnerable cert templates ESC1 (SAN spec +
   ClientAuth + no-manager-approval + low-priv enroll), ESC2 (Any-Purpose/no EKU), ESC3 (Cert-Request-Agent
   EKU), ESC9/10 (weak mapping), ESC13/14. Detection only — never `req`/`auth`/forge. `gap`, build-worthy.
4. **`ad_dacl_audit`** (LDAP read): dangerous ACEs (`WriteDacl`/`GenericAll`/`GenericWrite`/
   `AllExtendedRights`) on privileged (`adminCount=1`) objects → feeds attack-path graph (#116). `gap`/partial.
5. **`ldap_signing_posture`**: LDAP signing + channel binding not enforced (relay-vulnerable). `gap`.

**Out of scope (`n/a`, offensive/post-compromise):** password-spray/SprayHound (brute — excluded),
Responder LLMNR/NBT-NS poisoning (active MiTM), secretsdump/lsassy/DonPAPI/Mimikatz (cred dumping needs
admin+remote-registry), NTLM-relay (ntlmrelayx), Golden SAML (needs stolen ADFS key — note it *relates* to
the existing SAML engine #109 but is not remotely detectable), Entra-Connect SyncJacking / PIM abuse
(post-compromise). BloodHound graph = conceptually `have` (#116 attack-path ranking).

> **Build note:** items 1–5 form one "AD read-only detection tranche" to build as a batch AFTER the read,
> gated + candidate-only, verifying against what #105 already covers so nothing is duplicated.

### Ch.7 Linux (lines 7430–7840): buffer overflow / ASLR / NX / ROP — *out of scope*
Memory-corruption exploitation (stack/heap overflow, ROP gadget chaining, ret2libc). **→ `n/a`:** Apolaki
is a web/API/net/cloud/ICS scanner, not a binary-exploitation framework — it never crafts ROP chains or
overflows. Defensive framing (safe funcs, `-fstack-protector`, ASLR/DEP/CFI, canaries) is remediation
advice, not an engine.

### Ch.8 Future — AI in Red Teaming (lines 7854–8850+) — *validates Apolaki's ethos + minor yield*
- **Deterministic-tool → structured-data → LLM-analysis pattern** (ai_recon.py: certspy CT-logs+DNS+WHOIS
  → GPT synthesis; ai_scan.py: `nmap --script ssl-enum-ciphers` → GPT synthesis w/ prescriptive prompt
  template). **→ `have` (this IS Apolaki's model):** deterministic engines are the source of truth; LLM is
  an optional analyst layer, never the oracle. Reinforces the zero-token / deterministic-first discipline.
- **`tls_posture` engine from ssl-enum-ciphers:** the concrete deterministic mapping the book's AI
  narrates — weak CBC suites (padding-oracle risk), missing forward secrecy (non-ECDHE/RSA-kx),
  TLS1.0/1.1 enabled, no HSTS, deprecated ciphers → findings. **→ `gap`/verify:** confirm vs any existing
  TLS check; if absent, a deterministic `tls_posture` engine (nmap ssl-enum-ciphers parse) is build-worthy
  and fully in-policy (read-only).
- **RAG over the technique/knowledge corpus** (vector DB + semantic + hybrid BM25 + MMR + RAG-Fusion/
  RAPTOR): could surface the most relevant techniques for an observed surface. **→ `gap` (OPTIONAL, low
  priority):** Apolaki's deterministic **precondition graph** (technique_planner) is a more trustworthy
  source-of-truth than embedding similarity for a security tool — keep the graph authoritative; a RAG layer
  would be an advisory add-on only, never a gate. Note, don't rush.
- **Local-LLM / confidentiality** (BurpGPT Pro local models; never feed client scan data to a training
  endpoint). **→ `have` (principle):** matches Apolaki's zero-token-by-default + no-exfil + secrets-vaulted
  discipline. Carry-over: any future LLM report-synthesis must stay local/no-train.
- **Uncensored exploit-gen models (WhiteRabbitNeo)** / **AI-red-teaming (prompt-injection, data poisoning)**:
  exploit-gen → `n/a` (deterministic-first, never LLM-as-exploit-source). LLM-app prompt-injection testing →
  `have` (#88 already shipped an LLM prompt-injection upgrade); ties to the ML/AI-surface candidate from Ch.1.

### Ch.8-end — AI-red-teaming probe taxonomy (lines 8850–9430): *enriches the LLM-app engine (#88)*
- **garak + ps-fuzz probe families** (a concrete, target-agnostic taxonomy for LLM-app security testing):
  system-prompt-stealer, base64/hex/ROT13/Morse **encoding injection**, DAN/"do-anything-now"/roleplay
  jailbreaks, **payload-splitting**, linguistic/non-English evasion, typoglycemia, affirmative-suffix,
  `xss.MarkdownImageExfil`, `promptinject.Hijack*`, `packagehallucination`, `leakreplay` (training-data/
  copyright leak). **→ `have`/enhance (#88):** Apolaki already shipped an LLM prompt-injection upgrade;
  this taxonomy is the durable checklist to broaden it (each probe family = a technique-registry entry with
  an oracle). In-scope only for LLM-backed apps that are in the engagement scope; deterministic detection of
  reflected system-prompt / successful jailbreak marker, never a jailbreak-for-harm generator.

### Ch.9 Bug Bounty & Recon (lines 9448–10250) — *mostly already-have recon + a couple gaps*
- Program/VDP/ASM framing, scope+RoE template (in/out-scope targets + vuln types + reward). **→ `n/a`**
  (process) — though the RoE "out-of-scope: DoS/social-eng" mirrors Apolaki's own hard exclusions.
- DNS recon (dnsrecon: A/MX/NS/SOA/SPF/TXT/SRV/**DNSSEC**/DNSKEY), WHOIS contacts, **cloud-vs-self-hosted**
  (WHOIS OrgName → provider), subdomain enum, MassDNS, cert inspection. **→ mostly `have`** (#114 external
  recon, #106 cloud detection).
- **Email-auth + DNS posture gap:** SPF present but no **DMARC**/**DKIM**, or `~all`/`?all` soft SPF, and
  **DNSSEC not configured** = spoofing/tamper exposure. **→ `gap` (low-med value):** a deterministic
  `dns_email_posture` recon finding (read-only DNS TXT lookups). Cheap, standards-mappable.
- SSL cert inspection for crypto flaws → ties to `tls_posture` (Ch.8) — `have`/verify.

### Ch.9 depth (lines 10250–11650): recon tooling — *almost entirely already-have*
- **`tls_posture` (CONSOLIDATED, the one real gap here):** testssl.sh maps a concrete named-CVE checklist
  Apolaki can encode deterministically from a TLS handshake/cipher scan: **Heartbleed** (CVE-2014-0160),
  **CCS** (2014-0224), **ROBOT**, **CRIME**/**BREACH** (compression), **POODLE**, **SWEET32**, **FREAK**,
  **DROWN**, **LOGJAM**, **BEAST**, **LUCKY13** (CBC), **RC4**; plus SSLv2/3+TLS1.0/1.1 offered, no-PFS,
  weak/NULL/EXPORT ciphers, short cert validity, no OCSP-stapling, no CAA. **→ `gap`/verify** — build a
  deterministic `tls_posture` engine (or confirm one exists) mapping each to CWE/CVE. Read-only, high-value,
  standards-mappable. This is the single concrete web-adjacent engine gap from Book 1.
- Already-have: crt.sh CT logs (#114), Google dorks/GHDB (#10), Wayback (#69), TruffleHog secrets
  git/github/docker/S3 (#33 code-intel), Shodan/Amass/Recon-ng/Maltego OSINT + ASN/netblock (#114),
  nmap+NSE (smb-enum-users/groups/shares, -T0..T5 timing, script categories) — wired per backlog facts,
  cloud-vs-self-host (#106).
- `n/a`: h8mail/WhatBreach breach-credential dumps (privacy + no-cred-handling policy); Scapy custom
  scanner (nmap already covers). Open-Interpreter/Gorilla LLM-drives-recon = the deterministic-tool→LLM
  pattern already noted (`have` ethos).

### Ch.9 web/API recon (lines 11980–12145) — *all already-have*
Directory/file brute-force (gobuster/ffuf/feroxbuster) → content-discovery `have`; Wappalyzer/BuiltWith/
Retire.js tech-fingerprint `have`; OWASP ZAP DAST proxy `have` (#40 mitmproxy); the **guest / authenticated
/ admin three-angle** analysis = Apolaki's persona + authz-matrix `have`; Burp intercept `have` (#40);
DevTools Network/XHR/**Memory heap-snapshot** for secrets-in-JS `have` (#29 CDP + #10 sourcemap); API-doc
reverse-engineering (OpenAPI/Swagger/GraphQL/WSDL/Postman) `have` (#104 auto-fetch OpenAPI + probe /graphql).

### Ch.10 "Hacking Modern Web Apps and APIs" — *BODY ABSENT from this extraction (honest gap)*
The text file jumps Ch.9 exercises → Ch.11; Ch.10's body was not extracted. Its scope is recoverable from
the **Appendix-A answer key** (lines 13461–13490): OWASP Top-10-for-LLM (prompt injection / insecure output),
Burp lab, business-logic flaws, **SQLi** (`' OR '1'='1'`), brute-force, **broken access control**, **stored
XSS**, **CSRF** (X-CSRF-Token), **SSRF** (`http://127.0.0.1:8080/admin`), **clickjacking** (X-Frame-Options),
**LFI**. **→ all `have`** (Apolaki has SQLi/XSS-stored+reflected+DOM/BOLA-IDOR-BAC/CSRF/SSRF/LFI/clickjacking/
business-logic/LLM-injection engines). No new engine gap from Ch.10's topic set; body unavailable to mine
deeper. (If the fuller Ch.10 text is wanted, it would need the eBook/PDF, not this .txt.)

### Ch.11 Automating a Bug Hunt + AI (lines 12435–13520) — *one new signal, rest already-have*
- **EPSS prioritization signal (the one new gap):** Exploit Prediction Scoring System (probability 0–1,
  daily-updated dataset) alongside **CVSS** + CISA **KEV**. Apolaki already has KEV/CAPEC enrichment +
  utility-scored attack-path ranking (#116). **→ `gap` (low-med):** add EPSS as a deterministic
  prioritization input (published-dataset lookup, no LLM). Standards-mappable.
- Nuclei YAML template-driven scanning → `have` (#115 absorbed the executable-knowledge schema).
- Bug-bounty data model (platform→program→root-domain→subdomain→IP→port→URL→vuln) = Apolaki's canonical
  AssetGraph `have`. CVSS/KEV `have`. Recon→scan→enumerate automation = Apolaki orchestration `have`.
- AI-generated Nuclei templates / RAG-for-bugbounty / fine-tuning / LoRA/QLoRA / uncensored models →
  `n/a`/optional (deterministic-first; Apolaki neither fine-tunes models nor uses LLM-as-exploit-source).
  The hallucination/guardrail discussion validates Apolaki's deterministic-first, oracle-gated design.

---

## Book 1 — CONCLUSION (fully read: 13,939 / 13,939 lines)

**Net actionable, build-worthy engine candidates** (all deterministic, read-only, in-policy — gated on
scope + authenticated_scan where noted; candidate/lead only; zero brute/crack/forge/relay). Ranked:

1. **`tls_posture`** (Ch.8/9) — parse a TLS handshake/cipher scan → named-CVE + weak-config findings:
   Heartbleed/ROBOT/CRIME/BREACH/POODLE/SWEET32/FREAK/DROWN/LOGJAM/BEAST/LUCKY13/RC4, SSLv2/3+TLS1.0/1.1,
   no-PFS, NULL/EXPORT/weak ciphers, short validity, no OCSP-staple, no CAA. **HIGH value, web-adjacent,
   fully standards-mappable. TOP pick.** (verify no existing TLS engine first.)
2. **AD read-only detection tranche** (Ch.7, fits #105): `smb_posture` (signing-off / SMBv1 / null-session /
   weak password-policy), `ad_ldap_roast_detect` (Kerberoastable-SPN + ASREPRoastable candidates),
   `adcs_esc_audit` (vulnerable ESC1–14 templates), `ad_dacl_audit` (WriteDacl/GenericAll/GenericWrite/
   AllExtendedRights on adminCount=1), `ldap_signing_posture`. Build as ONE batch after verifying #105 gaps.
3. **`identity_posture`** (Ch.4) — o365 `getuserrealm` Managed/Federated classifier + IdP (Okta/ADFS)
   extraction. Deterministic identity recon, zero-auth.
4. **`dns_email_posture`** (Ch.9) — soft-SPF / no-DMARC / no-DKIM / no-DNSSEC (read-only TXT lookups). Cheap.
5. **EPSS prioritization input** (Ch.11) — add to attack-path ranking (#116).
6. **LLM-app prompt-injection taxonomy expansion** (Ch.8/9) — fold garak/ps-fuzz probe families (system-
   prompt-stealer, encoding/base64 injection, DAN/roleplay, payload-splitting, linguistic evasion) into #88.
7. **ML/AI supply-chain surface detection** (Ch.1) — unsafe model formats (pickle/Keras-Lambda), writable
   training stores, Jupyter/model-registry exposure. Read-only; needs corroboration from other books.

**Everything else in the book is, for Apolaki, either (a) out-of-scope BY DESIGN** — C2/redirectors/implants,
persistence, social-engineering, physical/badge, memory-corruption exploitation, credential-brute/spray,
credential-dumping, NTLM-relay — **or (b) already-have** — external recon (#114/#106/#69/#10), nmap+NSE,
the OWASP web/API vuln classes, business-logic, Nuclei schema (#115), CVSS/KEV, the canonical AssetGraph, and
the deterministic-first / LLM-as-analyst-not-oracle ethos which the book's AI chapters independently validate.

**Honest yield ratio:** one 13.9k-line red-team+bug-bounty book → 1 clear win (`tls_posture`), 1 coherent AD
batch, and ~5 smaller candidates. The book's center of mass (red-team operator tradecraft) is deliberately
outside Apolaki's scanner scope, so the transferable-per-page rate is low — expected, and now evidenced.

---

## Book 2 — The Web Application Hacker's Handbook, 2nd Edition
*(Stuttard & Pinto — Wiley; 18,844 lines. The canonical web-app pentest text — the richest core-engine yield.)*

### Ch.1-2 Web (In)security + Core Defense Mechanisms (lines 1–470) — *foundational, mostly ethos/have*
- Core model: all user input untrusted; the trio auth / session-management / access-control; **boundary
  validation** (validate at each trust boundary, not just the frontier). **→ `have`** (Apolaki tests the vuln
  side of each: broken-auth, session, BOLA/BAC).
- **Filter / canonicalization bypass taxonomy (the durable extract):** case-variation (`SeLeCt`),
  inline-comment token-splitting (`SELECT/*foo*/username`), **NULL-byte** (`%00<script>`), **nested-strip**
  (`<scr<script>ipt>` — a non-recursive filter re-forms the payload), **double-URL-encode**
  (`%2527`→`%27`→`'`), multi-step-order abuse (`....\/` vs sequential `../`+`..\` strip), **HTML-entity
  encoding** (`j&#x61;vasc&#x72ipt&#x3a;`), **best-fit charset mapping** (`«`→`<`, `Ÿ`→`Y`). **→ `have`/
  enhance:** Apolaki's mutation/WAF-evasion engine should carry this as an explicit encoding-bypass checklist
  (each = a mutation variant to try when a payload is blocked). Note as an enhancement to the existing engine.
- Handling-attackers (error handling, audit logs, alerting, reactive throttling), managing-the-app
  (admin-interface = privilege-escalation surface). **→ `n/a`/have** — defensive design; Apolaki already flags
  verbose errors (info-leak) + tests admin-interface access-control.

### Ch.3 Web Application Technologies (lines 480+) — *HTTP/tech primer*
HTTP request/response structure, GET/POST semantics, headers, status codes. **→ `have`/`n/a`** (primer).
Watch later sections for encoding schemes + 301/403 status nuance (already covered in Book 1 Ch.9 content
discovery).

### Ch.3 depth (lines 560–1120): HTTP methods / headers / cookies / tech stack / encodings
Extractable **HTTP-posture engine cluster** (deterministic, read-only, standards-mappable — reinforces the
`tls_posture` candidate; consolidate + verify vs existing clickjacking/CORS checks):
- **`http_security_headers`** — missing/weak **X-Frame-Options** (clickjacking), **CSP**, **HSTS**,
  **X-Content-Type-Options**, Referrer-Policy, Permissions-Policy; **CORS** `Access-Control-Allow-Origin`
  reflected/`*` **with** `Access-Control-Allow-Credentials: true` (real misconfig). (Nikto flagged the first
  three in Book 1 Ch.9.) `gap`/verify.
- **cookie-flags posture** — missing **HttpOnly** / **Secure** / **SameSite** on session cookies. `gap`/verify.
- **`http_methods_audit`** — dangerous methods enabled: **PUT** (arbitrary upload→RCE), **TRACE** (XST),
  **OPTIONS** (Allow-header disclosure), **DELETE**. Read-only probe (OPTIONS is safe; PUT/DELETE = HITL).
  `gap`/verify.
- ViewState (ASP.NET) unprotected/no-MAC tamper → niche `gap` low.
- Encoding schemes (URL / double-URL / `%u` Unicode / UTF-8-overlong / HTML-entity / Base64 / Hex) = the
  mutation/evasion inputs already noted in Ch.1-2 taxonomy → `have`/enhance (mutation engine).
- Tech-stack fingerprint (Java/ASP.NET/PHP/Rails + open-source component ID → known-CVE pivot) → `have`
  (Wappalyzer-style fingerprint + ExploitDB feed #112). HTTP Basic/NTLM/Digest auth, SOAP/WSDL (→ Ch.10
  SOAP-injection), same-origin/Ajax/JSON/HTML5 → context for later vuln chapters.

**Emerging theme (Books 1+2):** a consolidated **web/transport posture engine family** — `tls_posture`
(named-CVE + ciphers) + `http_security_headers` + cookie-flags + `http_methods_audit` + CORS-misconfig — is
the clearest deterministic, in-policy, standards-mapped build target. Verify what Apolaki already covers,
then fill the gaps as one batch.

### Ch.4 Mapping the Application (lines 1120–1680) — *Apolaki's home turf, ~all already-have*
Content/functionality enumeration; **user-directed spidering via intercepting proxy** (walk the app in a real
browser, proxy builds the site map — beats blind auto-spider on JS nav / multistage forms / auth-session
breakage) → `have` (mitmproxy #40 + CDP collector #29 + recursive authed crawl #79). robots.txt as hidden-
content seed, hidden-content brute-force (Burp-Intruder/dirsearch style), Wayback/search-cache/forums,
Wikto/Nikto default-content + known-vuln → `have` (#10 SecLists, #69 Wayback, #114 recon, nmap http-enum,
#112 ExploitDB). Notes:
- **Backup/temp/source-leak filename permutation** (`.bak`/`.old`/`.swp`/`file.php~`/`.DS_Store`/`.inc`/`.src`
  + dev-lang source exts `.java`/`.cs`) → concrete content-discovery enhancement. `have`/verify.
- **Application pages vs functional paths** (functions in params: `servlet=X&method=Y`, `action=editUser`) →
  the technique-planner's functional-map view. `have`.
- **Hidden-parameter discovery** (`debug=true`/`test`/`source`, cluster-bomb name×value) → `have`
  (param-discovery engine).
- **Entry points = URL path (REST params) + query + POST + cookies + headers**; **Referer / User-Agent /
  X-Forwarded-For as injection vectors** + out-of-band channels (SMTP→webmail, fetch-from-URL). `have`/verify
  (confirm XFF/Referer/UA are in the injection-surface set).
- Server-side fingerprint (banner / httprecon HTTP-fingerprint / file-ext / dir-names / session-token names
  JSESSIONID·PHPSESSID·ASP.NET_SessionId / third-party components→CVE) → `have` (#112 + tech fingerprint).
- Dissecting requests for clues (`OrderBy`→SQL, `template`/`loc`→path-traversal, `isExpired`/`edit` flags→
  access-control) = observation→hypothesis derivation → `have` (technique_planner).

### Ch.5 Bypassing Client-Side Controls (lines 1680–2680) — *Apolaki's proxy home turf*
Everything-client-is-untrusted: hidden-field price tampering (incl. **negative price** — try it), cookie
tampering (`DiscountAgreed=25`), URL-param tampering, **Referer-header trust bypass**, opaque/obfuscated data
+ **replay** (copy a cheaper product's encrypted `pricing_token`), `maxlength`/JS-`onsubmit`/`disabled`-element
bypass (client validation not re-checked server-side). **→ `have`** (mitmproxy #40 intercept/modify + client-
control bypass). Notes:
- **ViewState MAC-absence detection** (ASP.NET `_VIEWSTATE` without the 20-byte keyed hash = tamperable) →
  concrete deterministic finding. `gap` low.
- **Serialized-object content-type detection** (`application/x-java-serialized-object`, `x-amf`,
  `soap+msbin1`) = **insecure-deserialization surface** signal. `gap` low (flag surface, don't decompile).
- Browser-extension **decompilation** (Java-applet/Flash/Silverlight bytecode → Jad/Flare/.NET-Reflector,
  JavaSnoop debug, native ActiveX → OllyDbg/IDA) → **`n/a` (out of scope + largely dead tech)**; Apolaki is
  not a bytecode decompiler. The BIE (#124) covers the modern equivalent (runtime JS/SPA instrumentation).

### Ch.6 Attacking Authentication (lines 2684–2800+) — *auth engine themes; brute is policy-excluded*
- Weak/blank/default/username-equals-password → single-value check `have`/policy (Apolaki tries ONE known/
  default value, never loops).
- **Brute-forcible login** = the chapter's core, but **credential-brute loops are Apolaki-forbidden by
  policy**. The in-policy half = **detect the *absence* of defenses**: no account-lockout / no rate-limiting
  (a small BOUNDED probe, not a dictionary loop), reported as a lead. `have`/policy-bounded — verify the
  bound is honored.
- Client-side login-attempt counter bypass (`failedlogins` cookie / session-counter → fresh session) →
  `have` (client-control bypass).
- **Username enumeration via response-differential** (verbose "unknown user" vs "wrong password"; response
  length/status/**timing** deltas; account-lockout messages) → deterministic, low-intrusion (a couple of
  requests, NOT a brute loop), high-value. **→ `have`/verify** (confirm the username-enum engine keys on
  message + length + status + timing, and stays bounded).

### Ch.7 Attacking Session Management (lines 3361–3920) — *core-engine loot: a session-security family*
**GAP TO CLOSE:** lines 2801–3360 (rest of Ch.6 auth logic-flaws + Ch.7 opening) errored on read-size —
re-read in a smaller chunk before marking Ch.6/7 complete.
Token generation + handling + termination weaknesses → a coherent **`session_security` engine family**
(deterministic, low-intrusion; bounded token sampling, NOT a brute loop):
- **`session_token_analysis`** — decode the token (base64 / hex / XOR) → detect **meaningful structure**
  (`user=daf;app=admin;date=…`) and **predictability**: sequential, **concealed sequence** (decode→diff
  reveals constant delta), **time-dependency** (`index-millis`), **weak PRNG** (java.util.Random LCG /
  PHP-session entropy). Randomness/entropy scoring (Burp-Sequencer/FIPS-style) on a captured sample.
  **→ `gap`/candidate (medium)** — verify vs any existing session-token check. (Caveat: modern frameworks
  use CSPRNG, so many will pass — report honestly.)
- **Encrypted-token manipulation** — detect block cipher (username+1 char → token length jumps 8/16 B),
  then **ECB block-shuffle** (duplicate/move blocks to change `uid`) or **CBC bit-flip** (flip a byte to
  modify the *following* plaintext block) — also applies to any encrypted param (price). Padding-oracle
  cross-ref (Ch.18). **→ `gap` (niche/advanced)** — `crypto_token_bitflip` probe.
- **`session_lifecycle`** — **session fixation** (token NOT rotated after login = pre-auth token upgraded),
  **no logout invalidation** (token still valid server-side after logout), **no expiry** (token valid days
  later), **concurrent sessions** allowed, **static tokens**. **→ `gap`/verify (important + concrete):**
  reuse-token-after-logout + token-unchanged-across-login are deterministic oracles.
- **Token disclosure** — **session token in URL** (`jsessionid` → Referer leak; `inurl:jsessionid` dork),
  **missing Secure/HttpOnly/SameSite** (→ folds into `http_security_headers` cluster), HTTP↔HTTPS downgrade /
  mixed-content token exposure. **→ `gap`/verify (low, concrete).**

**Consolidated build theme (Books 1+2 so far):** two deterministic, in-policy, standards-mapped engine
families are the clearest targets — (A) **web/transport posture** (`tls_posture` + `http_security_headers`
+ cookie-flags + `http_methods_audit` + CORS) and (B) **session security** (`session_token_analysis` +
`session_lifecycle` + token-in-URL + fixation). Both fit Apolaki's deterministic-first + evidence model.

### Ch.6 rest — Auth logic flaws (lines 2801–3200, gap now closed) — *auxiliary-auth attack surface*
The key lesson: **the auxiliary auth functions repeat the main-login weaknesses** and are often less
hardened. Enhancement for Apolaki's auth artery — probe ALL of these, not just `/login`:
- **Username enumeration** everywhere a username is submitted — main login, **registration** (duplicate-name
  reject), **password-change**, **forgotten-password**. Keys: verbose msg + subtle HTML/comment diffs +
  **timing** (Comparer-style differential). `have`/enhance (extend enum oracle to the aux functions).
- **Credentials-in-transit posture** — creds in **query string** (logged), creds in **cookie**,
  **login form loaded over HTTP** then submitted HTTPS (MiTM-downgradeable). **→ `gap`/verify** (folds into
  the transport/session posture family). Deterministic, concrete.
- **`RememberUser=daf` remember-me bypass** (username-only persistent cookie → auth bypass) + predictable
  persistent-session-id → `have` (client-control bypass) / feeds `session_token_analysis`.
- **Impersonation flaws** — hidden `/admin/ImpersonateUser.jsp` (no access control), cookie/hidden-field
  chooses impersonated account, **backdoor password** (two brute "hits"). → `have`/note (BFLA + access
  control + hidden-content).
- **Username-override via hidden field** on password-change (submit extra `username=` param to target
  another user) → `have`/note (param tampering + BOLA on auth funcs).
- **Fail-open login** (exception → login succeeds) → probe by malforming each param (empty / remove /
  duplicate / type-swap / very-long/short) and watching for divergence. **→ `gap`/note** (bounded auth-
  robustness probe).
- **Multistage-login logic flaws** — skip/reorder stages, proceed direct to stage N, trust stage-1-validated
  data at stage 2, different-user-per-stage, client-side `stage2complete=true` flag, chooseable/cycleable
  randomly-varying question. **→ `gap`/note** (client-side stage-flag + question-cycling are detectable;
  full logic-flaw testing is hard to generalize).
- **Predictable usernames** (`cust5331`→`5332`) / **predictable initial passwords** / **activation-URL
  sequence** → predictability analysis (shares the `session_token_analysis` machinery). `gap`/note.
- **Insecure credential storage** — password **reflected back to client** = stored reversibly; unsalted
  MD5/SHA-1 → rainbow lookup. → `gap` low (detect password-returned-to-client).
- **Incomplete credential validation** (truncation / case-insensitive / char-stripping) → weakens password
  space; niche. `n/a`/note.

*(3201–3360 gap closed: auth remediation — CAPTCHA-hindrance + ALT-attribute/hidden-field CAPTCHA-answer
leak note; generic-lockout-message to avoid enum; password-change/recovery hardening. Remediation → `n/a`.)*

### Ch.7 securing (lines 3921–4136) — cookie-scope + fixation posture
- **Client token hijacking** — XSS→cookie theft, **session fixation** (no fresh token after login), **CSRF**
  (cookie auto-sent). Fixation/CSRF → `have`/note (fixation in `session_lifecycle`; CSRF = Ch.13).
- **Liberal cookie scope** — `domain=parent` → token leaks to sibling subdomains; cookies ignore protocol/
  port (weaker than SOP). **→ `gap`/verify:** `cookie_scope_posture` (overly-liberal domain/path) — folds
  into the cookie-flags posture. Concrete, deterministic.
- **Per-page tokens** = anti-CSRF/anti-fixation remediation. **Reactive session termination** (app logs you
  out on anomalous request) → operationally relevant to Apolaki's OWN authed scanning: detect forced-logout
  → re-login (Burp obtain-cookie equivalent). `have`/note.

### Ch.8 Attacking Access Controls (lines 4136–4460) — *STRONG validation of Apolaki's core*
Vertical / horizontal / context-dependent access control; the canonical **two-account site-map-diff +
persona-swap replay** testing methodology **IS Apolaki's Differential Authorization Engine (#26) + BOLA
confirmation + authz-matrix + the BIE #124 canonical example**. `have` (strongly aligned with the bible).
- ID-based functions (`ViewDocument.php?docid=…` → IDOR/BOLA), unprotected functionality (`/admin/`,
  cosmetic UI-hiding, JS `isAdmin`-revealed URLs), parameter-based (`admin=true`), Referer-based,
  location-based (IP geoloc) access control → **all `have`** (BOLA engine + param-tampering + hidden-content
  + Referer-trust). Predictable-ID harvest + **"lowest account-number = admin"** heuristic → `have`/enhance.
- **New notes (verify/small gaps):**
  - **HTTP-method access-control bypass** — POST denied but **GET / HEAD / arbitrary-method** reaches the
    same handler. **→ folds into `http_methods_audit`; `gap`/verify** (retry a sensitive action with GET/
    HEAD/bogus method + lower-priv account). Concrete.
  - **Direct-method sibling enumeration** — Java-naming (`get/set/add/is/has` + `com.x.y.Class`, `servlet=`)
    → guess `getAllUsers`/`getAllRoles`/`getCurrentUserPermissions`. `gap`/note (API method enum).
  - **Static-file direct access** — `download/<ISBN>.pdf`, sequential/predictable static resources, annual
    reports, log files → trawl by naming scheme. `gap`/note.

**Net for Books 1+2 access-control read:** Apolaki's BOLA/authz investment is confirmed as *exactly* the
canonical methodology — no core gap; only small add-ons (`http_methods_audit` method-bypass, direct-method
enum, static-file access, `cookie_scope_posture`).

### Ch.9 Attacking Data Stores — SQL Injection (lines 4534–5540) — *core engine Apolaki HAS; durable checklist*
The SQLi bible chapter. Apolaki already ships a SQLi engine (labs). Recorded as the definitive technique tree
to confirm the engine's coverage + confirmation-oracle discipline (deterministic-first, negative controls):
- **Detection:** `'` → error/diff; `''` escape restores → likely-vuln; concat equivalence (Oracle `'||'`,
  MS-SQL `'+'`, MySQL `' '`); numeric `1+1`/`67-ASCII('A')`; `%` wildcard; JS-error-on-quote → also XSS hint.
- **Statement types:** SELECT (WHERE/ORDER BY), INSERT (`foo',1,1)--` field-count probe), UPDATE/DELETE
  (⚠ WHERE-tamper is destructive — Apolaki policy: confirm, never run `OR 1=1` on UPDATE/DELETE or DROP/
  shutdown; no-destructive).
- **ORDER BY / column-name injection** (no quote needed; prepared-statements DON'T protect → key modern
  vector) — `1 ASC/DESC`, nested `(select 1 where <cond> or 1/0=0)`.
- **DB fingerprint** (concat method + `BITAND`/`@@PACK_RECEIVED`/`CONNECTION_ID()` + MySQL `/*!nnnnn */`).
- **UNION** (column count via `NULL,NULL,…`; find string column via `'a'`; `information_schema.columns`
  metadata / Oracle `all_tab_columns`; `CONCAT` columns).
- **Filter bypass** (case `SeLeCt`, inline `/*foo*/` incl. intra-keyword MySQL `SEL/*foo*/ECT`, `CHAR()`
  string build, `%00`, double-URL-encode, `SELSELECTECT`) = **same taxonomy as Ch.2** → mutation engine.
- **Second-order SQLi** (safe on insert, unsafe on later re-read) → **`gap`/verify:** Apolaki should test
  stored-then-reflected input, not just first-request (matches its create-object-IDOR discipline).
- **Blind:** inference via **boolean** (`AND 1=1`/`1=2`), **conditional error** (`1/0` when cond true),
  **time delay** (MS-SQL `WAITFOR DELAY`, MySQL `SLEEP`/`BENCHMARK`, PG `PG_SLEEP`, Oracle UTL_HTTP-timeout) —
  **time-delay is THE reliable fully-blind detector** → confirm Apolaki's blind-SQLi engine uses it.
- **Out-of-band (OAST)** — MS-SQL `OpenRowSet`, Oracle `UTL_HTTP`/`UTL_INADDR`(DNS)/`UTL_SMTP`, MySQL
  `INTO OUTFILE \\UNC`. **→ `gap`/candidate:** OAST-collaborator (DNS/HTTP callback) for blind injection
  detection — Burp-Collaborator-style. Needs an external collaborator server (infra); note as candidate,
  applies to blind SQLi + SSRF + XXE + blind-XSS.
- **DB escalation** (`xp_cmdshell`, `sp_configure` re-enable, Oracle `DBMS_JAVA.RUNJAVA`/`UTL_FILE`, MySQL
  `LOAD_FILE`/`INTO OUTFILE`/UDF) → **`n/a` (policy):** Apolaki confirms + grades impact, never runs OS-cmd/
  writes files/drops tables. sqlmap `--sql-shell` = the exploitation tool; Apolaki is confirm-not-exploit.

### Ch.9 rest — NoSQL / XPath / LDAP injection (lines 5540–6045)
Same "break out of the interpreted context" principle, new grammars → **new injection-engine candidates**:
- **NoSQL / MongoDB injection** — `$where` JS (`Marcus'//`, `a'||1==1||'a'=='a`) + operator injection
  (`$gt`/`$ne`/`$regex`). **→ `gap`/candidate (medium)** — Apolaki likely lacks NoSQL injection.
- **XPath injection** — `' or 'a'='a`, blind via `substring()` + `name(parent::*)` + `count()`/`string-length()`
  (extract full XML doc byte-by-byte, no schema knowledge). **→ `gap`/candidate (medium).**
- **LDAP injection** — search-filter breakout: `)(department=*`, `*))(&(…`, null-byte `*))%00`, `*` wildcard
  probe, `))))` bracket-break. **→ `gap`/candidate (medium)** — distinct from AD/LDAP *enum* (#105); this is
  injecting into an app's LDAP search filter.
- SQL error→DB-fingerprint cheat sheet + parameterized-query prevention → `have`/remediation.

### Ch.10 Attacking Back-End Components (lines 6081–6620)
- **OS command injection** — `; | & newline` batch, `&&`/`||`, backtick, **time-delay `ping -i/-n 30`**
  (THE reliable blind detector), `$IFS` space-bypass, `%0a`, out-of-band, redirect `>` to webroot. Apolaki
  HAS cmd-injection → `have`/verify (confirm time-delay blind detection + separator taxonomy).
- **Dynamic-execution / eval injection** (PHP/Perl `eval`, `phpinfo()`, `;echo 111111`, `response.write`)
  → related to Apolaki's CSTI/SSTI-adjacent detection. `gap`/verify.
- **Path traversal / LFI** — `../`,`..\`, `/etc/passwd`+`win.ini`, encoding bypass (`%2e`/`%2f`/`%5c`/`%u2215`/
  double `%252e`/**overlong-UTF8** `%c0%af`), **nested `....//`**, **null-byte `%00.jpg`**, prefix/suffix
  filter bypass. Apolaki HAS traversal/LFI → `have`/verify (same canonicalization taxonomy as Ch.2 → mutation
  engine; add nested/null-byte/overlong-UTF8 to the bypass set).
- **File inclusion (RFI/LFI)** — PHP `include($country.'.php')`; RFI = external URL (detect via **callback to
  attacker server** = OAST), LFI = local include of protected resources. `have`/verify (RFI callback = OAST).
- **XXE (XML External Entity)** — `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` → file-read
  reflected in response; `http://internal:25` → **SSRF/port-scan/proxy via XXE**; blind XXE → DoS or OAST.
  **→ `gap`/candidate (HIGH — TOP new web engine):** an `xxe` engine — detect XML content-type endpoints
  (`text/xml`, SOAP), inject entity, confirm via file-read reflection or OAST callback; chains to Apolaki's
  SSRF. Build-worthy.

**Recurring cross-cutting candidate — OAST collaborator (DNS/HTTP callback server):** powers blind detection
for **SQLi + RFI + XXE + SSRF + blind-XSS**. Burp-Collaborator-style. Infra-dependent (needs a callback
domain/server) but the single highest-leverage add for blind-vuln confirmation. Note as a first-class
candidate; gate on scope + safe (read-only callback).

**New web-engine candidate tally (Book 2 injection chapters):** `xxe` (top) · NoSQL · XPath · LDAP-injection ·
OAST-collaborator (cross-cutting) — all fit Apolaki's deterministic confirm-oracle model.

### Ch.10 rest — SOAP / SSRF / HPI-HPP / mail injection (lines 6620–7030)
- **SOAP injection** (inject `</tag><ClearedFunds>True</ClearedFunds>` into back-end SOAP) → `gap`/candidate
  (low — back-end SOAP rarer now; related to XXE/XML).
- **Server-side HTTP redirection = SSRF** (`loc=192.168.0.1:22` → SSH banner; proxy / internal-access /
  port-scan / loopback / XSS-via-proxy) → **`have`** (#43 SSRF + #106 metadata-SSRF). Confirms coverage.
- **HTTP Parameter Injection (HPI) / Pollution (HPP)** — inject `%26foo%3dbar` / `%3bfoo%3dbar` / double-enc
  `%2526foo%253dbar` into a value that feeds a back-end request; duplicate-param override (first/last/concat
  varies by platform); URL-rewrite `mode=view&…&mode=edit`. **→ `gap`/candidate (medium):** `hpp` engine —
  deterministic, concrete.
- **Mail / SMTP + CRLF injection** — `%0d%0aBcc:` header injection, `%0d%0a…MAIL FROM…` command injection
  (also = HTTP **response splitting** / header injection). **→ `gap`/candidate (medium):** `crlf_injection`
  engine (mail-header + HTTP-response-split), test both `%0a` and `%0d%0a`. Concrete.

### Ch.11 Attacking Application Logic (lines 7080–7560) — *strengthens the Business-Logic engine (#27)*
Logic flaws have **no signature** → invisible to scanners; this is Apolaki's business-logic frontier (#27).
The 12 examples distill into a **business-logic probe checklist** (encode into #27 / the technique registry):
1. **Parameter removal** — remove each param (NAME+value, not empty-string), one at a time → **fail-open**
   (missing `existingPassword` → admin path). `gap`/note.
2. **Forced browsing** — access multistage steps out of sequence / skip / repeat (checkout skip-payment).
   → `have` (context-dependent access control).
3. **Stage-parameter injection / mass-assignment** — submit a param the app expects at a DIFFERENT stage →
   bypass validation, set price/role. → `have`/note (mass-assignment engine, fix-pass).
4. **Negative / boundary values** — `-$20,000` transfer bypasses `<=threshold` approval. `gap`/note.
5. **Escape-the-escape-char** — `foo\;ls` → `foo\\;ls` (backslash not escaped) breaks cmd-inj/XSS filters.
   `gap`/note (always try `\` before a metachar).
6. **Filter-ordering / truncation abuse** — escape-then-truncate flips quote parity → SQLi; test `''''…` vs
   `a'''…`. `gap`/note.
7. **Encryption oracle** (reveal/encrypt) — feed one encrypted blob to a decrypt-display function. `gap`/note.
8. Discount-then-remove-items / search-count inference / static-container debug leak / login race-condition →
   `n/a`/note (workflow- or race-specific; hard to generalize; #27 headline-hypotheses can flag candidates).
**→ `have`/enhance #27:** fold probes 1–7 into the business-logic probe set (Apolaki already emits business-
logic *hypotheses*; these are the deterministic tests behind them).

### Ch.12 Attacking Users: XSS (lines 7574–7700+) — *Apolaki HAS deep XSS*
Reflected (first-order) / Stored (second-order) / DOM XSS; session-token theft via `document.cookie`→attacker;
same-origin-policy is WHY XSS matters (script runs in victim-origin context). **→ `have`** (#84-87 reflected/
stored/DOM/CSTI on labs). Recording the taxonomy; watch for filter-bypass + DOM-sink specifics next.

### Ch.12 XSS depth (lines 7700–8780) — *Apolaki HAS deep XSS; durable taxonomy to confirm*
Method = benign-string reflection → **syntactic-context** ID (tag-attr / JS-string / URL-attr / HTML-body) →
context-tailored payload → filter-bypass. `have` (#84-87). Durable checklists to verify the XSS + mutation
engines encode:
- **HTML filter-bypass taxonomy:** case-var, **NULL-byte** (IE), HTML-entity (dec/hex/leading-zeros/no-`;`),
  arbitrary-tag+event-handler, **base-tag hijacking**, whitespace alts (`/`,`%09`,`%0d`,`%0a`,backtick
  delimiters), superfluous `<<script>`, **E4X** `<script<{}/>`, **charset** (UTF-7, **Shift-JIS/EUC-JP/BIG5
  multibyte** `%f0"`, double-URL-decode, Unicode-glyph `«»`→`<>`). **HTML5 vectors:** `autofocus onfocus`,
  `<video/audio src=1 onerror>`, `event-source` (hyphen in tag name defeats regex), closing-tag handlers.
- **JS filter-bypass:** Unicode/hex/octal escapes (`l`/`\x6c`/`\154`), `String.fromCharCode`/`atob`/
  concat, eval-alts (`.replace(/.+/,eval)`, `function::[]`), dot-alts (`document['cookie']`, `with`),
  VBScript (IE, case-insensitive → beats uppercasing filters), `escape-the-escape` (`foo\'`).
- **DOM-XSS taxonomy (confirm #85 engine):** SOURCES `document.location/URL/URLUnencoded/referrer`,
  `window.location`; SINKS `document.write(ln)`, `innerHTML`, `eval`, `execScript`, `setInterval/setTimeout`.
  **Server-filter bypass via `#fragment`** (payload after `#` never reaches server) + invented-param append.
- **Length-limit beating:** span-across-fields, convert-to-DOM (`eval(location.hash.slice(1))`).
- **Delivery contexts:** XSS via cookie / Referer / POST→GET toggle / nonstandard content (XML-namespace→
  XHTML `<a xmlns:a=…xhtml><a:body onload>`, `text/plain` enctype cross-domain).
- **File-upload XSS (verify-gap):** HTML-in-image (content-type sniffing), **GIFAR/hybrid files**, `.jpg`
  containing `<script>` rendered as HTML, Ajax-`#fragment` image-as-HTML RFI. **→ `gap`/verify:** confirm
  Apolaki tests upload→download XSS + content-type-sniff. Concrete, often-overlooked.
- **IE XSS-filter bypass:** param-name not checked, span-same-name-params (server concatenates), on-site
  request. `n/a`/note (Apolaki isn't the browser filter; relevant if grading exploitability).

### Ch.13 Attacking Users: Other Techniques (lines 8780–9860) — *several clean web-posture additions*
- **CSRF detection** — 3-condition deterministic test: request (a) performs a privileged/state-changing
  action, (b) relies **solely on cookies** for session, (c) all params attacker-predictable (**no anti-CSRF
  token**). **→ `have`/verify** (confirm Apolaki flags state-changing requests lacking anti-CSRF token +
  SameSite). Concrete.
- **OSRF** (on-site request forgery) — inject `../admin/newUser.php?...#` into a URL/`img-src`/`href` field
  even when XSS is blocked → admin-viewed request forges action. **→ `gap`/candidate** (distinct from XSS;
  test URL-valued fields for `/ . \ ? & =` passthrough).
- **`crossdomain.xml` / `clientaccesspolicy.xml` audit (CLEAN new build — add to web-posture family):**
  Flash/Silverlight policy files granting `<allow-access-from domain="*">` (or overly-broad domains) = any
  site gets 2-way authenticated interaction. **→ `gap`/candidate (build-worthy):** deterministic, read-only
  GET of `/crossdomain.xml` + `/clientaccesspolicy.xml` → flag wildcard/overly-permissive. Easy win.
- **Clickjacking / UI-redress** — missing `X-Frame-Options` / CSP `frame-ancestors` (framebusting is
  bypassable) → folds into `http_security_headers`. `have`/verify (also check mobile UI variant).
- **CORS misconfig** (HTML5 `Access-Control-Allow-Origin` reflected/`*` + `Allow-Credentials: true`;
  test with spoofed `Origin:` header) → `http_security_headers` cluster. `have`/verify.
- **HTTP header injection / response splitting / cookie injection** — CRLF `%0d%0a` into `Location`/
  `Set-Cookie` → inject headers / split response / poison proxy cache; bypass `%0d`/`%250d`/`%00%0d`. **→
  reinforces `crlf_injection` candidate** (Ch.10 mail + here = one CRLF engine covering mail-header +
  response-split + cookie-inject). `gap`/candidate.
- **Session fixation** (token not rotated anon→auth / accepts arbitrary tokens / URL-param `;jsessionid=`) →
  `session_lifecycle`. `have`/verify.
- **Open redirect** — `redir=http://evil` + filter bypass (`HtTp://`, `%00http://`, ` http://`, `//host`,
  `%68%74...`, relative→absolute). Apolaki HAS (#85). `have` (durable bypass taxonomy for the engine).
- **JSONP / JavaScript-hijacking** (callback-wrapped JSON includable cross-domain) → `gap`/candidate (low —
  mostly old-browser/historical).

**Web-posture family now consolidated (Books 1+2):** `tls_posture` + `http_security_headers` (XFO/CSP/HSTS/
XCTO/Referrer/Permissions/**CORS**) + cookie-flags + `cookie_scope_posture` + `http_methods_audit` +
**`crossdomain.xml`/`clientaccesspolicy.xml` audit** + `dns_email_posture`. One deterministic, read-only,
standards-mapped batch — the single clearest build cluster from the whole read so far.

### Ch.13 end (lines 9860–10310): open-redirect bypass, client-side SQLi/HPP, local privacy, ActiveX, MITM
- **Open-redirect filter-bypass taxonomy** (`http://mdsec.net.evil.net`, `//evil`, `http://evil/?http://
  mdsec`, backslash/triple-slash, double-encode, absolute-prefix-no-trailing-slash `?redir=.evil.net`) →
  durable checklist for the existing open-redirect engine. `have`.
- **Client-side SQLi** (HTML5 WebSQL `openDatabase`/`executeSql` w/ attacker data) + **client-side HPP** →
  `gap`/candidate (client-side SQLi low/niche; HPP reinforces the `hpp` candidate).
- **Local-privacy / cache posture** — sensitive page missing `Cache-Control: no-store`/`Pragma: no-cache`,
  **sensitive data in URL** (→ history/logs/Referer), **`autocomplete=off` missing** on password/PII fields,
  persistent-cookie sensitive data. **→ `gap`/candidate (low-med):** deterministic, folds into the web-posture
  family (`autocomplete`, cache-control, secure/HttpOnly). **Mixed-content** (HTTP script-include on HTTPS
  page) → posture check. `have`/verify.
- ActiveX (`LaunchExe`/`SaveFile` dangerous methods) → `n/a` (dead tech). Browser attacks (keylog, history-
  steal, JS port-scan, **DNS-rebinding**, BeEF/XSS-Shell frameworks), active MITM → `n/a` (client-side
  offensive frameworks, out of Apolaki scanner scope).

### Ch.14 Automating Customized Attacks (lines 10337–10940) — *IS Apolaki's core automation model*
JAttack / Burp-Intruder methodology = **enumerate identifiers · harvest data · fuzz** — param positioning +
payload sources (list/numbers/dates/case-sub/illegal-unicode/char-block/brute/char-frobber/bit-flipper) +
**hit-detection discriminators** (HTTP status / response length / body-grep / Location / Set-Cookie /
**time-delay**). **→ `have` (strong validation):** this is exactly Apolaki's fuzz/harvest/enum + oracle-
discriminator engine. The canonical fuzz strings (`'`, `;/bin/ls`, `../../../etc/passwd`, `xsstest`) +
grep-strings (`error`/`exception`/`quotation`/`xsstest`) = Apolaki's deterministic detectors. Confirms the
automation core is aligned with the bible; no gap.

### Ch.14 rest — Barriers to Automation (lines 10941–11196)
Session-handling obstacles (defensive session-kill, per-request anti-CSRF tokens/nonces, multistage flows) +
CAPTCHA. Burp's answer = cookie-jar + request-macros + session-handling-rules (scope→actions: add cookies /
set param / validate-session-else-run-login-macro / derive param from prior response / prompt-for-recovery).
**→ `have` + one real gap: `session_handling_automation` (macro/token-refresh harness).** Apolaki already
carries auth-artery + bearer-login; the transferable method to absorb is *automatic token/nonce re-derivation
from the preceding response* so fuzz/authz engines survive anti-CSRF + multistage state (else they silently
fail closed). CAPTCHA-solving = out of scope by policy (Apolaki PAUSEs on CAPTCHA/MFA, never bypasses); the
ONLY in-scope CAPTCHA note = **implementation defects** (solution in hidden field/URL/comment; puzzle
replayable across requests; skip-param bypass) → a light `captcha_impl_check` candidate (detect, never solve).

### Ch.15 Exploiting Information Disclosure (lines 11197–11588) — **new-engine family**
- **`error_message_intel` (gap → build):** deterministic classifier over server responses for
  stack-traces / script errors (VBScript/ASP line-nums) / verbose debug dumps (session vars, DB creds, file
  paths, connection descriptors) / DB errors. Grep-signature set is explicit & target-agnostic:
  `error·exception·illegal·invalid·fail·stack·access·directory·file·not found·varchar·ODBC·SQL·SELECT`.
  Baseline-vs-probe (does the *original* response already contain the keyword? → FP guard). Feeds the graph
  as intel facts (tech/version/path/DB-host) that *sharpen other engines*, not a standalone "info-leak: low".
- **Engineered error disclosure** (ODBC/`convert`-to-int cast leak, UDF-throw) = SQLi-extraction sub-techniques
  → fold into existing SQLi engine's oracle, `have`/extend.
- **`timing_inference` (gap, careful):** response-time delta as an oracle — username-enum via password-hash
  timing, cache/lazy-load dormant-vs-active, SSRF-timeout-vs-refused. Controlled single-request-at-a-time,
  paired valid/invalid lists, negative-control; **NOT** a DoS/load loop. Complements blind-SQLi/SSRF oracles.
- Public-info/search-engine recon of error strings = OSINT `have`/`n/a`.

### Ch.16 Attacking Native Compiled Applications (lines 11589–11869) — mostly out-of-scope, ONE guarded probe
Buffer/heap/off-by-one overflow, integer overflow/signedness, format-string — classic memory-safety, relevant
only to native web endpoints (hardware devices, dll/exe/cgi, legacy modules). **The book itself flags: merely
*probing* these likely causes DoS** → collides with Apolaki's no-DoS guardrail. **→ mostly `n/a`.** The only
defensible piece = a **passive, opt-in `native_endpoint_flag`** that *marks* endpoints whose name/tech smells
native (dll/exe/cgi, device banners) as "native-code present → out-of-band manual/authorized fuzz required",
without sending overlong/format payloads by default. Absorb the taxonomy as knowledge, gate the active test
behind explicit owner-accepts-DoS-risk HITL. (Off-by-one null-terminator loss → cross-user data bleed is a
neat case but still device-class.)

### Ch.17 Attacking Application Architecture (lines 11870–12199) — methodology, few direct engines
Tiered-arch trust exploitation, LAMP file-read→MySQL-data, **LFI→RCE** (log-poisoning; PHP session-file
`<?php passthru(id)?>` nickname + `../sess_<token>%00` include), shared-hosting/ASP cross-tenant attacks,
virtual-hosting, **cloud** (cloned-entropy, ported mgmt tools w/ weak session/RBAC, permanent device tokens,
web-storage HTML/JAR upload → same-origin abuse). **→ mostly conceptual `n/a` (post-exploitation / infra
escalation, not scanner-detectable)**; two concrete absorbs: (1) **LFI-execution chain** = extend traversal/
file-include engine with the *log-poisoning + PHP-session-include* exploit recipes (methodology only, `have`/
extend); (2) **cloud misconfig** overlaps the existing cloud/IMDS work — feed "ported mgmt tool / permanent
token / public web-storage upload" as cloud-posture observations.

### Ch.18 Attacking the Application Server (lines 12200–12801) — **high-yield: several server-posture engines**
- **`default_content_probe` / admin-interface discovery (gap → build):** default creds tables (Tomcat
  admin/·, tomcat/tomcat, JBoss, Zeus…), default/sample/debug content (`phpinfo.php`, Tomcat SessionExample,
  Jetty Dump servlet-XSS, JMX-console WAR-deploy RCE, Oracle PL/SQL-gateway `OWA_UTIL.CELLSPRINT`). Detect
  presence deterministically; **single known default-cred attempt only, never a brute loop** (guardrail). Wire
  to ExploitDB-index (never auto-run) + tech-fingerprint graph facts.
- **`http_methods_audit` — CONFIRMED as its own engine (was surfaced Ch.3; here fully specified):** OPTIONS
  enumerate → **WebDAV** PUT/DELETE/COPY/MOVE/PROPFIND/SEARCH; PUT-then-MOVE backdoor-upload pattern (davtest);
  advertised≠usable (try each), HEAD-verb ACL bypass. Detect method availability + PUT-write test (benign file
  only, scope+HITL), never drop a real backdoor. **Top server-posture build.**
- **`open_proxy_ssrf` (gap → build, folds into SSRF):** server-as-forward-proxy via absolute-URI GET and
  `CONNECT host:port` → external relay / internal-host reach / loopback service via `127.0.0.1`. This is the
  server-config face of SSRF (Ch.10) — one engine, two entry surfaces.
- **`encoding_canonicalization_bypass` (gap → cross-cutting evasion layer):** the WAHH thesis "filter and
  interpreter are different components with different rules." Absorb the concrete bypass corpus as a reusable
  **payload-mutation/evasion transform set** every injection/traversal engine can draw on: overlong-UTF8
  (`..%c0%af`), double-encode (`..%255c`), `%3f`/`%00` parser confusion, whitespace/`%FF`→canonical/quote/
  goto-label PL/SQL-list bypasses, IIS pre-canonicalization traversal. **Not a detector — an evasion/coverage
  amplifier** feeding Apolaki's existing detectors (raises recall against filtered targets). High value.
- **`waf_ids_detect` (gap → build):** deduce inline-defense presence (arbitrary param w/ payload gets blocked
  vs benign) + **bypass methodology** (same param in different location GET/POST-body/cookie/`Request.Params`,
  HPP concat on ASP.NET, benign non-signature payloads, span across vars). Records a graph fact "WAF present →
  route detectors through evasion layer" — composes with the canonicalization engine above. Guardrail: probe
  with benign markers, no real `/etc/passwd`/`<script>` signatures.
- Server-software CVEs (mod_isapi dangling-ptr, IIS ISAPI overflows, Apache chunked, WEBrick/JRun/Tomcat
  traversal, .NET **padding-oracle**) = version→known-vuln lookup (`have` via ExploitDB/CVE index; padding-
  oracle is a real crypto-oracle technique but niche — knowledge entry, not auto-exploit).

### Ch.19 Finding Vulnerabilities in Source Code (lines 12802–...) — mostly `n/a` (white-box), one absorb
White-box audit methodology: trace user-data entry-points → grep vuln signatures → line-by-line risky code.
Signature corpus (XSS concat, SQLi `"SELECT`/`" AND` string-build, path-traversal file-API + user param,
open-redirect, OS-cmd `system()`, **backdoor passwords**, native strcpy/printf, and **comment greps**
`bug·problem·bad·hope·todo·fix·overflow·crash·inject·xss·trust`) + per-language input/session/dangerous-API
cheat-sheets (Java `getParameter`/`java.io.File`…). **→ `n/a` for the black-box scanner core**, BUT two real
absorbs: (1) **client-side JS review** needs no privileged access → Apolaki's JS-analysis/BIE can grep the
same signatures in served JS (DOM-XSS sinks, `?redir=` open-redirect, hardcoded secrets/endpoints), `have`/
extend; (2) if a **SAST-lite mode** is ever offered on provided source, this signature+comment-grep corpus is
the ready-made ruleset. Keep as reference knowledge.

### Ch.19 rest — per-language cheat-sheets (lines 13100–13934) — reference corpus, `n/a`/absorb
Java / ASP.NET / PHP / Perl / JS input-source, session, dangerous-API, config tables. All white-box SAST
reference. **Absorbed as knowledge, two live hooks:** (1) **client-side JS review** (Table 19.12 sources
`document.location/URL/referrer/window.location` → sinks `document.write/innerHTML/eval/setTimeout/setInterval/
execScript`) = the exact **DOM-XSS source→sink map** Apolaki's JS-analysis/BIE should carry — `have`/extend,
strong. (2) **DB code-component SQLi** (stored-proc dynamic `EXEC`/`EXECUTE IMMEDIATE`, definer-rights
escalation, `xp_cmdshell`) + **PHP `register_globals` uninit-var auth-bypass** (`?authenticated=1`) = concrete
methodology entries for the SQLi/logic engines. Config-flag knowledge (magic_quotes, safe_mode, taint mode,
`allow_url_include`, ASP.NET `customErrors`/`httpOnlyCookies`/`enableVersionHeader`) = server-posture facts.

### Ch.20 A Web Application Hacker's Toolkit (lines 13935–14544) — `have` (Apolaki ~IS this suite)
Intercepting-proxy-centric suite: **proxy + spider + fuzzer + scanner + repeater + sequencer + shared utils**.
This is literally Apolaki's own architecture — validated 1:1: intercept/modify (mitmproxy #40), passive+active
spider (recon), fuzzer/harvest (automation core), token-randomness analyzer (session engine), manual-request
repeater, encoders/comparer. **The single most important distillation = the book's OWN honest scanner-limits
section** (lines 14238–14400): automated scanners reliably catch ~half of vuln classes (reflected-XSS,
signature-SQLi, traversal-to-known-file, cmd-injection time/echo, dir-listing, cleartext-pw/cookie-flags,
backup-file ext-guess) and **CANNOT** catch broken-access-control/BOLA, param-meaning tampering (price/qty),
logic flaws (negative-value limit bypass, skip-stage), design flaws (weak-pw-rules, username-enum), token
sequence/session-hijack, sensitive-info leakage — because "scanners operate on **syntax**, not **semantics**;
don't improvise; aren't intuitive." **→ This IS Apolaki's whole thesis and moat**: the deterministic-first +
confirmation-oracle + persona-swap-BOLA + business-logic-graph + differential-authz work exists precisely to
cover the *second* list the syntactic scanners miss. Records as the north-star validation, no new engine — but
confirms priority: keep investing in semantic/stateful/authz engines, not more signature payloads. Also
absorbs: scanner **duplicate-finding individuation** problem (200 XSS = 1 function ×195 contexts) → Apolaki's
graph-dedup/individuation is the answer; and scanner **dangerous-effects** caution (blind-probing admin/reset
funcs) → Apolaki's scope+HITL+no-DoS guardrails are the answer. Tooling names (Nikto/Wikto/Firebug/Hydra/
Wget/Curl/Netcat/Stunnel) = `have`/`n/a` (Hydra=brute → policy-forbidden loop, never adopt).

### Ch.21 A Web Application Hacker's Methodology (lines 14545–...) — **COVERAGE CROSS-CHECK, not new engines**
The master step-by-step checklist recapping every chapter as actionable tasks (1 Map content → 2 Analyze → 3
Client-side → 4 Auth → 5 Session → 6 Access control → 7 Input-based (SQLi/XSS/…) → 8 Logic → 9 Shared-hosting
→ 10 App-server → 11 Misc → 12 Info-leak). **Value to Apolaki = a ready-made COVERAGE MATRIX to grade
"did we probe every region of the attack surface + why-not."** Treat as the authoritative checklist to diff
against Apolaki's coverage-engine (#21 "report what was NOT tested + why"). General guidelines absorbed:
URL-encode-special-chars discipline (`& = ? space + ; # %` → `%26 %3d %3f %20 %2b %3b %23 %25`, null=`%00`);
**benign-input false-positive double-check** (if benign input triggers the same signature → FP) = exactly
Apolaki's negative-control gate, validated; **fresh-session state-isolation** to reproduce anomalies =
Apolaki's clean-baseline discipline; load-balancer multi-request confirmation. **Action item:** map each of
the ~12 methodology sections to an Apolaki engine + coverage-matrix row; any section with no engine = a real
gap to log. (Reading the rest as a coverage diff, not for new distillations.)

### Ch.21 §4–13 — full methodology coverage cross-check (lines 14717–15381) — WAHH content ends here
The master checklist confirms Apolaki's engine map 1:1 and pins down the **injection-family gaps** as
first-class methodology steps (not my invention):
- **§4 Auth** — pw-quality, username-enum (response-diff + timing), pw-guess-resilience (lockout), account-
  recovery/forgot-pw, remember-me cookie reverse-eng, impersonation/backdoor-pw, username-uniqueness enum,
  autogen-credential predictability, unsafe cred transmission (URL/cookie/HTTP-form-over-HTTPS MITM), insecure
  storage (hash+rainbow), **fail-open logic** (empty/missing/dup param), multistage-mechanism abuse. → **mostly
  `have`** (auth artery, persona, authz-matrix, differential-authz) + confirms **`credential_transmission_posture`**
  and **`username_enumeration`** as clean deterministic engines (response-diff/timing oracle, single-value only,
  NEVER a guess loop — policy).
- **§5 Session** — token-meaning (encoding/XOR/Base64 structure), token-predictability (Burp-Sequencer-style
  statistical randomness + bit-flip), insecure transmission (secure-flag, HTTP↔HTTPS token reissue), token-in-
  logs/URL+Referer-leak, token↔session mapping (concurrent sessions, re-login reissue, user-component tamper),
  session-termination (idle-timeout + logout-invalidation), **session-fixation** (no-reissue-post-login),
  **CSRF** (cookie-only + predictable params), **cookie-scope** (domain/path over-liberalization). → confirms
  the **session-security family** I surfaced (Ch.7): `session_token_analysis` + `session_lifecycle` +
  `session_fixation` + `csrf_detect` + `cookie_scope_posture`. Strong build cluster.
- **§6 Access control** — vertical + horizontal, multi-account site-map diff, single-account IDOR via
  identifier-prediction, **insecure methods** (`edit=false`/`access=read` param tamper, **Referer-based** ACL,
  **HEAD-verb** container-ACL bypass). → **`have`** (differential-authz #26, BOLA #61/#62); absorb the
  Referer-ACL + HEAD-bypass tricks into the authz engine.
- **§7 Input-based** — the canonical fuzz corpus (SQLi `'`/`'--`/`waitfor`, XSS `"><script>`, OS-cmd
  `|ping`, traversal `../etc/passwd`, script-inj `response.write 111111`, RFI `http://<server>/`) + grep-set +
  the **benign-input FP double-check** + payload-grep for reflection. → **`have`** (Apolaki's deterministic
  detectors), 1:1 with its fuzz/oracle core.
- **§8 Function-specific injection — the GAP cluster, now methodology-confirmed:** **8.7 XXE** (`<!ENTITY xxe
  SYSTEM "file:///…">` + blind SSRF-via-entity timing) = **top new web engine**; **8.3 SOAP-injection**
  (`</foo>`/`<foo></foo>` XML-tag probe), **8.4 LDAP-injection** (`*`, `))))`, `)(cn=*`), **8.5 XPath-injection**
  (`' or count(parent::*)=0`, bytewise substring extraction), **8.1 SMTP/email-header-injection**
  (`%0aCc:`/`%0d%0aBcc:`/DATA-smuggle), **8.6 back-end request injection / HPI-HPP** (`%26foo%3dbar`,
  double-encoded) + **SSRF** (internal host/port + localhost + own-IP callback). **8.2 native (BOF/int/fmt)** =
  `n/a`/DoS-gated per Ch.16. → **BUILD: `xxe`, `soap_injection`, `ldap_injection`, `xpath_injection`,
  `smtp_header_injection`, `hpp_hpi`** — all deterministic, all with the exact probe+oracle strings above.
- **§9 Logic flaws** — multistage out-of-order/skip/replay, incomplete-input, trust-boundary transitions,
  **transaction logic** (negative-value limit-beat, low-value-accrue, price/qty adjustment abuse). → **`have`**
  (business-logic graph #27/#123) — validated as canonical.
- **§10 Shared hosting / §11 app-server** — §11 = my Ch.18 build cluster (default-creds, default-content,
  dangerous-HTTP-methods/WebDAV, proxy/SSRF, virtual-host misconfig, server-CVE, WAF-detect). §10 = `n/a`/infra.
- **§12 Misc — three concrete deterministic engines, all previously seeded, now methodology-confirmed:**
  **DOM-based XSS/redirect** (source→sink map, `have`/BIE); **local-privacy posture** (persistent-cookie
  sensitive-data, **cache-control** `no-cache`/`no-store` on sensitive pages, `autocomplete=off`, Flash/
  Silverlight/HTML5 client-storage) = **`http_privacy_posture`**; **weak-SSL/TLS ciphers** = **`tls_posture`**
  (MY TOP BUILD SEED — confirmed by the bible); **same-origin config** = **`crossdomain_policy_audit`**
  (`/crossdomain.xml` `allow-access-from *`, `/clientaccesspolicy.xml`, **CORS** `Access-Control-Allow-Origin`
  reflection + `Origin` probe). → BUILD `tls_posture`, `http_privacy_posture`, `crossdomain_policy_audit`
  (all in the **web/transport-posture family**).
- **§13 Info-leakage follow-up** = my Ch.15 `error_message_intel` — confirmed.

**(Index at lines 15390–18844 is the alphabetical back-matter index — not substantive prose; WAHH content
ends at §13/line 15381. Book 2 read cover-to-cover.)**

---

## BOOK 2 CONCLUSION — WAHH 2nd Ed (READ FULL, 21 chapters + methodology)
WAHH is the canonical web-app bible and it **validates Apolaki's whole thesis**: its own scanner-limits section
(Ch.20) says syntactic scanners catch ~half the classes and CANNOT catch access-control/BOLA, param-meaning,
logic, design, session-sequence, info-leak — which is *exactly* the semantic/stateful/authz territory Apolaki
was built to own. Core engines (SQLi/XSS/traversal/cmd-inj/differential-authz/business-logic/session/
automation-fuzz) confirmed 1:1 = `have`. **Net new build-worthy candidates from Book 2 (deterministic, target-
agnostic, oracle-backed):**
1. **`xxe`** (external-entity file-read + blind-SSRF-via-entity) — *top web engine*
2. **`soap_injection`**, **`ldap_injection`**, **`xpath_injection`** — injection-family completions
3. **`smtp_header_injection`** (email/CRLF header smuggle) + **`hpp_hpi`** (param pollution/injection) +
   **`crlf_http_response_splitting`** (Ch.13/12) + **`open_proxy_ssrf`** (Ch.18, folds into SSRF)
4. **web/transport-posture family:** `tls_posture` · `http_security_headers` · `cookie_scope_posture` ·
   `http_methods_audit`(+WebDAV) · `crossdomain_policy_audit`(+CORS) · `http_privacy_posture`(cache/autocomplete/
   client-storage) · `dns_email_posture`
5. **session-security family:** `session_token_analysis` · `session_lifecycle` · `session_fixation` ·
   `csrf_detect` (+ token-in-URL leak)
6. **server-posture family:** `default_content_probe`/admin-iface (single-cred, never brute) ·
   `waf_ids_detect` · `error_message_intel` · `native_endpoint_flag` (passive, DoS-gated)
7. **cross-cutting amplifier:** `encoding_canonicalization_bypass` (evasion transform-set feeding ALL
   detectors — raises recall vs filtered targets) + `timing_inference` oracle (careful, no-DoS)
8. **auth/cred:** `username_enumeration` · `credential_transmission_posture` (both single-value, no guess loops)
9. **methodology asset:** map WAHH §1–§13 to Apolaki's coverage-engine (#21) as the authoritative
   "attack-surface region covered? why-not?" matrix.

Running net build-worthy candidates after 2 books: **7 (Book1) + ~24 (Book2) — many consolidate into 6
families.** Guardrails hold on every one: deterministic-first, oracle+negative-control gates truth, scope+HITL,
no-DoS, no-credential-brute loops (single known/discovered values only), secrets vaulted/redacted.

*(Book 2 of ~21 COMPLETE. Next: Book 3 — pick the next substantial unread resource and read cover-to-cover.)*

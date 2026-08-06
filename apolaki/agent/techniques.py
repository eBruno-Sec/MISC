"""
Technique Registry — the platform's core asset.

A *technique* is a target-AGNOSTIC, reusable exploitation method distilled from CTF labs
and validated to generalize. Each technique is knowledge + procedure + oracle:
  - DETECT  — how the vuln class is discovered,
  - EXPLOIT — how it is proven/solved (often a packs.py workflow),
  - ORACLE  — the deterministic check that confirms the solve.

This is deliberately SEPARATE from lab answer-keys (labs.py). A technique never hardcodes a
target's secret. When a lab needs a fixture (a security answer, a product id, a coupon), the
fixture is *data the technique consumes* at run time — never the technique itself. That rule
is what keeps a CTF solve from decaying into a memorized script: the method transfers, only
the inputs change.

transferable=True  -> genuine real-world vuln-class capability (counts as "capability").
transferable=False -> lab-local trivia (e.g. "browse to the hidden score-board URL"): counts
                      toward a CTF's completion %, but is NOT claimed as capability.

A technique is GENERALIZED once `validated_on` lists >= 2 independent labs. Until then it is a
candidate — proven on one lab, not yet shown to transfer. The coverage matrix reports both
numbers so the headline claim ("general capability" vs "lab completion") stays honest.

No external dependencies; pure data + accessors. Safe to import without a target present.
"""
from __future__ import annotations

# Permission classes mirror the wrapper-level classification used by tools.py.
PASSIVE = "PASSIVE"
ACTIVE = "ACTIVE"
INTRUSIVE = "INTRUSIVE"

GENERALIZED_MIN_LABS = 2  # a technique is "general" only once confirmed on >= 2 labs

_REQUIRED = ("id", "vuln_class", "cwe", "owasp", "permission", "summary",
             "detect", "exploit", "oracle", "transferable")


def _t(**kw) -> dict:
    """Build + lightly validate a technique record. Fills optional fields with defaults."""
    for k in _REQUIRED:
        if k not in kw:
            raise ValueError("technique '%s' missing required field '%s'" % (kw.get("id"), k))
    kw.setdefault("pack", None)             # packs.py workflow id, if the exploit is one
    kw.setdefault("validated_on", [])       # lab ids where the ORACLE has actually confirmed it
    kw.setdefault("maps_to", {})            # lab_id -> [challenge names this technique targets]
    kw.setdefault("needs_fixture", [])      # per-run data the technique consumes (never hardcoded)
    kw.setdefault("execution", "auto")      # "auto" | "operator" (operator = gated, never auto-fired)
    # where needs_fixture values come from — THE honesty line:
    #   "harvest"  = derived live from the target's own surface (intel.py) -> transferable capability
    #   "external" = supplied by operator / offline crack / world knowledge (not target-derived)
    #   "none"     = technique needs no fixture
    kw.setdefault("fixture_source", "harvest" if kw.get("needs_fixture") else "none")
    # Taxonomy lenses — the same technique, filed under multiple frameworks (owasp already above).
    kw.setdefault("wstg", None)    # OWASP WSTG test id (e.g. WSTG-SESS-10)
    kw.setdefault("mitre", None)   # MITRE ATT&CK technique id (coarse fit for web; None where none fits)
    kw.setdefault("refs", [])      # external reference URLs (WSTG / PortSwigger topic) — links, not copied prose
    return kw


# --------------------------------------------------------------------------------------------
# The registry. Populated from atoms Apolaki already implements. maps_to challenge names are
# best-known and are reconciled against the lab's live oracle at benchmark time (labs.py) —
# the live /api/Challenges list is always the authority, never this table.
# --------------------------------------------------------------------------------------------
TECHNIQUES: dict[str, dict] = {t["id"]: t for t in [

    _t(id="sqli_auth_bypass", vuln_class="sql_injection", cwe="CWE-89", owasp="A03:2021",
       permission=ACTIVE, transferable=True, pack=None,
       summary="Authentication bypass via SQL injection in a login form.",
       detect="Error/boolean/time differential on login parameters (sqli_tool).",
       exploit="Inject a tautology / comment-terminator into the identity field to log in as the first/target row.",
       oracle="Authenticated response: a valid session token is issued where invalid creds are rejected.",
       validated_on=["juiceshop"],
       maps_to={"juiceshop": ["Login Admin", "Login Bender", "Login Jim"]}),

    _t(id="sqli_union_extract", vuln_class="sql_injection", cwe="CWE-89", owasp="A03:2021",
       permission=ACTIVE, transferable=True,
       summary="Data exfiltration via UNION-based SQL injection.",
       detect="Column-count + reflected-context discovery on an injectable parameter.",
       exploit="UNION SELECT to pivot context -> schema -> users table -> credential columns.",
       oracle="Response contains rows from a table not exposed by the endpoint's normal contract.",
       validated_on=["juiceshop"],
       maps_to={"juiceshop": ["User Credentials", "Database Schema", "Christmas Special"]}),

    _t(id="nosql_injection", vuln_class="nosql_injection", cwe="CWE-943", owasp="A03:2021",
       permission=ACTIVE, transferable=True,
       summary="Operator/query injection into a NoSQL (Mongo-style) backend.",
       detect="$-operator / query-object reflection differential (nosqli_tool).",
       exploit="Inject query operators ($ne, $gt, $where) to bypass filters or coerce mass updates.",
       oracle="Response set changes in a way only an interpreted operator (not a literal) explains."),
    # distilled from *Beginner Web Application Pentester* (Abdollahi), "Testing for XPath injection".
    # distilled from WAHH ch7 — weak session-token generation (predictable / meaningful).
    _t(id="weak_session_token", vuln_class="session", cwe="CWE-330", owasp="A07:2021", wstg="WSTG-SESS-01",
       permission=ACTIVE, transferable=True,
       summary="Session token is predictable — sequential/time-incrementing, or decodes to meaningful user data.",
       detect="Sample N fresh tokens: a numeric component forms an arithmetic/bounded sequence, or a decoding "
              "leaks user=/uid=/role= — signals a CSPRNG token never produces.",
       exploit="Extrapolate the sequence (or forge a meaningful token) to hijack other users' sessions.",
       oracle="Sampled tokens are sequential across the set, or decode to structured user/role data."),
    # distilled from WAHH ch6 — authentication that leaks account existence (username enumeration).
    _t(id="username_enumeration", vuln_class="authentication", cwe="CWE-204", owasp="A07:2021", wstg="WSTG-IDNT-04",
       permission=ACTIVE, transferable=True,
       summary="Login/registration/reset reveals whether an account exists via a response discrepancy.",
       detect="Submit a KNOWN account and two random non-existent ones with the SAME wrong password; a masked "
              "message or status divergence beyond the endpoint's own noise floor is a membership oracle.",
       exploit="Harvest valid usernames/emails pre-auth to seed credential-stuffing and targeted phishing.",
       oracle="The existing-account response diverges from a non-existent one (status or wording), same wrong pw."),
    # distilled from WAHH ch7/ch8 — session identifier not regenerated at authentication (session fixation).
    _t(id="session_fixation", vuln_class="session", cwe="CWE-384", owasp="A07:2021", wstg="WSTG-SESS-03",
       permission=ACTIVE, transferable=True,
       summary="The session id is not regenerated on login — a pre-auth token survives authentication unchanged.",
       detect="Drive one client with a known-good credential across the login boundary; the pre-auth session "
              "cookie is byte-for-byte identical after a SUCCESSFUL login (no rotation).",
       exploit="Fix a known token in a victim's browser; inherit their authenticated session when they log in.",
       oracle="A session-ish cookie held before login is unchanged after a confirmed-successful login."),
    # distilled from WAHH ch18 — a dropped-in admin interface still on its documented vendor default login.
    _t(id="default_credentials", vuln_class="authentication", cwe="CWE-1392", owasp="A07:2021", wstg="WSTG-ATHN-02",
       permission=ACTIVE, transferable=True,
       summary="A recognised admin interface (Tomcat Manager, JBoss jmx-console) still accepts its vendor-default login.",
       detect="Against a URL that IS a known product interface and issued a Basic 401, try the ONE documented default "
              "pair (single known value, never brute-force) and confirm via the product's authenticated marker.",
       exploit="Log in as administrator; on Tomcat/JBoss deploy a WAR/MBean for remote code execution.",
       oracle="The single default pair returns HTTP 200 with the product's admin-console marker."),
    # beyond web (network pentest): SSH crypto audit from the read-only handshake. Apolaki's first non-HTTP engine.
    _t(id="weak_ssh_crypto", vuln_class="network_service", cwe="CWE-326", owasp="A02:2021", wstg="WSTG-CRYP-04",
       permission=ACTIVE, transferable=True,
       summary="An SSH daemon advertises weak/deprecated KEX, cipher, MAC, or host-key algorithms.",
       detect="Complete ONE SSH handshake (no auth) and read the server's KEXINIT name-lists; exact-match the "
              "advertised algorithms against the deprecated set (CBC, SHA-1, arcfour, 3des, umac-64, ssh-rsa/dss).",
       exploit="From a MITM position, negotiate a weak cipher/MAC/KEX to attempt session decryption or tampering.",
       oracle="The server's KEXINIT literally lists a weak algorithm (exact name / anchored suffix, no substring FP)."),
    # beyond web (AD/directory pentest): anonymous LDAP directory read — the classic pre-auth AD enumeration foothold.
    _t(id="ldap_anonymous_read", vuln_class="network_service", cwe="CWE-306", owasp="A01:2021", wstg="WSTG-ATHN-01",
       permission=ACTIVE, transferable=True,
       summary="An LDAP/AD server permits an anonymous bind that can read the naming-context directory subtree.",
       detect="Anonymous bind, then a read-only SUBTREE search of the naming context returns directory entries "
              "(RootDSE-only read is normal and NOT flagged).",
       exploit="Enumerate users/groups/computers pre-auth to seed password spraying, Kerberoasting, lateral movement.",
       oracle="An anonymous session receives directory ENTRIES (person/OU/group objects) from the naming context."),
    # beyond web (AD/file-server pentest): SMB null-session share enumeration.
    _t(id="smb_null_session", vuln_class="network_service", cwe="CWE-306", owasp="A01:2021", wstg="WSTG-ATHN-01",
       permission=ACTIVE, transferable=True,
       summary="An SMB server lets an unauthenticated (null) session enumerate its shares.",
       detect="Connect with an EMPTY username/password (null session) and call listShares; a hardened server "
              "refuses the anonymous session and returns nothing.",
       exploit="Map the file-server layout pre-auth and read any guest-exposed non-administrative share.",
       oracle="A null session connects and listShares returns a share (a non-admin share escalates to high)."),
    # beyond web (AD relay): SMB message signing not required -> NTLM relay.
    _t(id="smb_signing_disabled", vuln_class="network_service", cwe="CWE-347", owasp="A02:2021", wstg="WSTG-CONF-11",
       permission=ACTIVE, transferable=True,
       summary="An SMB server does not require message signing, so authenticated sessions can be relayed/tampered.",
       detect="Read the server SecurityMode from an SMB2 NEGOTIATE response (no auth); SIGNING_REQUIRED (0x0002) "
              "is not set.",
       exploit="Coerce/capture an authentication and NTLM-relay it to this host to act as the victim.",
       oracle="The SMB2 NEGOTIATE SecurityMode lacks the SIGNING_REQUIRED flag."),
    # beyond web (ICS/OT pentest): unauthenticated Modbus/TCP device exposure. READ-ONLY — never writes to OT.
    _t(id="modbus_exposed", vuln_class="ics_ot", cwe="CWE-306", owasp="A05:2021", wstg="WSTG-CONF-01",
       permission=ACTIVE, transferable=True,
       summary="An unauthenticated Modbus/TCP (OT) device is reachable on the network.",
       detect="Send a READ-ONLY Modbus request (device-identification 0x2B/0x0E or read-holding-register 0x03); a "
              "well-formed response echoing the transaction id + protocol 0 proves a live, unauthenticated device.",
       exploit="Read process/register data with no auth; an attacker who reaches TCP/502 could also WRITE to "
               "manipulate the physical process (out of scope for Apolaki — read-only, never writes to OT).",
       oracle="A Modbus response (0x2B/0x03 or its exception) matching our transaction id returns without auth."),
    # beyond web (infra pentest): unauthenticated VNC remote desktop.
    _t(id="vnc_no_auth", vuln_class="network_service", cwe="CWE-306", owasp="A07:2021", wstg="WSTG-CONF-01",
       permission=ACTIVE, transferable=True,
       summary="A VNC server offers the 'None' security type — full remote desktop control with no password.",
       detect="Complete only the RFB version + security-type handshake (no session, no password); security type "
              "'None' (1) is advertised.",
       exploit="Connect with any VNC client and take full keyboard/mouse/screen control of the host.",
       oracle="The RFB handshake's offered security types include 'None' (1)."),
    # beyond web (infra pentest): anonymous rsync module enumeration.
    _t(id="rsync_anon", vuln_class="network_service", cwe="CWE-306", owasp="A01:2021", wstg="WSTG-CONF-01",
       permission=ACTIVE, transferable=True,
       summary="An rsync daemon lets an anonymous client enumerate (and often read) its modules.",
       detect="Complete the @RSYNCD greeting and send '#list' (no password); the daemon returns its module names.",
       exploit="Read exposed modules (backups/web roots/config) anonymously for data theft + lateral-movement intel.",
       oracle="An anonymous '#list' returns >=1 module name."),
    # beyond web (infra pentest): NTP monlist amplification + client disclosure.
    _t(id="ntp_monlist", vuln_class="network_service", cwe="CWE-406", owasp="A05:2021", wstg="WSTG-CONF-01",
       permission=ACTIVE, transferable=True,
       summary="An NTP server answers the legacy 'monlist' (mode 7) request — a UDP-amplification reflector.",
       detect="Send one read-only ntpdc REQ_MON_GETLIST_1 (monlist) query; a mode-7 response confirms it (CVE-2013-5211).",
       exploit="Abuse as a high-ratio UDP-amplification DDoS reflector; harvest recent client IPs it discloses.",
       oracle="The server returns a mode-7 monlist response to the monlist request."),
    # beyond web (BMC/infra pentest): IPMI 2.0 RMCP+ RAKP hash disclosure — detection only.
    _t(id="ipmi_rakp", vuln_class="network_service", cwe="CWE-522", owasp="A07:2021", wstg="WSTG-CONF-01",
       permission=ACTIVE, transferable=True,
       summary="An IPMI 2.0 BMC speaks RMCP+ over LAN, inherently disclosing a crackable RAKP password hash.",
       detect="Send one read-only RMCP+ Open Session Request; an Open Session Response confirms IPMI 2.0 "
              "(CVE-2013-4786). Detection only — never request the RAKP hash or try a credential.",
       exploit="Capture + crack the RAKP HMAC offline -> BMC admin -> out-of-band host takeover (power/console/vmedia).",
       oracle="The BMC returns an RMCP+ Open Session Response (payload type 0x11)."),
    # beyond web (infra pentest): RDP without Network Level Authentication.
    _t(id="rdp_no_nla", vuln_class="network_service", cwe="CWE-287", owasp="A07:2021", wstg="WSTG-CONF-01",
       permission=ACTIVE, transferable=True,
       summary="An RDP server does not require Network Level Authentication (CredSSP), exposing the pre-auth stack.",
       detect="Offer standard RDP security in the X.224 negotiation; a Negotiation Response (not a HYBRID_REQUIRED "
              "failure) confirms NLA is not enforced.",
       exploit="Reach the RDP login unauthenticated for credential attacks + pre-auth RCE (CVE-2019-0708 BlueKeep).",
       oracle="The RDP server returns a Negotiation Response to a standard-RDP offer instead of requiring CredSSP."),
    # beyond web (infra pentest): SNMP still on a documented default community string.
    _t(id="snmp_default_community", vuln_class="network_service", cwe="CWE-1188", owasp="A05:2021", wstg="WSTG-CONF-01",
       permission=ACTIVE, transferable=True,
       summary="An SNMP agent still accepts a documented default community string (public/private).",
       detect="One read-only SNMPv2c GET for sysDescr.0 per default community (single known values, no wordlist); "
              "an agent ignores a wrong community, so a GetResponse with error-status 0 proves the default is live.",
       exploit="Read device config/interfaces/routes/ARP (RO 'public'); a RW 'private' community rewrites config.",
       oracle="A GET with a default community returns a GetResponse (error-status 0) with a sysDescr value."),

    # distilled from WAHH ch9 — structural/ORDER BY SQLi (unquoted, prepared statements do NOT protect it).
    _t(id="sqli_structural", vuln_class="sql_injection", cwe="CWE-89", owasp="A03:2021", wstg="WSTG-INPV-05",
       permission=INTRUSIVE, transferable=True,
       summary="SQL injection into the query STRUCTURE (ORDER BY / column position), not a quoted data value.",
       detect="A valid subquery (SELECT 1) runs clean while an invalid one (SELECT 1 FROM <nonexistent>) raises "
              "a DBMS error absent from the baseline — a differential a non-SQL context cannot produce.",
       exploit="Escalate with a boolean-inference subquery in the ORDER BY position to read arbitrary data.",
       oracle="Invalid-subquery DBMS error present, valid-subquery error absent (both/neither = not SQL = no FP)."),

    _t(id="xpath_injection", vuln_class="xpath_injection", cwe="CWE-643", owasp="A03:2021",
       permission=INTRUSIVE, transferable=True,
       summary="Injection into an XPath query built over an XML document (often an XML-backed login form).",
       detect="Request-level differential (xpath_tool): a stray quote flips the HTTP status class (error-based), "
              "or the `' or '1'='1` / `' or '1'='2` pair splits (boolean) — same shape as SQLi.",
       exploit="Inject an XPath tautology to bypass an XML-backed login, or blind-boolean to read any node "
               "(XPath has no per-node ACLs).",
       oracle="A stray quote breaks the query (status-class change) OR the true-branch matches the baseline "
              "while the false-branch diverges — a differential a literal value cannot explain."),

    # distilled from *Beginner Web Application Pentester* (Abdollahi), "Testing for LDAP/SSI injection".
    _t(id="ldap_injection", vuln_class="ldap_injection", cwe="CWE-90", owasp="A03:2021",
       permission=INTRUSIVE, transferable=True, wstg="WSTG-INPV-06",
       summary="Injection into an LDAP search filter built from user input (directory auth / user lookup).",
       detect="An unbalanced filter metacharacter ( ) * & | provokes an LDAP DIRECTORY error signature "
              "(javax.naming/JNDI/OpenLDAP/AD/ldap_*) that the baseline lacks — LDAP-specific, so it never "
              "collides with SQLi/XPath.",
       exploit="Bypass an LDAP-backed login with a filter tautology `*)(uid=*))(|(uid=*`, or enumerate objects.",
       oracle="An LDAP directory error signature appears on the metacharacter break but not the baseline."),

    # distilled from OWASP WSTG / PortSwigger material (RedCyber corpus) — "Path confusion: web cache deception".
    _t(id="cache_deception", vuln_class="cache_deception", cwe="CWE-525", owasp="A05:2021",
       permission=ACTIVE, transferable=True, wstg="WSTG-ATHZ-05",
       summary="Web cache deception: a path-confused URL (/account/x.css) caches the victim's private page.",
       detect="The origin serves the private page for a fake static suffix; an ANONYMOUS fetch of the same "
              "URL then returns tokens private to the authenticated page — only the cache could have served them.",
       exploit="Lure a logged-in victim to /private/x.css; then read their cached private data unauthenticated.",
       oracle="An anonymous GET of the path-confused URL leaks the tester's OWN authenticated-only tokens.",
       needs_fixture=["authenticated_session"], fixture_source="harvest"),

    # deterministic client/config hygiene checks (RedCyber corpus WSTG coverage gaps) — content-confirmed.
    _t(id="reverse_tabnabbing", vuln_class="client_side", cwe="CWE-1022", owasp="A05:2021",
       permission=PASSIVE, transferable=True, wstg="WSTG-CLNT-14",
       summary="A target=_blank link to a different origin without rel=noopener leaks window.opener.",
       detect="Page HTML has <a target=_blank href=EXTERNAL> lacking rel=noopener/noreferrer.",
       exploit="From the opened page, set window.opener.location to a phishing clone of the original tab.",
       oracle="The offending anchor is present in the page HTML (deterministic, no runtime needed)."),

    _t(id="permissive_crossdomain", vuln_class="misconfiguration", cwe="CWE-942", owasp="A05:2021",
       permission=PASSIVE, transferable=True, wstg="WSTG-CONF-08",
       summary="crossdomain.xml / clientaccesspolicy.xml grants cross-origin access to any origin (domain=*).",
       detect="The served policy file contains a wildcard allow-access-from domain=\"*\" (or <domain uri=\"*\">).",
       exploit="A Flash/Silverlight object on any origin reads this site's authenticated responses.",
       oracle="The policy file content contains the wildcard grant (deterministic file content)."),

    # distilled from the WAF-evasion TTP material (RedCyber/NotebookLM corpus) — inspection-window padding.
    _t(id="waf_bypass", vuln_class="protection_failure", cwe="CWE-693", owasp="A05:2021",
       permission=ACTIVE, transferable=True,
       summary="WAF inspection-window bypass: pad a blocked signature past the ~8KB inspection ceiling.",
       detect="A bare signature payload is BLOCKED, but the same payload after ~8KB of junk is NOT blocked and reflects.",
       exploit="Smuggle any WAF-blocked payload (XSS/SQLi) to the app by prepending junk past the inspection limit.",
       oracle="Three-state differential: baseline OK, raw signature blocked, padded signature passes + reflects."),

    _t(id="css_injection", vuln_class="css_injection", cwe="CWE-74", owasp="A03:2021",
       permission=ACTIVE, transferable=True, wstg="WSTG-CLNT-05",
       summary="User input reflected into a <style> block / style attribute lets an attacker inject CSS rules.",
       detect="A marker carrying CSS breakout chars ({ } ; :) reflects into a style context with them unescaped.",
       exploit="Inject attribute-selector rules with background:url() to exfiltrate CSRF tokens / input values.",
       oracle="The CSS structural chars survive unescaped inside a <style> block or style=\"\" attribute."),

    _t(id="ssi_injection", vuln_class="ssi_injection", cwe="CWE-97", owasp="A03:2021",
       permission=ACTIVE, transferable=True, wstg="WSTG-INPV-08",
       summary="Server-Side Includes injection: user input reaches an SSI-parsed response and executes.",
       detect="Inject the benign `<!--#echo var=\"DATE_GMT\" -->` wrapped in unique markers; the server "
              "replaces it with a live DATE between the markers (executed) rather than echoing the literal.",
       exploit="Escalate to file read via `#include file=` and, if the exec directive is on, OS command via "
               "`#exec cmd=` (NOT fired by the engine — confirmation is the benign echo only).",
       oracle="A live date appears between our two random markers where the literal directive was injected."),

    # distilled from *Redefining Hacking* (Santos), ch 8 AI security — Table 8-2 + garak/ps-fuzz probes.
    _t(id="llm_prompt_injection", vuln_class="llm_prompt_injection", cwe="CWE-1427", owasp="LLM01:2025",
       permission=ACTIVE, transferable=True,
       summary="Direct prompt injection: user input overrides the app's LLM instructions.",
       detect="Chat-endpoint gate + a UNIQUE-marker instruction-override across a guardrail-evasion family "
              "(direct/leetspeak/base64/roleplay/hypothetical/reinforcement/format-shift/…) (llm_tool).",
       exploit="Frame the override so a guardrail lets it through; escalate to a real policy/context bypass.",
       oracle="The model returns the exact per-run marker verbatim (zero legitimate reason to appear)."),
    _t(id="llm_output_handling", vuln_class="llm_output_handling", cwe="CWE-79", owasp="LLM02:2025",
       permission=ACTIVE, transferable=True,
       summary="Insecure output handling: the app returns model-generated Markdown/HTML UNESCAPED.",
       detect="Ask the model to emit a Markdown image + HTML tag carrying a unique marker; check the raw, "
              "un-encoded markup survives in the response (llm_tool.output_handling_*).",
       exploit="A rendering client fetches the image (data exfil beacon) or executes the HTML (XSS) — "
               "reachable via direct or indirect/stored prompt injection.",
       oracle="Attacker-chosen markup with a unique marker appears un-encoded in the response (an encoding "
              "control would have neutralised it)."),

    _t(id="idor_bola_read", vuln_class="access_control", cwe="CWE-639", owasp="A01:2021",
       permission=ACTIVE, transferable=True, pack="idor_read",
       summary="IDOR/BOLA: one identity reads another identity's object.",
       detect="Object reference in a URL/param + a second same-privilege persona to compare against.",
       exploit="Mint two same-privilege personas (autonomous signup, or operator-supplied); read the "
               "owner's object id from the second persona.",
       oracle="Two-user authorization matrix: the ANONYMOUS control is denied (object is protected) and a "
              "DIFFERENT authenticated persona reads the SAME object as the owner (>=0.9 similarity) — "
              "ownership-proven cross-user access. A public endpoint (anon also reads it) is never reported.",
       validated_on=["juiceshop"],
       maps_to={"juiceshop": ["View Basket"]}),

    _t(id="bfla_privileged_action", vuln_class="access_control", cwe="CWE-285", owasp="A01:2021",
       permission=ACTIVE, transferable=True, pack="bfla_privileged_action",
       summary="Broken function-level authz: low-privilege session reaches a privileged function.",
       detect="Privileged endpoint referenced in client code but not gated server-side.",
       exploit="From a low-priv persona, invoke the admin/privileged endpoint directly.",
       oracle="Authorization matrix: a privileged-looking function returns 200 + privileged effect for a "
              "non-privileged persona (rank < privileged).",
       maps_to={"juiceshop": ["Admin Section", "GDPR Data Export"]}),

    _t(id="missing_authentication", vuln_class="access_control", cwe="CWE-306", owasp="A01:2021",
       permission=ACTIVE, transferable=True, pack="idor_read",
       summary="Broken access control: a protected object endpoint is reachable with no authentication.",
       detect="An object-bearing endpoint compared across the anonymous persona and an authenticated one.",
       exploit="Request the object endpoint with NO session; receive the same protected data an authed user sees.",
       oracle="Authorization matrix: the anonymous persona receives the SAME object data an authenticated "
              "persona does — the endpoint does not require a session (only fires on object endpoints, so a "
              "genuinely public page is never flagged).",
       validated_on=["juiceshop"]),

    _t(id="mass_assignment", vuln_class="access_control", cwe="CWE-915", owasp="A01:2021",
       permission=ACTIVE, transferable=True,
       summary="Mass assignment / over-posting a protected attribute (e.g. role).",
       detect="Object create/update accepts fields beyond the documented contract.",
       exploit="Add a privileged attribute (role, isAdmin, deluxeToken) to a write body.",
       oracle="Server persists the injected attribute (readback shows elevated state)."),

    _t(id="exposed_files_harvest", vuln_class="sensitive_exposure", cwe="CWE-548", owasp="A05:2021",
       permission=ACTIVE, transferable=True, pack=None,
       summary="Harvest sensitive files from a browsable/guessable path (incl. null-byte bypass).",
       detect="Directory listing / predictable backup + doc paths (dir_harvest).",
       exploit="Enumerate and retrieve files; apply poison-null-byte (%2500) to bypass extension filters.",
       oracle="File retrieved (200 + expected content signature) that is not linked by the app.",
       validated_on=["juiceshop"],
       maps_to={"juiceshop": ["Confidential Document", "Forgotten Sales Backup",
                              "Forgotten Developer Backup", "Misplaced Signature File",
                              "Poison Null Byte", "Access Log"]}),

    _t(id="exposed_credentials", vuln_class="sensitive_exposure", cwe="CWE-522", owasp="A07:2021",
       permission=ACTIVE, transferable=True,
       summary="Credentials the target itself exposes (published/leaked login) reused to authenticate.",
       detect="A username+password pair harvested from the target's OWN surface (page/JS/comment/help/docs).",
       exploit="Log in ONCE with the discovered credential (never brute-forced) to reach authenticated surface.",
       oracle="The discovered credential yields a valid session and an authenticated-only page loads.",
       validated_on=["ginandjuice"],
       maps_to={"ginandjuice": ["Published test account (carlos) -> authenticated scan"]}),

    _t(id="dom_xss", vuln_class="xss", cwe="CWE-79", owasp="A03:2021",
       permission=ACTIVE, transferable=True,
       summary="DOM-based XSS via an unsanitized client-side sink.",
       detect="User-controlled value flows into a DOM sink (dom_tool + rendered browser).",
       exploit="Deliver a payload that a client-side sink executes in the rendered DOM.",
       oracle="Browser confirms script execution originating from the injected value (host-matched).",
       validated_on=["juiceshop"],
       maps_to={"juiceshop": ["DOM XSS"]}),

    _t(id="reflected_xss", vuln_class="xss", cwe="CWE-79", owasp="A03:2021",
       permission=ACTIVE, transferable=True,
       summary="Reflected XSS: input echoed into a response without encoding.",
       detect="Marker reflected into an executable HTML/JS context.",
       exploit="Place a payload in a reflected parameter that the response renders unescaped.",
       oracle="Rendered response executes the payload (context-correct break-out).",
       maps_to={"juiceshop": ["Reflected XSS", "API-only XSS"]}),

    _t(id="stored_xss", vuln_class="xss", cwe="CWE-79", owasp="A03:2021",
       permission=ACTIVE, transferable=True,
       summary="Stored/persistent XSS surfaced to another viewer.",
       detect="Persisted field rendered unescaped on a read path.",
       exploit="Persist a payload via a write path; trigger on the read path.",
       oracle="Payload executes when the stored value is later rendered."),

    _t(id="csti", vuln_class="template_injection", cwe="CWE-1336", owasp="A03:2021",
       permission=ACTIVE, transferable=True,
       summary="Client-side template injection (Angular-style sandbox escape).",
       detect="Template expression evaluated client-side (e.g. {{ }} interpolation).",
       exploit="Inject a template expression that the client framework evaluates.",
       oracle="Framework evaluates the expression (arithmetic/constructor proof).",
       validated_on=["juiceshop", "ginandjuice"],
       maps_to={"juiceshop": ["CSTI"], "ginandjuice": ["Client-side template injection (search)"]}),

    _t(id="ssti", vuln_class="template_injection", cwe="CWE-94", owasp="A03:2021",
       permission=ACTIVE, transferable=True,
       summary="Server-side template injection.",
       detect="Server-side evaluation of a template expression in a response.",
       exploit="Inject an expression the server template engine evaluates.",
       oracle="Server response reflects evaluated (not literal) expression output.",
       validated_on=["juiceshop"],
       maps_to={"juiceshop": ["SSTi"]}),

    _t(id="xxe_file_ssrf", vuln_class="xxe", cwe="CWE-611", owasp="A05:2021",
       permission=INTRUSIVE, transferable=True,
       summary="XML external entity: file read / blind SSRF via entity dereference.",
       detect="XML intake (upload / B2B) that resolves external entities (xxe_tool).",
       exploit="Submit a DTD with an external entity; read a file or force an outbound fetch.",
       oracle="Out-of-band callback or file content proves external-entity resolution.",
       validated_on=["juiceshop"],
       maps_to={"juiceshop": ["XXE Data Access", "XXE DoS"]}),

    _t(id="jwt_forge", vuln_class="crypto_authz", cwe="CWE-347", owasp="A02:2021",
       permission=ACTIVE, transferable=True,
       summary="JWT forgery: alg=none, algorithm confusion, or offline weak-secret crack.",
       detect="JWT in use with a weak/omittable signature (jwt_tool).",
       exploit="Forge a token via none-alg, HS/RS confusion, or an OFFLINE crack of a weak HMAC key.",
       oracle="Server accepts the forged token and grants the asserted identity/claim.",
       needs_fixture=["weak_secret_if_crackable"], fixture_source="external",
       maps_to={"juiceshop": ["Forged Signed JWT", "Unsigned JWT"]}),

    _t(id="jwt_key_confusion", vuln_class="crypto_authz", cwe="CWE-347", owasp="A02:2021",
       permission=ACTIVE, transferable=True, wstg="WSTG-SESS-10",
       summary="JWT algorithm confusion (RS/ES/PS -> HS): forge HS256 signed with the server's OWN public key.",
       detect="Token uses an asymmetric alg and the public key is reachable (JWKS at /.well-known/jwks.json, or an x5c header).",
       exploit="Forge an HS256 token HMAC-signed with the RSA public-key PEM as the secret, escalating privilege claims.",
       oracle="The forged token authenticates on a scoped endpoint where a signature-tampered token is REJECTED (differential — never fires on an accept-anything endpoint).",
       needs_fixture=["asymmetric_jwt", "public_key_from_jwks_or_x5c"], fixture_source="harvest",
       refs=["https://portswigger.net/web-security/jwt/algorithm-confusion"]),

    _t(id="ssrf", vuln_class="ssrf", cwe="CWE-918", owasp="A10:2021",
       permission=INTRUSIVE, transferable=True,
       summary="Server-side request forgery to an attacker-influenced destination.",
       detect="Server fetches a user-supplied URL (ssrf_tool).",
       exploit="Point the server at an internal/OOB destination.",
       oracle="Out-of-band interaction or internal-only response proves server-side fetch."),

    _t(id="open_redirect", vuln_class="redirect", cwe="CWE-601", owasp="A01:2021",
       permission=ACTIVE, transferable=True,
       summary="Unvalidated redirect to an attacker-controlled host.",
       detect="Redirect target taken from user input (dom_tool.confirmed_redirect, host-matched).",
       exploit="Supply an external host as the redirect target.",
       oracle="Response redirects to the attacker HOST (parsed hostname match, not substring)."),

    _t(id="crlf_injection", vuln_class="injection", cwe="CWE-113", owasp="A03:2021",
       permission=ACTIVE, transferable=True,
       summary="CRLF / response-header injection.",
       detect="User input reflected into a response header unfiltered.",
       exploit="Inject CR/LF to split headers / set an unintended header.",
       oracle="Response contains an injected header line attributable to the payload."),

    _t(id="prototype_pollution", vuln_class="prototype_pollution", cwe="CWE-1321", owasp="A08:2021",
       permission=ACTIVE, transferable=True,
       summary="Prototype pollution via __proto__/constructor keys.",
       detect="Merge/assign of user object reaches Object.prototype.",
       exploit="Send a payload polluting a prototype key and observe a gadget effect.",
       oracle="A previously-absent property appears on unrelated objects post-injection.",
       validated_on=["ginandjuice"],
       maps_to={"ginandjuice": ["Client-side prototype pollution (DOM, query)"]}),

    _t(id="insecure_deser", vuln_class="deserialization", cwe="CWE-502", owasp="A08:2021",
       permission=INTRUSIVE, transferable=True,
       summary="Insecure deserialization leading to code/logic execution.",
       detect="Server deserializes attacker-controlled structured input (deser_tool).",
       exploit="Craft a payload whose deserialization triggers an unintended effect.",
       oracle="Deterministic side effect (timing / callback) proves payload execution."),

    _t(id="security_misconfig_errors", vuln_class="misconfig", cwe="CWE-209", owasp="A05:2021",
       permission=PASSIVE, transferable=True,
       summary="Security misconfiguration: verbose errors / stack traces leaking internals.",
       detect="Error path returns a stack trace / internal detail.",
       exploit="Trigger an unhandled condition and capture the leaked internals.",
       oracle="Response body exposes framework/DB internals not intended for clients.",
       validated_on=["juiceshop"],
       maps_to={"juiceshop": ["Error Handling"]}),

    _t(id="vulnerable_component", vuln_class="vuln_component", cwe="CWE-1035", owasp="A06:2021",
       permission=PASSIVE, transferable=True,
       summary="Known-vulnerable dependency (SCA), reported advisory-grade until reachability is shown.",
       detect="Exact version -> CVE mapping (dependency_intel), severity capped pending reachability.",
       exploit="Advisory lead; escalated only if a reachable sink is confirmed.",
       oracle="Version-pinned CVE match; NOT a confirmed exploit unless reachability proven.",
       validated_on=["juiceshop", "ginandjuice"],
       maps_to={"juiceshop": ["Vulnerable Library", "Legacy Typosquatting"],
                "ginandjuice": ["Vulnerable JavaScript dependency (angular@1.7.7 / CVE-2023-26118)"]}),

    _t(id="weak_password_reset", vuln_class="broken_auth", cwe="CWE-640", owasp="A07:2021",
       permission=ACTIVE, transferable=True,
       summary="Account takeover via a weak password-reset (guessable security question / poor flow).",
       detect="Reset flow keyed on a low-entropy security answer.",
       exploit="Answer the security question with data harvested from the app / known-defaults, then reset.",
       oracle="Password changes and the new credential authenticates as the victim.",
       needs_fixture=["security_answer"]),

    _t(id="target_intel_harvest", vuln_class="intelligence", cwe="CWE-200", owasp="A01:2021",
       permission=PASSIVE, transferable=True,
       summary="Mine the target's own surface (DOM/JS/source-maps/API/headers) into usable candidates.",
       detect="Every fetched response is intelligence: emails, users, ids, routes, encoded blobs, hints.",
       exploit="Harvest candidates (intel.py) and feed them as run-time FIXTURES to other techniques.",
       oracle="A harvested candidate enables a subsequent CONFIRMED step (its value proves the harvest).",
       validated_on=["juiceshop"],
       maps_to={"juiceshop": ["Confidential Document", "GDPR Data Export", "Meta Geo Stalking"]}),

    _t(id="encoded_data_decode", vuln_class="crypto_obscurity", cwe="CWE-311", owasp="A02:2021",
       permission=PASSIVE, transferable=True,
       summary="Recover plaintext from encoded/obscured data found on the target (base64/hex/rot).",
       detect="Encoded blob discovered in a file/comment/response during harvest.",
       exploit="Identify the encoding and decode offline (intel.decode_candidate); chain the plaintext.",
       oracle="Decoded value is meaningful and unlocks a subsequent step.",
       maps_to={"juiceshop": ["Easter Egg", "Nested Easter Egg", "Weird Crypto"]}),

    _t(id="weak_secret_forgery", vuln_class="crypto_authz", cwe="CWE-330", owasp="A02:2021",
       permission=ACTIVE, transferable=True,
       summary="Forge a signed artifact (token/coupon/continue-code) whose secret is weak, known, or salt-less.",
       detect="A signed value with a guessable scheme: default/known salt, no salt, short key, published algorithm.",
       exploit="Reproduce the signing offline (e.g. hashids default salt, salt-less base85) to mint a valid artifact.",
       oracle="Server accepts the forged artifact as authentic.",
       validated_on=["juiceshop"],
       maps_to={"juiceshop": ["Imaginary Challenge", "Forged Coupon"]}),

    _t(id="weak_2fa_bypass", vuln_class="broken_auth", cwe="CWE-308", owasp="A07:2021",
       permission=ACTIVE, transferable=True,
       summary="Defeat 2FA using a leaked/guessable TOTP seed or a skippable second-factor step.",
       detect="TOTP seed exposed in storage/source, or a 2FA step that can be bypassed.",
       exploit="Compute the current TOTP from the seed (HMAC-SHA1) and complete the second factor.",
       oracle="The second-factor step accepts the computed code and issues a full session.",
       needs_fixture=["totp_seed"], fixture_source="harvest",
       validated_on=["juiceshop"],
       maps_to={"juiceshop": ["Two Factor Authentication"]}),

    _t(id="business_logic_abuse", vuln_class="business_logic", cwe="CWE-840", owasp="A04:2021",
       permission=ACTIVE, transferable=True,
       summary="Abuse an application-flow assumption (price/quantity/state/time) for unintended value.",
       detect="A workflow trusts a client-controlled quantity, price, coupon, or step ordering.",
       exploit="Submit out-of-policy values: negative quantity, unpaid upgrade, expired/greedy coupon.",
       oracle="The transaction completes in a state the business policy should have forbidden.",
       validated_on=["juiceshop"],
       maps_to={"juiceshop": ["Payback Time", "Deluxe Fraud", "Expired Coupon"]}),

    _t(id="csrf", vuln_class="csrf", cwe="CWE-352", owasp="A01:2021",
       permission=ACTIVE, transferable=True,
       summary="Cross-site request forgery: a state-changing request rides the victim's ambient credential.",
       detect="A state-changing endpoint accepts requests with no anti-CSRF token / lax SameSite.",
       exploit="Issue the request cross-origin using the victim's cookie, with no CSRF token.",
       oracle="The state change is applied for a cross-origin request lacking a valid CSRF token.",
       validated_on=["juiceshop"],
       maps_to={"juiceshop": ["CSRF"]}),

    _t(id="excessive_data_exposure", vuln_class="access_control", cwe="CWE-213", owasp="A01:2021",
       permission=ACTIVE, transferable=True,
       summary="API returns more than the client should see (field over-selection / default over-serialization).",
       detect="A read endpoint reflects client-named fields, or serializes sensitive columns by default.",
       exploit="Request a sensitive field explicitly (e.g. ?fields=password) or read the over-shared object.",
       oracle="Response carries a field (hash, token, PII) outside the endpoint's intended contract.",
       validated_on=["juiceshop"],
       maps_to={"juiceshop": ["Password Hash Leak"]}),

    _t(id="jsonp_info_leak", vuln_class="sensitive_exposure", cwe="CWE-200", owasp="A01:2021",
       permission=ACTIVE, transferable=True,
       summary="Sensitive data exfiltrated cross-origin via a JSONP callback parameter.",
       detect="An endpoint wraps its JSON in an attacker-named callback function.",
       exploit="Supply a callback param so the response becomes script-includable cross-origin.",
       oracle="Response is returned as executable JSONP carrying the sensitive data.",
       validated_on=["juiceshop"],
       maps_to={"juiceshop": ["Email Leak"]}),

    _t(id="race_condition", vuln_class="business_logic", cwe="CWE-362", owasp="A04:2021",
       permission=ACTIVE, transferable=True,
       summary="Concurrency race defeats a single-use / limit check (TOCTOU).",
       detect="A guarded action whose check and commit are not atomic under parallel requests.",
       exploit="Fire concurrent requests so several pass the check before the state updates.",
       oracle="The limited action succeeds more times than the guard should allow.",
       validated_on=["juiceshop"],
       maps_to={"juiceshop": ["Multiple Likes"]}),

    _t(id="command_injection", vuln_class="command_injection", cwe="CWE-78", owasp="A03:2021",
       permission=INTRUSIVE, transferable=True,
       summary="OS command injection: user input reaches a shell command unsanitized.",
       detect="A parameter flows into a system/exec call; shell metacharacters change behavior.",
       exploit="Append a command separator (; | && backtick) plus a benign probe (id/whoami).",
       oracle="Response contains the injected command's output (e.g. uid= from id).",
       validated_on=["dvwa"],
       maps_to={"dvwa": ["Command Injection"]}),

    _t(id="path_traversal", vuln_class="path_traversal", cwe="CWE-22", owasp="A01:2021",
       permission=ACTIVE, transferable=True,
       summary="Path traversal / local file inclusion: a path or filename parameter reads files outside its folder.",
       detect="A parameter names a file/page that is read or included server-side.",
       exploit="Supply ../ sequences (or an absolute path) to escape the intended directory.",
       oracle="Response returns a file outside the app's document root (e.g. the contents of /etc/passwd).",
       validated_on=["dvwa"],
       maps_to={"dvwa": ["File Inclusion"], "juiceshop": ["Local File Read"]}),
    _t(id="archive_slip", vuln_class="path_traversal", cwe="CWE-22", owasp="A01:2021",
       permission=INTRUSIVE, transferable=True,
       summary="Zip-slip: a crafted archive entry name traverses out of the extraction directory and writes an attacker-chosen file.",
       detect="The app extracts a user-uploaded archive (zip/tar) server-side.",
       exploit="Upload an archive whose entry name is '../../<target>' so extraction escapes the intended folder and overwrites a known file.",
       oracle="A file appears/changes at the traversed path (a known file is overwritten), or a chained effect fires (e.g. an overwritten template runs).",
       validated_on=["juiceshop"],
       maps_to={"juiceshop": ["Arbitrary File Write", "Video XSS"]}),
    _t(id="soft_deleted_login", vuln_class="broken_auth", cwe="CWE-287", owasp="A07:2021",
       permission=ACTIVE, transferable=True,
       summary="A 'deleted' account that is only SOFT-deleted (a flag is set, the row is kept) can still authenticate.",
       detect="Account deletion / 'right to be forgotten' leaves the user row; the login path never filters the deleted flag.",
       exploit="Authenticate as the soft-deleted user with its known credentials or an SQLi email+comment that returns the retained row.",
       oracle="A valid session token is issued for an account that should no longer exist.",
       validated_on=["juiceshop"],
       maps_to={"juiceshop": ["GDPR Data Erasure"]}),

    # --- lab-local: counts toward a CTF % but NOT claimed as transferable capability ---
    _t(id="find_hidden_route", vuln_class="misc", cwe="CWE-425", owasp="A01:2021",
       permission=PASSIVE, transferable=False,
       summary="Discover an intentionally-hidden client route (e.g. the score board).",
       detect="Route table mined from the SPA bundle.",
       exploit="Navigate to the un-linked route.",
       oracle="Route loads its intended view.",
       validated_on=["juiceshop"],
       maps_to={"juiceshop": ["Score Board"]}),
]}


# --------------------------------------------------------------------------------------------
# Accessors
# --------------------------------------------------------------------------------------------
def get(tid: str) -> dict | None:
    return TECHNIQUES.get(tid)


def list_techniques() -> list[dict]:
    return [{"id": t["id"], "vuln_class": t["vuln_class"], "cwe": t["cwe"], "owasp": t["owasp"],
             "permission": t["permission"], "transferable": t["transferable"],
             "generalized": is_generalized(t), "pack": t["pack"], "summary": t["summary"]}
            for t in TECHNIQUES.values()]


def classes() -> list[str]:
    return sorted({t["vuln_class"] for t in TECHNIQUES.values()})


def is_generalized(t: dict) -> bool:
    return len(set(t.get("validated_on", []))) >= GENERALIZED_MIN_LABS


def generalized() -> list[str]:
    return [t["id"] for t in TECHNIQUES.values() if is_generalized(t)]


def all_labs() -> list[str]:
    labs = set()
    for t in TECHNIQUES.values():
        labs.update(t.get("validated_on", []))
        labs.update((t.get("maps_to") or {}).keys())
    return sorted(labs)


def coverage_matrix(lab_ids: list[str] | None = None) -> dict:
    """
    Registry-only coverage view (no network). For each technique, which labs it TARGETS
    (maps_to) and which it is VALIDATED on (oracle-confirmed). Summarizes the two honest
    numbers: transferable-capability count vs generalized (>=2 lab) count.
    """
    labs = lab_ids or all_labs()
    rows = []
    for t in TECHNIQUES.values():
        maps = t.get("maps_to") or {}
        validated = set(t.get("validated_on", []))
        rows.append({
            "id": t["id"], "vuln_class": t["vuln_class"], "transferable": t["transferable"],
            "execution": t.get("execution", "auto"),
            "targets": {lab: maps.get(lab, []) for lab in labs if lab in maps},
            "validated_on": sorted(validated & set(labs)) if lab_ids else sorted(validated),
            "transferability_score": len(validated),
            "generalized": is_generalized(t),
        })
    total = len(TECHNIQUES)
    return {
        "labs": labs,
        "techniques_total": total,
        "transferable_total": sum(1 for t in TECHNIQUES.values() if t["transferable"]),
        "generalized_total": len(generalized()),
        "lab_local_total": sum(1 for t in TECHNIQUES.values() if not t["transferable"]),
        "rows": rows,
    }


def techniques_for_lab(lab_id: str) -> list[dict]:
    """Techniques that target the given lab (via maps_to)."""
    out = []
    for t in TECHNIQUES.values():
        if lab_id in (t.get("maps_to") or {}):
            out.append(t)
    return out


# --------------------------------------------------------------------------------------------
# Backfill: mark techniques we ACTUALLY proved on Juice Shop this session (their oracle fired
# against the live board) so validated_on stops under-reporting real capability. maps_to is
# merged, never overwritten. This keeps the honesty metric honest in the *right* direction.
# --------------------------------------------------------------------------------------------
_JUICESHOP_PROVEN = {
    "ssrf": ["SSRF"],
    "reflected_xss": ["Reflected XSS", "HTTP-Header XSS"],
    "stored_xss": ["API-only XSS", "Server-side XSS Protection"],
    "nosql_injection": ["NoSQL Manipulation", "NoSQL Exfiltration"],
    "jwt_forge": ["Forged Signed JWT", "Unsigned JWT"],
    "mass_assignment": ["Admin Registration"],
    "open_redirect": ["Outdated Allowlist", "Allowlist Bypass"],
    "weak_password_reset": ["Reset Jim's Password", "Reset Bender's Password",
                            "Reset Bjoern's Password", "Reset Morty's Password",
                            "Reset Uvogin's Password", "Bjoern's Favorite Pet"],
    "bfla_privileged_action": ["Admin Section", "Product Tampering"],
    "encoded_data_decode": ["Nested Easter Egg", "Premium Paywall"],
}
for _tid, _chs in _JUICESHOP_PROVEN.items():
    _rec = TECHNIQUES.get(_tid)
    if _rec:
        if "juiceshop" not in _rec["validated_on"]:
            _rec["validated_on"] = _rec["validated_on"] + ["juiceshop"]
        _m = dict(_rec.get("maps_to") or {})
        _m["juiceshop"] = sorted(set(_m.get("juiceshop", []) + _chs))
        _rec["maps_to"] = _m

# Second lab: techniques whose ORACLE also fired on DVWA (low security), proven live via direct
# HTTP. Two independent labs => these flip to GENERALIZED — the honest transferability bar.
_DVWA_PROVEN = {
    "sqli_auth_bypass": ["SQL Injection"],
    "sqli_union_extract": ["SQL Injection"],
    "reflected_xss": ["XSS (Reflected)"],
    "stored_xss": ["XSS (Stored)"],
    "csrf": ["CSRF"],
    "command_injection": ["Command Injection"],
}
for _tid, _chs in _DVWA_PROVEN.items():
    _rec = TECHNIQUES.get(_tid)
    if _rec:
        if "dvwa" not in _rec["validated_on"]:
            _rec["validated_on"] = _rec["validated_on"] + ["dvwa"]
        _m = dict(_rec.get("maps_to") or {})
        _m["dvwa"] = sorted(set(_m.get("dvwa", []) + _chs))
        _rec["maps_to"] = _m

# Third lab: techniques whose EXACT oracle fired on bWAPP (bee/bug, low security), proven live via direct
# HTTP response signatures (command output / file contents / verbatim reflection). Flips command_injection
# and path_traversal (previously DVWA-only) to GENERALIZED. SQLi is confirmed at the CLASS level in the
# bwapp prover/benchmark (error-based injection) but not added here -- neither the auth-bypass nor the
# UNION-extract oracle was reproduced, so the specific sqli techniques stay honestly unclaimed on bWAPP.
_BWAPP_PROVEN = {
    "command_injection": ["OS Command Injection"],
    "path_traversal": ["Directory Traversal - Files"],
    "reflected_xss": ["XSS - Reflected (GET)"],
}
for _tid, _chs in _BWAPP_PROVEN.items():
    _rec = TECHNIQUES.get(_tid)
    if _rec:
        if "bwapp" not in _rec["validated_on"]:
            _rec["validated_on"] = _rec["validated_on"] + ["bwapp"]
        _m = dict(_rec.get("maps_to") or {})
        _m["bwapp"] = sorted(set(_m.get("bwapp", []) + _chs))
        _rec["maps_to"] = _m

# Fourth lab: techniques whose EXACT oracle fired on Mutillidae (NOWASP), proven live via response
# signatures (LFI file contents / command output / verbatim reflection / client redirect to attacker host).
# open_redirect was Juice-Shop-only -> Mutillidae is its 2nd lab -> it flips to GENERALIZED.
_MUTILLIDAE_PROVEN = {
    "open_redirect": ["Open Redirect (redirectandlog.php)"],
    "path_traversal": ["Local File Inclusion (page param)"],
    "command_injection": ["OS Command Injection (DNS Lookup)"],
    "reflected_xss": ["Reflected XSS (DNS Lookup)"],
}
for _tid, _chs in _MUTILLIDAE_PROVEN.items():
    _rec = TECHNIQUES.get(_tid)
    if _rec:
        if "mutillidae" not in _rec["validated_on"]:
            _rec["validated_on"] = _rec["validated_on"] + ["mutillidae"]
        _m = dict(_rec.get("maps_to") or {})
        _m["mutillidae"] = sorted(set(_m.get("mutillidae", []) + _chs))
        _rec["maps_to"] = _m

# Taxonomy-lens codes (best-effort; high-confidence mappings only, None where no clean fit).
_WSTG = {
    "sqli_auth_bypass": "WSTG-INPV-05", "sqli_union_extract": "WSTG-INPV-05",
    "nosql_injection": "WSTG-INPV-05", "command_injection": "WSTG-INPV-12", "reflected_xss": "WSTG-INPV-01",
    "stored_xss": "WSTG-INPV-02", "dom_xss": "WSTG-CLNT-01", "ssti": "WSTG-INPV-18",
    "xxe_file_ssrf": "WSTG-INPV-07", "jwt_forge": "WSTG-SESS-10", "ssrf": "WSTG-INPV-19",
    "open_redirect": "WSTG-CLNT-04", "crlf_injection": "WSTG-INPV-16",
    "idor_bola_read": "WSTG-ATHZ-04", "bfla_privileged_action": "WSTG-ATHZ-02",
    "mass_assignment": "WSTG-ATHZ-04", "excessive_data_exposure": "WSTG-ATHZ-04",
    "exposed_files_harvest": "WSTG-CONF-04", "security_misconfig_errors": "WSTG-ERRH-01",
    "weak_password_reset": "WSTG-ATHN-09", "weak_2fa_bypass": "WSTG-ATHN-11",
    "target_intel_harvest": "WSTG-INFO-05", "csrf": "WSTG-SESS-05",
    "business_logic_abuse": "WSTG-BUSL-01", "race_condition": "WSTG-BUSL-09",
    "weak_secret_forgery": "WSTG-CRYP-04", "encoded_data_decode": "WSTG-CRYP-04",
    "jsonp_info_leak": "WSTG-CLNT-11", "csti": "WSTG-CLNT-13",
}
# MITRE ATT&CK is an adversary-TTP lens — deliberately coarse for web-app bugs; mapped only
# where a technique genuinely corresponds, None elsewhere (honest gaps rather than forced fits).
_MITRE = {
    "sqli_auth_bypass": "T1190", "sqli_union_extract": "T1190", "nosql_injection": "T1190", "command_injection": "T1190",
    "xxe_file_ssrf": "T1190", "ssrf": "T1190", "ssti": "T1190", "insecure_deser": "T1190",
    "jwt_forge": "T1550.001", "weak_2fa_bypass": "T1111", "weak_password_reset": "T1098",
    "exposed_files_harvest": "T1083", "target_intel_harvest": "T1592",
    "excessive_data_exposure": "T1213",
    # session's new book/corpus engines — Exploit Public-Facing Application for the injection classes,
    # Use Alternate Auth Material (app access token) for the JWT forgery. Others have no clean ATT&CK fit.
    "xpath_injection": "T1190", "ldap_injection": "T1190", "ssi_injection": "T1190",
    "css_injection": "T1190", "jwt_key_confusion": "T1550.001",
}
# "Try it" — a concrete request to fire against a wired practice target (Juice Shop @ :42000 /
# DVWA @ :42080), so a technique can be learned by DOING it, in-app. Copy-paste, then tweak.
_TRY = {
    "sqli_auth_bypass": "POST /rest/user/login  json {\"email\":\"' or 1=1--\",\"password\":\"x\"}  → admin token",
    "sqli_union_extract": "GET /rest/products/search?q=')) UNION SELECT sql,2,3,4,5,6,7,8,9 FROM sqlite_master--",
    "reflected_xss": "GET /rest/track-order/<iframe src=\"javascript:alert(`xss`)\">",
    "stored_xss": "POST /api/Products  json {\"description\":\"<iframe src=\\\"javascript:alert(`xss`)\\\">\"}",
    "jwt_forge": "GET /encryptionkeys/jwt.pub  → sign an HS256 token with that key as the HMAC secret → send as Bearer",
    "excessive_data_exposure": "GET /rest/user/whoami?fields=id,email,password  (cookie: token=<jwt>)  → password hash",
    "bfla_privileged_action": "PUT /api/Products/9  json {\"description\":\"<a href=\\\"https://owasp.slack.com\\\" target=\\\"_blank\\\">x</a>\"}",
    "business_logic_abuse": "add a basket item with a NEGATIVE quantity, then POST /rest/basket/{bid}/checkout",
    "open_redirect": "GET /redirect?to=https://evil.example/?x=https://github.com/juice-shop/juice-shop",
    "idor_bola_read": "GET /rest/basket/2  with YOUR token (basket 2 isn't yours)",
    "csrf": "POST /profile  (cookie token, Origin: http://htmledit.squarefree.com, username change)",
    "weak_secret_forgery": "forge a z85 coupon (MMMYY-99, salt-free) offline → PUT /rest/basket/{bid}/coupon/{code}",
    "command_injection": "(DVWA :42080) POST /vulnerabilities/exec/  ip=127.0.0.1;id  → look for uid=",
    "archive_slip": "POST /file-upload  (multipart .zip) whose entry name is '../../../<target>' → extraction writes outside the dir",
    "soft_deleted_login": "POST /rest/user/login  json {\"email\":\"deleted-user@x'--\",\"password\":\"x\"} → session for a soft-deleted account",
    "weak_2fa_bypass": "compute the TOTP from the leaked secret (HMAC-SHA1) → POST /rest/2fa/verify",
    "exposed_files_harvest": "GET /ftp/package.json.bak%2500.md  (poison null byte past the extension filter)",
}
_WSTG_BASE = "https://owasp.org/www-project-web-security-testing-guide/stable/"
for _tid, _rec in TECHNIQUES.items():
    _rec["wstg"] = _WSTG.get(_tid)
    _rec["mitre"] = _MITRE.get(_tid)
    if _rec["wstg"] and not _rec.get("refs"):
        _rec["refs"] = [_WSTG_BASE]


# --------------------------------------------------------------------------------------------
# Taxonomy lenses — the SAME technique registry, grouped by whichever framework you enable.
# Adding techniques makes the tool smarter; switching a lens only changes the view.
# --------------------------------------------------------------------------------------------
_LENSES = [
    ("owasp", "OWASP Top 10 (2021)", "owasp"),
    ("wstg", "OWASP WSTG", "wstg"),
    ("cwe", "CWE", "cwe"),
    ("mitre", "MITRE ATT&CK", "mitre"),
    ("class", "Vulnerability class", "vuln_class"),
]
_LENS_FIELD = {lid: field for lid, _lbl, field in _LENSES}


def taxonomy_view(lens: str = "owasp") -> dict:
    """Group the technique registry by a chosen taxonomy lens. proven = oracle-confirmed on a
    lab; catalogued = known technique, not yet demonstrated (validated_on empty)."""
    field = _LENS_FIELD.get(lens, "owasp")
    groups: dict[str, list] = {}
    for t in TECHNIQUES.values():
        key = t.get(field) or "(unmapped)"
        groups.setdefault(key, []).append({
            "id": t["id"], "summary": t["summary"], "vuln_class": t["vuln_class"],
            "cwe": t["cwe"], "owasp": t["owasp"], "wstg": t.get("wstg"), "mitre": t.get("mitre"),
            "permission": t["permission"], "transferable": t["transferable"],
            "generalized": is_generalized(t), "validated_on": t.get("validated_on", []),
            "status": "proven" if t.get("validated_on") else "catalogued",
            "maps_to": t.get("maps_to") or {}, "refs": t.get("refs", []),
            "execution": t.get("execution", "auto"),
            # the in-app lesson — learn the method without leaving Apolaki
            "detect": t.get("detect", ""), "exploit": t.get("exploit", ""), "oracle": t.get("oracle", ""),
            "try_it": _TRY.get(t["id"]),   # concrete request to fire on a wired practice target
        })
    out = [{"key": k, "count": len(v),
            "techniques": sorted(v, key=lambda x: (x["status"] != "proven", x["id"]))}
           for k, v in groups.items()]
    out.sort(key=lambda g: (g["key"] == "(unmapped)", g["key"]))
    return {
        "lens": lens, "lenses": [{"id": lid, "label": lbl} for lid, lbl, _f in _LENSES],
        "groups": out,
        "total": len(TECHNIQUES),
        "proven": sum(1 for t in TECHNIQUES.values() if t.get("validated_on")),
        "transferable": sum(1 for t in TECHNIQUES.values() if t["transferable"]),
        "generalized": len(generalized()),
    }

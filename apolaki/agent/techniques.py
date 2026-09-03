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

A technique is GENERALIZED once it names >= 2 independent labs AND a liveness run has produced the
artifact. Until then it is a candidate — claimed on one lab, not yet shown to transfer. The coverage
matrix reports both numbers so the headline claim ("general capability" vs "lab completion") stays
honest.

`validated_on` IS TYPED; WHAT IT IS WORTH IS DERIVED. Every value in this file is a literal somebody
wrote, so the field alone can never be evidence. Three functions decide what a literal buys:
  - known_labs()        the legal vocabulary, derived from target registries + liveness runs, so a
                        lab id that names no real target cannot be spelled here at all;
  - validation_record() recorded / not_recorded / not_applicable, the Q-012 three-way split;
  - is_proven()         THE single shared predicate — every module that says "proven" calls this one,
                        because two subsystems disagreeing about the word is how /packs reported 48
                        while /techniques reported 16 about the same registry.

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
    # A HAND-WRITTEN BACKFILL IS NOT A PROOF. The four _*_PROVEN dicts below record labs where someone
    # once observed a technique work; they used to append straight into validated_on, which is the field
    # the UI renders as a green "Proven" badge. Nothing re-checked those entries, and at least one
    # (weak_password_reset) has no production executor at all — what fired was the lab SOLVER. The claim
    # is kept here, separate, so it stays visible and can be re-earned by a liveness run instead of
    # masquerading as verification.
    kw.setdefault("backfill_claim", [])
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
    # Executable-knowledge proof contract (Nuclei-style): the FP-safety differential + evidence obligations,
    # made explicit on every record (derived from class+oracle; an entry may pre-set any field to override).
    import technique_model as _tm
    for _k, _v in _tm.proof_contract(kw).items():
        kw.setdefault(_k, _v)
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

    # ── CYCLE 18: the five engines mined from Burp's published issue catalog. Each is declared
    # here because a liveness entry must carry a TYPED CLAIM -- an id with no technique record is
    # a green tick nothing can hold to account. Every `validated_on` below was earned by a
    # liveness run against the named lab, not hand-written.

    _t(id="private_key_disclosed", vuln_class="sensitive_exposure", cwe="CWE-522",
       owasp="A02:2021", permission=PASSIVE, transferable=True,
       summary="A private key is served in a response body.",
       detect="PEM armour with real key material between the markers, outside any display element.",
       exploit="Impersonate the service, decrypt captured traffic, or sign as the key holder.",
       oracle="Armour plus >=100 chars of key material, with no placeholder text and not inside a "
              "<pre>/<code> display span -- a documentation page SHOWING a PEM is not a leak.",
       wstg="WSTG-CONF-04", mitre="T1552",
       validated_on=["domsource"]),

    _t(id="websocket_url_poisoning", vuln_class="client_side", cwe="CWE-918", owasp="A10:2021",
       permission=ACTIVE, transferable=True,
       summary="The page opens a WebSocket to an endpoint the attacker chooses.",
       detect="Runtime hook on the WebSocket constructor during a browser render of a probed source.",
       exploit="Point the socket at attacker infrastructure; own both directions of the channel.",
       oracle="The canary is the AUTHORITY of the socket URL, not merely present in it -- a room "
              "name echoed into the app's own socket URL is data flow, not endpoint control.",
       wstg="WSTG-CLNT-10", mitre="T1190",
       validated_on=["domsource"]),

    _t(id="ajax_header_manipulation", vuln_class="client_side", cwe="CWE-113",
       owasp="A03:2021", permission=ACTIVE, transferable=True,
       summary="Client-side code puts attacker-controlled data into an outbound request header.",
       detect="Runtime hooks on XMLHttpRequest.setRequestHeader and fetch() init headers.",
       exploit="Introduce or control a header the application never intended to send.",
       oracle="The canary is in the NAME or VALUE of a header THE PAGE set. Browser-set headers are "
              "excluded: the browser puts the full probe URL, canary included, in Referer on every "
              "sub-resource request, so an unfiltered test fires on any page that loads one image.",
       wstg="WSTG-CLNT-10", mitre="T1190",
       validated_on=["domsource"]),

    _t(id="csp_allows_untrusted_script", vuln_class="misconfiguration", cwe="CWE-693",
       owasp="A05:2021", permission=PASSIVE, transferable=True,
       summary="The Content-Security-Policy permits untrusted script execution.",
       detect="Parse the enforced policy's script-src, accounting for default-src inheritance.",
       exploit="Any injection point becomes script execution; the policy stops nothing.",
       oracle="script-src (or the default-src it inherits) allows unsafe-inline with NO nonce and "
              "NO hash -- either would neutralise it -- and the policy is enforced, not Report-Only.",
       wstg="WSTG-CONF-12", mitre="T1189",
       validated_on=["domsource"]),

    _t(id="jwt_signature_not_verified", vuln_class="broken_auth", cwe="CWE-347",
       owasp="A07:2021", permission=ACTIVE, transferable=True,
       summary="The application honours a JWT whose signature it never verified.",
       detect="Three controls -- authenticated, unauthenticated, signature-tampered -- then compare.",
       exploit="Rewrite any claim (subject, role, expiry) and reattach the original signature.",
       oracle="A signature-tampered token is honoured where a no-token request is REFUSED. Without "
              "that discrimination the verdict is not_tested, never 'not vulnerable'.",
       wstg="WSTG-SESS-10", mitre="T1550",
       validated_on=["domsource"]),

    _t(id="python_code_injection", vuln_class="injection", cwe="CWE-94", owasp="A03:2021",
       permission=ACTIVE, transferable=True,
       summary="A parameter is evaluated as server-side Python.",
       detect="A probe carrying two independently-derived tokens: a random-operand arithmetic "
              "product, and a language-exclusive construct in the same payload.",
       exploit="Evaluate attacker code in the application's process.",
       oracle="BOTH tokens appear in the response and neither is a subsequence of the payload, so "
              "no echo -- and no punctuation-stripping sanitizer over an echo -- can produce them. "
              "Arithmetic alone proves evaluation but not WHICH language, and is reported as "
              "unidentified_code_injection with no language named.",
       wstg="WSTG-INPV-11", mitre="T1059",
       validated_on=["domsource"]),

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
    # WAHH ch7 / WSTG-SESS-06,-07,-11 — the MIRROR of session fixation. Fixation asks whether the id is
    # regenerated when a session is CREATED; this asks whether it is destroyed when the session ENDS.
    # Non-destructive by construction: the only session it ever ends is one it minted itself through the
    # target's own signup, and `tools._session_kill_is_safe` re-checks that as a fact before acting.
    _t(id="session_lifecycle", vuln_class="session", cwe="CWE-613", owasp="A07:2021", wstg="WSTG-SESS-06",
       permission=ACTIVE, transferable=True, validated_on=["sessionlife"],
       maps_to={"sessionlife": ["logout does not invalidate", "session survives password change",
                                "declared Max-Age not enforced"]},
       summary="A session that is supposed to have ended still works — logout, credential rotation and the "
               "server's own declared expiry are enforced on the client only.",
       detect="Mint a sacrificial account through the target's signup, capture cookie C, and find an endpoint "
              "that PROVABLY discriminates: C reaches an authenticated view there AND a freshly invented "
              "cookie of the same name is rejected. Then end the session three ways — the app's own logout, "
              "a password change made from a second session, and waiting out the declared Max-Age.",
       exploit="Replay a token captured from a log, proxy, backup or shared browser after the user believes "
               "they signed out; revoking access becomes impossible without changing the credential — and "
               "where the change-password variant also confirms, not even that evicts the holder.",
       oracle="C still returns the authenticated view after the app was OBSERVED to process the state change "
              "(cleared Set-Cookie / redirect / proven credential rotation), while the invented cookie is "
              "still rejected at that same endpoint on the post-change re-check."),
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
       oracle="An anonymous session receives directory ENTRIES (person/OU/group objects) from the naming context.",
       validated_on=["openldap"]),
    # beyond web (AD/file-server pentest): SMB null-session share enumeration.
    _t(id="smb_null_session", vuln_class="network_service", cwe="CWE-306", owasp="A01:2021", wstg="WSTG-ATHN-01",
       permission=ACTIVE, transferable=True,
       summary="An SMB server lets an unauthenticated (null) session enumerate its shares.",
       detect="Connect with an EMPTY username/password (null session) and call listShares; a hardened server "
              "refuses the anonymous session and returns nothing.",
       exploit="Map the file-server layout pre-auth and read any guest-exposed non-administrative share.",
       oracle="A null session connects and listShares returns a share (a non-admin share escalates to high).",
       validated_on=["smb"]),
    # beyond web (AD relay): SMB message signing not required -> NTLM relay.
    _t(id="smb_signing_disabled", vuln_class="network_service", cwe="CWE-347", owasp="A02:2021", wstg="WSTG-CONF-11",
       permission=ACTIVE, transferable=True,
       summary="An SMB server does not require message signing, so authenticated sessions can be relayed/tampered.",
       detect="Read the server SecurityMode from an SMB2 NEGOTIATE response (no auth); SIGNING_REQUIRED (0x0002) "
              "is not set.",
       exploit="Coerce/capture an authentication and NTLM-relay it to this host to act as the victim.",
       oracle="The SMB2 NEGOTIATE SecurityMode lacks the SIGNING_REQUIRED flag.",
       validated_on=["smb"]),
    # beyond web (ICS/OT pentest): unauthenticated Modbus/TCP device exposure. READ-ONLY — never writes to OT.
    _t(id="modbus_exposed", vuln_class="ics_ot", cwe="CWE-306", owasp="A05:2021", wstg="WSTG-CONF-01",
       permission=ACTIVE, transferable=True,
       summary="An unauthenticated Modbus/TCP (OT) device is reachable on the network.",
       detect="Send a READ-ONLY Modbus request (device-identification 0x2B/0x0E or read-holding-register 0x03); a "
              "well-formed response echoing the transaction id + protocol 0 proves a live, unauthenticated device.",
       exploit="Read process/register data with no auth; an attacker who reaches TCP/502 could also WRITE to "
               "manipulate the physical process (out of scope for Apolaki — read-only, never writes to OT).",
       oracle="A Modbus response (0x2B/0x03 or its exception) matching our transaction id returns without auth.",
       validated_on=["conpot"]),
    # beyond web (ICS/OT): unauthenticated EtherNet/IP (CIP) controller.
    _t(id="enip_exposed", vuln_class="ics_ot", cwe="CWE-306", owasp="A05:2021", wstg="WSTG-CONF-01",
       permission=ACTIVE, transferable=True,
       summary="An unauthenticated EtherNet/IP (CIP) industrial controller is reachable on the network.",
       detect="A single ListIdentity request (encapsulation command 0x0063) over UDP and then TCP 44818. "
              "Both transports are tried: UDP is the discovery path, but explicit messaging is TCP, and a "
              "controller that answers only on TCP would otherwise be reported as absent.",
       exploit="None. This engine builds ONLY ListIdentity — no CIP write, no ForwardOpen, no "
               "SendRRData carrying a Set_Attribute. A CIP write to a live PLC can move an actuator, so "
               "writes are categorically absent from the code rather than merely gated.",
       oracle="an encapsulation response echoing command 0x0063 with status 0 and a well-formed Identity "
              "item (type 0x000C) disclosing vendor / product / serial / revision",
       validated_on=["conpot"]),
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
       oracle="The BMC returns an RMCP+ Open Session Response (payload type 0x11).",
       validated_on=["conpot"]),
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
       oracle="A GET with a default community returns a GetResponse (error-status 0) with a sysDescr value.",
       # Two unrelated implementations — an ICS stack and a stock Net-SNMP agent — which is the bar for
       # calling the technique transferable rather than shaped to one lab's quirks.
       validated_on=["conpot", "snmpd"]),

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
       # WSTG-CONF-13 "Path Confusion" (the catalog already maps CONF-13 -> run_cache_deception). The old
       # WSTG-ATHZ-05 was OAuth Weaknesses — a taxonomy drift that showed the technique (unmapped) at runtime (#12).
       permission=ACTIVE, transferable=True, wstg="WSTG-CONF-13",
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
       oracle="A live date appears between our two random markers where the literal directive was injected.",
       # EARNED by a liveness run against domsource /ssi, not asserted by hand. 1333 field
       # dispatches had never produced one result, which proved nothing until the lab had the bug.
       validated_on=["domsource"]),

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

    _t(id="browser_persona_bola", vuln_class="access_control", cwe="CWE-639", owasp="API1:2023",
       permission=ACTIVE, transferable=True, wstg="WSTG-ATHZ-04",
       summary="Runtime persona-swap BOLA: prove cross-user object access inside two real browser sessions.",
       detect="A single-page app that fetches per-user objects after JavaScript runs — the object request "
              "the application itself makes, captured at the wire by raw CDP (bie.observe), not guessed "
              "from static HTML.",
       exploit="Give each of two same-privilege personas its own browser context (separate cookie jar, "
               "storage and session, seeded from the app's OWN login response), let each app boot for "
               "real, then replay the owner's runtime request from inside the attacker's page changing "
               "ONLY the object id. Read-only: GETs only, no writes, no id-spraying.",
       oracle="bie.judge — the attacker's browser receives the owner's object byte-for-byte (200) while "
              "THREE negative controls do not: anonymous (proves it is not public), an implausible id "
              "(proves the route is object-specific, not an SPA shell), and the attacker's own object "
              "(proves the objects are distinguishable). A missing control yields a lead, never a confirm.",
       validated_on=["juiceshop"],
       maps_to={"juiceshop": ["View Basket"]}),

    # ── GraphQL (#125, Black Hat GraphQL). The TOOL existed and was planner-reachable; what was missing
    # was registry presence (so it never appeared in coverage or the no-island accounting) and the
    # argument extraction that lets the existing injection engines reach a GraphQL sink at all.
    _t(id="header_trust_authz", vuln_class="access_control", cwe="CWE-807", owasp="A01:2021",
       permission=ACTIVE, transferable=True, wstg="WSTG-ATHZ-02",
       summary="Authorization decided by a client-controlled header (Referer, X-Forwarded-For, X-Real-IP).",
       detect="Send the request without the header, with a plausible value, and with an implausible value "
              "(header_trust_tool). Safe GETs only.",
       exploit="None beyond setting a header the client already controls — that is the point: if the "
               "decision turns on it, anyone can make the decision.",
       oracle="Either a status change (denied without, 200 with, denied again on an implausible value) or, "
              "on uniform-200 targets, a body differential: the two refusals match each other while the "
              "valid value yields a materially different page. The stability requirement doubles as the "
              "FP guard — a dynamic page fails it and the oracle declines.",
       # Q-164: the badge said "natas". Nothing re-ran it: no liveness CHECK, no recorded reply, and
       # natas is an OverTheWire target on the public internet that this bench is not authorized to
       # touch, so nothing here ever could. `known_labs()` never resolved the id either. The claim is
       # withdrawn rather than left standing -- `run_header_trust` is real and the technique is sound;
       # what was never evidence is the string. maps_to keeps the provenance of where it was first seen.
       validated_on=[],
       maps_to={"natas": ["Level 4 (Referer-gated access)"]}),
    _t(id="url_override_acl_bypass", vuln_class="access_control", cwe="CWE-807", owasp="A01:2021",
       permission=ACTIVE, transferable=True, wstg="WSTG-ATHZ-02",
       summary="Front-end ACL bypassed by naming the denied path in X-Original-URL / X-Rewrite-URL.",
       detect="Request the denied path directly, request a permitted path, then request the permitted path "
              "while naming the denied one in the override header.",
       exploit="A single GET carrying the header; nothing is written.",
       oracle="The denied path is served via the header AND the response differs from the permitted page — "
              "without that content control a server that IGNORES the header looks identical to one that "
              "honours it, which is the trap in this class.",
       validated_on=[]),

    _t(id="graphql_introspection", vuln_class="sensitive_exposure", cwe="CWE-200", owasp="A01:2021",
       permission=ACTIVE, transferable=True, wstg="WSTG-CONF-05",
       summary="GraphQL introspection enabled: the full schema, and therefore the whole API surface, is public.",
       detect="The standard __schema introspection query returns a parseable schema (graphql_tool).",
       exploit="None needed — the disclosure IS the finding. Its larger value is as surface expansion: "
               "every operation and argument becomes testable input for the other engines.",
       oracle="a parseable __schema with a query type and at least one root operation came back",
       validated_on=["dvga"]),
    _t(id="graphql_field_suggestions", vuln_class="sensitive_exposure", cwe="CWE-200", owasp="A01:2021",
       permission=ACTIVE, transferable=True, wstg="WSTG-CONF-05",
       summary="Schema still discoverable via 'Did you mean' field suggestions when introspection is off.",
       detect="A deliberately bogus field triggers an error naming real fields (graphql_tool).",
       exploit="Recovered names are dictionary-driven guesses, so they enter the graph as UNVERIFIED "
               "candidates, never as confirmed surface.",
       oracle="an error message for an unknown field names real schema fields",
       validated_on=[]),
    _t(id="graphql_batching_enabled", vuln_class="misconfiguration", cwe="CWE-770", owasp="A05:2021",
       permission=ACTIVE, transferable=True,
       summary="Array batching permitted: one request can carry many operations.",
       detect="A small JSON-array batch is answered with an array of results (graphql_tool).",
       exploit="POSTURE ONLY. Batching is a documented rate-limit and brute-force amplifier, and Apolaki "
               "does NOT use it that way — the no-brute rail stands. A token-sized batch establishes that "
               "the control is absent; no credential attempts are made through it.",
       oracle="an N-item batch returned N results; N is small by construction",
       validated_on=["dvga"]),
    _t(id="graphql_argument_injection", vuln_class="injection", cwe="CWE-74", owasp="A03:2021",
       permission=ACTIVE, transferable=True, wstg="WSTG-INPV-01",
       summary="GraphQL query/mutation arguments as injection entry points for the existing engines.",
       detect="Introspection enumerates every operation and its arguments; those arguments are sinks the "
              "query-string and form-field probes cannot see.",
       exploit="The existing injection engines supply the payload; graphql_tool.build_query carries it. "
               "The value is JSON-encoded so a payload can never restructure the document into a "
               "different — possibly far heavier — query.",
       oracle="the injecting engine's own oracle, unchanged; only the transport differs",
       validated_on=["dvga"]),

    # ── runtime DOM source→sink families (dom_trace) + encoded-parameter injection ──────────────
    # These four ENGINES were already shipping confirmed findings and the blind benchmark was already
    # counting them as true positives, but none of them had a registry record: no taxonomy entry, no
    # coverage credit, no planner reachability, no remediation mapping. Same gap enip_exposed had.
    _t(id="request_url_override", vuln_class="client_side", cwe="CWE-441", owasp="A10:2021",
       permission=ACTIVE, transferable=True, wstg="WSTG-CLNT-06",
       summary="The page builds a request TARGET from a client-side source instead of a constant.",
       detect="Two complementary views. dom_trace injects a canary into a client-side source and renders "
              "the page; client_request_source reads the script statically for a request whose target "
              "expression resolves to a DOM attribute or the URL. The static view exists because a "
              "server-rendered attribute that no parameter controls offers nothing to inject into, so a "
              "render alone would report the class absent.",
       exploit="None is fired. Safe methods only; the runtime probe points the source at a sink host and "
               "observes where the page's own fetch/XHR goes.",
       oracle="RUNTIME: a script-initiated fetch/XHR reaches the probe host, distinguished from a "
              "navigation (which is open_redirect). STATIC: the target expression is demonstrably not a "
              "constant — reported as a LEAD, never confirmed, because reachability of the DOM node is "
              "not proven by reading the code.",
       validated_on=["domsource"]),
    _t(id="dom_link_manipulation", vuln_class="client_side", cwe="CWE-79", owasp="A03:2021",
       permission=ACTIVE, transferable=True, wstg="WSTG-CLNT-06",
       summary="A client-side source controls a link or resource URL the page requests or a victim clicks.",
       detect="Inject a per-request canary into a client-side source (query parameter or URL fragment) "
              "and render the page in a real browser.",
       exploit="None. The canary is inert; only its arrival at the sink is observed.",
       oracle="the canary appears in an href/src/action attribute in the RENDERED DOM at runtime — a "
              "static match in the response body is not accepted.",
       validated_on=["domsource"]),
    _t(id="dom_data_manipulation", vuln_class="client_side", cwe="CWE-79", owasp="A03:2021",
       permission=ACTIVE, transferable=True,
       summary="A client-side source controls rendered DOM content or attributes (UI redress, spoofing).",
       detect="Same runtime canary as dom_link_manipulation, observed at a content/attribute sink rather "
              "than a URL sink.",
       exploit="None. Where the same sink also EXECUTES, the finding is raised as dom_xss instead; a sink "
               "that renders text but cannot execute stays this class.",
       oracle="the canary reaches rendered DOM content or a non-value attribute at runtime.",
       validated_on=["domsource"]),
    _t(id="base64_param", vuln_class="injection", cwe="CWE-20", owasp="A03:2021",
       permission=ACTIVE, transferable=True,
       summary="An encoded parameter or cookie carries an inner structure that reaches an injection sink.",
       detect="Decode base64/JSON-shaped parameter and cookie values, then re-encode a probe into the "
              "INNER field — the outer encoding is what hides the sink from an ordinary parameter sweep.",
       exploit="The existing injection engines supply the payload; only the transport differs.",
       oracle="the injecting engine's own oracle, unchanged, on the decoded inner field.",
       validated_on=["ginandjuice"]),

    _t(id="dnp3_exposed", vuln_class="ics_ot", cwe="CWE-306", owasp="A07:2021",
       permission=ACTIVE, transferable=True,
       summary="Unauthenticated DNP3 outstation reachable (ICS/OT).",
       detect="A single link-layer Request Link Status frame — no application layer is ever sent, so there "
              "is no point or object the probe could operate on.",
       exploit="None. DNP3 has no authentication, so reachability IS the exposure. Apolaki cannot "
               "construct a control frame: the safety rail is strict-by-default and a unit test asserts "
               "no builder in the engine produces a frame it accepts.",
       oracle="the outstation returns a well-formed DNP3 link frame (CRC-verified) to the read-only request",
       # EARNED 2026-08-09, having deliberately stayed empty until it was. Conpot speaks Modbus /
       # S7comm / EtherNet-IP / SNMP / IPMI but has NO DNP3 listener, so claiming this on the strength of
       # the lab that validated its neighbours would have been borrowing their credibility.
       # Open Energy Solutions' OpenFMB Adapter (opendnp3) now supplies a real outstation: probe_dnp3
       # parses its link-status reply with crc_ok=True — a CRC produced by THEIR encoder and verified by
       # ours, which is the property a self-built simulator could never provide — and _run_service_pack
       # confirms it end to end. A liveness CHECK re-runs that on every gate, so the claim expires the
       # moment it stops being true.
       validated_on=["openfmb"]),
    _t(id="s7comm_exposed", vuln_class="ics_ot", cwe="CWE-306", owasp="A07:2021",
       permission=ACTIVE, transferable=True,
       summary="Unauthenticated Siemens S7 PLC reachable (ICS/OT).",
       detect="ISO-on-TCP handshake, S7 setup communication, then a read of SZL 0x0011 (module "
              "identification) and, when that discloses nothing, SZL 0x001C (component identification). "
              "Both are vendor-documented System Status Lists and neither touches the process image — a "
              "real PLC answered 0x0011 with an empty payload and 0x001C with its full identity.",
       exploit="None. Write Var, PLC Stop, PLC Control and the download/upload jobs are catalogued only so "
               "the safety rail can REFUSE them; they are never built.",
       oracle="the PLC returns its module or component identification to an unauthenticated caller",
       validated_on=["conpot"]),

    # ── transport + web posture family (#103, distilled from WAHH ch.12/13) ──────────────────────────
    _t(id="tls_posture", vuln_class="crypto_transport", cwe="CWE-327", owasp="A02:2021",
       permission=ACTIVE, transferable=True, wstg="WSTG-CRYP-01",
       summary="TLS transport posture: deprecated protocol versions accepted, weak cipher, or a bad certificate.",
       detect="Read-only TLS handshakes against the origin, one pinned to each protocol version, plus the "
              "certificate the server actually presents.",
       exploit="None — this is an observation, not an attack. Apolaki never attempts a downgrade or a "
               "padding-oracle; it records what the server agrees to.",
       oracle="A version is reported supported only when a handshake PINNED to it completes; a version "
              "this client cannot speak is reported unknown, never 'absent'. A probe where every pinned "
              "version succeeds is treated as non-discriminating and reports nothing. Certificate defects "
              "are read from the presented certificate against the hostname requested and the clock.",
       validated_on=[]),
    _t(id="cookie_scope_posture", vuln_class="session", cwe="CWE-614", owasp="A05:2021",
       permission=PASSIVE, transferable=True, wstg="WSTG-SESS-02",
       summary="Session cookie missing Secure / HttpOnly / a restrictive SameSite.",
       detect="The Set-Cookie headers the server sends, parsed directly.",
       exploit="None needed — the attribute is present or it is not.",
       oracle="Directly observed in Set-Cookie. Scoped to SESSION cookies only, so a preference cookie "
              "without HttpOnly is never reported; Secure is not demanded on a plaintext origin.",
       validated_on=[]),
    _t(id="http_security_headers", vuln_class="misconfiguration", cwe="CWE-693", owasp="A05:2021",
       permission=PASSIVE, transferable=True, wstg="WSTG-CONF-12",
       summary="Missing protective response headers (framing control, HSTS, CSP, sniffing, referrer).",
       detect="Response headers, read directly.",
       exploit="None — defence-in-depth posture.",
       oracle="Present or absent in the response. Graded honestly: framing/HSTS are real weaknesses, "
              "hygiene headers are reported at info; clickjacking is only flagged when BOTH "
              "X-Frame-Options and a CSP frame-ancestors directive are absent.",
       validated_on=[]),
    _t(id="http_methods_audit", vuln_class="misconfiguration", cwe="CWE-650", owasp="A05:2021",
       permission=ACTIVE, transferable=True, wstg="WSTG-CONF-06",
       summary="Dangerous HTTP methods advertised, and TRACE (Cross-Site Tracing) confirmed.",
       detect="The Allow header from OPTIONS, plus a single TRACE carrying a random marker.",
       exploit="TRACE only. Write methods (PUT/DELETE/WebDAV) are NEVER sent — they are reported as an "
               "untested lead from the Allow header.",
       oracle="TRACE is confirmed only when the response echoes the exact random marker sent, which "
              "nothing else can produce; advertised methods stay a lead.",
       validated_on=[]),

    _t(id="client_supplied_identity_param", vuln_class="access_control", cwe="CWE-639", owasp="API1:2023",
       permission=ACTIVE, transferable=True, wstg="WSTG-ATHZ-04",
       summary="Server derives identity from a client-supplied parameter — proven by mutating the app's own request.",
       detect="Two personas' browsers send the SAME endpoint with DIFFERENT values for an identity-bearing "
              "query parameter. That difference is observed evidence the parameter is identity-scoped, not "
              "an inference from its name.",
       exploit="Intercept the owner's genuine outgoing request with Playwright route interception and "
               "rewrite ONLY that one value to the other persona's, before it leaves the browser. Safe "
               "methods only; the evidence records honestly whether the app re-issued the request "
               "(route-interception) or the mutated request had to be issued in-page.",
       oracle="bie.judge_param_swap — the response becomes the OTHER persona's baseline byte-for-byte. The "
              "secure behaviour (server ignores the parameter and answers about the session's own user) has "
              "a distinct signature and is explicitly rejected, as are public content and personas whose "
              "views are already identical.",
       validated_on=["clientauthz"],
       maps_to={}),

    _t(id="client_side_authz", vuln_class="access_control", cwe="CWE-602", owasp="A01:2021",
       permission=ACTIVE, transferable=True, wstg="WSTG-ATHZ-02",
       summary="Access control enforced only in the browser: the UI withholds a control the server still serves.",
       detect="Enumerate the RENDERED control surface per persona and split what the interface offers from "
              "what it withholds (Selenium's visibility contract: not displayed, zero-size, or disabled). "
              "A framework that removes the control from the DOM entirely yields nothing here — that case "
              "belongs to the JS-bundle route harvest, and this engine reports zero rather than guessing.",
       exploit="Request the withheld control's target with a SAFE GET as the same persona. Client-side-only "
               "routes and anything requiring a state-changing submit are never auto-fired — they become "
               "operator leads.",
       oracle="bie.judge_client_side_authz — the server returns a substantive body for a control the UI "
              "withheld, and that body is neither the SPA shell (unknown-path control) nor public content "
              "(anonymous control).",
       validated_on=["clientauthz"],
       maps_to={}),

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
       oracle="Server persists the injected attribute (readback shows elevated state).",
       # Q-011 liveness proof, not a hand-typed guess: `agent/liveness.py`'s `mass_assignment` check
       # drives the shipped `run_mass_assign` engine against VAmPI's `/users/v1/register` and gets a
       # CONFIRMED `admin` binding, baseline + ignored-field controls both run
       # (`liveness_baseline.json` ratcheted 18 -> 19). This is the ONE claim in this file the
       # liveness ledger can re-earn on every run rather than a backfill nobody re-checks.
       validated_on=["vampi"]),

    _t(id="unrestricted_file_upload", vuln_class="upload", cwe="CWE-434", owasp="A04:2021",
       permission=ACTIVE, transferable=True,
       summary="Unrestricted file upload — server-side type/content-type/size restriction bypass.",
       detect="A file-upload form/endpoint accepts files without enforcing the claimed type/size server-side.",
       exploit="Upload a non-allowlisted type or an oversize file via extension / Content-Type / poison-null-"
               "byte tricks (non-destructive canary payloads only); a dangerous type reaching a served path "
               "is web-shell-capable.",
       oracle="Server accepts + stores a file whose type/size the app claims to forbid (readback confirms).",
       validated_on=["juiceshop"],
       maps_to={"juiceshop": ["Upload Type", "Upload Size"]}),

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
       # Q-164 CORRECTED: the badge read ["juiceshop"] and the only thing that re-runs this technique
       # is the liveness CHECK against `domsource` (http://domsource:8080/hash). Nothing has ever
       # re-run dom_xss against Juice Shop. The technique IS proven -- on the lab now named. A badge
       # that names the wrong lab is not a smaller lie than one that names no lab: it survives every
       # technique-granular gate, because the id is genuinely liveness-confirmed.
       validated_on=["domsource"],
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
    _t(id="saml_signature_bypass", vuln_class="broken_auth", cwe="CWE-347", owasp="A07:2021",
       permission=INTRUSIVE, transferable=True,
       summary="SAML SSO assertion forgery: signature exclusion / stripping / XML signature wrapping (XSW).",
       detect="A SAMLResponse whose Assertion is unsigned, or Response-signed-but-Assertion-unsigned (saml_tool "
              "analyzes the captured SAMLResponse's signing posture).",
       exploit="Replay a tampered assertion (remove the signature, or wrap a forged unsigned assertion before the "
               "signed original) to the SP's ACS — NEVER forges a signature or cracks a key.",
       oracle="The SP issues an authenticated session for the TAMPERED assertion while the baseline flow also "
              "authenticated — zero-FP; a rejected tamper claims nothing.",
       needs_fixture=["captured_samlresponse"], fixture_source="harvest"),

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
       # Q-164 WITHDRAWN. engine_descriptor.build() binds NO engine to this id (routable=False,
       # engines=[]) and tools.py has no `_run_*` for the class, so no run by the PRODUCT could have
       # produced the confirmation this badge claimed -- what fired on the board was juiceshop_solvers.
       # Same shape as weak_password_reset in this module's own docstring.
       validated_on=[],
       maps_to={"juiceshop": ["Error Handling"]}),

    _t(id="vulnerable_component", vuln_class="vuln_component", cwe="CWE-1035", owasp="A06:2021",
       permission=PASSIVE, transferable=True,
       summary="Known-vulnerable dependency (SCA), reported advisory-grade until reachability is shown.",
       detect="Exact version -> CVE mapping (dependency_intel), severity capped pending reachability.",
       exploit="Advisory lead; escalated only if a reachable sink is confirmed.",
       oracle="Version-pinned CVE match; NOT a confirmed exploit unless reachability proven.",
       # Q-164 WITHDRAWN (both labs). No engine is bound to this id and no `_run_*` implements the
       # class. `run_js_review` / dependency_intel.py DO surface outdated libraries, so a producer may
       # exist that the descriptor does not join -- that is why this is a withdrawal, not a deletion of
       # the technique: re-add a lab here the moment a check re-runs it end to end.
       validated_on=[],
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
       validated_on=[],          # Q-164 WITHDRAWN: no engine bound, no `_run_*`; the solver proved it, not us
       maps_to={"juiceshop": ["Imaginary Challenge", "Forged Coupon"]}),

    _t(id="weak_2fa_bypass", vuln_class="broken_auth", cwe="CWE-308", owasp="A07:2021",
       permission=ACTIVE, transferable=True,
       summary="Defeat 2FA using a leaked/guessable TOTP seed or a skippable second-factor step.",
       detect="TOTP seed exposed in storage/source, or a 2FA step that can be bypassed.",
       exploit="Compute the current TOTP from the seed (HMAC-SHA1) and complete the second factor.",
       oracle="The second-factor step accepts the computed code and issues a full session.",
       needs_fixture=["totp_seed"], fixture_source="harvest",
       validated_on=[],          # Q-164 WITHDRAWN: no engine bound, no `_run_*`; the solver proved it, not us
       maps_to={"juiceshop": ["Two Factor Authentication"]}),

    _t(id="business_logic_abuse", vuln_class="business_logic", cwe="CWE-840", owasp="A04:2021",
       permission=ACTIVE, transferable=True,
       summary="Abuse an application-flow assumption (price/quantity/state/time) for unintended value.",
       detect="A workflow trusts a client-controlled quantity, price, coupon, or step ordering.",
       exploit="Submit out-of-policy values: negative quantity, unpaid upgrade, expired/greedy coupon.",
       oracle="The transaction completes in a state the business policy should have forbidden.",
       validated_on=[],          # Q-164 WITHDRAWN: no engine bound, no `_run_*`; the solver proved it, not us
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
       validated_on=[],          # Q-164 WITHDRAWN: no engine bound, no `_run_*`; the solver proved it, not us
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


def is_generalized(t: dict) -> bool:
    """>= 2 RESOLVABLE labs. A lab id that names no target cannot contribute to transferability:
    two invented strings used to confer `generalized` (and +8 confidence in technique_model), which
    is how a fabricated claim scored 90/100 in the `high` tier. See known_labs()."""
    legal = known_labs()
    return len({l for l in (t.get("validated_on") or []) if l in legal}) >= GENERALIZED_MIN_LABS


def generalized() -> list[str]:
    """Techniques whose transferability is EARNED: >= 2 resolvable labs AND a liveness artifact.

    Requiring the artifact is the Q-012 discipline applied to transferability. Without it this
    returned csti and vulnerable_component on the strength of typed strings alone; neither has ever
    been re-confirmed by a run, so neither was general capability in any sense a reader would expect."""
    return [t["id"] for t in TECHNIQUES.values()
            if is_generalized(t) and validation_record(t)["status"] == VALIDATION_RECORDED]


def all_labs() -> list[str]:
    """THE legal lab vocabulary.

    This used to build the answer by unioning `validated_on` across the registry -- so the set of
    valid labs was DEFINED as the set of labs somebody had typed, and the question "is this a real
    lab?" answered "yes, because you spelled it". That circularity is the root vacuity behind every
    other symptom in this file. The vocabulary is now derived (known_labs); `maps_to` keys are still
    unioned in because targeting a lab is a different claim from being validated on one, but they
    are filtered through the same vocabulary so a name that resolves to nothing cannot enter here."""
    legal = known_labs()
    targets = {lab for t in TECHNIQUES.values() for lab in (t.get("maps_to") or {})}
    return sorted(legal | (targets & legal))


def coverage_matrix(lab_ids: list[str] | None = None) -> dict:
    """
    Registry-only coverage view (no network). For each technique, which labs it TARGETS
    (maps_to) and which it is VALIDATED on (oracle-confirmed). Summarizes the two honest
    numbers: transferable-capability count vs generalized (>=2 lab) count.
    """
    labs = lab_ids or all_labs()
    rows, lab_local_rows = [], []
    for t in TECHNIQUES.values():
        maps = t.get("maps_to") or {}
        validated = set(t.get("validated_on", []))
        # LAB TRIVIA IS NOT CAPABILITY, and `rows` is the capability view. find_hidden_route is declared
        # transferable=False precisely because solving a scoreboard challenge is not a real-world method,
        # yet it sat in these rows anyway — the test meant to catch that filtered with `if False`, so the
        # leak survived behind a guard that had never checked anything. Kept, separately, under
        # lab_local_rows so nothing is lost and the count in lab_local_total stays reconcilable.
        (rows if t["transferable"] else lab_local_rows).append({
            "id": t["id"], "vuln_class": t["vuln_class"], "transferable": t["transferable"],
            "execution": t.get("execution", "auto"),
            "targets": {lab: maps.get(lab, []) for lab in labs if lab in maps},
            "validated_on": sorted(validated & set(labs)) if lab_ids else sorted(validated),
            # transferability counts RESOLVABLE labs only -- an id naming no target is not a data
            # point about transferring, it is a typo or a claim about a lab that was never stood up.
            "transferability_score": len(validation_record(t)["labs"]),
            "generalized": is_generalized(t),
            "validation": validation_record(t),
        })
    total = len(TECHNIQUES)
    return {
        "labs": labs,
        "techniques_total": total,
        "transferable_total": sum(1 for t in TECHNIQUES.values() if t["transferable"]),
        "generalized_total": len(generalized()),
        "lab_local_total": sum(1 for t in TECHNIQUES.values() if not t["transferable"]),
        "rows": rows,                       # capability view: transferable techniques only
        "lab_local_rows": lab_local_rows,   # kept visible, never counted as capability
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
        if "juiceshop" not in _rec["backfill_claim"]:
            _rec["backfill_claim"] = _rec["backfill_claim"] + ["juiceshop"]
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
        if "dvwa" not in _rec["backfill_claim"]:
            _rec["backfill_claim"] = _rec["backfill_claim"] + ["dvwa"]
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
        if "bwapp" not in _rec["backfill_claim"]:
            _rec["backfill_claim"] = _rec["backfill_claim"] + ["bwapp"]
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
        if "mutillidae" not in _rec["backfill_claim"]:
            _rec["backfill_claim"] = _rec["backfill_claim"] + ["mutillidae"]
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
    # cache_deception -> Path Confusion. This `_WSTG` map is AUTHORITATIVE at runtime (line ~854 overwrites
    # each record's wstg from it), so the fix must live HERE — cache_deception was simply absent, which is
    # why the runtime showed it (unmapped) even though its _t() carried a wstg kwarg (#12).
    "cache_deception": "WSTG-CONF-13",
    # Mapped after auditing the remaining unmapped set against wstg_catalog's authoritative titles.
    "xpath_injection": "WSTG-INPV-09",              # XPath Injection
    "path_traversal": "WSTG-ATHZ-01",               # Directory Traversal File Include
    "archive_slip": "WSTG-BUSL-09",                 # Upload of Malicious Files (zip-slip arrives as one)
    "unrestricted_file_upload": "WSTG-BUSL-08",     # Upload of Unexpected File Types
    "find_hidden_route": "WSTG-CONF-04",            # Old Backup and Unreferenced Files
    "missing_authentication": "WSTG-ATHZ-02",       # Bypassing Authorization Schema
    "client_side_authz": "WSTG-ATHZ-02",            # Bypassing Authorization Schema
}

# Techniques with NO WSTG test, recorded as a DECISION rather than left looking like an oversight.
# WSTG v4.2 is a web-application testing guide: it has no tests for LLM behaviour, industrial protocols,
# or dependency inventory, and no dedicated test for prototype pollution, deserialization or SAML. A
# forced mapping is worse than an honest blank — it tells a reader a standard covers something it does
# not. Revisit when WSTG adds the coverage.
WSTG_DELIBERATELY_UNMAPPED = {
    "dom_data_manipulation": "PortSwigger taxonomy, not OWASP's: WSTG has no test for attacker-controlled "
                             "rendered CONTENT that cannot execute (CLNT-01 is DOM XSS, CLNT-03 is HTML "
                             "injection); mapping it to either would overstate what the standard covers",
    "base64_param": "the TRANSPORT, not the defect - the inner injection carries the WSTG mapping",
    "llm_prompt_injection": "WSTG v4.2 predates LLM testing",
    "llm_output_handling": "WSTG v4.2 predates LLM testing",
    "dnp3_exposed": "WSTG is web-only; ICS/OT is out of its scope",
    "s7comm_exposed": "WSTG is web-only; ICS/OT is out of its scope",
    "modbus_exposed": "WSTG is web-only; ICS/OT is out of its scope",
    "waf_bypass": "an evasion amplifier applied to other tests, not a test of its own",
    "prototype_pollution": "no dedicated WSTG v4.2 test",
    "insecure_deser": "no dedicated WSTG v4.2 test (covered by ASVS instead)",
    "vulnerable_component": "no dedicated WSTG v4.2 test (dependency inventory, not a test case)",
    "saml_signature_bypass": "WSTG-ATHZ-05 covers OAuth, not SAML assertion handling",
    "exposed_credentials": "credential exposure spans several WSTG tests; none is a clean fit",
    "soft_deleted_login": "no dedicated WSTG v4.2 test",
    "graphql_batching_enabled": "WSTG v4.2 has no GraphQL-specific tests; batching is a rate-limit "
                                "control gap with no clean WSTG home",
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
    # The `_WSTG` map stays AUTHORITATIVE where it has an entry, but it must not DELETE a mapping a
    # technique declared inline: the old `= _WSTG.get(_tid)` clobbered every `_t(wstg=...)` kwarg to None
    # for any id absent from the map, so techniques that correctly declared their WSTG test silently
    # reported "unmapped". Fall back to the record's own value instead of destroying it.
    _rec["wstg"] = _WSTG.get(_tid) or _rec.get("wstg")
    _rec["mitre"] = _MITRE.get(_tid) or _rec.get("mitre")
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
            "status": technique_status(t),
            # what the claim is actually worth: recorded / not_recorded / not_applicable, plus any
            # lab id that resolves to no target at all (reported, never silently dropped).
            "validation": validation_record(t),
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
        # THE HEADLINE NUMBER. ui/index.html renders this as a green "Proven" stat, so it must count
        # only what a liveness run actually confirmed — not what a hand-written backfill dict asserted.
        # `claimed` keeps the old number visible rather than hiding the gap: the distance between the two
        # IS the honesty debt, and burying it would repeat the mistake.
        "proven": sum(1 for t in TECHNIQUES.values() if technique_status(t) == "proven"),
        "unverified": sum(1 for t in TECHNIQUES.values() if technique_status(t) == "unverified"),
        "solver_only": sum(1 for t in TECHNIQUES.values() if technique_status(t) == "solver_only"),
        "claimed": sum(1 for t in TECHNIQUES.values() if t.get("validated_on")),
        "transferable": sum(1 for t in TECHNIQUES.values() if t["transferable"]),
        "generalized": len(generalized()),
        # The three-way honesty split (Q-012 vocabulary). `not_recorded` is the number that must not
        # be allowed to hide inside `catalogued`: those techniques CLAIM a validation and no run has
        # ever produced the artifact. `unresolved_labs` names ids that point at no target at all.
        "recorded": sum(1 for t in TECHNIQUES.values()
                        if validation_record(t)["status"] == VALIDATION_RECORDED),
        "not_recorded": sum(1 for t in TECHNIQUES.values()
                            if validation_record(t)["status"] == VALIDATION_NOT_RECORDED),
        "unresolved_labs": sorted({l for t in TECHNIQUES.values()
                                   for l in validation_record(t)["unresolved"]}),
    }


# ── what the UI is allowed to call "proven" ──────────────────────────────────────────────────
def _liveness_verified() -> set:
    """Technique ids an end-to-end liveness run has actually confirmed. Empty on any error, which
    deliberately degrades every claim to 'unverified' rather than silently back to 'proven'."""
    import json
    import os
    try:
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tests", "liveness_baseline.json")
        with open(p, encoding="utf8") as fh:
            return set(json.load(fh).get("live") or [])
    except Exception:
        return set()


# ── the lab vocabulary, DERIVED ──────────────────────────────────────────────────────────────
# A hand-maintained allowlist of lab names would be the same defect one level up: a second typed
# field, guarding the first. So the legal set is derived from artifacts that MUST already exist for
# a lab to be real, and each source is independent of `validated_on`:
#
#   (a) a target registry names it  -- benchmark.MANIFESTS (to SCORE it), bench_all.LAB_URLS (to
#       REACH it), labs.LABS (to FINGERPRINT it). None of these exist for the benefit of this field.
#   (b) a liveness-confirmed technique claims it -- the technique was re-proven end to end by a RUN,
#       so whatever target it names demonstrably answered. This is the only source derived from
#       execution, and it is what legitimises real labs nobody wired into the benchmark registry
#       (openfmb, domsource) without legitimising labs that were never stood up (natas, sessionlife).
#
# To spell a new lab id you must therefore either make it scoreable/reachable or actually confirm a
# technique against it. Neither can be done by typing a string into this file.
def _registry_labs() -> set:
    ids = set()
    for mod, attr in (("benchmark", "MANIFESTS"), ("bench_all", "LAB_URLS"), ("labs", "LABS")):
        try:
            ids |= set(getattr(__import__(mod), attr, {}) or {})
        except Exception:
            continue          # a missing optional registry narrows the vocabulary, never widens it
    return ids


def _liveness_vouched_labs() -> set:
    out = set()
    for tid in _liveness_verified():
        rec = TECHNIQUES.get(tid)
        if rec:
            out |= set(rec.get("validated_on") or [])
    return out


def known_labs() -> set:
    """The lab ids a `validated_on` entry is allowed to name. Fails CLOSED: if every source errors
    the set is empty, which demotes every claim to unresolved rather than silently accepting all."""
    return _registry_labs() | _liveness_vouched_labs()


# ── what a claim is worth, three-valued ──────────────────────────────────────────────────────
# Mirrors proof_schema.control_status(): the third value is the point. A technique nothing has ever
# run must SAY so rather than carry a string somebody typed, exactly as Q-012 made a capability the
# product does not have report `not_implemented` instead of hiding inside `not_tested`.
VALIDATION_RECORDED = "recorded"              # a liveness RUN produced the artifact
VALIDATION_NOT_RECORDED = "not_recorded"      # claims labs, but no run has ever confirmed it
VALIDATION_NOT_APPLICABLE = "not_applicable"  # claims nothing -- catalogued, and honest about it


def validation_record(t: dict) -> dict:
    """{status, labs, unresolved} for one technique. THE single definition of what a claim is worth.

    `labs` are the claim's resolvable targets; `unresolved` are names that resolve to nothing and are
    reported rather than dropped, so a bad id is visible instead of silently vanishing."""
    vo = list(dict.fromkeys(t.get("validated_on") or []))
    legal = known_labs()
    resolved = [l for l in vo if l in legal]
    unresolved = [l for l in vo if l not in legal]
    if not vo:
        status = VALIDATION_NOT_APPLICABLE
    elif t.get("id") in _liveness_verified():
        status = VALIDATION_RECORDED
    else:
        status = VALIDATION_NOT_RECORDED
    return {"status": status, "labs": resolved, "unresolved": unresolved}


def is_proven(t: dict) -> bool:
    """THE shared predicate. Every module that wants to say "proven" must call this one function.

    Two subsystems disagreeing about the same word is not a display bug: /packs summed
    `len(validated_on) > 0` and reported 48 while /techniques reported the liveness-earned 16, in the
    same product, about the same registry. One definition, one place, both read it."""
    return technique_status(t) == "proven"


def technique_status(t: dict) -> str:
    """proven | unverified | solver_only | catalogued.

    "proven" USED TO MEAN "validated_on is non-empty", and validated_on is written by hand: four
    backfill dicts append a lab id with nothing checking the claim. The UI renders that count as a green
    "Proven" badge and a headline stat, so lab-solver behaviour and never-re-checked entries were being
    shown to a reader as capability. Commit 2e551ea backfilled 9 techniques "whose oracle actually fired
    on the live board" — honest in intent, but weak_password_reset has no production executor at all, so
    what fired was the Juice Shop solver, not the technique's oracle.

    Now the word is earned by an end-to-end liveness run and nothing else:
      proven      — a liveness CHECK confirmed it against a standing lab
      unverified  — claims validated_on, but no liveness check has ever confirmed it
      solver_only — demonstrated only by lab-specific solver code; never transferable capability
      catalogued  — known technique, not demonstrated
    """
    if t.get("solver_only"):
        return "solver_only"
    if t.get("id") in _liveness_verified():
        return "proven"
    return "unverified" if t.get("validated_on") else "catalogued"

"""
Design-level remediation (T5) — *Building Secure and Reliable Systems*, Ch.5/6/8/9.

Apolaki already answers "how do I fix this bug" three ways: a concise tactical line
(`report._FAMILY_FIX`), copy-paste secure snippets (`remediation.CATALOG`), and a Fix Now / Fix If /
Strengthen band (`remediation.fix_priority`). All three are about the DEFECT.

BSRS is a design book, and the gap it exposes is the set of questions a client asks after the defect is
patched — none of which any existing layer answers:

  * **Ch.5 Least Privilege** — what structural constraint means this component *could not* do the damage
    even if the bug came back? A fix removes an instance; a privilege boundary removes the class.
  * **Ch.6 Understandability** — how does the invariant become enforced by CONSTRUCTION rather than by
    every future developer remembering it? "Remember to check authorization" is not a control.
  * **Ch.8 Resilience** — when the fix is bypassed, what bounds the blast radius?
  * **Ch.9 Recovery** — **assume it was already exploited.** A pentest report that says "you have SQLi"
    without saying "treat the credential store as disclosed" is describing a bug, not an incident.

`recovery` is the field with no equivalent anywhere else in the platform, and the one most likely to be
acted on: a confirmed finding is evidence the door was open, and the report never previously said what
that implies for data already behind it.

**Discipline this file must keep.** Every entry is design guidance that does NOT restate the tactical
fix — a duplicated one-liner in a bigger font is filler, and filler in a remediation section trains
readers to skip it. A family with no meaningful design-level answer (a missing security header, an
informational posture note) gets NO entry rather than padding. `tests/test_remediation_depth.py` enforces
both rules mechanically.

Pure and deterministic: no I/O, no network, same finding in, same text out.
"""
from __future__ import annotations

# family -> {structural, blast_radius, recovery, verify}
#
# `structural` : the Ch.5/Ch.6 answer — the boundary or construction that removes the CLASS.
# `blast_radius`: the Ch.8 answer — what bounds the damage when the fix fails.
# `recovery`   : the Ch.9 answer — what to do ASSUMING it was already exploited.
# `verify`     : how to prove the fix landed. Names Apolaki's own retest where that is the honest answer.
DEPTH = {
    "sqli": {
        "structural": "Give the application's DB role only the rights it needs (no DDL, no access to other "
                      "schemas, read-only where possible) so a successful injection cannot reach the "
                      "credential store or alter structure. Enforce parameterisation by construction: a "
                      "query builder or ORM the application cannot bypass, plus a lint/CI rule that fails "
                      "on raw string-built SQL, rather than relying on review to catch concatenation.",
        "blast_radius": "Separate the accounts used for reads, writes and migrations. Keep secrets out of "
                        "the database the application queries. Log and alert on statements the application "
                        "never legitimately issues (UNION, INFORMATION_SCHEMA, stacked queries).",
        "recovery": "Treat every row the vulnerable query could reach as disclosed, not merely at risk. "
                    "Rotate credentials and any secrets stored in that database, and force re-authentication. "
                    "If password hashes were reachable, rotate the pepper/salt scheme and require a reset. "
                    "Preserve DB and WAF logs before rotation — they are the only record of what was read.",
        "verify": "Re-run the confirming oracle against the fixed endpoint (Apolaki retest), then repeat "
                  "with the payload URL-encoded and with an equivalent second-order path, since a fix that "
                  "only filters one encoding will pass a single-shot check.",
    },
    "xss": {
        "structural": "Make escaping the default the application cannot opt out of accidentally: an "
                      "auto-escaping template engine, with the raw/unsafe sink (dangerouslySetInnerHTML, "
                      "|safe, v-html) forbidden by lint and allowed only with a reviewed exemption. A "
                      "Content-Security-Policy without unsafe-inline turns a missed escape from an "
                      "exploited bug into a blocked one.",
        "blast_radius": "Set session cookies HttpOnly so script cannot read them, and SameSite so a "
                        "foothold on one origin cannot silently act on another. Keep privileged actions "
                        "behind re-authentication so a stolen session cannot change credentials or export "
                        "data unaided.",
        "recovery": "Treat sessions active during the exposure window as potentially hijacked: invalidate "
                    "them server-side rather than waiting for expiry. For STORED XSS, the payload is in "
                    "your data — find and purge every stored copy, and check whether it was served to "
                    "other users before deciding this was theoretical.",
        "verify": "Confirm the CSP is actually enforcing (not Report-Only), then retest the original sink "
                  "with a payload in a different context (attribute, JS string, URL) — context-specific "
                  "encoding fixes commonly close one context and leave the others open.",
    },
    "idor": {
        "structural": "Move the authorization decision from the handler to a layer the handler cannot skip: "
                      "a data-access layer that requires the caller's identity to load an object at all, so "
                      "the insecure call is not expressible. Per-endpoint checks are the failure mode — the "
                      "class recurs the first time someone adds a route and forgets one.",
        "blast_radius": "Scope object ids to the tenant or user where the model allows, so enumeration "
                        "cannot cross a boundary even if a check is missed. Rate-limit and alert on "
                        "sequential-id access patterns; unguessable ids raise the cost of discovery but are "
                        "not the control.",
        "recovery": "Enumerate which objects were actually accessed, not just which were reachable — access "
                    "logs keyed by (caller, object) are what makes this answerable, and their absence is "
                    "itself a finding. Notify affected data subjects where the exposed records carry a "
                    "regulatory obligation.",
        "verify": "Retest with the same two-persona differential that confirmed it (Apolaki's retest replays "
                  "the persona swap), and add a permanent test for the same object under a second identity — "
                  "the check that would have caught it before release.",
    },
    "bfla": {
        "structural": "Deny by default: the framework refuses a request to a privileged route unless a "
                      "policy explicitly permits the caller's role, so a new endpoint is unreachable rather "
                      "than open until someone remembers to guard it. Keep the policy declarative and "
                      "reviewable in one place instead of scattered across handlers.",
        "blast_radius": "Split administrative capability so no single role can both change permissions and "
                        "act on data. Require re-authentication or a second approval for irreversible "
                        "administrative actions.",
        "recovery": "Audit what was actually invoked through the unprotected function, and reverse any state "
                    "it changed. Review whether the caller granted themselves durable access — a new "
                    "account, an API key, an altered role — because revoking the session does not revoke "
                    "that.",
        "verify": "Retest every privileged route with a low-privilege persona, not only the one that was "
                  "reported; a fix applied to a single handler is the common partial remediation.",
    },
    "ssrf": {
        "structural": "Route outbound requests through a single egress proxy that enforces the destination "
                      "allowlist, so the policy cannot be bypassed by whichever HTTP client a future feature "
                      "happens to use. Resolve and pin the address, then connect to the pinned IP, which is "
                      "what closes DNS-rebinding rather than merely validating the hostname.",
        "blast_radius": "Remove ambient credentials from the compute environment — IMDSv2 with hop limits, "
                        "or better, no instance-attached role the application does not require. Network "
                        "policy should make the metadata endpoint and internal control planes unreachable "
                        "from the workload in the first place.",
        "recovery": "Assume any credential reachable from that workload is disclosed: rotate instance and "
                    "service-account credentials, and review the control-plane audit log for use of them "
                    "from unexpected callers. Internal services the workload could reach should be treated "
                    "as having been probed.",
        "verify": "Retest with the redirect and DNS-rebinding variants as well as the direct URL — an "
                  "allowlist checked before a redirect is followed is the standard incomplete fix.",
    },
    "path_traversal": {
        "structural": "Make the dangerous call unrepresentable rather than validated: a storage interface "
                      "that accepts only an opaque key resolved through a table the caller cannot "
                      "influence leaves nothing to traverse, so no future endpoint can reintroduce the "
                      "class. Where the API must take a filename, enforce confinement in the operating "
                      "system too — a read-only bind mount, chroot, or container view exposing only the "
                      "intended tree — so application correctness is not the sole boundary.",
        "blast_radius": "Run the service as a user that cannot read configuration, keys, or other tenants' "
                        "data. Container or chroot confinement bounds what a missed check can reach.",
        "recovery": "Treat every file readable by the service account as disclosed, and rotate any secret "
                    "among them. Application config, environment files, and key material are the usual "
                    "targets and the usual omission from the rotation list.",
        "verify": "Retest with encoded and doubly-encoded separators and with an absolute path, since "
                  "filters that strip a literal '../' commonly miss both.",
    },
    "cmdi": {
        "structural": "Remove the shell from the path entirely — call the native API, or exec with an "
                      "argument array so there is no string for a metacharacter to break out of. If a shell "
                      "is genuinely required, the reviewable control is an allowlist of complete commands, "
                      "not escaping of user input.",
        "blast_radius": "Run with the least privilege the task needs, in a container without a shell or "
                        "package manager, with egress restricted so a successful execution cannot fetch a "
                        "second stage or exfiltrate.",
        "recovery": "Treat the host as compromised rather than the endpoint as buggy: rebuild from a known "
                    "image rather than cleaning in place, rotate every credential the host held, and check "
                    "for persistence (cron, systemd units, authorized_keys, injected containers). Preserve "
                    "a forensic copy before rebuilding.",
        "verify": "Retest with blind/time-based and out-of-band variants, not only the echoing payload — the "
                  "usual partial fix suppresses output while leaving execution intact.",
    },
    "deserialization": {
        "structural": "Treat the parser as a trust boundary and move it: authenticate the payload before "
                      "anything interprets it (a MAC checked first means unverified bytes never reach the "
                      "reader), or run the reader in a separate least-privileged process so a gadget chain "
                      "executes somewhere that cannot reach your data. The reachable gadget set is a "
                      "property of the whole dependency tree, not of your code, so it changes under you "
                      "whenever a library is added — which is why the boundary, not the blocklist, is the "
                      "durable control.",
        "blast_radius": "Least-privilege the process and restrict egress, as with command injection — a "
                        "gadget chain generally ends in code execution, so treat the containment posture as "
                        "the real boundary.",
        "recovery": "Treat as remote code execution: rebuild the host, rotate everything it held, hunt for "
                    "persistence. Signed payloads added after the fact do not undo an execution that "
                    "already happened.",
        "verify": "Retest with a gadget from a different library present in the dependency tree — blocking "
                  "one known chain while leaving the sink open is the common incomplete fix.",
    },
    "exposure": {
        "structural": "Build the deployment artifact so the file is not there to serve: exclude backups, "
                      "dotfiles and archives at packaging time rather than blocking them at the web server, "
                      "where one misconfigured vhost re-exposes them. Deny by default and allowlist the "
                      "paths intended to be public.",
        "blast_radius": "Keep secrets out of files that can end up in a web root at all — a secret manager "
                        "the application reads at runtime means an exposed config file leaks structure "
                        "rather than credentials.",
        "recovery": "Rotate every credential the file contained, on the assumption it was retrieved and "
                    "indexed. Check search-engine and archive caches, since removing the file does not "
                    "remove copies. Review access logs for prior retrieval before deciding this was "
                    "theoretical.",
        "verify": "Re-request the exact URL, then check for the same artifact at the other conventional "
                  "paths (.bak, ~, .old, /backup/) — a single removed file is the usual partial fix.",
    },
    "git_exposure": {
        "structural": "Do not ship the VCS directory into the artifact; a build that copies a working tree "
                      "into an image is the root cause, and blocking `.git/` at the proxy only hides it.",
        "blast_radius": "Keep secrets out of the repository, so history disclosure costs source but not "
                        "access. Pre-commit secret scanning is what keeps that true over time.",
        "recovery": "Assume the full history was cloned, and rotate every secret that ever appeared in it — "
                    "including ones deleted in a later commit, which remain in history. Removing them from "
                    "HEAD does not invalidate anything already fetched.",
        "verify": "Confirm `.git/config`, `.git/HEAD` and the packfile paths all fail, not just the "
                  "directory index — directory listing is commonly disabled while the objects stay "
                  "fetchable.",
    },
    "csrf": {
        "structural": "Make the protection a property of the framework rather than of each handler: tokens "
                      "issued and validated by middleware on every state-changing method, with exemptions "
                      "explicit and reviewable. SameSite cookies are strong defence-in-depth but leave "
                      "same-site and older-client cases uncovered.",
        "blast_radius": "Require re-authentication for account-takeover-grade actions (password, email, MFA "
                        "changes) so a single forged request cannot become durable access.",
        "recovery": "Review whether state-changing actions were performed without the user's intent during "
                    "the window, focusing on changes to credentials, contact addresses, and permissions.",
        "verify": "Retest with the token omitted, emptied, and replayed from a different session — accepting "
                  "any of the three is the usual incomplete fix.",
    },
    "default_credentials": {
        "structural": "Make the deployment fail closed: no product should reach a reachable network with a "
                      "shipped credential intact. Enforce a forced credential change at first boot, and "
                      "detect the default in CI/inventory rather than in a pentest.",
        "blast_radius": "Keep management interfaces off routable networks — a dedicated management VLAN or "
                        "VPN means a missed default is not internet-reachable.",
        "recovery": "Assume the account was used: review its activity, rotate every credential it could "
                    "read or set, and check for added accounts, keys, or scheduled tasks. Changing the "
                    "password does not evict an established session or an added key.",
        "verify": "Retest the default credential AND the vendor's other documented defaults on the same "
                  "service; changing one account while leaving a second default is common.",
    },
    "vulnerable_component": {
        "structural": "Treat dependency currency as a standing process, not a finding: an SBOM, automated "
                      "advisory matching, and a patch cadence with a stated SLA. An end-of-life component "
                      "needs a migration plan, because no patch is coming.",
        "blast_radius": "Isolate components with a history of severe issues behind a boundary that bounds "
                        "what a compromise reaches, and keep the process least-privileged.",
        "recovery": "Determine whether the known exploit was actually used before treating this as "
                    "preventative — for a KEV-listed component the prior probability is not low. Preserve "
                    "logs covering the whole exposure window, which is the time since disclosure, not since "
                    "the scan.",
        "verify": "Confirm the deployed version at runtime rather than in the manifest; a patched lockfile "
                  "with a stale image is the standard false remediation.",
    },
    "session_fixation": {
        "structural": "Regenerate the session identifier inside the authentication routine itself, so no "
                      "login path can omit it. A framework that mints a new session on privilege change "
                      "makes this structural rather than remembered.",
        "blast_radius": "Bind sessions to a stable client property and expire them aggressively; require "
                        "re-authentication for sensitive actions so a fixed session yields limited value.",
        "recovery": "Invalidate all sessions predating the fix rather than only the reported one — a fixated "
                    "identifier is by definition known to the attacker before the victim uses it.",
        "verify": "Retest that the pre-authentication identifier is refused after login, and that logout "
                  "invalidates server-side rather than only clearing the cookie.",
    },
    "weak_session_token": {
        "structural": "Delegate token generation to the platform's session mechanism backed by a CSPRNG, "
                      "instead of application code composing an identifier. Tokens should carry no meaning: "
                      "a token that encodes a username or role invites both forgery and enumeration.",
        "blast_radius": "Keep sessions short-lived with server-side revocation, so a guessed token is useful "
                        "only briefly. Bind privileged actions to re-authentication.",
        "recovery": "Rotate the signing/generation secret and invalidate every outstanding session; existing "
                    "tokens must be assumed predictable, so expiry alone does not close the window.",
        "verify": "Sample fresh tokens after the fix and re-measure entropy and structure, rather than "
                  "inspecting the generation code — the deployed behaviour is what matters.",
    },
}

# Families deliberately WITHOUT an entry, with the reason. Kept explicit so the omission is a decision on
# the record rather than an oversight, and so a reviewer can challenge it.
NO_DEPTH_REASON = {
    "security_headers": "the tactical fix IS the complete answer; a header is set or it is not",
    "cookie_flags": "same — attribute flags have no design-level dimension beyond setting them",
    "open_redirect": "allowlisting the target is the whole control; no meaningful containment or recovery story",
    "username_enumeration": "the fix is response uniformity; there is no post-exploitation recovery posture",
}


def depth_for(finding: dict, family: str = None) -> dict:
    """Design-level guidance for a finding, or {} when the family has none. Pure.

    Returning {} rather than generic text is the point: a remediation section padded with advice that
    applies to everything teaches readers to skip the section that sometimes matters."""
    fam = (family or finding.get("family") or finding.get("vuln_class") or "").strip().lower()
    return dict(DEPTH.get(fam, {}))


def markdown(finding: dict, family: str = None) -> str:
    """The report block. Empty string when there is nothing substantive to add. Pure."""
    d = depth_for(finding, family)
    if not d:
        return ""
    return "\n".join([
        "**Design-level remediation**", "",
        "- **Remove the class (least privilege / by construction):** %s" % d["structural"],
        "- **Bound the blast radius:** %s" % d["blast_radius"],
        "- **Assume it was already exploited:** %s" % d["recovery"],
        "- **Verify the fix:** %s" % d["verify"],
        "",
    ])

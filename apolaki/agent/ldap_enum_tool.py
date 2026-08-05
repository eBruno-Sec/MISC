"""LDAP anonymous-read audit (AD / directory pentest — CWE-306 / CWE-284). A directory server (OpenLDAP or
Active Directory) that permits an ANONYMOUS bind AND lets that unauthenticated session read the naming-context
subtree leaks the org's users / computers / OUs to anyone on the network — the classic pre-auth enumeration
foothold on an AD engagement. READ-ONLY, no credentials, no brute-force.

FP-SAFE ORACLE: 'anonymous bind succeeds AND a SUBTREE search of the naming context returns directory ENTRIES'.
Reading only the RootDSE (server metadata under the empty base DN) is NOT flagged — that is normal and allowed on
almost every server, including hardened ones; the finding requires actual directory DATA (person / OU / group
objects) coming back to an anonymous session. A hardened server denies the anonymous subtree (0 entries /
insufficientAccessRights) and yields nothing. The analyze() half is pure (unit-testable without a server); probe()
does the read-only ldap3 conversation."""
from __future__ import annotations

_USER_CLASSES = ("inetorgperson", "organizationalperson", "person", "user", "posixaccount", "account")


def analyze(res: dict):
    """(severity, evidence) when an anonymous session could read directory entries; None otherwise. Reading user
    objects => 'high' (user enumeration); structure/OU/group only => 'medium'; RootDSE-only / bind-fail => None."""
    if not res or res.get("error") or not res.get("bound"):
        return None
    entries = res.get("entries") or []
    if not entries:                                          # anonymous bound but the subtree returned nothing = safe
        return None
    users = res.get("user_dns") or []
    if users:
        return ("high", "an anonymous bind reads %d directory entries including %d user object(s) (e.g. %s)"
                % (len(entries), len(users), users[0]))
    return ("medium", "an anonymous bind reads %d directory entries — OU/group/structure disclosure (e.g. %s)"
            % (len(entries), entries[0]))


def probe(host: str, port: int = 389, timeout: float = 6.0) -> dict:
    """One READ-ONLY anonymous LDAP conversation: anonymous bind, read RootDSE naming contexts, then a bounded
    SUBTREE search of each context. Returns {bound, naming_contexts, entries, user_dns} or {error}. No writes."""
    try:
        from ldap3 import ANONYMOUS, SUBTREE, Connection, Server
    except Exception as e:
        return {"error": "ldap3 unavailable: %s" % e}
    try:
        s = Server(host, port=int(port), get_info="ALL", connect_timeout=int(timeout))
        c = Connection(s, authentication=ANONYMOUS, receive_timeout=int(timeout))
        if not c.bind():
            return {"bound": False}
        ncs = list(getattr(s.info, "naming_contexts", None) or [])
        entries, user_dns = [], []
        for nc in (ncs or [""])[:2]:
            if not nc:
                continue
            try:
                c.search(nc, "(objectClass=*)", search_scope=SUBTREE, attributes=["objectClass"],
                         size_limit=50, time_limit=int(timeout))
            except Exception:
                continue
            for e in c.entries:
                entries.append(e.entry_dn)
                try:
                    ocs = [str(x).lower() for x in e.objectClass.values]
                except Exception:
                    ocs = []
                if any(u in ocs for u in _USER_CLASSES):
                    user_dns.append(e.entry_dn)
        try:
            c.unbind()
        except Exception:
            pass
        return {"bound": True, "naming_contexts": ncs, "entries": entries, "user_dns": user_dns}
    except Exception as e:
        return {"error": str(e)[:140]}


def finding(host: str, port: int, res: dict, severity: str, evidence: str) -> dict:
    vec = ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" if severity == "high"
           else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")
    ncs = ", ".join(res.get("naming_contexts") or []) or "(default)"
    return {
        "title": "LDAP allows anonymous directory read (%s:%d)" % (host, port),
        "severity": severity, "family": "ldap_anonymous_read", "confidence": "confirmed",
        "target": "%s:%d" % (host, port), "cwe": "CWE-306",
        "cvss_vector": vec, "cvss_score": 7.5 if severity == "high" else 5.3,
        "evidence": ("The directory at %s:%d (naming context %s) accepts an ANONYMOUS bind and %s. Read passively "
                     "with no credentials." % (host, port, ncs, evidence)),
        "success_oracle": evidence,
        "reproduction_steps": [
            "Bind anonymously to ldap://%s:%d (empty DN + empty password)." % (host, port),
            "Read the RootDSE to learn the naming context, then run a subtree search for (objectClass=*).",
            "Directory entries return to the unauthenticated session — %s." % evidence],
        "impact": ("Pre-auth enumeration of the directory (users, groups, computers, OUs) — reconnaissance for "
                   "password spraying, Kerberoasting target selection, and lateral-movement planning."),
        "remediation": ("Disable anonymous bind (olcDisallows: bind_anon / AD: dsHeuristics) or, at minimum, deny "
                        "anonymous read of the naming context so only authenticated principals can enumerate the "
                        "directory."),
        "tags": ["ldap", "active-directory", "anonymous-bind", "cwe-306", "network-service"],
    }

"""
Persona manager: the identities Apolaki tests AS.

Access-control testing is differential — a bug is proven by comparing what two identities can do
(PortSwigger/OWASP: two same-privilege users for horizontal access control). This holds the
mission's personas (anonymous, user_a, user_b, admin, tenant users, custom) and the session each
one has acquired. It sits ON TOP of the existing session store (ToolRegistry._sessions) and
InvestigationState.identities; it never touches the network itself.

Two rules from the spec are enforced here:
  - Privilege RANK (0=anonymous, 1=user, 2=privileged) is PROVEN, not guessed from a username. A
    persona becomes rank 2 only via prove_privileged(evidence) — never because "admin" is in the
    name.
  - Secrets are server-side only. to_dict() exposes role / rank / identity-label / method /
    has_session — never headers, passwords or tokens. The model references a role name; the raw
    secret stays in the registry session store (and, once built, the encrypted vault).
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Standard privilege ranks (match authz.py's matrix: 0=anon, 1=user, 2=privileged).
RANK_ANON = 0
RANK_USER = 1
RANK_PRIV = 2

# Canonical role names the orchestration and tests agree on.
ANON = "anonymous"
USER_A = "user_a"
USER_B = "user_b"
ADMIN = "admin"
# The SACRIFICIAL identity. Session-lifecycle testing (CWE-613) has to actually END a session, and a
# session the engagement is still testing with must never be the one that ends. A persona minted under
# this role is marked `sacrificial` and is deliberately invisible to every consumer that would keep
# using it — the matrix pair, the authenticated re-crawl, the registry session store. It exists so the
# destructive test has something of its own to destroy.
SESSION_PROBE = "session_probe"


@dataclass
class Persona:
    role: str
    rank: int = RANK_USER
    identity: str = ""              # email/username label (a test account we created — non-secret)
    tenant: str = ""               # tenant label for cross-tenant testing ("" = none)
    method: str = ""               # how the session was acquired: api|form|browser|registered|supplied
    headers: dict = field(default_factory=dict)   # SERVER-SIDE ONLY — never surfaced by to_dict
    account: dict = field(default_factory=dict)   # SERVER-SIDE ONLY — {username,email,password,...}
    recipe: dict = field(default_factory=dict)    # reusable login recipe (field map, csrf, token extract…)
    objects: list = field(default_factory=list)   # object URLs this persona legitimately owns
    verified: bool = False         # a session was actually captured
    proven_privilege: bool = False # rank was proven by app behavior, not guessed
    blocked: list = field(default_factory=list)   # manual-step walls hit (captcha/mfa/email/invite)
    sacrificial: bool = False      # minted to be DESTROYED (session-lifecycle); never reused for testing

    def has_session(self) -> bool:
        return bool(self.headers) and self.rank != RANK_ANON

    def usable(self) -> bool:
        """Holds a session the engagement may keep TESTING WITH. A sacrificial persona has a real
        session and is deliberately excluded here: the whole point of it is that something is about to
        end it, and a matrix built on a session that dies mid-run reports authorization failures that
        are really just a dead cookie."""
        return self.has_session() and not self.sacrificial

    def safe(self) -> dict:
        """Model/report-safe view — no secrets."""
        return {"role": self.role, "rank": self.rank, "identity": self.identity or None,
                "tenant": self.tenant or None, "method": self.method or None,
                "has_session": self.has_session(), "verified": self.verified,
                "proven_privilege": self.proven_privilege, "objects": len(self.objects),
                "blocked": list(self.blocked), "sacrificial": self.sacrificial}


class PersonaManager:
    def __init__(self):
        self._personas: dict = {}
        # anonymous always exists (rank 0, no session) so the matrix always has a public baseline.
        self._personas[ANON] = Persona(role=ANON, rank=RANK_ANON, identity="(anonymous)", verified=True)

    # ── mutation ──
    def add(self, role: str, *, rank: int = RANK_USER, identity: str = "", tenant: str = "",
            method: str = "", headers: dict = None, account: dict = None, recipe: dict = None,
            blocked: list = None, sacrificial: bool = None) -> Persona:
        """Create/replace a persona. Anonymous rank is protected. Rank is capped at USER unless
        prove_privileged() is later called — a caller cannot mint a rank-2 admin by assertion.

        The SESSION_PROBE role is always sacrificial, whatever the caller passes: the carve-out must not
        depend on every call site remembering to ask for it."""
        if role == ANON:
            rank = RANK_ANON
        elif rank >= RANK_PRIV:
            rank = RANK_USER  # privilege must be PROVEN, not declared at creation
        p = self._personas.get(role) or Persona(role=role)
        p.rank = rank
        if sacrificial is not None:
            p.sacrificial = bool(sacrificial)
        if role == SESSION_PROBE:
            p.sacrificial = True
        if identity:
            p.identity = identity
        if tenant:
            p.tenant = tenant
        if method:
            p.method = method
        if headers is not None:
            p.headers = dict(headers)
            p.verified = bool(headers)
        if account is not None:
            p.account = dict(account)
        if recipe is not None:
            p.recipe = dict(recipe)
        if blocked is not None:
            p.blocked = list(blocked)
        self._personas[role] = p
        return p

    def prove_privileged(self, role: str, evidence: str = "") -> bool:
        """Promote a persona to privileged rank — ONLY with real evidence (an admin-only function
        it could invoke, a role claim in a token/profile). Never call this from a username guess."""
        p = self._personas.get(role)
        if not p or not evidence:
            return False
        p.rank = RANK_PRIV
        p.proven_privilege = True
        p.recipe.setdefault("privilege_evidence", evidence)
        return True

    def add_object(self, role: str, url: str) -> None:
        p = self._personas.get(role)
        if p and url and url not in p.objects:
            p.objects.append(url)

    # ── queries ──
    def get(self, role: str):
        return self._personas.get(role)

    def headers_for(self, role: str) -> dict:
        p = self._personas.get(role)
        return dict(p.headers) if p else {}

    def roles(self) -> list:
        return list(self._personas.keys())

    def session_roles(self) -> list:
        """Roles holding a session the engagement may keep testing with (excludes anonymous AND any
        sacrificial persona, whose session is about to be deliberately destroyed)."""
        return [r for r, p in self._personas.items() if p.usable()]

    def sacrificial_roles(self) -> list:
        """Roles minted to be DESTROYED — the set `bind()` has to keep out of the live registry.

        Deliberately not filtered on `has_session()`. The role is what makes a persona sacrificial, and
        the session that has to be pruned is frequently one the MANAGER never held: `acquire_session`
        and `browser_login`'s promote_session write straight into `registry._sessions` under whatever
        role name they are given. Filtering on our own copy of the headers would skip exactly those."""
        return [r for r, p in self._personas.items() if p.sacrificial]

    def same_privilege_pair(self):
        """A pair of DISTINCT same-privilege personas with sessions (for horizontal testing), or None.
        Prefers user_a/user_b; falls back to any two rank-equal session-holders."""
        by_rank: dict = {}
        for p in self._personas.values():
            if p.usable():
                by_rank.setdefault(p.rank, []).append(p.role)
        if self.get(USER_A) and self.get(USER_B) and self.get(USER_A).usable() and self.get(USER_B).usable() \
                and self.get(USER_A).rank == self.get(USER_B).rank:
            return (USER_A, USER_B)
        for rank, roles in by_rank.items():
            if len(roles) >= 2:
                return (roles[0], roles[1])
        return None

    def privileged_role(self):
        for r, p in self._personas.items():
            if p.rank >= RANK_PRIV and p.usable():
                return r
        return None

    def tenant_pair(self):
        """Two session personas in DIFFERENT tenants (for cross-tenant testing), or None."""
        seen = {}
        for p in self._personas.values():
            if p.usable() and p.tenant:
                if p.tenant in seen:
                    continue
                seen[p.tenant] = p.role
        if len(seen) >= 2:
            roles = list(seen.values())
            return (roles[0], roles[1])
        return None

    # ── orchestration capabilities (CHAD §9) ──
    def capabilities(self) -> list:
        caps = []
        if self.session_roles():
            caps.append("session_acquired")
        if any(p.account for p in self._personas.values()):
            caps.append("account_created")
        if self.same_privilege_pair():
            caps.append("second_persona_available")
        if self.privileged_role():
            caps.append("privileged_persona_available")
        if self.tenant_pair():
            caps.append("tenant_boundary_available")
        if any(p.objects for p in self._personas.values()):
            caps.append("object_ownership_mapped")
        return caps

    def matrix_roles(self) -> list:
        """Roles shaped for authz.run_matrix / build_matrix: {role, rank, headers, tenant}. Always
        includes anonymous so a public baseline exists (prevents public endpoints reading as IDOR), and
        never includes a sacrificial persona — a matrix row whose session is destroyed mid-run would
        report every endpoint as denied and read exactly like correct authorization."""
        out = []
        for p in self._personas.values():
            if p.sacrificial:
                continue
            out.append({"role": p.role, "rank": p.rank,
                        "headers": dict(p.headers), "tenant": p.tenant or None})
        return out

    # ── integration ──
    def bind(self, registry) -> None:
        """Write persona sessions THROUGH to the live ToolRegistry so existing tools (confirm_idor,
        http_read with session=role, the matrix driver) resolve them, and mirror identities into the
        InvestigationState. Single source of truth stays here; this projects it onto the registry.

        A SACRIFICIAL persona is never projected, and any session already sitting under its role is
        REMOVED. `_sessions` is what every other engine reaches into, and `tools._session_kill_is_safe`
        reads it to decide whether a logout is safe to send — a sacrificial session in there makes the
        safety check refuse its own subject, and the engine then reports inconclusive on every target
        while nothing looks broken.

        Both halves are needed. Skipping the write alone would be a one-sided carve-out, because
        `bind()` is not the only writer: `_run_acquire_session` and `browser_login`'s `promote_session`
        both write `registry._sessions[role]` directly under whatever role name the caller passes."""
        sessions = getattr(registry, "_sessions", None)
        state = getattr(registry, "state", None)
        if sessions is not None:
            for role in self.sacrificial_roles():
                sessions.pop(role, None)
        for role, p in self._personas.items():
            if p.sacrificial:
                continue
            if p.has_session() and sessions is not None:
                sessions[role] = dict(p.headers)
            if state is not None and hasattr(state, "add_identity") and p.rank != RANK_ANON:
                try:
                    state.add_identity(role, {"auth_type": "bearer" if "Authorization" in p.headers else "cookie",
                                              "identity": p.identity, "is_admin": p.rank >= RANK_PRIV})
                except Exception:
                    pass

    def to_dict(self) -> dict:
        return {"personas": [p.safe() for p in self._personas.values()],
                "capabilities": self.capabilities()}

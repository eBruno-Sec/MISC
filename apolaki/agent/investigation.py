"""
Mission investigation state: identities, object-ownership, acquired capabilities, and
extracted variables. This is the substrate for capability-based attack chaining — instead
of correlating findings at report time, confirmed oracles record CAPABILITIES here as they
are earned, and workflows/planning can declare prerequisites against them.

Pure and additive: a single InvestigationState lives on the ToolRegistry; tools populate
it when they confirm something. Nothing here contacts a target.
"""
from __future__ import annotations

from enum import Enum


class Capability(str, Enum):
    SESSION_ACQUIRED = "session_acquired"
    ADMIN_SESSION = "admin_session"
    FOREIGN_OBJECT_READ = "foreign_object_read"
    FOREIGN_OBJECT_WRITE = "foreign_object_write"
    DATABASE_READ = "database_read"
    PASSWORD_HASH_OBTAINED = "password_hash_obtained"
    CREDENTIAL_CRACKED = "credential_cracked"
    FORGED_TOKEN = "forged_token"
    ARBITRARY_FILE_READ = "arbitrary_file_read"
    FILE_UPLOAD = "file_upload"
    INTERNAL_REQUEST = "internal_request"


# what a capability typically UNLOCKS next — advisory chaining hints (not hardcoded exploits)
CHAINS_TO = {
    Capability.DATABASE_READ: [Capability.PASSWORD_HASH_OBTAINED],
    Capability.PASSWORD_HASH_OBTAINED: [Capability.CREDENTIAL_CRACKED],
    Capability.CREDENTIAL_CRACKED: [Capability.ADMIN_SESSION],
    Capability.FORGED_TOKEN: [Capability.ADMIN_SESSION],
    Capability.ADMIN_SESSION: [Capability.FOREIGN_OBJECT_WRITE],
    Capability.ARBITRARY_FILE_READ: [Capability.INTERNAL_REQUEST],
}


class InvestigationState:
    def __init__(self):
        self.identities = {}     # role -> {auth_type, identity, is_admin}
        self.objects = {}        # url -> {owner_role, status}
        self._caps = {}          # Capability -> evidence str (insertion-ordered)
        self.variables = {}      # name -> value (extracted from responses)

    # ── identities ──
    def add_identity(self, role: str, meta: dict):
        self.identities[role] = {k: meta.get(k) for k in ("auth_type", "identity", "is_admin")}
        self.add_capability(Capability.SESSION_ACQUIRED, f"session '{role}' ({meta.get('identity')})")
        if meta.get("is_admin"):
            self.add_capability(Capability.ADMIN_SESSION, f"admin session '{role}'")

    # ── objects / ownership ──
    def add_object(self, url: str, owner_role: str = None, status: int = None):
        self.objects[url] = {"owner_role": owner_role, "status": status}

    # ── capabilities ──
    def add_capability(self, cap, evidence: str = ""):
        cap = cap.value if isinstance(cap, Capability) else str(cap)
        if cap not in self._caps:
            self._caps[cap] = evidence

    def has(self, cap) -> bool:
        return (cap.value if isinstance(cap, Capability) else str(cap)) in self._caps

    # ── variables ──
    def set_var(self, name: str, value):
        self.variables[str(name)] = value

    def get_var(self, name: str, default=None):
        return self.variables.get(str(name), default)

    # ── views ──
    def next_hints(self) -> list:
        out = []
        for cap in self._caps:
            for nxt in CHAINS_TO.get(Capability(cap) if cap in Capability._value2member_map_ else None, []):
                if not self.has(nxt):
                    out.append({"have": cap, "chase": nxt.value})
        return out

    def to_dict(self) -> dict:
        return {
            "identities": self.identities,
            "capabilities": [{"capability": c, "evidence": e} for c, e in self._caps.items()],
            "objects_seen": len(self.objects),
            "variables": list(self.variables.keys()),
            "chaining_hints": self.next_hints(),
        }

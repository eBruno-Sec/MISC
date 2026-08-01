"""PersonaManager — the identities Apolaki tests as. Pure; no network.
Enforces: anonymous baseline, proven (not guessed) privilege, secret redaction, and the
capability derivations that unlock the authorization matrix."""
from __future__ import annotations

import personas as P


def _two_users():
    m = P.PersonaManager()
    m.add(P.USER_A, identity="a@t.local", method="registered", headers={"Cookie": "s=A"})
    m.add(P.USER_B, identity="b@t.local", method="registered", headers={"Cookie": "s=B"})
    return m


def test_anonymous_always_present_rank0():
    m = P.PersonaManager()
    anon = m.get(P.ANON)
    assert anon is not None and anon.rank == P.RANK_ANON
    assert not anon.has_session()          # anon never "holds" a session
    assert "anonymous" in [r["role"] for r in m.matrix_roles()]


def test_privilege_must_be_proven_not_declared():
    m = P.PersonaManager()
    # try to mint an admin at rank 2 by assertion -> capped to USER
    m.add(P.ADMIN, rank=P.RANK_PRIV, identity="admin@t.local", headers={"Cookie": "s=ad"})
    assert m.get(P.ADMIN).rank == P.RANK_USER
    assert not m.get(P.ADMIN).proven_privilege
    # promotion requires evidence
    assert m.prove_privileged(P.ADMIN, "invoked /admin/users and got 200 with user list") is True
    assert m.get(P.ADMIN).rank == P.RANK_PRIV and m.get(P.ADMIN).proven_privilege
    # no evidence -> refused
    assert m.prove_privileged(P.USER_A, "") is False


def test_same_privilege_pair_enables_horizontal():
    m = _two_users()
    assert m.same_privilege_pair() == (P.USER_A, P.USER_B)
    assert "second_persona_available" in m.capabilities()
    assert "account_created" not in m.capabilities()  # no account dict attached yet


def test_account_and_object_capabilities():
    m = _two_users()
    m.add(P.USER_A, account={"username": "apolaki_a", "password": "x"})
    m.add_object(P.USER_A, "https://t/api/orders/1")
    caps = m.capabilities()
    assert "account_created" in caps
    assert "object_ownership_mapped" in caps


def test_tenant_pair():
    m = P.PersonaManager()
    m.add("tenant_a_user", tenant="A", headers={"Cookie": "s=1"})
    m.add("tenant_b_user", tenant="B", headers={"Cookie": "s=2"})
    assert m.tenant_pair() is not None
    assert "tenant_boundary_available" in m.capabilities()


def test_secrets_never_in_safe_view():
    m = _two_users()
    m.add(P.USER_A, account={"username": "apolaki_a", "email": "a@t.local", "password": "SUPERSECRET"})
    dump = str(m.to_dict())
    assert "SUPERSECRET" not in dump
    assert "s=A" not in dump          # headers never surfaced
    # but the role and non-secret identity label are present
    assert "user_a" in dump and "a@t.local" in dump


def test_bind_projects_sessions_onto_registry():
    class _State:
        def __init__(self):
            self.identities = {}

        def add_identity(self, role, meta):
            self.identities[role] = meta

    class _Reg:
        def __init__(self):
            self._sessions = {}
            self.state = _State()

    m = _two_users()
    m.prove_privileged(P.USER_A, "reached /admin")   # rank 2, is_admin True
    reg = _Reg()
    m.bind(reg)
    assert reg._sessions[P.USER_A] == {"Cookie": "s=A"}
    assert reg._sessions[P.USER_B] == {"Cookie": "s=B"}
    assert reg.state.identities[P.USER_A]["is_admin"] is True
    assert reg.state.identities[P.USER_B]["is_admin"] is False
    assert P.ANON not in reg._sessions                # anonymous carries no session

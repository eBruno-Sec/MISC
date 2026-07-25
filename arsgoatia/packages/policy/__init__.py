"""Policy and safety primitives.

M2 ships the scope firewall's core (ported apolaki ScopeEngine) and the target
guard (ported olympus is_valid_target). M3 adds the layered policy engine, the
signed action envelope, and the DNS-resolution / rebinding / redirect checks that
wrap this core in the executor.
"""

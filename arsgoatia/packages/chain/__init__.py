"""Attack-chain engine (§19). Chains express aggregate, multi-step impact that
per-finding severity does not. Chain severity uses a versioned ArsGoatia method,
never CVSS (§17, ADR 0005)."""

from chain.engine import (
    CHAIN_SEVERITY_VERSION,
    build_capability_transition,
    build_chain_step,
    chain_severity,
)

__all__ = [
    "CHAIN_SEVERITY_VERSION",
    "build_capability_transition",
    "build_chain_step",
    "chain_severity",
]

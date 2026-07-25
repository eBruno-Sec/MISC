"""Tool SDK (§21).

The only component that touches a target. Every request carries a signed action
envelope which the executor re-verifies, then re-runs the scope firewall + SSRF
checks, applies limits, injects the secret at call time (never logging it), and
returns the raw exchange as immutable evidence.
"""

from tool_sdk.http_client import execute, preflight_verify

__all__ = ["execute", "preflight_verify"]

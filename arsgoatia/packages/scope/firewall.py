from __future__ import annotations

from dataclasses import dataclass

from packages.contracts.schemas.engagement import ScopeSpec
from packages.scope import _is_dangerous_address, check_target


@dataclass(frozen=True)
class FirewallResult:
    allowed: bool
    reason: str
    checks_passed: list[str]
    failed_check: str | None = None


class ScopeFirewall:
    def __init__(self, scope: ScopeSpec) -> None:
        self._scope = scope

    def preflight(
        self,
        locator: str,
        resolved_addresses: list[str],
        port: int | None = None,
    ) -> FirewallResult:
        checks: list[str] = []

        scope_result = check_target(self._scope, locator, port=port)
        if not scope_result.allowed:
            return FirewallResult(
                allowed=False,
                reason=scope_result.reason,
                checks_passed=checks,
                failed_check="scope",
            )
        checks.append("scope")

        for addr in resolved_addresses:
            if _is_dangerous_address(addr, allow_private=self._scope.allow_private_targets):
                return FirewallResult(
                    allowed=False,
                    reason=f"resolved address {addr} is dangerous",
                    checks_passed=checks,
                    failed_check="address_classification",
                )
        checks.append("address_classification")

        if port is not None and self._scope.ports:
            if port not in self._scope.ports:
                return FirewallResult(
                    allowed=False,
                    reason=f"port {port} not allowed",
                    checks_passed=checks,
                    failed_check="port_pin",
                )
        checks.append("port_pin")

        return FirewallResult(allowed=True, reason="all checks passed", checks_passed=checks)

    def check_redirect(self, original: str, redirect_url: str) -> FirewallResult:
        result = check_target(self._scope, redirect_url, is_redirect=True)
        if not result.allowed:
            return FirewallResult(
                allowed=False,
                reason=f"redirect to {redirect_url}: {result.reason}",
                checks_passed=[],
                failed_check="redirect_scope",
            )
        return FirewallResult(
            allowed=True, reason="redirect in scope", checks_passed=["redirect_scope"]
        )

    def check_dns_answers(self, hostname: str, addresses: list[str]) -> FirewallResult:
        for addr in addresses:
            if _is_dangerous_address(addr, allow_private=self._scope.allow_private_targets):
                return FirewallResult(
                    allowed=False,
                    reason=f"DNS answer {addr} for {hostname} is dangerous",
                    checks_passed=[],
                    failed_check="dns_answer_classification",
                )
        return FirewallResult(
            allowed=True, reason="DNS answers safe", checks_passed=["dns_answer_classification"]
        )

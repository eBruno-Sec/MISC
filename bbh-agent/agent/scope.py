from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse


class PermissionLevel(Enum):
    PASSIVE = "passive"
    ACTIVE = "active"
    INTRUSIVE = "intrusive"


@dataclass
class ScopeEntry:
    value: str
    asset_type: str


class ScopeEngine:
    def __init__(self):
        self.in_scope: list[ScopeEntry] = []
        self.out_of_scope: list[ScopeEntry] = []
        self.program_name: str = ""

    def load_manual(self, in_scope: list[str], out_of_scope: list[str], program_name: str = "Program") -> None:
        self.program_name = program_name
        for d in in_scope:
            d = d.strip().lower()
            if d:
                self.in_scope.append(ScopeEntry(d, "wildcard" if d.startswith("*") else "domain"))
        for d in out_of_scope:
            d = d.strip().lower()
            if d:
                self.out_of_scope.append(ScopeEntry(d, "wildcard" if d.startswith("*") else "domain"))

    def validate(self, target: str) -> tuple[bool, str]:
        host = self._extract_host(target)
        if not host:
            return False, "Invalid target"
        for entry in self.out_of_scope:
            if self._matches(host, entry.value):
                return False, f"{host} is explicitly out of scope"
        for entry in self.in_scope:
            if self._matches(host, entry.value):
                return True, f"In scope via {entry.value}"
        return False, f"{host} not in scope"

    def _extract_host(self, target: str) -> str:
        if "://" in target:
            return urlparse(target).netloc.split(":")[0].lower()
        return target.split(":")[0].split("/")[0].lower()

    def _matches(self, host: str, pattern: str) -> bool:
        clean = pattern.lstrip("*.").lower()
        return host == clean or host.endswith("." + clean)

    def to_dict(self) -> dict:
        return {
            "program": self.program_name,
            "in_scope": [e.value for e in self.in_scope],
            "out_of_scope": [e.value for e in self.out_of_scope],
        }

"""ArsGoatia tool pack registry -- adapter-backed tool definitions.

Each tool pack describes a single adapter-backed tool with its parameter
schema, resource defaults, and container image digest so that runners
can materialise the correct environment.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ToolPack:
    pack_id: str
    version: str
    adapter_id: str
    parameter_schema: dict[str, Any] = field(default_factory=dict)
    resource_defaults: dict[str, Any] = field(default_factory=dict)
    image_digest: str = ""


_REGISTRY: dict[str, ToolPack] = {}


def register_tool_pack(pack: ToolPack) -> None:
    """Register a tool pack by its pack_id.  Overwrites silently."""
    _REGISTRY[pack.pack_id] = pack


def get_tool_pack(pack_id: str) -> ToolPack | None:
    """Return a registered tool pack or ``None`` if not found."""
    return _REGISTRY.get(pack_id)


def list_tool_packs() -> list[ToolPack]:
    """Return all registered tool packs sorted by pack_id."""
    return sorted(_REGISTRY.values(), key=lambda p: p.pack_id)


# ---------------------------------------------------------------------------
# Built-in tool pack: HTTP_PROBE
# ---------------------------------------------------------------------------

HTTP_PROBE = ToolPack(
    pack_id="http_probe",
    version="1.0.0",
    adapter_id="http-probe",
    parameter_schema={
        "method": {
            "type": "string",
            "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
        },
        "url": {"type": "string"},
        "headers": {"type": "object"},
        "body": {"type": "string"},
        "timeout_seconds": {"type": "integer", "default": 30},
    },
    resource_defaults={
        "max_concurrent": 4,
        "timeout_seconds": 30,
    },
)

register_tool_pack(HTTP_PROBE)

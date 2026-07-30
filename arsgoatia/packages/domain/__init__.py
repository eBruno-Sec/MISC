"""ArsGoatia domain models.

This package owns every persistent aggregate in the system.  Each
subpackage corresponds to a bounded context and maps to a dedicated
PostgreSQL schema.
"""

from __future__ import annotations

__all__ = [
    "evidence",
    "findings",
    "governance",
    "iam",
    "knowledge",
    "remediation",
    "reporting",
]

"""Tool-execution provenance + parser versioning (Codex cross-check Tier-3 #14).

The Bash/Metasploit/Black-Hat-Python workflow material pushes REPEATABLE tooling. Apolaki already wraps + tests
its external tools; this makes each execution auditable: for every external tool run we record tool name,
binary path + version, an argv hash, timeout, exit code, PARSER VERSION, input/output/scope hashes, permission
class, and approval id. It adds no attack surface — it makes reports + retests stronger and reproducible.

Secrets never enter the record: argv/inputs are secret-redacted before hashing + preview. Pure + offline.
"""
from __future__ import annotations

import hashlib
import json
import re
import time

_SECRET_KEYS = ("authorization", "cookie", "token", "password", "passwd", "secret", "api_key", "apikey",
                "x-api-key", "bearer", "session", "private_key")
# CLI secret patterns: -p<val>, --password val, Authorization: Bearer x, token=...
_ARGV_SECRET = re.compile(r"""(?ix)
    (authorization\s*:\s*bearer\s+)\S+ |
    (--?(?:password|passwd|token|secret|api[-_]?key|auth[-_]?token)[=\s]+)\S+ |
    (bearer\s+)[A-Za-z0-9._\-]{8,}
""")


def _strip_secrets(obj):
    if isinstance(obj, dict):
        return {k: _strip_secrets(v) for k, v in obj.items()
                if not any(tok in str(k).lower() for tok in _SECRET_KEYS)}
    if isinstance(obj, list):
        return [_strip_secrets(v) for v in obj]
    return obj


def _hash(obj) -> str:
    canon = json.dumps(_strip_secrets(obj), sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canon.encode("utf-8", "replace")).hexdigest()[:16]


def _redact_argv(argv) -> list:
    out = []
    for a in (argv or []):
        s = str(a)
        s = _ARGV_SECRET.sub(lambda m: (m.group(1) or m.group(2) or m.group(3) or "") + "«redacted»", s)
        out.append(s)
    return out


def record(tool: str, argv=None, *, binary_path: str = None, binary_version: str = None,
           timeout=None, exit_code=None, parser_version: str = None, inputs=None, output=None,
           scope=None, permission: str = "ACTIVE", approval_id: str = None) -> dict:
    """Build a provenance record for one external tool execution. Argv/inputs are secret-redacted before
    hashing/preview; the raw output is NOT stored (only its artifact hash)."""
    redacted_argv = _redact_argv(argv)
    return {
        "tool": tool,
        "binary_path": binary_path,
        "binary_version": binary_version,
        "argv_redacted": redacted_argv,
        "argv_hash": _hash(redacted_argv),
        "timeout": timeout,
        "exit_code": exit_code,
        "parser_version": parser_version,
        "input_hash": _hash(inputs) if inputs is not None else None,
        "output_artifact_hash": (_hash(output) if output is not None else None),
        "scope_hash": _hash(scope) if scope is not None else None,
        "permission": str(permission or "ACTIVE").upper(),
        "approval_id": approval_id,
        "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def argv_hash(argv) -> str:
    return _hash(_redact_argv(argv))

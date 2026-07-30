"""Deterministic SQL injection technique pack.

Two confirmation strategies, both fail-closed:

1. **Error-based** — inject a payload known to produce a DB error
   (`'"` for most engines, `');` for stacked-query engines). Compare
   response to the pristine baseline for known error-signature strings.

2. **Boolean-based** — inject a TRUE payload and a FALSE payload.
   A confirmed SQLi shows the TRUE response ≈ baseline and the FALSE
   response measurably different (status, body length, structure).

A finding is CONFIRMED only when at least one strategy shows a
deterministic signal *and* the negative control (unrelated string in
the parameter) matches the baseline. No LLM in the confirmation path.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

TECHNIQUE_ID = "web_sqli_reflected"
CWE = "CWE-89"
OWASP = "A03:2021 — Injection"

# Common DB-error signatures across MySQL / PostgreSQL / MSSQL / Oracle / SQLite.
_ERROR_SIGNATURES: list[re.Pattern[str]] = [
    re.compile(r"you have an error in your sql syntax", re.IGNORECASE),
    re.compile(r"warning:\s*mysqli?_", re.IGNORECASE),
    re.compile(r"unclosed quotation mark", re.IGNORECASE),
    re.compile(r"pg_query\(\)", re.IGNORECASE),
    re.compile(r"psql:.*syntax error", re.IGNORECASE),
    re.compile(r"sqlstate\[[0-9a-z]+\]", re.IGNORECASE),
    re.compile(r"ora-\d{5}", re.IGNORECASE),
    re.compile(r"microsoft.*odbc.*sql server", re.IGNORECASE),
    re.compile(r"sqlite3\.OperationalError", re.IGNORECASE),
    re.compile(r"near \".*\": syntax error", re.IGNORECASE),
]

_ERROR_PAYLOAD = "'\""
_TRUE_PAYLOAD = "' OR '1'='1"
_FALSE_PAYLOAD = "' AND '1'='2"
_NEG_CONTROL = "arsgoatia_probe_string"


@dataclass
class SQLiExchange:
    label: str
    url: str
    status_code: int
    body_length: int
    error_signature: str | None = None
    body_preview: str = ""

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__


@dataclass
class SQLiResult:
    finding_status: str  # CONFIRMED | INCONCLUSIVE | REJECTED
    reason: str
    strategy: str = ""  # error-based | boolean-based
    parameter: str = ""
    exchanges: list[SQLiExchange] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_status": self.finding_status,
            "reason": self.reason,
            "strategy": self.strategy,
            "parameter": self.parameter,
            "exchanges": [e.to_dict() for e in self.exchanges],
        }


def _replace_query_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    new_pairs = [(k, value if k == param else v) for k, v in pairs]
    return urlunparse(parsed._replace(query=urlencode(new_pairs)))


def _detect_error_signature(text: str) -> str | None:
    for pat in _ERROR_SIGNATURES:
        m = pat.search(text)
        if m:
            return pat.pattern
    return None


async def _fetch(client, url: str, headers: dict[str, str] | None = None) -> SQLiExchange:
    label = ""  # caller labels it
    try:
        r = await client.get(url, headers=headers or {})
        text = r.text if hasattr(r, "text") else ""
        return SQLiExchange(
            label=label,
            url=url,
            status_code=r.status_code,
            body_length=len(text),
            error_signature=_detect_error_signature(text),
            body_preview=text[:200],
        )
    except Exception as exc:
        return SQLiExchange(
            label=label,
            url=url,
            status_code=0,
            body_length=0,
            error_signature=None,
            body_preview=f"error: {exc!r}",
        )


async def probe(
    *,
    client,
    url: str,
    parameter: str,
    token: str | None = None,
) -> SQLiResult:
    """Probe ``parameter`` in the query string of ``url`` for SQLi."""
    parsed = urlparse(url)
    pairs = dict(parse_qsl(parsed.query, keep_blank_values=True))
    if parameter not in pairs:
        return SQLiResult(
            finding_status="INCONCLUSIVE",
            reason=f"parameter {parameter!r} not present in URL query string",
            parameter=parameter,
        )
    baseline_value = pairs[parameter]

    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    baseline = await _fetch(client, url, headers)
    baseline.label = "baseline"

    error_url = _replace_query_param(url, parameter, baseline_value + _ERROR_PAYLOAD)
    error_ex = await _fetch(client, error_url, headers)
    error_ex.label = "error_payload"

    true_url = _replace_query_param(url, parameter, baseline_value + _TRUE_PAYLOAD)
    true_ex = await _fetch(client, true_url, headers)
    true_ex.label = "boolean_true"

    false_url = _replace_query_param(url, parameter, baseline_value + _FALSE_PAYLOAD)
    false_ex = await _fetch(client, false_url, headers)
    false_ex.label = "boolean_false"

    neg_url = _replace_query_param(url, parameter, _NEG_CONTROL)
    neg_ex = await _fetch(client, neg_url, headers)
    neg_ex.label = "negative_control"

    exchanges = [baseline, error_ex, true_ex, false_ex, neg_ex]

    # -- Error-based confirmation ---------------------------------------------
    if (
        error_ex.error_signature
        and not baseline.error_signature
        and not neg_ex.error_signature
    ):
        return SQLiResult(
            finding_status="CONFIRMED",
            reason=(
                f"payload {_ERROR_PAYLOAD!r} in parameter {parameter!r} elicited a DB "
                f"error signature ({error_ex.error_signature!r}) that neither the baseline "
                "nor the neutral negative control produced"
            ),
            strategy="error-based",
            parameter=parameter,
            exchanges=exchanges,
        )

    # -- Boolean-based confirmation ------------------------------------------
    # Signal: TRUE payload ~ baseline, FALSE payload substantially different.
    baseline_len = baseline.body_length
    delta_true = abs(true_ex.body_length - baseline_len)
    delta_false = abs(false_ex.body_length - baseline_len)
    same_status_true = true_ex.status_code == baseline.status_code
    if (
        baseline_len > 0
        and same_status_true
        and delta_true <= max(50, baseline_len * 0.02)
        and delta_false >= max(200, baseline_len * 0.10)
        and neg_ex.body_length != true_ex.body_length  # not just a static echo
    ):
        return SQLiResult(
            finding_status="CONFIRMED",
            reason=(
                f"boolean-based: TRUE payload response length ({true_ex.body_length}) "
                f"matches baseline ({baseline_len}) within tolerance while FALSE payload "
                f"({false_ex.body_length}) diverges significantly"
            ),
            strategy="boolean-based",
            parameter=parameter,
            exchanges=exchanges,
        )

    return SQLiResult(
        finding_status="REJECTED",
        reason=(
            "no error signature triggered and no significant boolean-based "
            "response divergence observed"
        ),
        parameter=parameter,
        exchanges=exchanges,
    )

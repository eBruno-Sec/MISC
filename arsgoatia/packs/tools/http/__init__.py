"""HTTP tool pack — configuration for the HTTP differential probe tool.

Defines request templates, response matchers, and evidence capture profiles
for the HTTP adapter's differential testing mode.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class RequestTemplate:
    method: str = "GET"
    path: str = "/"
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes | None = None
    follow_redirects: bool = False
    timeout_ms: int = 10000


@dataclass(frozen=True)
class ResponseMatcher:
    expected_status: int | None = None
    body_contains: str | None = None
    body_not_contains: str | None = None
    header_present: str | None = None
    header_value: tuple[str, str] | None = None


@dataclass(frozen=True)
class DifferentialProbe:
    name: str
    baseline: RequestTemplate
    differential: RequestTemplate
    positive_control: RequestTemplate
    negative_control: RequestTemplate
    baseline_matcher: ResponseMatcher = field(default_factory=ResponseMatcher)
    differential_matcher: ResponseMatcher = field(default_factory=ResponseMatcher)


BOLA_BASKET_PROBE = DifferentialProbe(
    name="bola_basket_access",
    baseline=RequestTemplate(
        method="GET",
        path="/rest/basket/{own_basket_id}",
        headers={"Authorization": "Bearer {own_token}"},
    ),
    differential=RequestTemplate(
        method="GET",
        path="/rest/basket/{target_basket_id}",
        headers={"Authorization": "Bearer {own_token}"},
    ),
    positive_control=RequestTemplate(
        method="GET",
        path="/rest/basket/{target_basket_id}",
        headers={"Authorization": "Bearer {target_token}"},
    ),
    negative_control=RequestTemplate(
        method="GET",
        path="/rest/basket/{target_basket_id}",
    ),
    baseline_matcher=ResponseMatcher(expected_status=200),
    differential_matcher=ResponseMatcher(expected_status=200),
)

from __future__ import annotations

from packs.techniques.web_authz.bola_differential import (
    BOLAConfirmation,
    ExchangeResult,
    build_capability,
    confirm_bola,
)


def _exchange(label: str, status: int, body_contains_object: bool = False, object_id: str | None = None):
    return ExchangeResult(
        label=label,
        status_code=status,
        body_contains_object=body_contains_object,
        object_id=object_id,
    )


def test_confirmed_bola():
    result = confirm_bola(
        baseline=_exchange("baseline", 200, body_contains_object=True, object_id="basket-1"),
        differential=_exchange("differential", 200, body_contains_object=True, object_id="basket-1"),
        positive_control=_exchange("positive", 200, body_contains_object=True, object_id="basket-2"),
        negative_control=_exchange("negative", 401),
    )
    assert result.confirmed is True


def test_bola_negative_control_must_fail():
    result = confirm_bola(
        baseline=_exchange("baseline", 200, body_contains_object=True, object_id="basket-1"),
        differential=_exchange("differential", 200, body_contains_object=True, object_id="basket-1"),
        positive_control=_exchange("positive", 200, body_contains_object=True, object_id="basket-2"),
        negative_control=_exchange("negative", 200, body_contains_object=True),
    )
    assert result.confirmed is False


def test_bola_differential_must_succeed():
    result = confirm_bola(
        baseline=_exchange("baseline", 200, body_contains_object=True, object_id="basket-1"),
        differential=_exchange("differential", 403),
        positive_control=_exchange("positive", 200, body_contains_object=True, object_id="basket-2"),
        negative_control=_exchange("negative", 401),
    )
    assert result.confirmed is False


def test_baseline_must_succeed():
    result = confirm_bola(
        baseline=_exchange("baseline", 500),
        differential=_exchange("differential", 200, body_contains_object=True),
        positive_control=_exchange("positive", 200, body_contains_object=True),
        negative_control=_exchange("negative", 401),
    )
    assert result.confirmed is False


def test_build_capability():
    cap = build_capability(
        actor_id="user-a",
        access_context_id="ctx-1",
        target_object="basket-1",
        evidence_refs=["ev-1", "ev-2", "ev-3", "ev-4"],
    )
    assert cap["type"] == "read_foreign_object"
    assert cap["technique_id"] == "web.authz.bola.differential"
    assert len(cap["evidence_refs"]) == 4

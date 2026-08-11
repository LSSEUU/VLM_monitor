from __future__ import annotations

import pytest
from pydantic import ValidationError

from labcourt.contracts.m8_access_cases import M8ActorRole
from labcourt.contracts.m8_personal_demo import (
    M8PersonalDemoActorBindingV1,
    M8PersonalDemoBootstrapReceiptV1,
)
from labcourt.schema_registry import SCHEMA_MODELS


def _receipt() -> M8PersonalDemoBootstrapReceiptV1:
    bindings = tuple(
        M8PersonalDemoActorBindingV1(
            actor_id=actor_id,
            role=role,
            actor_commit_receipt_id=character * 64,
        )
        for actor_id, role, character in (
            ("leader-demo", M8ActorRole.LEADER, "1"),
            ("operations-demo", M8ActorRole.OPERATIONS, "2"),
            ("safety-officer-demo", M8ActorRole.SAFETY_OFFICER, "3"),
            ("student-demo", M8ActorRole.STUDENT, "4"),
        )
    )
    return M8PersonalDemoBootstrapReceiptV1(
        topology_commit_receipt_id="a" * 64,
        source_catalog_commit_receipt_id="b" * 64,
        actor_bindings=bindings,
        sensor_poll_cache_commit_receipt_id="c" * 64,
        latest_sensor_sample_commit_receipt_id="d" * 64,
        raw_signal_refs=("m8/raw/smoke/0.json", "m8/raw/smoke/1.json"),
        case_commit_receipt_id="e" * 64,
        case_id="f" * 64,
        operations_projection_id="0" * 64,
        bootstrap_manifest_id="9" * 64,
    )


def test_bootstrap_receipt_is_fixed_simulated_pending_case_authority() -> None:
    receipt = _receipt()

    assert receipt.simulated is True
    assert receipt.human_verification_required is True
    assert receipt.case_transition_permitted is False
    assert receipt.certified_fire_detection_claim_permitted is False
    assert receipt.pending_verification_case_count == 1
    assert len(receipt.bootstrap_receipt_id) == 64


def test_bootstrap_receipt_rejects_role_or_identity_forgery() -> None:
    payload = _receipt().model_dump(mode="json")
    payload["actor_bindings"][0]["role"] = M8ActorRole.SAFETY_OFFICER.value

    with pytest.raises(ValidationError):
        M8PersonalDemoBootstrapReceiptV1.model_validate(payload)


def test_personal_demo_schemas_are_exported() -> None:
    assert SCHEMA_MODELS["m8-personal-demo-actor-binding-v1"] is (M8PersonalDemoActorBindingV1)
    assert SCHEMA_MODELS["m8-personal-demo-bootstrap-receipt-v1"] is (
        M8PersonalDemoBootstrapReceiptV1
    )

from __future__ import annotations

import hashlib

import pytest
from pydantic import ValidationError

from labcourt.contracts.m8_access_cases import M8ActorRole
from labcourt.contracts.m8_api import (
    M8ApiCredentialAuthorityV1,
    M8ApiCredentialCatalogAuthorityV1,
)
from labcourt.contracts.m8_personal_demo import (
    M8PersonalDemoActorBindingV1,
    M8PersonalDemoBootstrapReceiptV1,
)
from labcourt.contracts.m8_personal_demo_api import (
    M8PersonalDemoApiProfileV1,
    M8PersonalDemoLocalAccessV1,
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
    assert SCHEMA_MODELS["m8-personal-demo-api-profile-v1"] is M8PersonalDemoApiProfileV1
    assert SCHEMA_MODELS["m8-personal-demo-local-access-v1"] is M8PersonalDemoLocalAccessV1


def test_api_profile_keeps_plaintext_tokens_out_of_authority() -> None:
    credentials = tuple(
        M8ApiCredentialAuthorityV1(
            credential_id=credential_id,
            actor_id=actor_id,
            bearer_token_sha256=hashlib.sha256(credential_id.encode()).hexdigest(),
            active=True,
            manifest_id="8" * 64,
        )
        for credential_id, actor_id in (
            ("credential-leader-demo", "leader-demo"),
            ("credential-operations-demo", "operations-demo"),
            ("credential-safety-demo", "safety-officer-demo"),
            ("credential-student-demo", "student-demo"),
        )
    )
    profile = M8PersonalDemoApiProfileV1(
        bind_port=8877,
        bootstrap_receipt_id="7" * 64,
        credential_catalog=M8ApiCredentialCatalogAuthorityV1(
            revision=1,
            credentials=credentials,
            authentication_manifest_id="6" * 64,
        ),
        server_manifest_id="5" * 64,
    )

    assert profile.base_url == "http://127.0.0.1:8877"
    assert profile.plaintext_demo_tokens_in_authority is False
    assert "labcourt-personal-demo-leader-token" not in profile.model_dump_json()


def test_local_access_contract_redacts_role_tokens_on_serialization() -> None:
    access = M8PersonalDemoLocalAccessV1(
        base_url="http://127.0.0.1:8877",
        tokens={
            "leader": "local-demo-leader-secret",
            "operations": "local-demo-operations-secret",
            "safety": "local-demo-safety-secret",
            "student": "local-demo-student-secret",
        },
    )

    serialized = access.model_dump_json()
    assert "local-demo-safety-secret" not in serialized
    assert access.tokens.safety.get_secret_value() == "local-demo-safety-secret"

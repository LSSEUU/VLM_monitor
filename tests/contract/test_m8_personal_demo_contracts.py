from __future__ import annotations

import hashlib
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from labcourt.contracts.m8_access_cases import M8ActorRole
from labcourt.contracts.m8_api import (
    M8ApiCredentialAuthorityV1,
    M8ApiCredentialCatalogAuthorityV1,
)
from labcourt.contracts.m8_knowledge import M8KnowledgeDocumentType
from labcourt.contracts.m8_notifications import M8NotificationStatus
from labcourt.contracts.m8_operations import M8OperationalSource, M8OperationalSourceMode
from labcourt.contracts.m8_personal_demo import (
    M8PersonalDemoActorBindingV1,
    M8PersonalDemoBootstrapReceiptV1,
    M8PersonalDemoCameraReceiptV1,
    M8PersonalDemoCameraViewV1,
    M8PersonalDemoKnowledgeReceiptV1,
    M8PersonalDemoNotificationReceiptV1,
    M8PersonalDemoPpeCaseReceiptV1,
    M8PersonalDemoRecordedMediaReceiptV1,
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
    assert SCHEMA_MODELS["m8-personal-demo-camera-receipt-v1"] is (M8PersonalDemoCameraReceiptV1)
    assert SCHEMA_MODELS["m8-personal-demo-camera-view-v1"] is M8PersonalDemoCameraViewV1
    assert SCHEMA_MODELS["m8-personal-demo-api-profile-v1"] is M8PersonalDemoApiProfileV1
    assert SCHEMA_MODELS["m8-personal-demo-local-access-v1"] is M8PersonalDemoLocalAccessV1
    assert SCHEMA_MODELS["m8-personal-demo-knowledge-receipt-v1"] is (
        M8PersonalDemoKnowledgeReceiptV1
    )
    assert SCHEMA_MODELS["m8-personal-demo-notification-receipt-v1"] is (
        M8PersonalDemoNotificationReceiptV1
    )
    assert SCHEMA_MODELS["m8-personal-demo-recorded-media-receipt-v1"] is (
        M8PersonalDemoRecordedMediaReceiptV1
    )
    assert SCHEMA_MODELS["m8-personal-demo-ppe-case-receipt-v1"] is (
        M8PersonalDemoPpeCaseReceiptV1
    )


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


def test_knowledge_receipt_covers_all_types_without_rule_authority() -> None:
    receipt = M8PersonalDemoKnowledgeReceiptV1(
        catalog_authority_id="4" * 64,
        catalog_commit_receipt_id="3" * 64,
        generated_at=datetime(2026, 8, 10, 9, 0, tzinfo=UTC),
        document_types=tuple(sorted(M8KnowledgeDocumentType, key=lambda item: item.value)),
        knowledge_manifest_id="2" * 64,
    )

    assert receipt.document_count == 6
    assert receipt.ordinary_documents_can_define_case_rules is False
    assert receipt.model_used is False
    assert receipt.network_used is False
    assert len(receipt.knowledge_receipt_id) == 64


def test_notification_receipt_is_queued_simulated_and_non_disciplinary() -> None:
    receipt = M8PersonalDemoNotificationReceiptV1(
        case_id="1" * 64,
        source_case_authority_sha256="2" * 64,
        target_commit_receipt_id="3" * 64,
        target_authority_id="4" * 64,
        notification_id="5" * 64,
        notification_commit_receipt_id="6" * 64,
        routed_at=datetime(2026, 8, 10, 9, 1, 1, tzinfo=UTC),
        offline_card_id="7" * 64,
        notification_manifest_id="8" * 64,
    )

    assert receipt.notification_status == M8NotificationStatus.QUEUED
    assert receipt.simulated is True
    assert receipt.network_used is False
    assert receipt.real_delivery_confirmed is False
    assert receipt.case_transition_permitted is False
    assert receipt.direct_disciplinary_action_permitted is False
    assert len(receipt.notification_receipt_id) == 64
    assert (
        M8PersonalDemoNotificationReceiptV1.model_validate_json(receipt.model_dump_json())
        == receipt
    )


def test_camera_receipt_cannot_claim_live_or_attached_media() -> None:
    receipt = M8PersonalDemoCameraReceiptV1(
        source_catalog_id="1" * 64,
        source_catalog_commit_receipt_id="2" * 64,
        sensor_refresh_commit_receipt_id="3" * 64,
        camera_manifest_id="4" * 64,
    )

    assert receipt.display_badge == "SIMULATED · RECORDED VIDEO"
    assert receipt.media_attached is False
    assert receipt.live_camera_claim_permitted is False
    assert receipt.life_safety_eligible is False
    assert receipt.network_used is False
    assert receipt.gpu_used is False
    assert len(receipt.camera_receipt_id) == 64


def test_recorded_media_receipt_requires_an_exact_non_authoritative_copy() -> None:
    receipt = M8PersonalDemoRecordedMediaReceiptV1(
        source_catalog_id="1" * 64,
        source_catalog_commit_receipt_id="2" * 64,
        raw_media_ref="raw-media-3",
        input_file_sha256="3" * 64,
        input_size_bytes=128,
        playback_file_sha256="3" * 64,
        playback_size_bytes=128,
        media_binding_manifest_id="4" * 64,
    )

    assert receipt.media_attached is True
    assert receipt.exact_byte_copy is True
    assert receipt.original_media_modified is False
    assert receipt.decoder_preflight_performed is False
    assert receipt.live_camera_claim_permitted is False
    assert receipt.face_recognition_performed is False
    assert receipt.cross_camera_reidentification_performed is False
    assert len(receipt.media_binding_receipt_id) == 64
    assert (
        M8PersonalDemoRecordedMediaReceiptV1.model_validate_json(receipt.model_dump_json())
        == receipt
    )

    payload = receipt.model_dump(mode="json")
    payload["playback_file_sha256"] = "5" * 64
    with pytest.raises(ValidationError):
        M8PersonalDemoRecordedMediaReceiptV1.model_validate(payload)


def test_camera_view_requires_binding_and_attachment_state_to_match() -> None:
    source = M8OperationalSource(
        source_id="camera-recorded-demo-01",
        device_id="device-recorded-camera-01",
        location_id="room-chem-301",
        mode=M8OperationalSourceMode.RECORDED_VIDEO_SIMULATION,
        adapter_id="m8-recorded-video-simulator",
        manifest_id="5" * 64,
    )
    view = M8PersonalDemoCameraViewV1(
        source_catalog_id="1" * 64,
        source_catalog_commit_receipt_id="2" * 64,
        source=source,
        media_attached=False,
        camera_view_manifest_id="4" * 64,
    )

    assert view.media_binding is None
    assert view.simulated is True
    assert view.authentication_required is True
    assert M8PersonalDemoCameraViewV1.model_validate_json(view.model_dump_json()) == view

    payload = view.model_dump(mode="json")
    payload["media_attached"] = True
    with pytest.raises(ValidationError):
        M8PersonalDemoCameraViewV1.model_validate(payload)


def test_ppe_case_receipt_is_only_a_simulated_weak_label_candidate() -> None:
    receipt = M8PersonalDemoPpeCaseReceiptV1(
        source_catalog_id="1" * 64,
        media_binding_receipt_id="2" * 64,
        video_event_document_sha256="3" * 64,
        case_id="4" * 64,
        case_commit_receipt_id="5" * 64,
        ppe_case_manifest_id="6" * 64,
    )

    assert receipt.input_media_content_claim_verified is False
    assert receipt.filename_used_as_evidence is False
    assert receipt.machine_weak_label_is_ground_truth is False
    assert receipt.model_used is False
    assert receipt.human_verification_required is True
    assert receipt.case_transition_permitted is False
    assert receipt.direct_disciplinary_action_permitted is False
    assert M8PersonalDemoPpeCaseReceiptV1.model_validate_json(receipt.model_dump_json()) == receipt

"""Compact authorities for the reproducible local M8 product demonstration."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Literal, Self

from pydantic import Field, computed_field, model_validator
from pydantic.functional_validators import ModelWrapValidatorHandler

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_access_cases import (
    M8ActorRole,
    M8OperationalCaseStatus,
    M8OperationalRiskLevel,
)
from labcourt.contracts.m8_knowledge import M8KnowledgeDocumentType
from labcourt.contracts.m8_notifications import (
    M8NotificationAudienceKind,
    M8NotificationChannelKind,
    M8NotificationPurpose,
    M8NotificationStatus,
)
from labcourt.contracts.m8_operations import M8OperationalSource, M8OperationalSourceMode
from labcourt.contracts.references import ReferenceToken, require_reference_token


class M8PersonalDemoActorBindingV1(FrozenContractModel):
    schema_version: Literal["m8-personal-demo-actor-binding-v1"] = (
        "m8-personal-demo-actor-binding-v1"
    )
    actor_id: ReferenceToken
    role: M8ActorRole
    actor_commit_receipt_id: Sha256Hex

    @model_validator(mode="after")
    def validate_actor_id(self) -> Self:
        require_reference_token(self.actor_id, "M8 personal demo actor_id")
        return self


class M8PersonalDemoBootstrapReceiptV1(FrozenContractModel):
    """Small content-addressed receipt over the complete persisted demo cut."""

    schema_version: Literal["m8-personal-demo-bootstrap-receipt-v1"] = (
        "m8-personal-demo-bootstrap-receipt-v1"
    )
    display_badge: Literal["PERSONAL DEMO · SIMULATED CAMPUS OPERATIONS"] = (
        "PERSONAL DEMO · SIMULATED CAMPUS OPERATIONS"
    )
    campus_id: Literal["campus-demo"] = "campus-demo"
    case_location_id: Literal["room-chem-301"] = "room-chem-301"
    source_id: Literal["sensor-simulated-smoke-01"] = "sensor-simulated-smoke-01"
    topology_commit_receipt_id: Sha256Hex
    source_catalog_commit_receipt_id: Sha256Hex
    actor_bindings: tuple[M8PersonalDemoActorBindingV1, ...] = Field(
        min_length=4,
        max_length=4,
    )
    sensor_poll_cache_commit_receipt_id: Sha256Hex
    latest_sensor_sample_commit_receipt_id: Sha256Hex
    raw_signal_refs: tuple[str, ...] = Field(min_length=2, max_length=2)
    case_commit_receipt_id: Sha256Hex
    case_id: Sha256Hex
    case_status: Literal[M8OperationalCaseStatus.PENDING_VERIFICATION] = (
        M8OperationalCaseStatus.PENDING_VERIFICATION
    )
    risk_level: Literal[M8OperationalRiskLevel.EMERGENCY] = M8OperationalRiskLevel.EMERGENCY
    operations_projection_id: Sha256Hex
    location_count: Literal[4] = 4
    source_count: Literal[1] = 1
    observed_sensor_count: Literal[1] = 1
    current_case_count: Literal[1] = 1
    pending_verification_case_count: Literal[1] = 1
    simulated: Literal[True] = True
    certified_fire_detection_claim_permitted: Literal[False] = False
    human_verification_required: Literal[True] = True
    case_transition_permitted: Literal[False] = False
    direct_disciplinary_action_permitted: Literal[False] = False
    bootstrap_manifest_id: Sha256Hex

    @model_validator(mode="wrap")
    @classmethod
    def validate_computed_claim(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        claimed: object | None = None
        present = False
        if isinstance(value, dict):
            payload = dict(value)
            present = "bootstrap_receipt_id" in payload
            claimed = payload.pop("bootstrap_receipt_id", None)
            value = payload
        receipt = handler(value)
        if present and canonical_json(claimed) != canonical_json(receipt.bootstrap_receipt_id):
            raise ValueError("serialized bootstrap receipt ID conflicts with derived authority")
        return receipt

    @model_validator(mode="after")
    def validate_fixed_inventory(self) -> Self:
        expected = (
            ("leader-demo", M8ActorRole.LEADER),
            ("operations-demo", M8ActorRole.OPERATIONS),
            ("safety-officer-demo", M8ActorRole.SAFETY_OFFICER),
            ("student-demo", M8ActorRole.STUDENT),
        )
        observed = tuple((item.actor_id, item.role) for item in self.actor_bindings)
        if observed != expected:
            raise ValueError("M8 personal demo actor inventory is not the fixed role matrix")
        commit_ids = tuple(item.actor_commit_receipt_id for item in self.actor_bindings)
        if len(commit_ids) != len(set(commit_ids)):
            raise ValueError("M8 personal demo actor commits must be unique")
        if self.raw_signal_refs != tuple(sorted(self.raw_signal_refs)):
            raise ValueError("M8 personal demo raw signal refs must use stable order")
        if len(set(self.raw_signal_refs)) != 2:
            raise ValueError("M8 personal demo raw signal refs must be unique")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def bootstrap_receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-personal-demo-bootstrap-receipt",
                1,
                self.campus_id,
                self.case_location_id,
                self.source_id,
                self.topology_commit_receipt_id,
                self.source_catalog_commit_receipt_id,
                [item.model_dump(mode="json") for item in self.actor_bindings],
                self.sensor_poll_cache_commit_receipt_id,
                self.latest_sensor_sample_commit_receipt_id,
                self.raw_signal_refs,
                self.case_commit_receipt_id,
                self.case_id,
                self.case_status,
                self.risk_level,
                self.operations_projection_id,
                self.location_count,
                self.source_count,
                self.observed_sensor_count,
                self.current_case_count,
                self.pending_verification_case_count,
                self.simulated,
                self.certified_fire_detection_claim_permitted,
                self.human_verification_required,
                self.case_transition_permitted,
                self.direct_disciplinary_action_permitted,
                self.bootstrap_manifest_id,
            ]
        )


class M8PersonalDemoKnowledgeReceiptV1(FrozenContractModel):
    schema_version: Literal["m8-personal-demo-knowledge-receipt-v1"] = (
        "m8-personal-demo-knowledge-receipt-v1"
    )
    catalog_id: Literal["campus-safety-knowledge"] = "campus-safety-knowledge"
    catalog_authority_id: Sha256Hex
    catalog_commit_receipt_id: Sha256Hex
    generated_at: datetime
    document_types: tuple[M8KnowledgeDocumentType, ...] = Field(
        min_length=6,
        max_length=6,
    )
    document_count: Literal[6] = 6
    ordinary_documents_can_define_case_rules: Literal[False] = False
    model_used: Literal[False] = False
    network_used: Literal[False] = False
    knowledge_manifest_id: Sha256Hex

    @model_validator(mode="after")
    def validate_knowledge_inventory(self) -> Self:
        if self.generated_at.tzinfo is None or self.generated_at.utcoffset() != timedelta(0):
            raise ValueError("M8 personal Demo knowledge generated_at must be UTC")
        expected = tuple(sorted(M8KnowledgeDocumentType, key=lambda item: item.value))
        if self.document_types != expected:
            raise ValueError("M8 personal Demo knowledge must cover the six fixed document types")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def knowledge_receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-personal-demo-knowledge-receipt",
                1,
                self.catalog_id,
                self.catalog_authority_id,
                self.catalog_commit_receipt_id,
                self.generated_at.isoformat(timespec="microseconds"),
                [item.value for item in self.document_types],
                self.document_count,
                self.ordinary_documents_can_define_case_rules,
                self.model_used,
                self.network_used,
                self.knowledge_manifest_id,
            ]
        )


class M8PersonalDemoNotificationReceiptV1(FrozenContractModel):
    """Compact authority for one deterministic emergency notification route."""

    schema_version: Literal["m8-personal-demo-notification-receipt-v1"] = (
        "m8-personal-demo-notification-receipt-v1"
    )
    case_id: Sha256Hex
    source_case_version: Literal[1] = 1
    source_case_authority_sha256: Sha256Hex
    target_commit_receipt_id: Sha256Hex
    target_authority_id: Sha256Hex
    target_actor_id: Literal["safety-officer-demo"] = "safety-officer-demo"
    purpose: Literal[M8NotificationPurpose.CASE_ACTION_REQUIRED] = (
        M8NotificationPurpose.CASE_ACTION_REQUIRED
    )
    audience: Literal[M8NotificationAudienceKind.SAFETY_RESPONDER] = (
        M8NotificationAudienceKind.SAFETY_RESPONDER
    )
    channel: Literal[M8NotificationChannelKind.LOCAL_OFFLINE_FAKE] = (
        M8NotificationChannelKind.LOCAL_OFFLINE_FAKE
    )
    notification_id: Sha256Hex
    notification_version: Literal[2] = 2
    notification_commit_receipt_id: Sha256Hex
    notification_status: Literal[M8NotificationStatus.QUEUED] = M8NotificationStatus.QUEUED
    routed_at: datetime
    offline_card_id: Sha256Hex
    display_badge: Literal["SIMULATED · LOCAL MESSAGE CARD"] = "SIMULATED · LOCAL MESSAGE CARD"
    simulated: Literal[True] = True
    network_used: Literal[False] = False
    model_used: Literal[False] = False
    real_delivery_confirmed: Literal[False] = False
    case_transition_permitted: Literal[False] = False
    direct_disciplinary_action_permitted: Literal[False] = False
    notification_manifest_id: Sha256Hex

    @model_validator(mode="wrap")
    @classmethod
    def validate_computed_claim(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        claimed: object | None = None
        present = False
        if isinstance(value, dict):
            payload = dict(value)
            present = "notification_receipt_id" in payload
            claimed = payload.pop("notification_receipt_id", None)
            value = payload
        receipt = handler(value)
        if present and canonical_json(claimed) != canonical_json(receipt.notification_receipt_id):
            raise ValueError("serialized notification receipt ID conflicts with authority")
        return receipt

    @model_validator(mode="after")
    def validate_routed_at(self) -> Self:
        if self.routed_at.tzinfo is None or self.routed_at.utcoffset() != timedelta(0):
            raise ValueError("M8 personal Demo notification routed_at must be UTC")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def notification_receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-personal-demo-notification-receipt",
                1,
                self.case_id,
                self.source_case_version,
                self.source_case_authority_sha256,
                self.target_commit_receipt_id,
                self.target_authority_id,
                self.target_actor_id,
                self.purpose,
                self.audience,
                self.channel,
                self.notification_id,
                self.notification_version,
                self.notification_commit_receipt_id,
                self.notification_status,
                self.routed_at.isoformat(timespec="microseconds"),
                self.offline_card_id,
                self.simulated,
                self.network_used,
                self.model_used,
                self.real_delivery_confirmed,
                self.case_transition_permitted,
                self.direct_disciplinary_action_permitted,
                self.notification_manifest_id,
            ]
        )


class M8PersonalDemoCameraReceiptV1(FrozenContractModel):
    """Receipt for the additive recorded-video camera Demo catalog revision."""

    schema_version: Literal["m8-personal-demo-camera-receipt-v1"] = (
        "m8-personal-demo-camera-receipt-v1"
    )
    campus_id: Literal["campus-demo"] = "campus-demo"
    location_id: Literal["room-chem-301"] = "room-chem-301"
    source_id: Literal["camera-recorded-demo-01"] = "camera-recorded-demo-01"
    device_id: Literal["device-recorded-camera-01"] = "device-recorded-camera-01"
    mode: Literal[M8OperationalSourceMode.RECORDED_VIDEO_SIMULATION] = (
        M8OperationalSourceMode.RECORDED_VIDEO_SIMULATION
    )
    display_badge: Literal["SIMULATED · RECORDED VIDEO"] = "SIMULATED · RECORDED VIDEO"
    source_catalog_revision: Literal[2] = 2
    source_catalog_id: Sha256Hex
    source_catalog_commit_receipt_id: Sha256Hex
    sensor_refresh_commit_receipt_id: Sha256Hex
    source_count: Literal[2] = 2
    camera_count: Literal[1] = 1
    simulated_source_count: Literal[2] = 2
    media_attached: Literal[False] = False
    raw_media_reference_required: Literal[True] = True
    live_camera_claim_permitted: Literal[False] = False
    life_safety_eligible: Literal[False] = False
    network_used: Literal[False] = False
    gpu_used: Literal[False] = False
    camera_manifest_id: Sha256Hex

    @computed_field  # type: ignore[prop-decorator]
    @property
    def camera_receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-personal-demo-camera-receipt",
                1,
                self.campus_id,
                self.location_id,
                self.source_id,
                self.device_id,
                self.mode,
                self.source_catalog_revision,
                self.source_catalog_id,
                self.source_catalog_commit_receipt_id,
                self.sensor_refresh_commit_receipt_id,
                self.source_count,
                self.camera_count,
                self.simulated_source_count,
                self.media_attached,
                self.raw_media_reference_required,
                self.live_camera_claim_permitted,
                self.life_safety_eligible,
                self.network_used,
                self.gpu_used,
                self.camera_manifest_id,
            ]
        )


class M8PersonalDemoRecordedMediaReceiptV1(FrozenContractModel):
    """Content-addressed binding of one local MP4 to the simulated Demo camera."""

    schema_version: Literal["m8-personal-demo-recorded-media-receipt-v1"] = (
        "m8-personal-demo-recorded-media-receipt-v1"
    )
    source_id: Literal["camera-recorded-demo-01"] = "camera-recorded-demo-01"
    source_catalog_id: Sha256Hex
    source_catalog_commit_receipt_id: Sha256Hex
    raw_media_ref: ReferenceToken
    input_file_sha256: Sha256Hex
    input_size_bytes: int = Field(gt=0)
    playback_media_ref: Literal["media/camera-recorded-demo-01.mp4"] = (
        "media/camera-recorded-demo-01.mp4"
    )
    playback_file_sha256: Sha256Hex
    playback_size_bytes: int = Field(gt=0)
    mode: Literal[M8OperationalSourceMode.RECORDED_VIDEO_SIMULATION] = (
        M8OperationalSourceMode.RECORDED_VIDEO_SIMULATION
    )
    display_badge: Literal["SIMULATED · RECORDED VIDEO"] = (
        "SIMULATED · RECORDED VIDEO"
    )
    container_signature: Literal["ISO_BMFF_FTYP"] = "ISO_BMFF_FTYP"
    media_attached: Literal[True] = True
    exact_byte_copy: Literal[True] = True
    original_media_modified: Literal[False] = False
    transcoding_performed: Literal[False] = False
    decoder_preflight_performed: Literal[False] = False
    live_camera_claim_permitted: Literal[False] = False
    life_safety_eligible: Literal[False] = False
    face_recognition_performed: Literal[False] = False
    cross_camera_reidentification_performed: Literal[False] = False
    network_used: Literal[False] = False
    gpu_used: Literal[False] = False
    media_binding_manifest_id: Sha256Hex

    @model_validator(mode="wrap")
    @classmethod
    def validate_computed_claim(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        claimed: object | None = None
        present = False
        if isinstance(value, dict):
            payload = dict(value)
            present = "media_binding_receipt_id" in payload
            claimed = payload.pop("media_binding_receipt_id", None)
            value = payload
        receipt = handler(value)
        if present and canonical_json(claimed) != canonical_json(
            receipt.media_binding_receipt_id
        ):
            raise ValueError("serialized media binding receipt ID conflicts with authority")
        return receipt

    @model_validator(mode="after")
    def validate_exact_copy(self) -> Self:
        require_reference_token(self.raw_media_ref, "M8 personal Demo raw_media_ref")
        if self.playback_file_sha256 != self.input_file_sha256:
            raise ValueError("M8 personal Demo playback bytes must match input bytes")
        if self.playback_size_bytes != self.input_size_bytes:
            raise ValueError("M8 personal Demo playback size must match input size")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def media_binding_receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-personal-demo-recorded-media-receipt",
                1,
                self.source_id,
                self.source_catalog_id,
                self.source_catalog_commit_receipt_id,
                self.raw_media_ref,
                self.input_file_sha256,
                self.input_size_bytes,
                self.playback_media_ref,
                self.playback_file_sha256,
                self.playback_size_bytes,
                self.mode,
                self.container_signature,
                self.media_attached,
                self.exact_byte_copy,
                self.original_media_modified,
                self.transcoding_performed,
                self.decoder_preflight_performed,
                self.live_camera_claim_permitted,
                self.life_safety_eligible,
                self.face_recognition_performed,
                self.cross_camera_reidentification_performed,
                self.network_used,
                self.gpu_used,
                self.media_binding_manifest_id,
            ]
        )


class M8PersonalDemoCameraViewV1(FrozenContractModel):
    """Discoverable product view over the fixed simulated recorded camera."""

    schema_version: Literal["m8-personal-demo-camera-view-v1"] = (
        "m8-personal-demo-camera-view-v1"
    )
    source_catalog_id: Sha256Hex
    source_catalog_commit_receipt_id: Sha256Hex
    source: M8OperationalSource
    display_badge: Literal["SIMULATED · RECORDED VIDEO"] = (
        "SIMULATED · RECORDED VIDEO"
    )
    media_attached: bool
    media_binding: M8PersonalDemoRecordedMediaReceiptV1 | None = None
    media_metadata_api_path: Literal[
        "/api/m8/cameras/camera-recorded-demo-01/media-metadata"
    ] = "/api/m8/cameras/camera-recorded-demo-01/media-metadata"
    media_api_path: Literal["/api/m8/cameras/camera-recorded-demo-01/media"] = (
        "/api/m8/cameras/camera-recorded-demo-01/media"
    )
    authentication_required: Literal[True] = True
    simulated: Literal[True] = True
    live_camera_claim_permitted: Literal[False] = False
    life_safety_eligible: Literal[False] = False
    camera_view_manifest_id: Sha256Hex

    @model_validator(mode="wrap")
    @classmethod
    def validate_computed_claim(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        claimed: object | None = None
        present = False
        if isinstance(value, dict):
            payload = dict(value)
            present = "camera_view_id" in payload
            claimed = payload.pop("camera_view_id", None)
            value = payload
        view = handler(value)
        if present and canonical_json(claimed) != canonical_json(view.camera_view_id):
            raise ValueError("serialized camera view ID conflicts with authority")
        return view

    @model_validator(mode="after")
    def validate_camera_binding(self) -> Self:
        if (
            self.source.source_id != "camera-recorded-demo-01"
            or self.source.mode != M8OperationalSourceMode.RECORDED_VIDEO_SIMULATION
        ):
            raise ValueError("M8 personal Demo camera view requires the fixed recorded source")
        if self.media_attached != (self.media_binding is not None):
            raise ValueError("M8 personal Demo media attachment state conflicts with binding")
        if self.media_binding is not None and (
            self.media_binding.source_id != self.source.source_id
            or self.media_binding.source_catalog_id != self.source_catalog_id
            or self.media_binding.source_catalog_commit_receipt_id
            != self.source_catalog_commit_receipt_id
        ):
            raise ValueError("M8 personal Demo media binding belongs to another catalog cut")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def camera_view_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-personal-demo-camera-view",
                1,
                self.source_catalog_id,
                self.source_catalog_commit_receipt_id,
                self.source.model_dump(mode="json"),
                self.media_attached,
                (
                    self.media_binding.model_dump(mode="json")
                    if self.media_binding is not None
                    else None
                ),
                self.media_metadata_api_path,
                self.media_api_path,
                self.authentication_required,
                self.simulated,
                self.live_camera_claim_permitted,
                self.life_safety_eligible,
                self.camera_view_manifest_id,
            ]
        )


__all__ = [
    "M8PersonalDemoActorBindingV1",
    "M8PersonalDemoBootstrapReceiptV1",
    "M8PersonalDemoCameraReceiptV1",
    "M8PersonalDemoCameraViewV1",
    "M8PersonalDemoKnowledgeReceiptV1",
    "M8PersonalDemoNotificationReceiptV1",
    "M8PersonalDemoRecordedMediaReceiptV1",
]

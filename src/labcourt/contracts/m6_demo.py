"""Canonical authority for the complete offline M6 demonstration."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Literal, Self

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.references import ReferenceToken, require_reference_token

MAX_M6_OFFLINE_DEMO_SCENARIO_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_M6_OFFLINE_DEMO_VERIFICATION_TARGET_CHARACTERS = 512
_VERIFICATION_TARGET = re.compile(
    r"^tests/(?:[a-z0-9_]+/)*test_[a-z0-9_]+\.py::test_[a-z0-9_]+$",
    flags=re.ASCII,
)


class M6OfflineDemoScenarioName(StrEnum):
    PRESENCE_TRUE_POSITIVE = "presence_true_positive"
    PRESENCE_FALSE_POSITIVE = "presence_false_positive"
    ABSENCE_TRUE_VIOLATION = "absence_true_violation"
    ABSENCE_DETECTOR_MISS_BUT_WORN = "absence_detector_miss_but_worn"
    ABSENCE_ALL_UNCLEAR = "absence_all_unclear"
    ABSENCE_DON_AFTER_THRESHOLD = "absence_don_after_threshold"
    LATE_RESULT_INSIDE_INTERVAL = "late_result_inside_interval"
    FABRICATED_CROP_REFERENCE = "fabricated_crop_reference"
    OBJECTIVE_PERSON_COUNT_CONFLICT = "objective_person_count_conflict"
    UNANSWERED_DEFENSE = "unanswered_defense"
    PRECEDENT_DIRECTION_MISMATCH = "precedent_direction_mismatch"
    PROVIDER_OUTAGE = "provider_outage"
    HARD_SIGNAL_UNCERTIFIED = "hard_signal_uncertified"
    APPEAL_OVERTURN = "appeal_overturn"
    REPLAY_LOCKED_IDENTICAL = "replay_locked_identical"
    UPGRADE_FLIP_GATE = "upgrade_flip_gate"


def _pop_claims(
    value: object,
    names: tuple[str, ...],
) -> tuple[object, dict[str, tuple[bool, object]]]:
    if not isinstance(value, dict):
        return value, {}
    payload = dict(value)
    claims = {name: (name in payload, payload.pop(name, None)) for name in names}
    return payload, claims


def _verify_claims(
    instance: FrozenContractModel,
    claims: dict[str, tuple[bool, object]],
) -> None:
    serialized = instance.model_dump(mode="json")
    for name, (present, claimed) in claims.items():
        if present and canonical_json(claimed) != canonical_json(serialized[name]):
            raise ValueError("serialized claim conflicts with derived M6 demo authority")


class M6OfflineDemoScenarioResultAuthorityV1(FrozenContractModel):
    schema_version: Literal["m6-offline-demo-scenario-result-authority-v1"] = (
        "m6-offline-demo-scenario-result-authority-v1"
    )
    scenario_name: M6OfflineDemoScenarioName
    classification: Literal["SYNTHETIC_PRECOMPUTED_FAKE"] = "SYNTHETIC_PRECOMPUTED_FAKE"
    status: Literal["PASSED"] = "PASSED"
    verification_kind: Literal["PYTEST_NODE"] = "PYTEST_NODE"
    verification_target: str = Field(
        min_length=1,
        max_length=MAX_M6_OFFLINE_DEMO_VERIFICATION_TARGET_CHARACTERS,
    )
    network_used: Literal[False] = False
    gpu_used: Literal[False] = False
    provider_called: Literal[False] = False

    @field_validator("verification_target")
    @classmethod
    def validate_verification_target(cls, value: str) -> str:
        if _VERIFICATION_TARGET.fullmatch(value) is None:
            raise ValueError("M6 demo verification target must be one exact pytest function node")
        return value

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(value, ("result_id",))
        result = handler(payload)
        _verify_claims(result, claims)
        return result

    @computed_field  # type: ignore[prop-decorator]
    @property
    def result_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-offline-demo-scenario-result",
                1,
                self.scenario_name,
                self.classification,
                self.status,
                self.verification_kind,
                self.verification_target,
                self.network_used,
                self.gpu_used,
                self.provider_called,
            ]
        )


class M6OfflineDemoScenarioArtifactReceiptV1(FrozenContractModel):
    schema_version: Literal["m6-offline-demo-scenario-artifact-receipt-v1"] = (
        "m6-offline-demo-scenario-artifact-receipt-v1"
    )
    scenario_name: M6OfflineDemoScenarioName
    artifact_content_sha256: Sha256Hex
    artifact_size_bytes: int = Field(
        gt=0,
        le=MAX_M6_OFFLINE_DEMO_SCENARIO_ARTIFACT_BYTES,
        strict=True,
    )

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(
            value,
            ("artifact_relative_path", "artifact_receipt_id"),
        )
        receipt = handler(payload)
        _verify_claims(receipt, claims)
        return receipt

    @computed_field  # type: ignore[prop-decorator]
    @property
    def artifact_relative_path(self) -> str:
        return f"demo/scenarios/{self.scenario_name.value}/result.json"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def artifact_receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-offline-demo-scenario-artifact-receipt",
                1,
                self.scenario_name,
                self.artifact_relative_path,
                self.artifact_content_sha256,
                self.artifact_size_bytes,
            ]
        )


class M6OfflineDemoManifestAuthorityV1(FrozenContractModel):
    schema_version: Literal["m6-offline-demo-manifest-authority-v1"] = (
        "m6-offline-demo-manifest-authority-v1"
    )
    candidate_run_id: ReferenceToken
    closed_regression_report_id: Sha256Hex
    closed_regression_publication_seal_id: Sha256Hex
    static_report_publication_seal_id: Sha256Hex
    static_report_index_content_sha256: Sha256Hex
    classification: Literal["SYNTHETIC_PRECOMPUTED_FAKE"] = "SYNTHETIC_PRECOMPUTED_FAKE"
    network_used: Literal[False] = False
    gpu_used: Literal[False] = False
    provider_called: Literal[False] = False
    scenario_receipts: tuple[M6OfflineDemoScenarioArtifactReceiptV1, ...] = Field(
        min_length=len(M6OfflineDemoScenarioName),
        max_length=len(M6OfflineDemoScenarioName),
    )

    @field_validator("candidate_run_id")
    @classmethod
    def validate_candidate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "M6 offline demo candidate run_id")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(
            value,
            ("scenario_count", "scenario_inventory_root_sha256", "demo_manifest_id"),
        )
        manifest = handler(payload)
        _verify_claims(manifest, claims)
        return manifest

    @model_validator(mode="after")
    def validate_exact_scenario_inventory(self) -> Self:
        canonical = tuple(
            M6OfflineDemoScenarioArtifactReceiptV1.model_validate(
                item.model_dump(mode="json", exclude_computed_fields=True)
            )
            for item in self.scenario_receipts
        )
        if tuple(item.scenario_name for item in canonical) != tuple(M6OfflineDemoScenarioName):
            raise ValueError("M6 offline demo requires the exact ordered scenario inventory")
        if canonical != self.scenario_receipts:
            raise ValueError("M6 offline demo scenario receipts must be canonical")
        object.__setattr__(self, "scenario_receipts", canonical)
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def scenario_count(self) -> int:
        return len(self.scenario_receipts)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def scenario_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-offline-demo-scenario-inventory",
                1,
                [item.artifact_receipt_id for item in self.scenario_receipts],
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def demo_manifest_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-offline-demo-manifest",
                1,
                self.candidate_run_id,
                self.closed_regression_report_id,
                self.closed_regression_publication_seal_id,
                self.static_report_publication_seal_id,
                self.static_report_index_content_sha256,
                self.classification,
                self.network_used,
                self.gpu_used,
                self.provider_called,
                self.scenario_inventory_root_sha256,
            ]
        )


__all__ = [
    "MAX_M6_OFFLINE_DEMO_SCENARIO_ARTIFACT_BYTES",
    "MAX_M6_OFFLINE_DEMO_VERIFICATION_TARGET_CHARACTERS",
    "M6OfflineDemoManifestAuthorityV1",
    "M6OfflineDemoScenarioArtifactReceiptV1",
    "M6OfflineDemoScenarioName",
    "M6OfflineDemoScenarioResultAuthorityV1",
]

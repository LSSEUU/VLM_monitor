"""M8 sensor sample, raw-signal, and durable poll-cache receipts."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import Field, ModelWrapValidatorHandler, computed_field, model_validator

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_sensor_signals import (
    MAX_M8_SENSOR_BATCH_SIZE,
    M8SensorPollResultV1,
    M8SensorSample,
)

MAX_M8_RAW_SIGNAL_BYTES = 1_048_576
MAX_M8_POLL_RAW_SIGNAL_BYTES = 67_108_864


def _pop_computed_claims(
    value: object,
    names: tuple[str, ...],
) -> tuple[object, dict[str, tuple[bool, object]]]:
    if not isinstance(value, dict):
        return value, {}
    payload = dict(value)
    claims = {name: (name in payload, payload.pop(name, None)) for name in names}
    return payload, claims


def _verify_computed_claims(
    instance: FrozenContractModel,
    claims: dict[str, tuple[bool, object]],
) -> None:
    serialized = instance.model_dump(mode="json")
    for name, (present, claimed) in claims.items():
        if present and canonical_json(claimed) != canonical_json(serialized[name]):
            raise ValueError(f"serialized {name} conflicts with derived M8 sensor receipt")


class M8SensorSampleCommitReceiptV1(FrozenContractModel):
    """Commit receipt for one sample and its separately stored exact raw bytes."""

    schema_version: Literal["m8-sensor-sample-commit-receipt-v1"] = (
        "m8-sensor-sample-commit-receipt-v1"
    )
    sample: M8SensorSample
    raw_signal_size_bytes: int = Field(
        gt=0,
        le=MAX_M8_RAW_SIGNAL_BYTES,
        strict=True,
    )
    resolved_source_catalog_commit_receipt_id: Sha256Hex
    raw_storage_manifest_id: Sha256Hex
    repository_manifest_id: Sha256Hex

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(
            value,
            ("sample_document_sha256", "commit_receipt_id"),
        )
        receipt = handler(payload)
        _verify_computed_claims(receipt, claims)
        return receipt

    @computed_field  # type: ignore[prop-decorator]
    @property
    def sample_document_sha256(self) -> Sha256Hex:
        return sha256_hex(self.sample.model_dump(mode="json"))

    @computed_field  # type: ignore[prop-decorator]
    @property
    def commit_receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-sensor-sample-commit-receipt",
                1,
                self.sample.sample_id,
                self.sample_document_sha256,
                self.sample.raw_signal_ref,
                self.sample.raw_signal_sha256,
                self.raw_signal_size_bytes,
                self.resolved_source_catalog_commit_receipt_id,
                self.raw_storage_manifest_id,
                self.repository_manifest_id,
            ]
        )


class M8SensorPollCacheCommitReceiptV1(FrozenContractModel):
    """Atomic durable-cache receipt closing a poll result over sample/raw commits."""

    schema_version: Literal["m8-sensor-poll-cache-commit-receipt-v1"] = (
        "m8-sensor-poll-cache-commit-receipt-v1"
    )
    poll_result: M8SensorPollResultV1
    sample_receipts: tuple[M8SensorSampleCommitReceiptV1, ...] = Field(
        max_length=MAX_M8_SENSOR_BATCH_SIZE
    )
    resolved_source_catalog_commit_receipt_id: Sha256Hex
    raw_storage_manifest_id: Sha256Hex
    cache_manifest_id: Sha256Hex
    repository_manifest_id: Sha256Hex

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(
            value,
            (
                "cache_key",
                "poll_result_document_sha256",
                "sample_receipt_inventory_sha256",
                "total_raw_signal_size_bytes",
                "commit_receipt_id",
            ),
        )
        receipt = handler(payload)
        _verify_computed_claims(receipt, claims)
        return receipt

    @model_validator(mode="after")
    def validate_closed_poll_commit(self) -> Self:
        if tuple(item.sample for item in self.sample_receipts) != self.poll_result.samples:
            raise ValueError("M8 poll cache sample receipts must exactly close the poll result")
        receipt_ids = tuple(item.commit_receipt_id for item in self.sample_receipts)
        if len(receipt_ids) != len(set(receipt_ids)):
            raise ValueError("M8 poll cache sample receipts must be unique")
        raw_refs = tuple(item.sample.raw_signal_ref for item in self.sample_receipts)
        if len(raw_refs) != len(set(raw_refs)):
            raise ValueError("M8 poll cache raw signal references must be unique")
        for item in self.sample_receipts:
            if (
                item.resolved_source_catalog_commit_receipt_id
                != self.resolved_source_catalog_commit_receipt_id
            ):
                raise ValueError("M8 poll cache sample uses another source catalog receipt")
            if item.raw_storage_manifest_id != self.raw_storage_manifest_id:
                raise ValueError("M8 poll cache sample uses another raw storage manifest")
            if item.repository_manifest_id != self.repository_manifest_id:
                raise ValueError("M8 poll cache sample uses another repository manifest")
        if self.total_raw_signal_size_bytes > MAX_M8_POLL_RAW_SIGNAL_BYTES:
            raise ValueError("M8 poll cache raw signal bytes exceed the bounded total")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def cache_key(self) -> Sha256Hex:
        return self.poll_result.request.cache_key

    @computed_field  # type: ignore[prop-decorator]
    @property
    def poll_result_document_sha256(self) -> Sha256Hex:
        return sha256_hex(self.poll_result.model_dump(mode="json"))

    @computed_field  # type: ignore[prop-decorator]
    @property
    def sample_receipt_inventory_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-sensor-sample-commit-receipt-inventory",
                1,
                [item.commit_receipt_id for item in self.sample_receipts],
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def total_raw_signal_size_bytes(self) -> int:
        return sum(item.raw_signal_size_bytes for item in self.sample_receipts)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def commit_receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-sensor-poll-cache-commit-receipt",
                1,
                self.poll_result.result_id,
                self.poll_result_document_sha256,
                self.cache_key,
                self.sample_receipt_inventory_sha256,
                self.total_raw_signal_size_bytes,
                self.resolved_source_catalog_commit_receipt_id,
                self.raw_storage_manifest_id,
                self.cache_manifest_id,
                self.repository_manifest_id,
            ]
        )


__all__ = [
    "MAX_M8_POLL_RAW_SIGNAL_BYTES",
    "MAX_M8_RAW_SIGNAL_BYTES",
    "M8SensorPollCacheCommitReceiptV1",
    "M8SensorSampleCommitReceiptV1",
]

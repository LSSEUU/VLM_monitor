from __future__ import annotations

import hashlib

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from labcourt.contracts.m8_operations import (
    M8OperationalSource,
    M8OperationalSourceMode,
    M8SensorType,
)
from labcourt.contracts.m8_sensor_persistence import (
    MAX_M8_RAW_SIGNAL_BYTES,
    M8SensorPollCacheCommitReceiptV1,
    M8SensorSampleCommitReceiptV1,
)
from labcourt.contracts.m8_sensor_signals import (
    M8SensorAdapterCapabilityAuthorityV1,
    M8SensorPollRequestV1,
    M8SensorPollResultV1,
    M8SensorQuality,
    M8SensorSample,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
RAW = b'{"simulated":true}\n'


def _result() -> M8SensorPollResultV1:
    source = M8OperationalSource(
        source_id="sensor-simulated-smoke-01",
        device_id="sensor-smoke-01",
        location_id="room-chem-301",
        mode=M8OperationalSourceMode.SIMULATED_SENSOR,
        sensor_type=M8SensorType.SMOKE,
        adapter_id="m8-offline-sensor-simulator",
        manifest_id=SHA_A,
    )
    capability = M8SensorAdapterCapabilityAuthorityV1(
        adapter_id=source.adapter_id,
        adapter_manifest_id=source.manifest_id,
        supported_source_modes=(M8OperationalSourceMode.SIMULATED_SENSOR,),
        supported_sensor_types=(M8SensorType.SMOKE,),
        offline_capable=True,
        network_required=False,
        deterministic_replay=True,
        raw_reference_required=True,
        max_batch_size=8,
        poll_timeout_ms=1_000,
    )
    request = M8SensorPollRequestV1(
        source_catalog_id=SHA_B,
        source=source,
        adapter_capability=capability,
        limit=1,
        timeout_ms=500,
    )
    sample = M8SensorSample(
        source_catalog_id=SHA_B,
        source=source,
        source_sequence=1,
        simulation_tick=5,
        value=True,
        quality=M8SensorQuality.GOOD,
        raw_signal_ref="m8/sensor-raw/scenario/1.json",
        raw_signal_sha256=hashlib.sha256(RAW).hexdigest(),
        adapter_input_authority_id=SHA_C,
        adapter_manifest_id=SHA_A,
    )
    return M8SensorPollResultV1(request=request, samples=(sample,), exhausted=True)


def _sample_receipt() -> M8SensorSampleCommitReceiptV1:
    return M8SensorSampleCommitReceiptV1(
        sample=_result().samples[0],
        raw_signal_size_bytes=len(RAW),
        resolved_source_catalog_commit_receipt_id=SHA_C,
        raw_storage_manifest_id=SHA_D,
        repository_manifest_id=SHA_A,
    )


def _poll_receipt() -> M8SensorPollCacheCommitReceiptV1:
    return M8SensorPollCacheCommitReceiptV1(
        poll_result=_result(),
        sample_receipts=(_sample_receipt(),),
        resolved_source_catalog_commit_receipt_id=SHA_C,
        raw_storage_manifest_id=SHA_D,
        cache_manifest_id=SHA_B,
        repository_manifest_id=SHA_A,
    )


def test_sample_receipt_binds_exact_sample_raw_metadata_and_manifests() -> None:
    receipt = _sample_receipt()
    assert receipt.raw_signal_size_bytes == len(RAW)
    assert len(receipt.sample_document_sha256) == 64
    assert len(receipt.commit_receipt_id) == 64

    with pytest.raises(ValidationError):
        receipt.model_copy(update={"raw_signal_size_bytes": MAX_M8_RAW_SIGNAL_BYTES + 1})


def test_poll_cache_receipt_closes_result_samples_raw_total_and_cache_key() -> None:
    receipt = _poll_receipt()
    assert receipt.cache_key == receipt.poll_result.request.cache_key
    assert receipt.total_raw_signal_size_bytes == len(RAW)
    assert receipt.sample_receipts[0].sample == receipt.poll_result.samples[0]
    assert len(receipt.sample_receipt_inventory_sha256) == 64
    assert len(receipt.commit_receipt_id) == 64


@pytest.mark.parametrize(
    ("field", "value", "match"),
    (
        ("sample_receipts", (), "exactly close"),
        ("resolved_source_catalog_commit_receipt_id", SHA_D, "source catalog"),
        ("raw_storage_manifest_id", SHA_A, "raw storage"),
        ("repository_manifest_id", SHA_B, "repository manifest"),
    ),
)
def test_poll_cache_receipt_rejects_grafted_closure(
    field: str,
    value: object,
    match: str,
) -> None:
    with pytest.raises(ValidationError, match=match):
        _poll_receipt().model_copy(update={field: value})


@pytest.mark.parametrize(
    "field",
    (
        "cache_key",
        "poll_result_document_sha256",
        "sample_receipt_inventory_sha256",
        "total_raw_signal_size_bytes",
        "commit_receipt_id",
    ),
)
def test_poll_cache_receipt_rejects_serialized_computed_forgery(field: str) -> None:
    payload = _poll_receipt().model_dump(mode="json")
    payload[field] = 999 if field == "total_raw_signal_size_bytes" else "0" * 64
    with pytest.raises(ValidationError, match=field):
        M8SensorPollCacheCommitReceiptV1.model_validate(payload)


def test_sensor_persistence_receipts_validate_as_serialization_schemas() -> None:
    sample = _sample_receipt()
    poll = _poll_receipt()
    Draft202012Validator(
        M8SensorSampleCommitReceiptV1.model_json_schema(mode="serialization")
    ).validate(sample.model_dump(mode="json"))
    Draft202012Validator(
        M8SensorPollCacheCommitReceiptV1.model_json_schema(mode="serialization")
    ).validate(poll.model_dump(mode="json"))


def test_sensor_persistence_receipt_schemas_are_registered() -> None:
    from labcourt.schema_registry import SCHEMA_MODELS, SCHEMA_VALIDATION_MODELS

    expected = {
        "m8-sensor-poll-cache-commit-receipt-v1": M8SensorPollCacheCommitReceiptV1,
        "m8-sensor-sample-commit-receipt-v1": M8SensorSampleCommitReceiptV1,
    }
    assert {name: SCHEMA_MODELS[name] for name in expected} == expected
    assert expected.keys().isdisjoint(SCHEMA_VALIDATION_MODELS)

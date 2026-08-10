"""Pure construction of durable M8 sensor poll-cache receipts."""

from __future__ import annotations

import hashlib

from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_inventory_persistence import (
    M8OperationalSourceCatalogCommitReceiptV1,
)
from labcourt.contracts.m8_sensor_persistence import (
    M8SensorPollCacheCommitReceiptV1,
    M8SensorSampleCommitReceiptV1,
)
from labcourt.contracts.m8_sensor_signals import M8SensorPollResultV1


def build_sensor_poll_cache_commit(
    result: M8SensorPollResultV1,
    raw_signals: tuple[bytes, ...],
    resolved_catalog: M8OperationalSourceCatalogCommitReceiptV1,
    raw_storage_manifest_id: Sha256Hex,
    cache_manifest_id: Sha256Hex,
    repository_manifest_id: Sha256Hex,
) -> M8SensorPollCacheCommitReceiptV1:
    if result.request.source_catalog_id != resolved_catalog.catalog.catalog_id:
        raise ValueError("M8 sensor poll references another persisted source catalog")
    if result.request.source not in resolved_catalog.catalog.sources:
        raise ValueError("M8 sensor poll source is absent from the persisted source catalog")
    if len(raw_signals) != len(result.samples):
        raise ValueError("M8 sensor poll requires exactly one raw payload per sample")

    sample_receipts: list[M8SensorSampleCommitReceiptV1] = []
    for sample, raw_signal in zip(result.samples, raw_signals, strict=True):
        if not isinstance(raw_signal, bytes):
            raise TypeError("M8 raw signals must be exact bytes")
        if hashlib.sha256(raw_signal).hexdigest() != sample.raw_signal_sha256:
            raise ValueError("M8 raw signal bytes conflict with the sample hash")
        sample_receipts.append(
            M8SensorSampleCommitReceiptV1(
                sample=sample,
                raw_signal_size_bytes=len(raw_signal),
                resolved_source_catalog_commit_receipt_id=resolved_catalog.commit_receipt_id,
                raw_storage_manifest_id=raw_storage_manifest_id,
                repository_manifest_id=repository_manifest_id,
            )
        )
    return M8SensorPollCacheCommitReceiptV1(
        poll_result=result,
        sample_receipts=tuple(sample_receipts),
        resolved_source_catalog_commit_receipt_id=resolved_catalog.commit_receipt_id,
        raw_storage_manifest_id=raw_storage_manifest_id,
        cache_manifest_id=cache_manifest_id,
        repository_manifest_id=repository_manifest_id,
    )


__all__ = ["build_sensor_poll_cache_commit"]

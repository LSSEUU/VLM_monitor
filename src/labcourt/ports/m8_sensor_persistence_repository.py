"""Persistence port for M8 typed samples, exact raw bytes, and poll cache."""

from __future__ import annotations

from typing import Protocol

from labcourt.contracts.m8_sensor_persistence import (
    M8SensorPollCacheCommitReceiptV1,
    M8SensorSampleCommitReceiptV1,
)
from labcourt.contracts.m8_sensor_signals import M8SensorPollResultV1


class M8SensorPersistenceRepository(Protocol):
    def commit_poll_result(
        self,
        result: M8SensorPollResultV1,
        raw_signals: tuple[bytes, ...],
        raw_storage_manifest_id: str,
        cache_manifest_id: str,
    ) -> M8SensorPollCacheCommitReceiptV1: ...

    def get_poll_cache(self, request_id: str) -> M8SensorPollCacheCommitReceiptV1: ...

    def get_sample(self, sample_id: str) -> M8SensorSampleCommitReceiptV1: ...

    def list_latest_sensor_samples(
        self,
        limit: int,
    ) -> tuple[M8SensorSampleCommitReceiptV1, ...]: ...

    def read_raw_signal(self, raw_signal_ref: str) -> bytes: ...


__all__ = ["M8SensorPersistenceRepository"]

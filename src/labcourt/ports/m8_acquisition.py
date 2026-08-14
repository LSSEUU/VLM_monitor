"""Composition ports for additive M8 recorded-run acquisition."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from labcourt.contracts.m8_acquisition_v2 import (
    M8HearingAcquisitionResultV2,
    M8RedetectionDetectorRequestV1,
    M8ResolvedRecordedRunSourceV1,
)
from labcourt.contracts.manifests import RunManifest


class M8RecordedRunSourceResolver(Protocol):
    """Resolve one immutable persisted media sidecar for an exact run."""

    @property
    def project_root(self) -> Path: ...

    def resolve(
        self,
        run_id: str,
        manifest: RunManifest,
        *,
        max_input_bytes: int,
    ) -> M8ResolvedRecordedRunSourceV1: ...


class M8HighResolutionRedetector(Protocol):
    """Strict local detector.  Bytes are parsed and journaled by the caller."""

    @property
    def component_manifest_id(self) -> str: ...

    @property
    def model_manifest_id(self) -> str: ...

    def execute(
        self,
        request: M8RedetectionDetectorRequestV1,
        *,
        idempotency_key: str,
    ) -> bytes: ...

    def recover(
        self,
        request: M8RedetectionDetectorRequestV1,
        *,
        idempotency_key: str,
    ) -> bytes | None: ...


class M8AcquisitionOutcomeRepository(Protocol):
    """Durable additive outcomes addressable without exposing artifact paths."""

    def put(self, outcome: M8HearingAcquisitionResultV2) -> M8HearingAcquisitionResultV2: ...

    def get(self, run_id: str, request_id: str) -> M8HearingAcquisitionResultV2 | None: ...

    def list_for_case(
        self,
        run_id: str,
        case_id: str,
    ) -> tuple[M8HearingAcquisitionResultV2, ...]: ...


__all__ = [
    "M8AcquisitionOutcomeRepository",
    "M8HighResolutionRedetector",
    "M8RecordedRunSourceResolver",
]

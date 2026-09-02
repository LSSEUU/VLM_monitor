"""Role-scoped verified reads of the personal Demo recorded camera media."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, TypeVar

from pydantic import ValidationError

from labcourt.contracts.m8_access_cases import M8ActorAuthorityV1, M8ActorRole
from labcourt.contracts.m8_api import M8ApiPrincipalV1
from labcourt.contracts.m8_operations import M8OperationalSourceMode
from labcourt.contracts.m8_personal_demo import (
    M8PersonalDemoCameraViewV1,
    M8PersonalDemoRecordedMediaReceiptV1,
)
from labcourt.exceptions import BudgetExceeded, ConcurrentModification, EvidenceMissing
from labcourt.ports.m8_inventory_repository import M8InventoryRepository
from labcourt.ports.m8_operations_repository import M8OperationsRepository
from labcourt.services.m8_operations_api import M8ApiServiceError, M8ApiServiceFailureCode

_CHUNK_SIZE = 1024 * 1024
_MAX_RECEIPT_BYTES = 256 * 1024
_T = TypeVar("_T")


@dataclass(frozen=True, slots=True)
class M8OpenedRecordedMedia:
    receipt: M8PersonalDemoRecordedMediaReceiptV1
    handle: BinaryIO
    size_bytes: int


class M8RecordedMediaApiService:
    def __init__(
        self,
        artifact_root: Path,
        inventory_repository: M8InventoryRepository,
        operations_repository: M8OperationsRepository,
        camera_view_manifest_id: str,
    ) -> None:
        self._artifact_root = artifact_root.resolve()
        self._inventory = inventory_repository
        self._operations = operations_repository
        self._camera_view_manifest_id = camera_view_manifest_id

    def cameras(
        self,
        principal: M8ApiPrincipalV1,
    ) -> tuple[M8PersonalDemoCameraViewV1, ...]:
        actor = self._actor(principal)
        if actor.role not in {M8ActorRole.OPERATIONS, M8ActorRole.SAFETY_OFFICER}:
            return ()
        catalog = self._call(lambda: self._inventory.get_current_source_catalog("campus-demo"))
        cameras = tuple(
            source
            for source in catalog.catalog.sources
            if source.mode == M8OperationalSourceMode.RECORDED_VIDEO_SIMULATION
        )
        views: list[M8PersonalDemoCameraViewV1] = []
        for source in cameras:
            binding = None
            if (self._artifact_root / "camera-media-receipt.json").exists():
                with self.open_verified(principal, source.source_id) as opened:
                    binding = opened.receipt
            views.append(
                M8PersonalDemoCameraViewV1(
                    source_catalog_id=catalog.catalog.catalog_id,
                    source_catalog_commit_receipt_id=catalog.commit_receipt_id,
                    source=source,
                    media_attached=binding is not None,
                    media_binding=binding,
                    camera_view_manifest_id=self._camera_view_manifest_id,
                )
            )
        return tuple(views)

    def metadata(
        self,
        principal: M8ApiPrincipalV1,
        source_id: str,
    ) -> M8PersonalDemoRecordedMediaReceiptV1:
        with self.open_verified(principal, source_id) as opened:
            return opened.receipt

    @contextmanager
    def open_verified(
        self,
        principal: M8ApiPrincipalV1,
        source_id: str,
    ) -> Iterator[M8OpenedRecordedMedia]:
        self._authorize(principal)
        receipt = self._receipt(source_id)
        catalog = self._call(lambda: self._inventory.get_current_source_catalog("campus-demo"))
        if (
            catalog.catalog.catalog_id != receipt.source_catalog_id
            or catalog.commit_receipt_id != receipt.source_catalog_commit_receipt_id
            or not any(source.source_id == receipt.source_id for source in catalog.catalog.sources)
        ):
            raise M8ApiServiceError(M8ApiServiceFailureCode.CONCURRENT_MODIFICATION)

        media_path = self._artifact_root / receipt.playback_media_ref
        try:
            handle = media_path.open("rb")
        except FileNotFoundError as error:
            raise M8ApiServiceError(M8ApiServiceFailureCode.RESOURCE_NOT_FOUND) from error
        try:
            stat = os.fstat(handle.fileno())
            digest = hashlib.sha256()
            size = 0
            while chunk := handle.read(_CHUNK_SIZE):
                digest.update(chunk)
                size += len(chunk)
            if (
                not stat.st_size == size == receipt.playback_size_bytes
                or digest.hexdigest() != receipt.playback_file_sha256
            ):
                raise M8ApiServiceError(M8ApiServiceFailureCode.CONCURRENT_MODIFICATION)
            handle.seek(0)
            yield M8OpenedRecordedMedia(receipt=receipt, handle=handle, size_bytes=size)
        finally:
            handle.close()

    def _authorize(self, principal: M8ApiPrincipalV1) -> None:
        actor = self._actor(principal)
        if actor.role not in {M8ActorRole.OPERATIONS, M8ActorRole.SAFETY_OFFICER}:
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)

    def _actor(self, principal: M8ApiPrincipalV1) -> M8ActorAuthorityV1:
        if not isinstance(principal, M8ApiPrincipalV1):
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        actor_receipt = self._call(
            lambda: self._operations.get_current_actor_authority(principal.actor_id)
        )
        actor = actor_receipt.authority
        if not actor.active or actor.actor_id != principal.actor_id:
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        return actor

    def _receipt(self, source_id: str) -> M8PersonalDemoRecordedMediaReceiptV1:
        if source_id != "camera-recorded-demo-01":
            raise M8ApiServiceError(M8ApiServiceFailureCode.RESOURCE_NOT_FOUND)
        receipt_path = self._artifact_root / "camera-media-receipt.json"
        try:
            stat = receipt_path.stat()
            if not receipt_path.is_file() or not 0 < stat.st_size <= _MAX_RECEIPT_BYTES:
                raise M8ApiServiceError(M8ApiServiceFailureCode.INTERNAL_FAILURE)
            return M8PersonalDemoRecordedMediaReceiptV1.model_validate_json(
                receipt_path.read_bytes()
            )
        except FileNotFoundError as error:
            raise M8ApiServiceError(M8ApiServiceFailureCode.RESOURCE_NOT_FOUND) from error
        except ValidationError as error:
            raise M8ApiServiceError(M8ApiServiceFailureCode.INTERNAL_FAILURE) from error

    @staticmethod
    def _call(function: Callable[[], _T]) -> _T:
        try:
            return function()
        except EvidenceMissing as error:
            raise M8ApiServiceError(M8ApiServiceFailureCode.RESOURCE_NOT_FOUND) from error
        except ConcurrentModification as error:
            raise M8ApiServiceError(M8ApiServiceFailureCode.CONCURRENT_MODIFICATION) from error
        except BudgetExceeded as error:
            raise M8ApiServiceError(M8ApiServiceFailureCode.INTERNAL_FAILURE) from error


__all__ = ["M8OpenedRecordedMedia", "M8RecordedMediaApiService"]

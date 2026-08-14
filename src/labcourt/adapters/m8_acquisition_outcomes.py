"""Immutable filesystem repository for additive M8 acquisition outcomes."""

from __future__ import annotations

import hashlib
from pathlib import Path

from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m8_acquisition_v2 import M8HearingAcquisitionResultV2
from labcourt.contracts.references import require_portable_run_id, require_reference_token
from labcourt.exceptions import ArtifactConflict, PathBoundaryViolation


class PersistedM8AcquisitionOutcomeRepository:
    """Store one immutable document per acquisition request and list by Case."""

    __slots__ = ("_max_document_bytes", "_workspace_root")

    def __init__(self, *, workspace_root: Path, max_document_bytes: int) -> None:
        if not isinstance(workspace_root, Path):
            raise TypeError("M8 acquisition outcome workspace_root must be a Path")
        if (
            not isinstance(max_document_bytes, int)
            or isinstance(max_document_bytes, bool)
            or max_document_bytes <= 0
        ):
            raise ValueError("M8 acquisition outcome document limit must be positive")
        self._workspace_root = workspace_root.absolute()
        self._max_document_bytes = max_document_bytes

    def put(
        self,
        outcome: M8HearingAcquisitionResultV2,
    ) -> M8HearingAcquisitionResultV2:
        if not isinstance(outcome, M8HearingAcquisitionResultV2):
            raise TypeError("outcome repository requires an M8 acquisition outcome")
        path = self._path(outcome.run_id, outcome.acquisition_request_id)
        body = canonical_json(outcome.model_dump(mode="json", exclude_computed_fields=True)).encode(
            "utf-8"
        )
        if len(body) > self._max_document_bytes:
            raise ValueError("M8 acquisition outcome exceeds its document limit")
        digest = hashlib.sha256(body).hexdigest()
        with SecureWorkspace(
            self._workspace_root,
            max_file_bytes=self._max_document_bytes,
        ) as workspace:
            workspace.ensure_private_directory(outcome.run_id)
            workspace.ensure_private_directory(f"{outcome.run_id}/acquisition-v2")
            try:
                workspace.create_new(path, body, digest)
            except ArtifactConflict:
                existing = workspace.read_verified(path)
                if existing.bytes != body:
                    raise ArtifactConflict("M8_ACQUISITION_OUTCOME_CONFLICT", path) from None
        return outcome

    def get(
        self,
        run_id: str,
        request_id: str,
    ) -> M8HearingAcquisitionResultV2 | None:
        path = self._path(run_id, request_id)
        with SecureWorkspace(
            self._workspace_root,
            max_file_bytes=self._max_document_bytes,
        ) as workspace:
            try:
                snapshot = workspace.read_verified(path)
            except PathBoundaryViolation as error:
                if error.reason_code == "FILE_MISSING":
                    return None
                raise
        outcome = M8HearingAcquisitionResultV2.model_validate_json(snapshot.bytes)
        if outcome.run_id != run_id or outcome.acquisition_request_id != request_id:
            raise ValueError("persisted acquisition outcome conflicts with its address")
        return outcome

    def list_for_case(
        self,
        run_id: str,
        case_id: str,
    ) -> tuple[M8HearingAcquisitionResultV2, ...]:
        controlled_run = require_portable_run_id(run_id, "M8 acquisition outcome run_id")
        controlled_case = require_reference_token(case_id, "M8 acquisition outcome case_id")
        relative_directory = Path(controlled_run) / "acquisition-v2"
        directory = (self._workspace_root / relative_directory).absolute()
        directory.relative_to(self._workspace_root)
        if not directory.is_dir():
            return ()
        request_ids = tuple(
            sorted(
                path.stem
                for path in directory.glob("*.json")
                if path.is_file()
                and len(path.stem) == 64
                and all(character in "0123456789abcdef" for character in path.stem)
            )
        )
        outcomes = tuple(
            outcome
            for request_id in request_ids
            if (outcome := self.get(controlled_run, request_id)) is not None
            and outcome.case_id == controlled_case
        )
        return tuple(
            sorted(
                outcomes,
                key=lambda item: (item.acquisition_request_id, item.result_id),
            )
        )

    @staticmethod
    def _path(run_id: str, request_id: str) -> str:
        controlled_run = require_portable_run_id(run_id, "M8 acquisition outcome run_id")
        if (
            not isinstance(request_id, str)
            or len(request_id) != 64
            or any(character not in "0123456789abcdef" for character in request_id)
        ):
            raise ValueError("M8 acquisition request ID must be a SHA-256")
        return f"{controlled_run}/acquisition-v2/{request_id}.json"


__all__ = ["PersistedM8AcquisitionOutcomeRepository"]

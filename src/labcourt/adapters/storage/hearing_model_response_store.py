"""Crash-recoverable owner-only storage for exact M4 hearing response bytes."""

from __future__ import annotations

import hashlib
from typing import NoReturn

from labcourt.adapters.storage._hearing_response_journal import (
    MAX_HEARING_JOURNAL_BYTES,
    build_hearing_response,
    decode_hearing_response_journal,
    encode_hearing_response_journal,
    expected_hearing_response_id,
    hearing_response_matches_request,
    hearing_response_within_request_budget,
    require_hearing_request,
    require_hearing_response,
)
from labcourt.adapters.storage.secure_workspace import SecureFileSnapshot, SecureWorkspace
from labcourt.contracts.hearing import HearingModelRequest, HearingModelResponse
from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import (
    ArtifactConflict,
    ArtifactIntegrityViolation,
    PathBoundaryViolation,
)
from labcourt.ports.hearing_vlm import (
    HearingModelResponseStoreError,
    HearingModelResponseStoreFailureCode,
)


class SecureHearingModelResponseStore:
    """Journal, publish, recover, and verify M4 raw response bytes.

    The final raw body shares the established private
    ``<run>/model_responses`` boundary, while every journal byte and binding is
    M4-specific.  Recovery has no provider, parser, or case-state capability.
    """

    __slots__ = ("_workspace",)

    def __init__(self, workspace: SecureWorkspace) -> None:
        if not isinstance(workspace, SecureWorkspace):
            raise TypeError("workspace must be a SecureWorkspace")
        self._workspace = workspace

    def __repr__(self) -> str:
        return "SecureHearingModelResponseStore()"

    def publish(
        self,
        request: HearingModelRequest,
        raw_response: bytes,
        *,
        input_tokens: int = 0,
        output_tokens: int = 0,
        latency_ms: int = 0,
    ) -> HearingModelResponse:
        """Persist raw, then its durable journal, before atomic publication."""

        request = require_hearing_request(request)
        if not isinstance(raw_response, bytes):
            self._raise(HearingModelResponseStoreFailureCode.INVALID_ARGUMENT)
        metrics = (input_tokens, output_tokens, latency_ms)
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in metrics
        ):
            self._raise(HearingModelResponseStoreFailureCode.INVALID_ARGUMENT)
        if (
            len(raw_response) > request.budget.max_response_bytes
            or input_tokens > request.budget.max_input_tokens
            or output_tokens > request.budget.max_output_tokens
            or not request.budget.allows_cost(
                input_tokens=input_tokens,
                output_tokens=output_tokens,
            )
        ):
            self._raise(HearingModelResponseStoreFailureCode.CALL_BUDGET_EXCEEDED)

        content_sha256 = hashlib.sha256(raw_response).hexdigest()
        response_id = expected_hearing_response_id(request, content_sha256)
        staged_directory = self._staged_directory(request.run_id, response_id)
        staged_relative = f"{staged_directory}/response.json"
        journal_directory, journal_relative = self._journal_paths(request)
        final_relative = self._final_path(request.run_id, response_id)
        response = build_hearing_response(
            request,
            final_relative=final_relative,
            content_sha256=content_sha256,
            size_bytes=len(raw_response),
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency_ms=latency_ms,
        )
        journal_bytes = encode_hearing_response_journal(request, response)

        try:
            for directory in (
                ".staging",
                f".staging/{request.run_id}",
                staged_directory,
                journal_directory,
                request.run_id,
                f"{request.run_id}/model_responses",
            ):
                self._workspace.ensure_private_directory(directory)
            self._persist_staged_bytes(staged_relative, raw_response, content_sha256)
            self._persist_journal(journal_relative, journal_bytes)
            published = self._workspace.publish_hearing_model_response_staged(
                staged_relative,
                final_relative,
                content_sha256,
                max_bytes=len(raw_response),
            )
            self._verify_snapshot(
                published,
                relative_path=final_relative,
                content_sha256=content_sha256,
                raw_response=raw_response,
            )
            reopened = self._workspace.read_verified(
                final_relative,
                content_sha256,
                max_bytes=len(raw_response),
            )
            self._verify_snapshot(
                reopened,
                relative_path=final_relative,
                content_sha256=content_sha256,
                raw_response=raw_response,
            )
            self._workspace.remove_empty_hearing_model_response_staging_directory(staged_directory)
        except HearingModelResponseStoreError:
            raise
        except ArtifactConflict:
            self._raise(HearingModelResponseStoreFailureCode.RESPONSE_CONFLICT)
        except ArtifactIntegrityViolation:
            self._raise(HearingModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE)
        except PathBoundaryViolation as error:
            self._raise(self._path_failure(error))
        except Exception:
            self._raise(HearingModelResponseStoreFailureCode.WORKSPACE_REJECTED)
        return response

    def probe_recovery(
        self,
        request: HearingModelRequest,
    ) -> HearingModelResponse | None:
        """Read and verify a crash prefix without mutating it."""

        request = require_hearing_request(request)
        _journal_directory, journal_relative = self._journal_paths(request)
        try:
            try:
                journal = self._workspace.read_verified(
                    journal_relative,
                    max_bytes=min(
                        MAX_HEARING_JOURNAL_BYTES,
                        self._workspace.max_file_bytes,
                    ),
                )
            except PathBoundaryViolation as error:
                if error.reason_code == "FILE_MISSING":
                    return None
                raise
            response = decode_hearing_response_journal(
                request,
                journal,
                expected_relative_path=journal_relative,
            )
            staged_relative = self._staged_path(request.run_id, response.response_id)
            observed = False
            for relative_path in (staged_relative, response.raw_response_ref):
                try:
                    snapshot = self._workspace.read_verified(
                        relative_path,
                        response.content_sha256,
                        max_bytes=response.size_bytes,
                    )
                except PathBoundaryViolation as error:
                    if error.reason_code == "FILE_MISSING":
                        continue
                    raise
                self._verify_receipt_snapshot(snapshot, relative_path, response)
                observed = True
            if not observed:
                self._raise(HearingModelResponseStoreFailureCode.RESPONSE_NOT_FOUND)
            return response
        except HearingModelResponseStoreError:
            raise
        except ArtifactConflict:
            self._raise(HearingModelResponseStoreFailureCode.RESPONSE_CONFLICT)
        except ArtifactIntegrityViolation:
            self._raise(HearingModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE)
        except PathBoundaryViolation as error:
            self._raise(self._path_failure(error))
        except Exception:
            self._raise(HearingModelResponseStoreFailureCode.WORKSPACE_REJECTED)

    def recover(
        self,
        request: HearingModelRequest,
    ) -> HearingModelResponse | None:
        """Converge one exact journaled response without calling a provider."""

        request = require_hearing_request(request)
        _journal_directory, journal_relative = self._journal_paths(request)
        try:
            try:
                journal = self._workspace.read_verified(
                    journal_relative,
                    max_bytes=min(
                        MAX_HEARING_JOURNAL_BYTES,
                        self._workspace.max_file_bytes,
                    ),
                )
            except PathBoundaryViolation as error:
                if error.reason_code == "FILE_MISSING":
                    return None
                raise
            response = decode_hearing_response_journal(
                request,
                journal,
                expected_relative_path=journal_relative,
            )
            staged_directory = self._staged_directory(
                request.run_id,
                response.response_id,
            )
            staged_relative = f"{staged_directory}/response.json"
            final_relative = response.raw_response_ref
            try:
                staged: SecureFileSnapshot | None = self._workspace.read_verified(
                    staged_relative,
                    response.content_sha256,
                    max_bytes=response.size_bytes,
                )
            except PathBoundaryViolation as error:
                if error.reason_code == "FILE_MISSING":
                    staged = None
                else:
                    raise
            if staged is not None:
                self._verify_receipt_snapshot(staged, staged_relative, response)
                published = self._workspace.publish_hearing_model_response_staged(
                    staged_relative,
                    final_relative,
                    response.content_sha256,
                    max_bytes=response.size_bytes,
                )
                self._verify_receipt_snapshot(published, final_relative, response)
            final = self._workspace.read_verified(
                final_relative,
                response.content_sha256,
                max_bytes=response.size_bytes,
            )
            self._verify_receipt_snapshot(final, final_relative, response)
            self._workspace.remove_empty_hearing_model_response_staging_directory(staged_directory)
            return response
        except HearingModelResponseStoreError:
            raise
        except ArtifactConflict:
            self._raise(HearingModelResponseStoreFailureCode.RESPONSE_CONFLICT)
        except ArtifactIntegrityViolation:
            self._raise(HearingModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE)
        except PathBoundaryViolation as error:
            self._raise(self._path_failure(error))
        except Exception:
            self._raise(HearingModelResponseStoreFailureCode.WORKSPACE_REJECTED)

    def acknowledge(
        self,
        request: HearingModelRequest,
        response: HearingModelResponse,
    ) -> None:
        """Delete only the exact journal after durable business acknowledgement."""

        request = require_hearing_request(request)
        response = require_hearing_response(response)
        if not hearing_response_matches_request(request, response):
            self._raise(HearingModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE)
        journal_directory, journal_relative = self._journal_paths(request)
        recovered = self.recover(request)
        if recovered is None:
            # A raced or repeated acknowledgement is benign only while the
            # exact final response remains physically valid.
            self.verify_raw_response(request.run_id, request, response)
            try:
                self._workspace.remove_empty_hearing_model_response_journal_directory(
                    journal_directory
                )
            except ArtifactConflict:
                self._raise(HearingModelResponseStoreFailureCode.RESPONSE_CONFLICT)
            except PathBoundaryViolation:
                self._raise(HearingModelResponseStoreFailureCode.WORKSPACE_REJECTED)
            return
        if recovered != response:
            self._raise(HearingModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE)
        journal_bytes = encode_hearing_response_journal(request, recovered)
        journal_file_sha256 = hashlib.sha256(journal_bytes).hexdigest()
        try:
            try:
                self._workspace.delete_verified_hearing_model_response_journal(
                    journal_relative,
                    journal_file_sha256,
                )
            except PathBoundaryViolation as error:
                if error.reason_code != "FILE_MISSING":
                    raise
            self._workspace.remove_empty_hearing_model_response_journal_directory(journal_directory)
        except ArtifactConflict:
            self._raise(HearingModelResponseStoreFailureCode.RESPONSE_CONFLICT)
        except ArtifactIntegrityViolation:
            self._raise(HearingModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE)
        except PathBoundaryViolation:
            self._raise(HearingModelResponseStoreFailureCode.WORKSPACE_REJECTED)
        except Exception:
            self._raise(HearingModelResponseStoreFailureCode.WORKSPACE_REJECTED)

    def read_bytes(
        self,
        run_id: str,
        response: HearingModelResponse,
        max_bytes: int,
    ) -> bytes:
        """Read exact bytes through the same verified handle used for hashing."""

        if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 0:
            self._raise(HearingModelResponseStoreFailureCode.INVALID_ARGUMENT)
        response = require_hearing_response(response)
        expected_path = self._require_scope(run_id, response)
        if response.size_bytes > max_bytes:
            self._raise(HearingModelResponseStoreFailureCode.READ_LIMIT_EXCEEDED)
        try:
            snapshot = self._workspace.read_verified(
                expected_path,
                response.content_sha256,
                max_bytes=response.size_bytes,
            )
        except ArtifactIntegrityViolation:
            self._raise(HearingModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE)
        except PathBoundaryViolation as error:
            self._raise(self._path_failure(error))
        except Exception:
            self._raise(HearingModelResponseStoreFailureCode.WORKSPACE_REJECTED)
        if (
            snapshot.relative_path != expected_path
            or snapshot.sha256 != response.content_sha256
            or snapshot.size_bytes != response.size_bytes
        ):
            self._raise(HearingModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE)
        return snapshot.bytes

    def read_json(
        self,
        run_id: str,
        response: HearingModelResponse,
        max_bytes: int,
    ) -> str:
        """Decode UTF-8 only; strict JSON parsing remains a separate boundary."""

        try:
            return self.read_bytes(run_id, response, max_bytes).decode("utf-8")
        except UnicodeDecodeError:
            self._raise(HearingModelResponseStoreFailureCode.RESPONSE_UTF8_INVALID)

    def verify(
        self,
        run_id: str,
        response: HearingModelResponse,
    ) -> HearingModelResponse:
        """Reopen and verify one typed response receipt and its physical bytes."""

        response = require_hearing_response(response)
        expected_path = self._require_scope(run_id, response)
        try:
            snapshot = self._workspace.read_verified(
                expected_path,
                response.content_sha256,
                max_bytes=response.size_bytes,
            )
        except ArtifactIntegrityViolation:
            self._raise(HearingModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE)
        except PathBoundaryViolation as error:
            self._raise(self._path_failure(error))
        except Exception:
            self._raise(HearingModelResponseStoreFailureCode.WORKSPACE_REJECTED)
        self._verify_receipt_snapshot(snapshot, expected_path, response)
        return response

    def verify_raw_response(
        self,
        run_id: str,
        request: HearingModelRequest,
        response: HearingModelResponse,
    ) -> HearingModelResponse:
        """Verify exact request binding, budgets, receipt, and physical raw bytes."""

        request = require_hearing_request(request)
        response = require_hearing_response(response)
        if (
            request.run_id != run_id
            or not hearing_response_matches_request(request, response)
            or not hearing_response_within_request_budget(request, response)
        ):
            self._raise(HearingModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE)
        return self.verify(run_id, response)

    def _persist_staged_bytes(
        self,
        relative_path: str,
        raw_response: bytes,
        content_sha256: str,
    ) -> None:
        try:
            self._workspace.create_new(relative_path, raw_response, content_sha256)
        except ArtifactConflict as error:
            if error.reason_code != "TARGET_ALREADY_EXISTS":
                raise
            try:
                staged = self._workspace.read_verified(
                    relative_path,
                    content_sha256,
                    max_bytes=len(raw_response),
                )
            except (ArtifactIntegrityViolation, PathBoundaryViolation):
                raise ArtifactConflict("STAGING_CONTENT_CONFLICT") from None
            self._verify_snapshot(
                staged,
                relative_path=relative_path,
                content_sha256=content_sha256,
                raw_response=raw_response,
            )

    def _persist_journal(self, relative_path: str, journal_bytes: bytes) -> None:
        journal_file_sha256 = hashlib.sha256(journal_bytes).hexdigest()
        try:
            self._workspace.create_new(
                relative_path,
                journal_bytes,
                journal_file_sha256,
            )
        except ArtifactConflict as error:
            if error.reason_code != "TARGET_ALREADY_EXISTS":
                raise
            try:
                existing = self._workspace.read_verified(
                    relative_path,
                    journal_file_sha256,
                    max_bytes=len(journal_bytes),
                )
            except (ArtifactIntegrityViolation, PathBoundaryViolation):
                raise ArtifactConflict("JOURNAL_CONTENT_CONFLICT") from None
            if existing.bytes != journal_bytes or existing.size_bytes != len(journal_bytes):
                raise ArtifactConflict("JOURNAL_CONTENT_CONFLICT") from None

    @staticmethod
    def _journal_paths(request: HearingModelRequest) -> tuple[str, str]:
        directory = f".staging/{request.run_id}/hearing-model-request-{request.request_id}"
        return directory, f"{directory}/receipt.json"

    @staticmethod
    def _staged_directory(run_id: str, response_id: str) -> str:
        return f".staging/{run_id}/hearing-model-response-{response_id}"

    @classmethod
    def _staged_path(cls, run_id: str, response_id: str) -> str:
        return f"{cls._staged_directory(run_id, response_id)}/response.json"

    @staticmethod
    def _final_path(run_id: str, response_id: str) -> str:
        return f"{run_id}/model_responses/{response_id}.json"

    @classmethod
    def _require_scope(
        cls,
        run_id: str,
        response: HearingModelResponse,
    ) -> str:
        try:
            controlled_run_id = require_reference_token(
                run_id,
                "hearing model response run_id",
            )
        except (TypeError, ValueError):
            cls._raise(HearingModelResponseStoreFailureCode.INVALID_ARGUMENT)
        expected_path = cls._final_path(controlled_run_id, response.response_id)
        if response.run_id != controlled_run_id or response.raw_response_ref != expected_path:
            cls._raise(HearingModelResponseStoreFailureCode.RUN_SCOPE_MISMATCH)
        return expected_path

    @staticmethod
    def _verify_snapshot(
        snapshot: SecureFileSnapshot,
        *,
        relative_path: str,
        content_sha256: str,
        raw_response: bytes,
    ) -> None:
        if (
            snapshot.relative_path != relative_path
            or snapshot.sha256 != content_sha256
            or snapshot.size_bytes != len(raw_response)
            or snapshot.bytes != raw_response
        ):
            raise ArtifactIntegrityViolation("HEARING_RESPONSE_SNAPSHOT_MISMATCH")

    @staticmethod
    def _verify_receipt_snapshot(
        snapshot: SecureFileSnapshot,
        relative_path: str,
        response: HearingModelResponse,
    ) -> None:
        if (
            snapshot.relative_path != relative_path
            or snapshot.sha256 != response.content_sha256
            or snapshot.size_bytes != response.size_bytes
        ):
            raise ArtifactIntegrityViolation("HEARING_RESPONSE_SNAPSHOT_MISMATCH")

    @staticmethod
    def _path_failure(
        error: PathBoundaryViolation,
    ) -> HearingModelResponseStoreFailureCode:
        if error.reason_code == "FILE_TOO_LARGE":
            return HearingModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE
        if error.reason_code in {"FILE_MISSING", "SOURCE_OR_PARENT_MISSING"}:
            return HearingModelResponseStoreFailureCode.RESPONSE_NOT_FOUND
        return HearingModelResponseStoreFailureCode.WORKSPACE_REJECTED

    @staticmethod
    def _raise(reason: HearingModelResponseStoreFailureCode) -> NoReturn:
        raise HearingModelResponseStoreError(reason)


__all__ = [
    "HearingModelResponseStoreError",
    "HearingModelResponseStoreFailureCode",
    "SecureHearingModelResponseStore",
]

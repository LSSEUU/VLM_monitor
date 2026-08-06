"""Crash-recoverable, owner-only persistence for exact model-output bytes."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Final

from pydantic import ValidationError

from labcourt.adapters.storage.secure_workspace import SecureFileSnapshot, SecureWorkspace
from labcourt.contracts.canonical import canonical_bytes
from labcourt.contracts.enums import VlmCallPurpose
from labcourt.contracts.references import require_reference_token
from labcourt.contracts.screening import (
    StructureRepairRequest,
    VLMCallRequest,
    VLMRequest,
    VLMResponse,
    derive_model_response_id,
)
from labcourt.exceptions import (
    ArtifactConflict,
    ArtifactIntegrityViolation,
    PathBoundaryViolation,
)
from labcourt.ports.vlm import ModelResponseStoreError, ModelResponseStoreFailureCode

_JOURNAL_SCHEMA: Final = "m3-model-response-publication-journal-v1"
_JOURNAL_HASH_DOMAIN: Final = "labcourt:model-response-publication-journal"
_MAX_JOURNAL_BYTES: Final = 64 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_JOURNAL_KEYS = frozenset({"schema_version", "request_binding", "response", "journal_sha256"})
_REQUEST_BINDING_KEYS = frozenset(
    {
        "run_id",
        "case_id",
        "evidence_pack_id",
        "evidence_pack_version",
        "request_id",
        "request_sha256",
        "cache_key",
        "purpose",
        "model_manifest_id",
        "manifest_id",
    }
)


class _DuplicateJournalField(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJournalField
        result[key] = value
    return result


def _reject_nonfinite(_value: str) -> object:
    raise ValueError


class SecureModelResponseStore:
    """Persist raw bytes plus a durable request-bound publication receipt."""

    __slots__ = ("_workspace",)

    def __init__(self, workspace: SecureWorkspace) -> None:
        if not isinstance(workspace, SecureWorkspace):
            raise TypeError("workspace must be a SecureWorkspace")
        self._workspace = workspace

    def __repr__(self) -> str:
        return "SecureModelResponseStore()"

    def publish(
        self,
        request: VLMCallRequest,
        raw_response: bytes,
        *,
        input_tokens: int = 0,
        output_tokens: int = 0,
        latency_ms: int = 0,
    ) -> VLMResponse:
        """Journal, fsync, and atomically publish one exact response byte string."""

        request = self._require_request(request)
        if not isinstance(raw_response, bytes):
            raise ModelResponseStoreError(ModelResponseStoreFailureCode.INVALID_ARGUMENT)
        metrics = (input_tokens, output_tokens, latency_ms)
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in metrics
        ):
            raise ModelResponseStoreError(ModelResponseStoreFailureCode.INVALID_ARGUMENT)
        if (
            len(raw_response) > request.budget.max_response_bytes
            or output_tokens > request.budget.max_output_tokens
        ):
            raise ModelResponseStoreError(ModelResponseStoreFailureCode.CALL_BUDGET_EXCEEDED)

        content_sha256 = hashlib.sha256(raw_response).hexdigest()
        response_id = derive_model_response_id(
            request.run_id,
            request.request_id,
            content_sha256,
        )
        staged_directory = f".staging/{request.run_id}/model-response-{response_id}"
        staged_relative = f"{staged_directory}/response.json"
        journal_directory, journal_relative = self._journal_paths(request)
        final_relative = f"{request.run_id}/model_responses/{response_id}.json"
        receipt = self._build_receipt(
            request,
            final_relative=final_relative,
            content_sha256=content_sha256,
            size_bytes=len(raw_response),
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency_ms=latency_ms,
        )
        journal_bytes = self._encode_journal(request, receipt)

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
            published = self._workspace.publish_model_response_staged(
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
            self._workspace.remove_empty_model_response_staging_directory(staged_directory)
        except ArtifactConflict:
            raise ModelResponseStoreError(ModelResponseStoreFailureCode.RESPONSE_CONFLICT) from None
        except ArtifactIntegrityViolation:
            raise ModelResponseStoreError(
                ModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE
            ) from None
        except PathBoundaryViolation as error:
            reason = (
                ModelResponseStoreFailureCode.RESPONSE_NOT_FOUND
                if error.reason_code in {"FILE_MISSING", "SOURCE_OR_PARENT_MISSING"}
                else ModelResponseStoreFailureCode.WORKSPACE_REJECTED
            )
            raise ModelResponseStoreError(reason) from None
        except Exception:
            raise ModelResponseStoreError(
                ModelResponseStoreFailureCode.WORKSPACE_REJECTED
            ) from None
        return receipt

    def probe_recovery(self, request: VLMCallRequest) -> VLMResponse | None:
        """Verify a journaled publication without moving or deleting any entry."""

        request = self._require_request(request)
        _journal_directory, journal_relative = self._journal_paths(request)
        try:
            try:
                journal = self._workspace.read_verified(
                    journal_relative,
                    max_bytes=min(_MAX_JOURNAL_BYTES, self._workspace.max_file_bytes),
                )
            except PathBoundaryViolation as error:
                if error.reason_code == "FILE_MISSING":
                    return None
                raise
            response = self._decode_journal(request, journal)
            staged_relative = (
                f".staging/{request.run_id}/model-response-{response.response_id}/response.json"
            )
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
                raise ModelResponseStoreError(ModelResponseStoreFailureCode.RESPONSE_NOT_FOUND)
            return response
        except ModelResponseStoreError:
            raise
        except ArtifactConflict:
            raise ModelResponseStoreError(ModelResponseStoreFailureCode.RESPONSE_CONFLICT) from None
        except ArtifactIntegrityViolation:
            raise ModelResponseStoreError(
                ModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE
            ) from None
        except PathBoundaryViolation as error:
            if error.reason_code == "FILE_TOO_LARGE":
                reason = ModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE
            elif error.reason_code in {"FILE_MISSING", "SOURCE_OR_PARENT_MISSING"}:
                reason = ModelResponseStoreFailureCode.RESPONSE_NOT_FOUND
            else:
                reason = ModelResponseStoreFailureCode.WORKSPACE_REJECTED
            raise ModelResponseStoreError(reason) from None
        except Exception:
            raise ModelResponseStoreError(
                ModelResponseStoreFailureCode.WORKSPACE_REJECTED
            ) from None

    def recover(self, request: VLMCallRequest) -> VLMResponse | None:
        """Recover a journaled publication without making another provider call."""

        request = self._require_request(request)
        _journal_directory, journal_relative = self._journal_paths(request)
        try:
            try:
                journal = self._workspace.read_verified(
                    journal_relative,
                    max_bytes=min(_MAX_JOURNAL_BYTES, self._workspace.max_file_bytes),
                )
            except PathBoundaryViolation as error:
                if error.reason_code == "FILE_MISSING":
                    return None
                raise
            response = self._decode_journal(request, journal)
            staged_directory = f".staging/{request.run_id}/model-response-{response.response_id}"
            staged_relative = f"{staged_directory}/response.json"
            final_relative = response.raw_response_ref

            staged: SecureFileSnapshot | None
            try:
                staged = self._workspace.read_verified(
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
                published = self._workspace.publish_model_response_staged(
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
            self._workspace.remove_empty_model_response_staging_directory(staged_directory)
            return response
        except ModelResponseStoreError:
            raise
        except ArtifactConflict:
            raise ModelResponseStoreError(ModelResponseStoreFailureCode.RESPONSE_CONFLICT) from None
        except ArtifactIntegrityViolation:
            raise ModelResponseStoreError(
                ModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE
            ) from None
        except PathBoundaryViolation as error:
            if error.reason_code == "FILE_TOO_LARGE":
                reason = ModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE
            elif error.reason_code in {"FILE_MISSING", "SOURCE_OR_PARENT_MISSING"}:
                reason = ModelResponseStoreFailureCode.RESPONSE_NOT_FOUND
            else:
                reason = ModelResponseStoreFailureCode.WORKSPACE_REJECTED
            raise ModelResponseStoreError(reason) from None
        except Exception:
            raise ModelResponseStoreError(
                ModelResponseStoreFailureCode.WORKSPACE_REJECTED
            ) from None

    def acknowledge(self, request: VLMCallRequest, response: VLMResponse) -> None:
        """Delete only the exact verified journal after publication is durable."""

        request = self._require_request(request)
        response = self._require_response(response)
        if not self._response_matches_request(request, response):
            raise ModelResponseStoreError(ModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE)
        journal_directory, journal_relative = self._journal_paths(request)
        recovered = self.recover(request)
        if recovered is None:
            try:
                self._workspace.remove_empty_model_response_journal_directory(journal_directory)
            except ArtifactConflict:
                raise ModelResponseStoreError(
                    ModelResponseStoreFailureCode.RESPONSE_CONFLICT
                ) from None
            except PathBoundaryViolation:
                raise ModelResponseStoreError(
                    ModelResponseStoreFailureCode.WORKSPACE_REJECTED
                ) from None
            return
        if recovered != response:
            raise ModelResponseStoreError(ModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE)
        journal_bytes = self._encode_journal(request, recovered)
        journal_file_sha256 = hashlib.sha256(journal_bytes).hexdigest()
        try:
            try:
                self._workspace.delete_verified_model_response_journal(
                    journal_relative,
                    journal_file_sha256,
                )
            except PathBoundaryViolation as error:
                if error.reason_code != "FILE_MISSING":
                    raise
            self._workspace.remove_empty_model_response_journal_directory(journal_directory)
        except ArtifactConflict:
            raise ModelResponseStoreError(ModelResponseStoreFailureCode.RESPONSE_CONFLICT) from None
        except ArtifactIntegrityViolation:
            raise ModelResponseStoreError(
                ModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE
            ) from None
        except PathBoundaryViolation:
            raise ModelResponseStoreError(
                ModelResponseStoreFailureCode.WORKSPACE_REJECTED
            ) from None
        except Exception:
            raise ModelResponseStoreError(
                ModelResponseStoreFailureCode.WORKSPACE_REJECTED
            ) from None

    def read_bytes(
        self,
        run_id: str,
        response: VLMResponse,
        max_bytes: int,
    ) -> bytes:
        """Read the exact persisted bytes after bounded identity verification."""

        if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 0:
            raise ModelResponseStoreError(ModelResponseStoreFailureCode.INVALID_ARGUMENT)
        response = self._require_response(response)
        expected_path = self._require_scope(run_id, response)
        if response.size_bytes > max_bytes:
            raise ModelResponseStoreError(ModelResponseStoreFailureCode.READ_LIMIT_EXCEEDED)
        try:
            snapshot = self._workspace.read_verified(
                expected_path,
                response.content_sha256,
                max_bytes=response.size_bytes,
            )
        except ArtifactIntegrityViolation:
            raise ModelResponseStoreError(
                ModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE
            ) from None
        except PathBoundaryViolation as error:
            if error.reason_code == "FILE_MISSING":
                reason = ModelResponseStoreFailureCode.RESPONSE_NOT_FOUND
            elif error.reason_code == "FILE_TOO_LARGE":
                reason = ModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE
            else:
                reason = ModelResponseStoreFailureCode.WORKSPACE_REJECTED
            raise ModelResponseStoreError(reason) from None
        except Exception:
            raise ModelResponseStoreError(
                ModelResponseStoreFailureCode.WORKSPACE_REJECTED
            ) from None
        if snapshot.size_bytes != response.size_bytes:
            raise ModelResponseStoreError(ModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE)
        return snapshot.bytes

    def read_json(self, run_id: str, response: VLMResponse, max_bytes: int) -> str:
        """Read exact UTF-8 model content; JSON syntax is the parser's authority."""

        try:
            return self.read_bytes(run_id, response, max_bytes).decode("utf-8")
        except UnicodeDecodeError:
            raise ModelResponseStoreError(
                ModelResponseStoreFailureCode.RESPONSE_UTF8_INVALID
            ) from None

    def verify(self, run_id: str, response: VLMResponse) -> VLMResponse:
        """Reopen and verify one receipt without trusting its serialized locator alone."""

        response = self._require_response(response)
        expected_path = self._require_scope(run_id, response)
        try:
            snapshot = self._workspace.read_verified(
                expected_path,
                response.content_sha256,
                max_bytes=response.size_bytes,
            )
        except ArtifactIntegrityViolation:
            raise ModelResponseStoreError(
                ModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE
            ) from None
        except PathBoundaryViolation as error:
            if error.reason_code == "FILE_MISSING":
                reason = ModelResponseStoreFailureCode.RESPONSE_NOT_FOUND
            elif error.reason_code == "FILE_TOO_LARGE":
                reason = ModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE
            else:
                reason = ModelResponseStoreFailureCode.WORKSPACE_REJECTED
            raise ModelResponseStoreError(reason) from None
        except Exception:
            raise ModelResponseStoreError(
                ModelResponseStoreFailureCode.WORKSPACE_REJECTED
            ) from None
        if (
            snapshot.relative_path != expected_path
            or snapshot.sha256 != response.content_sha256
            or snapshot.size_bytes != response.size_bytes
        ):
            raise ModelResponseStoreError(ModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE)
        return response

    def verify_raw_response(
        self,
        run_id: str,
        request: VLMCallRequest,
        response: VLMResponse,
    ) -> VLMResponse:
        """Verify physical bytes and the complete canonical request binding."""

        request = self._require_request(request)
        response = self._require_response(response)
        if request.run_id != run_id or not self._response_matches_request(request, response):
            raise ModelResponseStoreError(ModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE)
        if response.size_bytes > request.budget.max_response_bytes:
            raise ModelResponseStoreError(ModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE)
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
            self._workspace.create_new(relative_path, journal_bytes, journal_file_sha256)
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

    @classmethod
    def _encode_journal(cls, request: VLMCallRequest, response: VLMResponse) -> bytes:
        body = cls._journal_body(request, response)
        journal_sha256 = hashlib.sha256(
            canonical_bytes([_JOURNAL_HASH_DOMAIN, 1, body])
        ).hexdigest()
        return canonical_bytes({**body, "journal_sha256": journal_sha256})

    @classmethod
    def _decode_journal(
        cls,
        request: VLMCallRequest,
        snapshot: SecureFileSnapshot,
    ) -> VLMResponse:
        try:
            root = json.loads(
                snapshot.bytes.decode("utf-8"),
                object_pairs_hook=_unique_object,
                parse_constant=_reject_nonfinite,
            )
            if not isinstance(root, dict) or frozenset(root) != _JOURNAL_KEYS:
                raise ValueError
            if canonical_bytes(root) != snapshot.bytes:
                raise ValueError
            if root["schema_version"] != _JOURNAL_SCHEMA:
                raise ValueError
            binding = root["request_binding"]
            response_document = root["response"]
            journal_sha256 = root["journal_sha256"]
            if (
                not isinstance(binding, dict)
                or frozenset(binding) != _REQUEST_BINDING_KEYS
                or binding != cls._request_binding(request)
                or not isinstance(response_document, dict)
                or not isinstance(journal_sha256, str)
                or _SHA256.fullmatch(journal_sha256) is None
            ):
                raise ValueError
            body = {
                "schema_version": root["schema_version"],
                "request_binding": binding,
                "response": response_document,
            }
            expected_journal_sha256 = hashlib.sha256(
                canonical_bytes([_JOURNAL_HASH_DOMAIN, 1, body])
            ).hexdigest()
            if journal_sha256 != expected_journal_sha256:
                raise ValueError
            response = VLMResponse.model_validate(response_document)
            if not cls._response_matches_request(request, response):
                raise ValueError
            if response.size_bytes > request.budget.max_response_bytes:
                raise ValueError
            if response.output_tokens > request.budget.max_output_tokens:
                raise ValueError
            if cls._encode_journal(request, response) != snapshot.bytes:
                raise ValueError
            return response
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValidationError,
            TypeError,
            ValueError,
            OverflowError,
            RecursionError,
        ):
            raise ArtifactIntegrityViolation("MODEL_RESPONSE_JOURNAL_INVALID") from None

    @staticmethod
    def _journal_body(
        request: VLMCallRequest,
        response: VLMResponse,
    ) -> dict[str, object]:
        return {
            "schema_version": _JOURNAL_SCHEMA,
            "request_binding": SecureModelResponseStore._request_binding(request),
            "response": response.model_dump(mode="json"),
        }

    @staticmethod
    def _request_binding(request: VLMCallRequest) -> dict[str, object]:
        return {
            "run_id": request.run_id,
            "case_id": request.case_id,
            "evidence_pack_id": request.evidence_pack_id,
            "evidence_pack_version": request.evidence_pack_version,
            "request_id": request.request_id,
            "request_sha256": request.request_sha256,
            "cache_key": request.cache_key,
            "purpose": request.purpose.value,
            "model_manifest_id": request.model_manifest_id,
            "manifest_id": request.manifest_id,
        }

    @staticmethod
    def _journal_paths(request: VLMCallRequest) -> tuple[str, str]:
        directory = f".staging/{request.run_id}/model-request-{request.request_id}"
        return directory, f"{directory}/receipt.json"

    @staticmethod
    def _require_request(request: VLMCallRequest) -> VLMCallRequest:
        if not isinstance(request, (VLMRequest, StructureRepairRequest)):
            raise ModelResponseStoreError(ModelResponseStoreFailureCode.INVALID_ARGUMENT)
        try:
            validated = type(request).model_validate(request.model_dump(mode="json"))
        except (TypeError, ValueError, ValidationError):
            raise ModelResponseStoreError(ModelResponseStoreFailureCode.INVALID_ARGUMENT) from None
        if validated != request:
            raise ModelResponseStoreError(ModelResponseStoreFailureCode.INVALID_ARGUMENT)
        return validated

    @staticmethod
    def _require_response(response: VLMResponse) -> VLMResponse:
        if not isinstance(response, VLMResponse):
            raise ModelResponseStoreError(ModelResponseStoreFailureCode.INVALID_ARGUMENT)
        try:
            validated = VLMResponse.model_validate(response.model_dump(mode="json"))
        except (TypeError, ValueError, ValidationError):
            raise ModelResponseStoreError(ModelResponseStoreFailureCode.INVALID_ARGUMENT) from None
        if validated != response:
            raise ModelResponseStoreError(ModelResponseStoreFailureCode.INVALID_ARGUMENT)
        return validated

    @staticmethod
    def _response_matches_request(
        request: VLMCallRequest,
        response: VLMResponse,
    ) -> bool:
        return (
            response.run_id == request.run_id
            and response.case_id == request.case_id
            and response.evidence_pack_id == request.evidence_pack_id
            and response.evidence_pack_version == request.evidence_pack_version
            and response.request_id == request.request_id
            and response.request_sha256 == request.request_sha256
            and response.cache_key == request.cache_key
            and response.purpose == request.purpose
            and response.attempt_index == (0 if request.purpose == VlmCallPurpose.SCREENING else 1)
            and response.model_manifest_id == request.model_manifest_id
            and response.manifest_id == request.manifest_id
        )

    @staticmethod
    def _require_scope(run_id: str, response: VLMResponse) -> str:
        try:
            controlled_run_id = require_reference_token(run_id, "model response run_id")
        except (TypeError, ValueError):
            raise ModelResponseStoreError(ModelResponseStoreFailureCode.INVALID_ARGUMENT) from None
        expected_path = f"{controlled_run_id}/model_responses/{response.response_id}.json"
        if response.run_id != controlled_run_id or response.raw_response_ref != expected_path:
            raise ModelResponseStoreError(ModelResponseStoreFailureCode.RUN_SCOPE_MISMATCH)
        return expected_path

    @staticmethod
    def _build_receipt(
        request: VLMCallRequest,
        *,
        final_relative: str,
        content_sha256: str,
        size_bytes: int,
        input_tokens: int,
        output_tokens: int,
        latency_ms: int,
    ) -> VLMResponse:
        try:
            return VLMResponse(
                run_id=request.run_id,
                case_id=request.case_id,
                evidence_pack_id=request.evidence_pack_id,
                evidence_pack_version=request.evidence_pack_version,
                request_id=request.request_id,
                request_sha256=request.request_sha256,
                cache_key=request.cache_key,
                purpose=request.purpose,
                attempt_index=(0 if request.purpose == VlmCallPurpose.SCREENING else 1),
                raw_response_ref=final_relative,
                content_sha256=content_sha256,
                size_bytes=size_bytes,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                latency_ms=latency_ms,
                model_manifest_id=request.model_manifest_id,
                manifest_id=request.manifest_id,
            )
        except (TypeError, ValueError, ValidationError):
            raise ModelResponseStoreError(
                ModelResponseStoreFailureCode.RESPONSE_RECEIPT_INVALID
            ) from None

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
            raise ArtifactIntegrityViolation("MODEL_RESPONSE_SNAPSHOT_MISMATCH")

    @staticmethod
    def _verify_receipt_snapshot(
        snapshot: SecureFileSnapshot,
        relative_path: str,
        response: VLMResponse,
    ) -> None:
        if (
            snapshot.relative_path != relative_path
            or snapshot.sha256 != response.content_sha256
            or snapshot.size_bytes != response.size_bytes
        ):
            raise ArtifactIntegrityViolation("MODEL_RESPONSE_SNAPSHOT_MISMATCH")


__all__ = [
    "ModelResponseStoreError",
    "ModelResponseStoreFailureCode",
    "SecureModelResponseStore",
]

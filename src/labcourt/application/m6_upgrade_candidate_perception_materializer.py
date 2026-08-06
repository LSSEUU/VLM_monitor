"""Offline, restart-safe materialization of candidate Frame/Detection rows."""

from __future__ import annotations

import hashlib
from typing import NoReturn, Protocol

from pydantic import ValidationError

from labcourt.application.m6_regression_execution_source_catalog import (
    M6RegressionExecutionSourceCatalogBindingError,
    M6RegressionExecutionSourceCatalogBindingErrorCode,
    bind_m6_regression_execution_source_catalog,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.detections import Detection
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.m6_regression_dataset import (
    M6RegressionExecutionSourceCatalogEntry,
)
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.contracts.m6_source_authority_store import M6SourceAuthoritySeal
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.references import require_reference_token
from labcourt.domain.m6_semantic_projection import M6ResolvedPerception
from labcourt.exceptions import ContractViolation, LabCourtError, ManifestMismatch
from labcourt.ports.m6_regression_execution_source_catalog import (
    M6RegressionExecutionSourceCatalogError,
    M6RegressionExecutionSourceCatalogFailureCode,
    M6RegressionExecutionSourceCatalogProvider,
    M6StoredRegressionExecutionSourceCatalog,
)
from labcourt.ports.m6_upgrade_candidate_perception_materializer import (
    M6UpgradeCandidatePerceptionMaterializerError,
    M6UpgradeCandidatePerceptionMaterializerFailureCode,
)
from labcourt.ports.m6_upgrade_execution_ledger_v3 import (
    M6UpgradeExecutionLedgerV3Error,
    M6UpgradeExecutionLedgerV3FailureCode,
    M6UpgradeExecutionLedgerV3Repository,
    M6UpgradeExecutionLedgerV3Status,
    M6UpgradeExecutionResumeV3,
)

_FailureCode = M6UpgradeCandidatePerceptionMaterializerFailureCode


class _SourceSealProvider(Protocol):
    def load_source_seal(
        self,
        closure: M6ReplayInputClosureAuthority,
    ) -> M6SourceAuthoritySeal: ...


class _SourcePerceptionReader(Protocol):
    def assemble(
        self,
        closure: M6ReplayInputClosureAuthority,
    ) -> M6ResolvedPerception: ...


class _CandidatePerceptionWriter(Protocol):
    def load_run_manifest(self, run_id: str) -> RunManifest: ...

    def register_frame(self, run_id: str, frame: FrameRef) -> None: ...

    def register_detection(self, run_id: str, detection: Detection) -> None: ...


def _error(code: _FailureCode) -> M6UpgradeCandidatePerceptionMaterializerError:
    return M6UpgradeCandidatePerceptionMaterializerError(code)


def _fail(code: _FailureCode) -> NoReturn:
    raise _error(code) from None


def _public_identity(candidate_run_id: object, scope_id: object) -> tuple[str, str]:
    try:
        if not isinstance(candidate_run_id, str):
            raise TypeError
        run_id = require_reference_token(candidate_run_id, "M6 candidate perception run_id")
    except (TypeError, ValueError):
        _fail(_FailureCode.INVALID_ARGUMENT)
    if (
        not isinstance(scope_id, str)
        or len(scope_id) != 64
        or any(character not in "0123456789abcdef" for character in scope_id)
    ):
        _fail(_FailureCode.INVALID_ARGUMENT)
    return run_id, scope_id


def _ledger_failure(code: M6UpgradeExecutionLedgerV3FailureCode) -> _FailureCode:
    direct = {
        M6UpgradeExecutionLedgerV3FailureCode.INVALID_ARGUMENT: _FailureCode.INVALID_ARGUMENT,
        M6UpgradeExecutionLedgerV3FailureCode.SCOPE_NOT_FOUND: _FailureCode.SCOPE_NOT_FOUND,
        M6UpgradeExecutionLedgerV3FailureCode.DOCUMENT_TOO_LARGE: (_FailureCode.DOCUMENT_TOO_LARGE),
        M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID: (
            _FailureCode.STORED_AUTHORITY_INVALID
        ),
        M6UpgradeExecutionLedgerV3FailureCode.STORAGE_REJECTED: (_FailureCode.STORAGE_REJECTED),
    }
    return direct.get(code, _FailureCode.EXECUTION_STATE_MISMATCH)


def _catalog_failure(code: M6RegressionExecutionSourceCatalogFailureCode) -> _FailureCode:
    direct = {
        M6RegressionExecutionSourceCatalogFailureCode.CATALOG_NOT_FOUND: (
            _FailureCode.CATALOG_NOT_FOUND
        ),
        M6RegressionExecutionSourceCatalogFailureCode.DOCUMENT_TOO_LARGE: (
            _FailureCode.DOCUMENT_TOO_LARGE
        ),
        M6RegressionExecutionSourceCatalogFailureCode.STORAGE_REJECTED: (
            _FailureCode.STORAGE_REJECTED
        ),
        M6RegressionExecutionSourceCatalogFailureCode.COMMIT_OUTCOME_UNKNOWN: (
            _FailureCode.STORAGE_REJECTED
        ),
    }
    return direct.get(code, _FailureCode.CATALOG_REJECTED)


def _binding_failure(code: M6RegressionExecutionSourceCatalogBindingErrorCode) -> _FailureCode:
    if code == M6RegressionExecutionSourceCatalogBindingErrorCode.DOCUMENT_TOO_LARGE:
        return _FailureCode.DOCUMENT_TOO_LARGE
    return _FailureCode.CATALOG_REJECTED


def _controlled_resume(
    value: object,
    run_id: str,
    scope_id: str,
) -> M6UpgradeExecutionResumeV3:
    if type(value) is not M6UpgradeExecutionResumeV3:
        _fail(_FailureCode.STORED_AUTHORITY_INVALID)
    try:
        controlled = M6UpgradeExecutionResumeV3(
            status=value.status,
            execution_scope=value.execution_scope,
            committed_sample_count=value.committed_sample_count,
            ledger_head_hash=value.ledger_head_hash,
            next_execution_entry=value.next_execution_entry,
            pending_observation=value.pending_observation,
            pending_commitment=value.pending_commitment,
            seal=value.seal,
        )
    except (AttributeError, TypeError, ValueError):
        _fail(_FailureCode.STORED_AUTHORITY_INVALID)
    if (
        controlled != value
        or controlled.execution_scope.candidate_run_id != run_id
        or controlled.execution_scope.execution_scope_authority_id != scope_id
    ):
        _fail(_FailureCode.STORED_AUTHORITY_INVALID)
    if controlled.status != M6UpgradeExecutionLedgerV3Status.READY_FOR_OBSERVATION:
        _fail(_FailureCode.EXECUTION_STATE_MISMATCH)
    return controlled


def _controlled_catalog(value: object) -> M6StoredRegressionExecutionSourceCatalog:
    if type(value) is not M6StoredRegressionExecutionSourceCatalog:
        _fail(_FailureCode.STORED_AUTHORITY_INVALID)
    try:
        controlled = M6StoredRegressionExecutionSourceCatalog(
            source_catalog=value.source_catalog,
            canonical_document=value.canonical_document,
            content_sha256=value.content_sha256,
            size_bytes=value.size_bytes,
        )
    except (AttributeError, TypeError, ValueError):
        _fail(_FailureCode.STORED_AUTHORITY_INVALID)
    if controlled != value:
        _fail(_FailureCode.STORED_AUTHORITY_INVALID)
    return controlled


def _next_catalog_entry(
    resume: M6UpgradeExecutionResumeV3,
    stored: M6StoredRegressionExecutionSourceCatalog,
) -> M6RegressionExecutionSourceCatalogEntry:
    scope = resume.execution_scope
    bound = bind_m6_regression_execution_source_catalog(
        execution_scope=scope,
        execution_source_catalog=stored.source_catalog,
        execution_source_catalog_document=stored.canonical_document,
    )
    try:
        entry = bound.execution_source_catalog.entries[resume.committed_sample_count]
        execution_entry = scope.execution_dataset.entries[resume.committed_sample_count]
    except IndexError:
        _fail(_FailureCode.EXECUTION_STATE_MISMATCH)
    if resume.next_execution_entry != execution_entry or (
        entry.replay_input_closure.replay_input_closure_authority_id
        != execution_entry.replay_input_closure_authority_id
    ):
        _fail(_FailureCode.CATALOG_REJECTED)
    return entry


def _controlled_source_seal(
    value: object,
    entry: M6RegressionExecutionSourceCatalogEntry,
) -> M6SourceAuthoritySeal:
    if type(value) is not M6SourceAuthoritySeal:
        _fail(_FailureCode.SOURCE_SEAL_REJECTED)
    try:
        controlled = M6SourceAuthoritySeal.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
        document = canonical_json(controlled.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(_FailureCode.SOURCE_SEAL_REJECTED)
    payload = document.encode("utf-8")
    closure = entry.replay_input_closure
    if (
        controlled != value
        or controlled.seal_id != entry.source_seal_id
        or hashlib.sha256(payload).hexdigest() != entry.source_seal_content_sha256
        or len(payload) != entry.source_seal_size_bytes
        or controlled.sample_id != closure.sample_id
        or controlled.source_run_id != closure.source_run_id
        or controlled.source_case_id != closure.source_case_id
        or controlled.source_case_revision != closure.source_case_revision
        or controlled.source_manifest_id != closure.source_manifest_id
        or controlled.replay_input_closure_authority_id != closure.replay_input_closure_authority_id
        or controlled.replay_input_closure_document_sha256
        != closure.replay_input_closure_document_sha256
    ):
        _fail(_FailureCode.SOURCE_SEAL_REJECTED)
    return controlled


def _controlled_manifest(value: object, expected: RunManifest) -> RunManifest:
    if type(value) is not RunManifest:
        _fail(_FailureCode.STORED_AUTHORITY_INVALID)
    try:
        controlled = RunManifest.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(_FailureCode.STORED_AUTHORITY_INVALID)
    if controlled != value or controlled != expected:
        _fail(_FailureCode.CANDIDATE_MANIFEST_MISMATCH)
    return controlled


def _candidate_perception(
    closure: M6ReplayInputClosureAuthority,
    value: object,
    candidate_detector_manifest_id: str,
) -> M6ResolvedPerception:
    if type(value) is not M6ResolvedPerception:
        _fail(_FailureCode.SOURCE_PERCEPTION_REJECTED)
    try:
        source = M6ResolvedPerception(frames=value.frames, detections=value.detections)
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(_FailureCode.SOURCE_PERCEPTION_REJECTED)
    if source != value:
        _fail(_FailureCode.SOURCE_PERCEPTION_REJECTED)
    if tuple((item.frame_id, item.content_sha256) for item in source.frames) != tuple(
        (item.frame_id, item.content_sha256) for item in closure.frames
    ) or tuple(
        (item.detection_id, item.frame_id, item.model_manifest_id) for item in source.detections
    ) != tuple(
        (item.detection_id, item.frame_id, item.model_manifest_id) for item in closure.detections
    ):
        _fail(_FailureCode.SOURCE_PERCEPTION_REJECTED)
    try:
        detections = tuple(
            Detection.model_validate(
                {
                    **item.model_dump(mode="json", exclude_computed_fields=True),
                    "model_manifest_id": candidate_detector_manifest_id,
                }
            )
            for item in source.detections
        )
        return M6ResolvedPerception(frames=source.frames, detections=detections)
    except (TypeError, ValueError, ValidationError):
        _fail(_FailureCode.CANDIDATE_MANIFEST_MISMATCH)


def _require_candidate_streams(
    manifest: RunManifest,
    perception: M6ResolvedPerception,
) -> None:
    if not manifest.streams:
        return
    streams = {(item.camera_id, item.stream_id): item for item in manifest.streams}
    for frame in perception.frames:
        stream = streams.get((frame.camera_id, frame.stream_id))
        if stream is None or (
            frame.fps_num != stream.fps_num
            or frame.fps_den != stream.fps_den
            or frame.width != stream.width
            or frame.height != stream.height
            or frame.frame_index >= stream.frame_count
        ):
            _fail(_FailureCode.CANDIDATE_MANIFEST_MISMATCH)


class M6PrecomputedCandidatePerceptionMaterializerV3:
    """Copy locked source perception into one precomputed candidate run.

    Frame content identity is preserved. Detection semantic fields are
    preserved while provenance is rebound to the pinned candidate detector.
    Partial Frame/Detection writes are safe because the candidate repository is
    append-only and exact-idempotent; Observation remains the commit point.
    """

    __slots__ = ("_catalogs", "_ledger", "_seals", "_source", "_writer")

    def __init__(
        self,
        *,
        ledger_repository: M6UpgradeExecutionLedgerV3Repository,
        source_catalog_provider: M6RegressionExecutionSourceCatalogProvider,
        source_seal_provider: _SourceSealProvider,
        source_perception_reader: _SourcePerceptionReader,
        candidate_perception_writer: _CandidatePerceptionWriter,
    ) -> None:
        dependencies = (
            (ledger_repository, "resume"),
            (source_catalog_provider, "load"),
            (source_seal_provider, "load_source_seal"),
            (source_perception_reader, "assemble"),
            (candidate_perception_writer, "load_run_manifest"),
            (candidate_perception_writer, "register_frame"),
            (candidate_perception_writer, "register_detection"),
        )
        if any(not callable(getattr(value, method, None)) for value, method in dependencies):
            raise TypeError("invalid M6 candidate perception materializer dependency")
        self._ledger = ledger_repository
        self._catalogs = source_catalog_provider
        self._seals = source_seal_provider
        self._source = source_perception_reader
        self._writer = candidate_perception_writer

    def _attempt_materialize_next_perception(
        self,
        candidate_run_id: object,
        execution_scope_authority_id: object,
    ) -> M6ResolvedPerception:
        run_id, scope_id = _public_identity(candidate_run_id, execution_scope_authority_id)
        try:
            resume = _controlled_resume(self._ledger.resume(run_id, scope_id), run_id, scope_id)
            dataset = resume.execution_scope.execution_dataset
            stored = _controlled_catalog(
                self._catalogs.load(
                    dataset.source_catalog_authority_id,
                    dataset.source_catalog_document_sha256,
                )
            )
            entry = _next_catalog_entry(resume, stored)
            closure = entry.replay_input_closure
            try:
                seal = self._seals.load_source_seal(closure)
            except Exception:
                _fail(_FailureCode.SOURCE_SEAL_REJECTED)
            _controlled_source_seal(seal, entry)
            try:
                source_perception = self._source.assemble(closure)
            except Exception:
                _fail(_FailureCode.SOURCE_PERCEPTION_REJECTED)
            scope = resume.execution_scope
            manifest = _controlled_manifest(
                self._writer.load_run_manifest(run_id),
                scope.candidate_manifest,
            )
            detector = manifest.models.get("detector")
            if (
                detector is None
                or detector.provider != "precomputed"
                or scope.candidate_config.perception.provider != "precomputed"
            ):
                _fail(_FailureCode.CANDIDATE_MANIFEST_MISMATCH)
            candidate = _candidate_perception(
                closure,
                source_perception,
                detector.model_manifest_id,
            )
            _require_candidate_streams(manifest, candidate)
            try:
                for frame in candidate.frames:
                    self._writer.register_frame(run_id, frame)
                for detection in candidate.detections:
                    self._writer.register_detection(run_id, detection)
            except ManifestMismatch:
                _fail(_FailureCode.CANDIDATE_MANIFEST_MISMATCH)
            except ContractViolation:
                _fail(_FailureCode.IDENTITY_CONFLICT)
            except LabCourtError:
                _fail(_FailureCode.STORAGE_REJECTED)
            return candidate
        except M6UpgradeCandidatePerceptionMaterializerError:
            raise
        except M6UpgradeExecutionLedgerV3Error as error:
            _fail(_ledger_failure(error.reason_code))
        except M6RegressionExecutionSourceCatalogError as error:
            _fail(_catalog_failure(error.reason_code))
        except M6RegressionExecutionSourceCatalogBindingError as error:
            _fail(_binding_failure(error.code))

    def materialize_next_perception(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
    ) -> M6ResolvedPerception:
        """Materialize through a fresh payload-free public boundary."""

        failure = _FailureCode.STORAGE_REJECTED
        try:
            return self._attempt_materialize_next_perception(
                candidate_run_id,
                execution_scope_authority_id,
            )
        except M6UpgradeCandidatePerceptionMaterializerError as error:
            failure = error.reason_code
        except Exception:
            pass
        del self, candidate_run_id, execution_scope_authority_id
        raise _error(failure) from None


__all__ = ["M6PrecomputedCandidatePerceptionMaterializerV3"]

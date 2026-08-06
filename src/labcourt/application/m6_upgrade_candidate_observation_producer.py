"""Offline candidate observation producers for protocol-V3 execution."""

from __future__ import annotations

from typing import NoReturn

from pydantic import ValidationError

from labcourt.application.m6_regression_execution_source_catalog import (
    M6RegressionExecutionSourceCatalogBindingError,
    M6RegressionExecutionSourceCatalogBindingErrorCode,
    bind_m6_regression_execution_source_catalog,
)
from labcourt.contracts.m6_regression import M6ReplayExecutionOutcome
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeObservedArtifactIdentity,
    M6UpgradeSampleExecutionObservationAuthorityV2,
)
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradeArtifactUsage,
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactSource,
)
from labcourt.contracts.references import require_reference_token
from labcourt.domain.m6_semantic_projection import M6ResolvedPerception
from labcourt.ports.m6_regression_execution_source_catalog import (
    M6RegressionExecutionSourceCatalogError,
    M6RegressionExecutionSourceCatalogFailureCode,
    M6RegressionExecutionSourceCatalogProvider,
    M6StoredRegressionExecutionSourceCatalog,
)
from labcourt.ports.m6_upgrade_candidate_observation_producer import (
    M6UpgradeCandidateObservationProducerError,
    M6UpgradeCandidateObservationProducerFailureCode,
)
from labcourt.ports.m6_upgrade_candidate_perception_materializer import (
    M6UpgradeCandidatePerceptionMaterializerError,
    M6UpgradeCandidatePerceptionMaterializerFailureCode,
    M6UpgradeCandidatePerceptionMaterializerV3,
)
from labcourt.ports.m6_upgrade_execution_ledger_v3 import (
    M6UpgradeExecutionLedgerV3Error,
    M6UpgradeExecutionLedgerV3FailureCode,
    M6UpgradeExecutionLedgerV3Repository,
    M6UpgradeExecutionLedgerV3Status,
    M6UpgradeExecutionResumeV3,
)

_FailureCode = M6UpgradeCandidateObservationProducerFailureCode


def _error(code: _FailureCode) -> M6UpgradeCandidateObservationProducerError:
    return M6UpgradeCandidateObservationProducerError(code)


def _fail(code: _FailureCode) -> NoReturn:
    raise _error(code) from None


def _public_identity(candidate_run_id: object, scope_id: object) -> tuple[str, str]:
    try:
        if not isinstance(candidate_run_id, str):
            raise TypeError
        run_id = require_reference_token(candidate_run_id, "M6 candidate observation run_id")
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
        M6UpgradeExecutionLedgerV3FailureCode.LEDGER_SEALED: _FailureCode.LEDGER_SEALED,
        M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID: (
            _FailureCode.STORED_AUTHORITY_INVALID
        ),
        M6UpgradeExecutionLedgerV3FailureCode.STORAGE_REJECTED: (_FailureCode.STORAGE_REJECTED),
    }
    return direct.get(code, _FailureCode.APPEND_STATE_MISMATCH)


def _catalog_failure(code: M6RegressionExecutionSourceCatalogFailureCode) -> _FailureCode:
    direct = {
        M6RegressionExecutionSourceCatalogFailureCode.CATALOG_NOT_FOUND: (
            _FailureCode.CATALOG_NOT_FOUND
        ),
        M6RegressionExecutionSourceCatalogFailureCode.DOCUMENT_TOO_LARGE: (
            _FailureCode.DOCUMENT_TOO_LARGE
        ),
        M6RegressionExecutionSourceCatalogFailureCode.COMMIT_OUTCOME_UNKNOWN: (
            _FailureCode.STORAGE_REJECTED
        ),
        M6RegressionExecutionSourceCatalogFailureCode.STORAGE_REJECTED: (
            _FailureCode.STORAGE_REJECTED
        ),
    }
    return direct.get(code, _FailureCode.CATALOG_REJECTED)


def _binding_failure(
    code: M6RegressionExecutionSourceCatalogBindingErrorCode,
) -> _FailureCode:
    if code == M6RegressionExecutionSourceCatalogBindingErrorCode.DOCUMENT_TOO_LARGE:
        return _FailureCode.DOCUMENT_TOO_LARGE
    return _FailureCode.CATALOG_REJECTED


def _materializer_failure(
    code: M6UpgradeCandidatePerceptionMaterializerFailureCode,
) -> _FailureCode:
    direct = {
        M6UpgradeCandidatePerceptionMaterializerFailureCode.INVALID_ARGUMENT: (
            _FailureCode.INVALID_ARGUMENT
        ),
        M6UpgradeCandidatePerceptionMaterializerFailureCode.SCOPE_NOT_FOUND: (
            _FailureCode.SCOPE_NOT_FOUND
        ),
        M6UpgradeCandidatePerceptionMaterializerFailureCode.EXECUTION_STATE_MISMATCH: (
            _FailureCode.APPEND_STATE_MISMATCH
        ),
        M6UpgradeCandidatePerceptionMaterializerFailureCode.CATALOG_NOT_FOUND: (
            _FailureCode.CATALOG_NOT_FOUND
        ),
        M6UpgradeCandidatePerceptionMaterializerFailureCode.CATALOG_REJECTED: (
            _FailureCode.CATALOG_REJECTED
        ),
        M6UpgradeCandidatePerceptionMaterializerFailureCode.DOCUMENT_TOO_LARGE: (
            _FailureCode.DOCUMENT_TOO_LARGE
        ),
        M6UpgradeCandidatePerceptionMaterializerFailureCode.STORED_AUTHORITY_INVALID: (
            _FailureCode.STORED_AUTHORITY_INVALID
        ),
        M6UpgradeCandidatePerceptionMaterializerFailureCode.STORAGE_REJECTED: (
            _FailureCode.STORAGE_REJECTED
        ),
    }
    return direct.get(code, _FailureCode.CANDIDATE_PERCEPTION_REJECTED)


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
    scope = controlled.execution_scope
    if (
        controlled != value
        or scope.candidate_run_id != run_id
        or scope.execution_scope_authority_id != scope_id
    ):
        _fail(_FailureCode.STORED_AUTHORITY_INVALID)
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


def _require_ready(resume: M6UpgradeExecutionResumeV3) -> None:
    if resume.status == M6UpgradeExecutionLedgerV3Status.READY_FOR_OBSERVATION:
        return
    if resume.status in {
        M6UpgradeExecutionLedgerV3Status.READY_FOR_COMMITMENT,
        M6UpgradeExecutionLedgerV3Status.READY_FOR_LEDGER_APPEND,
    }:
        _fail(_FailureCode.OBSERVATION_ALREADY_EXISTS)
    if resume.status == M6UpgradeExecutionLedgerV3Status.READY_TO_SEAL:
        _fail(_FailureCode.LEDGER_COMPLETE)
    if resume.status == M6UpgradeExecutionLedgerV3Status.SEALED:
        _fail(_FailureCode.LEDGER_SEALED)
    _fail(_FailureCode.APPEND_STATE_MISMATCH)


def _build_precomputed_no_case_observation(
    resume: M6UpgradeExecutionResumeV3,
    stored: M6StoredRegressionExecutionSourceCatalog,
    perception: object,
) -> M6UpgradeSampleExecutionObservationAuthorityV2:
    scope = resume.execution_scope
    bound = bind_m6_regression_execution_source_catalog(
        execution_scope=scope,
        execution_source_catalog=stored.source_catalog,
        execution_source_catalog_document=stored.canonical_document,
    )
    sequence = resume.committed_sample_count
    try:
        catalog_entry = bound.execution_source_catalog.entries[sequence]
        execution_entry = scope.execution_dataset.entries[sequence]
    except IndexError:
        _fail(_FailureCode.APPEND_STATE_MISMATCH)
    if resume.next_execution_entry != execution_entry:
        _fail(_FailureCode.APPEND_STATE_MISMATCH)
    closure = catalog_entry.replay_input_closure
    if type(perception) is not M6ResolvedPerception:
        _fail(_FailureCode.CANDIDATE_PERCEPTION_REJECTED)
    try:
        controlled_perception = M6ResolvedPerception(
            frames=perception.frames,
            detections=perception.detections,
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(_FailureCode.CANDIDATE_PERCEPTION_REJECTED)
    detector = scope.candidate_manifest.models.get("detector")
    if (
        controlled_perception != perception
        or tuple(item.frame_id for item in controlled_perception.frames)
        != tuple(item.frame_id for item in closure.frames)
        or tuple(item.content_sha256 for item in controlled_perception.frames)
        != tuple(item.content_sha256 for item in closure.frames)
        or tuple(item.detection_id for item in controlled_perception.detections)
        != tuple(item.detection_id for item in closure.detections)
        or tuple(item.frame_id for item in controlled_perception.detections)
        != tuple(item.frame_id for item in closure.detections)
        or detector is None
        or any(
            item.model_manifest_id != detector.model_manifest_id
            for item in controlled_perception.detections
        )
    ):
        _fail(_FailureCode.CANDIDATE_PERCEPTION_REJECTED)
    artifacts = tuple(
        sorted(
            (
                *(
                    M6UpgradeObservedArtifactIdentity(
                        source=M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
                        kind=M6UpgradePhysicalArtifactKind.FRAME,
                        artifact_id=item.frame_id,
                        usage=M6UpgradeArtifactUsage.CONSUMED,
                    )
                    for item in controlled_perception.frames
                ),
                *(
                    M6UpgradeObservedArtifactIdentity(
                        source=M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
                        kind=M6UpgradePhysicalArtifactKind.DETECTION,
                        artifact_id=item.detection_id,
                        usage=M6UpgradeArtifactUsage.PRODUCED,
                    )
                    for item in controlled_perception.detections
                ),
            ),
            key=lambda item: item.sort_key,
        )
    )
    try:
        observation = M6UpgradeSampleExecutionObservationAuthorityV2(
            execution_scope_authority_id=scope.execution_scope_authority_id,
            candidate_run_id=scope.candidate_run_id,
            command_id=scope.command.command_id,
            execution_dataset_snapshot_id=(scope.execution_dataset.execution_dataset_snapshot_id),
            execution_entry=execution_entry,
            ledger_sequence=sequence,
            outcome=M6ReplayExecutionOutcome.NO_CASE,
            candidate_case=None,
            selected_case_audit_anchor=None,
            artifacts=artifacts,
            model_calls=(),
        )
        controlled = M6UpgradeSampleExecutionObservationAuthorityV2.model_validate(
            observation.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(_FailureCode.SOURCE_CLOSURE_REJECTED)
    if controlled != observation:
        _fail(_FailureCode.SOURCE_CLOSURE_REJECTED)
    return controlled


class M6PrecomputedNoCaseObservationProducerV3:
    """Offline fake adapter: consume every locked Frame and produce each Detection.

    It materializes a pinned precomputed perception result, but makes no VLM,
    embedding, acquisition, alert, network, or cache call. The deliberately
    narrow outcome is always ``NO_CASE``; richer candidate execution belongs
    behind a later trusted executor port.
    """

    __slots__ = ("_catalogs", "_ledger", "_materializer")

    def __init__(
        self,
        *,
        ledger_repository: M6UpgradeExecutionLedgerV3Repository,
        source_catalog_provider: M6RegressionExecutionSourceCatalogProvider,
        perception_materializer: M6UpgradeCandidatePerceptionMaterializerV3,
    ) -> None:
        if (
            not callable(getattr(ledger_repository, "resume", None))
            or not callable(getattr(source_catalog_provider, "load", None))
            or not callable(getattr(perception_materializer, "materialize_next_perception", None))
        ):
            raise TypeError("invalid M6 precomputed observation-producer dependency")
        self._ledger = ledger_repository
        self._catalogs = source_catalog_provider
        self._materializer = perception_materializer

    def _attempt_produce_next_observation(
        self,
        candidate_run_id: object,
        execution_scope_authority_id: object,
    ) -> M6UpgradeSampleExecutionObservationAuthorityV2:
        run_id, scope_id = _public_identity(candidate_run_id, execution_scope_authority_id)
        try:
            resume = _controlled_resume(self._ledger.resume(run_id, scope_id), run_id, scope_id)
            _require_ready(resume)
            dataset = resume.execution_scope.execution_dataset
            stored = _controlled_catalog(
                self._catalogs.load(
                    dataset.source_catalog_authority_id,
                    dataset.source_catalog_document_sha256,
                )
            )
            perception = self._materializer.materialize_next_perception(run_id, scope_id)
            return _build_precomputed_no_case_observation(resume, stored, perception)
        except M6UpgradeCandidateObservationProducerError:
            raise
        except M6UpgradeExecutionLedgerV3Error as error:
            _fail(_ledger_failure(error.reason_code))
        except M6RegressionExecutionSourceCatalogError as error:
            _fail(_catalog_failure(error.reason_code))
        except M6RegressionExecutionSourceCatalogBindingError as error:
            _fail(_binding_failure(error.code))
        except M6UpgradeCandidatePerceptionMaterializerError as error:
            _fail(_materializer_failure(error.reason_code))

    def produce_next_observation(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeSampleExecutionObservationAuthorityV2:
        """Derive one observation through a fresh payload-free boundary."""

        failure = _FailureCode.STORAGE_REJECTED
        try:
            return self._attempt_produce_next_observation(
                candidate_run_id,
                execution_scope_authority_id,
            )
        except M6UpgradeCandidateObservationProducerError as error:
            failure = error.reason_code
        except Exception:
            pass
        del self, candidate_run_id, execution_scope_authority_id
        raise _error(failure) from None


__all__ = ["M6PrecomputedNoCaseObservationProducerV3"]

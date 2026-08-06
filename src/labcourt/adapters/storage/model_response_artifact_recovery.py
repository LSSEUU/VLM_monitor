"""SecureWorkspace-backed discovery and quarantine for M3 response artifacts."""

from __future__ import annotations

import re
from datetime import datetime

from labcourt.adapters.storage.secure_workspace import SecureDirectoryHint, SecureWorkspace
from labcourt.contracts.model_response_recovery import (
    ModelResponseRecoveryArea,
    ModelResponseRecoveryDisposition,
    ModelResponseRecoveryItem,
    ModelResponseRecoveryReason,
)
from labcourt.contracts.recovery import recovery_source_token
from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import (
    ArtifactConflict,
    ArtifactIntegrityViolation,
    BudgetExceeded,
    PathBoundaryViolation,
)
from labcourt.ports.model_response_artifacts import (
    MAX_MODEL_RESPONSE_RECOVERY_FILE_BYTES,
    MAX_MODEL_RESPONSE_RECOVERY_ITEMS,
    MAX_MODEL_RESPONSE_RECOVERY_NAME_BYTES,
    MAX_MODEL_RESPONSE_RECOVERY_TOTAL_BYTES,
    ModelResponseArtifactCandidate,
    ModelResponseArtifactScan,
    ModelResponseEmptyOperationCandidate,
)

_RESPONSE_OPERATION = re.compile(r"^model-response-(?P<authority>[0-9a-f]{64})$")
_JOURNAL_OPERATION = re.compile(r"^model-request-(?P<authority>[0-9a-f]{64})$")
_FINAL_RESPONSE = re.compile(r"^(?P<authority>[0-9a-f]{64})\.json$")


class SecureModelResponseArtifactRecovery:
    """Enumerate only fixed M3 namespaces and reopen every file by secure handle."""

    __slots__ = ("_workspace",)

    def __init__(self, workspace: SecureWorkspace) -> None:
        if not isinstance(workspace, SecureWorkspace):
            raise TypeError("workspace must be a SecureWorkspace")
        self._workspace = workspace

    def discover_model_response_artifacts(
        self,
        run_id: str,
        max_items: int,
        max_name_bytes: int,
        max_file_bytes: int,
        max_total_bytes: int,
    ) -> ModelResponseArtifactScan:
        controlled_run_id = require_reference_token(
            run_id,
            "model response artifact recovery run reference",
        )
        self._require_budget(
            max_items,
            MAX_MODEL_RESPONSE_RECOVERY_ITEMS,
            "max_items",
        )
        self._require_budget(
            max_name_bytes,
            MAX_MODEL_RESPONSE_RECOVERY_NAME_BYTES,
            "max_name_bytes",
        )
        self._require_budget(
            max_file_bytes,
            MAX_MODEL_RESPONSE_RECOVERY_FILE_BYTES,
            "max_file_bytes",
        )
        self._require_budget(
            max_total_bytes,
            MAX_MODEL_RESPONSE_RECOVERY_TOTAL_BYTES,
            "max_total_bytes",
        )
        if max_total_bytes < max_file_bytes:
            raise ValueError("max_total_bytes must cover at least one maximum-size file")
        candidates: list[ModelResponseArtifactCandidate] = []
        cleanup_candidates: list[ModelResponseEmptyOperationCandidate] = []
        anomalies: list[ModelResponseRecoveryItem] = []
        budget_exhaustions: list[ModelResponseRecoveryItem] = []
        bytes_scanned = 0
        complete = True

        staging_root = f".staging/{controlled_run_id}"
        try:
            staging_hints = self._list(staging_root, max_items, max_name_bytes)
        except BudgetExceeded:
            staging_hints = ()
            complete = False
        except PathBoundaryViolation as error:
            if error.reason_code == "DIRECTORY_MISSING":
                staging_hints = ()
            else:
                staging_hints = ()
                anomalies.append(
                    self._directory_anomaly(
                        controlled_run_id,
                        ModelResponseRecoveryArea.STAGED_RESPONSE,
                        staging_root,
                        ModelResponseRecoveryReason.UNSAFE_FILESYSTEM_ENTRY,
                    )
                )

        for operation_hint in staging_hints:
            if (
                len(candidates) + len(cleanup_candidates) + len(anomalies) + len(budget_exhaustions)
                >= max_items
            ):
                complete = False
                break
            operation = operation_hint.name
            if operation is None:
                anomalies.append(
                    self._hint_anomaly(
                        controlled_run_id,
                        ModelResponseRecoveryArea.STAGED_RESPONSE,
                        operation_hint,
                    )
                )
                continue
            response_match = _RESPONSE_OPERATION.fullmatch(operation)
            journal_match = _JOURNAL_OPERATION.fullmatch(operation)
            if response_match is not None:
                area = ModelResponseRecoveryArea.STAGED_RESPONSE
                authority_id = response_match.group("authority")
                expected_name = "response.json"
            elif journal_match is not None:
                area = ModelResponseRecoveryArea.JOURNAL
                authority_id = journal_match.group("authority")
                expected_name = "receipt.json"
            else:
                anomalies.append(
                    self._hint_anomaly(
                        controlled_run_id,
                        ModelResponseRecoveryArea.STAGED_RESPONSE,
                        operation_hint,
                    )
                )
                continue

            operation_relative = f"{staging_root}/{operation}"
            remaining = (
                max_items
                - len(candidates)
                - len(cleanup_candidates)
                - len(anomalies)
                - len(budget_exhaustions)
            )
            try:
                child_hints = self._list(
                    operation_relative,
                    remaining,
                    max_name_bytes,
                )
            except BudgetExceeded:
                complete = False
                break
            except PathBoundaryViolation as error:
                anomalies.append(
                    self._directory_anomaly(
                        controlled_run_id,
                        area,
                        operation_relative,
                        (
                            ModelResponseRecoveryReason.ENTRY_CHANGED_DURING_RECOVERY
                            if error.reason_code == "DIRECTORY_MISSING"
                            else ModelResponseRecoveryReason.UNSAFE_FILESYSTEM_ENTRY
                        ),
                    )
                )
                continue
            if not child_hints:
                cleanup_candidates.append(
                    ModelResponseEmptyOperationCandidate(
                        run_id=controlled_run_id,
                        area=area,
                        authority_id=authority_id,
                        source_token=recovery_source_token(operation_relative),
                    )
                )
                continue
            for child_hint in child_hints:
                if (
                    len(candidates)
                    + len(cleanup_candidates)
                    + len(anomalies)
                    + len(budget_exhaustions)
                    >= max_items
                ):
                    complete = False
                    break
                if child_hint.name != expected_name:
                    anomalies.append(
                        self._hint_anomaly(
                            controlled_run_id,
                            area,
                            child_hint,
                        )
                    )
                    continue
                relative_path = f"{operation_relative}/{expected_name}"
                read_limit = min(max_file_bytes, max_total_bytes - bytes_scanned)
                observed, consumed_bytes = self._candidate_or_anomaly(
                    controlled_run_id,
                    area,
                    authority_id,
                    relative_path,
                    child_hint,
                    read_limit,
                    read_limit < max_file_bytes,
                )
                bytes_scanned += consumed_bytes
                if isinstance(observed, ModelResponseArtifactCandidate):
                    candidates.append(observed)
                elif (
                    observed.reason_code
                    == ModelResponseRecoveryReason.ARTIFACT_TOTAL_BYTES_EXHAUSTED
                ):
                    budget_exhaustions.append(observed)
                    complete = False
                    break
                else:
                    anomalies.append(observed)
            if not complete:
                break

        final_root = f"{controlled_run_id}/model_responses"
        if complete:
            remaining = (
                max_items
                - len(candidates)
                - len(cleanup_candidates)
                - len(anomalies)
                - len(budget_exhaustions)
            )
            try:
                final_hints = self._list(final_root, remaining, max_name_bytes)
            except BudgetExceeded:
                final_hints = ()
                complete = False
            except PathBoundaryViolation as error:
                if error.reason_code == "DIRECTORY_MISSING":
                    final_hints = ()
                else:
                    final_hints = ()
                    anomalies.append(
                        self._directory_anomaly(
                            controlled_run_id,
                            ModelResponseRecoveryArea.FINAL_RESPONSE,
                            final_root,
                            ModelResponseRecoveryReason.UNSAFE_FILESYSTEM_ENTRY,
                        )
                    )
            for final_hint in final_hints:
                if (
                    len(candidates)
                    + len(cleanup_candidates)
                    + len(anomalies)
                    + len(budget_exhaustions)
                    >= max_items
                ):
                    complete = False
                    break
                match = (
                    _FINAL_RESPONSE.fullmatch(final_hint.name)
                    if final_hint.name is not None
                    else None
                )
                if match is None:
                    anomalies.append(
                        self._hint_anomaly(
                            controlled_run_id,
                            ModelResponseRecoveryArea.FINAL_RESPONSE,
                            final_hint,
                        )
                    )
                    continue
                authority_id = match.group("authority")
                relative_path = f"{final_root}/{final_hint.name}"
                read_limit = min(max_file_bytes, max_total_bytes - bytes_scanned)
                observed, consumed_bytes = self._candidate_or_anomaly(
                    controlled_run_id,
                    ModelResponseRecoveryArea.FINAL_RESPONSE,
                    authority_id,
                    relative_path,
                    final_hint,
                    read_limit,
                    read_limit < max_file_bytes,
                )
                bytes_scanned += consumed_bytes
                if isinstance(observed, ModelResponseArtifactCandidate):
                    candidates.append(observed)
                elif (
                    observed.reason_code
                    == ModelResponseRecoveryReason.ARTIFACT_TOTAL_BYTES_EXHAUSTED
                ):
                    budget_exhaustions.append(observed)
                    complete = False
                    break
                else:
                    anomalies.append(observed)

        return ModelResponseArtifactScan(
            run_id=controlled_run_id,
            max_items=max_items,
            max_file_bytes=max_file_bytes,
            max_total_bytes=max_total_bytes,
            bytes_scanned=bytes_scanned,
            candidates=tuple(sorted(candidates, key=lambda item: item.sort_key)),
            anomalies=tuple(sorted(anomalies, key=lambda item: item.sort_key)),
            complete=complete,
            cleanup_candidates=tuple(sorted(cleanup_candidates, key=lambda item: item.sort_key)),
            budget_exhaustions=tuple(sorted(budget_exhaustions, key=lambda item: item.sort_key)),
        )

    def cleanup_empty_model_response_operation(
        self,
        candidate: ModelResponseEmptyOperationCandidate,
        not_modified_after: datetime,
    ) -> ModelResponseRecoveryItem:
        if not isinstance(candidate, ModelResponseEmptyOperationCandidate):
            raise TypeError("candidate must be a ModelResponseEmptyOperationCandidate")
        source_relative = {
            ModelResponseRecoveryArea.STAGED_RESPONSE: (
                f".staging/{candidate.run_id}/model-response-{candidate.authority_id}"
            ),
            ModelResponseRecoveryArea.JOURNAL: (
                f".staging/{candidate.run_id}/model-request-{candidate.authority_id}"
            ),
        }[candidate.area]
        if recovery_source_token(source_relative) != candidate.source_token:
            raise ValueError("model response empty-operation token is not path-bound")
        try:
            if candidate.area == ModelResponseRecoveryArea.STAGED_RESPONSE:
                self._workspace.remove_empty_model_response_staging_directory(
                    source_relative,
                    not_modified_after,
                )
            else:
                self._workspace.remove_empty_model_response_journal_directory(
                    source_relative,
                    not_modified_after,
                )
        except ArtifactConflict:
            return self._empty_operation_anomaly(
                candidate,
                ModelResponseRecoveryReason.ENTRY_CHANGED_DURING_RECOVERY,
            )
        except PathBoundaryViolation as error:
            if error.reason_code == "DIRECTORY_TOO_YOUNG":
                return ModelResponseRecoveryItem(
                    run_id=candidate.run_id,
                    area=candidate.area,
                    source_token=candidate.source_token,
                    disposition=ModelResponseRecoveryDisposition.RETAINED,
                    reason_code=ModelResponseRecoveryReason.MINIMUM_AGE_NOT_MET,
                )
            return self._empty_operation_anomaly(
                candidate,
                (
                    ModelResponseRecoveryReason.ENTRY_CHANGED_DURING_RECOVERY
                    if error.reason_code
                    in {
                        "DIRECTORY_MISSING",
                        "SOURCE_OR_PARENT_MISSING",
                    }
                    else ModelResponseRecoveryReason.UNSAFE_FILESYSTEM_ENTRY
                ),
            )
        return ModelResponseRecoveryItem(
            run_id=candidate.run_id,
            area=candidate.area,
            source_token=candidate.source_token,
            disposition=ModelResponseRecoveryDisposition.CLEANED,
            reason_code=ModelResponseRecoveryReason.EMPTY_OPERATION_CLEANED,
        )

    def quarantine_model_response_artifact(
        self,
        candidate: ModelResponseArtifactCandidate,
        not_modified_after: datetime,
        max_file_bytes: int,
    ) -> ModelResponseRecoveryItem:
        if not isinstance(candidate, ModelResponseArtifactCandidate):
            raise TypeError("candidate must be a ModelResponseArtifactCandidate")
        self._require_budget(
            max_file_bytes,
            MAX_MODEL_RESPONSE_RECOVERY_FILE_BYTES,
            "max_file_bytes",
        )
        if candidate.size_bytes > max_file_bytes:
            raise ValueError("candidate exceeds the model response file-byte limit")
        source_relative = self._source_relative(candidate)
        if recovery_source_token(source_relative) != candidate.source_token:
            raise ValueError("model response artifact source token is not path-bound")
        area_name, reason = {
            ModelResponseRecoveryArea.STAGED_RESPONSE: (
                "staging",
                ModelResponseRecoveryReason.ORPHAN_STAGE_QUARANTINED,
            ),
            ModelResponseRecoveryArea.FINAL_RESPONSE: (
                "final",
                ModelResponseRecoveryReason.ORPHAN_FINAL_QUARANTINED,
            ),
            ModelResponseRecoveryArea.JOURNAL: (
                "journal",
                ModelResponseRecoveryReason.ORPHAN_JOURNAL_QUARANTINED,
            ),
        }[candidate.area]
        quarantine_directory = f".quarantine/{candidate.run_id}/model_responses/{area_name}"
        try:
            for directory in (
                ".quarantine",
                f".quarantine/{candidate.run_id}",
                f".quarantine/{candidate.run_id}/model_responses",
                quarantine_directory,
            ):
                self._workspace.ensure_private_directory(directory)
            moved = self._workspace.quarantine_model_response_recovery(
                source_relative,
                candidate.content_sha256,
                not_modified_after,
                max_bytes=candidate.size_bytes,
            )
            if candidate.area != ModelResponseRecoveryArea.FINAL_RESPONSE:
                operation_relative = source_relative.rsplit("/", 1)[0]
                try:
                    if candidate.area == ModelResponseRecoveryArea.STAGED_RESPONSE:
                        self._workspace.remove_empty_model_response_staging_directory(
                            operation_relative
                        )
                    else:
                        self._workspace.remove_empty_model_response_journal_directory(
                            operation_relative
                        )
                except ArtifactConflict:
                    return self._mutation_anomaly(
                        candidate,
                        ModelResponseRecoveryReason.ENTRY_CHANGED_DURING_RECOVERY,
                    )
                except PathBoundaryViolation as error:
                    return self._mutation_anomaly(
                        candidate,
                        (
                            ModelResponseRecoveryReason.ENTRY_CHANGED_DURING_RECOVERY
                            if error.reason_code
                            in {
                                "DIRECTORY_MISSING",
                                "SOURCE_OR_PARENT_MISSING",
                            }
                            else ModelResponseRecoveryReason.UNSAFE_FILESYSTEM_ENTRY
                        ),
                    )
            return ModelResponseRecoveryItem(
                run_id=candidate.run_id,
                area=candidate.area,
                source_token=candidate.source_token,
                content_sha256=candidate.content_sha256,
                quarantine_relative_path=moved.relative_path,
                disposition=ModelResponseRecoveryDisposition.QUARANTINED,
                reason_code=reason,
            )
        except PathBoundaryViolation as error:
            if error.reason_code == "FILE_TOO_YOUNG":
                return self._retained_too_young(candidate)
            if error.reason_code == "FILE_TOO_LARGE":
                return self._mutation_anomaly(
                    candidate,
                    ModelResponseRecoveryReason.ENTRY_CHANGED_DURING_RECOVERY,
                )
            return self._mutation_anomaly(
                candidate,
                (
                    ModelResponseRecoveryReason.ENTRY_CHANGED_DURING_RECOVERY
                    if error.reason_code
                    in {"FILE_MISSING", "SOURCE_OR_PARENT_MISSING", "DIRECTORY_MISSING"}
                    else ModelResponseRecoveryReason.UNSAFE_FILESYSTEM_ENTRY
                ),
            )
        except ArtifactIntegrityViolation:
            return self._mutation_anomaly(
                candidate,
                self._content_failure_reason(candidate.area),
            )
        except ArtifactConflict:
            return self._mutation_anomaly(
                candidate,
                ModelResponseRecoveryReason.RESPONSE_CONFLICT,
            )

    def _list(
        self,
        relative_path: str,
        max_items: int,
        max_name_bytes: int,
    ) -> tuple[SecureDirectoryHint, ...]:
        return self._workspace.list_model_response_recovery_directory(
            relative_path,
            max_items,
            max_name_bytes,
        )

    def _candidate_or_anomaly(
        self,
        run_id: str,
        area: ModelResponseRecoveryArea,
        authority_id: str,
        relative_path: str,
        hint: SecureDirectoryHint,
        max_read_bytes: int,
        aggregate_limited: bool,
    ) -> tuple[ModelResponseArtifactCandidate | ModelResponseRecoveryItem, int]:
        try:
            snapshot = self._workspace.read_verified(
                relative_path,
                max_bytes=max_read_bytes,
            )
        except ArtifactIntegrityViolation:
            return (
                ModelResponseRecoveryItem(
                    run_id=run_id,
                    area=area,
                    source_token=hint.source_token,
                    disposition=ModelResponseRecoveryDisposition.ANOMALY,
                    reason_code=self._content_failure_reason(area),
                ),
                max_read_bytes,
            )
        except PathBoundaryViolation as error:
            if error.reason_code == "FILE_TOO_LARGE":
                return (
                    ModelResponseRecoveryItem(
                        run_id=run_id,
                        area=area,
                        source_token=hint.source_token,
                        disposition=(
                            ModelResponseRecoveryDisposition.RETAINED
                            if aggregate_limited
                            else ModelResponseRecoveryDisposition.ANOMALY
                        ),
                        reason_code=(
                            ModelResponseRecoveryReason.ARTIFACT_TOTAL_BYTES_EXHAUSTED
                            if aggregate_limited
                            else ModelResponseRecoveryReason.ARTIFACT_FILE_BYTES_EXCEEDED
                        ),
                    ),
                    0,
                )
            return (
                ModelResponseRecoveryItem(
                    run_id=run_id,
                    area=area,
                    source_token=hint.source_token,
                    disposition=ModelResponseRecoveryDisposition.ANOMALY,
                    reason_code=(
                        ModelResponseRecoveryReason.ENTRY_CHANGED_DURING_RECOVERY
                        if error.reason_code in {"FILE_MISSING", "SOURCE_OR_PARENT_MISSING"}
                        else ModelResponseRecoveryReason.UNSAFE_FILESYSTEM_ENTRY
                    ),
                ),
                0,
            )
        expected_token = recovery_source_token(relative_path)
        if hint.source_token != expected_token:
            return (
                ModelResponseRecoveryItem(
                    run_id=run_id,
                    area=area,
                    source_token=hint.source_token,
                    content_sha256=snapshot.sha256,
                    disposition=ModelResponseRecoveryDisposition.ANOMALY,
                    reason_code=self._content_failure_reason(area),
                ),
                snapshot.size_bytes,
            )
        return (
            ModelResponseArtifactCandidate(
                run_id=run_id,
                area=area,
                authority_id=authority_id,
                source_token=hint.source_token,
                content_sha256=snapshot.sha256,
                size_bytes=snapshot.size_bytes,
            ),
            snapshot.size_bytes,
        )

    @staticmethod
    def _hint_anomaly(
        run_id: str,
        area: ModelResponseRecoveryArea,
        hint: SecureDirectoryHint,
    ) -> ModelResponseRecoveryItem:
        return ModelResponseRecoveryItem(
            run_id=run_id,
            area=area,
            source_token=hint.source_token,
            disposition=ModelResponseRecoveryDisposition.ANOMALY,
            reason_code=ModelResponseRecoveryReason.UNKNOWN_ENTRY_SHAPE,
        )

    @staticmethod
    def _directory_anomaly(
        run_id: str,
        area: ModelResponseRecoveryArea,
        relative_path: str,
        reason: ModelResponseRecoveryReason,
    ) -> ModelResponseRecoveryItem:
        return ModelResponseRecoveryItem(
            run_id=run_id,
            area=area,
            source_token=recovery_source_token(relative_path),
            disposition=ModelResponseRecoveryDisposition.ANOMALY,
            reason_code=reason,
        )

    @staticmethod
    def _source_relative(candidate: ModelResponseArtifactCandidate) -> str:
        return {
            ModelResponseRecoveryArea.STAGED_RESPONSE: (
                f".staging/{candidate.run_id}/model-response-{candidate.authority_id}/response.json"
            ),
            ModelResponseRecoveryArea.FINAL_RESPONSE: (
                f"{candidate.run_id}/model_responses/{candidate.authority_id}.json"
            ),
            ModelResponseRecoveryArea.JOURNAL: (
                f".staging/{candidate.run_id}/model-request-{candidate.authority_id}/receipt.json"
            ),
        }[candidate.area]

    @staticmethod
    def _retained_too_young(
        candidate: ModelResponseArtifactCandidate,
    ) -> ModelResponseRecoveryItem:
        return ModelResponseRecoveryItem(
            run_id=candidate.run_id,
            area=candidate.area,
            source_token=candidate.source_token,
            content_sha256=candidate.content_sha256,
            disposition=ModelResponseRecoveryDisposition.RETAINED,
            reason_code=ModelResponseRecoveryReason.MINIMUM_AGE_NOT_MET,
        )

    @staticmethod
    def _mutation_anomaly(
        candidate: ModelResponseArtifactCandidate,
        reason: ModelResponseRecoveryReason,
    ) -> ModelResponseRecoveryItem:
        return ModelResponseRecoveryItem(
            run_id=candidate.run_id,
            area=candidate.area,
            source_token=candidate.source_token,
            content_sha256=candidate.content_sha256,
            disposition=ModelResponseRecoveryDisposition.ANOMALY,
            reason_code=reason,
        )

    @staticmethod
    def _empty_operation_anomaly(
        candidate: ModelResponseEmptyOperationCandidate,
        reason: ModelResponseRecoveryReason,
    ) -> ModelResponseRecoveryItem:
        return ModelResponseRecoveryItem(
            run_id=candidate.run_id,
            area=candidate.area,
            source_token=candidate.source_token,
            disposition=ModelResponseRecoveryDisposition.ANOMALY,
            reason_code=reason,
        )

    @staticmethod
    def _content_failure_reason(
        area: ModelResponseRecoveryArea,
    ) -> ModelResponseRecoveryReason:
        return (
            ModelResponseRecoveryReason.JOURNAL_INTEGRITY_FAILURE
            if area == ModelResponseRecoveryArea.JOURNAL
            else ModelResponseRecoveryReason.CONTENT_IDENTITY_MISMATCH
        )

    @staticmethod
    def _require_budget(value: int, upper_bound: int, name: str) -> None:
        if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= upper_bound:
            raise ValueError(f"{name} must be an integer from 1 through {upper_bound}")


__all__ = ["SecureModelResponseArtifactRecovery"]

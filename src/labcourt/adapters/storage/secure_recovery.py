"""Handle-verified bounded discovery and quarantine for M2 startup recovery."""

from __future__ import annotations

import re
from contextlib import suppress
from datetime import datetime

from labcourt.adapters.storage.secure_workspace import SecureDirectoryHint, SecureWorkspace
from labcourt.contracts.enums import (
    RecoveryArea,
    RecoveryDisposition,
    RecoveryReasonCode,
)
from labcourt.contracts.recovery import RecoveryItemResult, recovery_source_token
from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import (
    ArtifactConflict,
    ArtifactIntegrityViolation,
    BudgetExceeded,
    PathBoundaryViolation,
)
from labcourt.ports.recovery import (
    MAX_RECOVERY_DEPTH,
    MAX_RECOVERY_ITEMS,
    MAX_RECOVERY_NAME_BYTES,
    RecoveryCandidate,
    RecoveryScan,
    StagingCleanupCandidate,
)

_STAGING_OPERATION = re.compile(r"^crop-[0-9a-f]{64}$")
_MODEL_RESPONSE_STAGING_PREFIXES = ("model-response-", "model-request-")
_FINAL_MEDIA_NAME = re.compile(r"^(?P<sha256>[0-9a-f]{64})\.png$")
_MISSING_REASONS = frozenset(
    {
        "DIRECTORY_MISSING",
        "FILE_MISSING",
        "SOURCE_OR_PARENT_MISSING",
        "ENTRY_IDENTITY_CHANGED",
        "IDENTITY_CHANGED",
    }
)


class SecureOrphanRecoveryFileOps:
    """Treat enumeration as hints and re-open every candidate before acting."""

    __slots__ = ("_workspace",)

    def __init__(self, workspace: SecureWorkspace) -> None:
        if not isinstance(workspace, SecureWorkspace):
            raise TypeError("workspace must be a SecureWorkspace")
        self._workspace = workspace

    def discover(
        self,
        run_id: str,
        max_items: int,
        max_depth: int,
        max_name_bytes: int,
    ) -> RecoveryScan:
        controlled_run_id = require_reference_token(run_id, "recovery run_id")
        self._require_budget(max_items, "max_items", upper_bound=MAX_RECOVERY_ITEMS)
        self._require_budget(max_depth, "max_depth", upper_bound=MAX_RECOVERY_DEPTH)
        self._require_budget(
            max_name_bytes,
            "max_name_bytes",
            upper_bound=MAX_RECOVERY_NAME_BYTES,
        )

        candidates: list[RecoveryCandidate] = []
        cleanup_candidates: list[StagingCleanupCandidate] = []
        anomalies: list[RecoveryItemResult] = []
        staging_consumed = 0

        staging_root = f".staging/{controlled_run_id}"
        shared_staging_hints = self._list_optional(
            staging_root,
            max_items * 3,
            max_name_bytes,
        )
        model_response_counts = tuple(
            sum(
                hint.name is not None and hint.name.startswith(prefix)
                for hint in shared_staging_hints
            )
            for prefix in _MODEL_RESPONSE_STAGING_PREFIXES
        )
        staging_hints = tuple(
            hint
            for hint in shared_staging_hints
            if hint.name is None or not hint.name.startswith(_MODEL_RESPONSE_STAGING_PREFIXES)
        )
        if (
            any(count > max_items for count in model_response_counts)
            or len(staging_hints) > max_items
        ):
            raise BudgetExceeded("staging recovery namespace exceeded its item budget")
        staging_consumed += len(staging_hints)
        for operation_hint in staging_hints:
            if operation_hint.name is None:
                anomalies.append(
                    self._hint_anomaly(
                        controlled_run_id,
                        RecoveryArea.STAGING,
                        operation_hint,
                    )
                )
                continue
            operation_path = f"{staging_root}/{operation_hint.name}"
            operation_token = recovery_source_token(operation_path)
            # M3 response staging is owned by its dedicated bounded recovery pass.
            # The M2 media scanner must neither descend into it nor report it as an
            # unknown anomaly merely because both operations share `.staging/<run>`.
            if operation_hint.name.startswith(_MODEL_RESPONSE_STAGING_PREFIXES):
                continue
            if _STAGING_OPERATION.fullmatch(operation_hint.name) is None:
                anomalies.append(
                    self._anomaly(
                        controlled_run_id,
                        RecoveryArea.STAGING,
                        operation_token,
                        RecoveryReasonCode.UNKNOWN_ENTRY_SHAPE,
                    )
                )
                continue
            if max_depth < 2:
                anomalies.append(
                    self._anomaly(
                        controlled_run_id,
                        RecoveryArea.STAGING,
                        operation_token,
                        RecoveryReasonCode.DEPTH_LIMIT_REACHED,
                    )
                )
                continue
            try:
                file_hints = self._workspace.list_recovery_directory(
                    operation_path,
                    max_items - staging_consumed,
                    max_name_bytes,
                )
            except PathBoundaryViolation as error:
                anomalies.append(
                    self._anomaly(
                        controlled_run_id,
                        RecoveryArea.STAGING,
                        operation_token,
                        self._path_failure_reason(error),
                    )
                )
                continue
            staging_consumed += len(file_hints)
            if not file_hints:
                cleanup_candidates.append(
                    StagingCleanupCandidate(
                        run_id=controlled_run_id,
                        source_relative_path=operation_path,
                        source_token=operation_token,
                    )
                )
                continue
            for file_hint in file_hints:
                if file_hint.name is None:
                    anomalies.append(
                        self._hint_anomaly(
                            controlled_run_id,
                            RecoveryArea.STAGING,
                            file_hint,
                        )
                    )
                    continue
                source_path = f"{operation_path}/{file_hint.name}"
                source_token = recovery_source_token(source_path)
                if file_hint.name != "media.png":
                    anomalies.append(
                        self._anomaly(
                            controlled_run_id,
                            RecoveryArea.STAGING,
                            source_token,
                            RecoveryReasonCode.UNKNOWN_ENTRY_SHAPE,
                        )
                    )
                    continue
                candidate, anomaly = self._inspect_candidate(
                    controlled_run_id,
                    RecoveryArea.STAGING,
                    source_path,
                    expected_sha256=None,
                )
                if candidate is not None:
                    candidates.append(candidate)
                elif anomaly is not None:
                    anomalies.append(anomaly)

        final_root = f"{controlled_run_id}/frames"
        final_hints = self._list_optional(
            final_root,
            max_items,
            max_name_bytes,
        )
        for final_hint in final_hints:
            if final_hint.name is None:
                anomalies.append(
                    self._hint_anomaly(
                        controlled_run_id,
                        RecoveryArea.FINAL_MEDIA,
                        final_hint,
                    )
                )
                continue
            source_path = f"{final_root}/{final_hint.name}"
            source_token = recovery_source_token(source_path)
            matched = _FINAL_MEDIA_NAME.fullmatch(final_hint.name)
            if matched is None:
                anomalies.append(
                    self._anomaly(
                        controlled_run_id,
                        RecoveryArea.FINAL_MEDIA,
                        source_token,
                        RecoveryReasonCode.UNKNOWN_ENTRY_SHAPE,
                    )
                )
                continue
            candidate, anomaly = self._inspect_candidate(
                controlled_run_id,
                RecoveryArea.FINAL_MEDIA,
                source_path,
                expected_sha256=matched.group("sha256"),
            )
            if candidate is not None:
                candidates.append(candidate)
            elif anomaly is not None:
                anomalies.append(anomaly)

        # Staging and final media are independent fixed roots. Each gets a complete
        # bounded scan so a full staging budget cannot permanently hide final orphans.
        if staging_consumed > max_items or len(final_hints) > max_items:
            raise AssertionError("secure workspace exceeded an enforced recovery-area budget")
        return RecoveryScan(
            run_id=controlled_run_id,
            candidates=tuple(sorted(candidates, key=lambda item: item.sort_key)),
            staging_cleanup_candidates=tuple(
                sorted(cleanup_candidates, key=lambda item: item.sort_key)
            ),
            anomalies=tuple(sorted(anomalies, key=lambda item: item.sort_key)),
        )

    def quarantine(
        self,
        candidate: RecoveryCandidate,
        not_modified_after: datetime,
    ) -> RecoveryItemResult:
        if not isinstance(candidate, RecoveryCandidate):
            raise TypeError("candidate must be a RecoveryCandidate")
        self._ensure_quarantine_directories(candidate)
        try:
            snapshot = self._workspace.quarantine_recovery(
                candidate.source_relative_path,
                candidate.content_sha256,
                not_modified_after,
            )
        except ArtifactConflict:
            return self._anomaly(
                candidate.run_id,
                candidate.area,
                candidate.source_token,
                RecoveryReasonCode.CONTENT_IDENTITY_MISMATCH,
                content_sha256=candidate.content_sha256,
            )
        except ArtifactIntegrityViolation:
            return self._anomaly(
                candidate.run_id,
                candidate.area,
                candidate.source_token,
                RecoveryReasonCode.CONTENT_IDENTITY_MISMATCH,
                content_sha256=candidate.content_sha256,
            )
        except PathBoundaryViolation as error:
            if error.reason_code == "FILE_TOO_YOUNG":
                return RecoveryItemResult(
                    run_id=candidate.run_id,
                    area=candidate.area,
                    source_token=candidate.source_token,
                    disposition=RecoveryDisposition.RETAINED,
                    reason_code=RecoveryReasonCode.MINIMUM_AGE_NOT_MET,
                    content_sha256=candidate.content_sha256,
                )
            return self._anomaly(
                candidate.run_id,
                candidate.area,
                candidate.source_token,
                self._path_failure_reason(error),
                content_sha256=candidate.content_sha256,
            )

        expected_path = self._quarantine_path(candidate)
        if snapshot.relative_path != expected_path or snapshot.sha256 != candidate.content_sha256:
            raise ArtifactIntegrityViolation(
                "QUARANTINE_RECEIPT_MISMATCH",
                candidate.source_relative_path,
            )
        reason = (
            RecoveryReasonCode.ORPHAN_QUARANTINED
            if candidate.area == RecoveryArea.FINAL_MEDIA
            else RecoveryReasonCode.STAGING_QUARANTINED
        )
        if candidate.area == RecoveryArea.STAGING:
            operation_directory = candidate.source_relative_path.removesuffix("/media.png")
            # The file move is already complete.  A concurrently added entry must
            # not turn that valid quarantine into an unreported partial result;
            # the next bounded scan will classify the remaining directory.
            with suppress(ArtifactConflict, PathBoundaryViolation):
                self._workspace.remove_empty_staging_directory(operation_directory)
        return RecoveryItemResult(
            run_id=candidate.run_id,
            area=candidate.area,
            source_token=candidate.source_token,
            disposition=RecoveryDisposition.QUARANTINED,
            reason_code=reason,
            content_sha256=candidate.content_sha256,
            quarantine_relative_path=expected_path,
        )

    def cleanup_empty_staging(
        self,
        candidate: StagingCleanupCandidate,
        not_modified_after: datetime,
    ) -> RecoveryItemResult:
        if not isinstance(candidate, StagingCleanupCandidate):
            raise TypeError("candidate must be a StagingCleanupCandidate")
        try:
            self._workspace.remove_empty_staging_directory(
                candidate.source_relative_path,
                not_modified_after,
            )
        except ArtifactConflict:
            return self._anomaly(
                candidate.run_id,
                RecoveryArea.STAGING,
                candidate.source_token,
                RecoveryReasonCode.ENTRY_CHANGED_DURING_RECOVERY,
            )
        except PathBoundaryViolation as error:
            if error.reason_code == "DIRECTORY_TOO_YOUNG":
                return RecoveryItemResult(
                    run_id=candidate.run_id,
                    area=RecoveryArea.STAGING,
                    source_token=candidate.source_token,
                    disposition=RecoveryDisposition.RETAINED,
                    reason_code=RecoveryReasonCode.MINIMUM_AGE_NOT_MET,
                )
            return self._anomaly(
                candidate.run_id,
                RecoveryArea.STAGING,
                candidate.source_token,
                self._path_failure_reason(error),
            )
        return RecoveryItemResult(
            run_id=candidate.run_id,
            area=RecoveryArea.STAGING,
            source_token=candidate.source_token,
            disposition=RecoveryDisposition.CLEANED,
            reason_code=RecoveryReasonCode.EMPTY_STAGING_CLEANED,
        )

    def _inspect_candidate(
        self,
        run_id: str,
        area: RecoveryArea,
        source_path: str,
        *,
        expected_sha256: str | None,
    ) -> tuple[RecoveryCandidate | None, RecoveryItemResult | None]:
        source_token = recovery_source_token(source_path)
        try:
            snapshot = self._workspace.read_verified(source_path)
        except ArtifactIntegrityViolation:
            return None, self._anomaly(
                run_id,
                area,
                source_token,
                RecoveryReasonCode.CONTENT_IDENTITY_MISMATCH,
            )
        except PathBoundaryViolation as error:
            return None, self._anomaly(
                run_id,
                area,
                source_token,
                self._path_failure_reason(error),
            )
        if expected_sha256 is not None and snapshot.sha256 != expected_sha256:
            return None, self._anomaly(
                run_id,
                area,
                source_token,
                RecoveryReasonCode.CONTENT_IDENTITY_MISMATCH,
                content_sha256=snapshot.sha256,
            )
        return (
            RecoveryCandidate(
                run_id=run_id,
                area=area,
                source_relative_path=source_path,
                source_token=source_token,
                content_sha256=snapshot.sha256,
            ),
            None,
        )

    def _list_optional(
        self,
        relative_path: str,
        max_items: int,
        max_name_bytes: int,
    ) -> tuple[SecureDirectoryHint, ...]:
        try:
            return self._workspace.list_recovery_directory(
                relative_path,
                max_items,
                max_name_bytes,
            )
        except PathBoundaryViolation as error:
            if error.reason_code == "DIRECTORY_MISSING":
                return ()
            raise

    def _ensure_quarantine_directories(self, candidate: RecoveryCandidate) -> None:
        leaf = "frames" if candidate.area == RecoveryArea.FINAL_MEDIA else "staging"
        for relative_path in (
            ".quarantine",
            f".quarantine/{candidate.run_id}",
            f".quarantine/{candidate.run_id}/{leaf}",
        ):
            self._workspace.ensure_private_directory(relative_path)

    @staticmethod
    def _quarantine_path(candidate: RecoveryCandidate) -> str:
        if candidate.area == RecoveryArea.FINAL_MEDIA:
            return f".quarantine/{candidate.run_id}/frames/{candidate.content_sha256}.png"
        return (
            f".quarantine/{candidate.run_id}/staging/"
            f"{candidate.source_token}-{candidate.content_sha256}.bin"
        )

    @staticmethod
    def _hint_anomaly(
        run_id: str,
        area: RecoveryArea,
        hint: SecureDirectoryHint,
    ) -> RecoveryItemResult:
        return SecureOrphanRecoveryFileOps._anomaly(
            run_id,
            area,
            hint.source_token,
            RecoveryReasonCode.UNSAFE_FILESYSTEM_ENTRY,
        )

    @staticmethod
    def _anomaly(
        run_id: str,
        area: RecoveryArea,
        source_token: str,
        reason: RecoveryReasonCode,
        *,
        content_sha256: str | None = None,
    ) -> RecoveryItemResult:
        return RecoveryItemResult(
            run_id=run_id,
            area=area,
            source_token=source_token,
            disposition=RecoveryDisposition.ANOMALY,
            reason_code=reason,
            content_sha256=content_sha256,
        )

    @staticmethod
    def _path_failure_reason(error: PathBoundaryViolation) -> RecoveryReasonCode:
        if error.reason_code in _MISSING_REASONS:
            return RecoveryReasonCode.ENTRY_CHANGED_DURING_RECOVERY
        return RecoveryReasonCode.UNSAFE_FILESYSTEM_ENTRY

    @staticmethod
    def _require_budget(value: int, name: str, *, upper_bound: int) -> None:
        if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= upper_bound:
            raise ValueError(f"{name} must be an integer from 1 through {upper_bound}")


__all__ = ["SecureOrphanRecoveryFileOps"]

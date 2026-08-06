"""Bounded M5 close coordinator over deterministic policy and SQLite ports."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from labcourt.contracts.alert_policy import AlertCooldownKey
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import CaseStatus
from labcourt.contracts.m5_operations import M5CloseCaseOutcome, M5FinalizeCommandReport
from labcourt.contracts.m5_precedent_usage import (
    M5PrecedentApplicationBatchAuthority,
    M5PrecedentApplicationCitationCommit,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.references import require_reference_token
from labcourt.ports.alert_policy import AlertPolicyRepository, AlertPolicyVerifier
from labcourt.ports.m5_precedent_usage import (
    M5PrecedentApplicationRepository,
    M5ReadyPrecedentUsageKind,
)
from labcourt.ports.m5_precedents import M5PrecedentEmbeddingProvider

from .m5_automatic_precedent import build_automatic_precedent_authority
from .m5_precedent_usage import (
    build_m5_precedent_application_batch,
    build_m5_precedent_application_citation_commits,
)

MAX_M5_FINALIZE_CASES = 256


class M5FinalizationRepository(
    AlertPolicyRepository,
    M5PrecedentApplicationRepository,
    Protocol,
):
    """Complete read/rebuild/atomic-write surface used by finalization."""


class M5FinalizationErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    AUTHORITY_SCOPE_MISMATCH = "AUTHORITY_SCOPE_MISMATCH"
    COMMIT_RESULT_INVALID = "COMMIT_RESULT_INVALID"


class M5FinalizationError(RuntimeError):
    def __init__(self, code: M5FinalizationErrorCode) -> None:
        self.code = code
        super().__init__(code.value)


class M5FinalizationCoordinator:
    def __init__(
        self,
        *,
        repository: M5FinalizationRepository,
        verifier: AlertPolicyVerifier,
        embedding_provider: M5PrecedentEmbeddingProvider,
        config: AppConfig,
        manifest: RunManifest,
        clock: Callable[[], datetime],
    ) -> None:
        if not isinstance(config, AppConfig) or not isinstance(manifest, RunManifest):
            raise M5FinalizationError(M5FinalizationErrorCode.INVALID_ARGUMENT)
        if manifest.config_sha256 != config.config_sha256:
            raise M5FinalizationError(M5FinalizationErrorCode.AUTHORITY_SCOPE_MISMATCH)
        self._repository = repository
        self._verifier = verifier
        self._embedding_provider = embedding_provider
        self._config = config
        self._manifest = manifest
        self._clock = clock

    def finalize(
        self,
        run_id: str,
        *,
        limit: int = MAX_M5_FINALIZE_CASES,
    ) -> M5FinalizeCommandReport:
        try:
            controlled_run_id = require_reference_token(run_id, "M5 finalize run_id")
        except (TypeError, ValueError):
            raise M5FinalizationError(M5FinalizationErrorCode.INVALID_ARGUMENT) from None
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= MAX_M5_FINALIZE_CASES
        ):
            raise M5FinalizationError(M5FinalizationErrorCode.INVALID_ARGUMENT)

        snapshots = self._repository.list_ready_cases(controlled_run_id, limit)
        ordered = tuple(sorted(snapshots, key=lambda item: item.case.case_id))
        if len(ordered) != len({item.case.case_id for item in ordered}):
            raise M5FinalizationError(M5FinalizationErrorCode.COMMIT_RESULT_INVALID)

        outcomes: list[M5CloseCaseOutcome] = []
        for snapshot in ordered:
            case = snapshot.case
            if (
                case.run_id != controlled_run_id
                or case.manifest_id != self._manifest.manifest_id
                or snapshot.revision <= 0
                or case.status != CaseStatus.READY_FOR_ALERT_POLICY
            ):
                raise M5FinalizationError(M5FinalizationErrorCode.AUTHORITY_SCOPE_MISMATCH)

            preliminary = self._verifier.rebuild(case, self._manifest, None, None)
            request = preliminary.request
            cooldown_key = (
                AlertCooldownKey(
                    zone_id=request.zone_id,
                    violation_type=request.violation_type,
                    track_ref=request.primary_track_ref,
                )
                if request.primary_track_ref is not None
                else None
            )
            prior_cooldown = (
                self._repository.load_current_cooldown(
                    controlled_run_id,
                    cooldown_key,
                    request.stream_id,
                    request.stream_authority_sha256,
                )
                if cooldown_key is not None
                else None
            )
            authority = self._verifier.rebuild(
                case,
                self._manifest,
                prior_cooldown,
                None,
            )
            operation_time = self._clock()
            usage = self._repository.resolve_ready_precedent_usage(
                controlled_run_id,
                case.case_id,
                snapshot.revision,
            )
            application_batch: M5PrecedentApplicationBatchAuthority | None = None
            application_citations: tuple[M5PrecedentApplicationCitationCommit, ...] = ()
            if usage.kind == M5ReadyPrecedentUsageKind.FINAL_EXPOSED:
                if usage.exposure is None:
                    raise M5FinalizationError(M5FinalizationErrorCode.COMMIT_RESULT_INVALID)
                application_batch = build_m5_precedent_application_batch(
                    case_snapshot=snapshot,
                    exposure=usage.exposure,
                    config=self._config,
                )
                application_citations = build_m5_precedent_application_citation_commits(
                    application_batch=application_batch,
                    cited_at=operation_time,
                )
            automatic = build_automatic_precedent_authority(
                case=case,
                manifest=self._manifest,
                alert_authority=authority,
                config=self._config,
                embedding_provider=self._embedding_provider,
                created_at=operation_time,
            )
            committed = self._repository.commit_alert_policy(
                controlled_run_id,
                snapshot.revision,
                authority,
                automatic,
                application_batch,
                application_citations,
            )
            if (
                committed.revision != snapshot.revision + 1
                or committed.case.case_id != case.case_id
                or committed.case.status != CaseStatus.CLOSED
                or committed.case.final_decision != authority.final_decision
            ):
                raise M5FinalizationError(M5FinalizationErrorCode.COMMIT_RESULT_INVALID)
            outcomes.append(
                M5CloseCaseOutcome(
                    case_id=case.case_id,
                    source_revision=snapshot.revision,
                    closed_revision=committed.revision,
                    disposition=authority.disposition,
                    alert_id=(
                        authority.decision.alert_id if authority.decision is not None else None
                    ),
                    alert_policy_authority_id=authority.authority_id,
                    automatic_precedent_id=automatic.precedent.precedent_id,
                    automatic_precedent_authority_id=automatic.authority_id,
                    application_batch_id=(
                        application_batch.application_batch_id
                        if application_batch is not None
                        else None
                    ),
                    applied_citation_count=len(application_citations),
                )
            )
        return M5FinalizeCommandReport(
            run_id=controlled_run_id,
            manifest_id=self._manifest.manifest_id,
            config_sha256=self._config.config_sha256,
            selected_count=len(ordered),
            outcomes=tuple(outcomes),
        )


__all__ = [
    "MAX_M5_FINALIZE_CASES",
    "M5FinalizationCoordinator",
    "M5FinalizationError",
    "M5FinalizationErrorCode",
]

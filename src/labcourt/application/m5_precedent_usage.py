"""Pure builders for M5 precedent APPLIED and citation authorities.

The functions in this module consume only explicit frozen authorities.  They
perform no repository access, provider calls, or wall-clock reads.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from typing import NoReturn

from pydantic import ValidationError

from labcourt.application.m5_precedents import m5_precedent_policy_from_config
from labcourt.contracts.cases import Case
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import CaseStatus, RunMode
from labcourt.contracts.m5_precedent_usage import (
    M5PrecedentApplicationBatchAuthority,
    M5PrecedentApplicationBinding,
    M5PrecedentApplicationCitationCommit,
    M5PrecedentExposureBatchAuthority,
)
from labcourt.contracts.m5_precedents import M5PrecedentCitationAuthority
from labcourt.exceptions import ContractViolation
from labcourt.ports.evidence_repository import CaseSnapshot


class M5PrecedentUsageErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    INVALID_CASE_SNAPSHOT = "INVALID_CASE_SNAPSHOT"
    INVALID_EXPOSURE = "INVALID_EXPOSURE"
    CASE_NOT_READY = "CASE_NOT_READY"
    AUTHORITY_SCOPE_MISMATCH = "AUTHORITY_SCOPE_MISMATCH"
    CONFIG_AUTHORITY_MISMATCH = "CONFIG_AUTHORITY_MISMATCH"
    VERDICT_APPLICATION_INVALID = "VERDICT_APPLICATION_INVALID"
    INVALID_APPLICATION_BATCH = "INVALID_APPLICATION_BATCH"
    INVALID_CITATION_TIME = "INVALID_CITATION_TIME"
    CITATION_CONTRACT_VIOLATION = "CITATION_CONTRACT_VIOLATION"


class M5PrecedentUsageError(ContractViolation):
    """Typed fail-closed error for pure M5 precedent-usage construction."""

    def __init__(self, code: M5PrecedentUsageErrorCode) -> None:
        if not isinstance(code, M5PrecedentUsageErrorCode):
            raise TypeError("code must be an M5PrecedentUsageErrorCode")
        self.code = code
        super().__init__(code.value)


def _fail(
    code: M5PrecedentUsageErrorCode,
    cause: Exception | None = None,
) -> NoReturn:
    error = M5PrecedentUsageError(code)
    if cause is None:
        raise error
    raise error from cause


def _canonical_case_snapshot(snapshot: object) -> tuple[Case, int]:
    if not isinstance(snapshot, CaseSnapshot) or not isinstance(snapshot.case, Case):
        _fail(M5PrecedentUsageErrorCode.INVALID_ARGUMENT)
    if (
        not isinstance(snapshot.revision, int)
        or isinstance(snapshot.revision, bool)
        or snapshot.revision <= 0
    ):
        _fail(M5PrecedentUsageErrorCode.INVALID_CASE_SNAPSHOT)
    try:
        case = Case.model_validate(snapshot.case.model_dump(mode="json"))
    except (AttributeError, KeyError, TypeError, ValueError, ValidationError) as exc:
        _fail(M5PrecedentUsageErrorCode.INVALID_CASE_SNAPSHOT, exc)
    if case != snapshot.case:
        _fail(M5PrecedentUsageErrorCode.INVALID_CASE_SNAPSHOT)
    return case, snapshot.revision


def _canonical_exposure(value: object) -> M5PrecedentExposureBatchAuthority:
    if not isinstance(value, M5PrecedentExposureBatchAuthority):
        _fail(M5PrecedentUsageErrorCode.INVALID_ARGUMENT)
    try:
        exposure = M5PrecedentExposureBatchAuthority.model_validate(value.model_dump(mode="json"))
    except (AttributeError, KeyError, TypeError, ValueError, ValidationError) as exc:
        _fail(M5PrecedentUsageErrorCode.INVALID_EXPOSURE, exc)
    if exposure != value:
        _fail(M5PrecedentUsageErrorCode.INVALID_EXPOSURE)
    return exposure


def _canonical_config(value: object) -> AppConfig:
    if not isinstance(value, AppConfig):
        _fail(M5PrecedentUsageErrorCode.INVALID_ARGUMENT)
    try:
        config = AppConfig.model_validate(value.model_dump(mode="json"))
    except (AttributeError, KeyError, TypeError, ValueError, ValidationError) as exc:
        _fail(M5PrecedentUsageErrorCode.CONFIG_AUTHORITY_MISMATCH, exc)
    if config != value:
        _fail(M5PrecedentUsageErrorCode.CONFIG_AUTHORITY_MISMATCH)
    return config


def build_m5_precedent_application_batch(
    *,
    case_snapshot: CaseSnapshot,
    exposure: M5PrecedentExposureBatchAuthority,
    config: AppConfig,
) -> M5PrecedentApplicationBatchAuthority:
    """Build one exact APPLIED batch from a READY case revision and exposure."""

    case, case_revision = _canonical_case_snapshot(case_snapshot)
    canonical_exposure = _canonical_exposure(exposure)
    canonical_config = _canonical_config(config)
    if case.status != CaseStatus.READY_FOR_ALERT_POLICY or not case.verdicts:
        _fail(M5PrecedentUsageErrorCode.CASE_NOT_READY)
    if (
        case.run_id != canonical_exposure.run_id
        or case.case_id != canonical_exposure.case_id
        or case.manifest_id != canonical_exposure.manifest_id
    ):
        _fail(M5PrecedentUsageErrorCode.AUTHORITY_SCOPE_MISMATCH)
    m4_query = canonical_exposure.m4_retrieval_outcome.query
    m5_query = canonical_exposure.m5_retrieval_result.query
    if (
        canonical_exposure.config_sha256 != canonical_config.config_sha256
        or canonical_config.run.mode != RunMode.STANDARD
        or m4_query.rule_version != canonical_config.rule_version
        or m4_query.top_k != canonical_config.hearing.precedent_top_k
        or m5_query.policy != m5_precedent_policy_from_config(canonical_config)
    ):
        _fail(M5PrecedentUsageErrorCode.CONFIG_AUTHORITY_MISMATCH)

    verdict = case.verdicts[-1]
    exposure_by_precedent_id = {
        item.precedent_id: item for item in canonical_exposure.exposed_precedents
    }
    bindings: list[M5PrecedentApplicationBinding] = []
    try:
        for application in verdict.precedent_applications:
            item = exposure_by_precedent_id.get(application.precedent_ref.artifact_id)
            if item is None:
                _fail(M5PrecedentUsageErrorCode.VERDICT_APPLICATION_INVALID)
            bindings.append(
                M5PrecedentApplicationBinding(
                    application=application,
                    exposure_item=item,
                )
            )
        return M5PrecedentApplicationBatchAuthority(
            run_id=case.run_id,
            case_id=case.case_id,
            manifest_id=case.manifest_id,
            config_sha256=canonical_config.config_sha256,
            ready_case_revision=case_revision,
            ready_case=case,
            verdict=verdict,
            exposure=canonical_exposure,
            precedent_similarity_min=(canonical_config.procedural_gate.precedent_similarity_min),
            application_bindings=tuple(bindings),
        )
    except M5PrecedentUsageError:
        raise
    except (AttributeError, KeyError, TypeError, ValueError, ValidationError) as exc:
        _fail(M5PrecedentUsageErrorCode.VERDICT_APPLICATION_INVALID, exc)


def _canonical_application_batch(
    value: object,
) -> M5PrecedentApplicationBatchAuthority:
    if not isinstance(value, M5PrecedentApplicationBatchAuthority):
        _fail(M5PrecedentUsageErrorCode.INVALID_ARGUMENT)
    try:
        batch = M5PrecedentApplicationBatchAuthority.model_validate(value.model_dump(mode="json"))
    except (AttributeError, KeyError, TypeError, ValueError, ValidationError) as exc:
        _fail(M5PrecedentUsageErrorCode.INVALID_APPLICATION_BATCH, exc)
    if batch != value:
        _fail(M5PrecedentUsageErrorCode.INVALID_APPLICATION_BATCH)
    return batch


def _require_explicit_utc(value: object) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset() != timedelta(0)
    ):
        _fail(M5PrecedentUsageErrorCode.INVALID_CITATION_TIME)
    return value


def build_m5_precedent_application_citation_commits(
    *,
    application_batch: M5PrecedentApplicationBatchAuthority,
    cited_at: datetime,
) -> tuple[M5PrecedentApplicationCitationCommit, ...]:
    """Build one stable raw-score citation commit per exact APPLIED binding."""

    batch = _canonical_application_batch(application_batch)
    citation_time = _require_explicit_utc(cited_at)
    commits: list[M5PrecedentApplicationCitationCommit] = []
    try:
        for binding in batch.application_bindings:
            item = binding.exposure_item
            score = item.candidate_evaluation.score
            authority = item.historical_authority
            if score is None:
                _fail(M5PrecedentUsageErrorCode.CITATION_CONTRACT_VIOLATION)
            if (
                citation_time < authority.created_at
                or authority.activated_at is None
                or citation_time < authority.activated_at
            ):
                _fail(M5PrecedentUsageErrorCode.INVALID_CITATION_TIME)
            citation = M5PrecedentCitationAuthority(
                run_id=batch.run_id,
                case_id=batch.case_id,
                precedent_id=item.precedent_id,
                precedent_authority_id=item.precedent_authority_id,
                precedent_revision=item.precedent_revision,
                query_id=batch.exposure.m5_retrieval_result.query.query_id,
                score=score,
                cited_at=citation_time,
            )
            commits.append(
                M5PrecedentApplicationCitationCommit(
                    application_batch=batch,
                    application_binding=binding,
                    citation=citation,
                )
            )
        return tuple(commits)
    except M5PrecedentUsageError:
        raise
    except (AttributeError, KeyError, TypeError, ValueError, ValidationError) as exc:
        _fail(M5PrecedentUsageErrorCode.CITATION_CONTRACT_VIOLATION, exc)


__all__ = [
    "M5PrecedentUsageError",
    "M5PrecedentUsageErrorCode",
    "build_m5_precedent_application_batch",
    "build_m5_precedent_application_citation_commits",
]

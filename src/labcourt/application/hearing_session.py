"""Prepare the immutable roots that enter one M4 hearing.

This module is side-effect free.  It proves the current Case, latest pack,
configuration, run manifest, three independent role models, and optional
failed M3 review before constructing the session/cycle/checkpoint transaction
payload consumed by ``HearingRepository.begin_hearing_case``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn

from labcourt.application.hearing_request import (
    FROZEN_M4_PROMPT_BUNDLE_SHA256,
    HEARING_DEFENDER_PROMPT_ID,
    HEARING_JUDGE_PROMPT_ID,
    HEARING_PROSECUTOR_PROMPT_ID,
)
from labcourt.contracts.cases import Case
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import (
    ArtifactKind,
    CaseStatus,
    ProceduralDefectCode,
    ScreeningDecision,
    VlmRole,
)
from labcourt.contracts.evidence import EvidencePack
from labcourt.contracts.hearing import (
    HearingCheckpoint,
    HearingCycleScope,
    HearingSession,
    HearingSessionEntryStatus,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.storage import ArtifactRef
from labcourt.domain.hearing_fsm import begin_hearing
from labcourt.exceptions import ContractViolation
from labcourt.ports.evidence_repository import CaseSnapshot
from labcourt.ports.prompts import PromptCatalog


class HearingSessionPreparationFailureCode(StrEnum):
    """Stable reasons an authoritative Case cannot enter M4."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    INVALID_CASE_STATE = "INVALID_CASE_STATE"
    CASE_AUTHORITY_MISMATCH = "CASE_AUTHORITY_MISMATCH"
    EVIDENCE_AUTHORITY_MISMATCH = "EVIDENCE_AUTHORITY_MISMATCH"
    INITIAL_REVIEW_AUTHORITY_MISMATCH = "INITIAL_REVIEW_AUTHORITY_MISMATCH"
    CONFIG_MANIFEST_MISMATCH = "CONFIG_MANIFEST_MISMATCH"
    ROLE_MODEL_AUTHORITY_MISMATCH = "ROLE_MODEL_AUTHORITY_MISMATCH"
    PROMPT_AUTHORITY_MISMATCH = "PROMPT_AUTHORITY_MISMATCH"


class HearingSessionPreparationError(ContractViolation):
    """The current immutable authorities cannot open a hearing."""

    def __init__(self, reason_code: HearingSessionPreparationFailureCode) -> None:
        if not isinstance(reason_code, HearingSessionPreparationFailureCode):
            raise TypeError("reason_code must be HearingSessionPreparationFailureCode")
        self.reason_code = reason_code
        super().__init__(f"hearing session preparation failed: {reason_code.value}")


def _fail(reason: HearingSessionPreparationFailureCode) -> NoReturn:
    raise HearingSessionPreparationError(reason)


@dataclass(frozen=True, slots=True)
class PreparedHearingSession:
    """Exact roots and input snapshot for one atomic start transaction."""

    source_case: CaseSnapshot
    evidence_pack: EvidencePack
    session: HearingSession
    cycle_scope: HearingCycleScope
    checkpoint: HearingCheckpoint

    def __post_init__(self) -> None:
        expected = (
            (self.source_case, CaseSnapshot, "source_case"),
            (self.evidence_pack, EvidencePack, "evidence_pack"),
            (self.session, HearingSession, "session"),
            (self.cycle_scope, HearingCycleScope, "cycle_scope"),
            (self.checkpoint, HearingCheckpoint, "checkpoint"),
        )
        for value, kind, name in expected:
            if not isinstance(value, kind):
                raise TypeError(f"{name} has the wrong contract type")
        case = self.source_case.case
        if (
            case.case_id != self.session.case_id
            or case.run_id != self.session.run_id
            or self.evidence_pack.pack_id != self.session.initial_evidence_pack_id
            or self.evidence_pack.version != self.session.initial_evidence_pack_version
            or self.cycle_scope.hearing_session_id != self.session.session_id
            or self.checkpoint.hearing_session_id != self.session.session_id
            or self.cycle_scope.cycle_id != self.checkpoint.cycle_scope_id
            or self.cycle_scope.cycle_sha256 != self.checkpoint.cycle_scope_sha256
        ):
            raise ValueError("prepared hearing roots do not share one exact authority")


_ROLE_BINDINGS = (
    (
        VlmRole.PROSECUTOR,
        "prosecutor",
        "prosecutor_profile",
        HEARING_PROSECUTOR_PROMPT_ID,
    ),
    (
        VlmRole.DEFENDER,
        "defender",
        "defender_profile",
        HEARING_DEFENDER_PROMPT_ID,
    ),
    (
        VlmRole.JUDGE,
        "judge",
        "judge_profile",
        HEARING_JUDGE_PROMPT_ID,
    ),
)


def _role_model_ids(
    config: AppConfig,
    run_manifest: RunManifest,
    catalog: PromptCatalog,
) -> dict[VlmRole, str]:
    if (
        catalog.bundle_sha256 != FROZEN_M4_PROMPT_BUNDLE_SHA256
        or run_manifest.config_sha256 != config.config_sha256
    ):
        _fail(HearingSessionPreparationFailureCode.PROMPT_AUTHORITY_MISMATCH)
    identities: dict[VlmRole, str] = {}
    for role, component, profile_field, prompt_id in _ROLE_BINDINGS:
        profile_name = getattr(config.hearing, profile_field)
        profile = config.providers.get(profile_name)
        manifest = run_manifest.models.get(component)
        if (
            profile is None
            or manifest is None
            or (
                manifest.component,
                manifest.provider,
                manifest.model,
                manifest.revision,
                manifest.quantization,
            )
            != (
                component,
                profile.provider,
                profile.model,
                profile.revision,
                profile.quantization,
            )
        ):
            _fail(HearingSessionPreparationFailureCode.ROLE_MODEL_AUTHORITY_MISMATCH)
        try:
            prompt_manifest = catalog.manifest(prompt_id)
        except Exception:
            _fail(HearingSessionPreparationFailureCode.PROMPT_AUTHORITY_MISMATCH)
        if (
            prompt_manifest.role != role
            or prompt_manifest.prompt_bundle_sha256 != FROZEN_M4_PROMPT_BUNDLE_SHA256
        ):
            _fail(HearingSessionPreparationFailureCode.PROMPT_AUTHORITY_MISMATCH)
        identities[role] = manifest.model_manifest_id
    return identities


def prepare_hearing_session(
    source_case: CaseSnapshot,
    *,
    config: AppConfig,
    run_manifest: RunManifest,
    catalog: PromptCatalog,
) -> PreparedHearingSession:
    """Prove and construct one initial M4 session/cycle/checkpoint closure."""

    if (
        not isinstance(source_case, CaseSnapshot)
        or not isinstance(config, AppConfig)
        or not isinstance(run_manifest, RunManifest)
        or not isinstance(catalog, PromptCatalog)
        or not isinstance(source_case.revision, int)
        or isinstance(source_case.revision, bool)
        or source_case.revision <= 0
    ):
        _fail(HearingSessionPreparationFailureCode.INVALID_ARGUMENT)
    try:
        case = Case.model_validate(source_case.case.model_dump(mode="json"))
    except Exception:
        _fail(HearingSessionPreparationFailureCode.CASE_AUTHORITY_MISMATCH)
    if case != source_case.case:
        _fail(HearingSessionPreparationFailureCode.CASE_AUTHORITY_MISMATCH)
    if case.status not in {CaseStatus.ESCALATED, CaseStatus.REWORK_REQUIRED}:
        _fail(HearingSessionPreparationFailureCode.INVALID_CASE_STATE)
    if (
        case.manifest_id != run_manifest.manifest_id
        or case.event.manifest_id != run_manifest.manifest_id
        or run_manifest.config_sha256 != config.config_sha256
        or run_manifest.rule_version != config.rule_version
        or run_manifest.schema_version != config.schema_version
        or run_manifest.reproducibility_mode != config.run.reproducibility_mode
        or run_manifest.random_seed != config.run.random_seed
        or run_manifest.storage_boundary != config.run.storage_boundary
        or run_manifest.privacy_transform_version != config.evidence.privacy_transform_version
        or run_manifest.image_encoding_version != config.evidence.encoding_version
    ):
        _fail(HearingSessionPreparationFailureCode.CONFIG_MANIFEST_MISMATCH)
    if not case.evidence_packs:
        _fail(HearingSessionPreparationFailureCode.EVIDENCE_AUTHORITY_MISMATCH)
    pack = case.evidence_packs[-1]
    if (
        not pack.complete
        or pack.run_id != case.run_id
        or pack.case_id != case.case_id
        or pack.event != case.event
        or pack.manifest_id != case.manifest_id
        or case.evidence_packs != tuple(sorted(case.evidence_packs, key=lambda item: item.version))
    ):
        _fail(HearingSessionPreparationFailureCode.EVIDENCE_AUTHORITY_MISMATCH)
    if not case.screening_results:
        _fail(HearingSessionPreparationFailureCode.CASE_AUTHORITY_MISMATCH)
    screening = case.screening_results[-1]
    if (
        screening.run_id != case.run_id
        or screening.case_id != case.case_id
        or screening.evidence_pack_id != pack.pack_id
        or screening.evidence_pack_version != pack.version
        or screening.manifest_id != case.manifest_id
    ):
        _fail(HearingSessionPreparationFailureCode.CASE_AUTHORITY_MISMATCH)

    entry_status = HearingSessionEntryStatus.ESCALATED
    initial_review_ref: ArtifactRef | None = None
    initial_defect_codes: tuple[ProceduralDefectCode, ...] = ()
    if case.status == CaseStatus.ESCALATED:
        if screening.decision != ScreeningDecision.ESCALATE:
            _fail(HearingSessionPreparationFailureCode.CASE_AUTHORITY_MISMATCH)
    else:
        entry_status = HearingSessionEntryStatus.REWORK_REQUIRED
        if not case.verdicts or not case.procedural_reviews:
            _fail(HearingSessionPreparationFailureCode.INITIAL_REVIEW_AUTHORITY_MISMATCH)
        verdict = case.verdicts[-1]
        review = case.procedural_reviews[-1]
        if (
            review.passed
            or review.run_id != case.run_id
            or review.case_id != case.case_id
            or review.reviewed_verdict_id != verdict.verdict_id
            or review.reviewed_verdict_version != verdict.version
            or review.reviewed_verdict_sha256 != verdict.verdict_sha256
            or review.evidence_pack_id != pack.pack_id
            or review.evidence_pack_version != pack.version
            or verdict.evidence_pack_id != pack.pack_id
            or verdict.evidence_pack_version != pack.version
            or verdict.screening_id != screening.screening_id
            or review.manifest_id != case.manifest_id
            or not review.defects
        ):
            _fail(HearingSessionPreparationFailureCode.INITIAL_REVIEW_AUTHORITY_MISMATCH)
        initial_review_ref = ArtifactRef(
            kind=ArtifactKind.PROCEDURAL_REVIEW,
            artifact_id=review.review_id,
        )
        initial_defect_codes = tuple(
            sorted({defect.code for defect in review.defects}, key=lambda code: code.value)
        )

    role_models = _role_model_ids(config, run_manifest, catalog)
    session = HearingSession(
        run_id=case.run_id,
        case_id=case.case_id,
        screening_id=screening.screening_id,
        entry_status=entry_status,
        initial_evidence_pack_id=pack.pack_id,
        initial_evidence_pack_version=pack.version,
        initial_trigger_review_ref=initial_review_ref,
        initial_defect_codes=initial_defect_codes,
        acquisition_round_limit=config.hearing.max_acquisition_rounds,
        rework_round_limit=config.hearing.max_rework_rounds,
        max_total_images=config.hearing.max_total_images,
        max_total_output_tokens=config.hearing.max_total_output_tokens,
        hearing_prompt_bundle_sha256=FROZEN_M4_PROMPT_BUNDLE_SHA256,
        prosecutor_model_manifest_id=role_models[VlmRole.PROSECUTOR],
        defender_model_manifest_id=role_models[VlmRole.DEFENDER],
        judge_model_manifest_id=role_models[VlmRole.JUDGE],
        manifest_id=run_manifest.manifest_id,
    )
    checkpoint = begin_hearing(session)
    cycle_scope = HearingCycleScope(
        run_id=session.run_id,
        case_id=session.case_id,
        hearing_session_id=session.session_id,
        cycle_index=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        cycle_evidence_pack_id=pack.pack_id,
        cycle_evidence_pack_version=pack.version,
        initial_trigger_review_ref=session.initial_trigger_review_ref,
        initial_defect_codes=session.initial_defect_codes,
        manifest_id=session.manifest_id,
    )
    return PreparedHearingSession(
        source_case=source_case,
        evidence_pack=pack,
        session=session,
        cycle_scope=cycle_scope,
        checkpoint=checkpoint,
    )


__all__ = [
    "HearingSessionPreparationError",
    "HearingSessionPreparationFailureCode",
    "PreparedHearingSession",
    "prepare_hearing_session",
]

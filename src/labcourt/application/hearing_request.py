"""Deterministic, privacy-bounded preparation of M4 hearing role calls.

The builder is deliberately side-effect free.  It binds one stored hearing
cycle, one closed evidence authority, one precedent retrieval receipt, and one
role-specific model/prompt authority into an immutable request.  Provider I/O,
budget reservation, and persistence remain orchestration responsibilities.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Final, NoReturn

from labcourt.application.hearing_budget import (
    HearingBudgetPolicyError,
    derive_hearing_call_budget_limits,
)
from labcourt.application.hearing_model_parser import HearingParseInspection
from labcourt.contracts.backlog import BacklogRetryContext
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.config import AppConfig, VlmProviderProfile
from labcourt.contracts.enums import (
    ArtifactKind,
    CropSource,
    ExecutionLocation,
    MediaAccess,
    MediaAvailability,
    ProceduralDefectCode,
    ProceduralDefectOrigin,
    VlmRole,
)
from labcourt.contracts.evidence import Crop, EvidencePack
from labcourt.contracts.frames import SHA256_PATTERN
from labcourt.contracts.hearing import (
    HearingCycleScope,
    HearingModelRequest,
    HearingModelResponse,
    HearingPrecedentRetrievalReceipt,
    HearingPrecedentRetrievalStatus,
    HearingRoleOutput,
    HearingSession,
    validate_hearing_cycle_scope_binding,
)
from labcourt.contracts.m3_models import PromptManifest, VlmCallBudget
from labcourt.contracts.manifests import ModelManifest, RunManifest
from labcourt.contracts.storage import ArtifactRef
from labcourt.contracts.verdicts import ProceduralDefect
from labcourt.domain.evidence_authority import (
    EvidenceAuthority,
    EvidenceAuthorityError,
    EvidenceDisclosureError,
    HearingEvidenceGrant,
    RoleEvidenceDisclosure,
    derive_evidence_authority,
    derive_role_disclosure,
    extend_hearing_evidence_grant,
)
from labcourt.exceptions import LabCourtError
from labcourt.ports.prompts import (
    MAX_PROMPT_STRING_CHARS,
    MAX_PROMPT_VARIABLE_BYTES,
    PromptCatalog,
    RenderedPrompt,
)

FROZEN_M4_PROMPT_BUNDLE_SHA256: Final = (
    "97457a7e57710ed3e0a99bcd87b33629487115417f6dcdd24bb4fa65d1495c68"
)
LEGACY_M4_PROMPT_BUNDLE_SHA256: Final = (
    "0b7d777f01abe5bc74fc511f7a10a03dbdd3365c9b6b8f784cc32995fd5fb8a8"
)
SUPPORTED_M4_PROMPT_BUNDLE_SHA256S: Final = frozenset(
    {FROZEN_M4_PROMPT_BUNDLE_SHA256, LEGACY_M4_PROMPT_BUNDLE_SHA256}
)

HEARING_PROSECUTOR_PROMPT_ID: Final = "hearing_prosecutor_v1"
HEARING_DEFENDER_PROMPT_ID: Final = "hearing_defender_v1"
HEARING_JUDGE_PROMPT_ID: Final = "hearing_judge_v1"

_SHA256: Final = re.compile(SHA256_PATTERN)
_PRIMARY_ROLES: Final = frozenset({VlmRole.PROSECUTOR, VlmRole.DEFENDER, VlmRole.JUDGE})
_PARSER_DEFECT_CODES: Final = frozenset(
    {
        ProceduralDefectCode.MALFORMED_STRUCTURE,
        ProceduralDefectCode.INVALID_ENUM,
        ProceduralDefectCode.MISSING_REQUIRED_FIELD,
    }
)
_ROLE_PROMPT_IDS: Final = {
    VlmRole.PROSECUTOR: HEARING_PROSECUTOR_PROMPT_ID,
    VlmRole.DEFENDER: HEARING_DEFENDER_PROMPT_ID,
    VlmRole.JUDGE: HEARING_JUDGE_PROMPT_ID,
}
_ROLE_PROFILE_FIELDS: Final = {
    VlmRole.PROSECUTOR: "prosecutor_profile",
    VlmRole.DEFENDER: "defender_profile",
    VlmRole.JUDGE: "judge_profile",
}
_ROLE_MODEL_FIELDS: Final = {
    VlmRole.PROSECUTOR: "prosecutor_model_manifest_id",
    VlmRole.DEFENDER: "defender_model_manifest_id",
    VlmRole.JUDGE: "judge_model_manifest_id",
}


class HearingRequestPreparationErrorCode(StrEnum):
    """Controlled, provider-text-free reasons request preparation can fail."""

    CYCLE_SCOPE_MISMATCH = "CYCLE_SCOPE_MISMATCH"
    RUN_MANIFEST_MISMATCH = "RUN_MANIFEST_MISMATCH"
    SESSION_AUTHORITY_MISMATCH = "SESSION_AUTHORITY_MISMATCH"
    MODEL_MANIFEST_MISMATCH = "MODEL_MANIFEST_MISMATCH"
    PROMPT_BUNDLE_MISMATCH = "PROMPT_BUNDLE_MISMATCH"
    PRECEDENT_AUTHORITY_MISMATCH = "PRECEDENT_AUTHORITY_MISMATCH"
    EVIDENCE_AUTHORITY_MISMATCH = "EVIDENCE_AUTHORITY_MISMATCH"
    MEDIA_UNAVAILABLE = "MEDIA_UNAVAILABLE"
    PRIVACY_POLICY_VIOLATION = "PRIVACY_POLICY_VIOLATION"
    IMAGE_BUDGET_EXHAUSTED = "IMAGE_BUDGET_EXHAUSTED"
    OUTPUT_TOKEN_BUDGET_EXHAUSTED = "OUTPUT_TOKEN_BUDGET_EXHAUSTED"
    INPUT_PIXEL_BUDGET_EXCEEDED = "INPUT_PIXEL_BUDGET_EXCEEDED"
    PROMPT_BUDGET_EXCEEDED = "PROMPT_BUDGET_EXCEEDED"
    UPSTREAM_OUTPUT_MISMATCH = "UPSTREAM_OUTPUT_MISMATCH"
    BACKLOG_GENERATION_INVALID = "BACKLOG_GENERATION_INVALID"
    ORIGINAL_REQUEST_MISMATCH = "ORIGINAL_REQUEST_MISMATCH"
    ORIGINAL_RESPONSE_BINDING_MISMATCH = "ORIGINAL_RESPONSE_BINDING_MISMATCH"
    RAW_RESPONSE_NOT_BYTES = "RAW_RESPONSE_NOT_BYTES"
    RAW_RESPONSE_SIZE_MISMATCH = "RAW_RESPONSE_SIZE_MISMATCH"
    RAW_RESPONSE_CONTENT_MISMATCH = "RAW_RESPONSE_CONTENT_MISMATCH"
    ORIGINAL_RESPONSE_TOO_LARGE = "ORIGINAL_RESPONSE_TOO_LARGE"
    INSPECTION_NOT_REPAIRABLE = "INSPECTION_NOT_REPAIRABLE"
    INSPECTION_BINDING_MISMATCH = "INSPECTION_BINDING_MISMATCH"
    PARSE_DEFECTS_INVALID = "PARSE_DEFECTS_INVALID"


class HearingRequestPreparationError(LabCourtError):
    """Expected request-preparation failure with a stable machine code."""

    def __init__(self, reason_code: HearingRequestPreparationErrorCode) -> None:
        if not isinstance(reason_code, HearingRequestPreparationErrorCode):
            raise TypeError("reason_code must be a HearingRequestPreparationErrorCode")
        self.reason_code = reason_code
        super().__init__(f"hearing request preparation failed: {reason_code.value}")


def _fail(code: HearingRequestPreparationErrorCode) -> NoReturn:
    raise HearingRequestPreparationError(code)


@dataclass(frozen=True, slots=True)
class HearingBudgetUsage:
    """Persisted aggregate usage before reserving the request being prepared."""

    reserved_images: int = 0
    accounted_output_tokens: int = 0

    def __post_init__(self) -> None:
        for name, value in (
            ("reserved_images", self.reserved_images),
            ("accounted_output_tokens", self.accounted_output_tokens),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise TypeError(f"{name} must be a non-negative integer")


@dataclass(frozen=True, slots=True)
class HearingRequestGeneration:
    """Strict backlog generation input used in deterministic request identity."""

    retry_generation: int = 0
    backlog_item_id: str | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.retry_generation, int)
            or isinstance(self.retry_generation, bool)
            or self.retry_generation < 0
        ):
            _fail(HearingRequestPreparationErrorCode.BACKLOG_GENERATION_INVALID)
        if self.retry_generation == 0:
            if self.backlog_item_id is not None:
                _fail(HearingRequestPreparationErrorCode.BACKLOG_GENERATION_INVALID)
        elif (
            not isinstance(self.backlog_item_id, str)
            or _SHA256.fullmatch(self.backlog_item_id) is None
        ):
            _fail(HearingRequestPreparationErrorCode.BACKLOG_GENERATION_INVALID)

    @property
    def backlog_retry_context(self) -> BacklogRetryContext | None:
        if self.retry_generation == 0:
            return None
        assert self.backlog_item_id is not None
        return BacklogRetryContext(
            backlog_item_id=self.backlog_item_id,
            retry_generation=self.retry_generation,
        )


def _require_canonical_document(value: str, name: str) -> None:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a canonical JSON string")
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be canonical JSON") from None
    if canonical_json(parsed) != value:
        raise ValueError(f"{name} must use LCJ-1 canonical JSON")


@dataclass(frozen=True, slots=True)
class HearingCanonicalInputs:
    """Exact canonical JSON variables used to render one M4 role prompt."""

    hearing_context_json: str
    allowed_refs_json: str
    precedents_json: str
    prosecutor_output_json: str = "null"
    defender_output_json: str = "null"
    repair_context_json: str = "null"
    prior_response_json: str = "null"

    def __post_init__(self) -> None:
        for name in (
            "hearing_context_json",
            "allowed_refs_json",
            "precedents_json",
            "prosecutor_output_json",
            "defender_output_json",
            "repair_context_json",
            "prior_response_json",
        ):
            _require_canonical_document(getattr(self, name), name)

    def variables_for(self, role: VlmRole) -> dict[str, str]:
        common = {
            "allowed_refs_json": self.allowed_refs_json,
            "hearing_context_json": self.hearing_context_json,
            "precedents_json": self.precedents_json,
            "prior_response_json": self.prior_response_json,
            "repair_context_json": self.repair_context_json,
        }
        if role == VlmRole.PROSECUTOR:
            return common
        if role == VlmRole.DEFENDER:
            return {**common, "prosecutor_output_json": self.prosecutor_output_json}
        if role == VlmRole.JUDGE:
            return {
                **common,
                "prosecutor_output_json": self.prosecutor_output_json,
                "defender_output_json": self.defender_output_json,
            }
        raise TypeError("role must be a primary hearing role")


@dataclass(frozen=True, slots=True)
class PreparedHearingRequest:
    """One request plus the exact bytes and evidence grant it binds."""

    request: HearingModelRequest
    rendered_prompt: RenderedPrompt
    canonical_inputs: HearingCanonicalInputs
    disclosure: RoleEvidenceDisclosure | None
    hearing_grant: HearingEvidenceGrant

    def __post_init__(self) -> None:
        if not isinstance(self.request, HearingModelRequest):
            raise TypeError("request must be a HearingModelRequest")
        if not isinstance(self.rendered_prompt, RenderedPrompt):
            raise TypeError("rendered_prompt must be a RenderedPrompt")
        if not isinstance(self.canonical_inputs, HearingCanonicalInputs):
            raise TypeError("canonical_inputs must be HearingCanonicalInputs")
        if not isinstance(self.hearing_grant, HearingEvidenceGrant):
            raise TypeError("hearing_grant must be a HearingEvidenceGrant")
        if self.request.prompt_manifest != self.rendered_prompt.manifest:
            raise ValueError("prepared hearing request has another prompt manifest")
        if self.request.rendered_prompt_sha256 != self.rendered_prompt.rendered_prompt_sha256:
            raise ValueError("prepared hearing request does not bind rendered prompt bytes")
        if self.request.hearing_context_sha256 != _document_sha256(
            self.canonical_inputs.hearing_context_json
        ):
            raise ValueError("prepared hearing request does not bind its canonical context")
        if self.request.attempt_index == 0:
            disclosure = self.disclosure
            if disclosure is None or (
                disclosure.run_id,
                disclosure.case_id,
                disclosure.evidence_pack_id,
                disclosure.evidence_pack_version,
                disclosure.media,
                disclosure.allowed_evidence_refs,
            ) != (
                self.request.run_id,
                self.request.case_id,
                self.request.current_evidence_pack_id,
                self.request.current_evidence_pack_version,
                self.request.media,
                self.request.allowed_evidence_refs,
            ):
                raise ValueError("primary request conflicts with its exact disclosure")
        elif self.disclosure is not None:
            raise ValueError("repair request cannot create another media disclosure")


@dataclass(frozen=True, slots=True)
class _RoleAuthority:
    prompt_id: str
    profile_name: str
    profile: VlmProviderProfile
    model_manifest: ModelManifest


def _document_sha256(document: str) -> str:
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


def _validate_argument_types(
    *,
    session: HearingSession,
    cycle_scope: HearingCycleScope,
    retrieval: HearingPrecedentRetrievalReceipt,
    evidence_pack: EvidencePack,
    evidence_authority: EvidenceAuthority,
    budget_usage: HearingBudgetUsage,
    config: AppConfig,
    run_manifest: RunManifest,
    catalog: PromptCatalog,
) -> None:
    expected = (
        (session, HearingSession, "session"),
        (cycle_scope, HearingCycleScope, "cycle_scope"),
        (retrieval, HearingPrecedentRetrievalReceipt, "retrieval"),
        (evidence_pack, EvidencePack, "evidence_pack"),
        (evidence_authority, EvidenceAuthority, "evidence_authority"),
        (budget_usage, HearingBudgetUsage, "budget_usage"),
        (config, AppConfig, "config"),
        (run_manifest, RunManifest, "run_manifest"),
    )
    for value, expected_type, name in expected:
        if not isinstance(value, expected_type):
            raise TypeError(f"{name} must be {expected_type.__name__}")
    if not isinstance(catalog, PromptCatalog):
        raise TypeError("catalog must implement PromptCatalog")


def _validate_run_session_authority(
    *,
    role: VlmRole,
    session: HearingSession,
    cycle_scope: HearingCycleScope,
    evidence_pack: EvidencePack,
    evidence_authority: EvidenceAuthority,
    config: AppConfig,
    run_manifest: RunManifest,
    catalog: PromptCatalog,
) -> _RoleAuthority:
    if not isinstance(role, VlmRole) or role not in _PRIMARY_ROLES:
        raise TypeError("role must be PROSECUTOR, DEFENDER, or JUDGE")
    run_checks = (
        config.schema_version == run_manifest.schema_version,
        config.config_sha256 == run_manifest.config_sha256,
        config.rule_version == run_manifest.rule_version,
        config.run.reproducibility_mode == run_manifest.reproducibility_mode,
        config.run.random_seed == run_manifest.random_seed,
        config.run.storage_boundary == run_manifest.storage_boundary,
        config.evidence.privacy_transform_version == run_manifest.privacy_transform_version,
        config.evidence.encoding_version == run_manifest.image_encoding_version,
        evidence_pack.event.rule_version == run_manifest.rule_version,
        evidence_pack.manifest_id == run_manifest.manifest_id,
        evidence_pack.event.manifest_id == run_manifest.manifest_id,
    )
    if not all(run_checks):
        _fail(HearingRequestPreparationErrorCode.RUN_MANIFEST_MISMATCH)

    session_checks = (
        session.run_id == evidence_pack.run_id == cycle_scope.run_id,
        session.case_id == evidence_pack.case_id == cycle_scope.case_id,
        session.session_id == cycle_scope.hearing_session_id,
        session.manifest_id == run_manifest.manifest_id == cycle_scope.manifest_id,
        session.acquisition_round_limit == config.hearing.max_acquisition_rounds,
        session.rework_round_limit == config.hearing.max_rework_rounds,
        session.max_total_images == config.hearing.max_total_images,
        session.max_total_output_tokens == config.hearing.max_total_output_tokens,
        cycle_scope.cycle_index <= session.max_total_judge_cycles,
        cycle_scope.prior_acquisition_rounds <= session.acquisition_round_limit,
        cycle_scope.prior_rework_rounds <= session.rework_round_limit,
        cycle_scope.cycle_evidence_pack_id == evidence_pack.pack_id,
        cycle_scope.cycle_evidence_pack_version == evidence_pack.version,
        len(evidence_authority.receipts) == cycle_scope.prior_acquisition_rounds,
        all(
            receipt.request.hearing_session_id == session.session_id
            for receipt in evidence_authority.receipts
        ),
    )
    if not all(session_checks):
        _fail(HearingRequestPreparationErrorCode.SESSION_AUTHORITY_MISMATCH)
    if cycle_scope.cycle_index == 1 and (
        cycle_scope.initial_trigger_review_ref != session.initial_trigger_review_ref
        or cycle_scope.initial_defect_codes != session.initial_defect_codes
    ):
        _fail(HearingRequestPreparationErrorCode.SESSION_AUTHORITY_MISMATCH)
    if evidence_authority.receipts:
        first = evidence_authority.receipts[0].request
        if (
            first.current_evidence_pack_id != session.initial_evidence_pack_id
            or first.current_evidence_pack_version != session.initial_evidence_pack_version
        ):
            _fail(HearingRequestPreparationErrorCode.SESSION_AUTHORITY_MISMATCH)
    elif (
        evidence_pack.pack_id != session.initial_evidence_pack_id
        or evidence_pack.version != session.initial_evidence_pack_version
    ):
        _fail(HearingRequestPreparationErrorCode.SESSION_AUTHORITY_MISMATCH)

    if (
        catalog.bundle_sha256 not in SUPPORTED_M4_PROMPT_BUNDLE_SHA256S
        or session.hearing_prompt_bundle_sha256 != catalog.bundle_sha256
    ):
        _fail(HearingRequestPreparationErrorCode.PROMPT_BUNDLE_MISMATCH)

    authorities: dict[VlmRole, _RoleAuthority] = {}
    for candidate_role in (VlmRole.PROSECUTOR, VlmRole.DEFENDER, VlmRole.JUDGE):
        profile_name = getattr(config.hearing, _ROLE_PROFILE_FIELDS[candidate_role])
        profile = config.providers.get(profile_name)
        component = candidate_role.value.lower()
        model_manifest = run_manifest.models.get(component)
        if profile is None or model_manifest is None:
            _fail(HearingRequestPreparationErrorCode.MODEL_MANIFEST_MISMATCH)
        expected_session_id = getattr(session, _ROLE_MODEL_FIELDS[candidate_role])
        if (
            model_manifest.component != component
            or model_manifest.provider != profile.provider
            or model_manifest.model != profile.model
            or model_manifest.revision != profile.revision
            or model_manifest.quantization != profile.quantization
            or model_manifest.model_manifest_id != expected_session_id
        ):
            _fail(HearingRequestPreparationErrorCode.MODEL_MANIFEST_MISMATCH)
        authorities[candidate_role] = _RoleAuthority(
            prompt_id=_ROLE_PROMPT_IDS[candidate_role],
            profile_name=profile_name,
            profile=profile,
            model_manifest=model_manifest,
        )
    return authorities[role]


def _validate_cycle_and_retrieval(
    *,
    cycle_scope: HearingCycleScope,
    retrieval: HearingPrecedentRetrievalReceipt,
    evidence_pack: EvidencePack,
    config: AppConfig,
    run_manifest: RunManifest,
) -> None:
    try:
        validate_hearing_cycle_scope_binding(cycle_scope, retrieval)
    except (TypeError, ValueError):
        _fail(HearingRequestPreparationErrorCode.CYCLE_SCOPE_MISMATCH)
    if (
        retrieval.evidence_class != evidence_pack.event.evidence_class
        or retrieval.violation_type != evidence_pack.event.violation_type
        or retrieval.rule_version != run_manifest.rule_version
        or retrieval.top_k != config.hearing.precedent_top_k
        or retrieval.manifest_id != run_manifest.manifest_id
    ):
        _fail(HearingRequestPreparationErrorCode.PRECEDENT_AUTHORITY_MISMATCH)


def _validate_evidence_authority(
    evidence_pack: EvidencePack,
    authority: EvidenceAuthority,
) -> None:
    if authority.pack != evidence_pack or not evidence_pack.complete:
        _fail(HearingRequestPreparationErrorCode.EVIDENCE_AUTHORITY_MISMATCH)
    try:
        reloaded = derive_evidence_authority(
            evidence_pack,
            authority.receipts,
            authority.loaded_objects,
        )
    except EvidenceAuthorityError:
        _fail(HearingRequestPreparationErrorCode.EVIDENCE_AUTHORITY_MISMATCH)
    if reloaded != authority:
        _fail(HearingRequestPreparationErrorCode.EVIDENCE_AUTHORITY_MISMATCH)


def _eligible_crop(
    crop: Crop,
    *,
    pack: EvidencePack,
    profile: VlmProviderProfile,
    run_manifest: RunManifest,
) -> bool:
    if (
        crop.availability != MediaAvailability.AVAILABLE
        or crop.local_path != f"{pack.run_id}/frames/{crop.media_sha256}.png"
    ):
        return False
    if (
        crop.privacy_receipt.transform_version != run_manifest.privacy_transform_version
        or crop.encoding_version != run_manifest.image_encoding_version
    ):
        return False
    if profile.execution_location == ExecutionLocation.EXTERNAL:
        return (
            crop.source != CropSource.PANORAMA
            and crop.privacy_receipt.media_access == MediaAccess.CLOUD_ALLOWED
        )
    return True


def _select_crop(
    authority: EvidenceAuthority,
    role_authority: _RoleAuthority,
    run_manifest: RunManifest,
) -> Crop:
    pack = authority.pack
    available_canonical = tuple(
        crop
        for crop in authority.crops
        if crop.availability == MediaAvailability.AVAILABLE
        and crop.local_path == f"{pack.run_id}/frames/{crop.media_sha256}.png"
    )
    if not available_canonical:
        _fail(HearingRequestPreparationErrorCode.MEDIA_UNAVAILABLE)
    manifest_compatible = tuple(
        crop
        for crop in available_canonical
        if crop.privacy_receipt.transform_version == run_manifest.privacy_transform_version
        and crop.encoding_version == run_manifest.image_encoding_version
    )
    if not manifest_compatible:
        _fail(HearingRequestPreparationErrorCode.RUN_MANIFEST_MISMATCH)
    eligible = tuple(
        sorted(
            (
                crop
                for crop in manifest_compatible
                if _eligible_crop(
                    crop,
                    pack=pack,
                    profile=role_authority.profile,
                    run_manifest=run_manifest,
                )
            ),
            key=lambda item: item.crop_id,
        )
    )
    if not eligible:
        _fail(HearingRequestPreparationErrorCode.PRIVACY_POLICY_VIOLATION)

    new_crop_ids: set[str] = set()
    if authority.receipts:
        latest = authority.receipts[-1]
        if (
            latest.resulting_evidence_pack_id == pack.pack_id
            and latest.resulting_evidence_pack_version == pack.version
        ):
            new_crop_ids = {
                ref.artifact_id
                for ref in latest.tool_result.output_refs
                if ref.kind == ArtifactKind.CROP
            }
    newly_acquired = tuple(crop for crop in eligible if crop.crop_id in new_crop_ids)
    return newly_acquired[0] if newly_acquired else eligible[0]


def _validate_grant(grant: HearingEvidenceGrant | None) -> None:
    if grant is None:
        return
    if not isinstance(grant, HearingEvidenceGrant):
        raise TypeError("hearing_grant must be HearingEvidenceGrant or None")
    try:
        reconstructed = HearingEvidenceGrant(
            run_id=grant.run_id,
            case_id=grant.case_id,
            latest_evidence_pack_id=grant.latest_evidence_pack_id,
            latest_evidence_pack_version=grant.latest_evidence_pack_version,
            allowed_evidence_refs=grant.allowed_evidence_refs,
            artifact_bounds=grant.artifact_bounds,
        )
    except (TypeError, ValueError):
        _fail(HearingRequestPreparationErrorCode.EVIDENCE_AUTHORITY_MISMATCH)
    if reconstructed != grant:
        _fail(HearingRequestPreparationErrorCode.EVIDENCE_AUTHORITY_MISMATCH)


def _role_output_scope(
    output: HearingRoleOutput,
    *,
    expected_role: VlmRole,
    session: HearingSession,
    scope: HearingCycleScope,
    retrieval: HearingPrecedentRetrievalReceipt,
    expected_model_manifest_id: str,
    expected_prompt_manifest: PromptManifest,
) -> None:
    if not isinstance(output, HearingRoleOutput):
        _fail(HearingRequestPreparationErrorCode.UPSTREAM_OUTPUT_MISMATCH)
    binding = (
        output.run_id,
        output.case_id,
        output.hearing_session_id,
        output.round_index,
        output.prior_acquisition_rounds,
        output.prior_rework_rounds,
        output.current_evidence_pack_id,
        output.current_evidence_pack_version,
        output.initial_trigger_review_ref,
        output.initial_defect_codes,
        output.rework_review_ref,
        output.rework_defect_codes,
        output.manifest_id,
        output.role,
        output.model_manifest_id,
        output.precedent_retrieval_degraded,
        output.precedent_retrieval_receipt_id,
        output.precedent_retrieval_receipt_sha256,
        output.prompt_manifest.prompt_bundle_sha256,
        output.prompt_manifest,
    )
    expected = (
        scope.run_id,
        scope.case_id,
        session.session_id,
        scope.cycle_index,
        scope.prior_acquisition_rounds,
        scope.prior_rework_rounds,
        scope.cycle_evidence_pack_id,
        scope.cycle_evidence_pack_version,
        scope.initial_trigger_review_ref,
        scope.initial_defect_codes,
        scope.rework_review_ref,
        scope.rework_defect_codes,
        scope.manifest_id,
        expected_role,
        expected_model_manifest_id,
        retrieval.status == HearingPrecedentRetrievalStatus.DEGRADED,
        retrieval.receipt_id,
        retrieval.receipt_sha256,
        session.hearing_prompt_bundle_sha256,
        expected_prompt_manifest,
    )
    if binding != expected:
        _fail(HearingRequestPreparationErrorCode.UPSTREAM_OUTPUT_MISMATCH)


def _upstream_inputs(
    *,
    role: VlmRole,
    session: HearingSession,
    scope: HearingCycleScope,
    retrieval: HearingPrecedentRetrievalReceipt,
    catalog: PromptCatalog,
    prosecutor_output: HearingRoleOutput | None,
    defender_output: HearingRoleOutput | None,
) -> tuple[ArtifactRef | None, ArtifactRef | None, str, str]:
    if role == VlmRole.PROSECUTOR:
        if prosecutor_output is not None or defender_output is not None:
            _fail(HearingRequestPreparationErrorCode.UPSTREAM_OUTPUT_MISMATCH)
        return None, None, "null", "null"

    if prosecutor_output is None:
        _fail(HearingRequestPreparationErrorCode.UPSTREAM_OUTPUT_MISMATCH)
    _role_output_scope(
        prosecutor_output,
        expected_role=VlmRole.PROSECUTOR,
        session=session,
        scope=scope,
        retrieval=retrieval,
        expected_model_manifest_id=session.prosecutor_model_manifest_id,
        expected_prompt_manifest=catalog.manifest(HEARING_PROSECUTOR_PROMPT_ID),
    )
    prosecutor_ref = ArtifactRef(
        kind=ArtifactKind.PARSED_MODEL_OUTPUT,
        artifact_id=prosecutor_output.output_id,
    )
    prosecutor_json = canonical_json(prosecutor_output.model_dump(mode="json"))
    if role == VlmRole.DEFENDER:
        if defender_output is not None:
            _fail(HearingRequestPreparationErrorCode.UPSTREAM_OUTPUT_MISMATCH)
        return prosecutor_ref, None, prosecutor_json, "null"

    if defender_output is None:
        _fail(HearingRequestPreparationErrorCode.UPSTREAM_OUTPUT_MISMATCH)
    _role_output_scope(
        defender_output,
        expected_role=VlmRole.DEFENDER,
        session=session,
        scope=scope,
        retrieval=retrieval,
        expected_model_manifest_id=session.defender_model_manifest_id,
        expected_prompt_manifest=catalog.manifest(HEARING_DEFENDER_PROMPT_ID),
    )
    if defender_output.prosecutor_output_id != prosecutor_output.output_id:
        _fail(HearingRequestPreparationErrorCode.UPSTREAM_OUTPUT_MISMATCH)
    defender_ref = ArtifactRef(
        kind=ArtifactKind.PARSED_MODEL_OUTPUT,
        artifact_id=defender_output.output_id,
    )
    return (
        prosecutor_ref,
        defender_ref,
        prosecutor_json,
        canonical_json(defender_output.model_dump(mode="json")),
    )


def _precedent_inputs(
    retrieval: HearingPrecedentRetrievalReceipt,
) -> tuple[tuple[ArtifactRef, ...], str]:
    refs = tuple(
        sorted(
            (
                ArtifactRef(
                    kind=ArtifactKind.PRECEDENT,
                    artifact_id=item.precedent.precedent_id,
                )
                for item in retrieval.scored_precedents
            ),
            key=lambda ref: ref.sort_key,
        )
    )
    precedents_json = canonical_json(
        [
            {
                "rank": rank,
                "scored_precedent": item.model_dump(mode="json"),
            }
            for rank, item in enumerate(retrieval.scored_precedents, start=1)
        ]
    )
    return refs, precedents_json


def _hearing_context(
    *,
    role: VlmRole,
    session: HearingSession,
    scope: HearingCycleScope,
    retrieval: HearingPrecedentRetrievalReceipt,
    pack: EvidencePack,
    disclosure: RoleEvidenceDisclosure,
) -> str:
    selected_ids = {item.crop_id for item in disclosure.media}
    selected_crops = tuple(crop for crop in pack.crops if crop.crop_id in selected_ids)
    return canonical_json(
        {
            "schema_version": "m4-hearing-prompt-context-v1",
            "role": role.value,
            "session": {
                "session_id": session.session_id,
                "session_sha256": session.session_sha256,
                "max_total_judge_cycles": session.max_total_judge_cycles,
                "max_total_images": session.max_total_images,
                "max_total_output_tokens": session.max_total_output_tokens,
            },
            "cycle_scope": scope.model_dump(mode="json"),
            "screening_ref": {
                "kind": ArtifactKind.SCREENING_RESULT.value,
                "artifact_id": session.screening_id,
            },
            "evidence_pack": {
                "pack_id": pack.pack_id,
                "version": pack.version,
                "event": pack.event.model_dump(mode="json"),
                "selected_crops": [
                    {
                        "crop_id": crop.crop_id,
                        "frame_id": crop.frame_id,
                        "source": crop.source.value,
                        "bbox": crop.bbox.model_dump(mode="json"),
                        "width": crop.output_width,
                        "height": crop.output_height,
                        "observability": (
                            crop.observability.model_dump(mode="json")
                            if crop.observability is not None
                            else None
                        ),
                        "privacy_policy": crop.privacy_receipt.policy.value,
                    }
                    for crop in selected_crops
                ],
                "objective_facts": [fact.model_dump(mode="json") for fact in pack.objective_facts],
                "track_summary": pack.track_summary.model_dump(mode="json"),
                "confirmation_record": pack.confirmation_record.model_dump(mode="json"),
                "observation_sufficiency_input": (
                    pack.observation_sufficiency_input.model_dump(mode="json")
                    if pack.observation_sufficiency_input is not None
                    else None
                ),
                "tool_results": [result.model_dump(mode="json") for result in pack.tool_results],
            },
            "precedent_retrieval": {
                "receipt_id": retrieval.receipt_id,
                "receipt_sha256": retrieval.receipt_sha256,
                "query_sha256": retrieval.query_sha256,
                "status": retrieval.status.value,
                "degraded_reason": (
                    retrieval.degraded_reason.value
                    if retrieval.degraded_reason is not None
                    else None
                ),
            },
        }
    )


def _call_budget(
    *,
    primary: bool,
    selected_pixels: int,
    budget_usage: HearingBudgetUsage,
    session: HearingSession,
    config: AppConfig,
    profile: VlmProviderProfile,
    run_manifest: RunManifest,
) -> VlmCallBudget:
    try:
        limits = derive_hearing_call_budget_limits(
            primary=primary,
            selected_pixels=selected_pixels,
            reserved_images=budget_usage.reserved_images,
            accounted_output_tokens=budget_usage.accounted_output_tokens,
            max_total_images=session.max_total_images,
            max_total_output_tokens=session.max_total_output_tokens,
            max_input_pixels=config.screening.max_input_pixels,
            max_output_tokens=config.screening.max_output_tokens,
            manifest_max_output_tokens=run_manifest.decoding_parameters.max_output_tokens,
        )
    except HearingBudgetPolicyError as exc:
        _fail(HearingRequestPreparationErrorCode(exc.reason_code.value))
    return VlmCallBudget(
        max_images=limits.max_images,
        max_input_pixels=limits.max_input_pixels,
        max_prompt_bytes=config.screening.max_prompt_bytes,
        max_input_tokens=config.screening.max_input_tokens,
        max_output_tokens=limits.max_output_tokens,
        pricing_currency=profile.pricing_currency,
        input_cost_per_million_tokens=profile.input_cost_per_million_tokens,
        output_cost_per_million_tokens=profile.output_cost_per_million_tokens,
        max_estimated_cost=config.screening.max_estimated_cost,
        max_response_bytes=config.screening.max_response_bytes,
        max_json_depth=config.screening.max_json_depth,
        max_json_fields=config.screening.max_json_fields,
        max_string_chars=config.screening.max_string_chars,
        timeout_seconds=profile.timeout_seconds,
    )


def _render(
    *,
    catalog: PromptCatalog,
    role_authority: _RoleAuthority,
    inputs: HearingCanonicalInputs,
    budget: VlmCallBudget,
) -> RenderedPrompt:
    rendered_role = rendered_role_for(role_authority)
    rendered = catalog.render(
        prompt_id=role_authority.prompt_id,
        variables=inputs.variables_for(rendered_role),
    )
    if (
        rendered.manifest.prompt_bundle_sha256 != catalog.bundle_sha256
        or catalog.bundle_sha256 not in SUPPORTED_M4_PROMPT_BUNDLE_SHA256S
        or rendered.manifest.role != rendered_role
    ):
        _fail(HearingRequestPreparationErrorCode.PROMPT_BUNDLE_MISMATCH)
    if len(rendered.utf8_bytes) > budget.max_prompt_bytes:
        _fail(HearingRequestPreparationErrorCode.PROMPT_BUDGET_EXCEEDED)
    return rendered


def rendered_role_for(role_authority: _RoleAuthority) -> VlmRole:
    """Recover the role from a closed prompt ID without accepting aliases."""

    for role, prompt_id in _ROLE_PROMPT_IDS.items():
        if prompt_id == role_authority.prompt_id:
            return role
    raise AssertionError("unreachable hearing role authority")


def prepare_primary_hearing_request(
    *,
    role: VlmRole,
    session: HearingSession,
    cycle_scope: HearingCycleScope,
    retrieval: HearingPrecedentRetrievalReceipt,
    evidence_pack: EvidencePack,
    evidence_authority: EvidenceAuthority,
    hearing_grant: HearingEvidenceGrant | None,
    budget_usage: HearingBudgetUsage,
    config: AppConfig,
    run_manifest: RunManifest,
    catalog: PromptCatalog,
    prosecutor_output: HearingRoleOutput | None = None,
    defender_output: HearingRoleOutput | None = None,
    generation: HearingRequestGeneration | None = None,
) -> PreparedHearingRequest:
    """Prepare one primary Prosecutor, Defender, or Judge request."""

    _validate_argument_types(
        session=session,
        cycle_scope=cycle_scope,
        retrieval=retrieval,
        evidence_pack=evidence_pack,
        evidence_authority=evidence_authority,
        budget_usage=budget_usage,
        config=config,
        run_manifest=run_manifest,
        catalog=catalog,
    )
    role_authority = _validate_run_session_authority(
        role=role,
        session=session,
        cycle_scope=cycle_scope,
        evidence_pack=evidence_pack,
        evidence_authority=evidence_authority,
        config=config,
        run_manifest=run_manifest,
        catalog=catalog,
    )
    _validate_cycle_and_retrieval(
        cycle_scope=cycle_scope,
        retrieval=retrieval,
        evidence_pack=evidence_pack,
        config=config,
        run_manifest=run_manifest,
    )
    _validate_evidence_authority(evidence_pack, evidence_authority)
    _validate_grant(hearing_grant)
    selected_crop = _select_crop(evidence_authority, role_authority, run_manifest)
    try:
        disclosure = derive_role_disclosure(
            evidence_authority,
            (selected_crop.crop_id,),
        )
        next_grant = extend_hearing_evidence_grant(hearing_grant, disclosure)
    except EvidenceDisclosureError:
        _fail(HearingRequestPreparationErrorCode.EVIDENCE_AUTHORITY_MISMATCH)

    prosecutor_ref, defender_ref, prosecutor_json, defender_json = _upstream_inputs(
        role=role,
        session=session,
        scope=cycle_scope,
        retrieval=retrieval,
        catalog=catalog,
        prosecutor_output=prosecutor_output,
        defender_output=defender_output,
    )
    precedent_refs, precedents_json = _precedent_inputs(retrieval)
    inputs = HearingCanonicalInputs(
        hearing_context_json=_hearing_context(
            role=role,
            session=session,
            scope=cycle_scope,
            retrieval=retrieval,
            pack=evidence_pack,
            disclosure=disclosure,
        ),
        allowed_refs_json=canonical_json(
            [ref.model_dump(mode="json") for ref in disclosure.allowed_evidence_refs]
        ),
        precedents_json=precedents_json,
        prosecutor_output_json=prosecutor_json,
        defender_output_json=defender_json,
    )
    budget = _call_budget(
        primary=True,
        selected_pixels=selected_crop.output_width * selected_crop.output_height,
        budget_usage=budget_usage,
        session=session,
        config=config,
        profile=role_authority.profile,
        run_manifest=run_manifest,
    )
    rendered = _render(
        catalog=catalog,
        role_authority=role_authority,
        inputs=inputs,
        budget=budget,
    )
    request_generation = generation or HearingRequestGeneration()
    if not isinstance(request_generation, HearingRequestGeneration):
        raise TypeError("generation must be HearingRequestGeneration or None")
    request = HearingModelRequest(
        attempt_index=0,
        run_id=cycle_scope.run_id,
        case_id=cycle_scope.case_id,
        hearing_session_id=session.session_id,
        round_index=cycle_scope.cycle_index,
        prior_acquisition_rounds=cycle_scope.prior_acquisition_rounds,
        prior_rework_rounds=cycle_scope.prior_rework_rounds,
        current_evidence_pack_id=evidence_pack.pack_id,
        current_evidence_pack_version=evidence_pack.version,
        screening_ref=ArtifactRef(
            kind=ArtifactKind.SCREENING_RESULT,
            artifact_id=session.screening_id,
        ),
        violation_type=evidence_pack.event.violation_type,
        evidence_class=evidence_pack.event.evidence_class,
        role=role,
        provider_profile=role_authority.profile_name,
        provider=role_authority.profile.provider,
        model=role_authority.profile.model,
        revision=role_authority.profile.revision,
        model_manifest_id=role_authority.model_manifest.model_manifest_id,
        execution_location=role_authority.profile.execution_location,
        prompt_manifest=rendered.manifest,
        hearing_prompt_bundle_sha256=session.hearing_prompt_bundle_sha256,
        rendered_prompt_sha256=rendered.rendered_prompt_sha256,
        hearing_context_sha256=_document_sha256(inputs.hearing_context_json),
        media=disclosure.media,
        allowed_evidence_refs=disclosure.allowed_evidence_refs,
        allowed_precedent_refs=precedent_refs,
        prosecutor_output_ref=prosecutor_ref,
        defender_output_ref=defender_ref,
        precedent_retrieval_degraded=(retrieval.status == HearingPrecedentRetrievalStatus.DEGRADED),
        precedent_retrieval_receipt_id=retrieval.receipt_id,
        precedent_retrieval_receipt_sha256=retrieval.receipt_sha256,
        initial_trigger_review_ref=cycle_scope.initial_trigger_review_ref,
        initial_defect_codes=cycle_scope.initial_defect_codes,
        rework_review_ref=cycle_scope.rework_review_ref,
        rework_defect_codes=cycle_scope.rework_defect_codes,
        temperature=run_manifest.decoding_parameters.temperature,
        seed=run_manifest.decoding_parameters.seed,
        budget=budget,
        backlog_retry_context=request_generation.backlog_retry_context,
        manifest_id=run_manifest.manifest_id,
    )
    try:
        validate_hearing_cycle_scope_binding(cycle_scope, request)
    except (TypeError, ValueError):
        _fail(HearingRequestPreparationErrorCode.CYCLE_SCOPE_MISMATCH)
    return PreparedHearingRequest(
        request=request,
        rendered_prompt=rendered,
        canonical_inputs=inputs,
        disclosure=disclosure,
        hearing_grant=next_grant,
    )


def _validate_original_response(
    request: HearingModelRequest,
    response: HearingModelResponse,
    raw_response: bytes,
) -> None:
    if request.attempt_index != 0:
        _fail(HearingRequestPreparationErrorCode.ORIGINAL_REQUEST_MISMATCH)
    expected = (
        request.run_id,
        request.case_id,
        request.hearing_session_id,
        request.round_index,
        request.prior_acquisition_rounds,
        request.prior_rework_rounds,
        request.current_evidence_pack_id,
        request.current_evidence_pack_version,
        request.role,
        0,
        request.request_id,
        request.request_sha256,
        request.cache_key,
        request.model_manifest_id,
        request.manifest_id,
        f"{request.run_id}/model_responses/{response.response_id}.json",
    )
    actual = (
        response.run_id,
        response.case_id,
        response.hearing_session_id,
        response.round_index,
        response.prior_acquisition_rounds,
        response.prior_rework_rounds,
        response.current_evidence_pack_id,
        response.current_evidence_pack_version,
        response.role,
        response.attempt_index,
        response.request_id,
        response.request_sha256,
        response.cache_key,
        response.model_manifest_id,
        response.manifest_id,
        response.raw_response_ref,
    )
    if actual != expected:
        _fail(HearingRequestPreparationErrorCode.ORIGINAL_RESPONSE_BINDING_MISMATCH)
    if len(raw_response) != response.size_bytes:
        _fail(HearingRequestPreparationErrorCode.RAW_RESPONSE_SIZE_MISMATCH)
    if hashlib.sha256(raw_response).hexdigest() != response.content_sha256:
        _fail(HearingRequestPreparationErrorCode.RAW_RESPONSE_CONTENT_MISMATCH)
    if len(raw_response) > request.budget.max_response_bytes:
        _fail(HearingRequestPreparationErrorCode.ORIGINAL_RESPONSE_TOO_LARGE)


def _validate_repair_inspection(
    request: HearingModelRequest,
    response: HearingModelResponse,
    inspection: HearingParseInspection,
) -> tuple[ProceduralDefect, ...]:
    if inspection.payload is not None or not inspection.defects:
        _fail(HearingRequestPreparationErrorCode.INSPECTION_NOT_REPAIRABLE)
    if inspection.request != request or inspection.response != response:
        _fail(HearingRequestPreparationErrorCode.INSPECTION_BINDING_MISMATCH)
    defects = inspection.defects
    if (
        not isinstance(defects, tuple)
        or any(not isinstance(defect, ProceduralDefect) for defect in defects)
        or tuple(defect.sort_key for defect in defects)
        != tuple(sorted(defect.sort_key for defect in defects))
        or len({defect.sort_key for defect in defects}) != len(defects)
        or any(
            defect.origin != ProceduralDefectOrigin.PARSER
            or defect.code not in _PARSER_DEFECT_CODES
            or defect.artifact_ref.kind != ArtifactKind.MODEL_RESPONSE
            or defect.artifact_ref.artifact_id != response.response_id
            for defect in defects
        )
    ):
        _fail(HearingRequestPreparationErrorCode.PARSE_DEFECTS_INVALID)
    return defects


def _prior_response_json(raw_response: bytes, response: HearingModelResponse) -> str:
    common: dict[str, object] = {
        "content_sha256": response.content_sha256,
        "size_bytes": response.size_bytes,
    }
    try:
        decoded = raw_response.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        decoded = None
    if decoded is not None:
        document = canonical_json({**common, "encoding": "utf-8", "text": decoded})
        if (
            len(decoded) <= MAX_PROMPT_STRING_CHARS
            and len(document.encode("utf-8")) <= MAX_PROMPT_VARIABLE_BYTES
        ):
            return document

    encoded = base64.b64encode(raw_response).decode("ascii")
    data: dict[str, object]
    if len(encoded) <= MAX_PROMPT_STRING_CHARS:
        data = {"data": encoded}
    else:
        data = {
            "data_chunks": [
                encoded[offset : offset + MAX_PROMPT_STRING_CHARS]
                for offset in range(0, len(encoded), MAX_PROMPT_STRING_CHARS)
            ]
        }
    document = canonical_json({**common, **data, "encoding": "base64"})
    if len(document.encode("utf-8")) > MAX_PROMPT_VARIABLE_BYTES:
        _fail(HearingRequestPreparationErrorCode.ORIGINAL_RESPONSE_TOO_LARGE)
    return document


def _repair_context_json(
    request: HearingModelRequest,
    response: HearingModelResponse,
    defects: tuple[ProceduralDefect, ...],
) -> str:
    return canonical_json(
        {
            "schema_version": "m4-hearing-repair-context-v1",
            "original_request_id": request.request_id,
            "original_request_sha256": request.request_sha256,
            "original_response_id": response.response_id,
            "original_response_content_sha256": response.content_sha256,
            "structural_defects": [
                {
                    "code": defect.code.value,
                    "reason_code": defect.reason_code.value,
                    "field": defect.field.value,
                    "defect_id": defect.defect_id,
                }
                for defect in defects
            ],
        }
    )


def _validate_repair_authorities(
    *,
    original: PreparedHearingRequest,
    session: HearingSession,
    config: AppConfig,
    run_manifest: RunManifest,
    catalog: PromptCatalog,
) -> tuple[str, VlmProviderProfile, ModelManifest]:
    request = original.request
    if (
        request.attempt_index != 0
        or original.disclosure is None
        or original.canonical_inputs.repair_context_json != "null"
        or original.canonical_inputs.prior_response_json != "null"
    ):
        _fail(HearingRequestPreparationErrorCode.ORIGINAL_REQUEST_MISMATCH)
    if not all(
        (
            config.schema_version == run_manifest.schema_version,
            config.config_sha256 == run_manifest.config_sha256,
            config.rule_version == run_manifest.rule_version,
            config.run.reproducibility_mode == run_manifest.reproducibility_mode,
            config.run.random_seed == run_manifest.random_seed,
            config.run.storage_boundary == run_manifest.storage_boundary,
            config.evidence.privacy_transform_version == run_manifest.privacy_transform_version,
            config.evidence.encoding_version == run_manifest.image_encoding_version,
        )
    ):
        _fail(HearingRequestPreparationErrorCode.RUN_MANIFEST_MISMATCH)
    if (
        session.session_id != request.hearing_session_id
        or session.run_id != request.run_id
        or session.case_id != request.case_id
        or session.manifest_id != request.manifest_id
        or session.acquisition_round_limit != config.hearing.max_acquisition_rounds
        or session.rework_round_limit != config.hearing.max_rework_rounds
        or session.max_total_images != config.hearing.max_total_images
        or session.max_total_output_tokens != config.hearing.max_total_output_tokens
    ):
        _fail(HearingRequestPreparationErrorCode.SESSION_AUTHORITY_MISMATCH)

    selected: tuple[str, VlmProviderProfile, ModelManifest] | None = None
    for role in (VlmRole.PROSECUTOR, VlmRole.DEFENDER, VlmRole.JUDGE):
        profile_name = getattr(config.hearing, _ROLE_PROFILE_FIELDS[role])
        profile = config.providers.get(profile_name)
        model_manifest = run_manifest.models.get(role.value.lower())
        if (
            profile is None
            or model_manifest is None
            or (
                model_manifest.component != role.value.lower()
                or model_manifest.provider != profile.provider
                or model_manifest.model != profile.model
                or model_manifest.revision != profile.revision
                or model_manifest.quantization != profile.quantization
                or model_manifest.model_manifest_id != getattr(session, _ROLE_MODEL_FIELDS[role])
            )
        ):
            _fail(HearingRequestPreparationErrorCode.MODEL_MANIFEST_MISMATCH)
        if role == request.role:
            selected = profile_name, profile, model_manifest
    assert selected is not None
    profile_name, profile, model_manifest = selected
    if (
        request.provider_profile,
        request.provider,
        request.model,
        request.revision,
        request.model_manifest_id,
        request.execution_location,
        request.temperature,
        request.seed,
        request.manifest_id,
    ) != (
        profile_name,
        profile.provider,
        profile.model,
        profile.revision,
        model_manifest.model_manifest_id,
        profile.execution_location,
        run_manifest.decoding_parameters.temperature,
        run_manifest.decoding_parameters.seed,
        run_manifest.manifest_id,
    ):
        _fail(HearingRequestPreparationErrorCode.MODEL_MANIFEST_MISMATCH)
    if (
        session.hearing_prompt_bundle_sha256 != catalog.bundle_sha256
        or catalog.bundle_sha256 not in SUPPORTED_M4_PROMPT_BUNDLE_SHA256S
        or request.hearing_prompt_bundle_sha256 != catalog.bundle_sha256
    ):
        _fail(HearingRequestPreparationErrorCode.PROMPT_BUNDLE_MISMATCH)
    prompt_id = _ROLE_PROMPT_IDS[request.role]
    if request.prompt_manifest != catalog.manifest(prompt_id):
        _fail(HearingRequestPreparationErrorCode.PROMPT_BUNDLE_MISMATCH)
    expected_original = catalog.render(
        prompt_id=prompt_id,
        variables=original.canonical_inputs.variables_for(request.role),
    )
    if expected_original != original.rendered_prompt:
        _fail(HearingRequestPreparationErrorCode.ORIGINAL_REQUEST_MISMATCH)
    return profile_name, profile, model_manifest


def prepare_hearing_repair_request(
    *,
    original: PreparedHearingRequest,
    response: HearingModelResponse,
    inspection: HearingParseInspection,
    raw_response: bytes,
    session: HearingSession,
    cycle_scope: HearingCycleScope,
    budget_usage: HearingBudgetUsage,
    config: AppConfig,
    run_manifest: RunManifest,
    catalog: PromptCatalog,
) -> PreparedHearingRequest:
    """Prepare the sole media-free structural repair for one primary call."""

    if not isinstance(original, PreparedHearingRequest):
        raise TypeError("original must be a PreparedHearingRequest")
    if not isinstance(response, HearingModelResponse):
        raise TypeError("response must be a HearingModelResponse")
    if not isinstance(inspection, HearingParseInspection):
        raise TypeError("inspection must be a HearingParseInspection")
    if not isinstance(raw_response, bytes):
        _fail(HearingRequestPreparationErrorCode.RAW_RESPONSE_NOT_BYTES)
    if not isinstance(session, HearingSession):
        raise TypeError("session must be a HearingSession")
    if not isinstance(cycle_scope, HearingCycleScope):
        raise TypeError("cycle_scope must be a HearingCycleScope")
    if not isinstance(budget_usage, HearingBudgetUsage):
        raise TypeError("budget_usage must be HearingBudgetUsage")
    if not isinstance(config, AppConfig) or not isinstance(run_manifest, RunManifest):
        raise TypeError("config and run_manifest must be their exact contract types")
    if not isinstance(catalog, PromptCatalog):
        raise TypeError("catalog must implement PromptCatalog")

    request = original.request
    try:
        validate_hearing_cycle_scope_binding(cycle_scope, request)
    except (TypeError, ValueError):
        _fail(HearingRequestPreparationErrorCode.CYCLE_SCOPE_MISMATCH)
    _validate_original_response(request, response, raw_response)
    defects = _validate_repair_inspection(request, response, inspection)

    # Revalidate every frozen authority that can be checked without reopening
    # media or repositories.  Repair deliberately does not reselect evidence.
    profile_name, profile, model_manifest = _validate_repair_authorities(
        original=original,
        session=session,
        config=config,
        run_manifest=run_manifest,
        catalog=catalog,
    )

    prior_json = _prior_response_json(raw_response, response)
    repair_json = _repair_context_json(request, response, defects)
    inputs = replace(
        original.canonical_inputs,
        repair_context_json=repair_json,
        prior_response_json=prior_json,
    )
    budget = _call_budget(
        primary=False,
        selected_pixels=0,
        budget_usage=budget_usage,
        session=session,
        config=config,
        profile=profile,
        run_manifest=run_manifest,
    )
    role_authority = _RoleAuthority(
        prompt_id=_ROLE_PROMPT_IDS[request.role],
        profile_name=profile_name,
        profile=profile,
        model_manifest=model_manifest,
    )
    rendered = _render(
        catalog=catalog,
        role_authority=role_authority,
        inputs=inputs,
        budget=budget,
    )
    repaired = HearingModelRequest(
        attempt_index=1,
        run_id=request.run_id,
        case_id=request.case_id,
        hearing_session_id=request.hearing_session_id,
        round_index=request.round_index,
        prior_acquisition_rounds=request.prior_acquisition_rounds,
        prior_rework_rounds=request.prior_rework_rounds,
        current_evidence_pack_id=request.current_evidence_pack_id,
        current_evidence_pack_version=request.current_evidence_pack_version,
        screening_ref=request.screening_ref,
        violation_type=request.violation_type,
        evidence_class=request.evidence_class,
        role=request.role,
        provider_profile=request.provider_profile,
        provider=request.provider,
        model=request.model,
        revision=request.revision,
        model_manifest_id=request.model_manifest_id,
        execution_location=request.execution_location,
        prompt_manifest=rendered.manifest,
        hearing_prompt_bundle_sha256=request.hearing_prompt_bundle_sha256,
        rendered_prompt_sha256=rendered.rendered_prompt_sha256,
        hearing_context_sha256=request.hearing_context_sha256,
        media=(),
        allowed_evidence_refs=request.allowed_evidence_refs,
        allowed_precedent_refs=request.allowed_precedent_refs,
        prosecutor_output_ref=request.prosecutor_output_ref,
        defender_output_ref=request.defender_output_ref,
        precedent_retrieval_degraded=request.precedent_retrieval_degraded,
        precedent_retrieval_receipt_id=request.precedent_retrieval_receipt_id,
        precedent_retrieval_receipt_sha256=request.precedent_retrieval_receipt_sha256,
        initial_trigger_review_ref=request.initial_trigger_review_ref,
        initial_defect_codes=request.initial_defect_codes,
        rework_review_ref=request.rework_review_ref,
        rework_defect_codes=request.rework_defect_codes,
        original_request_id=request.request_id,
        original_response_id=response.response_id,
        original_response_content_sha256=response.content_sha256,
        repair_context_sha256=_document_sha256(repair_json),
        temperature=request.temperature,
        seed=request.seed,
        budget=budget,
        backlog_retry_context=request.backlog_retry_context,
        manifest_id=request.manifest_id,
    )
    try:
        validate_hearing_cycle_scope_binding(cycle_scope, repaired)
    except (TypeError, ValueError):
        _fail(HearingRequestPreparationErrorCode.CYCLE_SCOPE_MISMATCH)
    return PreparedHearingRequest(
        request=repaired,
        rendered_prompt=rendered,
        canonical_inputs=inputs,
        disclosure=None,
        hearing_grant=original.hearing_grant,
    )


__all__ = [
    "FROZEN_M4_PROMPT_BUNDLE_SHA256",
    "HEARING_DEFENDER_PROMPT_ID",
    "HEARING_JUDGE_PROMPT_ID",
    "HEARING_PROSECUTOR_PROMPT_ID",
    "LEGACY_M4_PROMPT_BUNDLE_SHA256",
    "SUPPORTED_M4_PROMPT_BUNDLE_SHA256S",
    "HearingBudgetUsage",
    "HearingCanonicalInputs",
    "HearingRequestGeneration",
    "HearingRequestPreparationError",
    "HearingRequestPreparationErrorCode",
    "PreparedHearingRequest",
    "prepare_hearing_repair_request",
    "prepare_primary_hearing_request",
]

"""Body-free reconstruction of the controlled M5 hearing query embedding."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn, TypeVar

from pydantic import ValidationError

from labcourt.application.hearing_request import FROZEN_M4_PROMPT_BUNDLE_SHA256
from labcourt.application.hearing_situation import (
    HearingSituationBuildError,
    build_hearing_situation_text,
)
from labcourt.application.m5_hearing_precedent_bridge import (
    M5_HEARING_PRECEDENT_BRIDGE_MANIFEST_ID,
    M5_HEARING_PRECEDENT_BRIDGE_VERSION,
    M5HearingPrecedentBridgeError,
    derive_m5_query_for_hearing,
)
from labcourt.application.m5_precedent_policy_verifier import (
    ConfiguredM5PrecedentPolicyVerifier,
)
from labcourt.application.m6_upgrade_physical_resolution import (
    M6UpgradePhysicalResolutionError,
    derive_m6_upgrade_embedding_physical_ref,
)
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.cases import Case
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import (
    ArtifactKind,
    EvidenceClass,
    ProceduralDefectCode,
    ViolationType,
)
from labcourt.contracts.evidence import EvidencePack
from labcourt.contracts.hearing_common import HearingCycleScope
from labcourt.contracts.hearing_retrieval import (
    HearingPrecedentRetrievalQuery,
    derive_hearing_evidence_pack_document_sha256,
)
from labcourt.contracts.hearing_state import (
    HearingPrecedentDegradedReason,
    HearingPrecedentRetrievalStatus,
    HearingSession,
    HearingSessionEntryStatus,
)
from labcourt.contracts.m5_precedents import M5EmbeddingVector, M5PrecedentRetrievalQuery
from labcourt.contracts.m6_replay_locked import (
    M6LockedEmbeddingChannel,
    M6LockedEmbeddingScope,
)
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactRef,
    M6UpgradePhysicalArtifactSource,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.references import require_reference_token
from labcourt.contracts.storage import ArtifactRef
from labcourt.domain.m6_embedding_authority import M6ResolvedEmbeddingAuthority
from labcourt.exceptions import LabCourtError


class M6SQLiteM5PrecedentQueryFailureCode(StrEnum):
    """Closed reasons why normalized M4/M5 metadata cannot prove a query."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    CASE_BINDING_MISMATCH = "CASE_BINDING_MISMATCH"
    HEARING_BINDING_MISMATCH = "HEARING_BINDING_MISMATCH"
    CYCLE_BINDING_MISMATCH = "CYCLE_BINDING_MISMATCH"
    PACK_BINDING_MISMATCH = "PACK_BINDING_MISMATCH"
    RETRIEVAL_BINDING_MISMATCH = "RETRIEVAL_BINDING_MISMATCH"
    BRIDGE_BINDING_MISMATCH = "BRIDGE_BINDING_MISMATCH"
    QUERY_BINDING_MISMATCH = "QUERY_BINDING_MISMATCH"
    POLICY_BINDING_MISMATCH = "POLICY_BINDING_MISMATCH"
    EMBEDDING_BINDING_MISMATCH = "EMBEDDING_BINDING_MISMATCH"
    PHYSICAL_PLAN_INVALID = "PHYSICAL_PLAN_INVALID"


class M6SQLiteM5PrecedentQueryError(LabCourtError):
    """The body-free M5 hearing query cannot be reconstructed exactly."""

    def __init__(self, reason_code: M6SQLiteM5PrecedentQueryFailureCode) -> None:
        if not isinstance(reason_code, M6SQLiteM5PrecedentQueryFailureCode):
            raise TypeError("reason_code must be an M6 SQLite M5 query failure code")
        self.reason_code = reason_code
        super().__init__(reason_code.value)


def _fail(reason_code: M6SQLiteM5PrecedentQueryFailureCode) -> NoReturn:
    raise M6SQLiteM5PrecedentQueryError(reason_code)


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _require_sha256(value: object, label: str) -> str:
    if not _is_sha256(value):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    assert isinstance(value, str)
    return value


def _require_optional_sha256(value: object, label: str) -> str | None:
    if value is None:
        return None
    return _require_sha256(value, label)


def _require_positive(value: object, label: str, *, maximum: int | None = None) -> int:
    if type(value) is not int or value < 1 or (maximum is not None and value > maximum):
        raise ValueError(f"{label} is outside its closed positive bound")
    assert isinstance(value, int)
    return value


def _require_non_negative(value: object, label: str, *, maximum: int | None = None) -> int:
    if type(value) is not int or value < 0 or (maximum is not None and value > maximum):
        raise ValueError(f"{label} is outside its closed non-negative bound")
    assert isinstance(value, int)
    return value


def _require_reference(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a reference token")
    return require_reference_token(value, label)


@dataclass(frozen=True, slots=True)
class M6SQLiteM5HearingQueryMetadata:
    """Normalized hearing columns sufficient to rebuild one session document."""

    run_id: str
    case_id: str
    hearing_id: str
    screening_id: str
    entry_status: HearingSessionEntryStatus
    trigger_review_id: str | None
    initial_defect_codes_sha256: str
    initial_pack_id: str
    initial_pack_version: int
    max_acquisition_rounds: int
    max_rework_rounds: int
    max_total_images: int
    max_total_output_tokens: int
    max_judge_cycles: int
    hearing_prompt_bundle_sha256: str
    prosecutor_model_manifest_id: str
    defender_model_manifest_id: str
    judge_model_manifest_id: str
    manifest_id: str
    document_sha256: str

    def __post_init__(self) -> None:
        _require_reference(self.run_id, "M6 M5 hearing run_id")
        _require_reference(self.case_id, "M6 M5 hearing case_id")
        for label, value in (
            ("hearing_id", self.hearing_id),
            ("screening_id", self.screening_id),
            ("initial_defect_codes_sha256", self.initial_defect_codes_sha256),
            ("initial_pack_id", self.initial_pack_id),
            ("hearing_prompt_bundle_sha256", self.hearing_prompt_bundle_sha256),
            ("prosecutor_model_manifest_id", self.prosecutor_model_manifest_id),
            ("defender_model_manifest_id", self.defender_model_manifest_id),
            ("judge_model_manifest_id", self.judge_model_manifest_id),
            ("manifest_id", self.manifest_id),
            ("document_sha256", self.document_sha256),
        ):
            _require_sha256(value, f"M6 M5 hearing {label}")
        if type(self.entry_status) is not HearingSessionEntryStatus:
            raise TypeError("M6 M5 hearing entry_status must be typed")
        _require_optional_sha256(self.trigger_review_id, "M6 M5 hearing trigger_review_id")
        _require_positive(self.initial_pack_version, "M6 M5 hearing initial pack version")
        _require_non_negative(
            self.max_acquisition_rounds,
            "M6 M5 hearing acquisition limit",
            maximum=2,
        )
        _require_non_negative(
            self.max_rework_rounds,
            "M6 M5 hearing rework limit",
            maximum=2,
        )
        _require_positive(self.max_total_images, "M6 M5 hearing image budget", maximum=320)
        _require_positive(
            self.max_total_output_tokens,
            "M6 M5 hearing token budget",
            maximum=1_000_000,
        )
        _require_positive(self.max_judge_cycles, "M6 M5 hearing cycle budget", maximum=5)


@dataclass(frozen=True, slots=True)
class M6SQLiteM5CycleQueryMetadata:
    """Normalized cycle columns sufficient to rebuild one cycle scope."""

    run_id: str
    case_id: str
    hearing_id: str
    cycle_id: str
    cycle_sha256: str
    cycle_index: int
    prior_acquisition_rounds: int
    prior_rework_rounds: int
    cycle_pack_id: str
    cycle_pack_version: int
    initial_trigger_review_id: str | None
    initial_defect_codes_sha256: str
    rework_review_id: str | None
    rework_defect_codes_sha256: str
    manifest_id: str

    def __post_init__(self) -> None:
        _require_reference(self.run_id, "M6 M5 cycle run_id")
        _require_reference(self.case_id, "M6 M5 cycle case_id")
        for label, value in (
            ("hearing_id", self.hearing_id),
            ("cycle_id", self.cycle_id),
            ("cycle_sha256", self.cycle_sha256),
            ("cycle_pack_id", self.cycle_pack_id),
            ("initial_defect_codes_sha256", self.initial_defect_codes_sha256),
            ("rework_defect_codes_sha256", self.rework_defect_codes_sha256),
            ("manifest_id", self.manifest_id),
        ):
            _require_sha256(value, f"M6 M5 cycle {label}")
        _require_positive(self.cycle_index, "M6 M5 cycle index", maximum=5)
        _require_non_negative(
            self.prior_acquisition_rounds,
            "M6 M5 prior acquisition rounds",
            maximum=2,
        )
        _require_non_negative(
            self.prior_rework_rounds,
            "M6 M5 prior rework rounds",
            maximum=2,
        )
        _require_positive(self.cycle_pack_version, "M6 M5 cycle pack version")
        _require_optional_sha256(
            self.initial_trigger_review_id,
            "M6 M5 cycle initial review",
        )
        _require_optional_sha256(self.rework_review_id, "M6 M5 cycle rework review")


@dataclass(frozen=True, slots=True)
class M6SQLiteM5RetrievalQueryMetadata:
    """Normalized successful M4 retrieval columns used by the M5 bridge."""

    run_id: str
    retrieval_receipt_id: str
    hearing_id: str
    cycle_scope_id: str
    cycle_scope_sha256: str
    case_id: str
    prior_acquisition_rounds: int
    prior_rework_rounds: int
    current_pack_id: str
    current_pack_version: int
    evidence_class: EvidenceClass
    violation_type: ViolationType
    rule_version: str
    top_k: int
    initial_trigger_review_id: str | None
    initial_defect_codes_sha256: str
    rework_review_id: str | None
    rework_defect_codes_sha256: str
    retrieval_status: HearingPrecedentRetrievalStatus
    degraded_reason: HearingPrecedentDegradedReason | None
    precedent_retrieval_degraded: bool
    retriever_version: str
    retriever_manifest_id: str
    query_sha256: str
    embedding_model_manifest_id: str | None
    manifest_id: str

    def __post_init__(self) -> None:
        _require_reference(self.run_id, "M6 M5 retrieval run_id")
        _require_reference(self.case_id, "M6 M5 retrieval case_id")
        _require_reference(self.rule_version, "M6 M5 retrieval rule_version")
        _require_reference(self.retriever_version, "M6 M5 retrieval retriever_version")
        for label, value in (
            ("retrieval_receipt_id", self.retrieval_receipt_id),
            ("hearing_id", self.hearing_id),
            ("cycle_scope_id", self.cycle_scope_id),
            ("cycle_scope_sha256", self.cycle_scope_sha256),
            ("current_pack_id", self.current_pack_id),
            ("initial_defect_codes_sha256", self.initial_defect_codes_sha256),
            ("rework_defect_codes_sha256", self.rework_defect_codes_sha256),
            ("retriever_manifest_id", self.retriever_manifest_id),
            ("query_sha256", self.query_sha256),
            ("manifest_id", self.manifest_id),
        ):
            _require_sha256(value, f"M6 M5 retrieval {label}")
        _require_optional_sha256(
            self.initial_trigger_review_id,
            "M6 M5 retrieval initial review",
        )
        _require_optional_sha256(self.rework_review_id, "M6 M5 retrieval rework review")
        _require_optional_sha256(
            self.embedding_model_manifest_id,
            "M6 M5 retrieval embedding model",
        )
        _require_non_negative(
            self.prior_acquisition_rounds,
            "M6 M5 retrieval prior acquisition rounds",
            maximum=2,
        )
        _require_non_negative(
            self.prior_rework_rounds,
            "M6 M5 retrieval prior rework rounds",
            maximum=2,
        )
        _require_positive(self.current_pack_version, "M6 M5 retrieval pack version")
        _require_positive(self.top_k, "M6 M5 retrieval top_k", maximum=64)
        if (
            type(self.evidence_class) is not EvidenceClass
            or type(self.violation_type) is not ViolationType
        ):
            raise TypeError("M6 M5 retrieval evidence and violation classes must be typed")
        if type(self.retrieval_status) is not HearingPrecedentRetrievalStatus:
            raise TypeError("M6 M5 retrieval status must be typed")
        if (
            self.degraded_reason is not None
            and type(self.degraded_reason) is not HearingPrecedentDegradedReason
        ):
            raise TypeError("M6 M5 retrieval degraded reason must be typed")
        if type(self.precedent_retrieval_degraded) is not bool:
            raise TypeError("M6 M5 retrieval degraded flag must be bool")


@dataclass(frozen=True, slots=True)
class M6SQLiteM5ExposureQueryMetadata:
    """Normalized exposure identities that must equal the rebuilt bridge query."""

    run_id: str
    exposure_id: str
    case_id: str
    hearing_id: str
    cycle_index: int
    cycle_scope_id: str
    cycle_scope_sha256: str
    retrieval_receipt_id: str
    m4_query_id: str
    m5_query_id: str
    policy_id: str
    bridge_manifest_id: str
    manifest_id: str

    def __post_init__(self) -> None:
        _require_reference(self.run_id, "M6 M5 exposure run_id")
        _require_reference(self.case_id, "M6 M5 exposure case_id")
        for label, value in (
            ("exposure_id", self.exposure_id),
            ("hearing_id", self.hearing_id),
            ("cycle_scope_id", self.cycle_scope_id),
            ("cycle_scope_sha256", self.cycle_scope_sha256),
            ("retrieval_receipt_id", self.retrieval_receipt_id),
            ("m4_query_id", self.m4_query_id),
            ("m5_query_id", self.m5_query_id),
            ("policy_id", self.policy_id),
            ("bridge_manifest_id", self.bridge_manifest_id),
            ("manifest_id", self.manifest_id),
        ):
            _require_sha256(value, f"M6 M5 exposure {label}")
        _require_positive(self.cycle_index, "M6 M5 exposure cycle index", maximum=5)


@dataclass(frozen=True, slots=True)
class M6SQLiteM5ReconstructedPrecedentQuery:
    """Exact query and query-vector physical identity proven without M5 bodies."""

    exposure_id: str
    hearing_session: HearingSession
    cycle_scope: HearingCycleScope
    m4_query: HearingPrecedentRetrievalQuery
    m5_query: M5PrecedentRetrievalQuery
    query_embedding_authority: M6ResolvedEmbeddingAuthority
    query_embedding_ref: M6UpgradePhysicalArtifactRef

    def __post_init__(self) -> None:
        _require_sha256(self.exposure_id, "M6 M5 reconstructed exposure_id")
        if (
            type(self.hearing_session) is not HearingSession
            or type(self.cycle_scope) is not HearingCycleScope
            or type(self.m4_query) is not HearingPrecedentRetrievalQuery
            or type(self.m5_query) is not M5PrecedentRetrievalQuery
            or type(self.query_embedding_authority) is not M6ResolvedEmbeddingAuthority
            or type(self.query_embedding_ref) is not M6UpgradePhysicalArtifactRef
        ):
            raise TypeError("M6 M5 reconstructed query requires exact typed authorities")
        vector = self.m5_query.text_embedding
        authority = self.query_embedding_authority
        ref = self.query_embedding_ref
        if (
            vector is None
            or self.m5_query.visual_embeddings
            or authority.scope != M6LockedEmbeddingScope.QUERY
            or authority.channel != M6LockedEmbeddingChannel.TEXT
            or authority.vector != vector
            or ref.source != M6UpgradePhysicalArtifactSource.M5_PRECEDENT
            or ref.kind != M6UpgradePhysicalArtifactKind.EMBEDDING
            or ref.artifact_id != vector.embedding_id
            or ref.document_sha256 != authority.document_sha256
            or ref.content_sha256 != authority.document_sha256
        ):
            raise ValueError("M6 M5 reconstructed query embedding binding is invalid")
        document = canonical_json(vector.model_dump(mode="json"))
        if ref.size_bytes != len(document.encode("utf-8")):
            raise ValueError("M6 M5 reconstructed query embedding size is invalid")

    @property
    def reconstruction_identity_sha256(self) -> str:
        return sha256_hex(
            [
                "m6-sqlite-m5-precedent-query-reconstruction",
                1,
                self.exposure_id,
                self.hearing_session.session_id,
                self.hearing_session.session_sha256,
                self.cycle_scope.cycle_id,
                self.cycle_scope.cycle_sha256,
                self.m4_query.query_id,
                self.m4_query.query_sha256,
                self.m5_query.query_id,
                self.query_embedding_ref.artifact_ref_id,
            ]
        )


_ContractT = TypeVar("_ContractT", AppConfig, Case, RunManifest)


def _controlled_contract(value: object, expected: type[_ContractT]) -> _ContractT:
    if type(value) is not expected:
        _fail(M6SQLiteM5PrecedentQueryFailureCode.INVALID_ARGUMENT)
    try:
        controlled = expected.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6SQLiteM5PrecedentQueryFailureCode.INVALID_ARGUMENT)
    if controlled != value:
        _fail(M6SQLiteM5PrecedentQueryFailureCode.INVALID_ARGUMENT)
    return controlled


def _defect_codes_sha256(codes: tuple[ProceduralDefectCode, ...]) -> str:
    document = canonical_json([code.value for code in codes])
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


def _review_defect_codes(
    selected_case: Case,
    review_id: str | None,
    *,
    reason_code: M6SQLiteM5PrecedentQueryFailureCode,
) -> tuple[ProceduralDefectCode, ...]:
    if review_id is None:
        return ()
    matches = tuple(
        review for review in selected_case.procedural_reviews if review.review_id == review_id
    )
    if len(matches) != 1 or matches[0].passed:
        _fail(reason_code)
    return tuple(
        sorted({defect.code for defect in matches[0].defects}, key=lambda code: code.value)
    )


def _selected_pack(selected_case: Case, pack_id: str, version: int) -> EvidencePack:
    matches = tuple(
        pack
        for pack in selected_case.evidence_packs
        if pack.pack_id == pack_id and pack.version == version
    )
    if len(matches) != 1 or not matches[0].complete:
        _fail(M6SQLiteM5PrecedentQueryFailureCode.PACK_BINDING_MISMATCH)
    return matches[0]


def _rebuild_hearing(
    *,
    metadata: M6SQLiteM5HearingQueryMetadata,
    selected_case: Case,
    manifest: RunManifest,
    config: AppConfig,
) -> HearingSession:
    if (
        metadata.run_id != selected_case.run_id
        or metadata.case_id != selected_case.case_id
        or metadata.manifest_id != selected_case.manifest_id
        or metadata.manifest_id != manifest.manifest_id
        or metadata.max_acquisition_rounds != config.hearing.max_acquisition_rounds
        or metadata.max_rework_rounds != config.hearing.max_rework_rounds
        or metadata.max_total_images != config.hearing.max_total_images
        or metadata.max_total_output_tokens != config.hearing.max_total_output_tokens
        or metadata.max_judge_cycles
        != 1 + metadata.max_acquisition_rounds + metadata.max_rework_rounds
        or metadata.hearing_prompt_bundle_sha256 != FROZEN_M4_PROMPT_BUNDLE_SHA256
        or metadata.prosecutor_model_manifest_id != manifest.models["prosecutor"].model_manifest_id
        or metadata.defender_model_manifest_id != manifest.models["defender"].model_manifest_id
        or metadata.judge_model_manifest_id != manifest.models["judge"].model_manifest_id
    ):
        _fail(M6SQLiteM5PrecedentQueryFailureCode.HEARING_BINDING_MISMATCH)
    _selected_pack(selected_case, metadata.initial_pack_id, metadata.initial_pack_version)
    codes = _review_defect_codes(
        selected_case,
        metadata.trigger_review_id,
        reason_code=M6SQLiteM5PrecedentQueryFailureCode.HEARING_BINDING_MISMATCH,
    )
    if _defect_codes_sha256(codes) != metadata.initial_defect_codes_sha256:
        _fail(M6SQLiteM5PrecedentQueryFailureCode.HEARING_BINDING_MISMATCH)
    review_ref = (
        None
        if metadata.trigger_review_id is None
        else ArtifactRef(
            kind=ArtifactKind.PROCEDURAL_REVIEW,
            artifact_id=metadata.trigger_review_id,
        )
    )
    try:
        session = HearingSession(
            run_id=metadata.run_id,
            case_id=metadata.case_id,
            screening_id=metadata.screening_id,
            entry_status=metadata.entry_status,
            initial_evidence_pack_id=metadata.initial_pack_id,
            initial_evidence_pack_version=metadata.initial_pack_version,
            initial_trigger_review_ref=review_ref,
            initial_defect_codes=codes,
            acquisition_round_limit=metadata.max_acquisition_rounds,
            rework_round_limit=metadata.max_rework_rounds,
            max_total_images=metadata.max_total_images,
            max_total_output_tokens=metadata.max_total_output_tokens,
            hearing_prompt_bundle_sha256=metadata.hearing_prompt_bundle_sha256,
            prosecutor_model_manifest_id=metadata.prosecutor_model_manifest_id,
            defender_model_manifest_id=metadata.defender_model_manifest_id,
            judge_model_manifest_id=metadata.judge_model_manifest_id,
            manifest_id=metadata.manifest_id,
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6SQLiteM5PrecedentQueryFailureCode.HEARING_BINDING_MISMATCH)
    if (
        session.session_id != metadata.hearing_id
        or session.session_sha256 != metadata.document_sha256
    ):
        _fail(M6SQLiteM5PrecedentQueryFailureCode.HEARING_BINDING_MISMATCH)
    return session


def _rebuild_cycle(
    *,
    metadata: M6SQLiteM5CycleQueryMetadata,
    hearing: HearingSession,
    selected_case: Case,
) -> HearingCycleScope:
    initial_codes = _review_defect_codes(
        selected_case,
        metadata.initial_trigger_review_id,
        reason_code=M6SQLiteM5PrecedentQueryFailureCode.CYCLE_BINDING_MISMATCH,
    )
    rework_codes = _review_defect_codes(
        selected_case,
        metadata.rework_review_id,
        reason_code=M6SQLiteM5PrecedentQueryFailureCode.CYCLE_BINDING_MISMATCH,
    )
    if (
        metadata.run_id != hearing.run_id
        or metadata.case_id != hearing.case_id
        or metadata.hearing_id != hearing.session_id
        or metadata.manifest_id != hearing.manifest_id
        or metadata.initial_trigger_review_id
        != (
            hearing.initial_trigger_review_ref.artifact_id
            if hearing.initial_trigger_review_ref is not None
            else None
        )
        or initial_codes != hearing.initial_defect_codes
        or _defect_codes_sha256(initial_codes) != metadata.initial_defect_codes_sha256
        or _defect_codes_sha256(rework_codes) != metadata.rework_defect_codes_sha256
        or metadata.cycle_index
        != 1 + metadata.prior_acquisition_rounds + metadata.prior_rework_rounds
        or metadata.cycle_index > hearing.max_total_judge_cycles
        or metadata.prior_acquisition_rounds > hearing.acquisition_round_limit
        or metadata.prior_rework_rounds > hearing.rework_round_limit
    ):
        _fail(M6SQLiteM5PrecedentQueryFailureCode.CYCLE_BINDING_MISMATCH)
    _selected_pack(selected_case, metadata.cycle_pack_id, metadata.cycle_pack_version)
    try:
        cycle = HearingCycleScope(
            run_id=metadata.run_id,
            case_id=metadata.case_id,
            hearing_session_id=metadata.hearing_id,
            cycle_index=metadata.cycle_index,
            prior_acquisition_rounds=metadata.prior_acquisition_rounds,
            prior_rework_rounds=metadata.prior_rework_rounds,
            cycle_evidence_pack_id=metadata.cycle_pack_id,
            cycle_evidence_pack_version=metadata.cycle_pack_version,
            initial_trigger_review_ref=(
                None
                if metadata.initial_trigger_review_id is None
                else ArtifactRef(
                    kind=ArtifactKind.PROCEDURAL_REVIEW,
                    artifact_id=metadata.initial_trigger_review_id,
                )
            ),
            initial_defect_codes=initial_codes,
            rework_review_ref=(
                None
                if metadata.rework_review_id is None
                else ArtifactRef(
                    kind=ArtifactKind.PROCEDURAL_REVIEW,
                    artifact_id=metadata.rework_review_id,
                )
            ),
            rework_defect_codes=rework_codes,
            manifest_id=metadata.manifest_id,
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6SQLiteM5PrecedentQueryFailureCode.CYCLE_BINDING_MISMATCH)
    if cycle.cycle_id != metadata.cycle_id or cycle.cycle_sha256 != metadata.cycle_sha256:
        _fail(M6SQLiteM5PrecedentQueryFailureCode.CYCLE_BINDING_MISMATCH)
    return cycle


def _rebuild_m4_query(
    *,
    metadata: M6SQLiteM5RetrievalQueryMetadata,
    hearing: HearingSession,
    cycle: HearingCycleScope,
    selected_case: Case,
    manifest: RunManifest,
    config: AppConfig,
) -> HearingPrecedentRetrievalQuery:
    pack = _selected_pack(selected_case, metadata.current_pack_id, metadata.current_pack_version)
    initial_codes = cycle.initial_defect_codes
    rework_codes = cycle.rework_defect_codes
    text_model = manifest.models["text_embedding"]
    if (
        metadata.run_id != cycle.run_id
        or metadata.case_id != cycle.case_id
        or metadata.hearing_id != hearing.session_id
        or metadata.cycle_scope_id != cycle.cycle_id
        or metadata.cycle_scope_sha256 != cycle.cycle_sha256
        or metadata.prior_acquisition_rounds != cycle.prior_acquisition_rounds
        or metadata.prior_rework_rounds != cycle.prior_rework_rounds
        or metadata.current_pack_id != cycle.cycle_evidence_pack_id
        or metadata.current_pack_version != cycle.cycle_evidence_pack_version
        or metadata.initial_trigger_review_id
        != (
            cycle.initial_trigger_review_ref.artifact_id
            if cycle.initial_trigger_review_ref is not None
            else None
        )
        or metadata.rework_review_id
        != (cycle.rework_review_ref.artifact_id if cycle.rework_review_ref is not None else None)
        or _defect_codes_sha256(initial_codes) != metadata.initial_defect_codes_sha256
        or _defect_codes_sha256(rework_codes) != metadata.rework_defect_codes_sha256
        or metadata.evidence_class != pack.event.evidence_class
        or metadata.violation_type != pack.event.violation_type
        or metadata.rule_version != manifest.rule_version
        or metadata.rule_version != config.rule_version
        or metadata.top_k != config.hearing.precedent_top_k
        or metadata.manifest_id != manifest.manifest_id
        or metadata.embedding_model_manifest_id != text_model.model_manifest_id
        or metadata.retrieval_status != HearingPrecedentRetrievalStatus.SUCCESS
        or metadata.degraded_reason is not None
        or metadata.precedent_retrieval_degraded
    ):
        _fail(M6SQLiteM5PrecedentQueryFailureCode.RETRIEVAL_BINDING_MISMATCH)
    if (
        metadata.retriever_version != M5_HEARING_PRECEDENT_BRIDGE_VERSION
        or metadata.retriever_manifest_id != M5_HEARING_PRECEDENT_BRIDGE_MANIFEST_ID
    ):
        _fail(M6SQLiteM5PrecedentQueryFailureCode.BRIDGE_BINDING_MISMATCH)
    try:
        situation_text = build_hearing_situation_text(pack)
        query = HearingPrecedentRetrievalQuery(
            run_id=metadata.run_id,
            case_id=metadata.case_id,
            hearing_session_id=hearing.session_id,
            hearing_session_sha256=hearing.session_sha256,
            cycle_scope_id=cycle.cycle_id,
            cycle_scope_sha256=cycle.cycle_sha256,
            current_evidence_pack_id=pack.pack_id,
            current_evidence_pack_version=pack.version,
            current_evidence_pack_sha256=derive_hearing_evidence_pack_document_sha256(pack),
            evidence_class=pack.event.evidence_class,
            violation_type=pack.event.violation_type,
            rule_version=manifest.rule_version,
            situation_text=situation_text,
            top_k=config.hearing.precedent_top_k,
            config_sha256=config.config_sha256,
            retriever_version=metadata.retriever_version,
            retriever_manifest_id=metadata.retriever_manifest_id,
            embedding_model_manifest=text_model,
            manifest_id=manifest.manifest_id,
        )
    except (HearingSituationBuildError, TypeError, ValueError, ValidationError):
        _fail(M6SQLiteM5PrecedentQueryFailureCode.QUERY_BINDING_MISMATCH)
    if query.query_sha256 != metadata.query_sha256:
        _fail(M6SQLiteM5PrecedentQueryFailureCode.QUERY_BINDING_MISMATCH)
    return query


def reconstruct_m6_sqlite_m5_precedent_query(
    *,
    manifest: RunManifest,
    config: AppConfig,
    selected_case: Case,
    hearing_metadata: M6SQLiteM5HearingQueryMetadata,
    cycle_metadata: M6SQLiteM5CycleQueryMetadata,
    retrieval_metadata: M6SQLiteM5RetrievalQueryMetadata,
    exposure_metadata: M6SQLiteM5ExposureQueryMetadata,
) -> M6SQLiteM5ReconstructedPrecedentQuery:
    """Rebuild the one controlled TEXT query vector before any M5 body read."""

    controlled_manifest = _controlled_contract(manifest, RunManifest)
    controlled_config = _controlled_contract(config, AppConfig)
    controlled_case = _controlled_contract(selected_case, Case)
    if any(
        type(value) is not expected
        for value, expected in (
            (hearing_metadata, M6SQLiteM5HearingQueryMetadata),
            (cycle_metadata, M6SQLiteM5CycleQueryMetadata),
            (retrieval_metadata, M6SQLiteM5RetrievalQueryMetadata),
            (exposure_metadata, M6SQLiteM5ExposureQueryMetadata),
        )
    ):
        _fail(M6SQLiteM5PrecedentQueryFailureCode.INVALID_ARGUMENT)
    if (
        controlled_manifest.config_sha256 != controlled_config.config_sha256
        or controlled_manifest.rule_version != controlled_config.rule_version
        or controlled_case.manifest_id != controlled_manifest.manifest_id
        or hearing_metadata.run_id != controlled_case.run_id
        or hearing_metadata.case_id != controlled_case.case_id
    ):
        _fail(M6SQLiteM5PrecedentQueryFailureCode.SCOPE_MISMATCH)

    hearing = _rebuild_hearing(
        metadata=hearing_metadata,
        selected_case=controlled_case,
        manifest=controlled_manifest,
        config=controlled_config,
    )
    cycle = _rebuild_cycle(
        metadata=cycle_metadata,
        hearing=hearing,
        selected_case=controlled_case,
    )
    m4_query = _rebuild_m4_query(
        metadata=retrieval_metadata,
        hearing=hearing,
        cycle=cycle,
        selected_case=controlled_case,
        manifest=controlled_manifest,
        config=controlled_config,
    )
    if (
        exposure_metadata.run_id != controlled_case.run_id
        or exposure_metadata.case_id != controlled_case.case_id
        or exposure_metadata.hearing_id != hearing.session_id
        or exposure_metadata.cycle_index != cycle.cycle_index
        or exposure_metadata.cycle_scope_id != cycle.cycle_id
        or exposure_metadata.cycle_scope_sha256 != cycle.cycle_sha256
        or exposure_metadata.retrieval_receipt_id != retrieval_metadata.retrieval_receipt_id
        or exposure_metadata.manifest_id != controlled_manifest.manifest_id
    ):
        _fail(M6SQLiteM5PrecedentQueryFailureCode.RETRIEVAL_BINDING_MISMATCH)
    if (
        exposure_metadata.m4_query_id != m4_query.query_id
        or exposure_metadata.bridge_manifest_id != M5_HEARING_PRECEDENT_BRIDGE_MANIFEST_ID
        or exposure_metadata.bridge_manifest_id != retrieval_metadata.retriever_manifest_id
    ):
        _fail(M6SQLiteM5PrecedentQueryFailureCode.BRIDGE_BINDING_MISMATCH)

    try:
        verifier = ConfiguredM5PrecedentPolicyVerifier(controlled_config)
        policy = verifier.expected_policy(controlled_manifest)
    except (TypeError, ValueError, RuntimeError, ValidationError):
        _fail(M6SQLiteM5PrecedentQueryFailureCode.POLICY_BINDING_MISMATCH)
    if exposure_metadata.policy_id != policy.policy_id:
        _fail(M6SQLiteM5PrecedentQueryFailureCode.POLICY_BINDING_MISMATCH)
    try:
        m5_query = derive_m5_query_for_hearing(
            query=m4_query,
            manifest=controlled_manifest,
            policy=policy,
            run_mode=verifier.run_mode,
        )
    except (M5HearingPrecedentBridgeError, TypeError, ValueError, RuntimeError):
        _fail(M6SQLiteM5PrecedentQueryFailureCode.QUERY_BINDING_MISMATCH)
    if exposure_metadata.m5_query_id != m5_query.query_id or m5_query.text_embedding is None:
        _fail(M6SQLiteM5PrecedentQueryFailureCode.QUERY_BINDING_MISMATCH)
    if m5_query.visual_embeddings:
        _fail(M6SQLiteM5PrecedentQueryFailureCode.EMBEDDING_BINDING_MISMATCH)

    vector: M5EmbeddingVector = m5_query.text_embedding
    document = canonical_json(vector.model_dump(mode="json"))
    document_sha256 = hashlib.sha256(document.encode("utf-8")).hexdigest()
    try:
        authority = M6ResolvedEmbeddingAuthority(
            scope=M6LockedEmbeddingScope.QUERY,
            channel=M6LockedEmbeddingChannel.TEXT,
            vector=vector,
            document_sha256=document_sha256,
        )
        physical_ref = derive_m6_upgrade_embedding_physical_ref(
            expected_embedding_id=vector.embedding_id,
            authority=authority,
        )
        result = M6SQLiteM5ReconstructedPrecedentQuery(
            exposure_id=exposure_metadata.exposure_id,
            hearing_session=hearing,
            cycle_scope=cycle,
            m4_query=m4_query,
            m5_query=m5_query,
            query_embedding_authority=authority,
            query_embedding_ref=physical_ref,
        )
    except (M6UpgradePhysicalResolutionError, TypeError, ValueError, ValidationError):
        _fail(M6SQLiteM5PrecedentQueryFailureCode.PHYSICAL_PLAN_INVALID)
    return result


__all__ = [
    "M6SQLiteM5CycleQueryMetadata",
    "M6SQLiteM5ExposureQueryMetadata",
    "M6SQLiteM5HearingQueryMetadata",
    "M6SQLiteM5PrecedentQueryError",
    "M6SQLiteM5PrecedentQueryFailureCode",
    "M6SQLiteM5ReconstructedPrecedentQuery",
    "M6SQLiteM5RetrievalQueryMetadata",
    "reconstruct_m6_sqlite_m5_precedent_query",
]

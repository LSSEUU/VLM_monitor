"""Pure deterministic L5 review of an already structured verdict.

The gate deliberately consumes only typed, explicit authority.  It never reads
pixels, storage, the wall clock, provider output, or model prose.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from decimal import Decimal
from typing import cast

from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.config import AlertConfig, ProceduralGateConfig
from labcourt.contracts.enums import (
    AlertLevel,
    ArtifactKind,
    EvidenceClass,
    ObjectiveFactKind,
    PrecedentApplicationMode,
    PrecedentLookupStatus,
    ProceduralDefectCode,
    ProceduralDefectOrigin,
    ProceduralField,
    ProceduralReasonCode,
    UnknownReferenceNamespace,
    UnknownReferenceSource,
    VerdictDecision,
    WearStatus,
)
from labcourt.contracts.events import ObjectiveValue
from labcourt.contracts.evidence import EvidencePack
from labcourt.contracts.m3_models import (
    PrecedentResolution,
    UnknownReferenceAttempt,
)
from labcourt.contracts.storage import ArtifactRef, ClosureReport
from labcourt.contracts.verdicts import (
    ObjectiveClaim,
    ProceduralDefect,
    ProceduralReview,
    Verdict,
)

_CITABLE_KINDS = frozenset(
    {
        ArtifactKind.CROP,
        ArtifactKind.FRAME,
        ArtifactKind.OBJECTIVE_FACT,
        ArtifactKind.TOOL_RESULT,
    }
)
_ALERT_RANK = {
    AlertLevel.ADVISORY: 0,
    AlertLevel.CONFIRMED: 1,
    AlertLevel.EMERGENCY: 2,
}


class ProceduralGateAuthorityError(ValueError):
    """Trusted L5 authority is incomplete, ambiguous, or out of scope."""


@dataclass(frozen=True, slots=True)
class ArtifactBounds:
    """Authoritative local-pixel dimensions for one citable image artifact."""

    artifact_ref: ArtifactRef
    width: int
    height: int

    def __post_init__(self) -> None:
        if self.artifact_ref.kind not in {ArtifactKind.CROP, ArtifactKind.FRAME}:
            raise ValueError("artifact bounds require a crop or frame reference")
        if (
            not isinstance(self.width, int)
            or isinstance(self.width, bool)
            or self.width <= 0
            or not isinstance(self.height, int)
            or isinstance(self.height, bool)
            or self.height <= 0
        ):
            raise ValueError("artifact bounds dimensions must be positive integers")

    @property
    def sort_key(self) -> tuple[str, str]:
        return self.artifact_ref.sort_key


@dataclass(frozen=True, slots=True)
class ProceduralGateInput:
    """Complete immutable authority required to reproduce one L5 review."""

    verdict: Verdict
    evidence_pack: EvidencePack
    current_closure: ClosureReport
    gate_config: ProceduralGateConfig
    alert_config: AlertConfig
    gate_version: str
    review_version: int = 1
    unknown_reference_attempts: tuple[UnknownReferenceAttempt, ...] = ()
    precedent_resolutions: tuple[PrecedentResolution, ...] = ()
    artifact_bounds: tuple[ArtifactBounds, ...] = ()


def review_verdict(review_input: ProceduralGateInput) -> ProceduralReview:
    """Return a stable review without modifying the verdict or its evidence pack."""

    _validate_authority(review_input)
    verdict = review_input.verdict
    pack = review_input.evidence_pack
    target = ArtifactRef(kind=ArtifactKind.VERDICT, artifact_id=verdict.verdict_id)
    allowed_refs = _allowed_evidence_refs(pack)
    dimensions = _artifact_dimensions(review_input, allowed_refs)
    defects: list[ProceduralDefect] = []

    defects.extend(
        _fabricated_reference_attempt_defects(
            review_input.unknown_reference_attempts,
            target,
        )
    )
    verdict_refs = _verdict_evidence_refs(verdict)
    defects.extend(_fabricated_typed_reference_defects(verdict_refs, allowed_refs, target))
    defects.extend(_coordinate_defects(verdict, allowed_refs, dimensions, target))
    defects.extend(_precedent_defects(review_input, target))

    if verdict.decision == VerdictDecision.ESTABLISHED and (
        not verdict.evidence_citations or not verdict.prosecution_arguments
    ):
        defects.append(
            _defect(
                code=ProceduralDefectCode.ESTABLISHED_WITHOUT_EVIDENCE,
                reason=ProceduralReasonCode.ESTABLISHED_REQUIRES_SUPPORT,
                field=ProceduralField.EVIDENCE_REFS,
                target=target,
            )
        )

    defense_ids = tuple(argument.argument_id for argument in verdict.defense_arguments)
    response_ids = tuple(response.defense_argument_id for response in verdict.judge_responses)
    if _response_cardinality_mismatch(defense_ids, response_ids):
        defects.append(
            _defect(
                code=ProceduralDefectCode.UNANSWERED_DEFENSE_POINT,
                reason=ProceduralReasonCode.DEFENSE_RESPONSE_CARDINALITY,
                field=ProceduralField.DEFENSE_ARGUMENTS,
                target=target,
                value_sha256=sha256_hex(
                    [
                        "defense-response-cardinality",
                        1,
                        sorted(defense_ids),
                        sorted(response_ids),
                    ]
                ),
            )
        )

    if _alert_policy_mismatch(verdict, review_input.alert_config):
        defects.append(
            _defect(
                code=ProceduralDefectCode.CONFIDENCE_ALERT_LEVEL_MISMATCH,
                reason=ProceduralReasonCode.ALERT_POLICY_CONFLICT,
                field=ProceduralField.RECOMMENDED_ALERT_LEVEL,
                target=target,
            )
        )

    defects.extend(
        _objective_claim_defects(
            verdict.objective_claims,
            pack,
            review_input.gate_config,
            target,
        )
    )

    if verdict.violation_type != pack.event.violation_type:
        defects.append(
            _defect(
                code=ProceduralDefectCode.VIOLATION_TYPE_MISMATCH,
                reason=ProceduralReasonCode.CASE_VIOLATION_CONFLICT,
                field=ProceduralField.VIOLATION_TYPE,
                target=target,
                related_refs=(
                    ArtifactRef(
                        kind=ArtifactKind.EVENT,
                        artifact_id=pack.event.event_id,
                    ),
                ),
            )
        )

    absence_defect = _absence_observation_defect(
        verdict,
        pack,
        review_input.gate_config,
        target,
    )
    if absence_defect is not None:
        defects.append(absence_defect)

    ordered = _stable_unique_defects(defects)
    return ProceduralReview(
        run_id=verdict.run_id,
        case_id=verdict.case_id,
        version=review_input.review_version,
        evidence_pack_id=pack.pack_id,
        evidence_pack_version=pack.version,
        reviewed_verdict_id=verdict.verdict_id,
        reviewed_verdict_version=verdict.version,
        reviewed_verdict_sha256=verdict.verdict_sha256,
        gate_version=review_input.gate_version,
        defects=ordered,
        manifest_id=verdict.manifest_id,
    )


def _validate_authority(review_input: ProceduralGateInput) -> None:
    verdict = review_input.verdict
    pack = review_input.evidence_pack
    closure = review_input.current_closure
    if (
        verdict.run_id != pack.run_id
        or verdict.case_id != pack.case_id
        or verdict.evidence_pack_id != pack.pack_id
        or verdict.evidence_pack_version != pack.version
        or verdict.manifest_id != pack.manifest_id
    ):
        raise ProceduralGateAuthorityError("procedural gate received an out-of-scope verdict")
    expected_root = ArtifactRef(
        kind=ArtifactKind.EVIDENCE_PACK,
        artifact_id=pack.pack_id,
    )
    expected_checked = {ref.sort_key: ref for ref in (*pack.expected_closure_refs(), expected_root)}
    if (
        not closure.passed
        or closure.run_id != pack.run_id
        or closure.root_ref != expected_root
        or closure.manifest_id != pack.manifest_id
        or closure.input_sha256 != pack.closure_input_sha256
        or closure.checked_refs != tuple(expected_checked[key] for key in sorted(expected_checked))
    ):
        raise ProceduralGateAuthorityError(
            "procedural gate requires the exact passing current closure"
        )
    if (
        not isinstance(review_input.review_version, int)
        or isinstance(review_input.review_version, bool)
        or review_input.review_version <= 0
    ):
        raise ProceduralGateAuthorityError("procedural review version must be a positive integer")


def _allowed_evidence_refs(pack: EvidencePack) -> frozenset[ArtifactRef]:
    return frozenset(ref for ref in pack.expected_closure_refs() if ref.kind in _CITABLE_KINDS)


def _artifact_dimensions(
    review_input: ProceduralGateInput,
    allowed_refs: frozenset[ArtifactRef],
) -> dict[ArtifactRef, tuple[int, int]]:
    pack = review_input.evidence_pack
    dimensions = {
        ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop.crop_id): (
            crop.output_width,
            crop.output_height,
        )
        for crop in pack.crops
    }
    keys = tuple(bounds.sort_key for bounds in review_input.artifact_bounds)
    if len(keys) != len(set(keys)) or keys != tuple(sorted(keys)):
        raise ProceduralGateAuthorityError("artifact bounds must be unique and use stable order")
    for bounds in review_input.artifact_bounds:
        ref = bounds.artifact_ref
        if ref not in allowed_refs:
            raise ProceduralGateAuthorityError(
                "artifact bounds reference evidence outside the current pack"
            )
        candidate = (bounds.width, bounds.height)
        if ref in dimensions and dimensions[ref] != candidate:
            raise ProceduralGateAuthorityError(
                "artifact bounds conflict with current pack dimensions"
            )
        dimensions[ref] = candidate
    return dimensions


def _verdict_evidence_refs(
    verdict: Verdict,
) -> tuple[tuple[ArtifactRef, UnknownReferenceSource | None], ...]:
    refs: list[tuple[ArtifactRef, UnknownReferenceSource | None]] = []
    refs.extend(
        (
            citation.evidence_ref,
            UnknownReferenceSource.EVIDENCE_CITATION_REF,
        )
        for citation in verdict.evidence_citations
    )
    for argument in verdict.prosecution_arguments + verdict.defense_arguments:
        refs.extend(
            (ref, UnknownReferenceSource.ARGUMENT_EVIDENCE_REF) for ref in argument.evidence_refs
        )
    for response in verdict.judge_responses:
        refs.extend(
            (ref, UnknownReferenceSource.JUDGE_RESPONSE_EVIDENCE_REF)
            for ref in response.evidence_refs
        )
    for application in verdict.precedent_applications:
        refs.extend((ref, None) for ref in application.fact_difference_refs)
    for entry in verdict.acquisition_log:
        if entry.tool_result_ref is not None:
            refs.append((entry.tool_result_ref, None))
    refs.extend(
        (
            claim.evidence_ref,
            UnknownReferenceSource.OBJECTIVE_CLAIM_EVIDENCE_REF,
        )
        for claim in verdict.objective_claims
    )
    if verdict.observation_sufficiency is not None:
        refs.extend(
            (
                ArtifactRef(
                    kind=ArtifactKind.CROP,
                    artifact_id=observation.crop_id,
                ),
                UnknownReferenceSource.FRAME_OBSERVATION_CROP_ID,
            )
            for observation in verdict.observation_sufficiency.observations
        )
    return tuple(refs)


def _fabricated_reference_attempt_defects(
    attempts: tuple[UnknownReferenceAttempt, ...],
    target: ArtifactRef,
) -> tuple[ProceduralDefect, ...]:
    defects = []
    for attempt in attempts:
        if attempt.namespace == UnknownReferenceNamespace.EVIDENCE:
            defects.append(
                _defect(
                    code=ProceduralDefectCode.FABRICATED_EVIDENCE_REFERENCE,
                    reason=ProceduralReasonCode.REFERENCE_NOT_ALLOWED,
                    field=ProceduralField.EVIDENCE_REFERENCE,
                    target=target,
                    value_sha256=attempt.value_sha256,
                )
            )
        else:
            defects.append(
                _defect(
                    code=ProceduralDefectCode.FABRICATED_PRECEDENT_REFERENCE,
                    reason=ProceduralReasonCode.PRECEDENT_NOT_VISIBLE,
                    field=ProceduralField.PRECEDENT_REFERENCE,
                    target=target,
                    value_sha256=attempt.value_sha256,
                )
            )
    return tuple(defects)


def _fabricated_typed_reference_defects(
    refs: tuple[tuple[ArtifactRef, UnknownReferenceSource | None], ...],
    allowed_refs: frozenset[ArtifactRef],
    target: ArtifactRef,
) -> tuple[ProceduralDefect, ...]:
    return tuple(
        _defect(
            code=ProceduralDefectCode.FABRICATED_EVIDENCE_REFERENCE,
            reason=ProceduralReasonCode.REFERENCE_NOT_ALLOWED,
            field=ProceduralField.EVIDENCE_REFERENCE,
            target=target,
            value_sha256=_evidence_reference_value_hash(ref, source),
        )
        for ref, source in refs
        if ref not in allowed_refs
    )


def _coordinate_defects(
    verdict: Verdict,
    allowed_refs: frozenset[ArtifactRef],
    dimensions: dict[ArtifactRef, tuple[int, int]],
    target: ArtifactRef,
) -> tuple[ProceduralDefect, ...]:
    defects = []
    for citation in verdict.evidence_citations:
        bbox = citation.bbox
        ref = citation.evidence_ref
        if bbox is None or ref not in allowed_refs:
            continue
        bounds = dimensions.get(ref)
        if bounds is None or not bbox.is_within(*bounds):
            defects.append(
                _defect(
                    code=ProceduralDefectCode.INVALID_COORDINATES,
                    reason=ProceduralReasonCode.COORDINATE_OUTSIDE_EVIDENCE,
                    field=ProceduralField.EVIDENCE_COORDINATES,
                    target=target,
                    related_refs=(ref,),
                )
            )
    return tuple(defects)


def _precedent_defects(
    review_input: ProceduralGateInput,
    target: ArtifactRef,
) -> tuple[ProceduralDefect, ...]:
    verdict = review_input.verdict
    pack = review_input.evidence_pack
    defects: list[ProceduralDefect] = []
    applied_ids = {
        application.precedent_ref.artifact_id for application in verdict.precedent_applications
    }
    for resolution in review_input.precedent_resolutions:
        if (
            _resolution_matches_scope(
                resolution,
                resolution.query.precedent_id,
                verdict,
                pack,
            )
            and resolution.status == PrecedentLookupStatus.FOUND
            and resolution.authoritative_similarity is not None
            and resolution.authoritative_similarity
            >= review_input.gate_config.precedent_similarity_min
            and resolution.query.precedent_id not in applied_ids
        ):
            # The frozen L5 taxonomy has no separate "unaddressed precedent"
            # code.  A visible precedent that was not followed still requires
            # an explicit distinction, so its complete omission is represented
            # by the existing EMPTY_DISTINGUISHING_REASON gate defect.
            defects.append(
                _defect(
                    code=ProceduralDefectCode.EMPTY_DISTINGUISHING_REASON,
                    reason=ProceduralReasonCode.DISTINGUISHING_REASON_ABSENT,
                    field=ProceduralField.DISTINGUISHING_REASON,
                    target=target,
                    related_refs=(
                        ArtifactRef(
                            kind=ArtifactKind.PRECEDENT,
                            artifact_id=resolution.query.precedent_id,
                        ),
                    ),
                )
            )
    for application in verdict.precedent_applications:
        precedent_ref = application.precedent_ref
        matches = tuple(
            resolution
            for resolution in review_input.precedent_resolutions
            if _resolution_matches_scope(
                resolution,
                precedent_ref.artifact_id,
                verdict,
                pack,
            )
        )
        if (
            len(matches) != 1
            or matches[0].status != PrecedentLookupStatus.FOUND
            or matches[0].authoritative_similarity is None
            or matches[0].authoritative_similarity
            < review_input.gate_config.precedent_similarity_min
        ):
            defects.append(
                _defect(
                    code=ProceduralDefectCode.FABRICATED_PRECEDENT_REFERENCE,
                    reason=ProceduralReasonCode.PRECEDENT_NOT_VISIBLE,
                    field=ProceduralField.PRECEDENT_REFERENCE,
                    target=target,
                    value_sha256=_reference_value_hash(precedent_ref),
                )
            )
            continue

        snapshot = matches[0].snapshot
        assert snapshot is not None
        if (
            application.mode == PrecedentApplicationMode.FOLLOWED
            and snapshot.decision_direction != verdict.decision
        ):
            defects.append(
                _defect(
                    code=ProceduralDefectCode.PRECEDENT_DIRECTION_MISMATCH,
                    reason=ProceduralReasonCode.PRECEDENT_DIRECTION_CONFLICT,
                    field=ProceduralField.PRECEDENT_MODE,
                    target=target,
                    related_refs=(precedent_ref,),
                )
            )
        if application.mode == PrecedentApplicationMode.DISTINGUISHED and (
            application.distinguishing_reason is None or not application.fact_difference_refs
        ):
            related = tuple(
                sorted(
                    (precedent_ref, *application.fact_difference_refs),
                    key=lambda ref: ref.sort_key,
                )
            )
            defects.append(
                _defect(
                    code=ProceduralDefectCode.EMPTY_DISTINGUISHING_REASON,
                    reason=ProceduralReasonCode.DISTINGUISHING_REASON_ABSENT,
                    field=ProceduralField.DISTINGUISHING_REASON,
                    target=target,
                    related_refs=related,
                )
            )
    return tuple(defects)


def _resolution_matches_scope(
    resolution: PrecedentResolution,
    precedent_id: str,
    verdict: Verdict,
    pack: EvidencePack,
) -> bool:
    query = resolution.query
    return (
        query.run_id,
        query.case_id,
        query.precedent_id,
        query.rule_version,
        query.evidence_class,
        query.violation_type,
        query.manifest_id,
    ) == (
        verdict.run_id,
        verdict.case_id,
        precedent_id,
        pack.event.rule_version,
        pack.event.evidence_class,
        pack.event.violation_type,
        pack.manifest_id,
    )


def _response_cardinality_mismatch(
    defense_ids: tuple[str, ...],
    response_ids: tuple[str, ...],
) -> bool:
    return Counter(response_ids) != Counter({defense_id: 1 for defense_id in defense_ids})


def _alert_policy_mismatch(verdict: Verdict, config: AlertConfig) -> bool:
    above_insufficient_ceiling = (
        verdict.decision == VerdictDecision.INSUFFICIENT_EVIDENCE
        and _ALERT_RANK[verdict.recommended_alert_level]
        > _ALERT_RANK[config.insufficient_evidence_max_level]
    )
    low_confidence_confirmed = (
        verdict.recommended_alert_level in {AlertLevel.CONFIRMED, AlertLevel.EMERGENCY}
        and verdict.confidence < config.confirmed_min_confidence
    )
    return above_insufficient_ceiling or low_confidence_confirmed


def _objective_claim_defects(
    claims: tuple[ObjectiveClaim, ...],
    pack: EvidencePack,
    config: ProceduralGateConfig,
    target: ArtifactRef,
) -> tuple[ProceduralDefect, ...]:
    facts = {fact.fact_id: fact for fact in pack.objective_facts}
    defects = []
    for claim in claims:
        fact = facts.get(claim.evidence_ref.artifact_id)
        if fact is None:
            continue
        if fact.kind != claim.kind or not _objective_values_match(
            claim.kind,
            claim.value,
            fact.value,
            config,
        ):
            defects.append(
                _defect(
                    code=ProceduralDefectCode.OBJECTIVE_ASSERTION_CONTRADICTION,
                    reason=ProceduralReasonCode.OBJECTIVE_VALUE_CONFLICT,
                    field=ProceduralField.OBJECTIVE_CLAIMS,
                    target=target,
                    related_refs=(claim.evidence_ref,),
                )
            )
    return tuple(defects)


def _objective_values_match(
    kind: ObjectiveFactKind,
    claimed: ObjectiveValue,
    authoritative: ObjectiveValue,
    config: ProceduralGateConfig,
) -> bool:
    tolerance = config.objective_numeric_tolerance
    if kind == ObjectiveFactKind.DURATION_FRAMES:
        return abs(cast(int, claimed) - cast(int, authoritative)) <= tolerance.duration_frames
    if kind == ObjectiveFactKind.PERSON_COUNT:
        return abs(cast(int, claimed) - cast(int, authoritative)) <= tolerance.person_count
    if kind == ObjectiveFactKind.FRAME_INTERVAL:
        return _interval_within_tolerance(
            claimed,
            authoritative,
            tolerance.frame_interval_frames,
        )
    if kind == ObjectiveFactKind.TRACK_PRESENCE_INTERVAL:
        return _interval_within_tolerance(
            claimed,
            authoritative,
            tolerance.track_presence_interval_frames,
        )
    if kind == ObjectiveFactKind.DETECTION_SCORE:
        return _decimal_delta_within(
            cast(int | float, claimed),
            cast(int | float, authoritative),
            tolerance.detection_score,
        )
    if kind == ObjectiveFactKind.OBSERVABILITY:
        return _decimal_delta_within(
            cast(int | float, claimed),
            cast(int | float, authoritative),
            tolerance.observability,
        )
    return claimed == authoritative


def _interval_within_tolerance(
    claimed: ObjectiveValue,
    authoritative: ObjectiveValue,
    tolerance: int,
) -> bool:
    claimed_interval = cast(tuple[int, int], claimed)
    authoritative_interval = cast(tuple[int, int], authoritative)
    return all(
        abs(int(claimed_value) - int(authoritative_value)) <= tolerance
        for claimed_value, authoritative_value in zip(
            claimed_interval,
            authoritative_interval,
            strict=True,
        )
    )


def _decimal_delta_within(
    claimed: int | float,
    authoritative: int | float,
    tolerance: float,
) -> bool:
    return abs(Decimal(str(claimed)) - Decimal(str(authoritative))) <= Decimal(str(tolerance))


def _absence_observation_defect(
    verdict: Verdict,
    pack: EvidencePack,
    config: ProceduralGateConfig,
    target: ArtifactRef,
) -> ProceduralDefect | None:
    if (
        pack.event.evidence_class != EvidenceClass.ABSENCE
        or verdict.decision != VerdictDecision.ESTABLISHED
    ):
        return None
    authority = pack.observation_sufficiency_input
    observed = verdict.observation_sufficiency
    assert authority is not None
    invalid = observed is None
    clear_ids = authority.clear_crop_ids
    if observed is not None:
        labels = {
            observation.crop_id: observation.wear_status for observation in observed.observations
        }
        invalid = (
            authority.clear_threshold != config.absence_clear_frame_threshold
            or authority.required_clear_count != config.minimum_absence_clear_frames
            or observed.clear_threshold != authority.clear_threshold
            or observed.required_clear_count != authority.required_clear_count
            or len(clear_ids) < authority.required_clear_count
            or any(labels.get(crop_id) != WearStatus.NOT_WORN for crop_id in clear_ids)
        )
    if not invalid:
        return None
    related_refs = tuple(
        sorted(
            (ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop_id) for crop_id in clear_ids),
            key=lambda ref: ref.sort_key,
        )
    )
    return _defect(
        code=ProceduralDefectCode.ABSENCE_FROM_INSUFFICIENT_OBSERVATION,
        reason=ProceduralReasonCode.ABSENCE_OBSERVATION_INSUFFICIENT,
        field=ProceduralField.OBSERVATION_SUFFICIENCY,
        target=target,
        related_refs=related_refs,
    )


def _reference_value_hash(ref: ArtifactRef) -> str:
    return sha256_hex(
        [
            "procedural-reference-value",
            1,
            ref.model_dump(mode="json"),
        ]
    )


def _evidence_reference_value_hash(
    ref: ArtifactRef,
    source: UnknownReferenceSource | None,
) -> str:
    if source is None:
        return _reference_value_hash(ref)
    raw_value: object = (
        ref.artifact_id
        if source == UnknownReferenceSource.FRAME_OBSERVATION_CROP_ID
        else ref.model_dump(mode="json")
    )
    return sha256_hex(
        [
            "unknown-model-reference",
            1,
            UnknownReferenceNamespace.EVIDENCE.value,
            source.value,
            raw_value,
        ]
    )


def _defect(
    *,
    code: ProceduralDefectCode,
    reason: ProceduralReasonCode,
    field: ProceduralField,
    target: ArtifactRef,
    related_refs: tuple[ArtifactRef, ...] = (),
    value_sha256: str | None = None,
) -> ProceduralDefect:
    return ProceduralDefect(
        code=code,
        origin=ProceduralDefectOrigin.PROCEDURAL_GATE,
        reason_code=reason,
        artifact_ref=target,
        field=field,
        related_refs=related_refs,
        value_sha256=value_sha256,
    )


def _stable_unique_defects(
    defects: Iterable[ProceduralDefect],
) -> tuple[ProceduralDefect, ...]:
    by_id = {defect.defect_id: defect for defect in defects}
    return tuple(sorted(by_id.values(), key=lambda defect: defect.sort_key))


__all__ = [
    "ArtifactBounds",
    "ProceduralGateAuthorityError",
    "ProceduralGateInput",
    "review_verdict",
]

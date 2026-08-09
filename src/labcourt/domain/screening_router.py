"""Pure M3 screening routing and deterministic fast-verdict construction.

The model payload is a proposal.  Routing authority comes from the current
``EvidencePack``: its evidence class, L1 score, alleged temporal crops,
observability-derived clear crops, and causal correction context.  This module
does no I/O and deliberately leaves semantic mismatches intact for L5 review.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from math import isfinite

from labcourt.contracts.enums import (
    AlertLevel,
    ArgumentStance,
    ArtifactKind,
    EvidenceClass,
    ScreeningDecision,
    VerdictDecision,
)
from labcourt.contracts.evidence import EvidencePack
from labcourt.contracts.m3_models import EvidenceCitation
from labcourt.contracts.references import require_reference_token
from labcourt.contracts.screening import ParsedScreeningOutput, ScreeningResult
from labcourt.contracts.storage import ArtifactRef
from labcourt.contracts.verdicts import (
    Argument,
    ObservationLabel,
    ObservationSufficiency,
    Verdict,
)

DEFAULT_ROUTER_VERSION = "screening-router-v1"
DEFAULT_CONFLICT_POLICY_VERSION = "strong-signal-v1"


class ScreeningRouteError(ValueError):
    """The supplied typed authorities cannot produce the requested pure result."""


def _require_probability(value: float, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be a real number")
    if not isfinite(value) or not 0 <= value <= 1:
        raise ValueError(f"{name} must be between zero and one")


def _require_positive_version(value: int, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True, slots=True)
class ScreeningRoutePolicy:
    """Versioned deterministic thresholds used to reproduce one route."""

    low_probability: float
    high_probability: float
    strong_signal_threshold: float
    router_version: str = DEFAULT_ROUTER_VERSION
    conflict_policy_version: str = DEFAULT_CONFLICT_POLICY_VERSION

    def __post_init__(self) -> None:
        _require_probability(self.low_probability, "low_probability")
        _require_probability(self.high_probability, "high_probability")
        _require_probability(self.strong_signal_threshold, "strong_signal_threshold")
        if self.low_probability >= self.high_probability:
            raise ValueError("low_probability must be below high_probability")
        require_reference_token(self.router_version, "screening router version")
        require_reference_token(
            self.conflict_policy_version,
            "screening conflict policy version",
        )


@dataclass(frozen=True, slots=True)
class FastVerdictPolicy:
    """Safe recommendations emitted before the later alert-policy milestone."""

    established_alert_level: AlertLevel = AlertLevel.CONFIRMED
    not_established_alert_level: AlertLevel = AlertLevel.ADVISORY

    def __post_init__(self) -> None:
        if not isinstance(self.established_alert_level, AlertLevel):
            raise TypeError("established_alert_level must be an AlertLevel")
        if not isinstance(self.not_established_alert_level, AlertLevel):
            raise TypeError("not_established_alert_level must be an AlertLevel")


def _validate_parsed_pack_scope(
    parsed_output: ParsedScreeningOutput,
    evidence_pack: EvidencePack,
) -> None:
    if not evidence_pack.complete:
        raise ScreeningRouteError("screening requires a complete evidence pack")
    if (
        parsed_output.run_id != evidence_pack.run_id
        or parsed_output.case_id != evidence_pack.case_id
        or parsed_output.evidence_pack_id != evidence_pack.pack_id
        or parsed_output.evidence_pack_version != evidence_pack.version
        or parsed_output.manifest_id != evidence_pack.manifest_id
    ):
        raise ScreeningRouteError("parsed screening output is outside the evidence-pack scope")


def route_screening(
    parsed_output: ParsedScreeningOutput,
    evidence_pack: EvidencePack,
    policy: ScreeningRoutePolicy,
    *,
    version: int = 1,
) -> ScreeningResult:
    """Route one strictly parsed output using only pack-authoritative inputs."""

    if not isinstance(policy, ScreeningRoutePolicy):
        raise TypeError("policy must be a ScreeningRoutePolicy")
    _require_positive_version(version, "screening result version")
    _validate_parsed_pack_scope(parsed_output, evidence_pack)

    alleged_crop_ids: tuple[str, ...] = ()
    clear_crop_ids: tuple[str, ...] = ()
    correction_frame_ids: tuple[str, ...] = ()
    required_clear_count: int | None = None

    if evidence_pack.event.evidence_class == EvidenceClass.ABSENCE:
        authority = evidence_pack.observation_sufficiency_input
        if authority is None:
            raise ScreeningRouteError("absence screening requires observation authority")
        alleged_crop_ids = tuple(sorted(crop.crop_id for crop in evidence_pack.temporal_crops))
        if not alleged_crop_ids:
            raise ScreeningRouteError("absence screening requires alleged-interval crops")
        clear_crop_ids = tuple(sorted(authority.clear_crop_ids))
        required_clear_count = authority.required_clear_count
        recovery_frame = evidence_pack.confirmation_record.post_threshold_recovery_frame_id
        correction_frame_ids = (recovery_frame,) if recovery_frame is not None else ()

    return ScreeningResult(
        run_id=evidence_pack.run_id,
        case_id=evidence_pack.case_id,
        version=version,
        evidence_pack_id=evidence_pack.pack_id,
        evidence_pack_version=evidence_pack.version,
        parsed_output=parsed_output,
        low_probability=policy.low_probability,
        high_probability=policy.high_probability,
        authoritative_evidence_class=evidence_pack.event.evidence_class,
        authoritative_l1_score=evidence_pack.event.l1_score,
        strong_signal_threshold=policy.strong_signal_threshold,
        conflict_policy_version=policy.conflict_policy_version,
        alleged_interval_crop_ids=alleged_crop_ids,
        authoritative_clear_crop_ids=clear_crop_ids,
        correction_frame_ids=correction_frame_ids,
        required_clear_count=required_clear_count,
        router_version=policy.router_version,
        manifest_id=evidence_pack.manifest_id,
    )


@dataclass(frozen=True, slots=True)
class ScreeningRouter:
    """Small immutable façade for dependency-injected routing policy."""

    policy: ScreeningRoutePolicy

    def __post_init__(self) -> None:
        if not isinstance(self.policy, ScreeningRoutePolicy):
            raise TypeError("policy must be a ScreeningRoutePolicy")

    def route(
        self,
        parsed_output: ParsedScreeningOutput,
        evidence_pack: EvidencePack,
        *,
        version: int = 1,
    ) -> ScreeningResult:
        return route_screening(
            parsed_output,
            evidence_pack,
            self.policy,
            version=version,
        )


def _expected_absence_authority(
    evidence_pack: EvidencePack,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], int | None]:
    if evidence_pack.event.evidence_class != EvidenceClass.ABSENCE:
        return (), (), (), None
    authority = evidence_pack.observation_sufficiency_input
    if authority is None:
        raise ScreeningRouteError("absence verdict requires observation authority")
    recovery_frame = evidence_pack.confirmation_record.post_threshold_recovery_frame_id
    return (
        tuple(sorted(crop.crop_id for crop in evidence_pack.temporal_crops)),
        tuple(sorted(authority.clear_crop_ids)),
        (recovery_frame,) if recovery_frame is not None else (),
        authority.required_clear_count,
    )


def _validate_screening_pack_scope(
    screening_result: ScreeningResult,
    evidence_pack: EvidencePack,
) -> None:
    if not evidence_pack.complete:
        raise ScreeningRouteError("fast verdict requires a complete evidence pack")
    if (
        screening_result.run_id != evidence_pack.run_id
        or screening_result.case_id != evidence_pack.case_id
        or screening_result.evidence_pack_id != evidence_pack.pack_id
        or screening_result.evidence_pack_version != evidence_pack.version
        or screening_result.manifest_id != evidence_pack.manifest_id
    ):
        raise ScreeningRouteError("screening result is outside the evidence-pack scope")
    if (
        screening_result.authoritative_evidence_class != evidence_pack.event.evidence_class
        or screening_result.authoritative_l1_score != evidence_pack.event.l1_score
    ):
        raise ScreeningRouteError("screening authority conflicts with its evidence pack")

    alleged, clear, correction, required = _expected_absence_authority(evidence_pack)
    if (
        screening_result.alleged_interval_crop_ids != alleged
        or screening_result.authoritative_clear_crop_ids != clear
        or screening_result.correction_frame_ids != correction
        or screening_result.required_clear_count != required
    ):
        raise ScreeningRouteError("screening absence authority conflicts with its evidence pack")


def _verdict_citations(
    screening_result: ScreeningResult,
) -> tuple[EvidenceCitation, ...]:
    """Add exact crop citations for typed observations not already cited.

    The model still authors each observation and its crop ID.  LabCourt only
    converts that strictly parsed, allowlist-checked reference into the formal
    no-coordinate citation required by the procedural gate.  It never infers a
    reference from prose or treats the model as evidence-existence authority.
    """

    citations = list(screening_result.parsed_output.evidence_citations)
    cited_refs = {citation.evidence_ref.sort_key for citation in citations}
    for observation in screening_result.parsed_output.frame_observations:
        evidence_ref = ArtifactRef(kind=ArtifactKind.CROP, artifact_id=observation.crop_id)
        if evidence_ref.sort_key in cited_refs:
            continue
        citations.append(EvidenceCitation(evidence_ref=evidence_ref))
        cited_refs.add(evidence_ref.sort_key)
    return tuple(sorted(citations, key=lambda citation: citation.sort_key))


def _stable_citation_refs(
    citations: tuple[EvidenceCitation, ...],
) -> tuple[ArtifactRef, ...]:
    refs = {citation.evidence_ref.sort_key: citation.evidence_ref for citation in citations}
    return tuple(refs[key] for key in sorted(refs))


def _observation_sufficiency(
    screening_result: ScreeningResult,
    evidence_pack: EvidencePack,
) -> ObservationSufficiency | None:
    if evidence_pack.event.evidence_class != EvidenceClass.ABSENCE:
        return None
    authority = evidence_pack.observation_sufficiency_input
    if authority is None:
        raise ScreeningRouteError("absence verdict requires observation authority")
    observations = tuple(
        ObservationLabel(
            crop_id=observation.crop_id,
            wear_status=observation.wear_status,
        )
        for observation in screening_result.parsed_output.frame_observations
    )
    return ObservationSufficiency(
        clear_threshold=authority.clear_threshold,
        required_clear_count=authority.required_clear_count,
        observations=observations,
    )


def _model_response_refs(
    screening_result: ScreeningResult,
    supplied: tuple[ArtifactRef, ...] | None,
) -> tuple[ArtifactRef, ...]:
    final_ref = ArtifactRef(
        kind=ArtifactKind.MODEL_RESPONSE,
        artifact_id=screening_result.parsed_output.response_id,
    )
    if supplied is None:
        return (final_ref,)
    keys = tuple(ref.sort_key for ref in supplied)
    if (
        not supplied
        or any(ref.kind != ArtifactKind.MODEL_RESPONSE for ref in supplied)
        or len(keys) != len(set(keys))
        or keys != tuple(sorted(keys))
        or final_ref not in supplied
    ):
        raise ScreeningRouteError(
            "model response refs must be unique, stable, and include the parsed response"
        )
    return supplied


def build_fast_verdict(
    screening_result: ScreeningResult,
    evidence_pack: EvidencePack,
    policy: FastVerdictPolicy | None = None,
    *,
    version: int = 1,
    model_response_refs: tuple[ArtifactRef, ...] | None = None,
) -> Verdict:
    """Build a complete verdict for a final screening route.

    ``ESCALATE`` has no fast-verdict meaning and is rejected.  Unknown citations
    and a model-authored violation-type mismatch are intentionally preserved so
    the deterministic procedural gate can record them rather than silently
    correcting the proposal.
    """

    if policy is not None and not isinstance(policy, FastVerdictPolicy):
        raise TypeError("policy must be a FastVerdictPolicy")
    _require_positive_version(version, "verdict version")
    _validate_screening_pack_scope(screening_result, evidence_pack)
    if screening_result.decision == ScreeningDecision.ESCALATE:
        raise ScreeningRouteError("an escalated screening cannot produce a fast verdict")

    verdict_policy = policy or FastVerdictPolicy()
    citations = _verdict_citations(screening_result)
    citation_refs = _stable_citation_refs(citations)

    if screening_result.decision == ScreeningDecision.ESTABLISHED:
        decision = VerdictDecision.ESTABLISHED
        confidence = screening_result.parsed_output.violation_probability
        recommended_alert = verdict_policy.established_alert_level
    else:
        decision = VerdictDecision.NOT_ESTABLISHED
        confidence = 1.0 - screening_result.parsed_output.violation_probability
        recommended_alert = verdict_policy.not_established_alert_level

    prosecution_argument = Argument(
        stance=ArgumentStance.PROSECUTION,
        claim=screening_result.parsed_output.prosecution_summary,
        evidence_refs=citation_refs,
        uncertainty=1.0 - confidence,
    )

    return Verdict(
        run_id=screening_result.run_id,
        case_id=screening_result.case_id,
        version=version,
        screening_id=screening_result.screening_id,
        # Preserve the model proposal; L5, not this builder, owns mismatch review.
        violation_type=screening_result.parsed_output.violation_type,
        evidence_pack_id=screening_result.evidence_pack_id,
        evidence_pack_version=screening_result.evidence_pack_version,
        decision=decision,
        confidence=confidence,
        recommended_alert_level=recommended_alert,
        rationale_summary=screening_result.parsed_output.rationale_summary,
        evidence_citations=citations,
        prosecution_arguments=(prosecution_argument,),
        defense_arguments=(),
        judge_responses=(),
        precedent_applications=(),
        acquisition_log=(),
        objective_claims=screening_result.parsed_output.objective_claims,
        observation_sufficiency=_observation_sufficiency(
            screening_result,
            evidence_pack,
        ),
        model_response_refs=_model_response_refs(
            screening_result,
            model_response_refs,
        ),
        manifest_id=screening_result.manifest_id,
    )


@dataclass(frozen=True, slots=True)
class FastVerdictBuilder:
    """Immutable façade for deterministic fast-verdict policy."""

    policy: FastVerdictPolicy = field(default_factory=FastVerdictPolicy)

    def __post_init__(self) -> None:
        if not isinstance(self.policy, FastVerdictPolicy):
            raise TypeError("policy must be a FastVerdictPolicy")

    def build(
        self,
        screening_result: ScreeningResult,
        evidence_pack: EvidencePack,
        *,
        version: int = 1,
        model_response_refs: tuple[ArtifactRef, ...] | None = None,
    ) -> Verdict:
        return build_fast_verdict(
            screening_result,
            evidence_pack,
            self.policy,
            version=version,
            model_response_refs=model_response_refs,
        )


__all__ = [
    "DEFAULT_CONFLICT_POLICY_VERSION",
    "DEFAULT_ROUTER_VERSION",
    "FastVerdictBuilder",
    "FastVerdictPolicy",
    "ScreeningRouteError",
    "ScreeningRoutePolicy",
    "ScreeningRouter",
    "build_fast_verdict",
    "route_screening",
]

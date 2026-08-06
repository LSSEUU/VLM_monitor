"""Typed, replayable inputs for the M6 procedural Gate projection.

The persisted ``ProceduralReview`` is an output and therefore cannot be the
candidate Gate authority.  This module keeps the complete deterministic Gate
input together and rebuilds the review through the frozen L5 pure function.
Operational source-review identities are retained only to prove coverage; they
never supply defects or ``passed`` to the rebuilt result.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.config import AlertConfig, ProceduralGateConfig
from labcourt.contracts.enums import PrecedentLookupStatus
from labcourt.contracts.evidence import EvidencePack
from labcourt.contracts.hearing_state import (
    HearingPrecedentRetrievalReceipt,
    HearingPrecedentRetrievalStatus,
)
from labcourt.contracts.m3_models import (
    PrecedentLookupQuery,
    PrecedentResolution,
    UnknownReferenceAttempt,
)
from labcourt.contracts.references import require_reference_token
from labcourt.contracts.storage import ClosureReport
from labcourt.contracts.verdicts import ProceduralReview, Verdict
from labcourt.domain.procedural_gate import (
    ArtifactBounds,
    ProceduralGateInput,
    review_verdict,
)


def _require_sha256(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return value


def _canonical_model(value: object, model_type: type[object], label: str) -> object:
    if not isinstance(value, model_type):
        raise TypeError(f"{label} must be a {model_type.__name__}")
    model_dump = getattr(value, "model_dump", None)
    model_validate = getattr(model_type, "model_validate", None)
    if not callable(model_dump) or not callable(model_validate):
        raise TypeError(f"{label} must be a canonical contract")
    canonical = model_validate(model_dump(mode="json", exclude_computed_fields=True))
    if canonical != value:
        raise ValueError(f"{label} is not canonical")
    return canonical


def _document_sha256(value: object) -> str:
    model_dump = getattr(value, "model_dump", None)
    if not callable(model_dump):
        raise TypeError("M6 Gate source document must be a typed contract")
    return hashlib.sha256(canonical_json(model_dump(mode="json")).encode("utf-8")).hexdigest()


def build_m6_gate_precedent_resolutions(
    *,
    evidence_pack: EvidencePack,
    receipt: HearingPrecedentRetrievalReceipt,
) -> tuple[PrecedentResolution, ...]:
    """Project one exact M4 terminal retrieval receipt into frozen Gate inputs."""

    pack = _canonical_model(evidence_pack, EvidencePack, "M6 Gate evidence pack")
    controlled_receipt = _canonical_model(
        receipt,
        HearingPrecedentRetrievalReceipt,
        "M6 Gate retrieval receipt",
    )
    assert isinstance(pack, EvidencePack)
    assert isinstance(controlled_receipt, HearingPrecedentRetrievalReceipt)
    if (
        controlled_receipt.run_id != pack.run_id
        or controlled_receipt.case_id != pack.case_id
        or controlled_receipt.manifest_id != pack.manifest_id
        or controlled_receipt.current_evidence_pack_id != pack.pack_id
        or controlled_receipt.current_evidence_pack_version != pack.version
        or controlled_receipt.evidence_class != pack.event.evidence_class
        or controlled_receipt.violation_type != pack.event.violation_type
    ):
        raise ValueError("M6 Gate retrieval receipt differs from its evidence pack scope")
    if controlled_receipt.status == HearingPrecedentRetrievalStatus.DEGRADED:
        return ()
    if controlled_receipt.status != HearingPrecedentRetrievalStatus.SUCCESS:
        raise ValueError("M6 Gate retrieval receipt has an unsupported status")
    resolutions = tuple(
        PrecedentResolution(
            query=PrecedentLookupQuery(
                run_id=pack.run_id,
                case_id=pack.case_id,
                precedent_id=scored.precedent.precedent_id,
                rule_version=controlled_receipt.rule_version,
                evidence_class=pack.event.evidence_class,
                violation_type=pack.event.violation_type,
                manifest_id=pack.manifest_id,
            ),
            status=PrecedentLookupStatus.FOUND,
            snapshot=scored.precedent,
            authoritative_similarity=max(-1.0, min(1.0, float(scored.fused_score))),
            lookup_version=controlled_receipt.retriever_version,
        )
        for scored in controlled_receipt.scored_precedents
    )
    return tuple(
        sorted(
            resolutions,
            key=lambda item: (item.query.precedent_id, item.receipt_id),
        )
    )


@dataclass(frozen=True, slots=True)
class M6ProceduralGateExecutionInput:
    """One exact Gate invocation, independent of its persisted output."""

    source_review_id: str
    source_review_document_sha256: str
    verdict: Verdict
    evidence_pack: EvidencePack
    current_closure: ClosureReport
    gate_config: ProceduralGateConfig
    alert_config: AlertConfig
    review_version: int
    unknown_reference_attempts: tuple[UnknownReferenceAttempt, ...] = ()
    precedent_resolutions: tuple[PrecedentResolution, ...] = ()
    artifact_bounds: tuple[ArtifactBounds, ...] = ()

    def __post_init__(self) -> None:
        require_reference_token(self.source_review_id, "M6 Gate source review ID")
        _require_sha256(
            self.source_review_document_sha256,
            "M6 Gate source review document",
        )
        verdict = _canonical_model(self.verdict, Verdict, "M6 Gate verdict")
        pack = _canonical_model(self.evidence_pack, EvidencePack, "M6 Gate evidence pack")
        closure = _canonical_model(
            self.current_closure,
            ClosureReport,
            "M6 Gate current closure",
        )
        gate_config = _canonical_model(
            self.gate_config,
            ProceduralGateConfig,
            "M6 Gate configuration",
        )
        alert_config = _canonical_model(
            self.alert_config,
            AlertConfig,
            "M6 alert configuration",
        )
        assert isinstance(verdict, Verdict)
        assert isinstance(pack, EvidencePack)
        assert isinstance(closure, ClosureReport)
        assert isinstance(gate_config, ProceduralGateConfig)
        assert isinstance(alert_config, AlertConfig)
        if (
            not isinstance(self.review_version, int)
            or isinstance(self.review_version, bool)
            or self.review_version <= 0
        ):
            raise ValueError("M6 Gate review_version must be positive")
        if not isinstance(self.unknown_reference_attempts, tuple) or any(
            not isinstance(item, UnknownReferenceAttempt)
            for item in self.unknown_reference_attempts
        ):
            raise TypeError("M6 Gate unknown-reference attempts must be a typed tuple")
        attempts = tuple(
            UnknownReferenceAttempt.model_validate(
                item.model_dump(mode="json", exclude_computed_fields=True)
            )
            for item in self.unknown_reference_attempts
        )
        attempt_keys = tuple(item.sort_key for item in attempts)
        if attempt_keys != tuple(sorted(attempt_keys)) or len(attempt_keys) != len(
            set(attempt_keys)
        ):
            raise ValueError("M6 Gate unknown-reference attempts must be unique and ordered")
        if not isinstance(self.precedent_resolutions, tuple) or any(
            not isinstance(item, PrecedentResolution) for item in self.precedent_resolutions
        ):
            raise TypeError("M6 Gate precedent resolutions must be a typed tuple")
        resolutions = tuple(
            PrecedentResolution.model_validate(
                item.model_dump(mode="json", exclude_computed_fields=True)
            )
            for item in self.precedent_resolutions
        )
        resolution_ids = tuple(item.query.precedent_id for item in resolutions)
        if resolution_ids != tuple(sorted(resolution_ids)) or len(resolution_ids) != len(
            set(resolution_ids)
        ):
            raise ValueError("M6 Gate precedent resolutions must be unique and ordered")
        if not isinstance(self.artifact_bounds, tuple) or any(
            not isinstance(item, ArtifactBounds) for item in self.artifact_bounds
        ):
            raise TypeError("M6 Gate artifact bounds must be a typed tuple")
        bounds = tuple(
            ArtifactBounds(
                artifact_ref=item.artifact_ref,
                width=item.width,
                height=item.height,
            )
            for item in self.artifact_bounds
        )
        bound_keys = tuple(item.sort_key for item in bounds)
        if bound_keys != tuple(sorted(bound_keys)) or len(bound_keys) != len(set(bound_keys)):
            raise ValueError("M6 Gate artifact bounds must be unique and ordered")
        object.__setattr__(self, "verdict", verdict)
        object.__setattr__(self, "evidence_pack", pack)
        object.__setattr__(self, "current_closure", closure)
        object.__setattr__(self, "gate_config", gate_config)
        object.__setattr__(self, "alert_config", alert_config)
        object.__setattr__(self, "unknown_reference_attempts", attempts)
        object.__setattr__(self, "precedent_resolutions", resolutions)
        object.__setattr__(self, "artifact_bounds", bounds)
        # Validate the complete authority now; callers cannot carry an input
        # that only fails when the semantic projection is attempted later.
        self.rebuild_review()

    @property
    def sort_key(self) -> tuple[int, int, str]:
        return self.review_version, self.verdict.version, self.verdict.verdict_id

    def rebuild_review(self) -> ProceduralReview:
        """Execute the sole frozen Gate implementation for this input."""

        return review_verdict(
            ProceduralGateInput(
                verdict=self.verdict,
                evidence_pack=self.evidence_pack,
                current_closure=self.current_closure,
                gate_config=self.gate_config,
                alert_config=self.alert_config,
                gate_version=self.gate_config.gate_version,
                review_version=self.review_version,
                unknown_reference_attempts=self.unknown_reference_attempts,
                precedent_resolutions=self.precedent_resolutions,
                artifact_bounds=self.artifact_bounds,
            )
        )


@dataclass(frozen=True, slots=True)
class M6CaseProceduralGateAuthority:
    """Case-scoped collection of independently executable Gate inputs."""

    source_identity_sha256: str
    run_id: str
    case_id: str
    manifest_id: str
    inputs: tuple[M6ProceduralGateExecutionInput, ...] = ()

    def __post_init__(self) -> None:
        _require_sha256(self.source_identity_sha256, "M6 Gate source identity")
        require_reference_token(self.run_id, "M6 Gate run_id")
        require_reference_token(self.case_id, "M6 Gate case_id")
        _require_sha256(self.manifest_id, "M6 Gate manifest_id")
        if not isinstance(self.inputs, tuple) or any(
            not isinstance(item, M6ProceduralGateExecutionInput) for item in self.inputs
        ):
            raise TypeError("M6 Gate inputs must be a typed tuple")
        inputs = tuple(
            M6ProceduralGateExecutionInput(
                source_review_id=item.source_review_id,
                source_review_document_sha256=item.source_review_document_sha256,
                verdict=item.verdict,
                evidence_pack=item.evidence_pack,
                current_closure=item.current_closure,
                gate_config=item.gate_config,
                alert_config=item.alert_config,
                review_version=item.review_version,
                unknown_reference_attempts=item.unknown_reference_attempts,
                precedent_resolutions=item.precedent_resolutions,
                artifact_bounds=item.artifact_bounds,
            )
            for item in self.inputs
        )
        keys = tuple(item.sort_key for item in inputs)
        source_review_ids = tuple(item.source_review_id for item in inputs)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ValueError("M6 Gate inputs must be unique and ordered")
        if len(source_review_ids) != len(set(source_review_ids)):
            raise ValueError("M6 Gate source reviews must be unique")
        if inputs and (
            len({canonical_json(item.gate_config.model_dump(mode="json")) for item in inputs}) != 1
            or len({canonical_json(item.alert_config.model_dump(mode="json")) for item in inputs})
            != 1
        ):
            raise ValueError("M6 Gate inputs must use one Case-wide configuration")
        for item in inputs:
            if (
                item.verdict.run_id != self.run_id
                or item.verdict.case_id != self.case_id
                or item.verdict.manifest_id != self.manifest_id
                or item.evidence_pack.run_id != self.run_id
                or item.evidence_pack.case_id != self.case_id
                or item.evidence_pack.manifest_id != self.manifest_id
            ):
                raise ValueError("M6 Gate input differs from its Case scope")
        object.__setattr__(self, "inputs", inputs)

    def input_for_review(self, review: ProceduralReview) -> M6ProceduralGateExecutionInput:
        if not isinstance(review, ProceduralReview):
            raise TypeError("review must be a ProceduralReview")
        if (
            review.run_id != self.run_id
            or review.case_id != self.case_id
            or review.manifest_id != self.manifest_id
        ):
            raise ValueError("M6 Gate source review differs from its Case scope")
        matches = tuple(item for item in self.inputs if item.source_review_id == review.review_id)
        if len(matches) != 1:
            raise ValueError("M6 Gate authority cannot resolve the exact source review")
        item = matches[0]
        if (
            item.source_review_document_sha256 != _document_sha256(review)
            or item.review_version != review.version
            or item.verdict.verdict_id != review.reviewed_verdict_id
            or item.verdict.version != review.reviewed_verdict_version
            or item.verdict.verdict_sha256 != review.reviewed_verdict_sha256
            or item.evidence_pack.pack_id != review.evidence_pack_id
            or item.evidence_pack.version != review.evidence_pack_version
        ):
            raise ValueError("M6 Gate source review binding is inconsistent")
        return item


__all__ = [
    "M6CaseProceduralGateAuthority",
    "M6ProceduralGateExecutionInput",
    "build_m6_gate_precedent_resolutions",
]

"""Trusted, reproducible reconstruction of an M3 procedural review."""

from __future__ import annotations

from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import ArtifactKind, ModelParseStatus
from labcourt.contracts.evidence import EvidencePack
from labcourt.contracts.m3_models import UnknownReferenceAttempt
from labcourt.contracts.screening import (
    ModelParseReceipt,
    ParsedScreeningOutput,
    ScreeningResult,
)
from labcourt.contracts.storage import ArtifactRef, ClosureReport
from labcourt.contracts.verdicts import ProceduralReview, Verdict
from labcourt.domain.procedural_gate import (
    ArtifactBounds,
    ProceduralGateInput,
    review_verdict,
)
from labcourt.domain.screening_router import (
    FastVerdictBuilder,
    ScreeningRoutePolicy,
    ScreeningRouter,
)
from labcourt.ports.evidence_repository import EvidenceRepository


class ProceduralReviewVerificationError(ValueError):
    """Trusted review authority is missing, stale, or internally inconsistent."""


class DeterministicProceduralReviewVerifier:
    """Rebuild M3 derived semantics from pinned configuration and persisted authority."""

    def __init__(
        self,
        config: AppConfig,
        evidence_repository: EvidenceRepository,
    ) -> None:
        if not isinstance(config, AppConfig):
            raise TypeError("config must be an AppConfig")
        for method in (
            "load_pack",
            "load_frame",
            "load_run_manifest",
            "verify_current_pack",
        ):
            if not callable(getattr(evidence_repository, method, None)):
                raise TypeError(
                    f"evidence_repository does not implement its required {method} capability"
                )
        self._config = config
        self._evidence = evidence_repository

    def rebuild_screening(
        self,
        parsed_output: ParsedScreeningOutput,
        evidence_pack: EvidencePack,
        screening_version: int,
    ) -> ScreeningResult:
        """Return the sole deterministic screening result for persisted roots."""

        if not isinstance(parsed_output, ParsedScreeningOutput):
            raise TypeError("parsed_output must be a ParsedScreeningOutput")
        if not isinstance(evidence_pack, EvidencePack):
            raise TypeError("evidence_pack must be an EvidencePack")
        if (
            not isinstance(screening_version, int)
            or isinstance(screening_version, bool)
            or screening_version <= 0
        ):
            raise ValueError("screening_version must be a positive integer")
        self._require_pinned_pack(evidence_pack)
        screening = self._config.screening
        return ScreeningRouter(
            ScreeningRoutePolicy(
                low_probability=screening.low_probability,
                high_probability=screening.high_probability,
                strong_signal_threshold=screening.strong_signal_threshold,
                router_version=screening.router_version,
                conflict_policy_version=screening.conflict_policy_version,
            )
        ).route(
            parsed_output,
            evidence_pack,
            version=screening_version,
        )

    def rebuild_fast_verdict(
        self,
        screening_result: ScreeningResult,
        evidence_pack: EvidencePack,
        model_response_refs: tuple[ArtifactRef, ...],
        verdict_version: int,
    ) -> Verdict:
        """Return the sole deterministic fast verdict for persisted roots."""

        if not isinstance(screening_result, ScreeningResult):
            raise TypeError("screening_result must be a ScreeningResult")
        if not isinstance(evidence_pack, EvidencePack):
            raise TypeError("evidence_pack must be an EvidencePack")
        if not isinstance(model_response_refs, tuple) or any(
            not isinstance(ref, ArtifactRef) for ref in model_response_refs
        ):
            raise TypeError("model_response_refs must be a tuple of ArtifactRef values")
        if (
            not isinstance(verdict_version, int)
            or isinstance(verdict_version, bool)
            or verdict_version <= 0
        ):
            raise ValueError("verdict_version must be a positive integer")
        self._require_pinned_pack(evidence_pack)
        return FastVerdictBuilder().build(
            screening_result,
            evidence_pack,
            version=verdict_version,
            model_response_refs=model_response_refs,
        )

    def rebuild_review(
        self,
        verdict: Verdict,
        evidence_pack: EvidencePack,
        current_closure: ClosureReport,
        parse_history: tuple[ModelParseReceipt, ...],
        review_version: int,
    ) -> ProceduralReview:
        """Return the sole review allowed for the supplied immutable M3 roots."""

        if not isinstance(verdict, Verdict):
            raise TypeError("verdict must be a Verdict")
        if not isinstance(evidence_pack, EvidencePack):
            raise TypeError("evidence_pack must be an EvidencePack")
        if not isinstance(current_closure, ClosureReport):
            raise TypeError("current_closure must be a ClosureReport")
        if not isinstance(parse_history, tuple) or any(
            not isinstance(receipt, ModelParseReceipt) for receipt in parse_history
        ):
            raise TypeError("parse_history must be a tuple of ModelParseReceipt values")
        if (
            not isinstance(review_version, int)
            or isinstance(review_version, bool)
            or review_version <= 0
        ):
            raise ValueError("review_version must be a positive integer")

        self._require_pinned_authority(evidence_pack, current_closure)
        self._require_complete_parse_history(verdict, evidence_pack, parse_history)
        return review_verdict(
            ProceduralGateInput(
                verdict=verdict,
                evidence_pack=evidence_pack,
                current_closure=current_closure,
                gate_config=self._config.procedural_gate,
                alert_config=self._config.alerts,
                gate_version=self._config.procedural_gate.gate_version,
                review_version=review_version,
                unknown_reference_attempts=self._unknown_attempts(parse_history),
                precedent_resolutions=(),
                artifact_bounds=self._artifact_bounds(evidence_pack),
            )
        )

    def _require_pinned_authority(
        self,
        pack: EvidencePack,
        closure: ClosureReport,
    ) -> None:
        self._require_pinned_pack(pack)
        fresh_closure = self._evidence.verify_current_pack(pack.run_id, pack.pack_id)
        if fresh_closure != closure:
            raise ProceduralReviewVerificationError(
                "procedural review closure differs from current evidence authority"
            )

    def _require_pinned_pack(self, pack: EvidencePack) -> None:
        manifest = self._evidence.load_run_manifest(pack.run_id)
        if (
            manifest.manifest_id != pack.manifest_id
            or manifest.config_sha256 != self._config.config_sha256
        ):
            raise ProceduralReviewVerificationError(
                "procedural review configuration is not pinned by the run manifest"
            )
        persisted_pack = self._evidence.load_pack(pack.run_id, pack.pack_id)
        if persisted_pack != pack:
            raise ProceduralReviewVerificationError(
                "procedural review pack differs from persisted evidence authority"
            )

    @staticmethod
    def _require_complete_parse_history(
        verdict: Verdict,
        pack: EvidencePack,
        history: tuple[ModelParseReceipt, ...],
    ) -> None:
        if len(history) not in {1, 2}:
            raise ProceduralReviewVerificationError(
                "procedural review requires one complete direct or repaired parse history"
            )
        expected_attempts = (0,) if len(history) == 1 else (0, 1)
        if tuple(receipt.attempt_index for receipt in history) != expected_attempts:
            raise ProceduralReviewVerificationError(
                "procedural review parse history attempt order is invalid"
            )
        if history[-1].status != ModelParseStatus.PARSED or (
            len(history) == 2 and history[0].status != ModelParseStatus.REPAIR_REQUIRED
        ):
            raise ProceduralReviewVerificationError(
                "procedural review requires a successful terminal parse receipt"
            )
        expected_scope = (
            pack.run_id,
            pack.case_id,
            pack.pack_id,
            pack.version,
            pack.manifest_id,
        )
        if any(
            (
                receipt.run_id,
                receipt.case_id,
                receipt.evidence_pack_id,
                receipt.evidence_pack_version,
                receipt.manifest_id,
            )
            != expected_scope
            for receipt in history
        ):
            raise ProceduralReviewVerificationError(
                "procedural review parse history is outside the current pack scope"
            )
        expected_response_refs = tuple(
            sorted(
                (
                    ArtifactRef(
                        kind=ArtifactKind.MODEL_RESPONSE,
                        artifact_id=receipt.response_id,
                    )
                    for receipt in history
                ),
                key=lambda ref: ref.sort_key,
            )
        )
        if verdict.model_response_refs != expected_response_refs:
            raise ProceduralReviewVerificationError(
                "procedural review verdict does not bind the complete parse response history"
            )

    def _artifact_bounds(self, pack: EvidencePack) -> tuple[ArtifactBounds, ...]:
        values: dict[tuple[str, str], ArtifactBounds] = {}
        for crop in pack.crops:
            bounds = ArtifactBounds(
                artifact_ref=ArtifactRef(
                    kind=ArtifactKind.CROP,
                    artifact_id=crop.crop_id,
                ),
                width=crop.output_width,
                height=crop.output_height,
            )
            values[bounds.sort_key] = bounds
        frame_ids = {
            ref.artifact_id
            for ref in pack.expected_closure_refs()
            if ref.kind == ArtifactKind.FRAME
        }
        for frame_id in sorted(frame_ids):
            frame = self._evidence.load_frame(pack.run_id, frame_id)
            if frame.frame_id != frame_id:
                raise ProceduralReviewVerificationError(
                    "procedural review frame authority returned a different frame"
                )
            bounds = ArtifactBounds(
                artifact_ref=ArtifactRef(
                    kind=ArtifactKind.FRAME,
                    artifact_id=frame.frame_id,
                ),
                width=frame.width,
                height=frame.height,
            )
            values[bounds.sort_key] = bounds
        return tuple(values[key] for key in sorted(values))

    @staticmethod
    def _unknown_attempts(
        history: tuple[ModelParseReceipt, ...],
    ) -> tuple[UnknownReferenceAttempt, ...]:
        values = {
            attempt.sort_key: attempt
            for receipt in history
            for attempt in receipt.unknown_reference_attempts
        }
        return tuple(values[key] for key in sorted(values))


__all__ = [
    "DeterministicProceduralReviewVerifier",
    "ProceduralReviewVerificationError",
]

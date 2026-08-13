"""Deterministic typed M4 hearing responses for the platform's explicit Demo mode."""

from __future__ import annotations

from labcourt.adapters.vlm.errors import (
    VLMDeliveryCertainty,
    VLMProviderError,
    VLMProviderFailureCode,
)
from labcourt.contracts.canonical import canonical_bytes
from labcourt.contracts.enums import (
    AlertLevel,
    ArgumentStance,
    ArtifactKind,
    JudgeDisposition,
    VerdictDecision,
    VlmRole,
)
from labcourt.contracts.hearing import (
    DefenderModelPayload,
    HearingModelRequest,
    HearingModelResponse,
    JudgeFinalDecisionPayload,
    JudgeModelPayload,
    ProsecutorModelPayload,
)
from labcourt.contracts.m3_models import EvidenceCitation
from labcourt.contracts.storage import ArtifactRef
from labcourt.contracts.verdicts import Argument, JudgeResponse
from labcourt.ports.hearing_vlm import HearingModelResponsePublisher


class DeterministicSyntheticDemoHearingVLMClient:
    """Publish strict, visibly synthetic role payloads without a provider call."""

    __slots__ = ("_response_store",)

    def __init__(self, response_store: HearingModelResponsePublisher) -> None:
        if not hasattr(response_store, "publish"):
            raise TypeError("response_store must publish hearing responses")
        self._response_store = response_store

    @staticmethod
    def _evidence_ref(request: HearingModelRequest) -> ArtifactRef:
        return next(
            (item for item in request.allowed_evidence_refs if item.kind == ArtifactKind.CROP),
            request.allowed_evidence_refs[0],
        )

    def complete(self, request: HearingModelRequest) -> HearingModelResponse:
        if not isinstance(request, HearingModelRequest):
            raise VLMProviderError(
                VLMProviderFailureCode.REQUEST_IDENTITY_MISMATCH,
                VLMDeliveryCertainty.DEFINITELY_NOT_SENT,
            )
        evidence_ref = self._evidence_ref(request)
        defense_argument = Argument(
            stance=ArgumentStance.DEFENSE,
            claim="DEMO: 现有证据仍需保留一项有边界的反方异议。",
            evidence_refs=(evidence_ref,),
            uncertainty=0.2,
        )
        if request.role == VlmRole.PROSECUTOR:
            payload = ProsecutorModelPayload(
                arguments=(
                    Argument(
                        stance=ArgumentStance.PROSECUTION,
                        claim="DEMO: 已披露的类型化证据支持进入程序化会审。",
                        evidence_refs=(evidence_ref,),
                        uncertainty=0.1,
                    ),
                ),
                case_summary="DEMO / SYNTHETIC HEARING INPUT: 控方仅引用已披露证据。",
            )
        elif request.role == VlmRole.DEFENDER:
            payload = DefenderModelPayload(
                arguments=(defense_argument,),
                case_summary="DEMO / SYNTHETIC HEARING INPUT: 辩方保留证据解释异议。",
            )
        elif request.role == VlmRole.JUDGE:
            payload = JudgeModelPayload(
                judge_responses=(
                    JudgeResponse(
                        defense_argument_id=defense_argument.argument_id,
                        disposition=JudgeDisposition.REJECTED,
                        response_summary="DEMO: 裁决方已逐项处理该反方异议。",
                        evidence_refs=(evidence_ref,),
                    ),
                ),
                outcome=JudgeFinalDecisionPayload(
                    decision=VerdictDecision.ESTABLISHED,
                    confidence=0.9,
                    recommended_alert_level=AlertLevel.CONFIRMED,
                    rationale_summary=(
                        "DEMO: 类型化会审记录支持本次程序性演示结论; 该输出不是人工处分依据。"
                    ),
                    evidence_citations=(EvidenceCitation(evidence_ref=evidence_ref),),
                ),
            )
        else:
            raise VLMProviderError(
                VLMProviderFailureCode.REQUEST_IDENTITY_MISMATCH,
                VLMDeliveryCertainty.DEFINITELY_NOT_SENT,
            )
        raw = canonical_bytes(payload.model_dump(mode="json", exclude_computed_fields=True))
        if len(raw) > request.budget.max_response_bytes:
            raise VLMProviderError(
                VLMProviderFailureCode.RESPONSE_TOO_LARGE,
                VLMDeliveryCertainty.COMPLETED,
            )
        try:
            return self._response_store.publish(
                request,
                raw,
                input_tokens=1,
                output_tokens=1,
                latency_ms=1,
            )
        except Exception as error:
            raise VLMProviderError(
                VLMProviderFailureCode.RESPONSE_PERSISTENCE_FAILURE,
                VLMDeliveryCertainty.COMPLETED,
            ) from error


__all__ = ["DeterministicSyntheticDemoHearingVLMClient"]

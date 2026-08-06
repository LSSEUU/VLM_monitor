"""Trusted M4 reconstruction of a hearing-origin procedural review.

The M3 gate intentionally accepts the complete current EvidencePack as its
evidence universe.  A hearing has a narrower authority boundary: a model role
may cite only the privacy-safe objects that were actually disclosed in that
role's immutable request.  This verifier reconstructs that boundary from the
complete request/response/parse/usage history and converts any cross-role or
undisclosed reference into the same deterministic L5 defect taxonomy.
"""

from __future__ import annotations

from collections.abc import Iterable

from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import (
    ArtifactKind,
    ModelParseStatus,
    PrecedentLookupStatus,
    UnknownReferenceNamespace,
    UnknownReferenceSource,
    VlmRole,
)
from labcourt.contracts.evidence import EvidencePack
from labcourt.contracts.hearing import (
    DefenderModelPayload,
    HearingModelRequest,
    HearingPrecedentRetrievalReceipt,
    HearingRecord,
    HearingRoleOutput,
    HearingUnknownReferenceAttempt,
    HearingUnknownReferenceSource,
    HearingVerdictBinding,
    JudgeAcquisitionDecisionPayload,
    JudgeFinalDecisionPayload,
    JudgeModelPayload,
    ProsecutorModelPayload,
)
from labcourt.contracts.m3_models import (
    PrecedentLookupQuery,
    PrecedentResolution,
    UnknownReferenceAttempt,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.storage import ArtifactRef, ClosureReport
from labcourt.contracts.verdicts import ProceduralReview, Verdict
from labcourt.domain.evidence_authority import HearingEvidenceGrant
from labcourt.domain.hearing_fsm import HearingCallClosure
from labcourt.domain.hearing_verdict_builder import (
    HearingVerdictBuildError,
    validate_hearing_verdict_binding,
)
from labcourt.domain.procedural_gate import (
    ArtifactBounds,
    ProceduralGateInput,
    review_verdict,
)
from labcourt.ports.evidence_repository import EvidenceRepository


class HearingProceduralReviewVerificationError(ValueError):
    """Persisted M4 authority is missing, stale, or internally inconsistent."""


_ROLE_ORDER = {
    VlmRole.PROSECUTOR: 0,
    VlmRole.DEFENDER: 1,
    VlmRole.JUDGE: 2,
}

_PROFILE_ATTRIBUTE = {
    VlmRole.PROSECUTOR: "prosecutor_profile",
    VlmRole.DEFENDER: "defender_profile",
    VlmRole.JUDGE: "judge_profile",
}

_MODEL_COMPONENT = {
    VlmRole.PROSECUTOR: "prosecutor",
    VlmRole.DEFENDER: "defender",
    VlmRole.JUDGE: "judge",
}

_M3_SOURCE_BY_HEARING_SOURCE = {
    HearingUnknownReferenceSource.ARGUMENT_EVIDENCE_REF: (
        UnknownReferenceSource.ARGUMENT_EVIDENCE_REF
    ),
    HearingUnknownReferenceSource.JUDGE_RESPONSE_EVIDENCE_REF: (
        UnknownReferenceSource.JUDGE_RESPONSE_EVIDENCE_REF
    ),
    HearingUnknownReferenceSource.JUDGE_CITATION_REF: (
        UnknownReferenceSource.EVIDENCE_CITATION_REF
    ),
    HearingUnknownReferenceSource.OBJECTIVE_CLAIM_EVIDENCE_REF: (
        UnknownReferenceSource.OBJECTIVE_CLAIM_EVIDENCE_REF
    ),
    HearingUnknownReferenceSource.OBSERVATION_CROP_ID: (
        UnknownReferenceSource.FRAME_OBSERVATION_CROP_ID
    ),
    HearingUnknownReferenceSource.PRECEDENT_APPLICATION_ID: (
        UnknownReferenceSource.PRECEDENT_APPLICATION_ID
    ),
    HearingUnknownReferenceSource.PRECEDENT_FACT_DIFFERENCE_REF: (
        UnknownReferenceSource.EVIDENCE_CITATION_REF
    ),
    HearingUnknownReferenceSource.ACQUISITION_SUPPORTING_EVIDENCE_REF: (
        UnknownReferenceSource.EVIDENCE_CITATION_REF
    ),
    HearingUnknownReferenceSource.ACQUISITION_PARAMETER_FRAME_ID: (
        UnknownReferenceSource.EVIDENCE_CITATION_REF
    ),
    HearingUnknownReferenceSource.ACQUISITION_PARAMETER_CROP_ID: (
        UnknownReferenceSource.EVIDENCE_CITATION_REF
    ),
}


def _artifact_ref(kind: ArtifactKind, artifact_id: str) -> ArtifactRef:
    return ArtifactRef(kind=kind, artifact_id=artifact_id)


def _call_sort_key(call: HearingCallClosure) -> tuple[int, int, int, int, str]:
    request = call.request
    context = request.backlog_retry_context
    generation = context.retry_generation if context is not None else 0
    return (
        request.round_index,
        _ROLE_ORDER[request.role],
        generation,
        request.attempt_index,
        request.request_id,
    )


def _scored_precedent_refs(
    receipt: HearingPrecedentRetrievalReceipt,
) -> tuple[ArtifactRef, ...]:
    return tuple(
        sorted(
            (
                _artifact_ref(ArtifactKind.PRECEDENT, item.precedent.precedent_id)
                for item in receipt.scored_precedents
            ),
            key=lambda ref: ref.sort_key,
        )
    )


def _hearing_attempt(
    namespace: UnknownReferenceNamespace,
    source: HearingUnknownReferenceSource,
    raw_value: object,
) -> HearingUnknownReferenceAttempt:
    return HearingUnknownReferenceAttempt(
        namespace=namespace,
        source=source,
        value_sha256=sha256_hex(
            [
                "unknown-hearing-model-reference",
                1,
                namespace.value,
                source.value,
                raw_value,
            ]
        ),
    )


def _evidence_attempt(
    source: HearingUnknownReferenceSource,
    ref: ArtifactRef,
) -> HearingUnknownReferenceAttempt:
    return _hearing_attempt(
        UnknownReferenceNamespace.EVIDENCE,
        source,
        ref.model_dump(mode="json"),
    )


def _precedent_attempt(
    source: HearingUnknownReferenceSource,
    ref: ArtifactRef,
) -> HearingUnknownReferenceAttempt:
    return _hearing_attempt(
        UnknownReferenceNamespace.PRECEDENT,
        source,
        ref.model_dump(mode="json"),
    )


def _output_reference_attempts(
    output: HearingRoleOutput,
    request: HearingModelRequest,
) -> tuple[HearingUnknownReferenceAttempt, ...]:
    """Independently compare a parsed payload with its exact role whitelist."""

    allowed_evidence = frozenset(request.allowed_evidence_refs)
    allowed_precedents = frozenset(request.allowed_precedent_refs)
    attempts: dict[tuple[str, str, str], HearingUnknownReferenceAttempt] = {}

    def evidence(source: HearingUnknownReferenceSource, refs: Iterable[ArtifactRef]) -> None:
        for ref in refs:
            if ref not in allowed_evidence:
                attempt = _evidence_attempt(source, ref)
                attempts[attempt.sort_key] = attempt

    payload = output.payload
    if isinstance(payload, ProsecutorModelPayload | DefenderModelPayload):
        for argument in payload.arguments:
            evidence(
                HearingUnknownReferenceSource.ARGUMENT_EVIDENCE_REF,
                argument.evidence_refs,
            )
    elif isinstance(payload, JudgeModelPayload):
        for response in payload.judge_responses:
            evidence(
                HearingUnknownReferenceSource.JUDGE_RESPONSE_EVIDENCE_REF,
                response.evidence_refs,
            )
        for application in payload.precedent_applications:
            if application.precedent_ref not in allowed_precedents:
                attempt = _precedent_attempt(
                    HearingUnknownReferenceSource.PRECEDENT_APPLICATION_ID,
                    application.precedent_ref,
                )
                attempts[attempt.sort_key] = attempt
            evidence(
                HearingUnknownReferenceSource.PRECEDENT_FACT_DIFFERENCE_REF,
                application.fact_difference_refs,
            )
        outcome = payload.outcome
        if isinstance(outcome, JudgeFinalDecisionPayload):
            evidence(
                HearingUnknownReferenceSource.JUDGE_CITATION_REF,
                (citation.evidence_ref for citation in outcome.evidence_citations),
            )
            evidence(
                HearingUnknownReferenceSource.OBJECTIVE_CLAIM_EVIDENCE_REF,
                (claim.evidence_ref for claim in outcome.objective_claims),
            )
            if outcome.observation_sufficiency is not None:
                evidence(
                    HearingUnknownReferenceSource.OBSERVATION_CROP_ID,
                    (
                        _artifact_ref(ArtifactKind.CROP, observation.crop_id)
                        for observation in outcome.observation_sufficiency.observations
                    ),
                )
        elif isinstance(outcome, JudgeAcquisitionDecisionPayload):
            evidence(
                HearingUnknownReferenceSource.ACQUISITION_SUPPORTING_EVIDENCE_REF,
                outcome.request.supporting_evidence_refs,
            )
    else:  # pragma: no cover - the discriminated contract prevents this
        raise HearingProceduralReviewVerificationError(
            "hearing output contains an unsupported role payload"
        )
    return tuple(attempts[key] for key in sorted(attempts))


def _as_m3_attempt(attempt: HearingUnknownReferenceAttempt) -> UnknownReferenceAttempt:
    return UnknownReferenceAttempt(
        namespace=attempt.namespace,
        source=_M3_SOURCE_BY_HEARING_SOURCE[attempt.source],
        value_sha256=attempt.value_sha256,
    )


class DeterministicHearingProceduralReviewVerifier:
    """Rebuild the sole L5 result allowed for a persisted terminal hearing."""

    def __init__(
        self,
        config: AppConfig,
        evidence_repository: EvidenceRepository,
    ) -> None:
        if not isinstance(config, AppConfig):
            raise TypeError("config must be an AppConfig")
        for method in (
            "load_pack",
            "load_run_manifest",
            "verify_current_pack",
        ):
            if not callable(getattr(evidence_repository, method, None)):
                raise TypeError(
                    f"evidence_repository does not implement its required {method} capability"
                )
        self._config = config
        self._evidence = evidence_repository

    def rebuild_review(
        self,
        *,
        record: HearingRecord,
        verdict: Verdict,
        binding: HearingVerdictBinding,
        evidence_pack: EvidencePack,
        current_closure: ClosureReport,
        call_history: tuple[HearingCallClosure, ...],
        evidence_grant: HearingEvidenceGrant,
        review_version: int,
    ) -> ProceduralReview:
        """Verify every persisted root, then invoke the unchanged pure L5 gate."""

        self._require_inputs(
            record,
            verdict,
            binding,
            evidence_pack,
            current_closure,
            call_history,
            evidence_grant,
            review_version,
        )
        try:
            validate_hearing_verdict_binding(
                record,
                verdict,
                binding,
                violation_type=evidence_pack.event.violation_type,
            )
        except (HearingVerdictBuildError, TypeError, ValueError) as exc:
            raise HearingProceduralReviewVerificationError(
                "hearing verdict is not the exact terminal record projection"
            ) from exc

        manifest = self._require_pinned_authority(
            record,
            verdict,
            evidence_pack,
            current_closure,
        )
        calls_by_request = self._require_complete_call_history(
            record,
            evidence_pack,
            call_history,
            manifest,
        )
        derived_grant = self._derive_grant(record, call_history)
        if derived_grant != evidence_grant:
            raise HearingProceduralReviewVerificationError(
                "hearing evidence grant differs from the actual provider disclosure history"
            )

        hearing_attempts: dict[
            tuple[str, str, str],
            HearingUnknownReferenceAttempt,
        ] = {}
        for call in call_history:
            for attempt in call.parse_receipt.unknown_reference_attempts:
                hearing_attempts[attempt.sort_key] = attempt
        for hearing_round in record.rounds:
            for output in (
                hearing_round.prosecutor_output,
                hearing_round.defender_output,
                hearing_round.judge_output,
            ):
                request_id = output.request_ref.artifact_id
                call = calls_by_request[request_id]
                for attempt in _output_reference_attempts(output, call.request):
                    hearing_attempts[attempt.sort_key] = attempt

        unknown_attempts = {
            converted.sort_key: converted
            for converted in (_as_m3_attempt(attempt) for attempt in hearing_attempts.values())
        }
        return review_verdict(
            ProceduralGateInput(
                verdict=verdict,
                evidence_pack=evidence_pack,
                current_closure=current_closure,
                gate_config=self._config.procedural_gate,
                alert_config=self._config.alerts,
                gate_version=self._config.procedural_gate.gate_version,
                review_version=review_version,
                unknown_reference_attempts=tuple(
                    unknown_attempts[key] for key in sorted(unknown_attempts)
                ),
                precedent_resolutions=self._precedent_resolutions(record, evidence_pack),
                # M4 never grants FRAME pixels.  Acquired RECROP objects can be
                # external to the frozen pack crop tuples, so their exact bounds
                # come from the reconstructed disclosure grant.
                artifact_bounds=evidence_grant.artifact_bounds,
            )
        )

    @staticmethod
    def _require_inputs(
        record: HearingRecord,
        verdict: Verdict,
        binding: HearingVerdictBinding,
        evidence_pack: EvidencePack,
        current_closure: ClosureReport,
        call_history: tuple[HearingCallClosure, ...],
        evidence_grant: HearingEvidenceGrant,
        review_version: int,
    ) -> None:
        expected = (
            (record, HearingRecord, "record"),
            (verdict, Verdict, "verdict"),
            (binding, HearingVerdictBinding, "binding"),
            (evidence_pack, EvidencePack, "evidence_pack"),
            (current_closure, ClosureReport, "current_closure"),
            (evidence_grant, HearingEvidenceGrant, "evidence_grant"),
        )
        for value, expected_type, name in expected:
            if not isinstance(value, expected_type):
                raise TypeError(f"{name} must be a {expected_type.__name__}")
        if not isinstance(call_history, tuple) or any(
            not isinstance(call, HearingCallClosure) for call in call_history
        ):
            raise TypeError("call_history must be a tuple of HearingCallClosure values")
        if (
            not isinstance(review_version, int)
            or isinstance(review_version, bool)
            or review_version <= 0
        ):
            raise ValueError("review_version must be a positive integer")
        if not record.complete:
            raise HearingProceduralReviewVerificationError(
                "procedural review requires a terminal hearing record"
            )

    def _require_pinned_authority(
        self,
        record: HearingRecord,
        verdict: Verdict,
        pack: EvidencePack,
        closure: ClosureReport,
    ) -> RunManifest:
        terminal = record.rounds[-1]
        if (
            record.run_id != pack.run_id
            or record.case_id != pack.case_id
            or record.manifest_id != pack.manifest_id
            or record.current_evidence_pack_id != pack.pack_id
            or record.current_evidence_pack_version != pack.version
            or terminal.current_evidence_pack_id != pack.pack_id
            or terminal.current_evidence_pack_version != pack.version
            or verdict.evidence_pack_id != pack.pack_id
            or verdict.evidence_pack_version != pack.version
        ):
            raise HearingProceduralReviewVerificationError(
                "terminal hearing, verdict, and evidence pack do not share one scope"
            )
        persisted = self._evidence.load_pack(pack.run_id, pack.pack_id)
        if persisted != pack:
            raise HearingProceduralReviewVerificationError(
                "hearing evidence pack differs from persisted authority"
            )
        manifest = self._evidence.load_run_manifest(pack.run_id)
        if (
            manifest.manifest_id != pack.manifest_id
            or manifest.config_sha256 != self._config.config_sha256
        ):
            raise HearingProceduralReviewVerificationError(
                "hearing configuration is not pinned by the run manifest"
            )
        fresh = self._evidence.verify_current_pack(pack.run_id, pack.pack_id)
        if fresh != closure:
            raise HearingProceduralReviewVerificationError(
                "hearing closure differs from current physical evidence authority"
            )

        hearing = self._config.hearing
        session = record.session
        if (
            session.acquisition_round_limit != hearing.max_acquisition_rounds
            or session.rework_round_limit != hearing.max_rework_rounds
            or session.max_total_images != hearing.max_total_images
            or session.max_total_output_tokens != hearing.max_total_output_tokens
            or session.prosecutor_model_manifest_id
            != manifest.models["prosecutor"].model_manifest_id
            or session.defender_model_manifest_id != manifest.models["defender"].model_manifest_id
            or session.judge_model_manifest_id != manifest.models["judge"].model_manifest_id
        ):
            raise HearingProceduralReviewVerificationError(
                "hearing session conflicts with pinned config or model manifests"
            )
        return manifest

    def _require_complete_call_history(
        self,
        record: HearingRecord,
        pack: EvidencePack,
        history: tuple[HearingCallClosure, ...],
        manifest: RunManifest,
    ) -> dict[str, HearingCallClosure]:
        if not history or history != tuple(sorted(history, key=_call_sort_key)):
            raise HearingProceduralReviewVerificationError(
                "hearing call history must be non-empty and use stable logical order"
            )
        request_ids = tuple(call.request.request_id for call in history)
        response_ids = tuple(call.response.response_id for call in history)
        parse_ids = tuple(call.parse_receipt.parse_receipt_id for call in history)
        if any(
            len(values) != len(set(values)) for values in (request_ids, response_ids, parse_ids)
        ):
            raise HearingProceduralReviewVerificationError(
                "hearing call history contains duplicate immutable identities"
            )
        expected_request_refs = tuple(
            sorted(
                (
                    _artifact_ref(ArtifactKind.MODEL_REQUEST, request_id)
                    for request_id in request_ids
                ),
                key=lambda ref: ref.sort_key,
            )
        )
        expected_response_refs = tuple(
            sorted(
                (
                    _artifact_ref(ArtifactKind.MODEL_RESPONSE, response_id)
                    for response_id in response_ids
                ),
                key=lambda ref: ref.sort_key,
            )
        )
        expected_parse_refs = tuple(
            sorted(
                (
                    _artifact_ref(ArtifactKind.MODEL_PARSE_RECEIPT, parse_id)
                    for parse_id in parse_ids
                ),
                key=lambda ref: ref.sort_key,
            )
        )
        expected_usage = tuple(
            sorted(
                (call.usage for call in history),
                key=lambda item: (
                    item.round_index,
                    item.role.value,
                    item.request_ref.artifact_id,
                ),
            )
        )
        if (
            record.model_request_refs != expected_request_refs
            or record.model_response_refs != expected_response_refs
            or record.parse_receipt_refs != expected_parse_refs
            or record.usage_receipts != expected_usage
        ):
            raise HearingProceduralReviewVerificationError(
                "hearing record does not preserve the exact successful call history"
            )

        calls_by_request = {call.request.request_id: call for call in history}
        calls_by_parse = {call.parse_receipt.parse_receipt_id: call for call in history}
        for call in history:
            self._require_request_scope(record, pack, call.request, manifest)
            if call.request.attempt_index == 1:
                self._require_repair_pair(call, calls_by_request)
            elif call.parse_receipt.status == ModelParseStatus.REPAIR_REQUIRED:
                repair_id = call.parse_receipt.repair_request_id
                if repair_id is None or repair_id not in calls_by_request:
                    raise HearingProceduralReviewVerificationError(
                        "repair-required hearing call lacks its persisted repair"
                    )

        output_parse_ids: set[str] = set()
        for hearing_round in record.rounds:
            outputs = (
                hearing_round.prosecutor_output,
                hearing_round.defender_output,
                hearing_round.judge_output,
            )
            for output in outputs:
                parse_id = output.parse_receipt_ref.artifact_id
                bound_call = calls_by_parse.get(parse_id)
                if bound_call is None:
                    raise HearingProceduralReviewVerificationError(
                        "hearing role output lacks its exact parsed call"
                    )
                self._require_output_call_binding(output, bound_call)
                output_parse_ids.add(parse_id)
            prosecutor, defender, judge = outputs
            defender_call = calls_by_parse[defender.parse_receipt_ref.artifact_id]
            judge_call = calls_by_parse[judge.parse_receipt_ref.artifact_id]
            if defender_call.request.prosecutor_output_ref != _artifact_ref(
                ArtifactKind.PARSED_MODEL_OUTPUT,
                prosecutor.output_id,
            ) or (
                judge_call.request.prosecutor_output_ref
                != _artifact_ref(ArtifactKind.PARSED_MODEL_OUTPUT, prosecutor.output_id)
                or judge_call.request.defender_output_ref
                != _artifact_ref(ArtifactKind.PARSED_MODEL_OUTPUT, defender.output_id)
            ):
                raise HearingProceduralReviewVerificationError(
                    "hearing role request does not bind the exact upstream outputs"
                )
        parsed_ids = {
            call.parse_receipt.parse_receipt_id
            for call in history
            if call.parse_receipt.status == ModelParseStatus.PARSED
        }
        if parsed_ids != output_parse_ids:
            raise HearingProceduralReviewVerificationError(
                "hearing history contains an unbound successful parsed output"
            )
        return calls_by_request

    def _require_request_scope(
        self,
        record: HearingRecord,
        pack: EvidencePack,
        request: HearingModelRequest,
        manifest: RunManifest,
    ) -> None:
        if request.role not in _ROLE_ORDER or not 1 <= request.round_index <= len(record.rounds):
            raise HearingProceduralReviewVerificationError(
                "hearing request has an unsupported role or round"
            )
        hearing_round = record.rounds[request.round_index - 1]
        retrieval = hearing_round.precedent_retrieval_receipt
        expected_profile_name = getattr(
            self._config.hearing,
            _PROFILE_ATTRIBUTE[request.role],
        )
        profile = self._config.providers.get(expected_profile_name)
        component = manifest.models[_MODEL_COMPONENT[request.role]]
        if profile is None:
            raise HearingProceduralReviewVerificationError(
                "configured hearing provider profile is absent"
            )
        if (
            request.run_id != record.run_id
            or request.case_id != record.case_id
            or request.hearing_session_id != record.hearing_session_id
            or request.round_index != hearing_round.round_index
            or request.prior_acquisition_rounds != hearing_round.prior_acquisition_rounds
            or request.prior_rework_rounds != hearing_round.prior_rework_rounds
            or request.current_evidence_pack_id != hearing_round.current_evidence_pack_id
            or request.current_evidence_pack_version != hearing_round.current_evidence_pack_version
            or request.screening_ref.artifact_id != record.screening_id
            or request.violation_type != pack.event.violation_type
            or request.evidence_class != pack.event.evidence_class
            or request.provider_profile != expected_profile_name
            or request.provider != profile.provider
            or request.model != profile.model
            or request.revision != profile.revision
            or request.execution_location != profile.execution_location
            or request.model_manifest_id != component.model_manifest_id
            or request.provider != component.provider
            or request.model != component.model
            or request.revision != component.revision
            or request.hearing_prompt_bundle_sha256 != record.session.hearing_prompt_bundle_sha256
            or request.prompt_manifest.prompt_bundle_sha256
            != record.session.hearing_prompt_bundle_sha256
            or request.precedent_retrieval_degraded != hearing_round.precedent_retrieval_degraded
            or request.precedent_retrieval_receipt_id != retrieval.receipt_id
            or request.precedent_retrieval_receipt_sha256 != retrieval.receipt_sha256
            or request.allowed_precedent_refs != _scored_precedent_refs(retrieval)
            or request.initial_trigger_review_ref != hearing_round.initial_trigger_review_ref
            or request.initial_defect_codes != hearing_round.initial_defect_codes
            or request.rework_review_ref != hearing_round.rework_review_ref
            or request.rework_defect_codes != hearing_round.rework_defect_codes
            or request.manifest_id != record.manifest_id
        ):
            raise HearingProceduralReviewVerificationError(
                "hearing request conflicts with its round, config, or manifest authority"
            )
        final_refs = frozenset(pack.expected_closure_refs())
        if any(ref not in final_refs for ref in request.allowed_evidence_refs):
            raise HearingProceduralReviewVerificationError(
                "hearing request granted evidence outside the final successor closure"
            )

    @staticmethod
    def _require_repair_pair(
        repair: HearingCallClosure,
        calls_by_request: dict[str, HearingCallClosure],
    ) -> None:
        original_id = repair.request.original_request_id
        primary = calls_by_request.get(original_id or "")
        if primary is None or primary.request.attempt_index != 0:
            raise HearingProceduralReviewVerificationError(
                "hearing repair lacks its exact primary request"
            )
        same_scope = (
            "run_id",
            "case_id",
            "hearing_session_id",
            "round_index",
            "prior_acquisition_rounds",
            "prior_rework_rounds",
            "current_evidence_pack_id",
            "current_evidence_pack_version",
            "screening_ref",
            "violation_type",
            "evidence_class",
            "role",
            "provider_profile",
            "provider",
            "model",
            "revision",
            "model_manifest_id",
            "execution_location",
            "hearing_prompt_bundle_sha256",
            "allowed_evidence_refs",
            "allowed_precedent_refs",
            "prosecutor_output_ref",
            "defender_output_ref",
            "precedent_retrieval_degraded",
            "precedent_retrieval_receipt_id",
            "precedent_retrieval_receipt_sha256",
            "initial_trigger_review_ref",
            "initial_defect_codes",
            "rework_review_ref",
            "rework_defect_codes",
            "temperature",
            "seed",
            "backlog_retry_context",
            "manifest_id",
        )
        if (
            any(
                getattr(primary.request, name) != getattr(repair.request, name)
                for name in same_scope
            )
            or primary.parse_receipt.status != ModelParseStatus.REPAIR_REQUIRED
            or primary.parse_receipt.repair_request_id != repair.request.request_id
            or repair.request.original_response_id != primary.response.response_id
            or repair.request.original_response_content_sha256 != primary.response.content_sha256
        ):
            raise HearingProceduralReviewVerificationError(
                "hearing repair changed or omitted its primary call authority"
            )

    @staticmethod
    def _require_output_call_binding(
        output: HearingRoleOutput,
        call: HearingCallClosure,
    ) -> None:
        request = call.request
        parse = call.parse_receipt
        if (
            parse.status != ModelParseStatus.PARSED
            or parse.parsed_payload_sha256 != output.payload.payload_sha256
            or output.request_ref != call.request_ref
            or output.response_ref != call.response_ref
            or output.parse_receipt_ref != call.parse_receipt_ref
            or output.prompt_manifest != request.prompt_manifest
            or output.model_manifest_id != request.model_manifest_id
            or output.role != request.role
            or output.round_index != request.round_index
            or output.current_evidence_pack_id != request.current_evidence_pack_id
            or output.current_evidence_pack_version != request.current_evidence_pack_version
        ):
            raise HearingProceduralReviewVerificationError(
                "hearing role output conflicts with its terminal parsed call"
            )

    @staticmethod
    def _derive_grant(
        record: HearingRecord,
        history: tuple[HearingCallClosure, ...],
    ) -> HearingEvidenceGrant:
        requests: dict[str, HearingModelRequest] = {
            call.request.request_id: call.request for call in history if call.request.media
        }
        for authority in record.failure_authorities:
            if authority.disclosed_images:
                requests[authority.request.request_id] = authority.request
        refs: dict[tuple[str, str], ArtifactRef] = {}
        bounds: dict[tuple[str, str], tuple[int, int]] = {}
        for request in requests.values():
            refs.update({ref.sort_key: ref for ref in request.allowed_evidence_refs})
            for media in request.media:
                ref = _artifact_ref(ArtifactKind.CROP, media.crop_id)
                candidate = (media.width, media.height)
                prior = bounds.get(ref.sort_key)
                if prior is not None and prior != candidate:
                    raise HearingProceduralReviewVerificationError(
                        "one disclosed crop has conflicting pixel dimensions"
                    )
                bounds[ref.sort_key] = candidate
        return HearingEvidenceGrant(
            run_id=record.run_id,
            case_id=record.case_id,
            latest_evidence_pack_id=record.current_evidence_pack_id,
            latest_evidence_pack_version=record.current_evidence_pack_version,
            allowed_evidence_refs=tuple(refs[key] for key in sorted(refs)),
            artifact_bounds=tuple(
                ArtifactBounds(
                    artifact_ref=refs[key],
                    width=bounds[key][0],
                    height=bounds[key][1],
                )
                for key in sorted(bounds)
            ),
        )

    @staticmethod
    def _precedent_resolutions(
        record: HearingRecord,
        pack: EvidencePack,
    ) -> tuple[PrecedentResolution, ...]:
        receipt = record.rounds[-1].precedent_retrieval_receipt
        resolutions = []
        for scored in receipt.scored_precedents:
            # M4 fused scores may include a bounded source boost and therefore
            # reach 1.25.  The frozen M3 lookup contract is cosine-shaped and
            # capped at 1.0, so the deterministic compatibility projection is
            # clamped without changing rank or the configured pass threshold.
            similarity = max(-1.0, min(1.0, float(scored.fused_score)))
            resolutions.append(
                PrecedentResolution(
                    query=PrecedentLookupQuery(
                        run_id=record.run_id,
                        case_id=record.case_id,
                        precedent_id=scored.precedent.precedent_id,
                        rule_version=receipt.rule_version,
                        evidence_class=pack.event.evidence_class,
                        violation_type=pack.event.violation_type,
                        manifest_id=record.manifest_id,
                    ),
                    status=PrecedentLookupStatus.FOUND,
                    snapshot=scored.precedent,
                    authoritative_similarity=similarity,
                    lookup_version=receipt.retriever_version,
                )
            )
        return tuple(resolutions)


__all__ = [
    "DeterministicHearingProceduralReviewVerifier",
    "HearingProceduralReviewVerificationError",
]

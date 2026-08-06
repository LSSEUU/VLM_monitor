"""Aggregate case contract and append-only semantic timeline."""

from __future__ import annotations

from typing import Self

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    StrictFloat,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.alerts import AlertDecision
from labcourt.contracts.appeals import Appeal
from labcourt.contracts.base import FrozenContractModel, Scalar
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.enums import (
    AcquisitionAction,
    AppealStatus,
    ArtifactKind,
    AuditAction,
    BacklogReasonCode,
    BacklogStatus,
    CaseStatus,
    EvidenceClass,
    EvidenceFailureCode,
    ScreeningDecision,
    VerdictDecision,
)
from labcourt.contracts.events import CandidateEvent, derive_case_id
from labcourt.contracts.evidence import EvidencePack, ToolResult
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.metadata import validate_safe_scalar_metadata
from labcourt.contracts.references import ReferenceToken, require_reference_token
from labcourt.contracts.screening import ScreeningResult
from labcourt.contracts.storage import ArtifactRef
from labcourt.contracts.verdicts import ProceduralReview, Verdict

_HEARING_HUMAN_REVIEW_REASONS = frozenset(
    {
        "ACQUISITION_LIMIT_EXHAUSTED",
        "REWORK_LIMIT_EXHAUSTED",
        "HEARING_BUDGET_EXHAUSTED",
        "EVIDENCE_UNAVAILABLE",
        "ACQUISITION_UNRECOVERABLE",
        "HEARING_BACKLOG_EXHAUSTED",
    }
)

_M4_ACQUISITION_IMMUTABLE_PACK_FIELDS = (
    "run_id",
    "case_id",
    "complete",
    "event",
    "key_frame_ids",
    "panorama_crops",
    "subject_crops",
    "focus_crops",
    "temporal_crops",
    "track_summary",
    "confirmation_record",
    "observation_sufficiency_input",
    "manifest_id",
)


def _derive_m4_tool_result_id(result: ToolResult) -> str:
    return sha256_hex(
        [
            "m4-tool-result",
            1,
            result.action.value,
            [ref.model_dump(mode="json") for ref in result.input_refs],
            [ref.model_dump(mode="json") for ref in result.output_refs],
            result.validated_parameters.model_dump(mode="json"),
            result.execution_manifest_id,
        ]
    )


def _require_m4_acquisition_successor(
    previous: EvidencePack,
    successor: EvidencePack,
) -> None:
    """Validate the pack-local proof available without importing hearing receipts."""

    if successor.version != previous.version + 1:
        raise ValueError("M4 acquisition evidence packs must advance by one version")
    for field_name in _M4_ACQUISITION_IMMUTABLE_PACK_FIELDS:
        if getattr(successor, field_name) != getattr(previous, field_name):
            raise ValueError(f"M4 acquisition rewrote immutable pack field {field_name}")

    previous_results = {result.tool_result_id: result for result in previous.tool_results}
    successor_results = {result.tool_result_id: result for result in successor.tool_results}
    if any(
        successor_results.get(result_id) != result for result_id, result in previous_results.items()
    ):
        raise ValueError("M4 acquisition rewrote or removed an earlier tool result")
    added_result_ids = set(successor_results) - set(previous_results)
    if len(added_result_ids) != 1:
        raise ValueError("M4 acquisition must add exactly one tool result")
    result = successor_results[added_result_ids.pop()]
    if result.tool_result_id != _derive_m4_tool_result_id(result):
        raise ValueError("M4 acquisition tool result is not content addressed")

    predecessor_refs = tuple(
        ref for ref in result.input_refs if ref.kind == ArtifactKind.EVIDENCE_PACK
    )
    expected_predecessor_ref = ArtifactRef(
        kind=ArtifactKind.EVIDENCE_PACK,
        artifact_id=previous.pack_id,
    )
    if predecessor_refs != (expected_predecessor_ref,):
        raise ValueError("M4 acquisition tool result does not bind its predecessor pack")

    previous_facts = {fact.fact_id: fact for fact in previous.objective_facts}
    successor_facts = {fact.fact_id: fact for fact in successor.objective_facts}
    if any(successor_facts.get(fact_id) != fact for fact_id, fact in previous_facts.items()):
        raise ValueError("M4 acquisition rewrote or removed an earlier objective fact")
    added_fact_ids = set(successor_facts) - set(previous_facts)
    if result.action != AcquisitionAction.TRACK_CONFIDENCE_CURVE:
        if added_fact_ids:
            raise ValueError("this M4 acquisition action cannot add objective facts")
        return

    output_fact_ids = {
        ref.artifact_id for ref in result.output_refs if ref.kind == ArtifactKind.OBJECTIVE_FACT
    }
    if (
        not result.output_refs
        or len(output_fact_ids) != len(result.output_refs)
        or added_fact_ids != output_fact_ids
    ):
        raise ValueError("track-confidence acquisition facts must match its exact outputs")
    expected_source = ArtifactRef(
        kind=ArtifactKind.TOOL_RESULT,
        artifact_id=result.tool_result_id,
    )
    for fact_id in added_fact_ids:
        fact = successor_facts[fact_id]
        if (
            fact.source_ref != expected_source
            or fact.source_manifest_id != result.execution_manifest_id
        ):
            raise ValueError("track-confidence fact lacks exact tool-result provenance")


def _require_verdict_pack_scope(
    evidence_packs: tuple[EvidencePack, ...],
    screening_pack: EvidencePack,
    verdict_pack: EvidencePack,
) -> None:
    if (
        screening_pack.pack_id == verdict_pack.pack_id
        and screening_pack.version == verdict_pack.version
    ):
        return
    if verdict_pack.version <= screening_pack.version:
        raise ValueError("verdict evidence pack cannot precede its screening pack")
    current = screening_pack
    for version in range(screening_pack.version + 1, verdict_pack.version + 1):
        successor = evidence_packs[version - 1]
        _require_m4_acquisition_successor(current, successor)
        current = successor
    if current.pack_id != verdict_pack.pack_id:
        raise ValueError("verdict evidence pack is not the proven M4 successor")


class TimelineEntry(FrozenContractModel):
    sequence: int = Field(ge=0, strict=True)
    action: str = Field(min_length=1)
    stage: str = Field(min_length=1)
    object_ref: str = Field(min_length=1)
    details: dict[str, Scalar] = Field(default_factory=dict)

    @field_validator("details")
    @classmethod
    def validate_details(cls, value: dict[str, Scalar]) -> dict[str, Scalar]:
        validate_safe_scalar_metadata(value)
        return value


class UsageSummary(FrozenContractModel):
    input_images: int = Field(default=0, ge=0, strict=True)
    input_pixels: int = Field(default=0, ge=0, strict=True)
    input_tokens: int = Field(default=0, ge=0, strict=True)
    output_tokens: int = Field(default=0, ge=0, strict=True)
    provider_latency_ms: int = Field(default=0, ge=0, strict=True)
    retries: int = Field(default=0, ge=0, strict=True)
    estimated_cost: StrictFloat = Field(default=0.0, ge=0)


def _is_typed_human_review_entry(entry: TimelineEntry, case_id: str) -> bool:
    if entry.action != AuditAction.CASE_STATE_CHANGED.value:
        return False
    if entry.stage == "EVIDENCE":
        return (
            entry.object_ref == case_id
            and set(entry.details) == {"failure_code"}
            and entry.details["failure_code"] in {failure.value for failure in EvidenceFailureCode}
        )
    if entry.stage == "HEARING":
        hearing_session_id = entry.details.get("hearing_session_id")
        judge_cycle = entry.details.get("judge_cycle")
        return (
            len(entry.object_ref) == 64
            and all(character in "0123456789abcdef" for character in entry.object_ref)
            and set(entry.details) == {"reason", "hearing_session_id", "judge_cycle"}
            and entry.details["reason"] in _HEARING_HUMAN_REVIEW_REASONS
            and isinstance(hearing_session_id, str)
            and len(hearing_session_id) == 64
            and all(character in "0123456789abcdef" for character in hearing_session_id)
            and isinstance(judge_cycle, int)
            and not isinstance(judge_cycle, bool)
            and 1 <= judge_cycle <= 5
        )
    if entry.stage != "BACKLOG":
        return False
    retry_generation = entry.details.get("retry_generation")
    return (
        len(entry.object_ref) == 64
        and all(character in "0123456789abcdef" for character in entry.object_ref)
        and set(entry.details) == {"outcome", "reason_code", "status", "retry_generation"}
        and entry.details["outcome"] == "FAILURE"
        and entry.details["reason_code"] in {reason.value for reason in BacklogReasonCode}
        and entry.details["status"] == BacklogStatus.EXHAUSTED.value
        and isinstance(retry_generation, int)
        and not isinstance(retry_generation, bool)
        and retry_generation >= 0
    )


class Case(FrozenContractModel):
    run_id: ReferenceToken
    status: CaseStatus
    event: CandidateEvent
    evidence_packs: tuple[EvidencePack, ...] = ()
    screening_results: tuple[ScreeningResult, ...] = ()
    verdicts: tuple[Verdict, ...] = ()
    procedural_reviews: tuple[ProceduralReview, ...] = ()
    alerts: tuple[AlertDecision, ...] = ()
    appeals: tuple[Appeal, ...] = ()
    final_decision: VerdictDecision | None = None
    usage: UsageSummary = Field(default_factory=UsageSummary)
    manifest_id: Sha256Hex
    current_backlog_item_id: Sha256Hex | None = None
    timeline: tuple[TimelineEntry, ...] = ()
    semantic_case_hash: Sha256Hex | None = None

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "case run_id")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_case_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "case_id" in payload
        claimed = payload.pop("case_id", None)
        case = handler(payload)
        if claimed_present and not isinstance(claimed, str):
            raise ValueError("serialized case_id must be a string")
        if claimed_present and claimed != case.case_id:
            raise ValueError("serialized case_id does not match the event")
        return case

    @computed_field  # type: ignore[prop-decorator]
    @property
    def case_id(self) -> str:
        return derive_case_id(self.event.event_id)

    @model_validator(mode="after")
    def validate_versions_and_timeline(self) -> Case:
        pack_versions = [pack.version for pack in self.evidence_packs]
        if pack_versions != list(range(1, len(pack_versions) + 1)):
            raise ValueError("evidence pack versions must be contiguous and start at one")
        seen_complete = False
        for pack in self.evidence_packs:
            if seen_complete and not pack.complete:
                raise ValueError("evidence pack completeness cannot regress")
            seen_complete = seen_complete or pack.complete
        verdict_versions = [verdict.version for verdict in self.verdicts]
        if verdict_versions != list(range(1, len(verdict_versions) + 1)):
            raise ValueError("verdict versions must be contiguous and start at one")
        screening_versions = [screening.version for screening in self.screening_results]
        if screening_versions != list(range(1, len(screening_versions) + 1)):
            raise ValueError("screening versions must be contiguous and start at one")
        review_versions = [review.version for review in self.procedural_reviews]
        if review_versions != list(range(1, len(review_versions) + 1)):
            raise ValueError("procedural review versions must be contiguous and start at one")
        sequences = [entry.sequence for entry in self.timeline]
        if sequences != list(range(len(sequences))):
            raise ValueError("timeline sequence must be contiguous and start at zero")
        if self.event.manifest_id != self.manifest_id:
            raise ValueError("case and event must use the same manifest")

        pack_keys: dict[tuple[str, int], EvidencePack] = {}
        for pack in self.evidence_packs:
            if pack.run_id != self.run_id:
                raise ValueError("evidence pack belongs to another run")
            if pack.case_id != self.case_id:
                raise ValueError("evidence pack belongs to another case")
            if pack.event.event_id != self.event.event_id:
                raise ValueError("evidence pack belongs to another event")
            if pack.manifest_id != self.manifest_id:
                raise ValueError("evidence pack uses another manifest")
            pack_keys[(pack.pack_id, pack.version)] = pack

        if self.status == CaseStatus.CANDIDATE and any(
            pack.complete for pack in self.evidence_packs
        ):
            raise ValueError("a candidate case cannot contain a complete evidence pack")
        if self.status == CaseStatus.EVIDENCE_READY and (
            not self.evidence_packs or not self.evidence_packs[-1].complete
        ):
            raise ValueError("EVIDENCE_READY requires a latest complete evidence pack")

        for screening in self.screening_results:
            if screening.run_id != self.run_id:
                raise ValueError("screening result belongs to another run")
            if screening.case_id != self.case_id:
                raise ValueError("screening result belongs to another case")
            screening_pack = pack_keys.get(
                (screening.evidence_pack_id, screening.evidence_pack_version)
            )
            if screening_pack is None:
                raise ValueError("screening result references an unknown evidence pack")
            if not screening_pack.complete:
                raise ValueError("screening result cannot reference an incomplete evidence pack")
            if screening.manifest_id != self.manifest_id:
                raise ValueError("screening result uses another manifest")
            if screening.authoritative_l1_score != screening_pack.event.l1_score:
                raise ValueError("screening L1 authority conflicts with its evidence pack")
            if screening.authoritative_evidence_class != screening_pack.event.evidence_class:
                raise ValueError(
                    "screening evidence-class authority conflicts with its evidence pack"
                )
            recovery_frame = screening_pack.confirmation_record.post_threshold_recovery_frame_id
            expected_correction_frames = (recovery_frame,) if recovery_frame is not None else ()
            if screening.correction_frame_ids != expected_correction_frames:
                raise ValueError("screening correction frames must match pack confirmation context")
            if screening_pack.event.evidence_class == EvidenceClass.ABSENCE:
                sufficiency = screening_pack.observation_sufficiency_input
                if sufficiency is None:
                    raise ValueError("absence pack is missing observation authority")
                expected_temporal_ids = tuple(
                    sorted(crop.crop_id for crop in screening_pack.temporal_crops)
                )
                expected_clear_ids = tuple(sorted(sufficiency.clear_crop_ids))
                if (
                    screening.alleged_interval_crop_ids != expected_temporal_ids
                    or screening.authoritative_clear_crop_ids != expected_clear_ids
                    or screening.required_clear_count != sufficiency.required_clear_count
                ):
                    raise ValueError(
                        "absence screening routing authority conflicts with its evidence pack"
                    )

        screening_by_id = {
            screening.screening_id: screening for screening in self.screening_results
        }
        verdict_by_version: dict[int, Verdict] = {}
        for verdict in self.verdicts:
            if verdict.run_id != self.run_id:
                raise ValueError("verdict belongs to another run")
            if verdict.case_id != self.case_id:
                raise ValueError("verdict belongs to another case")
            verdict_pack = pack_keys.get((verdict.evidence_pack_id, verdict.evidence_pack_version))
            if verdict_pack is None:
                raise ValueError("verdict references an unknown evidence pack")
            if not verdict_pack.complete:
                raise ValueError("verdict cannot reference an incomplete evidence pack")
            if verdict.manifest_id != self.manifest_id:
                raise ValueError("verdict uses another manifest")
            verdict_screening = screening_by_id.get(verdict.screening_id)
            if verdict_screening is None:
                raise ValueError("verdict references an unknown screening result")
            screening_pack = pack_keys[
                (
                    verdict_screening.evidence_pack_id,
                    verdict_screening.evidence_pack_version,
                )
            ]
            _require_verdict_pack_scope(self.evidence_packs, screening_pack, verdict_pack)
            verdict_by_version[verdict.version] = verdict

        for review in self.procedural_reviews:
            if review.run_id != self.run_id:
                raise ValueError("procedural review belongs to another run")
            if review.case_id != self.case_id:
                raise ValueError("procedural review belongs to another case")
            if review.manifest_id != self.manifest_id:
                raise ValueError("procedural review uses another manifest")
            reviewed_verdict = verdict_by_version.get(review.reviewed_verdict_version)
            if reviewed_verdict is None:
                raise ValueError("procedural review references an unknown verdict version")
            if (
                review.reviewed_verdict_id != reviewed_verdict.verdict_id
                or review.reviewed_verdict_sha256 != reviewed_verdict.verdict_sha256
                or review.evidence_pack_id != reviewed_verdict.evidence_pack_id
                or review.evidence_pack_version != reviewed_verdict.evidence_pack_version
            ):
                raise ValueError("procedural review does not bind its reviewed verdict")

        if self.status == CaseStatus.READY_FOR_ALERT_POLICY:
            if not self.verdicts or not self.procedural_reviews:
                raise ValueError("READY_FOR_ALERT_POLICY requires a verdict and procedural review")
            latest_verdict = self.verdicts[-1]
            latest_review = self.procedural_reviews[-1]
            if (
                latest_review.reviewed_verdict_version != latest_verdict.version
                or latest_review.reviewed_verdict_id != latest_verdict.verdict_id
                or not latest_review.passed
            ):
                raise ValueError(
                    "READY_FOR_ALERT_POLICY requires the latest verdict to pass review"
                )
        if self.status == CaseStatus.SCREENED and (
            not self.screening_results
            or self.screening_results[-1].decision == ScreeningDecision.ESCALATE
        ):
            raise ValueError("SCREENED requires a latest screening that does not escalate")
        if self.status == CaseStatus.ESCALATED and (
            not self.screening_results
            or self.screening_results[-1].decision != ScreeningDecision.ESCALATE
        ):
            raise ValueError("ESCALATED requires the latest screening to escalate")
        if self.status == CaseStatus.REWORK_REQUIRED:
            if not self.verdicts or not self.procedural_reviews:
                raise ValueError("REWORK_REQUIRED requires a failed procedural review")
            latest_verdict = self.verdicts[-1]
            latest_review = self.procedural_reviews[-1]
            if (
                latest_review.reviewed_verdict_version != latest_verdict.version
                or latest_review.reviewed_verdict_id != latest_verdict.verdict_id
                or latest_review.passed
            ):
                raise ValueError("REWORK_REQUIRED requires the latest verdict to fail review")
        if self.status == CaseStatus.BACKLOGGED:
            if self.current_backlog_item_id is None:
                raise ValueError("BACKLOGGED requires a current backlog item binding")
        elif self.current_backlog_item_id is not None:
            raise ValueError("only BACKLOGGED may bind a current backlog item")
        if self.status == CaseStatus.HUMAN_REVIEW and (
            not self.timeline or not _is_typed_human_review_entry(self.timeline[-1], self.case_id)
        ):
            raise ValueError(
                "HUMAN_REVIEW requires a typed evidence or exhausted-backlog transition"
            )

        if any(alert.case_id != self.case_id for alert in self.alerts):
            raise ValueError("alert belongs to another case")
        if any(appeal.case_id != self.case_id for appeal in self.appeals):
            raise ValueError("appeal belongs to another case")

        if self.final_decision is not None:
            terminal_appeals = [
                appeal
                for appeal in self.appeals
                if appeal.status in {AppealStatus.UPHELD, AppealStatus.OVERTURNED}
            ]
            expected_decision = (
                terminal_appeals[-1].resolved_decision
                if terminal_appeals
                else self.verdicts[-1].decision
                if self.verdicts
                else None
            )
            if expected_decision is None or self.final_decision != expected_decision:
                raise ValueError("final_decision does not match the latest terminal decision")
        return self

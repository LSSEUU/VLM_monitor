from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from labcourt.application.model_parser import parse_screening_response
from labcourt.application.procedural_review import DeterministicProceduralReviewVerifier
from labcourt.application.screening_coordinator import ScreeningCoordinator
from labcourt.application.screening_request import prepare_screening_request
from labcourt.config_loader import load_config
from labcourt.contracts.backlog import (
    BacklogCompletionReceipt,
    BacklogItem,
    BacklogLeaseIdentity,
    BacklogRetryContext,
    BacklogRetryFailure,
    BacklogRetrySuccess,
)
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.cases import Case, TimelineEntry
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import (
    ArtifactKind,
    AuditAction,
    BacklogReasonCode,
    BacklogStage,
    BacklogStatus,
    CaseStatus,
    CropSource,
    MediaAccess,
    MediaAvailability,
    MediaType,
    ModelParseStatus,
    PrivacyPolicy,
    PrivacyReasonCode,
    ProceduralDefectCode,
    UnknownReferenceSource,
    VlmCallPurpose,
    VlmRole,
)
from labcourt.contracts.events import CandidateEvent, derive_case_id
from labcourt.contracts.evidence import (
    Crop,
    EvidencePack,
    EvidencePackDraft,
    PrivacyReceipt,
    TrackSummary,
)
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.screening import (
    CachedModelResponse,
    ModelCacheEntry,
    ModelParseReceipt,
    ParsedScreeningOutput,
    ScreeningResult,
    StructureRepairRequest,
    VLMCallRequest,
    VLMResponse,
    derive_model_response_id,
)
from labcourt.contracts.storage import ArtifactRef, ClosureReport
from labcourt.contracts.verdicts import ProceduralReview, Verdict
from labcourt.domain.screening_router import ScreeningRoutePolicy, ScreeningRouter
from labcourt.exceptions import ConcurrentModification, ContractViolation, ProviderUnavailable
from labcourt.ports.evidence_repository import AuditHead, CaseSnapshot
from labcourt.ports.prompts import RenderedPrompt
from labcourt.ports.screening_repository import (
    M3BacklogRetryCommit,
    M3CaseCommit,
    ModelCallClaim,
    ModelCallClaimStatus,
    ModelCallFailureIntent,
)
from labcourt.services.m3 import build_screening_prompt_catalog

ROOT = Path(__file__).parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "m2"
RUN_ID = "run-01"


def _config() -> AppConfig:
    return load_config(ROOT / "configs" / "demo.yaml")


def _manifest() -> RunManifest:
    return RunManifest.model_validate_json(
        (FIXTURES / "run-manifest-fake.json").read_text(encoding="utf-8")
    )


def _event(manifest: RunManifest) -> CandidateEvent:
    payload = json.loads((FIXTURES / "candidate-event-presence.json").read_text(encoding="utf-8"))
    payload.pop("event_id", None)
    payload["manifest_id"] = manifest.manifest_id
    return CandidateEvent.model_validate(payload)


def _frame(event: CandidateEvent) -> FrameRef:
    return FrameRef(
        camera_id=event.camera_id,
        stream_id=event.stream_id,
        frame_index=event.trigger_frame,
        fps_num=30,
        fps_den=1,
        width=640,
        height=480,
        content_sha256="a" * 64,
    )


def _pack(manifest: RunManifest) -> EvidencePack:
    event = _event(manifest)
    frame = _frame(event)
    frame_ref = ArtifactRef(kind=ArtifactKind.FRAME, artifact_id=frame.frame_id)
    detection_ref = ArtifactRef(kind=ArtifactKind.DETECTION, artifact_id="det-focus-090")
    source_refs = tuple(sorted((detection_ref, frame_ref), key=lambda item: item.sort_key))
    media_sha256 = sha256_hex(["coordinator-test-media", event.event_id])
    crop = Crop(
        frame_id=frame.frame_id,
        source=CropSource.DETECTION_FOCUS,
        bbox=BBoxXYXY(x1=10, y1=20, x2=110, y2=220),
        source_refs=source_refs,
        local_path=f"{RUN_ID}/frames/{media_sha256}.png",
        availability=MediaAvailability.AVAILABLE,
        source_media_sha256=sha256_hex(["coordinator-source", event.event_id]),
        pixel_sha256=sha256_hex(["coordinator-pixels", event.event_id]),
        media_sha256=media_sha256,
        output_width=100,
        output_height=200,
        size_bytes=1_024,
        media_type=MediaType.IMAGE_PNG,
        encoding_version="png-v1",
        privacy_receipt=PrivacyReceipt(
            policy=PrivacyPolicy.FULL_REDACTION,
            transform_version="ppe-redaction-v1",
            media_access=MediaAccess.LOCAL_ONLY,
            reason_code=PrivacyReasonCode.POLICY_LOCAL_ONLY,
            input_refs=source_refs,
            fill_rgb=(0, 0, 0),
        ),
        primary_track_ref=event.primary_track_ref,
        tags={"zone_id": event.zone_id},
    )
    draft = EvidencePackDraft(
        run_id=RUN_ID,
        case_id=derive_case_id(event.event_id),
        version=1,
        event=event,
        key_frame_ids=(frame.frame_id,),
        focus_crops=(crop,),
        objective_facts=event.objective_facts,
        track_summary=TrackSummary(
            primary_track_ref=event.primary_track_ref,
            start_frame=event.start_frame,
            end_frame_exclusive=event.end_frame_exclusive,
            observed_frame_count=event.end_frame_exclusive - event.start_frame,
        ),
        confirmation_record=event.confirmation,
        manifest_id=manifest.manifest_id,
    )
    creation_closure = ClosureReport(
        run_id=draft.run_id,
        root_ref=ArtifactRef(kind=ArtifactKind.CASE, artifact_id=draft.case_id),
        manifest_id=draft.manifest_id,
        input_sha256=draft.closure_input_sha256,
        checked_refs=draft.expected_closure_refs(),
    )
    payload = draft.model_dump(mode="json", exclude={"pack_id"})
    payload["closure_report"] = creation_closure.model_dump(mode="json")
    return EvidencePack.model_validate(payload)


def _current_closure(pack: EvidencePack) -> ClosureReport:
    root = ArtifactRef(kind=ArtifactKind.EVIDENCE_PACK, artifact_id=pack.pack_id)
    refs = {item.sort_key: item for item in (*pack.expected_closure_refs(), root)}
    return ClosureReport(
        run_id=pack.run_id,
        root_ref=root,
        manifest_id=pack.manifest_id,
        input_sha256=pack.closure_input_sha256,
        checked_refs=tuple(refs[key] for key in sorted(refs)),
    )


def _case(pack: EvidencePack, status: CaseStatus = CaseStatus.EVIDENCE_READY) -> Case:
    return Case(
        run_id=pack.run_id,
        status=status,
        event=pack.event,
        evidence_packs=(pack,),
        manifest_id=pack.manifest_id,
    )


def _replace_case(snapshot: CaseSnapshot, **updates: object) -> CaseSnapshot:
    payload = snapshot.case.model_dump(mode="json")
    payload.update(updates)
    return CaseSnapshot(case=Case.model_validate(payload), revision=snapshot.revision + 1)


def _raw_payload(
    pack: EvidencePack,
    probability: float,
    *,
    unknown_reference: bool = False,
    missing_required_field: bool = False,
) -> bytes:
    crop_id = "fabricated-crop" if unknown_reference else pack.crops[0].crop_id
    fact = pack.objective_facts[0]
    payload: dict[str, object] = {
        "violation_type": pack.event.violation_type.value,
        "evidence_class": pack.event.evidence_class.value,
        "violation_probability": probability,
        "frame_observations": [],
        "evidence_citations": [
            {
                "evidence_ref": {"kind": "CROP", "artifact_id": crop_id},
                "bbox": None,
                "coordinate_space": None,
            }
        ],
        "objective_claims": [
            {
                "kind": fact.kind.value,
                "value": fact.value,
                "evidence_ref": {
                    "kind": "OBJECTIVE_FACT",
                    "artifact_id": fact.fact_id,
                },
            }
        ],
        "prosecution_summary": "The typed evidence supports deterministic screening.",
        "rationale_summary": "Only bounded structured claims are used.",
    }
    if missing_required_field:
        payload.pop("prosecution_summary")
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _response(request: VLMCallRequest, raw: bytes) -> VLMResponse:
    content_sha256 = hashlib.sha256(raw).hexdigest()
    response_id = derive_model_response_id(request.run_id, request.request_id, content_sha256)
    return VLMResponse(
        run_id=request.run_id,
        case_id=request.case_id,
        evidence_pack_id=request.evidence_pack_id,
        evidence_pack_version=request.evidence_pack_version,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        cache_key=request.cache_key,
        purpose=request.purpose,
        attempt_index=0 if request.purpose == VlmCallPurpose.SCREENING else 1,
        raw_response_ref=f"{request.run_id}/model_responses/{response_id}.json",
        content_sha256=content_sha256,
        size_bytes=len(raw),
        input_tokens=11,
        output_tokens=7,
        latency_ms=13,
        model_manifest_id=request.model_manifest_id,
        manifest_id=request.manifest_id,
    )


def _cache_entry(request: VLMCallRequest, response: VLMResponse) -> CachedModelResponse:
    entry = ModelCacheEntry(
        run_id=request.run_id,
        case_id=request.case_id,
        evidence_pack_id=request.evidence_pack_id,
        evidence_pack_version=request.evidence_pack_version,
        cache_key=request.cache_key,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        response_id=response.response_id,
        response_content_sha256=response.content_sha256,
        model_manifest_id=request.model_manifest_id,
        prompt_manifest_id=request.prompt_manifest.prompt_manifest_id,
        output_schema_sha256=request.prompt_manifest.output_schema_sha256,
        manifest_id=request.manifest_id,
    )
    return CachedModelResponse(entry=entry, response=response)


class _ResponseStore:
    def __init__(self) -> None:
        self.raw_by_response: dict[str, bytes] = {}
        self.journal_by_request: dict[str, VLMResponse] = {}
        self.verify_calls: list[str] = []

    def persist(self, response: VLMResponse, raw: bytes) -> None:
        self.raw_by_response[response.response_id] = raw
        self.journal_by_request[response.request_id] = response

    def probe_recovery(self, request: VLMCallRequest) -> VLMResponse | None:
        return self.recover(request)

    def recover(self, request: VLMCallRequest) -> VLMResponse | None:
        response = self.journal_by_request.get(request.request_id)
        if response is not None:
            self.verify(request.run_id, response)
        return response

    def acknowledge(self, request: VLMCallRequest, response: VLMResponse) -> None:
        journaled = self.journal_by_request.get(request.request_id)
        if journaled is None:
            return
        assert journaled == response
        del self.journal_by_request[request.request_id]

    def verify(self, run_id: str, response: VLMResponse) -> VLMResponse:
        assert run_id == response.run_id
        raw = self.raw_by_response[response.response_id]
        assert hashlib.sha256(raw).hexdigest() == response.content_sha256
        assert len(raw) == response.size_bytes
        self.verify_calls.append(response.response_id)
        return response

    def verify_raw_response(
        self,
        run_id: str,
        request: VLMCallRequest,
        response: VLMResponse,
    ) -> VLMResponse:
        assert request.run_id == run_id
        assert request.request_id == response.request_id
        assert request.request_sha256 == response.request_sha256
        assert request.cache_key == response.cache_key
        return self.verify(run_id, response)

    def read_bytes(self, run_id: str, response: VLMResponse, max_bytes: int) -> bytes:
        assert run_id == response.run_id
        raw = self.raw_by_response[response.response_id]
        assert len(raw) <= max_bytes
        return raw

    def read_json(self, run_id: str, response: VLMResponse, max_bytes: int) -> str:
        return self.read_bytes(run_id, response, max_bytes).decode("utf-8")


class _VLM:
    def __init__(
        self,
        store: _ResponseStore,
        results: list[bytes | Exception] | None = None,
    ) -> None:
        self.store = store
        self.results = results or []
        self.calls: list[VLMCallRequest] = []

    def complete(self, request: VLMCallRequest) -> VLMResponse:
        self.calls.append(request)
        result = self.results[len(self.calls) - 1]
        if isinstance(result, Exception):
            raise result
        response = _response(request, result)
        # The provider/store boundary persists bytes before returning its receipt.
        self.store.persist(response, result)
        return response


class _Prompts:
    def __init__(self) -> None:
        self.values: list[RenderedPrompt] = []

    def register(self, prompt: RenderedPrompt) -> None:
        self.values.append(prompt)


class _Evidence:
    def __init__(
        self,
        snapshot: CaseSnapshot,
        pack: EvidencePack,
        manifest: RunManifest,
        *,
        mutate_revision_on_load: int | None = None,
    ) -> None:
        self.snapshot = snapshot
        self.pack = pack
        self.manifest = manifest
        self.closure = _current_closure(pack)
        self.frame = _frame(pack.event)
        self.load_case_calls = 0
        self.mutate_revision_on_load = mutate_revision_on_load
        self.load_hook_at: int | None = None
        self.load_hook: Callable[[], None] | None = None
        self.audit_head = AuditHead(
            run_id=pack.run_id,
            manifest_id=pack.manifest_id,
            run_revision=1,
            sequence=1,
            entry_hash="b" * 64,
        )

    def load_case(self, run_id: str, case_id: str) -> CaseSnapshot:
        assert (run_id, case_id) == (self.pack.run_id, self.pack.case_id)
        self.load_case_calls += 1
        if self.load_case_calls == self.mutate_revision_on_load:
            self.snapshot = CaseSnapshot(
                case=self.snapshot.case,
                revision=self.snapshot.revision + 1,
            )
        if self.load_case_calls == self.load_hook_at and self.load_hook is not None:
            self.load_hook()
        return self.snapshot

    def load_pack(self, run_id: str, pack_id: str) -> EvidencePack:
        assert (run_id, pack_id) == (self.pack.run_id, self.pack.pack_id)
        return self.pack

    def verify_current_pack(self, run_id: str, pack_id: str) -> ClosureReport:
        assert (run_id, pack_id) == (self.pack.run_id, self.pack.pack_id)
        return self.closure

    def load_run_manifest(self, run_id: str) -> RunManifest:
        assert run_id == self.pack.run_id
        return self.manifest

    def load_frame(self, run_id: str, frame_id: str) -> FrameRef:
        assert (run_id, frame_id) == (self.pack.run_id, self.frame.frame_id)
        return self.frame

    def get_audit_head(self, run_id: str) -> AuditHead:
        assert run_id == self.pack.run_id
        return self.audit_head

    def advance_audit(self) -> None:
        self.audit_head = AuditHead(
            run_id=self.audit_head.run_id,
            manifest_id=self.audit_head.manifest_id,
            run_revision=self.audit_head.run_revision + 1,
            sequence=self.audit_head.sequence + 1,
            entry_hash=sha256_hex(["test-audit", self.audit_head.sequence + 1]),
        )


class _ScreeningRepository:
    def __init__(
        self,
        evidence: _Evidence,
        store: _ResponseStore,
        *,
        response_mode: str = "provider",
        recovered_raw: bytes | None = None,
        fail_first_screening_commit: bool = False,
    ) -> None:
        self.evidence = evidence
        self.store = store
        self.response_mode = response_mode
        self.recovered_raw = recovered_raw
        self.fail_first_screening_commit = fail_first_screening_commit
        self._last_request: VLMCallRequest | None = None
        self.cache: dict[str, CachedModelResponse] = {}
        self.raw_responses: dict[str, VLMResponse] = {}
        self.claims: dict[str, tuple[VLMCallRequest, str, VLMResponse | None]] = {}
        self.parse_receipts: list[ModelParseReceipt] = []
        self.parse_history: dict[str, tuple[ModelParseReceipt, ...]] = {}
        self.backlog_items: dict[str, BacklogItem] = {}
        self.append_raw_calls = 0
        self.put_calls = 0
        self.commit_screening_calls: list[tuple[int, AuditHead]] = []
        self.commit_verdict_calls = 0
        self.commit_backlog_calls = 0
        self.commit_backlog_retry_calls = 0

    def _ensure_seeded_response(self, request: VLMCallRequest) -> CachedModelResponse:
        cached = self.cache.get(request.cache_key)
        if cached is not None:
            return cached
        assert self.recovered_raw is not None
        response = _response(request, self.recovered_raw)
        self.store.persist(response, self.recovered_raw)
        cached = _cache_entry(request, response)
        if self.response_mode == "cache":
            self.cache[request.cache_key] = cached
            self.store.journal_by_request.pop(request.request_id, None)
        self.raw_responses[response.response_id] = response
        return cached

    def get(self, run_id: str, request: VLMCallRequest) -> CachedModelResponse | None:
        assert run_id == request.run_id
        self._last_request = request
        if self.response_mode == "cache":
            return self._ensure_seeded_response(request)
        return self.cache.get(request.cache_key)

    def put(
        self,
        run_id: str,
        request: VLMCallRequest,
        response: VLMResponse,
    ) -> CachedModelResponse:
        assert run_id == request.run_id
        value = _cache_entry(request, response)
        if request.cache_key not in self.cache:
            self.cache[request.cache_key] = value
            self.put_calls += 1
        return value

    def append_raw_response(self, response: VLMResponse) -> VLMResponse:
        if response.response_id not in self.raw_responses:
            self.raw_responses[response.response_id] = response
            self.append_raw_calls += 1
        return response

    def load_raw_response(self, run_id: str, response_id: str) -> VLMResponse:
        response = self.raw_responses[response_id]
        assert response.run_id == run_id
        return response

    def claim_model_call(
        self,
        run_id: str,
        request: VLMCallRequest,
        owner_token: str,
        backlog_lease: BacklogLeaseIdentity | None = None,
    ) -> ModelCallClaim:
        assert run_id == request.run_id
        if request.backlog_retry_context is not None:
            assert backlog_lease is not None
            assert backlog_lease.item_id == request.backlog_retry_context.backlog_item_id
            assert backlog_lease.retry_generation == (
                request.backlog_retry_context.retry_generation
            )
        else:
            assert backlog_lease is None
        expiry = datetime.now(UTC) + timedelta(seconds=request.budget.claim_lease_seconds)
        existing = self.claims.get(request.request_id)
        if existing is None:
            self.claims[request.request_id] = (request, owner_token, None)
            return ModelCallClaim(
                ModelCallClaimStatus.ACQUIRED,
                request.request_id,
                expiry,
            )
        stored_request, stored_owner, response = existing
        assert stored_request == request
        if response is not None:
            return ModelCallClaim(
                ModelCallClaimStatus.COMPLETED,
                request.request_id,
                response_id=response.response_id,
            )
        if stored_owner == owner_token:
            return ModelCallClaim(ModelCallClaimStatus.ACQUIRED, request.request_id, expiry)
        return ModelCallClaim(ModelCallClaimStatus.WAITING, request.request_id, expiry)

    def complete_model_call(
        self,
        run_id: str,
        request: VLMCallRequest,
        response: VLMResponse,
        owner_token: str,
    ) -> CachedModelResponse:
        stored_request, stored_owner, completed = self.claims[request.request_id]
        assert (run_id, stored_request, stored_owner) == (request.run_id, request, owner_token)
        if completed is not None:
            assert completed == response
        self.append_raw_response(response)
        cached = self.put(run_id, request, response)
        self.claims[request.request_id] = (request, owner_token, response)
        return cached

    def load_raw_response_for_request(
        self,
        run_id: str,
        request_id: str,
    ) -> VLMResponse | None:
        if self.response_mode == "recover":
            assert self._last_request is not None
            assert (run_id, request_id) == (
                self._last_request.run_id,
                self._last_request.request_id,
            )
            return self._ensure_seeded_response(self._last_request).response
        return next(
            (
                response
                for response in self.raw_responses.values()
                if response.run_id == run_id and response.request_id == request_id
            ),
            None,
        )

    def append_parse_receipt(
        self,
        receipt: ModelParseReceipt,
        parsed_output: ParsedScreeningOutput | None = None,
    ) -> ModelParseReceipt:
        self.parse_receipts.append(receipt)
        if parsed_output is not None:
            self.parse_history[parsed_output.parsed_output_id] = tuple(self.parse_receipts)
        return receipt

    def load_parse_history_for_output(
        self,
        run_id: str,
        parsed_output_id: str,
    ) -> tuple[ModelParseReceipt, ...]:
        assert run_id == self.evidence.pack.run_id
        return self.parse_history[parsed_output_id]

    def commit_screening(
        self,
        run_id: str,
        expected_revision: int,
        expected_audit_head: AuditHead,
        current_pack_closure: ClosureReport,
        screening: ScreeningResult,
    ) -> M3CaseCommit:
        assert run_id == self.evidence.pack.run_id
        assert current_pack_closure == self.evidence.closure
        self.commit_screening_calls.append((expected_revision, expected_audit_head))
        if self.fail_first_screening_commit and len(self.commit_screening_calls) == 1:
            self.evidence.advance_audit()
            raise ConcurrentModification("audit head advanced")
        assert expected_revision == self.evidence.snapshot.revision
        assert expected_audit_head == self.evidence.audit_head
        status = (
            CaseStatus.ESCALATED if screening.decision.value == "ESCALATE" else CaseStatus.SCREENED
        )
        self.evidence.snapshot = _replace_case(
            self.evidence.snapshot,
            status=status.value,
            screening_results=[
                *self.evidence.snapshot.case.model_dump(mode="json")["screening_results"],
                screening.model_dump(mode="json"),
            ],
        )
        self.evidence.advance_audit()
        return M3CaseCommit(case=self.evidence.snapshot, created=True)

    def commit_verdict_review(
        self,
        run_id: str,
        expected_revision: int,
        expected_audit_head: AuditHead,
        current_pack_closure: ClosureReport,
        verdict: Verdict,
        review: ProceduralReview,
    ) -> M3CaseCommit:
        assert run_id == self.evidence.pack.run_id
        assert expected_revision == self.evidence.snapshot.revision
        assert expected_audit_head == self.evidence.audit_head
        assert current_pack_closure == self.evidence.closure
        self.commit_verdict_calls += 1
        status = CaseStatus.READY_FOR_ALERT_POLICY if review.passed else CaseStatus.REWORK_REQUIRED
        current = self.evidence.snapshot.case.model_dump(mode="json")
        self.evidence.snapshot = _replace_case(
            self.evidence.snapshot,
            status=status.value,
            verdicts=[*current["verdicts"], verdict.model_dump(mode="json")],
            procedural_reviews=[
                *current["procedural_reviews"],
                review.model_dump(mode="json"),
            ],
        )
        self.evidence.advance_audit()
        return M3CaseCommit(case=self.evidence.snapshot, created=True)

    def commit_backlog(
        self,
        run_id: str,
        expected_revision: int,
        expected_audit_head: AuditHead,
        current_pack_closure: ClosureReport,
        item: BacklogItem,
        response_ids: tuple[str, ...] = (),
        model_call_failure: ModelCallFailureIntent | None = None,
    ) -> M3CaseCommit:
        del model_call_failure
        assert run_id == self.evidence.pack.run_id
        assert expected_revision == self.evidence.snapshot.revision
        assert expected_audit_head == self.evidence.audit_head
        assert current_pack_closure == self.evidence.closure
        assert all(response_id in self.raw_responses for response_id in response_ids)
        self.commit_backlog_calls += 1
        self.backlog_items[item.item_id] = item
        self.evidence.snapshot = _replace_case(
            self.evidence.snapshot,
            status=CaseStatus.BACKLOGGED.value,
            current_backlog_item_id=item.item_id,
        )
        self.evidence.advance_audit()
        return M3CaseCommit(case=self.evidence.snapshot, created=True)

    def commit_backlog_screening_success(
        self,
        run_id: str,
        expected_revision: int,
        expected_audit_head: AuditHead,
        current_pack_closure: ClosureReport,
        success: BacklogRetrySuccess,
        screening: ScreeningResult,
    ) -> M3BacklogRetryCommit:
        assert run_id == self.evidence.pack.run_id
        assert expected_revision == self.evidence.snapshot.revision
        assert expected_audit_head == self.evidence.audit_head
        assert current_pack_closure == self.evidence.closure
        current = self.backlog_items[success.lease.item_id]
        updated = BacklogItem.model_validate(
            {
                **current.model_dump(mode="json", exclude_computed_fields=True),
                "status": BacklogStatus.COMPLETED.value,
                "lease_id": None,
                "lease_owner_sha256": None,
                "lease_expires_at": None,
            }
        )
        case_payload = self.evidence.snapshot.case.model_dump(mode="json")
        self.evidence.snapshot = _replace_case(
            self.evidence.snapshot,
            status=CaseStatus.ESCALATED.value,
            current_backlog_item_id=None,
            screening_results=[
                *case_payload["screening_results"],
                screening.model_dump(mode="json"),
            ],
        )
        self.evidence.advance_audit()
        receipt = BacklogCompletionReceipt(
            outcome=success,
            backlog_status=BacklogStatus.COMPLETED,
            completion_ref=success.completion_ref,
            completion_case_status=CaseStatus.ESCALATED,
            completion_case_revision=self.evidence.snapshot.revision,
            completion_audit_sequence=self.evidence.audit_head.sequence,
            completion_audit_entry_hash=self.evidence.audit_head.entry_hash,
            manifest_id=success.manifest_id,
        )
        self.backlog_items[updated.item_id] = updated
        self.commit_backlog_retry_calls += 1
        return M3BacklogRetryCommit(
            case=self.evidence.snapshot,
            item=updated,
            receipt=receipt,
            created=True,
        )

    def commit_backlog_verdict_review_success(
        self,
        run_id: str,
        expected_revision: int,
        expected_audit_head: AuditHead,
        current_pack_closure: ClosureReport,
        success: BacklogRetrySuccess,
        verdict: Verdict,
        review: ProceduralReview,
        screening: ScreeningResult | None = None,
    ) -> M3BacklogRetryCommit:
        assert run_id == self.evidence.pack.run_id
        assert expected_revision == self.evidence.snapshot.revision
        assert expected_audit_head == self.evidence.audit_head
        assert current_pack_closure == self.evidence.closure
        current = self.backlog_items[success.lease.item_id]
        updated = BacklogItem.model_validate(
            {
                **current.model_dump(mode="json", exclude_computed_fields=True),
                "status": BacklogStatus.COMPLETED.value,
                "lease_id": None,
                "lease_owner_sha256": None,
                "lease_expires_at": None,
            }
        )
        case_payload = self.evidence.snapshot.case.model_dump(mode="json")
        screenings = list(case_payload["screening_results"])
        if screening is not None:
            screenings.append(screening.model_dump(mode="json"))
        target = CaseStatus.READY_FOR_ALERT_POLICY if review.passed else CaseStatus.REWORK_REQUIRED
        self.evidence.snapshot = _replace_case(
            self.evidence.snapshot,
            status=target.value,
            current_backlog_item_id=None,
            screening_results=screenings,
            verdicts=[*case_payload["verdicts"], verdict.model_dump(mode="json")],
            procedural_reviews=[
                *case_payload["procedural_reviews"],
                review.model_dump(mode="json"),
            ],
        )
        self.evidence.advance_audit()
        receipt = BacklogCompletionReceipt(
            outcome=success,
            backlog_status=BacklogStatus.COMPLETED,
            completion_ref=success.completion_ref,
            completion_case_status=target,
            completion_case_revision=self.evidence.snapshot.revision,
            completion_audit_sequence=self.evidence.audit_head.sequence,
            completion_audit_entry_hash=self.evidence.audit_head.entry_hash,
            manifest_id=success.manifest_id,
        )
        self.backlog_items[updated.item_id] = updated
        self.commit_backlog_retry_calls += 1
        return M3BacklogRetryCommit(
            case=self.evidence.snapshot,
            item=updated,
            receipt=receipt,
            created=True,
        )

    def commit_backlog_retry_failure(
        self,
        run_id: str,
        expected_revision: int,
        expected_audit_head: AuditHead,
        current_pack_closure: ClosureReport,
        failure: BacklogRetryFailure,
        model_call_failure: ModelCallFailureIntent | None = None,
    ) -> M3BacklogRetryCommit:
        del model_call_failure
        assert run_id == self.evidence.pack.run_id
        assert expected_revision == self.evidence.snapshot.revision
        assert expected_audit_head == self.evidence.audit_head
        assert current_pack_closure == self.evidence.closure
        current = self.backlog_items[failure.lease.item_id]
        updated = BacklogItem.model_validate(
            {
                **current.model_dump(mode="json", exclude_computed_fields=True),
                "retry_generation": failure.next_retry_generation,
                "status": failure.next_status.value,
                "lease_id": None,
                "lease_owner_sha256": None,
                "lease_expires_at": None,
            }
        )
        self.evidence.snapshot = _replace_case(
            self.evidence.snapshot,
            status=failure.completion_case_status.value,
            current_backlog_item_id=(
                current.item_id if failure.next_status == BacklogStatus.PENDING else None
            ),
            timeline=[
                *self.evidence.snapshot.case.model_dump(mode="json")["timeline"],
                TimelineEntry(
                    sequence=len(self.evidence.snapshot.case.timeline),
                    action=AuditAction.CASE_STATE_CHANGED.value,
                    stage="BACKLOG",
                    object_ref=current.item_id,
                    details={
                        "outcome": "FAILURE",
                        "reason_code": failure.reason_code.value,
                        "status": failure.next_status.value,
                        "retry_generation": failure.next_retry_generation,
                    },
                ).model_dump(mode="json"),
            ],
        )
        self.evidence.advance_audit()
        completion_ref = ArtifactRef(
            kind=ArtifactKind.BACKLOG_ITEM,
            artifact_id=current.item_id,
        )
        receipt = BacklogCompletionReceipt(
            outcome=failure,
            backlog_status=failure.next_status,
            completion_ref=completion_ref,
            completion_case_status=failure.completion_case_status,
            completion_case_revision=self.evidence.snapshot.revision,
            completion_audit_sequence=self.evidence.audit_head.sequence,
            completion_audit_entry_hash=self.evidence.audit_head.entry_hash,
            manifest_id=failure.manifest_id,
        )
        self.backlog_items[updated.item_id] = updated
        self.commit_backlog_retry_calls += 1
        return M3BacklogRetryCommit(
            case=self.evidence.snapshot,
            item=updated,
            receipt=receipt,
            created=True,
        )

    def load_backlog_item(self, run_id: str, item_id: str) -> BacklogItem:
        assert run_id == self.evidence.pack.run_id
        return self.backlog_items[item_id]

    def load_case(self, run_id: str, case_id: str) -> CaseSnapshot:
        assert (run_id, case_id) == (
            self.evidence.pack.run_id,
            self.evidence.pack.case_id,
        )
        return self.evidence.snapshot


@dataclass(slots=True)
class _Harness:
    config: AppConfig
    manifest: RunManifest
    pack: EvidencePack
    evidence: _Evidence
    repository: _ScreeningRepository
    store: _ResponseStore
    vlm: _VLM
    prompts: _Prompts
    review_verifier: DeterministicProceduralReviewVerifier
    coordinator: ScreeningCoordinator


def _harness(
    *,
    results: list[bytes | Exception] | None = None,
    response_mode: str = "provider",
    recovered_raw: bytes | None = None,
    snapshot: CaseSnapshot | None = None,
    mutate_revision_on_load: int | None = None,
    fail_first_screening_commit: bool = False,
) -> _Harness:
    config = _config()
    manifest = _manifest()
    pack = _pack(manifest)
    evidence = _Evidence(
        snapshot or CaseSnapshot(case=_case(pack), revision=2),
        pack,
        manifest,
        mutate_revision_on_load=mutate_revision_on_load,
    )
    store = _ResponseStore()
    repository = _ScreeningRepository(
        evidence,
        store,
        response_mode=response_mode,
        recovered_raw=recovered_raw,
        fail_first_screening_commit=fail_first_screening_commit,
    )
    vlm = _VLM(store, results)
    prompts = _Prompts()
    catalog = build_screening_prompt_catalog(manifest)
    review_verifier = DeterministicProceduralReviewVerifier(config, evidence)
    coordinator = ScreeningCoordinator(
        config=config,
        evidence_repository=evidence,
        screening_repository=repository,
        response_store=store,
        vlm_client=vlm,
        prompt_catalog=catalog,
        prompt_registrar=prompts,
        procedural_review_verifier=review_verifier,
    )
    return _Harness(
        config,
        manifest,
        pack,
        evidence,
        repository,
        store,
        vlm,
        prompts,
        review_verifier,
        coordinator,
    )


def _screening_fixture(
    harness: _Harness,
    probability: float,
) -> tuple[ScreeningResult, ModelParseReceipt]:
    catalog = build_screening_prompt_catalog(harness.manifest)
    request = prepare_screening_request(
        harness.pack,
        harness.config,
        harness.manifest,
        catalog,
    ).request
    raw = _raw_payload(harness.pack, probability)
    response = _response(request, raw)
    harness.store.persist(response, raw)
    harness.repository.raw_responses[response.response_id] = response
    parsed = parse_screening_response(raw, request=request, response=response)
    assert parsed.output is not None
    policy = ScreeningRoutePolicy(
        low_probability=harness.config.screening.low_probability,
        high_probability=harness.config.screening.high_probability,
        strong_signal_threshold=harness.config.screening.strong_signal_threshold,
        router_version=harness.config.screening.router_version,
        conflict_policy_version=harness.config.screening.conflict_policy_version,
    )
    screening = ScreeningRouter(policy).route(parsed.output, harness.pack)
    return screening, parsed.receipt


def _leased_backlog_item(
    harness: _Harness,
    *,
    reason: BacklogReasonCode = BacklogReasonCode.PROVIDER_UNAVAILABLE,
    max_attempts: int = 3,
) -> BacklogItem:
    pending = BacklogItem(
        run_id=RUN_ID,
        case_id=harness.pack.case_id,
        stage=BacklogStage.SCREENING,
        role=VlmRole.SCREENING,
        reason_code=reason,
        stage_input_ref=ArtifactRef(
            kind=ArtifactKind.EVIDENCE_PACK,
            artifact_id=harness.pack.pack_id,
        ),
        stage_input_sha256=sha256_hex(harness.pack.model_dump(mode="json")),
        max_attempts=max_attempts,
        retry_generation=(1 if reason == BacklogReasonCode.MODEL_OUTPUT_INVALID else 0),
        manifest_id=harness.manifest.manifest_id,
    )
    leased = BacklogItem.model_validate(
        {
            **pending.model_dump(mode="json", exclude_computed_fields=True),
            "attempt_count": 1,
            "status": BacklogStatus.LEASED.value,
            "lease_id": "4" * 64,
            "lease_owner_sha256": "5" * 64,
            "lease_expires_at": "2026-07-28T12:05:00Z",
        }
    )
    harness.repository.backlog_items[leased.item_id] = leased
    harness.evidence.snapshot = _replace_case(
        harness.evidence.snapshot,
        status=CaseStatus.BACKLOGGED.value,
        current_backlog_item_id=leased.item_id,
    )
    return leased


def test_existing_escalated_case_is_terminal_and_has_no_side_effects() -> None:
    harness = _harness()
    screening, _ = _screening_fixture(harness, 0.5)
    harness.evidence.snapshot = _replace_case(
        harness.evidence.snapshot,
        status=CaseStatus.ESCALATED.value,
        screening_results=[screening.model_dump(mode="json")],
    )

    outcome = harness.coordinator.process_case(RUN_ID, harness.pack.case_id)

    assert outcome.case == harness.evidence.snapshot
    assert outcome.screening_result == screening
    assert harness.vlm.calls == []
    assert harness.prompts.values == []
    assert harness.repository.commit_screening_calls == []


def test_backlogged_case_is_returned_without_bypassing_its_retry_boundary() -> None:
    harness = _harness()
    item = BacklogItem(
        run_id=RUN_ID,
        case_id=harness.pack.case_id,
        stage=BacklogStage.SCREENING,
        role=VlmRole.SCREENING,
        reason_code=BacklogReasonCode.PROVIDER_UNAVAILABLE,
        stage_input_ref=ArtifactRef(
            kind=ArtifactKind.EVIDENCE_PACK,
            artifact_id=harness.pack.pack_id,
        ),
        stage_input_sha256=sha256_hex(harness.pack.model_dump(mode="json")),
        max_attempts=3,
        manifest_id=harness.manifest.manifest_id,
    )
    harness.repository.backlog_items[item.item_id] = item
    harness.evidence.snapshot = _replace_case(
        harness.evidence.snapshot,
        status=CaseStatus.BACKLOGGED.value,
        current_backlog_item_id=item.item_id,
    )

    outcome = harness.coordinator.process_case(RUN_ID, harness.pack.case_id)

    assert outcome.backlog_item == item
    assert harness.vlm.calls == []
    assert harness.repository.commit_backlog_calls == 0


def test_revision_change_during_request_setup_backlogs_without_provider_call() -> None:
    harness = _harness(
        results=[_raw_payload(_pack(_manifest()), 0.95)],
        mutate_revision_on_load=2,
    )

    outcome = harness.coordinator.process_case(RUN_ID, harness.pack.case_id)

    assert outcome.backlog_item is not None
    assert outcome.backlog_item.reason_code == BacklogReasonCode.CURRENT_PACK_CHANGED
    assert harness.vlm.calls == []
    assert harness.repository.append_raw_calls == 0
    assert harness.repository.commit_backlog_calls == 1


def test_concurrent_screening_progress_is_resumed_instead_of_backlogged() -> None:
    harness = _harness()
    screening, receipt = _screening_fixture(harness, 0.95)
    harness.repository.parse_history[screening.parsed_output.parsed_output_id] = (receipt,)

    def complete_screening_elsewhere() -> None:
        harness.evidence.snapshot = _replace_case(
            harness.evidence.snapshot,
            status=CaseStatus.SCREENED.value,
            screening_results=[screening.model_dump(mode="json")],
        )
        harness.evidence.advance_audit()

    harness.evidence.load_hook_at = 2
    harness.evidence.load_hook = complete_screening_elsewhere

    outcome = harness.coordinator.process_case(RUN_ID, harness.pack.case_id)

    assert outcome.case.case.status == CaseStatus.READY_FOR_ALERT_POLICY
    assert outcome.verdict is not None
    assert outcome.procedural_review is not None
    assert harness.vlm.calls == []
    assert harness.repository.commit_screening_calls == []
    assert harness.repository.commit_backlog_calls == 0
    assert harness.repository.commit_verdict_calls == 1


@pytest.mark.parametrize(
    ("mode", "expected_cache_hits", "expected_recovered"),
    [("cache", 1, 0), ("recover", 0, 1)],
)
def test_cache_and_raw_before_cache_recovery_never_recall_provider(
    mode: str,
    expected_cache_hits: int,
    expected_recovered: int,
) -> None:
    manifest = _manifest()
    raw = _raw_payload(_pack(manifest), 0.5)
    harness = _harness(response_mode=mode, recovered_raw=raw)

    outcome = harness.coordinator.process_case(RUN_ID, harness.pack.case_id)

    assert outcome.case.case.status == CaseStatus.ESCALATED
    assert outcome.cache_hit_count == expected_cache_hits
    assert outcome.recovered_response_count == expected_recovered
    assert harness.vlm.calls == []
    assert harness.repository.append_raw_calls == 0
    assert harness.repository.put_calls == expected_recovered
    assert len(harness.repository.parse_receipts) == 1


def test_direct_parse_commits_screening_verdict_and_real_l5_review() -> None:
    manifest = _manifest()
    raw = _raw_payload(_pack(manifest), 0.95)
    harness = _harness(results=[raw])

    outcome = harness.coordinator.process_case(RUN_ID, harness.pack.case_id)

    assert outcome.screening_result is not None
    assert outcome.verdict is not None
    assert outcome.procedural_review is not None
    assert outcome.procedural_review.passed
    assert outcome.case.case.status == CaseStatus.READY_FOR_ALERT_POLICY
    assert harness.repository.append_raw_calls == 1
    assert len(harness.repository.parse_receipts) == 1
    assert len(harness.repository.commit_screening_calls) == 1
    assert harness.repository.commit_verdict_calls == 1
    assert [call.purpose for call in harness.vlm.calls] == [VlmCallPurpose.SCREENING]


def test_gray_probability_commits_only_escalated_screening() -> None:
    manifest = _manifest()
    raw = _raw_payload(_pack(manifest), 0.5)
    harness = _harness(results=[raw])

    outcome = harness.coordinator.process_case(RUN_ID, harness.pack.case_id)

    assert outcome.case.case.status == CaseStatus.ESCALATED
    assert outcome.screening_result is not None
    assert outcome.verdict is None
    assert harness.repository.commit_verdict_calls == 0


def test_provider_outage_atomically_commits_only_a_typed_backlog() -> None:
    harness = _harness(results=[ProviderUnavailable("offline")])

    outcome = harness.coordinator.process_case(RUN_ID, harness.pack.case_id)

    assert outcome.backlog_item is not None
    assert outcome.backlog_item.reason_code == BacklogReasonCode.PROVIDER_UNAVAILABLE
    assert outcome.backlog_item.role == VlmRole.SCREENING
    assert outcome.case.case.status == CaseStatus.BACKLOGGED
    assert harness.repository.append_raw_calls == 0
    assert harness.repository.parse_receipts == []
    assert harness.repository.commit_screening_calls == []
    assert harness.repository.commit_verdict_calls == 0
    assert harness.repository.commit_backlog_calls == 1


def test_two_malformed_responses_end_in_model_output_invalid_backlog() -> None:
    harness = _harness(results=[b"not-json", b"still-not-json"])

    outcome = harness.coordinator.process_case(RUN_ID, harness.pack.case_id)

    assert outcome.backlog_item is not None
    assert outcome.backlog_item.reason_code == BacklogReasonCode.MODEL_OUTPUT_INVALID
    assert outcome.backlog_item.role == VlmRole.STRUCTURE_REPAIR
    assert [receipt.status for receipt in harness.repository.parse_receipts] == [
        ModelParseStatus.REPAIR_REQUIRED,
        ModelParseStatus.INVALID_FINAL,
    ]
    assert [call.purpose for call in harness.vlm.calls] == [
        VlmCallPurpose.SCREENING,
        VlmCallPurpose.STRUCTURE_REPAIR,
    ]
    assert harness.repository.commit_screening_calls == []


def test_screened_crash_resume_runs_only_verdict_and_gate() -> None:
    harness = _harness()
    screening, receipt = _screening_fixture(harness, 0.95)
    harness.repository.parse_history[screening.parsed_output.parsed_output_id] = (receipt,)
    harness.evidence.snapshot = _replace_case(
        harness.evidence.snapshot,
        status=CaseStatus.SCREENED.value,
        screening_results=[screening.model_dump(mode="json")],
    )

    outcome = harness.coordinator.process_case(RUN_ID, harness.pack.case_id)

    assert outcome.verdict is not None
    assert outcome.procedural_review is not None
    assert outcome.case.case.status == CaseStatus.READY_FOR_ALERT_POLICY
    assert harness.vlm.calls == []
    assert harness.prompts.values == []
    assert harness.repository.append_raw_calls == 0
    assert harness.repository.commit_screening_calls == []
    assert harness.repository.commit_verdict_calls == 1


def test_attempt_zero_unknown_reference_survives_successful_repair_into_l5(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _manifest()
    pack = _pack(manifest)
    invalid = _raw_payload(
        pack,
        0.95,
        unknown_reference=True,
        missing_required_field=True,
    )
    repaired = _raw_payload(pack, 0.95)
    harness = _harness(results=[invalid, repaired])
    captured: list[tuple[ModelParseReceipt, ...]] = []
    real_rebuild = harness.review_verifier.rebuild_review

    def _capturing_rebuild(**kwargs: object) -> ProceduralReview:
        history = kwargs["parse_history"]
        assert isinstance(history, tuple)
        captured.append(history)
        return real_rebuild(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(harness.review_verifier, "rebuild_review", _capturing_rebuild)

    outcome = harness.coordinator.process_case(RUN_ID, harness.pack.case_id)

    assert outcome.repair_attempted
    assert len(captured) == 1
    attempts = tuple(
        attempt for receipt in captured[0] for attempt in receipt.unknown_reference_attempts
    )
    assert len(attempts) == 1
    assert attempts[0].source == UnknownReferenceSource.EVIDENCE_CITATION_REF
    assert outcome.procedural_review is not None
    assert ProceduralDefectCode.FABRICATED_EVIDENCE_REFERENCE in {
        defect.code for defect in outcome.procedural_review.defects
    }
    assert outcome.case.case.status == CaseStatus.REWORK_REQUIRED
    assert len(harness.repository.parse_receipts) == 2


def test_audit_head_only_conflict_rebases_once_without_recalling_provider() -> None:
    manifest = _manifest()
    raw = _raw_payload(_pack(manifest), 0.5)
    harness = _harness(results=[raw], fail_first_screening_commit=True)

    outcome = harness.coordinator.process_case(RUN_ID, harness.pack.case_id)

    assert outcome.case.case.status == CaseStatus.ESCALATED
    assert len(harness.repository.commit_screening_calls) == 2
    first_revision, first_head = harness.repository.commit_screening_calls[0]
    second_revision, second_head = harness.repository.commit_screening_calls[1]
    assert second_revision == first_revision
    assert second_head.sequence == first_head.sequence + 1
    assert len(harness.vlm.calls) == 1


def test_leased_retry_binds_generation_and_atomically_completes_escalation() -> None:
    manifest = _manifest()
    harness = _harness(results=[_raw_payload(_pack(manifest), 0.5)])
    leased = _leased_backlog_item(harness)

    committed = harness.coordinator.retry_leased_item(leased)

    assert committed.item.status == BacklogStatus.COMPLETED
    assert committed.case.case.status == CaseStatus.ESCALATED
    assert isinstance(committed.receipt.outcome, BacklogRetrySuccess)
    assert len(harness.vlm.calls) == 1
    assert harness.vlm.calls[0].backlog_retry_context == BacklogRetryContext(
        backlog_item_id=leased.item_id,
        retry_generation=leased.retry_generation,
    )
    assert tuple(ref.artifact_id for ref in committed.receipt.outcome.response_refs) == (
        harness.repository.parse_receipts[0].response_id,
    )


def test_leased_retry_atomically_commits_screening_verdict_and_review() -> None:
    manifest = _manifest()
    harness = _harness(results=[_raw_payload(_pack(manifest), 0.95)])
    leased = _leased_backlog_item(harness)

    committed = harness.coordinator.retry_leased_item(leased)

    assert committed.item.status == BacklogStatus.COMPLETED
    assert committed.case.case.status == CaseStatus.READY_FOR_ALERT_POLICY
    assert len(committed.case.case.screening_results) == 1
    assert len(committed.case.case.verdicts) == 1
    assert len(committed.case.case.procedural_reviews) == 1
    assert harness.repository.commit_screening_calls == []
    assert harness.repository.commit_verdict_calls == 0
    assert harness.repository.commit_backlog_retry_calls == 1


def test_retry_provider_outage_atomically_returns_pending_without_generation_advance() -> None:
    harness = _harness(results=[ProviderUnavailable("offline")])
    leased = _leased_backlog_item(harness)

    committed = harness.coordinator.retry_leased_item(leased)

    assert committed.item.status == BacklogStatus.PENDING
    assert committed.item.retry_generation == leased.retry_generation
    assert committed.case.case.status == CaseStatus.BACKLOGGED
    assert isinstance(committed.receipt.outcome, BacklogRetryFailure)
    assert committed.receipt.outcome.reason_code == BacklogReasonCode.PROVIDER_UNAVAILABLE
    assert committed.receipt.outcome.response_refs == ()


def test_retry_failure_after_durable_response_binds_exact_response_ref(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _manifest()
    harness = _harness(results=[_raw_payload(_pack(manifest), 0.5)])
    leased = _leased_backlog_item(harness)

    real_append = harness.repository.append_parse_receipt
    append_calls = 0

    def fail_once_then_append(
        receipt: ModelParseReceipt,
        parsed_output: ParsedScreeningOutput | None = None,
    ) -> ModelParseReceipt:
        nonlocal append_calls
        append_calls += 1
        if append_calls == 1:
            raise ContractViolation("parse persistence unavailable")
        return real_append(receipt, parsed_output)

    monkeypatch.setattr(
        harness.repository,
        "append_parse_receipt",
        fail_once_then_append,
    )
    committed = harness.coordinator.retry_leased_item(leased)

    assert isinstance(committed.receipt.outcome, BacklogRetryFailure)
    assert committed.receipt.outcome.reason_code == (BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE)
    assert len(committed.receipt.outcome.response_refs) == 1
    response_ref = committed.receipt.outcome.response_refs[0]
    assert response_ref.kind == ArtifactKind.MODEL_RESPONSE
    assert response_ref.artifact_id in harness.repository.raw_responses
    assert committed.item.retry_generation == leased.retry_generation
    assert len(harness.vlm.calls) == 1

    second_lease = BacklogItem.model_validate(
        {
            **committed.item.model_dump(mode="json", exclude_computed_fields=True),
            "attempt_count": committed.item.attempt_count + 1,
            "status": BacklogStatus.LEASED.value,
            "lease_id": "6" * 64,
            "lease_owner_sha256": "7" * 64,
            "lease_expires_at": "2026-07-28T12:06:00Z",
        }
    )
    harness.repository.backlog_items[second_lease.item_id] = second_lease

    recovered = harness.coordinator.retry_leased_item(second_lease)

    assert recovered.item.status == BacklogStatus.COMPLETED
    assert recovered.case.case.status == CaseStatus.ESCALATED
    assert len(harness.vlm.calls) == 1


def test_retry_journal_without_sqlite_publication_preserves_lease_for_recovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _manifest()
    harness = _harness(results=[_raw_payload(_pack(manifest), 0.5)])
    leased = _leased_backlog_item(harness)

    def fail_completion(
        run_id: str,
        request: VLMCallRequest,
        response: VLMResponse,
        owner_token: str,
    ) -> CachedModelResponse:
        del run_id, request, response, owner_token
        raise ContractViolation("SQLite publication unavailable")

    monkeypatch.setattr(harness.repository, "complete_model_call", fail_completion)

    with pytest.raises(ContractViolation, match="SQLite publication unavailable"):
        harness.coordinator.retry_leased_item(leased)

    assert harness.repository.load_backlog_item(RUN_ID, leased.item_id) == leased
    assert harness.repository.commit_backlog_retry_calls == 0
    assert len(harness.vlm.calls) == 1
    assert harness.store.recover(harness.vlm.calls[0]) is not None


def test_two_strict_retry_parse_failures_prove_and_advance_one_generation() -> None:
    harness = _harness(results=[b"not-json", b"still-not-json"])
    leased = _leased_backlog_item(harness)

    committed = harness.coordinator.retry_leased_item(leased)

    assert isinstance(committed.receipt.outcome, BacklogRetryFailure)
    failure = committed.receipt.outcome
    assert failure.reason_code == BacklogReasonCode.MODEL_OUTPUT_INVALID
    assert failure.strict_parse_failure is not None
    assert failure.strict_parse_failure.retry_context == BacklogRetryContext(
        backlog_item_id=leased.item_id,
        retry_generation=leased.retry_generation,
    )
    assert tuple(
        attempt.parse_receipt_ref.artifact_id for attempt in failure.strict_parse_failure.attempts
    ) == tuple(receipt.parse_receipt_id for receipt in harness.repository.parse_receipts)
    assert (
        tuple(
            sorted(
                (attempt.response_ref for attempt in failure.strict_parse_failure.attempts),
                key=lambda ref: ref.sort_key,
            )
        )
        == failure.response_refs
    )
    assert committed.item.retry_generation == leased.retry_generation + 1
    assert len(harness.vlm.calls) == 2
    assert all(
        call.backlog_retry_context == failure.strict_parse_failure.retry_context
        for call in harness.vlm.calls
    )
    repair_call = harness.vlm.calls[1]
    assert isinstance(repair_call, StructureRepairRequest)
    assert repair_call.original_backlog_retry_context_id == (
        failure.strict_parse_failure.retry_context.context_id
    )


def test_retry_existing_screening_resumes_without_provider_or_duplicate_screening() -> None:
    harness = _harness()
    screening, receipt = _screening_fixture(harness, 0.95)
    harness.repository.parse_history[screening.parsed_output.parsed_output_id] = (receipt,)
    harness.evidence.snapshot = _replace_case(
        harness.evidence.snapshot,
        screening_results=[screening.model_dump(mode="json")],
    )
    leased = _leased_backlog_item(
        harness,
        reason=BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE,
    )

    committed = harness.coordinator.retry_leased_item(leased)

    assert committed.item.status == BacklogStatus.COMPLETED
    assert committed.case.case.status == CaseStatus.READY_FOR_ALERT_POLICY
    assert len(committed.case.case.screening_results) == 1
    assert len(committed.case.case.verdicts) == 1
    assert harness.vlm.calls == []
    assert harness.prompts.values == []


def test_last_retry_failure_atomically_exhausts_to_human_review() -> None:
    harness = _harness(results=[ProviderUnavailable("offline")])
    leased = _leased_backlog_item(harness, max_attempts=1)

    committed = harness.coordinator.retry_leased_item(leased)

    assert committed.item.status == BacklogStatus.EXHAUSTED
    assert committed.case.case.status == CaseStatus.HUMAN_REVIEW
    assert committed.case.case.current_backlog_item_id is None

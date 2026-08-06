"""Production, bounded HEARING backlog worker over persisted M4 authority."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from math import ceil
from typing import Protocol

from labcourt.application.hearing_backlog_retry import (
    HearingBacklogCallPlan,
    HearingBacklogRetryService,
    HearingBacklogRoleCallExecutor,
)
from labcourt.application.hearing_model_parser import (
    finalize_hearing_parse,
    inspect_hearing_response,
)
from labcourt.application.hearing_request import (
    HearingBudgetUsage,
    HearingRequestGeneration,
    PreparedHearingRequest,
    prepare_hearing_repair_request,
    prepare_primary_hearing_request,
)
from labcourt.application.hearing_role_call import HearingRoleCallContext
from labcourt.contracts.backlog import BacklogLeaseIdentity
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import (
    ArtifactKind,
    BacklogReasonCode,
    BacklogStage,
    BacklogStatus,
    CaseStatus,
    VlmRole,
)
from labcourt.contracts.hearing import (
    HearingBacklogRetryFailure,
    HearingModelCallFailureAuthority,
    HearingModelRequest,
    HearingPrecedentRetrievalReceipt,
    HearingRoleOutput,
    HearingUsageReceipt,
)
from labcourt.contracts.m4_operations import (
    M4BacklogRetryDisposition,
    M4BacklogRetryReport,
    M4FakeVLMFixtureBundle,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.references import require_reference_token
from labcourt.contracts.storage import ArtifactRef
from labcourt.domain.evidence_authority import (
    EvidenceAuthority,
    HearingEvidenceGrant,
    RoleEvidenceDisclosure,
    extend_hearing_evidence_grant,
)
from labcourt.domain.procedural_gate import ArtifactBounds
from labcourt.exceptions import ContractViolation
from labcourt.ports.evidence_repository import EvidenceRepository
from labcourt.ports.hearing_backlog import (
    HearingBacklogRepository,
    HearingBacklogRetryAuthority,
    HearingBacklogRetryCommit,
)
from labcourt.ports.hearing_repository import HearingRepository
from labcourt.ports.hearing_vlm import HearingModelResponseStore
from labcourt.ports.prompts import PromptCatalog


class M4BacklogAuthorityRepository(
    EvidenceRepository,
    HearingRepository,
    HearingBacklogRepository,
    Protocol,
):
    """Composite local authority used by the production retry planner."""


def _utc_now() -> datetime:
    return datetime.now(UTC)


_ROLE_ORDER = {
    VlmRole.PROSECUTOR: 0,
    VlmRole.DEFENDER: 1,
    VlmRole.JUDGE: 2,
}


def _request_sort_key(request: HearingModelRequest) -> tuple[int, int, int, int, str]:
    retry = request.backlog_retry_context
    return (
        request.round_index,
        _ROLE_ORDER[request.role],
        retry.retry_generation if retry is not None else 0,
        request.attempt_index,
        request.request_id,
    )


def _disclosure_for(request: HearingModelRequest) -> RoleEvidenceDisclosure:
    return RoleEvidenceDisclosure(
        run_id=request.run_id,
        case_id=request.case_id,
        evidence_pack_id=request.current_evidence_pack_id,
        evidence_pack_version=request.current_evidence_pack_version,
        media=request.media,
        allowed_evidence_refs=request.allowed_evidence_refs,
        artifact_bounds=tuple(
            sorted(
                (
                    ArtifactBounds(
                        artifact_ref=ArtifactRef(
                            kind=ArtifactKind.CROP,
                            artifact_id=media.crop_id,
                        ),
                        width=media.width,
                        height=media.height,
                    )
                    for media in request.media
                ),
                key=lambda item: item.sort_key,
            )
        ),
    )


class M4HearingBacklogPlanBuilder:
    """Rebuild one exact primary/repair preparation from immutable SQLite roots."""

    __slots__ = (
        "_catalog",
        "_config",
        "_manifest",
        "_repository",
        "_responses",
    )

    def __init__(
        self,
        *,
        config: AppConfig,
        manifest: RunManifest,
        catalog: PromptCatalog,
        repository: M4BacklogAuthorityRepository,
        response_store: HearingModelResponseStore,
    ) -> None:
        if not isinstance(config, AppConfig):
            raise TypeError("config must be an AppConfig")
        if not isinstance(manifest, RunManifest):
            raise TypeError("manifest must be a RunManifest")
        if not isinstance(catalog, PromptCatalog):
            raise TypeError("catalog must implement PromptCatalog")
        required_repository_methods = (
            "load_pack",
            "load_hearing_evidence_authority",
            "load_precedent_retrieval",
            "load_hearing_role_output",
            "list_hearing_model_requests",
            "list_hearing_usage_receipts",
            "list_hearing_failure_authorities",
        )
        if any(
            not callable(getattr(repository, method, None))
            for method in required_repository_methods
        ):
            raise TypeError("repository lacks an M4 backlog planning capability")
        if not callable(getattr(response_store, "verify_raw_response", None)) or not callable(
            getattr(response_store, "read_bytes", None)
        ):
            raise TypeError("response_store lacks raw-response verification")
        self._config = config
        self._manifest = manifest
        self._catalog = catalog
        self._repository = repository
        self._responses = response_store

    def build(self, authority: HearingBacklogRetryAuthority) -> HearingBacklogCallPlan:
        """Reconstruct and cross-check the exact leased generation call."""

        if not isinstance(authority, HearingBacklogRetryAuthority):
            raise TypeError("authority must be a HearingBacklogRetryAuthority")
        if authority.item.manifest_id != self._manifest.manifest_id:
            raise ContractViolation("hearing backlog authority changed its run manifest")

        template = authority.primary_template_request
        pack = self._repository.load_pack(
            authority.item.run_id,
            template.current_evidence_pack_id,
        )
        evidence = self._repository.load_hearing_evidence_authority(
            authority.item.run_id,
            authority.session.session_id,
            template.current_evidence_pack_id,
        )
        if not isinstance(evidence, EvidenceAuthority) or evidence.pack != pack:
            raise ContractViolation("hearing backlog evidence authority changed its pack")
        retrieval = self._repository.load_precedent_retrieval(
            authority.item.run_id,
            template.precedent_retrieval_receipt_id,
        )
        if not isinstance(retrieval, HearingPrecedentRetrievalReceipt):
            raise ContractViolation("hearing backlog retrieval authority is invalid")

        prosecutor = self._load_upstream_output(
            authority.item.run_id,
            template.prosecutor_output_ref,
            expected_role=VlmRole.PROSECUTOR,
        )
        defender = self._load_upstream_output(
            authority.item.run_id,
            template.defender_output_ref,
            expected_role=VlmRole.DEFENDER,
        )
        grant, budget = self._reconstruct_before_primary(authority)
        generation = self._generation_for(authority)
        primary = prepare_primary_hearing_request(
            role=template.role,
            session=authority.session,
            cycle_scope=authority.cycle_scope,
            retrieval=retrieval,
            evidence_pack=pack,
            evidence_authority=evidence,
            hearing_grant=grant,
            budget_usage=budget,
            config=self._config,
            run_manifest=self._manifest,
            catalog=self._catalog,
            prosecutor_output=prosecutor,
            defender_output=defender,
            generation=generation,
        )

        target = authority.unfinished_request
        if target is not None and primary.request != authority.primary_template_request:
            raise ContractViolation("reconstructed hearing primary changed persisted authority")
        repair = self._repair_if_required(authority, primary, budget)
        return HearingBacklogCallPlan(
            primary=primary,
            repair=repair,
            context=HearingRoleCallContext(
                session=authority.session,
                cycle_scope=authority.cycle_scope,
                budget_usage_before_primary=budget,
                config=self._config,
                run_manifest=self._manifest,
                catalog=self._catalog,
                backlog_lease=authority.lease,
            ),
        )

    def _load_upstream_output(
        self,
        run_id: str,
        ref: ArtifactRef | None,
        *,
        expected_role: VlmRole,
    ) -> HearingRoleOutput | None:
        if ref is None:
            return None
        if ref.kind != ArtifactKind.PARSED_MODEL_OUTPUT:
            raise ContractViolation("hearing upstream output has the wrong artifact kind")
        output = self._repository.load_hearing_role_output(run_id, ref.artifact_id)
        if not isinstance(output, HearingRoleOutput) or output.role != expected_role:
            raise ContractViolation("hearing upstream output changed role authority")
        return output

    @staticmethod
    def _generation_for(authority: HearingBacklogRetryAuthority) -> HearingRequestGeneration:
        unfinished = authority.unfinished_request
        if unfinished is not None:
            context = authority.primary_template_request.backlog_retry_context
            if context is None:
                return HearingRequestGeneration()
            if (
                context.backlog_item_id != authority.item.item_id
                or context.retry_generation != authority.item.retry_generation
            ):
                raise ContractViolation("unfinished hearing request changed retry generation")
            return HearingRequestGeneration(
                retry_generation=context.retry_generation,
                backlog_item_id=context.backlog_item_id,
            )
        return HearingRequestGeneration(
            retry_generation=authority.item.retry_generation,
            backlog_item_id=authority.item.item_id,
        )

    def _reconstruct_before_primary(
        self,
        authority: HearingBacklogRetryAuthority,
    ) -> tuple[HearingEvidenceGrant | None, HearingBudgetUsage]:
        requests = self._repository.list_hearing_model_requests(
            authority.item.run_id,
            authority.session.session_id,
        )
        usage = self._repository.list_hearing_usage_receipts(
            authority.item.run_id,
            authority.session.session_id,
        )
        failures = self._repository.list_hearing_failure_authorities(
            authority.item.run_id,
            authority.session.session_id,
        )
        if (
            not isinstance(requests, tuple)
            or any(not isinstance(item, HearingModelRequest) for item in requests)
            or requests != tuple(sorted(requests, key=_request_sort_key))
            or len({item.request_id for item in requests}) != len(requests)
            or any(
                item.run_id != authority.item.run_id
                or item.case_id != authority.item.case_id
                or item.hearing_session_id != authority.session.session_id
                or item.manifest_id != authority.item.manifest_id
                for item in requests
            )
            or not isinstance(usage, tuple)
            or any(not isinstance(item, HearingUsageReceipt) for item in usage)
            or len({item.usage_receipt_id for item in usage}) != len(usage)
            or len({item.request_ref.artifact_id for item in usage}) != len(usage)
            or not isinstance(failures, tuple)
            or any(not isinstance(item, HearingModelCallFailureAuthority) for item in failures)
            or len({item.authority_id for item in failures}) != len(failures)
        ):
            raise ContractViolation("hearing backlog call history is not canonical")
        request_by_id = {item.request_id: item for item in requests}
        disclosed_request_ids: set[str] = set()
        output_tokens_by_request: dict[str, int] = {}
        for receipt in usage:
            request_id = receipt.request_ref.artifact_id
            request = request_by_id.get(request_id)
            if (
                request is None
                or receipt.request_ref.kind != ArtifactKind.MODEL_REQUEST
                or receipt.run_id != authority.item.run_id
                or receipt.hearing_session_id != authority.session.session_id
                or receipt.manifest_id != authority.item.manifest_id
                or receipt.input_images != len(request.media)
                or receipt.input_pixels
                != sum(media.width * media.height for media in request.media)
            ):
                raise ContractViolation("hearing usage changed disclosure authority")
            disclosed_request_ids.add(request_id)
            output_tokens_by_request[request_id] = (
                output_tokens_by_request.get(request_id, 0) + receipt.output_tokens
            )
        for failure in failures:
            request = request_by_id.get(failure.request.request_id)
            if (
                request is None
                or request != failure.request
                or failure.run_id != authority.item.run_id
                or failure.hearing_session_id != authority.session.session_id
                or failure.manifest_id != authority.item.manifest_id
                or failure.reserved_images != len(request.media)
                or failure.reserved_pixels
                != sum(media.width * media.height for media in request.media)
            ):
                raise ContractViolation("hearing failure changed disclosure authority")
            output_tokens_by_request[request.request_id] = (
                output_tokens_by_request.get(request.request_id, 0) + failure.output_tokens
            )
            if failure.disclosed_images:
                if failure.disclosed_images != len(
                    request.media
                ) or failure.disclosed_pixels != sum(
                    media.width * media.height for media in request.media
                ):
                    raise ContractViolation("hearing failure disclosure counts are invalid")
                disclosed_request_ids.add(request.request_id)

        expected_images = sum(len(request.media) for request in requests)
        expected_output_tokens = sum(output_tokens_by_request.values())
        if (
            authority.reserved_images != expected_images
            or authority.accounted_output_tokens != expected_output_tokens
        ):
            raise ContractViolation("hearing backlog aggregate budget changed its history")

        unfinished = authority.unfinished_request
        current_ids: set[str] = set()
        if unfinished is not None:
            primary_id = authority.primary_template_request.request_id
            if request_by_id.get(primary_id) != authority.primary_template_request:
                raise ContractViolation("hearing backlog primary is absent from call history")
            current_ids.add(primary_id)
            if unfinished.attempt_index == 1:
                if request_by_id.get(unfinished.request_id) != unfinished:
                    raise ContractViolation("hearing backlog repair is absent from call history")
                current_ids.add(unfinished.request_id)
            elif unfinished.request_id != primary_id:
                raise ContractViolation("unfinished primary changed its generation template")

        before_images = authority.reserved_images - sum(
            len(request_by_id[request_id].media) for request_id in current_ids
        )
        before_tokens = authority.accounted_output_tokens - sum(
            output_tokens_by_request.get(request_id, 0) for request_id in current_ids
        )
        if (
            before_images < 0
            or before_tokens < 0
            or authority.reserved_images_before_primary != before_images
            or authority.accounted_output_tokens_before_primary != before_tokens
        ):
            raise ContractViolation("hearing backlog before-primary budget changed its history")

        grant: HearingEvidenceGrant | None = None
        for request in requests:
            if (
                request.request_id in current_ids
                or request.request_id not in disclosed_request_ids
                or not request.media
            ):
                continue
            grant = extend_hearing_evidence_grant(grant, _disclosure_for(request))
        return grant, HearingBudgetUsage(
            reserved_images=authority.reserved_images_before_primary,
            accounted_output_tokens=authority.accounted_output_tokens_before_primary,
        )

    def _repair_if_required(
        self,
        authority: HearingBacklogRetryAuthority,
        primary: PreparedHearingRequest,
        budget_before_primary: HearingBudgetUsage,
    ) -> PreparedHearingRequest | None:
        unfinished = authority.unfinished_request
        if unfinished is None or unfinished.attempt_index == 0:
            return None
        failure = authority.prior_primary_failure
        if failure is None or failure.request != primary.request:
            raise ContractViolation("repair resume lost its primary failure closure")
        verified = self._responses.verify_raw_response(
            authority.item.run_id,
            failure.request,
            failure.response,
        )
        if verified != failure.response:
            raise ContractViolation("raw response verifier returned another response")
        raw = self._responses.read_bytes(
            authority.item.run_id,
            failure.response,
            failure.request.budget.max_response_bytes,
        )
        inspection = inspect_hearing_response(
            raw,
            request=failure.request,
            response=failure.response,
        )
        if inspection.payload is not None:
            raise ContractViolation("persisted repair authority now parses as a payload")
        repair_budget = HearingBudgetUsage(
            reserved_images=(budget_before_primary.reserved_images + len(failure.request.media)),
            accounted_output_tokens=(
                budget_before_primary.accounted_output_tokens + failure.usage.output_tokens
            ),
        )
        repair = prepare_hearing_repair_request(
            original=primary,
            response=failure.response,
            inspection=inspection,
            raw_response=raw,
            session=authority.session,
            cycle_scope=authority.cycle_scope,
            budget_usage=repair_budget,
            config=self._config,
            run_manifest=self._manifest,
            catalog=self._catalog,
        )
        if repair.request != unfinished:
            raise ContractViolation("reconstructed hearing repair changed persisted authority")
        reparsed = finalize_hearing_parse(
            inspection,
            repair_request_id=repair.request.request_id,
        )
        if reparsed.receipt != failure.parse_receipt:
            raise ContractViolation("reconstructed primary parse closure changed")
        return repair


class M4HearingBacklogWorker:
    """Reclaim stale leases and resolve at most one exact HEARING item."""

    __slots__ = (
        "_clock",
        "_fixture_bundle",
        "_manifest",
        "_minimum_lease_seconds",
        "_planner",
        "_repository",
        "_retry",
        "_run_id",
    )

    def __init__(
        self,
        *,
        run_id: str,
        config: AppConfig,
        manifest: RunManifest,
        fixture_bundle: M4FakeVLMFixtureBundle,
        catalog: PromptCatalog,
        repository: M4BacklogAuthorityRepository,
        response_store: HearingModelResponseStore,
        role_calls: HearingBacklogRoleCallExecutor,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._run_id = require_reference_token(run_id, "M4 backlog worker run reference")
        if not isinstance(config, AppConfig) or not isinstance(manifest, RunManifest):
            raise TypeError("config and manifest must be exact contract types")
        if not isinstance(fixture_bundle, M4FakeVLMFixtureBundle):
            raise TypeError("fixture_bundle must be an M4FakeVLMFixtureBundle")
        if not callable(clock):
            raise TypeError("clock must be callable")
        for method in (
            "reclaim_expired_hearing_backlog",
            "lease_next_hearing_backlog",
            "load_hearing_backlog_retry_authority",
            "commit_hearing_backlog_retry",
        ):
            if not callable(getattr(repository, method, None)):
                raise TypeError(f"repository does not implement {method}")
        profile_names = (
            config.hearing.prosecutor_profile,
            config.hearing.defender_profile,
            config.hearing.judge_profile,
        )
        max_timeout = max(float(config.providers[name].timeout_seconds) for name in profile_names)
        self._minimum_lease_seconds = ceil(3 * (max_timeout + 5.0) + 30.0)
        if not 1 <= self._minimum_lease_seconds <= 14_400:
            raise ValueError("M4 backlog lease floor is outside the supported bound")
        self._manifest = manifest
        self._fixture_bundle = fixture_bundle
        self._repository = repository
        self._planner = M4HearingBacklogPlanBuilder(
            config=config,
            manifest=manifest,
            catalog=catalog,
            repository=repository,
            response_store=response_store,
        )
        self._retry = HearingBacklogRetryService(
            repository=repository,
            role_calls=role_calls,
        )
        self._clock = clock

    @property
    def minimum_backlog_lease_seconds(self) -> int:
        return self._minimum_lease_seconds

    def run_once(
        self,
        *,
        run_id: str,
        worker_id: str,
        lease_duration_seconds: int | None,
        reclaim_limit: int,
    ) -> M4BacklogRetryReport:
        safe_run_id = require_reference_token(run_id, "M4 backlog retry run reference")
        safe_worker_id = require_reference_token(worker_id, "M4 backlog retry worker reference")
        if safe_run_id != self._run_id:
            raise ContractViolation("M4 backlog worker cannot cross run authority")
        if (
            not isinstance(reclaim_limit, int)
            or isinstance(reclaim_limit, bool)
            or not 1 <= reclaim_limit <= 10_000
        ):
            raise ValueError("reclaim_limit must be from 1 through 10000")
        effective_lease = (
            self._minimum_lease_seconds
            if lease_duration_seconds is None
            else lease_duration_seconds
        )
        if (
            not isinstance(effective_lease, int)
            or isinstance(effective_lease, bool)
            or not self._minimum_lease_seconds <= effective_lease <= 14_400
        ):
            raise ValueError(
                "lease_duration_seconds cannot cover stale-claim wait, two calls, and commit"
            )
        now = self._clock()
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() != timedelta(0):
            raise ValueError("M4 backlog worker clock must return timezone-aware UTC")

        reclaimed = self._repository.reclaim_expired_hearing_backlog(
            safe_run_id,
            now,
            reclaim_limit,
        )
        reclaimed_ids = self._validate_reclaimed(
            safe_run_id,
            reclaimed,
            reclaim_limit,
        )
        owner_sha256 = sha256_hex(["m4-hearing-backlog-worker", 1, safe_run_id, safe_worker_id])
        leased = self._repository.lease_next_hearing_backlog(
            safe_run_id,
            owner_sha256,
            now + timedelta(seconds=effective_lease),
        )
        if leased is None:
            return self._report(
                disposition=M4BacklogRetryDisposition.NO_WORK,
                reclaimed_ids=reclaimed_ids,
            )
        if (
            leased.run_id != safe_run_id
            or leased.stage != BacklogStage.HEARING
            or leased.status != BacklogStatus.LEASED
            or leased.role not in _ROLE_ORDER
            or leased.lease_id is None
        ):
            raise ContractViolation("M4 backlog lease returned invalid HEARING work")
        lease = BacklogLeaseIdentity(
            run_id=leased.run_id,
            item_id=leased.item_id,
            lease_id=leased.lease_id,
            attempt_count=leased.attempt_count,
            retry_generation=leased.retry_generation,
        )
        authority = self._repository.load_hearing_backlog_retry_authority(
            safe_run_id,
            lease,
        )
        if authority.item != leased:
            raise ContractViolation("M4 backlog lease changed before planning")
        plan = self._planner.build(authority)
        committed = self._retry.retry_leased_item(authority, plan)
        return self._report_from_commit(committed, reclaimed_ids)

    @staticmethod
    def _validate_reclaimed(
        run_id: str,
        reclaimed: tuple[HearingBacklogRetryCommit, ...],
        limit: int,
    ) -> tuple[str, ...]:
        if (
            not isinstance(reclaimed, tuple)
            or len(reclaimed) > limit
            or any(not isinstance(item, HearingBacklogRetryCommit) for item in reclaimed)
        ):
            raise ContractViolation("M4 backlog reclaim returned an invalid result")
        ids = tuple(item.receipt.receipt_id for item in reclaimed)
        if len(ids) != len(set(ids)) or any(
            item.item.run_id != run_id
            or item.item.stage != BacklogStage.HEARING
            or item.item.status not in {BacklogStatus.PENDING, BacklogStatus.EXHAUSTED}
            or not isinstance(item.receipt.outcome, HearingBacklogRetryFailure)
            or item.receipt.outcome.reason_code != BacklogReasonCode.WORKER_LEASE_EXPIRED
            for item in reclaimed
        ):
            raise ContractViolation("M4 backlog reclaim crossed authority")
        return tuple(sorted(ids))

    def _report_from_commit(
        self,
        committed: HearingBacklogRetryCommit,
        reclaimed_ids: tuple[str, ...],
    ) -> M4BacklogRetryReport:
        status = committed.item.status
        disposition = {
            BacklogStatus.COMPLETED: M4BacklogRetryDisposition.COMPLETED,
            BacklogStatus.PENDING: M4BacklogRetryDisposition.REQUEUED,
            BacklogStatus.EXHAUSTED: M4BacklogRetryDisposition.EXHAUSTED,
        }.get(status)
        if disposition is None:
            raise ContractViolation("M4 backlog retry left a non-terminal lease")
        outcome = committed.receipt.outcome
        human = outcome.human_review_receipt
        role = committed.item.role
        if role is None:
            raise ContractViolation("M4 backlog completion lost its exact role")
        return self._report(
            disposition=disposition,
            reclaimed_ids=reclaimed_ids,
            lease=outcome.lease,
            case_id=committed.item.case_id,
            role=role,
            completion_receipt_id=committed.receipt.receipt_id,
            outcome_id=outcome.outcome_id,
            source_checkpoint_id=outcome.source_checkpoint_id,
            resulting_checkpoint_id=committed.checkpoint.checkpoint_id,
            backlog_status=status,
            resulting_case_status=committed.case.case.status,
            resulting_retry_generation=committed.item.retry_generation,
            human_review_receipt_id=(human.receipt_id if human is not None else None),
        )

    def _report(
        self,
        *,
        disposition: M4BacklogRetryDisposition,
        reclaimed_ids: tuple[str, ...],
        lease: BacklogLeaseIdentity | None = None,
        case_id: str | None = None,
        role: VlmRole | None = None,
        completion_receipt_id: str | None = None,
        outcome_id: str | None = None,
        source_checkpoint_id: str | None = None,
        resulting_checkpoint_id: str | None = None,
        backlog_status: BacklogStatus | None = None,
        resulting_case_status: CaseStatus | None = None,
        resulting_retry_generation: int | None = None,
        human_review_receipt_id: str | None = None,
    ) -> M4BacklogRetryReport:
        return M4BacklogRetryReport(
            run_id=self._run_id,
            manifest_id=self._manifest.manifest_id,
            fixture_bundle_id=self._fixture_bundle.fixture_bundle_id,
            fixture_entry_count=self._fixture_bundle.fixture_count,
            acquisition_fixture_count=self._fixture_bundle.acquisition_fixture_count,
            disposition=disposition,
            reclaimed_completion_receipt_ids=reclaimed_ids,
            lease=lease,
            case_id=case_id,
            role=role,
            completion_receipt_id=completion_receipt_id,
            outcome_id=outcome_id,
            source_checkpoint_id=source_checkpoint_id,
            resulting_checkpoint_id=resulting_checkpoint_id,
            backlog_status=backlog_status,
            resulting_case_status=resulting_case_status,
            resulting_retry_generation=resulting_retry_generation,
            human_review_receipt_id=human_review_receipt_id,
        )


__all__ = [
    "M4BacklogAuthorityRepository",
    "M4HearingBacklogPlanBuilder",
    "M4HearingBacklogWorker",
]

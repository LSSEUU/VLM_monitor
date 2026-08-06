"""Build and execute one authority-bound M4 precedent retrieval query."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import NoReturn

from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import ArtifactKind
from labcourt.contracts.evidence import EvidencePack
from labcourt.contracts.frames import SHA256_PATTERN, Sha256Hex
from labcourt.contracts.hearing_common import HearingCycleScope
from labcourt.contracts.hearing_retrieval import (
    MAX_HEARING_PRECEDENT_RESULTS,
    HearingPrecedentRetrievalOutcome,
    HearingPrecedentRetrievalQuery,
    HearingPrecedentRetrievalResult,
    derive_hearing_candidate_snapshot_sha256,
    derive_hearing_evidence_pack_document_sha256,
    derive_hearing_visible_snapshot_sha256,
)
from labcourt.contracts.hearing_state import (
    HearingPrecedentDegradedReason,
    HearingPrecedentRetrievalReceipt,
    HearingPrecedentRetrievalStatus,
    HearingSession,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.precedents import Precedent, ScoredPrecedent
from labcourt.contracts.references import require_reference_token
from labcourt.contracts.storage import ArtifactRef
from labcourt.ports.hearing_precedents import (
    HearingPrecedentRetrievalUnavailable,
    HearingPrecedentRetriever,
)

_SHA256 = re.compile(SHA256_PATTERN)


class HearingPrecedentRetrievalServiceErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    AUTHORITY_MISMATCH = "AUTHORITY_MISMATCH"
    CONFIG_MISMATCH = "CONFIG_MISMATCH"
    RETRIEVER_CONTRACT_VIOLATION = "RETRIEVER_CONTRACT_VIOLATION"


class HearingPrecedentRetrievalServiceError(ValueError):
    """Typed application failure; controlled outages are returned as receipts instead."""

    def __init__(self, code: HearingPrecedentRetrievalServiceErrorCode) -> None:
        self.code = code
        super().__init__(code.value)


def _fail(code: HearingPrecedentRetrievalServiceErrorCode) -> NoReturn:
    raise HearingPrecedentRetrievalServiceError(code)


class HearingPrecedentRetrievalService:
    """Create a stable query, call the replaceable retriever, and seal its receipt."""

    def __init__(
        self,
        retriever: HearingPrecedentRetriever,
        *,
        retriever_version: str,
        retriever_manifest_id: str,
    ) -> None:
        if not callable(getattr(retriever, "retrieve", None)):
            raise TypeError("retriever must implement retrieve(query)")
        try:
            self._retriever_version = require_reference_token(
                retriever_version,
                "hearing precedent retriever version",
            )
        except (TypeError, ValueError):
            _fail(HearingPrecedentRetrievalServiceErrorCode.INVALID_ARGUMENT)
        if (
            not isinstance(retriever_manifest_id, str)
            or _SHA256.fullmatch(retriever_manifest_id) is None
        ):
            _fail(HearingPrecedentRetrievalServiceErrorCode.INVALID_ARGUMENT)
        self._retriever = retriever
        self._retriever_manifest_id = retriever_manifest_id

    def retrieve(
        self,
        *,
        session: HearingSession,
        cycle_scope: HearingCycleScope,
        evidence_pack: EvidencePack,
        run_manifest: RunManifest,
        config: AppConfig,
        situation_text: str,
    ) -> HearingPrecedentRetrievalOutcome:
        query = self.prepare_query(
            session=session,
            cycle_scope=cycle_scope,
            evidence_pack=evidence_pack,
            run_manifest=run_manifest,
            config=config,
            situation_text=situation_text,
        )

        try:
            result = self._retriever.retrieve(query)
        except HearingPrecedentRetrievalUnavailable as unavailable:
            return self._degraded_outcome(
                query=query,
                session=session,
                cycle_scope=cycle_scope,
                reason=unavailable.reason,
            )

        if not isinstance(result, HearingPrecedentRetrievalResult) or result.query != query:
            _fail(HearingPrecedentRetrievalServiceErrorCode.RETRIEVER_CONTRACT_VIOLATION)
        try:
            result = HearingPrecedentRetrievalResult.model_validate(result.model_dump(mode="json"))
        except (TypeError, ValueError):
            _fail(HearingPrecedentRetrievalServiceErrorCode.RETRIEVER_CONTRACT_VIOLATION)
        if result.query != query:
            _fail(HearingPrecedentRetrievalServiceErrorCode.RETRIEVER_CONTRACT_VIOLATION)
        receipt = self._receipt(
            query=query,
            session=session,
            cycle_scope=cycle_scope,
            candidate_refs=tuple(
                ArtifactRef(
                    kind=ArtifactKind.PRECEDENT,
                    artifact_id=precedent.precedent_id,
                )
                for precedent in result.candidate_precedents
            ),
            candidate_snapshot_sha256=result.candidate_snapshot_sha256,
            visible_refs=tuple(
                ArtifactRef(
                    kind=ArtifactKind.PRECEDENT,
                    artifact_id=precedent.precedent_id,
                )
                for precedent in result.visible_precedents
            ),
            visible_snapshot_sha256=result.visible_snapshot_sha256,
            scored_precedents=result.scored_precedents,
            status=HearingPrecedentRetrievalStatus.SUCCESS,
        )
        return HearingPrecedentRetrievalOutcome(
            query=query,
            result=result,
            receipt=receipt,
        )

    def prepare_query(
        self,
        *,
        session: HearingSession,
        cycle_scope: HearingCycleScope,
        evidence_pack: EvidencePack,
        run_manifest: RunManifest,
        config: AppConfig,
        situation_text: str,
    ) -> HearingPrecedentRetrievalQuery:
        """Build the exact query used for fixture registration or retrieval."""

        self._validate_inputs(
            session=session,
            cycle_scope=cycle_scope,
            evidence_pack=evidence_pack,
            run_manifest=run_manifest,
            config=config,
        )
        embedding_manifest = run_manifest.models["text_embedding"]
        try:
            query = HearingPrecedentRetrievalQuery(
                run_id=evidence_pack.run_id,
                case_id=evidence_pack.case_id,
                hearing_session_id=session.session_id,
                hearing_session_sha256=session.session_sha256,
                cycle_scope_id=cycle_scope.cycle_id,
                cycle_scope_sha256=cycle_scope.cycle_sha256,
                current_evidence_pack_id=evidence_pack.pack_id,
                current_evidence_pack_version=evidence_pack.version,
                current_evidence_pack_sha256=(
                    derive_hearing_evidence_pack_document_sha256(evidence_pack)
                ),
                evidence_class=evidence_pack.event.evidence_class,
                violation_type=evidence_pack.event.violation_type,
                rule_version=run_manifest.rule_version,
                situation_text=situation_text,
                top_k=config.hearing.precedent_top_k,
                config_sha256=config.config_sha256,
                retriever_version=self._retriever_version,
                retriever_manifest_id=self._retriever_manifest_id,
                embedding_model_manifest=embedding_manifest,
                manifest_id=run_manifest.manifest_id,
            )
        except (TypeError, ValueError):
            _fail(HearingPrecedentRetrievalServiceErrorCode.INVALID_ARGUMENT)
        return query

    @staticmethod
    def _validate_inputs(
        *,
        session: HearingSession,
        cycle_scope: HearingCycleScope,
        evidence_pack: EvidencePack,
        run_manifest: RunManifest,
        config: AppConfig,
    ) -> None:
        if (
            not isinstance(session, HearingSession)
            or not isinstance(cycle_scope, HearingCycleScope)
            or not isinstance(evidence_pack, EvidencePack)
            or not isinstance(run_manifest, RunManifest)
            or not isinstance(config, AppConfig)
        ):
            _fail(HearingPrecedentRetrievalServiceErrorCode.INVALID_ARGUMENT)

        expected_scope = (
            evidence_pack.run_id,
            evidence_pack.case_id,
            session.session_id,
            evidence_pack.pack_id,
            evidence_pack.version,
            run_manifest.manifest_id,
        )
        actual_scope = (
            cycle_scope.run_id,
            cycle_scope.case_id,
            cycle_scope.hearing_session_id,
            cycle_scope.cycle_evidence_pack_id,
            cycle_scope.cycle_evidence_pack_version,
            cycle_scope.manifest_id,
        )
        if (
            actual_scope != expected_scope
            or session.run_id != evidence_pack.run_id
            or session.case_id != evidence_pack.case_id
            or session.manifest_id != run_manifest.manifest_id
            or evidence_pack.manifest_id != run_manifest.manifest_id
            or not evidence_pack.complete
            or cycle_scope.cycle_index > session.max_total_judge_cycles
            or cycle_scope.prior_acquisition_rounds > session.acquisition_round_limit
            or cycle_scope.prior_rework_rounds > session.rework_round_limit
        ):
            _fail(HearingPrecedentRetrievalServiceErrorCode.AUTHORITY_MISMATCH)
        if cycle_scope.cycle_index == 1 and (
            evidence_pack.pack_id != session.initial_evidence_pack_id
            or evidence_pack.version != session.initial_evidence_pack_version
            or cycle_scope.initial_trigger_review_ref != session.initial_trigger_review_ref
            or cycle_scope.initial_defect_codes != session.initial_defect_codes
        ):
            _fail(HearingPrecedentRetrievalServiceErrorCode.AUTHORITY_MISMATCH)

        if (
            run_manifest.config_sha256 != config.config_sha256
            or run_manifest.rule_version != config.rule_version
            or config.hearing.precedent_top_k > MAX_HEARING_PRECEDENT_RESULTS
        ):
            _fail(HearingPrecedentRetrievalServiceErrorCode.CONFIG_MISMATCH)
        embedding_manifest = run_manifest.models.get("text_embedding")
        if embedding_manifest is None or embedding_manifest.component != "text_embedding":
            _fail(HearingPrecedentRetrievalServiceErrorCode.AUTHORITY_MISMATCH)

    def _degraded_outcome(
        self,
        *,
        query: HearingPrecedentRetrievalQuery,
        session: HearingSession,
        cycle_scope: HearingCycleScope,
        reason: HearingPrecedentDegradedReason,
    ) -> HearingPrecedentRetrievalOutcome:
        # The port exception validates its reason.  Keeping this defensive check
        # prevents a structurally fake exception from becoming an open reason.
        if not isinstance(reason, HearingPrecedentDegradedReason):
            _fail(HearingPrecedentRetrievalServiceErrorCode.RETRIEVER_CONTRACT_VIOLATION)
        empty: tuple[Precedent, ...] = ()
        receipt = self._receipt(
            query=query,
            session=session,
            cycle_scope=cycle_scope,
            candidate_refs=(),
            candidate_snapshot_sha256=derive_hearing_candidate_snapshot_sha256(empty),
            visible_refs=(),
            visible_snapshot_sha256=derive_hearing_visible_snapshot_sha256(empty),
            scored_precedents=(),
            status=HearingPrecedentRetrievalStatus.DEGRADED,
            degraded_reason=reason,
        )
        return HearingPrecedentRetrievalOutcome(query=query, receipt=receipt)

    @staticmethod
    def _receipt(
        *,
        query: HearingPrecedentRetrievalQuery,
        session: HearingSession,
        cycle_scope: HearingCycleScope,
        candidate_refs: tuple[ArtifactRef, ...],
        candidate_snapshot_sha256: Sha256Hex,
        visible_refs: tuple[ArtifactRef, ...],
        visible_snapshot_sha256: Sha256Hex,
        scored_precedents: tuple[ScoredPrecedent, ...],
        status: HearingPrecedentRetrievalStatus,
        degraded_reason: HearingPrecedentDegradedReason | None = None,
    ) -> HearingPrecedentRetrievalReceipt:
        if not isinstance(scored_precedents, tuple) or any(
            not isinstance(item, ScoredPrecedent) for item in scored_precedents
        ):
            _fail(HearingPrecedentRetrievalServiceErrorCode.RETRIEVER_CONTRACT_VIOLATION)
        if degraded_reason is not None and not isinstance(
            degraded_reason,
            HearingPrecedentDegradedReason,
        ):
            _fail(HearingPrecedentRetrievalServiceErrorCode.RETRIEVER_CONTRACT_VIOLATION)
        return HearingPrecedentRetrievalReceipt(
            run_id=query.run_id,
            case_id=query.case_id,
            hearing_session_id=session.session_id,
            round_index=cycle_scope.cycle_index,
            prior_acquisition_rounds=cycle_scope.prior_acquisition_rounds,
            prior_rework_rounds=cycle_scope.prior_rework_rounds,
            current_evidence_pack_id=query.current_evidence_pack_id,
            current_evidence_pack_version=query.current_evidence_pack_version,
            evidence_class=query.evidence_class,
            violation_type=query.violation_type,
            rule_version=query.rule_version,
            top_k=query.top_k,
            query_sha256=query.query_sha256,
            initial_trigger_review_ref=cycle_scope.initial_trigger_review_ref,
            initial_defect_codes=cycle_scope.initial_defect_codes,
            rework_review_ref=cycle_scope.rework_review_ref,
            rework_defect_codes=cycle_scope.rework_defect_codes,
            candidate_precedent_refs=candidate_refs,
            candidate_snapshot_sha256=candidate_snapshot_sha256,
            visible_precedent_refs=visible_refs,
            visible_snapshot_sha256=visible_snapshot_sha256,
            scored_precedents=scored_precedents,
            status=status,
            degraded_reason=degraded_reason,
            retriever_version=query.retriever_version,
            retriever_manifest_id=query.retriever_manifest_id,
            embedding_model_manifest_id=(query.embedding_model_manifest.model_manifest_id),
            manifest_id=query.manifest_id,
        )


__all__ = [
    "HearingPrecedentRetrievalService",
    "HearingPrecedentRetrievalServiceError",
    "HearingPrecedentRetrievalServiceErrorCode",
]

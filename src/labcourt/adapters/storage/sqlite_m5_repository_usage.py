"""READY Verdict origin resolution and atomic M5 APPLIED persistence helpers."""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from typing import cast

from pydantic import ValidationError

from labcourt.contracts.enums import ArtifactKind, CaseStatus
from labcourt.contracts.hearing_common import JudgeFinalDecisionPayload, JudgeModelPayload
from labcourt.contracts.hearing_state import HearingPrecedentRetrievalStatus
from labcourt.contracts.m5_precedent_causal_ledger import (
    M5PrecedentCausalEventSourceKind,
)
from labcourt.contracts.m5_precedent_usage import (
    M5PrecedentApplicationBatchAuthority,
    M5PrecedentApplicationCitationCommit,
    M5PrecedentExposureBatchAuthority,
)
from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import ConcurrentModification, ContractViolation, EvidenceMissing
from labcourt.ports.evidence_repository import CaseSnapshot
from labcourt.ports.m5_precedent_usage import (
    M5ReadyPrecedentUsage,
    M5ReadyPrecedentUsageKind,
)

from ._sqlite_m5_precedent_causal_ledger import (
    append_m5_precedent_causal_event,
    m5_precedent_citation_causal_source,
)
from ._sqlite_m5_precedent_exposure_codec import (
    load_m5_precedent_exposure_in_connection,
)
from .sqlite_hearing_repository import SQLiteHearingRepository, _SQLiteHearingHost
from .sqlite_m5_repository_host import SQLiteM5RepositoryHost
from .sqlite_repository import (
    RepositoryIntegrityError,
    _contract_document,
    _document,
    _row_int,
    _row_optional_str,
    _row_str,
    _verify_contract_document,
)


@dataclass(frozen=True, slots=True)
class _HearingLoadedCaseView:
    snapshot: CaseSnapshot


class _M5HearingHostAdapter:
    """Preserve M4's richer internal Case load shape over the M3/M5 facade."""

    def __init__(self, repository: SQLiteM5RepositoryHost) -> None:
        self._repository = repository

    def _load_case(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        case_id: str,
    ) -> _HearingLoadedCaseView:
        return _HearingLoadedCaseView(
            snapshot=self._repository._load_case(connection, run_id, case_id)
        )

    def __getattr__(self, name: str) -> object:
        return getattr(self._repository, name)


class SQLiteM5PrecedentUsageRepository(SQLiteM5RepositoryHost):
    """Behavior-only mixin for exact final-round usage and APPLIED roots."""

    def _load_m5_exposure_in_connection(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        cycle_scope_id: str,
    ) -> M5PrecedentExposureBatchAuthority | None:
        hearings = SQLiteHearingRepository(cast(_SQLiteHearingHost, _M5HearingHostAdapter(self)))
        return load_m5_precedent_exposure_in_connection(
            connection,
            repository=self,
            hearing_repository=hearings,
            run_id=run_id,
            cycle_scope_id=cycle_scope_id,
        )

    @staticmethod
    def _has_m4_hearing_response(
        connection: sqlite3.Connection,
        *,
        run_id: str,
        response_ids: tuple[str, ...],
    ) -> bool:
        if not response_ids:
            return False
        placeholders = ", ".join("?" for _response_id in response_ids)
        row = connection.execute(
            f"""
            SELECT COUNT(*) AS count FROM m4_model_responses
            WHERE run_id = ? AND response_id IN ({placeholders})
            """,
            (run_id, *response_ids),
        ).fetchone()
        if row is None:
            raise RepositoryIntegrityError("M4 response-origin query returned no aggregate")
        return _row_int(row, "count") > 0

    def _resolve_ready_precedent_usage_in_connection(
        self,
        connection: sqlite3.Connection,
        snapshot: CaseSnapshot,
    ) -> M5ReadyPrecedentUsage:
        case = snapshot.case
        if case.status != CaseStatus.READY_FOR_ALERT_POLICY or not case.verdicts:
            raise ConcurrentModification("precedent usage requires a READY Case with a Verdict")
        verdict = case.verdicts[-1]
        binding_rows = connection.execute(
            """
            SELECT binding_id FROM m4_hearing_verdict_bindings
            WHERE run_id = ? AND case_id = ?
              AND verdict_id = ? AND verdict_version = ?
            LIMIT 2
            """,
            (case.run_id, case.case_id, verdict.verdict_id, verdict.version),
        ).fetchall()
        if len(binding_rows) > 1:
            raise RepositoryIntegrityError("latest Verdict has multiple M4 hearing bindings")
        if not binding_rows:
            response_ids = tuple(
                ref.artifact_id
                for ref in verdict.model_response_refs
                if ref.kind == ArtifactKind.MODEL_RESPONSE
            )
            if self._has_m4_hearing_response(
                connection,
                run_id=case.run_id,
                response_ids=response_ids,
            ):
                raise RepositoryIntegrityError("hearing-origin Verdict lost its M4 binding")
            if verdict.precedent_applications:
                raise RepositoryIntegrityError("fast Verdict contains precedent applications")
            self._require_application_roots_absent(
                connection,
                run_id=case.run_id,
                case_id=case.case_id,
            )
            return M5ReadyPrecedentUsage(kind=M5ReadyPrecedentUsageKind.FAST)

        hearings = SQLiteHearingRepository(cast(_SQLiteHearingHost, _M5HearingHostAdapter(self)))
        binding = hearings._load_hearing_verdict_binding(
            connection,
            case.run_id,
            _row_str(binding_rows[0], "binding_id"),
        )
        record = hearings._rebuild_hearing_record(
            connection,
            run_id=case.run_id,
            case_id=case.case_id,
            hearing_id=binding.hearing_session_id,
        )
        hearing_round = hearings._load_hearing_round(
            connection,
            case.run_id,
            binding.judge_round_id,
        )
        judge_payload = hearing_round.judge_output.payload
        if (
            binding.verdict_id != verdict.verdict_id
            or binding.verdict_version != verdict.version
            or binding.verdict_input_sha256 != verdict.verdict_input_sha256
            or binding.verdict_sha256 != verdict.verdict_sha256
            or binding.evidence_pack_id != verdict.evidence_pack_id
            or binding.evidence_pack_version != verdict.evidence_pack_version
            or binding.hearing_record_id != record.record_id
            or binding.hearing_record_version != record.version
            or binding.hearing_record_sha256 != record.record_sha256
            or not record.rounds
            or record.rounds[-1] != hearing_round
            or binding.judge_round_index != hearing_round.round_index
            or not isinstance(judge_payload, JudgeModelPayload)
            or not isinstance(judge_payload.outcome, JudgeFinalDecisionPayload)
        ):
            raise RepositoryIntegrityError(
                "latest READY Verdict does not close its exact terminal hearing record"
            )
        receipt = hearing_round.precedent_retrieval_receipt
        exposure = self._load_m5_exposure_in_connection(
            connection,
            case.run_id,
            hearing_round.cycle_scope_id,
        )
        if receipt.status == HearingPrecedentRetrievalStatus.DEGRADED:
            if exposure is not None or verdict.precedent_applications:
                raise RepositoryIntegrityError(
                    "final degraded hearing round cannot expose or apply precedents"
                )
            self._require_application_roots_absent(
                connection,
                run_id=case.run_id,
                case_id=case.case_id,
            )
            return M5ReadyPrecedentUsage(
                kind=M5ReadyPrecedentUsageKind.FINAL_DEGRADED,
                verdict_binding=binding,
                hearing_record=record,
                hearing_round=hearing_round,
                retrieval_receipt=receipt,
            )
        if exposure is None:
            raise EvidenceMissing("successful final hearing round lost its M5 exposure")
        return M5ReadyPrecedentUsage(
            kind=M5ReadyPrecedentUsageKind.FINAL_EXPOSED,
            verdict_binding=binding,
            hearing_record=record,
            hearing_round=hearing_round,
            retrieval_receipt=receipt,
            exposure=exposure,
        )

    def resolve_ready_precedent_usage(
        self,
        run_id: str,
        case_id: str,
        expected_revision: int,
    ) -> M5ReadyPrecedentUsage:
        require_reference_token(run_id, "M5 precedent usage run_id")
        require_reference_token(case_id, "M5 precedent usage case_id")
        if (
            not isinstance(expected_revision, int)
            or isinstance(expected_revision, bool)
            or expected_revision <= 0
        ):
            raise ValueError("expected_revision must be a positive integer")
        with self._read() as connection:
            self._load_run_manifest(connection, run_id)
            snapshot = self._load_case(connection, run_id, case_id)
            if snapshot.revision != expected_revision:
                raise ConcurrentModification(
                    f"case revision is {snapshot.revision}, expected {expected_revision}"
                )
            return self._resolve_ready_precedent_usage_in_connection(connection, snapshot)

    @staticmethod
    def _validated_application_batch(
        batch: M5PrecedentApplicationBatchAuthority | None,
    ) -> M5PrecedentApplicationBatchAuthority | None:
        if batch is None:
            return None
        if not isinstance(batch, M5PrecedentApplicationBatchAuthority):
            raise TypeError("application_batch must be an M5 application batch or None")
        try:
            return M5PrecedentApplicationBatchAuthority.model_validate(
                batch.model_dump(mode="json")
            )
        except (TypeError, ValidationError, ValueError) as exc:
            raise ContractViolation("M5 application batch is not canonical") from exc

    @staticmethod
    def _validated_application_citations(
        commits: tuple[M5PrecedentApplicationCitationCommit, ...],
    ) -> tuple[M5PrecedentApplicationCitationCommit, ...]:
        if not isinstance(commits, tuple):
            raise TypeError("application_citations must be a tuple")
        try:
            validated = tuple(
                M5PrecedentApplicationCitationCommit.model_validate(commit.model_dump(mode="json"))
                for commit in commits
            )
        except (AttributeError, TypeError, ValidationError, ValueError) as exc:
            raise ContractViolation("M5 application citations are not canonical") from exc
        if len({commit.commit_id for commit in validated}) != len(validated):
            raise ContractViolation("M5 application citation commits must be unique")
        return validated

    def _require_rebuilt_application_roots(
        self,
        *,
        snapshot: CaseSnapshot,
        usage: M5ReadyPrecedentUsage,
        proposed_batch: M5PrecedentApplicationBatchAuthority | None,
        proposed_citations: tuple[M5PrecedentApplicationCitationCommit, ...],
        cited_at: datetime,
    ) -> tuple[
        M5PrecedentApplicationBatchAuthority | None,
        tuple[M5PrecedentApplicationCitationCommit, ...],
    ]:
        if usage.kind != M5ReadyPrecedentUsageKind.FINAL_EXPOSED:
            if proposed_batch is not None or proposed_citations:
                raise ContractViolation("fast/degraded close cannot persist APPLIED roots")
            return None, ()
        exposure = usage.exposure
        if exposure is None:
            raise RepositoryIntegrityError("FINAL_EXPOSED usage lost its exposure")
        verifier = self._m5_precedent_application_verifier
        if verifier is None:
            raise ContractViolation("APPLIED close requires a precedent application verifier")
        try:
            rebuilt_batch = verifier.rebuild_application(snapshot, exposure)
            rebuilt_citations = verifier.rebuild_citations(rebuilt_batch, cited_at)
        except (TypeError, ValueError, ContractViolation) as exc:
            raise ContractViolation("trusted M5 APPLIED reconstruction failed") from exc
        if proposed_batch != rebuilt_batch or proposed_citations != rebuilt_citations:
            raise ContractViolation("proposed M5 APPLIED roots differ from trusted reconstruction")
        return rebuilt_batch, rebuilt_citations

    @staticmethod
    def _insert_application_batch(
        connection: sqlite3.Connection,
        *,
        batch: M5PrecedentApplicationBatchAuthority,
        closing_case_revision: int,
    ) -> None:
        raw, document_sha256 = _document(batch)
        connection.execute(
            """
            INSERT INTO m5_precedent_application_batches(
                run_id, application_batch_id, application_batch_sha256,
                case_id, ready_case_revision, closing_case_revision,
                ready_case_document_sha256,
                verdict_id, verdict_version, verdict_sha256,
                exposure_id, binding_count, config_sha256, manifest_id,
                application_batch_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                batch.run_id,
                batch.application_batch_id,
                batch.application_batch_sha256,
                batch.case_id,
                batch.ready_case_revision,
                closing_case_revision,
                batch.ready_case_document_sha256,
                batch.verdict.verdict_id,
                batch.verdict.version,
                batch.verdict.verdict_sha256,
                batch.exposure.exposure_id,
                len(batch.application_bindings),
                batch.config_sha256,
                batch.manifest_id,
                raw,
                document_sha256,
            ),
        )

    def _application_batch_from_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> M5PrecedentApplicationBatchAuthority:
        raw = _row_str(row, "application_batch_json")
        try:
            batch = M5PrecedentApplicationBatchAuthority.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored M5 application batch is invalid") from exc
        _verify_contract_document(raw, batch)
        canonical_raw, document_sha256 = _document(batch)
        if (
            canonical_raw != raw
            or _row_str(row, "run_id") != batch.run_id
            or _row_str(row, "application_batch_id") != batch.application_batch_id
            or _row_str(row, "application_batch_sha256") != batch.application_batch_sha256
            or _row_str(row, "case_id") != batch.case_id
            or _row_int(row, "ready_case_revision") != batch.ready_case_revision
            or _row_str(row, "ready_case_document_sha256") != batch.ready_case_document_sha256
            or _row_str(row, "verdict_id") != batch.verdict.verdict_id
            or _row_int(row, "verdict_version") != batch.verdict.version
            or _row_str(row, "verdict_sha256") != batch.verdict.verdict_sha256
            or _row_str(row, "exposure_id") != batch.exposure.exposure_id
            or _row_int(row, "binding_count") != len(batch.application_bindings)
            or _row_str(row, "config_sha256") != batch.config_sha256
            or _row_str(row, "manifest_id") != batch.manifest_id
            or _row_str(row, "document_sha256") != document_sha256
        ):
            raise RepositoryIntegrityError(
                "M5 application batch indexes conflict with canonical content"
            )
        exposure = self._load_m5_exposure_in_connection(
            connection,
            batch.run_id,
            batch.exposure.cycle_scope_id,
        )
        if exposure != batch.exposure:
            raise RepositoryIntegrityError("M5 application batch rewrites its exposure")
        return batch

    def _insert_application_citation(
        self,
        connection: sqlite3.Connection,
        *,
        commit: M5PrecedentApplicationCitationCommit,
        causal_fault_scope: str,
    ) -> None:
        citation = commit.citation
        citation_document = _contract_document(citation)
        commit_document = _contract_document(commit)
        result = commit.application_batch.exposure.m5_retrieval_result
        document_sha256 = hashlib.sha256(commit_document.encode("utf-8")).hexdigest()

        def insert_applied_citation_source() -> None:
            try:
                connection.execute(
                    """
                    INSERT INTO precedent_citations(
                        run_id, citation_kind, citation_id, commit_id,
                        case_id, precedent_id, precedent_authority_id, precedent_revision,
                        retrieval_result_id, application_batch_id, application_binding_id,
                        query_id, score, cited_at, manifest_id,
                        citation_json, commit_json, document_sha256
                    ) VALUES (?, 'APPLIED', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        citation.run_id,
                        citation.citation_id,
                        commit.commit_id,
                        citation.case_id,
                        citation.precedent_id,
                        citation.precedent_authority_id,
                        citation.precedent_revision,
                        result.result_id,
                        commit.application_batch.application_batch_id,
                        commit.application_binding.binding_id,
                        citation.query_id,
                        citation.score,
                        citation.model_dump(mode="json")["cited_at"],
                        commit.application_batch.manifest_id,
                        citation_document,
                        commit_document,
                        document_sha256,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ConcurrentModification("M5 APPLIED citation could not be appended") from exc

        append_m5_precedent_causal_event(
            connection,
            source=m5_precedent_citation_causal_source(
                citation,
                citation_kind=M5PrecedentCausalEventSourceKind.APPLIED,
                manifest_id=commit.application_batch.manifest_id,
                source_document_sha256=document_sha256,
            ),
            insert_source=insert_applied_citation_source,
            fault_scope=causal_fault_scope,
            fault=self._m5_fault,
        )

    def _stored_application_roots(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        case_id: str,
    ) -> tuple[
        M5PrecedentApplicationBatchAuthority | None,
        tuple[M5PrecedentApplicationCitationCommit, ...],
        int | None,
    ]:
        batch_rows = connection.execute(
            """
            SELECT * FROM m5_precedent_application_batches
            WHERE run_id = ? AND case_id = ?
            """,
            (run_id, case_id),
        ).fetchall()
        if len(batch_rows) > 1:
            raise RepositoryIntegrityError("Case has multiple M5 application batches")
        if not batch_rows:
            orphan = connection.execute(
                """
                SELECT 1 FROM precedent_citations
                WHERE run_id = ? AND case_id = ? AND citation_kind = 'APPLIED'
                LIMIT 1
                """,
                (run_id, case_id),
            ).fetchone()
            if orphan is not None:
                raise RepositoryIntegrityError("Case has APPLIED citations without a batch")
            return None, (), None
        row = batch_rows[0]
        batch = self._application_batch_from_row(connection, row)
        citation_rows = connection.execute(
            """
            SELECT * FROM precedent_citations
            WHERE run_id = ? AND case_id = ? AND citation_kind = 'APPLIED'
            """,
            (run_id, case_id),
        ).fetchall()
        expected_bindings = {binding.binding_id: binding for binding in batch.application_bindings}
        by_binding: dict[str, M5PrecedentApplicationCitationCommit] = {}
        for citation_row in citation_rows:
            commit = self._citation_commit_from_row(connection, citation_row)
            if not isinstance(commit, M5PrecedentApplicationCitationCommit):
                raise RepositoryIntegrityError("APPLIED citation row decoded as DIRECT")
            binding_id = commit.application_binding.binding_id
            expected_binding = expected_bindings.get(binding_id)
            if (
                commit.application_batch != batch
                or expected_binding is None
                or commit.application_binding != expected_binding
                or _row_optional_str(citation_row, "application_batch_id")
                != batch.application_batch_id
                or binding_id in by_binding
            ):
                raise RepositoryIntegrityError(
                    "APPLIED citation does not close its exact batch binding"
                )
            by_binding[binding_id] = commit
        ordered: list[M5PrecedentApplicationCitationCommit] = []
        for binding in batch.application_bindings:
            selected_commit = by_binding.pop(binding.binding_id, None)
            if selected_commit is None:
                raise RepositoryIntegrityError("application binding lost its exact citation")
            ordered.append(selected_commit)
        if by_binding:
            raise RepositoryIntegrityError("application batch has extra citation bindings")
        return batch, tuple(ordered), _row_int(row, "closing_case_revision")

    def _insert_application_roots(
        self,
        connection: sqlite3.Connection,
        *,
        batch: M5PrecedentApplicationBatchAuthority | None,
        citations: tuple[M5PrecedentApplicationCitationCommit, ...],
        closing_case_revision: int,
    ) -> None:
        if batch is None:
            if citations:
                raise RepositoryIntegrityError("application citations require a batch")
            return
        self._insert_application_batch(
            connection,
            batch=batch,
            closing_case_revision=closing_case_revision,
        )
        self._m5_fault("m5.alert.application_batch_inserted")
        for ordinal, commit in enumerate(citations, start=1):
            self._insert_application_citation(
                connection,
                commit=commit,
                causal_fault_scope=f"m5.alert.application_citation.{ordinal}",
            )
            self._m5_fault(f"m5.alert.application_citation.{ordinal}.inserted")
        self._m5_fault("m5.alert.application_citations_complete")

    @staticmethod
    def _require_application_roots_absent(
        connection: sqlite3.Connection,
        *,
        run_id: str,
        case_id: str,
    ) -> None:
        batch = connection.execute(
            """
            SELECT 1 FROM m5_precedent_application_batches
            WHERE run_id = ? AND case_id = ? LIMIT 1
            """,
            (run_id, case_id),
        ).fetchone()
        citation = connection.execute(
            """
            SELECT 1 FROM precedent_citations
            WHERE run_id = ? AND case_id = ? AND citation_kind = 'APPLIED'
            LIMIT 1
            """,
            (run_id, case_id),
        ).fetchone()
        if batch is not None or citation is not None:
            raise ConcurrentModification("closing Case already has M5 APPLIED roots")

    def _require_stored_application_roots(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        case_id: str,
        expected_batch: M5PrecedentApplicationBatchAuthority | None,
        expected_citations: tuple[M5PrecedentApplicationCitationCommit, ...],
        closing_case_revision: int,
    ) -> None:
        stored_batch, stored_citations, stored_closing_revision = self._stored_application_roots(
            connection,
            run_id=run_id,
            case_id=case_id,
        )
        if (
            stored_batch != expected_batch
            or stored_citations != expected_citations
            or (expected_batch is not None and stored_closing_revision != closing_case_revision)
            or (expected_batch is None and stored_closing_revision is not None)
        ):
            raise RepositoryIntegrityError("stored M5 APPLIED roots differ from close authority")


__all__ = ["SQLiteM5PrecedentUsageRepository"]

"""Atomic SQLite commit of M4 retrieval and independent M5 EXPOSED authority."""

from __future__ import annotations

import sqlite3

from pydantic import ValidationError

from labcourt.application.m5_hearing_precedent_bridge import (
    M5_HEARING_PRECEDENT_BRIDGE_MANIFEST_ID,
    M5_HEARING_PRECEDENT_BRIDGE_VERSION,
    build_m4_success_outcome,
    build_m5_precedent_exposure,
    build_m5_query_for_hearing,
    retrieve_m5_for_hearing,
)
from labcourt.contracts.hearing_retrieval import HearingPrecedentRetrievalOutcome
from labcourt.contracts.hearing_state import (
    HearingPrecedentRetrievalReceipt,
    HearingPrecedentRetrievalStatus,
)
from labcourt.contracts.m5_precedent_usage import M5PrecedentExposureBatchAuthority
from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import ConcurrentModification, ContractViolation
from labcourt.ports.m5_precedents import M5PrecedentEmbeddingProvider

from ._sqlite_m5_precedent_exposure_codec import (
    load_m5_precedent_exposure_in_connection,
)
from .sqlite_hearing_repository import SQLiteHearingRepository
from .sqlite_m5_repository import SQLiteM5Repository
from .sqlite_repository import (
    RepositoryIntegrityError,
    _document,
)


class SQLiteM5PrecedentExposureCommitter:
    """One ``BEGIN IMMEDIATE`` for the M4 receipt and complete M5 exposure."""

    def __init__(
        self,
        *,
        repository: SQLiteM5Repository,
        hearing_repository: SQLiteHearingRepository,
        embedding_provider: M5PrecedentEmbeddingProvider,
    ) -> None:
        required_repository_methods = (
            "_immediate",
            "_read",
            "_load_run_manifest",
            "_require_trusted_m5_precedent_policy",
            "_retrieval_candidates_in_connection",
            "_load_m5_precedent_revision",
            "_m5_fault",
        )
        if any(
            not callable(getattr(repository, method, None))
            for method in required_repository_methods
        ):
            raise TypeError("repository does not expose the guarded M5 transaction surface")
        required_hearing_methods = (
            "_load_hearing_session",
            "_load_hearing_cycle",
            "_load_precedent_retrieval",
            "_append_precedent_retrieval_in_connection",
        )
        if any(
            not callable(getattr(hearing_repository, method, None))
            for method in required_hearing_methods
        ):
            raise TypeError("hearing_repository lacks same-connection M4 helpers")
        if not callable(getattr(embedding_provider, "embed", None)):
            raise TypeError("embedding_provider must implement embed")
        self._repository = repository
        self._hearings = hearing_repository
        self._embedding_provider = embedding_provider

    @staticmethod
    def _validated_outcome(
        outcome: HearingPrecedentRetrievalOutcome,
    ) -> HearingPrecedentRetrievalOutcome:
        if not isinstance(outcome, HearingPrecedentRetrievalOutcome):
            raise TypeError("outcome must be a HearingPrecedentRetrievalOutcome")
        try:
            validated = HearingPrecedentRetrievalOutcome.model_validate(
                outcome.model_dump(mode="json")
            )
        except (TypeError, ValidationError, ValueError) as exc:
            raise ContractViolation("M5 bridge commit requires a canonical M4 outcome") from exc
        if validated.receipt.status == HearingPrecedentRetrievalStatus.SUCCESS:
            if validated.result is None:
                raise ContractViolation("M5 exposure requires a complete successful M4 outcome")
        elif validated.receipt.status == HearingPrecedentRetrievalStatus.DEGRADED:
            if validated.result is not None:
                raise ContractViolation("degraded M5 bridge commit cannot carry a result")
        else:
            raise ContractViolation("M5 bridge commit has an unsupported retrieval status")
        query = validated.query
        if (
            query.retriever_version != M5_HEARING_PRECEDENT_BRIDGE_VERSION
            or query.retriever_manifest_id != M5_HEARING_PRECEDENT_BRIDGE_MANIFEST_ID
        ):
            raise ContractViolation("M5 exposure requires the controlled production bridge")
        return validated

    def _load_exposure_in_connection(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        cycle_scope_id: str,
    ) -> M5PrecedentExposureBatchAuthority | None:
        return load_m5_precedent_exposure_in_connection(
            connection,
            repository=self._repository,
            hearing_repository=self._hearings,
            run_id=run_id,
            cycle_scope_id=cycle_scope_id,
        )

    def load_exposure(
        self,
        run_id: str,
        cycle_scope_id: str,
    ) -> M5PrecedentExposureBatchAuthority | None:
        require_reference_token(run_id, "M5 exposure run_id")
        require_reference_token(cycle_scope_id, "M5 exposure cycle_scope_id")
        with self._repository._read() as connection:
            self._repository._load_run_manifest(connection, run_id)
            return self._load_exposure_in_connection(
                connection,
                run_id,
                cycle_scope_id,
            )

    @staticmethod
    def _insert_exposure(
        connection: sqlite3.Connection,
        exposure: M5PrecedentExposureBatchAuthority,
    ) -> None:
        outcome = exposure.m4_retrieval_outcome
        m5 = exposure.m5_retrieval_result
        exposure_json, document_sha256 = _document(exposure)
        connection.execute(
            """
            INSERT INTO m5_precedent_exposures(
                run_id, exposure_id, exposure_sha256, case_id, hearing_id,
                cycle_index, cycle_scope_id, cycle_scope_sha256,
                retrieval_receipt_id, m4_query_id, m5_query_id, m5_result_id,
                candidate_count, exposed_count, policy_id,
                bridge_manifest_id, manifest_id, exposure_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                exposure.run_id,
                exposure.exposure_id,
                exposure.exposure_sha256,
                exposure.case_id,
                exposure.hearing_session_id,
                exposure.cycle_index,
                exposure.cycle_scope_id,
                exposure.cycle_scope_sha256,
                outcome.receipt.receipt_id,
                outcome.query.query_id,
                m5.query.query_id,
                m5.result_id,
                m5.candidate_count,
                len(exposure.exposed_precedents),
                exposure.policy_id,
                exposure.bridge_manifest_id,
                exposure.manifest_id,
                exposure_json,
                document_sha256,
            ),
        )

    def commit(
        self,
        outcome: HearingPrecedentRetrievalOutcome,
    ) -> HearingPrecedentRetrievalReceipt:
        proposed = self._validated_outcome(outcome)
        query = proposed.query
        try:
            with self._repository._immediate() as connection:
                manifest = self._repository._load_run_manifest(connection, query.run_id)
                if (
                    manifest.manifest_id != query.manifest_id
                    or manifest.config_sha256 != query.config_sha256
                ):
                    raise ContractViolation(
                        "M5 bridge query conflicts with the durable run manifest"
                    )
                if proposed.receipt.status == HearingPrecedentRetrievalStatus.DEGRADED:
                    if (
                        self._load_exposure_in_connection(
                            connection,
                            query.run_id,
                            query.cycle_scope_id,
                        )
                        is not None
                    ):
                        raise ContractViolation(
                            "degraded M5 bridge cycle already has an exposure authority"
                        )
                    self._repository._m5_fault("m5.precedent_exposure.before_m4_receipt")
                    canonical = self._hearings._append_precedent_retrieval_in_connection(
                        connection,
                        query.run_id,
                        proposed.receipt,
                    )
                    self._repository._m5_fault("m5.precedent_exposure.after_m4_receipt")
                    return canonical
                existing = self._load_exposure_in_connection(
                    connection,
                    query.run_id,
                    query.cycle_scope_id,
                )
                if existing is not None:
                    if existing.m4_retrieval_outcome.query != query:
                        raise ContractViolation(
                            "M5 exposure cycle identity was replayed with another query"
                        )
                    return existing.m4_retrieval_outcome.receipt

                policy, run_mode = self._repository._require_trusted_m5_precedent_policy(manifest)
                session = self._hearings._load_hearing_session(
                    connection,
                    query.run_id,
                    query.hearing_session_id,
                )
                cycle = self._hearings._load_hearing_cycle(
                    connection,
                    query.run_id,
                    query.cycle_scope_id,
                )
                if (
                    session.session_sha256 != query.hearing_session_sha256
                    or session.case_id != query.case_id
                    or session.manifest_id != query.manifest_id
                ):
                    raise ContractViolation(
                        "M5 exposure query conflicts with its persisted hearing session"
                    )
                m5_query = build_m5_query_for_hearing(
                    query=query,
                    manifest=manifest,
                    policy=policy,
                    run_mode=run_mode,
                    embedding_provider=self._embedding_provider,
                )
                candidates = self._repository._retrieval_candidates_in_connection(
                    connection,
                    m5_query,
                )
                m5_result, m4_result = retrieve_m5_for_hearing(
                    query=query,
                    manifest=manifest,
                    policy=policy,
                    run_mode=run_mode,
                    candidates=candidates,
                    embedding_provider=self._embedding_provider,
                )
                expected = build_m4_success_outcome(
                    query=query,
                    result=m4_result,
                    cycle_scope=cycle,
                )
                if expected != proposed:
                    raise ConcurrentModification(
                        "M5 precedent corpus changed before exposure commit"
                    )
                exposure = build_m5_precedent_exposure(
                    outcome=expected,
                    result=m5_result,
                )

                self._repository._m5_fault("m5.precedent_exposure.before_m4_receipt")
                canonical = self._hearings._append_precedent_retrieval_in_connection(
                    connection,
                    query.run_id,
                    expected.receipt,
                )
                self._repository._m5_fault("m5.precedent_exposure.after_m4_receipt")
                self._insert_exposure(connection, exposure)
                self._repository._m5_fault("m5.precedent_exposure.after_exposure")
                if canonical != exposure.m4_retrieval_outcome.receipt:
                    raise RepositoryIntegrityError(
                        "M5 exposure transaction returned a non-canonical M4 receipt"
                    )
                return canonical
        except sqlite3.IntegrityError as exc:
            raise ContractViolation("M5 precedent exposure authority was rejected") from exc


__all__ = ["SQLiteM5PrecedentExposureCommitter"]

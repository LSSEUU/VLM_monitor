"""Immutable SQLite authority for M5 precedents, embeddings, and citations."""

from __future__ import annotations

import hashlib
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.adapters.fake_precedent_embeddings import (
    DeterministicFakePrecedentEmbeddingProvider,
)
from labcourt.application.m5_embedding_integrity import (
    M5EmbeddingIntegrityError,
    build_m5_controlled_fake_embedding,
)
from labcourt.application.m5_precedents import (
    ExactM5PrecedentRetrievalService,
    evaluate_m5_automatic_activation,
    record_m5_precedent_citation,
    resolve_m5_precedent_conflict_batch,
    revoke_m5_precedent,
)
from labcourt.contracts.audit import AuditEntry
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.enums import (
    ArtifactKind,
    AuditAction,
    AuditActorRole,
    CaseStatus,
    PrecedentSource,
    PrecedentStatus,
    RunMode,
)
from labcourt.contracts.m5_appeals import AppealVersionAuthority, PrecedentRevocationIntent
from labcourt.contracts.m5_precedent_causal_ledger import (
    M5_PRECEDENT_CAUSAL_GENESIS_SHA256,
    M5PrecedentCausalEventKind,
    M5PrecedentCausalEventSourceKind,
)
from labcourt.contracts.m5_precedent_usage import M5PrecedentApplicationCitationCommit
from labcourt.contracts.m5_precedents import (
    MAX_M5_CITATION_SNAPSHOT_ENTRIES,
    MAX_M5_PRECEDENTS,
    M5AppealWindowSnapshot,
    M5EmbeddingChannel,
    M5EmbeddingVector,
    M5PrecedentActivationOutcome,
    M5PrecedentActivationReceipt,
    M5PrecedentActivationResult,
    M5PrecedentAuthority,
    M5PrecedentCitationAuthority,
    M5PrecedentCitationCommit,
    M5PrecedentCitationSnapshot,
    M5PrecedentConflictBatchAuthority,
    M5PrecedentConflictBatchReceipt,
    M5PrecedentConflictBatchResolution,
    M5PrecedentConflictCausalCut,
    M5PrecedentConflictReceipt,
    M5PrecedentConflictResolution,
    M5PrecedentConflictSnapshot,
    M5PrecedentPolicy,
    M5PrecedentRetrievalQuery,
    M5PrecedentRetrievalResult,
    M5PrecedentRevocationReceipt,
    M5PrecedentRevocationResult,
    m5_precedent_active_head_root_sha256,
)
from labcourt.contracts.manifests import ModelManifest, RunManifest
from labcourt.contracts.references import require_reference_token
from labcourt.contracts.storage import ArtifactRef
from labcourt.exceptions import (
    ConcurrentModification,
    ContractViolation,
    EvidenceMissing,
    ManifestMismatch,
)

from ._m5_precedent_conflict_history import (
    M5PrecedentConflictHistoryError,
    rebuild_m5_precedent_conflict_history,
)
from ._sqlite_m5_precedent_causal_ledger import (
    append_m5_precedent_causal_event,
    load_m5_precedent_causal_events,
    m5_precedent_authority_causal_source,
    m5_precedent_citation_causal_source,
    m5_precedent_conflict_receipt_causal_source,
    m5_precedent_revocation_receipt_causal_source,
    require_m5_precedent_causal_event,
)
from .sqlite_m5_case_transitions import m5_case_transition_audit
from .sqlite_m5_repository_host import SQLiteM5RepositoryHost
from .sqlite_repository import (
    RepositoryIntegrityError,
    _contract_document,
    _row_int,
    _row_optional_str,
    _row_str,
    _verify_contract_document,
    _verify_document,
)

_LifecycleReceipt = (
    M5PrecedentActivationReceipt | M5PrecedentConflictReceipt | M5PrecedentRevocationReceipt
)
_LifecycleContext = M5AppealWindowSnapshot | M5PrecedentPolicy | M5PrecedentCitationSnapshot
_CitationCommit = M5PrecedentCitationCommit | M5PrecedentApplicationCitationCommit
_ContractT = TypeVar("_ContractT", bound=BaseModel)


def _canonical_document_sha256(document: str) -> str:
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


def _validated_contract(
    model: _ContractT,
    model_type: type[_ContractT],
    name: str,
) -> _ContractT:
    try:
        return model_type.model_validate(model.model_dump(mode="json"))
    except (TypeError, ValidationError, ValueError) as exc:
        raise ContractViolation(f"{name} is not a valid canonical contract") from exc


class SQLiteM5PrecedentRepository(SQLiteM5RepositoryHost):
    """Behavior-only mixin; the public facade supplies transactions and guards."""

    def _require_trusted_m5_precedent_policy(
        self,
        manifest: RunManifest,
        *,
        claimed_policy: M5PrecedentPolicy | None = None,
        write: bool = False,
    ) -> tuple[M5PrecedentPolicy, RunMode]:
        verifier = self._m5_precedent_policy_verifier
        if verifier is None:
            raise ContractViolation("trusted M5 precedent policy verifier is required")
        expected = verifier.expected_policy(manifest)
        run_mode = verifier.run_mode
        if not isinstance(expected, M5PrecedentPolicy) or not isinstance(run_mode, RunMode):
            raise ContractViolation(
                "trusted M5 precedent policy verifier returned invalid authority"
            )
        expected = _validated_contract(
            expected,
            M5PrecedentPolicy,
            "trusted M5 precedent policy",
        )
        if expected.config_sha256 != manifest.config_sha256:
            raise ManifestMismatch("trusted M5 precedent policy differs from the run manifest")
        if claimed_policy is not None and (
            claimed_policy != expected or claimed_policy.policy_id != expected.policy_id
        ):
            raise ManifestMismatch("claimed M5 precedent policy differs from trusted AppConfig")
        if write and run_mode != RunMode.STANDARD:
            raise ContractViolation("OFFLINE_EXPERIMENT M5 precedent authority is read-only")
        return expected, run_mode

    @staticmethod
    def _validated_public_preset_authority(
        authority: M5PrecedentAuthority,
    ) -> M5PrecedentAuthority:
        validated = _validated_contract(
            authority,
            M5PrecedentAuthority,
            "M5 precedent authority",
        )
        if (
            validated.revision != 1
            or validated.precedent.source != PrecedentSource.PRESET
            or validated.precedent.status != PrecedentStatus.ACTIVE
            or validated.precedent.source_case_id is not None
            or validated.precedent.citation_count != 0
        ):
            raise ContractViolation(
                "public M5 append accepts only an initial active PRESET authority"
            )
        return validated

    @staticmethod
    def _m5_embedding_manifest(
        manifest: RunManifest,
        channel: M5EmbeddingChannel,
    ) -> ModelManifest:
        key = {
            M5EmbeddingChannel.TEXT: "text_embedding",
            M5EmbeddingChannel.VISUAL: "visual_embedding",
        }[channel]
        component = manifest.models[key]
        if component.component != key:
            raise RepositoryIntegrityError(
                f"run manifest {key} key contains another model component"
            )
        return component

    def _require_controlled_m5_embedding_content(
        self,
        *,
        situation_text: str,
        text_embedding: M5EmbeddingVector | None,
        visual_embeddings: tuple[M5EmbeddingVector, ...],
        manifest: RunManifest,
        stored: bool,
        context: str,
    ) -> None:
        text_model = self._m5_embedding_manifest(manifest, M5EmbeddingChannel.TEXT)
        visual_model = self._m5_embedding_manifest(manifest, M5EmbeddingChannel.VISUAL)

        def fail_manifest(message: str) -> None:
            if stored:
                raise RepositoryIntegrityError(message)
            raise ManifestMismatch(message)

        if text_embedding is not None and (
            text_embedding.request.model_manifest_id != text_model.model_manifest_id
        ):
            fail_manifest(f"{context} TEXT embedding is not pinned to text_embedding")
        if any(
            embedding.request.model_manifest_id != visual_model.model_manifest_id
            for embedding in visual_embeddings
        ):
            fail_manifest(f"{context} VISUAL embedding is not pinned to visual_embedding")

        provider = DeterministicFakePrecedentEmbeddingProvider()
        try:
            expected_text = (
                build_m5_controlled_fake_embedding(
                    channel=M5EmbeddingChannel.TEXT,
                    situation_text=situation_text,
                    model_manifest=text_model,
                    embedding_provider=provider,
                )
                if text_embedding is not None
                else None
            )
            expected_visuals = tuple(
                sorted(
                    (
                        build_m5_controlled_fake_embedding(
                            channel=M5EmbeddingChannel.VISUAL,
                            situation_text=situation_text,
                            model_manifest=visual_model,
                            embedding_provider=provider,
                            ordinal=ordinal,
                        )
                        for ordinal in range(len(visual_embeddings))
                    ),
                    key=lambda item: item.embedding_id,
                )
            )
        except M5EmbeddingIntegrityError as exc:
            if stored:
                raise RepositoryIntegrityError(
                    f"stored {context} embedding cannot be reconstructed"
                ) from exc
            raise ContractViolation(f"{context} embedding cannot be reconstructed") from exc
        if expected_text != text_embedding or expected_visuals != visual_embeddings:
            if stored:
                raise RepositoryIntegrityError(
                    f"stored {context} vector differs from controlled fake reconstruction"
                )
            raise ContractViolation(f"{context} vector differs from controlled fake reconstruction")

    def _load_m5_embedding(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        embedding_id: str,
        manifest_id: str,
        expected_channel: M5EmbeddingChannel,
        expected_model_manifest_id: str,
    ) -> M5EmbeddingVector:
        row = connection.execute(
            """
            SELECT * FROM precedent_embeddings
            WHERE run_id = ? AND embedding_id = ?
            """,
            (run_id, embedding_id),
        ).fetchone()
        if row is None:
            raise RepositoryIntegrityError("precedent authority references a missing embedding")
        raw = _row_str(row, "embedding_json")
        try:
            embedding = M5EmbeddingVector.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored precedent embedding is invalid") from exc
        _verify_contract_document(raw, embedding)
        request = embedding.request
        indexed = (
            _row_str(row, "run_id") == run_id,
            _row_str(row, "embedding_id") == embedding.embedding_id,
            _row_str(row, "request_id") == request.request_id,
            _row_str(row, "channel") == request.channel.value,
            _row_str(row, "input_ref") == request.input_ref,
            _row_str(row, "input_sha256") == request.input_sha256,
            _row_str(row, "model_manifest_id") == request.model_manifest_id,
            _row_int(row, "dimensions") == request.dimensions,
            _row_str(row, "algorithm") == request.algorithm,
            _row_str(row, "manifest_id") == manifest_id,
            _row_str(row, "document_sha256") == _canonical_document_sha256(raw),
            request.channel == expected_channel,
            request.model_manifest_id == expected_model_manifest_id,
        )
        if not all(indexed):
            raise RepositoryIntegrityError(
                "precedent embedding index columns do not match its canonical document"
            )
        return embedding

    def _insert_m5_embedding(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        embedding: M5EmbeddingVector,
        manifest_id: str,
        expected_channel: M5EmbeddingChannel,
        expected_model_manifest_id: str,
    ) -> M5EmbeddingVector:
        validated = _validated_contract(embedding, M5EmbeddingVector, "M5 embedding")
        request = validated.request
        if request.channel != expected_channel:
            raise ContractViolation("M5 embedding channel differs from its authority slot")
        if request.model_manifest_id != expected_model_manifest_id:
            raise ManifestMismatch("M5 embedding model is not pinned to its channel manifest")
        rows = connection.execute(
            """
            SELECT embedding_id FROM precedent_embeddings
            WHERE run_id = ? AND (embedding_id = ? OR request_id = ?)
            LIMIT 2
            """,
            (run_id, validated.embedding_id, request.request_id),
        ).fetchall()
        if rows:
            if len(rows) != 1:
                raise RepositoryIntegrityError("embedding identities resolve to multiple rows")
            durable = self._load_m5_embedding(
                connection,
                run_id=run_id,
                embedding_id=_row_str(rows[0], "embedding_id"),
                manifest_id=manifest_id,
                expected_channel=expected_channel,
                expected_model_manifest_id=expected_model_manifest_id,
            )
            if durable != validated:
                raise ConcurrentModification("M5 embedding identity collision")
            return durable
        document = _contract_document(validated)
        try:
            connection.execute(
                """
                INSERT INTO precedent_embeddings(
                    run_id, embedding_id, request_id, channel, input_ref,
                    input_sha256, model_manifest_id, dimensions, algorithm,
                    manifest_id, embedding_json, document_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    validated.embedding_id,
                    request.request_id,
                    request.channel.value,
                    request.input_ref,
                    request.input_sha256,
                    request.model_manifest_id,
                    request.dimensions,
                    request.algorithm,
                    manifest_id,
                    document,
                    _canonical_document_sha256(document),
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ConcurrentModification("M5 embedding could not be appended") from exc
        return validated

    @staticmethod
    def _require_m5_successor(
        current: M5PrecedentAuthority,
        proposed: M5PrecedentAuthority,
    ) -> None:
        current_precedent = current.precedent
        proposed_precedent = proposed.precedent
        immutable_precedent = (
            "precedent_id",
            "situation_text",
            "text_embedding_ref",
            "visual_embedding_refs",
            "decision_direction",
            "source",
            "evidence_class",
            "violation_type",
            "rule_version",
            "source_case_id",
        )
        if (
            proposed.run_id != current.run_id
            or proposed.revision != current.revision + 1
            or proposed.created_at != current.created_at
            or proposed.activation_not_before != current.activation_not_before
            or proposed.text_embedding != current.text_embedding
            or proposed.visual_embeddings != current.visual_embeddings
            or any(
                getattr(proposed_precedent, name) != getattr(current_precedent, name)
                for name in immutable_precedent
            )
            or proposed_precedent.citation_count != 0
            or current_precedent.citation_count != 0
        ):
            raise ContractViolation("M5 precedent successor changes immutable authority")

    def _m5_authority_from_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> M5PrecedentAuthority:
        raw = _row_str(row, "authority_json")
        try:
            authority = M5PrecedentAuthority.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored M5 precedent authority is invalid") from exc
        _verify_contract_document(raw, authority)
        manifest = self._load_run_manifest(connection, authority.run_id)
        text_model = self._m5_embedding_manifest(manifest, M5EmbeddingChannel.TEXT)
        visual_model = self._m5_embedding_manifest(manifest, M5EmbeddingChannel.VISUAL)
        precedent = authority.precedent
        dump = authority.model_dump(mode="json")
        visual_ids = [item.embedding_id for item in authority.visual_embeddings]
        indexed = (
            _row_str(row, "run_id") == authority.run_id,
            _row_str(row, "precedent_id") == precedent.precedent_id,
            _row_int(row, "revision") == authority.revision,
            _row_str(row, "authority_id") == authority.authority_id,
            _row_str(row, "status") == precedent.status.value,
            _row_str(row, "source") == precedent.source.value,
            _row_str(row, "evidence_class") == precedent.evidence_class.value,
            _row_str(row, "violation_type") == precedent.violation_type.value,
            _row_str(row, "decision_direction") == precedent.decision_direction.value,
            _row_str(row, "rule_version") == precedent.rule_version,
            _row_optional_str(row, "source_case_id") == precedent.source_case_id,
            _row_int(row, "citation_count") == precedent.citation_count,
            _row_optional_str(row, "text_embedding_id")
            == (authority.text_embedding.embedding_id if authority.text_embedding else None),
            _row_str(row, "visual_embedding_ids_json") == canonical_json(visual_ids),
            _row_str(row, "created_at") == dump["created_at"],
            _row_optional_str(row, "activation_not_before") == dump["activation_not_before"],
            _row_optional_str(row, "activated_at") == dump["activated_at"],
            _row_str(row, "manifest_id") == manifest.manifest_id,
            _row_str(row, "document_sha256") == _canonical_document_sha256(raw),
            authority.config_sha256 == manifest.config_sha256,
            precedent.rule_version == manifest.rule_version,
        )
        if not all(indexed):
            raise RepositoryIntegrityError(
                "M5 precedent index columns do not match its canonical document"
            )
        if authority.text_embedding is not None:
            durable_text = self._load_m5_embedding(
                connection,
                run_id=authority.run_id,
                embedding_id=authority.text_embedding.embedding_id,
                manifest_id=manifest.manifest_id,
                expected_channel=M5EmbeddingChannel.TEXT,
                expected_model_manifest_id=text_model.model_manifest_id,
            )
            if durable_text != authority.text_embedding:
                raise RepositoryIntegrityError("M5 text embedding authority is inconsistent")
        for expected in authority.visual_embeddings:
            durable_visual = self._load_m5_embedding(
                connection,
                run_id=authority.run_id,
                embedding_id=expected.embedding_id,
                manifest_id=manifest.manifest_id,
                expected_channel=M5EmbeddingChannel.VISUAL,
                expected_model_manifest_id=visual_model.model_manifest_id,
            )
            if durable_visual != expected:
                raise RepositoryIntegrityError("M5 visual embedding authority is inconsistent")
        self._require_controlled_m5_embedding_content(
            situation_text=authority.precedent.situation_text,
            text_embedding=authority.text_embedding,
            visual_embeddings=authority.visual_embeddings,
            manifest=manifest,
            stored=True,
            context="M5 precedent authority",
        )
        require_m5_precedent_causal_event(
            connection,
            source=m5_precedent_authority_causal_source(
                authority,
                manifest_id=manifest.manifest_id,
                source_document_sha256=_row_str(row, "document_sha256"),
            ),
        )
        return authority

    def _load_m5_precedent_revision(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        precedent_id: str,
        revision: int,
    ) -> M5PrecedentAuthority | None:
        row = connection.execute(
            """
            SELECT * FROM precedents
            WHERE run_id = ? AND precedent_id = ? AND revision = ?
            """,
            (run_id, precedent_id, revision),
        ).fetchone()
        if row is None:
            return None
        return self._m5_authority_from_row(connection, row)

    def _load_m5_precedent_authority(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        precedent_id: str,
    ) -> M5PrecedentAuthority | None:
        row = connection.execute(
            """
            SELECT * FROM precedents
            WHERE run_id = ? AND precedent_id = ?
            ORDER BY revision DESC
            LIMIT 1
            """,
            (run_id, precedent_id),
        ).fetchone()
        if row is None:
            return None
        authority = self._m5_authority_from_row(connection, row)
        shape = connection.execute(
            """
            SELECT COUNT(*) AS revision_count, MIN(revision) AS first_revision,
                   MAX(revision) AS last_revision
            FROM precedents WHERE run_id = ? AND precedent_id = ?
            """,
            (run_id, precedent_id),
        ).fetchone()
        if shape is None or (
            _row_int(shape, "revision_count") != authority.revision
            or _row_int(shape, "first_revision") != 1
            or _row_int(shape, "last_revision") != authority.revision
        ):
            raise RepositoryIntegrityError("M5 precedent revision history is not contiguous")
        return authority

    def _insert_m5_precedent_authority(
        self,
        connection: sqlite3.Connection,
        authority: M5PrecedentAuthority,
        expected_revision: int | None,
        *,
        causal_fault_scope: str,
    ) -> M5PrecedentAuthority:
        validated = _validated_contract(
            authority,
            M5PrecedentAuthority,
            "M5 precedent authority",
        )
        if isinstance(expected_revision, bool) or (
            expected_revision is not None
            and (not isinstance(expected_revision, int) or expected_revision < 1)
        ):
            raise ContractViolation("expected M5 precedent revision must be null or positive")
        manifest = self._load_run_manifest(connection, validated.run_id)
        if validated.config_sha256 != manifest.config_sha256:
            raise ManifestMismatch("M5 precedent config differs from the run manifest")
        if validated.precedent.rule_version != manifest.rule_version:
            raise ManifestMismatch("M5 precedent rule version differs from the run manifest")
        if validated.precedent.source_case_id is not None:
            case_row = connection.execute(
                """
                SELECT manifest_id FROM cases WHERE run_id = ? AND case_id = ?
                """,
                (validated.run_id, validated.precedent.source_case_id),
            ).fetchone()
            if case_row is None:
                raise EvidenceMissing("M5 precedent source Case does not exist")
            if _row_str(case_row, "manifest_id") != manifest.manifest_id:
                raise ManifestMismatch("M5 precedent source Case uses another manifest")

        current = self._load_m5_precedent_authority(
            connection,
            validated.run_id,
            validated.precedent.precedent_id,
        )
        if current is not None and current.authority_id == validated.authority_id:
            replay_revision = None if validated.revision == 1 else validated.revision - 1
            if current != validated or expected_revision != replay_revision:
                raise ConcurrentModification("M5 precedent authority replay differs")
            return current
        if current is None:
            if expected_revision is not None or validated.revision != 1:
                raise ConcurrentModification("M5 precedent initial revision changed")
            count_row = connection.execute(
                """
                SELECT COUNT(*) AS precedent_count
                FROM precedents WHERE run_id = ? AND revision = 1
                """,
                (validated.run_id,),
            ).fetchone()
            if count_row is None or _row_int(count_row, "precedent_count") >= MAX_M5_PRECEDENTS:
                raise ContractViolation("M5 precedent corpus exceeds its hard bound")
        else:
            if expected_revision != current.revision:
                raise ConcurrentModification("M5 precedent revision changed")
            self._require_m5_successor(current, validated)

        self._require_controlled_m5_embedding_content(
            situation_text=validated.precedent.situation_text,
            text_embedding=validated.text_embedding,
            visual_embeddings=validated.visual_embeddings,
            manifest=manifest,
            stored=False,
            context="M5 precedent authority",
        )
        text_model = self._m5_embedding_manifest(manifest, M5EmbeddingChannel.TEXT)
        visual_model = self._m5_embedding_manifest(manifest, M5EmbeddingChannel.VISUAL)
        if validated.text_embedding is not None:
            self._insert_m5_embedding(
                connection,
                run_id=validated.run_id,
                embedding=validated.text_embedding,
                manifest_id=manifest.manifest_id,
                expected_channel=M5EmbeddingChannel.TEXT,
                expected_model_manifest_id=text_model.model_manifest_id,
            )
        for embedding in validated.visual_embeddings:
            self._insert_m5_embedding(
                connection,
                run_id=validated.run_id,
                embedding=embedding,
                manifest_id=manifest.manifest_id,
                expected_channel=M5EmbeddingChannel.VISUAL,
                expected_model_manifest_id=visual_model.model_manifest_id,
            )
        precedent = validated.precedent
        document = _contract_document(validated)
        document_sha256 = _canonical_document_sha256(document)
        dump = validated.model_dump(mode="json")

        def insert_authority_source() -> None:
            try:
                connection.execute(
                    """
                    INSERT INTO precedents(
                        run_id, precedent_id, revision, authority_id, status, source,
                        evidence_class, violation_type, decision_direction, rule_version,
                        source_case_id, citation_count, text_embedding_id,
                        visual_embedding_ids_json, created_at, activation_not_before,
                        activated_at, manifest_id, authority_json, document_sha256
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        validated.run_id,
                        precedent.precedent_id,
                        validated.revision,
                        validated.authority_id,
                        precedent.status.value,
                        precedent.source.value,
                        precedent.evidence_class.value,
                        precedent.violation_type.value,
                        precedent.decision_direction.value,
                        precedent.rule_version,
                        precedent.source_case_id,
                        precedent.citation_count,
                        validated.text_embedding.embedding_id if validated.text_embedding else None,
                        canonical_json([item.embedding_id for item in validated.visual_embeddings]),
                        dump["created_at"],
                        dump["activation_not_before"],
                        dump["activated_at"],
                        manifest.manifest_id,
                        document,
                        document_sha256,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ConcurrentModification(
                    "M5 precedent authority could not be appended"
                ) from exc

        append_m5_precedent_causal_event(
            connection,
            source=m5_precedent_authority_causal_source(
                validated,
                manifest_id=manifest.manifest_id,
                source_document_sha256=document_sha256,
            ),
            insert_source=insert_authority_source,
            fault_scope=causal_fault_scope,
            fault=self._m5_fault,
        )
        durable = self._load_m5_precedent_revision(
            connection,
            validated.run_id,
            precedent.precedent_id,
            validated.revision,
        )
        if durable != validated:
            raise RepositoryIntegrityError("M5 precedent append did not preserve exact authority")
        return validated

    @staticmethod
    def _require_reference(value: str, name: str) -> str:
        try:
            return require_reference_token(value, name)
        except (TypeError, ValueError) as exc:
            raise ContractViolation(f"{name} is invalid") from exc

    @staticmethod
    def _require_utc_datetime(value: datetime, name: str) -> datetime:
        if not isinstance(value, datetime):
            raise ContractViolation(f"{name} must be a datetime")
        if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
            raise ContractViolation(f"{name} must use timezone-aware UTC")
        return value

    def get(  # type: ignore[override]
        self,
        run_id: str,
        precedent_id: str,
    ) -> M5PrecedentAuthority | None:
        self._require_reference(run_id, "M5 run_id")
        self._require_reference(precedent_id, "M5 precedent_id")
        with self._read() as connection:
            self._load_run_manifest(connection, run_id)
            return self._load_m5_precedent_authority(connection, run_id, precedent_id)

    def _retrieval_candidates_in_connection(
        self,
        connection: sqlite3.Connection,
        query: M5PrecedentRetrievalQuery,
    ) -> tuple[M5PrecedentAuthority, ...]:
        manifest = self._load_run_manifest(connection, query.run_id)
        _expected_policy, trusted_run_mode = self._require_trusted_m5_precedent_policy(
            manifest,
            claimed_policy=query.policy,
        )
        expected_include_provisional = trusted_run_mode == RunMode.OFFLINE_EXPERIMENT
        if (
            query.run_mode != trusted_run_mode
            or query.include_provisional_experiment != expected_include_provisional
        ):
            raise ManifestMismatch(
                "M5 retrieval mode and provisional visibility differ from trusted AppConfig"
            )
        if query.rule_version != manifest.rule_version:
            raise ManifestMismatch("M5 retrieval rule differs from the run manifest")
        text_model = self._m5_embedding_manifest(manifest, M5EmbeddingChannel.TEXT)
        visual_model = self._m5_embedding_manifest(manifest, M5EmbeddingChannel.VISUAL)
        if (
            query.text_embedding_model_manifest_id != text_model.model_manifest_id
            or query.visual_embedding_model_manifest_id != visual_model.model_manifest_id
        ):
            raise ManifestMismatch(
                "M5 retrieval model manifest bindings differ from the run manifest"
            )
        self._require_controlled_m5_embedding_content(
            situation_text=query.situation_text,
            text_embedding=query.text_embedding,
            visual_embeddings=query.visual_embeddings,
            manifest=manifest,
            stored=False,
            context="M5 retrieval query",
        )
        case_row = connection.execute(
            "SELECT manifest_id FROM cases WHERE run_id = ? AND case_id = ?",
            (query.run_id, query.case_id),
        ).fetchone()
        if case_row is None:
            raise EvidenceMissing("M5 retrieval Case does not exist")
        if _row_str(case_row, "manifest_id") != manifest.manifest_id:
            raise ManifestMismatch("M5 retrieval Case uses another manifest")
        rows = connection.execute(
            """
            SELECT p.precedent_id
            FROM precedents AS p
            JOIN (
                SELECT run_id, precedent_id, MAX(revision) AS revision
                FROM precedents
                WHERE run_id = ?
                GROUP BY run_id, precedent_id
            ) AS latest
              ON latest.run_id = p.run_id
             AND latest.precedent_id = p.precedent_id
             AND latest.revision = p.revision
            WHERE p.run_id = ?
            ORDER BY p.precedent_id
            LIMIT ?
            """,
            (
                query.run_id,
                query.run_id,
                MAX_M5_PRECEDENTS + 1,
            ),
        ).fetchall()
        if len(rows) > MAX_M5_PRECEDENTS:
            raise RepositoryIntegrityError("M5 precedent corpus exceeds its hard bound")
        authorities: list[M5PrecedentAuthority] = []
        for row in rows:
            authority = self._load_m5_precedent_authority(
                connection,
                query.run_id,
                _row_str(row, "precedent_id"),
            )
            if authority is None:
                raise RepositoryIntegrityError("retrieval index references no precedent")
            if authority.config_sha256 != manifest.config_sha256:
                raise RepositoryIntegrityError("M5 retrieval index changed during read")
            authorities.append(authority)
        return tuple(authorities)

    def list_for_retrieval(
        self,
        query: M5PrecedentRetrievalQuery,
    ) -> tuple[M5PrecedentAuthority, ...]:
        validated = _validated_contract(
            query,
            M5PrecedentRetrievalQuery,
            "M5 precedent retrieval query",
        )
        with self._read() as connection:
            return self._retrieval_candidates_in_connection(connection, validated)

    def list_conflicts(
        self,
        run_id: str,
        limit: int,
    ) -> tuple[M5PrecedentAuthority, ...]:
        self._require_reference(run_id, "M5 run_id")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= MAX_M5_PRECEDENTS
        ):
            raise ContractViolation(
                f"M5 conflict limit must be an integer in [1, {MAX_M5_PRECEDENTS}]"
            )
        with self._read() as connection:
            self._load_run_manifest(connection, run_id)
            rows = connection.execute(
                """
                SELECT p.precedent_id
                FROM precedents AS p
                JOIN (
                    SELECT run_id, precedent_id, MAX(revision) AS revision
                    FROM precedents
                    WHERE run_id = ?
                    GROUP BY run_id, precedent_id
                ) AS latest
                  ON latest.run_id = p.run_id
                 AND latest.precedent_id = p.precedent_id
                 AND latest.revision = p.revision
                WHERE p.run_id = ? AND p.status = 'CONFLICT'
                ORDER BY p.precedent_id
                LIMIT ?
                """,
                (run_id, run_id, limit),
            ).fetchall()
            result: list[M5PrecedentAuthority] = []
            for row in rows:
                authority = self._load_m5_precedent_authority(
                    connection,
                    run_id,
                    _row_str(row, "precedent_id"),
                )
                if authority is None or authority.precedent.status != PrecedentStatus.CONFLICT:
                    raise RepositoryIntegrityError("M5 conflict index is inconsistent")
                result.append(authority)
            return tuple(result)

    def _conflict_candidates_in_connection(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        limit: int,
    ) -> tuple[M5PrecedentAuthority, ...]:
        self._require_reference(run_id, "M5 run_id")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= MAX_M5_PRECEDENTS
        ):
            raise ContractViolation(
                f"M5 conflict candidate limit must be an integer in [1, {MAX_M5_PRECEDENTS}]"
            )
        self._load_run_manifest(connection, run_id)
        rows = connection.execute(
            """
            SELECT p.precedent_id
            FROM precedents AS p
            JOIN (
                SELECT run_id, precedent_id, MAX(revision) AS revision
                FROM precedents
                WHERE run_id = ?
                GROUP BY run_id, precedent_id
            ) AS latest
              ON latest.run_id = p.run_id
             AND latest.precedent_id = p.precedent_id
             AND latest.revision = p.revision
            WHERE p.run_id = ? AND p.status = 'ACTIVE'
            ORDER BY p.precedent_id
            LIMIT ?
            """,
            (run_id, run_id, MAX_M5_PRECEDENTS + 1),
        ).fetchall()
        if len(rows) > MAX_M5_PRECEDENTS:
            raise RepositoryIntegrityError("M5 precedent corpus exceeds its hard bound")
        candidates: list[M5PrecedentAuthority] = []
        for row in rows:
            authority = self._load_m5_precedent_authority(
                connection,
                run_id,
                _row_str(row, "precedent_id"),
            )
            if authority is None or authority.precedent.status != PrecedentStatus.ACTIVE:
                raise RepositoryIntegrityError("M5 conflict candidate index is inconsistent")
            candidates.append(authority)
        expected = tuple(sorted(candidates, key=lambda item: item.precedent.precedent_id))
        if tuple(candidates) != expected:
            raise RepositoryIntegrityError("M5 conflict candidate order is inconsistent")
        if len(expected) > limit:
            raise ContractViolation(
                "M5 conflict candidate complete snapshot budget "
                f"{limit} is smaller than {len(expected)} active candidates"
            )
        return expected

    def _conflict_snapshot_in_connection(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        limit: int,
        policy: M5PrecedentPolicy,
    ) -> M5PrecedentConflictSnapshot:
        manifest = self._load_run_manifest(connection, run_id)
        if policy.config_sha256 != manifest.config_sha256:
            raise ManifestMismatch("M5 conflict policy differs from the run manifest")
        events = load_m5_precedent_causal_events(connection, run_id=run_id)
        authorities = self._conflict_candidates_in_connection(connection, run_id, limit)
        authority_events = tuple(
            event
            for event in events
            if event.event_kind == M5PrecedentCausalEventKind.PRECEDENT_AUTHORITY_APPENDED
        )
        if authority_events:
            watermark_sequence = authority_events[-1].sequence
            watermark_sha256 = authority_events[-1].event_sha256
        else:
            watermark_sequence = 0
            watermark_sha256 = M5_PRECEDENT_CAUSAL_GENESIS_SHA256
        active_root = m5_precedent_active_head_root_sha256(
            run_id=run_id,
            heads=tuple(
                (
                    authority.precedent.precedent_id,
                    authority.authority_id,
                    authority.revision,
                )
                for authority in authorities
            ),
        )
        cut = M5PrecedentConflictCausalCut(
            run_id=run_id,
            manifest_id=manifest.manifest_id,
            config_sha256=manifest.config_sha256,
            policy_id=policy.policy_id,
            authority_event_sequence=watermark_sequence,
            authority_event_sha256=watermark_sha256,
            active_head_count=len(authorities),
            active_head_root_sha256=active_root,
        )
        return M5PrecedentConflictSnapshot(
            causal_cut=cut,
            authorities=authorities,
        )

    def load_conflict_snapshot(
        self,
        run_id: str,
        limit: int,
    ) -> M5PrecedentConflictSnapshot:
        self._require_reference(run_id, "M5 run_id")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= MAX_M5_PRECEDENTS
        ):
            raise ContractViolation(
                f"M5 conflict candidate limit must be an integer in [1, {MAX_M5_PRECEDENTS}]"
            )
        with self._read() as connection:
            manifest = self._load_run_manifest(connection, run_id)
            policy, _run_mode = self._require_trusted_m5_precedent_policy(
                manifest,
                write=True,
            )
            return self._conflict_snapshot_in_connection(
                connection,
                run_id=run_id,
                limit=limit,
                policy=policy,
            )

    def _has_appeal_present_activation_receipt(
        self,
        connection: sqlite3.Connection,
        authority: M5PrecedentAuthority,
    ) -> bool:
        rows = connection.execute(
            """
            SELECT * FROM precedent_lifecycle_receipts
            WHERE run_id = ?
              AND receipt_kind = 'ACTIVATION'
              AND primary_precedent_id = ?
              AND primary_prior_authority_id = ?
            ORDER BY receipt_id
            LIMIT ?
            """,
            (
                authority.run_id,
                authority.precedent.precedent_id,
                authority.authority_id,
                MAX_M5_PRECEDENTS + 1,
            ),
        ).fetchall()
        if len(rows) > MAX_M5_PRECEDENTS:
            raise RepositoryIntegrityError(
                "M5 activation evaluation history exceeds its hard bound"
            )
        appeal_present = False
        for row in rows:
            receipt = self._lifecycle_receipt_from_row(connection, row)
            if (
                not isinstance(receipt, M5PrecedentActivationReceipt)
                or receipt.precedent_id != authority.precedent.precedent_id
                or receipt.prior_authority_id != authority.authority_id
            ):
                raise RepositoryIntegrityError(
                    "M5 activation evaluation index differs from its receipt"
                )
            if receipt.outcome == M5PrecedentActivationOutcome.APPEAL_PRESENT:
                appeal_present = True
        return appeal_present

    def list_activation_candidates(
        self,
        run_id: str,
        evaluated_at: datetime,
        limit: int,
    ) -> tuple[M5PrecedentAuthority, ...]:
        self._require_reference(run_id, "M5 run_id")
        self._require_utc_datetime(evaluated_at, "M5 activation evaluation timestamp")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= MAX_M5_PRECEDENTS
        ):
            raise ContractViolation(
                f"M5 activation candidate limit must be an integer in [1, {MAX_M5_PRECEDENTS}]"
            )
        with self._read() as connection:
            manifest = self._load_run_manifest(connection, run_id)
            expected_policy, _run_mode = self._require_trusted_m5_precedent_policy(
                manifest,
                write=True,
            )
            rows = connection.execute(
                """
                SELECT p.precedent_id
                FROM precedents AS p
                JOIN (
                    SELECT run_id, precedent_id, MAX(revision) AS revision
                    FROM precedents
                    WHERE run_id = ?
                    GROUP BY run_id, precedent_id
                ) AS latest
                  ON latest.run_id = p.run_id
                 AND latest.precedent_id = p.precedent_id
                 AND latest.revision = p.revision
                WHERE p.run_id = ?
                  AND p.source = 'AUTOMATIC'
                  AND p.status = 'PROVISIONAL'
                ORDER BY p.precedent_id
                LIMIT ?
                """,
                (run_id, run_id, MAX_M5_PRECEDENTS + 1),
            ).fetchall()
            if len(rows) > MAX_M5_PRECEDENTS:
                raise RepositoryIntegrityError("M5 precedent corpus exceeds its hard bound")
            eligible: list[M5PrecedentAuthority] = []
            for row in rows:
                authority = self._load_m5_precedent_authority(
                    connection,
                    run_id,
                    _row_str(row, "precedent_id"),
                )
                if (
                    authority is None
                    or authority.precedent.source != PrecedentSource.AUTOMATIC
                    or authority.precedent.status != PrecedentStatus.PROVISIONAL
                    or authority.activation_not_before is None
                ):
                    raise RepositoryIntegrityError("M5 activation candidate index is inconsistent")
                expected_not_before = authority.created_at + timedelta(
                    seconds=expected_policy.automatic_activation_delay_seconds
                )
                if authority.activation_not_before != expected_not_before:
                    raise RepositoryIntegrityError(
                        "M5 automatic precedent cooling period differs from trusted policy"
                    )
                if (
                    authority.activation_not_before <= evaluated_at
                    and not self._has_appeal_present_activation_receipt(connection, authority)
                ):
                    eligible.append(authority)
            eligible.sort(
                key=lambda item: (
                    item.activation_not_before,
                    item.precedent.precedent_id,
                )
            )
            return tuple(eligible[:limit])

    def append_authority(
        self,
        authority: M5PrecedentAuthority,
        expected_revision: int | None,
    ) -> M5PrecedentAuthority:
        validated = self._validated_public_preset_authority(authority)
        if expected_revision is not None:
            raise ContractViolation(
                "public M5 append accepts only an initial active PRESET authority"
            )
        with self._immediate() as connection:
            manifest = self._load_run_manifest(connection, validated.run_id)
            self._require_trusted_m5_precedent_policy(manifest, write=True)
            self._m5_fault("precedent.append.before")
            durable = self._insert_m5_precedent_authority(
                connection,
                validated,
                expected_revision,
                causal_fault_scope="precedent.append.authority",
            )
            self._m5_fault("precedent.append.after")
            return durable

    def append_authorities(
        self,
        run_id: str,
        authorities: tuple[M5PrecedentAuthority, ...],
    ) -> tuple[M5PrecedentAuthority, ...]:
        """Atomically append or exactly replay one complete public PRESET batch."""

        self._require_reference(run_id, "M5 run_id")
        if not isinstance(authorities, tuple):
            raise TypeError("authorities must be a tuple")
        if len(authorities) > MAX_M5_PRECEDENTS:
            raise ContractViolation("M5 precedent import exceeds its hard authority bound")
        validated = tuple(self._validated_public_preset_authority(item) for item in authorities)
        ordered = tuple(sorted(validated, key=lambda item: item.precedent.precedent_id))
        precedent_ids = tuple(item.precedent.precedent_id for item in ordered)
        if len(precedent_ids) != len(set(precedent_ids)):
            raise ContractViolation("M5 precedent import contains duplicate precedent IDs")
        if any(item.run_id != run_id for item in ordered):
            raise ContractViolation("M5 precedent import contains an authority from another run")

        with self._immediate() as connection:
            manifest = self._load_run_manifest(connection, run_id)
            self._require_trusted_m5_precedent_policy(manifest, write=True)
            current = tuple(
                self._load_m5_precedent_authority(connection, run_id, precedent_id)
                for precedent_id in precedent_ids
            )
            if current and all(item is not None for item in current):
                durable = tuple(item for item in current if item is not None)
                if durable != ordered:
                    raise ConcurrentModification("M5 precedent import replay differs")
                return durable
            if any(item is not None for item in current):
                raise ConcurrentModification("M5 precedent import is only partially present")

            count_row = connection.execute(
                "SELECT COUNT(*) AS precedent_count FROM precedents "
                "WHERE run_id = ? AND revision = 1",
                (run_id,),
            ).fetchone()
            if (
                count_row is None
                or _row_int(count_row, "precedent_count") + len(ordered) > MAX_M5_PRECEDENTS
            ):
                raise ContractViolation("M5 precedent corpus exceeds its hard bound")

            self._m5_fault("precedent.import.before_authorities")
            accepted: list[M5PrecedentAuthority] = []
            for ordinal, authority_item in enumerate(ordered, start=1):
                accepted.append(
                    self._insert_m5_precedent_authority(
                        connection,
                        authority_item,
                        None,
                        causal_fault_scope=f"precedent.import.authority.{ordinal}",
                    )
                )
                self._m5_fault("precedent.import.after_authority")
            self._m5_fault("precedent.import.after_authorities")
            return tuple(accepted)

    def _historical_retrieval_candidates(
        self,
        connection: sqlite3.Connection,
        result: M5PrecedentRetrievalResult,
    ) -> tuple[M5PrecedentAuthority, ...]:
        """Resolve and exactly replay a result without consulting mutable heads."""

        candidates: list[M5PrecedentAuthority] = []
        for evaluation in result.candidate_evaluations:
            claimed = evaluation.authority
            durable = self._load_m5_precedent_revision(
                connection,
                claimed.run_id,
                claimed.precedent.precedent_id,
                claimed.revision,
            )
            if durable is None or durable != claimed:
                raise RepositoryIntegrityError(
                    "M5 retrieval inventory references a missing historical authority"
                )
            candidates.append(durable)
        try:
            rebuilt = ExactM5PrecedentRetrievalService().retrieve(
                result.query,
                tuple(candidates),
            )
        except (TypeError, ValueError, RuntimeError) as exc:
            raise RepositoryIntegrityError(
                "M5 historical retrieval inventory cannot be replayed"
            ) from exc
        if rebuilt != result:
            raise RepositoryIntegrityError(
                "M5 historical retrieval inventory or evaluation is not exact"
            )
        return tuple(candidates)

    def _citation_commit_from_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> _CitationCommit:
        commit_raw = _row_str(row, "commit_json")
        citation_raw = _row_str(row, "citation_json")
        citation_kind = _row_str(row, "citation_kind")
        try:
            if citation_kind == "DIRECT":
                direct_commit = M5PrecedentCitationCommit.model_validate_json(commit_raw)
                commit: _CitationCommit = direct_commit
                retrieval_result = direct_commit.retrieval_result
                application_batch_id = None
                application_binding_id = None
            elif citation_kind == "APPLIED":
                applied_commit = M5PrecedentApplicationCitationCommit.model_validate_json(
                    commit_raw
                )
                commit = applied_commit
                retrieval_result = applied_commit.application_batch.exposure.m5_retrieval_result
                application_batch_id = applied_commit.application_batch.application_batch_id
                application_binding_id = applied_commit.application_binding.binding_id
            else:
                raise RepositoryIntegrityError("stored M5 citation kind is invalid")
            citation = M5PrecedentCitationAuthority.model_validate_json(citation_raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored M5 citation commit is invalid") from exc
        _verify_contract_document(commit_raw, commit)
        _verify_contract_document(citation_raw, citation)
        if citation != commit.citation:
            raise RepositoryIntegrityError("M5 citation root differs from its commit")
        historical = self._load_m5_precedent_revision(
            connection,
            citation.run_id,
            citation.precedent_id,
            citation.precedent_revision,
        )
        if historical is None or historical.authority_id != citation.precedent_authority_id:
            raise RepositoryIntegrityError("M5 citation references a missing authority revision")
        self._historical_retrieval_candidates(connection, retrieval_result)
        if citation_kind == "APPLIED":
            batch_row = connection.execute(
                """
                SELECT * FROM m5_precedent_application_batches
                WHERE run_id = ? AND application_batch_id = ?
                """,
                (citation.run_id, application_batch_id),
            ).fetchone()
            if batch_row is None:
                raise RepositoryIntegrityError("APPLIED citation references a missing batch")
            durable_batch = self._application_batch_from_row(connection, batch_row)
            assert isinstance(commit, M5PrecedentApplicationCitationCommit)
            expected_binding = next(
                (
                    binding
                    for binding in durable_batch.application_bindings
                    if binding.binding_id == application_binding_id
                ),
                None,
            )
            if (
                commit.application_batch != durable_batch
                or expected_binding is None
                or commit.application_binding != expected_binding
            ):
                raise RepositoryIntegrityError(
                    "APPLIED citation does not close its exact durable batch binding"
                )
        score = row["score"]
        dump = citation.model_dump(mode="json")
        manifest = self._load_run_manifest(connection, citation.run_id)
        indexed = (
            _row_str(row, "run_id") == citation.run_id,
            _row_str(row, "citation_id") == citation.citation_id,
            _row_str(row, "commit_id") == commit.commit_id,
            _row_str(row, "case_id") == citation.case_id,
            _row_str(row, "precedent_id") == citation.precedent_id,
            _row_str(row, "precedent_authority_id") == citation.precedent_authority_id,
            _row_int(row, "precedent_revision") == citation.precedent_revision,
            _row_str(row, "retrieval_result_id") == retrieval_result.result_id,
            _row_optional_str(row, "application_batch_id") == application_batch_id,
            _row_optional_str(row, "application_binding_id") == application_binding_id,
            _row_str(row, "query_id") == citation.query_id,
            isinstance(score, float) and not isinstance(score, bool) and score == citation.score,
            _row_str(row, "cited_at") == dump["cited_at"],
            _row_str(row, "manifest_id") == manifest.manifest_id,
            _row_str(row, "document_sha256") == _canonical_document_sha256(commit_raw),
        )
        if not all(indexed):
            raise RepositoryIntegrityError(
                "M5 citation index columns do not match its canonical document"
            )
        require_m5_precedent_causal_event(
            connection,
            source=m5_precedent_citation_causal_source(
                citation,
                citation_kind=M5PrecedentCausalEventSourceKind(citation_kind),
                manifest_id=manifest.manifest_id,
                source_document_sha256=_row_str(row, "document_sha256"),
            ),
        )
        return commit

    def _find_citation_commit(
        self,
        connection: sqlite3.Connection,
        commit: M5PrecedentCitationCommit,
    ) -> M5PrecedentCitationCommit | None:
        citation = commit.citation
        rows = connection.execute(
            """
            SELECT * FROM precedent_citations
            WHERE run_id = ? AND (
                citation_id = ? OR commit_id = ?
                OR (case_id = ? AND precedent_id = ? AND query_id = ?)
            )
            LIMIT 2
            """,
            (
                citation.run_id,
                citation.citation_id,
                commit.commit_id,
                citation.case_id,
                citation.precedent_id,
                citation.query_id,
            ),
        ).fetchall()
        if not rows:
            return None
        if len(rows) != 1:
            raise RepositoryIntegrityError("M5 citation identities resolve to multiple rows")
        durable = self._citation_commit_from_row(connection, rows[0])
        if durable != commit:
            raise ConcurrentModification("M5 citation identity collision")
        return durable

    def commit_citation(
        self,
        commit: M5PrecedentCitationCommit,
    ) -> M5PrecedentCitationCommit:
        validated = _validated_contract(
            commit,
            M5PrecedentCitationCommit,
            "M5 precedent citation commit",
        )
        citation = validated.citation
        with self._immediate() as connection:
            manifest = self._load_run_manifest(connection, citation.run_id)
            self._require_trusted_m5_precedent_policy(
                manifest,
                claimed_policy=validated.retrieval_result.query.policy,
                write=True,
            )
            replay = self._find_citation_commit(connection, validated)
            if replay is not None:
                return replay
            current_candidates = self._retrieval_candidates_in_connection(
                connection,
                validated.retrieval_result.query,
            )
            current_ids = tuple(item.precedent.precedent_id for item in current_candidates)
            historical_ids = tuple(
                item.authority.precedent.precedent_id
                for item in validated.retrieval_result.candidate_evaluations
            )
            if historical_ids != current_ids:
                raise ContractViolation(
                    "M5 citation retrieval inventory is missing or adds a precedent identity"
                )
            try:
                self._historical_retrieval_candidates(
                    connection,
                    validated.retrieval_result,
                )
                rebuilt_commit = record_m5_precedent_citation(
                    result=validated.retrieval_result,
                    precedent_id=citation.precedent_id,
                    cited_at=citation.cited_at,
                )
            except (RepositoryIntegrityError, TypeError, ValueError, RuntimeError) as exc:
                raise ContractViolation(
                    "M5 citation historical retrieval cannot be rebuilt"
                ) from exc
            if rebuilt_commit != validated:
                raise ContractViolation("M5 citation commit differs from the exact retrieval fact")
            case_row = connection.execute(
                "SELECT manifest_id FROM cases WHERE run_id = ? AND case_id = ?",
                (citation.run_id, citation.case_id),
            ).fetchone()
            if case_row is None:
                raise EvidenceMissing("M5 citation Case does not exist")
            if _row_str(case_row, "manifest_id") != manifest.manifest_id:
                raise ManifestMismatch("M5 citation Case uses another manifest")
            self._m5_fault("precedent.citation.before_append")
            citation_document = _contract_document(citation)
            commit_document = _contract_document(validated)
            commit_document_sha256 = _canonical_document_sha256(commit_document)
            cited_at = citation.model_dump(mode="json")["cited_at"]

            def insert_direct_citation_source() -> None:
                try:
                    connection.execute(
                        """
                        INSERT INTO precedent_citations(
                            run_id, citation_kind, citation_id, commit_id,
                            case_id, precedent_id,
                            precedent_authority_id, precedent_revision,
                            retrieval_result_id,
                            application_batch_id, application_binding_id,
                            query_id,
                            score, cited_at, manifest_id, citation_json, commit_json,
                            document_sha256
                        ) VALUES (
                            ?, 'DIRECT', ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?, ?, ?, ?, ?
                        )
                        """,
                        (
                            citation.run_id,
                            citation.citation_id,
                            validated.commit_id,
                            citation.case_id,
                            citation.precedent_id,
                            citation.precedent_authority_id,
                            citation.precedent_revision,
                            validated.retrieval_result.result_id,
                            citation.query_id,
                            citation.score,
                            cited_at,
                            manifest.manifest_id,
                            citation_document,
                            commit_document,
                            commit_document_sha256,
                        ),
                    )
                except sqlite3.IntegrityError as exc:
                    raise ConcurrentModification("M5 citation could not be appended") from exc

            append_m5_precedent_causal_event(
                connection,
                source=m5_precedent_citation_causal_source(
                    citation,
                    citation_kind=M5PrecedentCausalEventSourceKind.DIRECT,
                    manifest_id=manifest.manifest_id,
                    source_document_sha256=commit_document_sha256,
                ),
                insert_source=insert_direct_citation_source,
                fault_scope="precedent.citation.direct",
                fault=self._m5_fault,
            )
            self._m5_fault("precedent.citation.after_append")
            durable = self._find_citation_commit(connection, validated)
            if durable is None:
                raise RepositoryIntegrityError("M5 citation commit disappeared")
            return durable

    def _citation_authorities(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        precedent_id: str,
    ) -> tuple[M5PrecedentCitationAuthority, ...]:
        rows = connection.execute(
            """
            SELECT * FROM precedent_citations
            WHERE run_id = ? AND precedent_id = ?
            ORDER BY case_id, citation_id
            LIMIT ?
            """,
            (run_id, precedent_id, MAX_M5_CITATION_SNAPSHOT_ENTRIES + 1),
        ).fetchall()
        if len(rows) > MAX_M5_CITATION_SNAPSHOT_ENTRIES:
            raise RepositoryIntegrityError("M5 citation snapshot exceeds its hard bound")
        return tuple(self._citation_commit_from_row(connection, row).citation for row in rows)

    def _citation_snapshot_in_connection(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        precedent_id: str,
        captured_at: datetime,
    ) -> M5PrecedentCitationSnapshot:
        exists = connection.execute(
            "SELECT 1 FROM precedents WHERE run_id = ? AND precedent_id = ? LIMIT 1",
            (run_id, precedent_id),
        ).fetchone()
        if exists is None:
            raise EvidenceMissing("M5 citation snapshot precedent does not exist")
        citations = self._citation_authorities(
            connection,
            run_id=run_id,
            precedent_id=precedent_id,
        )
        try:
            return M5PrecedentCitationSnapshot(
                run_id=run_id,
                precedent_id=precedent_id,
                captured_at=captured_at,
                citations=citations,
            )
        except ValidationError as exc:
            raise RepositoryIntegrityError("M5 citation snapshot cannot be reconstructed") from exc

    def citation_snapshot(
        self,
        run_id: str,
        precedent_id: str,
    ) -> M5PrecedentCitationSnapshot:
        self._require_reference(run_id, "M5 run_id")
        self._require_reference(precedent_id, "M5 precedent_id")
        recorded_at = self._recorded_at()
        captured_at = datetime.fromisoformat(recorded_at.replace("Z", "+00:00")).astimezone(UTC)
        with self._read() as connection:
            return self._citation_snapshot_in_connection(
                connection,
                run_id=run_id,
                precedent_id=precedent_id,
                captured_at=captured_at,
            )

    @staticmethod
    def _lifecycle_projection(
        receipt: _LifecycleReceipt,
    ) -> tuple[
        str,
        str,
        str,
        int,
        str,
        int,
        str | None,
        str | None,
        int | None,
        str | None,
        int | None,
    ]:
        if isinstance(receipt, M5PrecedentActivationReceipt):
            return (
                "ACTIVATION",
                receipt.precedent_id,
                receipt.prior_authority_id,
                receipt.prior_revision,
                receipt.resulting_authority_id,
                receipt.resulting_revision,
                None,
                None,
                None,
                None,
                None,
            )
        if isinstance(receipt, M5PrecedentRevocationReceipt):
            return (
                "REVOCATION",
                receipt.precedent_id,
                receipt.prior_authority_id,
                receipt.prior_revision,
                receipt.resulting_authority_id,
                receipt.resulting_revision,
                None,
                None,
                None,
                None,
                None,
            )
        return (
            "CONFLICT",
            receipt.existing_precedent_id,
            receipt.existing_prior_authority_id,
            receipt.existing_prior_revision,
            receipt.existing_resulting_authority_id,
            receipt.existing_resulting_revision,
            receipt.new_precedent_id,
            receipt.new_prior_authority_id,
            receipt.new_prior_revision,
            receipt.new_resulting_authority_id,
            receipt.new_resulting_revision,
        )

    def _lifecycle_receipt_from_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> _LifecycleReceipt:
        raw = _row_str(row, "receipt_json")
        kind = _row_str(row, "receipt_kind")
        model_type: type[_LifecycleReceipt]
        if kind == "ACTIVATION":
            model_type = M5PrecedentActivationReceipt
        elif kind == "CONFLICT":
            model_type = M5PrecedentConflictReceipt
        elif kind == "REVOCATION":
            model_type = M5PrecedentRevocationReceipt
        else:
            raise RepositoryIntegrityError("stored M5 lifecycle receipt kind is invalid")
        try:
            receipt = model_type.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored M5 lifecycle receipt is invalid") from exc
        _verify_contract_document(raw, receipt)
        (
            expected_kind,
            primary_id,
            primary_prior_id,
            primary_prior_revision,
            primary_result_id,
            primary_result_revision,
            secondary_id,
            secondary_prior_id,
            secondary_prior_revision,
            secondary_result_id,
            secondary_result_revision,
        ) = self._lifecycle_projection(receipt)
        manifest = self._load_run_manifest(connection, receipt.run_id)
        indexed = (
            kind == expected_kind,
            _row_str(row, "run_id") == receipt.run_id,
            _row_str(row, "receipt_id") == receipt.receipt_id,
            _row_str(row, "outcome") == receipt.outcome.value,
            _row_str(row, "primary_precedent_id") == primary_id,
            _row_str(row, "primary_prior_authority_id") == primary_prior_id,
            _row_int(row, "primary_prior_revision") == primary_prior_revision,
            _row_str(row, "primary_resulting_authority_id") == primary_result_id,
            _row_int(row, "primary_resulting_revision") == primary_result_revision,
            _row_optional_str(row, "secondary_precedent_id") == secondary_id,
            _row_optional_str(row, "secondary_prior_authority_id") == secondary_prior_id,
            row["secondary_prior_revision"] == secondary_prior_revision,
            _row_optional_str(row, "secondary_resulting_authority_id") == secondary_result_id,
            row["secondary_resulting_revision"] == secondary_result_revision,
            _row_str(row, "manifest_id") == manifest.manifest_id,
            _row_str(row, "document_sha256") == _canonical_document_sha256(raw),
        )
        if not all(indexed):
            raise RepositoryIntegrityError(
                "M5 lifecycle index columns do not match its canonical document"
            )
        context = self._lifecycle_context_from_row(row, kind)
        if isinstance(context, M5PrecedentPolicy):
            self._require_trusted_m5_precedent_policy(
                manifest,
                claimed_policy=context,
            )
        context_matches = (
            (
                isinstance(receipt, M5PrecedentActivationReceipt)
                and isinstance(context, M5AppealWindowSnapshot)
                and receipt.appeal_snapshot_id == context.snapshot_id
            )
            or (
                isinstance(receipt, M5PrecedentConflictReceipt)
                and isinstance(context, M5PrecedentPolicy)
                and receipt.policy_id == context.policy_id
            )
            or (
                isinstance(receipt, M5PrecedentRevocationReceipt)
                and isinstance(context, M5PrecedentCitationSnapshot)
                and receipt.citation_snapshot_id == context.snapshot_id
            )
        )
        if not context_matches:
            raise RepositoryIntegrityError("M5 lifecycle context does not bind its receipt")
        authority_refs: tuple[tuple[str, str, int], ...] = (
            (primary_id, primary_prior_id, primary_prior_revision),
            (primary_id, primary_result_id, primary_result_revision),
        )
        if secondary_id is not None:
            assert secondary_prior_id is not None
            assert secondary_prior_revision is not None
            assert secondary_result_id is not None
            assert secondary_result_revision is not None
            authority_refs += (
                (secondary_id, secondary_prior_id, secondary_prior_revision),
                (secondary_id, secondary_result_id, secondary_result_revision),
            )
        for precedent_id, authority_id, revision in authority_refs:
            authority = self._load_m5_precedent_revision(
                connection,
                receipt.run_id,
                precedent_id,
                revision,
            )
            if authority is None or authority.authority_id != authority_id:
                raise RepositoryIntegrityError(
                    "M5 lifecycle receipt references a missing authority revision"
                )
        return receipt

    @staticmethod
    def _lifecycle_context_from_row(
        row: sqlite3.Row,
        kind: str,
    ) -> _LifecycleContext:
        raw = _row_str(row, "context_json")
        try:
            if kind == "ACTIVATION":
                context: _LifecycleContext = M5AppealWindowSnapshot.model_validate_json(raw)
            elif kind == "CONFLICT":
                context = M5PrecedentPolicy.model_validate_json(raw)
            elif kind == "REVOCATION":
                context = M5PrecedentCitationSnapshot.model_validate_json(raw)
            else:
                raise RepositoryIntegrityError("stored M5 lifecycle context kind is invalid")
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored M5 lifecycle context is invalid") from exc
        _verify_contract_document(raw, context)
        if _row_str(row, "context_sha256") != _canonical_document_sha256(raw):
            raise RepositoryIntegrityError("stored M5 lifecycle context hash differs")
        return context

    def _find_lifecycle_receipt(
        self,
        connection: sqlite3.Connection,
        receipt: _LifecycleReceipt,
        context: _LifecycleContext,
    ) -> _LifecycleReceipt | None:
        (
            kind,
            primary_id,
            primary_prior_id,
            _primary_prior_revision,
            _primary_result_id,
            _primary_result_revision,
            secondary_id,
            secondary_prior_id,
            _secondary_prior_revision,
            _secondary_result_id,
            _secondary_result_revision,
        ) = self._lifecycle_projection(receipt)
        receipt_rows = connection.execute(
            """
            SELECT * FROM precedent_lifecycle_receipts
            WHERE run_id = ? AND receipt_id = ?
            LIMIT 2
            """,
            (receipt.run_id, receipt.receipt_id),
        ).fetchall()
        if len(receipt_rows) > 1:
            raise RepositoryIntegrityError("M5 lifecycle receipt identity is ambiguous")
        if receipt_rows:
            rows = receipt_rows
        elif kind == "ACTIVATION":
            rows = connection.execute(
                """
                SELECT * FROM precedent_lifecycle_receipts
                WHERE run_id = ?
                  AND receipt_kind = 'ACTIVATION'
                  AND outcome = 'APPEAL_PRESENT'
                  AND primary_precedent_id = ?
                  AND primary_prior_authority_id = ?
                  AND primary_prior_revision = ?
                LIMIT 2
                """,
                (
                    receipt.run_id,
                    primary_id,
                    primary_prior_id,
                    _primary_prior_revision,
                ),
            ).fetchall()
        else:
            rows = connection.execute(
                """
                SELECT * FROM precedent_lifecycle_receipts
                WHERE run_id = ?
                  AND receipt_kind = ?
                  AND primary_precedent_id = ?
                  AND primary_prior_authority_id = ?
                  AND secondary_precedent_id IS ?
                  AND secondary_prior_authority_id IS ?
                LIMIT 2
                """,
                (
                    receipt.run_id,
                    kind,
                    primary_id,
                    primary_prior_id,
                    secondary_id,
                    secondary_prior_id,
                ),
            ).fetchall()
        if not rows:
            return None
        if len(rows) != 1:
            raise RepositoryIntegrityError("M5 lifecycle identities resolve to multiple rows")
        durable = self._lifecycle_receipt_from_row(connection, rows[0])
        durable_context = self._lifecycle_context_from_row(rows[0], kind)
        if durable != receipt or durable_context != context:
            raise ConcurrentModification("M5 lifecycle receipt identity collision")
        return durable

    def _insert_lifecycle_receipt(
        self,
        connection: sqlite3.Connection,
        receipt: _LifecycleReceipt,
        context: _LifecycleContext,
        *,
        validate_after_insert: bool = True,
    ) -> _LifecycleReceipt:
        replay = self._find_lifecycle_receipt(connection, receipt, context)
        if replay is not None:
            return replay
        (
            kind,
            primary_id,
            primary_prior_id,
            primary_prior_revision,
            primary_result_id,
            primary_result_revision,
            secondary_id,
            secondary_prior_id,
            secondary_prior_revision,
            secondary_result_id,
            secondary_result_revision,
        ) = self._lifecycle_projection(receipt)
        manifest = self._load_run_manifest(connection, receipt.run_id)
        document = _contract_document(receipt)
        context_document = _contract_document(context)
        try:
            connection.execute(
                """
                INSERT INTO precedent_lifecycle_receipts(
                    run_id, receipt_id, receipt_kind, outcome,
                    primary_precedent_id, primary_prior_authority_id,
                    primary_prior_revision, primary_resulting_authority_id,
                    primary_resulting_revision, secondary_precedent_id,
                    secondary_prior_authority_id, secondary_prior_revision,
                    secondary_resulting_authority_id, secondary_resulting_revision,
                    manifest_id, receipt_json, context_json, context_sha256,
                    document_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt.run_id,
                    receipt.receipt_id,
                    kind,
                    receipt.outcome.value,
                    primary_id,
                    primary_prior_id,
                    primary_prior_revision,
                    primary_result_id,
                    primary_result_revision,
                    secondary_id,
                    secondary_prior_id,
                    secondary_prior_revision,
                    secondary_result_id,
                    secondary_result_revision,
                    manifest.manifest_id,
                    document,
                    context_document,
                    _canonical_document_sha256(context_document),
                    _canonical_document_sha256(document),
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ConcurrentModification("M5 lifecycle receipt could not be appended") from exc
        if not validate_after_insert:
            return receipt
        durable = self._find_lifecycle_receipt(connection, receipt, context)
        if durable is None:
            raise RepositoryIntegrityError("M5 lifecycle receipt disappeared")
        return durable

    def _append_revocation_receipt_marker(
        self,
        connection: sqlite3.Connection,
        *,
        receipt: M5PrecedentRevocationReceipt,
        snapshot: M5PrecedentCitationSnapshot,
        fault_scope: str,
    ) -> M5PrecedentRevocationReceipt:
        manifest = self._load_run_manifest(connection, receipt.run_id)
        document = _contract_document(receipt)
        source = m5_precedent_revocation_receipt_causal_source(
            receipt,
            manifest_id=manifest.manifest_id,
            source_document_sha256=_canonical_document_sha256(document),
        )

        def insert_source() -> None:
            inserted = self._insert_lifecycle_receipt(
                connection,
                receipt,
                snapshot,
                validate_after_insert=False,
            )
            if inserted != receipt:
                raise RepositoryIntegrityError("M5 revocation source insert changed its receipt")
            self._m5_fault(f"{fault_scope}.after_source")

        append_m5_precedent_causal_event(
            connection,
            source=source,
            insert_source=insert_source,
            fault_scope=fault_scope,
            fault=self._m5_fault,
        )
        durable = self._find_lifecycle_receipt(connection, receipt, snapshot)
        if durable != receipt:
            raise RepositoryIntegrityError("M5 revocation receipt marker replay differs")
        return receipt

    def _appeal_window_snapshot_in_connection(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        source_case_id: str,
        observed_through: datetime,
    ) -> M5AppealWindowSnapshot:
        manifest = self._load_run_manifest(connection, run_id)
        case_rows = connection.execute(
            """
            SELECT c.current_revision, c.status AS current_status, c.manifest_id,
                   cv.status, cv.case_json, cv.document_sha256
            FROM cases AS c
            JOIN case_versions AS cv
              ON cv.run_id = c.run_id AND cv.case_id = c.case_id
             AND cv.revision = c.current_revision
            WHERE c.run_id = ? AND c.case_id = ?
            """,
            (run_id, source_case_id),
        ).fetchall()
        if not case_rows:
            raise EvidenceMissing("M5 appeal snapshot source Case does not exist")
        if len(case_rows) != 1:
            raise RepositoryIntegrityError("M5 appeal snapshot source Case is ambiguous")
        case_row = case_rows[0]
        if _row_str(case_row, "manifest_id") != manifest.manifest_id:
            raise ManifestMismatch("M5 appeal snapshot source Case uses another manifest")
        raw = _row_str(case_row, "case_json")
        try:
            source_case = Case.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored M5 appeal snapshot Case is invalid") from exc
        source_case_document_sha256 = _row_str(case_row, "document_sha256")
        _verify_document(raw, source_case_document_sha256, source_case)
        source_case_revision = _row_int(case_row, "current_revision")
        if source_case_revision <= 0:
            raise RepositoryIntegrityError("M5 appeal snapshot Case revision is invalid")
        maximum = connection.execute(
            "SELECT MAX(revision) FROM case_versions WHERE run_id = ? AND case_id = ?",
            (run_id, source_case_id),
        ).fetchone()
        if maximum is None or maximum[0] != source_case_revision:
            raise RepositoryIntegrityError("M5 appeal snapshot Case head is not latest")
        if (
            source_case.run_id != run_id
            or source_case.case_id != source_case_id
            or source_case.manifest_id != manifest.manifest_id
            or _row_str(case_row, "status") != source_case.status.value
            or _row_str(case_row, "current_status") != source_case.status.value
        ):
            raise RepositoryIntegrityError("M5 appeal snapshot Case indexes are inconsistent")
        appeal_ids = tuple(sorted(item.appeal_id for item in source_case.appeals))
        if len(appeal_ids) > 1_000:
            raise RepositoryIntegrityError("M5 appeal window exceeds its hard bound")
        snapshot = M5AppealWindowSnapshot(
            run_id=run_id,
            source_case_id=source_case_id,
            source_case_revision=source_case_revision,
            source_case_document_sha256=source_case_document_sha256,
            observed_through=observed_through,
            appeal_ids=appeal_ids,
        )
        self._require_activation_snapshot_history(connection, snapshot)
        return snapshot

    @staticmethod
    def _load_activation_case_cut(
        connection: sqlite3.Connection,
        snapshot: M5AppealWindowSnapshot,
        revision: int,
    ) -> tuple[Case, str]:
        rows = connection.execute(
            """
            SELECT status, case_json, document_sha256
            FROM case_versions
            WHERE run_id = ? AND case_id = ? AND revision = ?
            """,
            (snapshot.run_id, snapshot.source_case_id, revision),
        ).fetchall()
        if len(rows) != 1:
            raise RepositoryIntegrityError("M5 activation Case cut is missing or ambiguous")
        row = rows[0]
        raw = _row_str(row, "case_json")
        try:
            case = Case.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored M5 activation Case cut is invalid") from exc
        document_sha256 = _row_str(row, "document_sha256")
        _verify_document(raw, document_sha256, case)
        if (
            case.run_id != snapshot.run_id
            or case.case_id != snapshot.source_case_id
            or _row_str(row, "status") != case.status.value
        ):
            raise RepositoryIntegrityError("M5 activation Case cut indexes are inconsistent")
        return case, document_sha256

    @staticmethod
    def _activation_appeal_authority_from_row(row: sqlite3.Row) -> AppealVersionAuthority:
        raw = _row_str(row, "authority_json")
        try:
            authority = AppealVersionAuthority.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored M5 activation appeal is invalid") from exc
        _verify_document(raw, _row_str(row, "document_sha256"), authority)
        indexed = (
            _row_str(row, "run_id") == authority.run_id,
            _row_str(row, "appeal_id") == authority.appeal.appeal_id,
            _row_int(row, "version") == authority.version,
            _row_str(row, "authority_sha256") == authority.authority_sha256,
            _row_optional_str(row, "previous_authority_sha256")
            == authority.previous_authority_sha256,
            _row_str(row, "case_id") == authority.appeal.case_id,
            _row_int(row, "source_case_revision") == authority.source_case_revision,
            _row_str(row, "source_case_authority_sha256") == authority.source_case_authority_sha256,
        )
        if not all(indexed):
            raise RepositoryIntegrityError("M5 activation appeal indexes are inconsistent")
        return authority

    @staticmethod
    def _activation_audit_from_case_row(
        connection: sqlite3.Connection,
        snapshot: M5AppealWindowSnapshot,
        revision: int,
    ) -> AuditEntry:
        rows = connection.execute(
            """
            SELECT ae.*
            FROM case_versions AS cv
            JOIN audit_entries AS ae
              ON ae.run_id = cv.run_id AND ae.sequence = cv.audit_sequence
            WHERE cv.run_id = ? AND cv.case_id = ? AND cv.revision = ?
            """,
            (snapshot.run_id, snapshot.source_case_id, revision),
        ).fetchall()
        if len(rows) != 1:
            raise RepositoryIntegrityError("M5 activation Case cut audit is missing")
        row = rows[0]
        raw = _row_str(row, "entry_json")
        try:
            audit = AuditEntry.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored M5 activation audit is invalid") from exc
        _verify_document(raw, _row_str(row, "document_sha256"), audit)
        return audit

    def _require_activation_snapshot_history(
        self,
        connection: sqlite3.Connection,
        snapshot: M5AppealWindowSnapshot,
    ) -> None:
        source_case, source_digest = self._load_activation_case_cut(
            connection,
            snapshot,
            snapshot.source_case_revision,
        )
        if source_digest != snapshot.source_case_document_sha256:
            raise RepositoryIntegrityError("M5 activation source Case cut hash differs")
        closing_revision = self._require_activation_case_causal_state(connection, snapshot)
        case_appeal_ids = tuple(sorted(item.appeal_id for item in source_case.appeals))
        if case_appeal_ids != snapshot.appeal_ids or len(case_appeal_ids) != len(
            set(case_appeal_ids)
        ):
            raise RepositoryIntegrityError("M5 activation appeal inventory differs from Case cut")
        offset = snapshot.source_case_revision - closing_revision
        if offset == 0:
            if source_case.appeals:
                raise RepositoryIntegrityError("M5 activation closing Case unexpectedly has appeal")
            return
        if offset not in {1, 2, 3} or len(source_case.appeals) != 1:
            raise RepositoryIntegrityError("M5 activation appeal Case revision is invalid")
        appeal_id = source_case.appeals[0].appeal_id
        rows = connection.execute(
            """
            SELECT * FROM appeals
            WHERE run_id = ? AND case_id = ? AND appeal_id = ? AND version <= ?
            ORDER BY version
            LIMIT 4
            """,
            (snapshot.run_id, snapshot.source_case_id, appeal_id, offset),
        ).fetchall()
        if len(rows) != offset:
            raise RepositoryIntegrityError("M5 activation appeal history is incomplete")
        authorities = tuple(self._activation_appeal_authority_from_row(row) for row in rows)
        base_case, base_digest = self._load_activation_case_cut(
            connection,
            snapshot,
            closing_revision,
        )
        if base_case.status != CaseStatus.CLOSED:
            raise RepositoryIntegrityError("M5 activation appeal base Case is not CLOSED")
        source_authority = authorities[0].source_case_authority
        if (
            source_authority.case_revision != closing_revision
            or source_authority.run_id != snapshot.run_id
            or source_authority.case_id != snapshot.source_case_id
            or source_authority.effective_appeal_ids
            != tuple(sorted(item.appeal_id for item in base_case.appeals))
        ):
            raise RepositoryIntegrityError("M5 activation appeal source base is invalid")
        previous_authority_sha256: str | None = None
        previous_case = base_case
        previous_digest = base_digest
        for version, authority in enumerate(authorities, start=1):
            if (
                authority.version != version
                or authority.source_case_revision != closing_revision
                or authority.source_case_authority != source_authority
                or authority.previous_authority_sha256 != previous_authority_sha256
            ):
                raise RepositoryIntegrityError("M5 activation appeal chain is not contiguous")
            current_case, current_digest = self._load_activation_case_cut(
                connection,
                snapshot,
                closing_revision + version,
            )
            expected_ref = ArtifactRef(kind=ArtifactKind.APPEAL, artifact_id=appeal_id)
            if (
                not current_case.appeals
                or current_case.appeals[-1] != authority.appeal
                or m5_case_transition_audit(previous_case, current_case)
                != (AuditAction.CASE_STATE_CHANGED, expected_ref)
            ):
                raise RepositoryIntegrityError("M5 activation appeal Case transition is invalid")
            audit = self._activation_audit_from_case_row(
                connection,
                snapshot,
                closing_revision + version,
            )
            if (
                audit.actor != AuditActorRole.SYSTEM.value
                or audit.action != AuditAction.CASE_STATE_CHANGED
                or audit.object_ref != expected_ref
                or audit.before_sha256 != previous_digest
                or audit.after_sha256 != current_digest
                or audit.manifest_id != source_case.manifest_id
            ):
                raise RepositoryIntegrityError("M5 activation appeal audit chain is invalid")
            previous_authority_sha256 = authority.authority_sha256
            previous_case = current_case
            previous_digest = current_digest
        if previous_case != source_case or previous_digest != source_digest:
            raise RepositoryIntegrityError("M5 activation appeal cut is not the chain head")

    @staticmethod
    def _require_activation_case_causal_state(
        connection: sqlite3.Connection,
        snapshot: M5AppealWindowSnapshot,
    ) -> int:
        rows = connection.execute(
            """
            SELECT cv.status, a.closing_case_revision
            FROM case_versions AS cv
            JOIN alerts AS a
              ON a.run_id = cv.run_id AND a.case_id = cv.case_id
            WHERE cv.run_id = ? AND cv.case_id = ? AND cv.revision = ?
            """,
            (snapshot.run_id, snapshot.source_case_id, snapshot.source_case_revision),
        ).fetchall()
        if len(rows) != 1:
            raise RepositoryIntegrityError("M5 activation source Case lacks one close authority")
        row = rows[0]
        status = _row_str(row, "status")
        closing_revision = _row_int(row, "closing_case_revision")
        if snapshot.appeal_ids:
            valid = snapshot.source_case_revision > closing_revision and status in {
                CaseStatus.APPEALED.value,
                CaseStatus.APPEAL_RESOLVED.value,
            }
        else:
            valid = (
                snapshot.source_case_revision == closing_revision
                and status == CaseStatus.CLOSED.value
            )
        if not valid:
            raise ContractViolation("M5 activation source Case causal state is invalid")
        return closing_revision

    def load_appeal_window_snapshot(
        self,
        run_id: str,
        source_case_id: str,
        observed_through: datetime,
    ) -> M5AppealWindowSnapshot:
        self._require_reference(run_id, "M5 run_id")
        self._require_reference(source_case_id, "M5 appeal snapshot source_case_id")
        self._require_utc_datetime(observed_through, "M5 appeal snapshot timestamp")
        with self._read() as connection:
            return self._appeal_window_snapshot_in_connection(
                connection,
                run_id=run_id,
                source_case_id=source_case_id,
                observed_through=observed_through,
            )

    def commit_activation(
        self,
        result: M5PrecedentActivationResult,
    ) -> M5PrecedentActivationResult:
        validated = _validated_contract(
            result,
            M5PrecedentActivationResult,
            "M5 precedent activation result",
        )
        receipt = validated.receipt
        with self._immediate() as connection:
            manifest = self._load_run_manifest(connection, receipt.run_id)
            expected_policy, _run_mode = self._require_trusted_m5_precedent_policy(
                manifest,
                write=True,
            )
            prior = self._load_m5_precedent_revision(
                connection,
                receipt.run_id,
                receipt.precedent_id,
                receipt.prior_revision,
            )
            if (
                prior is None
                or prior.authority_id != receipt.prior_authority_id
                or prior.precedent.source != PrecedentSource.AUTOMATIC
                or prior.precedent.source_case_id is None
            ):
                raise ConcurrentModification("M5 activation prior authority changed")
            expected_not_before = prior.created_at + timedelta(
                seconds=expected_policy.automatic_activation_delay_seconds
            )
            if prior.activation_not_before != expected_not_before:
                raise ContractViolation(
                    "M5 activation cooling period differs from trusted AppConfig"
                )
            replay = self._find_lifecycle_receipt(
                connection,
                receipt,
                validated.appeal_snapshot,
            )
            if replay is not None:
                self._require_activation_snapshot_history(
                    connection,
                    validated.appeal_snapshot,
                )
                durable = self._load_m5_precedent_revision(
                    connection,
                    receipt.run_id,
                    receipt.precedent_id,
                    receipt.resulting_revision,
                )
                if replay != receipt or durable != validated.authority:
                    raise ConcurrentModification("M5 activation replay differs")
                return validated
            rebuilt_snapshot = self._appeal_window_snapshot_in_connection(
                connection,
                run_id=receipt.run_id,
                source_case_id=prior.precedent.source_case_id,
                observed_through=receipt.evaluated_at,
            )
            claimed_snapshot = validated.appeal_snapshot
            if (
                rebuilt_snapshot.source_case_revision != claimed_snapshot.source_case_revision
                or rebuilt_snapshot.source_case_document_sha256
                != claimed_snapshot.source_case_document_sha256
            ):
                raise ConcurrentModification("M5 activation source Case causal cut changed")
            if rebuilt_snapshot != claimed_snapshot:
                raise ContractViolation("M5 activation appeal inventory is not exact")
            try:
                rebuilt = evaluate_m5_automatic_activation(
                    authority=prior,
                    appeal_snapshot=rebuilt_snapshot,
                    evaluated_at=receipt.evaluated_at,
                )
            except (TypeError, ValueError, RuntimeError) as exc:
                raise ContractViolation("M5 activation cannot be rebuilt") from exc
            if rebuilt != validated:
                raise ContractViolation("M5 activation is not the exact appeal-window result")
            current = self._load_m5_precedent_authority(
                connection,
                receipt.run_id,
                receipt.precedent_id,
            )
            if current is None or current != prior:
                raise ConcurrentModification("M5 activation prior authority changed")
            self._m5_fault("precedent.activation.before_authority")
            if validated.authority.authority_id != current.authority_id:
                self._insert_m5_precedent_authority(
                    connection,
                    validated.authority,
                    current.revision,
                    causal_fault_scope="precedent.activation.resulting_authority",
                )
            elif validated.authority != current:
                raise ContractViolation("non-mutating M5 activation changed authority")
            self._m5_fault("precedent.activation.after_authority")
            self._insert_lifecycle_receipt(
                connection,
                receipt,
                validated.appeal_snapshot,
            )
            self._m5_fault("precedent.activation.after_receipt")
            return validated

    def _conflict_batch_authority_from_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> tuple[M5PrecedentConflictBatchAuthority, M5PrecedentPolicy]:
        authority_raw = _row_str(row, "authority_json")
        policy_raw = _row_str(row, "policy_json")
        try:
            authority = M5PrecedentConflictBatchAuthority.model_validate_json(authority_raw)
            policy = M5PrecedentPolicy.model_validate_json(policy_raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored M5 conflict batch authority is invalid") from exc
        _verify_contract_document(authority_raw, authority)
        _verify_contract_document(policy_raw, policy)
        manifest = self._load_run_manifest(connection, authority.run_id)
        self._require_trusted_m5_precedent_policy(
            manifest,
            claimed_policy=policy,
        )
        indexed = (
            _row_str(row, "run_id") == authority.run_id,
            _row_str(row, "batch_authority_id") == authority.batch_authority_id,
            _row_str(row, "policy_id") == authority.policy_id == policy.policy_id,
            _row_str(row, "config_sha256")
            == authority.config_sha256
            == policy.config_sha256
            == manifest.config_sha256,
            authority.causal_cut.manifest_id == manifest.manifest_id,
            _row_str(row, "causal_cut_id") == authority.causal_cut.cut_id,
            _row_int(row, "authority_event_sequence")
            == authority.causal_cut.authority_event_sequence,
            _row_str(row, "authority_event_sha256") == authority.causal_cut.authority_event_sha256,
            _row_str(row, "active_head_root_sha256")
            == authority.causal_cut.active_head_root_sha256,
            _row_int(row, "scan_limit") == authority.scan_limit,
            _row_int(row, "candidate_count") == len(authority.candidates),
            _row_int(row, "evaluated_pair_count") == authority.evaluated_pair_count,
            _row_int(row, "edge_count") == len(authority.edges),
            _row_str(row, "manifest_id") == manifest.manifest_id,
            _row_str(row, "policy_sha256") == _canonical_document_sha256(policy_raw),
            _row_str(row, "document_sha256") == _canonical_document_sha256(authority_raw),
        )
        if not all(indexed):
            raise RepositoryIntegrityError(
                "M5 conflict batch index columns differ from canonical authority"
            )
        return authority, policy

    def _conflict_batch_receipt_from_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> M5PrecedentConflictBatchReceipt:
        raw = _row_str(row, "receipt_json")
        try:
            receipt = M5PrecedentConflictBatchReceipt.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored M5 conflict batch receipt is invalid") from exc
        _verify_contract_document(raw, receipt)
        manifest = self._load_run_manifest(connection, receipt.run_id)
        changed_count = sum(
            item.resulting_authority_id != item.prior_authority_id for item in receipt.results
        )
        indexed = (
            _row_str(row, "run_id") == receipt.run_id,
            _row_str(row, "receipt_id") == receipt.receipt_id,
            _row_str(row, "batch_authority_id") == receipt.batch_authority_id,
            _row_str(row, "causal_cut_id") == receipt.causal_cut_id,
            _row_int(row, "result_count") == len(receipt.results),
            _row_int(row, "changed_count") == changed_count,
            _row_str(row, "manifest_id") == manifest.manifest_id,
            _row_str(row, "document_sha256") == _canonical_document_sha256(raw),
        )
        if not all(indexed):
            raise RepositoryIntegrityError(
                "M5 conflict batch receipt indexes differ from canonical document"
            )
        require_m5_precedent_causal_event(
            connection,
            source=m5_precedent_conflict_receipt_causal_source(
                receipt,
                manifest_id=manifest.manifest_id,
                source_document_sha256=_canonical_document_sha256(raw),
            ),
        )
        return receipt

    def _load_conflict_batch_resolution(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        batch_authority_id: str,
    ) -> M5PrecedentConflictBatchResolution | None:
        batch_rows = connection.execute(
            """
            SELECT * FROM precedent_conflict_batches
            WHERE run_id = ? AND batch_authority_id = ?
            LIMIT 2
            """,
            (run_id, batch_authority_id),
        ).fetchall()
        if not batch_rows:
            return None
        if len(batch_rows) != 1:
            raise RepositoryIntegrityError("M5 conflict batch identity resolves to multiple rows")
        batch, policy = self._conflict_batch_authority_from_row(connection, batch_rows[0])
        receipt_rows = connection.execute(
            """
            SELECT * FROM precedent_conflict_batch_receipts
            WHERE run_id = ? AND batch_authority_id = ?
            LIMIT 2
            """,
            (run_id, batch_authority_id),
        ).fetchall()
        if len(receipt_rows) != 1:
            raise RepositoryIntegrityError("M5 conflict batch has no unique commit receipt")
        receipt = self._conflict_batch_receipt_from_row(connection, receipt_rows[0])
        causal_events = load_m5_precedent_causal_events(connection, run_id=run_id)
        authority_rows = connection.execute(
            """
            SELECT * FROM precedents
            WHERE run_id = ?
            ORDER BY precedent_id, revision
            """,
            (run_id,),
        ).fetchall()
        authorities = tuple(self._m5_authority_from_row(connection, row) for row in authority_rows)
        try:
            return rebuild_m5_precedent_conflict_history(
                authorities=authorities,
                causal_events=causal_events,
                trusted_policy=policy,
                batch_authority=batch,
                receipt=receipt,
            )
        except M5PrecedentConflictHistoryError as exc:
            raise RepositoryIntegrityError(
                f"stored M5 conflict batch history is invalid: {exc.code.value}"
            ) from exc

    def _find_conflict_batch_resolution(
        self,
        connection: sqlite3.Connection,
        resolution: M5PrecedentConflictBatchResolution,
    ) -> M5PrecedentConflictBatchResolution | None:
        durable = self._load_conflict_batch_resolution(
            connection,
            run_id=resolution.batch_authority.run_id,
            batch_authority_id=resolution.batch_authority.batch_authority_id,
        )
        receipt_collision = connection.execute(
            """
            SELECT batch_authority_id FROM precedent_conflict_batch_receipts
            WHERE run_id = ? AND receipt_id = ?
            LIMIT 2
            """,
            (resolution.receipt.run_id, resolution.receipt.receipt_id),
        ).fetchall()
        if durable is None:
            if receipt_collision:
                raise ConcurrentModification("M5 conflict batch receipt identity collision")
            return None
        if len(receipt_collision) != 1 or durable != resolution:
            raise ConcurrentModification("M5 conflict batch replay differs")
        return durable

    def _insert_conflict_batch_authority(
        self,
        connection: sqlite3.Connection,
        resolution: M5PrecedentConflictBatchResolution,
    ) -> None:
        batch = resolution.batch_authority
        manifest = self._load_run_manifest(connection, batch.run_id)
        authority_json = _contract_document(batch)
        policy_json = _contract_document(resolution.policy)
        try:
            connection.execute(
                """
                INSERT INTO precedent_conflict_batches(
                    run_id, batch_authority_id, policy_id, config_sha256,
                    causal_cut_id, authority_event_sequence,
                    authority_event_sha256, active_head_root_sha256,
                    scan_limit, candidate_count, evaluated_pair_count, edge_count,
                    manifest_id, authority_json, policy_json, policy_sha256,
                    document_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    batch.run_id,
                    batch.batch_authority_id,
                    batch.policy_id,
                    batch.config_sha256,
                    batch.causal_cut.cut_id,
                    batch.causal_cut.authority_event_sequence,
                    batch.causal_cut.authority_event_sha256,
                    batch.causal_cut.active_head_root_sha256,
                    batch.scan_limit,
                    len(batch.candidates),
                    batch.evaluated_pair_count,
                    len(batch.edges),
                    manifest.manifest_id,
                    authority_json,
                    policy_json,
                    _canonical_document_sha256(policy_json),
                    _canonical_document_sha256(authority_json),
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ConcurrentModification(
                "M5 conflict batch authority could not be appended"
            ) from exc

    def _insert_conflict_batch_receipt(
        self,
        connection: sqlite3.Connection,
        receipt: M5PrecedentConflictBatchReceipt,
    ) -> None:
        manifest = self._load_run_manifest(connection, receipt.run_id)
        raw = _contract_document(receipt)
        document_sha256 = _canonical_document_sha256(raw)
        changed_count = sum(
            item.resulting_authority_id != item.prior_authority_id for item in receipt.results
        )

        def insert_receipt() -> None:
            try:
                connection.execute(
                    """
                    INSERT INTO precedent_conflict_batch_receipts(
                        run_id, receipt_id, batch_authority_id, causal_cut_id,
                        result_count, changed_count, manifest_id, receipt_json,
                        document_sha256
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        receipt.run_id,
                        receipt.receipt_id,
                        receipt.batch_authority_id,
                        receipt.causal_cut_id,
                        len(receipt.results),
                        changed_count,
                        manifest.manifest_id,
                        raw,
                        document_sha256,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ConcurrentModification(
                    "M5 conflict batch receipt could not be appended"
                ) from exc

        append_m5_precedent_causal_event(
            connection,
            source=m5_precedent_conflict_receipt_causal_source(
                receipt,
                manifest_id=manifest.manifest_id,
                source_document_sha256=document_sha256,
            ),
            insert_source=insert_receipt,
            fault_scope="precedent.conflict_batch.commit_marker",
            fault=self._m5_fault,
        )

    def commit_conflict_batch(
        self,
        resolution: M5PrecedentConflictBatchResolution,
    ) -> M5PrecedentConflictBatchResolution:
        validated = _validated_contract(
            resolution,
            M5PrecedentConflictBatchResolution,
            "M5 precedent conflict batch resolution",
        )
        batch = validated.batch_authority
        with self._immediate() as connection:
            manifest = self._load_run_manifest(connection, batch.run_id)
            trusted_policy, _run_mode = self._require_trusted_m5_precedent_policy(
                manifest,
                claimed_policy=validated.policy,
                write=True,
            )
            replay = self._find_conflict_batch_resolution(connection, validated)
            if replay is not None:
                return replay
            snapshot = self._conflict_snapshot_in_connection(
                connection,
                run_id=batch.run_id,
                limit=batch.scan_limit,
                policy=trusted_policy,
            )
            current_by_id = snapshot.authorities
            if (
                snapshot.causal_cut != batch.causal_cut
                or current_by_id != validated.prior_authorities
            ):
                raise ConcurrentModification("M5 conflict batch authority causal cut changed")
            try:
                rebuilt = resolve_m5_precedent_conflict_batch(
                    snapshot=snapshot,
                    policy=trusted_policy,
                    scan_limit=batch.scan_limit,
                )
            except (TypeError, ValueError, RuntimeError) as exc:
                raise ContractViolation("M5 conflict batch cannot be rebuilt") from exc
            if rebuilt != validated:
                raise ContractViolation("M5 conflict batch is not the exact complete graph result")
            self._m5_fault("precedent.conflict_batch.before_authorities")
            for ordinal, (current_authority, proposed) in enumerate(
                zip(
                    current_by_id,
                    validated.resulting_authorities,
                    strict=True,
                ),
                start=1,
            ):
                if proposed.authority_id == current_authority.authority_id:
                    if proposed != current_authority:
                        raise ContractViolation("non-mutating M5 conflict batch changed authority")
                    continue
                self._insert_m5_precedent_authority(
                    connection,
                    proposed,
                    current_authority.revision,
                    causal_fault_scope=(f"precedent.conflict_batch.resulting_authority.{ordinal}"),
                )
                self._m5_fault("precedent.conflict_batch.after_authority")
            self._m5_fault("precedent.conflict_batch.after_authorities")
            self._insert_conflict_batch_authority(connection, validated)
            self._m5_fault("precedent.conflict_batch.after_batch_authority")
            self._insert_conflict_batch_receipt(connection, validated.receipt)
            self._m5_fault("precedent.conflict_batch.after_batch_receipt")
            durable = self._find_conflict_batch_resolution(connection, validated)
            if durable is None:
                raise RepositoryIntegrityError("M5 conflict batch disappeared before commit")
            return durable

    def commit_conflict(
        self,
        resolution: M5PrecedentConflictResolution,
    ) -> M5PrecedentConflictResolution:
        _validated_contract(
            resolution,
            M5PrecedentConflictResolution,
            "M5 precedent conflict resolution",
        )
        raise ContractViolation(
            "pair-wise M5 conflict writes are disabled; use the causal batch commit"
        )

    def commit_revocation(
        self,
        result: M5PrecedentRevocationResult,
    ) -> M5PrecedentRevocationResult:
        validated = _validated_contract(
            result,
            M5PrecedentRevocationResult,
            "M5 precedent revocation result",
        )
        receipt = validated.receipt
        with self._immediate() as connection:
            manifest = self._load_run_manifest(connection, receipt.run_id)
            self._require_trusted_m5_precedent_policy(manifest, write=True)
            prior = self._load_m5_precedent_revision(
                connection,
                receipt.run_id,
                receipt.precedent_id,
                receipt.prior_revision,
            )
            if prior is None or prior.authority_id != receipt.prior_authority_id:
                raise ConcurrentModification("M5 revocation prior authority changed")
            replay = self._find_lifecycle_receipt(
                connection,
                receipt,
                validated.citation_snapshot,
            )
            if replay is not None:
                durable = self._load_m5_precedent_revision(
                    connection,
                    receipt.run_id,
                    receipt.precedent_id,
                    receipt.resulting_revision,
                )
                if replay != receipt or durable != validated.authority:
                    raise ConcurrentModification("M5 revocation replay differs")
                return validated
            rebuilt_snapshot = self._citation_snapshot_in_connection(
                connection,
                run_id=receipt.run_id,
                precedent_id=receipt.precedent_id,
                captured_at=validated.citation_snapshot.captured_at,
            )
            if rebuilt_snapshot != validated.citation_snapshot:
                raise ContractViolation("M5 revocation citation snapshot is not complete")
            try:
                rebuilt = revoke_m5_precedent(
                    authority=prior,
                    citation_snapshot=rebuilt_snapshot,
                    revoked_by_ref=receipt.revoked_by_ref,
                    revoked_at=receipt.revoked_at,
                )
            except (TypeError, ValueError, RuntimeError) as exc:
                raise ContractViolation("M5 revocation cannot be rebuilt") from exc
            if rebuilt != validated:
                raise ContractViolation("M5 revocation is not the exact snapshot result")
            current = self._load_m5_precedent_authority(
                connection,
                receipt.run_id,
                receipt.precedent_id,
            )
            if current is None or current != prior:
                raise ConcurrentModification("M5 revocation prior authority changed")
            self._m5_fault("precedent.revocation.before_authority")
            if validated.authority.authority_id != current.authority_id:
                self._insert_m5_precedent_authority(
                    connection,
                    validated.authority,
                    current.revision,
                    causal_fault_scope="precedent.revocation.resulting_authority",
                )
            elif validated.authority != current:
                raise ContractViolation("idempotent M5 revocation changed authority")
            self._m5_fault("precedent.revocation.after_authority")
            self._append_revocation_receipt_marker(
                connection,
                receipt=receipt,
                snapshot=validated.citation_snapshot,
                fault_scope="precedent.revocation.receipt",
            )
            self._m5_fault("precedent.revocation.after_receipt")
            return validated

    def _find_revocation_by_prior(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        precedent_id: str,
        prior_authority_id: str,
    ) -> tuple[M5PrecedentRevocationReceipt, M5PrecedentCitationSnapshot] | None:
        rows = connection.execute(
            """
            SELECT * FROM precedent_lifecycle_receipts
            WHERE run_id = ? AND receipt_kind = 'REVOCATION'
              AND primary_precedent_id = ?
              AND primary_prior_authority_id = ?
            LIMIT 2
            """,
            (run_id, precedent_id, prior_authority_id),
        ).fetchall()
        if not rows:
            return None
        if len(rows) != 1:
            raise RepositoryIntegrityError("M5 revocation prior resolves to multiple receipts")
        receipt = self._lifecycle_receipt_from_row(connection, rows[0])
        if not isinstance(receipt, M5PrecedentRevocationReceipt):
            raise RepositoryIntegrityError("M5 revocation row contains another receipt kind")
        context = self._lifecycle_context_from_row(rows[0], "REVOCATION")
        if not isinstance(context, M5PrecedentCitationSnapshot):
            raise RepositoryIntegrityError("M5 revocation row contains another context kind")
        return receipt, context

    def _commit_m5_appeal_revocation(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        intent: PrecedentRevocationIntent,
        revoked_by_ref: str,
        revoked_at: datetime,
    ) -> M5PrecedentRevocationResult:
        validated_intent = _validated_contract(
            intent,
            PrecedentRevocationIntent,
            "appeal precedent revocation intent",
        )
        self._require_reference(run_id, "M5 run_id")
        self._require_reference(revoked_by_ref, "M5 revocation authority")
        prior = self._load_m5_precedent_revision(
            connection,
            run_id,
            validated_intent.precedent_id,
            validated_intent.prior_revision,
        )
        if (
            prior is None
            or prior.authority_id != validated_intent.prior_authority_id
            or prior.precedent.source != validated_intent.source
            or prior.precedent.status != validated_intent.previous_status
        ):
            raise ConcurrentModification("appeal precedent revocation prior differs")
        replay = self._find_revocation_by_prior(
            connection,
            run_id=run_id,
            precedent_id=validated_intent.precedent_id,
            prior_authority_id=validated_intent.prior_authority_id,
        )
        if replay is not None:
            replay_receipt, replay_snapshot = replay
            if replay_receipt.revoked_by_ref != revoked_by_ref:
                raise ConcurrentModification("appeal precedent was revoked by another authority")
            durable = self._load_m5_precedent_revision(
                connection,
                run_id,
                validated_intent.precedent_id,
                replay_receipt.resulting_revision,
            )
            if durable is None:
                raise RepositoryIntegrityError("appeal revocation result authority is absent")
            return M5PrecedentRevocationResult(
                citation_snapshot=replay_snapshot,
                receipt=replay_receipt,
                authority=durable,
            )
        current = self._load_m5_precedent_authority(
            connection,
            run_id,
            validated_intent.precedent_id,
        )
        if current != prior:
            raise ConcurrentModification("appeal precedent revocation CAS changed")
        snapshot = self._citation_snapshot_in_connection(
            connection,
            run_id=run_id,
            precedent_id=validated_intent.precedent_id,
            captured_at=revoked_at,
        )
        try:
            result = revoke_m5_precedent(
                authority=prior,
                citation_snapshot=snapshot,
                revoked_by_ref=revoked_by_ref,
                revoked_at=revoked_at,
            )
        except (TypeError, ValueError, RuntimeError) as exc:
            raise ContractViolation("appeal precedent revocation cannot be derived") from exc
        self._insert_m5_precedent_authority(
            connection,
            result.authority,
            prior.revision,
            causal_fault_scope="precedent.appeal_revocation.resulting_authority",
        )
        self._m5_fault("precedent.appeal_revocation.after_authority")
        self._append_revocation_receipt_marker(
            connection,
            receipt=result.receipt,
            snapshot=result.citation_snapshot,
            fault_scope="precedent.appeal_revocation.receipt",
        )
        self._m5_fault("precedent.appeal_revocation.after_receipt")
        return result


__all__ = ["SQLiteM5PrecedentRepository"]

"""Resolve the exact M5 embedding closure admitted to locked M6 replay."""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import NoReturn

from pydantic import ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m5_precedent_usage import M5PrecedentExposureBatchAuthority
from labcourt.contracts.m5_precedents import M5EmbeddingChannel, M5EmbeddingVector
from labcourt.contracts.m5_projection import M5AuthorityKind
from labcourt.contracts.m6_replay_locked import (
    M6LockedEmbeddingChannel,
    M6LockedEmbeddingScope,
    M6LockedRetrievalOutcomeKind,
    M6ReplayInputClosureAuthority,
)
from labcourt.domain.m6_embedding_authority import M6ResolvedEmbeddingAuthority
from labcourt.exceptions import LabCourtError
from labcourt.ports.m6_embeddings import (
    M6EmbeddingAuthorityDocument,
    M6EmbeddingAuthoritySnapshot,
)


class M6EmbeddingAuthorityErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SNAPSHOT_AUTHORITY_INVALID = "SNAPSHOT_AUTHORITY_INVALID"
    SNAPSHOT_SCOPE_MISMATCH = "SNAPSHOT_SCOPE_MISMATCH"
    VALIDATED_DOCUMENT_INVALID = "VALIDATED_DOCUMENT_INVALID"
    EXPOSURE_AUTHORITY_MISSING = "EXPOSURE_AUTHORITY_MISSING"
    EXPOSURE_AUTHORITY_DUPLICATE = "EXPOSURE_AUTHORITY_DUPLICATE"
    EXPOSURE_AUTHORITY_BINDING_MISMATCH = "EXPOSURE_AUTHORITY_BINDING_MISMATCH"
    EXPOSURE_AUTHORITY_SCOPE_MISMATCH = "EXPOSURE_AUTHORITY_SCOPE_MISMATCH"
    EMBEDDING_AUTHORITY_MISSING = "EMBEDDING_AUTHORITY_MISSING"
    EMBEDDING_AUTHORITY_DUPLICATE = "EMBEDDING_AUTHORITY_DUPLICATE"
    EMBEDDING_AUTHORITY_FORGED = "EMBEDDING_AUTHORITY_FORGED"
    EMBEDDING_SCOPE_COLLISION = "EMBEDDING_SCOPE_COLLISION"
    CLOSURE_EMBEDDING_MISSING = "CLOSURE_EMBEDDING_MISSING"
    CLOSURE_EMBEDDING_EXTRA = "CLOSURE_EMBEDDING_EXTRA"
    CLOSURE_EMBEDDING_BINDING_MISMATCH = "CLOSURE_EMBEDDING_BINDING_MISMATCH"


class M6EmbeddingAuthorityError(LabCourtError):
    """The locked embedding inventory cannot be proved from M5 authority."""

    def __init__(self, code: M6EmbeddingAuthorityErrorCode) -> None:
        if not isinstance(code, M6EmbeddingAuthorityErrorCode):
            raise TypeError("code must be an M6EmbeddingAuthorityErrorCode")
        self.code = code
        super().__init__(f"M6 embedding authority failed: {code.value}")


def _fail(code: M6EmbeddingAuthorityErrorCode) -> NoReturn:
    raise M6EmbeddingAuthorityError(code)


def _document_sha256(document: str) -> str:
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


def _validated_arguments(
    closure: object,
    snapshot: object,
) -> tuple[M6ReplayInputClosureAuthority, M6EmbeddingAuthoritySnapshot]:
    if not isinstance(closure, M6ReplayInputClosureAuthority) or not isinstance(
        snapshot, M6EmbeddingAuthoritySnapshot
    ):
        _fail(M6EmbeddingAuthorityErrorCode.INVALID_ARGUMENT)
    try:
        canonical = M6ReplayInputClosureAuthority.model_validate(
            closure.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6EmbeddingAuthorityErrorCode.INVALID_ARGUMENT)
    if canonical != closure:
        _fail(M6EmbeddingAuthorityErrorCode.INVALID_ARGUMENT)
    digests = (
        snapshot.source_identity_sha256,
        snapshot.manifest_id,
        snapshot.source_authority_root_sha256,
    )
    if any(
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
        for value in digests
    ):
        _fail(M6EmbeddingAuthorityErrorCode.INVALID_ARGUMENT)
    if not snapshot.authority_valid:
        _fail(M6EmbeddingAuthorityErrorCode.SNAPSHOT_AUTHORITY_INVALID)
    if (
        snapshot.run_id != canonical.source_run_id
        or snapshot.manifest_id != canonical.source_manifest_id
    ):
        _fail(M6EmbeddingAuthorityErrorCode.SNAPSHOT_SCOPE_MISMATCH)
    return canonical, snapshot


def _document_maps(
    snapshot: M6EmbeddingAuthoritySnapshot,
) -> tuple[
    dict[str, M6EmbeddingAuthorityDocument],
    dict[str, M6EmbeddingAuthorityDocument],
]:
    if not isinstance(snapshot.documents, tuple) or any(
        not isinstance(item, M6EmbeddingAuthorityDocument) for item in snapshot.documents
    ):
        _fail(M6EmbeddingAuthorityErrorCode.INVALID_ARGUMENT)
    validated_documents: list[M6EmbeddingAuthorityDocument] = []
    for document in snapshot.documents:
        try:
            canonical_document = M6EmbeddingAuthorityDocument(
                kind=document.kind,
                artifact_id=document.artifact_id,
                canonical_document=document.canonical_document,
                document_sha256=document.document_sha256,
            )
        except (TypeError, ValueError):
            _fail(M6EmbeddingAuthorityErrorCode.VALIDATED_DOCUMENT_INVALID)
        if canonical_document != document:
            _fail(M6EmbeddingAuthorityErrorCode.VALIDATED_DOCUMENT_INVALID)
        validated_documents.append(canonical_document)
    keys = tuple(item.sort_key for item in validated_documents)
    if keys != tuple(sorted(keys)):
        _fail(M6EmbeddingAuthorityErrorCode.INVALID_ARGUMENT)
    exposures: dict[str, M6EmbeddingAuthorityDocument] = {}
    embeddings: dict[str, M6EmbeddingAuthorityDocument] = {}
    for document in validated_documents:
        if document.kind == M5AuthorityKind.PRECEDENT_EXPOSURE:
            target = exposures
        elif document.kind == M5AuthorityKind.PRECEDENT_EMBEDDING:
            target = embeddings
        else:
            _fail(M6EmbeddingAuthorityErrorCode.VALIDATED_DOCUMENT_INVALID)
        if document.artifact_id in target:
            _fail(
                M6EmbeddingAuthorityErrorCode.EXPOSURE_AUTHORITY_DUPLICATE
                if document.kind == M5AuthorityKind.PRECEDENT_EXPOSURE
                else M6EmbeddingAuthorityErrorCode.EMBEDDING_AUTHORITY_DUPLICATE
            )
        target[document.artifact_id] = document
    return exposures, embeddings


def _parse_exposure(
    document: M6EmbeddingAuthorityDocument,
) -> M5PrecedentExposureBatchAuthority:
    try:
        exposure = M5PrecedentExposureBatchAuthority.model_validate_json(
            document.canonical_document
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6EmbeddingAuthorityErrorCode.VALIDATED_DOCUMENT_INVALID)
    if (
        canonical_json(exposure.model_dump(mode="json")) != document.canonical_document
        or exposure.exposure_id != document.artifact_id
    ):
        _fail(M6EmbeddingAuthorityErrorCode.VALIDATED_DOCUMENT_INVALID)
    return exposure


def _parse_embedding(document: M6EmbeddingAuthorityDocument) -> M5EmbeddingVector:
    try:
        embedding = M5EmbeddingVector.model_validate_json(document.canonical_document)
    except (TypeError, ValueError, ValidationError):
        _fail(M6EmbeddingAuthorityErrorCode.VALIDATED_DOCUMENT_INVALID)
    if canonical_json(embedding.model_dump(mode="json")) != document.canonical_document:
        _fail(M6EmbeddingAuthorityErrorCode.VALIDATED_DOCUMENT_INVALID)
    if embedding.embedding_id != document.artifact_id:
        _fail(M6EmbeddingAuthorityErrorCode.EMBEDDING_AUTHORITY_FORGED)
    return embedding


def _selected_exposures(
    closure: M6ReplayInputClosureAuthority,
    documents: dict[str, M6EmbeddingAuthorityDocument],
) -> tuple[M5PrecedentExposureBatchAuthority, ...]:
    selected: list[M5PrecedentExposureBatchAuthority] = []
    for cycle in closure.historical_cut.retrieval_cycles:
        if cycle.outcome == M6LockedRetrievalOutcomeKind.DEGRADED:
            continue
        document = documents.get(cycle.authority_ref.artifact_id)
        if document is None:
            _fail(M6EmbeddingAuthorityErrorCode.EXPOSURE_AUTHORITY_MISSING)
        if document.document_sha256 != cycle.authority_ref.document_sha256:
            _fail(M6EmbeddingAuthorityErrorCode.EXPOSURE_AUTHORITY_BINDING_MISMATCH)
        exposure = _parse_exposure(document)
        if (
            exposure.run_id != closure.source_run_id
            or exposure.case_id != closure.source_case_id
            or exposure.manifest_id != closure.source_manifest_id
            or exposure.hearing_session_id != cycle.hearing_session_id
            or exposure.cycle_index != cycle.cycle_index
            or exposure.cycle_scope_id != cycle.cycle_scope_id
        ):
            _fail(M6EmbeddingAuthorityErrorCode.EXPOSURE_AUTHORITY_SCOPE_MISMATCH)
        selected.append(exposure)
    return tuple(selected)


def _channel(vector: M5EmbeddingVector) -> M6LockedEmbeddingChannel:
    return {
        M5EmbeddingChannel.TEXT: M6LockedEmbeddingChannel.TEXT,
        M5EmbeddingChannel.VISUAL: M6LockedEmbeddingChannel.VISUAL,
    }[vector.request.channel]


def _exposure_vectors(
    exposure: M5PrecedentExposureBatchAuthority,
) -> tuple[tuple[M6LockedEmbeddingScope, M5EmbeddingVector], ...]:
    query = exposure.m5_retrieval_result.query
    query_vectors = (
        () if query.text_embedding is None else (query.text_embedding,)
    ) + query.visual_embeddings
    precedent_vectors = tuple(
        vector
        for evaluation in exposure.m5_retrieval_result.candidate_evaluations
        for vector in (
            (
                ()
                if evaluation.authority.text_embedding is None
                else (evaluation.authority.text_embedding,)
            )
            + evaluation.authority.visual_embeddings
        )
    )
    return tuple((M6LockedEmbeddingScope.QUERY, vector) for vector in query_vectors) + tuple(
        (M6LockedEmbeddingScope.PRECEDENT, vector) for vector in precedent_vectors
    )


def _resolve_vectors(
    exposures: tuple[M5PrecedentExposureBatchAuthority, ...],
    documents: dict[str, M6EmbeddingAuthorityDocument],
) -> tuple[M6ResolvedEmbeddingAuthority, ...]:
    by_key: dict[tuple[M6LockedEmbeddingScope, str], M6ResolvedEmbeddingAuthority] = {}
    scopes_by_id: dict[str, set[M6LockedEmbeddingScope]] = {}
    for exposure in exposures:
        for scope, nested in _exposure_vectors(exposure):
            durable = nested
            document_sha256 = _document_sha256(canonical_json(nested.model_dump(mode="json")))
            if scope == M6LockedEmbeddingScope.PRECEDENT:
                document = documents.get(nested.embedding_id)
                if document is None:
                    _fail(M6EmbeddingAuthorityErrorCode.EMBEDDING_AUTHORITY_MISSING)
                durable = _parse_embedding(document)
                if durable != nested:
                    _fail(M6EmbeddingAuthorityErrorCode.EMBEDDING_AUTHORITY_FORGED)
                document_sha256 = document.document_sha256
            scopes = scopes_by_id.setdefault(durable.embedding_id, set())
            scopes.add(scope)
            if len(scopes) != 1:
                _fail(M6EmbeddingAuthorityErrorCode.EMBEDDING_SCOPE_COLLISION)
            resolved = M6ResolvedEmbeddingAuthority(
                scope=scope,
                channel=_channel(durable),
                vector=durable,
                document_sha256=document_sha256,
            )
            key = (scope, durable.embedding_id)
            previous = by_key.get(key)
            if previous is not None and previous != resolved:
                _fail(M6EmbeddingAuthorityErrorCode.EMBEDDING_AUTHORITY_FORGED)
            by_key[key] = resolved
    return tuple(sorted(by_key.values(), key=lambda item: item.sort_key))


def _require_exact_closure(
    closure: M6ReplayInputClosureAuthority,
    resolved: tuple[M6ResolvedEmbeddingAuthority, ...],
) -> None:
    expected = {item.embedding_id: item for item in resolved}
    actual = {item.embedding_ref.artifact_id: item for item in closure.embeddings}
    if set(expected) - set(actual):
        _fail(M6EmbeddingAuthorityErrorCode.CLOSURE_EMBEDDING_MISSING)
    if set(actual) - set(expected):
        _fail(M6EmbeddingAuthorityErrorCode.CLOSURE_EMBEDDING_EXTRA)
    for embedding_id, authority in expected.items():
        locked = actual[embedding_id]
        if locked.scope != authority.scope:
            _fail(M6EmbeddingAuthorityErrorCode.EMBEDDING_SCOPE_COLLISION)
        if (
            locked.channel != authority.channel
            or locked.embedding_ref.document_sha256 != authority.document_sha256
            or locked.request_id != authority.request_id
            or locked.model_manifest_id != authority.model_manifest_id
        ):
            _fail(M6EmbeddingAuthorityErrorCode.CLOSURE_EMBEDDING_BINDING_MISMATCH)


def assemble_m6_resolved_embeddings(
    *,
    closure: M6ReplayInputClosureAuthority,
    snapshot: M6EmbeddingAuthoritySnapshot,
) -> tuple[M6ResolvedEmbeddingAuthority, ...]:
    """Resolve and verify the complete embedding inventory for successful cycles."""

    controlled, authority = _validated_arguments(closure, snapshot)
    exposure_documents, embedding_documents = _document_maps(authority)
    exposures = _selected_exposures(controlled, exposure_documents)
    resolved = _resolve_vectors(exposures, embedding_documents)
    _require_exact_closure(controlled, resolved)
    return resolved


__all__ = [
    "M6EmbeddingAuthorityError",
    "M6EmbeddingAuthorityErrorCode",
    "assemble_m6_resolved_embeddings",
]

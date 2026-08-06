from __future__ import annotations

import hashlib

import pytest

from labcourt.application.m6_embedding_authority import (
    M6EmbeddingAuthorityError,
    M6EmbeddingAuthorityErrorCode,
    assemble_m6_resolved_embeddings,
)
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.m5_precedent_usage import M5PrecedentExposureBatchAuthority
from labcourt.contracts.m5_precedents import (
    M5EmbeddingChannel,
    M5EmbeddingRequest,
    M5EmbeddingVector,
)
from labcourt.contracts.m5_projection import M5AuthorityKind
from labcourt.contracts.m6_replay_locked import (
    M6HistoricalCausalCut,
    M6LockedEmbeddingChannel,
    M6LockedEmbeddingInput,
    M6LockedEmbeddingScope,
    M6LockedFrameInput,
    M6LockedRetrievalCycleInput,
    M6LockedRetrievalOutcomeKind,
    M6ReplayAuthorityKind,
    M6ReplayAuthorityRef,
    M6ReplayInputClosureAuthority,
)
from labcourt.ports.m6_embeddings import (
    M6EmbeddingAuthorityDocument,
    M6EmbeddingAuthoritySnapshot,
)
from tests.contract.test_m5_precedent_usage_contracts import (
    OTHER_VIOLATION_ID,
    VISUAL_MODEL_MANIFEST_ID,
    _exposure,
)
from tests.unit.test_m6_historical_retrieval_cut import _relocate_exposure


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _document(
    kind: M5AuthorityKind,
    artifact_id: str,
    value: M5PrecedentExposureBatchAuthority | M5EmbeddingVector,
) -> M6EmbeddingAuthorityDocument:
    raw = canonical_json(value.model_dump(mode="json"))
    return M6EmbeddingAuthorityDocument(
        kind=kind,
        artifact_id=artifact_id,
        canonical_document=raw,
        document_sha256=hashlib.sha256(raw.encode("utf-8")).hexdigest(),
    )


def _vectors(
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


def _visual_embedding(input_ref: str) -> M5EmbeddingVector:
    return M5EmbeddingVector(
        request=M5EmbeddingRequest(
            channel=M5EmbeddingChannel.VISUAL,
            input_ref=input_ref,
            input_sha256=sha256_hex(["m6-visual-embedding", input_ref]),
            model_manifest_id=VISUAL_MODEL_MANIFEST_ID,
            dimensions=2,
        ),
        values=(0.25, 1.0),
    )


def _with_visual_query(
    exposure: M5PrecedentExposureBatchAuthority,
) -> M5PrecedentExposureBatchAuthority:
    query = exposure.m5_retrieval_result.query.model_copy(
        update={"visual_embeddings": (_visual_embedding("query-visual"),)}
    )
    result = exposure.m5_retrieval_result.model_copy(update={"query": query})
    proposed = exposure.model_copy(update={"m5_retrieval_result": result})
    return M5PrecedentExposureBatchAuthority.model_validate(
        proposed.model_dump(mode="json", exclude_computed_fields=True)
    )


def _with_visual_precedent(
    exposure: M5PrecedentExposureBatchAuthority,
) -> M5PrecedentExposureBatchAuthority:
    visual = _visual_embedding("precedent-visual")
    evaluations = list(exposure.m5_retrieval_result.candidate_evaluations)
    index = next(
        index
        for index, evaluation in enumerate(evaluations)
        if evaluation.authority.precedent.precedent_id == OTHER_VIOLATION_ID
    )
    evaluation = evaluations[index]
    precedent = evaluation.authority.precedent.model_copy(
        update={"visual_embedding_refs": (visual.embedding_id,)}
    )
    authority = evaluation.authority.model_copy(
        update={"precedent": precedent, "visual_embeddings": (visual,)}
    )
    evaluations[index] = evaluation.model_copy(update={"authority": authority})
    m5_result = exposure.m5_retrieval_result.model_copy(
        update={"candidate_evaluations": tuple(evaluations)}
    )
    m4_result = exposure.m4_retrieval_outcome.result
    assert m4_result is not None
    updated_m4_result = m4_result.model_copy(
        update={"candidate_precedents": tuple(item.authority.precedent for item in evaluations)}
    )
    receipt = exposure.m4_retrieval_outcome.receipt.model_copy(
        update={"candidate_snapshot_sha256": updated_m4_result.candidate_snapshot_sha256}
    )
    outcome = exposure.m4_retrieval_outcome.model_copy(
        update={"result": updated_m4_result, "receipt": receipt}
    )
    proposed = exposure.model_copy(
        update={"m5_retrieval_result": m5_result, "m4_retrieval_outcome": outcome}
    )
    return M5PrecedentExposureBatchAuthority.model_validate(
        proposed.model_dump(mode="json", exclude_computed_fields=True)
    )


def _snapshot(
    exposures: tuple[M5PrecedentExposureBatchAuthority, ...],
    *,
    run_id: str | None = None,
    authority_failure_count: int = 0,
) -> M6EmbeddingAuthoritySnapshot:
    vectors = {
        vector.embedding_id: vector
        for exposure in exposures
        for scope, vector in _vectors(exposure)
        if scope == M6LockedEmbeddingScope.PRECEDENT
    }
    documents = tuple(
        sorted(
            (
                *(
                    _document(
                        M5AuthorityKind.PRECEDENT_EXPOSURE,
                        exposure.exposure_id,
                        exposure,
                    )
                    for exposure in exposures
                ),
                *(
                    _document(M5AuthorityKind.PRECEDENT_EMBEDDING, key, vector)
                    for key, vector in vectors.items()
                ),
            ),
            key=lambda item: item.sort_key,
        )
    )
    first = exposures[0]
    return M6EmbeddingAuthoritySnapshot(
        source_identity_sha256=_sha("snapshot"),
        run_id=run_id or first.run_id,
        manifest_id=first.manifest_id,
        source_authority_root_sha256=_sha("authority-root"),
        documents=documents,
        authority_failure_count=authority_failure_count,
    )


def _cycle(
    exposure: M5PrecedentExposureBatchAuthority,
) -> M6LockedRetrievalCycleInput:
    document = _document(
        M5AuthorityKind.PRECEDENT_EXPOSURE,
        exposure.exposure_id,
        exposure,
    )
    return M6LockedRetrievalCycleInput(
        source_run_id=exposure.run_id,
        source_case_id=exposure.case_id,
        hearing_session_id=exposure.hearing_session_id,
        cycle_index=exposure.cycle_index,
        cycle_scope_id=exposure.cycle_scope_id,
        outcome=M6LockedRetrievalOutcomeKind.SUCCESS,
        authority_ref=M6ReplayAuthorityRef(
            kind=M6ReplayAuthorityKind.M5_PRECEDENT_EXPOSURE,
            artifact_id=exposure.exposure_id,
            document_sha256=document.document_sha256,
        ),
    )


def _locked_embeddings(
    exposures: tuple[M5PrecedentExposureBatchAuthority, ...],
    snapshot: M6EmbeddingAuthoritySnapshot,
) -> tuple[M6LockedEmbeddingInput, ...]:
    document_by_id = {
        document.artifact_id: document
        for document in snapshot.documents
        if document.kind == M5AuthorityKind.PRECEDENT_EMBEDDING
    }
    by_id: dict[str, tuple[M6LockedEmbeddingScope, M5EmbeddingVector]] = {}
    for exposure in exposures:
        for scope, vector in _vectors(exposure):
            previous = by_id.get(vector.embedding_id)
            if previous is not None:
                assert previous == (scope, vector)
            by_id[vector.embedding_id] = (scope, vector)
    values = tuple(
        M6LockedEmbeddingInput(
            scope=scope,
            channel=M6LockedEmbeddingChannel(vector.request.channel.value),
            embedding_ref=M6ReplayAuthorityRef(
                kind=M6ReplayAuthorityKind.M5_EMBEDDING,
                artifact_id=vector.embedding_id,
                document_sha256=(
                    document_by_id[vector.embedding_id].document_sha256
                    if scope == M6LockedEmbeddingScope.PRECEDENT
                    else hashlib.sha256(
                        canonical_json(vector.model_dump(mode="json")).encode("utf-8")
                    ).hexdigest()
                ),
            ),
            request_id=vector.request.request_id,
            model_manifest_id=vector.request.model_manifest_id,
        )
        for scope, vector in by_id.values()
    )
    return tuple(sorted(values, key=lambda item: item.sort_key))


def _closure(
    exposures: tuple[M5PrecedentExposureBatchAuthority, ...],
    snapshot: M6EmbeddingAuthoritySnapshot,
    *,
    embeddings: tuple[M6LockedEmbeddingInput, ...] | None = None,
    run_id: str | None = None,
    retrieval_cycles: tuple[M6LockedRetrievalCycleInput, ...] | None = None,
) -> M6ReplayInputClosureAuthority:
    first = exposures[0]
    return M6ReplayInputClosureAuthority(
        sample_id="sample-embedding-closure",
        source_run_id=run_id or first.run_id,
        source_case_id=first.case_id,
        source_case_revision=1,
        source_case_document_sha256=_sha("case"),
        source_manifest_id=first.manifest_id,
        source_manifest_document_sha256=_sha("manifest"),
        input_authority_id=_sha("input"),
        input_authority_document_sha256=_sha("input-document"),
        source_validation_report_id=_sha("validation"),
        source_validation_report_document_sha256=_sha("validation-document"),
        frames=(
            M6LockedFrameInput(
                frame_id="cam-01:stream-01:1",
                document_sha256=_sha("frame-document"),
                content_sha256=_sha("frame-content"),
            ),
        ),
        embeddings=(_locked_embeddings(exposures, snapshot) if embeddings is None else embeddings),
        historical_cut=M6HistoricalCausalCut(
            retrieval_cycles=(
                tuple(_cycle(exposure) for exposure in exposures)
                if retrieval_cycles is None
                else retrieval_cycles
            )
        ),
    )


def _assert_error(
    expected: M6EmbeddingAuthorityErrorCode,
    closure: M6ReplayInputClosureAuthority,
    snapshot: M6EmbeddingAuthoritySnapshot,
) -> None:
    with pytest.raises(M6EmbeddingAuthorityError) as raised:
        assemble_m6_resolved_embeddings(closure=closure, snapshot=snapshot)
    assert raised.value.code == expected


def test_resolves_query_and_every_candidate_vector_from_exact_success_exposure() -> None:
    exposure = _exposure()
    snapshot = _snapshot((exposure,))

    resolved = assemble_m6_resolved_embeddings(
        closure=_closure((exposure,), snapshot),
        snapshot=snapshot,
    )

    assert len(resolved) == 4
    assert tuple(item.scope for item in resolved) == (
        M6LockedEmbeddingScope.QUERY,
        M6LockedEmbeddingScope.PRECEDENT,
        M6LockedEmbeddingScope.PRECEDENT,
        M6LockedEmbeddingScope.PRECEDENT,
    )
    assert {item.embedding_id for item in resolved} == {
        vector.embedding_id for _scope, vector in _vectors(exposure)
    }


@pytest.mark.parametrize(
    ("exposure", "expected_scope"),
    (
        (_with_visual_query(_exposure()), M6LockedEmbeddingScope.QUERY),
        (_with_visual_precedent(_exposure()), M6LockedEmbeddingScope.PRECEDENT),
    ),
)
def test_resolves_every_text_and_visual_channel(
    exposure: M5PrecedentExposureBatchAuthority,
    expected_scope: M6LockedEmbeddingScope,
) -> None:
    snapshot = _snapshot((exposure,))

    resolved = assemble_m6_resolved_embeddings(
        closure=_closure((exposure,), snapshot),
        snapshot=snapshot,
    )

    assert any(
        item.scope == expected_scope and item.channel == M6LockedEmbeddingChannel.VISUAL
        for item in resolved
    )


def test_repeated_vectors_across_success_cycles_are_deduplicated() -> None:
    first = _exposure()
    second = _relocate_exposure(first, cycle_index=2)
    snapshot = _snapshot((first, second))

    resolved = assemble_m6_resolved_embeddings(
        closure=_closure((first, second), snapshot),
        snapshot=snapshot,
    )

    assert len(resolved) == 4


def test_degraded_only_cut_requires_no_embedding_even_when_snapshot_has_other_documents() -> None:
    exposure = _exposure()
    snapshot = _snapshot((exposure,))
    degraded = M6LockedRetrievalCycleInput(
        source_run_id=exposure.run_id,
        source_case_id=exposure.case_id,
        hearing_session_id=exposure.hearing_session_id,
        cycle_index=1,
        cycle_scope_id=exposure.cycle_scope_id,
        outcome=M6LockedRetrievalOutcomeKind.DEGRADED,
        authority_ref=M6ReplayAuthorityRef(
            kind=M6ReplayAuthorityKind.M4_PRECEDENT_RETRIEVAL_RECEIPT,
            artifact_id="degraded-receipt",
            document_sha256=_sha("degraded"),
        ),
    )
    closure = _closure((exposure,), snapshot, embeddings=()).model_copy(
        update={"historical_cut": M6HistoricalCausalCut(retrieval_cycles=(degraded,))}
    )

    assert assemble_m6_resolved_embeddings(closure=closure, snapshot=snapshot) == ()


def test_missing_and_extra_closure_embeddings_fail_closed() -> None:
    exposure = _exposure()
    snapshot = _snapshot((exposure,))
    exact = _locked_embeddings((exposure,), snapshot)
    missing = _closure((exposure,), snapshot, embeddings=exact[:-1])
    extra_input = M6LockedEmbeddingInput(
        scope=M6LockedEmbeddingScope.PRECEDENT,
        channel=M6LockedEmbeddingChannel.TEXT,
        embedding_ref=M6ReplayAuthorityRef(
            kind=M6ReplayAuthorityKind.M5_EMBEDDING,
            artifact_id=_sha("extra-id"),
            document_sha256=_sha("extra-document"),
        ),
        request_id=_sha("extra-request"),
        model_manifest_id=_sha("extra-model"),
    )
    extra_values = tuple(sorted((*exact, extra_input), key=lambda item: item.sort_key))
    extra = _closure((exposure,), snapshot, embeddings=extra_values)

    _assert_error(M6EmbeddingAuthorityErrorCode.CLOSURE_EMBEDDING_MISSING, missing, snapshot)
    _assert_error(M6EmbeddingAuthorityErrorCode.CLOSURE_EMBEDDING_EXTRA, extra, snapshot)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("channel", M6LockedEmbeddingChannel.VISUAL),
        ("request_id", _sha("wrong-request")),
        ("model_manifest_id", _sha("wrong-model")),
    ),
)
def test_closure_embedding_metadata_must_match_exact_authority(
    field: str,
    value: object,
) -> None:
    exposure = _exposure()
    snapshot = _snapshot((exposure,))
    exact = list(_locked_embeddings((exposure,), snapshot))
    exact[0] = exact[0].model_copy(update={field: value})
    closure = _closure(
        (exposure,),
        snapshot,
        embeddings=tuple(sorted(exact, key=lambda item: item.sort_key)),
    )

    _assert_error(
        M6EmbeddingAuthorityErrorCode.CLOSURE_EMBEDDING_BINDING_MISMATCH,
        closure,
        snapshot,
    )


def test_closure_embedding_document_hash_must_match_exact_authority() -> None:
    exposure = _exposure()
    snapshot = _snapshot((exposure,))
    exact = list(_locked_embeddings((exposure,), snapshot))
    attacked_ref = exact[0].embedding_ref.model_copy(
        update={"document_sha256": _sha("wrong-document")}
    )
    exact[0] = exact[0].model_copy(update={"embedding_ref": attacked_ref})
    closure = _closure(
        (exposure,),
        snapshot,
        embeddings=tuple(sorted(exact, key=lambda item: item.sort_key)),
    )

    _assert_error(
        M6EmbeddingAuthorityErrorCode.CLOSURE_EMBEDDING_BINDING_MISMATCH,
        closure,
        snapshot,
    )


def test_missing_durable_vector_and_forged_document_fail_closed() -> None:
    exposure = _exposure()
    snapshot = _snapshot((exposure,))
    closure = _closure((exposure,), snapshot)
    vector_documents = [
        document
        for document in snapshot.documents
        if document.kind == M5AuthorityKind.PRECEDENT_EMBEDDING
    ]
    missing_snapshot = _snapshot((exposure,))
    object.__setattr__(
        missing_snapshot,
        "documents",
        tuple(
            document for document in missing_snapshot.documents if document != vector_documents[0]
        ),
    )
    forged_snapshot = _snapshot((exposure,))
    first, second = vector_documents[:2]
    forged = M6EmbeddingAuthorityDocument(
        kind=M5AuthorityKind.PRECEDENT_EMBEDDING,
        artifact_id=first.artifact_id,
        canonical_document=second.canonical_document,
        document_sha256=second.document_sha256,
    )
    object.__setattr__(
        forged_snapshot,
        "documents",
        tuple(
            sorted(
                (
                    forged if document.artifact_id == first.artifact_id else document
                    for document in forged_snapshot.documents
                ),
                key=lambda item: item.sort_key,
            )
        ),
    )

    _assert_error(
        M6EmbeddingAuthorityErrorCode.EMBEDDING_AUTHORITY_MISSING,
        closure,
        missing_snapshot,
    )
    _assert_error(
        M6EmbeddingAuthorityErrorCode.EMBEDDING_AUTHORITY_FORGED,
        closure,
        forged_snapshot,
    )


def test_duplicate_durable_embedding_document_fails_closed() -> None:
    exposure = _exposure()
    snapshot = _snapshot((exposure,))
    closure = _closure((exposure,), snapshot)
    duplicate = next(
        document
        for document in snapshot.documents
        if document.kind == M5AuthorityKind.PRECEDENT_EMBEDDING
    )
    object.__setattr__(
        snapshot,
        "documents",
        tuple(sorted((*snapshot.documents, duplicate), key=lambda item: item.sort_key)),
    )

    _assert_error(
        M6EmbeddingAuthorityErrorCode.EMBEDDING_AUTHORITY_DUPLICATE,
        closure,
        snapshot,
    )


def test_foreign_exposure_scope_and_invalid_full_snapshot_fail_closed() -> None:
    exposure = _exposure()
    snapshot = _snapshot((exposure,), run_id="foreign-run")
    foreign_cycle = _cycle(exposure).model_copy(update={"source_run_id": "foreign-run"})
    closure = _closure(
        (exposure,),
        snapshot,
        run_id="foreign-run",
        retrieval_cycles=(foreign_cycle,),
    )
    invalid_snapshot = _snapshot((exposure,), authority_failure_count=1)

    _assert_error(
        M6EmbeddingAuthorityErrorCode.EXPOSURE_AUTHORITY_SCOPE_MISMATCH,
        closure,
        snapshot,
    )
    _assert_error(
        M6EmbeddingAuthorityErrorCode.SNAPSHOT_AUTHORITY_INVALID,
        _closure((exposure,), invalid_snapshot),
        invalid_snapshot,
    )


def test_one_embedding_cannot_be_both_query_and_precedent_scope() -> None:
    exposure = _exposure()
    precedent_vector = exposure.m5_retrieval_result.candidate_evaluations[
        0
    ].authority.text_embedding
    assert precedent_vector is not None
    query = exposure.m5_retrieval_result.query.model_copy(
        update={"text_embedding": precedent_vector}
    )
    result = exposure.m5_retrieval_result.model_copy(update={"query": query})
    collided = exposure.model_copy(update={"m5_retrieval_result": result})
    collided = M5PrecedentExposureBatchAuthority.model_validate(
        collided.model_dump(mode="json", exclude_computed_fields=True)
    )
    snapshot = _snapshot((collided,))
    closure = _closure((collided,), snapshot, embeddings=())

    _assert_error(
        M6EmbeddingAuthorityErrorCode.EMBEDDING_SCOPE_COLLISION,
        closure,
        snapshot,
    )

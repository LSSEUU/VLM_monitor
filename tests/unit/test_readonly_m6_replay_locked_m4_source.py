from __future__ import annotations

from types import SimpleNamespace

import pytest

from labcourt.adapters.storage import readonly_m6_projection_context as adapter_module
from labcourt.adapters.storage.readonly_m4_artifacts import (
    ReadonlyM4ArtifactRepository,
)
from labcourt.adapters.storage.readonly_m6_perception import (
    ReadonlyM6PerceptionAuthorityRepository,
)
from labcourt.adapters.storage.readonly_m6_projection_context import (
    ReadonlyM6SqliteProjectionAssemblyRepository,
)
from labcourt.adapters.storage.readonly_m6_source_authority import (
    ReadonlyM6SealedSourceAuthorityRepository,
)
from labcourt.application.m6_verified_projection_context import (
    M6SqliteProjectionAssembly,
    M6SqliteProjectionAssemblyError,
    M6SqliteProjectionAssemblyErrorCode,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import CaseStatus
from labcourt.contracts.m4_projection import M4ProjectionArtifactKind
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from tests.unit.test_m6_replay_locked_closed_policy_m4_predecessor import (
    _closed_cut,
    _ready_terminal_source,
)
from tests.unit.test_m6_replay_locked_m4_source import _terminal_source
from tests.unit.test_m6_source_authority import _bundle


def _document(kind: M4ProjectionArtifactKind, value: object) -> SimpleNamespace:
    return SimpleNamespace(
        kind=kind,
        canonical_document=canonical_json(value.model_dump(mode="json")),  # type: ignore[attr-defined]
    )


def _repository(
    monkeypatch: pytest.MonkeyPatch,
    *,
    duplicate_binding: bool = False,
) -> tuple[ReadonlyM6SqliteProjectionAssemblyRepository, object]:
    source = _terminal_source(monkeypatch)
    config = _bundle().config
    assembly = M6SqliteProjectionAssembly(
        source_identity_sha256=source.source_identity_sha256,
        closure=source.closure,
        model_calls=source.closure.model_calls,
        embeddings=(),
        projection_context=source.projection_context,
        case_replay_snapshot=source.source_snapshot,
    )
    record_document = _document(
        M4ProjectionArtifactKind.HEARING_RECORD,
        source.hearing_record,
    )
    binding_document = _document(
        M4ProjectionArtifactKind.VERDICT_BINDING,
        source.hearing_verdict_binding,
    )
    documents = (record_document, binding_document)
    if duplicate_binding:
        documents = (*documents, binding_document)
    scan = SimpleNamespace(failures=(), documents=documents)
    identity = SimpleNamespace(identity_sha256=source.source_identity_sha256)
    authority = SimpleNamespace(
        source_identity_sha256=source.source_identity_sha256,
        receipt_for_review=lambda review_id: (
            source.gate_current_closure_receipt
            if review_id == source.projection_context.case.procedural_reviews[0].review_id
            else None
        ),
    )
    monkeypatch.setattr(
        adapter_module,
        "capture_m6_readonly_snapshot_identity",
        lambda _snapshot: identity,
    )
    monkeypatch.setattr(
        ReadonlyM6SqliteProjectionAssemblyRepository,
        "assemble",
        lambda _self, _closure: assembly,
    )
    monkeypatch.setattr(
        ReadonlyM4ArtifactRepository,
        "scan",
        lambda _self, _run_id: scan,
    )
    monkeypatch.setattr(
        ReadonlyM6SealedSourceAuthorityRepository,
        "load_validated_source",
        lambda _self, _closure: authority,
    )
    return (
        ReadonlyM6SqliteProjectionAssemblyRepository(
            "private-source.sqlite3",
            config=config,
            source_authority_root="sealed-source-authority",
        ),
        source,
    )


def test_adapter_joins_exact_hearing_binding_and_gate_receipt_from_one_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, expected = _repository(monkeypatch)

    observed = repository.assemble_m4_gate_terminal(expected.closure)  # type: ignore[attr-defined]

    assert observed == expected


def test_adapter_rejects_ambiguous_hearing_binding_instead_of_guessing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, expected = _repository(monkeypatch, duplicate_binding=True)

    with pytest.raises(M6SqliteProjectionAssemblyError) as raised:
        repository.assemble_m4_gate_terminal(expected.closure)  # type: ignore[attr-defined]

    assert raised.value.code == M6SqliteProjectionAssemblyErrorCode.PROJECTION_CONTEXT_INVALID


def _closed_repository(
    monkeypatch: pytest.MonkeyPatch,
    *,
    duplicate_binding: bool = False,
) -> tuple[
    ReadonlyM6SqliteProjectionAssemblyRepository,
    object,
    M6ReplayInputClosureAuthority,
    list[M6ReplayInputClosureAuthority],
]:
    source = _ready_terminal_source(monkeypatch)
    closure, closed_assembly = _closed_cut(source)
    config = _bundle().config
    record_document = _document(
        M4ProjectionArtifactKind.HEARING_RECORD,
        source.hearing_record,
    )
    binding_document = _document(
        M4ProjectionArtifactKind.VERDICT_BINDING,
        source.hearing_verdict_binding,
    )
    documents = (record_document, binding_document)
    if duplicate_binding:
        documents = (*documents, binding_document)
    scan = SimpleNamespace(failures=(), documents=documents)
    identity = SimpleNamespace(identity_sha256=source.source_identity_sha256)
    authority = SimpleNamespace(
        source_identity_sha256=source.source_identity_sha256,
        receipt_for_review=lambda review_id: (
            source.gate_current_closure_receipt
            if review_id == source.projection_context.case.procedural_reviews[0].review_id
            else None
        ),
    )
    selectors: list[M6ReplayInputClosureAuthority] = []

    def read_ready(_self, selector):  # type: ignore[no-untyped-def]
        selectors.append(selector)
        return SimpleNamespace(
            source_identity_sha256=source.source_identity_sha256,
            source_case_canonical_document=canonical_json(
                source.projection_context.case.model_dump(mode="json")
            ),
        )

    monkeypatch.setattr(
        adapter_module,
        "capture_m6_readonly_snapshot_identity",
        lambda _snapshot: identity,
    )
    monkeypatch.setattr(
        ReadonlyM6SqliteProjectionAssemblyRepository,
        "assemble",
        lambda _self, _closure: closed_assembly,
    )
    monkeypatch.setattr(
        ReadonlyM6PerceptionAuthorityRepository,
        "read_authority_snapshot",
        read_ready,
    )
    monkeypatch.setattr(
        ReadonlyM4ArtifactRepository,
        "scan",
        lambda _self, _run_id: scan,
    )
    monkeypatch.setattr(
        ReadonlyM6SealedSourceAuthorityRepository,
        "load_validated_source",
        lambda _self, _closure: authority,
    )
    return (
        ReadonlyM6SqliteProjectionAssemblyRepository(
            "private-source.sqlite3",
            config=config,
            source_authority_root="sealed-source-authority",
        ),
        source,
        closure,
        selectors,
    )


def test_closed_adapter_keeps_ready_selector_private_and_returns_real_catalog_cut(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, source, closure, selectors = _closed_repository(monkeypatch)

    observed = repository.assemble_closed_policy_m4_predecessor(
        closure,
        ready_case=source.projection_context.case,  # type: ignore[attr-defined]
        ready_case_revision=source.source_snapshot.source_case_revision,  # type: ignore[attr-defined]
    )

    assert observed.catalog_closure == closure
    assert observed.projection_context.case.status is CaseStatus.READY_FOR_ALERT_POLICY
    assert observed.hearing_record == source.hearing_record  # type: ignore[attr-defined]
    assert len(selectors) == 1
    assert selectors[0].source_case_revision == observed.source_ready_case_revision
    assert selectors[0].source_case_document_sha256 == (
        observed.source_snapshot.source_case_document_sha256
    )
    assert selectors[0] != observed.catalog_closure
    assert not hasattr(observed, "private_ready_selector")


def test_closed_adapter_rejects_ambiguous_m4_join_before_returning_projection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, source, closure, _selectors = _closed_repository(
        monkeypatch,
        duplicate_binding=True,
    )

    with pytest.raises(M6SqliteProjectionAssemblyError) as raised:
        repository.assemble_closed_policy_m4_predecessor(
            closure,
            ready_case=source.projection_context.case,  # type: ignore[attr-defined]
            ready_case_revision=source.source_snapshot.source_case_revision,  # type: ignore[attr-defined]
        )

    assert raised.value.code == M6SqliteProjectionAssemblyErrorCode.PROJECTION_CONTEXT_INVALID

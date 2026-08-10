from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from labcourt.adapters.m8_offline_knowledge import DeterministicOfflineKnowledgeRetriever
from labcourt.adapters.storage.sqlite_m8_knowledge_repository import (
    SQLiteM8KnowledgeRepository,
)
from labcourt.adapters.storage.sqlite_m8_operations_repository import (
    SQLiteM8OperationsRepository,
)
from labcourt.application.m8_knowledge_demo import build_offline_knowledge_demo_bundle
from labcourt.contracts.m8_access_cases import (
    M8ActorAuthorityV1,
    M8ActorRole,
    M8ActorScopeKind,
)
from labcourt.contracts.m8_knowledge import (
    M8KnowledgeCatalogAuthorityV1,
    M8KnowledgeDocumentType,
    M8KnowledgeQueryV1,
)
from labcourt.exceptions import ConcurrentModification

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64
BASE_TIME = datetime(2026, 8, 10, 9, 0, tzinfo=UTC)
BUSY_TIMEOUT_MS = 5_000


def _student(*, revision: int = 1, active: bool = True) -> M8ActorAuthorityV1:
    return M8ActorAuthorityV1(
        actor_id="student-01",
        role=M8ActorRole.STUDENT,
        scope_kind=M8ActorScopeKind.SELF_ONLY,
        scope_location_ids=(),
        identity_provider_id="campus-idp",
        subject_binding_sha256=SHA_A,
        authority_revision=revision,
        active=active,
        manifest_id=SHA_B,
    )


def _repositories(
    tmp_path: Path,
) -> tuple[SQLiteM8OperationsRepository, SQLiteM8KnowledgeRepository, Path]:
    operations_root = tmp_path / "operations"
    operations_root.mkdir()
    database = operations_root / "labcourt.sqlite3"
    operations = SQLiteM8OperationsRepository.initialize(
        database,
        BUSY_TIMEOUT_MS,
        SHA_C,
    )
    knowledge = SQLiteM8KnowledgeRepository(database, BUSY_TIMEOUT_MS, SHA_C)
    return operations, knowledge, database


def _bundle():
    return build_offline_knowledge_demo_bundle(
        generated_at=BASE_TIME,
        document_manifest_id=SHA_A,
        catalog_manifest_id=SHA_B,
        adapter_manifest_id=SHA_E,
    )


def _query(
    catalog: M8KnowledgeCatalogAuthorityV1,
    actor: M8ActorAuthorityV1,
    *,
    text: str = "\u62a4\u76ee\u955c \u4f69\u6234",
) -> M8KnowledgeQueryV1:
    return M8KnowledgeQueryV1(
        catalog_authority_id=catalog.catalog_authority_id,
        requester_actor_id=actor.actor_id,
        requester_actor_authority_id=actor.actor_authority_id,
        query_text=text,
        locale="zh-CN",
        as_of=BASE_TIME,
        allowed_document_types=tuple(sorted(M8KnowledgeDocumentType, key=lambda item: item.value)),
        max_citations=3,
        query_manifest_id=SHA_D,
    )


def _catalog_v2(catalog: M8KnowledgeCatalogAuthorityV1) -> M8KnowledgeCatalogAuthorityV1:
    return M8KnowledgeCatalogAuthorityV1(
        catalog_id=catalog.catalog_id,
        catalog_revision=2,
        documents=catalog.documents,
        generated_at=catalog.generated_at + timedelta(seconds=1),
        catalog_manifest_id=catalog.catalog_manifest_id,
    )


def test_catalog_publication_is_atomic_idempotent_and_restart_safe(tmp_path: Path) -> None:
    _operations, repository, database = _repositories(tmp_path)
    bundle = _bundle()
    raw_contents = tuple(
        bundle.content_map()[document.content_ref] for document in bundle.catalog.documents
    )

    corrupted = list(raw_contents)
    corrupted[-1] = b"x" * len(corrupted[-1])
    with pytest.raises(ConcurrentModification, match="hash or size"):
        repository.publish_catalog(bundle.catalog, tuple(corrupted), None, SHA_D)
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT count(*) FROM m8_knowledge_raw_contents").fetchone() == (
            0,
        )
        assert connection.execute(
            "SELECT count(*) FROM m8_knowledge_catalog_versions"
        ).fetchone() == (0,)

    committed = repository.publish_catalog(bundle.catalog, raw_contents, None, SHA_D)
    assert repository.publish_catalog(bundle.catalog, raw_contents, None, SHA_D) == committed
    with pytest.raises(ConcurrentModification, match="retry content bytes conflict"):
        repository.publish_catalog(bundle.catalog, raw_contents, None, SHA_E)

    reopened = SQLiteM8KnowledgeRepository(database, BUSY_TIMEOUT_MS, SHA_C)
    assert reopened.get_current_catalog(bundle.catalog.catalog_id) == committed
    for document, raw in zip(bundle.catalog.documents, raw_contents, strict=True):
        assert reopened.read_content(document.content_ref) == raw


def test_answer_commit_binds_current_actor_and_catalog_but_preserves_history(
    tmp_path: Path,
) -> None:
    operations, repository, database = _repositories(tmp_path)
    actor = _student()
    operations.publish_actor_authority(actor, None)
    bundle = _bundle()
    contents = bundle.content_map()
    raw_contents = tuple(contents[document.content_ref] for document in bundle.catalog.documents)
    repository.publish_catalog(bundle.catalog, raw_contents, None, SHA_D)

    adapter = DeterministicOfflineKnowledgeRetriever(
        bundle.catalog,
        contents,
        bundle.adapter_manifest_id,
    )
    answer = adapter.query(_query(bundle.catalog, actor))
    committed = repository.commit_answer(answer)
    assert repository.commit_answer(answer) == committed
    assert (
        SQLiteM8KnowledgeRepository(database, BUSY_TIMEOUT_MS, SHA_C).get_answer(
            answer.query.query_id
        )
        == committed
    )

    stale_actor_answer = adapter.query(
        _query(bundle.catalog, actor, text="\u5b9e\u9a8c\u5ba4 \u5b89\u5168")
    )
    operations.publish_actor_authority(_student(revision=2, active=False), 1)
    with pytest.raises(ConcurrentModification, match="current active actor"):
        repository.commit_answer(stale_actor_answer)
    assert repository.get_answer(answer.query.query_id) == committed


def test_answer_commit_rejects_a_superseded_catalog_and_tables_are_append_only(
    tmp_path: Path,
) -> None:
    operations, repository, database = _repositories(tmp_path)
    actor = _student()
    operations.publish_actor_authority(actor, None)
    bundle = _bundle()
    contents = bundle.content_map()
    raw_contents = tuple(contents[document.content_ref] for document in bundle.catalog.documents)
    repository.publish_catalog(bundle.catalog, raw_contents, None, SHA_D)
    adapter = DeterministicOfflineKnowledgeRetriever(
        bundle.catalog,
        contents,
        bundle.adapter_manifest_id,
    )
    stale_answer = adapter.query(_query(bundle.catalog, actor))

    catalog_v2 = _catalog_v2(bundle.catalog)
    repository.publish_catalog(catalog_v2, raw_contents, 1, SHA_D)
    with pytest.raises(ConcurrentModification, match="no longer current"):
        repository.commit_answer(stale_answer)

    with (
        sqlite3.connect(database) as connection,
        pytest.raises(sqlite3.IntegrityError, match="append-only"),
    ):
        connection.execute("UPDATE m8_knowledge_catalog_versions SET catalog_revision = 9")

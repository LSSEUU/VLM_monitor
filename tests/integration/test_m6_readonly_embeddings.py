from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest

from labcourt.adapters.fake_precedent_embeddings import (
    DeterministicFakePrecedentEmbeddingProvider,
)
from labcourt.adapters.storage.readonly_m6_embeddings import (
    ReadonlyM6EmbeddingAuthorityRepository,
)
from labcourt.adapters.storage.readonly_sqlite import readonly_sqlite_snapshot
from labcourt.application.m6_embedding_authority import (
    M6EmbeddingAuthorityError,
    M6EmbeddingAuthorityErrorCode,
)
from labcourt.contracts.m5_projection import M5AuthorityKind
from tests.integration.test_m5_precedent_exposure_sqlite import _proposed, _runtime
from tests.integration.test_m5_sqlite_precedents import _authority
from tests.unit.test_m6_embedding_authority import _closure


def _source_fingerprint(root: Path) -> dict[str, tuple[int, str]]:
    return {
        path.name: (path.stat().st_size, hashlib.sha256(path.read_bytes()).hexdigest())
        for path in root.iterdir()
        if path.is_file()
    }


def test_repository_resolves_exact_m5_embedding_closure_without_provider_or_sidecars(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime(tmp_path)
    runtime.m5.append_authority(
        _authority(runtime.manifest, "precedent-m6-embedding"),
        None,
    )
    runtime.committer.commit(_proposed(runtime))
    exposure = runtime.committer.load_exposure(
        runtime.prepared.session.run_id,
        runtime.prepared.cycle_scope.cycle_id,
    )
    assert exposure is not None
    source_before = _source_fingerprint(tmp_path)

    def reject_provider_call(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("M6 locked embedding resolution called a provider")

    monkeypatch.setattr(
        DeterministicFakePrecedentEmbeddingProvider,
        "embed",
        reject_provider_call,
    )
    with readonly_sqlite_snapshot(runtime.database) as snapshot_path:
        private_before = {path.name for path in snapshot_path.parent.iterdir()}
        repository = ReadonlyM6EmbeddingAuthorityRepository(
            snapshot_path,
            config=runtime.config,
        )
        authority = repository.read_authority_snapshot(runtime.prepared.session.run_id)
        closure = _closure((exposure,), authority)
        resolved = repository.assemble(closure)
        private_after = {path.name for path in snapshot_path.parent.iterdir()}

    assert {document.kind for document in authority.documents} == {
        M5AuthorityKind.PRECEDENT_EMBEDDING,
        M5AuthorityKind.PRECEDENT_EXPOSURE,
    }
    assert len(resolved) == 2
    query_embedding = exposure.m5_retrieval_result.query.text_embedding
    precedent_embedding = exposure.m5_retrieval_result.candidate_evaluations[
        0
    ].authority.text_embedding
    assert query_embedding is not None
    assert precedent_embedding is not None
    assert {item.embedding_id for item in resolved} == {
        query_embedding.embedding_id,
        precedent_embedding.embedding_id,
    }
    assert private_after == private_before
    assert _source_fingerprint(tmp_path) == source_before


def test_repository_rejects_a_forged_durable_embedding_from_full_m5_validation(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    runtime.m5.append_authority(
        _authority(runtime.manifest, "precedent-m6-forged-embedding"),
        None,
    )
    runtime.committer.commit(_proposed(runtime))
    exposure = runtime.committer.load_exposure(
        runtime.prepared.session.run_id,
        runtime.prepared.cycle_scope.cycle_id,
    )
    assert exposure is not None
    with readonly_sqlite_snapshot(runtime.database) as snapshot_path:
        authority = ReadonlyM6EmbeddingAuthorityRepository(
            snapshot_path,
            config=runtime.config,
        ).read_authority_snapshot(runtime.prepared.session.run_id)
    closure = _closure((exposure,), authority)

    with sqlite3.connect(runtime.database) as connection:
        # Corruption injection only: production writes cannot bypass this
        # append-only trigger. The disposable database is deliberately damaged.
        trigger_row = connection.execute(
            "SELECT sql FROM sqlite_master "
            "WHERE type = 'trigger' AND name = 'precedent_embeddings_no_update'"
        ).fetchone()
        assert trigger_row is not None and isinstance(trigger_row[0], str)
        trigger_sql = trigger_row[0]
        connection.execute("DROP TRIGGER precedent_embeddings_no_update")
        connection.execute(
            "UPDATE precedent_embeddings SET document_sha256 = ? WHERE run_id = ?",
            ("0" * 64, runtime.prepared.session.run_id),
        )
        connection.execute(trigger_sql)
        connection.commit()

    with readonly_sqlite_snapshot(runtime.database) as snapshot_path:
        repository = ReadonlyM6EmbeddingAuthorityRepository(
            snapshot_path,
            config=runtime.config,
        )
        with pytest.raises(M6EmbeddingAuthorityError) as raised:
            repository.assemble(closure)

    assert raised.value.code == M6EmbeddingAuthorityErrorCode.SNAPSHOT_AUTHORITY_INVALID

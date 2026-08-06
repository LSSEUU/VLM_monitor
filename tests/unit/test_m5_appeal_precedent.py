from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from labcourt.adapters.fake_precedent_embeddings import (
    DeterministicFakePrecedentEmbeddingProvider,
)
from labcourt.adapters.storage.sqlite_m5_repository import SQLiteM5Repository
from labcourt.application.m5_appeal_precedent import (
    AppealPrecedentError,
    AppealPrecedentFailureCode,
    build_appeal_overturn_precedent,
)
from labcourt.contracts.enums import PrecedentSource, PrecedentStatus, VerdictDecision
from labcourt.services.m5_operations import finalize_m5_run
from tests.integration.test_m5_sqlite_alert_repository import _prepare_ready_case

ROOT = Path(__file__).parents[2]
NOW = datetime(2026, 8, 2, 15, tzinfo=UTC)


def _closed_authority(tmp_path: Path):
    database, _, _, ready, manifest, config = _prepare_ready_case(tmp_path)
    finalize_m5_run(
        config=config,
        workspace_root=tmp_path,
        database_path=database,
        run_id=ready.case.run_id,
        clock=lambda: NOW,
    )
    repository = SQLiteM5Repository(database, config.storage.busy_timeout_ms)
    return (
        repository.load_closed_case_authority(ready.case.run_id, ready.case.case_id),
        manifest,
        config,
    )


def test_appeal_overturn_precedent_is_active_fake_embedded_and_reproducible(
    tmp_path: Path,
) -> None:
    authority, manifest, config = _closed_authority(tmp_path)
    provider = DeterministicFakePrecedentEmbeddingProvider()
    first = build_appeal_overturn_precedent(
        case_authority=authority,
        manifest=manifest,
        appeal_id="appeal-01",
        situation_text="Human review established that the original decision was incorrect.",
        resolved_decision=VerdictDecision.NOT_ESTABLISHED,
        config=config,
        embedding_provider=provider,
        created_at=NOW,
    )
    second = build_appeal_overturn_precedent(
        case_authority=authority,
        manifest=manifest,
        appeal_id="appeal-01",
        situation_text="Human review established that the original decision was incorrect.",
        resolved_decision=VerdictDecision.NOT_ESTABLISHED,
        config=config,
        embedding_provider=provider,
        created_at=NOW,
    )

    assert first == second
    assert first.config_sha256 == manifest.config_sha256
    assert first.precedent.source == PrecedentSource.APPEAL_OVERTURN
    assert first.precedent.status == PrecedentStatus.ACTIVE
    assert first.precedent.source_case_id == authority.case_id
    assert first.text_embedding is not None
    assert first.text_embedding.request.model_manifest_id == authority.text_embedding_manifest_id


def test_appeal_precedent_requires_a_changed_human_decision(tmp_path: Path) -> None:
    authority, manifest, config = _closed_authority(tmp_path)
    with pytest.raises(AppealPrecedentError) as raised:
        build_appeal_overturn_precedent(
            case_authority=authority,
            manifest=manifest,
            appeal_id="appeal-01",
            situation_text="Human review summary.",
            resolved_decision=authority.final_decision,
            config=config,
            embedding_provider=DeterministicFakePrecedentEmbeddingProvider(),
            created_at=NOW,
        )
    assert raised.value.reason_code == AppealPrecedentFailureCode.DECISION_NOT_OVERTURNED


def test_appeal_precedent_rejects_cross_manifest_authority(tmp_path: Path) -> None:
    authority, manifest, config = _closed_authority(tmp_path)
    other = manifest.model_copy(update={"random_seed": manifest.random_seed + 1})
    with pytest.raises(AppealPrecedentError) as raised:
        build_appeal_overturn_precedent(
            case_authority=authority,
            manifest=other,
            appeal_id="appeal-01",
            situation_text="Human review summary.",
            resolved_decision=VerdictDecision.NOT_ESTABLISHED,
            config=config,
            embedding_provider=DeterministicFakePrecedentEmbeddingProvider(),
            created_at=NOW,
        )
    assert raised.value.reason_code == AppealPrecedentFailureCode.MANIFEST_MISMATCH


def test_appeal_precedent_rejects_foreign_valid_precedent_config(tmp_path: Path) -> None:
    authority, manifest, config = _closed_authority(tmp_path)
    foreign_precedents = config.precedents.model_copy(
        update={
            "source_weights": {
                **config.precedents.source_weights,
                PrecedentSource.APPEAL_OVERTURN: 1.2,
            }
        }
    )
    foreign_config = config.model_copy(update={"precedents": foreign_precedents})
    assert foreign_config.config_sha256 != manifest.config_sha256

    with pytest.raises(AppealPrecedentError) as raised:
        build_appeal_overturn_precedent(
            case_authority=authority,
            manifest=manifest,
            appeal_id="appeal-foreign-config",
            situation_text="Human review summary.",
            resolved_decision=VerdictDecision.NOT_ESTABLISHED,
            config=foreign_config,
            embedding_provider=DeterministicFakePrecedentEmbeddingProvider(),
            created_at=NOW,
        )

    assert raised.value.reason_code == AppealPrecedentFailureCode.CONFIG_AUTHORITY_MISMATCH

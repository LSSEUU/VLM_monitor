from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from labcourt.adapters.fake_precedent_embeddings import (
    DeterministicFakePrecedentEmbeddingProvider,
)
from labcourt.application.m5_automatic_precedent import (
    AutomaticPrecedentError,
    AutomaticPrecedentErrorCode,
    build_automatic_precedent_authority,
)
from labcourt.config_loader import load_config
from labcourt.contracts.enums import PrecedentSource, PrecedentStatus
from labcourt.domain.alert_policy import plan_case_alert
from tests.unit.test_m5_alert_policy import _manifest_with_stream, _ready_case

ROOT = Path(__file__).parents[2]
NOW = datetime(2026, 8, 2, 12, tzinfo=UTC)


def _build():
    config = load_config(ROOT / "configs/demo.yaml")
    manifest = _manifest_with_stream()
    case = _ready_case(manifest)
    alert = plan_case_alert(case, config, manifest)
    authority = build_automatic_precedent_authority(
        case=case,
        manifest=manifest,
        alert_authority=alert,
        config=config,
        embedding_provider=DeterministicFakePrecedentEmbeddingProvider(),
        created_at=NOW,
    )
    return config, manifest, case, alert, authority


def test_automatic_precedent_is_manifest_pinned_provisional_and_reproducible() -> None:
    config, manifest, case, alert, first = _build()
    second = build_automatic_precedent_authority(
        case=case,
        manifest=manifest,
        alert_authority=alert,
        config=config,
        embedding_provider=DeterministicFakePrecedentEmbeddingProvider(),
        created_at=NOW,
    )

    assert first == second
    assert first.config_sha256 == manifest.config_sha256
    assert first.precedent.source == PrecedentSource.AUTOMATIC
    assert first.precedent.status == PrecedentStatus.PROVISIONAL
    assert first.precedent.source_case_id == case.case_id
    assert first.precedent.decision_direction == case.verdicts[-1].decision
    assert first.activation_not_before == NOW + timedelta(days=7)
    assert first.text_embedding is not None
    assert (
        first.text_embedding.request.model_manifest_id
        == manifest.models["text_embedding"].model_manifest_id
    )
    assert first.text_embedding.request.dimensions == 32


def test_automatic_precedent_rejects_cross_manifest_alert_authority() -> None:
    config, manifest, case, _, _ = _build()
    other_manifest = manifest.model_copy(update={"random_seed": manifest.random_seed + 1})
    other_case = _ready_case(other_manifest)
    mismatched = plan_case_alert(other_case, config, other_manifest)

    with pytest.raises(AutomaticPrecedentError) as raised:
        build_automatic_precedent_authority(
            case=case,
            manifest=manifest,
            alert_authority=mismatched,
            config=config,
            embedding_provider=DeterministicFakePrecedentEmbeddingProvider(),
            created_at=NOW,
        )

    assert raised.value.code == AutomaticPrecedentErrorCode.SOURCE_AUTHORITY_MISMATCH


def test_automatic_precedent_rejects_foreign_valid_precedent_config() -> None:
    config, manifest, case, alert, _ = _build()
    foreign_precedents = config.precedents.model_copy(
        update={"conflict_similarity": config.precedents.conflict_similarity - 0.01}
    )
    foreign_config = config.model_copy(update={"precedents": foreign_precedents})
    assert foreign_config.config_sha256 != manifest.config_sha256

    with pytest.raises(AutomaticPrecedentError) as raised:
        build_automatic_precedent_authority(
            case=case,
            manifest=manifest,
            alert_authority=alert,
            config=foreign_config,
            embedding_provider=DeterministicFakePrecedentEmbeddingProvider(),
            created_at=NOW,
        )

    assert raised.value.code == AutomaticPrecedentErrorCode.CONFIG_AUTHORITY_MISMATCH


@pytest.mark.parametrize("dimensions", [True, 0, 4_097])
def test_automatic_precedent_rejects_invalid_embedding_dimensions(dimensions: object) -> None:
    config, manifest, case, alert, _ = _build()
    with pytest.raises(AutomaticPrecedentError) as raised:
        build_automatic_precedent_authority(
            case=case,
            manifest=manifest,
            alert_authority=alert,
            config=config,
            embedding_provider=DeterministicFakePrecedentEmbeddingProvider(),
            created_at=NOW,
            dimensions=dimensions,  # type: ignore[arg-type]
        )
    assert raised.value.code == AutomaticPrecedentErrorCode.INVALID_ARGUMENT

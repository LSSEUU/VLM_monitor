from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from labcourt.adapters.fake_precedent_embeddings import (
    DeterministicFakePrecedentEmbeddingProvider,
)
from labcourt.application.alert_policy_verifier import ConfiguredAlertPolicyVerifier
from labcourt.application.automatic_precedent_verifier import (
    AutomaticPrecedentVerificationError,
    ConfiguredAutomaticPrecedentVerifier,
)
from labcourt.application.m5_automatic_precedent import (
    build_automatic_precedent_authority,
    derive_automatic_precedent_authority,
)
from labcourt.config_loader import load_config
from tests.unit.test_m5_alert_policy import _manifest_with_stream, _ready_case

ROOT = Path(__file__).parents[2]
NOW = datetime(2026, 8, 2, 12, tzinfo=UTC)


def test_configured_automatic_precedent_verifier_exactly_rebuilds_fake_content() -> None:
    config = load_config(ROOT / "configs" / "demo.yaml")
    manifest = _manifest_with_stream()
    case = _ready_case(manifest)
    alert = ConfiguredAlertPolicyVerifier(config).rebuild(case, manifest, None, None)
    provider = DeterministicFakePrecedentEmbeddingProvider()
    verifier = ConfiguredAutomaticPrecedentVerifier(config, provider)

    expected = build_automatic_precedent_authority(
        case=case,
        manifest=manifest,
        alert_authority=alert,
        config=config,
        embedding_provider=provider,
        created_at=NOW,
    )
    readonly = derive_automatic_precedent_authority(
        case=case,
        manifest=manifest,
        alert_authority=alert,
        config=config,
        created_at=NOW,
    )

    assert verifier.rebuild(case, manifest, alert, NOW) == expected
    assert readonly == expected
    for invalid_created_at in (
        datetime(2026, 8, 2, 12),
        datetime(2026, 8, 2, 20, tzinfo=timezone(timedelta(hours=8))),
    ):
        with pytest.raises(AutomaticPrecedentVerificationError, match="UTC"):
            verifier.rebuild(case, manifest, alert, invalid_created_at)

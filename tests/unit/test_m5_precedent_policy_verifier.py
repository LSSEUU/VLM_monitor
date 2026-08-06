from pathlib import Path

import pytest

from labcourt.application.m5_precedent_policy_verifier import (
    ConfiguredM5PrecedentPolicyVerifier,
)
from labcourt.application.m5_precedents import m5_precedent_policy_from_config
from labcourt.config_loader import load_config
from labcourt.contracts.enums import RunMode
from labcourt.contracts.manifests import RunManifest
from labcourt.exceptions import ManifestMismatch

ROOT = Path(__file__).parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "m2"


def _manifest() -> RunManifest:
    return RunManifest.model_validate_json(
        (FIXTURES / "run-manifest-fake.json").read_text(encoding="utf-8")
    )


def test_configured_precedent_policy_verifier_freezes_complete_app_config() -> None:
    config = load_config(ROOT / "configs/demo.yaml")
    verifier = ConfiguredM5PrecedentPolicyVerifier(config)
    expected = m5_precedent_policy_from_config(config)

    object.__setattr__(config.precedents, "conflict_similarity", 0.99)

    assert verifier.run_mode == RunMode.STANDARD
    assert verifier.expected_policy(_manifest()) == expected
    assert verifier.expected_policy(_manifest()).policy_id == expected.policy_id


def test_configured_precedent_policy_verifier_rejects_foreign_manifest_config() -> None:
    verifier = ConfiguredM5PrecedentPolicyVerifier(load_config(ROOT / "configs/demo.yaml"))
    foreign = _manifest().model_copy(update={"config_sha256": "f" * 64})

    with pytest.raises(ManifestMismatch, match="AppConfig"):
        verifier.expected_policy(foreign)

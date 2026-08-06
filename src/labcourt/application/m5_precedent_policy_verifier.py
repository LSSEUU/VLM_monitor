"""Trusted AppConfig-backed policy authority for M5 precedent operations."""

from __future__ import annotations

from pydantic import ValidationError

from labcourt.application.m5_precedents import m5_precedent_policy_from_config
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import RunMode
from labcourt.contracts.m5_precedents import M5PrecedentPolicy
from labcourt.contracts.manifests import RunManifest
from labcourt.exceptions import ContractViolation, ManifestMismatch


class ConfiguredM5PrecedentPolicyVerifier:
    """Keep a canonical config snapshot and derive one immutable M5 policy from it."""

    def __init__(self, config: AppConfig) -> None:
        if not isinstance(config, AppConfig):
            raise TypeError("config must be an AppConfig")
        try:
            trusted = AppConfig.model_validate(config.model_dump(mode="json"))
        except (TypeError, ValidationError, ValueError) as exc:
            raise ContractViolation("trusted M5 precedent config is invalid") from exc
        self._config = trusted
        self._policy = m5_precedent_policy_from_config(trusted)

    @property
    def run_mode(self) -> RunMode:
        return self._config.run.mode

    def expected_policy(self, manifest: RunManifest) -> M5PrecedentPolicy:
        if not isinstance(manifest, RunManifest):
            raise TypeError("manifest must be a RunManifest")
        if (
            manifest.config_sha256 != self._config.config_sha256
            or manifest.rule_version != self._config.rule_version
        ):
            raise ManifestMismatch("trusted M5 precedent AppConfig differs from the run manifest")
        return self._policy


__all__ = ["ConfiguredM5PrecedentPolicyVerifier"]

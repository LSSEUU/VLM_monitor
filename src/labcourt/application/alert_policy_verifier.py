"""Configured deterministic reconstruction of M5 alert-policy authority."""

from __future__ import annotations

from labcourt.contracts.alert_policy import (
    AlertCooldownAuthority,
    AlertPolicyAuthority,
    ImmediateSafetyDeliveryAuthority,
)
from labcourt.contracts.cases import Case
from labcourt.contracts.config import AppConfig
from labcourt.contracts.manifests import RunManifest
from labcourt.domain.alert_policy import plan_case_alert


class AlertPolicyVerificationError(ValueError):
    """The configured verifier is not pinned by the supplied run manifest."""


class ConfiguredAlertPolicyVerifier:
    """Rebuild alert policy using one validated and manifest-pinned AppConfig."""

    def __init__(self, config: AppConfig) -> None:
        if not isinstance(config, AppConfig):
            raise TypeError("config must be an AppConfig")
        self._config = config

    def rebuild(
        self,
        case: Case,
        manifest: RunManifest,
        prior_cooldown: AlertCooldownAuthority | None,
        prior_emergency_delivery: ImmediateSafetyDeliveryAuthority | None,
    ) -> AlertPolicyAuthority:
        if not isinstance(case, Case):
            raise TypeError("case must be a Case")
        if not isinstance(manifest, RunManifest):
            raise TypeError("manifest must be a RunManifest")
        if manifest.config_sha256 != self._config.config_sha256:
            raise AlertPolicyVerificationError(
                "alert policy configuration is not pinned by the run manifest"
            )
        return plan_case_alert(
            case,
            self._config,
            manifest,
            prior_cooldown=prior_cooldown,
            prior_emergency_delivery=prior_emergency_delivery,
        )


__all__ = ["AlertPolicyVerificationError", "ConfiguredAlertPolicyVerifier"]

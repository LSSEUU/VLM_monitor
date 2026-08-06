"""Trusted configured reconstruction of an automatic M5 precedent."""

from __future__ import annotations

from datetime import datetime, timedelta

from labcourt.contracts.alert_policy import AlertPolicyAuthority
from labcourt.contracts.cases import Case
from labcourt.contracts.config import AppConfig
from labcourt.contracts.m5_precedents import M5PrecedentAuthority
from labcourt.contracts.manifests import RunManifest
from labcourt.ports.m5_precedents import M5PrecedentEmbeddingProvider

from .m5_automatic_precedent import build_automatic_precedent_authority


class AutomaticPrecedentVerificationError(ValueError):
    """The proposed automatic precedent cannot be reproducibly rebuilt."""


class ConfiguredAutomaticPrecedentVerifier:
    """Rebuild automatic precedent content from pinned config and an offline fake."""

    def __init__(
        self,
        config: AppConfig,
        embedding_provider: M5PrecedentEmbeddingProvider,
    ) -> None:
        if not isinstance(config, AppConfig):
            raise TypeError("config must be an AppConfig")
        if not callable(getattr(embedding_provider, "embed", None)):
            raise TypeError("embedding_provider must implement embed")
        self._config = config
        self._embedding_provider = embedding_provider

    def rebuild(
        self,
        case: Case,
        manifest: RunManifest,
        alert_authority: AlertPolicyAuthority,
        created_at: datetime,
    ) -> M5PrecedentAuthority:
        if not isinstance(case, Case):
            raise TypeError("case must be a Case")
        if not isinstance(manifest, RunManifest):
            raise TypeError("manifest must be a RunManifest")
        if not isinstance(alert_authority, AlertPolicyAuthority):
            raise TypeError("alert_authority must be an AlertPolicyAuthority")
        if (
            not isinstance(created_at, datetime)
            or created_at.tzinfo is None
            or created_at.utcoffset() != timedelta(0)
        ):
            raise AutomaticPrecedentVerificationError(
                "automatic precedent created_at must be timezone-aware UTC"
            )
        return build_automatic_precedent_authority(
            case=case,
            manifest=manifest,
            alert_authority=alert_authority,
            config=self._config,
            embedding_provider=self._embedding_provider,
            created_at=created_at,
        )


__all__ = [
    "AutomaticPrecedentVerificationError",
    "ConfiguredAutomaticPrecedentVerifier",
]

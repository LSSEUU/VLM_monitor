"""Trusted AppConfig-backed reconstruction of M5 APPLIED authorities."""

from __future__ import annotations

from datetime import datetime

from pydantic import ValidationError

from labcourt.contracts.config import AppConfig
from labcourt.contracts.m5_precedent_usage import (
    M5PrecedentApplicationBatchAuthority,
    M5PrecedentApplicationCitationCommit,
    M5PrecedentExposureBatchAuthority,
)
from labcourt.exceptions import ContractViolation
from labcourt.ports.evidence_repository import CaseSnapshot

from .m5_precedent_usage import (
    build_m5_precedent_application_batch,
    build_m5_precedent_application_citation_commits,
)


class ConfiguredM5PrecedentApplicationVerifier:
    """Keep one canonical config snapshot and rebuild pure APPLIED documents."""

    def __init__(self, config: AppConfig) -> None:
        if not isinstance(config, AppConfig):
            raise TypeError("config must be an AppConfig")
        try:
            self._config = AppConfig.model_validate(config.model_dump(mode="json"))
        except (TypeError, ValidationError, ValueError) as exc:
            raise ContractViolation("trusted M5 precedent application config is invalid") from exc

    def rebuild_application(
        self,
        case_snapshot: CaseSnapshot,
        exposure: M5PrecedentExposureBatchAuthority,
    ) -> M5PrecedentApplicationBatchAuthority:
        return build_m5_precedent_application_batch(
            case_snapshot=case_snapshot,
            exposure=exposure,
            config=self._config,
        )

    def rebuild_citations(
        self,
        application_batch: M5PrecedentApplicationBatchAuthority,
        cited_at: datetime,
    ) -> tuple[M5PrecedentApplicationCitationCommit, ...]:
        return build_m5_precedent_application_citation_commits(
            application_batch=application_batch,
            cited_at=cited_at,
        )


__all__ = ["ConfiguredM5PrecedentApplicationVerifier"]

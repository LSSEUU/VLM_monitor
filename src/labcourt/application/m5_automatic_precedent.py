"""Build the deterministic provisional precedent committed with an M5 close."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from labcourt.contracts.alert_policy import AlertPolicyAuthority
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.cases import Case
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import CaseStatus, PrecedentSource
from labcourt.contracts.m5_precedents import (
    M5EmbeddingChannel,
    M5EmbeddingVector,
    M5PrecedentAuthority,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.ports.m5_precedents import M5PrecedentEmbeddingProvider

from .m5_embedding_integrity import (
    M5_CONTROLLED_FAKE_EMBEDDING_DIMENSIONS,
    M5EmbeddingIntegrityError,
    build_m5_controlled_fake_embedding,
    derive_m5_controlled_fake_embedding,
)
from .m5_precedents import create_m5_precedent_authority, m5_precedent_policy_from_config

DEFAULT_AUTOMATIC_EMBEDDING_DIMENSIONS = M5_CONTROLLED_FAKE_EMBEDDING_DIMENSIONS


class AutomaticPrecedentErrorCode(StrEnum):
    CONFIG_AUTHORITY_MISMATCH = "CONFIG_AUTHORITY_MISMATCH"
    EMBEDDING_PROVIDER_UNSUPPORTED = "EMBEDDING_PROVIDER_UNSUPPORTED"
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SOURCE_AUTHORITY_MISMATCH = "SOURCE_AUTHORITY_MISMATCH"


class AutomaticPrecedentError(RuntimeError):
    def __init__(self, code: AutomaticPrecedentErrorCode) -> None:
        self.code = code
        super().__init__(code.value)


def _situation_projection(case: Case) -> dict[str, object]:
    verdict = case.verdicts[-1]
    return {
        "schema_version": "m5-automatic-precedent-situation-v1",
        "case_id": case.case_id,
        "violation_type": case.event.violation_type.value,
        "evidence_class": case.event.evidence_class.value,
        "rule_version": case.event.rule_version,
        "verdict_id": verdict.verdict_id,
        "verdict_version": verdict.version,
        "verdict_sha256": verdict.verdict_sha256,
        "decision": verdict.decision.value,
        "rationale_summary": verdict.rationale_summary,
        "objective_claims": [claim.model_dump(mode="json") for claim in verdict.objective_claims],
        "observation_sufficiency": (
            verdict.observation_sufficiency.model_dump(mode="json")
            if verdict.observation_sufficiency is not None
            else None
        ),
    }


def _require_automatic_precedent_context(
    *,
    case: Case,
    manifest: RunManifest,
    alert_authority: AlertPolicyAuthority,
    config: AppConfig,
    dimensions: int,
) -> tuple[str, str]:
    if (
        not isinstance(case, Case)
        or not isinstance(manifest, RunManifest)
        or not isinstance(alert_authority, AlertPolicyAuthority)
        or not isinstance(config, AppConfig)
        or isinstance(dimensions, bool)
        or not isinstance(dimensions, int)
        or dimensions != DEFAULT_AUTOMATIC_EMBEDDING_DIMENSIONS
    ):
        raise AutomaticPrecedentError(AutomaticPrecedentErrorCode.INVALID_ARGUMENT)
    if not case.verdicts or case.status != CaseStatus.READY_FOR_ALERT_POLICY:
        raise AutomaticPrecedentError(AutomaticPrecedentErrorCode.SOURCE_AUTHORITY_MISMATCH)
    if config.config_sha256 != manifest.config_sha256:
        raise AutomaticPrecedentError(AutomaticPrecedentErrorCode.CONFIG_AUTHORITY_MISMATCH)
    if manifest.models["text_embedding"].provider != "fake":
        raise AutomaticPrecedentError(AutomaticPrecedentErrorCode.EMBEDDING_PROVIDER_UNSUPPORTED)

    request = alert_authority.request
    verdict = case.verdicts[-1]
    if (
        case.run_id != request.run_id
        or case.case_id != request.case_id
        or case.manifest_id != manifest.manifest_id
        or request.manifest_id != manifest.manifest_id
        or request.config_sha256 != manifest.config_sha256
        or request.verdict_id != verdict.verdict_id
        or request.verdict_version != verdict.version
        or request.verdict_sha256 != verdict.verdict_sha256
        or alert_authority.final_decision != verdict.decision
    ):
        raise AutomaticPrecedentError(AutomaticPrecedentErrorCode.SOURCE_AUTHORITY_MISMATCH)

    situation_text = canonical_json(_situation_projection(case))
    precedent_id = sha256_hex(
        [
            "m5-automatic-precedent",
            1,
            case.run_id,
            case.case_id,
            verdict.verdict_sha256,
        ]
    )
    return situation_text, precedent_id


def _create_automatic_precedent_authority(
    *,
    case: Case,
    config: AppConfig,
    created_at: datetime,
    situation_text: str,
    precedent_id: str,
    text_embedding: M5EmbeddingVector,
) -> M5PrecedentAuthority:
    verdict = case.verdicts[-1]
    return create_m5_precedent_authority(
        run_id=case.run_id,
        precedent_id=precedent_id,
        situation_text=situation_text,
        decision_direction=verdict.decision,
        source=PrecedentSource.AUTOMATIC,
        evidence_class=case.event.evidence_class,
        violation_type=case.event.violation_type,
        rule_version=case.event.rule_version,
        source_case_id=case.case_id,
        created_at=created_at,
        policy=m5_precedent_policy_from_config(config),
        text_embedding=text_embedding,
    )


def build_automatic_precedent_authority(
    *,
    case: Case,
    manifest: RunManifest,
    alert_authority: AlertPolicyAuthority,
    config: AppConfig,
    embedding_provider: M5PrecedentEmbeddingProvider,
    created_at: datetime,
    dimensions: int = DEFAULT_AUTOMATIC_EMBEDDING_DIMENSIONS,
) -> M5PrecedentAuthority:
    """Create the text-backed automatic precedent for one exact READY snapshot."""

    situation_text, precedent_id = _require_automatic_precedent_context(
        case=case,
        manifest=manifest,
        alert_authority=alert_authority,
        config=config,
        dimensions=dimensions,
    )
    try:
        text_embedding = build_m5_controlled_fake_embedding(
            channel=M5EmbeddingChannel.TEXT,
            situation_text=situation_text,
            model_manifest=manifest.models["text_embedding"],
            embedding_provider=embedding_provider,
        )
    except M5EmbeddingIntegrityError as exc:
        raise AutomaticPrecedentError(
            AutomaticPrecedentErrorCode.EMBEDDING_PROVIDER_UNSUPPORTED
        ) from exc
    return _create_automatic_precedent_authority(
        case=case,
        config=config,
        created_at=created_at,
        precedent_id=precedent_id,
        situation_text=situation_text,
        text_embedding=text_embedding,
    )


def derive_automatic_precedent_authority(
    *,
    case: Case,
    manifest: RunManifest,
    alert_authority: AlertPolicyAuthority,
    config: AppConfig,
    created_at: datetime,
    dimensions: int = DEFAULT_AUTOMATIC_EMBEDDING_DIMENSIONS,
) -> M5PrecedentAuthority:
    """Purely rebuild an automatic precedent for readonly verification."""

    situation_text, precedent_id = _require_automatic_precedent_context(
        case=case,
        manifest=manifest,
        alert_authority=alert_authority,
        config=config,
        dimensions=dimensions,
    )
    try:
        text_embedding = derive_m5_controlled_fake_embedding(
            channel=M5EmbeddingChannel.TEXT,
            situation_text=situation_text,
            model_manifest=manifest.models["text_embedding"],
        )
    except M5EmbeddingIntegrityError as exc:
        raise AutomaticPrecedentError(
            AutomaticPrecedentErrorCode.EMBEDDING_PROVIDER_UNSUPPORTED
        ) from exc
    return _create_automatic_precedent_authority(
        case=case,
        config=config,
        created_at=created_at,
        precedent_id=precedent_id,
        situation_text=situation_text,
        text_embedding=text_embedding,
    )


__all__ = [
    "DEFAULT_AUTOMATIC_EMBEDDING_DIMENSIONS",
    "AutomaticPrecedentError",
    "AutomaticPrecedentErrorCode",
    "build_automatic_precedent_authority",
    "derive_automatic_precedent_authority",
]

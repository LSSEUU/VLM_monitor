"""Deterministic offline replacement precedent for a human appeal overturn."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum

from labcourt.application.m5_automatic_precedent import (
    DEFAULT_AUTOMATIC_EMBEDDING_DIMENSIONS,
)
from labcourt.application.m5_embedding_integrity import (
    M5EmbeddingIntegrityError,
    build_m5_controlled_fake_embedding,
)
from labcourt.application.m5_precedents import (
    create_m5_precedent_authority,
    m5_precedent_policy_from_config,
)
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import PrecedentSource, VerdictDecision
from labcourt.contracts.m3_models import require_bounded_public_text
from labcourt.contracts.m5_appeals import ClosedCaseAppealAuthority
from labcourt.contracts.m5_precedents import (
    M5EmbeddingChannel,
    M5PrecedentAuthority,
    M5PrecedentPolicy,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.references import require_reference_token
from labcourt.ports.m5_precedents import M5PrecedentEmbeddingProvider


class AppealPrecedentFailureCode(StrEnum):
    CANONICAL_AUTHORITY_MISMATCH = "CANONICAL_AUTHORITY_MISMATCH"
    CONFIG_AUTHORITY_MISMATCH = "CONFIG_AUTHORITY_MISMATCH"
    DECISION_NOT_OVERTURNED = "DECISION_NOT_OVERTURNED"
    EMBEDDING_PROVIDER_UNSUPPORTED = "EMBEDDING_PROVIDER_UNSUPPORTED"
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    MANIFEST_MISMATCH = "MANIFEST_MISMATCH"


class AppealPrecedentError(RuntimeError):
    def __init__(self, reason_code: AppealPrecedentFailureCode) -> None:
        self.reason_code = reason_code
        super().__init__(f"appeal precedent failed: {reason_code.value}")


def build_appeal_overturn_precedent(
    *,
    case_authority: ClosedCaseAppealAuthority,
    manifest: RunManifest,
    appeal_id: str,
    situation_text: str,
    resolved_decision: VerdictDecision,
    config: AppConfig,
    embedding_provider: M5PrecedentEmbeddingProvider,
    created_at: datetime,
    dimensions: int = DEFAULT_AUTOMATIC_EMBEDDING_DIMENSIONS,
) -> M5PrecedentAuthority:
    """Turn explicit human-authored appeal facts into a fake-embedded active precedent."""

    if (
        not isinstance(case_authority, ClosedCaseAppealAuthority)
        or not isinstance(manifest, RunManifest)
        or not isinstance(resolved_decision, VerdictDecision)
        or not isinstance(config, AppConfig)
        or not isinstance(created_at, datetime)
        or created_at.tzinfo is None
        or created_at.utcoffset() != UTC.utcoffset(created_at)
        or isinstance(dimensions, bool)
        or not isinstance(dimensions, int)
        or dimensions != DEFAULT_AUTOMATIC_EMBEDDING_DIMENSIONS
    ):
        raise AppealPrecedentError(AppealPrecedentFailureCode.INVALID_ARGUMENT)
    try:
        require_reference_token(appeal_id, "appeal precedent appeal_id")
        authored_situation = require_bounded_public_text(
            situation_text,
            "appeal precedent situation",
            max_length=2_048,
        )
    except (TypeError, ValueError) as exc:
        raise AppealPrecedentError(AppealPrecedentFailureCode.INVALID_ARGUMENT) from exc
    if resolved_decision == case_authority.final_decision:
        raise AppealPrecedentError(AppealPrecedentFailureCode.DECISION_NOT_OVERTURNED)
    if (
        case_authority.config_sha256 != manifest.config_sha256
        or config.config_sha256 != manifest.config_sha256
    ):
        raise AppealPrecedentError(AppealPrecedentFailureCode.CONFIG_AUTHORITY_MISMATCH)
    if (
        case_authority.manifest_id != manifest.manifest_id
        or case_authority.rule_version != manifest.rule_version
        or case_authority.detector_manifest_id != manifest.models["detector"].model_manifest_id
        or case_authority.text_embedding_manifest_id
        != manifest.models["text_embedding"].model_manifest_id
        or case_authority.visual_embedding_manifest_id
        != manifest.models["visual_embedding"].model_manifest_id
    ):
        raise AppealPrecedentError(AppealPrecedentFailureCode.MANIFEST_MISMATCH)
    if manifest.models["text_embedding"].provider != "fake":
        raise AppealPrecedentError(AppealPrecedentFailureCode.EMBEDDING_PROVIDER_UNSUPPORTED)

    projection = _appeal_situation_projection(
        case_authority=case_authority,
        appeal_id=appeal_id,
        resolved_decision=resolved_decision,
        authored_situation=authored_situation,
    )
    canonical_situation = canonical_json(projection)
    precedent_id = _appeal_precedent_id(
        case_authority=case_authority,
        appeal_id=appeal_id,
        resolved_decision=resolved_decision,
        canonical_situation=canonical_situation,
    )
    try:
        embedding = build_m5_controlled_fake_embedding(
            channel=M5EmbeddingChannel.TEXT,
            situation_text=canonical_situation,
            model_manifest=manifest.models["text_embedding"],
            embedding_provider=embedding_provider,
        )
    except M5EmbeddingIntegrityError as exc:
        raise AppealPrecedentError(
            AppealPrecedentFailureCode.EMBEDDING_PROVIDER_UNSUPPORTED
        ) from exc
    return create_m5_precedent_authority(
        run_id=case_authority.run_id,
        precedent_id=precedent_id,
        situation_text=canonical_situation,
        decision_direction=resolved_decision,
        source=PrecedentSource.APPEAL_OVERTURN,
        evidence_class=case_authority.evidence_class,
        violation_type=case_authority.violation_type,
        rule_version=case_authority.rule_version,
        source_case_id=case_authority.case_id,
        created_at=created_at,
        policy=m5_precedent_policy_from_config(config),
        text_embedding=embedding,
    )


def _appeal_situation_projection(
    *,
    case_authority: ClosedCaseAppealAuthority,
    appeal_id: str,
    resolved_decision: VerdictDecision,
    authored_situation: str,
) -> dict[str, str]:
    return {
        "schema_version": "m5-appeal-overturn-precedent-situation-v1",
        "appeal_id": appeal_id,
        "case_id": case_authority.case_id,
        "source_case_authority_sha256": case_authority.authority_sha256,
        "source_verdict_sha256": case_authority.verdict_sha256,
        "source_decision": case_authority.final_decision.value,
        "resolved_decision": resolved_decision.value,
        "evidence_class": case_authority.evidence_class.value,
        "violation_type": case_authority.violation_type.value,
        "rule_version": case_authority.rule_version,
        "human_authored_situation": authored_situation,
    }


def _appeal_precedent_id(
    *,
    case_authority: ClosedCaseAppealAuthority,
    appeal_id: str,
    resolved_decision: VerdictDecision,
    canonical_situation: str,
) -> str:
    return sha256_hex(
        [
            "m5-appeal-overturn-precedent",
            1,
            case_authority.run_id,
            case_authority.case_id,
            appeal_id,
            case_authority.authority_sha256,
            resolved_decision,
            hashlib.sha256(canonical_situation.encode("utf-8")).hexdigest(),
        ]
    )


def rebuild_appeal_overturn_precedent_nonpolicy_authority(
    *,
    case_authority: ClosedCaseAppealAuthority,
    appeal_id: str,
    resolved_decision: VerdictDecision,
    proposed: M5PrecedentAuthority,
) -> M5PrecedentAuthority:
    """Rebuild all canonical replacement fields not sourced from configured policy.

    The policy shell below contributes only the already-bound ``config_sha256`` for
    this non-automatic source. Trusted embedding reconstruction remains a manifest
    verifier responsibility at the repository boundary.
    """

    if (
        not isinstance(case_authority, ClosedCaseAppealAuthority)
        or not isinstance(resolved_decision, VerdictDecision)
        or not isinstance(proposed, M5PrecedentAuthority)
    ):
        raise AppealPrecedentError(AppealPrecedentFailureCode.INVALID_ARGUMENT)
    try:
        require_reference_token(appeal_id, "appeal precedent appeal_id")
        decoded = json.loads(proposed.precedent.situation_text)
        if not isinstance(decoded, dict):
            raise ValueError("appeal situation must be a canonical JSON object")
        authored_value = decoded.get("human_authored_situation")
        if not isinstance(authored_value, str):
            raise ValueError("appeal situation must preserve its human-authored text")
        authored = require_bounded_public_text(
            authored_value,
            "appeal precedent situation",
            max_length=2_048,
        )
        expected_projection = _appeal_situation_projection(
            case_authority=case_authority,
            appeal_id=appeal_id,
            resolved_decision=resolved_decision,
            authored_situation=authored,
        )
        canonical_situation = canonical_json(expected_projection)
        if (
            decoded != expected_projection
            or proposed.precedent.situation_text != canonical_situation
        ):
            raise ValueError("appeal situation projection differs from trusted authority")
        precedent_id = _appeal_precedent_id(
            case_authority=case_authority,
            appeal_id=appeal_id,
            resolved_decision=resolved_decision,
            canonical_situation=canonical_situation,
        )
        structural_policy = M5PrecedentPolicy(
            config_sha256=case_authority.config_sha256,
            text_weight=1.0,
            visual_weight=0.0,
            source_weights={source: 1.0 for source in PrecedentSource},
            source_priorities={source: index for index, source in enumerate(PrecedentSource)},
            conflict_similarity=0.0,
            automatic_activation_delay_seconds=0,
        )
        rebuilt = create_m5_precedent_authority(
            run_id=case_authority.run_id,
            precedent_id=precedent_id,
            situation_text=canonical_situation,
            decision_direction=resolved_decision,
            source=PrecedentSource.APPEAL_OVERTURN,
            evidence_class=case_authority.evidence_class,
            violation_type=case_authority.violation_type,
            rule_version=case_authority.rule_version,
            source_case_id=case_authority.case_id,
            created_at=proposed.created_at,
            policy=structural_policy,
            text_embedding=proposed.text_embedding,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise AppealPrecedentError(AppealPrecedentFailureCode.CANONICAL_AUTHORITY_MISMATCH) from exc
    if rebuilt != proposed:
        raise AppealPrecedentError(AppealPrecedentFailureCode.CANONICAL_AUTHORITY_MISMATCH)
    return rebuilt


__all__ = [
    "AppealPrecedentError",
    "AppealPrecedentFailureCode",
    "build_appeal_overturn_precedent",
    "rebuild_appeal_overturn_precedent_nonpolicy_authority",
]

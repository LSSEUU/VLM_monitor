"""Deterministic, objective-only text used by the M4 precedent query."""

from __future__ import annotations

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.evidence import EvidencePack
from labcourt.contracts.hearing_retrieval import (
    MAX_HEARING_PRECEDENT_SITUATION_CHARS,
)
from labcourt.exceptions import ContractViolation


class HearingSituationBuildError(ContractViolation):
    """The current pack cannot produce a bounded precedent-query document."""


def build_hearing_situation_text(pack: EvidencePack) -> str:
    """Serialize only deterministic event and objective-fact authority.

    The text deliberately excludes model summaries, identities, raw paths, and
    pixels.  It is canonical JSON so fixture registration and crash recovery
    derive the same precedent query identity.
    """

    if not isinstance(pack, EvidencePack) or not pack.complete:
        raise HearingSituationBuildError("hearing situation requires a complete EvidencePack")
    event = pack.event
    document = canonical_json(
        {
            "violation_type": event.violation_type.value,
            "evidence_class": event.evidence_class.value,
            "zone_id": event.zone_id,
            "start_frame": event.start_frame,
            "end_frame_exclusive": event.end_frame_exclusive,
            "trigger_frame": event.trigger_frame,
            "hard_rule": event.hard_rule,
            "l1_score": event.l1_score,
            "confirmation": {
                "policy": pack.confirmation_record.policy.value,
                "examined_frame_count": len(pack.confirmation_record.examined_frame_ids),
                "counterevidence_frame_count": len(
                    pack.confirmation_record.counterevidence_frame_ids
                ),
                "resolved_frame": pack.confirmation_record.resolved_frame,
                "causal_risk": pack.confirmation_record.causal_risk,
            },
            "objective_facts": [
                {
                    "kind": fact.kind.value,
                    "value": fact.value,
                    "unit": fact.unit,
                    "source_kind": fact.source_ref.kind.value,
                }
                for fact in pack.objective_facts
            ],
        }
    )
    if not document or len(document) > MAX_HEARING_PRECEDENT_SITUATION_CHARS:
        raise HearingSituationBuildError("hearing situation exceeds its immutable query bound")
    return document


__all__ = [
    "HearingSituationBuildError",
    "build_hearing_situation_text",
]

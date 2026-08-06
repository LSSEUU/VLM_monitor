from labcourt.contracts.enums import AnchorType, EvidenceClass, ViolationType
from labcourt.contracts.registry import VIOLATION_REGISTRY, validate_violation_registry


def test_registry_covers_every_violation_exactly_once() -> None:
    validate_violation_registry()
    assert set(VIOLATION_REGISTRY) == set(ViolationType)


def test_absence_rules_have_anchor_regions() -> None:
    absence = {
        ViolationType.PPE_GOGGLES_MISSING: AnchorType.HEAD,
        ViolationType.PPE_GLOVES_MISSING: AnchorType.HANDS,
        ViolationType.PPE_LAB_COAT_MISSING: AnchorType.TORSO,
    }
    for violation_type, anchor in absence.items():
        definition = VIOLATION_REGISTRY[violation_type]
        assert definition.evidence_class == EvidenceClass.ABSENCE
        assert definition.anchor_type == anchor
        assert definition.required_ppe


def test_every_non_ppe_rule_is_presence() -> None:
    ppe_rules = {
        ViolationType.PPE_GOGGLES_MISSING,
        ViolationType.PPE_GLOVES_MISSING,
        ViolationType.PPE_LAB_COAT_MISSING,
    }
    for violation_type in set(ViolationType) - ppe_rules:
        assert VIOLATION_REGISTRY[violation_type].evidence_class == EvidenceClass.PRESENCE

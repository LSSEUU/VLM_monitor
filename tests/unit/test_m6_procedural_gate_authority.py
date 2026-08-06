from __future__ import annotations

import hashlib

import pytest

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import (
    ArtifactKind,
    ProceduralDefectCode,
    UnknownReferenceNamespace,
    UnknownReferenceSource,
)
from labcourt.contracts.m3_models import (
    EvidenceCitation,
    PrecedentResolution,
    UnknownReferenceAttempt,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.domain.m6_procedural_gate_authority import (
    M6CaseProceduralGateAuthority,
    M6ProceduralGateExecutionInput,
)
from tests.unit.test_procedural_gate import (
    _alert_config,
    _current_closure,
    _gate_config,
    _precedent_resolution,
    _presence_pack,
    _verdict,
)


def _input(
    *,
    unknown: tuple[UnknownReferenceAttempt, ...] = (),
    precedents: tuple[PrecedentResolution, ...] = (),
    foreign_typed_reference: bool = False,
) -> M6ProceduralGateExecutionInput:
    pack = _presence_pack()
    if foreign_typed_reference:
        verdict = _verdict(
            pack,
            citations=(
                EvidenceCitation(
                    evidence_ref=ArtifactRef(
                        kind=ArtifactKind.CROP,
                        artifact_id="f" * 64,
                    )
                ),
            ),
        )
    else:
        verdict = _verdict(pack)
    return M6ProceduralGateExecutionInput(
        source_review_id="source-review",
        source_review_document_sha256="a" * 64,
        verdict=verdict,
        evidence_pack=pack,
        current_closure=_current_closure(pack),
        gate_config=_gate_config(),
        alert_config=_alert_config(),
        review_version=1,
        unknown_reference_attempts=unknown,
        precedent_resolutions=precedents,
    )


def test_rebuild_uses_exact_unknown_reference_inventory_and_multiplicity() -> None:
    attempts = tuple(
        UnknownReferenceAttempt(
            namespace=UnknownReferenceNamespace.EVIDENCE,
            source=UnknownReferenceSource.EVIDENCE_CITATION_REF,
            value_sha256=value,
        )
        for value in ("1" * 64, "2" * 64)
    )

    review = _input(unknown=attempts).rebuild_review()

    fabricated = tuple(
        defect
        for defect in review.defects
        if defect.code == ProceduralDefectCode.FABRICATED_EVIDENCE_REFERENCE
    )
    assert tuple(sorted(item.value_sha256 for item in fabricated)) == (
        "1" * 64,
        "2" * 64,
    )


def test_rebuild_detects_typed_reference_even_without_parser_attempt() -> None:
    review = _input(foreign_typed_reference=True).rebuild_review()

    assert any(
        defect.code == ProceduralDefectCode.FABRICATED_EVIDENCE_REFERENCE
        for defect in review.defects
    )


def test_execution_input_rejects_reordered_unknown_reference_authority() -> None:
    attempts = tuple(
        UnknownReferenceAttempt(
            namespace=UnknownReferenceNamespace.EVIDENCE,
            source=UnknownReferenceSource.EVIDENCE_CITATION_REF,
            value_sha256=value,
        )
        for value in ("2" * 64, "1" * 64)
    )

    with pytest.raises(ValueError, match="unique and ordered"):
        _input(unknown=attempts)


def test_execution_input_rejects_duplicate_precedent_identity() -> None:
    pack = _presence_pack()
    verdict = _verdict(pack)
    first = _precedent_resolution(pack, verdict, similarity=0.8)
    second = _precedent_resolution(pack, verdict, similarity=0.9)

    with pytest.raises(ValueError, match="precedent resolutions must be unique"):
        _input(precedents=(first, second))


def test_case_authority_rejects_per_review_configuration_drift() -> None:
    first = _input()
    second = M6ProceduralGateExecutionInput(
        source_review_id="source-review-2",
        source_review_document_sha256="b" * 64,
        verdict=first.verdict,
        evidence_pack=first.evidence_pack,
        current_closure=first.current_closure,
        gate_config=_gate_config(precedent_min=0.6),
        alert_config=first.alert_config,
        review_version=2,
    )

    with pytest.raises(ValueError, match="one Case-wide configuration"):
        M6CaseProceduralGateAuthority(
            source_identity_sha256="c" * 64,
            run_id=first.verdict.run_id,
            case_id=first.verdict.case_id,
            manifest_id=first.verdict.manifest_id,
            inputs=(first, second),
        )


def test_case_authority_binds_source_review_identity_but_rebuilds_defects() -> None:
    provisional = _input()
    rebuilt = provisional.rebuild_review()
    document_sha256 = hashlib.sha256(
        canonical_json(rebuilt.model_dump(mode="json")).encode("utf-8")
    ).hexdigest()
    exact = M6ProceduralGateExecutionInput(
        source_review_id=rebuilt.review_id,
        source_review_document_sha256=document_sha256,
        verdict=provisional.verdict,
        evidence_pack=provisional.evidence_pack,
        current_closure=provisional.current_closure,
        gate_config=provisional.gate_config,
        alert_config=provisional.alert_config,
        review_version=provisional.review_version,
    )
    authority = M6CaseProceduralGateAuthority(
        source_identity_sha256="b" * 64,
        run_id=rebuilt.run_id,
        case_id=rebuilt.case_id,
        manifest_id=rebuilt.manifest_id,
        inputs=(exact,),
    )

    assert authority.input_for_review(rebuilt).rebuild_review() == rebuilt

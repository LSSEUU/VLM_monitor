from __future__ import annotations

import hashlib
import json

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_regression import M6ReplayExecutionOutcome
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6_UPGRADE_LEDGER_GENESIS_HASH,
    MAX_M6_UPGRADE_LEDGER_DOCUMENT_BYTES,
    M6UpgradeArtifactUsage,
    M6UpgradeCandidateCaseBinding,
    M6UpgradeExecutionComponentAuthority,
    M6UpgradeExecutionLedgerSeal,
    M6UpgradeExecutionScopeAuthority,
    M6UpgradePhysicalArtifactKind,
    M6UpgradeSampleArtifactLink,
    M6UpgradeSampleExecutionRecord,
)
from labcourt.contracts.m6_upgrade_physical import (
    MAX_M6_UPGRADE_PHYSICAL_ARTIFACT_BYTES,
    MAX_M6_UPGRADE_SAMPLE_PHYSICAL_BYTES,
    M6UpgradePhysicalArtifactRef,
    M6UpgradePhysicalArtifactSource,
    M6UpgradePhysicalByteAuthority,
    m6_upgrade_physical_artifact_requires_case,
    m6_upgrade_physical_byte_authority_for,
)
from labcourt.schema_export import expected_schema_files
from tests.contract.test_m6_regression_execution_contracts import _inventory

_BYTE_AUTHORITY_ROUTES = (
    (
        M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
        M6UpgradePhysicalArtifactKind.FRAME,
        M6UpgradePhysicalByteAuthority.LCPIX1,
    ),
    (
        M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
        M6UpgradePhysicalArtifactKind.DETECTION,
        M6UpgradePhysicalByteAuthority.CANONICAL_JSON,
    ),
    (
        M6UpgradePhysicalArtifactSource.M2_EVIDENCE,
        M6UpgradePhysicalArtifactKind.EVIDENCE_PACK,
        M6UpgradePhysicalByteAuthority.CANONICAL_JSON,
    ),
    *(
        (
            source,
            kind,
            (
                M6UpgradePhysicalByteAuthority.CANONICAL_PLUS_RAW
                if kind == M6UpgradePhysicalArtifactKind.MODEL_RESPONSE
                else M6UpgradePhysicalByteAuthority.CANONICAL_JSON
            ),
        )
        for source in (
            M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL,
            M6UpgradePhysicalArtifactSource.M4_HEARING_MODEL,
        )
        for kind in (
            M6UpgradePhysicalArtifactKind.MODEL_REQUEST,
            M6UpgradePhysicalArtifactKind.MODEL_RESPONSE,
            M6UpgradePhysicalArtifactKind.MODEL_CACHE,
            M6UpgradePhysicalArtifactKind.MODEL_PARSE_RECEIPT,
            M6UpgradePhysicalArtifactKind.MODEL_PARSED_OUTPUT,
            M6UpgradePhysicalArtifactKind.MODEL_CALL_FAILURE,
            M6UpgradePhysicalArtifactKind.MODEL_USAGE_RECEIPT,
        )
    ),
    (
        M6UpgradePhysicalArtifactSource.M4_ACQUISITION,
        M6UpgradePhysicalArtifactKind.TOOL_EXECUTION_MANIFEST,
        M6UpgradePhysicalByteAuthority.CANONICAL_JSON,
    ),
    (
        M6UpgradePhysicalArtifactSource.M4_ACQUISITION,
        M6UpgradePhysicalArtifactKind.TOOL_RESULT,
        M6UpgradePhysicalByteAuthority.DERIVED_CANONICAL_JSON,
    ),
    (
        M6UpgradePhysicalArtifactSource.M5_PRECEDENT,
        M6UpgradePhysicalArtifactKind.EMBEDDING,
        M6UpgradePhysicalByteAuthority.CANONICAL_JSON,
    ),
    (
        M6UpgradePhysicalArtifactSource.M5_PRECEDENT,
        M6UpgradePhysicalArtifactKind.PRECEDENT_EXPOSURE,
        M6UpgradePhysicalByteAuthority.CANONICAL_JSON,
    ),
)
_CANONICAL_BYTE_AUTHORITIES = frozenset(
    {
        M6UpgradePhysicalByteAuthority.CANONICAL_JSON,
        M6UpgradePhysicalByteAuthority.DERIVED_CANONICAL_JSON,
    }
)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _ledger() -> M6UpgradeExecutionLedgerSeal:
    return _inventory().execution_ledger


def _rechain(
    seal: M6UpgradeExecutionLedgerSeal,
    replacements: dict[int, M6UpgradeSampleExecutionRecord],
) -> tuple[M6UpgradeSampleExecutionRecord, ...]:
    records: list[M6UpgradeSampleExecutionRecord] = []
    previous = M6_UPGRADE_LEDGER_GENESIS_HASH
    for index, original in enumerate(seal.sample_executions):
        candidate = replacements.get(index, original)
        record = candidate.model_copy(
            update={
                "ledger_sequence": index,
                "previous_ledger_entry_hash": previous,
            }
        )
        records.append(record)
        previous = record.sample_execution_record_id
    return tuple(records)


def test_upgrade_execution_ledger_is_complete_blind_and_round_trips() -> None:
    seal = _ledger()
    assert seal.sample_execution_count == len(seal.execution_dataset.entries) == 3
    assert seal.artifact_link_count > seal.sample_execution_count
    assert seal.candidate_case_count == 2
    assert seal.ledger_preseal_hash == seal.sample_executions[-1].sample_execution_record_id
    assert seal.ledger_head_sequence == seal.sample_execution_count

    payload = seal.model_dump(mode="json")
    assert M6UpgradeExecutionLedgerSeal.model_validate(payload) == seal
    serialized = canonical_json(payload)
    for forbidden in (
        "memberships",
        "gold_truth",
        "expected_decision",
        "baseline_snapshot",
    ):
        assert forbidden not in serialized


def test_upgrade_execution_ledger_rejects_missing_swapped_and_grafted_records() -> None:
    seal = _ledger()
    with pytest.raises(ValidationError, match="cover every blinded execution entry"):
        seal.model_copy(update={"sample_executions": seal.sample_executions[:-1]})

    first, second = seal.sample_executions[:2]
    swapped = _rechain(
        seal,
        {
            0: first.model_copy(update={"execution_entry": second.execution_entry}),
            1: second.model_copy(update={"execution_entry": first.execution_entry}),
        },
    )
    with pytest.raises(ValidationError, match="chain or execution scope differs"):
        seal.model_copy(update={"sample_executions": swapped})

    with pytest.raises(ValidationError, match="genesis binding is invalid"):
        seal.sample_executions[1].model_copy(
            update={"previous_ledger_entry_hash": M6_UPGRADE_LEDGER_GENESIS_HASH}
        )

    with pytest.raises(ValidationError, match="source audit head is invalid"):
        seal.model_copy(
            update={
                "source_audit_head_sequence": -1,
                "source_audit_head_hash": _sha("not-genesis"),
            }
        )

    with pytest.raises(ValidationError, match="offline start cut"):
        seal.execution_scope.model_copy(update={"command_content_sha256": _sha("forged-command")})
    with pytest.raises(ValidationError, match="offline start cut"):
        seal.execution_scope.model_copy(
            update={"execution_dataset_content_sha256": _sha("forged-dataset")}
        )
    with pytest.raises(ValidationError, match="offline start cut"):
        seal.execution_scope.model_copy(
            update={"execution_component_content_sha256": _sha("forged-component")}
        )
    with pytest.raises(ValidationError, match="fresh audit genesis"):
        seal.execution_scope.model_copy(
            update={
                "execution_start_audit_head_sequence": 0,
                "execution_start_audit_head_hash": _sha("preexisting-audit-head"),
            }
        )
    with pytest.raises(ValidationError, match="scope physical content differs"):
        seal.model_copy(update={"execution_scope_content_sha256": _sha("forged-scope")})


def test_upgrade_execution_record_enforces_outcome_case_and_artifact_matrix() -> None:
    seal = _ledger()
    case_record = next(
        item
        for item in seal.sample_executions
        if item.outcome == M6ReplayExecutionOutcome.CASE_REPLAYED
    )
    no_case_record = next(
        item for item in seal.sample_executions if item.outcome == M6ReplayExecutionOutcome.NO_CASE
    )
    assert case_record.candidate_case is not None

    with pytest.raises(ValidationError, match="outcome and Case binding differ"):
        case_record.model_copy(update={"candidate_case": None})
    with pytest.raises(ValidationError, match="outcome and Case binding differ"):
        no_case_record.model_copy(update={"candidate_case": case_record.candidate_case})

    case_scoped = next(
        item
        for item in case_record.artifact_links
        if m6_upgrade_physical_artifact_requires_case(item.artifact.kind)
    )
    grafted_artifacts = tuple(
        sorted(
            (
                *(item.artifact for item in no_case_record.artifact_links),
                case_scoped.artifact,
            ),
            key=lambda item: item.physical_key,
        )
    )
    grafted_links = tuple(
        M6UpgradeSampleArtifactLink(
            ordinal=ordinal,
            usage=(
                case_scoped.usage
                if artifact.artifact_ref_id == case_scoped.artifact.artifact_ref_id
                else next(
                    item.usage
                    for item in no_case_record.artifact_links
                    if item.artifact.artifact_ref_id == artifact.artifact_ref_id
                )
            ),
            artifact=artifact,
        )
        for ordinal, artifact in enumerate(grafted_artifacts)
    )
    with pytest.raises(ValidationError, match="no-Case sample cannot claim case-scoped"):
        no_case_record.model_copy(update={"artifact_links": grafted_links})

    detection_link = next(
        item
        for item in case_record.artifact_links
        if item.artifact.kind == M6UpgradePhysicalArtifactKind.DETECTION
    )
    detection_only = M6UpgradeSampleArtifactLink(
        ordinal=0,
        usage=detection_link.usage,
        artifact=detection_link.artifact,
    )
    with pytest.raises(ValidationError, match="requires a physical Frame"):
        case_record.model_copy(update={"artifact_links": (detection_only,)})

    frame = case_record.artifact_links[0]
    assert frame.artifact.kind == M6UpgradePhysicalArtifactKind.FRAME
    with pytest.raises(ValidationError, match="must be recorded as consumed"):
        frame.model_copy(update={"usage": M6UpgradeArtifactUsage.PRODUCED})

    duplicate = frame.model_copy(update={"ordinal": 1})
    with pytest.raises(ValidationError, match="physical artifact links must be unique"):
        case_record.model_copy(update={"artifact_links": (frame, duplicate)})

    detection = detection_only.model_copy(update={"ordinal": 0})
    reordered_frame = frame.model_copy(update={"ordinal": 1})
    with pytest.raises(ValidationError, match="stable order"):
        case_record.model_copy(update={"artifact_links": (detection, reordered_frame)})

    foreign_detection = detection_link.model_copy(
        update={
            "artifact": detection_link.artifact.model_copy(
                update={"container_id": "foreign-camera:stream:0"}
            )
        }
    )
    foreign_links = tuple(
        foreign_detection if item.ordinal == detection_link.ordinal else item
        for item in case_record.artifact_links
    )
    with pytest.raises(ValidationError, match="Frame in the same sample"):
        case_record.model_copy(update={"artifact_links": foreign_links})


def test_upgrade_execution_ledger_allows_shared_physical_artifact_across_samples() -> None:
    seal = _ledger()
    first, second = seal.sample_executions[:2]
    shared_frame = second.artifact_links[0].model_copy(
        update={"artifact": first.artifact_links[0].artifact}
    )
    shared_container = shared_frame.artifact.artifact_id
    rebound_links = tuple(
        link.model_copy(
            update={"artifact": link.artifact.model_copy(update={"container_id": shared_container})}
        )
        if link.artifact.kind == M6UpgradePhysicalArtifactKind.DETECTION
        else link
        for link in second.artifact_links[1:]
    )
    shared_second = second.model_copy(update={"artifact_links": (shared_frame, *rebound_links)})
    records = _rechain(seal, {1: shared_second})
    shared_seal = seal.model_copy(update={"sample_executions": records})

    assert shared_seal.sample_execution_count == seal.sample_execution_count
    assert shared_seal.artifact_link_count == seal.artifact_link_count
    assert (
        shared_seal.sample_executions[0].artifact_links[0].artifact.artifact_ref_id
        == shared_seal.sample_executions[1].artifact_links[0].artifact.artifact_ref_id
    )

    conflicting_artifact = first.artifact_links[0].artifact.model_copy(
        update={"content_sha256": _sha("conflicting-frame-bytes")}
    )
    conflicting_frame = shared_frame.model_copy(update={"artifact": conflicting_artifact})
    conflicting_second = second.model_copy(
        update={"artifact_links": (conflicting_frame, *rebound_links)}
    )
    conflicting_records = _rechain(seal, {1: conflicting_second})
    with pytest.raises(ValidationError, match="identity conflicts across samples"):
        seal.model_copy(update={"sample_executions": conflicting_records})


def test_upgrade_execution_ledger_rejects_duplicate_current_cases() -> None:
    seal = _ledger()
    case_indexes = [
        index
        for index, item in enumerate(seal.sample_executions)
        if item.candidate_case is not None
    ]
    first_index, second_index = case_indexes
    first = seal.sample_executions[first_index]
    second = seal.sample_executions[second_index]
    assert first.candidate_case is not None
    duplicated = second.model_copy(update={"candidate_case": first.candidate_case})
    records = _rechain(seal, {second_index: duplicated})
    with pytest.raises(ValidationError, match="current Case bindings must be unique"):
        seal.model_copy(update={"sample_executions": records})

    first_case = first.candidate_case
    assert first_case is not None
    future_case = first.model_copy(
        update={
            "candidate_case": first_case.model_copy(
                update={"case_audit_sequence": seal.source_audit_head_sequence + 1}
            )
        }
    )
    future_records = _rechain(seal, {first_index: future_case})
    with pytest.raises(ValidationError, match="beyond its candidate audit head"):
        seal.model_copy(update={"sample_executions": future_records})


def test_upgrade_physical_ref_requires_real_frame_id_and_static_source_route() -> None:
    frame = _ledger().sample_executions[0].artifact_links[0].artifact
    assert frame.kind == M6UpgradePhysicalArtifactKind.FRAME
    assert frame.artifact_id.count(":") == 2

    with pytest.raises(ValidationError, match="frame_id"):
        frame.model_copy(update={"artifact_id": "not-a-frame-id"})
    with pytest.raises(ValidationError, match="no resolver for its source"):
        frame.model_copy(update={"source": M6UpgradePhysicalArtifactSource.M4_HEARING_MODEL})
    with pytest.raises(ValidationError, match="cannot claim a container"):
        frame.model_copy(update={"container_id": "camera-sample:stream:0"})

    detection = next(
        item.artifact
        for item in _ledger().sample_executions[0].artifact_links
        if item.artifact.kind == M6UpgradePhysicalArtifactKind.DETECTION
    )
    with pytest.raises(ValidationError, match="requires its containing frame_id"):
        detection.model_copy(update={"container_id": None})
    with pytest.raises(ValidationError, match="frame_id"):
        detection.model_copy(update={"container_id": "not-a-frame-id"})
    with pytest.raises(ValidationError, match="less than or equal"):
        frame.model_copy(update={"size_bytes": MAX_M6_UPGRADE_PHYSICAL_ARTIFACT_BYTES + 1})

    with pytest.raises(ValidationError, match="less than or equal"):
        _ledger().execution_scope.model_copy(
            update={"command_size_bytes": MAX_M6_UPGRADE_LEDGER_DOCUMENT_BYTES + 1}
        )


def test_legacy_upgrade_sample_v1_preserves_pre_budget_semantics() -> None:
    record = _ledger().sample_executions[0]
    frame_link = next(
        item
        for item in record.artifact_links
        if item.artifact.kind == M6UpgradePhysicalArtifactKind.FRAME
    )
    oversized_frame = frame_link.artifact.model_copy(
        update={"size_bytes": MAX_M6_UPGRADE_SAMPLE_PHYSICAL_BYTES + 1}
    )
    links = tuple(
        item.model_copy(update={"artifact": oversized_frame})
        if item.artifact.artifact_ref_id == frame_link.artifact.artifact_ref_id
        else item
        for item in record.artifact_links
    )

    legacy = record.model_copy(update={"artifact_links": links})
    assert legacy.schema_version == "m6-upgrade-sample-execution-record-v1"


@pytest.mark.parametrize(("source", "kind", "expected"), _BYTE_AUTHORITY_ROUTES)
def test_upgrade_physical_byte_authority_covers_all_21_legal_routes(
    source: M6UpgradePhysicalArtifactSource,
    kind: M6UpgradePhysicalArtifactKind,
    expected: M6UpgradePhysicalByteAuthority,
) -> None:
    assert len(_BYTE_AUTHORITY_ROUTES) == 21
    assert len({(item[0], item[1]) for item in _BYTE_AUTHORITY_ROUTES}) == 21
    assert m6_upgrade_physical_byte_authority_for(source, kind) == expected


def test_upgrade_physical_byte_authority_rejects_every_unrouted_pair() -> None:
    routed = {(source, kind) for source, kind, _authority in _BYTE_AUTHORITY_ROUTES}
    rejected = {
        (source, kind)
        for source in M6UpgradePhysicalArtifactSource
        for kind in M6UpgradePhysicalArtifactKind
        if (source, kind) not in routed
    }
    assert len(rejected) == 63
    for source, kind in rejected:
        with pytest.raises(ValueError, match="no resolver for its source"):
            m6_upgrade_physical_byte_authority_for(source, kind)


def test_upgrade_physical_case_scope_policy_exhausts_every_artifact_kind() -> None:
    non_case_scoped = {
        kind
        for kind in M6UpgradePhysicalArtifactKind
        if not m6_upgrade_physical_artifact_requires_case(kind)
    }
    assert non_case_scoped == {
        M6UpgradePhysicalArtifactKind.FRAME,
        M6UpgradePhysicalArtifactKind.DETECTION,
    }
    assert all(
        m6_upgrade_physical_artifact_requires_case(kind)
        for kind in M6UpgradePhysicalArtifactKind
        if kind not in non_case_scoped
    )


@pytest.mark.parametrize(
    ("source", "kind", "byte_authority"),
    tuple(
        route
        for route in _BYTE_AUTHORITY_ROUTES
        if route[1] != M6UpgradePhysicalArtifactKind.DETECTION
    ),
)
def test_only_detection_can_graft_a_container(
    source: M6UpgradePhysicalArtifactSource,
    kind: M6UpgradePhysicalArtifactKind,
    byte_authority: M6UpgradePhysicalByteAuthority,
) -> None:
    document_sha256 = _sha(f"document:{source.value}:{kind.value}")
    content_sha256 = (
        document_sha256
        if byte_authority in _CANONICAL_BYTE_AUTHORITIES
        else _sha(f"content:{source.value}:{kind.value}")
    )
    artifact_id = (
        "camera-route:stream:0"
        if kind == M6UpgradePhysicalArtifactKind.FRAME
        else f"artifact-{source.value.lower()}-{kind.value.lower()}"
    )
    with pytest.raises(ValidationError, match="cannot claim a container"):
        M6UpgradePhysicalArtifactRef(
            source=source,
            kind=kind,
            artifact_id=artifact_id,
            container_id="camera-graft:stream:0",
            document_sha256=document_sha256,
            content_sha256=content_sha256,
            size_bytes=1,
        )


@pytest.mark.parametrize(
    ("source", "kind", "byte_authority"),
    tuple(route for route in _BYTE_AUTHORITY_ROUTES if route[2] in _CANONICAL_BYTE_AUTHORITIES),
)
def test_canonical_byte_authorities_reject_distinct_content_hashes(
    source: M6UpgradePhysicalArtifactSource,
    kind: M6UpgradePhysicalArtifactKind,
    byte_authority: M6UpgradePhysicalByteAuthority,
) -> None:
    assert byte_authority in _CANONICAL_BYTE_AUTHORITIES
    with pytest.raises(ValidationError, match="content_sha256 must equal document_sha256"):
        M6UpgradePhysicalArtifactRef(
            source=source,
            kind=kind,
            artifact_id=f"artifact-{source.value.lower()}-{kind.value.lower()}",
            container_id=(
                "camera-authority:stream:0"
                if kind == M6UpgradePhysicalArtifactKind.DETECTION
                else None
            ),
            document_sha256=_sha(f"document:{source.value}:{kind.value}"),
            content_sha256=_sha(f"content:{source.value}:{kind.value}"),
            size_bytes=1,
        )


@pytest.mark.parametrize(
    ("source", "kind", "byte_authority"),
    tuple(route for route in _BYTE_AUTHORITY_ROUTES if route[2] not in _CANONICAL_BYTE_AUTHORITIES),
)
def test_raw_and_lcpix1_byte_authorities_allow_distinct_content_hashes(
    source: M6UpgradePhysicalArtifactSource,
    kind: M6UpgradePhysicalArtifactKind,
    byte_authority: M6UpgradePhysicalByteAuthority,
) -> None:
    assert byte_authority in {
        M6UpgradePhysicalByteAuthority.CANONICAL_PLUS_RAW,
        M6UpgradePhysicalByteAuthority.LCPIX1,
    }
    artifact = M6UpgradePhysicalArtifactRef(
        source=source,
        kind=kind,
        artifact_id=(
            "camera-route:stream:0"
            if kind == M6UpgradePhysicalArtifactKind.FRAME
            else f"artifact-{source.value.lower()}-{kind.value.lower()}"
        ),
        document_sha256=_sha(f"document:{source.value}:{kind.value}"),
        content_sha256=_sha(f"content:{source.value}:{kind.value}"),
        size_bytes=1,
    )
    assert artifact.content_sha256 != artifact.document_sha256


def test_upgrade_execution_ledger_computed_claims_and_schemas_reject_tampering() -> None:
    seal = _ledger()
    payload = seal.model_dump(mode="json")
    payload["ledger_seal_authority_id"] = _sha("forged-seal")
    with pytest.raises(ValidationError, match="ledger_seal_authority_id"):
        M6UpgradeExecutionLedgerSeal.model_validate(payload)

    record_payload = seal.sample_executions[0].model_dump(mode="json")
    record_payload["sample_execution_record_id"] = _sha("forged-record")
    with pytest.raises(ValidationError, match="sample_execution_record_id"):
        M6UpgradeSampleExecutionRecord.model_validate(record_payload)

    case_record = next(item for item in seal.sample_executions if item.candidate_case is not None)
    assert case_record.candidate_case is not None
    case_payload = case_record.candidate_case.model_dump(mode="json")
    case_payload["case_binding_id"] = _sha("forged-case-binding")
    with pytest.raises(ValidationError, match="case_binding_id"):
        M6UpgradeCandidateCaseBinding.model_validate(case_payload)

    component_payload = seal.execution_component.model_dump(mode="json")
    component_payload["component_authority_id"] = _sha("forged-component")
    with pytest.raises(ValidationError, match="component_authority_id"):
        M6UpgradeExecutionComponentAuthority.model_validate(component_payload)

    artifact_payload = seal.sample_executions[0].artifact_links[0].artifact.model_dump(mode="json")
    artifact_payload["artifact_ref_id"] = _sha("forged-artifact")
    with pytest.raises(ValidationError, match="artifact_ref_id"):
        M6UpgradePhysicalArtifactRef.model_validate(artifact_payload)

    scope_payload = seal.execution_scope.model_dump(mode="json")
    scope_payload["execution_scope_authority_id"] = _sha("forged-scope")
    with pytest.raises(ValidationError, match="execution_scope_authority_id"):
        M6UpgradeExecutionScopeAuthority.model_validate(scope_payload)

    artifacts = {
        "m6-upgrade-execution-component-authority": seal.execution_component,
        "m6-upgrade-execution-scope-authority": seal.execution_scope,
        "m6-upgrade-physical-artifact-ref": seal.sample_executions[0].artifact_links[0].artifact,
        "m6-upgrade-sample-execution-record": seal.sample_executions[0],
        "m6-upgrade-execution-ledger-seal": seal,
    }
    schemas = expected_schema_files()
    for name, artifact in artifacts.items():
        schema = json.loads(schemas[f"{name}.schema.json"])
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(artifact.model_dump(mode="json"))

from __future__ import annotations

import pytest
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ValidationError

from labcourt.application.m8_projection_view_workflow import build_operations_projection_view
from labcourt.contracts.m8_access_cases import (
    M8ActorAuthorityV1,
    M8ActorRole,
    M8ActorScopeKind,
    M8AuthorityReference,
    M8AuthorityReferenceKind,
    M8OperationalCaseCreateCommandV1,
    M8OperationalCaseStatus,
    M8OperationalRiskLevel,
)
from labcourt.contracts.m8_case_persistence import (
    M8_AUDIT_GENESIS_SHA256,
    M8ActorAuthorityCommitReceiptV1,
    M8OperationalCaseAuditEventV1,
    M8OperationalCaseAuthorityV1,
    M8OperationalCaseCommitReceiptV1,
)
from labcourt.contracts.m8_inventory_persistence import (
    M8CampusTopologyCommitReceiptV1,
    M8OperationalSourceCatalogCommitReceiptV1,
)
from labcourt.contracts.m8_operations import (
    M8CampusLocation,
    M8CampusLocationKind,
    M8CampusTopologyAuthorityV1,
    M8OperationalSource,
    M8OperationalSourceCatalogAuthorityV1,
    M8OperationalSourceMode,
    M8SensorType,
)
from labcourt.contracts.m8_projection_views import (
    M8OperationsProjectionViewV1,
    M8ProjectionViewKind,
)
from labcourt.contracts.m8_projections import (
    M8OperationsProjectionV1,
    M8ProjectionMapNodeV1,
    M8ProjectionOverviewV1,
    M8ProjectionSourceObservationState,
    M8ProjectionSourceV1,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64


def _topology() -> M8CampusTopologyAuthorityV1:
    return M8CampusTopologyAuthorityV1(
        revision=1,
        locations=(
            M8CampusLocation(
                location_id="campus-main",
                kind=M8CampusLocationKind.CAMPUS,
                parent_location_id=None,
                display_name="主校区",
            ),
            M8CampusLocation(
                location_id="building-chem",
                kind=M8CampusLocationKind.BUILDING,
                parent_location_id="campus-main",
                display_name="化学楼",
            ),
            M8CampusLocation(
                location_id="floor-chem-03",
                kind=M8CampusLocationKind.FLOOR,
                parent_location_id="building-chem",
                display_name="三层",
            ),
            M8CampusLocation(
                location_id="room-chem-301",
                kind=M8CampusLocationKind.ROOM,
                parent_location_id="floor-chem-03",
                display_name="实验室 301",
            ),
        ),
        manifest_id=SHA_A,
    )


def _source() -> M8OperationalSource:
    return M8OperationalSource(
        source_id="sensor-simulated-smoke-01",
        device_id="sensor-smoke-01",
        location_id="room-chem-301",
        mode=M8OperationalSourceMode.SIMULATED_SENSOR,
        sensor_type=M8SensorType.SMOKE,
        adapter_id="m8-offline-sensor-simulator",
        manifest_id=SHA_B,
    )


def _inventory() -> tuple[
    M8CampusTopologyCommitReceiptV1,
    M8OperationalSourceCatalogCommitReceiptV1,
]:
    topology_receipt = M8CampusTopologyCommitReceiptV1(
        topology=_topology(),
        repository_manifest_id=SHA_C,
    )
    catalog = M8OperationalSourceCatalogAuthorityV1(
        revision=1,
        topology=topology_receipt.topology,
        sources=(_source(),),
        catalog_manifest_id=SHA_D,
    )
    catalog_receipt = M8OperationalSourceCatalogCommitReceiptV1(
        catalog=catalog,
        resolved_topology_commit_receipt_id=topology_receipt.commit_receipt_id,
        repository_manifest_id=SHA_C,
    )
    return topology_receipt, catalog_receipt


def _case(
    catalog_id: str,
    *,
    source_id: str = "sensor-simulated-smoke-01",
    risk_level: M8OperationalRiskLevel = M8OperationalRiskLevel.EMERGENCY,
) -> M8OperationalCaseCommitReceiptV1:
    command = M8OperationalCaseCreateCommandV1(
        source_catalog_id=catalog_id,
        location_id="room-chem-301",
        risk_level=risk_level,
        policy_rule_id="simulated-smoke-active-emergency-v1",
        policy_manifest_id=SHA_A,
        source_ids=(source_id,),
        simulated_source_ids=(source_id,),
        trigger_authorities=(
            M8AuthorityReference(
                kind=M8AuthorityReferenceKind.SENSOR_SIGNAL,
                authority_id="simulated-smoke-sample-01",
                document_sha256=SHA_B,
            ),
        ),
        automation_component_id="m8-offline-case-builder",
        automation_manifest_id=SHA_D,
    )
    authority = M8OperationalCaseAuthorityV1(
        create_command=command,
        case_version=1,
        status=M8OperationalCaseStatus.PENDING_VERIFICATION,
        subject_actor_id="student-01",
        case_manifest_id=SHA_D,
    )
    event = M8OperationalCaseAuditEventV1(
        case_authority=authority,
        event_sequence=1,
        create_command_id=command.create_command_id,
        prior_audit_event_sha256=M8_AUDIT_GENESIS_SHA256,
        audit_manifest_id=SHA_E,
    )
    return M8OperationalCaseCommitReceiptV1(
        audit_event=event,
        repository_manifest_id=SHA_C,
    )


def _projection(*, include_case: bool = True) -> M8OperationsProjectionV1:
    topology, catalog = _inventory()
    cases = (_case(catalog.catalog.catalog_id),) if include_case else ()
    return M8OperationsProjectionV1(
        topology_receipt=topology,
        source_catalog_receipt=catalog,
        sources=(M8ProjectionSourceV1(source=catalog.catalog.sources[0]),),
        current_cases=cases,
        case_audit_events=tuple(item.audit_event for item in cases),
        current_notifications=(),
        notification_audit_events=(),
        projection_manifest_id=SHA_E,
    )


def _actor_receipt(role: M8ActorRole) -> M8ActorAuthorityCommitReceiptV1:
    if role == M8ActorRole.STUDENT:
        scope = M8ActorScopeKind.SELF_ONLY
        locations: tuple[str, ...] = ()
    elif role == M8ActorRole.SAFETY_OFFICER:
        scope = M8ActorScopeKind.LOCATIONS
        locations = ("room-chem-301",)
    else:
        scope = M8ActorScopeKind.CAMPUS_WIDE
        locations = ()
    actor = M8ActorAuthorityV1(
        actor_id=f"{role.value.lower()}-01",
        role=role,
        scope_kind=scope,
        scope_location_ids=locations,
        identity_provider_id="campus-idp",
        subject_binding_sha256=SHA_A,
        authority_revision=1,
        active=True,
        manifest_id=SHA_B,
    )
    return M8ActorAuthorityCommitReceiptV1(
        authority=actor,
        repository_manifest_id=SHA_C,
    )


def test_projection_derives_truthful_overview_map_and_source_state() -> None:
    projection = _projection()
    source = projection.sources[0]
    assert source.observation_state == M8ProjectionSourceObservationState.NO_PERSISTED_SAMPLE
    assert source.display_badge == "SIMULATED · SENSOR"
    assert source.simulated is True
    assert source.live_observation_confirmed is False
    assert source.certified_fire_detection_claim_permitted is False
    assert projection.overview.current_case_count == 1
    assert projection.overview.pending_verification_case_count == 1
    assert projection.overview.active_major_case_count == 1
    assert projection.map_nodes[0].source_ids == (source.source.source_id,)
    assert projection.map_nodes[0].current_case_ids == (projection.current_cases[0].case_id,)
    assert projection.read_only is True
    assert projection.case_transition_permitted is False
    assert projection.direct_disciplinary_action_permitted is False


def test_projection_rejects_incomplete_audit_and_cross_catalog_cases() -> None:
    projection = _projection()
    with pytest.raises(ValidationError, match="audit does not close"):
        projection.model_copy(update={"case_audit_events": ()})

    invalid_case = _case(SHA_A, source_id="removed-sensor-01")
    with pytest.raises(ValidationError, match="outside the topology or source catalog"):
        projection.model_copy(
            update={
                "current_cases": (invalid_case,),
                "case_audit_events": (invalid_case.audit_event,),
            }
        )


def test_projection_view_enforces_closed_role_scope_and_read_only_flags() -> None:
    projection = _projection()
    leader = M8OperationsProjectionViewV1(
        viewer_actor_receipt=_actor_receipt(M8ActorRole.LEADER),
        source_projection_id=projection.projection_id,
        visible_projection=projection,
    )
    assert leader.view_kind == M8ProjectionViewKind.LEADER_GLOBAL_MAJOR
    assert leader.projection_write_permitted is False
    assert leader.case_action_permitted is False
    assert leader.direct_disciplinary_action_permitted is False

    operations_projection = _projection(include_case=False)
    operations = M8OperationsProjectionViewV1(
        viewer_actor_receipt=_actor_receipt(M8ActorRole.OPERATIONS),
        source_projection_id=projection.projection_id,
        visible_projection=operations_projection,
    )
    assert operations.view_kind == M8ProjectionViewKind.OPERATIONS_DEVICES

    with pytest.raises(ValidationError, match="students cannot access"):
        M8OperationsProjectionViewV1(
            viewer_actor_receipt=_actor_receipt(M8ActorRole.STUDENT),
            source_projection_id=projection.projection_id,
            visible_projection=projection,
        )


def test_projection_view_rejects_leader_general_case_and_operations_case_graft() -> None:
    projection = _projection()
    general = _case(
        projection.source_catalog_receipt.catalog.catalog_id,
        risk_level=M8OperationalRiskLevel.GENERAL,
    )
    general_projection = projection.model_copy(
        update={
            "current_cases": (general,),
            "case_audit_events": (general.audit_event,),
        }
    )
    with pytest.raises(ValidationError, match="only major Cases"):
        M8OperationsProjectionViewV1(
            viewer_actor_receipt=_actor_receipt(M8ActorRole.LEADER),
            source_projection_id=projection.projection_id,
            visible_projection=general_projection,
        )
    with pytest.raises(ValidationError, match="cannot expose Case"):
        M8OperationsProjectionViewV1(
            viewer_actor_receipt=_actor_receipt(M8ActorRole.OPERATIONS),
            source_projection_id=projection.projection_id,
            visible_projection=projection,
        )


def test_projection_view_rejects_serialized_authority_forgery() -> None:
    projection = _projection()
    view = M8OperationsProjectionViewV1(
        viewer_actor_receipt=_actor_receipt(M8ActorRole.SAFETY_OFFICER),
        source_projection_id=projection.projection_id,
        visible_projection=projection,
    )
    payload = view.model_dump(mode="json")
    payload["view_id"] = "0" * 64
    with pytest.raises(ValidationError, match="view_id"):
        M8OperationsProjectionViewV1.model_validate(payload)


def test_projection_view_builder_filters_cases_without_mutating_source_cut() -> None:
    projection = _projection()
    emergency = projection.current_cases[0]
    general = _case(
        projection.source_catalog_receipt.catalog.catalog_id,
        risk_level=M8OperationalRiskLevel.GENERAL,
    )
    mixed = projection.model_copy(
        update={
            "current_cases": tuple(sorted((emergency, general), key=lambda item: item.case_id)),
            "case_audit_events": tuple(
                sorted(
                    (emergency.audit_event, general.audit_event),
                    key=lambda item: (item.case_authority.case_id, item.event_sequence),
                )
            ),
        }
    )

    safety = build_operations_projection_view(
        mixed,
        _actor_receipt(M8ActorRole.SAFETY_OFFICER),
    )
    leader = build_operations_projection_view(mixed, _actor_receipt(M8ActorRole.LEADER))
    operations = build_operations_projection_view(mixed, _actor_receipt(M8ActorRole.OPERATIONS))

    assert safety.visible_projection == mixed
    assert leader.visible_projection.current_cases == (emergency,)
    assert leader.visible_projection.case_audit_events == (emergency.audit_event,)
    assert operations.visible_projection.current_cases == ()
    assert operations.visible_projection.case_audit_events == ()
    assert mixed.current_cases == tuple(sorted((emergency, general), key=lambda item: item.case_id))


@pytest.mark.parametrize(
    "field",
    (
        "overview",
        "map_nodes",
        "source_projection_inventory_sha256",
        "read_only",
        "case_transition_permitted",
        "projection_id",
    ),
)
def test_projection_rejects_serialized_computed_forgery(field: str) -> None:
    projection = _projection(include_case=False)
    payload = projection.model_dump(mode="json")
    payload[field] = False if field == "read_only" else "0" * 64
    with pytest.raises(ValidationError, match=field):
        M8OperationsProjectionV1.model_validate(payload)


@pytest.mark.parametrize(
    "model",
    (
        _projection(),
        _projection().sources[0],
        _projection().overview,
        _projection().map_nodes[0],
        M8OperationsProjectionViewV1(
            viewer_actor_receipt=_actor_receipt(M8ActorRole.SAFETY_OFFICER),
            source_projection_id=_projection().projection_id,
            visible_projection=_projection(),
        ),
    ),
)
def test_projection_contracts_validate_as_serialization_schemas(model: BaseModel) -> None:
    Draft202012Validator(type(model).model_json_schema(mode="serialization")).validate(
        model.model_dump(mode="json")
    )


def test_projection_schemas_are_registered_serialization_roots() -> None:
    from labcourt.schema_registry import SCHEMA_MODELS, SCHEMA_VALIDATION_MODELS

    expected = {
        "m8-operations-projection-v1": M8OperationsProjectionV1,
        "m8-operations-projection-view-v1": M8OperationsProjectionViewV1,
        "m8-projection-map-node-v1": M8ProjectionMapNodeV1,
        "m8-projection-overview-v1": M8ProjectionOverviewV1,
        "m8-projection-source-v1": M8ProjectionSourceV1,
    }
    assert {name: SCHEMA_MODELS[name] for name in expected} == expected
    assert expected.keys().isdisjoint(SCHEMA_VALIDATION_MODELS)

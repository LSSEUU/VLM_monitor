from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from labcourt.contracts.m6_regression import (
    M6RegressionExecutionEntry,
    M6ReplayExecutionOutcome,
)
from labcourt.contracts.m6_replay_locked import (
    M6LockedModelCallLayer,
    M6LockedModelCallResultKind,
    M6LockedModelRole,
)
from labcourt.contracts.m6_upgrade_execution_ledger import M6UpgradeCandidateCaseBinding
from labcourt.contracts.m6_upgrade_execution_observation import (
    MAX_M6_UPGRADE_MODEL_CALL_OBSERVATIONS_PER_SAMPLE,
    M6UpgradeObservedArtifactIdentity,
    M6UpgradeObservedModelCall,
    M6UpgradeSampleExecutionObservationAuthority,
)
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradeArtifactUsage,
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactSource,
)
from labcourt.ports.m6_upgrade_execution_observation import (
    M6UpgradeExecutionObservationError,
    M6UpgradeExecutionObservationFailureCode,
)
from labcourt.schema_export import expected_schema_files

_A = "a" * 64
_B = "b" * 64
_C = "c" * 64
_D = "d" * 64
_E = "e" * 64
_F = "f" * 64


def _entry() -> M6RegressionExecutionEntry:
    return M6RegressionExecutionEntry(
        sample_id="sample-001",
        input_authority_id=_A,
        input_authority_document_sha256=_B,
        replay_input_closure_authority_id=_C,
        replay_input_closure_document_sha256=_D,
    )


def _case() -> M6UpgradeCandidateCaseBinding:
    return M6UpgradeCandidateCaseBinding(
        case_id="candidate-case-001",
        case_revision=1,
        case_document_sha256=_E,
        case_audit_sequence=7,
        case_audit_entry_hash=_F,
    )


def _artifact(
    kind: M6UpgradePhysicalArtifactKind,
    artifact_id: str,
    *,
    source: M6UpgradePhysicalArtifactSource = M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
    usage: M6UpgradeArtifactUsage = M6UpgradeArtifactUsage.PRODUCED,
) -> M6UpgradeObservedArtifactIdentity:
    return M6UpgradeObservedArtifactIdentity(
        source=source,
        kind=kind,
        artifact_id=artifact_id,
        usage=usage,
    )


def _frame(frame_id: str = "camera-a:stream-a:0") -> M6UpgradeObservedArtifactIdentity:
    return _artifact(
        M6UpgradePhysicalArtifactKind.FRAME,
        frame_id,
        usage=M6UpgradeArtifactUsage.CONSUMED,
    )


def _model_call(
    *,
    request_id: str = _E,
    layer: M6LockedModelCallLayer = M6LockedModelCallLayer.SCREENING,
    role: M6LockedModelRole = M6LockedModelRole.SCREENING,
    attempt_index: int = 0,
    result_kind: M6LockedModelCallResultKind = M6LockedModelCallResultKind.RESPONSE,
    provider_invoked: bool = True,
) -> M6UpgradeObservedModelCall:
    return M6UpgradeObservedModelCall(
        request_id=request_id,
        layer=layer,
        role=role,
        attempt_index=attempt_index,
        result_kind=result_kind,
        provider_invoked=provider_invoked,
    )


def _observation(
    *,
    candidate_case: M6UpgradeCandidateCaseBinding | None = None,
    outcome: M6ReplayExecutionOutcome | None = None,
    artifacts: tuple[M6UpgradeObservedArtifactIdentity, ...] | None = None,
    model_calls: tuple[M6UpgradeObservedModelCall, ...] = (),
    ledger_sequence: int = 0,
) -> M6UpgradeSampleExecutionObservationAuthority:
    resolved_outcome = outcome or (
        M6ReplayExecutionOutcome.CASE_REPLAYED
        if candidate_case is not None
        else M6ReplayExecutionOutcome.NO_CASE
    )
    return M6UpgradeSampleExecutionObservationAuthority(
        execution_scope_authority_id=_A,
        candidate_run_id="candidate-run-001",
        command_id=_B,
        execution_dataset_snapshot_id=_C,
        execution_entry=_entry(),
        ledger_sequence=ledger_sequence,
        outcome=resolved_outcome,
        candidate_case=candidate_case,
        artifacts=artifacts or (_frame(),),
        model_calls=model_calls,
    )


def test_observation_is_preledger_authority_with_canonical_round_trip() -> None:
    observation = _observation(
        candidate_case=_case(),
        ledger_sequence=3,
        artifacts=(
            _frame(),
            _artifact(M6UpgradePhysicalArtifactKind.DETECTION, "detection-001"),
            _artifact(
                M6UpgradePhysicalArtifactKind.EVIDENCE_PACK,
                "evidence-001",
                source=M6UpgradePhysicalArtifactSource.M2_EVIDENCE,
            ),
        ),
        model_calls=(_model_call(),),
    )

    serialized = observation.model_dump(mode="json")
    assert serialized["ledger_sequence"] == 3
    assert "previous_ledger_entry_hash" not in serialized
    assert "sample_execution_record_id" not in serialized
    assert M6UpgradeSampleExecutionObservationAuthority.model_validate(serialized) == observation
    assert len(observation.observation_authority_id) == 64


def test_observation_authority_id_binds_sequence_and_runtime_facts() -> None:
    base = _observation(candidate_case=_case(), model_calls=(_model_call(),))
    next_sequence = _observation(
        candidate_case=_case(),
        model_calls=(_model_call(),),
        ledger_sequence=1,
    )
    cached = _observation(
        candidate_case=_case(),
        model_calls=(_model_call(provider_invoked=False),),
    )

    assert (
        len(
            {
                base.observation_authority_id,
                next_sequence.observation_authority_id,
                cached.observation_authority_id,
            }
        )
        == 3
    )

    payload = base.model_dump(mode="json")
    payload["observation_authority_id"] = _F
    with pytest.raises(ValidationError, match="serialized observation_authority_id"):
        M6UpgradeSampleExecutionObservationAuthority.model_validate(payload)


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (
            {
                "source": M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL,
                "kind": M6UpgradePhysicalArtifactKind.MODEL_REQUEST,
                "artifact_id": _A,
                "usage": M6UpgradeArtifactUsage.PRODUCED,
            },
            "typed model-call observation",
        ),
        (
            {
                "source": M6UpgradePhysicalArtifactSource.M2_EVIDENCE,
                "kind": M6UpgradePhysicalArtifactKind.DETECTION,
                "artifact_id": "detection-001",
                "usage": M6UpgradeArtifactUsage.PRODUCED,
            },
            "no resolver for its source",
        ),
        (
            {
                "source": M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
                "kind": M6UpgradePhysicalArtifactKind.FRAME,
                "artifact_id": "camera-a:stream-a:0",
                "usage": M6UpgradeArtifactUsage.PRODUCED,
            },
            "must be recorded as consumed",
        ),
        (
            {
                "source": M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
                "kind": M6UpgradePhysicalArtifactKind.DETECTION,
                "artifact_id": "not/an/anonymous-token",
                "usage": M6UpgradeArtifactUsage.PRODUCED,
            },
            "anonymous ASCII reference token",
        ),
    ],
)
def test_non_model_artifact_identity_fails_closed(
    payload: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        M6UpgradeObservedArtifactIdentity.model_validate(payload)


@pytest.mark.parametrize(
    "kind",
    [kind for kind in M6UpgradePhysicalArtifactKind if kind.value.startswith("MODEL_")],
)
def test_generic_identity_rejects_every_model_artifact_kind(
    kind: M6UpgradePhysicalArtifactKind,
) -> None:
    with pytest.raises(ValidationError, match="typed model-call observation"):
        M6UpgradeObservedArtifactIdentity(
            source=M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL,
            kind=kind,
            artifact_id=_A,
            usage=M6UpgradeArtifactUsage.PRODUCED,
        )


def test_detection_cannot_self_report_a_container_or_physical_content() -> None:
    payload = _artifact(
        M6UpgradePhysicalArtifactKind.DETECTION,
        "detection-001",
    ).model_dump(mode="json")
    for forbidden_name, forbidden_value in (
        ("container_id", "camera-a:stream-a:0"),
        ("document_sha256", _A),
        ("content_sha256", _B),
        ("size_bytes", 100),
        ("artifact_ref_id", _C),
    ):
        candidate = dict(payload)
        candidate[forbidden_name] = forbidden_value
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            M6UpgradeObservedArtifactIdentity.model_validate(candidate)


def test_artifact_identities_are_stably_ordered_and_physically_unique() -> None:
    detection = _artifact(M6UpgradePhysicalArtifactKind.DETECTION, "detection-001")
    with pytest.raises(ValidationError, match="stable order"):
        _observation(artifacts=(detection, _frame()))

    embedding_produced = _artifact(
        M6UpgradePhysicalArtifactKind.EMBEDDING,
        "embedding-001",
        source=M6UpgradePhysicalArtifactSource.M5_PRECEDENT,
    )
    embedding_consumed = embedding_produced.model_copy(
        update={"usage": M6UpgradeArtifactUsage.CONSUMED}
    )
    with pytest.raises(ValidationError, match="identities must be unique"):
        _observation(
            candidate_case=_case(),
            artifacts=(_frame(), embedding_produced, embedding_consumed),
        )


def test_outcome_case_and_model_scope_matrix_is_fail_closed() -> None:
    with pytest.raises(ValidationError, match="outcome and candidate Case binding differ"):
        _observation(outcome=M6ReplayExecutionOutcome.CASE_REPLAYED)
    with pytest.raises(ValidationError, match="outcome and candidate Case binding differ"):
        _observation(candidate_case=_case(), outcome=M6ReplayExecutionOutcome.NO_CASE)
    with pytest.raises(ValidationError, match="model calls require a candidate Case"):
        _observation(model_calls=(_model_call(),))
    with pytest.raises(ValidationError, match=r"NO_CASE.*Frame and Detection"):
        _observation(
            artifacts=(
                _frame(),
                _artifact(
                    M6UpgradePhysicalArtifactKind.EVIDENCE_PACK,
                    "evidence-001",
                    source=M6UpgradePhysicalArtifactSource.M2_EVIDENCE,
                ),
            )
        )
    with pytest.raises(ValidationError, match="requires at least one Frame"):
        _observation(
            candidate_case=_case(),
            artifacts=(
                _artifact(
                    M6UpgradePhysicalArtifactKind.EVIDENCE_PACK,
                    "evidence-001",
                    source=M6UpgradePhysicalArtifactSource.M2_EVIDENCE,
                ),
            ),
        )


def test_model_call_observation_enforces_layer_role_and_strict_runtime_types() -> None:
    with pytest.raises(ValidationError, match="requires the SCREENING role"):
        _model_call(role=M6LockedModelRole.JUDGE)
    with pytest.raises(ValidationError, match="cannot use the SCREENING role"):
        _model_call(
            layer=M6LockedModelCallLayer.HEARING,
            role=M6LockedModelRole.SCREENING,
        )

    payload = _model_call().model_dump(mode="json")
    payload["attempt_index"] = True
    with pytest.raises(ValidationError):
        M6UpgradeObservedModelCall.model_validate(payload)
    payload = _model_call().model_dump(mode="json")
    payload["provider_invoked"] = 1
    with pytest.raises(ValidationError):
        M6UpgradeObservedModelCall.model_validate(payload)
    with pytest.raises(ValidationError):
        _observation(ledger_sequence=True)  # type: ignore[arg-type]


def test_model_calls_require_stable_order_and_unique_request_identity() -> None:
    first = _model_call(request_id=_D)
    second = _model_call(
        request_id=_E,
        layer=M6LockedModelCallLayer.HEARING,
        role=M6LockedModelRole.JUDGE,
    )
    with pytest.raises(ValidationError, match="unique and ordered"):
        _observation(candidate_case=_case(), model_calls=(second, first))

    duplicate_request = _model_call(
        request_id=_D,
        layer=M6LockedModelCallLayer.HEARING,
        role=M6LockedModelRole.JUDGE,
    )
    with pytest.raises(ValidationError, match="request_ids must be unique"):
        _observation(
            candidate_case=_case(),
            model_calls=(first, duplicate_request),
        )


def test_serialization_schema_exposes_only_logical_observation_fields() -> None:
    filename = "m6-upgrade-sample-execution-observation-authority.schema.json"
    schema = json.loads(expected_schema_files()[filename])
    artifact = schema["$defs"]["M6UpgradeObservedArtifactIdentity"]
    model_call = schema["$defs"]["M6UpgradeObservedModelCall"]

    assert set(artifact["properties"]) == {"source", "kind", "artifact_id", "usage"}
    assert set(model_call["properties"]) == {
        "request_id",
        "layer",
        "role",
        "attempt_index",
        "result_kind",
        "provider_invoked",
    }
    properties = schema["properties"]
    assert properties["artifacts"]["minItems"] == 1
    assert properties["artifacts"]["maxItems"] == 20_000
    assert (
        properties["model_calls"]["maxItems"] == MAX_M6_UPGRADE_MODEL_CALL_OBSERVATIONS_PER_SAMPLE
    )
    assert properties["ledger_sequence"]["minimum"] == 0
    assert "observation_authority_id" in properties


def test_observation_failure_is_typed_and_payload_free() -> None:
    error = M6UpgradeExecutionObservationError(
        M6UpgradeExecutionObservationFailureCode.OBSERVATION_CONFLICT
    )
    assert error.reason_code == M6UpgradeExecutionObservationFailureCode.OBSERVATION_CONFLICT
    assert error.args == ("M6 execution observation failed: OBSERVATION_CONFLICT",)
    assert vars(error) == {"reason_code": error.reason_code}
    with pytest.raises(TypeError, match="reason_code"):
        M6UpgradeExecutionObservationError("OBSERVATION_CONFLICT")  # type: ignore[arg-type]

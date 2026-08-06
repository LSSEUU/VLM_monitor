from __future__ import annotations

import traceback
from dataclasses import replace

import pytest

import labcourt.application.m6_upgrade_whole_sample_record as subject
from labcourt.contracts.m6_upgrade_execution_ledger import M6UpgradeSampleExecutionRecordV2
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradeArtifactUsage,
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactRef,
    M6UpgradePhysicalArtifactSource,
)
from labcourt.ports.m6_upgrade_whole_sample_record_builder import (
    M6UpgradeWholeSampleRecordBuilderError,
    M6UpgradeWholeSampleRecordBuilderFailureCode,
)
from tests.unit.test_m6_upgrade_whole_sample_record import (
    _case_observation_v2,
    _evidence_pack,
    _frame,
    _no_case_observation_v2,
    _observed_model_call,
    _scope,
    _v3_case_binding,
)
from tests.unit.test_m6_upgrade_whole_sample_record_m4 import _m4_calls


def _acquisition_ref(
    kind: M6UpgradePhysicalArtifactKind,
    seed: int,
    *,
    artifact_id: str | None = None,
) -> M6UpgradePhysicalArtifactRef:
    digest = f"{seed + 31_000:064x}"
    return M6UpgradePhysicalArtifactRef(
        source=M6UpgradePhysicalArtifactSource.M4_ACQUISITION,
        kind=kind,
        artifact_id=artifact_id or f"{seed + 32_000:064x}",
        document_sha256=digest,
        content_sha256=digest,
        size_bytes=37 + seed,
    )


def _acquisition_refs(seed: int = 0) -> tuple[M6UpgradePhysicalArtifactRef, ...]:
    return (
        _acquisition_ref(
            M6UpgradePhysicalArtifactKind.TOOL_EXECUTION_MANIFEST,
            seed * 10,
        ),
        _acquisition_ref(
            M6UpgradePhysicalArtifactKind.TOOL_RESULT,
            seed * 10 + 1,
        ),
    )


def _metadata_calls() -> tuple[subject.M6MetadataModelCallArtifactPlan, ...]:
    calls = _m4_calls()
    observed = tuple(
        _observed_model_call(call, provider_invoked=index != 1) for index, call in enumerate(calls)
    )
    return tuple(
        subject.M6MetadataModelCallArtifactPlan(
            observation=observed_call,
            artifact_refs=planned_call.artifact_refs,
        )
        for observed_call, planned_call in zip(observed, calls, strict=True)
    )


def _build(
    *,
    sequence: int = 0,
    prior_records: tuple[M6UpgradeSampleExecutionRecordV2, ...] = (),
    candidate_label: str = "m4-pure-composer-case",
    observed_acquisition: tuple[M6UpgradePhysicalArtifactRef, ...] | None = None,
    acquisition_artifacts: tuple[M6UpgradePhysicalArtifactRef, ...] | None = None,
) -> M6UpgradeSampleExecutionRecordV2:
    scope = _scope()
    candidate_case = _v3_case_binding(candidate_label)
    frame = _frame(sequence)
    pack = _evidence_pack(sequence)
    calls = _metadata_calls()
    observed_calls = tuple(item.observation for item in calls)
    observed_acquisition = (
        _acquisition_refs(sequence) if observed_acquisition is None else observed_acquisition
    )
    acquisition_artifacts = (
        observed_acquisition if acquisition_artifacts is None else acquisition_artifacts
    )
    observation = _case_observation_v2(
        scope,
        sequence,
        (frame, pack, *observed_acquisition),
        candidate_case,
        model_calls=observed_calls,
    )
    return subject.build_m6_upgrade_case_replayed_metadata_acquisition_record_v3(
        scope=scope,
        observation=observation,
        prior_records=prior_records,
        artifacts=(pack, frame),
        model_calls=calls,
        acquisition_artifacts=acquisition_artifacts,
        candidate_case=candidate_case,
    )


def test_v3_metadata_acquisition_record_is_deterministic_and_complete() -> None:
    first = _build()
    second = _build()

    scope = _scope()
    candidate_case = _v3_case_binding("m4-pure-composer-case")
    frame = _frame(0)
    pack = _evidence_pack(0)
    planned_calls = _m4_calls()
    acquisition = _acquisition_refs()
    observation = _case_observation_v2(
        scope,
        0,
        (frame, pack, *acquisition),
        candidate_case,
        model_calls=tuple(
            _observed_model_call(call, provider_invoked=index != 1)
            for index, call in enumerate(planned_calls)
        ),
    )
    verified = subject.build_m6_upgrade_case_replayed_acquisition_record_v3(
        scope=scope,
        observation=observation,
        prior_records=(),
        artifacts=(frame, pack),
        planned_calls=planned_calls,
        acquisition_artifacts=acquisition,
        candidate_case=candidate_case,
    )

    assert first == second == verified
    acquisition_links = tuple(
        link
        for link in first.artifact_links
        if link.artifact.source == M6UpgradePhysicalArtifactSource.M4_ACQUISITION
    )
    assert tuple(link.artifact.kind for link in acquisition_links) == (
        M6UpgradePhysicalArtifactKind.TOOL_EXECUTION_MANIFEST,
        M6UpgradePhysicalArtifactKind.TOOL_RESULT,
    )
    assert {link.usage for link in acquisition_links} == {M6UpgradeArtifactUsage.PRODUCED}
    assert (
        len(
            [
                link
                for link in first.artifact_links
                if link.artifact.source == M6UpgradePhysicalArtifactSource.M4_HEARING_MODEL
                and link.artifact.kind == M6UpgradePhysicalArtifactKind.MODEL_REQUEST
            ]
        )
        == 3
    )
    cache_usages = tuple(
        link.usage
        for link in first.artifact_links
        if link.artifact.kind == M6UpgradePhysicalArtifactKind.MODEL_CACHE
    )
    assert cache_usages == (
        M6UpgradeArtifactUsage.PRODUCED,
        M6UpgradeArtifactUsage.CONSUMED,
        M6UpgradeArtifactUsage.PRODUCED,
    )


def test_v3_verified_acquisition_record_preserves_planned_call_validation() -> None:
    scope = _scope()
    candidate_case = _v3_case_binding("m4-pure-composer-case")
    frame = _frame(0)
    acquisition = _acquisition_refs()
    calls = _m4_calls()
    observation = _case_observation_v2(
        scope,
        0,
        (frame, *acquisition),
        candidate_case,
        model_calls=tuple(_observed_model_call(call, provider_invoked=True) for call in calls),
    )

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        subject.build_m6_upgrade_case_replayed_acquisition_record_v3(
            scope=scope,
            observation=observation,
            prior_records=(),
            artifacts=(frame,),
            planned_calls=(replace(calls[0], timeout_ms=3_600_000), *calls[1:]),
            acquisition_artifacts=acquisition,
            candidate_case=candidate_case,
        )
    assert raised.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH
    )


@pytest.mark.parametrize(
    ("mutation", "expected"),
    (
        (
            "missing",
            M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_CLOSURE_MISMATCH,
        ),
        (
            "extra",
            M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_CLOSURE_MISMATCH,
        ),
        (
            "wrong_route",
            M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED,
        ),
        (
            "duplicate",
            M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT,
        ),
        (
            "unstable",
            M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_CLOSURE_MISMATCH,
        ),
    ),
)
def test_v3_metadata_acquisition_record_rejects_non_exact_inputs(
    mutation: str,
    expected: M6UpgradeWholeSampleRecordBuilderFailureCode,
) -> None:
    refs = _acquisition_refs()
    observed = refs
    supplied = refs
    if mutation == "missing":
        supplied = refs[:1]
    elif mutation == "extra":
        observed = refs[:1]
    elif mutation == "wrong_route":
        wrong = M6UpgradePhysicalArtifactRef(
            source=M6UpgradePhysicalArtifactSource.M5_PRECEDENT,
            kind=M6UpgradePhysicalArtifactKind.EMBEDDING,
            artifact_id="wrong-acquisition-route",
            document_sha256="d" * 64,
            content_sha256="d" * 64,
            size_bytes=1,
        )
        observed = (wrong,)
        supplied = (wrong,)
    elif mutation == "duplicate":
        supplied = (refs[0], refs[0])
    else:
        supplied = tuple(reversed(refs))

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        _build(
            observed_acquisition=observed,
            acquisition_artifacts=supplied,
        )
    assert raised.value.reason_code == expected


def test_v3_metadata_acquisition_record_rejects_non_produced_observation() -> None:
    scope = _scope()
    candidate_case = _v3_case_binding("m4-pure-composer-case")
    frame = _frame(0)
    refs = _acquisition_refs()
    calls = _metadata_calls()
    valid = _case_observation_v2(
        scope,
        0,
        (frame, *refs),
        candidate_case,
        model_calls=tuple(item.observation for item in calls),
    )
    invalid_artifact = valid.artifacts[1].model_copy()
    object.__setattr__(
        invalid_artifact,
        "usage",
        M6UpgradeArtifactUsage.CONSUMED,
    )
    invalid = valid
    object.__setattr__(
        invalid,
        "artifacts",
        (
            valid.artifacts[0],
            invalid_artifact,
            *valid.artifacts[2:],
        ),
    )

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        subject.build_m6_upgrade_case_replayed_metadata_acquisition_record_v3(
            scope=scope,
            observation=invalid,
            prior_records=(),
            artifacts=(frame,),
            model_calls=calls,
            acquisition_artifacts=refs,
            candidate_case=candidate_case,
        )
    assert raised.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID
    )


def test_v3_metadata_acquisition_record_detects_prefix_identity_conflict() -> None:
    first = _build()
    first_refs = _acquisition_refs(0)
    conflicting_manifest = _acquisition_ref(
        M6UpgradePhysicalArtifactKind.TOOL_EXECUTION_MANIFEST,
        99,
        artifact_id=first_refs[0].artifact_id,
    )
    second_refs = (conflicting_manifest, _acquisition_refs(1)[1])

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        _build(
            sequence=1,
            prior_records=(first,),
            candidate_label="m4-acquisition-second-case",
            observed_acquisition=second_refs,
        )
    assert raised.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT
    )


def test_v3_acquisition_prefix_allows_a_later_no_case_record() -> None:
    scope = _scope()
    first = _build()
    frame = _frame(1)

    second = subject.build_m6_upgrade_no_case_record_v3(
        scope=scope,
        observation=_no_case_observation_v2(scope, 1, (frame,)),
        prior_records=(first,),
        artifacts=(frame,),
    )

    assert second.ledger_sequence == 1
    assert second.previous_ledger_entry_hash == first.sample_execution_record_id


def test_v3_metadata_acquisition_public_failure_is_payload_free() -> None:
    secret = "SECRET C:\\people\\alice-acquisition.json"
    valid = _acquisition_refs()
    payload = valid[0].model_dump(mode="python", exclude_computed_fields=True)
    payload["artifact_id"] = secret
    invalid = M6UpgradePhysicalArtifactRef.model_construct(**payload)

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        _build(acquisition_artifacts=(invalid, valid[1]))

    assert raised.value.reason_code == M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    rendered = "".join(traceback.format_exception(raised.value))
    assert "SECRET" not in rendered
    assert "alice-acquisition" not in rendered
    public_frames = []
    current = raised.value.__traceback__
    while current is not None:
        if (
            current.tb_frame.f_globals.get("__name__") == subject.__name__
            and current.tb_frame.f_code.co_name
            == "build_m6_upgrade_case_replayed_metadata_acquisition_record_v3"
        ):
            public_frames.append(current.tb_frame)
        current = current.tb_next
    assert len(public_frames) == 1
    assert {
        "scope",
        "observation",
        "prior_records",
        "artifacts",
        "model_calls",
        "acquisition_artifacts",
        "candidate_case",
    }.isdisjoint(public_frames[0].f_locals)

from __future__ import annotations

import traceback
from dataclasses import replace

import pytest

import labcourt.application.m6_upgrade_whole_sample_record as subject
from labcourt.contracts.m6_upgrade_execution_ledger import M6UpgradeSampleExecutionRecordV2
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeObservedArtifactIdentity,
    M6UpgradeSampleExecutionObservationAuthorityV2,
)
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradeArtifactUsage,
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactRef,
    M6UpgradePhysicalArtifactSource,
)
from labcourt.ports.m6_upgrade_model_physical import M6PlannedModelCallPhysicalClosure
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
from tests.unit.test_m6_upgrade_whole_sample_record_acquisition import _acquisition_refs
from tests.unit.test_m6_upgrade_whole_sample_record_m4 import _m4_calls


def _precedent_ref(
    kind: M6UpgradePhysicalArtifactKind,
    seed: int,
    *,
    artifact_id: str | None = None,
) -> M6UpgradePhysicalArtifactRef:
    digest = f"{seed + 41_000:064x}"
    return M6UpgradePhysicalArtifactRef(
        source=M6UpgradePhysicalArtifactSource.M5_PRECEDENT,
        kind=kind,
        artifact_id=artifact_id or f"{seed + 42_000:064x}",
        document_sha256=digest,
        content_sha256=digest,
        size_bytes=43 + seed,
    )


def _precedent_refs(seed: int = 0) -> tuple[M6UpgradePhysicalArtifactRef, ...]:
    refs = (
        _precedent_ref(M6UpgradePhysicalArtifactKind.EMBEDDING, seed * 10),
        _precedent_ref(M6UpgradePhysicalArtifactKind.EMBEDDING, seed * 10 + 1),
        _precedent_ref(M6UpgradePhysicalArtifactKind.PRECEDENT_EXPOSURE, seed * 10 + 2),
    )
    return tuple(sorted(refs, key=lambda item: item.physical_key))


def _calls_for_case(case_id: str) -> tuple[M6PlannedModelCallPhysicalClosure, ...]:
    return tuple(replace(item, case_id=case_id) for item in _m4_calls())


def _metadata_calls(
    calls: tuple[M6PlannedModelCallPhysicalClosure, ...],
) -> tuple[subject.M6MetadataModelCallArtifactPlan, ...]:
    observed = tuple(
        _observed_model_call(item, provider_invoked=index != 1) for index, item in enumerate(calls)
    )
    return tuple(
        subject.M6MetadataModelCallArtifactPlan(
            observation=observed_call,
            artifact_refs=planned_call.artifact_refs,
        )
        for observed_call, planned_call in zip(observed, calls, strict=True)
    )


def _observation(
    *,
    sequence: int,
    candidate_label: str,
    artifacts: tuple[M6UpgradePhysicalArtifactRef, ...],
    calls: tuple[M6PlannedModelCallPhysicalClosure, ...],
    precedent: tuple[M6UpgradePhysicalArtifactRef, ...],
) -> M6UpgradeSampleExecutionObservationAuthorityV2:
    scope = _scope()
    candidate_case = _v3_case_binding(candidate_label)
    usages = {
        item.artifact_id: (
            M6UpgradeArtifactUsage.PRODUCED if index == 0 else M6UpgradeArtifactUsage.CONSUMED
        )
        for index, item in enumerate(
            item for item in precedent if item.kind == M6UpgradePhysicalArtifactKind.EMBEDDING
        )
    }
    observed = tuple(
        sorted(
            (
                M6UpgradeObservedArtifactIdentity(
                    source=item.source,
                    kind=item.kind,
                    artifact_id=item.artifact_id,
                    usage=usages.get(
                        item.artifact_id,
                        (
                            M6UpgradeArtifactUsage.CONSUMED
                            if item.kind == M6UpgradePhysicalArtifactKind.FRAME
                            else M6UpgradeArtifactUsage.PRODUCED
                        ),
                    ),
                )
                for item in artifacts
            ),
            key=lambda item: item.sort_key,
        )
    )
    base = _case_observation_v2(
        scope,
        sequence,
        artifacts,
        candidate_case,
        model_calls=tuple(item.observation for item in _metadata_calls(calls)),
    )
    payload = base.model_dump(mode="python", exclude_computed_fields=True)
    payload["artifacts"] = observed
    return M6UpgradeSampleExecutionObservationAuthorityV2.model_validate(payload)


def _build(
    *,
    sequence: int = 0,
    prior_records: tuple[M6UpgradeSampleExecutionRecordV2, ...] = (),
    candidate_label: str = "m4-pure-composer-case",
    observed_precedent: tuple[M6UpgradePhysicalArtifactRef, ...] | None = None,
    precedent_artifacts: tuple[M6UpgradePhysicalArtifactRef, ...] | None = None,
) -> M6UpgradeSampleExecutionRecordV2:
    scope = _scope()
    candidate_case = _v3_case_binding(candidate_label)
    frame = _frame(sequence)
    pack = _evidence_pack(sequence)
    acquisition = _acquisition_refs(sequence)
    calls = _calls_for_case(candidate_case.case_id)
    metadata_calls = _metadata_calls(calls)
    observed_precedent = (
        _precedent_refs(sequence) if observed_precedent is None else observed_precedent
    )
    precedent_artifacts = observed_precedent if precedent_artifacts is None else precedent_artifacts
    observation = _observation(
        sequence=sequence,
        candidate_label=candidate_label,
        artifacts=(frame, pack, *acquisition, *observed_precedent),
        calls=calls,
        precedent=observed_precedent,
    )
    return subject.build_m6_upgrade_case_replayed_metadata_precedent_record_v3(
        scope=scope,
        observation=observation,
        prior_records=prior_records,
        artifacts=(pack, frame),
        model_calls=metadata_calls,
        acquisition_artifacts=acquisition,
        precedent_artifacts=precedent_artifacts,
        candidate_case=candidate_case,
    )


def test_v3_precedent_metadata_and_verified_records_are_identical() -> None:
    first = _build()
    second = _build()

    scope = _scope()
    candidate_case = _v3_case_binding("m4-pure-composer-case")
    frame = _frame(0)
    pack = _evidence_pack(0)
    acquisition = _acquisition_refs()
    precedent = _precedent_refs()
    calls = _calls_for_case(candidate_case.case_id)
    observation = _observation(
        sequence=0,
        candidate_label="m4-pure-composer-case",
        artifacts=(frame, pack, *acquisition, *precedent),
        calls=calls,
        precedent=precedent,
    )
    verified = subject.build_m6_upgrade_case_replayed_precedent_record_v3(
        scope=scope,
        observation=observation,
        prior_records=(),
        artifacts=(frame, pack),
        planned_calls=calls,
        acquisition_artifacts=acquisition,
        precedent_artifacts=precedent,
        candidate_case=candidate_case,
    )

    assert first == second == verified
    links = tuple(
        link
        for link in first.artifact_links
        if link.artifact.source == M6UpgradePhysicalArtifactSource.M5_PRECEDENT
    )
    assert tuple(link.artifact.kind for link in links) == (
        M6UpgradePhysicalArtifactKind.EMBEDDING,
        M6UpgradePhysicalArtifactKind.EMBEDDING,
        M6UpgradePhysicalArtifactKind.PRECEDENT_EXPOSURE,
    )
    assert tuple(link.usage for link in links) == (
        M6UpgradeArtifactUsage.PRODUCED,
        M6UpgradeArtifactUsage.CONSUMED,
        M6UpgradeArtifactUsage.PRODUCED,
    )
    assert tuple(link.physical_key for link in first.artifact_links) == tuple(
        sorted(link.physical_key for link in first.artifact_links)
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
        ("wrong_route", M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED),
        ("duplicate", M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT),
        (
            "unstable",
            M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_CLOSURE_MISMATCH,
        ),
    ),
)
def test_v3_metadata_precedent_record_requires_an_exact_stable_route_set(
    mutation: str,
    expected: M6UpgradeWholeSampleRecordBuilderFailureCode,
) -> None:
    refs = _precedent_refs()
    observed = refs
    supplied = refs
    if mutation == "missing":
        supplied = refs[:-1]
    elif mutation == "extra":
        observed = refs[:-1]
    elif mutation == "wrong_route":
        wrong = _acquisition_refs(99)[0]
        observed = (wrong,)
        supplied = (wrong,)
    elif mutation == "duplicate":
        supplied = (refs[0], refs[0])
    else:
        supplied = tuple(reversed(refs))

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        _build(observed_precedent=observed, precedent_artifacts=supplied)
    assert raised.value.reason_code == expected


def test_v3_verified_precedent_record_preserves_model_closure_validation() -> None:
    scope = _scope()
    candidate_case = _v3_case_binding("m4-pure-composer-case")
    frame = _frame(0)
    acquisition = _acquisition_refs()
    precedent = _precedent_refs()
    calls = _calls_for_case(candidate_case.case_id)
    observation = _observation(
        sequence=0,
        candidate_label="m4-pure-composer-case",
        artifacts=(frame, *acquisition, *precedent),
        calls=calls,
        precedent=precedent,
    )

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        subject.build_m6_upgrade_case_replayed_precedent_record_v3(
            scope=scope,
            observation=observation,
            prior_records=(),
            artifacts=(frame,),
            planned_calls=(replace(calls[0], timeout_ms=3_600_000), *calls[1:]),
            acquisition_artifacts=acquisition,
            precedent_artifacts=precedent,
            candidate_case=candidate_case,
        )
    assert raised.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH
    )


def test_v3_precedent_prefix_allows_a_later_no_case_record() -> None:
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


def test_existing_acquisition_api_keeps_the_m5_current_route_closed() -> None:
    scope = _scope()
    candidate_case = _v3_case_binding("m4-pure-composer-case")
    frame = _frame(0)
    acquisition = _acquisition_refs()
    precedent = _precedent_refs()
    calls = _calls_for_case(candidate_case.case_id)
    observation = _observation(
        sequence=0,
        candidate_label="m4-pure-composer-case",
        artifacts=(frame, *acquisition, *precedent),
        calls=calls,
        precedent=precedent,
    )

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        subject.build_m6_upgrade_case_replayed_acquisition_record_v3(
            scope=scope,
            observation=observation,
            prior_records=(),
            artifacts=(frame,),
            planned_calls=calls,
            acquisition_artifacts=acquisition,
            candidate_case=candidate_case,
        )
    assert raised.value.reason_code == M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED


def test_v3_precedent_record_detects_prefix_identity_conflict() -> None:
    first = _build()
    initial = _precedent_refs()
    conflicting = _precedent_ref(
        M6UpgradePhysicalArtifactKind.EMBEDDING,
        99,
        artifact_id=initial[0].artifact_id,
    )
    second = tuple(sorted((conflicting, *initial[1:]), key=lambda item: item.physical_key))

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        _build(
            sequence=1,
            prior_records=(first,),
            candidate_label="m5-precedent-second-case",
            observed_precedent=second,
        )
    assert (
        raised.value.reason_code == M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT
    )


def test_v3_metadata_precedent_record_counts_m5_bytes_in_the_sample_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    total = sum(item.size_bytes for item in _precedent_refs())
    monkeypatch.setattr(subject, "MAX_M6_UPGRADE_SAMPLE_PHYSICAL_BYTES", total - 1)

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        _build()
    assert raised.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.PHYSICAL_BYTE_LIMIT_EXCEEDED
    )


def test_v3_metadata_precedent_public_failure_is_payload_free() -> None:
    secret = "SECRET C:\\people\\alice-precedent.json"
    valid = _precedent_refs()
    payload = valid[0].model_dump(mode="python", exclude_computed_fields=True)
    payload["artifact_id"] = secret
    invalid = M6UpgradePhysicalArtifactRef.model_construct(**payload)

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        _build(precedent_artifacts=(invalid, *valid[1:]))

    assert raised.value.reason_code == M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    rendered = "".join(traceback.format_exception(raised.value))
    assert "SECRET" not in rendered
    assert "alice-precedent" not in rendered
    public_frames = []
    current = raised.value.__traceback__
    while current is not None:
        if (
            current.tb_frame.f_globals.get("__name__") == subject.__name__
            and current.tb_frame.f_code.co_name
            == "build_m6_upgrade_case_replayed_metadata_precedent_record_v3"
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
        "precedent_artifacts",
        "candidate_case",
    }.isdisjoint(public_frames[0].f_locals)

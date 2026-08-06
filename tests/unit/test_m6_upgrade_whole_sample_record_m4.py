from __future__ import annotations

from dataclasses import replace

import pytest

import labcourt.application.m6_upgrade_whole_sample_record as subject
from labcourt.contracts.m6_replay_locked import (
    M6LockedModelCallLayer,
    M6LockedModelCallResultKind,
    M6LockedModelRole,
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
    _observed_model_call,
    _planned_m3_call,
    _scope,
    _v3_case_binding,
)


def _m4_ref(
    kind: M6UpgradePhysicalArtifactKind,
    seed: int,
    *,
    artifact_id: str | None = None,
) -> M6UpgradePhysicalArtifactRef:
    document_sha256 = f"{seed + 11_000:064x}"
    return M6UpgradePhysicalArtifactRef(
        source=M6UpgradePhysicalArtifactSource.M4_HEARING_MODEL,
        kind=kind,
        artifact_id=artifact_id or f"{seed + 12_000:064x}",
        document_sha256=document_sha256,
        content_sha256=(
            f"{seed + 13_000:064x}"
            if kind == M6UpgradePhysicalArtifactKind.MODEL_RESPONSE
            else document_sha256
        ),
        size_bytes=29,
    )


def _planned_m4_call(
    *,
    role: M6LockedModelRole,
    seed: int,
    source_identity_sha256: str = "8" * 64,
) -> M6PlannedModelCallPhysicalClosure:
    scope = _scope()
    candidate_case = _v3_case_binding("m4-pure-composer-case")
    request_id = f"{seed + 10_000:064x}"
    return M6PlannedModelCallPhysicalClosure(
        source_identity_sha256=source_identity_sha256,
        run_id=scope.candidate_run_id,
        case_id=candidate_case.case_id,
        manifest_id=scope.candidate_manifest.manifest_id,
        layer=M6LockedModelCallLayer.HEARING,
        role=role,
        attempt_index=0,
        timeout_ms=1,
        execution_model_manifest_id=scope.candidate_manifest.models[
            role.value.lower()
        ].model_manifest_id,
        request_ref=_m4_ref(
            M6UpgradePhysicalArtifactKind.MODEL_REQUEST,
            seed * 10,
            artifact_id=request_id,
        ),
        result_kind=M6LockedModelCallResultKind.RESPONSE,
        response_ref=_m4_ref(
            M6UpgradePhysicalArtifactKind.MODEL_RESPONSE,
            seed * 10 + 1,
        ),
        cache_ref=_m4_ref(
            M6UpgradePhysicalArtifactKind.MODEL_CACHE,
            seed * 10 + 2,
        ),
        parse_receipt_ref=_m4_ref(
            M6UpgradePhysicalArtifactKind.MODEL_PARSE_RECEIPT,
            seed * 10 + 3,
        ),
        parsed_output_ref=_m4_ref(
            M6UpgradePhysicalArtifactKind.MODEL_PARSED_OUTPUT,
            seed * 10 + 4,
        ),
        usage_receipt_ref=_m4_ref(
            M6UpgradePhysicalArtifactKind.MODEL_USAGE_RECEIPT,
            seed * 10 + 5,
        ),
    )


def _m4_calls() -> tuple[M6PlannedModelCallPhysicalClosure, ...]:
    return tuple(
        _planned_m4_call(role=role, seed=index + 1)
        for index, role in enumerate(
            (
                M6LockedModelRole.PROSECUTOR,
                M6LockedModelRole.DEFENDER,
                M6LockedModelRole.JUDGE,
            )
        )
    )


def test_v3_model_record_opens_three_role_m4_and_derives_cache_usage() -> None:
    scope = _scope()
    candidate_case = _v3_case_binding("m4-pure-composer-case")
    frame = _frame(0)
    pack = _evidence_pack(0)
    calls = _m4_calls()
    observed = tuple(
        _observed_model_call(call, provider_invoked=index != 1) for index, call in enumerate(calls)
    )
    observation = _case_observation_v2(
        scope,
        0,
        (frame, pack),
        candidate_case,
        model_calls=observed,
    )

    record = subject.build_m6_upgrade_case_replayed_model_record_v3(
        scope=scope,
        observation=observation,
        prior_records=(),
        artifacts=(pack, frame),
        planned_calls=calls,
        candidate_case=candidate_case,
    )

    expected_refs = tuple(ref for call in calls for ref in call.artifact_refs)
    assert tuple(link.artifact for link in record.artifact_links) == tuple(
        sorted((frame, pack, *expected_refs), key=lambda value: value.physical_key)
    )
    cache_usage = {
        link.artifact.artifact_id: link.usage
        for link in record.artifact_links
        if link.artifact.kind == M6UpgradePhysicalArtifactKind.MODEL_CACHE
    }
    assert cache_usage == {
        calls[0].cache_ref.artifact_id: M6UpgradeArtifactUsage.PRODUCED,
        calls[1].cache_ref.artifact_id: M6UpgradeArtifactUsage.CONSUMED,
        calls[2].cache_ref.artifact_id: M6UpgradeArtifactUsage.PRODUCED,
    }

    metadata_record = subject.build_m6_upgrade_case_replayed_metadata_model_record_v3(
        scope=scope,
        observation=observation,
        prior_records=(),
        artifacts=(pack, frame),
        model_calls=tuple(
            subject.M6MetadataModelCallArtifactPlan(
                observation=observed_call,
                artifact_refs=planned_call.artifact_refs,
            )
            for observed_call, planned_call in zip(observed, calls, strict=True)
        ),
        candidate_case=candidate_case,
    )
    assert metadata_record == record


def test_v3_metadata_model_record_requires_the_exact_observed_call_set() -> None:
    scope = _scope()
    candidate_case = _v3_case_binding("m4-pure-composer-case")
    frame = _frame(0)
    call = _planned_m4_call(role=M6LockedModelRole.PROSECUTOR, seed=1)
    observed = _observed_model_call(call, provider_invoked=True)
    observation = _case_observation_v2(
        scope,
        0,
        (frame,),
        candidate_case,
        model_calls=(observed,),
    )

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        subject.build_m6_upgrade_case_replayed_metadata_model_record_v3(
            scope=scope,
            observation=observation,
            prior_records=(),
            artifacts=(frame,),
            model_calls=(),
            candidate_case=candidate_case,
        )
    assert raised.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH
    )


def test_v3_model_record_accepts_independent_m3_and_m4_plan_identities() -> None:
    scope = _scope()
    candidate_case = _v3_case_binding("m4-pure-composer-case")
    frame = _frame(0)
    m3 = _planned_m3_call(scope, candidate_case)
    m4 = _planned_m4_call(
        role=M6LockedModelRole.PROSECUTOR,
        seed=9,
        source_identity_sha256="9" * 64,
    )
    calls = (m3, m4)
    observation = _case_observation_v2(
        scope,
        0,
        (frame,),
        candidate_case,
        model_calls=tuple(
            sorted(
                (
                    _observed_model_call(m3, provider_invoked=True),
                    _observed_model_call(m4, provider_invoked=True),
                ),
                key=lambda value: value.sort_key,
            )
        ),
    )

    record = subject.build_m6_upgrade_case_replayed_model_record_v3(
        scope=scope,
        observation=observation,
        prior_records=(),
        artifacts=(frame,),
        planned_calls=calls,
        candidate_case=candidate_case,
    )

    assert {
        link.artifact.source
        for link in record.artifact_links
        if link.artifact.kind
        in {
            M6UpgradePhysicalArtifactKind.MODEL_REQUEST,
            M6UpgradePhysicalArtifactKind.MODEL_RESPONSE,
        }
    } == {
        M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL,
        M6UpgradePhysicalArtifactSource.M4_HEARING_MODEL,
    }


@pytest.mark.parametrize(
    ("mutation", "expected"),
    (
        (
            "manifest",
            M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH,
        ),
        (
            "timeout",
            M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH,
        ),
        (
            "duplicate_identity",
            M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT,
        ),
    ),
)
def test_v3_model_record_rejects_invalid_m4_plan(
    mutation: str,
    expected: M6UpgradeWholeSampleRecordBuilderFailureCode,
) -> None:
    scope = _scope()
    candidate_case = _v3_case_binding("m4-pure-composer-case")
    frame = _frame(0)
    call = _planned_m4_call(role=M6LockedModelRole.PROSECUTOR, seed=1)
    calls = (call,)
    if mutation == "manifest":
        calls = (replace(call, execution_model_manifest_id="f" * 64),)
    elif mutation == "timeout":
        calls = (replace(call, timeout_ms=3_600_000),)
    else:
        second = _planned_m4_call(role=M6LockedModelRole.DEFENDER, seed=2)
        assert call.cache_ref is not None
        object.__setattr__(second, "cache_ref", call.cache_ref)
        calls = (call, second)
    observation = _case_observation_v2(
        scope,
        0,
        (frame,),
        candidate_case,
        model_calls=tuple(
            sorted(
                (_observed_model_call(item, provider_invoked=True) for item in calls),
                key=lambda value: value.sort_key,
            )
        ),
    )

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        subject.build_m6_upgrade_case_replayed_model_record_v3(
            scope=scope,
            observation=observation,
            prior_records=(),
            artifacts=(frame,),
            planned_calls=calls,
            candidate_case=candidate_case,
        )
    assert raised.value.reason_code == expected

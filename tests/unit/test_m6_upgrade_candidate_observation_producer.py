from __future__ import annotations

from dataclasses import dataclass

import pytest

from labcourt.application.m6_upgrade_candidate_observation_producer import (
    M6PrecomputedNoCaseObservationProducerV3,
)
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.m6_regression import M6ReplayExecutionOutcome
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6_UPGRADE_LEDGER_GENESIS_HASH,
    M6UpgradeExecutionScopeAuthority,
)
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradeArtifactUsage,
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactSource,
)
from labcourt.contracts.references import parse_frame_id
from labcourt.domain.m6_semantic_projection import M6ResolvedPerception
from labcourt.ports.m6_regression_execution_source_catalog import (
    M6RegressionExecutionSourceCatalogError,
    M6RegressionExecutionSourceCatalogFailureCode,
    M6StoredRegressionExecutionSourceCatalog,
)
from labcourt.ports.m6_upgrade_candidate_observation_producer import (
    M6UpgradeCandidateObservationProducerError,
    M6UpgradeCandidateObservationProducerFailureCode,
)
from labcourt.ports.m6_upgrade_candidate_perception_materializer import (
    M6UpgradeCandidatePerceptionMaterializerError,
    M6UpgradeCandidatePerceptionMaterializerFailureCode,
)
from labcourt.ports.m6_upgrade_execution_ledger_v3 import (
    M6UpgradeExecutionLedgerV3Error,
    M6UpgradeExecutionLedgerV3FailureCode,
    M6UpgradeExecutionLedgerV3Status,
    M6UpgradeExecutionResumeV3,
)
from tests.unit.test_m6_regression_execution_source_catalog import (
    _catalog,
    _execution_scope,
)
from tests.unit.test_m6_upgrade_durable_sample_appender import (
    _pending_resume,
    _ready_to_seal,
    _sealed,
)

_FailureCode = M6UpgradeCandidateObservationProducerFailureCode
_UNSET = object()


@dataclass(frozen=True, slots=True)
class _Bundle:
    stored: M6StoredRegressionExecutionSourceCatalog
    scope: M6UpgradeExecutionScopeAuthority


class _Ledger:
    def __init__(self, log: list[str], result: M6UpgradeExecutionResumeV3 | Exception) -> None:
        self._log = log
        self._result = result
        self.calls: list[tuple[str, str]] = []

    def resume(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeExecutionResumeV3:
        self._log.append("ledger.resume")
        self.calls.append((candidate_run_id, execution_scope_authority_id))
        if isinstance(self._result, Exception):
            raise self._result
        return self._result


class _Catalogs:
    def __init__(
        self,
        log: list[str],
        result: M6StoredRegressionExecutionSourceCatalog | Exception | object,
    ) -> None:
        self._log = log
        self._result = result
        self.calls: list[tuple[str, str]] = []

    def load(
        self,
        source_catalog_authority_id: str,
        source_catalog_document_sha256: str,
    ) -> M6StoredRegressionExecutionSourceCatalog:
        self._log.append("catalog.load")
        self.calls.append((source_catalog_authority_id, source_catalog_document_sha256))
        if isinstance(self._result, Exception):
            raise self._result
        return self._result  # type: ignore[return-value]


class _Materializer:
    def __init__(self, log: list[str], result: object) -> None:
        self._log = log
        self._result = result
        self.calls: list[tuple[str, str]] = []

    def materialize_next_perception(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
    ) -> object:
        self._log.append("perception.materialize")
        self.calls.append((candidate_run_id, execution_scope_authority_id))
        if isinstance(self._result, Exception):
            raise self._result
        return self._result


def _bundle(seed: str = "opaque-sample") -> _Bundle:
    built = _catalog(seed)
    document = built.execution_source_catalog_document
    stored = M6StoredRegressionExecutionSourceCatalog(
        source_catalog=built.execution_source_catalog,
        canonical_document=document,
        content_sha256=built.execution_source_catalog_content_sha256,
        size_bytes=len(document.encode("utf-8")),
    )
    scope = _execution_scope(stored.source_catalog, stored.content_sha256)
    return _Bundle(stored=stored, scope=scope)


def _ready(scope: M6UpgradeExecutionScopeAuthority) -> M6UpgradeExecutionResumeV3:
    return M6UpgradeExecutionResumeV3(
        status=M6UpgradeExecutionLedgerV3Status.READY_FOR_OBSERVATION,
        execution_scope=scope,
        committed_sample_count=0,
        ledger_head_hash=M6_UPGRADE_LEDGER_GENESIS_HASH,
        next_execution_entry=scope.execution_dataset.entries[0],
    )


def _perception(stored: M6StoredRegressionExecutionSourceCatalog) -> M6ResolvedPerception:
    closure = stored.source_catalog.entries[0].replay_input_closure
    camera_id, stream_id, frame_index = parse_frame_id(closure.frames[0].frame_id)
    return M6ResolvedPerception(
        frames=(
            FrameRef(
                camera_id=camera_id,
                stream_id=stream_id,
                frame_index=frame_index,
                fps_num=30,
                fps_den=1,
                width=640,
                height=480,
                content_sha256=closure.frames[0].content_sha256,
            ),
        )
    )


def _producer(
    resume: M6UpgradeExecutionResumeV3 | Exception,
    stored: M6StoredRegressionExecutionSourceCatalog | Exception | object,
    log: list[str] | None = None,
    materializer_result: object = _UNSET,
) -> tuple[
    M6PrecomputedNoCaseObservationProducerV3,
    _Ledger,
    _Catalogs,
    _Materializer,
]:
    events = [] if log is None else log
    ledger = _Ledger(events, resume)
    catalogs = _Catalogs(events, stored)
    selected_perception = (
        _perception(stored)
        if materializer_result is _UNSET
        and isinstance(stored, M6StoredRegressionExecutionSourceCatalog)
        else (object() if materializer_result is _UNSET else materializer_result)
    )
    materializer = _Materializer(events, selected_perception)
    return (
        M6PrecomputedNoCaseObservationProducerV3(
            ledger_repository=ledger,  # type: ignore[arg-type]
            source_catalog_provider=catalogs,  # type: ignore[arg-type]
            perception_materializer=materializer,  # type: ignore[arg-type]
        ),
        ledger,
        catalogs,
        materializer,
    )


def test_precomputed_no_case_producer_loads_exact_blind_catalog_and_observes_all_inputs() -> None:
    bundle = _bundle()
    events: list[str] = []
    producer, ledger, catalogs, materializer = _producer(
        _ready(bundle.scope), bundle.stored, events
    )

    observation = producer.produce_next_observation(
        bundle.scope.candidate_run_id,
        bundle.scope.execution_scope_authority_id,
    )

    closure = bundle.stored.source_catalog.entries[0].replay_input_closure
    assert events == ["ledger.resume", "catalog.load", "perception.materialize"]
    assert ledger.calls == [
        (bundle.scope.candidate_run_id, bundle.scope.execution_scope_authority_id)
    ]
    assert catalogs.calls == [
        (
            bundle.scope.execution_dataset.source_catalog_authority_id,
            bundle.scope.execution_dataset.source_catalog_document_sha256,
        )
    ]
    assert materializer.calls == [
        (bundle.scope.candidate_run_id, bundle.scope.execution_scope_authority_id)
    ]
    assert observation.outcome == M6ReplayExecutionOutcome.NO_CASE
    assert observation.candidate_case is None
    assert observation.selected_case_audit_anchor is None
    assert observation.model_calls == ()
    assert observation.execution_entry == bundle.scope.execution_dataset.entries[0]
    assert observation.ledger_sequence == 0
    assert {
        item.artifact_id
        for item in observation.artifacts
        if item.kind == M6UpgradePhysicalArtifactKind.FRAME
    } == {item.frame_id for item in closure.frames}
    assert {
        item.artifact_id
        for item in observation.artifacts
        if item.kind == M6UpgradePhysicalArtifactKind.DETECTION
    } == {item.detection_id for item in closure.detections}
    assert all(
        item.source == M6UpgradePhysicalArtifactSource.M2_PERCEPTION
        for item in observation.artifacts
    )
    assert all(
        item.usage == M6UpgradeArtifactUsage.CONSUMED
        for item in observation.artifacts
        if item.kind == M6UpgradePhysicalArtifactKind.FRAME
    )
    assert all(
        item.usage == M6UpgradeArtifactUsage.PRODUCED
        for item in observation.artifacts
        if item.kind == M6UpgradePhysicalArtifactKind.DETECTION
    )
    serialized_catalog = bundle.stored.canonical_document
    for evaluator_only_name in (
        "memberships",
        "gold_truth",
        "expected_decision",
        "challenge_kinds",
    ):
        assert evaluator_only_name not in serialized_catalog


@pytest.mark.parametrize(
    ("resume", "expected"),
    (
        (
            _pending_resume(0, M6UpgradeExecutionLedgerV3Status.READY_FOR_COMMITMENT),
            _FailureCode.OBSERVATION_ALREADY_EXISTS,
        ),
        (
            _pending_resume(0, M6UpgradeExecutionLedgerV3Status.READY_FOR_LEDGER_APPEND),
            _FailureCode.OBSERVATION_ALREADY_EXISTS,
        ),
        (_ready_to_seal(), _FailureCode.LEDGER_COMPLETE),
        (_sealed(), _FailureCode.LEDGER_SEALED),
    ),
)
def test_non_observation_states_stop_before_catalog_load(
    resume: M6UpgradeExecutionResumeV3,
    expected: _FailureCode,
) -> None:
    producer, _ledger, catalogs, materializer = _producer(resume, object())

    with pytest.raises(M6UpgradeCandidateObservationProducerError) as rejected:
        producer.produce_next_observation(
            resume.execution_scope.candidate_run_id,
            resume.execution_scope.execution_scope_authority_id,
        )

    assert rejected.value.reason_code == expected
    assert catalogs.calls == []
    assert materializer.calls == []


def test_foreign_but_valid_catalog_is_rejected_after_exact_two_identity_load() -> None:
    bundle = _bundle()
    foreign = _bundle("foreign-source")
    producer, _ledger, catalogs, _materializer = _producer(_ready(bundle.scope), foreign.stored)

    with pytest.raises(M6UpgradeCandidateObservationProducerError) as rejected:
        producer.produce_next_observation(
            bundle.scope.candidate_run_id,
            bundle.scope.execution_scope_authority_id,
        )

    assert rejected.value.reason_code == _FailureCode.CATALOG_REJECTED
    assert catalogs.calls == [
        (
            bundle.scope.execution_dataset.source_catalog_authority_id,
            bundle.scope.execution_dataset.source_catalog_document_sha256,
        )
    ]


@pytest.mark.parametrize(
    ("resume_result", "catalog_result", "expected"),
    (
        (
            M6UpgradeExecutionLedgerV3Error(M6UpgradeExecutionLedgerV3FailureCode.SCOPE_NOT_FOUND),
            object(),
            _FailureCode.SCOPE_NOT_FOUND,
        ),
        (
            None,
            M6RegressionExecutionSourceCatalogError(
                M6RegressionExecutionSourceCatalogFailureCode.CATALOG_NOT_FOUND
            ),
            _FailureCode.CATALOG_NOT_FOUND,
        ),
        (
            None,
            M6RegressionExecutionSourceCatalogError(
                M6RegressionExecutionSourceCatalogFailureCode.DOCUMENT_TOO_LARGE
            ),
            _FailureCode.DOCUMENT_TOO_LARGE,
        ),
        (
            None,
            M6RegressionExecutionSourceCatalogError(
                M6RegressionExecutionSourceCatalogFailureCode.DOCUMENT_INVALID
            ),
            _FailureCode.CATALOG_REJECTED,
        ),
        (None, object(), _FailureCode.STORED_AUTHORITY_INVALID),
    ),
)
def test_typed_lower_failures_are_mapped_without_payloads(
    resume_result: M6UpgradeExecutionResumeV3 | Exception | None,
    catalog_result: M6StoredRegressionExecutionSourceCatalog | Exception | object,
    expected: _FailureCode,
) -> None:
    bundle = _bundle()
    producer, _ledger, _catalogs, _materializer = _producer(
        _ready(bundle.scope) if resume_result is None else resume_result,
        bundle.stored if catalog_result is None else catalog_result,
    )

    with pytest.raises(M6UpgradeCandidateObservationProducerError) as rejected:
        producer.produce_next_observation(
            bundle.scope.candidate_run_id,
            bundle.scope.execution_scope_authority_id,
        )

    assert rejected.value.reason_code == expected
    assert rejected.value.__context__ is None
    assert rejected.value.__cause__ is None
    assert vars(rejected.value) == {"reason_code": expected}


def test_materialization_failure_and_wrong_inventory_are_rejected_before_observation() -> None:
    bundle = _bundle()
    lower = M6UpgradeCandidatePerceptionMaterializerError(
        M6UpgradeCandidatePerceptionMaterializerFailureCode.IDENTITY_CONFLICT
    )
    failed, _ledger, _catalogs, materializer = _producer(
        _ready(bundle.scope),
        bundle.stored,
        materializer_result=lower,
    )
    with pytest.raises(M6UpgradeCandidateObservationProducerError) as rejected:
        failed.produce_next_observation(
            bundle.scope.candidate_run_id,
            bundle.scope.execution_scope_authority_id,
        )
    assert rejected.value.reason_code == _FailureCode.CANDIDATE_PERCEPTION_REJECTED
    assert len(materializer.calls) == 1

    wrong = M6ResolvedPerception(
        frames=(_perception(bundle.stored).frames[0].model_copy(update={"frame_index": 91}),)
    )
    mismatched, _ledger, _catalogs, _materializer = _producer(
        _ready(bundle.scope),
        bundle.stored,
        materializer_result=wrong,
    )
    with pytest.raises(M6UpgradeCandidateObservationProducerError) as rejected:
        mismatched.produce_next_observation(
            bundle.scope.candidate_run_id,
            bundle.scope.execution_scope_authority_id,
        )
    assert rejected.value.reason_code == _FailureCode.CANDIDATE_PERCEPTION_REJECTED


def test_invalid_identity_and_unknown_failure_are_fresh_and_payload_free() -> None:
    bundle = _bundle()
    producer, _ledger, _catalogs, _materializer = _producer(
        _ready(bundle.scope), RuntimeError("secret")
    )

    with pytest.raises(M6UpgradeCandidateObservationProducerError) as invalid:
        producer.produce_next_observation("bad run id", "x")
    assert invalid.value.reason_code == _FailureCode.INVALID_ARGUMENT
    assert invalid.value.__context__ is None

    with pytest.raises(M6UpgradeCandidateObservationProducerError) as unknown:
        producer.produce_next_observation(
            bundle.scope.candidate_run_id,
            bundle.scope.execution_scope_authority_id,
        )
    assert unknown.value.reason_code == _FailureCode.STORAGE_REJECTED
    assert unknown.value.__context__ is None
    assert unknown.value.__cause__ is None
    assert "secret" not in str(unknown.value)

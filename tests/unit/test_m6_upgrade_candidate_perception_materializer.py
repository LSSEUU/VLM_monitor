from __future__ import annotations

import hashlib
from dataclasses import dataclass

import pytest

from labcourt.application.m6_regression_source_catalog import (
    build_m6_regression_source_catalog,
)
from labcourt.application.m6_upgrade_candidate_perception_materializer import (
    M6PrecomputedCandidatePerceptionMaterializerV3,
    _candidate_perception,
)
from labcourt.contracts.detections import BBoxXYXY, Detection
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.m6_replay_locked import M6LockedDetectionInput
from labcourt.contracts.m6_upgrade_execution_ledger import M6_UPGRADE_LEDGER_GENESIS_HASH
from labcourt.contracts.references import parse_frame_id
from labcourt.domain.m6_semantic_projection import M6ResolvedPerception
from labcourt.exceptions import ContractViolation
from labcourt.ports.m6_regression_execution_source_catalog import (
    M6StoredRegressionExecutionSourceCatalog,
)
from labcourt.ports.m6_upgrade_candidate_perception_materializer import (
    M6UpgradeCandidatePerceptionMaterializerError,
    M6UpgradeCandidatePerceptionMaterializerFailureCode,
)
from labcourt.ports.m6_upgrade_execution_ledger_v3 import (
    M6UpgradeExecutionLedgerV3Status,
    M6UpgradeExecutionResumeV3,
)
from tests.unit.test_m6_regression_execution_source_catalog import _execution_scope
from tests.unit.test_m6_regression_source_catalog import _sealed_source
from tests.unit.test_m6_upgrade_durable_sample_appender import _pending_resume

_FailureCode = M6UpgradeCandidatePerceptionMaterializerFailureCode


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class _Bundle:
    scope: object
    resume: M6UpgradeExecutionResumeV3
    stored: M6StoredRegressionExecutionSourceCatalog
    seal: object
    perception: M6ResolvedPerception


def _bundle() -> _Bundle:
    source_scope, source = _sealed_source()
    built = build_m6_regression_source_catalog(
        run_scopes=(source_scope,),
        sealed_sources=(source,),
    )
    document = built.execution_source_catalog_document
    stored = M6StoredRegressionExecutionSourceCatalog(
        source_catalog=built.execution_source_catalog,
        canonical_document=document,
        content_sha256=hashlib.sha256(document.encode("utf-8")).hexdigest(),
        size_bytes=len(document.encode("utf-8")),
    )
    scope = _execution_scope(stored.source_catalog, stored.content_sha256)
    closure = stored.source_catalog.entries[0].replay_input_closure
    camera_id, stream_id, frame_index = parse_frame_id(closure.frames[0].frame_id)
    frame = FrameRef(
        camera_id=camera_id,
        stream_id=stream_id,
        frame_index=frame_index,
        fps_num=30,
        fps_den=1,
        width=640,
        height=480,
        content_sha256=closure.frames[0].content_sha256,
    )
    resume = M6UpgradeExecutionResumeV3(
        status=M6UpgradeExecutionLedgerV3Status.READY_FOR_OBSERVATION,
        execution_scope=scope,
        committed_sample_count=0,
        ledger_head_hash=M6_UPGRADE_LEDGER_GENESIS_HASH,
        next_execution_entry=scope.execution_dataset.entries[0],
    )
    return _Bundle(
        scope=scope,
        resume=resume,
        stored=stored,
        seal=source.source_seal,
        perception=M6ResolvedPerception(frames=(frame,)),
    )


class _Ledger:
    def __init__(self, value: object, log: list[str]) -> None:
        self.value = value
        self.log = log

    def resume(self, *_identities: str) -> object:
        self.log.append("resume")
        return self.value


class _Catalogs:
    def __init__(self, value: object, log: list[str]) -> None:
        self.value = value
        self.log = log

    def load(self, *_identities: str) -> object:
        self.log.append("catalog")
        return self.value


class _Seals:
    def __init__(self, value: object, log: list[str]) -> None:
        self.value = value
        self.log = log

    def load_source_seal(self, _closure: object) -> object:
        self.log.append("seal")
        if isinstance(self.value, Exception):
            raise self.value
        return self.value


class _Source:
    def __init__(self, value: object, log: list[str]) -> None:
        self.value = value
        self.log = log

    def assemble(self, _closure: object) -> object:
        self.log.append("source")
        if isinstance(self.value, Exception):
            raise self.value
        return self.value


class _Writer:
    def __init__(self, manifest: object, log: list[str], *, conflict: bool = False) -> None:
        self.manifest = manifest
        self.log = log
        self.conflict = conflict
        self.frames: list[FrameRef] = []
        self.detections: list[Detection] = []

    def load_run_manifest(self, _run_id: str) -> object:
        self.log.append("manifest")
        return self.manifest

    def register_frame(self, _run_id: str, frame: FrameRef) -> None:
        self.log.append("frame")
        if self.conflict:
            raise ContractViolation("private conflicting frame body")
        self.frames.append(frame)

    def register_detection(self, _run_id: str, detection: Detection) -> None:
        self.log.append("detection")
        self.detections.append(detection)


def _service(
    bundle: _Bundle,
    *,
    resume: object | None = None,
    seal: object | None = None,
    source: object | None = None,
    manifest: object | None = None,
    conflict: bool = False,
) -> tuple[M6PrecomputedCandidatePerceptionMaterializerV3, _Writer, list[str]]:
    log: list[str] = []
    selected_manifest = (
        bundle.scope.candidate_manifest if manifest is None else manifest  # type: ignore[attr-defined]
    )
    writer = _Writer(selected_manifest, log, conflict=conflict)
    return (
        M6PrecomputedCandidatePerceptionMaterializerV3(
            ledger_repository=_Ledger(bundle.resume if resume is None else resume, log),  # type: ignore[arg-type]
            source_catalog_provider=_Catalogs(bundle.stored, log),  # type: ignore[arg-type]
            source_seal_provider=_Seals(bundle.seal if seal is None else seal, log),  # type: ignore[arg-type]
            source_perception_reader=_Source(
                bundle.perception if source is None else source,
                log,
            ),  # type: ignore[arg-type]
            candidate_perception_writer=writer,  # type: ignore[arg-type]
        ),
        writer,
        log,
    )


def _call(
    service: M6PrecomputedCandidatePerceptionMaterializerV3,
    bundle: _Bundle,
) -> M6ResolvedPerception:
    return service.materialize_next_perception(
        bundle.scope.candidate_run_id,  # type: ignore[attr-defined]
        bundle.scope.execution_scope_authority_id,  # type: ignore[attr-defined]
    )


def _assert_failure(
    service: M6PrecomputedCandidatePerceptionMaterializerV3,
    bundle: _Bundle,
    expected: _FailureCode,
) -> M6UpgradeCandidatePerceptionMaterializerError:
    with pytest.raises(M6UpgradeCandidatePerceptionMaterializerError) as raised:
        _call(service, bundle)
    assert raised.value.reason_code == expected
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    return raised.value


def test_materializes_exact_frame_after_catalog_seal_and_source_preflight() -> None:
    bundle = _bundle()
    service, writer, log = _service(bundle)

    observed = _call(service, bundle)

    assert observed == bundle.perception
    assert writer.frames == list(bundle.perception.frames)
    assert writer.detections == []
    assert log == ["resume", "catalog", "seal", "source", "manifest", "frame"]


def test_non_observation_state_short_circuits_before_source_or_candidate_access() -> None:
    bundle = _bundle()
    foreign_pending = _pending_resume(0, M6UpgradeExecutionLedgerV3Status.READY_FOR_LEDGER_APPEND)
    service, writer, log = _service(bundle, resume=foreign_pending)

    with pytest.raises(M6UpgradeCandidatePerceptionMaterializerError) as raised:
        service.materialize_next_perception(
            foreign_pending.execution_scope.candidate_run_id,
            foreign_pending.execution_scope.execution_scope_authority_id,
        )

    assert raised.value.reason_code == _FailureCode.EXECUTION_STATE_MISMATCH
    assert log == ["resume"]
    assert writer.frames == []


def test_source_seal_source_perception_manifest_and_write_conflicts_fail_closed() -> None:
    bundle = _bundle()
    wrong_manifest = bundle.scope.candidate_manifest.model_copy(  # type: ignore[attr-defined]
        update={"code_commit": "different-commit"}
    )
    cases = (
        ({"seal": RuntimeError("private seal path")}, _FailureCode.SOURCE_SEAL_REJECTED),
        (
            {"source": RuntimeError("private source database")},
            _FailureCode.SOURCE_PERCEPTION_REJECTED,
        ),
        (
            {"manifest": wrong_manifest},
            _FailureCode.CANDIDATE_MANIFEST_MISMATCH,
        ),
        ({"conflict": True}, _FailureCode.IDENTITY_CONFLICT),
    )
    for kwargs, expected in cases:
        service, writer, _log = _service(bundle, **kwargs)  # type: ignore[arg-type]
        error = _assert_failure(service, bundle, expected)
        assert "private" not in str(error)
        assert writer.detections == []


def test_source_detection_is_rebound_to_candidate_precomputed_detector_only() -> None:
    bundle = _bundle()
    source_frame = bundle.perception.frames[0]
    source_detector = _sha("source-detector")
    candidate_detector = _sha("candidate-detector")
    detection = Detection(
        detection_id="materialized-detection",
        frame_id=source_frame.frame_id,
        label="person",
        bbox=BBoxXYXY(x1=0, y1=0, x2=1, y2=1),
        score=0.75,
        model_manifest_id=source_detector,
    )
    closure = bundle.stored.source_catalog.entries[0].replay_input_closure.model_copy(
        update={
            "detections": (
                M6LockedDetectionInput(
                    detection_id=detection.detection_id,
                    frame_id=detection.frame_id,
                    document_sha256=_sha("source-detection-document"),
                    model_manifest_id=source_detector,
                ),
            )
        }
    )

    candidate = _candidate_perception(
        closure,
        M6ResolvedPerception(frames=(source_frame,), detections=(detection,)),
        candidate_detector,
    )

    assert len(candidate.detections) == 1
    rebound = candidate.detections[0]
    assert rebound.model_manifest_id == candidate_detector
    assert rebound.model_dump(exclude={"model_manifest_id"}) == detection.model_dump(
        exclude={"model_manifest_id"}
    )


def test_invalid_public_identity_never_touches_a_dependency() -> None:
    bundle = _bundle()
    service, writer, log = _service(bundle)

    with pytest.raises(M6UpgradeCandidatePerceptionMaterializerError) as raised:
        service.materialize_next_perception("", "not-a-scope")

    assert raised.value.reason_code == _FailureCode.INVALID_ARGUMENT
    assert log == []
    assert writer.frames == []

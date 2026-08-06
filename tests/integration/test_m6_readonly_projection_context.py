from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest

from labcourt.adapters.storage._m6_snapshot_identity import (
    capture_m6_readonly_snapshot_identity,
)
from labcourt.adapters.storage.readonly_m6_acquisition_authority import (
    ReadonlyM6AcquisitionAuthorityRepository,
)
from labcourt.adapters.storage.readonly_m6_embeddings import (
    ReadonlyM6EmbeddingAuthorityRepository,
)
from labcourt.adapters.storage.readonly_m6_hearing_model_calls import (
    ReadonlyM6HearingModelCallAuthorityRepository,
)
from labcourt.adapters.storage.readonly_m6_historical_retrieval import (
    ReadonlyM6HistoricalRetrievalCutRepository,
)
from labcourt.adapters.storage.readonly_m6_model_calls import (
    ReadonlyM6ModelCallAuthorityRepository,
)
from labcourt.adapters.storage.readonly_m6_perception import (
    ReadonlyM6PerceptionAuthorityRepository,
)
from labcourt.adapters.storage.readonly_m6_projection_context import (
    ReadonlyM6SqliteProjectionAssemblyRepository,
)
from labcourt.adapters.storage.readonly_m6_replay_locked_source import (
    ReadonlyM6ReplayLockedSourceProjectionRepository,
)
from labcourt.adapters.storage.readonly_sqlite import readonly_sqlite_snapshot
from labcourt.application.m6_hearing_model_call_authority import (
    assemble_m6_locked_hearing_model_calls,
)
from labcourt.application.m6_historical_retrieval_cut import (
    assemble_m6_historical_retrieval_cut,
)
from labcourt.application.m6_model_call_authority import (
    assemble_m6_locked_screening_model_calls,
)
from labcourt.application.m6_replay_locked_source_determinism import (
    prove_m6_replay_locked_source_determinism,
)
from labcourt.application.m6_verified_projection_context import (
    M6SqliteProjectionAssemblyError,
    M6SqliteProjectionAssemblyErrorCode,
)
from labcourt.contracts.cases import Case
from labcourt.contracts.config import AppConfig
from labcourt.contracts.detections import Detection
from labcourt.contracts.enums import ReproducibilityMode
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.m6_regression import (
    M6RegressionExecutionEntry,
    M6RegressionPolicyAuthority,
    M6RegressionRunCommand,
)
from labcourt.contracts.m6_replay_locked import (
    M6LockedDetectionInput,
    M6LockedFrameInput,
    M6ReplayInputClosureAuthority,
)
from tests.integration.test_m5_precedent_exposure_sqlite import (
    _degraded,
    _runtime,
)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _source_fingerprint(root: Path) -> dict[str, tuple[int, str]]:
    return {
        path.name: (path.stat().st_size, hashlib.sha256(path.read_bytes()).hexdigest())
        for path in root.iterdir()
        if path.is_file()
    }


def _base_closure(database: Path, run_id: str) -> tuple[Case, M6ReplayInputClosureAuthority]:
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        case_row = connection.execute(
            """
            SELECT revision, case_json, document_sha256
            FROM case_versions
            WHERE run_id = ?
            ORDER BY revision DESC
            LIMIT 1
            """,
            (run_id,),
        ).fetchone()
        manifest_row = connection.execute(
            """
            SELECT manifest.document_sha256
            FROM runs AS run
            JOIN run_manifests AS manifest
              ON manifest.manifest_id = run.manifest_id
            WHERE run.run_id = ?
            """,
            (run_id,),
        ).fetchone()
        frame_rows = connection.execute(
            """
            SELECT document_json, document_sha256
            FROM frames
            WHERE run_id = ?
            """,
            (run_id,),
        ).fetchall()
        detection_rows = connection.execute(
            """
            SELECT document_json, document_sha256
            FROM detections
            WHERE run_id = ?
            """,
            (run_id,),
        ).fetchall()
    assert case_row is not None
    assert manifest_row is not None
    source_case = Case.model_validate_json(str(case_row["case_json"]))
    frames = tuple(
        (FrameRef.model_validate_json(str(row["document_json"])), str(row["document_sha256"]))
        for row in frame_rows
    )
    detections = tuple(
        (
            Detection.model_validate_json(str(row["document_json"])),
            str(row["document_sha256"]),
        )
        for row in detection_rows
    )
    assert all(frame.content_sha256 is not None for frame, _document_sha256 in frames)
    closure = M6ReplayInputClosureAuthority(
        sample_id="sample-real-sqlite-projection",
        source_run_id=source_case.run_id,
        source_case_id=source_case.case_id,
        source_case_revision=int(case_row["revision"]),
        source_case_document_sha256=str(case_row["document_sha256"]),
        source_manifest_id=source_case.manifest_id,
        source_manifest_document_sha256=str(manifest_row["document_sha256"]),
        input_authority_id=_sha("unresolved-real-input-authority"),
        input_authority_document_sha256=_sha("unresolved-real-input-document"),
        source_validation_report_id=_sha("unresolved-real-validation-report"),
        source_validation_report_document_sha256=_sha("unresolved-real-validation-report-document"),
        frames=tuple(
            sorted(
                (
                    M6LockedFrameInput(
                        frame_id=frame.frame_id,
                        document_sha256=document_sha256,
                        content_sha256=frame.content_sha256,
                    )
                    for frame, document_sha256 in frames
                ),
                key=lambda item: item.sort_key,
            )
        ),
        detections=tuple(
            sorted(
                (
                    M6LockedDetectionInput(
                        detection_id=detection.detection_id,
                        frame_id=detection.frame_id,
                        document_sha256=document_sha256,
                        model_manifest_id=detection.model_manifest_id,
                    )
                    for detection, document_sha256 in detections
                ),
                key=lambda item: item.sort_key,
            )
        ),
    )
    return source_case, closure


def _exact_closure(
    snapshot: Path,
    *,
    source_case: Case,
    base: M6ReplayInputClosureAuthority,
    config: AppConfig,
) -> M6ReplayInputClosureAuthority:
    m3 = ReadonlyM6ModelCallAuthorityRepository(snapshot).load_validated_snapshot(source_case)
    m4 = ReadonlyM6HearingModelCallAuthorityRepository(snapshot).load_authority(source_case)
    model_calls = tuple(
        sorted(
            (
                *assemble_m6_locked_screening_model_calls(
                    source_case=source_case,
                    snapshot=m3,
                ),
                *assemble_m6_locked_hearing_model_calls(
                    source_case=source_case,
                    snapshot=m4,
                ),
            ),
            key=lambda item: item.sort_key,
        )
    )
    historical_repository = ReadonlyM6HistoricalRetrievalCutRepository(
        snapshot,
        config=config,
    )
    historical = historical_repository.load_validated_snapshots(source_case.run_id)
    cut = assemble_m6_historical_retrieval_cut(
        source_case=source_case,
        snapshots=historical,
    )
    return M6ReplayInputClosureAuthority.model_validate(
        {
            **base.model_dump(mode="json", exclude_computed_fields=True),
            "model_calls": [item.model_dump(mode="json") for item in model_calls],
            "historical_cut": cut.model_dump(mode="json"),
        }
    )


def test_facade_assembles_six_real_readonly_scans_without_sidecars_or_convenience_calls(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    runtime.committer.commit(_degraded(runtime))
    source_case, base = _base_closure(runtime.database, runtime.prepared.session.run_id)
    source_before = _source_fingerprint(tmp_path)

    with readonly_sqlite_snapshot(runtime.database) as snapshot:
        closure = _exact_closure(
            snapshot,
            source_case=source_case,
            base=base,
            config=runtime.config,
        )
        private_before = {path.name for path in snapshot.parent.iterdir()}
        with (
            patch.object(
                ReadonlyM6PerceptionAuthorityRepository,
                "assemble",
                side_effect=AssertionError("perception convenience assemble called"),
            ),
            patch.object(
                ReadonlyM6ModelCallAuthorityRepository,
                "assemble",
                side_effect=AssertionError("M3 convenience assemble called"),
            ),
            patch.object(
                ReadonlyM6HearingModelCallAuthorityRepository,
                "assemble",
                side_effect=AssertionError("M4 convenience assemble called"),
            ),
            patch.object(
                ReadonlyM6HistoricalRetrievalCutRepository,
                "assemble",
                side_effect=AssertionError("historical convenience assemble called"),
            ),
            patch.object(
                ReadonlyM6AcquisitionAuthorityRepository,
                "resolve",
                side_effect=AssertionError("acquisition convenience resolve called"),
            ),
            patch.object(
                ReadonlyM6EmbeddingAuthorityRepository,
                "assemble",
                side_effect=AssertionError("embedding convenience assemble called"),
            ),
        ):
            repository = ReadonlyM6SqliteProjectionAssemblyRepository(
                snapshot,
                config=runtime.config,
            )
            result = repository.assemble(closure)
            execution_entry = M6RegressionExecutionEntry(
                sample_id=closure.sample_id,
                input_authority_id=closure.input_authority_id,
                input_authority_document_sha256=closure.input_authority_document_sha256,
                replay_input_closure_authority_id=closure.replay_input_closure_authority_id,
                replay_input_closure_document_sha256=(closure.replay_input_closure_document_sha256),
            )
            command = M6RegressionRunCommand(
                mode=ReproducibilityMode.REPLAY_LOCKED,
                execution_dataset_snapshot_id=_sha("real-locked-execution-dataset"),
                baseline_manifest_id=closure.source_manifest_id,
                candidate_manifest_id=closure.source_manifest_id,
                policy_authority=M6RegressionPolicyAuthority(
                    config_sha256=runtime.config.config_sha256,
                    policy_version="m6-real-locked-source-determinism-v1",
                    maximum_machine_flip_rate=0.05,
                    gold_set_max_accuracy_drop=0.0,
                ),
            )
            proof = prove_m6_replay_locked_source_determinism(
                command=command,
                execution_entry=execution_entry,
                closure=closure,
                candidate_run_id="m6-locked-candidate-run",
                execution_component_manifest_id=_sha("m6-locked-source-prover"),
                projection_provider=ReadonlyM6ReplayLockedSourceProjectionRepository(
                    snapshot,
                    config=runtime.config,
                ),
            )
        private_after = {path.name for path in snapshot.parent.iterdir()}

    assert private_before == private_after == {"labcourt.sqlite3", "raw"}
    assert _source_fingerprint(tmp_path) == source_before
    assert result.closure == closure
    assert result.model_calls == closure.model_calls
    assert result.embeddings == ()
    assert result.case_replay_snapshot.source_run_id == source_case.run_id
    assert result.projection_context.case == source_case
    assert len(result.projection_context.retrieval_cycles) == 1
    assert not hasattr(result, "verified")
    assert proof.source_run_id == source_case.run_id
    assert proof.candidate_run_id == "m6-locked-candidate-run"
    assert proof.first_source_snapshot_id == proof.second_source_snapshot_id
    assert proof.first_semantic_case_hash == proof.second_semantic_case_hash
    assert proof.first_source_snapshot_id == result.case_replay_snapshot.snapshot_id
    assert proof.first_semantic_case_hash == result.case_replay_snapshot.semantic_case_hash


def test_facade_rejects_outer_snapshot_change_even_when_component_reads_succeed(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    runtime.committer.commit(_degraded(runtime))
    source_case, base = _base_closure(runtime.database, runtime.prepared.session.run_id)

    with readonly_sqlite_snapshot(runtime.database) as snapshot:
        closure = _exact_closure(
            snapshot,
            source_case=source_case,
            base=base,
            config=runtime.config,
        )
        before = capture_m6_readonly_snapshot_identity(snapshot)
        changed = replace(before, modified_ns=before.modified_ns + 1)
        with (
            patch(
                "labcourt.adapters.storage.readonly_m6_projection_context."
                "capture_m6_readonly_snapshot_identity",
                side_effect=(before, changed),
            ),
            pytest.raises(M6SqliteProjectionAssemblyError) as raised,
        ):
            ReadonlyM6SqliteProjectionAssemblyRepository(
                snapshot,
                config=runtime.config,
            ).assemble(closure)

    assert raised.value.code == M6SqliteProjectionAssemblyErrorCode.SNAPSHOT_CHANGED

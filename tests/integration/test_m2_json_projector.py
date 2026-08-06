import os
import sqlite3
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from threading import Event

import pytest

from labcourt.adapters.storage.json_projector import JsonProjector, ProjectionFailure
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.adapters.storage.sqlite_repository import (
    MigrationRunner,
    RepositoryIntegrityError,
    SQLiteEvidenceRepository,
)
from labcourt.contracts.audit import AuditEntry
from labcourt.contracts.canonical import canonical_bytes
from labcourt.contracts.detections import Detection
from labcourt.contracts.enums import (
    ArtifactKind,
    CropSource,
    MediaAccess,
    MediaAvailability,
    MediaType,
    PrivacyPolicy,
    PrivacyReasonCode,
    VerificationStatus,
)
from labcourt.contracts.events import CandidateEvent, derive_case_id
from labcourt.contracts.evidence import (
    Crop,
    EvidencePack,
    EvidencePackDraft,
    PrivacyReceipt,
    TrackSummary,
)
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.projection_generation import ProjectionCurrentPointer
from labcourt.contracts.storage import ArtifactRef, ArtifactVerification, ClosureReport
from labcourt.exceptions import PathBoundaryViolation
from labcourt.ports.evidence_repository import AuditHead, CaseSnapshot

FIXTURES = Path(__file__).parents[1] / "fixtures" / "m2"
RUN_ID = "run-01"
BUSY_TIMEOUT_MS = 5_000
RECORDED_AT = datetime(2026, 7, 27, 12, 34, 56, 123456, tzinfo=UTC)


class _Verifier:
    def verify_crop(self, crop: Crop) -> ArtifactVerification:
        return ArtifactVerification(
            artifact_ref=ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop.crop_id),
            status=VerificationStatus.VERIFIED,
            availability=crop.availability,
            media_type=crop.media_type,
            expected_source_pixel_sha256=crop.source_media_sha256,
            actual_source_pixel_sha256=crop.source_media_sha256,
            expected_output_pixel_sha256=crop.pixel_sha256,
            actual_output_pixel_sha256=crop.pixel_sha256,
            expected_media_sha256=crop.media_sha256,
            actual_media_sha256=crop.media_sha256,
            expected_width=crop.output_width,
            actual_width=crop.output_width,
            expected_height=crop.output_height,
            actual_height=crop.output_height,
            expected_size_bytes=crop.size_bytes,
            actual_size_bytes=crop.size_bytes,
        )

    def reference_exists(self, run_id: str, ref: ArtifactRef) -> bool:
        del run_id, ref
        return False


def _clock() -> datetime:
    return RECORDED_AT


def _create_directory_link(link: Path, target: Path) -> None:
    if os.name == "nt":
        result = subprocess.run(
            ["cmd", "/d", "/c", "mklink", "/J", str(link), str(target)],
            capture_output=True,
            check=False,
            text=True,
        )
        if result.returncode != 0:
            pytest.skip("Windows junction creation is unavailable")
        return
    try:
        os.symlink(target, link, target_is_directory=True)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"directory symlink creation is unavailable: {error.__class__.__name__}")


def _remove_directory_link(link: Path) -> None:
    if os.name == "nt":
        os.rmdir(link)
    else:
        link.unlink()


def _read_contract(name: str, contract: type[RunManifest] | type[CandidateEvent]) -> object:
    return contract.model_validate_json((FIXTURES / name).read_text(encoding="utf-8"))


def _manifest() -> RunManifest:
    return RunManifest.model_validate(_read_contract("run-manifest-fake.json", RunManifest))


def _event(name: str = "candidate-event-presence.json") -> CandidateEvent:
    return CandidateEvent.model_validate(_read_contract(name, CandidateEvent))


def _frame() -> FrameRef:
    return FrameRef(
        camera_id="cam-01",
        stream_id="demo-ntsc",
        frame_index=90,
        fps_num=30,
        fps_den=1,
        width=640,
        height=480,
        content_sha256="a" * 64,
    )


def _detection() -> Detection:
    frame = _frame()
    return Detection(
        detection_id="det-bottle-090",
        frame_id=frame.frame_id,
        label="reagent_bottle",
        bbox=BBoxXYXY(x1=10, y1=20, x2=110, y2=220),
        score=0.92,
        track_ref=_event().primary_track_ref,
        model_manifest_id=_manifest().models["detector"].model_manifest_id,
    )


def _pack() -> EvidencePack:
    event = _event()
    frame = _frame()
    frame_ref = ArtifactRef(kind=ArtifactKind.FRAME, artifact_id=frame.frame_id)
    detection_ref = ArtifactRef(
        kind=ArtifactKind.DETECTION,
        artifact_id="det-bottle-090",
    )
    source_refs = tuple(sorted((detection_ref, frame_ref), key=lambda ref: ref.sort_key))
    crop = Crop(
        frame_id=frame.frame_id,
        source=CropSource.DETECTION_FOCUS,
        bbox=BBoxXYXY(x1=10, y1=20, x2=110, y2=220),
        source_refs=source_refs,
        local_path="frames/focus.png",
        availability=MediaAvailability.AVAILABLE,
        source_media_sha256="a" * 64,
        pixel_sha256="b" * 64,
        media_sha256="c" * 64,
        output_width=100,
        output_height=200,
        size_bytes=512,
        media_type=MediaType.IMAGE_PNG,
        encoding_version="png-v1",
        privacy_receipt=PrivacyReceipt(
            policy=PrivacyPolicy.FULL_REDACTION,
            transform_version="ppe-redaction-v1",
            media_access=MediaAccess.LOCAL_ONLY,
            reason_code=PrivacyReasonCode.POLICY_LOCAL_ONLY,
            input_refs=source_refs,
            fill_rgb=(0, 0, 0),
        ),
        primary_track_ref=event.primary_track_ref,
    )
    draft = EvidencePackDraft(
        run_id=RUN_ID,
        case_id=derive_case_id(event.event_id),
        version=1,
        complete=True,
        event=event,
        key_frame_ids=(frame.frame_id,),
        focus_crops=(crop,),
        objective_facts=event.objective_facts,
        track_summary=TrackSummary(
            primary_track_ref=event.primary_track_ref,
            start_frame=event.start_frame,
            end_frame_exclusive=event.end_frame_exclusive,
            observed_frame_count=event.end_frame_exclusive - event.start_frame,
        ),
        confirmation_record=event.confirmation,
        manifest_id=event.manifest_id,
    )
    closure = ClosureReport(
        run_id=RUN_ID,
        root_ref=ArtifactRef(kind=ArtifactKind.CASE, artifact_id=draft.case_id),
        manifest_id=draft.manifest_id,
        input_sha256=draft.closure_input_sha256,
        checked_refs=draft.expected_closure_refs(),
    )
    return EvidencePack.model_validate(
        {
            **draft.model_dump(mode="json", exclude_computed_fields=True),
            "closure_report": closure.model_dump(mode="json"),
        }
    )


def _published_repository(tmp_path: Path) -> tuple[Path, SQLiteEvidenceRepository, EvidencePack]:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, clock=_clock).apply_all()
    repository = SQLiteEvidenceRepository(
        database,
        BUSY_TIMEOUT_MS,
        verifier=_Verifier(),
        clock=_clock,
    )
    repository.register_run(RUN_ID, _manifest())
    repository.register_frame(RUN_ID, _frame())
    repository.register_detection(RUN_ID, _detection())
    case = repository.create_or_get_case(RUN_ID, _event())
    pack = repository.publish_pack(RUN_ID, case.revision, _pack()).pack
    return database, repository, pack


def test_projector_rebuilds_canonical_utf8_lf_bytes_deterministically(
    tmp_path: Path,
) -> None:
    _, repository, pack = _published_repository(tmp_path)
    output_root = tmp_path / "projections"
    projector = JsonProjector(repository, output_root)

    result = projector.project_run(RUN_ID)
    case = repository.load_case(RUN_ID, derive_case_id(_event().event_id)).case
    audit_entries = repository.list_audit_entries(RUN_ID)
    assert (
        result.events_path.read_bytes() == canonical_bytes(_event().model_dump(mode="json")) + b"\n"
    )
    assert result.audit_path.read_bytes() == b"".join(
        canonical_bytes(entry.model_dump(mode="json")) + b"\n" for entry in audit_entries
    )
    assert result.case_paths[0].read_bytes() == canonical_bytes(case.model_dump(mode="json"))
    assert result.pack_paths[0].read_bytes() == canonical_bytes(pack.model_dump(mode="json"))
    assert b"\r\n" not in result.events_path.read_bytes()
    assert not result.events_path.read_bytes().startswith(b"\xef\xbb\xbf")
    assert not tuple(result.run_directory.rglob(".publish.lock"))

    first_bytes = {
        path.relative_to(result.run_directory): path.read_bytes()
        for path in result.run_directory.rglob("*.json*")
    }
    rebuilt = projector.project_run(RUN_ID)
    second_bytes = {
        path.relative_to(rebuilt.run_directory): path.read_bytes()
        for path in rebuilt.run_directory.rglob("*.json*")
    }
    assert second_bytes == first_bytes


def test_projector_caps_every_authority_sized_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, repository, _ = _published_repository(tmp_path)
    output_root = tmp_path / "projections"
    original_read = SecureWorkspace.read_verified
    reads: list[tuple[str, int | None]] = []

    def bounded_read(
        self: SecureWorkspace,
        relative_path: str,
        expected_sha256: str | None = None,
        *,
        max_bytes: int | None = None,
    ) -> object:
        reads.append((relative_path, max_bytes))
        return original_read(
            self,
            relative_path,
            expected_sha256,
            max_bytes=max_bytes,
        )

    monkeypatch.setattr(SecureWorkspace, "read_verified", bounded_read)
    first = JsonProjector(repository, output_root).project_run(RUN_ID)
    JsonProjector(repository, output_root).project_run(RUN_ID)

    assert reads
    assert all(limit is not None for _, limit in reads)
    pointer_limits = [
        limit for path, limit in reads if path == f"{RUN_ID}/projections/current.json"
    ]
    assert pointer_limits
    assert set(pointer_limits) == {4 * 1024}
    for path, limit in reads:
        if "/generations/" in path:
            assert limit == (output_root / Path(path)).stat().st_size
    assert first.current_pointer_path.is_file()


def test_projector_rejects_oversized_existing_current_before_json_parsing(
    tmp_path: Path,
) -> None:
    _, repository, _ = _published_repository(tmp_path)
    output_root = tmp_path / "projections"
    result = JsonProjector(repository, output_root).project_run(RUN_ID)
    result.current_pointer_path.write_bytes(b"x" * (4 * 1024 + 1))

    with pytest.raises(ProjectionFailure, match="secure projection workspace") as failure:
        JsonProjector(repository, output_root).project_run(RUN_ID)

    assert isinstance(failure.value.__cause__, PathBoundaryViolation)
    assert failure.value.__cause__.reason_code == "FILE_TOO_LARGE"


def test_projector_fault_keeps_previous_complete_generation_current(tmp_path: Path) -> None:
    _, repository, _ = _published_repository(tmp_path)
    output_root = tmp_path / "projections"
    original = JsonProjector(repository, output_root).project_run(RUN_ID)
    old_current = original.current_pointer_path.read_bytes()
    old_generation = {
        path.relative_to(original.run_directory): path.read_bytes()
        for path in original.run_directory.rglob("*")
        if path.is_file()
    }
    repository.create_or_get_case(
        RUN_ID,
        _event("candidate-event-absence-strict.json"),
    )

    def fail_after_new_events(phase: str) -> None:
        if phase == "after_generation_events":
            raise RuntimeError("projector crash")

    crashing = JsonProjector(repository, output_root, fail_after_new_events)
    with pytest.raises(ProjectionFailure, match="generation failed"):
        crashing.project_run(RUN_ID)

    assert original.current_pointer_path.read_bytes() == old_current
    assert {
        path.relative_to(original.run_directory): path.read_bytes()
        for path in original.run_directory.rglob("*")
        if path.is_file()
    } == old_generation


@pytest.mark.parametrize(
    "fault_point",
    (
        "events",
        "audit",
        "case",
        "pack",
        "before_manifest_publish",
        "after_manifest_publish",
        "before_current_publish",
    ),
)
def test_generation_faults_before_commit_never_replace_current(
    tmp_path: Path,
    fault_point: str,
) -> None:
    _, repository, _ = _published_repository(tmp_path)
    output_root = tmp_path / "projections"
    original = JsonProjector(repository, output_root).project_run(RUN_ID)
    old_current = original.current_pointer_path.read_bytes()
    old_generation = _file_bytes(original.run_directory)
    repository.create_or_get_case(
        RUN_ID,
        _event("candidate-event-absence-strict.json"),
    )

    def fail(phase: str) -> None:
        matched = (
            phase == f"after_generation_{fault_point}"
            or (fault_point == "case" and phase.startswith("after_generation_case:"))
            or (fault_point == "pack" and phase.startswith("after_generation_pack:"))
            or phase == fault_point
        )
        if matched:
            raise RuntimeError("simulated pre-commit crash")

    with pytest.raises(ProjectionFailure):
        JsonProjector(repository, output_root, fail).project_run(RUN_ID)

    assert original.current_pointer_path.read_bytes() == old_current
    assert _file_bytes(original.run_directory) == old_generation


def test_first_generation_failure_does_not_publish_false_current(tmp_path: Path) -> None:
    _, repository, _ = _published_repository(tmp_path)
    output_root = tmp_path / "projections"

    def fail(phase: str) -> None:
        if phase == "after_manifest_publish":
            raise RuntimeError("simulated first-release crash")

    with pytest.raises(ProjectionFailure):
        JsonProjector(repository, output_root, fail).project_run(RUN_ID)
    assert not (output_root / RUN_ID / "projections" / "current.json").exists()


def test_fault_after_current_commit_is_verified_success_and_base_exception_is_replayable(
    tmp_path: Path,
) -> None:
    _, repository, _ = _published_repository(tmp_path)
    output_root = tmp_path / "projections"
    original = JsonProjector(repository, output_root).project_run(RUN_ID)
    old_current = original.current_pointer_path.read_bytes()
    repository.create_or_get_case(
        RUN_ID,
        _event("candidate-event-absence-strict.json"),
    )

    def ordinary_fault(phase: str) -> None:
        if phase == "after_current_publish":
            raise RuntimeError("lost acknowledgement")

    committed = JsonProjector(repository, output_root, ordinary_fault).project_run(RUN_ID)
    assert committed.current_pointer_path.read_bytes() != old_current
    assert committed.events_path.is_file()


def test_replace_receipt_loss_after_atomic_current_commit_is_verified_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, repository, _ = _published_repository(tmp_path)
    output_root = tmp_path / "projections"
    original_replace = SecureWorkspace.replace_verified
    receipt_lost = False

    def replace_then_lose_receipt(
        self: SecureWorkspace,
        temporary_relative: str,
        final_relative: str,
        expected_sha256: str,
    ) -> object:
        nonlocal receipt_lost
        result = original_replace(
            self,
            temporary_relative,
            final_relative,
            expected_sha256,
        )
        if final_relative.endswith("/projections/current.json") and not receipt_lost:
            receipt_lost = True
            raise PathBoundaryViolation("SIMULATED_REPLACE_RECEIPT_LOSS", final_relative)
        return result

    monkeypatch.setattr(SecureWorkspace, "replace_verified", replace_then_lose_receipt)

    committed = JsonProjector(repository, output_root).project_run(RUN_ID)

    assert receipt_lost is True
    assert committed.current_pointer_path.is_file()
    assert committed.events_path.is_file()


def test_base_exception_after_commit_is_not_swallowed_and_retry_observes_commit(
    tmp_path: Path,
) -> None:
    _, repository, _ = _published_repository(tmp_path)
    output_root = tmp_path / "projections"

    def process_crash(phase: str) -> None:
        if phase == "after_current_publish":
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        JsonProjector(repository, output_root, process_crash).project_run(RUN_ID)
    current = output_root / RUN_ID / "projections" / "current.json"
    committed_bytes = current.read_bytes()

    replayed = JsonProjector(repository, output_root).project_run(RUN_ID)
    assert replayed.current_pointer_path.read_bytes() == committed_bytes


def test_concurrent_same_generation_projection_is_idempotent(tmp_path: Path) -> None:
    _, repository, _ = _published_repository(tmp_path)
    output_root = tmp_path / "projections"

    def publish() -> str:
        return JsonProjector(repository, output_root).project_run(RUN_ID).generation_id

    with ThreadPoolExecutor(max_workers=2) as executor:
        generation_ids = tuple(executor.map(lambda _item: publish(), range(2)))

    assert generation_ids[0] == generation_ids[1]
    pointer = output_root / RUN_ID / "projections" / "current.json"
    assert pointer.is_file()


def test_short_publish_lock_contention_waits_then_both_writers_succeed(
    tmp_path: Path,
) -> None:
    _, repository, _ = _published_repository(tmp_path)
    output_root = tmp_path / "projections"
    first_holds_lock = Event()
    release_first = Event()
    second_ready = Event()

    def hold_first(phase: str) -> None:
        if phase == "before_current_publish":
            first_holds_lock.set()
            assert release_first.wait(timeout=10)

    def observe_second(phase: str) -> None:
        if phase == "before_publish_lock":
            second_ready.set()

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(
            JsonProjector(repository, output_root, hold_first).project_run,
            RUN_ID,
        )
        assert first_holds_lock.wait(timeout=10)
        second = executor.submit(
            JsonProjector(repository, output_root, observe_second).project_run,
            RUN_ID,
        )
        assert second_ready.wait(timeout=10)
        release_first.set()
        first_result = first.result(timeout=10)
        second_result = second.result(timeout=10)

    assert first_result.generation_id == second_result.generation_id


def test_older_snapshot_cannot_publish_after_newer_head(tmp_path: Path) -> None:
    _, repository, _ = _published_repository(tmp_path)
    output_root = tmp_path / "projections"
    old_ready = Event()
    allow_old = Event()

    def pause_old(phase: str) -> None:
        if phase == "before_publish_lock":
            old_ready.set()
            assert allow_old.wait(timeout=10)

    def publish_old() -> object:
        return JsonProjector(repository, output_root, pause_old).project_run(RUN_ID)

    with ThreadPoolExecutor(max_workers=1) as executor:
        old_future = executor.submit(publish_old)
        assert old_ready.wait(timeout=10)
        repository.create_or_get_case(
            RUN_ID,
            _event("candidate-event-absence-strict.json"),
        )
        newer = JsonProjector(repository, output_root).project_run(RUN_ID)
        newer_current = newer.current_pointer_path.read_bytes()
        allow_old.set()
        with pytest.raises(ProjectionFailure, match="newer than the candidate"):
            old_future.result(timeout=10)

    assert newer.current_pointer_path.read_bytes() == newer_current


def test_same_sequence_different_audit_hash_current_fails_closed(tmp_path: Path) -> None:
    _, repository, _ = _published_repository(tmp_path)
    output_root = tmp_path / "projections"
    result = JsonProjector(repository, output_root).project_run(RUN_ID)
    pointer = ProjectionCurrentPointer.model_validate_json(result.current_pointer_path.read_bytes())
    forged = pointer.model_copy(update={"audit_head_hash": "f" * 64})
    result.current_pointer_path.write_bytes(canonical_bytes(forged.model_dump(mode="json")))

    with pytest.raises(ProjectionFailure, match="conflicts at the same audit head"):
        JsonProjector(repository, output_root).project_run(RUN_ID)


def test_current_pointer_from_another_run_fails_closed(tmp_path: Path) -> None:
    _, repository, _ = _published_repository(tmp_path)
    output_root = tmp_path / "projections"
    result = JsonProjector(repository, output_root).project_run(RUN_ID)
    pointer = ProjectionCurrentPointer.model_validate_json(result.current_pointer_path.read_bytes())
    forged = pointer.model_copy(
        update={
            "run_id": "other-run",
            "manifest_relative_path": pointer.manifest_relative_path.replace(
                f"{RUN_ID}/",
                "other-run/",
                1,
            ),
        }
    )
    result.current_pointer_path.write_bytes(canonical_bytes(forged.model_dump(mode="json")))

    with pytest.raises(ProjectionFailure, match="belongs to another run"):
        JsonProjector(repository, output_root).project_run(RUN_ID)


def _file_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def test_projector_rejects_noncanonical_target_and_projection_budget(tmp_path: Path) -> None:
    _, repository, _ = _published_repository(tmp_path)
    output_root = tmp_path / "projections"
    projector = JsonProjector(repository, output_root)

    with pytest.raises(ProjectionFailure, match="canonical run directory"):
        projector.project_run(RUN_ID, tmp_path / "outside")

    constrained = JsonProjector(
        repository,
        output_root,
        max_projection_bytes=8,
    )
    with pytest.raises(ProjectionFailure, match="secure projection workspace"):
        constrained.project_run(RUN_ID)
    assert not tuple((output_root / RUN_ID).glob(".*.tmp"))


def test_projector_rejects_hardlinked_formal_projection(tmp_path: Path) -> None:
    _, repository, _ = _published_repository(tmp_path)
    output_root = tmp_path / "projections"
    projector = JsonProjector(repository, output_root)
    result = projector.project_run(RUN_ID)
    outside = tmp_path / "outside-events.jsonl"
    outside.write_bytes(result.events_path.read_bytes())
    result.events_path.unlink()
    try:
        os.link(outside, result.events_path)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"hardlink creation is unavailable: {error.__class__.__name__}")

    with pytest.raises(ProjectionFailure, match="secure projection workspace"):
        projector.project_run(RUN_ID)

    assert result.events_path.samefile(outside)
    assert result.events_path.read_bytes() == outside.read_bytes()
    assert not tuple(result.run_directory.glob(".events.jsonl.*.tmp"))


def test_projector_detects_parent_swap_before_atomic_replace(tmp_path: Path) -> None:
    _, repository, _ = _published_repository(tmp_path)
    output_root = tmp_path / "projections"
    run_directory = output_root / RUN_ID
    detached = output_root / f"{RUN_ID}-detached"
    outside = tmp_path / "attacker-controlled"
    outside.mkdir()
    swapped = False

    def swap_parent(phase: str) -> None:
        nonlocal swapped
        if phase != "before_current_publish" or swapped:
            return
        run_directory.rename(detached)
        swapped = True
        _create_directory_link(run_directory, outside)

    projector = JsonProjector(repository, output_root, swap_parent)
    try:
        with pytest.raises(ProjectionFailure):
            projector.project_run(RUN_ID)
        assert not tuple(outside.iterdir())
    finally:
        if run_directory.exists() and swapped:
            _remove_directory_link(run_directory)
        if detached.exists():
            detached.rename(run_directory)


def test_projector_rejects_unsafe_case_pack_and_run_ids(tmp_path: Path) -> None:
    _, repository, _ = _published_repository(tmp_path)
    projector = JsonProjector(repository, tmp_path / "projections")

    with pytest.raises(ProjectionFailure, match="case_id"):
        projector.project_case(RUN_ID, "../case.json")
    with pytest.raises(ProjectionFailure, match="pack_id"):
        projector.project_pack(RUN_ID, "../pack.json")
    with pytest.raises(ValueError, match="anonymous ASCII"):
        projector.project_run("../run")


def test_projector_refuses_a_database_head_that_breaks_the_audit_chain(
    tmp_path: Path,
) -> None:
    database, repository, _ = _published_repository(tmp_path)
    connection = sqlite3.connect(database)
    try:
        connection.execute("DROP TRIGGER runs_monotonic_head_update")
        connection.execute("DROP TRIGGER runs_m6_audit_head_matches_entry")
        connection.execute(
            "UPDATE runs SET audit_head_hash = ? WHERE run_id = ?",
            ("f" * 64, RUN_ID),
        )
        connection.commit()
    finally:
        connection.close()

    output_root = tmp_path / "projections"
    projector = JsonProjector(repository, output_root)
    case_id = derive_case_id(_event().event_id)
    pack_id = repository.load_case(RUN_ID, case_id).case.evidence_packs[-1].pack_id
    for project in (
        lambda: projector.project_run(RUN_ID),
        lambda: projector.project_case(RUN_ID, case_id),
        lambda: projector.project_pack(RUN_ID, pack_id),
    ):
        with pytest.raises(ProjectionFailure, match="audit chain"):
            project()
    assert not (output_root / RUN_ID / "projections" / "current.json").exists()


def test_projector_retries_if_a_commit_splits_repository_reads(tmp_path: Path) -> None:
    _, repository, _ = _published_repository(tmp_path)

    class CommitDuringFirstRead:
        def __init__(self, backing: SQLiteEvidenceRepository) -> None:
            self.backing = backing
            self.injected = False

        def get_audit_head(self, run_id: str) -> AuditHead:
            return self.backing.get_audit_head(run_id)

        def list_events(self, run_id: str) -> tuple[CandidateEvent, ...]:
            events = self.backing.list_events(run_id)
            if not self.injected:
                self.injected = True
                self.backing.create_or_get_case(
                    run_id,
                    _event("candidate-event-absence-strict.json"),
                )
            return events

        def list_audit_entries(self, run_id: str) -> tuple[AuditEntry, ...]:
            return self.backing.list_audit_entries(run_id)

        def load_case(self, run_id: str, case_id: str) -> CaseSnapshot:
            return self.backing.load_case(run_id, case_id)

        def load_pack(self, run_id: str, pack_id: str) -> EvidencePack:
            return self.backing.load_pack(run_id, pack_id)

    result = JsonProjector(
        CommitDuringFirstRead(repository),
        tmp_path / "projections",
    ).project_run(RUN_ID)

    assert len(result.events_path.read_text(encoding="utf-8").splitlines()) == 2
    assert len(result.audit_path.read_text(encoding="utf-8").splitlines()) == 3
    assert len(result.case_paths) == 2
    assert len(result.pack_paths) == 1


def test_malformed_audit_document_has_sequence_and_projector_failure_boundary(
    tmp_path: Path,
) -> None:
    database, repository, _ = _published_repository(tmp_path)
    connection = sqlite3.connect(database)
    try:
        connection.execute("DROP TRIGGER audit_entries_no_update")
        connection.execute(
            """
            UPDATE audit_entries
            SET entry_json = '{}',
                document_sha256 = ?
            WHERE run_id = ? AND sequence = 0
            """,
            (
                "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
                RUN_ID,
            ),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(RepositoryIntegrityError, match="sequence 0"):
        repository.list_audit_entries(RUN_ID)
    with pytest.raises(ProjectionFailure, match="repository snapshot is invalid"):
        JsonProjector(repository, tmp_path / "projections").project_run(RUN_ID)


def test_projector_rejects_an_existing_nonprivate_run_directory(tmp_path: Path) -> None:
    _, repository, _ = _published_repository(tmp_path)
    output_root = tmp_path / "projections"
    run_directory = output_root / RUN_ID
    run_directory.mkdir(parents=True)
    if os.name != "nt":
        run_directory.chmod(0o755)

    with pytest.raises(ProjectionFailure, match="secure projection workspace"):
        JsonProjector(repository, output_root).project_run(RUN_ID)

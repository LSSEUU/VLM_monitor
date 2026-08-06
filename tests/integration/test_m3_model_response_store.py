from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from labcourt.adapters.storage import SecureOrphanRecoveryFileOps, SecureWorkspace
from labcourt.adapters.storage.model_response_store import (
    ModelResponseStoreError,
    ModelResponseStoreFailureCode,
    SecureModelResponseStore,
)
from labcourt.contracts.canonical import canonical_bytes
from labcourt.contracts.enums import (
    ArtifactKind,
    CropSource,
    EvidenceClass,
    ExecutionLocation,
    MediaAccess,
    PrivacyPolicy,
    ViolationType,
    VlmRole,
)
from labcourt.contracts.m3_models import PromptManifest, VlmCallBudget
from labcourt.contracts.screening import (
    VLMMediaRef,
    VLMRequest,
    VLMResponse,
    derive_model_response_id,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.exceptions import ArtifactConflict, PathBoundaryViolation

RUN_ID = "run-01"
CASE_ID = "case-01"
SHA_1 = "1" * 64
SHA_2 = "2" * 64
SHA_3 = "3" * 64
SHA_4 = "4" * 64
SHA_5 = "5" * 64
SHA_6 = "6" * 64
SHA_7 = "7" * 64


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _request(*, max_response_bytes: int = 1024) -> VLMRequest:
    media = VLMMediaRef(
        crop_id=SHA_4,
        media_sha256=SHA_5,
        local_path=f"{RUN_ID}/frames/{SHA_5}.png",
        source=CropSource.DETECTION_FOCUS,
        media_access=MediaAccess.LOCAL_ONLY,
        privacy_policy=PrivacyPolicy.FULL_REDACTION,
        privacy_transform_version="privacy-v1",
        width=10,
        height=10,
    )
    return VLMRequest(
        run_id=RUN_ID,
        case_id=CASE_ID,
        evidence_pack_id=SHA_6,
        evidence_pack_version=1,
        provider_profile="fake-v1",
        provider="fixture",
        model="fixture-vlm",
        revision="1",
        model_manifest_id=SHA_7,
        execution_location=ExecutionLocation.LOCAL,
        prompt_manifest=PromptManifest(
            prompt_id="screening-v1",
            role=VlmRole.SCREENING,
            template_sha256=SHA_1,
            output_schema_sha256=SHA_2,
            prompt_bundle_sha256=SHA_3,
            renderer_version="jinja-3-1",
        ),
        rendered_prompt_sha256=SHA_1,
        violation_type=ViolationType.REAGENT_CONTAINER_OPEN,
        evidence_class=EvidenceClass.PRESENCE,
        rule_summary="Apply the configured rule.",
        media=(media,),
        allowed_evidence_refs=(ArtifactRef(kind=ArtifactKind.CROP, artifact_id=media.crop_id),),
        objective_summary={},
        temperature=0.0,
        seed=7,
        budget=VlmCallBudget(
            max_images=1,
            max_input_pixels=100,
            max_output_tokens=128,
            pricing_currency="USD",
            input_cost_per_million_tokens=0.0,
            output_cost_per_million_tokens=0.0,
            max_estimated_cost=0.0,
            max_response_bytes=max_response_bytes,
            max_json_depth=8,
            max_json_fields=128,
            max_string_chars=1024,
            timeout_seconds=5.0,
            claim_completion_grace_seconds=5.0,
        ),
        manifest_id=SHA_2,
    )


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "workspace"
    root.mkdir(parents=True)
    return root


def _journal_path(root: Path, request: VLMRequest) -> Path:
    return (
        root / ".staging" / request.run_id / f"model-request-{request.request_id}" / "receipt.json"
    )


def _workspace_fingerprint(root: Path) -> tuple[tuple[str, str, int, str], ...]:
    """Capture every entry name and every regular file's exact byte identity."""

    entries: list[tuple[str, str, int, str]] = []
    paths = sorted(root.rglob("*"), key=lambda path: path.relative_to(root).as_posix())
    for path in paths:
        relative = path.relative_to(root).as_posix()
        if path.is_file():
            payload = path.read_bytes()
            entries.append(("FILE", relative, len(payload), _digest(payload)))
        elif path.is_dir():
            entries.append(("DIRECTORY", relative, 0, ""))
        else:
            entries.append(("OTHER", relative, 0, ""))
    return tuple(entries)


def _prepare_journaled_recovery_state(
    root: Path,
    request: VLMRequest,
    payload: bytes,
    placement: str,
) -> VLMResponse:
    """Create one controlled crash prefix with a valid request-bound journal."""

    if placement == "staging":

        def fail_before_move(relative_path: str) -> None:
            if "/model-response-" in relative_path:
                raise RuntimeError("simulated crash before response publication")

        with SecureWorkspace(root, 4096, fault_hook=fail_before_move) as workspace:
            with pytest.raises(ModelResponseStoreError) as interrupted:
                SecureModelResponseStore(workspace).publish(
                    request,
                    payload,
                    input_tokens=41,
                    output_tokens=42,
                    latency_ms=43,
                )
            assert interrupted.value.reason_code == (
                ModelResponseStoreFailureCode.WORKSPACE_REJECTED
            )
        journal = json.loads(_journal_path(root, request).read_text(encoding="utf-8"))
        return VLMResponse.model_validate(journal["response"])

    with SecureWorkspace(root, 4096) as workspace:
        store = SecureModelResponseStore(workspace)
        response = store.publish(
            request,
            payload,
            input_tokens=41,
            output_tokens=42,
            latency_ms=43,
        )
        if placement == "both":
            staged_directory = f".staging/{request.run_id}/model-response-{response.response_id}"
            workspace.ensure_private_directory(staged_directory)
            workspace.create_new(
                f"{staged_directory}/response.json",
                payload,
                response.content_sha256,
            )
    return response


@pytest.mark.parametrize("payload", [b"", b'{"malformed":', b"\xff"])
def test_store_publishes_exact_bytes_idempotently_and_owner_only(
    tmp_path: Path,
    payload: bytes,
) -> None:
    root = _root(tmp_path)
    request = _request()
    with SecureWorkspace(root, 4096) as workspace:
        store = SecureModelResponseStore(workspace)
        first = store.publish(request, payload, input_tokens=2, output_tokens=3, latency_ms=4)
        retry = store.publish(request, payload, input_tokens=2, output_tokens=3, latency_ms=4)
        assert retry == first
        assert store.verify(RUN_ID, first) == first
        if payload == b"":
            assert store.read_json(RUN_ID, first, 0) == ""

    response_path = root / Path(first.raw_response_ref)
    assert response_path.read_bytes() == payload
    assert first.content_sha256 == _digest(payload)
    assert first.size_bytes == len(payload)
    assert not (root / ".staging" / RUN_ID / f"model-response-{first.response_id}").exists()
    if os.name == "posix":
        assert stat.S_IMODE(response_path.stat().st_mode) == 0o600
        assert stat.S_IMODE(response_path.parent.stat().st_mode) == 0o700


def test_store_reads_utf8_without_parsing_and_enforces_read_budget(tmp_path: Path) -> None:
    root = _root(tmp_path)
    payload = b'{"not_yet_parsed":true}'
    with SecureWorkspace(root, 4096) as workspace:
        store = SecureModelResponseStore(workspace)
        response = store.publish(_request(), payload)
        assert store.read_json(RUN_ID, response, len(payload)) == payload.decode("utf-8")
        assert store.read_bytes(RUN_ID, response, len(payload)) == payload
        with pytest.raises(ModelResponseStoreError) as limited:
            store.read_json(RUN_ID, response, len(payload) - 1)
        assert limited.value.reason_code == ModelResponseStoreFailureCode.READ_LIMIT_EXCEEDED

    invalid_root = _root(tmp_path / "invalid")
    with SecureWorkspace(invalid_root, 4096) as workspace:
        store = SecureModelResponseStore(workspace)
        invalid = store.publish(_request(), b"\xff")
        with pytest.raises(ModelResponseStoreError) as utf8:
            store.read_json(RUN_ID, invalid, 1)
        assert utf8.value.reason_code == ModelResponseStoreFailureCode.RESPONSE_UTF8_INVALID
        assert store.read_bytes(RUN_ID, invalid, 1) == b"\xff"


def test_store_rejects_staging_conflict_and_final_tamper_with_controlled_codes(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    request = _request()
    intended = b'{"stable":true}'
    digest = _digest(intended)
    response_id = derive_model_response_id(RUN_ID, request.request_id, digest)
    staging_dir = f".staging/{RUN_ID}/model-response-{response_id}"
    with SecureWorkspace(root, 4096) as workspace:
        for directory in (".staging", f".staging/{RUN_ID}", staging_dir):
            workspace.ensure_private_directory(directory)
        wrong = b"different"
        workspace.create_new(f"{staging_dir}/response.json", wrong, _digest(wrong))
        store = SecureModelResponseStore(workspace)
        with pytest.raises(ModelResponseStoreError) as conflict:
            store.publish(request, intended)
        assert conflict.value.reason_code == ModelResponseStoreFailureCode.RESPONSE_CONFLICT
        assert str(root) not in str(conflict.value)

    clean_root = _root(tmp_path / "tamper")
    with SecureWorkspace(clean_root, 4096) as workspace:
        store = SecureModelResponseStore(workspace)
        response = store.publish(request, intended)
    (clean_root / Path(response.raw_response_ref)).write_bytes(intended + b"-oversized-tamper")
    with SecureWorkspace(clean_root, 4096) as workspace:
        tampered_store = SecureModelResponseStore(workspace)
        with pytest.raises(ModelResponseStoreError) as bounded:
            tampered_store.read_json(RUN_ID, response, response.size_bytes)
        assert bounded.value.reason_code == (
            ModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE
        )
        with pytest.raises(ModelResponseStoreError) as tamper:
            tampered_store.verify(RUN_ID, response)
        assert tamper.value.reason_code == (
            ModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE
        )
        assert str(clean_root) not in str(tamper.value)


def test_verify_raw_response_requires_exact_request_binding_and_live_bytes(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    request = _request()
    with SecureWorkspace(root, 4096) as workspace:
        store = SecureModelResponseStore(workspace)
        response = store.publish(request, b'{"verified":true}')

        assert store.verify_raw_response(RUN_ID, request, response) == response

        oversized_receipt = response.model_copy(
            update={"size_bytes": request.budget.max_response_bytes + 1}
        )
        with pytest.raises(ModelResponseStoreError) as oversized:
            store.verify_raw_response(RUN_ID, request, oversized_receipt)
        assert oversized.value.reason_code == (
            ModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE
        )

        other_request = request.model_copy(update={"case_id": "case-02"})
        with pytest.raises(ModelResponseStoreError) as mismatch:
            store.verify_raw_response(RUN_ID, other_request, response)
        assert mismatch.value.reason_code == (
            ModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE
        )

        (root / Path(response.raw_response_ref)).unlink()
        with pytest.raises(ModelResponseStoreError) as missing:
            store.verify_raw_response(RUN_ID, request, response)
        assert missing.value.reason_code == ModelResponseStoreFailureCode.RESPONSE_NOT_FOUND


def test_store_crash_before_publish_leaves_recoverable_stage_and_retry_completes(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    request = _request()
    payload = b'{"recoverable":true}'

    def fail_before_move(_relative_path: str) -> None:
        raise RuntimeError("secret fault detail")

    with SecureWorkspace(root, 4096, fault_hook=fail_before_move) as workspace:
        with pytest.raises(ModelResponseStoreError) as interrupted:
            SecureModelResponseStore(workspace).publish(request, payload)
        assert interrupted.value.reason_code == ModelResponseStoreFailureCode.WORKSPACE_REJECTED
        assert "secret fault detail" not in str(interrupted.value)
        response_id = derive_model_response_id(RUN_ID, request.request_id, _digest(payload))
        staged = root / ".staging" / RUN_ID / f"model-response-{response_id}" / "response.json"
        assert staged.read_bytes() == payload
        assert not (root / RUN_ID / "model_responses" / f"{response_id}.json").exists()

    with SecureWorkspace(root, 4096) as workspace:
        completed = SecureModelResponseStore(workspace).publish(request, payload)
    assert (root / Path(completed.raw_response_ref)).read_bytes() == payload
    assert not staged.parent.exists()


def test_model_response_recovery_namespace_is_dedicated_and_m2_media_scan_ignores_it(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    response_id = "a" * 64
    payload = b"orphan response"
    digest = _digest(payload)
    operation = f".staging/{RUN_ID}/model-response-{response_id}"
    request_operation = f".staging/{RUN_ID}/model-request-{'d' * 64}"
    final_dir = f"{RUN_ID}/model_responses"
    with SecureWorkspace(root, 4096) as workspace:
        for directory in (
            ".staging",
            f".staging/{RUN_ID}",
            operation,
            request_operation,
            RUN_ID,
            final_dir,
        ):
            workspace.ensure_private_directory(directory)
        workspace.create_new(f"{operation}/response.json", payload, digest)
        workspace.create_new(
            f"{request_operation}/receipt.json",
            payload,
            digest,
        )
        workspace.create_new(f"{final_dir}/{response_id}.json", payload, digest)

        staging = workspace.list_model_response_recovery_directory(
            operation,
            max_items=4,
            max_name_bytes=255,
        )
        final = workspace.list_model_response_recovery_directory(
            final_dir,
            max_items=4,
            max_name_bytes=255,
        )
        request_journal = workspace.list_model_response_recovery_directory(
            request_operation,
            max_items=4,
            max_name_bytes=255,
        )
        m2_scan = SecureOrphanRecoveryFileOps(workspace).discover(
            RUN_ID,
            max_items=10,
            max_depth=2,
            max_name_bytes=255,
        )

    assert [hint.name for hint in staging] == ["response.json"]
    assert [hint.name for hint in final] == [f"{response_id}.json"]
    assert [hint.name for hint in request_journal] == ["receipt.json"]
    assert m2_scan.candidates == ()
    assert m2_scan.anomalies == ()


def test_shared_staging_root_applies_independent_media_and_response_budgets(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    media_digest = "c" * 64
    media_operation = f".staging/{RUN_ID}/crop-{media_digest}"
    response_names = tuple(f"model-response-{index:064x}" for index in range(3))
    request_names = tuple(f"model-request-{index:064x}" for index in range(3))
    payload = b"media staging bytes"
    with SecureWorkspace(root, 4096) as workspace:
        workspace.ensure_private_directory(".staging")
        workspace.ensure_private_directory(f".staging/{RUN_ID}")
        for name in response_names:
            workspace.ensure_private_directory(f".staging/{RUN_ID}/{name}")
        for name in request_names:
            workspace.ensure_private_directory(f".staging/{RUN_ID}/{name}")
        workspace.ensure_private_directory(media_operation)
        workspace.create_new(
            f"{media_operation}/media.png",
            payload,
            _digest(payload),
        )

        response_hints = workspace.list_model_response_recovery_directory(
            f".staging/{RUN_ID}",
            max_items=4,
            max_name_bytes=255,
        )
        media_scan = SecureOrphanRecoveryFileOps(workspace).discover(
            RUN_ID,
            max_items=4,
            max_depth=2,
            max_name_bytes=255,
        )

    assert [hint.name for hint in response_hints] == sorted((*request_names, *response_names))
    assert len(media_scan.candidates) == 1
    assert media_scan.candidates[0].source_relative_path == f"{media_operation}/media.png"
    assert media_scan.anomalies == ()


def test_model_response_recovery_quarantine_is_age_checked_and_exact(tmp_path: Path) -> None:
    root = _root(tmp_path)
    response_id = "b" * 64
    payload = b"staged orphan"
    digest = _digest(payload)
    operation = f".staging/{RUN_ID}/model-response-{response_id}"
    source = f"{operation}/response.json"
    with SecureWorkspace(root, 4096) as workspace:
        for directory in (
            ".staging",
            f".staging/{RUN_ID}",
            operation,
            ".quarantine",
            f".quarantine/{RUN_ID}",
            f".quarantine/{RUN_ID}/model_responses",
            f".quarantine/{RUN_ID}/model_responses/staging",
        ):
            workspace.ensure_private_directory(directory)
        workspace.create_new(source, payload, digest)
        quarantined = workspace.quarantine_model_response_recovery(
            source,
            digest,
            datetime.now(UTC) + timedelta(seconds=1),
            max_bytes=len(payload),
        )
        workspace.remove_empty_model_response_staging_directory(operation)

    assert quarantined.sha256 == digest
    assert quarantined.bytes == payload
    assert quarantined.relative_path == (
        f".quarantine/{RUN_ID}/model_responses/staging/{response_id}-{digest}.json"
    )


def test_model_response_quarantine_fails_closed_when_equal_source_and_destination_coexist(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    response_id = "b" * 64
    payload = b"duplicate orphan"
    digest = _digest(payload)
    operation = f".staging/{RUN_ID}/model-response-{response_id}"
    source = f"{operation}/response.json"
    destination = f".quarantine/{RUN_ID}/model_responses/staging/{response_id}-{digest}.json"
    source_path = root / Path(*source.split("/"))
    destination_path = root / Path(*destination.split("/"))

    with SecureWorkspace(root, 4096) as workspace:
        for directory in (
            ".staging",
            f".staging/{RUN_ID}",
            operation,
            ".quarantine",
            f".quarantine/{RUN_ID}",
            f".quarantine/{RUN_ID}/model_responses",
            f".quarantine/{RUN_ID}/model_responses/staging",
        ):
            workspace.ensure_private_directory(directory)
        workspace.create_new(source, payload, digest)
        workspace.create_new(destination, payload, digest)

        with pytest.raises(ArtifactConflict) as blocked:
            workspace.quarantine_model_response_recovery(
                source,
                digest,
                datetime.now(UTC) + timedelta(seconds=1),
                max_bytes=len(payload),
            )

        assert blocked.value.reason_code == "QUARANTINE_CONTENT_CONFLICT"
        assert source_path.read_bytes() == payload
        assert destination_path.read_bytes() == payload

        # Once the source is absent, the same destination is a valid idempotent retry.
        source_path.unlink()
        retried = workspace.quarantine_model_response_recovery(
            source,
            digest,
            datetime.now(UTC) + timedelta(seconds=1),
            max_bytes=len(payload),
        )

    assert retried.relative_path == destination
    assert retried.bytes == payload


@pytest.mark.skipif(
    os.name != "posix" or sys.platform not in {"linux", "darwin"},
    reason="requires the supported POSIX atomic no-replace implementation",
)
def test_posix_quarantine_rejects_source_replaced_after_identity_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _root(tmp_path)
    response_id = "b" * 64
    payload = b"observed orphan"
    replacement_payload = b"raced replacement"
    digest = _digest(payload)
    operation = f".staging/{RUN_ID}/model-response-{response_id}"
    source = f"{operation}/response.json"
    destination = f".quarantine/{RUN_ID}/model_responses/staging/{response_id}-{digest}.json"

    with SecureWorkspace(root, 4096) as workspace:
        for directory in (
            ".staging",
            f".staging/{RUN_ID}",
            operation,
            ".quarantine",
            f".quarantine/{RUN_ID}",
            f".quarantine/{RUN_ID}/model_responses",
            f".quarantine/{RUN_ID}/model_responses/staging",
        ):
            workspace.ensure_private_directory(directory)
        workspace.create_new(source, payload, digest)
        workspace.create_new(
            f"{operation}/replacement.json",
            replacement_payload,
            _digest(replacement_payload),
        )
        rename_no_replace = workspace._posix_rename_no_replace

        def replace_immediately_before_rename(
            source_parent: int,
            source_name: str,
            target_parent: int,
            target_name: str,
        ) -> None:
            os.rename(
                source_name,
                "original.backup",
                src_dir_fd=source_parent,
                dst_dir_fd=source_parent,
            )
            os.rename(
                "replacement.json",
                source_name,
                src_dir_fd=source_parent,
                dst_dir_fd=source_parent,
            )
            rename_no_replace(source_parent, source_name, target_parent, target_name)

        monkeypatch.setattr(
            workspace,
            "_posix_rename_no_replace",
            replace_immediately_before_rename,
        )
        with pytest.raises(PathBoundaryViolation) as raced:
            workspace.quarantine_model_response_recovery(
                source,
                digest,
                datetime.now(UTC) + timedelta(seconds=1),
                max_bytes=len(payload),
            )

    assert raced.value.reason_code == "RENAMED_IDENTITY_MISMATCH"
    assert (root / Path(*operation.split("/")) / "original.backup").read_bytes() == payload
    assert (root / Path(*destination.split("/"))).read_bytes() == replacement_payload


@pytest.mark.skipif(
    os.name != "posix" or sys.platform not in {"linux", "darwin"},
    reason="requires the supported POSIX atomic no-replace implementation",
)
def test_posix_quarantine_rejects_source_name_recreated_after_exact_rename(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _root(tmp_path)
    response_id = "b" * 64
    payload = b"observed orphan"
    replacement_payload = b"late replacement"
    digest = _digest(payload)
    operation = f".staging/{RUN_ID}/model-response-{response_id}"
    source = f"{operation}/response.json"
    destination = f".quarantine/{RUN_ID}/model_responses/staging/{response_id}-{digest}.json"

    with SecureWorkspace(root, 4096) as workspace:
        for directory in (
            ".staging",
            f".staging/{RUN_ID}",
            operation,
            ".quarantine",
            f".quarantine/{RUN_ID}",
            f".quarantine/{RUN_ID}/model_responses",
            f".quarantine/{RUN_ID}/model_responses/staging",
        ):
            workspace.ensure_private_directory(directory)
        workspace.create_new(source, payload, digest)
        workspace.create_new(
            f"{operation}/replacement.json",
            replacement_payload,
            _digest(replacement_payload),
        )
        rename_no_replace = workspace._posix_rename_no_replace

        def recreate_immediately_after_rename(
            source_parent: int,
            source_name: str,
            target_parent: int,
            target_name: str,
        ) -> None:
            rename_no_replace(source_parent, source_name, target_parent, target_name)
            os.rename(
                "replacement.json",
                source_name,
                src_dir_fd=source_parent,
                dst_dir_fd=source_parent,
            )

        monkeypatch.setattr(
            workspace,
            "_posix_rename_no_replace",
            recreate_immediately_after_rename,
        )
        with pytest.raises(PathBoundaryViolation) as raced:
            workspace.quarantine_model_response_recovery(
                source,
                digest,
                datetime.now(UTC) + timedelta(seconds=1),
                max_bytes=len(payload),
            )

    assert raced.value.reason_code == "SOURCE_ENTRY_REAPPEARED"
    assert (root / Path(*source.split("/"))).read_bytes() == replacement_payload
    assert (root / Path(*destination.split("/"))).read_bytes() == payload


@pytest.mark.parametrize("placement", ["staging", "final", "both"])
def test_probe_recovery_verifies_each_crash_prefix_without_changing_workspace(
    tmp_path: Path,
    placement: str,
) -> None:
    root = _root(tmp_path)
    request = _request()
    payload = b'{"probe_read_only":true}'
    expected = _prepare_journaled_recovery_state(root, request, payload, placement)
    before = _workspace_fingerprint(root)

    with SecureWorkspace(root, 4096) as workspace:
        probed = SecureModelResponseStore(workspace).probe_recovery(request)

    assert probed == expected
    assert probed is not None
    assert (probed.input_tokens, probed.output_tokens, probed.latency_ms) == (41, 42, 43)
    assert _workspace_fingerprint(root) == before
    staged = root / ".staging" / RUN_ID / f"model-response-{expected.response_id}" / "response.json"
    final = root / Path(expected.raw_response_ref)
    assert staged.is_file() is (placement in {"staging", "both"})
    assert final.is_file() is (placement in {"final", "both"})


def test_probe_recovery_returns_none_for_missing_journal_without_changing_workspace(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    request = _request()
    payload = b'{"journal_was_acknowledged":true}'
    with SecureWorkspace(root, 4096) as workspace:
        store = SecureModelResponseStore(workspace)
        response = store.publish(request, payload)
        store.acknowledge(request, response)
        staged_directory = f".staging/{RUN_ID}/model-response-{response.response_id}"
        workspace.ensure_private_directory(staged_directory)
        workspace.create_new(
            f"{staged_directory}/response.json",
            payload,
            response.content_sha256,
        )
    assert not _journal_path(root, request).exists()
    before = _workspace_fingerprint(root)

    with SecureWorkspace(root, 4096) as workspace:
        assert SecureModelResponseStore(workspace).probe_recovery(request) is None

    assert _workspace_fingerprint(root) == before
    assert (root / Path(response.raw_response_ref)).read_bytes() == payload
    assert (root / staged_directory / "response.json").read_bytes() == payload


@pytest.mark.parametrize("corruption", ["journal", "staging-bytes", "final-bytes"])
def test_probe_recovery_rejects_corruption_without_changing_workspace(
    tmp_path: Path,
    corruption: str,
) -> None:
    root = _root(tmp_path)
    request = _request()
    payload = b'{"probe_integrity":true}'
    placement = "staging" if corruption == "staging-bytes" else "final"
    response = _prepare_journaled_recovery_state(root, request, payload, placement)

    if corruption == "journal":
        _journal_path(root, request).write_bytes(b'{"corrupt_journal":true}')
    else:
        target = (
            root / ".staging" / RUN_ID / f"model-response-{response.response_id}" / "response.json"
            if corruption == "staging-bytes"
            else root / Path(response.raw_response_ref)
        )
        target.write_bytes(payload[::-1])
    before = _workspace_fingerprint(root)

    with (
        SecureWorkspace(root, 4096) as workspace,
        pytest.raises(ModelResponseStoreError) as rejected,
    ):
        SecureModelResponseStore(workspace).probe_recovery(request)

    assert rejected.value.reason_code == ModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE
    assert str(root) not in str(rejected.value)
    assert _workspace_fingerprint(root) == before


def test_recover_returns_none_without_journal_even_when_uncommitted_stage_exists(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    request = _request()
    payload = b'{"not_committed":true}'
    response_id = derive_model_response_id(RUN_ID, request.request_id, _digest(payload))
    operation = f".staging/{RUN_ID}/model-response-{response_id}"
    with SecureWorkspace(root, 4096) as workspace:
        for directory in (".staging", f".staging/{RUN_ID}", operation):
            workspace.ensure_private_directory(directory)
        workspace.create_new(f"{operation}/response.json", payload, _digest(payload))
        assert SecureModelResponseStore(workspace).recover(request) is None


def test_recover_completes_journaled_stage_after_crash_and_preserves_usage(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    request = _request()
    payload = b'{"recover_from_journal":true}'

    def fail_before_move(relative_path: str) -> None:
        if "/model-response-" in relative_path:
            raise RuntimeError("private crash detail")

    with SecureWorkspace(root, 4096, fault_hook=fail_before_move) as workspace:
        with pytest.raises(ModelResponseStoreError) as interrupted:
            SecureModelResponseStore(workspace).publish(
                request,
                payload,
                input_tokens=11,
                output_tokens=12,
                latency_ms=13,
            )
        assert interrupted.value.reason_code == ModelResponseStoreFailureCode.WORKSPACE_REJECTED

    journal_path = _journal_path(root, request)
    assert journal_path.is_file()
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    assert journal["request_binding"]["request_id"] == request.request_id
    assert journal["response"]["input_tokens"] == 11
    assert journal["response"]["output_tokens"] == 12
    assert journal["response"]["latency_ms"] == 13

    with SecureWorkspace(root, 4096) as workspace:
        recovered = SecureModelResponseStore(workspace).recover(request)
    assert recovered is not None
    assert (recovered.input_tokens, recovered.output_tokens, recovered.latency_ms) == (11, 12, 13)
    assert journal["response"] == recovered.model_dump(mode="json")
    assert (root / Path(recovered.raw_response_ref)).read_bytes() == payload
    assert journal_path.is_file()


def test_recover_returns_exact_receipt_after_crash_following_final_publication(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    request = _request()
    payload = b'{"published_before_crash":true}'
    content_sha256 = _digest(payload)
    response_id = derive_model_response_id(RUN_ID, request.request_id, content_sha256)
    final_relative = f"{RUN_ID}/model_responses/{response_id}.json"

    def fail_after_publication(relative_path: str) -> None:
        if relative_path == final_relative:
            raise RuntimeError("private post-publication crash detail")

    with SecureWorkspace(root, 4096, fault_hook=fail_after_publication) as workspace:
        with pytest.raises(ModelResponseStoreError) as interrupted:
            SecureModelResponseStore(workspace).publish(
                request,
                payload,
                input_tokens=21,
                output_tokens=22,
                latency_ms=23,
            )
        assert interrupted.value.reason_code == ModelResponseStoreFailureCode.WORKSPACE_REJECTED

    assert (root / Path(final_relative)).read_bytes() == payload
    with SecureWorkspace(root, 4096) as workspace:
        recovered = SecureModelResponseStore(workspace).recover(request)
    assert recovered is not None
    assert recovered.raw_response_ref == final_relative
    assert (recovered.input_tokens, recovered.output_tokens, recovered.latency_ms) == (21, 22, 23)


@pytest.mark.parametrize("tamper", ["noncanonical", "self_hash", "request_binding"])
def test_recover_rejects_tampered_journal_fail_closed(
    tmp_path: Path,
    tamper: str,
) -> None:
    root = _root(tmp_path)
    request = _request()
    with SecureWorkspace(root, 4096) as workspace:
        response = SecureModelResponseStore(workspace).publish(request, b'{"stable":true}')

    journal_path = _journal_path(root, request)
    original = journal_path.read_bytes()
    document = json.loads(original)
    if tamper == "noncanonical":
        changed = b" " + original
    elif tamper == "self_hash":
        document["journal_sha256"] = "0" * 64
        changed = canonical_bytes(document)
    else:
        document["request_binding"]["case_id"] = "case-tampered"
        body = {
            "schema_version": document["schema_version"],
            "request_binding": document["request_binding"],
            "response": document["response"],
        }
        document["journal_sha256"] = _digest(
            canonical_bytes(["labcourt:model-response-publication-journal", 1, body])
        )
        changed = canonical_bytes(document)
    journal_path.write_bytes(changed)

    with SecureWorkspace(root, 4096) as workspace:
        store = SecureModelResponseStore(workspace)
        with pytest.raises(ModelResponseStoreError) as rejected:
            store.recover(request)
        assert rejected.value.reason_code == (
            ModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE
        )
        with pytest.raises(ModelResponseStoreError) as not_acknowledged:
            store.acknowledge(request, response)
        assert not_acknowledged.value.reason_code == (
            ModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE
        )
    assert journal_path.read_bytes() == changed


def test_recover_rejects_tampered_final_bound_by_journal(tmp_path: Path) -> None:
    root = _root(tmp_path)
    request = _request()
    payload = b'{"stable":true}'
    with SecureWorkspace(root, 4096) as workspace:
        response = SecureModelResponseStore(workspace).publish(request, payload)
    (root / Path(response.raw_response_ref)).write_bytes(b'{"stable":fals}')

    with (
        SecureWorkspace(root, 4096) as workspace,
        pytest.raises(ModelResponseStoreError) as rejected,
    ):
        SecureModelResponseStore(workspace).recover(request)
    assert rejected.value.reason_code == ModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE
    assert _journal_path(root, request).is_file()


def test_acknowledge_deletes_only_exact_journal_and_is_idempotent(tmp_path: Path) -> None:
    root = _root(tmp_path)
    request = _request()
    payload = b'{"acknowledge":true}'
    with SecureWorkspace(root, 4096) as workspace:
        store = SecureModelResponseStore(workspace)
        response = store.publish(
            request,
            payload,
            input_tokens=31,
            output_tokens=32,
            latency_ms=33,
        )
        wrong = response.model_copy(update={"latency_ms": 34})
        with pytest.raises(ModelResponseStoreError) as mismatch:
            store.acknowledge(request, wrong)
        assert mismatch.value.reason_code == (
            ModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE
        )
        assert _journal_path(root, request).is_file()

        store.acknowledge(request, response)
        assert store.recover(request) is None
        store.acknowledge(request, response)

    journal_directory = _journal_path(root, request).parent
    assert not journal_directory.exists()
    assert (root / Path(response.raw_response_ref)).read_bytes() == payload

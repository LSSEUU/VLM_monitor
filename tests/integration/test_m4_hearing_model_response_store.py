from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

import pytest

from labcourt.adapters.storage import (
    HearingModelResponseStoreError,
    HearingModelResponseStoreFailureCode,
    ImmutableHearingVLMResponseCache,
    SecureHearingModelResponseStore,
    SecureWorkspace,
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
from labcourt.contracts.hearing import (
    HearingModelRequest,
    HearingModelResponse,
    derive_hearing_model_response_id,
)
from labcourt.contracts.m3_models import PromptManifest, VlmCallBudget
from labcourt.contracts.screening import VLMMediaRef
from labcourt.contracts.storage import ArtifactRef

RUN_ID = "run-01"
CASE_ID = "case-01"
SHA_1 = "1" * 64
SHA_2 = "2" * 64
SHA_3 = "3" * 64
SHA_4 = "4" * 64
SHA_5 = "5" * 64
SHA_6 = "6" * 64
SHA_7 = "7" * 64
SHA_8 = "8" * 64
SHA_9 = "9" * 64

_JOURNAL_SCHEMA = "m4-hearing-model-response-publication-journal-v1"
_JOURNAL_DOMAIN = "labcourt:hearing-model-response-publication-journal"
_M3_JOURNAL_DOMAIN = "labcourt:model-response-publication-journal"
_COMPUTED_REQUEST_FIELDS = {
    "cycle_scope_id",
    "cycle_scope_sha256",
    "request_sha256",
    "request_id",
    "cache_key",
}


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "workspace"
    root.mkdir(parents=True)
    return root


def _request(
    role: VlmRole = VlmRole.PROSECUTOR,
    *,
    run_id: str = RUN_ID,
    max_response_bytes: int = 8_192,
) -> HearingModelRequest:
    media = VLMMediaRef(
        crop_id=SHA_4,
        media_sha256=SHA_5,
        local_path=f"{run_id}/frames/{SHA_5}.png",
        source=CropSource.DETECTION_FOCUS,
        media_access=MediaAccess.LOCAL_ONLY,
        privacy_policy=PrivacyPolicy.FULL_REDACTION,
        privacy_transform_version="privacy-v1",
        width=8,
        height=8,
    )
    upstream = ArtifactRef(kind=ArtifactKind.PARSED_MODEL_OUTPUT, artifact_id=SHA_8)
    return HearingModelRequest(
        run_id=run_id,
        case_id=CASE_ID,
        hearing_session_id=SHA_9,
        round_index=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        current_evidence_pack_id=SHA_6,
        current_evidence_pack_version=1,
        screening_ref=ArtifactRef(
            kind=ArtifactKind.SCREENING_RESULT,
            artifact_id=SHA_7,
        ),
        violation_type=ViolationType.REAGENT_CONTAINER_OPEN,
        evidence_class=EvidenceClass.PRESENCE,
        role=role,
        provider_profile=f"fake-{role.value.lower()}",
        provider="fake",
        model=f"deterministic-{role.value.lower()}",
        revision="1.0.0",
        model_manifest_id=SHA_1,
        execution_location=ExecutionLocation.LOCAL,
        prompt_manifest=PromptManifest(
            prompt_id=f"hearing_{role.value.lower()}_v1",
            role=role,
            template_sha256=SHA_2,
            output_schema_sha256=SHA_3,
            prompt_bundle_sha256=SHA_4,
            renderer_version="jinja-3-1",
        ),
        hearing_prompt_bundle_sha256=SHA_4,
        rendered_prompt_sha256=SHA_5,
        hearing_context_sha256=SHA_6,
        media=(media,),
        allowed_evidence_refs=(ArtifactRef(kind=ArtifactKind.CROP, artifact_id=media.crop_id),),
        prosecutor_output_ref=(upstream if role in {VlmRole.DEFENDER, VlmRole.JUDGE} else None),
        defender_output_ref=upstream if role == VlmRole.JUDGE else None,
        precedent_retrieval_degraded=False,
        precedent_retrieval_receipt_id=SHA_2,
        precedent_retrieval_receipt_sha256=SHA_3,
        temperature=0.0,
        seed=7,
        budget=VlmCallBudget(
            max_images=1,
            max_input_pixels=64,
            max_input_tokens=256,
            max_output_tokens=128,
            pricing_currency="USD",
            input_cost_per_million_tokens=0.0,
            output_cost_per_million_tokens=0.0,
            max_estimated_cost=0.0,
            max_response_bytes=max_response_bytes,
            max_json_depth=8,
            max_json_fields=128,
            max_string_chars=1_024,
            timeout_seconds=5.0,
            claim_completion_grace_seconds=5.0,
        ),
        manifest_id=SHA_7,
    )


def _repair_request(
    primary: HearingModelRequest,
    response: HearingModelResponse,
) -> HearingModelRequest:
    payload = primary.model_dump(mode="python", exclude=_COMPUTED_REQUEST_FIELDS)
    payload.update(
        {
            "attempt_index": 1,
            "media": (),
            "original_request_id": primary.request_id,
            "original_response_id": response.response_id,
            "original_response_content_sha256": response.content_sha256,
            "repair_context_sha256": SHA_8,
            "budget": primary.budget.model_copy(update={"max_images": 0, "max_input_pixels": 0}),
        }
    )
    return HearingModelRequest.model_validate(payload)


def _journal_path(root: Path, request: HearingModelRequest) -> Path:
    return (
        root
        / ".staging"
        / request.run_id
        / f"hearing-model-request-{request.request_id}"
        / "receipt.json"
    )


def _rehashed_journal(document: dict[str, object]) -> bytes:
    body = {
        "schema_version": document["schema_version"],
        "request_binding": document["request_binding"],
        "response": document["response"],
    }
    document["journal_sha256"] = _digest(canonical_bytes([_JOURNAL_DOMAIN, 1, body]))
    return canonical_bytes(document)


def _fingerprint(root: Path) -> tuple[tuple[str, int, str], ...]:
    observed: list[tuple[str, int, str]] = []
    for path in sorted(root.rglob("*"), key=lambda value: value.as_posix()):
        if path.is_file():
            payload = path.read_bytes()
            observed.append((path.relative_to(root).as_posix(), len(payload), _digest(payload)))
    return tuple(observed)


def test_m4_store_publishes_exact_bytes_with_independent_full_journal_binding(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    request = _request()
    payload = b'{"role":"PROSECUTOR","arguments":[]}'
    with SecureWorkspace(root, 128 * 1024) as workspace:
        store = SecureHearingModelResponseStore(workspace)
        first = store.publish(
            request,
            payload,
            input_tokens=11,
            output_tokens=12,
            latency_ms=13,
        )
        retry = store.publish(
            request,
            payload,
            input_tokens=11,
            output_tokens=12,
            latency_ms=13,
        )
        assert retry == first
        assert store.verify_raw_response(RUN_ID, request, first) == first
        assert store.read_bytes(RUN_ID, first, len(payload)) == payload
        assert store.read_json(RUN_ID, first, len(payload)) == payload.decode()

    document = json.loads(_journal_path(root, request).read_text(encoding="utf-8"))
    binding = document["request_binding"]
    assert document["schema_version"] == _JOURNAL_SCHEMA
    assert binding["cycle_scope_id"] == request.cycle_scope_id
    assert binding["cycle_scope_sha256"] == request.cycle_scope_sha256
    assert binding["role"] == VlmRole.PROSECUTOR.value
    assert binding["attempt_index"] == 0
    assert binding["current_evidence_pack_id"] == request.current_evidence_pack_id
    assert binding["current_evidence_pack_version"] == 1
    assert binding["request_id"] == request.request_id
    assert binding["request_sha256"] == request.request_sha256
    assert binding["cache_key"] == request.cache_key
    assert binding["model_manifest_id"] == request.model_manifest_id
    assert binding["prompt_manifest_id"] == request.prompt_manifest.prompt_manifest_id
    assert binding["manifest_id"] == request.manifest_id
    body = {
        "schema_version": document["schema_version"],
        "request_binding": binding,
        "response": document["response"],
    }
    assert document["journal_sha256"] == _digest(canonical_bytes([_JOURNAL_DOMAIN, 1, body]))
    assert document["journal_sha256"] != _digest(canonical_bytes([_M3_JOURNAL_DOMAIN, 1, body]))
    response_path = root / Path(first.raw_response_ref)
    assert response_path.read_bytes() == payload
    if os.name == "posix":
        assert stat.S_IMODE(response_path.stat().st_mode) == 0o600
        assert stat.S_IMODE(response_path.parent.stat().st_mode) == 0o700


def test_m4_store_rejects_different_bytes_and_conflicting_usage_for_same_request(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    request = _request()
    with SecureWorkspace(root, 128 * 1024) as workspace:
        store = SecureHearingModelResponseStore(workspace)
        store.publish(request, b'{"stable":true}', input_tokens=1)
        with pytest.raises(HearingModelResponseStoreError) as different:
            store.publish(request, b'{"stable":false}', input_tokens=1)
        assert different.value.reason_code == (
            HearingModelResponseStoreFailureCode.RESPONSE_CONFLICT
        )
        with pytest.raises(HearingModelResponseStoreError) as metrics:
            store.publish(request, b'{"stable":true}', input_tokens=2)
        assert metrics.value.reason_code == (HearingModelResponseStoreFailureCode.RESPONSE_CONFLICT)
        assert str(root) not in str(different.value)


def test_m4_store_probe_and_provider_free_recover_cover_crash_before_publish(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    request = _request()
    payload = b'{"recoverable":true}'

    def fail_before_move(relative_path: str) -> None:
        if "/hearing-model-response-" in relative_path:
            raise RuntimeError("private simulated crash")

    with SecureWorkspace(root, 128 * 1024, fault_hook=fail_before_move) as workspace:
        with pytest.raises(HearingModelResponseStoreError) as interrupted:
            SecureHearingModelResponseStore(workspace).publish(
                request,
                payload,
                input_tokens=21,
                output_tokens=22,
                latency_ms=23,
            )
        assert interrupted.value.reason_code == (
            HearingModelResponseStoreFailureCode.WORKSPACE_REJECTED
        )
        assert "private simulated crash" not in str(interrupted.value)

    response_id = derive_hearing_model_response_id(
        RUN_ID,
        request.request_id,
        _digest(payload),
    )
    staged = root / ".staging" / RUN_ID / f"hearing-model-response-{response_id}" / "response.json"
    assert staged.read_bytes() == payload
    assert _journal_path(root, request).is_file()
    before_probe = _fingerprint(root)

    with SecureWorkspace(root, 128 * 1024) as workspace:
        m3_hints = workspace.list_model_response_recovery_directory(
            f".staging/{RUN_ID}",
            max_items=4,
            max_name_bytes=255,
        )
        m4_hints = workspace.list_hearing_model_response_recovery_directory(
            f".staging/{RUN_ID}",
            max_items=4,
            max_name_bytes=255,
        )
        assert m3_hints == ()
        assert [hint.name for hint in m4_hints] == sorted(
            (
                f"hearing-model-request-{request.request_id}",
                f"hearing-model-response-{response_id}",
            )
        )
        store = SecureHearingModelResponseStore(workspace)
        probed = store.probe_recovery(request)
        assert _fingerprint(root) == before_probe
        recovered = store.recover(request)
        assert recovered == probed
        assert recovered is not None
        assert (recovered.input_tokens, recovered.output_tokens, recovered.latency_ms) == (
            21,
            22,
            23,
        )
        assert store.verify_raw_response(RUN_ID, request, recovered) == recovered
        store.acknowledge(request, recovered)
        assert store.recover(request) is None
        store.acknowledge(request, recovered)

    assert not staged.parent.exists()
    assert not _journal_path(root, request).parent.exists()
    assert (root / Path(recovered.raw_response_ref)).read_bytes() == payload


def test_m4_store_recovers_crash_after_final_publication(tmp_path: Path) -> None:
    root = _root(tmp_path)
    request = _request()
    payload = b'{"published":true}'
    response_id = derive_hearing_model_response_id(
        RUN_ID,
        request.request_id,
        _digest(payload),
    )
    final_relative = f"{RUN_ID}/model_responses/{response_id}.json"

    def fail_on_final_reopen(relative_path: str) -> None:
        if relative_path == final_relative:
            raise RuntimeError("crash after rename")

    with (
        SecureWorkspace(root, 128 * 1024, fault_hook=fail_on_final_reopen) as workspace,
        pytest.raises(HearingModelResponseStoreError),
    ):
        SecureHearingModelResponseStore(workspace).publish(request, payload)
    assert (root / Path(final_relative)).read_bytes() == payload

    with SecureWorkspace(root, 128 * 1024) as workspace:
        recovered = SecureHearingModelResponseStore(workspace).recover(request)
        assert recovered is not None
        assert recovered.raw_response_ref == final_relative


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("cycle_scope_id", "0" * 64),
        ("role", VlmRole.JUDGE.value),
        ("attempt_index", 1),
        ("current_evidence_pack_id", "0" * 64),
        ("request_id", "0" * 64),
        ("cache_key", "0" * 64),
        ("model_manifest_id", "0" * 64),
        ("manifest_id", "0" * 64),
    ],
)
def test_m4_recovery_rejects_rehashed_binding_tamper(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    root = _root(tmp_path)
    request = _request()
    with SecureWorkspace(root, 128 * 1024) as workspace:
        SecureHearingModelResponseStore(workspace).publish(request, b'{"stable":true}')
    journal_path = _journal_path(root, request)
    document = json.loads(journal_path.read_bytes())
    document["request_binding"][field] = value
    changed = _rehashed_journal(document)
    journal_path.write_bytes(changed)

    with (
        SecureWorkspace(root, 128 * 1024) as workspace,
        pytest.raises(HearingModelResponseStoreError) as rejected,
    ):
        SecureHearingModelResponseStore(workspace).recover(request)
    assert rejected.value.reason_code == (
        HearingModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE
    )
    assert journal_path.read_bytes() == changed


def test_m4_recovery_rejects_role_and_repair_journal_swaps(tmp_path: Path) -> None:
    root = _root(tmp_path)
    primary = _request()
    with SecureWorkspace(root, 128 * 1024) as workspace:
        store = SecureHearingModelResponseStore(workspace)
        response = store.publish(primary, b'{"stable":true}')
        defender = _request(VlmRole.DEFENDER)
        repair = _repair_request(primary, response)
        original_journal = _journal_path(root, primary).read_bytes()
        for swapped in (defender, repair):
            directory = f".staging/{swapped.run_id}/hearing-model-request-{swapped.request_id}"
            workspace.ensure_private_directory(directory)
            workspace.create_new(
                f"{directory}/receipt.json",
                original_journal,
                _digest(original_journal),
            )
            with pytest.raises(HearingModelResponseStoreError) as rejected:
                store.recover(swapped)
            assert rejected.value.reason_code == (
                HearingModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE
            )
        with pytest.raises(HearingModelResponseStoreError) as role_response_swap:
            store.verify_raw_response(RUN_ID, defender, response)
        assert role_response_swap.value.reason_code == (
            HearingModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE
        )
        with pytest.raises(HearingModelResponseStoreError) as repair_response_swap:
            store.verify_raw_response(RUN_ID, repair, response)
        assert repair_response_swap.value.reason_code == (
            HearingModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE
        )


def test_m4_store_fails_closed_for_raw_tamper_missing_and_cross_run(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    request = _request()
    payload = b'{"stable":true}'
    with SecureWorkspace(root, 128 * 1024) as workspace:
        response = SecureHearingModelResponseStore(workspace).publish(request, payload)
    raw_path = root / Path(response.raw_response_ref)
    raw_path.write_bytes(payload[::-1])
    with SecureWorkspace(root, 128 * 1024) as workspace:
        store = SecureHearingModelResponseStore(workspace)
        with pytest.raises(HearingModelResponseStoreError) as tampered:
            store.verify_raw_response(RUN_ID, request, response)
        assert tampered.value.reason_code == (
            HearingModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE
        )
        with pytest.raises(HearingModelResponseStoreError) as cross_run:
            store.verify("run-02", response)
        assert cross_run.value.reason_code == (
            HearingModelResponseStoreFailureCode.RUN_SCOPE_MISMATCH
        )
    raw_path.unlink()
    with SecureWorkspace(root, 128 * 1024) as workspace:
        with pytest.raises(HearingModelResponseStoreError) as missing:
            SecureHearingModelResponseStore(workspace).recover(request)
        assert missing.value.reason_code == (
            HearingModelResponseStoreFailureCode.RESPONSE_NOT_FOUND
        )


def test_repeated_acknowledgement_still_requires_exact_final_bytes(tmp_path: Path) -> None:
    root = _root(tmp_path)
    request = _request()
    with SecureWorkspace(root, 128 * 1024) as workspace:
        store = SecureHearingModelResponseStore(workspace)
        response = store.publish(request, b'{"ack":true}')
        store.acknowledge(request, response)
    (root / Path(response.raw_response_ref)).unlink()

    with (
        SecureWorkspace(root, 128 * 1024) as workspace,
        pytest.raises(HearingModelResponseStoreError) as missing,
    ):
        SecureHearingModelResponseStore(workspace).acknowledge(request, response)
    assert missing.value.reason_code == (HearingModelResponseStoreFailureCode.RESPONSE_NOT_FOUND)


def test_immutable_hearing_cache_revalidates_raw_and_rejects_conflicts(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    request = _request()
    with SecureWorkspace(root, 128 * 1024) as workspace:
        store = SecureHearingModelResponseStore(workspace)
        first = store.publish(request, b'{"answer":1}')
        cache = ImmutableHearingVLMResponseCache(store)
        assert cache.get(RUN_ID, request) is None
        entry = cache.put(RUN_ID, request, first)
        assert cache.put(RUN_ID, request, first) == entry
        assert cache.get(RUN_ID, request) == entry
        assert cache.get_response(RUN_ID, request) == first
        assert cache.verify_hit(RUN_ID, request, entry, first) == entry

        store.acknowledge(request, first)
        second = store.publish(request, b'{"answer":2}')
        with pytest.raises(HearingModelResponseStoreError) as conflict:
            cache.put(RUN_ID, request, second)
        assert conflict.value.reason_code == (HearingModelResponseStoreFailureCode.CACHE_CONFLICT)


@pytest.mark.parametrize("damage", ["missing", "raw", "metadata"])
def test_known_hearing_cache_entry_never_degrades_tamper_to_miss(
    tmp_path: Path,
    damage: str,
) -> None:
    root = _root(tmp_path)
    request = _request()
    with SecureWorkspace(root, 128 * 1024) as workspace:
        store = SecureHearingModelResponseStore(workspace)
        response = store.publish(request, b'{"answer":1}')
        cache = ImmutableHearingVLMResponseCache(store)
        cache.put(RUN_ID, request, response)
        raw_path = root / Path(response.raw_response_ref)
        if damage == "missing":
            raw_path.unlink()
        elif damage == "raw":
            raw_path.write_bytes(b'{"answer":0}')
        else:
            bindings = object.__getattribute__(cache, "_bindings")
            key = (RUN_ID, request.cache_key)
            cached = bindings[key]
            bindings[key] = type(cached)(
                entry=cached.entry.model_copy(update={"case_id": "case-02"}),
                response=cached.response,
            )

        with pytest.raises(HearingModelResponseStoreError) as rejected:
            cache.get(RUN_ID, request)
        expected = (
            HearingModelResponseStoreFailureCode.RESPONSE_NOT_FOUND
            if damage == "missing"
            else HearingModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE
            if damage == "raw"
            else HearingModelResponseStoreFailureCode.CACHE_INTEGRITY_FAILURE
        )
        assert rejected.value.reason_code == expected


def test_m4_store_enforces_call_and_read_budgets_without_parsing(tmp_path: Path) -> None:
    root = _root(tmp_path)
    request = _request(max_response_bytes=1)
    with SecureWorkspace(root, 128 * 1024) as workspace:
        store = SecureHearingModelResponseStore(workspace)
        with pytest.raises(HearingModelResponseStoreError) as oversized:
            store.publish(request, b"xx")
        assert oversized.value.reason_code == (
            HearingModelResponseStoreFailureCode.CALL_BUDGET_EXCEEDED
        )

        valid = _request()
        response = store.publish(valid, b"\xff")
        with pytest.raises(HearingModelResponseStoreError) as utf8:
            store.read_json(RUN_ID, response, 1)
        assert utf8.value.reason_code == (
            HearingModelResponseStoreFailureCode.RESPONSE_UTF8_INVALID
        )
        with pytest.raises(HearingModelResponseStoreError) as limited:
            store.read_bytes(RUN_ID, response, 0)
        assert limited.value.reason_code == (
            HearingModelResponseStoreFailureCode.READ_LIMIT_EXCEEDED
        )

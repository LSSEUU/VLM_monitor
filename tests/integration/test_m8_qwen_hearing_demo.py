from __future__ import annotations

import json
import shutil
from pathlib import Path

from PIL import Image

from labcourt.adapters.fake_hearing_precedents import FakeHearingPrecedentRetriever
from labcourt.adapters.pillow_media import encode_rgb_png
from labcourt.adapters.storage.sqlite_repository import SQLiteEvidenceRepository
from labcourt.adapters.vlm.openai_compatible import (
    OpenAICompatibleTransportRequest,
    OpenAICompatibleTransportResponse,
)
from labcourt.application.hearing_precedent_retrieval import (
    HearingPrecedentRetrievalService,
)
from labcourt.contracts.canonical import canonical_bytes
from labcourt.contracts.enums import (
    AcquisitionAction,
    AlertLevel,
    ArtifactKind,
    CaseStatus,
    JudgeDisposition,
    VerdictDecision,
)
from labcourt.contracts.evidence import RecropParameters
from labcourt.contracts.hearing import (
    AcquisitionRequestPayload,
    DefenderModelPayload,
    JudgeAcquisitionDecisionPayload,
    JudgeFinalDecisionPayload,
    JudgeModelPayload,
)
from labcourt.contracts.m3_models import EvidenceCitation
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.storage import ArtifactRef
from labcourt.contracts.verdicts import JudgeResponse
from labcourt.services.m4_operations import build_hearing_prompt_catalog
from labcourt.services.m8_qwen_hearing_demo import (
    QWEN_MODEL_SNAPSHOT,
    QWEN_PROFILE_NAMES,
    _demo_api,
    _http_json,
    load_m8_qwen_hearing_demo,
    prepare_m8_qwen_hearing_demo,
    run_m8_qwen_hearing_demo,
)
from tests.integration.test_m4_hearing_coordinator import (
    _digest,
    _fixtures_for_terminal_hearing,
)

ROOT = Path(__file__).parents[2]


class _RoleTransport:
    def __init__(
        self,
        response_id: str,
        content: tuple[bytes, ...],
        *,
        original_crop_id: str | None = None,
        original_defense_argument_id: str | None = None,
    ) -> None:
        self.response_id = response_id
        self.content = content
        self.original_crop_id = original_crop_id
        self.original_defense_argument_id = original_defense_argument_id
        self.calls: list[OpenAICompatibleTransportRequest] = []

    def send(
        self,
        request: OpenAICompatibleTransportRequest,
    ) -> OpenAICompatibleTransportResponse:
        self.calls.append(request)
        body = json.loads(request.body)
        assert body["model"] == QWEN_MODEL_SNAPSHOT
        assert body["enable_thinking"] is False
        assert body["response_format"] == {"type": "json_object"}
        index = len(self.calls) - 1
        response_id = f"{self.response_id}-{index + 1}"
        content = self.content[index].decode("utf-8")
        if index > 0 and self.original_crop_id is not None:
            prompt = body["messages"][0]["content"][0]["text"]
            allowed_line = next(
                line for line in prompt.splitlines() if line.startswith("ALLOWED_REFS_JSON=")
            )
            allowed = json.loads(allowed_line.removeprefix("ALLOWED_REFS_JSON="))
            current_crop_id = next(
                item["artifact_id"] for item in allowed if item["kind"] == "CROP"
            )
            content = content.replace(self.original_crop_id, current_crop_id)
        if index > 0 and self.original_defense_argument_id is not None:
            prompt = body["messages"][0]["content"][0]["text"]
            defender_line = next(
                line for line in prompt.splitlines() if line.startswith("DEFENDER_OUTPUT_JSON=")
            )
            defender = json.loads(defender_line.removeprefix("DEFENDER_OUTPUT_JSON="))
            current_argument_id = defender["payload"]["arguments"][0]["argument_id"]
            content = content.replace(
                self.original_defense_argument_id,
                current_argument_id,
            )
        return OpenAICompatibleTransportResponse(
            body=json.dumps(
                {
                    "id": response_id,
                    "choices": [
                        {
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": content,
                            },
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {"prompt_tokens": 2, "completion_tokens": 3},
                }
            ).encode("utf-8"),
            latency_ms=4,
        )


def _write_image(path: Path, color: tuple[int, int, int]) -> None:
    width, height = 32, 24
    path.write_bytes(encode_rgb_png(width, height, bytes(color) * width * height))
    with Image.open(path) as image:
        assert image.size == (width, height)


def test_qwen_demo_runs_authenticated_three_role_api_with_mocked_provider(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    del socket_enabled
    output = tmp_path / "m8-qwen-demo"
    source = output / "source"
    source.mkdir(parents=True)
    primary = source / "primary.png"
    supplementary = source / "supplementary.png"
    _write_image(primary, (60, 90, 120))
    _write_image(supplementary, (120, 90, 60))
    preparation = prepare_m8_qwen_hearing_demo(
        output_root=output,
        primary_image=primary,
        supplementary_image=supplementary,
        base_config_path=ROOT / "configs" / "demo.yaml",
    )
    missing_config_output = tmp_path / "missing-config"
    shutil.copytree(output, missing_config_output)
    missing_config = run_m8_qwen_hearing_demo(
        output_root=missing_config_output,
        environment={},
    )
    assert missing_config.outcome.value == "CONFIGURATION_FAILED"
    assert missing_config.delivery_state.value == "DEFINITELY_NOT_SENT"
    assert missing_config.external_call_attempted is False
    assert missing_config.reason_code == "QWEN_CONFIGURATION_MISSING"
    assert missing_config.provider_receipts == ()
    config, loaded = load_m8_qwen_hearing_demo(output)
    assert loaded == preparation
    workspace = output / "hearing-workspace"
    repository = SQLiteEvidenceRepository(
        workspace / config.storage.database_filename,
        config.storage.busy_timeout_ms,
    )
    case = repository.load_case(preparation.run_id, preparation.case_id)
    assert case.case.status == CaseStatus.ESCALATED
    manifest = RunManifest.model_validate_json((output / "run-manifest.json").read_text("utf-8"))
    catalog = build_hearing_prompt_catalog()
    precedents = HearingPrecedentRetrievalService(
        FakeHearingPrecedentRetriever(()),
        retriever_version="fake-hearing-precedents-v1",
        retriever_manifest_id=_digest("fake-hearing-precedents"),
    )
    fixtures = _fixtures_for_terminal_hearing(
        source_case=case,
        config=config,
        manifest=manifest,
        catalog=catalog,
        precedents=precedents,
    )
    raw = [fixture.raw_response for fixture in fixtures.values()]
    assert all(item is not None for item in raw)
    pack = case.case.evidence_packs[-1]
    crop_ref = ArtifactRef(kind=ArtifactKind.CROP, artifact_id=pack.crops[0].crop_id)
    defender = DefenderModelPayload.model_validate_json(raw[1] or b"")
    defense_argument_id = defender.arguments[0].argument_id
    judge_response = JudgeResponse(
        defense_argument_id=defense_argument_id,
        disposition=JudgeDisposition.PARTIALLY_ACCEPTED,
        response_summary="The ambiguity warrants one bounded synthetic recrop.",
    )
    acquisition_judge = canonical_bytes(
        JudgeModelPayload(
            judge_responses=(judge_response,),
            outcome=JudgeAcquisitionDecisionPayload(
                request=AcquisitionRequestPayload(
                    action=AcquisitionAction.RECROP,
                    validated_parameters=RecropParameters(
                        action=AcquisitionAction.RECROP,
                        frame_id=pack.key_frame_ids[0],
                        bbox=pack.crops[0].bbox,
                    ),
                    reason_summary="Use the sealed synthetic supplementary view once.",
                    supporting_evidence_refs=(crop_ref,),
                )
            ),
        ).model_dump(mode="json", exclude_computed_fields=True)
    )
    final_judge = canonical_bytes(
        JudgeModelPayload(
            judge_responses=(
                JudgeResponse(
                    defense_argument_id=defense_argument_id,
                    disposition=JudgeDisposition.ACCEPTED,
                    response_summary="The sealed recrop does not resolve the ambiguity.",
                ),
            ),
            outcome=JudgeFinalDecisionPayload(
                decision=VerdictDecision.INSUFFICIENT_EVIDENCE,
                confidence=0.5,
                recommended_alert_level=AlertLevel.ADVISORY,
                rationale_summary="The synthetic views remain insufficient for an absence finding.",
                evidence_citations=(EvidenceCitation(evidence_ref=crop_ref),),
            ),
        ).model_dump(mode="json", exclude_computed_fields=True)
    )
    role_contents = {
        QWEN_PROFILE_NAMES[0]: (raw[0] or b"", raw[0] or b""),
        QWEN_PROFILE_NAMES[1]: (raw[1] or b"", raw[1] or b""),
        QWEN_PROFILE_NAMES[2]: (acquisition_judge, final_judge),
    }
    transports = {
        profile: _RoleTransport(
            f"chatcmpl-{index}",
            role_contents[profile],
            original_crop_id=crop_ref.artifact_id,
            original_defense_argument_id=(
                defense_argument_id if profile == QWEN_PROFILE_NAMES[2] else None
            ),
        )
        for index, profile in enumerate(QWEN_PROFILE_NAMES, start=1)
    }

    attempt = run_m8_qwen_hearing_demo(
        output_root=output,
        transports=transports,
    )

    assert attempt.outcome.value == "COMPLETED"
    assert len(attempt.provider_receipts) == 6
    assert [item.provider_response_id for item in attempt.provider_receipts[:3]] == [
        "chatcmpl-1-1",
        "chatcmpl-2-1",
        "chatcmpl-3-1",
    ]
    assert all(len(transport.calls) == 2 for transport in transports.values())
    view = json.loads((output / "hearing-view.json").read_text("utf-8"))
    assert [item["role"] for item in view["role_outputs"][:3]] == [
        "PROSECUTOR",
        "DEFENDER",
        "JUDGE",
    ]
    assert view["final_verdict"] is not None
    assert len(view["acquisition_requests"]) == 1
    assert view["acquisition_requests"][0]["request_payload"]["action"] == "RECROP"
    assert len(view["tool_execution_receipts"]) == 1
    assert view["l5_status"] == "PASSED"
    assert view["case_status"] == "READY_FOR_ALERT_POLICY"
    report = (output / "hearing-record.md").read_text("utf-8")
    assert "chatcmpl-1-1" in report
    assert "PROSECUTOR" in report
    assert "DEFENDER" in report
    assert "JUDGE" in report
    assert QWEN_MODEL_SNAPSHOT in report

    blocked_transports = {
        profile: _RoleTransport(f"must-not-call-{index}", role_contents[profile])
        for index, profile in enumerate(QWEN_PROFILE_NAMES, start=1)
    }
    with _demo_api(
        output_root=output,
        config=config,
        preparation=preparation,
        transports=blocked_transports,
        environment={},
        port=0,
        start_enabled=False,
    ) as (base_url, _captured):
        status, body = _http_json(
            base_url,
            "POST",
            f"/api/m8/runs/{preparation.run_id}/cases/{preparation.case_id}/hearing",
            preparation.start_request.model_dump(mode="json"),
        )
    assert status == 403
    assert body["reason_code"] == "FORBIDDEN"
    assert all(not transport.calls for transport in blocked_transports.values())

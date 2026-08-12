"""Deterministic offline transports for the recorded PPE demonstration."""

from __future__ import annotations

import re
from dataclasses import dataclass

from labcourt.adapters.perception.local_worker import PerceptionWorkerExchange
from labcourt.adapters.vlm import (
    OpenAICompatibleTransportRequest,
    OpenAICompatibleTransportResponse,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.detections import Keypoint
from labcourt.contracts.pilot import (
    PilotPerceptionExecutionManifest,
    PilotPerceptionWorkerRequest,
    PilotPerceptionWorkerResponse,
    PilotWorkerBox,
    PilotWorkerDetection,
)

_CLEAR_IDS = re.compile(r'"clear_crop_ids"\s*:\s*\[(?P<values>[^]]+)\]')
_HEX_ID = re.compile(r'"(?P<value>[0-9a-f]{64})"')


class DeterministicRecordedPpePerceptionTransport:
    """Return typed people and pose landmarks over the real decoded MP4 pixels."""

    def __init__(self, manifest: PilotPerceptionExecutionManifest) -> None:
        self.manifest = manifest

    def exchange_with_raw(
        self,
        request: PilotPerceptionWorkerRequest,
    ) -> PerceptionWorkerExchange:
        detections = request.replay_detections
        if request.mode == "INFER":
            if self.manifest.pose is None:
                raise ValueError("platform PPE fixture requires a pose manifest")
            width = float(request.width)
            height = float(request.height)
            detections = (
                PilotWorkerDetection(
                    label="person",
                    source_label="person",
                    bbox=PilotWorkerBox(
                        x1=width * 0.27,
                        y1=height * 0.05,
                        x2=width * 0.73,
                        y2=height * 0.96,
                    ),
                    score=0.93,
                    local_track_id="recorded-subject-1",
                    keypoints=(
                        Keypoint(
                            name="left_eye",
                            x=width * 0.43,
                            y=height * 0.22,
                            score=0.95,
                        ),
                        Keypoint(
                            name="nose",
                            x=width * 0.50,
                            y=height * 0.30,
                            score=0.94,
                        ),
                        Keypoint(
                            name="right_eye",
                            x=width * 0.57,
                            y=height * 0.22,
                            score=0.96,
                        ),
                    ),
                    pose_manifest_id=self.manifest.pose.model_manifest_id,
                ),
            )
        response = PilotPerceptionWorkerResponse(
            request_id=request.request_id,
            frame_id=request.frame_id,
            frame_content_sha256=request.frame_content_sha256,
            manifest_id=request.expected_manifest_id,
            detections=detections,
        )
        raw = canonical_json(response.model_dump(mode="json")).encode("utf-8")
        return PerceptionWorkerExchange(result=response, raw_response=raw)

    def close(self) -> None:
        return None


@dataclass(slots=True)
class DeterministicRecordedPpeScreeningTransport:
    """Produce one strict structured weak label from prompt-authorized crop IDs."""

    calls: int = 0

    def send(
        self,
        request: OpenAICompatibleTransportRequest,
    ) -> OpenAICompatibleTransportResponse:
        self.calls += 1
        body_text = request.body.decode("utf-8")
        matched = _CLEAR_IDS.search(body_text.replace("\\\"", '"'))
        if matched is None:
            raise ValueError("platform PPE screening prompt lacks clear crop authority")
        crop_ids = tuple(
            match.group("value") for match in _HEX_ID.finditer(matched.group("values"))
        )
        if len(crop_ids) < 2:
            raise ValueError("platform PPE screening requires two clear temporal crops")
        content = canonical_json(
            {
                "evidence_citations": [
                    {
                        "bbox": None,
                        "coordinate_space": None,
                        "evidence_ref": {"artifact_id": crop_ids[0], "kind": "CROP"},
                    }
                ],
                "evidence_class": "ABSENCE",
                "frame_observations": [
                    {
                        "crop_id": crop_id,
                        "reason_summary": (
                            "The authorized eye-region crop is clear and goggles are not visible."
                        ),
                        "wear_status": "NOT_WORN",
                    }
                    for crop_id in crop_ids
                ],
                "objective_claims": [],
                "prosecution_summary": (
                    "Authorized clear temporal crops consistently show goggles not worn."
                ),
                "rationale_summary": (
                    "This is a deterministic structured fixture weak label for the local Demo."
                ),
                "violation_probability": 0.95,
                "violation_type": "PPE_GOGGLES_MISSING",
            }
        )
        envelope = canonical_json(
            {
                "choices": [
                    {
                        "finish_reason": "stop",
                        "index": 0,
                        "message": {"content": content, "role": "assistant"},
                    }
                ],
                "usage": {"completion_tokens": 100, "prompt_tokens": 200},
            }
        ).encode("utf-8")
        if len(envelope) > request.max_response_bytes:
            raise ValueError("platform PPE screening fixture exceeded response budget")
        return OpenAICompatibleTransportResponse(body=envelope, latency_ms=0)


__all__ = [
    "DeterministicRecordedPpePerceptionTransport",
    "DeterministicRecordedPpeScreeningTransport",
]

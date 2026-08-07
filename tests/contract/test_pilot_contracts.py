from __future__ import annotations

import pytest
from pydantic import ValidationError

from labcourt.contracts.enums import ViolationType
from labcourt.contracts.pilot import PilotRunRequest
from labcourt.schema_export import expected_schema_files


def _request() -> PilotRunRequest:
    return PilotRunRequest(
        run_id="pilot-001",
        config_sha256="1" * 64,
        video_relative_path="inputs/pilot-demo.mp4",
        video_sha256="2" * 64,
        selected_rules=(ViolationType.PPE_GOGGLES_MISSING,),
        resume=True,
        max_cases=20,
    )


def test_pilot_run_request_is_exported_and_round_trips() -> None:
    request = _request()
    assert PilotRunRequest.model_validate_json(request.model_dump_json()) == request
    assert "pilot-run-request.schema.json" in expected_schema_files()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("run_id", "CON"),
        ("video_relative_path", "../outside.mp4"),
        ("video_relative_path", "inputs/not-video.txt"),
        ("max_cases", 0),
        ("max_cases", True),
    ],
)
def test_pilot_run_request_rejects_untrusted_boundaries(field: str, value: object) -> None:
    payload = _request().model_dump(mode="python")
    payload[field] = value
    with pytest.raises(ValidationError):
        PilotRunRequest.model_validate(payload)


def test_pilot_run_request_rejects_duplicate_rules() -> None:
    payload = _request().model_dump(mode="python")
    payload["selected_rules"] = [
        ViolationType.PPE_GOGGLES_MISSING,
        ViolationType.PPE_GOGGLES_MISSING,
    ]
    with pytest.raises(ValidationError, match="unique"):
        PilotRunRequest.model_validate(payload)

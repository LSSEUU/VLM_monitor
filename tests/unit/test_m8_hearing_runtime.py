from __future__ import annotations

import sqlite3
from pathlib import Path

from labcourt.application.hearing_request import (
    FROZEN_M4_PROMPT_BUNDLE_SHA256,
    M8_HEARING_PROMPT_V2_BUNDLE_SHA256,
)
from labcourt.contracts.m8_hearing_api import M8HearingModelMode
from labcourt.services.m8_hearing_runtime import _hearing_prompt_bundle_for_run


def test_real_qwen_new_run_selects_v2_but_historical_run_keeps_its_bundle(
    tmp_path: Path,
) -> None:
    database = tmp_path / "hearing-runtime.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            CREATE TABLE m4_hearings (
                run_id TEXT NOT NULL,
                hearing_prompt_bundle_sha256 TEXT NOT NULL
            )
            """
        )

    assert (
        _hearing_prompt_bundle_for_run(
            database,
            "new-real-qwen-run",
            M8HearingModelMode.OPENAI_COMPATIBLE_QWEN,
        )
        == M8_HEARING_PROMPT_V2_BUNDLE_SHA256
    )
    assert (
        _hearing_prompt_bundle_for_run(
            database,
            "new-offline-run",
            M8HearingModelMode.OFFLINE_FIXTURE,
        )
        == FROZEN_M4_PROMPT_BUNDLE_SHA256
    )

    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            INSERT INTO m4_hearings(run_id, hearing_prompt_bundle_sha256)
            VALUES (?, ?)
            """,
            ("historical-run", FROZEN_M4_PROMPT_BUNDLE_SHA256),
        )

    assert (
        _hearing_prompt_bundle_for_run(
            database,
            "historical-run",
            M8HearingModelMode.OPENAI_COMPATIBLE_QWEN,
        )
        == FROZEN_M4_PROMPT_BUNDLE_SHA256
    )

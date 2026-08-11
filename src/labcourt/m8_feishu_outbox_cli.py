"""Explicit operator commands for Feishu sandbox send authority."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from labcourt.application.m8_feishu_outbox_authority import (
    commit_m8_feishu_outbox_activation,
    get_m8_feishu_outbox_activation_status,
    revoke_m8_feishu_outbox_activation,
)
from labcourt.contracts.m8_feishu_activation import M8FeishuSandboxRevocationReason
from labcourt.m8_feishu_cli_support import (
    OPERATOR_FAILURES,
    echo_summary,
    fail,
    parse_utc,
    read_document,
)


def register_m8_feishu_outbox_commands(feishu: typer.Typer) -> None:
    @feishu.command("outbox-activate")
    def outbox_activate(
        database: Annotated[
            Path,
            typer.Option("--database", exists=True, dir_okay=False, readable=True),
        ],
        activation_intent: Annotated[
            Path,
            typer.Option(
                "--activation-intent",
                exists=True,
                dir_okay=False,
                readable=True,
            ),
        ],
        runtime_config: Annotated[
            Path,
            typer.Option(
                "--runtime-config",
                exists=True,
                dir_okay=False,
                readable=True,
            ),
        ],
        runtime_config_storage_manifest_id: Annotated[
            str,
            typer.Option("--runtime-config-storage-manifest-id"),
        ],
        repository_manifest_id: Annotated[
            str,
            typer.Option("--repository-manifest-id"),
        ],
        assessment_manifest_id: Annotated[
            str,
            typer.Option("--assessment-manifest-id"),
        ],
        busy_timeout_ms: Annotated[
            int,
            typer.Option("--busy-timeout-ms", min=1, max=60_000),
        ] = 5_000,
        json_output: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        try:
            receipt = commit_m8_feishu_outbox_activation(
                database_path=database,
                activation_intent_document=read_document(
                    activation_intent,
                    "outbox activation intent",
                ),
                runtime_config_document=read_document(
                    runtime_config,
                    "outbox runtime config",
                ),
                runtime_config_storage_manifest_id=(
                    runtime_config_storage_manifest_id
                ),
                repository_manifest_id=repository_manifest_id,
                assessment_manifest_id=assessment_manifest_id,
                busy_timeout_ms=busy_timeout_ms,
            )
        except OPERATOR_FAILURES as error:
            fail("outbox activation", error)
        summary = {
            "activation_commit_id": receipt.activation_commit_id,
            "activation_revision": receipt.activation_revision,
            "activation_state": receipt.activation_state,
            "automatic_activation_permitted": (
                receipt.automatic_activation_permitted
            ),
            "production_external_call_permitted": (
                receipt.production_external_call_permitted
            ),
            "test_recipient_allowlist_only": receipt.test_recipient_allowlist_only,
        }
        echo_summary(
            summary,
            json_output,
            (
                "Feishu sandbox outbox activation committed: "
                f"{receipt.activation_commit_id}; no message was sent"
            ),
        )

    @feishu.command("outbox-revoke")
    def outbox_revoke(
        database: Annotated[
            Path,
            typer.Option("--database", exists=True, dir_okay=False, readable=True),
        ],
        activation_commit_id: Annotated[
            str,
            typer.Option("--activation-commit-id"),
        ],
        revoker_actor_id: Annotated[str, typer.Option("--revoker-actor-id")],
        reason: Annotated[
            M8FeishuSandboxRevocationReason,
            typer.Option("--reason"),
        ],
        reason_ref: Annotated[str, typer.Option("--reason-ref")],
        revoked_at: Annotated[
            str,
            typer.Option(
                "--revoked-at",
                help="Stable ISO-8601 UTC time reused for an exact retry.",
            ),
        ],
        revocation_manifest_id: Annotated[
            str,
            typer.Option("--revocation-manifest-id"),
        ],
        repository_manifest_id: Annotated[
            str,
            typer.Option("--repository-manifest-id"),
        ],
        assessment_manifest_id: Annotated[
            str,
            typer.Option("--assessment-manifest-id"),
        ],
        busy_timeout_ms: Annotated[
            int,
            typer.Option("--busy-timeout-ms", min=1, max=60_000),
        ] = 5_000,
        json_output: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        try:
            receipt = revoke_m8_feishu_outbox_activation(
                database_path=database,
                activation_commit_id=activation_commit_id,
                revoker_actor_id=revoker_actor_id,
                reason=reason,
                reason_ref=reason_ref,
                revoked_at=parse_utc(revoked_at, "outbox revoked_at"),
                revocation_manifest_id=revocation_manifest_id,
                repository_manifest_id=repository_manifest_id,
                assessment_manifest_id=assessment_manifest_id,
                busy_timeout_ms=busy_timeout_ms,
            )
        except OPERATOR_FAILURES as error:
            fail("outbox revocation", error)
        summary = {
            "activation_commit_id": receipt.activation_receipt.activation_commit_id,
            "activation_state": receipt.activation_state,
            "automatic_reactivation_permitted": (
                receipt.automatic_reactivation_permitted
            ),
            "revocation_commit_id": receipt.revocation_commit_id,
            "sandbox_external_call_permitted": (
                receipt.sandbox_external_call_permitted
            ),
        }
        echo_summary(
            summary,
            json_output,
            f"Feishu sandbox outbox activation revoked: {receipt.revocation_commit_id}",
        )

    @feishu.command("outbox-status")
    def outbox_status(
        database: Annotated[
            Path,
            typer.Option("--database", exists=True, dir_okay=False, readable=True),
        ],
        candidate_authority_id: Annotated[
            str,
            typer.Option("--candidate-authority-id"),
        ],
        repository_manifest_id: Annotated[
            str,
            typer.Option("--repository-manifest-id"),
        ],
        assessment_manifest_id: Annotated[
            str,
            typer.Option("--assessment-manifest-id"),
        ],
        busy_timeout_ms: Annotated[
            int,
            typer.Option("--busy-timeout-ms", min=1, max=60_000),
        ] = 5_000,
        json_output: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        try:
            status = get_m8_feishu_outbox_activation_status(
                database_path=database,
                candidate_authority_id=candidate_authority_id,
                repository_manifest_id=repository_manifest_id,
                assessment_manifest_id=assessment_manifest_id,
                busy_timeout_ms=busy_timeout_ms,
            )
        except OPERATOR_FAILURES as error:
            fail("outbox status", error)
        summary = {
            "activation_commit_id": status.activation_receipt.activation_commit_id,
            "activation_state": status.activation_state,
            "recipient_authority_current": status.recipient_authority_current,
            "sandbox_external_call_permitted": (
                status.sandbox_external_call_permitted
            ),
            "test_recipient_allowlist_only": status.test_recipient_allowlist_only,
        }
        echo_summary(
            summary,
            json_output,
            f"Feishu sandbox outbox status: {status.activation_state}",
        )


__all__ = ["register_m8_feishu_outbox_commands"]

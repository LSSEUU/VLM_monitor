"""Explicit operator CLI for the activation-gated Feishu webhook backend."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Annotated, NoReturn

import typer

from labcourt.adapters.storage.sqlite_repository import RepositoryIntegrityError
from labcourt.application.m8_feishu_webhook_authority import (
    commit_m8_feishu_webhook_activation,
    get_m8_feishu_webhook_activation_status,
    revoke_m8_feishu_webhook_activation,
)
from labcourt.application.m8_feishu_webhook_runtime import (
    build_m8_feishu_webhook_runtime,
)
from labcourt.contracts.m8_adapter_commissioning import MAX_M8_RUNTIME_CONFIG_BYTES
from labcourt.contracts.m8_feishu_inbound_activation import (
    M8FeishuInboundRevocationReason,
)
from labcourt.exceptions import ConcurrentModification, ContractViolation, EvidenceMissing

_OPERATOR_FAILURES = (
    ConcurrentModification,
    ContractViolation,
    EvidenceMissing,
    RepositoryIntegrityError,
    OSError,
    TypeError,
    ValueError,
    sqlite3.DatabaseError,
)


def _read_document(path: Path, name: str) -> bytes:
    document = path.read_bytes()
    if not 0 < len(document) <= MAX_M8_RUNTIME_CONFIG_BYTES:
        raise ValueError(f"Feishu webhook {name} exceeds the allowed bound")
    return document


def _parse_utc(value: str, name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"Feishu webhook {name} must be an ISO-8601 UTC time") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError(f"Feishu webhook {name} must be an ISO-8601 UTC time")
    return parsed


def _fail(operation: str, error: Exception) -> NoReturn:
    typer.echo(f"Feishu webhook {operation} failed: {error}", err=True)
    raise typer.Exit(code=2)


def _echo(summary: dict[str, object], json_output: bool, message: str) -> None:
    typer.echo(
        json.dumps(summary, ensure_ascii=True, sort_keys=True)
        if json_output
        else message
    )


def register_m8_feishu_commands(root: typer.Typer) -> None:
    feishu = typer.Typer(help="Explicit Feishu sandbox operator commands.")
    root.add_typer(feishu, name="feishu")

    @feishu.command("webhook-activate")
    def webhook_activate(
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
            receipt = commit_m8_feishu_webhook_activation(
                database_path=database,
                activation_intent_document=_read_document(
                    activation_intent,
                    "activation intent",
                ),
                runtime_config_document=_read_document(
                    runtime_config,
                    "runtime config",
                ),
                runtime_config_storage_manifest_id=(
                    runtime_config_storage_manifest_id
                ),
                repository_manifest_id=repository_manifest_id,
                assessment_manifest_id=assessment_manifest_id,
                busy_timeout_ms=busy_timeout_ms,
            )
        except _OPERATOR_FAILURES as error:
            _fail("activation", error)
        summary = {
            "activation_commit_id": receipt.activation_commit_id,
            "activation_revision": receipt.activation_revision,
            "activation_state": receipt.activation_state,
            "business_event_ingress_permitted": (
                receipt.business_event_ingress_permitted
            ),
            "listener_autostart_permitted": receipt.listener_autostart_permitted,
            "production_external_ingress_permitted": (
                receipt.production_external_ingress_permitted
            ),
        }
        _echo(
            summary,
            json_output,
            (
                "Feishu sandbox webhook activation committed: "
                f"{receipt.activation_commit_id}; listener remains stopped"
            ),
        )

    @feishu.command("webhook-revoke")
    def webhook_revoke(
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
            M8FeishuInboundRevocationReason,
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
            receipt = revoke_m8_feishu_webhook_activation(
                database_path=database,
                activation_commit_id=activation_commit_id,
                revoker_actor_id=revoker_actor_id,
                reason=reason,
                reason_ref=reason_ref,
                revoked_at=_parse_utc(revoked_at, "revoked_at"),
                revocation_manifest_id=revocation_manifest_id,
                repository_manifest_id=repository_manifest_id,
                assessment_manifest_id=assessment_manifest_id,
                busy_timeout_ms=busy_timeout_ms,
            )
        except _OPERATOR_FAILURES as error:
            _fail("revocation", error)
        summary = {
            "activation_commit_id": receipt.activation_receipt.activation_commit_id,
            "activation_state": receipt.activation_state,
            "automatic_reactivation_permitted": (
                receipt.automatic_reactivation_permitted
            ),
            "revocation_commit_id": receipt.revocation_commit_id,
            "sandbox_external_ingress_permitted": (
                receipt.sandbox_external_ingress_permitted
            ),
        }
        _echo(
            summary,
            json_output,
            (
                "Feishu sandbox webhook activation revoked: "
                f"{receipt.revocation_commit_id}"
            ),
        )

    @feishu.command("webhook-status")
    def webhook_status(
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
            status = get_m8_feishu_webhook_activation_status(
                database_path=database,
                candidate_authority_id=candidate_authority_id,
                repository_manifest_id=repository_manifest_id,
                assessment_manifest_id=assessment_manifest_id,
                busy_timeout_ms=busy_timeout_ms,
            )
        except _OPERATOR_FAILURES as error:
            _fail("status", error)
        summary = {
            "activation_commit_id": status.activation_receipt.activation_commit_id,
            "activation_state": status.activation_state,
            "business_event_ingress_permitted": status.business_event_ingress_permitted,
            "sandbox_external_ingress_permitted": (
                status.sandbox_external_ingress_permitted
            ),
            "url_challenge_permitted": status.url_challenge_permitted,
        }
        _echo(
            summary,
            json_output,
            f"Feishu sandbox webhook status: {status.activation_state}",
        )

    @feishu.command("webhook-serve")
    def webhook_serve(
        database: Annotated[
            Path,
            typer.Option("--database", exists=True, dir_okay=False, readable=True),
        ],
        candidate_authority_id: Annotated[
            str,
            typer.Option("--candidate-authority-id"),
        ],
        encrypt_key_env: Annotated[str, typer.Option("--encrypt-key-env")],
        verification_token_env: Annotated[
            str,
            typer.Option("--verification-token-env"),
        ],
        runtime_manifest_id: Annotated[
            str,
            typer.Option("--runtime-manifest-id"),
        ],
        busy_timeout_ms: Annotated[
            int,
            typer.Option("--busy-timeout-ms", min=1, max=60_000),
        ] = 5_000,
        check: Annotated[
            bool,
            typer.Option("--check", help="Validate and bind once, then close without serving."),
        ] = False,
        json_output: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        try:
            assembly = build_m8_feishu_webhook_runtime(
                database_path=database,
                candidate_authority_id=candidate_authority_id,
                encrypt_key_env=encrypt_key_env,
                verification_token_env=verification_token_env,
                runtime_manifest_id=runtime_manifest_id,
                busy_timeout_ms=busy_timeout_ms,
            )
        except _OPERATOR_FAILURES as error:
            _fail("startup", error)

        server = assembly.server
        config = assembly.activation_status.activation_receipt.runtime_config
        mode = "CHECKED" if check else "SERVING"
        summary = {
            "activation_commit_id": (
                assembly.activation_status.activation_receipt.activation_commit_id
            ),
            "bind_host": config.application_bind_host,
            "bind_port": server.server_port,
            "callback_path": config.callback_path,
            "mode": mode,
            "public_tls_managed_by_labcourt": False,
            "sandbox_external_ingress_permitted": True,
        }
        _echo(
            summary,
            json_output,
            (
                "Feishu sandbox webhook "
                f"{mode.lower()} on "
                f"http://{summary['bind_host']}:{summary['bind_port']}"
                f"{summary['callback_path']}; public TLS remains external"
            ),
        )
        if check:
            server.server_close()
            return
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()


__all__ = ["register_m8_feishu_commands"]

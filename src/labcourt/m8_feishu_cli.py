"""Explicit operator CLI for the activation-gated Feishu webhook backend."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Annotated

import typer

from labcourt.adapters.storage.sqlite_repository import RepositoryIntegrityError
from labcourt.application.m8_feishu_webhook_runtime import (
    build_m8_feishu_webhook_runtime,
)
from labcourt.exceptions import ConcurrentModification, ContractViolation, EvidenceMissing


def register_m8_feishu_commands(root: typer.Typer) -> None:
    feishu = typer.Typer(help="Explicit Feishu sandbox operator commands.")
    root.add_typer(feishu, name="feishu")

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
        except (
            ConcurrentModification,
            ContractViolation,
            EvidenceMissing,
            RepositoryIntegrityError,
            OSError,
            TypeError,
            ValueError,
            sqlite3.DatabaseError,
        ) as error:
            typer.echo(f"Feishu webhook startup failed: {error}", err=True)
            raise typer.Exit(code=2) from None

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
        typer.echo(
            json.dumps(summary, ensure_ascii=True, sort_keys=True)
            if json_output
            else (
                "Feishu sandbox webhook "
                f"{mode.lower()} on "
                f"http://{summary['bind_host']}:{summary['bind_port']}"
                f"{summary['callback_path']}; public TLS remains external"
            )
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

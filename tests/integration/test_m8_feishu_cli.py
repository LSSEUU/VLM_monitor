from __future__ import annotations

from typer.core import TyperCommand, TyperGroup
from typer.main import get_command

from labcourt.cli import app


def test_feishu_webhook_command_is_explicit_and_documents_check_mode() -> None:
    root = get_command(app)
    assert isinstance(root, TyperGroup)
    feishu = root.commands["feishu"]
    assert isinstance(feishu, TyperGroup)
    assert set(feishu.commands) >= {
        "webhook-activate",
        "webhook-revoke",
        "webhook-serve",
        "webhook-status",
    }
    serve = feishu.commands["webhook-serve"]
    assert isinstance(serve, TyperCommand)

    options = {option for parameter in serve.params for option in parameter.opts}
    assert {
        "--database",
        "--candidate-authority-id",
        "--encrypt-key-env",
        "--verification-token-env",
        "--runtime-manifest-id",
        "--check",
    } <= options

    activate = feishu.commands["webhook-activate"]
    assert isinstance(activate, TyperCommand)
    activation_options = {
        option for parameter in activate.params for option in parameter.opts
    }
    assert {
        "--activation-intent",
        "--runtime-config",
        "--runtime-config-storage-manifest-id",
        "--repository-manifest-id",
        "--assessment-manifest-id",
    } <= activation_options

    revoke = feishu.commands["webhook-revoke"]
    assert isinstance(revoke, TyperCommand)
    revocation_options = {
        option for parameter in revoke.params for option in parameter.opts
    }
    assert {
        "--activation-commit-id",
        "--revoker-actor-id",
        "--reason",
        "--reason-ref",
        "--revoked-at",
        "--revocation-manifest-id",
    } <= revocation_options

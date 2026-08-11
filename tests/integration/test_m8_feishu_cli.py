from __future__ import annotations

from typer.core import TyperCommand, TyperGroup
from typer.main import get_command

from labcourt.cli import app


def test_feishu_webhook_command_is_explicit_and_documents_check_mode() -> None:
    root = get_command(app)
    assert isinstance(root, TyperGroup)
    feishu = root.commands["feishu"]
    assert isinstance(feishu, TyperGroup)
    command = feishu.commands["webhook-serve"]
    assert isinstance(command, TyperCommand)

    options = {option for parameter in command.params for option in parameter.opts}
    assert {
        "--database",
        "--candidate-authority-id",
        "--encrypt-key-env",
        "--verification-token-env",
        "--runtime-manifest-id",
        "--check",
    } <= options

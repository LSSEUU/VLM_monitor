from __future__ import annotations

import sqlite3
from typing import NoReturn

import pytest

from labcourt.adapters.storage import _sqlite_migration_contract_functions as functions


def _raise_unexpected(*_args: object, **_kwargs: object) -> NoReturn:
    raise RuntimeError("provider payload must stay private")


def test_migration_sha256_utf8_fails_closed_for_type_and_internal_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert functions.migration_sha256_utf8(None) is None
    assert functions.migration_sha256_utf8(b"{}") is None

    monkeypatch.setattr(functions.hashlib, "sha256", _raise_unexpected)
    assert functions.migration_sha256_utf8("{}") is None


def test_migration_contract_validator_fails_closed_for_unknown_or_invalid_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert functions.migration_contract_is_canonical("unknown-kind", "{}") == 0
    assert functions.migration_contract_is_canonical(None, "{}") == 0
    assert functions.migration_contract_is_canonical("execution-scope-v1", b"{}") == 0
    assert functions.migration_contract_is_canonical("execution-scope-v1", "not-json") == 0

    class ExplodingModel:
        model_validate_json = staticmethod(_raise_unexpected)

    monkeypatch.setitem(
        functions._MIGRATION_CONTRACT_TYPES,
        "execution-scope-v1",
        ExplodingModel,
    )
    assert functions.migration_contract_is_canonical("execution-scope-v1", "{}") == 0


def test_registered_migration_functions_return_only_closed_sql_values() -> None:
    with sqlite3.connect(":memory:") as connection:
        connection.execute("PRAGMA trusted_schema = OFF")
        functions.register_migration_contract_functions(connection)
        assert connection.execute("SELECT labcourt_migration_sha256_utf8(NULL)").fetchone() == (
            None,
        )
        assert connection.execute(
            "SELECT labcourt_migration_contract_is_canonical('unknown-kind', '{}')"
        ).fetchone() == (0,)

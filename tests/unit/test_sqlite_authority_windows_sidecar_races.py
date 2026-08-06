from __future__ import annotations

from pathlib import Path

import pytest

from labcourt.adapters.storage.sqlite_authority import (
    SQLiteAuthorityError,
    _Identity,
    _WindowsAuthorityBackend,
    _WindowsFailure,
    _WindowsHeldFile,
)


class _RetiredThenMissingApi:
    FILE_ATTRIBUTE_REPARSE_POINT = 0x400
    FILE_ATTRIBUTE_DIRECTORY = 0x10

    def __init__(self) -> None:
        self.opens = [101, None]
        self.closed: list[int] = []

    def open_file(self, _path: str, *, sidecar: bool) -> int | None:
        assert sidecar is True
        return self.opens.pop(0)

    def identity_and_attributes(self, handle: int) -> tuple[_Identity, int, int]:
        assert handle == 101
        return _Identity(1, 101), 0, 0

    @staticmethod
    def is_disk_object(_handle: int) -> bool:
        return True

    @staticmethod
    def final_path(_handle: int) -> str:
        raise AssertionError("a zero-link sidecar must not be path-validated")

    def close(self, handle: int) -> None:
        self.closed.append(handle)


class _PathRaceThenReplacementApi:
    FILE_ATTRIBUTE_REPARSE_POINT = 0x400
    FILE_ATTRIBUTE_DIRECTORY = 0x10

    def __init__(self, expected_path: str) -> None:
        self.expected_path = expected_path
        self.opens = [201, 202]
        self.closed: list[int] = []
        self.identity_calls: dict[int, int] = {}

    def open_file(self, _path: str, *, sidecar: bool) -> int | None:
        assert sidecar is True
        return self.opens.pop(0)

    def identity_and_attributes(self, handle: int) -> tuple[_Identity, int, int]:
        calls = self.identity_calls.get(handle, 0)
        self.identity_calls[handle] = calls + 1
        if handle == 201:
            return _Identity(1, 201), 0, 1 if calls == 0 else 0
        assert handle == 202
        return _Identity(1, 202), 0, 1

    @staticmethod
    def is_disk_object(_handle: int) -> bool:
        return True

    def final_path(self, handle: int) -> str:
        return "retired-object-without-current-name" if handle == 201 else self.expected_path

    def close(self, handle: int) -> None:
        self.closed.append(handle)


class _HardlinkedApi:
    FILE_ATTRIBUTE_REPARSE_POINT = 0x400
    FILE_ATTRIBUTE_DIRECTORY = 0x10

    def __init__(self) -> None:
        self.closed: list[int] = []

    @staticmethod
    def open_file(_path: str, *, sidecar: bool) -> int:
        assert sidecar is True
        return 301

    @staticmethod
    def identity_and_attributes(_handle: int) -> tuple[_Identity, int, int]:
        return _Identity(1, 301), 0, 2

    @staticmethod
    def is_disk_object(_handle: int) -> bool:
        return True

    @staticmethod
    def final_path(_handle: int) -> str:
        raise AssertionError("a multi-link sidecar must fail before path validation")

    def close(self, handle: int) -> None:
        self.closed.append(handle)


class _UnsafeSidecarApi:
    FILE_ATTRIBUTE_REPARSE_POINT = 0x400
    FILE_ATTRIBUTE_DIRECTORY = 0x10

    def __init__(
        self,
        *,
        identities: list[_Identity],
        attributes: int = 0,
        link_counts: list[int] | None = None,
        final_path: str = r"\\?\Volume{outside}\escaped",
    ) -> None:
        self.identities = identities
        self.attributes = attributes
        self.link_counts = link_counts or [1] * len(identities)
        self.observed_final_path = final_path
        self.closed: list[int] = []

    @staticmethod
    def open_file(_path: str, *, sidecar: bool) -> int:
        assert sidecar is True
        return 401

    def identity_and_attributes(self, _handle: int) -> tuple[_Identity, int, int]:
        return self.identities.pop(0), self.attributes, self.link_counts.pop(0)

    @staticmethod
    def is_disk_object(_handle: int) -> bool:
        return True

    def final_path(self, _handle: int) -> str:
        return self.observed_final_path

    def close(self, handle: int) -> None:
        self.closed.append(handle)


class _AlwaysRetiredApi:
    FILE_ATTRIBUTE_REPARSE_POINT = 0x400
    FILE_ATTRIBUTE_DIRECTORY = 0x10

    def __init__(self) -> None:
        self.opens = list(range(501, 509))
        self.closed: list[int] = []

    def open_file(self, _path: str, *, sidecar: bool) -> int:
        assert sidecar is True
        return self.opens.pop(0)

    @staticmethod
    def identity_and_attributes(handle: int) -> tuple[_Identity, int, int]:
        return _Identity(1, handle), 0, 0

    @staticmethod
    def is_disk_object(_handle: int) -> bool:
        return True

    @staticmethod
    def final_path(_handle: int) -> str:
        raise AssertionError("a zero-link sidecar must not be path-validated")

    def close(self, handle: int) -> None:
        self.closed.append(handle)


class _TemporaryCloseFailureDuringRetirementApi:
    FILE_ATTRIBUTE_REPARSE_POINT = 0x400
    FILE_ATTRIBUTE_DIRECTORY = 0x10

    def __init__(self, expected_path: str) -> None:
        self.expected_path = expected_path
        self.held_info_calls = 0
        self.closed: list[int] = []

    @staticmethod
    def open_file(_path: str, *, sidecar: bool) -> int:
        assert sidecar is True
        return 602

    def identity_and_attributes(self, handle: int) -> tuple[_Identity, int, int]:
        if handle == 601:
            self.held_info_calls += 1
            link_count = 1 if self.held_info_calls == 1 else 0
            return _Identity(1, 601), 0, link_count
        assert handle == 602
        return _Identity(1, 601), 0, 1

    @staticmethod
    def is_disk_object(_handle: int) -> bool:
        return True

    def final_path(self, _handle: int) -> str:
        return self.expected_path

    def close(self, handle: int) -> None:
        self.closed.append(handle)
        if handle == 602:
            raise _WindowsFailure("DATABASE_HANDLE_CLOSE_FAILED")


def _backend(api: object) -> _WindowsAuthorityBackend:
    backend = _WindowsAuthorityBackend(Path("C:/workspace/labcourt.sqlite3"), allow_create=False)
    backend._api = api  # type: ignore[assignment]
    backend._parent_final_path = r"\\?\Volume{controlled}\workspace"
    return backend


def test_newly_opened_delete_pending_sidecar_is_retried_as_absent() -> None:
    api = _RetiredThenMissingApi()

    opened = _backend(api)._open_existing("labcourt.sqlite3-shm", sidecar=True)

    assert opened is None
    assert api.closed == [101]


def test_sidecar_path_race_reopens_and_validates_the_current_replacement() -> None:
    expected_path = r"\\?\Volume{controlled}\workspace\labcourt.sqlite3-shm"
    api = _PathRaceThenReplacementApi(expected_path)

    opened = _backend(api)._open_existing("labcourt.sqlite3-shm", sidecar=True)

    assert opened is not None
    assert opened.handle == 202
    assert opened.identity == _Identity(1, 202)
    assert api.closed == [201]


def test_sidecar_reopen_never_normalizes_a_hardlink_as_lifecycle_churn() -> None:
    api = _HardlinkedApi()

    with pytest.raises(SQLiteAuthorityError) as raised:
        _backend(api)._open_existing("labcourt.sqlite3-shm", sidecar=True)

    assert raised.value.reason_code == "DATABASE_SIDECAR_LINK_COUNT_UNSAFE"
    assert api.closed == [301]


def test_zero_link_reparse_sidecar_is_rejected_before_retirement_normalization() -> None:
    api = _UnsafeSidecarApi(
        identities=[_Identity(1, 401)],
        attributes=_UnsafeSidecarApi.FILE_ATTRIBUTE_REPARSE_POINT,
        link_counts=[0],
    )

    with pytest.raises(SQLiteAuthorityError) as raised:
        _backend(api)._open_existing("labcourt.sqlite3-shm", sidecar=True)

    assert raised.value.reason_code == "DATABASE_SIDECAR_REPARSE_POINT"
    assert api.closed == [401]


def test_single_link_path_escape_is_never_normalized_as_retirement() -> None:
    identity = _Identity(1, 401)
    api = _UnsafeSidecarApi(identities=[identity, identity], link_counts=[1, 1])

    with pytest.raises(SQLiteAuthorityError) as raised:
        _backend(api)._open_existing("labcourt.sqlite3-shm", sidecar=True)

    assert raised.value.reason_code == "DATABASE_SIDECAR_PATH_ESCAPE"
    assert api.closed == [401]


def test_hardlink_appearing_during_retirement_probe_is_rejected() -> None:
    identity = _Identity(1, 401)
    api = _UnsafeSidecarApi(identities=[identity, identity], link_counts=[1, 2])

    with pytest.raises(SQLiteAuthorityError) as raised:
        _backend(api)._open_existing("labcourt.sqlite3-shm", sidecar=True)

    assert raised.value.reason_code == "DATABASE_SIDECAR_LINK_COUNT_UNSAFE"
    assert api.closed == [401]


def test_identity_replacement_during_retirement_probe_is_rejected() -> None:
    api = _UnsafeSidecarApi(
        identities=[_Identity(1, 401), _Identity(1, 402)],
        link_counts=[1, 0],
    )

    with pytest.raises(SQLiteAuthorityError) as raised:
        _backend(api)._open_existing("labcourt.sqlite3-shm", sidecar=True)

    assert raised.value.reason_code == "DATABASE_SIDECAR_IDENTITY_CHANGED"
    assert api.closed == [401]


def test_sidecar_reopen_budget_is_bounded_and_closes_every_retired_handle() -> None:
    api = _AlwaysRetiredApi()

    with pytest.raises(SQLiteAuthorityError) as raised:
        _backend(api)._open_existing("labcourt.sqlite3-shm", sidecar=True)

    assert raised.value.reason_code == "DATABASE_SIDECAR_SET_UNSTABLE"
    assert api.opens == []
    assert api.closed == list(range(501, 509))


def test_temporary_handle_close_failure_is_not_hidden_by_old_sidecar_retirement() -> None:
    name = "labcourt.sqlite3-shm"
    expected_path = rf"\\?\Volume{{controlled}}\workspace\{name}"
    api = _TemporaryCloseFailureDuringRetirementApi(expected_path)
    backend = _backend(api)
    held = _WindowsHeldFile(601, _Identity(1, 601), expected_path)

    with pytest.raises(_WindowsFailure) as raised:
        backend._verify_current_sidecar(name, held)

    assert raised.value.reason_code == "DATABASE_HANDLE_CLOSE_FAILED"
    assert api.closed == [602]

"""Handle-anchored local workspace operations for M2 artifacts.

The adapter deliberately has no path-resolution fallback.  A platform that cannot
provide the required handle semantics fails closed with ``PathBoundaryViolation``.
"""

from __future__ import annotations

import contextlib
import ctypes
import errno
import hashlib
import os
import re
import stat
import sys
import time
import unicodedata
from collections.abc import Callable, Iterator
from ctypes import wintypes
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from labcourt.contracts.paths import require_safe_relative_posix_path
from labcourt.contracts.recovery import RECOVERY_SOURCE_TOKEN_DOMAIN, recovery_source_token
from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import (
    ArtifactConflict,
    ArtifactIntegrityViolation,
    BudgetExceeded,
    PathBoundaryViolation,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_READ_CHUNK: Final = 64 * 1024
_O_DIRECTORY = int(getattr(os, "O_DIRECTORY", 0))
_O_CLOEXEC = int(getattr(os, "O_CLOEXEC", 0))
_O_NOFOLLOW = int(getattr(os, "O_NOFOLLOW", 0))
_OS_FCHMOD: Any = getattr(os, "fchmod", None)
_OS_GETEUID: Any = getattr(os, "geteuid", None)
_WINDOWS_SUPERSCRIPT_DEVICES = {
    *(f"COM{suffix}" for suffix in "¹²³"),
    *(f"LPT{suffix}" for suffix in "¹²³"),
}
_STAGING_RECOVERY_SOURCE = re.compile(r"^\.staging/(?P<run_id>[^/]+)/crop-[0-9a-f]{64}/media\.png$")
_EMPTY_STAGING_OPERATION = re.compile(r"^\.staging/(?P<run_id>[^/]+)/crop-[0-9a-f]{64}$")
_FINAL_RECOVERY_SOURCE = re.compile(r"^(?P<run_id>[^/]+)/frames/(?P<sha256>[0-9a-f]{64})\.png$")
_MODEL_RESPONSE_STAGING_SOURCE = re.compile(
    r"^\.staging/(?P<run_id>[^/]+)/model-response-(?P<response_id>[0-9a-f]{64})/response\.json$"
)
_EMPTY_MODEL_RESPONSE_STAGING_OPERATION = re.compile(
    r"^\.staging/(?P<run_id>[^/]+)/model-response-(?P<response_id>[0-9a-f]{64})$"
)
_MODEL_RESPONSE_JOURNAL_SOURCE = re.compile(
    r"^\.staging/(?P<run_id>[^/]+)/model-request-(?P<request_id>[0-9a-f]{64})/receipt\.json$"
)
_EMPTY_MODEL_RESPONSE_JOURNAL_OPERATION = re.compile(
    r"^\.staging/(?P<run_id>[^/]+)/model-request-(?P<request_id>[0-9a-f]{64})$"
)
_FINAL_MODEL_RESPONSE_SOURCE = re.compile(
    r"^(?P<run_id>[^/]+)/model_responses/(?P<response_id>[0-9a-f]{64})\.json$"
)
_HEARING_MODEL_RESPONSE_STAGING_SOURCE = re.compile(
    r"^\.staging/(?P<run_id>[^/]+)/hearing-model-response-"
    r"(?P<response_id>[0-9a-f]{64})/response\.json$"
)
_EMPTY_HEARING_MODEL_RESPONSE_STAGING_OPERATION = re.compile(
    r"^\.staging/(?P<run_id>[^/]+)/hearing-model-response-"
    r"(?P<response_id>[0-9a-f]{64})$"
)
_HEARING_MODEL_RESPONSE_JOURNAL_SOURCE = re.compile(
    r"^\.staging/(?P<run_id>[^/]+)/hearing-model-request-"
    r"(?P<request_id>[0-9a-f]{64})/receipt\.json$"
)
_EMPTY_HEARING_MODEL_RESPONSE_JOURNAL_OPERATION = re.compile(
    r"^\.staging/(?P<run_id>[^/]+)/hearing-model-request-"
    r"(?P<request_id>[0-9a-f]{64})$"
)
_WINDOWS_UNIX_EPOCH_FILETIME: Final = 116_444_736_000_000_000
_PROJECTION_LOCK_PAYLOAD: Final = b"labcourt-projection-publish-lock-v1\n"
_PROJECTION_LOCK_TIMEOUT_SECONDS: Final = 5.0
_M6_STATIC_REPORT_LOCK_PAYLOAD: Final = b"labcourt-m6-static-report-publish-lock-v1\n"
_M6_STATIC_REPORT_LOCK_TIMEOUT_SECONDS: Final = 30.0
_M6_OFFLINE_DEMO_LOCK_PAYLOAD: Final = b"labcourt-m6-offline-demo-publish-lock-v1\n"
_M6_OFFLINE_DEMO_LOCK_TIMEOUT_SECONDS: Final = 30.0


@dataclass(frozen=True, slots=True)
class SecureFileSnapshot:
    relative_path: str
    size_bytes: int
    sha256: str
    bytes: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class SecureFileMetadata:
    """Opaque stable identity and size observed from one verified file handle."""

    relative_path: str
    size_bytes: int
    identity_token: str


@dataclass(frozen=True, slots=True)
class SecureVideoInput:
    """A decoder path valid only for the lifetime of ``open_verified_video``."""

    decoder_path: str
    input_file_sha256: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class SecureDeletionReceipt:
    """Proof that one verified private-trash entry was unlinked."""

    relative_path: str
    size_bytes: int
    sha256: str


@dataclass(frozen=True, slots=True)
class SecureDirectoryHint:
    """One untrusted directory name hint, sanitized before leaving the adapter."""

    name: str | None
    source_token: str
    reason_code: str | None = None


@dataclass(frozen=True, slots=True)
class _FileIdentity:
    device: int
    file_id: int
    size_bytes: int
    link_count: int
    mode_or_attributes: int
    modified_ns: int
    changed_ns: int

    @property
    def object_key(self) -> tuple[int, int]:
        return self.device, self.file_id


class _MissingEntry(Exception):
    pass


class _EntryExists(Exception):
    pass


class _DirectoryNotEmpty(Exception):
    pass


class _FilesystemFailure(Exception):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _validate_relative_path(value: str) -> tuple[str, ...]:
    try:
        canonical = require_safe_relative_posix_path(value)
    except (TypeError, ValueError):
        raise PathBoundaryViolation("INVALID_RELATIVE_PATH") from None

    for character in canonical:
        codepoint = ord(character)
        if codepoint == 0x7F or 0x80 <= codepoint <= 0x9F or 0xD800 <= codepoint <= 0xDFFF:
            raise PathBoundaryViolation("INVALID_RELATIVE_PATH")
    for component in canonical.split("/"):
        base = component.split(".", maxsplit=1)[0]
        normalized_base = unicodedata.normalize("NFKC", base).upper()
        if base.upper() in _WINDOWS_SUPERSCRIPT_DEVICES or (
            normalized_base in {"COM1", "COM2", "COM3", "LPT1", "LPT2", "LPT3"}
            and base.upper() != normalized_base
        ):
            raise PathBoundaryViolation("INVALID_RELATIVE_PATH")
    return tuple(canonical.split("/"))


def _validate_expected_sha256(value: str, relative_path: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ArtifactIntegrityViolation("INVALID_EXPECTED_SHA256", relative_path)
    return value


def _validate_size_limit(value: int, name: str = "max_file_bytes") -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _is_projection_target(parts: tuple[str, ...]) -> bool:
    if len(parts) == 2:
        return parts[-1] in {"events.jsonl", "audit.jsonl"}
    if len(parts) == 3 and parts[1:] in {
        ("projections", "current.json"),
        ("m4-projections", "current.json"),
        ("m5-projections", "current.json"),
    }:
        return True
    return len(parts) == 3 and parts[1] in {"cases", "packs"} and parts[-1].endswith(".json")


def _is_projection_temporary(parts: tuple[str, ...]) -> bool:
    if len(parts) == 2:
        return any(
            parts[-1].startswith(f".{name}.") and parts[-1].endswith(".tmp")
            for name in ("events.jsonl", "audit.jsonl")
        )
    if (
        len(parts) == 3
        and parts[1] in {"projections", "m4-projections", "m5-projections"}
        and parts[-1].startswith(".current.json.")
        and parts[-1].endswith(".tmp")
    ):
        return True
    return (
        len(parts) == 3
        and parts[1] in {"cases", "packs"}
        and parts[-1].startswith(".")
        and ".json." in parts[-1]
        and parts[-1].endswith(".tmp")
    )


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _recovery_hint_token(parent_relative: str, raw_name: str) -> str:
    raw_reference = f"{parent_relative}/{raw_name}"
    return hashlib.sha256(
        RECOVERY_SOURCE_TOKEN_DOMAIN + raw_reference.encode("utf-8", errors="surrogatepass")
    ).hexdigest()


def _validate_aware_datetime(value: datetime, name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be a timezone-aware datetime")
    return value.astimezone(UTC)


def _modified_at_or_before(identity: _FileIdentity, cutoff: datetime) -> bool:
    unix_microseconds = int(cutoff.timestamp() * 1_000_000)
    if os.name == "nt":
        cutoff_units = _WINDOWS_UNIX_EPOCH_FILETIME + unix_microseconds * 10
    else:
        cutoff_units = unix_microseconds * 1_000
    return identity.modified_ns <= cutoff_units


def _dynamic_attribute(owner: object, name: str) -> Any:
    return getattr(owner, name)


def _snapshot(relative_path: str, data: bytes) -> SecureFileSnapshot:
    return SecureFileSnapshot(
        relative_path=relative_path,
        size_bytes=len(data),
        sha256=_sha256(data),
        bytes=data,
    )


def _ensure_stable_identity(before: _FileIdentity, after: _FileIdentity) -> None:
    if before != after:
        raise _FilesystemFailure("IDENTITY_CHANGED")


def _ensure_stable_directory_object(before: _FileIdentity, after: _FileIdentity) -> None:
    """Allow ordinary child creation while proving the directory handle did not swap."""

    if (
        before.object_key != after.object_key
        or before.mode_or_attributes != after.mode_or_attributes
    ):
        raise _FilesystemFailure("IDENTITY_CHANGED")


def _file_identity_token(relative_path: str, identity: _FileIdentity) -> str:
    payload = "\x00".join(
        (
            relative_path,
            str(identity.device),
            str(identity.file_id),
            str(identity.size_bytes),
            str(identity.link_count),
            str(identity.mode_or_attributes),
            str(identity.modified_ns),
            str(identity.changed_ns),
        )
    ).encode("utf-8")
    return hashlib.sha256(b"LCFILEMETA1\x00" + payload).hexdigest()


def _posix_error_reason(error_number: int | None) -> str:
    if error_number in {errno.ELOOP, errno.ENOTDIR}:
        return "LINK_OR_NON_DIRECTORY"
    if error_number in {errno.EACCES, errno.EPERM}:
        return "ACCESS_DENIED"
    if error_number in {errno.ENAMETOOLONG, errno.EINVAL}:
        return "INVALID_FILESYSTEM_NAME"
    return "FILESYSTEM_OPERATION_FAILED"


class _ByHandleFileInformation(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes", wintypes.DWORD),
        ("ftCreationTime", wintypes.FILETIME),
        ("ftLastAccessTime", wintypes.FILETIME),
        ("ftLastWriteTime", wintypes.FILETIME),
        ("dwVolumeSerialNumber", wintypes.DWORD),
        ("nFileSizeHigh", wintypes.DWORD),
        ("nFileSizeLow", wintypes.DWORD),
        ("nNumberOfLinks", wintypes.DWORD),
        ("nFileIndexHigh", wintypes.DWORD),
        ("nFileIndexLow", wintypes.DWORD),
    ]


class _FileId128(ctypes.Structure):
    _fields_ = [("identifier", ctypes.c_ubyte * 16)]


class _FileIdInfo(ctypes.Structure):
    _fields_ = [
        ("volume_serial_number", ctypes.c_ulonglong),
        ("file_id", _FileId128),
    ]


class _FileRenameInfoLayout(ctypes.Structure):
    _fields_ = [
        ("flags", wintypes.DWORD),
        ("root_directory", wintypes.HANDLE),
        ("file_name_length", wintypes.DWORD),
        ("file_name", wintypes.WCHAR * 1),
    ]


class _FileDispositionInfo(ctypes.Structure):
    _fields_ = [("delete_file", wintypes.BOOL)]


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [
        ("length", wintypes.DWORD),
        ("security_descriptor", wintypes.LPVOID),
        ("inherit_handle", wintypes.BOOL),
    ]


class _Acl(ctypes.Structure):
    _fields_ = [
        ("revision", ctypes.c_ubyte),
        ("sbz1", ctypes.c_ubyte),
        ("size", wintypes.WORD),
        ("ace_count", wintypes.WORD),
        ("sbz2", wintypes.WORD),
    ]


class _AceHeader(ctypes.Structure):
    _fields_ = [
        ("ace_type", ctypes.c_ubyte),
        ("ace_flags", ctypes.c_ubyte),
        ("ace_size", wintypes.WORD),
    ]


class _AccessAllowedAce(ctypes.Structure):
    _fields_ = [
        ("header", _AceHeader),
        ("mask", wintypes.DWORD),
        ("sid_start", wintypes.DWORD),
    ]


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [("sid", wintypes.LPVOID), ("attributes", wintypes.DWORD)]


class _TokenUser(ctypes.Structure):
    _fields_ = [("user", _SidAndAttributes)]


class _Overlapped(ctypes.Structure):
    _fields_ = [
        ("internal", ctypes.c_size_t),
        ("internal_high", ctypes.c_size_t),
        ("offset", wintypes.DWORD),
        ("offset_high", wintypes.DWORD),
        ("event", wintypes.HANDLE),
    ]


class _WindowsApi:
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    DELETE = 0x00010000
    READ_CONTROL = 0x00020000
    FILE_READ_ATTRIBUTES = 0x00000080
    FILE_TRAVERSE = 0x00000020
    SYNCHRONIZE = 0x00100000
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    FILE_SHARE_DELETE = 0x00000004
    CREATE_NEW = 1
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    FILE_ATTRIBUTE_NORMAL = 0x00000080
    FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
    FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    FILE_TYPE_DISK = 1
    FILE_BEGIN = 0
    FILE_NAME_NORMALIZED_VOLUME_GUID = 0x1
    FILE_ID_INFO_CLASS = 18
    FILE_RENAME_INFO_CLASS = 3
    FILE_DISPOSITION_INFO_CLASS = 4
    ERROR_FILE_NOT_FOUND = 2
    ERROR_PATH_NOT_FOUND = 3
    ERROR_FILE_EXISTS = 80
    ERROR_ALREADY_EXISTS = 183
    ERROR_INSUFFICIENT_BUFFER = 122
    ERROR_DIR_NOT_EMPTY = 145
    ERROR_LOCK_VIOLATION = 33
    LOCKFILE_FAIL_IMMEDIATELY = 0x00000001
    LOCKFILE_EXCLUSIVE_LOCK = 0x00000002
    SE_FILE_OBJECT = 1
    OWNER_SECURITY_INFORMATION = 0x00000001
    DACL_SECURITY_INFORMATION = 0x00000004
    SE_DACL_PROTECTED = 0x1000
    ACCESS_ALLOWED_ACE_TYPE = 0x00
    FILE_ALL_ACCESS = 0x001F01FF
    TOKEN_QUERY = 0x0008
    TOKEN_USER_CLASS = 1
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    def __init__(self) -> None:
        loader = getattr(ctypes, "WinDLL", None)
        get_last_error = getattr(ctypes, "get_last_error", None)
        if loader is None or get_last_error is None:
            raise _FilesystemFailure("WINDOWS_HANDLE_API_UNAVAILABLE")
        self._get_last_error: Callable[[], int] = get_last_error
        self._kernel32: Any = loader("kernel32", use_last_error=True)
        self._advapi32: Any = loader("advapi32", use_last_error=True)

        self._create_file: Any = self._kernel32.CreateFileW
        self._create_file.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        self._create_file.restype = wintypes.HANDLE

        self._close_handle: Any = self._kernel32.CloseHandle
        self._close_handle.argtypes = [wintypes.HANDLE]
        self._close_handle.restype = wintypes.BOOL

        self._get_info: Any = self._kernel32.GetFileInformationByHandle
        self._get_info.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(_ByHandleFileInformation),
        ]
        self._get_info.restype = wintypes.BOOL

        self._get_info_ex: Any = self._kernel32.GetFileInformationByHandleEx
        self._get_info_ex.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            wintypes.LPVOID,
            wintypes.DWORD,
        ]
        self._get_info_ex.restype = wintypes.BOOL

        self._get_file_type: Any = self._kernel32.GetFileType
        self._get_file_type.argtypes = [wintypes.HANDLE]
        self._get_file_type.restype = wintypes.DWORD

        self._get_final_path: Any = self._kernel32.GetFinalPathNameByHandleW
        self._get_final_path.argtypes = [
            wintypes.HANDLE,
            wintypes.LPWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
        ]
        self._get_final_path.restype = wintypes.DWORD

        self._read_file: Any = self._kernel32.ReadFile
        self._read_file.argtypes = [
            wintypes.HANDLE,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            wintypes.LPVOID,
        ]
        self._read_file.restype = wintypes.BOOL

        self._write_file: Any = self._kernel32.WriteFile
        self._write_file.argtypes = [
            wintypes.HANDLE,
            wintypes.LPCVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            wintypes.LPVOID,
        ]
        self._write_file.restype = wintypes.BOOL

        self._set_pointer: Any = self._kernel32.SetFilePointerEx
        self._set_pointer.argtypes = [
            wintypes.HANDLE,
            ctypes.c_longlong,
            ctypes.POINTER(ctypes.c_longlong),
            wintypes.DWORD,
        ]
        self._set_pointer.restype = wintypes.BOOL

        self._flush_file: Any = self._kernel32.FlushFileBuffers
        self._flush_file.argtypes = [wintypes.HANDLE]
        self._flush_file.restype = wintypes.BOOL

        self._set_file_info: Any = self._kernel32.SetFileInformationByHandle
        self._set_file_info.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            wintypes.LPVOID,
            wintypes.DWORD,
        ]
        self._set_file_info.restype = wintypes.BOOL

        self._create_directory: Any = self._kernel32.CreateDirectoryW
        self._create_directory.argtypes = [
            wintypes.LPCWSTR,
            ctypes.POINTER(_SecurityAttributes),
        ]
        self._create_directory.restype = wintypes.BOOL

        self._convert_sddl: Any = (
            self._advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW
        )
        self._convert_sddl.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.LPVOID),
            ctypes.POINTER(wintypes.DWORD),
        ]
        self._convert_sddl.restype = wintypes.BOOL

        self._convert_sid_to_string: Any = self._advapi32.ConvertSidToStringSidW
        self._convert_sid_to_string.argtypes = [
            wintypes.LPVOID,
            ctypes.POINTER(wintypes.LPWSTR),
        ]
        self._convert_sid_to_string.restype = wintypes.BOOL

        self._local_free: Any = self._kernel32.LocalFree
        self._local_free.argtypes = [wintypes.HLOCAL]
        self._local_free.restype = wintypes.HLOCAL

        self._get_security_info: Any = self._advapi32.GetSecurityInfo
        self._get_security_info.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.LPVOID),
            ctypes.POINTER(wintypes.LPVOID),
            ctypes.POINTER(wintypes.LPVOID),
            ctypes.POINTER(wintypes.LPVOID),
            ctypes.POINTER(wintypes.LPVOID),
        ]
        self._get_security_info.restype = wintypes.DWORD

        self._get_security_descriptor_control: Any = self._advapi32.GetSecurityDescriptorControl
        self._get_security_descriptor_control.argtypes = [
            wintypes.LPVOID,
            ctypes.POINTER(wintypes.WORD),
            ctypes.POINTER(wintypes.DWORD),
        ]
        self._get_security_descriptor_control.restype = wintypes.BOOL

        self._get_ace: Any = self._advapi32.GetAce
        self._get_ace.argtypes = [
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.LPVOID),
        ]
        self._get_ace.restype = wintypes.BOOL

        self._equal_sid: Any = self._advapi32.EqualSid
        self._equal_sid.argtypes = [wintypes.LPVOID, wintypes.LPVOID]
        self._equal_sid.restype = wintypes.BOOL

        self._open_process_token: Any = self._advapi32.OpenProcessToken
        self._open_process_token.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.HANDLE),
        ]
        self._open_process_token.restype = wintypes.BOOL

        self._get_token_information: Any = self._advapi32.GetTokenInformation
        self._get_token_information.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        self._get_token_information.restype = wintypes.BOOL

        self._get_current_process: Any = self._kernel32.GetCurrentProcess
        self._get_current_process.argtypes = []
        self._get_current_process.restype = wintypes.HANDLE

        self._lock_file: Any = self._kernel32.LockFileEx
        self._lock_file.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(_Overlapped),
        ]
        self._lock_file.restype = wintypes.BOOL

        self._unlock_file: Any = self._kernel32.UnlockFileEx
        self._unlock_file.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(_Overlapped),
        ]
        self._unlock_file.restype = wintypes.BOOL

    def _error(self) -> int:
        return int(self._get_last_error())

    def try_lock_file(self, handle: int) -> _Overlapped | None:
        overlapped = _Overlapped()
        if self._lock_file(
            handle,
            self.LOCKFILE_EXCLUSIVE_LOCK | self.LOCKFILE_FAIL_IMMEDIATELY,
            0,
            1,
            0,
            ctypes.byref(overlapped),
        ):
            return overlapped
        if self._error() == self.ERROR_LOCK_VIOLATION:
            return None
        raise _FilesystemFailure("PROJECTION_LOCK_FAILED")

    def unlock_file(self, handle: int, overlapped: _Overlapped) -> None:
        if not self._unlock_file(handle, 0, 1, 0, ctypes.byref(overlapped)):
            raise _FilesystemFailure("PROJECTION_UNLOCK_FAILED")

    def open_handle(
        self,
        path: str,
        *,
        desired_access: int,
        share_mode: int,
        disposition: int,
        flags: int,
    ) -> int:
        raw_handle = self._create_file(
            path,
            desired_access,
            share_mode,
            None,
            disposition,
            flags,
            None,
        )
        handle = int(raw_handle) if raw_handle is not None else 0
        if handle == self.INVALID_HANDLE_VALUE:
            error_number = self._error()
            if error_number in {self.ERROR_FILE_NOT_FOUND, self.ERROR_PATH_NOT_FOUND}:
                raise _MissingEntry
            if error_number in {self.ERROR_FILE_EXISTS, self.ERROR_ALREADY_EXISTS}:
                raise _EntryExists
            raise _FilesystemFailure(f"WINDOWS_OPEN_{error_number}")
        return handle

    def close(self, handle: int) -> None:
        if not self._close_handle(handle):
            raise _FilesystemFailure("WINDOWS_CLOSE_FAILED")

    def identity(self, handle: int) -> _FileIdentity:
        basic = _ByHandleFileInformation()
        if not self._get_info(handle, ctypes.byref(basic)):
            raise _FilesystemFailure("WINDOWS_FILE_INFO_UNAVAILABLE")
        extended = _FileIdInfo()
        if not self._get_info_ex(
            handle,
            self.FILE_ID_INFO_CLASS,
            ctypes.byref(extended),
            ctypes.sizeof(extended),
        ):
            raise _FilesystemFailure("WINDOWS_FILE_ID_UNAVAILABLE")
        file_id = int.from_bytes(bytes(extended.file_id.identifier), "little")
        modified = (int(basic.ftLastWriteTime.dwHighDateTime) << 32) | int(
            basic.ftLastWriteTime.dwLowDateTime
        )
        created = (int(basic.ftCreationTime.dwHighDateTime) << 32) | int(
            basic.ftCreationTime.dwLowDateTime
        )
        return _FileIdentity(
            device=int(extended.volume_serial_number),
            file_id=file_id,
            size_bytes=(int(basic.nFileSizeHigh) << 32) | int(basic.nFileSizeLow),
            link_count=int(basic.nNumberOfLinks),
            mode_or_attributes=int(basic.dwFileAttributes),
            modified_ns=modified,
            changed_ns=created,
        )

    def final_path(self, handle: int) -> str:
        required = int(
            self._get_final_path(
                handle,
                None,
                0,
                self.FILE_NAME_NORMALIZED_VOLUME_GUID,
            )
        )
        if required <= 0 or required > 32768:
            raise _FilesystemFailure("WINDOWS_FINAL_PATH_UNAVAILABLE")
        buffer = ctypes.create_unicode_buffer(required + 1)
        written = int(
            self._get_final_path(
                handle,
                buffer,
                len(buffer),
                self.FILE_NAME_NORMALIZED_VOLUME_GUID,
            )
        )
        if written <= 0 or written >= len(buffer):
            raise _FilesystemFailure("WINDOWS_FINAL_PATH_UNAVAILABLE")
        return buffer.value.rstrip("\\")

    def is_disk_file(self, handle: int) -> bool:
        return int(self._get_file_type(handle)) == self.FILE_TYPE_DISK

    def seek_start(self, handle: int) -> None:
        new_position = ctypes.c_longlong()
        if not self._set_pointer(
            handle,
            ctypes.c_longlong(0),
            ctypes.byref(new_position),
            self.FILE_BEGIN,
        ):
            raise _FilesystemFailure("WINDOWS_SEEK_FAILED")

    def read_all(self, handle: int, max_bytes: int) -> bytes:
        self.seek_start(handle)
        chunks: list[bytes] = []
        total = 0
        while True:
            buffer = ctypes.create_string_buffer(_READ_CHUNK)
            read_count = wintypes.DWORD()
            if not self._read_file(
                handle,
                buffer,
                _READ_CHUNK,
                ctypes.byref(read_count),
                None,
            ):
                raise _FilesystemFailure("WINDOWS_READ_FAILED")
            count = int(read_count.value)
            if count == 0:
                break
            total += count
            if total > max_bytes:
                raise _FilesystemFailure("FILE_TOO_LARGE")
            chunks.append(buffer.raw[:count])
        return b"".join(chunks)

    def write_all(self, handle: int, data: bytes) -> None:
        offset = 0
        while offset < len(data):
            chunk = data[offset : offset + _READ_CHUNK]
            written = wintypes.DWORD()
            buffer = ctypes.create_string_buffer(chunk)
            if not self._write_file(
                handle,
                buffer,
                len(chunk),
                ctypes.byref(written),
                None,
            ):
                raise _FilesystemFailure("WINDOWS_WRITE_FAILED")
            count = int(written.value)
            if count <= 0 or count > len(chunk):
                raise _FilesystemFailure("WINDOWS_SHORT_WRITE")
            offset += count

    def flush(self, handle: int) -> None:
        if not self._flush_file(handle):
            raise _FilesystemFailure("WINDOWS_FLUSH_FAILED")

    def _rename(self, source_handle: int, target_path: str, *, replace: bool) -> None:
        encoded_name = target_path.encode("utf-16-le")
        offset = _FileRenameInfoLayout.file_name.offset
        # SetFileInformationByHandle requires a trailing WCHAR in its Win32 buffer even
        # though FileNameLength excludes it. Parent handles remain locked while this
        # absolute volume-GUID path is consumed.
        buffer = ctypes.create_string_buffer(offset + len(encoded_name) + 2)
        layout = _FileRenameInfoLayout.from_buffer(buffer)
        layout.flags = 1 if replace else 0
        layout.root_directory = None
        layout.file_name_length = len(encoded_name)
        ctypes.memmove(ctypes.addressof(buffer) + offset, encoded_name, len(encoded_name))
        if not self._set_file_info(
            source_handle,
            self.FILE_RENAME_INFO_CLASS,
            buffer,
            len(buffer),
        ):
            error_number = self._error()
            if error_number in {self.ERROR_FILE_EXISTS, self.ERROR_ALREADY_EXISTS}:
                raise _EntryExists
            raise _FilesystemFailure(f"WINDOWS_RENAME_{error_number}")

    def rename_no_replace(self, source_handle: int, target_path: str) -> None:
        self._rename(source_handle, target_path, replace=False)

    def rename_replace(self, source_handle: int, target_path: str) -> None:
        self._rename(source_handle, target_path, replace=True)

    def delete_by_handle(self, handle: int) -> None:
        disposition = _FileDispositionInfo(delete_file=True)
        if not self._set_file_info(
            handle,
            self.FILE_DISPOSITION_INFO_CLASS,
            ctypes.byref(disposition),
            ctypes.sizeof(disposition),
        ):
            raise _FilesystemFailure(f"WINDOWS_DELETE_{self._error()}")

    def delete_empty_directory_by_handle(self, handle: int) -> None:
        disposition = _FileDispositionInfo(delete_file=True)
        if self._set_file_info(
            handle,
            self.FILE_DISPOSITION_INFO_CLASS,
            ctypes.byref(disposition),
            ctypes.sizeof(disposition),
        ):
            return
        error_number = self._error()
        if error_number == self.ERROR_DIR_NOT_EMPTY:
            raise _DirectoryNotEmpty
        raise _FilesystemFailure(f"WINDOWS_DELETE_{error_number}")

    def create_private_directory(self, path: str) -> None:
        descriptor = wintypes.LPVOID()
        descriptor_size = wintypes.DWORD()
        # Bind both owner and the only inheritable ACE to the current process user SID.
        owner_sid = self._current_process_sid_string()
        sddl = f"O:{owner_sid}D:P(A;OICI;FA;;;{owner_sid})"
        if not self._convert_sddl(
            sddl,
            1,
            ctypes.byref(descriptor),
            ctypes.byref(descriptor_size),
        ):
            raise _FilesystemFailure("WINDOWS_PRIVATE_DACL_UNAVAILABLE")
        attributes = _SecurityAttributes(
            length=ctypes.sizeof(_SecurityAttributes),
            security_descriptor=descriptor,
            inherit_handle=False,
        )
        try:
            if not self._create_directory(path, ctypes.byref(attributes)):
                error_number = self._error()
                if error_number in {self.ERROR_FILE_EXISTS, self.ERROR_ALREADY_EXISTS}:
                    raise _EntryExists
                raise _FilesystemFailure(f"WINDOWS_MKDIR_{error_number}")
        finally:
            self._local_free(descriptor)

    def require_private_directory(self, handle: int) -> None:
        """Require a protected inheritable DACL granting access only to its owner."""

        owner = wintypes.LPVOID()
        dacl = wintypes.LPVOID()
        descriptor = wintypes.LPVOID()
        result = int(
            self._get_security_info(
                handle,
                self.SE_FILE_OBJECT,
                self.OWNER_SECURITY_INFORMATION | self.DACL_SECURITY_INFORMATION,
                ctypes.byref(owner),
                None,
                ctypes.byref(dacl),
                None,
                ctypes.byref(descriptor),
            )
        )
        if result != 0 or not descriptor.value:
            raise _FilesystemFailure("WINDOWS_DIRECTORY_SECURITY_UNAVAILABLE")
        try:
            control = wintypes.WORD()
            revision = wintypes.DWORD()
            if not self._get_security_descriptor_control(
                descriptor,
                ctypes.byref(control),
                ctypes.byref(revision),
            ):
                raise _FilesystemFailure("WINDOWS_DIRECTORY_SECURITY_UNAVAILABLE")
            if not int(control.value) & self.SE_DACL_PROTECTED:
                raise _FilesystemFailure("DIRECTORY_NOT_PRIVATE")
            if not owner.value or not dacl.value:
                raise _FilesystemFailure("DIRECTORY_NOT_PRIVATE")

            acl = ctypes.cast(dacl, ctypes.POINTER(_Acl)).contents
            if int(acl.ace_count) != 1:
                raise _FilesystemFailure("DIRECTORY_NOT_PRIVATE")
            ace_pointer = wintypes.LPVOID()
            if not self._get_ace(dacl, 0, ctypes.byref(ace_pointer)) or not ace_pointer.value:
                raise _FilesystemFailure("WINDOWS_DIRECTORY_SECURITY_UNAVAILABLE")
            ace = ctypes.cast(ace_pointer, ctypes.POINTER(_AccessAllowedAce)).contents
            if (
                int(ace.header.ace_type) != self.ACCESS_ALLOWED_ACE_TYPE
                or int(ace.header.ace_flags) != 0x03
                or int(ace.mask) != self.FILE_ALL_ACCESS
                or int(ace.header.ace_size) <= _AccessAllowedAce.sid_start.offset
            ):
                raise _FilesystemFailure("DIRECTORY_NOT_PRIVATE")
            ace_sid = wintypes.LPVOID(int(ace_pointer.value) + _AccessAllowedAce.sid_start.offset)
            if not self._equal_sid(owner, ace_sid):
                raise _FilesystemFailure("DIRECTORY_NOT_PRIVATE")
            self._require_current_process_sid(owner)
        finally:
            self._local_free(descriptor)

    def _require_current_process_sid(self, expected_sid: wintypes.LPVOID) -> None:
        if self._sid_string(expected_sid) != self._current_process_sid_string():
            raise _FilesystemFailure("DIRECTORY_NOT_PRIVATE")

    def _current_process_sid_string(self) -> str:
        token = wintypes.HANDLE()
        if not self._open_process_token(
            self._get_current_process(),
            self.TOKEN_QUERY,
            ctypes.byref(token),
        ):
            raise _FilesystemFailure("WINDOWS_PROCESS_IDENTITY_UNAVAILABLE")
        token_value = int(token.value) if token.value is not None else 0
        try:
            required = wintypes.DWORD()
            first = self._get_token_information(
                token,
                self.TOKEN_USER_CLASS,
                None,
                0,
                ctypes.byref(required),
            )
            if first or self._error() != self.ERROR_INSUFFICIENT_BUFFER or required.value == 0:
                raise _FilesystemFailure("WINDOWS_PROCESS_IDENTITY_UNAVAILABLE")
            buffer = ctypes.create_string_buffer(int(required.value))
            if not self._get_token_information(
                token,
                self.TOKEN_USER_CLASS,
                buffer,
                int(required.value),
                ctypes.byref(required),
            ):
                raise _FilesystemFailure("WINDOWS_PROCESS_IDENTITY_UNAVAILABLE")
            token_user = ctypes.cast(buffer, ctypes.POINTER(_TokenUser)).contents
            if not token_user.user.sid:
                raise _FilesystemFailure("WINDOWS_PROCESS_IDENTITY_UNAVAILABLE")
            return self._sid_string(token_user.user.sid)
        finally:
            if token_value:
                self.close(token_value)

    def _sid_string(self, sid: wintypes.LPVOID) -> str:
        value = wintypes.LPWSTR()
        if not self._convert_sid_to_string(sid, ctypes.byref(value)) or not value.value:
            raise _FilesystemFailure("WINDOWS_PROCESS_IDENTITY_UNAVAILABLE")
        try:
            return value.value
        finally:
            self._local_free(value)


@dataclass(slots=True)
class _WindowsOpenFile:
    handle: int
    parent_handle: int
    expected_final_path: str
    identity: _FileIdentity


@dataclass(slots=True)
class _PosixOpenFile:
    fd: int
    parent_fd: int
    leaf_name: str
    identity: _FileIdentity


def require_owner_only_directory(path: str | os.PathLike[str]) -> None:
    """Verify a directory is owned and accessible only by the current process user."""

    target = os.path.abspath(os.fspath(path))
    if os.name == "nt":
        try:
            api = _WindowsApi()
            handle = api.open_handle(
                target,
                desired_access=(
                    api.READ_CONTROL
                    | api.FILE_READ_ATTRIBUTES
                    | api.FILE_TRAVERSE
                    | api.SYNCHRONIZE
                ),
                share_mode=api.FILE_SHARE_READ | api.FILE_SHARE_WRITE | api.FILE_SHARE_DELETE,
                disposition=api.OPEN_EXISTING,
                flags=api.FILE_FLAG_BACKUP_SEMANTICS | api.FILE_FLAG_OPEN_REPARSE_POINT,
            )
            try:
                identity = api.identity(handle)
                if (
                    not api.is_disk_file(handle)
                    or not identity.mode_or_attributes & api.FILE_ATTRIBUTE_DIRECTORY
                    or identity.mode_or_attributes & api.FILE_ATTRIBUTE_REPARSE_POINT
                ):
                    raise _FilesystemFailure("DIRECTORY_NOT_PRIVATE")
                api.require_private_directory(handle)
            finally:
                api.close(handle)
        except (_MissingEntry, _EntryExists):
            raise PathBoundaryViolation("PRIVATE_DIRECTORY_MISSING") from None
        except _FilesystemFailure as error:
            raise PathBoundaryViolation(error.reason_code) from None
        return
    if os.name != "posix":
        raise PathBoundaryViolation("HANDLE_SECURITY_UNAVAILABLE")
    flags = os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW
    try:
        descriptor = os.open(target, flags)
    except OSError:
        raise PathBoundaryViolation("PRIVATE_DIRECTORY_OPEN_FAILED") from None
    try:
        info = os.fstat(descriptor)
        owner = int(_OS_GETEUID()) if _OS_GETEUID is not None else None
        if (
            owner is None
            or not stat.S_ISDIR(info.st_mode)
            or int(info.st_uid) != owner
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise PathBoundaryViolation("DIRECTORY_NOT_PRIVATE")
    finally:
        os.close(descriptor)


def create_owner_only_directory(path: str | os.PathLike[str]) -> None:
    """Create and re-read an owner-only directory using platform security primitives."""

    target = os.path.abspath(os.fspath(path))
    if os.name == "nt":
        try:
            _WindowsApi().create_private_directory(target)
        except _EntryExists:
            raise PathBoundaryViolation("PRIVATE_DIRECTORY_ALREADY_EXISTS") from None
        except _FilesystemFailure as error:
            raise PathBoundaryViolation(error.reason_code) from None
    elif os.name == "posix":
        try:
            os.mkdir(target, mode=0o700)
        except FileExistsError:
            raise PathBoundaryViolation("PRIVATE_DIRECTORY_ALREADY_EXISTS") from None
        except OSError:
            raise PathBoundaryViolation("PRIVATE_DIRECTORY_CREATE_FAILED") from None
    else:
        raise PathBoundaryViolation("HANDLE_SECURITY_UNAVAILABLE")
    require_owner_only_directory(target)


class SecureWorkspace:
    """A trusted directory handle plus fail-closed artifact operations."""

    def __init__(
        self,
        root: str | os.PathLike[str],
        max_file_bytes: int,
        *,
        fault_hook: Callable[[str], None] | None = None,
    ) -> None:
        self.max_file_bytes = _validate_size_limit(max_file_bytes)
        self._fault_hook = fault_hook
        self._root_fd: int | None = None
        self._root_handle: int | None = None
        self._root_final_path: str | None = None
        self._root_identity: _FileIdentity | None = None
        self._windows: _WindowsApi | None = None
        self._closed = False

        root_path = os.fspath(root)
        if os.name == "nt":
            self._initialize_windows(root_path)
        elif os.name == "posix":
            self._initialize_posix(root_path)
        else:
            raise PathBoundaryViolation("HANDLE_SECURITY_UNAVAILABLE")

    def __enter__(self) -> SecureWorkspace:
        self._ensure_open()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        failure: _FilesystemFailure | None = None
        if self._root_fd is not None:
            try:
                os.close(self._root_fd)
            except OSError:
                failure = _FilesystemFailure("ROOT_HANDLE_CLOSE_FAILED")
            self._root_fd = None
        if self._root_handle is not None and self._windows is not None:
            try:
                self._windows.close(self._root_handle)
            except _FilesystemFailure as error:
                failure = error
            self._root_handle = None
        if failure is not None:
            raise PathBoundaryViolation(failure.reason_code)

    def create_directory(self, relative_path: str) -> None:
        """Create one private directory below an already-safe parent."""

        self._ensure_open()
        parts = _validate_relative_path(relative_path)
        try:
            if os.name == "nt":
                self._create_directory_windows(parts)
            else:
                self._create_directory_posix(parts)
        except _EntryExists:
            raise ArtifactConflict("DIRECTORY_ALREADY_EXISTS", relative_path) from None
        except _MissingEntry:
            raise PathBoundaryViolation("PARENT_MISSING", relative_path) from None
        except _FilesystemFailure as error:
            raise PathBoundaryViolation(error.reason_code, relative_path) from None

    def ensure_private_directory(self, relative_path: str) -> None:
        """Create or revalidate one owner-only directory below a safe parent."""

        self._ensure_open()
        parts = _validate_relative_path(relative_path)
        try:
            try:
                if os.name == "nt":
                    self._create_directory_windows(parts)
                else:
                    self._create_directory_posix(parts)
            except _EntryExists:
                pass
            if os.name == "nt":
                self._require_private_directory_windows(parts)
            else:
                self._require_private_directory_posix(parts)
        except _MissingEntry:
            raise PathBoundaryViolation("PARENT_MISSING", relative_path) from None
        except _FilesystemFailure as error:
            raise PathBoundaryViolation(error.reason_code, relative_path) from None

    @contextlib.contextmanager
    def projection_publish_lock(self, run_id: str) -> Iterator[None]:
        """Serialize the current-pointer CAS window with a crash-released lock."""

        self._ensure_open()
        try:
            controlled_run_id = require_reference_token(run_id, "projection publish lock run_id")
        except (TypeError, ValueError):
            raise PathBoundaryViolation("INVALID_PROJECTION_RUN") from None
        relative_path = f"{controlled_run_id}/projections/.publish.lock"
        parts = _validate_relative_path(relative_path)
        expected_sha256 = _sha256(_PROJECTION_LOCK_PAYLOAD)
        try:
            deadline = time.monotonic() + _PROJECTION_LOCK_TIMEOUT_SECONDS
            while True:
                try:
                    self.create_new(relative_path, _PROJECTION_LOCK_PAYLOAD, expected_sha256)
                    break
                except ArtifactConflict:
                    try:
                        existing = self.read_verified(
                            relative_path,
                            expected_sha256,
                            max_bytes=len(_PROJECTION_LOCK_PAYLOAD),
                        )
                    except PathBoundaryViolation as error:
                        if error.reason_code == "WINDOWS_OPEN_32" and time.monotonic() < deadline:
                            time.sleep(0.005)
                            continue
                        raise
                    if existing.bytes != _PROJECTION_LOCK_PAYLOAD:
                        raise ArtifactIntegrityViolation(
                            "PROJECTION_LOCK_CONTENT_MISMATCH",
                            relative_path,
                        ) from None
                    break
            if os.name == "nt":
                with self._windows_file(
                    parts,
                    desired_access=(
                        self._windows_api().GENERIC_READ | self._windows_api().GENERIC_WRITE
                    ),
                    share_mode=(
                        self._windows_api().FILE_SHARE_READ | self._windows_api().FILE_SHARE_WRITE
                    ),
                    disposition=self._windows_api().OPEN_EXISTING,
                    max_bytes=len(_PROJECTION_LOCK_PAYLOAD),
                ) as opened:
                    api = self._windows_api()
                    deadline = time.monotonic() + _PROJECTION_LOCK_TIMEOUT_SECONDS
                    overlapped = api.try_lock_file(opened.handle)
                    while overlapped is None and time.monotonic() < deadline:
                        time.sleep(0.005)
                        overlapped = api.try_lock_file(opened.handle)
                    if overlapped is None:
                        raise _FilesystemFailure("PROJECTION_PUBLISH_BUSY")
                    try:
                        if api.read_all(opened.handle, len(_PROJECTION_LOCK_PAYLOAD)) != (
                            _PROJECTION_LOCK_PAYLOAD
                        ):
                            raise ArtifactIntegrityViolation(
                                "PROJECTION_LOCK_CONTENT_MISMATCH",
                                relative_path,
                            )
                        yield
                    finally:
                        api.unlock_file(opened.handle, overlapped)
            elif os.name == "posix":
                import fcntl

                flock: Any = _dynamic_attribute(fcntl, "flock")
                lock_ex = int(_dynamic_attribute(fcntl, "LOCK_EX"))
                lock_nb = int(_dynamic_attribute(fcntl, "LOCK_NB"))
                lock_un = int(_dynamic_attribute(fcntl, "LOCK_UN"))
                with self._posix_file(
                    parts,
                    flags=os.O_RDWR,
                    max_bytes=len(_PROJECTION_LOCK_PAYLOAD),
                ) as opened:
                    deadline = time.monotonic() + _PROJECTION_LOCK_TIMEOUT_SECONDS
                    while True:
                        try:
                            flock(opened.fd, lock_ex | lock_nb)
                            break
                        except BlockingIOError:
                            if time.monotonic() >= deadline:
                                raise _FilesystemFailure("PROJECTION_PUBLISH_BUSY") from None
                            time.sleep(0.005)
                    try:
                        if (
                            self._posix_read_all(
                                opened.fd,
                                len(_PROJECTION_LOCK_PAYLOAD),
                            )
                            != _PROJECTION_LOCK_PAYLOAD
                        ):
                            raise ArtifactIntegrityViolation(
                                "PROJECTION_LOCK_CONTENT_MISMATCH",
                                relative_path,
                            )
                        yield
                    finally:
                        flock(opened.fd, lock_un)
            else:
                raise _FilesystemFailure("HANDLE_SECURITY_UNAVAILABLE")
        except _MissingEntry:
            raise PathBoundaryViolation("SOURCE_OR_PARENT_MISSING", relative_path) from None
        except _FilesystemFailure as error:
            raise PathBoundaryViolation(error.reason_code, relative_path) from None

    @contextlib.contextmanager
    def m6_static_report_publish_lock(self, run_id: str) -> Iterator[None]:
        """Serialize one run's static-report preflight through exact readback."""

        self._ensure_open()
        try:
            controlled_run_id = require_reference_token(
                run_id,
                "M6 static report publish lock run_id",
            )
        except (TypeError, ValueError):
            raise PathBoundaryViolation("INVALID_M6_STATIC_REPORT_RUN") from None
        relative_path = f".staging/{controlled_run_id}/m6-static-report/.publish.lock"
        parts = _validate_relative_path(relative_path)
        expected_sha256 = _sha256(_M6_STATIC_REPORT_LOCK_PAYLOAD)
        try:
            deadline = time.monotonic() + _M6_STATIC_REPORT_LOCK_TIMEOUT_SECONDS
            while True:
                try:
                    self.create_new(
                        relative_path,
                        _M6_STATIC_REPORT_LOCK_PAYLOAD,
                        expected_sha256,
                    )
                    break
                except ArtifactConflict:
                    try:
                        existing = self.read_verified(
                            relative_path,
                            expected_sha256,
                            max_bytes=len(_M6_STATIC_REPORT_LOCK_PAYLOAD),
                        )
                    except PathBoundaryViolation as error:
                        if error.reason_code == "WINDOWS_OPEN_32" and time.monotonic() < deadline:
                            time.sleep(0.005)
                            continue
                        raise
                    if existing.bytes != _M6_STATIC_REPORT_LOCK_PAYLOAD:
                        raise ArtifactIntegrityViolation(
                            "M6_STATIC_REPORT_LOCK_CONTENT_MISMATCH",
                            relative_path,
                        ) from None
                    break
            if os.name == "nt":
                with self._windows_file(
                    parts,
                    desired_access=(
                        self._windows_api().GENERIC_READ | self._windows_api().GENERIC_WRITE
                    ),
                    share_mode=(
                        self._windows_api().FILE_SHARE_READ | self._windows_api().FILE_SHARE_WRITE
                    ),
                    disposition=self._windows_api().OPEN_EXISTING,
                    max_bytes=len(_M6_STATIC_REPORT_LOCK_PAYLOAD),
                ) as opened:
                    api = self._windows_api()
                    deadline = time.monotonic() + _M6_STATIC_REPORT_LOCK_TIMEOUT_SECONDS
                    overlapped = api.try_lock_file(opened.handle)
                    while overlapped is None and time.monotonic() < deadline:
                        time.sleep(0.005)
                        overlapped = api.try_lock_file(opened.handle)
                    if overlapped is None:
                        raise _FilesystemFailure("M6_STATIC_REPORT_PUBLISH_BUSY")
                    try:
                        if api.read_all(opened.handle, len(_M6_STATIC_REPORT_LOCK_PAYLOAD)) != (
                            _M6_STATIC_REPORT_LOCK_PAYLOAD
                        ):
                            raise ArtifactIntegrityViolation(
                                "M6_STATIC_REPORT_LOCK_CONTENT_MISMATCH",
                                relative_path,
                            )
                        yield
                    finally:
                        api.unlock_file(opened.handle, overlapped)
            elif os.name == "posix":
                import fcntl

                flock: Any = _dynamic_attribute(fcntl, "flock")
                lock_ex = int(_dynamic_attribute(fcntl, "LOCK_EX"))
                lock_nb = int(_dynamic_attribute(fcntl, "LOCK_NB"))
                lock_un = int(_dynamic_attribute(fcntl, "LOCK_UN"))
                with self._posix_file(
                    parts,
                    flags=os.O_RDWR,
                    max_bytes=len(_M6_STATIC_REPORT_LOCK_PAYLOAD),
                ) as opened:
                    deadline = time.monotonic() + _M6_STATIC_REPORT_LOCK_TIMEOUT_SECONDS
                    while True:
                        try:
                            flock(opened.fd, lock_ex | lock_nb)
                            break
                        except BlockingIOError:
                            if time.monotonic() >= deadline:
                                raise _FilesystemFailure("M6_STATIC_REPORT_PUBLISH_BUSY") from None
                            time.sleep(0.005)
                    try:
                        if (
                            self._posix_read_all(
                                opened.fd,
                                len(_M6_STATIC_REPORT_LOCK_PAYLOAD),
                            )
                            != _M6_STATIC_REPORT_LOCK_PAYLOAD
                        ):
                            raise ArtifactIntegrityViolation(
                                "M6_STATIC_REPORT_LOCK_CONTENT_MISMATCH",
                                relative_path,
                            )
                        yield
                    finally:
                        flock(opened.fd, lock_un)
            else:
                raise _FilesystemFailure("HANDLE_SECURITY_UNAVAILABLE")
        except _MissingEntry:
            raise PathBoundaryViolation("SOURCE_OR_PARENT_MISSING", relative_path) from None
        except _FilesystemFailure as error:
            raise PathBoundaryViolation(error.reason_code, relative_path) from None

    @contextlib.contextmanager
    def m6_offline_demo_publish_lock(self, run_id: str) -> Iterator[None]:
        """Serialize one run's offline-demo preflight through exact readback."""

        self._ensure_open()
        try:
            controlled_run_id = require_reference_token(
                run_id,
                "M6 offline demo publish lock run_id",
            )
        except (TypeError, ValueError):
            raise PathBoundaryViolation("INVALID_M6_OFFLINE_DEMO_RUN") from None
        relative_path = f".staging/{controlled_run_id}/m6-offline-demo/.publish.lock"
        parts = _validate_relative_path(relative_path)
        expected_sha256 = _sha256(_M6_OFFLINE_DEMO_LOCK_PAYLOAD)
        try:
            deadline = time.monotonic() + _M6_OFFLINE_DEMO_LOCK_TIMEOUT_SECONDS
            while True:
                try:
                    self.create_new(
                        relative_path,
                        _M6_OFFLINE_DEMO_LOCK_PAYLOAD,
                        expected_sha256,
                    )
                    break
                except ArtifactConflict:
                    try:
                        existing = self.read_verified(
                            relative_path,
                            expected_sha256,
                            max_bytes=len(_M6_OFFLINE_DEMO_LOCK_PAYLOAD),
                        )
                    except PathBoundaryViolation as error:
                        if error.reason_code == "WINDOWS_OPEN_32" and time.monotonic() < deadline:
                            time.sleep(0.005)
                            continue
                        raise
                    if existing.bytes != _M6_OFFLINE_DEMO_LOCK_PAYLOAD:
                        raise ArtifactIntegrityViolation(
                            "M6_OFFLINE_DEMO_LOCK_CONTENT_MISMATCH",
                            relative_path,
                        ) from None
                    break
            if os.name == "nt":
                with self._windows_file(
                    parts,
                    desired_access=(
                        self._windows_api().GENERIC_READ | self._windows_api().GENERIC_WRITE
                    ),
                    share_mode=(
                        self._windows_api().FILE_SHARE_READ | self._windows_api().FILE_SHARE_WRITE
                    ),
                    disposition=self._windows_api().OPEN_EXISTING,
                    max_bytes=len(_M6_OFFLINE_DEMO_LOCK_PAYLOAD),
                ) as opened:
                    api = self._windows_api()
                    deadline = time.monotonic() + _M6_OFFLINE_DEMO_LOCK_TIMEOUT_SECONDS
                    overlapped = api.try_lock_file(opened.handle)
                    while overlapped is None and time.monotonic() < deadline:
                        time.sleep(0.005)
                        overlapped = api.try_lock_file(opened.handle)
                    if overlapped is None:
                        raise _FilesystemFailure("M6_OFFLINE_DEMO_PUBLISH_BUSY")
                    try:
                        if api.read_all(opened.handle, len(_M6_OFFLINE_DEMO_LOCK_PAYLOAD)) != (
                            _M6_OFFLINE_DEMO_LOCK_PAYLOAD
                        ):
                            raise ArtifactIntegrityViolation(
                                "M6_OFFLINE_DEMO_LOCK_CONTENT_MISMATCH",
                                relative_path,
                            )
                        yield
                    finally:
                        api.unlock_file(opened.handle, overlapped)
            elif os.name == "posix":
                import fcntl

                flock: Any = _dynamic_attribute(fcntl, "flock")
                lock_ex = int(_dynamic_attribute(fcntl, "LOCK_EX"))
                lock_nb = int(_dynamic_attribute(fcntl, "LOCK_NB"))
                lock_un = int(_dynamic_attribute(fcntl, "LOCK_UN"))
                with self._posix_file(
                    parts,
                    flags=os.O_RDWR,
                    max_bytes=len(_M6_OFFLINE_DEMO_LOCK_PAYLOAD),
                ) as opened:
                    deadline = time.monotonic() + _M6_OFFLINE_DEMO_LOCK_TIMEOUT_SECONDS
                    while True:
                        try:
                            flock(opened.fd, lock_ex | lock_nb)
                            break
                        except BlockingIOError:
                            if time.monotonic() >= deadline:
                                raise _FilesystemFailure("M6_OFFLINE_DEMO_PUBLISH_BUSY") from None
                            time.sleep(0.005)
                    try:
                        if (
                            self._posix_read_all(
                                opened.fd,
                                len(_M6_OFFLINE_DEMO_LOCK_PAYLOAD),
                            )
                            != _M6_OFFLINE_DEMO_LOCK_PAYLOAD
                        ):
                            raise ArtifactIntegrityViolation(
                                "M6_OFFLINE_DEMO_LOCK_CONTENT_MISMATCH",
                                relative_path,
                            )
                        yield
                    finally:
                        flock(opened.fd, lock_un)
            else:
                raise _FilesystemFailure("HANDLE_SECURITY_UNAVAILABLE")
        except _MissingEntry:
            raise PathBoundaryViolation("SOURCE_OR_PARENT_MISSING", relative_path) from None
        except _FilesystemFailure as error:
            raise PathBoundaryViolation(error.reason_code, relative_path) from None

    def remove_empty_staging_directory(
        self,
        relative_path: str,
        not_modified_after: datetime | None = None,
    ) -> None:
        """Remove one verified empty ``.staging/<run>/crop-<sha>`` directory.

        This is deliberately not a general directory-deletion primitive.  It never
        descends into the target and fails if any entry is present.
        """

        self._ensure_open()
        parts = _validate_relative_path(relative_path)
        matched = _EMPTY_STAGING_OPERATION.fullmatch(relative_path)
        if matched is None:
            raise PathBoundaryViolation("DIRECTORY_NOT_STAGING_OPERATION", relative_path)
        try:
            require_reference_token(matched.group("run_id"), "staging cleanup run_id")
        except (TypeError, ValueError):
            raise PathBoundaryViolation("INVALID_RECOVERY_RUN", relative_path) from None
        cutoff = (
            _validate_aware_datetime(not_modified_after, "staging cleanup cutoff")
            if not_modified_after is not None
            else None
        )
        try:
            if os.name == "nt":
                self._remove_empty_staging_directory_windows(parts, cutoff)
            else:
                self._remove_empty_staging_directory_posix(parts, cutoff)
        except _MissingEntry:
            return
        except _DirectoryNotEmpty:
            raise ArtifactConflict("STAGING_DIRECTORY_NOT_EMPTY", relative_path) from None
        except _FilesystemFailure as error:
            raise PathBoundaryViolation(error.reason_code, relative_path) from None

    def remove_empty_model_response_staging_directory(
        self,
        relative_path: str,
        not_modified_after: datetime | None = None,
    ) -> None:
        """Remove one exact, verified empty model-response staging directory."""

        self._ensure_open()
        parts = _validate_relative_path(relative_path)
        matched = _EMPTY_MODEL_RESPONSE_STAGING_OPERATION.fullmatch(relative_path)
        if matched is None:
            raise PathBoundaryViolation("DIRECTORY_NOT_MODEL_RESPONSE_STAGING", relative_path)
        try:
            require_reference_token(matched.group("run_id"), "model response staging run_id")
        except (TypeError, ValueError):
            raise PathBoundaryViolation("INVALID_RECOVERY_RUN", relative_path) from None
        cutoff = (
            _validate_aware_datetime(not_modified_after, "model response staging cutoff")
            if not_modified_after is not None
            else None
        )
        try:
            if os.name == "nt":
                self._remove_empty_staging_directory_windows(parts, cutoff)
            else:
                self._remove_empty_staging_directory_posix(parts, cutoff)
        except _MissingEntry:
            return
        except _DirectoryNotEmpty:
            raise ArtifactConflict("STAGING_DIRECTORY_NOT_EMPTY", relative_path) from None
        except _FilesystemFailure as error:
            raise PathBoundaryViolation(error.reason_code, relative_path) from None

    def remove_empty_model_response_journal_directory(
        self,
        relative_path: str,
        not_modified_after: datetime | None = None,
    ) -> None:
        """Remove one exact, verified empty request-journal directory."""

        self._ensure_open()
        parts = _validate_relative_path(relative_path)
        matched = _EMPTY_MODEL_RESPONSE_JOURNAL_OPERATION.fullmatch(relative_path)
        if matched is None:
            raise PathBoundaryViolation("DIRECTORY_NOT_MODEL_RESPONSE_JOURNAL", relative_path)
        try:
            require_reference_token(matched.group("run_id"), "model response journal run_id")
        except (TypeError, ValueError):
            raise PathBoundaryViolation("INVALID_RECOVERY_RUN", relative_path) from None
        cutoff = (
            _validate_aware_datetime(not_modified_after, "journal cleanup cutoff")
            if not_modified_after is not None
            else None
        )
        try:
            if os.name == "nt":
                self._remove_empty_staging_directory_windows(parts, cutoff)
            else:
                self._remove_empty_staging_directory_posix(parts, cutoff)
        except _MissingEntry:
            return
        except _DirectoryNotEmpty:
            raise ArtifactConflict("JOURNAL_DIRECTORY_NOT_EMPTY", relative_path) from None
        except _FilesystemFailure as error:
            raise PathBoundaryViolation(error.reason_code, relative_path) from None

    def remove_empty_hearing_model_response_staging_directory(
        self,
        relative_path: str,
        not_modified_after: datetime | None = None,
    ) -> None:
        """Remove one exact, verified empty M4 response staging directory."""

        self._ensure_open()
        parts = _validate_relative_path(relative_path)
        matched = _EMPTY_HEARING_MODEL_RESPONSE_STAGING_OPERATION.fullmatch(relative_path)
        if matched is None:
            raise PathBoundaryViolation(
                "DIRECTORY_NOT_HEARING_MODEL_RESPONSE_STAGING",
                relative_path,
            )
        try:
            require_reference_token(
                matched.group("run_id"),
                "hearing model response staging run_id",
            )
        except (TypeError, ValueError):
            raise PathBoundaryViolation("INVALID_RECOVERY_RUN", relative_path) from None
        cutoff = (
            _validate_aware_datetime(not_modified_after, "staging cleanup cutoff")
            if not_modified_after is not None
            else None
        )
        try:
            if os.name == "nt":
                self._remove_empty_staging_directory_windows(parts, cutoff)
            else:
                self._remove_empty_staging_directory_posix(parts, cutoff)
        except _MissingEntry:
            return
        except _DirectoryNotEmpty:
            raise ArtifactConflict("STAGING_DIRECTORY_NOT_EMPTY", relative_path) from None
        except _FilesystemFailure as error:
            raise PathBoundaryViolation(error.reason_code, relative_path) from None

    def remove_empty_hearing_model_response_journal_directory(
        self,
        relative_path: str,
        not_modified_after: datetime | None = None,
    ) -> None:
        """Remove one exact, verified empty M4 request-journal directory."""

        self._ensure_open()
        parts = _validate_relative_path(relative_path)
        matched = _EMPTY_HEARING_MODEL_RESPONSE_JOURNAL_OPERATION.fullmatch(relative_path)
        if matched is None:
            raise PathBoundaryViolation(
                "DIRECTORY_NOT_HEARING_MODEL_RESPONSE_JOURNAL",
                relative_path,
            )
        try:
            require_reference_token(
                matched.group("run_id"),
                "hearing model response journal run_id",
            )
        except (TypeError, ValueError):
            raise PathBoundaryViolation("INVALID_RECOVERY_RUN", relative_path) from None
        cutoff = (
            _validate_aware_datetime(not_modified_after, "journal cleanup cutoff")
            if not_modified_after is not None
            else None
        )
        try:
            if os.name == "nt":
                self._remove_empty_staging_directory_windows(parts, cutoff)
            else:
                self._remove_empty_staging_directory_posix(parts, cutoff)
        except _MissingEntry:
            return
        except _DirectoryNotEmpty:
            raise ArtifactConflict("JOURNAL_DIRECTORY_NOT_EMPTY", relative_path) from None
        except _FilesystemFailure as error:
            raise PathBoundaryViolation(error.reason_code, relative_path) from None

    def list_recovery_directory(
        self,
        relative_path: str,
        max_items: int,
        max_name_bytes: int,
    ) -> tuple[SecureDirectoryHint, ...]:
        """List sanitized names from one fixed recovery directory.

        Names are discovery hints only. Any later read or move must reopen and verify
        the complete path through this workspace.
        """

        self._ensure_open()
        parts = _validate_relative_path(relative_path)
        if (
            not isinstance(max_items, int)
            or isinstance(max_items, bool)
            or max_items < 0
            or not isinstance(max_name_bytes, int)
            or isinstance(max_name_bytes, bool)
            or max_name_bytes <= 0
        ):
            raise ValueError("recovery listing budgets must be non-negative/positive integers")
        staging_directory = parts[0] == ".staging" and len(parts) in {2, 3}
        final_directory = len(parts) == 2 and parts[1] in {"frames", "model_responses"}
        controlled = staging_directory or final_directory
        if not controlled:
            raise PathBoundaryViolation("DIRECTORY_NOT_RECOVERY_SCOPED", relative_path)
        try:
            run_component = parts[1] if staging_directory else parts[0]
            require_reference_token(run_component, "recovery directory run_id")
        except (TypeError, ValueError):
            raise PathBoundaryViolation("INVALID_RECOVERY_RUN", relative_path) from None
        try:
            if os.name == "nt":
                names = self._list_recovery_directory_windows(parts, max_items)
            else:
                names = self._list_recovery_directory_posix(parts, max_items)
        except _MissingEntry:
            raise PathBoundaryViolation("DIRECTORY_MISSING", relative_path) from None
        except _FilesystemFailure as error:
            raise PathBoundaryViolation(error.reason_code, relative_path) from None

        hints: list[SecureDirectoryHint] = []
        for name in names:
            token = _recovery_hint_token(relative_path, name)
            encoded_length = len(name.encode("utf-8", errors="surrogatepass"))
            if encoded_length > max_name_bytes:
                hints.append(
                    SecureDirectoryHint(
                        name=None,
                        source_token=token,
                        reason_code="NAME_BUDGET_EXCEEDED",
                    )
                )
                continue
            candidate = f"{relative_path}/{name}"
            try:
                _validate_relative_path(candidate)
            except PathBoundaryViolation:
                hints.append(
                    SecureDirectoryHint(
                        name=None,
                        source_token=token,
                        reason_code="INVALID_ENTRY_NAME",
                    )
                )
                continue
            hints.append(SecureDirectoryHint(name=name, source_token=token))
        return tuple(
            sorted(
                hints,
                key=lambda hint: (
                    hint.name is None,
                    hint.name or "",
                    hint.source_token,
                ),
            )
        )

    def list_model_response_recovery_directory(
        self,
        relative_path: str,
        max_items: int,
        max_name_bytes: int,
    ) -> tuple[SecureDirectoryHint, ...]:
        """List hints from one exact M3 response staging or final directory."""

        parts = _validate_relative_path(relative_path)
        staging_root = len(parts) == 2 and parts[0] == ".staging"
        staging_operation = (
            len(parts) == 3
            and parts[0] == ".staging"
            and re.fullmatch(r"model-(?:response|request)-[0-9a-f]{64}", parts[2]) is not None
        )
        final_root = len(parts) == 2 and parts[1] == "model_responses"
        if not (staging_root or staging_operation or final_root):
            raise PathBoundaryViolation("DIRECTORY_NOT_MODEL_RESPONSE_RECOVERY", relative_path)
        if (
            not isinstance(max_items, int)
            or isinstance(max_items, bool)
            or max_items < 0
            or not isinstance(max_name_bytes, int)
            or isinstance(max_name_bytes, bool)
            or max_name_bytes <= 0
        ):
            raise ValueError("recovery listing budgets must be non-negative/positive integers")
        scan_budget = max_items * 3 if staging_root else max_items
        hints = self.list_recovery_directory(relative_path, scan_budget, max_name_bytes)
        if not staging_root:
            return hints
        owned = tuple(
            hint
            for hint in hints
            if hint.name is None
            or hint.name.startswith("model-response-")
            or hint.name.startswith("model-request-")
        )
        response_count = sum(
            hint.name is not None and hint.name.startswith("model-response-") for hint in owned
        )
        request_count = sum(
            hint.name is not None and hint.name.startswith("model-request-") for hint in owned
        )
        anomaly_count = sum(hint.name is None for hint in owned)
        if response_count > max_items or request_count > max_items or anomaly_count > max_items:
            raise BudgetExceeded("model-response staging exceeded the configured item budget")
        return owned

    def list_hearing_model_response_recovery_directory(
        self,
        relative_path: str,
        max_items: int,
        max_name_bytes: int,
    ) -> tuple[SecureDirectoryHint, ...]:
        """List hints from one exact M4 response staging or shared final directory."""

        parts = _validate_relative_path(relative_path)
        staging_root = len(parts) == 2 and parts[0] == ".staging"
        staging_operation = (
            len(parts) == 3
            and parts[0] == ".staging"
            and re.fullmatch(
                r"hearing-model-(?:response|request)-[0-9a-f]{64}",
                parts[2],
            )
            is not None
        )
        final_root = len(parts) == 2 and parts[1] == "model_responses"
        if not (staging_root or staging_operation or final_root):
            raise PathBoundaryViolation(
                "DIRECTORY_NOT_HEARING_MODEL_RESPONSE_RECOVERY",
                relative_path,
            )
        if (
            not isinstance(max_items, int)
            or isinstance(max_items, bool)
            or max_items < 0
            or not isinstance(max_name_bytes, int)
            or isinstance(max_name_bytes, bool)
            or max_name_bytes <= 0
        ):
            raise ValueError("recovery listing budgets must be non-negative/positive integers")
        scan_budget = max_items * 3 if staging_root else max_items
        hints = self.list_recovery_directory(relative_path, scan_budget, max_name_bytes)
        if not staging_root:
            return hints
        owned = tuple(
            hint
            for hint in hints
            if hint.name is None
            or hint.name.startswith("hearing-model-response-")
            or hint.name.startswith("hearing-model-request-")
        )
        response_count = sum(
            hint.name is not None and hint.name.startswith("hearing-model-response-")
            for hint in owned
        )
        request_count = sum(
            hint.name is not None and hint.name.startswith("hearing-model-request-")
            for hint in owned
        )
        anomaly_count = sum(hint.name is None for hint in owned)
        if response_count > max_items or request_count > max_items or anomaly_count > max_items:
            raise BudgetExceeded("hearing model-response staging exceeded the item budget")
        return owned

    def list_dataset_directory(
        self,
        run_id: str,
        max_items: int,
        max_name_bytes: int,
    ) -> tuple[SecureDirectoryHint, ...]:
        """List sanitized, untrusted hints from one run's canonical dataset directory."""

        self._ensure_open()
        try:
            controlled = require_reference_token(run_id, "dataset directory run_id")
        except (TypeError, ValueError):
            raise PathBoundaryViolation("INVALID_DATASET_RUN") from None
        if (
            not isinstance(max_items, int)
            or isinstance(max_items, bool)
            or max_items < 0
            or not isinstance(max_name_bytes, int)
            or isinstance(max_name_bytes, bool)
            or max_name_bytes <= 0
        ):
            raise ValueError("dataset listing budgets must be non-negative/positive integers")
        relative_path = f"{controlled}/datasets"
        parts = _validate_relative_path(relative_path)
        try:
            if os.name == "nt":
                names = self._list_recovery_directory_windows(parts, max_items)
            else:
                names = self._list_recovery_directory_posix(parts, max_items)
        except _MissingEntry:
            raise PathBoundaryViolation("DIRECTORY_MISSING", relative_path) from None
        except _FilesystemFailure as error:
            raise PathBoundaryViolation(error.reason_code, relative_path) from None

        hints: list[SecureDirectoryHint] = []
        for name in names:
            token = _recovery_hint_token(relative_path, name)
            if len(name.encode("utf-8", errors="surrogatepass")) > max_name_bytes:
                hints.append(
                    SecureDirectoryHint(
                        name=None,
                        source_token=token,
                        reason_code="NAME_BUDGET_EXCEEDED",
                    )
                )
                continue
            try:
                _validate_relative_path(f"{relative_path}/{name}")
            except PathBoundaryViolation:
                hints.append(
                    SecureDirectoryHint(
                        name=None,
                        source_token=token,
                        reason_code="INVALID_ENTRY_NAME",
                    )
                )
                continue
            hints.append(SecureDirectoryHint(name=name, source_token=token))
        return tuple(
            sorted(
                hints,
                key=lambda hint: (hint.name is None, hint.name or "", hint.source_token),
            )
        )

    def list_projection_directory(
        self,
        relative_path: str,
        max_items: int,
        max_name_bytes: int,
    ) -> tuple[SecureDirectoryHint, ...]:
        """List sanitized hints from one exact projection release directory."""

        self._ensure_open()
        parts = _validate_relative_path(relative_path)
        controlled = (
            (len(parts) == 2 and parts[1] == "projections")
            or (len(parts) == 3 and parts[1:] == ("projections", "generations"))
            or (
                len(parts) == 4
                and parts[1:3] == ("projections", "generations")
                and _SHA256.fullmatch(parts[3]) is not None
            )
            or (
                len(parts) == 5
                and parts[1:3] == ("projections", "generations")
                and _SHA256.fullmatch(parts[3]) is not None
                and parts[4] in {"cases", "packs"}
            )
            or (len(parts) == 2 and parts[1] == "m4-projections")
            or (len(parts) == 3 and parts[1:] == ("m4-projections", "generations"))
            or (
                len(parts) == 4
                and parts[1:3] == ("m4-projections", "generations")
                and _SHA256.fullmatch(parts[3]) is not None
            )
            or (
                len(parts) == 5
                and parts[1:3] == ("m4-projections", "generations")
                and _SHA256.fullmatch(parts[3]) is not None
                and parts[4] == "documents"
            )
            or (
                len(parts) == 6
                and parts[1:3] == ("m4-projections", "generations")
                and _SHA256.fullmatch(parts[3]) is not None
                and parts[4] == "documents"
                and re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", parts[5]) is not None
            )
            or (len(parts) == 2 and parts[1] == "m5-projections")
            or (len(parts) == 3 and parts[1:] == ("m5-projections", "generations"))
            or (
                len(parts) == 4
                and parts[1:3] == ("m5-projections", "generations")
                and _SHA256.fullmatch(parts[3]) is not None
            )
        )
        if not controlled:
            raise PathBoundaryViolation("DIRECTORY_NOT_PROJECTION_SCOPED", relative_path)
        try:
            require_reference_token(parts[0], "projection directory run_id")
        except (TypeError, ValueError):
            raise PathBoundaryViolation("INVALID_PROJECTION_RUN", relative_path) from None
        if (
            not isinstance(max_items, int)
            or isinstance(max_items, bool)
            or max_items < 0
            or not isinstance(max_name_bytes, int)
            or isinstance(max_name_bytes, bool)
            or max_name_bytes <= 0
        ):
            raise ValueError("projection listing budgets must be non-negative/positive integers")
        try:
            if os.name == "nt":
                names = self._list_recovery_directory_windows(parts, max_items)
            else:
                names = self._list_recovery_directory_posix(parts, max_items)
        except _MissingEntry:
            raise PathBoundaryViolation("DIRECTORY_MISSING", relative_path) from None
        except _FilesystemFailure as error:
            raise PathBoundaryViolation(error.reason_code, relative_path) from None

        hints: list[SecureDirectoryHint] = []
        for name in names:
            token = _recovery_hint_token(relative_path, name)
            if len(name.encode("utf-8", errors="surrogatepass")) > max_name_bytes:
                hints.append(
                    SecureDirectoryHint(
                        name=None,
                        source_token=token,
                        reason_code="NAME_BUDGET_EXCEEDED",
                    )
                )
                continue
            try:
                _validate_relative_path(f"{relative_path}/{name}")
            except PathBoundaryViolation:
                hints.append(
                    SecureDirectoryHint(
                        name=None,
                        source_token=token,
                        reason_code="INVALID_ENTRY_NAME",
                    )
                )
                continue
            hints.append(SecureDirectoryHint(name=name, source_token=token))
        return tuple(
            sorted(
                hints,
                key=lambda hint: (hint.name is None, hint.name or "", hint.source_token),
            )
        )

    def list_m6_source_authority_seal_directory(
        self,
        relative_path: str,
        max_items: int,
        max_name_bytes: int,
    ) -> tuple[SecureDirectoryHint, ...]:
        """List one exact, closure-scoped M6 source seal directory."""

        self._ensure_open()
        parts = _validate_relative_path(relative_path)
        if not (
            len(parts) == 4
            and parts[1:3] == ("m6-source-authorities", "seals")
            and _SHA256.fullmatch(parts[3]) is not None
        ):
            raise PathBoundaryViolation("DIRECTORY_NOT_M6_SOURCE_SEAL", relative_path)
        try:
            require_reference_token(parts[0], "M6 source authority seal run_id")
        except (TypeError, ValueError):
            raise PathBoundaryViolation("INVALID_M6_SOURCE_RUN", relative_path) from None
        if (
            not isinstance(max_items, int)
            or isinstance(max_items, bool)
            or max_items < 0
            or not isinstance(max_name_bytes, int)
            or isinstance(max_name_bytes, bool)
            or max_name_bytes <= 0
        ):
            raise ValueError("M6 source seal listing budgets must be valid integers")
        try:
            if os.name == "nt":
                names = self._list_recovery_directory_windows(parts, max_items)
            else:
                names = self._list_recovery_directory_posix(parts, max_items)
        except _MissingEntry:
            raise PathBoundaryViolation("DIRECTORY_MISSING", relative_path) from None
        except _FilesystemFailure as error:
            raise PathBoundaryViolation(error.reason_code, relative_path) from None

        hints: list[SecureDirectoryHint] = []
        for name in names:
            token = _recovery_hint_token(relative_path, name)
            if len(name.encode("utf-8", errors="surrogatepass")) > max_name_bytes:
                hints.append(
                    SecureDirectoryHint(
                        name=None,
                        source_token=token,
                        reason_code="NAME_BUDGET_EXCEEDED",
                    )
                )
                continue
            try:
                _validate_relative_path(f"{relative_path}/{name}")
            except PathBoundaryViolation:
                hints.append(
                    SecureDirectoryHint(
                        name=None,
                        source_token=token,
                        reason_code="INVALID_ENTRY_NAME",
                    )
                )
                continue
            hints.append(SecureDirectoryHint(name=name, source_token=token))
        return tuple(
            sorted(
                hints,
                key=lambda hint: (hint.name is None, hint.name or "", hint.source_token),
            )
        )

    def list_m6_regression_seal_directory(
        self,
        relative_path: str,
        max_items: int,
        max_name_bytes: int,
    ) -> tuple[SecureDirectoryHint, ...]:
        """List one exact, report-scoped M6 regression seal directory."""

        self._ensure_open()
        parts = _validate_relative_path(relative_path)
        if not (
            len(parts) == 4
            and parts[1:3] == ("m6-regression", "seals")
            and _SHA256.fullmatch(parts[3]) is not None
        ):
            raise PathBoundaryViolation("DIRECTORY_NOT_M6_REGRESSION_SEAL", relative_path)
        try:
            require_reference_token(parts[0], "M6 regression seal candidate run_id")
        except (TypeError, ValueError):
            raise PathBoundaryViolation("INVALID_M6_REGRESSION_RUN", relative_path) from None
        if (
            not isinstance(max_items, int)
            or isinstance(max_items, bool)
            or max_items < 0
            or not isinstance(max_name_bytes, int)
            or isinstance(max_name_bytes, bool)
            or max_name_bytes <= 0
        ):
            raise ValueError("M6 regression seal listing budgets must be valid integers")
        try:
            if os.name == "nt":
                names = self._list_recovery_directory_windows(parts, max_items)
            else:
                names = self._list_recovery_directory_posix(parts, max_items)
        except _MissingEntry:
            raise PathBoundaryViolation("DIRECTORY_MISSING", relative_path) from None
        except _FilesystemFailure as error:
            raise PathBoundaryViolation(error.reason_code, relative_path) from None

        hints: list[SecureDirectoryHint] = []
        for name in names:
            token = _recovery_hint_token(relative_path, name)
            if len(name.encode("utf-8", errors="surrogatepass")) > max_name_bytes:
                hints.append(
                    SecureDirectoryHint(
                        name=None,
                        source_token=token,
                        reason_code="NAME_BUDGET_EXCEEDED",
                    )
                )
                continue
            try:
                _validate_relative_path(f"{relative_path}/{name}")
            except PathBoundaryViolation:
                hints.append(
                    SecureDirectoryHint(
                        name=None,
                        source_token=token,
                        reason_code="INVALID_ENTRY_NAME",
                    )
                )
                continue
            hints.append(SecureDirectoryHint(name=name, source_token=token))
        return tuple(
            sorted(
                hints,
                key=lambda hint: (hint.name is None, hint.name or "", hint.source_token),
            )
        )

    def list_m6_replay_locked_closed_policy_seal_directory(
        self,
        relative_path: str,
        max_items: int,
        max_name_bytes: int,
    ) -> tuple[SecureDirectoryHint, ...]:
        """List one exact, report-scoped CLOSED-policy publication seal directory."""

        self._ensure_open()
        parts = _validate_relative_path(relative_path)
        if not (
            len(parts) == 4
            and parts[1:3] == ("m6-regression", "closed-policy-seals")
            and _SHA256.fullmatch(parts[3]) is not None
        ):
            raise PathBoundaryViolation(
                "DIRECTORY_NOT_M6_CLOSED_POLICY_REGRESSION_SEAL",
                relative_path,
            )
        try:
            require_reference_token(
                parts[0],
                "M6 CLOSED-policy regression seal candidate run_id",
            )
        except (TypeError, ValueError):
            raise PathBoundaryViolation(
                "INVALID_M6_CLOSED_POLICY_REGRESSION_RUN",
                relative_path,
            ) from None
        if (
            not isinstance(max_items, int)
            or isinstance(max_items, bool)
            or max_items < 0
            or not isinstance(max_name_bytes, int)
            or isinstance(max_name_bytes, bool)
            or max_name_bytes <= 0
        ):
            raise ValueError(
                "M6 CLOSED-policy regression seal listing budgets must be valid integers"
            )
        try:
            if os.name == "nt":
                names = self._list_recovery_directory_windows(parts, max_items)
            else:
                names = self._list_recovery_directory_posix(parts, max_items)
        except _MissingEntry:
            raise PathBoundaryViolation("DIRECTORY_MISSING", relative_path) from None
        except _FilesystemFailure as error:
            raise PathBoundaryViolation(error.reason_code, relative_path) from None

        hints: list[SecureDirectoryHint] = []
        for name in names:
            token = _recovery_hint_token(relative_path, name)
            if len(name.encode("utf-8", errors="surrogatepass")) > max_name_bytes:
                hints.append(
                    SecureDirectoryHint(
                        name=None,
                        source_token=token,
                        reason_code="NAME_BUDGET_EXCEEDED",
                    )
                )
                continue
            try:
                _validate_relative_path(f"{relative_path}/{name}")
            except PathBoundaryViolation:
                hints.append(
                    SecureDirectoryHint(
                        name=None,
                        source_token=token,
                        reason_code="INVALID_ENTRY_NAME",
                    )
                )
                continue
            hints.append(SecureDirectoryHint(name=name, source_token=token))
        return tuple(
            sorted(
                hints,
                key=lambda hint: (hint.name is None, hint.name or "", hint.source_token),
            )
        )

    def list_m6_static_report_directory(
        self,
        relative_path: str,
        max_items: int,
        max_name_bytes: int,
    ) -> tuple[SecureDirectoryHint, ...]:
        """List one exact directory owned by the M6 static-report namespace."""

        self._ensure_open()
        parts = _validate_relative_path(relative_path)
        controlled = (
            (len(parts) == 2 and parts[1] in {"m6-static-report", "privacy-media"})
            or (len(parts) == 3 and parts[1:] == ("m6-static-report", "manifests"))
            or (len(parts) >= 3 and parts[1] == "privacy-media")
        )
        if not controlled:
            raise PathBoundaryViolation("DIRECTORY_NOT_M6_STATIC_REPORT", relative_path)
        try:
            require_reference_token(parts[0], "M6 static report candidate run_id")
        except (TypeError, ValueError):
            raise PathBoundaryViolation("INVALID_M6_STATIC_REPORT_RUN", relative_path) from None
        if (
            not isinstance(max_items, int)
            or isinstance(max_items, bool)
            or max_items < 0
            or not isinstance(max_name_bytes, int)
            or isinstance(max_name_bytes, bool)
            or max_name_bytes <= 0
        ):
            raise ValueError("M6 static report listing budgets must be valid integers")
        try:
            if os.name == "nt":
                names = self._list_recovery_directory_windows(parts, max_items)
            else:
                names = self._list_recovery_directory_posix(parts, max_items)
        except _MissingEntry:
            raise PathBoundaryViolation("DIRECTORY_MISSING", relative_path) from None
        except _FilesystemFailure as error:
            raise PathBoundaryViolation(error.reason_code, relative_path) from None

        hints: list[SecureDirectoryHint] = []
        for name in names:
            token = _recovery_hint_token(relative_path, name)
            if len(name.encode("utf-8", errors="surrogatepass")) > max_name_bytes:
                hints.append(
                    SecureDirectoryHint(
                        name=None,
                        source_token=token,
                        reason_code="NAME_BUDGET_EXCEEDED",
                    )
                )
                continue
            try:
                _validate_relative_path(f"{relative_path}/{name}")
            except PathBoundaryViolation:
                hints.append(
                    SecureDirectoryHint(
                        name=None,
                        source_token=token,
                        reason_code="INVALID_ENTRY_NAME",
                    )
                )
                continue
            hints.append(SecureDirectoryHint(name=name, source_token=token))
        return tuple(
            sorted(
                hints,
                key=lambda hint: (hint.name is None, hint.name or "", hint.source_token),
            )
        )

    def list_m6_offline_demo_directory(
        self,
        relative_path: str,
        max_items: int,
        max_name_bytes: int,
    ) -> tuple[SecureDirectoryHint, ...]:
        """List one exact directory owned by the M6 offline-demo namespace."""

        self._ensure_open()
        parts = _validate_relative_path(relative_path)
        controlled = (
            (len(parts) == 2 and parts[1] == "demo")
            or (len(parts) == 3 and parts[1] == "demo" and parts[2] in {"manifests", "scenarios"})
            or (len(parts) == 4 and parts[1:3] == ("demo", "scenarios"))
        )
        if not controlled:
            raise PathBoundaryViolation("DIRECTORY_NOT_M6_OFFLINE_DEMO", relative_path)
        try:
            require_reference_token(parts[0], "M6 offline demo candidate run_id")
        except (TypeError, ValueError):
            raise PathBoundaryViolation("INVALID_M6_OFFLINE_DEMO_RUN", relative_path) from None
        if (
            not isinstance(max_items, int)
            or isinstance(max_items, bool)
            or max_items < 0
            or not isinstance(max_name_bytes, int)
            or isinstance(max_name_bytes, bool)
            or max_name_bytes <= 0
        ):
            raise ValueError("M6 offline demo listing budgets must be valid integers")
        try:
            if os.name == "nt":
                names = self._list_recovery_directory_windows(parts, max_items)
            else:
                names = self._list_recovery_directory_posix(parts, max_items)
        except _MissingEntry:
            raise PathBoundaryViolation("DIRECTORY_MISSING", relative_path) from None
        except _FilesystemFailure as error:
            raise PathBoundaryViolation(error.reason_code, relative_path) from None

        hints: list[SecureDirectoryHint] = []
        for name in names:
            token = _recovery_hint_token(relative_path, name)
            if len(name.encode("utf-8", errors="surrogatepass")) > max_name_bytes:
                hints.append(
                    SecureDirectoryHint(
                        name=None,
                        source_token=token,
                        reason_code="NAME_BUDGET_EXCEEDED",
                    )
                )
                continue
            try:
                _validate_relative_path(f"{relative_path}/{name}")
            except PathBoundaryViolation:
                hints.append(
                    SecureDirectoryHint(
                        name=None,
                        source_token=token,
                        reason_code="INVALID_ENTRY_NAME",
                    )
                )
                continue
            hints.append(SecureDirectoryHint(name=name, source_token=token))
        return tuple(
            sorted(
                hints,
                key=lambda hint: (hint.name is None, hint.name or "", hint.source_token),
            )
        )

    def quarantine_recovery(
        self,
        source_relative: str,
        expected_sha256: str,
        not_modified_after: datetime,
    ) -> SecureFileSnapshot:
        """Age-check and atomically move one exact recovery source to quarantine."""

        self._ensure_open()
        source_parts = _validate_relative_path(source_relative)
        expected = _validate_expected_sha256(expected_sha256, source_relative)
        cutoff = _validate_aware_datetime(not_modified_after, "not_modified_after")
        staging = _STAGING_RECOVERY_SOURCE.fullmatch(source_relative)
        final = _FINAL_RECOVERY_SOURCE.fullmatch(source_relative)
        if staging is not None:
            run_id = require_reference_token(staging.group("run_id"), "recovery run_id")
            token = recovery_source_token(source_relative)
            dest_relative = f".quarantine/{run_id}/staging/{token}-{expected}.bin"
        elif final is not None:
            run_id = require_reference_token(final.group("run_id"), "recovery run_id")
            if final.group("sha256") != expected:
                raise ArtifactIntegrityViolation("CONTENT_ADDRESS_MISMATCH", source_relative)
            dest_relative = f".quarantine/{run_id}/frames/{expected}.png"
        else:
            raise PathBoundaryViolation("SOURCE_NOT_RECOVERY_SCOPED", source_relative)
        dest_parts = _validate_relative_path(dest_relative)
        try:
            return self._move_internal(
                source_relative,
                source_parts,
                dest_relative,
                dest_parts,
                expected,
                allow_existing_equal=True,
                missing_source_is_retry=True,
                not_modified_after=cutoff,
                remove_source_if_existing_equal=True,
                invoke_fault_hook=True,
            )
        except _EntryExists:
            raise ArtifactConflict("QUARANTINE_CONTENT_CONFLICT", dest_relative) from None
        except _MissingEntry:
            raise PathBoundaryViolation("SOURCE_OR_PARENT_MISSING", source_relative) from None
        except _FilesystemFailure as error:
            raise PathBoundaryViolation(error.reason_code, source_relative) from None

    def read_verified(
        self,
        relative_path: str,
        expected_sha256: str | None = None,
        *,
        max_bytes: int | None = None,
    ) -> SecureFileSnapshot:
        self._ensure_open()
        parts = _validate_relative_path(relative_path)
        if max_bytes is None:
            read_limit = self.max_file_bytes
        elif (
            not isinstance(max_bytes, int)
            or isinstance(max_bytes, bool)
            or max_bytes < 0
            or max_bytes > self.max_file_bytes
        ):
            raise ValueError("max_bytes must be from zero through the workspace limit")
        else:
            read_limit = max_bytes
        expected = (
            _validate_expected_sha256(expected_sha256, relative_path)
            if expected_sha256 is not None
            else None
        )
        try:
            snapshot = self._read_internal(
                relative_path,
                parts,
                expected,
                read_limit,
                invoke_fault_hook=True,
            )
        except _MissingEntry:
            raise PathBoundaryViolation("FILE_MISSING", relative_path) from None
        except _FilesystemFailure as error:
            raise PathBoundaryViolation(error.reason_code, relative_path) from None
        return snapshot

    def inspect_verified(self, relative_path: str) -> SecureFileMetadata:
        """Inspect one regular, single-link file without materializing its bytes."""

        self._ensure_open()
        parts = _validate_relative_path(relative_path)
        try:
            if os.name == "nt":
                identity = self._inspect_windows(parts)
            elif os.name == "posix":
                identity = self._inspect_posix(parts)
            else:
                raise _FilesystemFailure("HANDLE_SECURITY_UNAVAILABLE")
        except _MissingEntry:
            raise PathBoundaryViolation("FILE_MISSING", relative_path) from None
        except _FilesystemFailure as error:
            raise PathBoundaryViolation(error.reason_code, relative_path) from None
        return SecureFileMetadata(
            relative_path=relative_path,
            size_bytes=identity.size_bytes,
            identity_token=_file_identity_token(relative_path, identity),
        )

    def create_new(
        self,
        relative_path: str,
        data: bytes,
        expected_sha256: str,
    ) -> SecureFileSnapshot:
        self._ensure_open()
        parts = _validate_relative_path(relative_path)
        expected = _validate_expected_sha256(expected_sha256, relative_path)
        if not isinstance(data, bytes):
            raise ArtifactIntegrityViolation("DATA_MUST_BE_BYTES", relative_path)
        if len(data) > self.max_file_bytes:
            raise PathBoundaryViolation("FILE_TOO_LARGE", relative_path)
        if _sha256(data) != expected:
            raise ArtifactIntegrityViolation("EXPECTED_HASH_MISMATCH", relative_path)
        try:
            if os.name == "nt":
                return self._create_new_windows(relative_path, parts, data, expected)
            return self._create_new_posix(relative_path, parts, data, expected)
        except _EntryExists:
            raise ArtifactConflict("TARGET_ALREADY_EXISTS", relative_path) from None
        except _MissingEntry:
            raise PathBoundaryViolation("PARENT_MISSING", relative_path) from None
        except _FilesystemFailure as error:
            raise PathBoundaryViolation(error.reason_code, relative_path) from None

    def publish_staged(
        self,
        staged_relative: str,
        final_relative: str,
        expected_sha256: str,
        *,
        remove_source_if_existing_equal: bool = False,
    ) -> SecureFileSnapshot:
        self._ensure_open()
        if not isinstance(remove_source_if_existing_equal, bool):
            raise TypeError("remove_source_if_existing_equal must be a bool")
        staged_parts = _validate_relative_path(staged_relative)
        final_parts = _validate_relative_path(final_relative)
        expected = _validate_expected_sha256(expected_sha256, staged_relative)
        if staged_parts[0] != ".staging" or len(staged_parts) < 3:
            raise PathBoundaryViolation("SOURCE_NOT_STAGING", staged_relative)
        if final_parts[0] in {".staging", ".trash"}:
            raise PathBoundaryViolation("INVALID_PUBLICATION_TARGET", final_relative)
        if staged_relative == final_relative:
            raise ArtifactConflict("SOURCE_EQUALS_DESTINATION", staged_relative)
        try:
            return self._move_internal(
                staged_relative,
                staged_parts,
                final_relative,
                final_parts,
                expected,
                allow_existing_equal=True,
                missing_source_is_retry=True,
                remove_source_if_existing_equal=remove_source_if_existing_equal,
            )
        except _EntryExists:
            try:
                return self._read_internal(
                    final_relative,
                    final_parts,
                    expected,
                    self.max_file_bytes,
                    invoke_fault_hook=False,
                )
            except (ArtifactIntegrityViolation, _FilesystemFailure, _MissingEntry):
                raise ArtifactConflict("DESTINATION_CONTENT_CONFLICT", final_relative) from None
        except _MissingEntry:
            raise PathBoundaryViolation("SOURCE_OR_PARENT_MISSING", staged_relative) from None
        except _FilesystemFailure as error:
            raise PathBoundaryViolation(error.reason_code, staged_relative) from None

    def publish_model_response_staged(
        self,
        staged_relative: str,
        final_relative: str,
        expected_sha256: str,
        *,
        max_bytes: int,
    ) -> SecureFileSnapshot:
        """Publish one exact M3 response and remove an equal raced staging source."""

        self._ensure_open()
        staged_parts = _validate_relative_path(staged_relative)
        final_parts = _validate_relative_path(final_relative)
        expected = _validate_expected_sha256(expected_sha256, staged_relative)
        if (
            not isinstance(max_bytes, int)
            or isinstance(max_bytes, bool)
            or not 0 <= max_bytes <= self.max_file_bytes
        ):
            raise ValueError("max_bytes must be from zero through the workspace limit")
        staged = _MODEL_RESPONSE_STAGING_SOURCE.fullmatch(staged_relative)
        final = _FINAL_MODEL_RESPONSE_SOURCE.fullmatch(final_relative)
        if staged is None:
            raise PathBoundaryViolation("SOURCE_NOT_MODEL_RESPONSE_STAGING", staged_relative)
        if final is None:
            raise PathBoundaryViolation("TARGET_NOT_MODEL_RESPONSE_FINAL", final_relative)
        if staged.group("run_id") != final.group("run_id") or staged.group(
            "response_id"
        ) != final.group("response_id"):
            raise ArtifactConflict("MODEL_RESPONSE_SCOPE_MISMATCH", staged_relative)
        try:
            return self._move_internal(
                staged_relative,
                staged_parts,
                final_relative,
                final_parts,
                expected,
                allow_existing_equal=True,
                missing_source_is_retry=True,
                remove_source_if_existing_equal=True,
                invoke_fault_hook=True,
                max_bytes=max_bytes,
            )
        except _EntryExists:
            try:
                return self._read_internal(
                    final_relative,
                    final_parts,
                    expected,
                    max_bytes,
                    invoke_fault_hook=False,
                )
            except (ArtifactIntegrityViolation, _FilesystemFailure, _MissingEntry):
                raise ArtifactConflict("DESTINATION_CONTENT_CONFLICT", final_relative) from None
        except _MissingEntry:
            raise PathBoundaryViolation("SOURCE_OR_PARENT_MISSING", staged_relative) from None
        except _FilesystemFailure as error:
            raise PathBoundaryViolation(error.reason_code, staged_relative) from None

    def publish_hearing_model_response_staged(
        self,
        staged_relative: str,
        final_relative: str,
        expected_sha256: str,
        *,
        max_bytes: int,
    ) -> SecureFileSnapshot:
        """Publish one exact M4 response through the shared final raw boundary."""

        self._ensure_open()
        staged_parts = _validate_relative_path(staged_relative)
        final_parts = _validate_relative_path(final_relative)
        expected = _validate_expected_sha256(expected_sha256, staged_relative)
        if (
            not isinstance(max_bytes, int)
            or isinstance(max_bytes, bool)
            or not 0 <= max_bytes <= self.max_file_bytes
        ):
            raise ValueError("max_bytes must be from zero through the workspace limit")
        staged = _HEARING_MODEL_RESPONSE_STAGING_SOURCE.fullmatch(staged_relative)
        final = _FINAL_MODEL_RESPONSE_SOURCE.fullmatch(final_relative)
        if staged is None:
            raise PathBoundaryViolation(
                "SOURCE_NOT_HEARING_MODEL_RESPONSE_STAGING",
                staged_relative,
            )
        if final is None:
            raise PathBoundaryViolation("TARGET_NOT_MODEL_RESPONSE_FINAL", final_relative)
        if staged.group("run_id") != final.group("run_id") or staged.group(
            "response_id"
        ) != final.group("response_id"):
            raise ArtifactConflict("HEARING_MODEL_RESPONSE_SCOPE_MISMATCH", staged_relative)
        try:
            return self._move_internal(
                staged_relative,
                staged_parts,
                final_relative,
                final_parts,
                expected,
                allow_existing_equal=True,
                missing_source_is_retry=True,
                remove_source_if_existing_equal=True,
                invoke_fault_hook=True,
                max_bytes=max_bytes,
            )
        except _EntryExists:
            try:
                return self._read_internal(
                    final_relative,
                    final_parts,
                    expected,
                    max_bytes,
                    invoke_fault_hook=False,
                )
            except (ArtifactIntegrityViolation, _FilesystemFailure, _MissingEntry):
                raise ArtifactConflict("DESTINATION_CONTENT_CONFLICT", final_relative) from None
        except _MissingEntry:
            raise PathBoundaryViolation("SOURCE_OR_PARENT_MISSING", staged_relative) from None
        except _FilesystemFailure as error:
            raise PathBoundaryViolation(error.reason_code, staged_relative) from None

    def quarantine_model_response_recovery(
        self,
        source_relative: str,
        expected_sha256: str,
        not_modified_after: datetime,
        *,
        max_bytes: int,
    ) -> SecureFileSnapshot:
        """Age-check and move one exact response or journal file to quarantine.

        A pre-existing destination is an idempotent retry only after the source
        name has disappeared.  When both names exist we fail closed instead of
        deleting the source by name: POSIX has no portable compare-and-unlink
        primitive that could prove the name still designates the opened file.
        """

        self._ensure_open()
        source_parts = _validate_relative_path(source_relative)
        expected = _validate_expected_sha256(expected_sha256, source_relative)
        if (
            not isinstance(max_bytes, int)
            or isinstance(max_bytes, bool)
            or not 0 <= max_bytes <= self.max_file_bytes
        ):
            raise ValueError("max_bytes must be from zero through the workspace limit")
        cutoff = _validate_aware_datetime(not_modified_after, "not_modified_after")
        staged = _MODEL_RESPONSE_STAGING_SOURCE.fullmatch(source_relative)
        final = _FINAL_MODEL_RESPONSE_SOURCE.fullmatch(source_relative)
        journal = _MODEL_RESPONSE_JOURNAL_SOURCE.fullmatch(source_relative)
        if staged is not None:
            run_id = require_reference_token(staged.group("run_id"), "recovery run_id")
            response_id = staged.group("response_id")
            dest_relative = (
                f".quarantine/{run_id}/model_responses/staging/{response_id}-{expected}.json"
            )
        elif final is not None:
            run_id = require_reference_token(final.group("run_id"), "recovery run_id")
            response_id = final.group("response_id")
            dest_relative = (
                f".quarantine/{run_id}/model_responses/final/{response_id}-{expected}.json"
            )
        elif journal is not None:
            run_id = require_reference_token(journal.group("run_id"), "recovery run_id")
            request_id = journal.group("request_id")
            dest_relative = (
                f".quarantine/{run_id}/model_responses/journal/{request_id}-{expected}.json"
            )
        else:
            raise PathBoundaryViolation("SOURCE_NOT_MODEL_RESPONSE_RECOVERY", source_relative)
        dest_parts = _validate_relative_path(dest_relative)
        try:
            return self._move_internal(
                source_relative,
                source_parts,
                dest_relative,
                dest_parts,
                expected,
                allow_existing_equal=False,
                missing_source_is_retry=True,
                not_modified_after=cutoff,
                invoke_fault_hook=True,
                max_bytes=max_bytes,
            )
        except _EntryExists:
            raise ArtifactConflict("QUARANTINE_CONTENT_CONFLICT", dest_relative) from None
        except _MissingEntry:
            raise PathBoundaryViolation("SOURCE_OR_PARENT_MISSING", source_relative) from None
        except _FilesystemFailure as error:
            raise PathBoundaryViolation(error.reason_code, source_relative) from None

    def replace_verified(
        self,
        temporary_relative: str,
        final_relative: str,
        expected_sha256: str,
    ) -> SecureFileSnapshot:
        """Atomically replace one state projection from a verified sibling temp file."""

        self._ensure_open()
        temporary_parts = _validate_relative_path(temporary_relative)
        final_parts = _validate_relative_path(final_relative)
        expected = _validate_expected_sha256(expected_sha256, temporary_relative)
        if temporary_parts[:-1] != final_parts[:-1]:
            raise PathBoundaryViolation("REPLACEMENT_NOT_SIBLING", temporary_relative)
        if not temporary_parts[-1].startswith(f".{final_parts[-1]}.") or not temporary_parts[
            -1
        ].endswith(".tmp"):
            raise PathBoundaryViolation("INVALID_REPLACEMENT_TEMP", temporary_relative)
        if not _is_projection_target(final_parts):
            raise PathBoundaryViolation("INVALID_REPLACEMENT_TARGET", final_relative)
        if temporary_relative == final_relative:
            raise ArtifactConflict("SOURCE_EQUALS_DESTINATION", temporary_relative)
        try:
            if os.name == "nt":
                return self._replace_windows(
                    temporary_relative,
                    temporary_parts,
                    final_relative,
                    final_parts,
                    expected,
                )
            return self._replace_posix(
                temporary_relative,
                temporary_parts,
                final_relative,
                final_parts,
                expected,
            )
        except _MissingEntry:
            raise PathBoundaryViolation("SOURCE_OR_PARENT_MISSING", temporary_relative) from None
        except _FilesystemFailure as error:
            raise PathBoundaryViolation(error.reason_code, temporary_relative) from None

    def move_verified(
        self,
        source: str,
        dest: str,
        expected_sha256: str,
    ) -> SecureFileSnapshot:
        self._ensure_open()
        source_parts = _validate_relative_path(source)
        dest_parts = _validate_relative_path(dest)
        expected = _validate_expected_sha256(expected_sha256, source)
        if dest_parts[0] != ".trash" or len(dest_parts) < 2:
            raise PathBoundaryViolation("DESTINATION_NOT_TRASH", dest)
        if source == dest:
            raise ArtifactConflict("SOURCE_EQUALS_DESTINATION", source)
        try:
            return self._move_internal(
                source,
                source_parts,
                dest,
                dest_parts,
                expected,
                allow_existing_equal=False,
                missing_source_is_retry=True,
            )
        except _EntryExists:
            raise ArtifactConflict("DESTINATION_ALREADY_EXISTS", dest) from None
        except _MissingEntry:
            raise PathBoundaryViolation("SOURCE_OR_PARENT_MISSING", source) from None
        except _FilesystemFailure as error:
            raise PathBoundaryViolation(error.reason_code, source) from None

    def delete_verified_trash(
        self,
        relative_path: str,
        expected_sha256: str,
    ) -> SecureDeletionReceipt:
        """Unlink one verified regular file from a run-scoped private trash path."""

        self._ensure_open()
        parts = _validate_relative_path(relative_path)
        expected = _validate_expected_sha256(expected_sha256, relative_path)
        if len(parts) < 3 or parts[0] != ".trash":
            raise PathBoundaryViolation("SOURCE_NOT_RUN_TRASH", relative_path)
        try:
            if os.name == "nt":
                return self._delete_windows(relative_path, parts, expected)
            return self._delete_posix(relative_path, parts, expected)
        except _MissingEntry:
            raise PathBoundaryViolation("FILE_MISSING", relative_path) from None
        except _FilesystemFailure as error:
            raise PathBoundaryViolation(error.reason_code, relative_path) from None

    def delete_verified_temporary(
        self,
        relative_path: str,
        expected_sha256: str,
    ) -> SecureDeletionReceipt:
        """Unlink one verified sibling temporary projection after a handled failure."""

        self._ensure_open()
        parts = _validate_relative_path(relative_path)
        expected = _validate_expected_sha256(expected_sha256, relative_path)
        if not _is_projection_temporary(parts):
            raise PathBoundaryViolation("SOURCE_NOT_PROJECTION_TEMP", relative_path)
        try:
            if os.name == "nt":
                return self._delete_windows(relative_path, parts, expected)
            return self._delete_posix(relative_path, parts, expected)
        except _MissingEntry:
            raise PathBoundaryViolation("FILE_MISSING", relative_path) from None
        except _FilesystemFailure as error:
            raise PathBoundaryViolation(error.reason_code, relative_path) from None

    def delete_verified_model_response_journal(
        self,
        relative_path: str,
        expected_sha256: str,
    ) -> SecureDeletionReceipt:
        """Unlink one exact request journal after verifying its complete bytes."""

        self._ensure_open()
        parts = _validate_relative_path(relative_path)
        expected = _validate_expected_sha256(expected_sha256, relative_path)
        matched = _MODEL_RESPONSE_JOURNAL_SOURCE.fullmatch(relative_path)
        if matched is None:
            raise PathBoundaryViolation("SOURCE_NOT_MODEL_RESPONSE_JOURNAL", relative_path)
        try:
            require_reference_token(matched.group("run_id"), "model response journal run_id")
        except (TypeError, ValueError):
            raise PathBoundaryViolation("INVALID_RECOVERY_RUN", relative_path) from None
        try:
            if os.name == "nt":
                return self._delete_windows(relative_path, parts, expected)
            return self._delete_posix(relative_path, parts, expected)
        except _MissingEntry:
            raise PathBoundaryViolation("FILE_MISSING", relative_path) from None
        except _FilesystemFailure as error:
            raise PathBoundaryViolation(error.reason_code, relative_path) from None

    def delete_verified_hearing_model_response_journal(
        self,
        relative_path: str,
        expected_sha256: str,
    ) -> SecureDeletionReceipt:
        """Unlink one exact M4 request journal after verifying its bytes."""

        self._ensure_open()
        parts = _validate_relative_path(relative_path)
        expected = _validate_expected_sha256(expected_sha256, relative_path)
        matched = _HEARING_MODEL_RESPONSE_JOURNAL_SOURCE.fullmatch(relative_path)
        if matched is None:
            raise PathBoundaryViolation(
                "SOURCE_NOT_HEARING_MODEL_RESPONSE_JOURNAL",
                relative_path,
            )
        try:
            require_reference_token(
                matched.group("run_id"),
                "hearing model response journal run_id",
            )
        except (TypeError, ValueError):
            raise PathBoundaryViolation("INVALID_RECOVERY_RUN", relative_path) from None
        try:
            if os.name == "nt":
                return self._delete_windows(relative_path, parts, expected)
            return self._delete_posix(relative_path, parts, expected)
        except _MissingEntry:
            raise PathBoundaryViolation("FILE_MISSING", relative_path) from None
        except _FilesystemFailure as error:
            raise PathBoundaryViolation(error.reason_code, relative_path) from None

    @contextlib.contextmanager
    def open_verified_video(
        self,
        relative_path: str,
        max_bytes: int,
    ) -> Iterator[SecureVideoInput]:
        """Yield a decoder input that cannot be replaced during the context lifetime."""

        self._ensure_open()
        parts = _validate_relative_path(relative_path)
        requested_limit = _validate_size_limit(max_bytes, "max_bytes")
        limit = min(requested_limit, self.max_file_bytes)
        try:
            if os.name == "nt":
                with self._open_verified_video_windows(relative_path, parts, limit) as value:
                    yield value
            elif sys.platform.startswith("linux"):
                with self._open_verified_video_linux(relative_path, parts, limit) as value:
                    yield value
            else:
                raise _FilesystemFailure("SEALED_VIDEO_HANDLE_UNAVAILABLE")
        except _MissingEntry:
            raise PathBoundaryViolation("FILE_MISSING", relative_path) from None
        except _FilesystemFailure as error:
            raise PathBoundaryViolation(error.reason_code, relative_path) from None

    def _ensure_open(self) -> None:
        if self._closed:
            raise PathBoundaryViolation("WORKSPACE_CLOSED")

    def _initialize_posix(self, root_path: str) -> None:
        required = ("O_DIRECTORY", "O_CLOEXEC", "O_NOFOLLOW")
        if (
            any(not hasattr(os, name) for name in required)
            or os.open not in os.supports_dir_fd
            or os.stat not in os.supports_dir_fd
            or os.stat not in os.supports_follow_symlinks
            or os.mkdir not in os.supports_dir_fd
        ):
            raise PathBoundaryViolation("POSIX_HANDLE_API_UNAVAILABLE")
        flags = os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW
        root_fd: int | None = None
        error_number: int | None = None
        try:
            root_fd = os.open(root_path, flags)
        except OSError as error:
            error_number = error.errno
        if root_fd is None:
            raise PathBoundaryViolation(
                "UNSAFE_ROOT" if error_number is not None else "POSIX_HANDLE_API_UNAVAILABLE"
            )
        try:
            info = os.fstat(root_fd)
            if not stat.S_ISDIR(info.st_mode):
                raise PathBoundaryViolation("UNSAFE_ROOT")
            self._root_identity = self._identity_from_stat(info)
            self._root_fd = root_fd
        except BaseException:
            os.close(root_fd)
            raise

    def _initialize_windows(self, root_path: str) -> None:
        try:
            api = _WindowsApi()
            handle = api.open_handle(
                os.path.abspath(root_path),
                desired_access=(api.FILE_READ_ATTRIBUTES | api.FILE_TRAVERSE | api.SYNCHRONIZE),
                share_mode=api.FILE_SHARE_READ | api.FILE_SHARE_WRITE,
                disposition=api.OPEN_EXISTING,
                flags=api.FILE_FLAG_BACKUP_SEMANTICS | api.FILE_FLAG_OPEN_REPARSE_POINT,
            )
            identity = api.identity(handle)
            attributes = identity.mode_or_attributes
            if not attributes & api.FILE_ATTRIBUTE_DIRECTORY:
                raise _FilesystemFailure("ROOT_NOT_DIRECTORY")
            if attributes & api.FILE_ATTRIBUTE_REPARSE_POINT:
                raise _FilesystemFailure("ROOT_IS_REPARSE_POINT")
            if not api.is_disk_file(handle):
                raise _FilesystemFailure("ROOT_NOT_DISK_OBJECT")
            final_path = api.final_path(handle)
        except (_MissingEntry, _EntryExists):
            raise PathBoundaryViolation("UNSAFE_ROOT") from None
        except _FilesystemFailure as error:
            if "handle" in locals():
                with contextlib.suppress(_FilesystemFailure):
                    api.close(handle)
            raise PathBoundaryViolation(error.reason_code) from None
        self._windows = api
        self._root_handle = handle
        self._root_identity = identity
        self._root_final_path = final_path

    @staticmethod
    def _identity_from_stat(info: os.stat_result) -> _FileIdentity:
        return _FileIdentity(
            device=int(info.st_dev),
            file_id=int(info.st_ino),
            size_bytes=int(info.st_size),
            link_count=int(info.st_nlink),
            mode_or_attributes=int(info.st_mode),
            modified_ns=int(info.st_mtime_ns),
            changed_ns=int(info.st_ctime_ns),
        )

    def _validate_posix_directory(self, fd: int) -> _FileIdentity:
        try:
            info = os.fstat(fd)
        except OSError:
            raise _FilesystemFailure("DIRECTORY_STAT_FAILED") from None
        identity = self._identity_from_stat(info)
        if not stat.S_ISDIR(info.st_mode):
            raise _FilesystemFailure("SEGMENT_NOT_DIRECTORY")
        if self._root_identity is None or identity.device != self._root_identity.device:
            raise _FilesystemFailure("CROSS_DEVICE_SEGMENT")
        return identity

    def _validate_posix_file(self, fd: int, max_bytes: int) -> _FileIdentity:
        try:
            info = os.fstat(fd)
        except OSError:
            raise _FilesystemFailure("FILE_STAT_FAILED") from None
        identity = self._identity_from_stat(info)
        if not stat.S_ISREG(info.st_mode):
            raise _FilesystemFailure("NOT_REGULAR_FILE")
        if identity.link_count != 1:
            raise _FilesystemFailure("UNSAFE_LINK_COUNT")
        if self._root_identity is None or identity.device != self._root_identity.device:
            raise _FilesystemFailure("CROSS_DEVICE_FILE")
        if identity.size_bytes > max_bytes:
            raise _FilesystemFailure("FILE_TOO_LARGE")
        return identity

    def _posix_open_at(self, name: str, flags: int, *, dir_fd: int) -> int:
        result: int | None = None
        error_number: int | None = None
        try:
            result = os.open(name, flags, dir_fd=dir_fd)
        except OSError as error:
            error_number = error.errno
        if result is not None:
            return result
        if error_number in {errno.ENOENT}:
            raise _MissingEntry
        if error_number in {errno.EEXIST}:
            raise _EntryExists
        raise _FilesystemFailure(_posix_error_reason(error_number))

    @contextlib.contextmanager
    def _posix_parent(self, parent_parts: tuple[str, ...]) -> Iterator[int]:
        if self._root_fd is None:
            raise _FilesystemFailure("WORKSPACE_CLOSED")
        current = os.dup(self._root_fd)
        try:
            self._validate_posix_directory(current)
            for component in parent_parts:
                next_fd = self._posix_open_at(
                    component,
                    os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW,
                    dir_fd=current,
                )
                try:
                    self._validate_posix_directory(next_fd)
                except BaseException:
                    os.close(next_fd)
                    raise
                os.close(current)
                current = next_fd
            yield current
        finally:
            os.close(current)

    @contextlib.contextmanager
    def _posix_file(
        self,
        parts: tuple[str, ...],
        *,
        flags: int,
        max_bytes: int,
        mode: int | None = None,
    ) -> Iterator[_PosixOpenFile]:
        with self._posix_parent(parts[:-1]) as parent_fd:
            open_flags = flags | _O_CLOEXEC | _O_NOFOLLOW
            if mode is None:
                fd = self._posix_open_at(parts[-1], open_flags, dir_fd=parent_fd)
            else:
                result: int | None = None
                error_number: int | None = None
                try:
                    result = os.open(parts[-1], open_flags, mode, dir_fd=parent_fd)
                except OSError as error:
                    error_number = error.errno
                if result is None:
                    if error_number == errno.EEXIST:
                        raise _EntryExists
                    if error_number == errno.ENOENT:
                        raise _MissingEntry
                    raise _FilesystemFailure(_posix_error_reason(error_number))
                fd = result
            try:
                identity = self._validate_posix_file(fd, max_bytes)
                yield _PosixOpenFile(
                    fd=fd,
                    parent_fd=parent_fd,
                    leaf_name=parts[-1],
                    identity=identity,
                )
            finally:
                os.close(fd)

    def _posix_read_all(self, fd: int, max_bytes: int) -> bytes:
        try:
            os.lseek(fd, 0, os.SEEK_SET)
        except OSError:
            raise _FilesystemFailure("FILE_SEEK_FAILED") from None
        chunks: list[bytes] = []
        total = 0
        while True:
            try:
                chunk = os.read(fd, _READ_CHUNK)
            except OSError:
                raise _FilesystemFailure("FILE_READ_FAILED") from None
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise _FilesystemFailure("FILE_TOO_LARGE")
            chunks.append(chunk)
        return b"".join(chunks)

    @staticmethod
    def _posix_write_all(fd: int, data: bytes) -> None:
        offset = 0
        while offset < len(data):
            try:
                written = os.write(fd, data[offset : offset + _READ_CHUNK])
            except OSError:
                raise _FilesystemFailure("FILE_WRITE_FAILED") from None
            if written <= 0:
                raise _FilesystemFailure("SHORT_WRITE")
            offset += written

    @staticmethod
    def _posix_fsync(fd: int, reason: str) -> None:
        try:
            os.fsync(fd)
        except OSError:
            raise _FilesystemFailure(reason) from None

    def _posix_entry_matches(
        self,
        parent_fd: int,
        leaf_name: str,
        identity: _FileIdentity,
    ) -> None:
        result: os.stat_result | None = None
        with contextlib.suppress(OSError):
            result = os.stat(leaf_name, dir_fd=parent_fd, follow_symlinks=False)
        if result is None or self._identity_from_stat(result).object_key != identity.object_key:
            raise _FilesystemFailure("ENTRY_IDENTITY_CHANGED")

    @staticmethod
    def _posix_entry_missing(parent_fd: int, leaf_name: str) -> None:
        try:
            os.stat(leaf_name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        except OSError as error:
            raise _FilesystemFailure(_posix_error_reason(error.errno)) from None
        raise _FilesystemFailure("SOURCE_ENTRY_REAPPEARED")

    def _validate_posix_move_commit(
        self,
        source_parent_fd: int,
        source_name: str,
        target_parent_fd: int,
        target_name: str,
        target_identity: _FileIdentity,
    ) -> None:
        """Establish a fail-closed linearization point for a name-based move.

        POSIX rename is name-based even when both parent directories are held by
        descriptor.  Directory metadata checkpoints plus exact target identity
        and source absence make every *observed* concurrent namespace mutation
        an error.  A non-cooperating writer can always mutate the namespace
        after this method returns; callers therefore must still treat the
        workspace's owner-only boundary as part of the trust model.
        """

        source_parent_before = self._validate_posix_directory(source_parent_fd)
        target_parent_before = self._validate_posix_directory(target_parent_fd)
        self._posix_entry_matches(target_parent_fd, target_name, target_identity)
        self._posix_entry_missing(source_parent_fd, source_name)
        source_parent_after = self._validate_posix_directory(source_parent_fd)
        target_parent_after = self._validate_posix_directory(target_parent_fd)
        _ensure_stable_identity(source_parent_before, source_parent_after)
        _ensure_stable_identity(target_parent_before, target_parent_after)

    def _remove_empty_staging_directory_posix(
        self,
        parts: tuple[str, ...],
        not_modified_after: datetime | None,
    ) -> None:
        with self._posix_parent(parts[:-1]) as parent_fd:
            directory_fd = self._posix_open_at(
                parts[-1],
                os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW,
                dir_fd=parent_fd,
            )
            try:
                identity = self._validate_posix_directory(directory_fd)
                if not_modified_after is not None and not _modified_at_or_before(
                    identity,
                    not_modified_after,
                ):
                    raise _FilesystemFailure("DIRECTORY_TOO_YOUNG")
                try:
                    entries = os.listdir(directory_fd)
                except OSError:
                    raise _FilesystemFailure("DIRECTORY_LIST_FAILED") from None
                if entries:
                    raise _DirectoryNotEmpty
                self._posix_entry_matches(parent_fd, parts[-1], identity)
                try:
                    os.rmdir(parts[-1], dir_fd=parent_fd)
                except FileNotFoundError:
                    raise _MissingEntry from None
                except OSError as error:
                    if error.errno in {errno.ENOTEMPTY, errno.EEXIST}:
                        raise _DirectoryNotEmpty from None
                    raise _FilesystemFailure(_posix_error_reason(error.errno)) from None
                after = self._validate_posix_directory(directory_fd)
                if after.object_key != identity.object_key or after.link_count != 0:
                    raise _FilesystemFailure("DELETED_IDENTITY_MISMATCH")
                try:
                    os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                except OSError as error:
                    raise _FilesystemFailure(_posix_error_reason(error.errno)) from None
                else:
                    raise _FilesystemFailure("DELETE_NOT_COMMITTED")
                self._posix_fsync(parent_fd, "DIRECTORY_FSYNC_FAILED")
            finally:
                os.close(directory_fd)

    def _inspect_posix(self, parts: tuple[str, ...]) -> _FileIdentity:
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
        with self._posix_file(parts, flags=flags, max_bytes=(1 << 63) - 1) as opened:
            after = self._validate_posix_file(opened.fd, (1 << 63) - 1)
            _ensure_stable_identity(opened.identity, after)
            self._posix_entry_matches(opened.parent_fd, opened.leaf_name, opened.identity)
            return opened.identity

    def _read_posix(
        self,
        relative_path: str,
        parts: tuple[str, ...],
        expected_sha256: str | None,
        max_bytes: int,
        invoke_fault_hook: bool,
    ) -> SecureFileSnapshot:
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
        with self._posix_file(parts, flags=flags, max_bytes=max_bytes) as opened:
            if invoke_fault_hook and self._fault_hook is not None:
                self._fault_hook(relative_path)
            data = self._posix_read_all(opened.fd, max_bytes)
            after = self._validate_posix_file(opened.fd, max_bytes)
            _ensure_stable_identity(opened.identity, after)
            self._posix_entry_matches(opened.parent_fd, opened.leaf_name, opened.identity)
        result = _snapshot(relative_path, data)
        if expected_sha256 is not None and result.sha256 != expected_sha256:
            raise ArtifactIntegrityViolation("EXPECTED_HASH_MISMATCH", relative_path)
        return result

    def _create_new_posix(
        self,
        relative_path: str,
        parts: tuple[str, ...],
        data: bytes,
        expected_sha256: str,
    ) -> SecureFileSnapshot:
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
        with self._posix_file(
            parts,
            flags=flags,
            max_bytes=self.max_file_bytes,
            mode=0o600,
        ) as opened:
            try:
                if _OS_FCHMOD is None:
                    raise _FilesystemFailure("PRIVATE_FILE_MODE_UNAVAILABLE")
                _OS_FCHMOD(opened.fd, 0o600)
            except OSError:
                raise _FilesystemFailure("PRIVATE_FILE_MODE_FAILED") from None
            self._posix_write_all(opened.fd, data)
            self._posix_fsync(opened.fd, "FILE_FSYNC_FAILED")
            read_back = self._posix_read_all(opened.fd, self.max_file_bytes)
            after = self._validate_posix_file(opened.fd, self.max_file_bytes)
            if after.object_key != opened.identity.object_key:
                raise _FilesystemFailure("IDENTITY_CHANGED")
            self._posix_entry_matches(opened.parent_fd, opened.leaf_name, opened.identity)
            self._posix_fsync(opened.parent_fd, "DIRECTORY_FSYNC_FAILED")
        result = _snapshot(relative_path, read_back)
        if result.sha256 != expected_sha256 or result.bytes != data:
            raise ArtifactIntegrityViolation("WRITE_VERIFICATION_FAILED", relative_path)
        return result

    def _create_directory_posix(self, parts: tuple[str, ...]) -> None:
        with self._posix_parent(parts[:-1]) as parent_fd:
            created = False
            error_number: int | None = None
            try:
                os.mkdir(parts[-1], 0o700, dir_fd=parent_fd)
                created = True
            except OSError as error:
                error_number = error.errno
            if not created:
                if error_number == errno.EEXIST:
                    raise _EntryExists
                if error_number == errno.ENOENT:
                    raise _MissingEntry
                raise _FilesystemFailure(_posix_error_reason(error_number))
            directory_fd = self._posix_open_at(
                parts[-1],
                os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW,
                dir_fd=parent_fd,
            )
            try:
                if _OS_FCHMOD is None:
                    raise _FilesystemFailure("PRIVATE_DIRECTORY_MODE_UNAVAILABLE")
                try:
                    _OS_FCHMOD(directory_fd, 0o700)
                except OSError:
                    raise _FilesystemFailure("PRIVATE_DIRECTORY_MODE_FAILED") from None
                identity = self._validate_posix_directory(directory_fd)
                info = os.fstat(directory_fd)
                if _OS_GETEUID is None:
                    raise _FilesystemFailure("DIRECTORY_OWNER_UNAVAILABLE")
                if (
                    info.st_uid != int(_OS_GETEUID())
                    or stat.S_IMODE(identity.mode_or_attributes) & 0o077
                ):
                    raise _FilesystemFailure("DIRECTORY_NOT_PRIVATE")
                self._posix_fsync(directory_fd, "DIRECTORY_FSYNC_FAILED")
                self._posix_fsync(parent_fd, "DIRECTORY_FSYNC_FAILED")
            finally:
                os.close(directory_fd)

    def _require_private_directory_posix(self, parts: tuple[str, ...]) -> None:
        with self._posix_parent(parts[:-1]) as parent_fd:
            directory_fd = self._posix_open_at(
                parts[-1],
                os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW,
                dir_fd=parent_fd,
            )
            try:
                identity = self._validate_posix_directory(directory_fd)
                self._posix_entry_matches(parent_fd, parts[-1], identity)
                try:
                    info = os.fstat(directory_fd)
                except OSError:
                    raise _FilesystemFailure("DIRECTORY_STAT_FAILED") from None
                if _OS_GETEUID is None:
                    raise _FilesystemFailure("DIRECTORY_OWNER_UNAVAILABLE")
                if info.st_uid != int(_OS_GETEUID()) or stat.S_IMODE(info.st_mode) != 0o700:
                    raise _FilesystemFailure("DIRECTORY_NOT_PRIVATE")
                after = self._validate_posix_directory(directory_fd)
                _ensure_stable_directory_object(identity, after)
                self._posix_entry_matches(parent_fd, parts[-1], identity)
            finally:
                os.close(directory_fd)

    def _list_recovery_directory_posix(
        self,
        parts: tuple[str, ...],
        max_items: int,
    ) -> tuple[str, ...]:
        if os.scandir not in os.supports_fd:
            raise _FilesystemFailure("POSIX_DIRECTORY_ENUMERATION_UNAVAILABLE")
        with self._posix_parent(parts[:-1]) as parent_fd:
            directory_fd = self._posix_open_at(
                parts[-1],
                os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW,
                dir_fd=parent_fd,
            )
            try:
                identity = self._validate_posix_directory(directory_fd)
                self._posix_entry_matches(parent_fd, parts[-1], identity)
                names: list[str] = []
                try:
                    with os.scandir(directory_fd) as entries:
                        for entry in entries:
                            names.append(entry.name)
                            if len(names) > max_items:
                                raise BudgetExceeded(
                                    "recovery directory exceeded the configured item budget"
                                )
                except BudgetExceeded:
                    raise
                except OSError:
                    raise _FilesystemFailure("DIRECTORY_ENUMERATION_FAILED") from None
                after = self._validate_posix_directory(directory_fd)
                _ensure_stable_identity(identity, after)
                self._posix_entry_matches(parent_fd, parts[-1], identity)
                return tuple(names)
            finally:
                os.close(directory_fd)

    def _posix_rename_no_replace(
        self,
        source_parent: int,
        source_name: str,
        target_parent: int,
        target_name: str,
    ) -> None:
        library: Any = ctypes.CDLL(None, use_errno=True)
        if sys.platform.startswith("linux"):
            function = getattr(library, "renameat2", None)
            flag = 1
        elif sys.platform == "darwin":
            function = getattr(library, "renameatx_np", None)
            flag = 0x4
        else:
            function = None
            flag = 0
        if function is None:
            raise _FilesystemFailure("ATOMIC_NOREPLACE_UNAVAILABLE")
        function.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        function.restype = ctypes.c_int
        result = int(
            function(
                source_parent,
                os.fsencode(source_name),
                target_parent,
                os.fsencode(target_name),
                flag,
            )
        )
        if result == 0:
            return
        error_number = ctypes.get_errno()
        if error_number == errno.EEXIST:
            raise _EntryExists
        if error_number in {errno.ENOSYS, errno.EINVAL, errno.ENOTSUP}:
            raise _FilesystemFailure("ATOMIC_NOREPLACE_UNAVAILABLE")
        if error_number == errno.ENOENT:
            raise _MissingEntry
        raise _FilesystemFailure(_posix_error_reason(error_number))

    def _move_posix(
        self,
        source_relative: str,
        source_parts: tuple[str, ...],
        dest_relative: str,
        dest_parts: tuple[str, ...],
        expected_sha256: str,
        *,
        allow_existing_equal: bool,
        not_modified_after: datetime | None,
        remove_source_if_existing_equal: bool,
        invoke_fault_hook: bool,
        max_bytes: int,
    ) -> SecureFileSnapshot:
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
        with contextlib.ExitStack() as stack:
            source = stack.enter_context(
                self._posix_file(source_parts, flags=flags, max_bytes=max_bytes)
            )
            if not_modified_after is not None and not _modified_at_or_before(
                source.identity,
                not_modified_after,
            ):
                raise _FilesystemFailure("FILE_TOO_YOUNG")
            if invoke_fault_hook and self._fault_hook is not None:
                self._fault_hook(source_relative)
            source_data = self._posix_read_all(source.fd, max_bytes)
            source_after = self._validate_posix_file(source.fd, max_bytes)
            _ensure_stable_identity(source.identity, source_after)
            self._posix_entry_matches(source.parent_fd, source.leaf_name, source.identity)
            source_snapshot = _snapshot(source_relative, source_data)
            if source_snapshot.sha256 != expected_sha256:
                raise ArtifactIntegrityViolation("EXPECTED_HASH_MISMATCH", source_relative)
            self._posix_fsync(source.fd, "SOURCE_FILE_FSYNC_FAILED")

            target_parent = stack.enter_context(self._posix_parent(dest_parts[:-1]))
            self._posix_entry_matches(source.parent_fd, source.leaf_name, source.identity)
            try:
                self._posix_rename_no_replace(
                    source.parent_fd,
                    source.leaf_name,
                    target_parent,
                    dest_parts[-1],
                )
            except _EntryExists:
                if not allow_existing_equal:
                    raise
                existing_file = stack.enter_context(
                    self._posix_file(
                        dest_parts,
                        flags=flags,
                        max_bytes=max_bytes,
                    )
                )
                existing_data = self._posix_read_all(existing_file.fd, max_bytes)
                existing_after = self._validate_posix_file(
                    existing_file.fd,
                    max_bytes,
                )
                _ensure_stable_identity(existing_file.identity, existing_after)
                self._posix_entry_matches(
                    existing_file.parent_fd,
                    existing_file.leaf_name,
                    existing_file.identity,
                )
                existing = _snapshot(dest_relative, existing_data)
                if existing.sha256 != expected_sha256 or existing.bytes != source_snapshot.bytes:
                    raise _EntryExists from None
                if not remove_source_if_existing_equal:
                    return existing

                source_before_delete = self._validate_posix_file(
                    source.fd,
                    max_bytes,
                )
                _ensure_stable_identity(source.identity, source_before_delete)
                self._posix_entry_matches(
                    source.parent_fd,
                    source.leaf_name,
                    source.identity,
                )
                try:
                    os.unlink(source.leaf_name, dir_fd=source.parent_fd)
                except FileNotFoundError:
                    raise _MissingEntry from None
                except OSError as error:
                    raise _FilesystemFailure(_posix_error_reason(error.errno)) from None
                try:
                    after_stat = os.fstat(source.fd)
                except OSError:
                    raise _FilesystemFailure("FILE_STAT_FAILED") from None
                after_delete = self._identity_from_stat(after_stat)
                if (
                    after_delete.object_key != source.identity.object_key
                    or after_delete.link_count != 0
                ):
                    raise _FilesystemFailure("DELETED_IDENTITY_MISMATCH") from None
                self._posix_fsync(source.parent_fd, "SOURCE_DIRECTORY_FSYNC_FAILED")

                existing_after_delete = self._validate_posix_file(
                    existing_file.fd,
                    max_bytes,
                )
                _ensure_stable_identity(existing_file.identity, existing_after_delete)
                existing_data_after_delete = self._posix_read_all(
                    existing_file.fd,
                    max_bytes,
                )
                if existing_data_after_delete != existing.bytes:
                    raise _FilesystemFailure("DESTINATION_CHANGED_DURING_MOVE") from None
                self._validate_posix_move_commit(
                    source.parent_fd,
                    source.leaf_name,
                    existing_file.parent_fd,
                    existing_file.leaf_name,
                    existing_file.identity,
                )
                return existing
            target_stat: os.stat_result | None = None
            with contextlib.suppress(OSError):
                target_stat = os.stat(
                    dest_parts[-1],
                    dir_fd=target_parent,
                    follow_symlinks=False,
                )
            if (
                target_stat is None
                or self._identity_from_stat(target_stat).object_key != source.identity.object_key
            ):
                raise _FilesystemFailure("RENAMED_IDENTITY_MISMATCH")
            self._posix_fsync(source.parent_fd, "SOURCE_DIRECTORY_FSYNC_FAILED")
            if target_parent != source.parent_fd:
                self._posix_fsync(target_parent, "TARGET_DIRECTORY_FSYNC_FAILED")
            target = stack.enter_context(
                self._posix_file(dest_parts, flags=flags, max_bytes=max_bytes)
            )
            if target.identity.object_key != source.identity.object_key:
                raise _FilesystemFailure("RENAMED_IDENTITY_MISMATCH")
            target_data = self._posix_read_all(target.fd, max_bytes)
            target_after = self._validate_posix_file(target.fd, max_bytes)
            _ensure_stable_identity(target.identity, target_after)
            self._posix_entry_matches(target.parent_fd, target.leaf_name, target.identity)
            result = _snapshot(dest_relative, target_data)
            if result.sha256 != source_snapshot.sha256 or result.bytes != source_snapshot.bytes:
                raise _FilesystemFailure("RENAMED_CONTENT_MISMATCH")
            self._validate_posix_move_commit(
                source.parent_fd,
                source.leaf_name,
                target.parent_fd,
                target.leaf_name,
                target.identity,
            )
            return result

    def _replace_posix(
        self,
        source_relative: str,
        source_parts: tuple[str, ...],
        dest_relative: str,
        dest_parts: tuple[str, ...],
        expected_sha256: str,
    ) -> SecureFileSnapshot:
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
        with self._posix_file(
            source_parts,
            flags=flags,
            max_bytes=self.max_file_bytes,
        ) as source:
            source_data = self._posix_read_all(source.fd, self.max_file_bytes)
            source_after = self._validate_posix_file(source.fd, self.max_file_bytes)
            _ensure_stable_identity(source.identity, source_after)
            self._posix_entry_matches(source.parent_fd, source.leaf_name, source.identity)
            source_snapshot = _snapshot(source_relative, source_data)
            if source_snapshot.sha256 != expected_sha256:
                raise ArtifactIntegrityViolation(
                    "EXPECTED_HASH_MISMATCH",
                    source_relative,
                )
            self._posix_fsync(source.fd, "SOURCE_FILE_FSYNC_FAILED")

            existing: os.stat_result | None = None
            try:
                existing = os.stat(
                    dest_parts[-1],
                    dir_fd=source.parent_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                pass
            except OSError as error:
                raise _FilesystemFailure(_posix_error_reason(error.errno)) from None
            if existing is not None:
                existing_identity = self._identity_from_stat(existing)
                if (
                    not stat.S_ISREG(existing.st_mode)
                    or existing_identity.link_count != 1
                    or existing_identity.device != source.identity.device
                ):
                    raise _FilesystemFailure("UNSAFE_REPLACEMENT_TARGET")

            if os.replace not in os.supports_dir_fd:
                raise _FilesystemFailure("ATOMIC_REPLACE_UNAVAILABLE")
            self._posix_entry_matches(source.parent_fd, source.leaf_name, source.identity)
            try:
                os.replace(
                    source.leaf_name,
                    dest_parts[-1],
                    src_dir_fd=source.parent_fd,
                    dst_dir_fd=source.parent_fd,
                )
            except FileNotFoundError:
                raise _MissingEntry from None
            except OSError as error:
                raise _FilesystemFailure(_posix_error_reason(error.errno)) from None
            target_stat: os.stat_result | None = None
            with contextlib.suppress(OSError):
                target_stat = os.stat(
                    dest_parts[-1],
                    dir_fd=source.parent_fd,
                    follow_symlinks=False,
                )
            if (
                target_stat is None
                or self._identity_from_stat(target_stat).object_key != source.identity.object_key
            ):
                raise _FilesystemFailure("RENAMED_IDENTITY_MISMATCH")
            self._posix_fsync(source.parent_fd, "TARGET_DIRECTORY_FSYNC_FAILED")

        result = self._read_internal(
            dest_relative,
            dest_parts,
            expected_sha256,
            self.max_file_bytes,
            invoke_fault_hook=False,
        )
        if result.bytes != source_snapshot.bytes:
            raise _FilesystemFailure("RENAMED_CONTENT_MISMATCH")
        return result

    def _delete_posix(
        self,
        relative_path: str,
        parts: tuple[str, ...],
        expected_sha256: str,
    ) -> SecureDeletionReceipt:
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
        with self._posix_file(
            parts,
            flags=flags,
            max_bytes=self.max_file_bytes,
        ) as opened:
            data = self._posix_read_all(opened.fd, self.max_file_bytes)
            before = self._validate_posix_file(opened.fd, self.max_file_bytes)
            _ensure_stable_identity(opened.identity, before)
            self._posix_entry_matches(
                opened.parent_fd,
                opened.leaf_name,
                opened.identity,
            )
            snapshot = _snapshot(relative_path, data)
            if snapshot.sha256 != expected_sha256:
                raise ArtifactIntegrityViolation(
                    "EXPECTED_HASH_MISMATCH",
                    relative_path,
                )
            try:
                os.unlink(opened.leaf_name, dir_fd=opened.parent_fd)
            except FileNotFoundError:
                raise _MissingEntry from None
            except OSError as error:
                raise _FilesystemFailure(_posix_error_reason(error.errno)) from None
            try:
                after_stat = os.fstat(opened.fd)
            except OSError:
                raise _FilesystemFailure("FILE_STAT_FAILED") from None
            after = self._identity_from_stat(after_stat)
            if after.object_key != opened.identity.object_key or after.link_count != 0:
                raise _FilesystemFailure("DELETED_IDENTITY_MISMATCH")
            try:
                os.stat(
                    opened.leaf_name,
                    dir_fd=opened.parent_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                pass
            except OSError as error:
                raise _FilesystemFailure(_posix_error_reason(error.errno)) from None
            else:
                raise _FilesystemFailure("DELETE_NOT_COMMITTED")
            self._posix_fsync(opened.parent_fd, "DIRECTORY_FSYNC_FAILED")
        return SecureDeletionReceipt(
            relative_path=relative_path,
            size_bytes=snapshot.size_bytes,
            sha256=snapshot.sha256,
        )

    def _windows_api(self) -> _WindowsApi:
        if self._windows is None:
            raise _FilesystemFailure("WINDOWS_HANDLE_API_UNAVAILABLE")
        return self._windows

    @staticmethod
    def _windows_join(parent: str, component: str) -> str:
        return parent.rstrip("\\") + "\\" + component

    def _validate_windows_directory(self, handle: int, expected_path: str) -> _FileIdentity:
        api = self._windows_api()
        identity = api.identity(handle)
        attributes = identity.mode_or_attributes
        if not attributes & api.FILE_ATTRIBUTE_DIRECTORY:
            raise _FilesystemFailure("SEGMENT_NOT_DIRECTORY")
        if attributes & api.FILE_ATTRIBUTE_REPARSE_POINT:
            raise _FilesystemFailure("REPARSE_POINT_REJECTED")
        if not api.is_disk_file(handle):
            raise _FilesystemFailure("NOT_DISK_OBJECT")
        if self._root_identity is None or identity.device != self._root_identity.device:
            raise _FilesystemFailure("CROSS_VOLUME_SEGMENT")
        if api.final_path(handle).casefold() != expected_path.casefold():
            raise _FilesystemFailure("FINAL_PATH_MISMATCH")
        return identity

    def _validate_windows_file(
        self,
        handle: int,
        expected_path: str,
        max_bytes: int,
    ) -> _FileIdentity:
        api = self._windows_api()
        identity = api.identity(handle)
        attributes = identity.mode_or_attributes
        if attributes & api.FILE_ATTRIBUTE_REPARSE_POINT:
            raise _FilesystemFailure("REPARSE_POINT_REJECTED")
        if attributes & api.FILE_ATTRIBUTE_DIRECTORY or not api.is_disk_file(handle):
            raise _FilesystemFailure("NOT_REGULAR_FILE")
        if identity.link_count != 1:
            raise _FilesystemFailure("UNSAFE_LINK_COUNT")
        if self._root_identity is None or identity.device != self._root_identity.device:
            raise _FilesystemFailure("CROSS_VOLUME_FILE")
        if identity.size_bytes > max_bytes:
            raise _FilesystemFailure("FILE_TOO_LARGE")
        if api.final_path(handle).casefold() != expected_path.casefold():
            raise _FilesystemFailure("FINAL_PATH_MISMATCH")
        return identity

    @contextlib.contextmanager
    def _windows_parent(
        self,
        parent_parts: tuple[str, ...],
    ) -> Iterator[tuple[int, str]]:
        api = self._windows_api()
        if self._root_handle is None or self._root_final_path is None:
            raise _FilesystemFailure("WORKSPACE_CLOSED")
        handles: list[int] = []
        current_handle = self._root_handle
        current_path = self._root_final_path
        try:
            for component in parent_parts:
                expected_path = self._windows_join(current_path, component)
                next_handle = api.open_handle(
                    expected_path,
                    desired_access=(api.FILE_READ_ATTRIBUTES | api.FILE_TRAVERSE | api.SYNCHRONIZE),
                    share_mode=api.FILE_SHARE_READ | api.FILE_SHARE_WRITE,
                    disposition=api.OPEN_EXISTING,
                    flags=(api.FILE_FLAG_BACKUP_SEMANTICS | api.FILE_FLAG_OPEN_REPARSE_POINT),
                )
                try:
                    self._validate_windows_directory(next_handle, expected_path)
                except BaseException:
                    api.close(next_handle)
                    raise
                handles.append(next_handle)
                current_handle = next_handle
                current_path = expected_path
            yield current_handle, current_path
        finally:
            close_failure: _FilesystemFailure | None = None
            for handle in reversed(handles):
                try:
                    api.close(handle)
                except _FilesystemFailure as error:
                    close_failure = error
            if close_failure is not None:
                raise close_failure

    @contextlib.contextmanager
    def _windows_file(
        self,
        parts: tuple[str, ...],
        *,
        desired_access: int,
        share_mode: int,
        disposition: int,
        max_bytes: int,
    ) -> Iterator[_WindowsOpenFile]:
        api = self._windows_api()
        with self._windows_parent(parts[:-1]) as (parent_handle, parent_path):
            expected_path = self._windows_join(parent_path, parts[-1])
            handle = api.open_handle(
                expected_path,
                desired_access=desired_access,
                share_mode=share_mode,
                disposition=disposition,
                flags=api.FILE_ATTRIBUTE_NORMAL | api.FILE_FLAG_OPEN_REPARSE_POINT,
            )
            try:
                identity = self._validate_windows_file(handle, expected_path, max_bytes)
                yield _WindowsOpenFile(
                    handle=handle,
                    parent_handle=parent_handle,
                    expected_final_path=expected_path,
                    identity=identity,
                )
            finally:
                api.close(handle)

    def _inspect_windows(self, parts: tuple[str, ...]) -> _FileIdentity:
        api = self._windows_api()
        with self._windows_file(
            parts,
            desired_access=api.FILE_READ_ATTRIBUTES,
            share_mode=api.FILE_SHARE_READ,
            disposition=api.OPEN_EXISTING,
            max_bytes=(1 << 63) - 1,
        ) as opened:
            after = self._validate_windows_file(
                opened.handle,
                opened.expected_final_path,
                (1 << 63) - 1,
            )
            _ensure_stable_identity(opened.identity, after)
            return opened.identity

    def _read_windows(
        self,
        relative_path: str,
        parts: tuple[str, ...],
        expected_sha256: str | None,
        max_bytes: int,
        invoke_fault_hook: bool,
    ) -> SecureFileSnapshot:
        api = self._windows_api()
        with self._windows_file(
            parts,
            desired_access=api.GENERIC_READ | api.FILE_READ_ATTRIBUTES,
            share_mode=api.FILE_SHARE_READ,
            disposition=api.OPEN_EXISTING,
            max_bytes=max_bytes,
        ) as opened:
            if invoke_fault_hook and self._fault_hook is not None:
                self._fault_hook(relative_path)
            data = api.read_all(opened.handle, max_bytes)
            after = self._validate_windows_file(
                opened.handle,
                opened.expected_final_path,
                max_bytes,
            )
            _ensure_stable_identity(opened.identity, after)
        result = _snapshot(relative_path, data)
        if expected_sha256 is not None and result.sha256 != expected_sha256:
            raise ArtifactIntegrityViolation("EXPECTED_HASH_MISMATCH", relative_path)
        return result

    def _remove_empty_staging_directory_windows(
        self,
        parts: tuple[str, ...],
        not_modified_after: datetime | None,
    ) -> None:
        api = self._windows_api()
        with self._windows_parent(parts[:-1]) as (_, parent_path):
            expected_path = self._windows_join(parent_path, parts[-1])
            handle = api.open_handle(
                expected_path,
                desired_access=api.FILE_READ_ATTRIBUTES | api.DELETE | api.SYNCHRONIZE,
                share_mode=api.FILE_SHARE_READ | api.FILE_SHARE_WRITE,
                disposition=api.OPEN_EXISTING,
                flags=api.FILE_FLAG_BACKUP_SEMANTICS | api.FILE_FLAG_OPEN_REPARSE_POINT,
            )
            try:
                identity = self._validate_windows_directory(handle, expected_path)
                if not_modified_after is not None and not _modified_at_or_before(
                    identity,
                    not_modified_after,
                ):
                    raise _FilesystemFailure("DIRECTORY_TOO_YOUNG")
                api.delete_empty_directory_by_handle(handle)
                after = api.identity(handle)
                if after.object_key != identity.object_key:
                    raise _FilesystemFailure("DELETED_IDENTITY_MISMATCH")
            finally:
                api.close(handle)

        try:
            replacement = api.open_handle(
                expected_path,
                desired_access=api.FILE_READ_ATTRIBUTES,
                share_mode=api.FILE_SHARE_READ | api.FILE_SHARE_WRITE | api.FILE_SHARE_DELETE,
                disposition=api.OPEN_EXISTING,
                flags=api.FILE_FLAG_BACKUP_SEMANTICS | api.FILE_FLAG_OPEN_REPARSE_POINT,
            )
        except _MissingEntry:
            return
        try:
            raise _FilesystemFailure("DELETE_NOT_COMMITTED")
        finally:
            api.close(replacement)

    def _create_new_windows(
        self,
        relative_path: str,
        parts: tuple[str, ...],
        data: bytes,
        expected_sha256: str,
    ) -> SecureFileSnapshot:
        api = self._windows_api()
        with self._windows_file(
            parts,
            desired_access=(api.GENERIC_READ | api.GENERIC_WRITE | api.FILE_READ_ATTRIBUTES),
            share_mode=api.FILE_SHARE_READ,
            disposition=api.CREATE_NEW,
            max_bytes=self.max_file_bytes,
        ) as opened:
            api.write_all(opened.handle, data)
            api.flush(opened.handle)
            read_back = api.read_all(opened.handle, self.max_file_bytes)
            after = self._validate_windows_file(
                opened.handle,
                opened.expected_final_path,
                self.max_file_bytes,
            )
            if after.object_key != opened.identity.object_key:
                raise _FilesystemFailure("IDENTITY_CHANGED")
        result = _snapshot(relative_path, read_back)
        if result.sha256 != expected_sha256 or result.bytes != data:
            raise ArtifactIntegrityViolation("WRITE_VERIFICATION_FAILED", relative_path)
        return result

    def _create_directory_windows(self, parts: tuple[str, ...]) -> None:
        api = self._windows_api()
        with self._windows_parent(parts[:-1]) as (_, parent_path):
            expected_path = self._windows_join(parent_path, parts[-1])
            api.create_private_directory(expected_path)
            handle = api.open_handle(
                expected_path,
                desired_access=(api.FILE_READ_ATTRIBUTES | api.FILE_TRAVERSE | api.SYNCHRONIZE),
                share_mode=api.FILE_SHARE_READ | api.FILE_SHARE_WRITE,
                disposition=api.OPEN_EXISTING,
                flags=api.FILE_FLAG_BACKUP_SEMANTICS | api.FILE_FLAG_OPEN_REPARSE_POINT,
            )
            try:
                self._validate_windows_directory(handle, expected_path)
            finally:
                api.close(handle)

    def _require_private_directory_windows(self, parts: tuple[str, ...]) -> None:
        api = self._windows_api()
        with self._windows_parent(parts[:-1]) as (_, parent_path):
            expected_path = self._windows_join(parent_path, parts[-1])
            handle = api.open_handle(
                expected_path,
                desired_access=(
                    api.FILE_READ_ATTRIBUTES
                    | api.FILE_TRAVERSE
                    | api.READ_CONTROL
                    | api.SYNCHRONIZE
                ),
                share_mode=api.FILE_SHARE_READ | api.FILE_SHARE_WRITE,
                disposition=api.OPEN_EXISTING,
                flags=api.FILE_FLAG_BACKUP_SEMANTICS | api.FILE_FLAG_OPEN_REPARSE_POINT,
            )
            try:
                identity = self._validate_windows_directory(handle, expected_path)
                api.require_private_directory(handle)
                after = self._validate_windows_directory(handle, expected_path)
                _ensure_stable_directory_object(identity, after)
            finally:
                api.close(handle)

    def _list_recovery_directory_windows(
        self,
        parts: tuple[str, ...],
        max_items: int,
    ) -> tuple[str, ...]:
        with self._windows_parent(parts) as (handle, expected_path):
            identity = self._validate_windows_directory(handle, expected_path)
            names: list[str] = []
            try:
                # CPython cannot enumerate by Windows HANDLE. The validated directory and
                # every parent remain open without FILE_SHARE_DELETE, so this name-based
                # enumeration is an untrusted hint only; every action reopens by handle.
                with os.scandir(expected_path) as entries:
                    for entry in entries:
                        names.append(entry.name)
                        if len(names) > max_items:
                            raise BudgetExceeded(
                                "recovery directory exceeded the configured item budget"
                            )
            except BudgetExceeded:
                raise
            except OSError:
                raise _FilesystemFailure("DIRECTORY_ENUMERATION_FAILED") from None
            after = self._validate_windows_directory(handle, expected_path)
            _ensure_stable_identity(identity, after)
            return tuple(names)

    def _move_windows(
        self,
        source_relative: str,
        source_parts: tuple[str, ...],
        dest_relative: str,
        dest_parts: tuple[str, ...],
        expected_sha256: str,
        *,
        allow_existing_equal: bool,
        not_modified_after: datetime | None,
        remove_source_if_existing_equal: bool,
        invoke_fault_hook: bool,
        max_bytes: int,
    ) -> SecureFileSnapshot:
        api = self._windows_api()
        with contextlib.ExitStack() as stack:
            source = stack.enter_context(
                self._windows_file(
                    source_parts,
                    desired_access=(api.GENERIC_READ | api.FILE_READ_ATTRIBUTES | api.DELETE),
                    share_mode=api.FILE_SHARE_READ,
                    disposition=api.OPEN_EXISTING,
                    max_bytes=max_bytes,
                )
            )
            if not_modified_after is not None and not _modified_at_or_before(
                source.identity,
                not_modified_after,
            ):
                raise _FilesystemFailure("FILE_TOO_YOUNG")
            if invoke_fault_hook and self._fault_hook is not None:
                self._fault_hook(source_relative)
            source_data = api.read_all(source.handle, max_bytes)
            source_after = self._validate_windows_file(
                source.handle,
                source.expected_final_path,
                max_bytes,
            )
            _ensure_stable_identity(source.identity, source_after)
            source_snapshot = _snapshot(source_relative, source_data)
            if source_snapshot.sha256 != expected_sha256:
                raise ArtifactIntegrityViolation("EXPECTED_HASH_MISMATCH", source_relative)

            _, target_parent_path = stack.enter_context(self._windows_parent(dest_parts[:-1]))
            target_path = self._windows_join(target_parent_path, dest_parts[-1])
            try:
                api.rename_no_replace(source.handle, target_path)
            except _EntryExists:
                if not allow_existing_equal:
                    raise
                try:
                    existing = self._read_internal(
                        dest_relative,
                        dest_parts,
                        expected_sha256,
                        max_bytes,
                        invoke_fault_hook=False,
                    )
                except ArtifactIntegrityViolation:
                    raise _EntryExists from None
                if remove_source_if_existing_equal:
                    source_before_delete = self._validate_windows_file(
                        source.handle,
                        source.expected_final_path,
                        max_bytes,
                    )
                    _ensure_stable_identity(source.identity, source_before_delete)
                    api.delete_by_handle(source.handle)
                return existing
            renamed_identity = self._validate_windows_file(
                source.handle,
                target_path,
                max_bytes,
            )
            if renamed_identity.object_key != source.identity.object_key:
                raise _FilesystemFailure("RENAMED_IDENTITY_MISMATCH")
            target = stack.enter_context(
                self._windows_file(
                    dest_parts,
                    desired_access=api.GENERIC_READ | api.FILE_READ_ATTRIBUTES,
                    share_mode=api.FILE_SHARE_READ | api.FILE_SHARE_DELETE,
                    disposition=api.OPEN_EXISTING,
                    max_bytes=max_bytes,
                )
            )
            if target.identity.object_key != source.identity.object_key:
                raise _FilesystemFailure("RENAMED_IDENTITY_MISMATCH")
            target_data = api.read_all(target.handle, max_bytes)
            target_after = self._validate_windows_file(
                target.handle,
                target.expected_final_path,
                max_bytes,
            )
            _ensure_stable_identity(target.identity, target_after)
            result = _snapshot(dest_relative, target_data)
            if result.sha256 != source_snapshot.sha256 or result.bytes != source_snapshot.bytes:
                raise _FilesystemFailure("RENAMED_CONTENT_MISMATCH")
            return result

    def _replace_windows(
        self,
        source_relative: str,
        source_parts: tuple[str, ...],
        dest_relative: str,
        dest_parts: tuple[str, ...],
        expected_sha256: str,
    ) -> SecureFileSnapshot:
        api = self._windows_api()
        with contextlib.ExitStack() as stack:
            source = stack.enter_context(
                self._windows_file(
                    source_parts,
                    desired_access=(api.GENERIC_READ | api.FILE_READ_ATTRIBUTES | api.DELETE),
                    share_mode=api.FILE_SHARE_READ,
                    disposition=api.OPEN_EXISTING,
                    max_bytes=self.max_file_bytes,
                )
            )
            source_data = api.read_all(source.handle, self.max_file_bytes)
            source_after = self._validate_windows_file(
                source.handle,
                source.expected_final_path,
                self.max_file_bytes,
            )
            _ensure_stable_identity(source.identity, source_after)
            source_snapshot = _snapshot(source_relative, source_data)
            if source_snapshot.sha256 != expected_sha256:
                raise ArtifactIntegrityViolation(
                    "EXPECTED_HASH_MISMATCH",
                    source_relative,
                )

            _, target_parent_path = stack.enter_context(self._windows_parent(dest_parts[:-1]))
            source_parent_path = source.expected_final_path.rsplit("\\", maxsplit=1)[0]
            if source_parent_path.casefold() != target_parent_path.casefold():
                raise _FilesystemFailure("REPLACEMENT_PARENT_MISMATCH")
            target_path = self._windows_join(target_parent_path, dest_parts[-1])
            target_handle: int | None = None
            try:
                target_handle = api.open_handle(
                    target_path,
                    desired_access=api.FILE_READ_ATTRIBUTES,
                    share_mode=(api.FILE_SHARE_READ | api.FILE_SHARE_WRITE | api.FILE_SHARE_DELETE),
                    disposition=api.OPEN_EXISTING,
                    flags=(api.FILE_FLAG_BACKUP_SEMANTICS | api.FILE_FLAG_OPEN_REPARSE_POINT),
                )
            except _MissingEntry:
                pass
            else:
                try:
                    self._validate_windows_file(
                        target_handle,
                        target_path,
                        self.max_file_bytes,
                    )
                except _FilesystemFailure:
                    raise _FilesystemFailure("UNSAFE_REPLACEMENT_TARGET") from None
                finally:
                    api.close(target_handle)

            api.rename_replace(source.handle, target_path)
            renamed_identity = self._validate_windows_file(
                source.handle,
                target_path,
                self.max_file_bytes,
            )
            if renamed_identity.object_key != source.identity.object_key:
                raise _FilesystemFailure("RENAMED_IDENTITY_MISMATCH")
            target = stack.enter_context(
                self._windows_file(
                    dest_parts,
                    desired_access=api.GENERIC_READ | api.FILE_READ_ATTRIBUTES,
                    share_mode=api.FILE_SHARE_READ | api.FILE_SHARE_DELETE,
                    disposition=api.OPEN_EXISTING,
                    max_bytes=self.max_file_bytes,
                )
            )
            if target.identity.object_key != source.identity.object_key:
                raise _FilesystemFailure("RENAMED_IDENTITY_MISMATCH")
            target_data = api.read_all(target.handle, self.max_file_bytes)
            target_after = self._validate_windows_file(
                target.handle,
                target.expected_final_path,
                self.max_file_bytes,
            )
            _ensure_stable_identity(target.identity, target_after)
            result = _snapshot(dest_relative, target_data)
            if result.sha256 != source_snapshot.sha256 or result.bytes != source_snapshot.bytes:
                raise _FilesystemFailure("RENAMED_CONTENT_MISMATCH")
            return result

    def _delete_windows(
        self,
        relative_path: str,
        parts: tuple[str, ...],
        expected_sha256: str,
    ) -> SecureDeletionReceipt:
        api = self._windows_api()
        with self._windows_file(
            parts,
            desired_access=api.GENERIC_READ | api.FILE_READ_ATTRIBUTES | api.DELETE,
            share_mode=api.FILE_SHARE_READ,
            disposition=api.OPEN_EXISTING,
            max_bytes=self.max_file_bytes,
        ) as opened:
            data = api.read_all(opened.handle, self.max_file_bytes)
            after = self._validate_windows_file(
                opened.handle,
                opened.expected_final_path,
                self.max_file_bytes,
            )
            _ensure_stable_identity(opened.identity, after)
            snapshot = _snapshot(relative_path, data)
            if snapshot.sha256 != expected_sha256:
                raise ArtifactIntegrityViolation(
                    "EXPECTED_HASH_MISMATCH",
                    relative_path,
                )
            api.delete_by_handle(opened.handle)

        try:
            self._read_internal(
                relative_path,
                parts,
                expected_sha256,
                self.max_file_bytes,
                invoke_fault_hook=False,
            )
        except _MissingEntry:
            pass
        else:
            raise _FilesystemFailure("DELETE_NOT_COMMITTED")
        return SecureDeletionReceipt(
            relative_path=relative_path,
            size_bytes=snapshot.size_bytes,
            sha256=snapshot.sha256,
        )

    def _read_internal(
        self,
        relative_path: str,
        parts: tuple[str, ...],
        expected_sha256: str | None,
        max_bytes: int,
        *,
        invoke_fault_hook: bool,
    ) -> SecureFileSnapshot:
        if os.name == "nt":
            return self._read_windows(
                relative_path,
                parts,
                expected_sha256,
                max_bytes,
                invoke_fault_hook,
            )
        return self._read_posix(
            relative_path,
            parts,
            expected_sha256,
            max_bytes,
            invoke_fault_hook,
        )

    def _move_internal(
        self,
        source_relative: str,
        source_parts: tuple[str, ...],
        dest_relative: str,
        dest_parts: tuple[str, ...],
        expected_sha256: str,
        *,
        allow_existing_equal: bool,
        missing_source_is_retry: bool,
        not_modified_after: datetime | None = None,
        remove_source_if_existing_equal: bool = False,
        invoke_fault_hook: bool = False,
        max_bytes: int | None = None,
    ) -> SecureFileSnapshot:
        if max_bytes is None:
            move_limit = self.max_file_bytes
        elif (
            not isinstance(max_bytes, int)
            or isinstance(max_bytes, bool)
            or not 0 <= max_bytes <= self.max_file_bytes
        ):
            raise ValueError("max_bytes must be from zero through the workspace limit")
        else:
            move_limit = max_bytes
        try:
            if os.name == "nt":
                return self._move_windows(
                    source_relative,
                    source_parts,
                    dest_relative,
                    dest_parts,
                    expected_sha256,
                    allow_existing_equal=allow_existing_equal,
                    not_modified_after=not_modified_after,
                    remove_source_if_existing_equal=remove_source_if_existing_equal,
                    invoke_fault_hook=invoke_fault_hook,
                    max_bytes=move_limit,
                )
            return self._move_posix(
                source_relative,
                source_parts,
                dest_relative,
                dest_parts,
                expected_sha256,
                allow_existing_equal=allow_existing_equal,
                not_modified_after=not_modified_after,
                remove_source_if_existing_equal=remove_source_if_existing_equal,
                invoke_fault_hook=invoke_fault_hook,
                max_bytes=move_limit,
            )
        except _MissingEntry:
            if not missing_source_is_retry:
                raise
            try:
                return self._read_internal(
                    dest_relative,
                    dest_parts,
                    expected_sha256,
                    move_limit,
                    invoke_fault_hook=False,
                )
            except ArtifactIntegrityViolation:
                raise _EntryExists from None

    @contextlib.contextmanager
    def _open_verified_video_windows(
        self,
        relative_path: str,
        parts: tuple[str, ...],
        max_bytes: int,
    ) -> Iterator[SecureVideoInput]:
        api = self._windows_api()
        with self._windows_file(
            parts,
            desired_access=api.GENERIC_READ | api.FILE_READ_ATTRIBUTES,
            share_mode=api.FILE_SHARE_READ,
            disposition=api.OPEN_EXISTING,
            max_bytes=max_bytes,
        ) as opened:
            data = api.read_all(opened.handle, max_bytes)
            if not data:
                raise _FilesystemFailure("EMPTY_VIDEO_INPUT")
            first_hash = _sha256(data)
            before_yield = self._validate_windows_file(
                opened.handle,
                opened.expected_final_path,
                max_bytes,
            )
            _ensure_stable_identity(opened.identity, before_yield)
            try:
                yield SecureVideoInput(
                    decoder_path=opened.expected_final_path,
                    input_file_sha256=first_hash,
                    size_bytes=len(data),
                )
            finally:
                after_data = api.read_all(opened.handle, max_bytes)
                after = self._validate_windows_file(
                    opened.handle,
                    opened.expected_final_path,
                    max_bytes,
                )
                _ensure_stable_identity(opened.identity, after)
                if _sha256(after_data) != first_hash or after_data != data:
                    raise _FilesystemFailure("VIDEO_INPUT_CHANGED")

    @contextlib.contextmanager
    def _open_verified_video_linux(
        self,
        relative_path: str,
        parts: tuple[str, ...],
        max_bytes: int,
    ) -> Iterator[SecureVideoInput]:
        if not hasattr(os, "memfd_create"):
            raise _FilesystemFailure("SEALED_VIDEO_HANDLE_UNAVAILABLE")
        try:
            import fcntl
        except ImportError:
            raise _FilesystemFailure("SEALED_VIDEO_HANDLE_UNAVAILABLE") from None
        required_constants = (
            "F_ADD_SEALS",
            "F_GET_SEALS",
            "F_SEAL_WRITE",
            "F_SEAL_GROW",
            "F_SEAL_SHRINK",
            "F_SEAL_SEAL",
        )
        if any(not hasattr(fcntl, name) for name in required_constants):
            raise _FilesystemFailure("SEALED_VIDEO_HANDLE_UNAVAILABLE")
        source = self._read_posix(
            relative_path,
            parts,
            expected_sha256=None,
            max_bytes=max_bytes,
            invoke_fault_hook=False,
        )
        if not source.bytes:
            raise _FilesystemFailure("EMPTY_VIDEO_INPUT")
        flags = getattr(os, "MFD_CLOEXEC", 0x0001) | getattr(os, "MFD_ALLOW_SEALING", 0x0002)
        memfd: int | None = None
        try:
            memfd = os.memfd_create("labcourt-video", flags)
            self._posix_write_all(memfd, source.bytes)
            self._posix_fsync(memfd, "MEMFD_FSYNC_FAILED")
            fcntl_call: Any = _dynamic_attribute(fcntl, "fcntl")
            seals = (
                int(_dynamic_attribute(fcntl, "F_SEAL_WRITE"))
                | int(_dynamic_attribute(fcntl, "F_SEAL_GROW"))
                | int(_dynamic_attribute(fcntl, "F_SEAL_SHRINK"))
                | int(_dynamic_attribute(fcntl, "F_SEAL_SEAL"))
            )
            fcntl_call(memfd, int(_dynamic_attribute(fcntl, "F_ADD_SEALS")), seals)
            actual_seals = int(fcntl_call(memfd, int(_dynamic_attribute(fcntl, "F_GET_SEALS"))))
            if actual_seals & seals != seals:
                raise _FilesystemFailure("MEMFD_SEAL_FAILED")
            decoder_path = f"/proc/self/fd/{memfd}"
            if not Path("/proc/self/fd").is_dir():
                raise _FilesystemFailure("PROC_FD_UNAVAILABLE")
        except OSError:
            if memfd is not None:
                os.close(memfd)
            raise _FilesystemFailure("SEALED_VIDEO_HANDLE_UNAVAILABLE") from None
        except BaseException:
            if memfd is not None:
                os.close(memfd)
            raise
        try:
            yield SecureVideoInput(
                decoder_path=decoder_path,
                input_file_sha256=source.sha256,
                size_bytes=source.size_bytes,
            )
        finally:
            os.close(memfd)


__all__ = [
    "SecureDeletionReceipt",
    "SecureDirectoryHint",
    "SecureFileMetadata",
    "SecureFileSnapshot",
    "SecureVideoInput",
    "SecureWorkspace",
    "create_owner_only_directory",
    "require_owner_only_directory",
]

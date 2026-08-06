"""Filesystem authority guard for the writable SQLite database.

The standard-library SQLite binding opens databases by path.  This adapter therefore
anchors and repeatedly validates the workspace parent, main database, and sidecars,
but deliberately does not claim custom-VFS path immutability.  See ADR 0005 and ADR
0008 for the same-permission ABA residual boundary.
"""

from __future__ import annotations

import ctypes
import errno
import os
import stat
from collections.abc import Callable
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from labcourt.exceptions import PathBoundaryViolation

SQLITE_AUTHORITY_FILENAME: Final = "labcourt.sqlite3"
_SIDECAR_SUFFIXES: Final = ("-wal", "-shm")
_ROLLBACK_SUFFIX: Final = "-journal"
_WINDOWS_SIDECAR_REOPEN_ATTEMPTS: Final = 8
_O_BINARY = int(getattr(os, "O_BINARY", 0))
_O_CLOEXEC = int(getattr(os, "O_CLOEXEC", 0))
_O_DIRECTORY = int(getattr(os, "O_DIRECTORY", 0))
_O_NOFOLLOW = int(getattr(os, "O_NOFOLLOW", 0))
_O_NONBLOCK = int(getattr(os, "O_NONBLOCK", 0))
_OS_FCHMOD: Any = getattr(os, "fchmod", None)
_OS_GETEUID: Any = getattr(os, "geteuid", None)

AuthorityFaultHook = Callable[[str], None]


class SQLiteAuthorityError(PathBoundaryViolation):
    """The writable SQLite authority could not be proven to be a safe local file."""

    def __init__(self, reason_code: str) -> None:
        # Never include the configured host path in this typed boundary.
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class _Identity:
    device: int
    file_id: int

    @property
    def object_key(self) -> tuple[int, int]:
        return self.device, self.file_id


@dataclass(slots=True)
class _PosixHeldFile:
    descriptor: int
    identity: _Identity


def _identity_from_stat(info: os.stat_result) -> _Identity:
    return _Identity(device=int(info.st_dev), file_id=int(info.st_ino))


def _is_reparse(info: os.stat_result) -> bool:
    attributes = int(getattr(info, "st_file_attributes", 0))
    return bool(attributes & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)))


class _PosixAuthorityBackend:
    def __init__(self, database: Path, *, allow_create: bool) -> None:
        self._database = database
        self._allow_create = allow_create
        self._parent_descriptor: int | None = None
        self._parent_identity: _Identity | None = None
        self._main: _PosixHeldFile | None = None
        self._sidecars: dict[str, _PosixHeldFile] = {}

    def start(self) -> None:
        required = ("O_DIRECTORY", "O_CLOEXEC", "O_NOFOLLOW")
        if (
            any(not hasattr(os, name) for name in required)
            or os.open not in os.supports_dir_fd
            or os.stat not in os.supports_dir_fd
            or os.stat not in os.supports_follow_symlinks
        ):
            raise SQLiteAuthorityError("SQLITE_AUTHORITY_HANDLE_API_UNAVAILABLE")
        try:
            parent_entry = os.stat(self._database.parent, follow_symlinks=False)
        except FileNotFoundError:
            raise SQLiteAuthorityError("DATABASE_PARENT_MISSING") from None
        except OSError:
            raise SQLiteAuthorityError("DATABASE_PARENT_UNSAFE") from None
        if stat.S_ISLNK(parent_entry.st_mode) or _is_reparse(parent_entry):
            raise SQLiteAuthorityError("DATABASE_PARENT_REPARSE_POINT")
        if not stat.S_ISDIR(parent_entry.st_mode):
            raise SQLiteAuthorityError("DATABASE_PARENT_UNSAFE")

        flags = os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW
        try:
            parent_descriptor = os.open(self._database.parent, flags)
        except OSError:
            raise SQLiteAuthorityError("DATABASE_PARENT_UNSAFE") from None
        self._parent_descriptor = parent_descriptor
        try:
            opened_parent = os.fstat(parent_descriptor)
            if not stat.S_ISDIR(opened_parent.st_mode) or _identity_from_stat(
                opened_parent
            ) != _identity_from_stat(parent_entry):
                raise SQLiteAuthorityError("DATABASE_PARENT_IDENTITY_CHANGED")
            self._parent_identity = _identity_from_stat(opened_parent)
            self._main = self._open_or_create_main()
            self._reject_rollback_journal()
            self._refresh_sidecars()
            self.verify()
        except BaseException:
            self.close()
            raise

    def _entry(self, name: str) -> os.stat_result | None:
        if self._parent_descriptor is None:
            raise SQLiteAuthorityError("DATABASE_PARENT_HANDLE_CLOSED")
        try:
            return os.stat(name, dir_fd=self._parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return None
        except OSError:
            raise SQLiteAuthorityError("DATABASE_ENTRY_STAT_FAILED") from None

    @staticmethod
    def _require_regular_entry(info: os.stat_result, *, sidecar: bool) -> None:
        prefix = "DATABASE_SIDECAR" if sidecar else "DATABASE"
        if stat.S_ISLNK(info.st_mode) or _is_reparse(info):
            raise SQLiteAuthorityError(f"{prefix}_REPARSE_POINT")
        if not stat.S_ISREG(info.st_mode):
            raise SQLiteAuthorityError(f"{prefix}_NOT_REGULAR")
        if int(info.st_nlink) != 1:
            raise SQLiteAuthorityError(f"{prefix}_LINK_COUNT_UNSAFE")

    def _open_existing(self, name: str, *, sidecar: bool) -> _PosixHeldFile | None:
        entry = self._entry(name)
        if entry is None:
            return None
        self._require_regular_entry(entry, sidecar=sidecar)
        if self._parent_descriptor is None:
            raise SQLiteAuthorityError("DATABASE_PARENT_HANDLE_CLOSED")
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | _O_BINARY | _O_CLOEXEC | _O_NOFOLLOW | _O_NONBLOCK,
                dir_fd=self._parent_descriptor,
            )
        except OSError as error:
            if error.errno in {errno.ELOOP, errno.EMLINK}:
                prefix = "DATABASE_SIDECAR" if sidecar else "DATABASE"
                raise SQLiteAuthorityError(f"{prefix}_REPARSE_POINT") from None
            raise SQLiteAuthorityError("DATABASE_ENTRY_OPEN_FAILED") from None
        try:
            opened = os.fstat(descriptor)
            self._require_regular_entry(opened, sidecar=sidecar)
            if _identity_from_stat(opened) != _identity_from_stat(entry):
                raise SQLiteAuthorityError("DATABASE_IDENTITY_CHANGED")
            return _PosixHeldFile(descriptor, _identity_from_stat(opened))
        except BaseException:
            os.close(descriptor)
            raise

    def _create_main(self) -> _PosixHeldFile:
        if self._parent_descriptor is None:
            raise SQLiteAuthorityError("DATABASE_PARENT_HANDLE_CLOSED")
        flags = (
            os.O_RDWR | os.O_CREAT | os.O_EXCL | _O_BINARY | _O_CLOEXEC | _O_NOFOLLOW | _O_NONBLOCK
        )
        try:
            descriptor = os.open(
                SQLITE_AUTHORITY_FILENAME,
                flags,
                0o600,
                dir_fd=self._parent_descriptor,
            )
        except FileExistsError:
            raise SQLiteAuthorityError("DATABASE_CREATE_RACE") from None
        except OSError:
            raise SQLiteAuthorityError("DATABASE_CREATE_FAILED") from None
        try:
            try:
                if _OS_FCHMOD is None:
                    raise OSError
                _OS_FCHMOD(descriptor, 0o600)
            except OSError:
                raise SQLiteAuthorityError("DATABASE_PRIVATE_MODE_FAILED") from None
            opened = os.fstat(descriptor)
            self._require_regular_entry(opened, sidecar=False)
            if stat.S_IMODE(opened.st_mode) != 0o600:
                raise SQLiteAuthorityError("DATABASE_NOT_OWNER_ONLY")
            if _OS_GETEUID is None or int(opened.st_uid) != int(_OS_GETEUID()):
                raise SQLiteAuthorityError("DATABASE_NOT_OWNER_ONLY")
            entry = self._entry(SQLITE_AUTHORITY_FILENAME)
            if entry is None or _identity_from_stat(entry) != _identity_from_stat(opened):
                raise SQLiteAuthorityError("DATABASE_IDENTITY_CHANGED")
            return _PosixHeldFile(descriptor, _identity_from_stat(opened))
        except BaseException:
            os.close(descriptor)
            raise

    def _open_or_create_main(self) -> _PosixHeldFile:
        opened = self._open_existing(SQLITE_AUTHORITY_FILENAME, sidecar=False)
        if opened is not None:
            return opened
        if not self._allow_create:
            raise SQLiteAuthorityError("DATABASE_MISSING")
        return self._create_main()

    def _verify_parent(self) -> None:
        if self._parent_descriptor is None or self._parent_identity is None:
            raise SQLiteAuthorityError("DATABASE_PARENT_HANDLE_CLOSED")
        try:
            held = os.fstat(self._parent_descriptor)
            entry = os.stat(self._database.parent, follow_symlinks=False)
        except OSError:
            raise SQLiteAuthorityError("DATABASE_PARENT_IDENTITY_CHANGED") from None
        if (
            not stat.S_ISDIR(held.st_mode)
            or not stat.S_ISDIR(entry.st_mode)
            or stat.S_ISLNK(entry.st_mode)
            or _is_reparse(entry)
            or _identity_from_stat(held) != self._parent_identity
            or _identity_from_stat(entry) != self._parent_identity
        ):
            raise SQLiteAuthorityError("DATABASE_PARENT_IDENTITY_CHANGED")

    def _verify_held(self, name: str, held: _PosixHeldFile, *, sidecar: bool) -> None:
        try:
            opened = os.fstat(held.descriptor)
        except OSError:
            raise SQLiteAuthorityError("DATABASE_HANDLE_STAT_FAILED") from None
        entry = self._entry(name)
        if entry is None:
            reason = "DATABASE_SIDECAR_SET_CHANGED" if sidecar else "DATABASE_IDENTITY_CHANGED"
            raise SQLiteAuthorityError(reason)
        if (
            _identity_from_stat(opened) != held.identity
            or _identity_from_stat(entry) != held.identity
        ):
            reason = "DATABASE_SIDECAR_IDENTITY_CHANGED" if sidecar else "DATABASE_IDENTITY_CHANGED"
            raise SQLiteAuthorityError(reason)
        self._require_regular_entry(opened, sidecar=sidecar)
        self._require_regular_entry(entry, sidecar=sidecar)

    def _reject_rollback_journal(self) -> None:
        if self._entry(f"{SQLITE_AUTHORITY_FILENAME}{_ROLLBACK_SUFFIX}") is not None:
            raise SQLiteAuthorityError("DATABASE_ROLLBACK_JOURNAL_PRESENT")

    def _refresh_sidecars(self) -> None:
        for suffix in _SIDECAR_SUFFIXES:
            held = self._sidecars.get(suffix)
            name = f"{SQLITE_AUTHORITY_FILENAME}{suffix}"
            if held is not None:
                self._verify_held(name, held, sidecar=True)
                continue
            opened = self._open_existing(name, sidecar=True)
            if opened is not None:
                self._sidecars[suffix] = opened

    def verify(self) -> None:
        self._verify_parent()
        if self._main is None:
            raise SQLiteAuthorityError("DATABASE_HANDLE_CLOSED")
        self._verify_held(SQLITE_AUTHORITY_FILENAME, self._main, sidecar=False)
        self._reject_rollback_journal()
        self._refresh_sidecars()

    def close(self) -> None:
        descriptors = [held.descriptor for held in self._sidecars.values()]
        if self._main is not None:
            descriptors.append(self._main.descriptor)
        if self._parent_descriptor is not None:
            descriptors.append(self._parent_descriptor)
        self._sidecars.clear()
        self._main = None
        self._parent_descriptor = None
        self._parent_identity = None
        failed = False
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                failed = True
        if failed:
            raise SQLiteAuthorityError("DATABASE_HANDLE_CLOSE_FAILED")


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


class _WindowsFailure(Exception):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class _WindowsSidecarRetired(_WindowsFailure):
    """An opened WAL/SHM handle lost its directory link during validation."""

    def __init__(self) -> None:
        super().__init__("DATABASE_SIDECAR_RETIRED")


class _WindowsAuthorityApi:
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
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
    FILE_NAME_NORMALIZED_VOLUME_GUID = 0x1
    ERROR_FILE_NOT_FOUND = 2
    ERROR_PATH_NOT_FOUND = 3
    ERROR_FILE_EXISTS = 80
    ERROR_ALREADY_EXISTS = 183
    ERROR_INSUFFICIENT_BUFFER = 122
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
            raise _WindowsFailure("SQLITE_AUTHORITY_HANDLE_API_UNAVAILABLE")
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
        self._get_info.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ByHandleFileInformation)]
        self._get_info.restype = wintypes.BOOL
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

    def _error(self) -> int:
        return int(self._get_last_error())

    def _raw_open(
        self,
        path: str,
        *,
        desired_access: int,
        share_mode: int,
        disposition: int,
        flags: int,
        security_attributes: _SecurityAttributes | None = None,
    ) -> int | None:
        raw = self._create_file(
            path,
            desired_access,
            share_mode,
            ctypes.byref(security_attributes) if security_attributes is not None else None,
            disposition,
            flags,
            None,
        )
        handle = int(raw) if raw is not None else 0
        if handle != self.INVALID_HANDLE_VALUE:
            return handle
        error_number = self._error()
        if error_number in {self.ERROR_FILE_NOT_FOUND, self.ERROR_PATH_NOT_FOUND}:
            return None
        if error_number in {self.ERROR_FILE_EXISTS, self.ERROR_ALREADY_EXISTS}:
            raise _WindowsFailure("DATABASE_CREATE_RACE")
        raise _WindowsFailure("WINDOWS_AUTHORITY_OPEN_FAILED")

    def open_parent(self, path: str) -> int | None:
        return self._raw_open(
            path,
            desired_access=self.FILE_READ_ATTRIBUTES | self.FILE_TRAVERSE | self.SYNCHRONIZE,
            share_mode=self.FILE_SHARE_READ | self.FILE_SHARE_WRITE,
            disposition=self.OPEN_EXISTING,
            flags=self.FILE_FLAG_BACKUP_SEMANTICS | self.FILE_FLAG_OPEN_REPARSE_POINT,
        )

    def open_file(self, path: str, *, sidecar: bool) -> int | None:
        share_mode = self.FILE_SHARE_READ | self.FILE_SHARE_WRITE
        if sidecar:
            share_mode |= self.FILE_SHARE_DELETE
        return self._raw_open(
            path,
            desired_access=self.FILE_READ_ATTRIBUTES | self.READ_CONTROL | self.SYNCHRONIZE,
            share_mode=share_mode,
            disposition=self.OPEN_EXISTING,
            flags=self.FILE_FLAG_BACKUP_SEMANTICS | self.FILE_FLAG_OPEN_REPARSE_POINT,
        )

    def create_private_file(self, path: str) -> int:
        descriptor = wintypes.LPVOID()
        descriptor_size = wintypes.DWORD()
        owner_sid = self.current_process_sid_string()
        sddl = f"O:{owner_sid}D:P(A;;FA;;;{owner_sid})"
        if not self._convert_sddl(
            sddl,
            1,
            ctypes.byref(descriptor),
            ctypes.byref(descriptor_size),
        ):
            raise _WindowsFailure("WINDOWS_PRIVATE_DACL_UNAVAILABLE")
        attributes = _SecurityAttributes(
            length=ctypes.sizeof(_SecurityAttributes),
            security_descriptor=descriptor,
            inherit_handle=False,
        )
        try:
            handle = self._raw_open(
                path,
                desired_access=(
                    self.GENERIC_READ
                    | self.GENERIC_WRITE
                    | self.FILE_READ_ATTRIBUTES
                    | self.READ_CONTROL
                    | self.SYNCHRONIZE
                ),
                share_mode=self.FILE_SHARE_READ | self.FILE_SHARE_WRITE,
                disposition=self.CREATE_NEW,
                flags=self.FILE_ATTRIBUTE_NORMAL | self.FILE_FLAG_OPEN_REPARSE_POINT,
                security_attributes=attributes,
            )
        finally:
            self._local_free(descriptor)
        if handle is None:
            raise _WindowsFailure("DATABASE_CREATE_FAILED")
        return handle

    def close(self, handle: int) -> None:
        if not self._close_handle(handle):
            raise _WindowsFailure("DATABASE_HANDLE_CLOSE_FAILED")

    def identity_and_attributes(self, handle: int) -> tuple[_Identity, int, int]:
        info = _ByHandleFileInformation()
        if not self._get_info(handle, ctypes.byref(info)):
            raise _WindowsFailure("WINDOWS_AUTHORITY_INFO_UNAVAILABLE")
        identity = _Identity(
            device=int(info.dwVolumeSerialNumber),
            file_id=(int(info.nFileIndexHigh) << 32) | int(info.nFileIndexLow),
        )
        return identity, int(info.dwFileAttributes), int(info.nNumberOfLinks)

    def is_disk_object(self, handle: int) -> bool:
        return int(self._get_file_type(handle)) == self.FILE_TYPE_DISK

    def final_path(self, handle: int) -> str:
        required = int(self._get_final_path(handle, None, 0, self.FILE_NAME_NORMALIZED_VOLUME_GUID))
        if required <= 0 or required > 32768:
            raise _WindowsFailure("WINDOWS_AUTHORITY_FINAL_PATH_UNAVAILABLE")
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
            raise _WindowsFailure("WINDOWS_AUTHORITY_FINAL_PATH_UNAVAILABLE")
        return buffer.value.rstrip("\\")

    def current_process_sid_string(self) -> str:
        token = wintypes.HANDLE()
        if not self._open_process_token(
            self._get_current_process(), self.TOKEN_QUERY, ctypes.byref(token)
        ):
            raise _WindowsFailure("WINDOWS_PROCESS_IDENTITY_UNAVAILABLE")
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
                raise _WindowsFailure("WINDOWS_PROCESS_IDENTITY_UNAVAILABLE")
            buffer = ctypes.create_string_buffer(int(required.value))
            if not self._get_token_information(
                token,
                self.TOKEN_USER_CLASS,
                buffer,
                int(required.value),
                ctypes.byref(required),
            ):
                raise _WindowsFailure("WINDOWS_PROCESS_IDENTITY_UNAVAILABLE")
            token_user = ctypes.cast(buffer, ctypes.POINTER(_TokenUser)).contents
            if not token_user.user.sid:
                raise _WindowsFailure("WINDOWS_PROCESS_IDENTITY_UNAVAILABLE")
            return self._sid_string(token_user.user.sid)
        finally:
            if token_value:
                self.close(token_value)

    def _sid_string(self, sid: wintypes.LPVOID) -> str:
        value = wintypes.LPWSTR()
        if not self._convert_sid_to_string(sid, ctypes.byref(value)) or not value.value:
            raise _WindowsFailure("WINDOWS_PROCESS_IDENTITY_UNAVAILABLE")
        try:
            return value.value
        finally:
            self._local_free(value)

    def require_owner_only_file(self, handle: int) -> None:
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
            raise _WindowsFailure("WINDOWS_FILE_SECURITY_UNAVAILABLE")
        try:
            control = wintypes.WORD()
            revision = wintypes.DWORD()
            if not self._get_security_descriptor_control(
                descriptor, ctypes.byref(control), ctypes.byref(revision)
            ):
                raise _WindowsFailure("WINDOWS_FILE_SECURITY_UNAVAILABLE")
            if not int(control.value) & self.SE_DACL_PROTECTED or not owner.value or not dacl.value:
                raise _WindowsFailure("DATABASE_NOT_OWNER_ONLY")
            acl = ctypes.cast(dacl, ctypes.POINTER(_Acl)).contents
            if int(acl.ace_count) != 1:
                raise _WindowsFailure("DATABASE_NOT_OWNER_ONLY")
            ace_pointer = wintypes.LPVOID()
            if not self._get_ace(dacl, 0, ctypes.byref(ace_pointer)) or not ace_pointer.value:
                raise _WindowsFailure("WINDOWS_FILE_SECURITY_UNAVAILABLE")
            ace = ctypes.cast(ace_pointer, ctypes.POINTER(_AccessAllowedAce)).contents
            if (
                int(ace.header.ace_type) != self.ACCESS_ALLOWED_ACE_TYPE
                or int(ace.header.ace_flags) != 0
                or int(ace.mask) != self.FILE_ALL_ACCESS
                or int(ace.header.ace_size) <= _AccessAllowedAce.sid_start.offset
            ):
                raise _WindowsFailure("DATABASE_NOT_OWNER_ONLY")
            ace_sid = wintypes.LPVOID(int(ace_pointer.value) + _AccessAllowedAce.sid_start.offset)
            if not self._equal_sid(owner, ace_sid):
                raise _WindowsFailure("DATABASE_NOT_OWNER_ONLY")
            if self._sid_string(owner) != self.current_process_sid_string():
                raise _WindowsFailure("DATABASE_NOT_OWNER_ONLY")
        finally:
            self._local_free(descriptor)


@dataclass(slots=True)
class _WindowsHeldFile:
    handle: int
    identity: _Identity
    expected_final_path: str


class _WindowsAuthorityBackend:
    def __init__(self, database: Path, *, allow_create: bool) -> None:
        self._database = database
        self._allow_create = allow_create
        self._api: _WindowsAuthorityApi | None = None
        self._parent_handle: int | None = None
        self._parent_identity: _Identity | None = None
        self._parent_final_path: str | None = None
        self._main: _WindowsHeldFile | None = None
        self._sidecars: dict[str, _WindowsHeldFile] = {}

    def start(self) -> None:
        try:
            api = _WindowsAuthorityApi()
            self._api = api
            parent_handle = api.open_parent(str(self._database.parent))
            if parent_handle is None:
                raise SQLiteAuthorityError("DATABASE_PARENT_MISSING")
            self._parent_handle = parent_handle
            parent_identity, attributes, _ = api.identity_and_attributes(parent_handle)
            if attributes & api.FILE_ATTRIBUTE_REPARSE_POINT:
                raise SQLiteAuthorityError("DATABASE_PARENT_REPARSE_POINT")
            if not attributes & api.FILE_ATTRIBUTE_DIRECTORY or not api.is_disk_object(
                parent_handle
            ):
                raise SQLiteAuthorityError("DATABASE_PARENT_UNSAFE")
            self._parent_identity = parent_identity
            self._parent_final_path = api.final_path(parent_handle)
            self._main = self._open_or_create_main()
            self._reject_rollback_journal()
            self._refresh_sidecars()
            self.verify()
        except _WindowsFailure as error:
            self.close(suppress_errors=True)
            raise SQLiteAuthorityError(error.reason_code) from None
        except BaseException:
            self.close(suppress_errors=True)
            raise

    def _api_or_fail(self) -> _WindowsAuthorityApi:
        if self._api is None:
            raise SQLiteAuthorityError("DATABASE_HANDLE_CLOSED")
        return self._api

    def _path_for(self, name: str) -> str:
        return str(self._database.parent / name)

    def _expected_final_path(self, name: str) -> str:
        if self._parent_final_path is None:
            raise SQLiteAuthorityError("DATABASE_PARENT_HANDLE_CLOSED")
        return f"{self._parent_final_path}\\{name}"

    def _validate_file(
        self,
        handle: int,
        *,
        name: str,
        sidecar: bool,
        expected_identity: _Identity | None = None,
    ) -> _WindowsHeldFile:
        api = self._api_or_fail()
        identity, attributes, link_count = api.identity_and_attributes(handle)
        prefix = "DATABASE_SIDECAR" if sidecar else "DATABASE"
        if attributes & api.FILE_ATTRIBUTE_REPARSE_POINT:
            raise SQLiteAuthorityError(f"{prefix}_REPARSE_POINT")
        if attributes & api.FILE_ATTRIBUTE_DIRECTORY or not api.is_disk_object(handle):
            raise SQLiteAuthorityError(f"{prefix}_NOT_REGULAR")
        if sidecar and link_count == 0:
            # SQLite may unlink a WAL/SHM name after CreateFileW has returned
            # our FILE_SHARE_DELETE handle but before this validation runs.
            # Such a delete-pending object is not the current named sidecar;
            # close it and reopen the name instead of accepting or reporting it.
            raise _WindowsSidecarRetired
        if link_count != 1:
            raise SQLiteAuthorityError(f"{prefix}_LINK_COUNT_UNSAFE")
        expected_path = self._expected_final_path(name)
        try:
            observed_path = api.final_path(handle)
        except _WindowsFailure:
            if sidecar and self._sidecar_retired_after_open(handle, identity):
                raise _WindowsSidecarRetired from None
            raise
        if observed_path.casefold() != expected_path.casefold():
            if sidecar and self._sidecar_retired_after_open(handle, identity):
                raise _WindowsSidecarRetired
            raise SQLiteAuthorityError(f"{prefix}_PATH_ESCAPE")
        if expected_identity is not None and identity != expected_identity:
            raise SQLiteAuthorityError(
                "DATABASE_SIDECAR_IDENTITY_CHANGED" if sidecar else "DATABASE_IDENTITY_CHANGED"
            )
        return _WindowsHeldFile(handle, identity, expected_path)

    def _sidecar_retired_after_open(
        self,
        handle: int,
        expected_identity: _Identity,
    ) -> bool:
        """Recognize only a same-object transition from one link to delete-pending."""

        api = self._api_or_fail()
        identity, attributes, link_count = api.identity_and_attributes(handle)
        if identity != expected_identity:
            raise SQLiteAuthorityError("DATABASE_SIDECAR_IDENTITY_CHANGED")
        if attributes & api.FILE_ATTRIBUTE_REPARSE_POINT:
            raise SQLiteAuthorityError("DATABASE_SIDECAR_REPARSE_POINT")
        if attributes & api.FILE_ATTRIBUTE_DIRECTORY or not api.is_disk_object(handle):
            raise SQLiteAuthorityError("DATABASE_SIDECAR_NOT_REGULAR")
        if link_count not in {0, 1}:
            raise SQLiteAuthorityError("DATABASE_SIDECAR_LINK_COUNT_UNSAFE")
        return link_count == 0

    def _open_existing(self, name: str, *, sidecar: bool) -> _WindowsHeldFile | None:
        api = self._api_or_fail()
        attempts = _WINDOWS_SIDECAR_REOPEN_ATTEMPTS if sidecar else 1
        for _ in range(attempts):
            try:
                handle = api.open_file(self._path_for(name), sidecar=sidecar)
            except _WindowsFailure as error:
                raise SQLiteAuthorityError(error.reason_code) from None
            if handle is None:
                return None
            try:
                return self._validate_file(handle, name=name, sidecar=sidecar)
            except _WindowsSidecarRetired:
                api.close(handle)
                continue
            except BaseException:
                api.close(handle)
                raise
        raise SQLiteAuthorityError("DATABASE_SIDECAR_SET_UNSTABLE")

    def _open_or_create_main(self) -> _WindowsHeldFile:
        opened = self._open_existing(SQLITE_AUTHORITY_FILENAME, sidecar=False)
        if opened is not None:
            return opened
        if not self._allow_create:
            raise SQLiteAuthorityError("DATABASE_MISSING")
        api = self._api_or_fail()
        try:
            handle = api.create_private_file(self._path_for(SQLITE_AUTHORITY_FILENAME))
            created = self._validate_file(
                handle,
                name=SQLITE_AUTHORITY_FILENAME,
                sidecar=False,
            )
            api.require_owner_only_file(handle)
            return created
        except _WindowsFailure as error:
            if "handle" in locals():
                api.close(handle)
            raise SQLiteAuthorityError(error.reason_code) from None
        except BaseException:
            if "handle" in locals():
                api.close(handle)
            raise

    def _verify_parent(self) -> None:
        api = self._api_or_fail()
        if self._parent_handle is None or self._parent_identity is None:
            raise SQLiteAuthorityError("DATABASE_PARENT_HANDLE_CLOSED")
        current: int | None = None
        try:
            held_identity, held_attributes, _ = api.identity_and_attributes(self._parent_handle)
            current = api.open_parent(str(self._database.parent))
            if current is None:
                raise SQLiteAuthorityError("DATABASE_PARENT_IDENTITY_CHANGED")
            current_identity, current_attributes, _ = api.identity_and_attributes(current)
            if (
                held_identity != self._parent_identity
                or current_identity != self._parent_identity
                or held_attributes & api.FILE_ATTRIBUTE_REPARSE_POINT
                or current_attributes & api.FILE_ATTRIBUTE_REPARSE_POINT
                or not held_attributes & api.FILE_ATTRIBUTE_DIRECTORY
                or not current_attributes & api.FILE_ATTRIBUTE_DIRECTORY
            ):
                raise SQLiteAuthorityError("DATABASE_PARENT_IDENTITY_CHANGED")
        except _WindowsFailure:
            raise SQLiteAuthorityError("DATABASE_PARENT_IDENTITY_CHANGED") from None
        finally:
            if current is not None:
                api.close(current)

    def _verify_held(self, name: str, held: _WindowsHeldFile, *, sidecar: bool) -> None:
        api = self._api_or_fail()
        self._validate_file(
            held.handle,
            name=name,
            sidecar=sidecar,
            expected_identity=held.identity,
        )
        current = self._open_existing(name, sidecar=sidecar)
        if current is None:
            reason = "DATABASE_SIDECAR_SET_CHANGED" if sidecar else "DATABASE_IDENTITY_CHANGED"
            raise SQLiteAuthorityError(reason)
        try:
            if current.identity != held.identity:
                reason = (
                    "DATABASE_SIDECAR_IDENTITY_CHANGED" if sidecar else "DATABASE_IDENTITY_CHANGED"
                )
                raise SQLiteAuthorityError(reason)
        finally:
            api.close(current.handle)

    def _sidecar_retired_during_verification(self, held: _WindowsHeldFile) -> bool:
        """Recognize only the normal unlink transition of an anchored WAL sidecar.

        Windows keeps a delete-pending file object alive while a handle opened with
        ``FILE_SHARE_DELETE`` remains open.  Its already-validated single directory
        link becomes zero even though the handle identity is unchanged.  Reparse,
        regular-file, identity, and multi-link checks remain fail-closed.
        """

        return self._sidecar_retired_after_open(held.handle, held.identity)

    def _verify_current_sidecar(self, name: str, held: _WindowsHeldFile) -> bool:
        """Return false only when the previously safe sidecar was normally unlinked."""

        try:
            self._verify_held(name, held, sidecar=True)
        except (SQLiteAuthorityError, _WindowsFailure) as error:
            # A failed CloseHandle for the temporary current-path anchor is not
            # SQLite lifecycle churn.  Never hide it merely because the older
            # anchored sidecar retired at the same time: that would lose the only
            # signal that the temporary handle may still be live.
            if error.reason_code == "DATABASE_HANDLE_CLOSE_FAILED":
                raise
            if self._sidecar_retired_during_verification(held):
                return False
            raise
        return not self._sidecar_retired_during_verification(held)

    def _reject_rollback_journal(self) -> None:
        api = self._api_or_fail()
        handle = api.open_file(
            self._path_for(f"{SQLITE_AUTHORITY_FILENAME}{_ROLLBACK_SUFFIX}"), sidecar=True
        )
        if handle is None:
            return
        try:
            raise SQLiteAuthorityError("DATABASE_ROLLBACK_JOURNAL_PRESENT")
        finally:
            api.close(handle)

    def _refresh_sidecars(self) -> None:
        api = self._api_or_fail()
        for suffix in _SIDECAR_SUFFIXES:
            held = self._sidecars.get(suffix)
            name = f"{SQLITE_AUTHORITY_FILENAME}{suffix}"
            if held is not None:
                if self._verify_current_sidecar(name, held):
                    continue
                # The old handle must be released before SQLite can recreate a
                # delete-pending WAL/SHM name.  Any replacement is then opened and
                # subjected to the complete path, identity, reparse, and link checks.
                del self._sidecars[suffix]
                api.close(held.handle)
            opened = self._open_existing(name, sidecar=True)
            if opened is not None:
                self._sidecars[suffix] = opened

    def verify(self) -> None:
        try:
            self._verify_parent()
            if self._main is None:
                raise SQLiteAuthorityError("DATABASE_HANDLE_CLOSED")
            self._verify_held(SQLITE_AUTHORITY_FILENAME, self._main, sidecar=False)
            self._reject_rollback_journal()
            self._refresh_sidecars()
        except _WindowsFailure as error:
            raise SQLiteAuthorityError(error.reason_code) from None

    def close(self, *, suppress_errors: bool = False) -> None:
        api = self._api
        handles = [held.handle for held in self._sidecars.values()]
        if self._main is not None:
            handles.append(self._main.handle)
        if self._parent_handle is not None:
            handles.append(self._parent_handle)
        self._sidecars.clear()
        self._main = None
        self._parent_handle = None
        self._parent_identity = None
        self._parent_final_path = None
        self._api = None
        failed = False
        if api is not None:
            for handle in handles:
                try:
                    api.close(handle)
                except _WindowsFailure:
                    failed = True
        if failed and not suppress_errors:
            raise SQLiteAuthorityError("DATABASE_HANDLE_CLOSE_FAILED")


class SQLiteAuthorityGuard:
    """Hold and revalidate the one canonical writable SQLite authority path."""

    def __init__(
        self,
        database_path: str | Path,
        *,
        allow_create: bool,
        fault_hook: AuthorityFaultHook | None = None,
    ) -> None:
        database = Path(database_path).absolute()
        if database.name != SQLITE_AUTHORITY_FILENAME:
            raise SQLiteAuthorityError("DATABASE_NAME_INVALID")
        self.database_path = database
        self._allow_create = allow_create
        self._fault_hook = fault_hook
        self._backend: _PosixAuthorityBackend | _WindowsAuthorityBackend | None = None

    def __enter__(self) -> SQLiteAuthorityGuard:
        if self._backend is not None:
            raise SQLiteAuthorityError("DATABASE_GUARD_ALREADY_OPEN")
        if os.name == "posix":
            backend: _PosixAuthorityBackend | _WindowsAuthorityBackend = _PosixAuthorityBackend(
                self.database_path,
                allow_create=self._allow_create,
            )
        elif os.name == "nt":
            backend = _WindowsAuthorityBackend(
                self.database_path,
                allow_create=self._allow_create,
            )
        else:
            raise SQLiteAuthorityError("SQLITE_AUTHORITY_HANDLE_API_UNAVAILABLE")
        backend.start()
        self._backend = backend
        return self

    def checkpoint(self, phase: str) -> None:
        """Run an injectable race checkpoint, then revalidate every anchored entry."""

        if self._backend is None:
            raise SQLiteAuthorityError("DATABASE_GUARD_CLOSED")
        if self._fault_hook is not None:
            self._fault_hook(phase)
        self._backend.verify()

    def close(self) -> None:
        backend = self._backend
        self._backend = None
        if backend is not None:
            backend.close()

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        try:
            self.close()
        except SQLiteAuthorityError:
            if exc_type is None:
                raise


__all__ = [
    "SQLITE_AUTHORITY_FILENAME",
    "AuthorityFaultHook",
    "SQLiteAuthorityError",
    "SQLiteAuthorityGuard",
]

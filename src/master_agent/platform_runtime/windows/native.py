"""Lazy stdlib-ctypes Win32 adapter for the secure filesystem backend."""

from __future__ import annotations

import ctypes
import errno
import sys
from typing import Any, Final

from master_agent.platform_runtime.contracts import PlatformCapabilityUnavailable
from master_agent.platform_runtime.windows.filesystem import (
    BUILTIN_ADMINISTRATORS_SID,
    NativeWindowsFileSnapshot,
    NativeWindowsSecurity,
    NativeWindowsVolume,
    WindowsAccessAllowedAce,
    WindowsDacl,
    WindowsPathSecurityError,
    parse_windows_ace_header,
    validate_windows_drive_path,
    windows_ace_sid_length,
    windows_ace_type_is_supported_allow,
)

_DWORD = ctypes.c_uint32
_BOOL = ctypes.c_int32
_HANDLE = ctypes.c_void_p

_INVALID_HANDLE_VALUE: Final[int] = ctypes.c_void_p(-1).value or -1
_ERROR_FILE_NOT_FOUND = 2
_ERROR_NO_MORE_FILES = 18
_ERROR_INSUFFICIENT_BUFFER = 122

_CSTR_LESS_THAN = 1
_CSTR_EQUAL = 2
_CSTR_GREATER_THAN = 3

_FILE_READ_ATTRIBUTES = 0x00000080
_FILE_READ_DATA = 0x00000001
_FILE_WRITE_DATA = 0x00000002
_FILE_TRAVERSE = 0x00000020
_READ_CONTROL = 0x00020000
_DELETE = 0x00010000
_SYNCHRONIZE = 0x00100000
_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_FILE_SHARE_READ = 0x00000001
_FILE_SHARE_WRITE = 0x00000002
_FILE_SHARE_DELETE = 0x00000004
_OPEN_EXISTING = 3
_FILE_FLAG_OPEN_NO_RECALL = 0x00100000
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_HANDLE_FLAG_INHERIT = 0x00000001
_FILE_TYPE_DISK = 0x00000001
_FILE_BEGIN = 0
_DUPLICATE_SAME_ACCESS = 0x00000002
_FILE_ATTRIBUTE_NORMAL = 0x00000080

_OBJ_CASE_INSENSITIVE = 0x00000040
_FILE_CREATE = 2
_FILE_DIRECTORY_FILE = 0x00000001
_FILE_WRITE_THROUGH = 0x00000002
_FILE_NON_DIRECTORY_FILE = 0x00000040
_FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
_STATUS_OBJECT_NAME_COLLISION = 0xC0000035
_FILE_DISPOSITION_INFO_CLASS = 4
_FILE_RENAME_INFO_EX_CLASS = 22
_FILE_RENAME_REPLACE_IF_EXISTS = 0x00000001
_FILE_RENAME_POSIX_SEMANTICS = 0x00000002

_FILE_BASIC_INFO_CLASS = 0
_FILE_STANDARD_INFO_CLASS = 1
_FILE_ID_INFO_CLASS = 18
_FILE_CASE_SENSITIVE_INFO_CLASS = 23
_FILE_CS_FLAG_CASE_SENSITIVE_DIR = 0x00000001
_VOLUME_NAME_DOS = 0x0

_SE_FILE_OBJECT = 1
_OWNER_SECURITY_INFORMATION = 0x00000001
_DACL_SECURITY_INFORMATION = 0x00000004
_SE_DACL_PROTECTED = 0x1000
_SDDL_REVISION_1 = 1
_TOKEN_QUERY = 0x0008
_TOKEN_USER_CLASS = 1

_OBJECT_ALLOW_ACE_TYPE = 0x05
_ACE_OBJECT_TYPE_PRESENT = 0x00000001
_ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x00000002

_MAX_DIRECTORY_ENTRIES = 65_536


class _FILE_BASIC_INFO(ctypes.Structure):
    _fields_ = [
        ("CreationTime", ctypes.c_int64),
        ("LastAccessTime", ctypes.c_int64),
        ("LastWriteTime", ctypes.c_int64),
        ("ChangeTime", ctypes.c_int64),
        ("FileAttributes", _DWORD),
    ]


class _FILE_STANDARD_INFO(ctypes.Structure):
    _fields_ = [
        ("AllocationSize", ctypes.c_int64),
        ("EndOfFile", ctypes.c_int64),
        ("NumberOfLinks", _DWORD),
        ("DeletePending", ctypes.c_ubyte),
        ("Directory", ctypes.c_ubyte),
    ]


class _FILE_ID_128(ctypes.Structure):
    _fields_ = [("Identifier", ctypes.c_ubyte * 16)]


class _FILE_ID_INFO(ctypes.Structure):
    _fields_ = [
        ("VolumeSerialNumber", ctypes.c_uint64),
        ("FileId", _FILE_ID_128),
    ]


class _FILE_CASE_SENSITIVE_INFO(ctypes.Structure):
    _fields_ = [("Flags", _DWORD)]


class _FILE_DISPOSITION_INFO(ctypes.Structure):
    _fields_ = [("DeleteFile", ctypes.c_ubyte)]


class _FILE_RENAME_INFO_EX(ctypes.Structure):
    """ABI prefix for ``FILE_RENAME_INFO`` with a variable UTF-16 name."""

    _fields_ = [
        ("Flags", _DWORD),
        ("RootDirectory", _HANDLE),
        ("FileNameLength", _DWORD),
        ("FileName", ctypes.c_uint16 * 1),
    ]


class _UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", ctypes.c_uint16),
        ("MaximumLength", ctypes.c_uint16),
        ("Buffer", ctypes.c_void_p),
    ]


class _OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Length", _DWORD),
        ("RootDirectory", _HANDLE),
        ("ObjectName", ctypes.POINTER(_UNICODE_STRING)),
        ("Attributes", _DWORD),
        ("SecurityDescriptor", ctypes.c_void_p),
        ("SecurityQualityOfService", ctypes.c_void_p),
    ]


class _IO_STATUS_BLOCK(ctypes.Structure):
    _fields_ = [
        ("Status", ctypes.c_void_p),
        ("Information", ctypes.c_size_t),
    ]


class _ACL(ctypes.Structure):
    _fields_ = [
        ("AclRevision", ctypes.c_ubyte),
        ("Sbz1", ctypes.c_ubyte),
        ("AclSize", ctypes.c_uint16),
        ("AceCount", ctypes.c_uint16),
        ("Sbz2", ctypes.c_uint16),
    ]


class _SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", _DWORD)]


class _TOKEN_USER(ctypes.Structure):
    _fields_ = [("User", _SID_AND_ATTRIBUTES)]


class _WIN32_FIND_DATAW(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes", _DWORD),
        ("ftCreationTimeLow", _DWORD),
        ("ftCreationTimeHigh", _DWORD),
        ("ftLastAccessTimeLow", _DWORD),
        ("ftLastAccessTimeHigh", _DWORD),
        ("ftLastWriteTimeLow", _DWORD),
        ("ftLastWriteTimeHigh", _DWORD),
        ("nFileSizeHigh", _DWORD),
        ("nFileSizeLow", _DWORD),
        ("dwReserved0", _DWORD),
        ("dwReserved1", _DWORD),
        ("cFileName", ctypes.c_wchar * 260),
        ("cAlternateFileName", ctypes.c_wchar * 14),
    ]


class NativeWindowsApi:
    """Small, explicitly typed Windows 11 API surface loaded on demand."""

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise PlatformCapabilityUnavailable(
                "native Windows secure-filesystem operations require Windows"
            )
        loader = getattr(ctypes, "WinDLL", None)
        if loader is None:
            raise PlatformCapabilityUnavailable(
                "stdlib ctypes Win32 loading is unavailable"
            )
        try:
            self._kernel32: Any = loader("kernel32", use_last_error=True)
            self._advapi32: Any = loader("advapi32", use_last_error=True)
            self._ntdll: Any = loader("ntdll", use_last_error=True)
            self._configure_signatures()
        except (AttributeError, OSError) as exc:
            raise PlatformCapabilityUnavailable(
                "required Windows secure-filesystem APIs are unavailable"
            ) from exc

    def current_user_sid(self) -> str:
        """Return the canonical SID from the current process token."""

        token = _HANDLE()
        process = self._kernel32.GetCurrentProcess()
        if not self._advapi32.OpenProcessToken(
            process,
            _TOKEN_QUERY,
            ctypes.byref(token),
        ):
            self._raise_last_error("OpenProcessToken")
        try:
            required = _DWORD()
            self._advapi32.GetTokenInformation(
                token,
                _TOKEN_USER_CLASS,
                None,
                0,
                ctypes.byref(required),
            )
            error = _last_error()
            if error != _ERROR_INSUFFICIENT_BUFFER or required.value == 0:
                self._raise_last_error("GetTokenInformation")
            buffer = ctypes.create_string_buffer(required.value)
            if not self._advapi32.GetTokenInformation(
                token,
                _TOKEN_USER_CLASS,
                buffer,
                required,
                ctypes.byref(required),
            ):
                self._raise_last_error("GetTokenInformation")
            token_user = ctypes.cast(buffer, ctypes.POINTER(_TOKEN_USER)).contents
            if not token_user.User.Sid:
                raise WindowsPathSecurityError("Windows process token has no user SID")
            return self._sid_to_string(int(token_user.User.Sid))
        finally:
            self.close_handle(self._handle_value(token))

    def current_token_is_administrator(self) -> bool:
        """Return whether the effective token has Administrators enabled."""

        administrators = ctypes.c_void_p()
        if not self._advapi32.ConvertStringSidToSidW(
            BUILTIN_ADMINISTRATORS_SID,
            ctypes.byref(administrators),
        ):
            self._raise_last_error("ConvertStringSidToSidW")
        try:
            is_member = _BOOL()
            if not self._advapi32.CheckTokenMembership(
                None,
                administrators,
                ctypes.byref(is_member),
            ):
                self._raise_last_error("CheckTokenMembership")
            return bool(is_member.value)
        finally:
            if administrators.value:
                self._kernel32.LocalFree(administrators)

    def volume_information(self, root: str) -> NativeWindowsVolume:
        """Return drive type, ACL support, filesystem, and volume identity."""

        selected = validate_windows_drive_path(root)
        if selected.components:
            raise ValueError("Windows volume query requires a drive root")
        drive_type = int(self._kernel32.GetDriveTypeW(selected.root))
        volume_name = ctypes.create_unicode_buffer(261)
        filesystem_name = ctypes.create_unicode_buffer(261)
        serial = _DWORD()
        maximum_component = _DWORD()
        flags = _DWORD()
        if not self._kernel32.GetVolumeInformationW(
            selected.root,
            volume_name,
            len(volume_name),
            ctypes.byref(serial),
            ctypes.byref(maximum_component),
            ctypes.byref(flags),
            filesystem_name,
            len(filesystem_name),
        ):
            self._raise_last_error("GetVolumeInformationW")
        return NativeWindowsVolume(
            drive_type=drive_type,
            serial_number=int(serial.value),
            filesystem=filesystem_name.value,
            maximum_component_length=int(maximum_component.value),
            filesystem_flags=int(flags.value),
        )

    def open_path(
        self,
        path: str,
        *,
        directory: bool,
        readable: bool,
        writable: bool = False,
    ) -> int:
        """Open a path without following its final reparse point or sharing delete."""

        selected = validate_windows_drive_path(path)
        desired_access = (
            _GENERIC_READ if readable else _READ_CONTROL | _FILE_READ_ATTRIBUTES
        )
        if writable:
            desired_access |= _FILE_WRITE_DATA
        if directory:
            desired_access |= _FILE_TRAVERSE
        raw_handle = self._kernel32.CreateFileW(
            selected.extended,
            desired_access,
            _FILE_SHARE_READ | (_FILE_SHARE_WRITE if directory else 0),
            None,
            _OPEN_EXISTING,
            _FILE_FLAG_BACKUP_SEMANTICS
            | _FILE_FLAG_OPEN_NO_RECALL
            | _FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        handle = self._handle_value(raw_handle)
        if handle == _INVALID_HANDLE_VALUE:
            self._raise_last_error("CreateFileW")
        try:
            if int(self._kernel32.GetFileType(_HANDLE(handle))) != _FILE_TYPE_DISK:
                raise WindowsPathSecurityError(
                    "Windows secure path is not a disk file object"
                )
            if not self._kernel32.SetHandleInformation(
                _HANDLE(handle),
                _HANDLE_FLAG_INHERIT,
                0,
            ):
                self._raise_last_error("SetHandleInformation")
            return handle
        except BaseException:
            self.close_handle(handle)
            raise

    def close_handle(self, handle: int) -> None:
        """Close one owned Win32 handle."""

        if not self._kernel32.CloseHandle(_HANDLE(handle)):
            self._raise_last_error("CloseHandle")

    def duplicate_handle(self, handle: int) -> int:
        """Duplicate one native handle and explicitly remove inheritability."""

        process = self._kernel32.GetCurrentProcess()
        duplicated = _HANDLE()
        if not self._kernel32.DuplicateHandle(
            process,
            _HANDLE(handle),
            process,
            ctypes.byref(duplicated),
            0,
            False,
            _DUPLICATE_SAME_ACCESS,
        ):
            self._raise_last_error("DuplicateHandle")
        value = self._handle_value(duplicated)
        try:
            if not self._kernel32.SetHandleInformation(
                duplicated,
                _HANDLE_FLAG_INHERIT,
                0,
            ):
                self._raise_last_error("SetHandleInformation")
            return value
        except BaseException:
            self.close_handle(value)
            raise

    def file_snapshot(self, handle: int) -> NativeWindowsFileSnapshot:
        """Read attributes, kind, size, volume serial, and 128-bit file ID."""

        if int(self._kernel32.GetFileType(_HANDLE(handle))) != _FILE_TYPE_DISK:
            raise WindowsPathSecurityError(
                "Windows secure path is not a disk file object"
            )
        basic = _FILE_BASIC_INFO()
        standard = _FILE_STANDARD_INFO()
        identity = _FILE_ID_INFO()
        self._get_file_information(handle, _FILE_BASIC_INFO_CLASS, basic)
        self._get_file_information(handle, _FILE_STANDARD_INFO_CLASS, standard)
        self._get_file_information(handle, _FILE_ID_INFO_CLASS, identity)
        return NativeWindowsFileSnapshot(
            attributes=int(basic.FileAttributes),
            is_directory=bool(standard.Directory),
            size=int(standard.EndOfFile),
            volume_serial_number=int(identity.VolumeSerialNumber),
            file_id=bytes(identity.FileId.Identifier),
        )

    def file_security(self, handle: int) -> NativeWindowsSecurity:
        """Copy and parse the handle owner plus exact DACL."""

        owner = ctypes.c_void_p()
        dacl = ctypes.c_void_p()
        descriptor = ctypes.c_void_p()
        result = int(
            self._advapi32.GetSecurityInfo(
                _HANDLE(handle),
                _SE_FILE_OBJECT,
                _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
                ctypes.byref(owner),
                None,
                ctypes.byref(dacl),
                None,
                ctypes.byref(descriptor),
            )
        )
        if result != 0:
            raise OSError(result, "GetSecurityInfo failed")
        try:
            if not owner.value:
                raise WindowsPathSecurityError("Windows file owner SID is missing")
            owner_sid = self._sid_to_string(int(owner.value))
            parsed = self._parse_dacl(int(dacl.value) if dacl.value else None)
            control = ctypes.c_uint16()
            revision = _DWORD()
            if not self._advapi32.GetSecurityDescriptorControl(
                descriptor,
                ctypes.byref(control),
                ctypes.byref(revision),
            ):
                self._raise_last_error("GetSecurityDescriptorControl")
            return NativeWindowsSecurity(
                owner_sid=owner_sid,
                dacl=parsed,
                dacl_protected=bool(control.value & _SE_DACL_PROTECTED),
            )
        finally:
            if descriptor.value:
                self._kernel32.LocalFree(descriptor)

    def directory_is_case_sensitive(self, handle: int) -> bool:
        """Return the per-directory case-sensitive flag, failing if unqueryable."""

        value = _FILE_CASE_SENSITIVE_INFO()
        self._get_file_information(handle, _FILE_CASE_SENSITIVE_INFO_CLASS, value)
        return bool(value.Flags & _FILE_CS_FLAG_CASE_SENSITIVE_DIR)

    def final_path(self, handle: int) -> str:
        """Return the DOS path derived from an already-open handle."""

        required = int(
            self._kernel32.GetFinalPathNameByHandleW(
                _HANDLE(handle),
                None,
                0,
                _VOLUME_NAME_DOS,
            )
        )
        if required <= 0 or required > 32_768:
            self._raise_last_error("GetFinalPathNameByHandleW")
        buffer = ctypes.create_unicode_buffer(required + 1)
        written = int(
            self._kernel32.GetFinalPathNameByHandleW(
                _HANDLE(handle),
                buffer,
                len(buffer),
                _VOLUME_NAME_DOS,
            )
        )
        if written <= 0 or written >= len(buffer):
            self._raise_last_error("GetFinalPathNameByHandleW")
        return buffer.value.removeprefix("\\\\?\\")

    def directory_names(self, path: str) -> tuple[str, ...]:
        """Enumerate an exact directory with a deterministic entry bound."""

        selected = validate_windows_drive_path(path)
        pattern = selected.extended.rstrip("\\") + "\\*"
        data = _WIN32_FIND_DATAW()
        raw_handle = self._kernel32.FindFirstFileW(pattern, ctypes.byref(data))
        handle = self._handle_value(raw_handle)
        if handle == _INVALID_HANDLE_VALUE:
            error = _last_error()
            if error == _ERROR_FILE_NOT_FOUND:
                return ()
            self._raise_last_error("FindFirstFileW")
        names: list[str] = []
        try:
            while True:
                name = str(data.cFileName)
                if name not in {".", ".."}:
                    names.append(name)
                    if len(names) > _MAX_DIRECTORY_ENTRIES:
                        raise WindowsPathSecurityError(
                            "Windows directory exceeds the bounded entry limit"
                        )
                if self._kernel32.FindNextFileW(_HANDLE(handle), ctypes.byref(data)):
                    continue
                error = _last_error()
                if error == _ERROR_NO_MORE_FILES:
                    break
                self._raise_last_error("FindNextFileW")
            return tuple(names)
        finally:
            if not self._kernel32.FindClose(_HANDLE(handle)):
                self._raise_last_error("FindClose")

    def compare_ordinal_ignore_case(self, left: str, right: str) -> int:
        """Compare two names with the Windows non-linguistic uppercase table."""

        if not isinstance(left, str) or not isinstance(right, str):
            raise TypeError("Windows ordinal comparison values must be text")
        if "\0" in left or "\0" in right:
            raise ValueError("Windows ordinal comparison values contain NUL")
        result = int(
            self._kernel32.CompareStringOrdinal(
                left,
                -1,
                right,
                -1,
                True,
            )
        )
        if result == 0:
            self._raise_last_error("CompareStringOrdinal")
        if result not in {_CSTR_LESS_THAN, _CSTR_EQUAL, _CSTR_GREATER_THAN}:
            raise OSError("CompareStringOrdinal returned an invalid result")
        return result - _CSTR_EQUAL

    def rewind_file(self, handle: int) -> None:
        """Set the pinned file pointer to byte zero."""

        observed = ctypes.c_int64()
        if not self._kernel32.SetFilePointerEx(
            _HANDLE(handle),
            ctypes.c_int64(0),
            ctypes.byref(observed),
            _FILE_BEGIN,
        ):
            self._raise_last_error("SetFilePointerEx")
        if observed.value != 0:
            raise OSError("SetFilePointerEx returned a nonzero offset")

    def read_file(self, handle: int, maximum_bytes: int) -> bytes:
        """Read at most one bounded chunk from the current handle position."""

        if not 0 <= maximum_bytes <= 0xFFFFFFFF:
            raise ValueError("Win32 read size is out of range")
        if maximum_bytes == 0:
            return b""
        buffer = ctypes.create_string_buffer(maximum_bytes)
        observed = _DWORD()
        if not self._kernel32.ReadFile(
            _HANDLE(handle),
            buffer,
            maximum_bytes,
            ctypes.byref(observed),
            None,
        ):
            self._raise_last_error("ReadFile")
        if observed.value > maximum_bytes:
            raise OSError("ReadFile returned an invalid byte count")
        return bytes(buffer.raw[: observed.value])

    def create_private_file(
        self,
        parent_handle: int,
        name: str,
        *,
        security_descriptor_sddl: str,
    ) -> int:
        """Create one non-replacement regular file relative to a directory handle."""

        return self._create_private_child(
            parent_handle,
            name,
            security_descriptor_sddl=security_descriptor_sddl,
            directory=False,
        )

    def create_private_directory(
        self,
        parent_handle: int,
        name: str,
        *,
        security_descriptor_sddl: str,
    ) -> int:
        """Create one protected directory relative to a retained parent handle."""

        return self._create_private_child(
            parent_handle,
            name,
            security_descriptor_sddl=security_descriptor_sddl,
            directory=True,
        )

    def _create_private_child(
        self,
        parent_handle: int,
        name: str,
        *,
        security_descriptor_sddl: str,
        directory: bool,
    ) -> int:
        """Create one exact protected child without resolving its parent by name.

        Share access does not grant filesystem access; the explicit protected
        DACL remains authoritative.  All three share modes are required so the
        retained creation handle can survive publication while the backend
        reopens the new name for identity, content, and security verification.
        """

        if not name or "\\" in name or "/" in name or ":" in name or "\x00" in name:
            raise WindowsPathSecurityError("Windows child name is unsafe")
        descriptor = ctypes.c_void_p()
        descriptor_size = _DWORD()
        if not self._advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            security_descriptor_sddl,
            _SDDL_REVISION_1,
            ctypes.byref(descriptor),
            ctypes.byref(descriptor_size),
        ):
            self._raise_last_error(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW"
            )
        try:
            if not descriptor.value or descriptor_size.value == 0:
                raise WindowsPathSecurityError(
                    "Windows creation security descriptor is invalid"
                )
            name_buffer = ctypes.create_unicode_buffer(name)
            name_length = len(name.encode("utf-16-le"))
            if name_length > 0xFFFC:
                raise WindowsPathSecurityError("Windows child file name is too long")
            object_name = _UNICODE_STRING(
                Length=name_length,
                MaximumLength=name_length + 2,
                Buffer=ctypes.cast(name_buffer, ctypes.c_void_p),
            )
            attributes = _OBJECT_ATTRIBUTES(
                Length=ctypes.sizeof(_OBJECT_ATTRIBUTES),
                RootDirectory=_HANDLE(parent_handle),
                ObjectName=ctypes.pointer(object_name),
                Attributes=_OBJ_CASE_INSENSITIVE,
                SecurityDescriptor=descriptor,
                SecurityQualityOfService=None,
            )
            io_status = _IO_STATUS_BLOCK()
            created = _HANDLE()
            status = int(
                self._ntdll.NtCreateFile(
                    ctypes.byref(created),
                    _FILE_READ_DATA
                    | _FILE_WRITE_DATA
                    | _FILE_READ_ATTRIBUTES
                    | _READ_CONTROL
                    | _DELETE
                    | _SYNCHRONIZE,
                    ctypes.byref(attributes),
                    ctypes.byref(io_status),
                    None,
                    0 if directory else _FILE_ATTRIBUTE_NORMAL,
                    _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
                    _FILE_CREATE,
                    (_FILE_DIRECTORY_FILE if directory else _FILE_NON_DIRECTORY_FILE)
                    | _FILE_WRITE_THROUGH
                    | _FILE_SYNCHRONOUS_IO_NONALERT
                    | _FILE_FLAG_OPEN_REPARSE_POINT,
                    None,
                    0,
                )
            )
        finally:
            self._kernel32.LocalFree(descriptor)
        status_code = status & 0xFFFFFFFF
        if status_code != 0:
            if status_code == _STATUS_OBJECT_NAME_COLLISION:
                raise FileExistsError(
                    errno.EEXIST,
                    "Windows child already exists",
                )
            error = int(self._ntdll.RtlNtStatusToDosError(ctypes.c_long(status)))
            raise OSError(error, "NtCreateFile failed")
        handle = self._handle_value(created)
        try:
            if handle <= 0:
                raise WindowsPathSecurityError(
                    "NtCreateFile returned an invalid Windows handle"
                )
            if int(self._kernel32.GetFileType(created)) != _FILE_TYPE_DISK:
                raise WindowsPathSecurityError(
                    "created Windows object is not a disk filesystem object"
                )
            if not self._kernel32.SetHandleInformation(
                created,
                _HANDLE_FLAG_INHERIT,
                0,
            ):
                self._raise_last_error("SetHandleInformation")
            return handle
        except BaseException:
            cleanup_error: OSError | None = None
            try:
                self.set_delete_on_close(handle, enabled=True)
            except OSError as exc:
                cleanup_error = exc
            try:
                self.close_handle(handle)
            except OSError as exc:
                if cleanup_error is None:
                    cleanup_error = exc
            if cleanup_error is not None:
                raise WindowsPathSecurityError(
                    "created Windows child cleanup failed"
                ) from cleanup_error
            raise

    def replace_file(
        self,
        source_handle: int,
        parent_handle: int,
        destination_name: str,
        *,
        replace_existing: bool,
    ) -> None:
        """Replace one child using the source and destination-parent handles.

        Windows 11 ``FileRenameInfoEx`` POSIX semantics keep an already-open
        validated destination handle usable while atomically rebinding its
        public name to the prepared source handle. Create-only publication
        omits ``REPLACE_IF_EXISTS`` so a raced destination fails atomically.
        """

        if not isinstance(replace_existing, bool):
            raise TypeError("Windows replacement mode must be a boolean")
        if (
            not destination_name
            or "\\" in destination_name
            or "/" in destination_name
            or ":" in destination_name
            or "\x00" in destination_name
        ):
            raise WindowsPathSecurityError("Windows replacement name is unsafe")
        encoded = destination_name.encode("utf-16-le", errors="strict")
        if not encoded or len(encoded) > 0xFFFC:
            raise WindowsPathSecurityError("Windows replacement name is too long")
        file_name_offset = _FILE_RENAME_INFO_EX.FileName.offset
        size = max(
            ctypes.sizeof(_FILE_RENAME_INFO_EX),
            file_name_offset + len(encoded),
        )
        buffer = ctypes.create_string_buffer(size)
        information = ctypes.cast(
            buffer,
            ctypes.POINTER(_FILE_RENAME_INFO_EX),
        ).contents
        information.Flags = _FILE_RENAME_POSIX_SEMANTICS | (
            _FILE_RENAME_REPLACE_IF_EXISTS if replace_existing else 0
        )
        information.RootDirectory = _HANDLE(parent_handle)
        information.FileNameLength = len(encoded)
        ctypes.memmove(
            ctypes.addressof(buffer) + file_name_offset, encoded, len(encoded)
        )
        if not self._kernel32.SetFileInformationByHandle(
            _HANDLE(source_handle),
            _FILE_RENAME_INFO_EX_CLASS,
            buffer,
            size,
        ):
            self._raise_last_error("SetFileInformationByHandle")

    def flush_directory(self, handle: int) -> None:
        """Synchronously flush one retained directory file object."""

        io_status = _IO_STATUS_BLOCK()
        status = int(
            self._ntdll.NtFlushBuffersFile(
                _HANDLE(handle),
                ctypes.byref(io_status),
            )
        )
        if status & 0xFFFFFFFF:
            error = int(self._ntdll.RtlNtStatusToDosError(ctypes.c_long(status)))
            raise OSError(error, "NtFlushBuffersFile failed")

    def write_file(self, handle: int, payload: bytes) -> int:
        """Write at most one caller-bounded chunk at the current file offset."""

        if not isinstance(payload, bytes):
            raise TypeError("Win32 write payload must be bytes")
        if len(payload) > 0xFFFFFFFF:
            raise ValueError("Win32 write size is out of range")
        if not payload:
            return 0
        buffer = ctypes.create_string_buffer(payload)
        observed = _DWORD()
        if not self._kernel32.WriteFile(
            _HANDLE(handle),
            buffer,
            len(payload),
            ctypes.byref(observed),
            None,
        ):
            self._raise_last_error("WriteFile")
        if observed.value > len(payload):
            raise OSError("WriteFile returned an invalid byte count")
        return int(observed.value)

    def flush_file(self, handle: int) -> None:
        """Flush one created file through the native storage boundary."""

        if not self._kernel32.FlushFileBuffers(_HANDLE(handle)):
            self._raise_last_error("FlushFileBuffers")

    def set_delete_on_close(self, handle: int, *, enabled: bool) -> None:
        """Set exact-handle cleanup state for a just-created file."""

        if not isinstance(enabled, bool):
            raise TypeError("Windows delete-on-close flag must be a boolean")
        disposition = _FILE_DISPOSITION_INFO(DeleteFile=int(enabled))
        if not self._kernel32.SetFileInformationByHandle(
            _HANDLE(handle),
            _FILE_DISPOSITION_INFO_CLASS,
            ctypes.byref(disposition),
            ctypes.sizeof(disposition),
        ):
            self._raise_last_error("SetFileInformationByHandle")

    def _get_file_information(
        self,
        handle: int,
        information_class: int,
        destination: ctypes.Structure,
    ) -> None:
        if not self._kernel32.GetFileInformationByHandleEx(
            _HANDLE(handle),
            information_class,
            ctypes.byref(destination),
            ctypes.sizeof(destination),
        ):
            self._raise_last_error("GetFileInformationByHandleEx")

    def _parse_dacl(self, address: int | None) -> WindowsDacl:
        if address is None:
            return WindowsDacl(raw=None, valid=False, allow_aces=())
        pointer = ctypes.c_void_p(address)
        if not self._advapi32.IsValidAcl(pointer):
            return WindowsDacl(raw=b"", valid=False, allow_aces=())
        header = _ACL.from_address(address)
        acl_size = int(header.AclSize)
        if acl_size < ctypes.sizeof(_ACL) or acl_size > 0xFFFF:
            return WindowsDacl(raw=b"", valid=False, allow_aces=())
        raw = bytes(ctypes.string_at(address, acl_size))
        allow_aces: list[WindowsAccessAllowedAce] = []
        for index in range(int(header.AceCount)):
            ace_pointer = ctypes.c_void_p()
            if not self._advapi32.GetAce(pointer, index, ctypes.byref(ace_pointer)):
                return WindowsDacl(raw=raw, valid=False, allow_aces=())
            if not ace_pointer.value:
                return WindowsDacl(raw=raw, valid=False, allow_aces=())
            parsed = self._parse_allow_ace(int(ace_pointer.value))
            if parsed is not None:
                allow_aces.append(parsed)
        return WindowsDacl(raw=raw, valid=True, allow_aces=tuple(allow_aces))

    def _parse_allow_ace(self, address: int) -> WindowsAccessAllowedAce | None:
        header = bytes(ctypes.string_at(address, 4))
        ace_type, flags, ace_size = parse_windows_ace_header(header)
        if not windows_ace_type_is_supported_allow(ace_type):
            return None
        raw = bytes(ctypes.string_at(address, ace_size))
        mask = int.from_bytes(raw[4:8], "little")
        if ace_type == _OBJECT_ALLOW_ACE_TYPE:
            if ace_size < 12:
                raise WindowsPathSecurityError(
                    "Windows DACL contains an invalid object ACE"
                )
            object_flags = int.from_bytes(raw[8:12], "little")
            if object_flags & ~(
                _ACE_OBJECT_TYPE_PRESENT | _ACE_INHERITED_OBJECT_TYPE_PRESENT
            ):
                raise WindowsPathSecurityError(
                    "Windows DACL contains unsupported object ACE flags"
                )
            sid_offset = 12
            if object_flags & _ACE_OBJECT_TYPE_PRESENT:
                sid_offset += 16
            if object_flags & _ACE_INHERITED_OBJECT_TYPE_PRESENT:
                sid_offset += 16
        else:
            sid_offset = 8
        expected_sid_length = windows_ace_sid_length(raw, sid_offset=sid_offset)
        sid_address = address + sid_offset
        if not self._advapi32.IsValidSid(ctypes.c_void_p(sid_address)):
            raise WindowsPathSecurityError("Windows DACL contains an invalid SID")
        sid_length = int(self._advapi32.GetLengthSid(ctypes.c_void_p(sid_address)))
        if sid_length != expected_sid_length:
            raise WindowsPathSecurityError("Windows DACL contains an invalid SID")
        return WindowsAccessAllowedAce(
            sid=self._sid_to_string(sid_address),
            access_mask=mask,
            flags=flags,
            ace_type=ace_type,
        )

    def _sid_to_string(self, address: int) -> str:
        if not self._advapi32.IsValidSid(ctypes.c_void_p(address)):
            raise WindowsPathSecurityError("Windows SID is invalid")
        output = ctypes.c_void_p()
        if not self._advapi32.ConvertSidToStringSidW(
            ctypes.c_void_p(address),
            ctypes.byref(output),
        ):
            self._raise_last_error("ConvertSidToStringSidW")
        try:
            if not output.value:
                raise WindowsPathSecurityError("Windows SID conversion failed")
            return ctypes.wstring_at(output.value)
        finally:
            if output.value:
                self._kernel32.LocalFree(output)

    @staticmethod
    def _handle_value(value: object) -> int:
        if isinstance(value, int):
            return value
        observed = getattr(value, "value", None)
        if isinstance(observed, int):
            return observed
        if observed is None:
            return 0
        raise OSError("Win32 API returned an invalid handle")

    @staticmethod
    def _raise_last_error(operation: str) -> None:
        error = _last_error()
        if error == 0:
            raise OSError(f"{operation} failed")
        raise OSError(error, f"{operation} failed")

    def _configure_signatures(self) -> None:
        self._kernel32.GetCurrentProcess.argtypes = []
        self._kernel32.GetCurrentProcess.restype = _HANDLE
        self._kernel32.CreateFileW.argtypes = [
            ctypes.c_wchar_p,
            _DWORD,
            _DWORD,
            ctypes.c_void_p,
            _DWORD,
            _DWORD,
            _HANDLE,
        ]
        self._kernel32.CreateFileW.restype = _HANDLE
        self._kernel32.CloseHandle.argtypes = [_HANDLE]
        self._kernel32.CloseHandle.restype = _BOOL
        self._kernel32.DuplicateHandle.argtypes = [
            _HANDLE,
            _HANDLE,
            _HANDLE,
            ctypes.POINTER(_HANDLE),
            _DWORD,
            _BOOL,
            _DWORD,
        ]
        self._kernel32.DuplicateHandle.restype = _BOOL
        self._kernel32.SetHandleInformation.argtypes = [_HANDLE, _DWORD, _DWORD]
        self._kernel32.SetHandleInformation.restype = _BOOL
        self._kernel32.GetFileType.argtypes = [_HANDLE]
        self._kernel32.GetFileType.restype = _DWORD
        self._kernel32.GetFileInformationByHandleEx.argtypes = [
            _HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            _DWORD,
        ]
        self._kernel32.GetFileInformationByHandleEx.restype = _BOOL
        self._kernel32.GetFinalPathNameByHandleW.argtypes = [
            _HANDLE,
            ctypes.c_void_p,
            _DWORD,
            _DWORD,
        ]
        self._kernel32.GetFinalPathNameByHandleW.restype = _DWORD
        self._kernel32.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
        self._kernel32.GetDriveTypeW.restype = _DWORD
        self._kernel32.GetVolumeInformationW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_void_p,
            _DWORD,
            ctypes.POINTER(_DWORD),
            ctypes.POINTER(_DWORD),
            ctypes.POINTER(_DWORD),
            ctypes.c_void_p,
            _DWORD,
        ]
        self._kernel32.GetVolumeInformationW.restype = _BOOL
        self._kernel32.FindFirstFileW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.POINTER(_WIN32_FIND_DATAW),
        ]
        self._kernel32.FindFirstFileW.restype = _HANDLE
        self._kernel32.FindNextFileW.argtypes = [
            _HANDLE,
            ctypes.POINTER(_WIN32_FIND_DATAW),
        ]
        self._kernel32.FindNextFileW.restype = _BOOL
        self._kernel32.FindClose.argtypes = [_HANDLE]
        self._kernel32.FindClose.restype = _BOOL
        self._kernel32.CompareStringOrdinal.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_int,
            ctypes.c_wchar_p,
            ctypes.c_int,
            _BOOL,
        ]
        self._kernel32.CompareStringOrdinal.restype = ctypes.c_int
        self._kernel32.SetFilePointerEx.argtypes = [
            _HANDLE,
            ctypes.c_int64,
            ctypes.POINTER(ctypes.c_int64),
            _DWORD,
        ]
        self._kernel32.SetFilePointerEx.restype = _BOOL
        self._kernel32.ReadFile.argtypes = [
            _HANDLE,
            ctypes.c_void_p,
            _DWORD,
            ctypes.POINTER(_DWORD),
            ctypes.c_void_p,
        ]
        self._kernel32.ReadFile.restype = _BOOL
        self._kernel32.WriteFile.argtypes = [
            _HANDLE,
            ctypes.c_void_p,
            _DWORD,
            ctypes.POINTER(_DWORD),
            ctypes.c_void_p,
        ]
        self._kernel32.WriteFile.restype = _BOOL
        self._kernel32.FlushFileBuffers.argtypes = [_HANDLE]
        self._kernel32.FlushFileBuffers.restype = _BOOL
        self._kernel32.SetFileInformationByHandle.argtypes = [
            _HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            _DWORD,
        ]
        self._kernel32.SetFileInformationByHandle.restype = _BOOL
        self._kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        self._kernel32.LocalFree.restype = ctypes.c_void_p

        self._advapi32.OpenProcessToken.argtypes = [
            _HANDLE,
            _DWORD,
            ctypes.POINTER(_HANDLE),
        ]
        self._advapi32.OpenProcessToken.restype = _BOOL
        self._advapi32.CheckTokenMembership.argtypes = [
            _HANDLE,
            ctypes.c_void_p,
            ctypes.POINTER(_BOOL),
        ]
        self._advapi32.CheckTokenMembership.restype = _BOOL
        self._advapi32.ConvertStringSidToSidW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self._advapi32.ConvertStringSidToSidW.restype = _BOOL
        self._advapi32.GetTokenInformation.argtypes = [
            _HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            _DWORD,
            ctypes.POINTER(_DWORD),
        ]
        self._advapi32.GetTokenInformation.restype = _BOOL
        self._advapi32.GetSecurityInfo.argtypes = [
            _HANDLE,
            ctypes.c_int,
            _DWORD,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self._advapi32.GetSecurityInfo.restype = _DWORD
        self._advapi32.IsValidAcl.argtypes = [ctypes.c_void_p]
        self._advapi32.IsValidAcl.restype = _BOOL
        self._advapi32.GetAce.argtypes = [
            ctypes.c_void_p,
            _DWORD,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self._advapi32.GetAce.restype = _BOOL
        self._advapi32.IsValidSid.argtypes = [ctypes.c_void_p]
        self._advapi32.IsValidSid.restype = _BOOL
        self._advapi32.GetLengthSid.argtypes = [ctypes.c_void_p]
        self._advapi32.GetLengthSid.restype = _DWORD
        self._advapi32.ConvertSidToStringSidW.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self._advapi32.ConvertSidToStringSidW.restype = _BOOL
        self._advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            ctypes.c_wchar_p,
            _DWORD,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(_DWORD),
        ]
        self._advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = (
            _BOOL
        )
        self._advapi32.GetSecurityDescriptorControl.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint16),
            ctypes.POINTER(_DWORD),
        ]
        self._advapi32.GetSecurityDescriptorControl.restype = _BOOL

        self._ntdll.NtCreateFile.argtypes = [
            ctypes.POINTER(_HANDLE),
            _DWORD,
            ctypes.POINTER(_OBJECT_ATTRIBUTES),
            ctypes.POINTER(_IO_STATUS_BLOCK),
            ctypes.c_void_p,
            _DWORD,
            _DWORD,
            _DWORD,
            _DWORD,
            ctypes.c_void_p,
            _DWORD,
        ]
        self._ntdll.NtCreateFile.restype = ctypes.c_long
        self._ntdll.NtFlushBuffersFile.argtypes = [
            _HANDLE,
            ctypes.POINTER(_IO_STATUS_BLOCK),
        ]
        self._ntdll.NtFlushBuffersFile.restype = ctypes.c_long
        self._ntdll.RtlNtStatusToDosError.argtypes = [ctypes.c_long]
        self._ntdll.RtlNtStatusToDosError.restype = _DWORD


def _last_error() -> int:
    getter = getattr(ctypes, "get_last_error", None)
    if getter is None:
        return 0
    return int(getter())

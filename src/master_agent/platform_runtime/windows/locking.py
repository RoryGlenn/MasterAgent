"""Native Windows whole-file cross-process locking with ``LockFileEx``."""

from __future__ import annotations

import ctypes
import errno
import sys
import threading
from typing import Any, Protocol

from master_agent.platform_runtime.contracts import (
    LockMode,
    PlatformCapabilityUnavailable,
)

WINDOWS_LOCKING_BACKEND_ID = "windows-lockfileex"

_LOCKFILE_FAIL_IMMEDIATELY = 0x00000001
_LOCKFILE_EXCLUSIVE_LOCK = 0x00000002
_ERROR_LOCK_VIOLATION = 33
_ERROR_LOCK_FAILED = 167
_FILE_MODE_INFORMATION_CLASS = 16
_FILE_SYNCHRONOUS_IO_ALERT = 0x00000010
_FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020


class _OVERLAPPED(ctypes.Structure):
    _fields_ = [
        ("Internal", ctypes.c_size_t),
        ("InternalHigh", ctypes.c_size_t),
        ("Offset", ctypes.c_uint32),
        ("OffsetHigh", ctypes.c_uint32),
        ("hEvent", ctypes.c_void_p),
    ]


class _IO_STATUS_BLOCK(ctypes.Structure):
    _fields_ = [
        ("Status", ctypes.c_void_p),
        ("Information", ctypes.c_size_t),
    ]


class _FILE_MODE_INFORMATION(ctypes.Structure):
    _fields_ = [("Mode", ctypes.c_uint32)]


class _WindowsLockApi(Protocol):
    def acquire(
        self,
        descriptor: int,
        *,
        exclusive: bool,
        blocking: bool,
    ) -> int | None: ...

    def release(self, descriptor: int) -> None: ...

    def acquire_handle(
        self,
        handle: int,
        *,
        exclusive: bool,
        blocking: bool,
    ) -> int | None: ...

    def release_handle(self, handle: int) -> None: ...


class WindowsCrossProcessLockingBackend:
    """Shared/exclusive whole-file locks for Windows CRT descriptors."""

    backend_id = WINDOWS_LOCKING_BACKEND_ID

    def __init__(self, *, _api: _WindowsLockApi | None = None) -> None:
        self._injected_api = _api
        self._selected_api: _WindowsLockApi | None = None
        self._api_lock = threading.Lock()

    def acquire(
        self,
        descriptor: int,
        *,
        mode: LockMode,
        blocking: bool = True,
    ) -> None:
        """Acquire a whole-file shared or exclusive native lock."""

        _validate_descriptor(descriptor)
        if mode is LockMode.EXCLUSIVE:
            exclusive = True
        elif mode is LockMode.SHARED:
            exclusive = False
        else:
            raise ValueError("cross-process lock mode is invalid")
        if not isinstance(blocking, bool):
            raise TypeError("cross-process lock blocking flag must be a boolean")
        error = self._native_api().acquire(
            descriptor,
            exclusive=exclusive,
            blocking=blocking,
        )
        if error is not None:
            if not blocking and error == _ERROR_LOCK_VIOLATION:
                raise BlockingIOError(
                    errno.EWOULDBLOCK,
                    "cross-process lock is already held",
                )
            raise OSError(error, "LockFileEx failed")

    def release(self, descriptor: int) -> None:
        """Release the whole-file range from byte zero."""

        _validate_descriptor(descriptor)
        self._native_api().release(descriptor)

    def acquire_handle(
        self,
        handle: int,
        *,
        mode: LockMode,
        blocking: bool = True,
    ) -> None:
        """Acquire a whole-file lock on an already validated native handle."""

        _validate_native_handle(handle)
        if mode is LockMode.EXCLUSIVE:
            exclusive = True
        elif mode is LockMode.SHARED:
            exclusive = False
        else:
            raise ValueError("cross-process lock mode is invalid")
        if not isinstance(blocking, bool):
            raise TypeError("cross-process lock blocking flag must be a boolean")
        error = self._native_api().acquire_handle(
            handle,
            exclusive=exclusive,
            blocking=blocking,
        )
        if error is not None:
            if not blocking and error == _ERROR_LOCK_VIOLATION:
                raise BlockingIOError(
                    errno.EWOULDBLOCK,
                    "cross-process lock is already held",
                )
            raise OSError(error, "LockFileEx failed")

    def release_handle(self, handle: int) -> None:
        """Release a whole-file lock from an already validated native handle."""

        _validate_native_handle(handle)
        self._native_api().release_handle(handle)

    def _native_api(self) -> _WindowsLockApi:
        with self._api_lock:
            if self._selected_api is None:
                if self._injected_api is not None:
                    self._selected_api = self._injected_api
                else:
                    self._selected_api = _NativeWindowsLockApi()
            return self._selected_api


class _NativeWindowsLockApi:
    """Lazy ``msvcrt`` and ``kernel32`` bridge."""

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise PlatformCapabilityUnavailable(
                "native Windows cross-process locking requires Windows"
            )
        loader = getattr(ctypes, "WinDLL", None)
        if loader is None:
            raise PlatformCapabilityUnavailable(
                "stdlib ctypes Win32 loading is unavailable"
            )
        try:
            import msvcrt

            self._msvcrt: Any = msvcrt
            self._kernel32: Any = loader("kernel32", use_last_error=True)
            self._ntdll: Any = loader("ntdll", use_last_error=True)
            self._kernel32.LockFileEx.argtypes = [
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.POINTER(_OVERLAPPED),
            ]
            self._kernel32.LockFileEx.restype = ctypes.c_int32
            self._kernel32.UnlockFileEx.argtypes = [
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.POINTER(_OVERLAPPED),
            ]
            self._kernel32.UnlockFileEx.restype = ctypes.c_int32
            self._ntdll.NtQueryInformationFile.argtypes = [
                ctypes.c_void_p,
                ctypes.POINTER(_IO_STATUS_BLOCK),
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.c_int,
            ]
            self._ntdll.NtQueryInformationFile.restype = ctypes.c_long
            self._ntdll.RtlNtStatusToDosError.argtypes = [ctypes.c_long]
            self._ntdll.RtlNtStatusToDosError.restype = ctypes.c_uint32
        except (AttributeError, ImportError, OSError) as exc:
            raise PlatformCapabilityUnavailable(
                "required Windows cross-process locking APIs are unavailable"
            ) from exc

    def acquire(
        self,
        descriptor: int,
        *,
        exclusive: bool,
        blocking: bool,
    ) -> int | None:
        handle = self._handle_for_descriptor(descriptor)
        return self.acquire_handle(
            handle,
            exclusive=exclusive,
            blocking=blocking,
        )

    def acquire_handle(
        self,
        handle: int,
        *,
        exclusive: bool,
        blocking: bool,
    ) -> int | None:
        """Lock the complete range of one synchronous native file handle."""

        self._require_synchronous(handle)
        flags = _LOCKFILE_EXCLUSIVE_LOCK if exclusive else 0
        if not blocking:
            flags |= _LOCKFILE_FAIL_IMMEDIATELY
        overlapped = _OVERLAPPED()
        if self._kernel32.LockFileEx(
            ctypes.c_void_p(handle),
            flags,
            0,
            0xFFFFFFFF,
            0xFFFFFFFF,
            ctypes.byref(overlapped),
        ):
            return None
        error = _last_error()
        return error or _ERROR_LOCK_FAILED

    def release(self, descriptor: int) -> None:
        handle = self._handle_for_descriptor(descriptor)
        self.release_handle(handle)

    def release_handle(self, handle: int) -> None:
        """Unlock the complete range of one native file handle."""

        overlapped = _OVERLAPPED()
        if not self._kernel32.UnlockFileEx(
            ctypes.c_void_p(handle),
            0,
            0xFFFFFFFF,
            0xFFFFFFFF,
            ctypes.byref(overlapped),
        ):
            error = _last_error()
            raise OSError(error or _ERROR_LOCK_FAILED, "UnlockFileEx failed")

    def _handle_for_descriptor(self, descriptor: int) -> int:
        try:
            handle = int(self._msvcrt.get_osfhandle(descriptor))
        except OSError:
            raise
        except (TypeError, ValueError) as exc:
            raise OSError(errno.EBADF, "Windows CRT descriptor is invalid") from exc
        if handle == -1:
            raise OSError(errno.EBADF, "Windows CRT descriptor is invalid")
        return handle

    def _require_synchronous(self, handle: int) -> None:
        io_status = _IO_STATUS_BLOCK()
        mode = _FILE_MODE_INFORMATION()
        status = int(
            self._ntdll.NtQueryInformationFile(
                ctypes.c_void_p(handle),
                ctypes.byref(io_status),
                ctypes.byref(mode),
                ctypes.sizeof(mode),
                _FILE_MODE_INFORMATION_CLASS,
            )
        )
        if status & 0xFFFFFFFF:
            error = int(self._ntdll.RtlNtStatusToDosError(ctypes.c_long(status)))
            raise OSError(error, "NtQueryInformationFile failed")
        if not mode.Mode & (_FILE_SYNCHRONOUS_IO_ALERT | _FILE_SYNCHRONOUS_IO_NONALERT):
            raise OSError(
                errno.EINVAL,
                "LockFileEx requires a synchronous Windows CRT descriptor",
            )


def _validate_descriptor(descriptor: int) -> None:
    if isinstance(descriptor, bool) or not isinstance(descriptor, int):
        raise TypeError("Windows CRT descriptor must be an integer")
    if descriptor < 0:
        raise ValueError("Windows CRT descriptor is invalid")


def _validate_native_handle(handle: int) -> None:
    if isinstance(handle, bool) or not isinstance(handle, int):
        raise TypeError("Windows native handle must be an integer")
    if handle <= 0:
        raise ValueError("Windows native handle is invalid")


def _last_error() -> int:
    getter = getattr(ctypes, "get_last_error", None)
    if getter is None:
        return 0
    return int(getter())


def probe_windows_locking_backend() -> None:
    """Fail closed unless CRT-handle and ``LockFileEx`` symbols load."""

    _NativeWindowsLockApi()

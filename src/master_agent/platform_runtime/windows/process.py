"""Native Windows process supervision with Job Objects and bounded pipes."""

from __future__ import annotations

import ctypes
import os
import sys
import threading
from collections.abc import Mapping, Sequence
from ctypes import wintypes
from pathlib import Path
from typing import Any, Final, Protocol

from master_agent.platform_runtime.contracts import (
    PlatformCapabilityUnavailable,
    ProcessExecutionResult,
    ProcessExitReason,
    ProcessSupervisionError,
)

WINDOWS_PROCESS_BACKEND_ID: Final = "windows-job-object"

_CREATE_SUSPENDED = 0x00000004
_CREATE_NO_WINDOW = 0x08000000
_CREATE_UNICODE_ENVIRONMENT = 0x00000400
_EXTENDED_STARTUPINFO_PRESENT = 0x00080000
_STARTF_USESTDHANDLES = 0x00000100
_PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002
_PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
_HANDLE_FLAG_INHERIT = 0x00000001
_GENERIC_READ = 0x80000000
_FILE_SHARE_READ = 0x00000001
_FILE_SHARE_WRITE = 0x00000002
_OPEN_EXISTING = 3
_FILE_ATTRIBUTE_NORMAL = 0x00000080
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_JOB_OBJECT_LIMIT_PROCESS_TIME = 0x00000002
_JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
_JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
_JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
_JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000

_WAIT_OBJECT_0 = 0
_WAIT_TIMEOUT = 258
_STILL_ACTIVE = 259
_ERROR_BROKEN_PIPE = 109
_ERROR_INSUFFICIENT_BUFFER = 122
_TIMEOUT_EXIT_CODE = 0x4D41544F
_MAX_ARGUMENTS = 256
_MAX_ARGUMENT_BYTES = 256 * 1024
_MAX_ENVIRONMENT_ENTRIES = 128
_MAX_ENVIRONMENT_BYTES = 256 * 1024


class _SecurityAttributes(ctypes.Structure):
    _fields_ = (
        ("length", wintypes.DWORD),
        ("security_descriptor", ctypes.c_void_p),
        ("inherit_handle", wintypes.BOOL),
    )


class _StartupInfoW(ctypes.Structure):
    _fields_ = (
        ("cb", wintypes.DWORD),
        ("reserved", wintypes.LPWSTR),
        ("desktop", wintypes.LPWSTR),
        ("title", wintypes.LPWSTR),
        ("x", wintypes.DWORD),
        ("y", wintypes.DWORD),
        ("x_size", wintypes.DWORD),
        ("y_size", wintypes.DWORD),
        ("x_count_chars", wintypes.DWORD),
        ("y_count_chars", wintypes.DWORD),
        ("fill_attribute", wintypes.DWORD),
        ("flags", wintypes.DWORD),
        ("show_window", wintypes.WORD),
        ("reserved2_size", wintypes.WORD),
        ("reserved2", ctypes.POINTER(ctypes.c_ubyte)),
        ("stdin", wintypes.HANDLE),
        ("stdout", wintypes.HANDLE),
        ("stderr", wintypes.HANDLE),
    )


class _StartupInfoExW(ctypes.Structure):
    _fields_ = (
        ("startup_info", _StartupInfoW),
        ("attribute_list", ctypes.c_void_p),
    )


class _ProcessInformation(ctypes.Structure):
    _fields_ = (
        ("process", wintypes.HANDLE),
        ("thread", wintypes.HANDLE),
        ("process_id", wintypes.DWORD),
        ("thread_id", wintypes.DWORD),
    )


class _SecurityCapabilities(ctypes.Structure):
    _fields_ = (
        ("app_container_sid", ctypes.c_void_p),
        ("capabilities", ctypes.c_void_p),
        ("capability_count", wintypes.DWORD),
        ("reserved", wintypes.DWORD),
    )


class _IoCounters(ctypes.Structure):
    _fields_ = tuple(
        (name, ctypes.c_ulonglong)
        for name in (
            "read_operation_count",
            "write_operation_count",
            "other_operation_count",
            "read_transfer_count",
            "write_transfer_count",
            "other_transfer_count",
        )
    )


class _BasicLimitInformation(ctypes.Structure):
    _fields_ = (
        ("per_process_user_time_limit", ctypes.c_longlong),
        ("per_job_user_time_limit", ctypes.c_longlong),
        ("limit_flags", wintypes.DWORD),
        ("minimum_working_set_size", ctypes.c_size_t),
        ("maximum_working_set_size", ctypes.c_size_t),
        ("active_process_limit", wintypes.DWORD),
        ("affinity", ctypes.c_size_t),
        ("priority_class", wintypes.DWORD),
        ("scheduling_class", wintypes.DWORD),
    )


class _ExtendedLimitInformation(ctypes.Structure):
    _fields_ = (
        ("basic_limit_information", _BasicLimitInformation),
        ("io_info", _IoCounters),
        ("process_memory_limit", ctypes.c_size_t),
        ("job_memory_limit", ctypes.c_size_t),
        ("peak_process_memory_used", ctypes.c_size_t),
        ("peak_job_memory_used", ctypes.c_size_t),
    )


class WindowsProcessApi(Protocol):
    """Injectable native boundary used by the Windows process backend."""

    def probe(self) -> None:
        """Verify required Win32 process and Job Object APIs."""

    def windows_directory(self) -> str:
        """Return the native Windows directory without reading caller env."""

    def run(
        self,
        *,
        executable: Path,
        arguments: tuple[str, ...],
        cwd: Path,
        environment: Mapping[str, str],
        inherited_handles: tuple[int, ...],
        timeout_seconds: float,
        cpu_seconds: int,
        memory_bytes: int,
        max_processes: int,
        max_output_bytes: int,
    ) -> ProcessExecutionResult:
        """Run one fixed command under a native Job Object."""


class WindowsProcessSupervisionBackend:
    """Launch fixed commands suspended and supervise their complete job tree."""

    backend_id = WINDOWS_PROCESS_BACKEND_ID

    def __init__(self, *, api: WindowsProcessApi | None = None) -> None:
        self._api = api

    def apply_capsule_limits(
        self,
        *,
        cpu_seconds: int,
        memory_bytes: int,
        max_processes: int,
        max_output_bytes: int,
    ) -> None:
        """Reject unsafe after-launch attachment; Windows limits require ``run``."""

        _validate_positive_limits(
            cpu_seconds=cpu_seconds,
            memory_bytes=memory_bytes,
            max_processes=max_processes,
            max_output_bytes=max_output_bytes,
        )
        raise ProcessSupervisionError("supervised_launch_required")

    def run(
        self,
        *,
        executable: Path,
        arguments: Sequence[str],
        cwd: Path,
        environment: Mapping[str, str],
        inherited_handles: Sequence[int] = (),
        timeout_seconds: float,
        cpu_seconds: int,
        memory_bytes: int,
        max_processes: int,
        max_output_bytes: int,
    ) -> ProcessExecutionResult:
        """Run one explicit executable with bounded environment, output, and tree."""

        api = self._native_api()
        parsed_arguments = _validate_arguments(arguments)
        parsed_handles = _validate_handles(inherited_handles)
        _validate_path(executable, name="executable")
        _validate_path(cwd, name="working directory")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or timeout_seconds <= 0
            or timeout_seconds > 86_400
        ):
            raise ValueError("process timeout is invalid")
        _validate_positive_limits(
            cpu_seconds=cpu_seconds,
            memory_bytes=memory_bytes,
            max_processes=max_processes,
            max_output_bytes=max_output_bytes,
        )
        minimal_environment = _build_minimal_environment(
            environment,
            windows_directory=api.windows_directory(),
        )
        try:
            return api.run(
                executable=executable,
                arguments=parsed_arguments,
                cwd=cwd,
                environment=minimal_environment,
                inherited_handles=parsed_handles,
                timeout_seconds=float(timeout_seconds),
                cpu_seconds=cpu_seconds,
                memory_bytes=memory_bytes,
                max_processes=max_processes,
                max_output_bytes=max_output_bytes,
            )
        except ProcessSupervisionError:
            raise
        except (OSError, ValueError) as error:
            raise ProcessSupervisionError("native_control_failed") from error

    def _native_api(self) -> WindowsProcessApi:
        if self._api is None:
            self._api = CtypesWindowsProcessApi()
        return self._api


class CtypesWindowsProcessApi:
    """Direct Win32 process, pipe, and Job Object bindings."""

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise PlatformCapabilityUnavailable(
                "native Windows process supervision requires Windows"
            )
        loader = getattr(ctypes, "WinDLL", None)
        if loader is None:
            raise PlatformCapabilityUnavailable(
                "stdlib ctypes Win32 loading is unavailable"
            )
        try:
            self._kernel: Any = loader("kernel32", use_last_error=True)
            self._bind_functions()
        except (AttributeError, OSError) as error:
            raise PlatformCapabilityUnavailable(
                "required Windows process APIs are unavailable"
            ) from error

    def _bind_functions(self) -> None:
        kernel = self._kernel
        kernel.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
        kernel.CreateJobObjectW.restype = wintypes.HANDLE
        kernel.SetInformationJobObject.argtypes = (
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        )
        kernel.SetInformationJobObject.restype = wintypes.BOOL
        kernel.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
        kernel.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
        kernel.TerminateJobObject.restype = wintypes.BOOL
        kernel.TerminateProcess.argtypes = (wintypes.HANDLE, wintypes.UINT)
        kernel.TerminateProcess.restype = wintypes.BOOL
        kernel.CreatePipe.argtypes = (
            ctypes.POINTER(wintypes.HANDLE),
            ctypes.POINTER(wintypes.HANDLE),
            ctypes.POINTER(_SecurityAttributes),
            wintypes.DWORD,
        )
        kernel.CreatePipe.restype = wintypes.BOOL
        kernel.SetHandleInformation.argtypes = (
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.DWORD,
        )
        kernel.SetHandleInformation.restype = wintypes.BOOL
        kernel.GetHandleInformation.argtypes = (
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.DWORD),
        )
        kernel.GetHandleInformation.restype = wintypes.BOOL
        kernel.CreateFileW.argtypes = (
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(_SecurityAttributes),
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        )
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.InitializeProcThreadAttributeList.argtypes = (
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_size_t),
        )
        kernel.InitializeProcThreadAttributeList.restype = wintypes.BOOL
        kernel.UpdateProcThreadAttribute.argtypes = (
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.c_size_t,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_void_p,
            ctypes.c_void_p,
        )
        kernel.UpdateProcThreadAttribute.restype = wintypes.BOOL
        kernel.DeleteProcThreadAttributeList.argtypes = (ctypes.c_void_p,)
        kernel.DeleteProcThreadAttributeList.restype = None
        kernel.CreateProcessW.argtypes = (
            wintypes.LPCWSTR,
            wintypes.LPWSTR,
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.BOOL,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.LPCWSTR,
            ctypes.POINTER(_StartupInfoExW),
            ctypes.POINTER(_ProcessInformation),
        )
        kernel.CreateProcessW.restype = wintypes.BOOL
        kernel.ResumeThread.argtypes = (wintypes.HANDLE,)
        kernel.ResumeThread.restype = wintypes.DWORD
        kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        kernel.GetExitCodeProcess.argtypes = (
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.DWORD),
        )
        kernel.GetExitCodeProcess.restype = wintypes.BOOL
        kernel.ReadFile.argtypes = (
            wintypes.HANDLE,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.c_void_p,
        )
        kernel.ReadFile.restype = wintypes.BOOL
        kernel.WriteFile.argtypes = (
            wintypes.HANDLE,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.c_void_p,
        )
        kernel.WriteFile.restype = wintypes.BOOL
        kernel.GetWindowsDirectoryW.argtypes = (wintypes.LPWSTR, wintypes.UINT)
        kernel.GetWindowsDirectoryW.restype = wintypes.UINT
        kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel.CloseHandle.restype = wintypes.BOOL

    def probe(self) -> None:
        """Create and close an empty Job Object after verifying all symbols."""

        job = self._kernel.CreateJobObjectW(None, None)
        if not job:
            raise OSError(_last_error(), "CreateJobObjectW failed")
        self._close(job)

    def windows_directory(self) -> str:
        """Return the native Windows directory through ``GetWindowsDirectoryW``."""

        size = 260
        while size <= 32_768:
            buffer = ctypes.create_unicode_buffer(size)
            result = int(self._kernel.GetWindowsDirectoryW(buffer, size))
            if result == 0:
                raise OSError(_last_error(), "GetWindowsDirectoryW failed")
            if result < size:
                return buffer.value
            size = result + 1
        raise OSError("Windows directory exceeds safety limit")

    def run(
        self,
        *,
        executable: Path,
        arguments: tuple[str, ...],
        cwd: Path,
        environment: Mapping[str, str],
        inherited_handles: tuple[int, ...],
        timeout_seconds: float,
        cpu_seconds: int,
        memory_bytes: int,
        max_processes: int,
        max_output_bytes: int,
    ) -> ProcessExecutionResult:
        """Launch a normal supervised process with a null input stream."""

        return self._run(
            executable=executable,
            arguments=arguments,
            cwd=cwd,
            environment=environment,
            inherited_handles=inherited_handles,
            input_payload=None,
            appcontainer_sid=None,
            timeout_seconds=timeout_seconds,
            cpu_seconds=cpu_seconds,
            memory_bytes=memory_bytes,
            max_processes=max_processes,
            max_output_bytes=max_output_bytes,
        )

    def run_appcontainer(
        self,
        *,
        executable: Path,
        arguments: tuple[str, ...],
        cwd: Path,
        environment: Mapping[str, str],
        input_payload: bytes,
        appcontainer_sid: int,
        timeout_seconds: float,
        cpu_seconds: int,
        memory_bytes: int,
        max_processes: int,
        max_output_bytes: int,
    ) -> ProcessExecutionResult:
        """Launch one zero-capability AppContainer with protocol-only handles."""

        if not isinstance(input_payload, bytes) or len(input_payload) > 2 * 1024 * 1024:
            raise ProcessSupervisionError("input_payload_invalid")
        if (
            isinstance(appcontainer_sid, bool)
            or not isinstance(appcontainer_sid, int)
            or appcontainer_sid <= 0
        ):
            raise ProcessSupervisionError("appcontainer_sid_invalid")
        return self._run(
            executable=executable,
            arguments=arguments,
            cwd=cwd,
            environment=environment,
            inherited_handles=(),
            input_payload=input_payload,
            appcontainer_sid=appcontainer_sid,
            timeout_seconds=timeout_seconds,
            cpu_seconds=cpu_seconds,
            memory_bytes=memory_bytes,
            max_processes=max_processes,
            max_output_bytes=max_output_bytes,
        )

    def _run(
        self,
        *,
        executable: Path,
        arguments: tuple[str, ...],
        cwd: Path,
        environment: Mapping[str, str],
        inherited_handles: tuple[int, ...],
        input_payload: bytes | None,
        appcontainer_sid: int | None,
        timeout_seconds: float,
        cpu_seconds: int,
        memory_bytes: int,
        max_processes: int,
        max_output_bytes: int,
    ) -> ProcessExecutionResult:
        """Launch suspended, bind the Job Object, resume, drain, and terminate."""

        if not executable.is_file() or not cwd.is_dir():
            raise ProcessSupervisionError("invalid_launch_path")
        job = self._create_job(
            cpu_seconds=cpu_seconds,
            memory_bytes=memory_bytes,
            max_processes=max_processes,
        )
        stdin_write: wintypes.HANDLE | None = None
        stdin: Any
        if input_payload is None:
            stdin = self._open_null_input()
        else:
            stdin, stdin_write = self._create_input_pipe()
        stdout_read, stdout_write = self._create_pipe()
        stderr_read, stderr_write = self._create_pipe()
        stdout_write_owned: Any = stdout_write
        stderr_write_owned: Any = stderr_write
        process_info = _ProcessInformation()
        attribute_list: Any | None = None
        process_created = False
        process_finished = False
        readers_started = False
        writer_started = False
        input_failed = threading.Event()
        try:
            child_handles = (
                _handle_value(stdin),
                _handle_value(stdout_write_owned),
                _handle_value(stderr_write_owned),
                *inherited_handles,
            )
            self._validate_inheritable_handles(child_handles)
            startup, attribute_list, _attribute_handles = self._build_startup(
                stdin=stdin,
                stdout=stdout_write_owned,
                stderr=stderr_write_owned,
                inherited_handles=child_handles,
                appcontainer_sid=appcontainer_sid,
            )
            command_line = ctypes.create_unicode_buffer(
                _windows_command_line((os.fspath(executable), *arguments))
            )
            environment_block = ctypes.create_unicode_buffer(
                "\x00".join(f"{key}={value}" for key, value in environment.items())
                + "\x00\x00"
            )
            flags = (
                _CREATE_SUSPENDED
                | _CREATE_NO_WINDOW
                | _CREATE_UNICODE_ENVIRONMENT
                | _EXTENDED_STARTUPINFO_PRESENT
            )
            if not self._kernel.CreateProcessW(
                os.fspath(executable),
                command_line,
                None,
                None,
                True,
                flags,
                ctypes.cast(environment_block, ctypes.c_void_p),
                os.fspath(cwd),
                ctypes.byref(startup),
                ctypes.byref(process_info),
            ):
                raise ProcessSupervisionError(
                    "launch_failed",
                    native_error_code=_last_error(),
                )
            process_created = True
            if not self._kernel.AssignProcessToJobObject(job, process_info.process):
                raise ProcessSupervisionError("job_assignment_failed")
            if int(self._kernel.ResumeThread(process_info.thread)) == 0xFFFFFFFF:
                raise ProcessSupervisionError("resume_failed")
            self._close(process_info.thread)
            process_info.thread = None
            self._close(stdin)
            stdin = None
            self._close(stdout_write_owned)
            stdout_write_owned = None
            self._close(stderr_write_owned)
            stderr_write_owned = None
            budget = _OutputBudget(max_output_bytes)
            stdout_thread = threading.Thread(
                target=self._drain_pipe,
                args=(stdout_read, budget, True),
                daemon=True,
            )
            stderr_thread = threading.Thread(
                target=self._drain_pipe,
                args=(stderr_read, budget, False),
                daemon=True,
            )
            stdout_thread.start()
            stderr_thread.start()
            readers_started = True
            input_thread: threading.Thread | None = None
            if stdin_write is not None and input_payload is not None:
                input_thread = threading.Thread(
                    target=self._write_pipe,
                    args=(stdin_write, input_payload, input_failed),
                    daemon=True,
                )
                input_thread.start()
                writer_started = True
                stdin_write = None
            wait = int(
                self._kernel.WaitForSingleObject(
                    process_info.process,
                    min(int(timeout_seconds * 1000 + 0.999), 0xFFFFFFFE),
                )
            )
            timed_out = wait == _WAIT_TIMEOUT
            if timed_out:
                if not self._kernel.TerminateJobObject(job, _TIMEOUT_EXIT_CODE):
                    raise ProcessSupervisionError("timeout_termination_failed")
                if (
                    int(self._kernel.WaitForSingleObject(process_info.process, 30_000))
                    != _WAIT_OBJECT_0
                ):
                    raise ProcessSupervisionError("timeout_wait_failed")
            elif wait != _WAIT_OBJECT_0:
                raise ProcessSupervisionError("process_wait_failed")
            process_finished = True
            stdout_thread.join(timeout=30)
            stderr_thread.join(timeout=30)
            if stdout_thread.is_alive() or stderr_thread.is_alive():
                raise ProcessSupervisionError("pipe_drain_failed")
            if input_thread is not None:
                input_thread.join(timeout=30)
                if input_thread.is_alive() or input_failed.is_set():
                    raise ProcessSupervisionError("pipe_write_failed")
            if timed_out:
                return budget.result(reason=ProcessExitReason.TIMED_OUT, exit_code=None)
            exit_code = wintypes.DWORD(_STILL_ACTIVE)
            if not self._kernel.GetExitCodeProcess(
                process_info.process, ctypes.byref(exit_code)
            ):
                raise ProcessSupervisionError("exit_status_failed")
            parsed_exit = int(exit_code.value)
            if parsed_exit == _STILL_ACTIVE:
                raise ProcessSupervisionError("process_state_invalid")
            return budget.result(
                reason=(
                    ProcessExitReason.EXITED
                    if parsed_exit == 0
                    else ProcessExitReason.NONZERO_EXIT
                ),
                exit_code=parsed_exit,
            )
        finally:
            if process_created and not process_finished:
                self._kernel.TerminateProcess(process_info.process, _TIMEOUT_EXIT_CODE)
                self._kernel.WaitForSingleObject(process_info.process, 30_000)
            if process_created and process_info.thread:
                self._close(process_info.thread)
            if process_created:
                self._close(process_info.process)
            read_handles = () if readers_started else (stdout_read, stderr_read)
            for handle in (
                stdin,
                None if writer_started else stdin_write,
                stdout_write_owned,
                stderr_write_owned,
                *read_handles,
            ):
                self._close(handle)
            if attribute_list is not None:
                self._kernel.DeleteProcThreadAttributeList(attribute_list)
            self._close(job)

    def _create_job(
        self,
        *,
        cpu_seconds: int,
        memory_bytes: int,
        max_processes: int,
    ) -> wintypes.HANDLE:
        job = self._kernel.CreateJobObjectW(None, None)
        if not job:
            raise ProcessSupervisionError("job_creation_failed")
        limits = _ExtendedLimitInformation()
        basic = limits.basic_limit_information
        basic.per_process_user_time_limit = cpu_seconds * 10_000_000
        basic.active_process_limit = max_processes
        basic.limit_flags = (
            _JOB_OBJECT_LIMIT_PROCESS_TIME
            | _JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | _JOB_OBJECT_LIMIT_PROCESS_MEMORY
            | _JOB_OBJECT_LIMIT_JOB_MEMORY
            | _JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
            | _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        )
        limits.process_memory_limit = memory_bytes
        limits.job_memory_limit = memory_bytes
        if not self._kernel.SetInformationJobObject(
            job,
            _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        ):
            self._close(job)
            raise ProcessSupervisionError("job_limit_configuration_failed")
        return wintypes.HANDLE(job)

    def _create_pipe(self) -> tuple[wintypes.HANDLE, wintypes.HANDLE]:
        attributes = _SecurityAttributes(
            length=ctypes.sizeof(_SecurityAttributes),
            security_descriptor=None,
            inherit_handle=True,
        )
        read = wintypes.HANDLE()
        write = wintypes.HANDLE()
        if not self._kernel.CreatePipe(
            ctypes.byref(read), ctypes.byref(write), ctypes.byref(attributes), 0
        ):
            raise ProcessSupervisionError("pipe_creation_failed")
        if not self._kernel.SetHandleInformation(read, _HANDLE_FLAG_INHERIT, 0):
            self._close(read)
            self._close(write)
            raise ProcessSupervisionError("pipe_configuration_failed")
        return read, write

    def _create_input_pipe(self) -> tuple[wintypes.HANDLE, wintypes.HANDLE]:
        attributes = _SecurityAttributes(
            length=ctypes.sizeof(_SecurityAttributes),
            security_descriptor=None,
            inherit_handle=True,
        )
        read = wintypes.HANDLE()
        write = wintypes.HANDLE()
        if not self._kernel.CreatePipe(
            ctypes.byref(read), ctypes.byref(write), ctypes.byref(attributes), 0
        ):
            raise ProcessSupervisionError("stdin_creation_failed")
        if not self._kernel.SetHandleInformation(write, _HANDLE_FLAG_INHERIT, 0):
            self._close(read)
            self._close(write)
            raise ProcessSupervisionError("stdin_configuration_failed")
        return read, write

    def _open_null_input(self) -> wintypes.HANDLE:
        attributes = _SecurityAttributes(
            length=ctypes.sizeof(_SecurityAttributes),
            security_descriptor=None,
            inherit_handle=True,
        )
        handle = self._kernel.CreateFileW(
            "NUL",
            _GENERIC_READ,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE,
            ctypes.byref(attributes),
            _OPEN_EXISTING,
            _FILE_ATTRIBUTE_NORMAL,
            None,
        )
        if not handle or _handle_value(handle) == _INVALID_HANDLE_VALUE:
            raise ProcessSupervisionError("stdin_creation_failed")
        return wintypes.HANDLE(handle)

    def _build_startup(
        self,
        *,
        stdin: wintypes.HANDLE,
        stdout: wintypes.HANDLE,
        stderr: wintypes.HANDLE,
        inherited_handles: tuple[int, ...],
        appcontainer_sid: int | None,
    ) -> tuple[_StartupInfoExW, Any, Any]:
        attribute_count = 2 if appcontainer_sid is not None else 1
        size = ctypes.c_size_t()
        self._kernel.InitializeProcThreadAttributeList(
            None, attribute_count, 0, ctypes.byref(size)
        )
        if _last_error() != _ERROR_INSUFFICIENT_BUFFER or size.value == 0:
            raise ProcessSupervisionError("handle_list_size_failed")
        storage = ctypes.create_string_buffer(size.value)
        if not self._kernel.InitializeProcThreadAttributeList(
            storage, attribute_count, 0, ctypes.byref(size)
        ):
            raise ProcessSupervisionError("handle_list_initialization_failed")
        handle_array = (wintypes.HANDLE * len(inherited_handles))(*inherited_handles)
        if not self._kernel.UpdateProcThreadAttribute(
            storage,
            0,
            _PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            handle_array,
            ctypes.sizeof(handle_array),
            None,
            None,
        ):
            self._kernel.DeleteProcThreadAttributeList(storage)
            raise ProcessSupervisionError("handle_list_configuration_failed")
        security_capabilities: _SecurityCapabilities | None = None
        if appcontainer_sid is not None:
            security_capabilities = _SecurityCapabilities(
                app_container_sid=ctypes.c_void_p(appcontainer_sid),
                capabilities=None,
                capability_count=0,
                reserved=0,
            )
            if not self._kernel.UpdateProcThreadAttribute(
                storage,
                0,
                _PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                ctypes.byref(security_capabilities),
                ctypes.sizeof(security_capabilities),
                None,
                None,
            ):
                self._kernel.DeleteProcThreadAttributeList(storage)
                raise ProcessSupervisionError(
                    "appcontainer_attribute_configuration_failed",
                    native_error_code=_last_error(),
                )
        startup = _StartupInfoExW()
        startup.startup_info.cb = ctypes.sizeof(_StartupInfoExW)
        startup.startup_info.flags = _STARTF_USESTDHANDLES
        startup.startup_info.stdin = stdin
        startup.startup_info.stdout = stdout
        startup.startup_info.stderr = stderr
        startup.attribute_list = ctypes.cast(storage, ctypes.c_void_p)
        return startup, storage, (handle_array, security_capabilities)

    def _validate_inheritable_handles(self, handles: tuple[int, ...]) -> None:
        for handle in handles:
            flags = wintypes.DWORD()
            if not self._kernel.GetHandleInformation(handle, ctypes.byref(flags)):
                raise ProcessSupervisionError("inherited_handle_invalid")
            if not flags.value & _HANDLE_FLAG_INHERIT:
                raise ProcessSupervisionError("inherited_handle_not_inheritable")

    def _drain_pipe(
        self,
        handle: wintypes.HANDLE,
        budget: _OutputBudget,
        stdout: bool,
    ) -> None:
        try:
            buffer = ctypes.create_string_buffer(64 * 1024)
            while True:
                read = wintypes.DWORD()
                if not self._kernel.ReadFile(
                    handle, buffer, len(buffer), ctypes.byref(read), None
                ):
                    if _last_error() == _ERROR_BROKEN_PIPE:
                        return
                    budget.fail()
                    return
                if read.value == 0:
                    return
                budget.add(buffer.raw[: read.value], stdout=stdout)
        finally:
            self._close(handle)

    def _write_pipe(
        self,
        handle: wintypes.HANDLE,
        payload: bytes,
        failed: threading.Event,
    ) -> None:
        try:
            offset = 0
            while offset < len(payload):
                selected = payload[offset : offset + 64 * 1024]
                buffer = ctypes.create_string_buffer(selected)
                written = wintypes.DWORD()
                if not self._kernel.WriteFile(
                    handle,
                    buffer,
                    len(selected),
                    ctypes.byref(written),
                    None,
                ):
                    if _last_error() == _ERROR_BROKEN_PIPE:
                        return
                    failed.set()
                    return
                if written.value <= 0:
                    failed.set()
                    return
                offset += int(written.value)
        finally:
            self._close(handle)

    def _close(self, handle: object) -> None:
        if handle:
            self._kernel.CloseHandle(handle)


class _OutputBudget:
    def __init__(self, maximum: int) -> None:
        self._remaining = maximum
        self._stdout = bytearray()
        self._stderr = bytearray()
        self._truncated = False
        self._failed = False
        self._lock = threading.Lock()

    def add(self, payload: bytes, *, stdout: bool) -> None:
        with self._lock:
            retained = payload[: self._remaining]
            self._remaining -= len(retained)
            (self._stdout if stdout else self._stderr).extend(retained)
            if len(retained) != len(payload):
                self._truncated = True

    def fail(self) -> None:
        with self._lock:
            self._failed = True

    def result(
        self,
        *,
        reason: ProcessExitReason,
        exit_code: int | None,
    ) -> ProcessExecutionResult:
        with self._lock:
            if self._failed:
                raise ProcessSupervisionError("pipe_read_failed")
            return ProcessExecutionResult(
                reason=reason,
                exit_code=exit_code,
                stdout=bytes(self._stdout),
                stderr=bytes(self._stderr),
                output_truncated=self._truncated,
            )


def probe_windows_process_backend() -> CtypesWindowsProcessApi:
    """Return a probed native process API without launching a child."""

    api = CtypesWindowsProcessApi()
    try:
        api.probe()
    except OSError as error:
        raise PlatformCapabilityUnavailable(
            "required Windows process APIs are unavailable"
        ) from error
    return api


def _validate_path(path: Path, *, name: str) -> None:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ValueError(f"process {name} must be an absolute path")


def _validate_arguments(arguments: Sequence[str]) -> tuple[str, ...]:
    if isinstance(arguments, (str, bytes)):
        raise TypeError("process arguments must be a sequence of strings")
    parsed = tuple(arguments)
    if len(parsed) > _MAX_ARGUMENTS:
        raise ValueError("process argument count exceeds safety limit")
    if any(not isinstance(value, str) or "\x00" in value for value in parsed):
        raise ValueError("process arguments are invalid")
    if sum(len(value.encode("utf-16-le")) for value in parsed) > _MAX_ARGUMENT_BYTES:
        raise ValueError("process arguments exceed safety limit")
    return parsed


def _validate_handles(handles: Sequence[int]) -> tuple[int, ...]:
    if isinstance(handles, (str, bytes)):
        raise TypeError("inherited handles must be a sequence of integers")
    parsed = tuple(handles)
    if len(parsed) > 32:
        raise ValueError("inherited handle count exceeds safety limit")
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value <= 0
        for value in parsed
    ):
        raise ValueError("inherited handle is invalid")
    if len(set(parsed)) != len(parsed):
        raise ValueError("inherited handles contain duplicates")
    return parsed


def _validate_positive_limits(
    *,
    cpu_seconds: int,
    memory_bytes: int,
    max_processes: int,
    max_output_bytes: int,
) -> None:
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value <= 0
        for value in (cpu_seconds, memory_bytes, max_processes, max_output_bytes)
    ):
        raise ValueError("process limits must be positive integers")
    if cpu_seconds > 86_400 or max_processes > 1_024:
        raise ValueError("process limits exceed safety maximum")


def _build_minimal_environment(
    requested: Mapping[str, str],
    *,
    windows_directory: str,
) -> Mapping[str, str]:
    if not isinstance(requested, Mapping):
        raise TypeError("process environment must be a mapping")
    if (
        not windows_directory
        or "\x00" in windows_directory
        or len(windows_directory.encode("utf-16-le")) > 32_768
    ):
        raise ProcessSupervisionError("windows_directory_invalid")
    if len(requested) > _MAX_ENVIRONMENT_ENTRIES:
        raise ValueError("process environment count exceeds safety limit")
    selected: dict[str, tuple[str, str]] = {
        "systemroot": ("SystemRoot", windows_directory),
        "windir": ("WINDIR", windows_directory),
    }
    for key, value in requested.items():
        if (
            not isinstance(key, str)
            or not key
            or key.startswith("=")
            or "=" in key
            or "\x00" in key
            or not isinstance(value, str)
            or "\x00" in value
        ):
            raise ValueError("process environment is invalid")
        folded = key.casefold()
        if folded in selected:
            raise ValueError("process environment duplicates a reserved baseline name")
        selected[folded] = (key, value)
    ordered = dict(
        sorted(
            (value for value in selected.values()), key=lambda item: item[0].casefold()
        )
    )
    encoded_size = (
        sum(
            len(f"{key}={value}\x00".encode("utf-16-le"))
            for key, value in ordered.items()
        )
        + 2
    )
    if encoded_size > _MAX_ENVIRONMENT_BYTES:
        raise ValueError("process environment exceeds safety limit")
    return ordered


def _last_error() -> int:
    getter = getattr(ctypes, "get_last_error", None)
    return int(getter()) if getter is not None else 0


def _windows_command_line(arguments: Sequence[str]) -> str:
    """Encode argv using the documented Microsoft C runtime parsing rules."""

    import subprocess

    return subprocess.list2cmdline(tuple(arguments))


def _handle_value(handle: object) -> int:
    value = getattr(handle, "value", handle)
    if not isinstance(value, int):
        raise ProcessSupervisionError("native_handle_invalid")
    return value

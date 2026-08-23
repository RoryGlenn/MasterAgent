"""Native Windows AppContainer isolation for pure capability capsules."""

from __future__ import annotations

import ctypes
import hashlib
import os
import secrets
import shutil
import socket
import sys
import threading
from collections.abc import Callable, Mapping, Sequence
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final, Protocol

from master_agent.platform_runtime.contracts import (
    PlatformCapabilityUnavailable,
    ProcessExecutionResult,
    ProcessExitReason,
    ProcessSupervisionError,
)
from master_agent.platform_runtime.windows.filesystem import (
    BUILTIN_ADMINISTRATORS_SID,
    FILE_ATTRIBUTE_REPARSE_POINT,
    LOCAL_SYSTEM_SID,
    WindowsSecureFilesystemBackend,
    canonicalize_windows_sid,
)
from master_agent.platform_runtime.windows.process import (
    CtypesWindowsProcessApi,
    _build_minimal_environment,
    _validate_arguments,
    _validate_positive_limits,
)

WINDOWS_CAPSULE_BACKEND_ID: Final = "windows-appcontainer"
WINDOWS_CAPSULE_UNAVAILABLE_REASON: Final = (
    "native windows capsule_isolation backend is unavailable: "
    "required AppContainer controls are unavailable"
)

_MAX_RUNTIME_FILES = 25_000
_MAX_RUNTIME_BYTES = 1024 * 1024 * 1024
_MAX_RUNTIME_PATH_BYTES = 8 * 1024 * 1024
_MAX_PROFILE_PATH_CHARS = 32_768
_SDDL_REVISION_1 = 1
_OWNER_SECURITY_INFORMATION = 0x00000001
_DACL_SECURITY_INFORMATION = 0x00000004
_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF

_RUNTIME_EXCLUDED_DIRECTORIES = frozenset(
    {
        "__pycache__",
        "distutils",
        "ensurepip",
        "idlelib",
        "site-packages",
        "test",
        "tests",
        "tkinter",
        "turtledemo",
        "venv",
    }
)


@dataclass(frozen=True, slots=True)
class WindowsAppContainerProjection:
    """One prepared read-only runtime and live AppContainer SID."""

    profile_name: str
    sid: int
    sid_string: str
    profile_root: Path
    runtime_root: Path
    interpreter: Path
    worker: Path
    source_interpreter_sha256: str
    source_worker_sha256: str
    runtime_sha256: str
    runtime_security_sha256: str


class WindowsAppContainerApi(Protocol):
    """Injectable profile, ACL, projection, and launch boundary."""

    def probe(self) -> None:
        """Verify the required native AppContainer symbols."""

    def prepare(
        self,
        *,
        worker: Path,
        interpreter: Path,
    ) -> WindowsAppContainerProjection:
        """Create one exact read-only runtime projection and profile."""

    def identity_components(
        self,
        projection: WindowsAppContainerProjection,
        *,
        worker: Path,
        interpreter: Path,
    ) -> Mapping[str, str | None]:
        """Revalidate the projection and return its exact component digests."""

    def run(
        self,
        projection: WindowsAppContainerProjection,
        *,
        request: bytes,
        environment: Mapping[str, str],
        timeout_seconds: float,
        cpu_seconds: int,
        memory_bytes: int,
        max_processes: int,
        max_output_bytes: int,
    ) -> ProcessExecutionResult:
        """Run one worker request under the prepared AppContainer."""

    def denial_probes(
        self,
        projection: WindowsAppContainerProjection,
    ) -> Sequence[Mapping[str, str]]:
        """Run the fixed native AppContainer denial probes."""

    def close(self, projection: WindowsAppContainerProjection) -> None:
        """Remove projected state and delete the native profile."""


class WindowsAppContainerCapsuleIsolationBackend:
    """Select and retain the zero-capability native capsule boundary."""

    backend_id = WINDOWS_CAPSULE_BACKEND_ID
    executable: Path | None = None

    def __init__(self, *, api: WindowsAppContainerApi) -> None:
        self._api = api
        self._projection: WindowsAppContainerProjection | None = None
        self._lock = threading.RLock()

    @property
    def production_isolated(self) -> bool:
        """Return the AppContainer production isolation status."""

        return True

    def identity_components(
        self,
        *,
        worker: Path,
        interpreter: Path,
    ) -> Mapping[str, str | None]:
        """Return exact backend, process, runtime, interpreter, and worker IDs."""

        with self._lock:
            projection = self._prepare(worker=worker, interpreter=interpreter)
            return self._api.identity_components(
                projection,
                worker=worker,
                interpreter=interpreter,
            )

    def run_worker(
        self,
        *,
        worker: Path,
        interpreter: Path,
        request: bytes,
        environment: Mapping[str, str],
        timeout_seconds: float,
        cpu_seconds: int,
        memory_bytes: int,
        max_processes: int,
        max_output_bytes: int,
    ) -> ProcessExecutionResult:
        """Run one request after exact projection and identity revalidation."""

        with self._lock:
            projection = self._prepare(worker=worker, interpreter=interpreter)
            self._api.identity_components(
                projection,
                worker=worker,
                interpreter=interpreter,
            )
            return self._api.run(
                projection,
                request=request,
                environment=environment,
                timeout_seconds=timeout_seconds,
                cpu_seconds=cpu_seconds,
                memory_bytes=memory_bytes,
                max_processes=max_processes,
                max_output_bytes=max_output_bytes,
            )

    def denial_probes(
        self,
        *,
        worker: Path,
        interpreter: Path,
    ) -> Sequence[Mapping[str, str]]:
        """Return fixed OS-enforced denial evidence after identity revalidation."""

        with self._lock:
            projection = self._prepare(worker=worker, interpreter=interpreter)
            self._api.identity_components(
                projection,
                worker=worker,
                interpreter=interpreter,
            )
            return self._api.denial_probes(projection)

    def close(self) -> None:
        """Remove the retained projection and AppContainer profile."""

        with self._lock:
            projection = self._projection
            if projection is None:
                return
            self._api.close(projection)
            self._projection = None

    def _prepare(
        self,
        *,
        worker: Path,
        interpreter: Path,
    ) -> WindowsAppContainerProjection:
        projection = self._projection
        if projection is None:
            projection = self._api.prepare(worker=worker, interpreter=interpreter)
            self._projection = projection
        return projection

    def __del__(self) -> None:
        if hasattr(self, "_projection"):
            try:
                self.close()
            except (OSError, ProcessSupervisionError):
                return


class CtypesWindowsAppContainerApi:
    """Direct Win32 AppContainer profile, ACL, and launch bindings."""

    def __init__(
        self,
        *,
        filesystem: WindowsSecureFilesystemBackend,
        process: CtypesWindowsProcessApi,
    ) -> None:
        if sys.platform != "win32":
            raise PlatformCapabilityUnavailable(
                "native Windows AppContainer isolation requires Windows"
            )
        loader = getattr(ctypes, "WinDLL", None)
        if loader is None:
            raise PlatformCapabilityUnavailable(
                "stdlib ctypes Win32 loading is unavailable"
            )
        self._filesystem: WindowsSecureFilesystemBackend = filesystem
        self._process: CtypesWindowsProcessApi = process
        try:
            self._userenv: Any = loader("userenv", use_last_error=True)
            self._advapi: Any = loader("advapi32", use_last_error=True)
            self._kernel: Any = loader("kernel32", use_last_error=True)
            self._ole32: Any = loader("ole32", use_last_error=True)
            self._bind_functions()
        except (AttributeError, OSError) as error:
            raise PlatformCapabilityUnavailable(
                WINDOWS_CAPSULE_UNAVAILABLE_REASON
            ) from error

    def _bind_functions(self) -> None:
        self._userenv.CreateAppContainerProfile.argtypes = (
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_void_p),
        )
        self._userenv.CreateAppContainerProfile.restype = ctypes.c_long
        self._userenv.DeleteAppContainerProfile.argtypes = (ctypes.c_wchar_p,)
        self._userenv.DeleteAppContainerProfile.restype = ctypes.c_long
        self._userenv.DeriveAppContainerSidFromAppContainerName.argtypes = (
            ctypes.c_wchar_p,
            ctypes.POINTER(ctypes.c_void_p),
        )
        self._userenv.DeriveAppContainerSidFromAppContainerName.restype = ctypes.c_long
        self._userenv.GetAppContainerFolderPath.argtypes = (
            ctypes.c_wchar_p,
            ctypes.POINTER(ctypes.c_wchar_p),
        )
        self._userenv.GetAppContainerFolderPath.restype = ctypes.c_long
        self._advapi.ConvertSidToStringSidW.argtypes = (
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_wchar_p),
        )
        self._advapi.ConvertSidToStringSidW.restype = ctypes.c_int
        self._advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = (
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_uint32),
        )
        self._advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = (
            ctypes.c_int
        )
        self._advapi.SetFileSecurityW.argtypes = (
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
        )
        self._advapi.SetFileSecurityW.restype = ctypes.c_int
        self._advapi.GetFileSecurityW.argtypes = (
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
        )
        self._advapi.GetFileSecurityW.restype = ctypes.c_int
        self._kernel.LocalFree.argtypes = (ctypes.c_void_p,)
        self._kernel.LocalFree.restype = ctypes.c_void_p
        self._advapi.FreeSid.argtypes = (ctypes.c_void_p,)
        self._advapi.FreeSid.restype = ctypes.c_void_p
        self._kernel.GetFileAttributesW.argtypes = (ctypes.c_wchar_p,)
        self._kernel.GetFileAttributesW.restype = ctypes.c_uint32
        self._ole32.CoTaskMemFree.argtypes = (ctypes.c_void_p,)
        self._ole32.CoTaskMemFree.restype = None

    def probe(self) -> None:
        """Derive and free a no-capability AppContainer SID."""

        sid = ctypes.c_void_p()
        result = int(
            self._userenv.DeriveAppContainerSidFromAppContainerName(
                "MasterAgent.Capsule.Probe",
                ctypes.byref(sid),
            )
        )
        if result != 0 or not sid.value:
            raise OSError(result, "AppContainer SID derivation failed")
        self._advapi.FreeSid(sid)

    def prepare(
        self,
        *,
        worker: Path,
        interpreter: Path,
    ) -> WindowsAppContainerProjection:
        """Create a profile and exact read-only runtime projection."""

        _require_absolute_file(worker, "worker")
        _require_absolute_file(interpreter, "interpreter")
        profile_name = f"MasterAgent.Capsule.{os.getpid()}.{secrets.token_hex(8)}"
        sid = ctypes.c_void_p()
        created = False
        try:
            result = int(
                self._userenv.CreateAppContainerProfile(
                    profile_name,
                    "MasterAgent Capsule",
                    "Ephemeral pure capability capsule",
                    None,
                    0,
                    ctypes.byref(sid),
                )
            )
            if result != 0 or not sid.value:
                raise OSError(result, "AppContainer profile creation failed")
            created = True
            sid_string = self._sid_string(int(sid.value))
            profile_root = self._profile_path(sid_string)
            runtime_root = profile_root / "Runtime"
            runtime_root.mkdir(exist_ok=False)
            projected_interpreter = self._copy_runtime(
                runtime_root=runtime_root,
                worker=worker,
            )
            projected_worker = runtime_root / "capsule-worker.py"
            owner_sid = canonicalize_windows_sid(self._filesystem.current_user_sid())
            readonly_sddl = _sddl(
                owner_sid=owner_sid,
                appcontainer_sid=sid_string,
                writable=False,
            )
            self._apply_tree_sddl(profile_root, readonly_sddl)
            runtime_sha256 = _tree_sha256(runtime_root)
            runtime_security_sha256 = self._tree_security_sha256(profile_root)
            return WindowsAppContainerProjection(
                profile_name=profile_name,
                sid=int(sid.value),
                sid_string=sid_string,
                profile_root=profile_root,
                runtime_root=runtime_root,
                interpreter=projected_interpreter,
                worker=projected_worker,
                source_interpreter_sha256=_sha256_file(interpreter),
                source_worker_sha256=_sha256_file(worker),
                runtime_sha256=runtime_sha256,
                runtime_security_sha256=runtime_security_sha256,
            )
        except BaseException:
            if created:
                self._remove_profile_contents(profile_name, sid)
            elif sid.value:
                self._advapi.FreeSid(sid)
            raise

    def identity_components(
        self,
        projection: WindowsAppContainerProjection,
        *,
        worker: Path,
        interpreter: Path,
    ) -> Mapping[str, str | None]:
        """Revalidate all mutable paths and return promotion-bound digests."""

        if (
            _sha256_file(worker) != projection.source_worker_sha256
            or _sha256_file(interpreter) != projection.source_interpreter_sha256
            or _tree_sha256(projection.runtime_root) != projection.runtime_sha256
            or self._tree_security_sha256(projection.profile_root)
            != projection.runtime_security_sha256
        ):
            raise ProcessSupervisionError("capsule_runtime_identity_changed")
        helper_path = Path(__file__).resolve()
        process_path = Path(
            sys.modules[self._process.__class__.__module__].__file__ or ""
        )
        return MappingProxyType(
            {
                "backend": WINDOWS_CAPSULE_BACKEND_ID,
                "worker_sha256": _sha256_file(projection.worker),
                "interpreter_sha256": _sha256_file(projection.interpreter),
                "sandbox_sha256": _sha256_file(helper_path),
                "runtime_sha256": projection.runtime_sha256,
                "process_boundary_sha256": _sha256_file(process_path),
                "dacl_policy_sha256": projection.runtime_security_sha256,
                "host_interpreter_sha256": projection.source_interpreter_sha256,
            }
        )

    def run(
        self,
        projection: WindowsAppContainerProjection,
        *,
        request: bytes,
        environment: Mapping[str, str],
        timeout_seconds: float,
        cpu_seconds: int,
        memory_bytes: int,
        max_processes: int,
        max_output_bytes: int,
    ) -> ProcessExecutionResult:
        """Create one writable directory and launch the projected worker."""

        _validate_positive_limits(
            cpu_seconds=cpu_seconds,
            memory_bytes=memory_bytes,
            max_processes=max_processes,
            max_output_bytes=max_output_bytes,
        )
        arguments = _validate_arguments(("-I", "-S", str(projection.worker)))
        work = projection.profile_root / f"Work-{secrets.token_hex(12)}"
        work.mkdir(exist_ok=False)
        owner_sid = canonicalize_windows_sid(self._filesystem.current_user_sid())
        writable_sddl = _sddl(
            owner_sid=owner_sid,
            appcontainer_sid=projection.sid_string,
            writable=True,
        )
        self._set_sddl(work, writable_sddl)
        selected_environment = dict(environment)
        selected_environment.update(
            {
                "APPDATA": str(work),
                "LOCALAPPDATA": str(work),
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONNOUSERSITE": "1",
                "TEMP": str(work),
                "TMP": str(work),
                "USERPROFILE": str(work),
            }
        )
        minimal_environment = _build_minimal_environment(
            selected_environment,
            windows_directory=self._process.windows_directory(),
        )
        caught: BaseException | None = None
        try:
            return self._process.run_appcontainer(
                executable=projection.interpreter,
                arguments=arguments,
                cwd=work,
                environment=minimal_environment,
                input_payload=request,
                appcontainer_sid=projection.sid,
                timeout_seconds=timeout_seconds,
                cpu_seconds=cpu_seconds,
                memory_bytes=memory_bytes,
                max_processes=max_processes,
                max_output_bytes=max_output_bytes,
            )
        except BaseException as error:
            caught = error
            raise
        finally:
            try:
                _remove_tree(work)
            except OSError as cleanup_error:
                if caught is None:
                    raise ProcessSupervisionError(
                        "appcontainer_cleanup_failed"
                    ) from cleanup_error

    def denial_probes(
        self,
        projection: WindowsAppContainerProjection,
    ) -> tuple[Mapping[str, str], ...]:
        """Prove native file, environment, network, and child denials."""

        owner_sid = canonicalize_windows_sid(self._filesystem.current_user_sid())
        secret_path = projection.profile_root.parent / (
            f".master-agent-capsule-probe-{secrets.token_hex(12)}"
        )
        with ExitStack() as resources:
            resources.callback(secret_path.unlink, missing_ok=True)
            secret_path.write_bytes(secrets.token_bytes(32))
            self._set_sddl(
                secret_path,
                _private_sddl(owner_sid=owner_sid),
            )
            ipv4_listener = _loopback_listener("127.0.0.1", family=socket.AF_INET)
            resources.callback(ipv4_listener.close)
            ipv6_listener = _loopback_listener("::1", family=socket.AF_INET6)
            resources.callback(ipv6_listener.close)
            import msvcrt
            from multiprocessing.connection import Listener

            inherited_read, inherited_write = os.pipe()
            resources.callback(os.close, inherited_read)
            resources.callback(os.close, inherited_write)
            os.set_inheritable(inherited_write, True)
            inherited_handle = int(msvcrt.get_osfhandle(inherited_write))  # type: ignore[attr-defined]
            pipe_name = rf"\\.\pipe\master-agent-capsule-{secrets.token_hex(12)}"
            pipe_listener = Listener(address=pipe_name, family="AF_PIPE")
            resources.callback(pipe_listener.close)
            probes = (
                (
                    "os_host_file",
                    (
                        "from pathlib import Path\n"
                        f"p=Path({str(secret_path)!r})\n"
                        "try:\n p.read_bytes()\n"
                        "except PermissionError:\n print('DENIED')\n"
                        "else:\n print('ALLOWED')\n"
                    ),
                ),
                (
                    "os_ambient_secret",
                    (
                        "import os\n"
                        "print('DENIED' if "
                        "'MASTER_AGENT_AMBIENT_CAPSULE_SECRET' not in os.environ "
                        "else 'ALLOWED')\n"
                    ),
                ),
                ("os_network_ipv4", _network_probe_source("1.1.1.1", family=2)),
                (
                    "os_network_ipv6",
                    _network_probe_source(
                        "::1",
                        family=23,
                        port=int(ipv6_listener.getsockname()[1]),
                        listener_backed=True,
                    ),
                ),
                (
                    "os_network_localhost",
                    _network_probe_source(
                        "127.0.0.1",
                        family=2,
                        port=int(ipv4_listener.getsockname()[1]),
                        listener_backed=True,
                    ),
                ),
                (
                    "os_named_pipe",
                    (
                        "from multiprocessing.connection import Client\n"
                        "try:\n"
                        f" Client({pipe_name!r}, family='AF_PIPE').close()\n"
                        "except OSError:\n print('DENIED')\n"
                        "else:\n print('ALLOWED')\n"
                    ),
                ),
                (
                    "os_parent_handle",
                    (
                        "import _winapi\n"
                        "try:\n"
                        f" _winapi.GetFileType({inherited_handle})\n"
                        "except OSError:\n print('DENIED')\n"
                        "else:\n print('ALLOWED')\n"
                    ),
                ),
                (
                    "os_subprocess",
                    (
                        "import subprocess\n"
                        "try:\n"
                        f" subprocess.run([{str(Path(self._process.windows_directory()) / 'System32' / 'cmd.exe')!r},'/c','exit','0'],check=False)\n"
                        "except OSError:\n print('DENIED')\n"
                        "else:\n print('ALLOWED')\n"
                    ),
                ),
            )
            results: list[Mapping[str, str]] = []
            for name, source in probes:
                result = self._run_probe(projection, source=source)
                if (
                    result.reason is not ProcessExitReason.EXITED
                    or result.exit_code != 0
                    or result.output_truncated
                    or result.stdout.strip() != b"DENIED"
                ):
                    diagnostic = result.stdout.strip().decode(
                        "ascii", errors="backslashreplace"
                    )[:64]
                    suffix = f"_{diagnostic}" if diagnostic else ""
                    raise ProcessSupervisionError(
                        f"appcontainer_{name}_probe_failed{suffix}"
                    )
                results.append(MappingProxyType({"name": name, "status": "denied"}))
        return tuple(results)

    def _run_probe(
        self,
        projection: WindowsAppContainerProjection,
        *,
        source: str,
    ) -> ProcessExecutionResult:
        work = projection.profile_root / f"Probe-{secrets.token_hex(12)}"
        work.mkdir(exist_ok=False)
        owner_sid = canonicalize_windows_sid(self._filesystem.current_user_sid())
        self._set_sddl(
            work,
            _sddl(
                owner_sid=owner_sid,
                appcontainer_sid=projection.sid_string,
                writable=True,
            ),
        )
        environment = _build_minimal_environment(
            {
                "APPDATA": str(work),
                "LOCALAPPDATA": str(work),
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONNOUSERSITE": "1",
                "TEMP": str(work),
                "TMP": str(work),
                "USERPROFILE": str(work),
            },
            windows_directory=self._process.windows_directory(),
        )
        caught: BaseException | None = None
        try:
            return self._process.run_appcontainer(
                executable=projection.interpreter,
                arguments=_validate_arguments(("-I", "-S", "-c", source)),
                cwd=work,
                environment=environment,
                input_payload=b"",
                appcontainer_sid=projection.sid,
                timeout_seconds=3,
                cpu_seconds=2,
                memory_bytes=64 * 1024 * 1024,
                max_processes=1,
                max_output_bytes=4_096,
            )
        except BaseException as error:
            caught = error
            raise
        finally:
            try:
                _remove_tree(work)
            except OSError as cleanup_error:
                if caught is None:
                    raise ProcessSupervisionError(
                        "appcontainer_probe_cleanup_failed"
                    ) from cleanup_error

    def close(self, projection: WindowsAppContainerProjection) -> None:
        """Remove local state, delete the profile, and free its SID."""

        sid = ctypes.c_void_p(projection.sid)
        self._remove_profile_contents(projection.profile_name, sid)

    def _copy_runtime(self, *, runtime_root: Path, worker: Path) -> Path:
        base = Path(sys.base_prefix).resolve()
        runtime_counters = [0, 0, 0]
        source_interpreter = base / "python.exe"
        if not source_interpreter.is_file():
            raise ProcessSupervisionError("capsule_interpreter_unavailable")
        projected_interpreter = runtime_root / "python.exe"
        _copy_regular_file(source_interpreter, projected_interpreter)
        _consume_runtime_budget(projected_interpreter, runtime_counters)
        for source in sorted(base.iterdir(), key=lambda item: item.name.casefold()):
            name = source.name.casefold()
            if source.is_file() and (
                name.startswith(("python", "vcruntime"))
                and source.suffix.casefold() == ".dll"
            ):
                _copy_regular_file(source, runtime_root / source.name)
                _consume_runtime_budget(runtime_root / source.name, runtime_counters)
        for directory_name in ("DLLs", "Lib"):
            source_root = base / directory_name
            if not source_root.is_dir():
                raise ProcessSupervisionError("capsule_runtime_unavailable")
            _copy_runtime_directory(
                source_root,
                runtime_root / directory_name,
                counters=runtime_counters,
            )
        _copy_regular_file(worker, runtime_root / "capsule-worker.py")
        _consume_runtime_budget(runtime_root / "capsule-worker.py", runtime_counters)
        _tree_sha256(runtime_root)
        return projected_interpreter

    def _apply_tree_sddl(self, root: Path, sddl: str) -> None:
        paths = sorted(
            root.rglob("*"),
            key=lambda item: (len(item.parts), str(item).casefold()),
            reverse=True,
        )
        for path in paths:
            self._set_sddl(path, sddl)
        self._set_sddl(root, sddl)

    def _set_sddl(self, path: Path, sddl: str) -> None:
        if _file_attributes(self._kernel, path) & FILE_ATTRIBUTE_REPARSE_POINT:
            raise ProcessSupervisionError("capsule_runtime_reparse_prohibited")
        descriptor = ctypes.c_void_p()
        size = ctypes.c_uint32()
        if not self._advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl,
            _SDDL_REVISION_1,
            ctypes.byref(descriptor),
            ctypes.byref(size),
        ):
            raise OSError(_last_error(), "security descriptor conversion failed")
        try:
            security_information = (
                _OWNER_SECURITY_INFORMATION
                | _DACL_SECURITY_INFORMATION
                | _PROTECTED_DACL_SECURITY_INFORMATION
            )
            if not self._advapi.SetFileSecurityW(
                str(path),
                security_information,
                descriptor,
            ):
                raise OSError(_last_error(), "file security update failed")
        finally:
            self._kernel.LocalFree(descriptor)

    def _tree_security_sha256(self, root: Path) -> str:
        digest = hashlib.sha256()
        paths = (root, *sorted(root.rglob("*"), key=lambda item: str(item).casefold()))
        for path in paths:
            _require_safe_source(path)
            relative = "." if path == root else path.relative_to(root).as_posix()
            descriptor = self._security_descriptor(path)
            digest.update(relative.encode("utf-8") + b"\x00")
            digest.update(len(descriptor).to_bytes(8, "big") + descriptor)
        return digest.hexdigest()

    def _security_descriptor(self, path: Path) -> bytes:
        security_information = _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION
        needed = ctypes.c_uint32()
        self._advapi.GetFileSecurityW(
            str(path),
            security_information,
            None,
            0,
            ctypes.byref(needed),
        )
        if _last_error() != 122 or needed.value == 0:
            raise OSError(_last_error(), "file security size lookup failed")
        buffer = ctypes.create_string_buffer(needed.value)
        if not self._advapi.GetFileSecurityW(
            str(path),
            security_information,
            buffer,
            needed.value,
            ctypes.byref(needed),
        ):
            raise OSError(_last_error(), "file security lookup failed")
        return bytes(buffer.raw[: needed.value])

    def _sid_string(self, sid: int) -> str:
        selected = ctypes.c_wchar_p()
        if not self._advapi.ConvertSidToStringSidW(
            ctypes.c_void_p(sid), ctypes.byref(selected)
        ):
            raise OSError(_last_error(), "AppContainer SID conversion failed")
        try:
            value = selected.value
            if value is None:
                raise OSError("AppContainer SID conversion returned no value")
            return canonicalize_windows_sid(value)
        finally:
            self._kernel.LocalFree(ctypes.cast(selected, ctypes.c_void_p))

    def _profile_path(self, sid_string: str) -> Path:
        selected = ctypes.c_wchar_p()
        result = int(
            self._userenv.GetAppContainerFolderPath(
                sid_string,
                ctypes.byref(selected),
            )
        )
        if result != 0 or not selected.value:
            raise OSError(result, "AppContainer profile path lookup failed")
        try:
            if len(selected.value) > _MAX_PROFILE_PATH_CHARS:
                raise OSError("AppContainer profile path exceeds safety limit")
            path = Path(selected.value).absolute()
            if not path.is_absolute() or not path.is_dir():
                raise OSError("AppContainer profile path is invalid")
            return path
        finally:
            self._ole32.CoTaskMemFree(ctypes.cast(selected, ctypes.c_void_p))

    def _remove_profile_contents(self, profile_name: str, sid: ctypes.c_void_p) -> None:
        cleanup_error: OSError | None = None
        if sid.value:
            try:
                sid_string = self._sid_string(int(sid.value))
                profile_root = self._profile_path(sid_string)
                for child in tuple(profile_root.iterdir()):
                    _remove_tree(child)
            except OSError as error:
                cleanup_error = error
        result = int(self._userenv.DeleteAppContainerProfile(profile_name))
        if result != 0 and cleanup_error is None:
            cleanup_error = OSError(result, "AppContainer profile deletion failed")
        if sid.value:
            self._advapi.FreeSid(sid)
        if cleanup_error is not None:
            raise cleanup_error


def probe_windows_capsule_backend(
    *,
    filesystem: WindowsSecureFilesystemBackend,
    process: CtypesWindowsProcessApi,
) -> WindowsAppContainerCapsuleIsolationBackend:
    """Return a backend only after all native AppContainer symbols probe."""

    api = CtypesWindowsAppContainerApi(filesystem=filesystem, process=process)
    try:
        api.probe()
    except OSError as error:
        raise PlatformCapabilityUnavailable(
            WINDOWS_CAPSULE_UNAVAILABLE_REASON
        ) from error
    return WindowsAppContainerCapsuleIsolationBackend(api=api)


def _copy_runtime_directory(
    source: Path,
    destination: Path,
    *,
    copy_file: Callable[[Path, Path], None] | None = None,
    counters: list[int] | None = None,
) -> None:
    selected_counters = counters if counters is not None else [0, 0, 0]
    selected_copy_file = copy_file or _copy_regular_file

    def copy_directory(current: Path, selected: Path) -> None:
        _require_safe_source(current)
        selected.mkdir(exist_ok=False)
        for child in sorted(current.iterdir(), key=lambda item: item.name.casefold()):
            if child.name.casefold() in _RUNTIME_EXCLUDED_DIRECTORIES:
                continue
            selected_counters[2] += len(child.name.encode("utf-8"))
            if selected_counters[2] > _MAX_RUNTIME_PATH_BYTES:
                raise ProcessSupervisionError("capsule_runtime_path_budget_exceeded")
            target = selected / child.name
            if child.is_dir():
                copy_directory(child, target)
            elif child.is_file():
                selected_copy_file(child, target)
                _consume_runtime_budget(target, selected_counters)
            else:
                raise ProcessSupervisionError("capsule_runtime_entry_invalid")

    copy_directory(source, destination)


def _consume_runtime_budget(path: Path, counters: list[int]) -> None:
    counters[0] += 1
    counters[1] += path.stat().st_size
    if counters[0] > _MAX_RUNTIME_FILES:
        raise ProcessSupervisionError("capsule_runtime_file_budget_exceeded")
    if counters[1] > _MAX_RUNTIME_BYTES:
        raise ProcessSupervisionError("capsule_runtime_byte_budget_exceeded")


def _copy_regular_file(source: Path, destination: Path) -> None:
    _require_safe_source(source)
    if not source.is_file():
        raise ProcessSupervisionError("capsule_runtime_file_invalid")
    with source.open("rb") as reader, destination.open("xb") as writer:
        shutil.copyfileobj(reader, writer, length=1024 * 1024)


def _require_safe_source(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ProcessSupervisionError("capsule_runtime_unavailable") from error
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    if path.is_symlink() or attributes & FILE_ATTRIBUTE_REPARSE_POINT:
        raise ProcessSupervisionError("capsule_runtime_reparse_prohibited")


def _tree_sha256(root: Path) -> str:
    if not root.is_absolute() or not root.is_dir():
        raise ProcessSupervisionError("capsule_runtime_projection_invalid")
    digest = hashlib.sha256()
    files = 0
    total = 0
    path_bytes = 0
    for path in sorted(root.rglob("*"), key=lambda item: str(item).casefold()):
        _require_safe_source(path)
        relative = path.relative_to(root).as_posix()
        encoded_path = relative.encode("utf-8")
        path_bytes += len(encoded_path)
        if path_bytes > _MAX_RUNTIME_PATH_BYTES:
            raise ProcessSupervisionError("capsule_runtime_path_budget_exceeded")
        if path.is_dir():
            digest.update(b"d\x00" + encoded_path + b"\x00")
            continue
        if not path.is_file():
            raise ProcessSupervisionError("capsule_runtime_entry_invalid")
        files += 1
        size = path.stat().st_size
        total += size
        if files > _MAX_RUNTIME_FILES:
            raise ProcessSupervisionError("capsule_runtime_file_budget_exceeded")
        if total > _MAX_RUNTIME_BYTES:
            raise ProcessSupervisionError("capsule_runtime_byte_budget_exceeded")
        digest.update(b"f\x00" + encoded_path + b"\x00" + str(size).encode() + b"\x00")
        with path.open("rb") as handle:
            while block := handle.read(1024 * 1024):
                digest.update(block)
    return digest.hexdigest()


def _remove_tree(path: Path) -> None:
    if not path.exists():
        return
    attributes = int(getattr(path.lstat(), "st_file_attributes", 0))
    if path.is_symlink() or attributes & FILE_ATTRIBUTE_REPARSE_POINT:
        if attributes & _FILE_ATTRIBUTE_DIRECTORY:
            path.rmdir()
        else:
            path.unlink()
        return
    if path.is_dir():
        for child in tuple(path.iterdir()):
            _remove_tree(child)
        path.rmdir()
    else:
        path.unlink()


def _sddl(*, owner_sid: str, appcontainer_sid: str, writable: bool) -> str:
    app_rights = "FA" if writable else "GRGX"
    return (
        f"O:{owner_sid}G:{owner_sid}D:P"
        f"(A;;FA;;;{owner_sid})"
        f"(A;;FA;;;{LOCAL_SYSTEM_SID})"
        f"(A;;FA;;;{BUILTIN_ADMINISTRATORS_SID})"
        f"(A;;{app_rights};;;{appcontainer_sid})"
    )


def _private_sddl(*, owner_sid: str) -> str:
    return (
        f"O:{owner_sid}G:{owner_sid}D:P"
        f"(A;;FA;;;{owner_sid})"
        f"(A;;FA;;;{LOCAL_SYSTEM_SID})"
        f"(A;;FA;;;{BUILTIN_ADMINISTRATORS_SID})"
    )


def _network_probe_source(
    host: str,
    *,
    family: int,
    port: int = 9,
    listener_backed: bool = False,
) -> str:
    denied_codes: tuple[int, ...] = (10013, 10047, 10049, 10050, 10051)
    if listener_backed:
        denied_codes += (10060,)
    return (
        "import select,socket\n"
        f"denied={denied_codes!r}\n"
        "pending={10035,10036,10037}\n"
        "try:\n"
        f" s=socket.socket({family},socket.SOCK_STREAM)\n"
        " s.settimeout(1)\n"
        f" code=s.connect_ex(({host!r},{port}))\n"
        " if code in pending:\n"
        "  _,writable,exceptional=select.select([], [s], [s], 1)\n"
        "  code=(s.getsockopt(socket.SOL_SOCKET,socket.SO_ERROR) "
        "if writable or exceptional else 10060)\n"
        " s.close()\n"
        "except OSError as error:\n"
        " code=int(error.winerror or error.errno or 0)\n"
        "print('DENIED' if code in denied else f'UNEXPECTED_{code}')\n"
    )


def _loopback_listener(host: str, *, family: socket.AddressFamily) -> socket.socket:
    listener: socket.socket | None = None
    try:
        listener = socket.socket(family, socket.SOCK_STREAM)
        listener.bind((host, 0))
        listener.listen(1)
    except OSError as error:
        if listener is not None:
            listener.close()
        raise ProcessSupervisionError(
            "appcontainer_network_probe_listener_failed"
        ) from error
    assert listener is not None
    return listener


def _file_attributes(kernel: Any, path: Path) -> int:
    value = int(kernel.GetFileAttributesW(str(path)))
    if value == _INVALID_FILE_ATTRIBUTES:
        raise OSError(_last_error(), "file attribute lookup failed")
    return value


def _require_absolute_file(path: Path, label: str) -> None:
    if not isinstance(path, Path) or not path.is_absolute() or not path.is_file():
        raise ValueError(f"Windows capsule {label} path is invalid")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _last_error() -> int:
    getter = getattr(ctypes, "get_last_error", None)
    return int(getter()) if getter is not None else 0

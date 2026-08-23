"""Windows Job Object process-supervision tests for issue #103."""

from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any

from master_agent.platform_runtime import (
    PlatformContract,
    ProcessExecutionResult,
    ProcessExitReason,
    ProcessSupervisionError,
)
from master_agent.platform_runtime.windows import (
    WINDOWS_PROCESS_BACKEND_ID,
    WindowsProcessSupervisionBackend,
    build_windows_runtime,
)
from master_agent.platform_runtime.windows.process import (
    _PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
)

_SECRET = "ambient-process-secret-canary"


class _FakeProcessApi:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def probe(self) -> None:
        return None

    def windows_directory(self) -> str:
        return r"C:\Windows"

    def run(self, **kwargs: Any) -> ProcessExecutionResult:
        self.calls.append(kwargs)
        return ProcessExecutionResult(
            reason=ProcessExitReason.EXITED,
            exit_code=0,
            stdout=b"ok",
            stderr=b"",
            output_truncated=False,
        )


class _PolicyDeniedProcessApi(_FakeProcessApi):
    def run(self, **kwargs: Any) -> ProcessExecutionResult:
        self.calls.append(kwargs)
        raise OSError(f"application control denied {_SECRET}")


class WindowsProcessContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.api = _FakeProcessApi()
        self.backend = WindowsProcessSupervisionBackend(api=self.api)

    def test_appcontainer_security_attribute_uses_win32_thread_input_value(
        self,
    ) -> None:
        self.assertEqual(_PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, 0x00020009)

    def test_minimal_environment_and_explicit_handle_selection(self) -> None:
        previous = os.environ.get("MASTER_AGENT_AMBIENT_PROCESS_SECRET")
        os.environ["MASTER_AGENT_AMBIENT_PROCESS_SECRET"] = _SECRET
        self.addCleanup(self._restore_environment, previous)

        result = self.backend.run(
            executable=Path.cwd() / "runtime" / "python.exe",
            arguments=("-c", "print('ok')"),
            cwd=Path.cwd() / "work",
            environment={"PYTHONHASHSEED": "0"},
            inherited_handles=(41, 43),
            timeout_seconds=2,
            cpu_seconds=1,
            memory_bytes=128 * 1024 * 1024,
            max_processes=2,
            max_output_bytes=1024,
        )

        self.assertEqual(result.reason, ProcessExitReason.EXITED)
        call = self.api.calls[0]
        self.assertEqual(
            call["environment"],
            {
                "PYTHONHASHSEED": "0",
                "SystemRoot": r"C:\Windows",
                "WINDIR": r"C:\Windows",
            },
        )
        self.assertNotIn("MASTER_AGENT_AMBIENT_PROCESS_SECRET", call["environment"])
        self.assertEqual(call["inherited_handles"], (41, 43))
        self.assertEqual(self.backend.backend_id, WINDOWS_PROCESS_BACKEND_ID)

    def test_inputs_fail_closed_before_native_launch(self) -> None:
        common: dict[str, Any] = {
            "executable": Path.cwd() / "runtime" / "python.exe",
            "arguments": (),
            "cwd": Path.cwd() / "work",
            "environment": {},
            "timeout_seconds": 2,
            "cpu_seconds": 1,
            "memory_bytes": 1024,
            "max_processes": 1,
            "max_output_bytes": 1024,
        }
        cases = (
            {"executable": Path("python.exe")},
            {"arguments": ("bad\x00argument",)},
            {"environment": {"Path": "one", "PATH": "two"}},
            {"environment": {"SystemRoot": "shadow"}},
            {"inherited_handles": (12, 12)},
            {"timeout_seconds": 0},
            {"memory_bytes": 0},
        )
        for replacement in cases:
            with (
                self.subTest(replacement=replacement),
                self.assertRaises((TypeError, ValueError)),
            ):
                self.backend.run(**(common | replacement))
        self.assertEqual(self.api.calls, [])

    def test_apply_only_route_returns_bounded_typed_failure(self) -> None:
        with self.assertRaisesRegex(
            ProcessSupervisionError,
            "^process supervision failed: supervised_launch_required$",
        ) as raised:
            self.backend.apply_capsule_limits(
                cpu_seconds=1,
                memory_bytes=1024,
                max_processes=1,
                max_output_bytes=1024,
            )
        self.assertEqual(raised.exception.reason, "supervised_launch_required")
        self.assertNotIn(_SECRET, str(raised.exception))

    def test_policy_denial_is_bounded_and_secret_free(self) -> None:
        backend = WindowsProcessSupervisionBackend(api=_PolicyDeniedProcessApi())
        with self.assertRaises(ProcessSupervisionError) as raised:
            backend.run(
                executable=Path.cwd() / "runtime" / "blocked.exe",
                arguments=("--secret", _SECRET),
                cwd=Path.cwd() / "work",
                environment={"CANARY": _SECRET},
                timeout_seconds=2,
                cpu_seconds=1,
                memory_bytes=128 * 1024 * 1024,
                max_processes=1,
                max_output_bytes=1024,
            )
        self.assertEqual(raised.exception.reason, "native_control_failed")
        self.assertEqual(
            str(raised.exception),
            "process supervision failed: native_control_failed",
        )
        self.assertNotIn(_SECRET, str(raised.exception))

    def _restore_environment(self, previous: str | None) -> None:
        if previous is None:
            os.environ.pop("MASTER_AGENT_AMBIENT_PROCESS_SECRET", None)
        else:
            os.environ["MASTER_AGENT_AMBIENT_PROCESS_SECRET"] = previous


@unittest.skipUnless(sys.platform == "win32", "native Windows test")
class NativeWindowsProcessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = WindowsProcessSupervisionBackend()
        self.executable = Path(sys.executable).resolve()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.cwd = Path(self.temporary.name).resolve()

    def run_python(
        self,
        source: str,
        *,
        arguments: tuple[str, ...] = (),
        environment: dict[str, str] | None = None,
        inherited_handles: tuple[int, ...] = (),
        timeout_seconds: float = 10,
        memory_bytes: int = 256 * 1024 * 1024,
        max_processes: int = 4,
        max_output_bytes: int = 4096,
    ) -> ProcessExecutionResult:
        try:
            return self.backend.run(
                executable=self.executable,
                arguments=("-I", "-c", source, *arguments),
                cwd=self.cwd,
                environment=environment or {"PYTHONIOENCODING": "utf-8"},
                inherited_handles=inherited_handles,
                timeout_seconds=timeout_seconds,
                cpu_seconds=10,
                memory_bytes=memory_bytes,
                max_processes=max_processes,
                max_output_bytes=max_output_bytes,
            )
        except ProcessSupervisionError as error:
            self.fail(f"{error}; native_error_code={error.native_error_code}")

    def test_runtime_reports_native_backend_and_minimal_environment(self) -> None:
        runtime = build_windows_runtime()
        status = runtime.status.contract_status(PlatformContract.PROCESS_SUPERVISION)
        self.assertTrue(status.available)
        self.assertEqual(status.backend, WINDOWS_PROCESS_BACKEND_ID)

        result = self.run_python(
            "import os; print(os.environ.get('ALLOWED_VALUE')); "
            "print(os.environ.get('MASTER_AGENT_AMBIENT_PROCESS_SECRET'))",
            environment={"ALLOWED_VALUE": "selected"},
        )
        self.assertEqual(result.reason, ProcessExitReason.EXITED)
        self.assertEqual(result.stdout.replace(b"\r\n", b"\n"), b"selected\nNone\n")

    def test_only_selected_native_handle_reaches_child(self) -> None:
        import msvcrt

        selected_read, selected_write = os.pipe()
        withheld_read, withheld_write = os.pipe()
        self.addCleanup(os.close, selected_read)
        self.addCleanup(os.close, selected_write)
        self.addCleanup(os.close, withheld_read)
        self.addCleanup(os.close, withheld_write)
        os.set_inheritable(selected_write, True)
        os.set_inheritable(withheld_write, True)
        get_osfhandle = msvcrt.get_osfhandle  # type: ignore[attr-defined]
        selected = int(get_osfhandle(selected_write))
        withheld = int(get_osfhandle(withheld_write))
        source = (
            "import ctypes,sys; from ctypes import wintypes; "
            "k=ctypes.WinDLL('kernel32',use_last_error=True); "
            "k.GetHandleInformation.argtypes=(wintypes.HANDLE,ctypes.POINTER(wintypes.DWORD)); "
            "k.GetHandleInformation.restype=wintypes.BOOL; "
            "f=lambda h: int(bool(k.GetHandleInformation(int(h),ctypes.byref(wintypes.DWORD())))); "
            "print(f(sys.argv[1]),f(sys.argv[2]),sep=',')"
        )
        result = self.run_python(
            source,
            arguments=(str(selected), str(withheld)),
            inherited_handles=(selected,),
        )
        self.assertEqual(result.reason, ProcessExitReason.EXITED)
        self.assertEqual(result.stdout.strip(), b"1,0")

    def test_timeout_terminates_descendant_tree(self) -> None:
        marker = self.cwd / "descendant-survived.txt"
        descendant = (
            "import pathlib,sys,time; time.sleep(3); "
            "pathlib.Path(sys.argv[1]).write_text('survived',encoding='utf-8')"
        )
        parent = (
            "import subprocess,sys,time; "
            "subprocess.Popen([sys.executable,'-I','-c',sys.argv[1],sys.argv[2]]); "
            "time.sleep(30)"
        )
        result = self.run_python(
            parent,
            arguments=(descendant, str(marker)),
            timeout_seconds=0.5,
        )
        self.assertEqual(result.reason, ProcessExitReason.TIMED_OUT)
        self.assertIsNone(result.exit_code)
        time.sleep(4)
        self.assertFalse(marker.exists())

    def test_process_count_and_memory_limits_are_enforced(self) -> None:
        child = "import subprocess,sys; subprocess.run([sys.executable,'-I','-c','pass'],check=True)"
        process_result = self.run_python(
            child,
            max_processes=1,
        )
        self.assertEqual(process_result.reason, ProcessExitReason.NONZERO_EXIT)

        memory = (
            "import sys; "
            "\ntry: bytearray(512*1024*1024)"
            "\nexcept MemoryError: print('blocked'); raise SystemExit(0)"
            "\nraise SystemExit(9)"
        )
        memory_result = self.run_python(memory, memory_bytes=256 * 1024 * 1024)
        self.assertIn(
            memory_result.reason,
            (ProcessExitReason.EXITED, ProcessExitReason.NONZERO_EXIT),
        )
        if memory_result.reason is ProcessExitReason.EXITED:
            self.assertEqual(memory_result.stdout.strip(), b"blocked")

    def test_output_is_bounded_and_failure_reason_is_secret_free(self) -> None:
        result = self.run_python(
            "import sys; sys.stdout.write('x'*10000); "
            f"sys.stderr.write({_SECRET!r}); raise SystemExit(7)",
            max_output_bytes=128,
        )
        self.assertEqual(result.reason, ProcessExitReason.NONZERO_EXIT)
        self.assertEqual(result.exit_code, 7)
        self.assertLessEqual(len(result.stdout) + len(result.stderr), 128)
        self.assertTrue(result.output_truncated)
        self.assertNotIn(_SECRET, str(result.reason))

    def test_unicode_console_output_is_explicit_utf8(self) -> None:
        result = self.run_python(
            "import sys; print('stdout-Δ-文-🙂'); print('stderr-ß-é', file=sys.stderr)",
            environment={
                "PYTHONIOENCODING": "utf-8",
                "PYTHONUTF8": "1",
            },
        )
        self.assertEqual(result.reason, ProcessExitReason.EXITED)
        self.assertEqual(
            result.stdout.replace(b"\r\n", b"\n"),
            "stdout-Δ-文-🙂\n".encode(),
        )
        self.assertEqual(
            result.stderr.replace(b"\r\n", b"\n"),
            "stderr-ß-é\n".encode(),
        )


if __name__ == "__main__":
    unittest.main()

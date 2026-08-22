"""Windows AppContainer capability-capsule tests for issue #104."""

from __future__ import annotations

import sys
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from master_agent.capsule_runtime import CapsuleWorker
from master_agent.errors import ConnectorError
from master_agent.platform_runtime import (
    ProcessExecutionResult,
    ProcessExitReason,
    ProcessSupervisionError,
)
from master_agent.platform_runtime.windows import (
    WINDOWS_CAPSULE_BACKEND_ID,
    WindowsAppContainerCapsuleIsolationBackend,
    WindowsAppContainerProjection,
)
from master_agent.platform_runtime.windows.capsules import (
    _copy_runtime_directory,
    _network_probe_source,
    _sddl,
    _tree_sha256,
)

CURRENT_SID = "S-1-5-21-100-200-300-1001"
APP_SID = "S-1-15-2-1234567890"


class _FakeAppContainerApi:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.prepare_calls = 0
        self.identity_calls = 0
        self.run_calls: list[dict[str, Any]] = []
        self.closed = False

    def probe(self) -> None:
        return None

    def prepare(
        self,
        *,
        worker: Path,
        interpreter: Path,
    ) -> WindowsAppContainerProjection:
        self.prepare_calls += 1
        runtime = self.root / "Runtime"
        runtime.mkdir(exist_ok=True)
        projected_worker = runtime / "capsule-worker.py"
        projected_interpreter = runtime / "python.exe"
        projected_worker.write_bytes(worker.read_bytes())
        projected_interpreter.write_bytes(interpreter.read_bytes())
        return WindowsAppContainerProjection(
            profile_name="MasterAgent.Capsule.Test",
            sid=42,
            sid_string=APP_SID,
            profile_root=self.root,
            runtime_root=runtime,
            interpreter=projected_interpreter,
            worker=projected_worker,
            source_interpreter_sha256="a" * 64,
            source_worker_sha256="b" * 64,
            runtime_sha256="c" * 64,
            runtime_security_sha256="d" * 64,
        )

    def identity_components(
        self,
        projection: WindowsAppContainerProjection,
        *,
        worker: Path,
        interpreter: Path,
    ) -> Mapping[str, str | None]:
        del projection, worker, interpreter
        self.identity_calls += 1
        return {
            "backend": WINDOWS_CAPSULE_BACKEND_ID,
            "worker_sha256": "b" * 64,
            "runtime_sha256": "c" * 64,
        }

    def run(
        self,
        projection: WindowsAppContainerProjection,
        **kwargs: Any,
    ) -> ProcessExecutionResult:
        del projection
        self.run_calls.append(kwargs)
        return ProcessExecutionResult(
            reason=ProcessExitReason.EXITED,
            exit_code=0,
            stdout=b'{"schema":"master-agent/capsule-worker@1","ok":true,"output":{}}',
            stderr=b"",
            output_truncated=False,
        )

    def denial_probes(
        self,
        projection: WindowsAppContainerProjection,
    ) -> Sequence[Mapping[str, str]]:
        del projection
        return ({"name": "os_host_file", "status": "denied"},)

    def close(self, projection: WindowsAppContainerProjection) -> None:
        del projection
        self.closed = True


class WindowsAppContainerContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.worker = self.root / "worker.py"
        self.interpreter = self.root / "host-python.exe"
        self.worker.write_text("pass\n", encoding="utf-8")
        self.interpreter.write_bytes(b"host interpreter")
        self.api = _FakeAppContainerApi(self.root / "profile")
        self.api.root.mkdir()
        self.backend = WindowsAppContainerCapsuleIsolationBackend(api=self.api)
        self.addCleanup(self.backend.close)

    def test_backend_reuses_projection_and_revalidates_before_every_action(
        self,
    ) -> None:
        identity = self.backend.identity_components(
            worker=self.worker,
            interpreter=self.interpreter,
        )
        result = self.backend.run_worker(
            worker=self.worker,
            interpreter=self.interpreter,
            request=b"request",
            environment={"PYTHONHASHSEED": "0"},
            timeout_seconds=2,
            cpu_seconds=1,
            memory_bytes=64 * 1024 * 1024,
            max_processes=1,
            max_output_bytes=4096,
        )
        probes = self.backend.denial_probes(
            worker=self.worker,
            interpreter=self.interpreter,
        )

        self.assertEqual(identity["backend"], WINDOWS_CAPSULE_BACKEND_ID)
        self.assertEqual(result.reason, ProcessExitReason.EXITED)
        self.assertEqual(probes[0], {"name": "os_host_file", "status": "denied"})
        self.assertEqual(self.api.prepare_calls, 1)
        self.assertEqual(self.api.identity_calls, 3)
        self.assertTrue(self.backend.production_isolated)
        self.assertIsNone(self.backend.executable)

    def test_close_deletes_only_the_retained_projection(self) -> None:
        self.backend.identity_components(
            worker=self.worker,
            interpreter=self.interpreter,
        )
        self.backend.close()
        self.backend.close()
        self.assertTrue(self.api.closed)

    def test_acl_policy_has_no_broad_principal_and_separates_write_access(self) -> None:
        readonly = _sddl(
            owner_sid=CURRENT_SID,
            appcontainer_sid=APP_SID,
            writable=False,
        )
        writable = _sddl(
            owner_sid=CURRENT_SID,
            appcontainer_sid=APP_SID,
            writable=True,
        )

        self.assertIn(f"(A;;GRGX;;;{APP_SID})", readonly)
        self.assertIn(f"(A;;FA;;;{APP_SID})", writable)
        for unsafe_sid in (";;;WD)", ";;;AU)", ";;;BU)"):
            self.assertNotIn(unsafe_sid, readonly)
            self.assertNotIn(unsafe_sid, writable)

    def test_projection_digest_is_deterministic_and_detects_tamper(self) -> None:
        runtime = self.root / "digest-runtime"
        nested = runtime / "Lib"
        nested.mkdir(parents=True)
        (runtime / "python.exe").write_bytes(b"python")
        artifact = nested / "module.py"
        artifact.write_bytes(b"first")

        first = _tree_sha256(runtime)
        second = _tree_sha256(runtime)
        artifact.write_bytes(b"second")

        self.assertEqual(first, second)
        self.assertNotEqual(first, _tree_sha256(runtime))

    def test_projection_copy_rejects_symlink_or_reparse_source(self) -> None:
        source = self.root / "source"
        source.mkdir()
        target = self.root / "outside.py"
        target.write_text("pass\n", encoding="utf-8")
        link = source / "link.py"
        try:
            link.symlink_to(target)
        except OSError:
            self.skipTest("symlink creation is unavailable")

        with self.assertRaisesRegex(
            ProcessSupervisionError,
            "capsule_runtime_reparse_prohibited",
        ):
            _copy_runtime_directory(source, self.root / "destination")

    def test_network_probes_require_native_access_denied_code(self) -> None:
        source = _network_probe_source("127.0.0.1", family=2)
        self.assertIn("10013", source)
        self.assertIn("10047", source)
        self.assertNotIn("10061", source)
        self.assertIn("except OSError", source)
        self.assertIn("UNEXPECTED_{code}", source)


@unittest.skipUnless(sys.platform == "win32", "native Windows test")
class NativeWindowsAppContainerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.worker = CapsuleWorker()
        backend = self.worker._isolation_backend
        if backend is not None and hasattr(backend, "close"):
            self.addCleanup(backend.close)  # type: ignore[attr-defined]

    def test_pure_worker_and_native_denial_suite(self) -> None:
        output = self.worker.execute_program(
            source=b'def run(request):\n    return {"value": request["value"] + 1}\n',
            request={"value": 2},
            max_input_bytes=4096,
            max_output_bytes=4096,
            timeout_seconds=2,
            cpu_seconds=1,
            memory_bytes=128 * 1024 * 1024,
            max_processes=1,
        )
        probes = self.worker.denial_probes()

        self.assertEqual(output, {"value": 3})
        self.assertEqual(self.worker.backend, WINDOWS_CAPSULE_BACKEND_ID)
        self.assertTrue(self.worker.production_isolated)
        self.assertEqual(
            {item["name"] for item in probes},
            {
                "os_host_file",
                "os_ambient_secret",
                "os_network_ipv4",
                "os_network_ipv6",
                "os_network_localhost",
                "os_subprocess",
            },
        )
        self.assertTrue(all(item["status"] == "denied" for item in probes))

    def test_runtime_identity_tamper_fails_closed(self) -> None:
        _ = self.worker.identity_components
        backend = self.worker._isolation_backend
        projection = getattr(backend, "_projection", None)
        self.assertIsNotNone(projection)
        assert projection is not None
        projection.worker.write_bytes(projection.worker.read_bytes() + b"\n# tamper\n")

        with self.assertRaisesRegex(
            ProcessSupervisionError,
            "capsule_runtime_identity_changed",
        ):
            _ = self.worker.identity_components

    def test_runtime_dacl_tamper_fails_closed(self) -> None:
        _ = self.worker.identity_components
        backend = self.worker._isolation_backend
        projection = getattr(backend, "_projection", None)
        api = getattr(backend, "_api", None)
        self.assertIsNotNone(projection)
        self.assertIsNotNone(api)
        assert projection is not None and api is not None
        api._set_sddl(  # type: ignore[attr-defined]
            projection.worker,
            _sddl(
                owner_sid=api._filesystem.current_user_sid(),  # type: ignore[attr-defined]
                appcontainer_sid=projection.sid_string,
                writable=True,
            ),
        )

        with self.assertRaisesRegex(
            ProcessSupervisionError,
            "capsule_runtime_identity_changed",
        ):
            _ = self.worker.identity_components

    def test_worker_output_and_wall_time_limits_fail_closed(self) -> None:
        with self.assertRaisesRegex(
            ConnectorError,
            "output exceeded quota|output_too_large",
        ):
            self.worker.execute_program(
                source=(
                    b'def run(request):\n    return {"value": "x" * request["size"]}\n'
                ),
                request={"size": 128 * 1024},
                max_input_bytes=4096,
                max_output_bytes=128,
                timeout_seconds=2,
                cpu_seconds=1,
                memory_bytes=128 * 1024 * 1024,
                max_processes=1,
            )
        with self.assertRaisesRegex(ConnectorError, "timed out|malformed"):
            self.worker.execute_program(
                source=b"def run(request):\n    while True:\n        pass\n",
                request={},
                max_input_bytes=4096,
                max_output_bytes=4096,
                timeout_seconds=1,
                cpu_seconds=2,
                memory_bytes=128 * 1024 * 1024,
                max_processes=1,
            )


if __name__ == "__main__":
    unittest.main()

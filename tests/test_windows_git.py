"""Native Windows trusted-Git tests for issue #102."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Self

from master_agent.platform_runtime import (
    PlatformContract,
    ProcessExecutionResult,
    ProcessExitReason,
    TrustedGitError,
)
from master_agent.platform_runtime.posix.git import PosixTrustedGitBackend
from master_agent.platform_runtime.windows import (
    WINDOWS_GIT_BACKEND_ID,
    WindowsObjectIdentity,
    WindowsObjectKind,
    WindowsTrustedGitBackend,
    build_windows_runtime,
)

_SECRET = "ambient-windows-git-secret-canary"


def _fixture_path(value: str) -> Path:
    """Return one absolute fixture path on POSIX and native Windows."""

    if sys.platform == "win32":
        return Path("C:" + value.replace("/", "\\"))
    return Path(value)


def _identity(kind: WindowsObjectKind) -> WindowsObjectIdentity:
    return WindowsObjectIdentity(
        volume_serial_number=7,
        file_id=bytes([1 if kind is WindowsObjectKind.FILE else 2]) * 16,
        owner_sid="S-1-5-21-1-2-3-1001",
        dacl_sha256="a" * 64,
        trust_policy_sha256="b" * 64,
        kind=kind,
    )


class _FakePin:
    def __init__(
        self,
        path: Path,
        *,
        directory: bool,
        payload: bytes = b"",
        children: dict[str, _FakePin] | None = None,
    ) -> None:
        self.path = path
        self.identity = _identity(
            WindowsObjectKind.DIRECTORY if directory else WindowsObjectKind.FILE
        )
        self._payload = payload
        self._children = children or {}
        self.closed = False
        self.validations = 0

    @property
    def size(self) -> int:
        return len(self._payload)

    def read_bytes(self, maximum: int) -> bytes:
        if len(self._payload) > maximum:
            raise ValueError("too large")
        return self._payload

    def list_children(self) -> tuple[str, ...]:
        return tuple(self._children)

    def pin_child(self, name: str, **_: Any) -> _FakePin:
        return self._children[name]

    def validate(self) -> None:
        if self.closed:
            raise ValueError("closed")
        self.validations += 1

    def close(self) -> None:
        self.closed = True

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class _FakeFilesystem:
    def __init__(self, executable: _FakePin, repository: _FakePin) -> None:
        self.executable = executable
        self.repository = repository

    def pin_file(self, _: Path, **__: Any) -> _FakePin:
        return self.executable

    def pin_directory(self, _: Path, **__: Any) -> _FakePin:
        return self.repository


class _FakeProcess:
    backend_id = "fake-process"

    def __init__(self, outputs: list[ProcessExecutionResult]) -> None:
        self.outputs = outputs
        self.calls: list[dict[str, Any]] = []

    def run(self, **kwargs: Any) -> ProcessExecutionResult:
        self.calls.append(kwargs)
        return self.outputs.pop(0)

    def apply_capsule_limits(self, **_: Any) -> None:
        return None


def _result(
    stdout: bytes,
    *,
    reason: ProcessExitReason = ProcessExitReason.EXITED,
    exit_code: int | None = 0,
    truncated: bool = False,
) -> ProcessExecutionResult:
    return ProcessExecutionResult(
        reason=reason,
        exit_code=exit_code,
        stdout=stdout,
        stderr=b"hostile diagnostic " + _SECRET.encode(),
        output_truncated=truncated,
    )


class WindowsTrustedGitContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.executable = _FakePin(
            _fixture_path("/trusted/Git/cmd/git.exe"),
            directory=False,
            payload=b"MZ trusted executable",
        )
        config = _FakePin(
            _fixture_path("/repo/.git/config"),
            directory=False,
            payload=b"[core]\nrepositoryformatversion = 0\n",
        )
        head = _FakePin(
            _fixture_path("/repo/.git/HEAD"), directory=False, payload=b"ref"
        )
        index = _FakePin(
            _fixture_path("/repo/.git/index"), directory=False, payload=b"index"
        )
        info = _FakePin(_fixture_path("/repo/.git/objects/info"), directory=True)
        objects = _FakePin(
            _fixture_path("/repo/.git/objects"),
            directory=True,
            children={"info": info},
        )
        refs = _FakePin(_fixture_path("/repo/.git/refs"), directory=True)
        self.git = _FakePin(
            _fixture_path("/repo/.git"),
            directory=True,
            children={
                "config": config,
                "HEAD": head,
                "index": index,
                "objects": objects,
                "refs": refs,
            },
        )
        self.repository = _FakePin(
            _fixture_path("/repo"),
            directory=True,
            children={".git": self.git},
        )

    def backend(self, process: _FakeProcess) -> WindowsTrustedGitBackend:
        return WindowsTrustedGitBackend(
            filesystem=_FakeFilesystem(  # type: ignore[arg-type]
                self.executable,
                self.repository,
            ),
            process=process,
            executable=self.executable.path,
        )

    def test_pins_identity_and_runs_with_minimal_hardened_context(self) -> None:
        process = _FakeProcess(
            [_result(b"core.repositoryformatversion\x00"), _result(b"clean\n")]
        )
        previous = os.environ.get("MASTER_AGENT_AMBIENT_GIT_SECRET")
        os.environ["MASTER_AGENT_AMBIENT_GIT_SECRET"] = _SECRET
        self.addCleanup(self._restore_environment, previous)
        backend = self.backend(process)
        self.addCleanup(backend.close)

        output = backend.read(
            self.repository.path,
            ("status", "--porcelain=v1"),
            timeout_seconds=10,
            max_output_bytes=4096,
        )

        self.assertEqual(output, b"clean\n")
        self.assertEqual(backend.backend_id, WINDOWS_GIT_BACKEND_ID)
        self.assertEqual(
            backend.executable_binding.to_dict()["sha256"],
            "a8b95a6896e6d493602c3bfb9639df21a6daa4f0cb81d0162f87a60edc15c0a1",
        )
        self.assertEqual(len(process.calls), 2)
        actual = process.calls[-1]
        self.assertEqual(actual["executable"], self.executable.path)
        self.assertEqual(actual["cwd"], self.repository.path)
        self.assertIn("--no-optional-locks", actual["arguments"])
        self.assertIn("-c", actual["arguments"])
        self.assertIn("protocol.allow=never", actual["arguments"])
        self.assertIn("--ignore-submodules=all", actual["arguments"])
        self.assertNotIn("MASTER_AGENT_AMBIENT_GIT_SECRET", actual["environment"])
        self.assertEqual(actual["environment"]["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(actual["environment"]["GCM_INTERACTIVE"], "Never")
        self.assertNotIn("NUL", actual["environment"].values())
        self.assertTrue(Path(actual["environment"]["GIT_CONFIG_GLOBAL"]).is_file())

    def test_prohibited_configuration_stops_before_requested_command(self) -> None:
        process = _FakeProcess([_result(b"include.path\x00")])
        backend = self.backend(process)
        self.addCleanup(backend.close)

        with self.assertRaisesRegex(
            TrustedGitError,
            "^trusted Git inspection failed: configuration_prohibited$",
        ):
            backend.read(
                self.repository.path,
                ("rev-parse", "--verify", "--end-of-options", "HEAD^{commit}"),
                timeout_seconds=10,
                max_output_bytes=4096,
            )
        self.assertEqual(len(process.calls), 1)

    def test_diff_safety_options_precede_literal_pathspec_separator(self) -> None:
        process = _FakeProcess(
            [_result(b"core.repositoryformatversion\x00"), _result(b"")]
        )
        backend = self.backend(process)
        self.addCleanup(backend.close)

        backend.read(
            self.repository.path,
            ("diff", "--binary", "--", ":(literal)nested/file.txt"),
            timeout_seconds=10,
            max_output_bytes=4096,
        )

        arguments = process.calls[-1]["arguments"]
        separator = arguments.index("--")
        self.assertLess(arguments.index("--no-ext-diff"), separator)
        self.assertLess(arguments.index("--no-textconv"), separator)
        self.assertLess(arguments.index("--ignore-submodules=all"), separator)
        self.assertEqual(arguments[separator + 1 :], (":(literal)nested/file.txt",))

    def test_lock_contention_stops_before_process_launch(self) -> None:
        self.git._children["INDEX.LOCK"] = _FakePin(
            _fixture_path("/repo/.git/INDEX.LOCK"),
            directory=False,
        )
        process = _FakeProcess([])
        backend = self.backend(process)
        self.addCleanup(backend.close)

        with self.assertRaisesRegex(TrustedGitError, "repository_busy"):
            backend.read(
                self.repository.path,
                ("ls-files", "-z"),
                timeout_seconds=10,
                max_output_bytes=4096,
            )
        self.assertEqual(process.calls, [])

    def test_mutating_or_converting_commands_are_rejected(self) -> None:
        backend = self.backend(_FakeProcess([]))
        self.addCleanup(backend.close)
        cases = (
            ("commit", "-m", "unsafe"),
            ("push", "origin", "main"),
            ("config", "--local", "review.owned", "true"),
            ("-c", "alias.pwn=!echo unsafe", "pwn"),
            ("cat-file", "--filters", "HEAD:file"),
            ("ls-files", "--recurse-submodules"),
            ("diff", "--no-index", "C:\\outside-a", "C:\\outside-b"),
            ("diff", "--output=C:\\outside.patch", "HEAD"),
            ("diff", "--ext-diff", "--textconv", "HEAD"),
            ("status", "--ignore-submodules=none"),
        )
        for arguments in cases:
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                backend.read(
                    self.repository.path,
                    arguments,
                    timeout_seconds=10,
                    max_output_bytes=4096,
                )

    def test_repository_redirection_metadata_is_rejected_before_launch(self) -> None:
        cases = (
            (
                "commondir",
                self.git,
                _FakePin(
                    _fixture_path("/repo/.git/commondir"),
                    directory=False,
                    payload=b"..",
                ),
            ),
            (
                "alternates",
                self.git._children["objects"]._children["info"],
                _FakePin(
                    _fixture_path("/repo/.git/objects/info/alternates"),
                    directory=False,
                    payload=b"C:\\outside\\objects",
                ),
            ),
        )
        for name, parent, child in cases:
            with self.subTest(name=name):
                parent._children[name] = child
                process = _FakeProcess([])
                backend = self.backend(process)
                self.addCleanup(backend.close)
                with self.assertRaisesRegex(
                    TrustedGitError, "repository_redirection_prohibited"
                ):
                    backend.read(
                        self.repository.path,
                        ("status", "--porcelain=v1"),
                        timeout_seconds=10,
                        max_output_bytes=4096,
                    )
                self.assertEqual(process.calls, [])
                del parent._children[name]

    def test_case_conflicting_git_directory_is_rejected(self) -> None:
        self.repository._children[".GIT"] = _FakePin(
            _fixture_path("/repo/.GIT"),
            directory=True,
        )
        process = _FakeProcess([])
        backend = self.backend(process)
        self.addCleanup(backend.close)

        with self.assertRaisesRegex(TrustedGitError, "case_collision"):
            backend.read(
                self.repository.path,
                ("status", "--porcelain=v1"),
                timeout_seconds=10,
                max_output_bytes=4096,
            )
        self.assertEqual(process.calls, [])

    def test_child_diagnostics_never_enter_failure_text(self) -> None:
        process = _FakeProcess(
            [
                _result(b"core.repositoryformatversion\x00"),
                _result(
                    b"",
                    reason=ProcessExitReason.NONZERO_EXIT,
                    exit_code=1,
                ),
            ]
        )
        backend = self.backend(process)
        self.addCleanup(backend.close)

        with self.assertRaises(TrustedGitError) as raised:
            backend.read(
                self.repository.path,
                ("diff", "--binary"),
                timeout_seconds=10,
                max_output_bytes=4096,
            )
        self.assertEqual(raised.exception.reason, "nonzero_exit")
        self.assertNotIn(_SECRET, str(raised.exception))

    def _restore_environment(self, previous: str | None) -> None:
        if previous is None:
            os.environ.pop("MASTER_AGENT_AMBIENT_GIT_SECRET", None)
        else:
            os.environ["MASTER_AGENT_AMBIENT_GIT_SECRET"] = previous


class PosixTrustedGitContractTests(unittest.TestCase):
    def test_public_backend_rejects_mutation_alias_and_unsafe_diff_vectors(
        self,
    ) -> None:
        backend = PosixTrustedGitBackend()
        for arguments in (
            ("config", "--local", "review.owned", "true"),
            ("-c", "alias.pwn=!echo unsafe", "pwn"),
            ("diff", "--no-index", "/etc/hosts", "/etc/shells"),
            ("diff", "--output=/tmp/unsafe.patch", "HEAD"),
            ("diff", "--ext-diff", "HEAD"),
        ):
            with (
                self.subTest(arguments=arguments),
                self.assertRaisesRegex(ValueError, "trusted Git"),
            ):
                backend.read(
                    Path("/absolute/repository"),
                    arguments,
                    timeout_seconds=10,
                    max_output_bytes=4096,
                )


@unittest.skipUnless(sys.platform == "win32", "native Windows test")
class NativeWindowsTrustedGitTests(unittest.TestCase):
    def setUp(self) -> None:
        runtime = build_windows_runtime()
        status = runtime.status.contract_status(PlatformContract.TRUSTED_GIT)
        self.assertTrue(status.available, status.reason)
        self.assertEqual(status.backend, WINDOWS_GIT_BACKEND_ID)
        self.backend = runtime.require_trusted_git()
        self.addCleanup(self.backend.close)

    def test_repository_status_diff_and_object_reads(self) -> None:
        with tempfile.TemporaryDirectory(prefix="git native reads ") as raw:
            repository = Path(raw).resolve()
            self._initialize_repository(repository, "native.txt")
            head = self.backend.read(
                repository,
                ("rev-parse", "--verify", "--end-of-options", "HEAD^{commit}"),
                timeout_seconds=20,
                max_output_bytes=4096,
            )
            revision = head.decode("ascii").strip()
            status = self.backend.read(
                repository,
                ("status", "--porcelain=v1", "-z"),
                timeout_seconds=20,
                max_output_bytes=4 * 1024 * 1024,
            )
            diff = self.backend.read(
                repository,
                ("diff", "--binary"),
                timeout_seconds=20,
                max_output_bytes=4 * 1024 * 1024,
            )
            commit = self.backend.read(
                repository,
                ("cat-file", "commit", revision),
                timeout_seconds=20,
                max_output_bytes=4096,
            )

            self.assertRegex(revision, r"^[0-9a-f]{40,64}$")
            self.assertIsInstance(status, bytes)
            self.assertIsInstance(diff, bytes)
            self.assertIn(b"tree ", commit)

    def test_spaces_unicode_and_index_contention(self) -> None:
        with tempfile.TemporaryDirectory(prefix="git space unicode é ") as raw:
            repository = Path(raw).resolve()
            self._initialize_repository(repository, "unicode-é.txt")
            output = self.backend.read(
                repository,
                ("ls-files", "-z"),
                timeout_seconds=20,
                max_output_bytes=4096,
            )
            self.assertIn("unicode-é.txt".encode(), output)
            lock = repository / ".git" / "index.lock"
            lock.write_bytes(b"")
            with self.assertRaisesRegex(TrustedGitError, "repository_busy"):
                self.backend.read(
                    repository,
                    ("status", "--porcelain=v1"),
                    timeout_seconds=20,
                    max_output_bytes=4096,
                )

    def _initialize_repository(self, repository: Path, filename: str) -> None:
        subprocess.run(("git", "init", "--quiet"), cwd=repository, check=True)
        subprocess.run(
            ("git", "config", "user.name", "MasterAgent Test"),
            cwd=repository,
            check=True,
        )
        subprocess.run(
            ("git", "config", "user.email", "test@example.invalid"),
            cwd=repository,
            check=True,
        )
        (repository / filename).write_text("line\n", encoding="utf-8")
        subprocess.run(("git", "add", "."), cwd=repository, check=True)
        subprocess.run(
            ("git", "commit", "--quiet", "-m", "fixture"),
            cwd=repository,
            check=True,
        )
        config_result = subprocess.run(
            (
                str(self.backend._require_open().path),
                "--no-pager",
                "config",
                "--file",
                str(repository / ".git" / "config"),
                "--no-includes",
                "--null",
                "--name-only",
                "--list",
            ),
            cwd=self.backend._home,
            env=self.backend._environment(),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
        )
        self.assertEqual(
            config_result.returncode,
            0,
            config_result.stderr.decode("utf-8", errors="replace"),
        )


if __name__ == "__main__":
    unittest.main()

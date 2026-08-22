"""Native Windows trusted-Git discovery and read-only execution."""

from __future__ import annotations

import hashlib
import sys
import tempfile
from collections.abc import Sequence
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Protocol, Self

from master_agent.errors import ConfigurationError
from master_agent.platform_runtime.contracts import (
    PlatformCapabilityUnavailable,
    ProcessExitReason,
    ProcessSupervisionBackend,
    ProcessSupervisionError,
    TrustedGitError,
    harden_trusted_git_command,
    validate_trusted_git_request,
)
from master_agent.platform_runtime.windows.filesystem import (
    MAX_PINNED_READ_BYTES,
    PinnedWindowsPath,
    WindowsObjectIdentity,
    WindowsSecureFilesystemBackend,
)

WINDOWS_GIT_BACKEND_ID: Final = "windows-trusted-git"
WINDOWS_GIT_UNAVAILABLE_REASON: Final = (
    "trusted Git for Windows executable is unavailable"
)

_MAX_CONFIG_BYTES = 4 * 1024 * 1024
_MAX_RETAINED_REPOSITORY_OBJECTS = 8192
_MAX_REPOSITORY_METADATA_DEPTH = 16
_DANGEROUS_EXACT_KEYS = frozenset(
    {
        "core.alternaterefscommand",
        "core.askpass",
        "core.attributesfile",
        "core.editor",
        "core.fsmonitor",
        "core.gitproxy",
        "core.hookspath",
        "core.pager",
        "core.sshcommand",
        "core.worktree",
        "diff.external",
        "extensions.worktreeconfig",
        "maintenance.repo",
        "ssh.variant",
    }
)


@dataclass(frozen=True, slots=True)
class WindowsGitExecutableBinding:
    """Content and native security identity retained for the selected executable."""

    sha256: str
    identity: WindowsObjectIdentity
    backend_id: str = WINDOWS_GIT_BACKEND_ID

    def __post_init__(self) -> None:
        if len(self.sha256) != 64 or any(
            character not in "0123456789abcdef" for character in self.sha256
        ):
            raise ValueError("Windows Git executable digest is invalid")

    def to_dict(self) -> dict[str, object]:
        """Return the path-free execution binding for runtime context."""

        return {
            "backend": self.backend_id,
            "sha256": self.sha256,
            "identity": self.identity.to_dict(),
        }


class WindowsGitDiscovery(Protocol):
    """Bounded source of Git for Windows installation candidates."""

    def candidates(self) -> tuple[Path, ...]:
        """Return absolute candidate executable paths in preference order."""


class RegistryWindowsGitDiscovery:
    """Read fixed Git for Windows registry keys and installation layouts."""

    def candidates(self) -> tuple[Path, ...]:
        """Return bounded registry and fixed-installation candidates."""

        if sys.platform != "win32":
            raise PlatformCapabilityUnavailable(
                "native Windows Git discovery requires Windows"
            )
        import winreg

        candidates: list[Path] = []
        key_access = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)
        roots = (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER)
        registry_values = (
            (r"SOFTWARE\GitForWindows", "InstallPath", False),
            (
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\git.exe",
                "",
                True,
            ),
        )
        for root in roots:
            for key_name, value_name, executable_value in registry_values:
                try:
                    with winreg.OpenKey(root, key_name, 0, key_access) as key:
                        value, value_type = winreg.QueryValueEx(key, value_name)
                except OSError:
                    continue
                if value_type not in {
                    winreg.REG_SZ,
                    winreg.REG_EXPAND_SZ,
                } or not isinstance(value, str):
                    continue
                selected = Path(value)
                if executable_value:
                    candidates.append(selected)
                else:
                    candidates.extend(
                        (selected / "cmd" / "git.exe", selected / "bin" / "git.exe")
                    )
        for drive in "CDEFGHIJKLMNOPQRSTUVWXYZ":
            base = Path(f"{drive}:\\Program Files\\Git")
            candidates.extend((base / "cmd" / "git.exe", base / "bin" / "git.exe"))
            base_x86 = Path(f"{drive}:\\Program Files (x86)\\Git")
            candidates.extend(
                (base_x86 / "cmd" / "git.exe", base_x86 / "bin" / "git.exe")
            )
        return _deduplicate_candidates(candidates)


class WindowsTrustedGitBackend:
    """Pin Git and repository state around fixed read-only Job Object launches."""

    backend_id = WINDOWS_GIT_BACKEND_ID

    def __init__(
        self,
        *,
        filesystem: WindowsSecureFilesystemBackend,
        process: ProcessSupervisionBackend,
        executable: Path | None = None,
        discovery: WindowsGitDiscovery | None = None,
    ) -> None:
        self._filesystem = filesystem
        self._process = process
        self._state = tempfile.TemporaryDirectory(prefix="master-agent-git-")
        self._home = Path(self._state.name).absolute()
        self._executable_pin: PinnedWindowsPath | None = None
        try:
            self._executable_pin = self._select_executable(
                executable=executable,
                discovery=discovery or RegistryWindowsGitDiscovery(),
            )
            payload = self._executable_pin.read_bytes(MAX_PINNED_READ_BYTES)
            if len(payload) < 2 or payload[:2] != b"MZ":
                raise PlatformCapabilityUnavailable(WINDOWS_GIT_UNAVAILABLE_REASON)
            self._binding = WindowsGitExecutableBinding(
                sha256=hashlib.sha256(payload).hexdigest(),
                identity=self._executable_pin.identity,
            )
            self._executable_pin.validate()
        except BaseException:
            self.close()
            raise

    @property
    def executable_binding(self) -> WindowsGitExecutableBinding:
        """Return the immutable path-free executable execution binding."""

        self._require_open().validate()
        return self._binding

    def read(
        self,
        repository: Path,
        arguments: Sequence[str],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> bytes:
        """Run one admitted local Git inspection under all native boundaries."""

        parsed = validate_trusted_git_request(
            repository,
            arguments,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )
        try:
            return self._read_unwrapped(
                repository,
                parsed,
                timeout_seconds=timeout_seconds,
                max_output_bytes=max_output_bytes,
            )
        except TrustedGitError:
            raise
        except (ConfigurationError, OSError, ValueError) as error:
            raise TrustedGitError("repository_identity_invalid") from error

    def _read_unwrapped(
        self,
        repository: Path,
        arguments: tuple[str, ...],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> bytes:
        """Execute an already error-bounded trusted-Git request."""

        executable_pin = self._require_open()
        with ExitStack() as stack:
            repository_pin = stack.enter_context(
                self._filesystem.pin_directory(repository, require_private=False)
            )
            root_names = repository_pin.list_children()
            git_name = _require_one_name(root_names, ".git", required=True)
            if git_name is None:  # pragma: no cover - required lookup raises.
                raise TrustedGitError("repository_metadata_invalid")
            git_pin = stack.enter_context(
                repository_pin.pin_child(
                    git_name,
                    kind="directory",
                    require_private=False,
                )
            )
            git_names = git_pin.list_children()
            if any(
                _require_one_name(git_names, prohibited, required=False) is not None
                for prohibited in ("commondir", "gitdir")
            ):
                raise TrustedGitError("repository_redirection_prohibited")
            if any(name.casefold().endswith(".lock") for name in git_names):
                raise TrustedGitError("repository_busy")
            config_name = _require_one_name(git_names, "config", required=True)
            if config_name is None:  # pragma: no cover - required lookup raises.
                raise TrustedGitError("repository_metadata_invalid")
            config_pin = stack.enter_context(
                git_pin.pin_child(
                    config_name,
                    kind="file",
                    require_private=False,
                )
            )
            if config_pin.size > _MAX_CONFIG_BYTES:
                raise TrustedGitError("configuration_too_large")
            retained: list[PinnedWindowsPath] = [
                executable_pin,
                repository_pin,
                git_pin,
                config_pin,
            ]
            for optional in ("HEAD", "index", "packed-refs", "shallow"):
                selected = _require_one_name(git_names, optional, required=False)
                if selected is not None:
                    pin = stack.enter_context(
                        git_pin.pin_child(
                            selected,
                            kind="file",
                            require_private=False,
                        )
                    )
                    retained.append(pin)
            objects_name = _require_one_name(git_names, "objects", required=True)
            if objects_name is None:  # pragma: no cover - required lookup raises.
                raise TrustedGitError("repository_metadata_invalid")
            budget = [_MAX_RETAINED_REPOSITORY_OBJECTS]
            objects_pin = stack.enter_context(
                git_pin.pin_child(
                    objects_name,
                    kind="directory",
                    require_private=False,
                )
            )
            retained.append(objects_pin)
            self._pin_metadata_tree(
                stack,
                objects_pin,
                retained,
                budget=budget,
                depth=0,
                reject_names=frozenset({"alternates", "http-alternates"}),
            )
            refs_name = _require_one_name(git_names, "refs", required=False)
            if refs_name is not None:
                refs_pin = stack.enter_context(
                    git_pin.pin_child(
                        refs_name,
                        kind="directory",
                        require_private=False,
                    )
                )
                retained.append(refs_pin)
                self._pin_metadata_tree(
                    stack,
                    refs_pin,
                    retained,
                    budget=budget,
                    depth=0,
                )
            self._validate_pins(retained)
            prefix = self._command_prefix(
                repository=repository_pin.path,
                git_directory=git_pin.path,
            )
            config_result = self._run_process(
                executable=executable_pin.path,
                cwd=repository_pin.path,
                arguments=(
                    *prefix,
                    "config",
                    "--file",
                    str(config_pin.path),
                    "--no-includes",
                    "--null",
                    "--name-only",
                    "--list",
                ),
                timeout_seconds=min(float(timeout_seconds), 10.0),
                max_output_bytes=_MAX_CONFIG_BYTES,
            )
            self._validate_configuration(config_result)
            output = self._run_process(
                executable=executable_pin.path,
                cwd=repository_pin.path,
                arguments=(*prefix, *harden_trusted_git_command(arguments)),
                timeout_seconds=float(timeout_seconds),
                max_output_bytes=max_output_bytes,
            )
            self._validate_pins(retained)
            if tuple(name.casefold() for name in git_pin.list_children()) != tuple(
                name.casefold() for name in git_names
            ):
                raise TrustedGitError("repository_metadata_changed")
            return output

    def close(self) -> None:
        """Release the executable pin before removing private Git state."""

        pin = getattr(self, "_executable_pin", None)
        if pin is not None:
            pin.close()
            self._executable_pin = None
        state = getattr(self, "_state", None)
        if state is not None:
            state.cleanup()

    def __enter__(self) -> Self:
        self._require_open().validate()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def __del__(self) -> None:
        if hasattr(self, "_state"):
            try:
                self.close()
            except (ConfigurationError, OSError):
                return

    def _select_executable(
        self,
        *,
        executable: Path | None,
        discovery: WindowsGitDiscovery,
    ) -> PinnedWindowsPath:
        explicit = executable is not None
        candidates = (executable,) if executable is not None else discovery.candidates()
        if not candidates or len(candidates) > 128:
            raise PlatformCapabilityUnavailable(WINDOWS_GIT_UNAVAILABLE_REASON)
        for candidate in _deduplicate_candidates(candidates):
            if (
                not isinstance(candidate, Path)
                or not candidate.is_absolute()
                or candidate.name.casefold() != "git.exe"
                or (not explicit and not _is_git_for_windows_layout(candidate))
            ):
                continue
            try:
                return self._filesystem.pin_file(candidate, require_private=False)
            except (ConfigurationError, OSError, ValueError):
                continue
        raise PlatformCapabilityUnavailable(WINDOWS_GIT_UNAVAILABLE_REASON)

    def _require_open(self) -> PinnedWindowsPath:
        pin = self._executable_pin
        if pin is None or pin.closed:
            raise TrustedGitError("backend_closed")
        return pin

    def _command_prefix(
        self,
        *,
        repository: Path,
        git_directory: Path,
    ) -> tuple[str, ...]:
        values = (
            ("core.hooksPath", "NUL"),
            ("core.attributesFile", "NUL"),
            ("core.excludesFile", "NUL"),
            ("core.fsmonitor", "false"),
            ("core.untrackedCache", "false"),
            ("core.autocrlf", "false"),
            ("core.eol", "lf"),
            ("core.safecrlf", "true"),
            ("core.sshCommand", ""),
            ("core.alternateRefsCommand", ""),
            ("credential.helper", ""),
            ("credential.interactive", "never"),
            ("diff.external", ""),
            ("diff.trustExitCode", "false"),
            ("maintenance.auto", "false"),
            ("gc.auto", "0"),
            ("submodule.recurse", "false"),
            ("fetch.recurseSubmodules", "false"),
            ("protocol.allow", "never"),
            ("protocol.file.allow", "never"),
            ("protocol.http.allow", "never"),
            ("protocol.https.allow", "never"),
            ("protocol.ssh.allow", "never"),
            ("protocol.ext.allow", "never"),
        )
        config = tuple(
            item for key, value in values for item in ("-c", f"{key}={value}")
        )
        return (
            "--no-pager",
            "--literal-pathspecs",
            "--no-optional-locks",
            f"--git-dir={git_directory}",
            f"--work-tree={repository}",
            *config,
        )

    def _environment(self) -> dict[str, str]:
        return {
            "GCM_INTERACTIVE": "Never",
            "GIT_ALLOW_PROTOCOL": "",
            "GIT_ASKPASS": "NUL",
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "NUL",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": "NUL",
            "GIT_EDITOR": "NUL",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "NUL",
            "GIT_PROTOCOL_FROM_USER": "0",
            "GIT_SEQUENCE_EDITOR": "NUL",
            "GIT_TERMINAL_PROMPT": "0",
            "HOME": str(self._home),
            "LANG": "C",
            "LC_ALL": "C",
            "NO_COLOR": "1",
            "SSH_ASKPASS": "NUL",
            "XDG_CONFIG_HOME": str(self._home),
        }

    def _run_process(
        self,
        *,
        executable: Path,
        cwd: Path,
        arguments: tuple[str, ...],
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> bytes:
        try:
            result = self._process.run(
                executable=executable,
                arguments=arguments,
                cwd=cwd,
                environment=self._environment(),
                timeout_seconds=timeout_seconds,
                cpu_seconds=max(1, min(30, int(timeout_seconds) + 1)),
                memory_bytes=1024 * 1024 * 1024,
                max_processes=16,
                max_output_bytes=max_output_bytes,
            )
        except ProcessSupervisionError as error:
            raise TrustedGitError("process_control_failed") from error
        if result.reason is ProcessExitReason.TIMED_OUT:
            raise TrustedGitError("timed_out")
        if result.reason is not ProcessExitReason.EXITED or result.exit_code != 0:
            raise TrustedGitError("nonzero_exit")
        if result.output_truncated or len(result.stdout) > max_output_bytes:
            raise TrustedGitError("output_limit_exceeded")
        return result.stdout

    @staticmethod
    def _validate_pins(pins: Sequence[PinnedWindowsPath]) -> None:
        try:
            for pin in pins:
                pin.validate()
        except (OSError, ValueError) as error:
            raise TrustedGitError("identity_changed") from error

    def _pin_metadata_tree(
        self,
        stack: ExitStack,
        parent: PinnedWindowsPath,
        retained: list[PinnedWindowsPath],
        *,
        budget: list[int],
        depth: int,
        reject_names: frozenset[str] = frozenset(),
    ) -> None:
        """Retain one bounded metadata subtree and reject path redirects."""

        if depth > _MAX_REPOSITORY_METADATA_DEPTH:
            raise TrustedGitError("repository_metadata_too_deep")
        names = parent.list_children()
        if any(name.casefold() in reject_names for name in names):
            raise TrustedGitError("repository_redirection_prohibited")
        for name in names:
            budget[0] -= 1
            if budget[0] < 0:
                raise TrustedGitError("repository_metadata_too_large")
            try:
                child = parent.pin_child(
                    name,
                    kind="directory",
                    require_private=False,
                )
            except (ConfigurationError, OSError, ValueError):
                child = parent.pin_child(
                    name,
                    kind="file",
                    require_private=False,
                )
            pin = stack.enter_context(child)
            retained.append(pin)
            if pin.identity.kind.value == "directory":
                self._pin_metadata_tree(
                    stack,
                    pin,
                    retained,
                    budget=budget,
                    depth=depth + 1,
                    reject_names=reject_names,
                )

    @staticmethod
    def _validate_configuration(payload: bytes) -> None:
        if payload and not payload.endswith(b"\x00"):
            raise TrustedGitError("configuration_invalid")
        try:
            keys = payload[:-1].decode("utf-8").split("\x00") if payload else []
        except UnicodeDecodeError as error:
            raise TrustedGitError("configuration_invalid") from error
        if any(_dangerous_config_key(key.strip().casefold()) for key in keys if key):
            raise TrustedGitError("configuration_prohibited")


def probe_windows_git_backend(
    *,
    filesystem: WindowsSecureFilesystemBackend,
    process: ProcessSupervisionBackend,
    executable: Path | None = None,
) -> WindowsTrustedGitBackend:
    """Return a fully selected native Git backend or a bounded unavailable error."""

    return WindowsTrustedGitBackend(
        filesystem=filesystem,
        process=process,
        executable=executable,
    )


def _require_one_name(
    names: Sequence[str],
    expected: str,
    *,
    required: bool,
) -> str | None:
    matches = tuple(name for name in names if name.casefold() == expected.casefold())
    if len(matches) > 1:
        raise TrustedGitError("case_collision")
    if not matches:
        if required:
            raise TrustedGitError("repository_metadata_invalid")
        return None
    return matches[0]


def _dangerous_config_key(key: str) -> bool:
    if key in _DANGEROUS_EXACT_KEYS:
        return True
    if key.startswith(("alias.", "include.", "includeif.", "credential.", "http.")):
        return True
    if key.startswith(("filter.", "diff.", "difftool.", "merge.", "mergetool.")):
        return True
    if key.startswith(("protocol.", "submodule.")):
        return True
    if key.startswith("url.") and key.endswith((".insteadof", ".pushinsteadof")):
        return True
    return key.startswith("remote.") and key.endswith((".proxy", ".pushurl"))


def _is_git_for_windows_layout(path: Path) -> bool:
    folded = tuple(part.casefold() for part in path.parts)
    return len(folded) >= 3 and folded[-3:] in {
        ("git", "cmd", "git.exe"),
        ("git", "bin", "git.exe"),
    }


def _deduplicate_candidates(values: Sequence[Path | None]) -> tuple[Path, ...]:
    result: list[Path] = []
    observed: set[str] = set()
    for value in values:
        if value is None:
            continue
        folded = str(value).casefold()
        if folded not in observed:
            result.append(value)
            observed.add(folded)
    return tuple(result)

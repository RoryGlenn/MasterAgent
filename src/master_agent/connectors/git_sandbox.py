"""Process and configuration isolation for fixed Git connector operations."""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from master_agent.errors import ConnectorError


@dataclass(frozen=True, slots=True)
class SandboxedGitResult:
    """Secret-free output from one fixed Git command."""

    stdout: str
    stderr: str
    returncode: int


class GitSandbox:
    """Run fixed Git commands without ambient credentials or executable config."""

    def __init__(
        self,
        *,
        timeout_seconds: float,
        allow_file_protocol: bool = False,
    ) -> None:
        executable = shutil.which("git", path="/usr/bin:/bin:/usr/local/bin")
        if not executable:
            raise ConnectorError("Git executable is unavailable")
        self._git = executable
        self._timeout_seconds = timeout_seconds
        self._allow_file_protocol = allow_file_protocol
        self._state = tempfile.TemporaryDirectory(prefix="master-agent-git-")
        root = Path(self._state.name)
        self._root = root.resolve()
        self._home = root / "home"
        self._hooks = root / "hooks"
        self._attributes = root / "attributes"
        self._home.mkdir(mode=0o700)
        self._hooks.mkdir(mode=0o700)
        self._attributes.write_bytes(b"")
        self._attributes.chmod(0o600)

    def close(self) -> None:
        """Remove trusted temporary state immediately."""

        self._state.cleanup()

    def __del__(self) -> None:
        self.close()

    def run(
        self,
        repository: Path,
        arguments: Sequence[str],
        *,
        input_bytes: bytes | None = None,
        index_file: Path | None = None,
        check: bool = True,
    ) -> SandboxedGitResult:
        """Run an argv-only Git command with a minimal deterministic environment."""

        command = [
            self._git,
            *self._config_overrides(),
            "-c",
            f"core.worktree={repository.resolve()}",
            *arguments,
        ]
        try:
            completed = subprocess.run(
                command,
                cwd=repository,
                input=input_bytes,
                capture_output=True,
                timeout=self._timeout_seconds,
                check=False,
                env=self._environment(index_file=index_file),
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ConnectorError(
                f"fixed Git operation failed: {type(error).__name__}"
            ) from error
        result = SandboxedGitResult(
            stdout=completed.stdout.decode("utf-8", errors="replace"),
            stderr=completed.stderr.decode("utf-8", errors="replace"),
            returncode=completed.returncode,
        )
        if check and result.returncode != 0:
            # Git diagnostics can contain credential-bearing URLs, paths, hook
            # output, and remote-controlled text.  Keep them out of audit logs.
            raise ConnectorError(f"Git operation returned {result.returncode}")
        return result

    @contextmanager
    def isolated_index(self) -> Iterator[Path]:
        """Yield a private alternate index path outside repository control."""

        with tempfile.TemporaryDirectory(
            prefix="index-",
            dir=self._root,
        ) as directory:
            yield Path(directory) / "index"

    def validate_repository_config(self, repository: Path) -> None:
        """Reject local config keys that can execute code or redirect I/O."""

        result = self.run(
            repository,
            ("config", "--local", "--no-includes", "--null", "--name-only", "--list"),
        )
        for key in result.stdout.split("\0"):
            normalized = key.strip().lower()
            if normalized and _dangerous_config_key(normalized):
                raise ConnectorError(
                    f"repository contains prohibited executable Git configuration: {normalized}"
                )
        expected_worktree = repository.resolve()
        observed_worktree = Path(
            self.run(repository, ("rev-parse", "--show-toplevel")).stdout.strip()
        ).resolve()
        if observed_worktree != expected_worktree:
            raise ConnectorError("Git worktree is outside the approved repository")
        observed_git_dir = Path(
            self.run(repository, ("rev-parse", "--absolute-git-dir")).stdout.strip()
        ).resolve()
        git_entry = expected_worktree / ".git"
        try:
            git_metadata = git_entry.lstat()
        except FileNotFoundError as error:
            raise ConnectorError("Git metadata is unavailable") from error
        if not stat.S_ISDIR(git_metadata.st_mode):
            raise ConnectorError("Git metadata must be a local non-symlink directory")
        expected_git_dir = git_entry.resolve()
        if observed_git_dir != expected_git_dir:
            raise ConnectorError("Git metadata is outside the approved repository")
        common_value = self.run(
            repository,
            ("rev-parse", "--git-common-dir"),
        ).stdout.strip()
        observed_common_dir = Path(common_value)
        if not observed_common_dir.is_absolute():
            observed_common_dir = repository / observed_common_dir
        if observed_common_dir.resolve() != expected_git_dir:
            raise ConnectorError(
                "Git common metadata is outside the approved repository"
            )
        if (
            self.run(repository, ("rev-parse", "--is-bare-repository")).stdout.strip()
            != "false"
        ):
            raise ConnectorError("bare Git repositories are not approved workspaces")

    def reject_path_filters(self, repository: Path, paths: Sequence[str]) -> None:
        """Reject repository attributes that can invoke clean filter drivers."""

        if not paths:
            return
        result = self.run(
            repository,
            ("check-attr", "-z", "filter", "working-tree-encoding", "--", *paths),
        )
        fields = result.stdout.split("\0")
        for index in range(0, len(fields) - 2, 3):
            attribute = fields[index + 1]
            value = fields[index + 2]
            if value not in {"", "unspecified", "unset"}:
                raise ConnectorError(
                    f"approved Git path uses prohibited {attribute} transformation"
                )

    def _config_overrides(self) -> tuple[str, ...]:
        values = (
            ("core.hooksPath", str(self._hooks)),
            ("core.attributesFile", str(self._attributes)),
            ("core.fsmonitor", "false"),
            (
                "core.sshCommand",
                "ssh -oBatchMode=yes -oClearAllForwardings=yes -oForwardAgent=no",
            ),
            ("credential.helper", ""),
            ("credential.interactive", "never"),
            ("commit.gpgSign", "false"),
            ("tag.gpgSign", "false"),
            ("maintenance.auto", "false"),
            ("gc.auto", "0"),
            ("protocol.allow", "never"),
            ("protocol.https.allow", "always"),
            ("protocol.ssh.allow", "always"),
            (
                "protocol.file.allow",
                "always" if self._allow_file_protocol else "never",
            ),
        )
        return tuple(item for key, value in values for item in ("-c", f"{key}={value}"))

    def _environment(self, *, index_file: Path | None = None) -> dict[str, str]:
        environment = {
            "PATH": "/usr/bin:/bin:/usr/local/bin",
            "HOME": str(self._home),
            "LANG": "C",
            "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": os.devnull,
            "SSH_ASKPASS": os.devnull,
            "GIT_PAGER": "cat",
            "GIT_EDITOR": os.devnull,
            "GIT_SEQUENCE_EDITOR": os.devnull,
            "GIT_OPTIONAL_LOCKS": "0",
        }
        if index_file is not None:
            resolved = index_file.resolve(strict=False)
            try:
                resolved.relative_to(self._root)
            except ValueError as error:
                raise ConnectorError(
                    "alternate Git index is outside trusted temporary state"
                ) from error
            environment["GIT_INDEX_FILE"] = str(resolved)
        return environment


_DANGEROUS_EXACT_KEYS = frozenset(
    {
        "core.hookspath",
        "core.sshcommand",
        "core.fsmonitor",
        "core.editor",
        "core.pager",
        "core.attributesfile",
        "core.worktree",
        "core.gitproxy",
        "core.alternaterefscommand",
        "extensions.worktreeconfig",
        "diff.external",
        "commit.gpgsign",
        "tag.gpgsign",
        "ssh.variant",
    }
)


def _dangerous_config_key(key: str) -> bool:
    if key in _DANGEROUS_EXACT_KEYS:
        return True
    if key.startswith(("include.", "includeif.", "credential.", "http.", "gpg.")):
        return True
    if key.startswith("url.") and key.endswith((".insteadof", ".pushinsteadof")):
        return True
    if key.startswith("protocol.") and key.endswith(".allow"):
        return True
    patterns = (
        r"^filter\..+\.(clean|smudge|process|required)$",
        r"^diff\..+\.command$",
        r"^difftool\..+\.cmd$",
        r"^merge\..+\.driver$",
        r"^mergetool\..+\.cmd$",
        r"^submodule\..+\.update$",
        r"^remote\..+\.proxy$",
    )
    return any(re.fullmatch(pattern, key) for pattern in patterns)


def validate_remote_url(value: str, *, allow_file: bool = False) -> str:
    """Validate one exact, approval-bound Git remote URL."""

    rendered = value.strip()
    if not rendered or any(character in rendered for character in ("\n", "\r", "\0")):
        raise ConnectorError("Git remote URL is invalid")
    if Path(rendered).is_absolute() and allow_file:
        return rendered
    parsed = urlparse(rendered)
    if parsed.scheme == "file" and allow_file:
        if parsed.username or parsed.password or not Path(parsed.path).is_absolute():
            raise ConnectorError("Git file remote URL is invalid")
        return rendered
    if parsed.scheme in {"https", "ssh"}:
        has_forbidden_userinfo = parsed.password is not None or (
            parsed.scheme == "https" and parsed.username is not None
        )
        if (
            not parsed.hostname
            or has_forbidden_userinfo
            or parsed.query
            or parsed.fragment
        ):
            raise ConnectorError("Git network remote URL is invalid")
        return rendered
    if re.fullmatch(r"[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:[^\s]+", rendered):
        return rendered
    raise ConnectorError("Git remote URL scheme is not approved")

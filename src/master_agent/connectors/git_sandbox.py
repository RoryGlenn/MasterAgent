"""Process and configuration isolation for fixed Git connector operations."""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Self
from urllib.parse import urlparse

from master_agent.directory_safety import PinnedDirectory
from master_agent.errors import ConnectorError

_MAX_CONFIG_BYTES = 4 * 1024 * 1024
_MAX_INDEX_BYTES = 128 * 1024 * 1024
_MAX_REFLOG_BYTES = 128 * 1024 * 1024
_PINNED_CWD_EXEC = (
    "import os,sys;"
    "fd=int(sys.argv[1]);"
    "argv=sys.argv[2:];"
    "os.fchdir(fd);"
    "os.close(fd);"
    "os.execve(argv[0],argv,os.environ)"
)


@dataclass(frozen=True, slots=True)
class IsolatedRefTransaction:
    """Trusted per-worktree metadata for one locked ref transaction."""

    git_dir: Path
    source_head_log: Path
    head_log_identity: tuple[int, int]
    head_log_before: bytes
    source_branch_log: Path
    branch_log_identity: tuple[int, int]
    branch_log_before: bytes

    def validate_records(
        self,
        records: Sequence[tuple[str, str, str]] = (),
    ) -> None:
        """Prove exact ref transaction records reached both pinned reflogs."""

        try:
            source_metadata = self.source_head_log.lstat()
            linked_metadata = (self.git_dir / "logs" / "HEAD").lstat()
            branch_metadata = self.source_branch_log.lstat()
        except FileNotFoundError as error:
            raise ConnectorError("repository reflog identity changed") from error
        if (
            not stat.S_ISREG(source_metadata.st_mode)
            or _identity(source_metadata) != self.head_log_identity
            or _identity(linked_metadata) != self.head_log_identity
            or source_metadata.st_nlink != 2
            or not stat.S_ISREG(branch_metadata.st_mode)
            or _identity(branch_metadata) != self.branch_log_identity
            or branch_metadata.st_nlink != 1
        ):
            raise ConnectorError("repository reflog identity changed")
        head_bytes = _read_path_bounded(
            self.source_head_log,
            maximum_bytes=_MAX_REFLOG_BYTES,
            label="repository HEAD reflog",
            expected_identity=self.head_log_identity,
            expected_links=2,
        )
        branch_bytes = _read_path_bounded(
            self.source_branch_log,
            maximum_bytes=_MAX_REFLOG_BYTES,
            label="repository branch reflog",
            expected_identity=self.branch_log_identity,
            expected_links=1,
        )
        head_suffix = head_bytes[len(self.head_log_before) :]
        branch_suffix = branch_bytes[len(self.branch_log_before) :]
        if (
            not head_bytes.startswith(self.head_log_before)
            or not branch_bytes.startswith(self.branch_log_before)
            or head_suffix != branch_suffix
            or not _valid_reflog_records(head_suffix, records)
        ):
            raise ConnectorError("repository reflog transaction record is invalid")


@dataclass(frozen=True, slots=True)
class IsolatedHeadReflogTransaction:
    """Trusted private symbolic HEAD linked to the pinned source HEAD reflog."""

    git_dir: Path
    source_head_log: Path
    head_log_identity: tuple[int, int]
    head_log_before: bytes

    def validate_records(
        self,
        records: Sequence[tuple[str, str, str]] = (),
    ) -> None:
        """Prove exact symbolic-HEAD records reached the pinned source reflog."""

        try:
            source_metadata = self.source_head_log.lstat()
            linked_metadata = (self.git_dir / "logs" / "HEAD").lstat()
        except FileNotFoundError as error:
            raise ConnectorError("repository HEAD reflog identity changed") from error
        if (
            not stat.S_ISREG(source_metadata.st_mode)
            or _identity(source_metadata) != self.head_log_identity
            or _identity(linked_metadata) != self.head_log_identity
            or source_metadata.st_nlink != 2
        ):
            raise ConnectorError("repository HEAD reflog identity changed")
        head_bytes = _read_path_bounded(
            self.source_head_log,
            maximum_bytes=_MAX_REFLOG_BYTES,
            label="repository HEAD reflog",
            expected_identity=self.head_log_identity,
            expected_links=2,
        )
        suffix = head_bytes[len(self.head_log_before) :]
        if not head_bytes.startswith(self.head_log_before) or not _valid_reflog_records(
            suffix,
            records,
        ):
            raise ConnectorError("repository HEAD reflog transaction record is invalid")


@dataclass(frozen=True, slots=True)
class IsolatedWorktreeSnapshot:
    """Trusted Git metadata and private index for worktree inspection."""

    git_dir: Path
    index_file: Path


class LockedGitConfig:
    """Pin repository config bytes while standard Git writers are excluded."""

    def __init__(self, repository: Path) -> None:
        self._git_path = repository / ".git"
        self._directory_fd = -1
        self._config_fd = -1
        self._lock_fd = -1
        self._directory_identity: tuple[int, int] | None = None
        self._config_identity: tuple[int, int] | None = None
        self._lock_identity: tuple[int, int] | None = None
        self._config_bytes = b""

    def __enter__(self) -> Self:
        try:
            path_metadata = self._git_path.lstat()
            if not stat.S_ISDIR(path_metadata.st_mode):
                raise ConnectorError("repository Git metadata changed")
            self._directory_fd = os.open(
                self._git_path,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
            directory_metadata = os.fstat(self._directory_fd)
            if _identity(path_metadata) != _identity(directory_metadata):
                raise ConnectorError("repository Git metadata changed")
            self._directory_identity = _identity(directory_metadata)
            self._lock_fd = os.open(
                "config.lock",
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=self._directory_fd,
            )
            lock_metadata = os.fstat(self._lock_fd)
            self._lock_identity = _identity(lock_metadata)
            if not stat.S_ISREG(lock_metadata.st_mode):
                raise ConnectorError("repository config lock is not a file")
            self._config_fd = os.open(
                "config",
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=self._directory_fd,
            )
            config_metadata = os.fstat(self._config_fd)
            self._config_identity = _identity(config_metadata)
            self._config_bytes = _read_bounded(
                self._config_fd,
                config_metadata,
                maximum_bytes=_MAX_CONFIG_BYTES,
                label="repository config",
            )
            return self
        except FileExistsError as error:
            self.close()
            raise ConnectorError(
                "repository config is busy; Git operation is refused"
            ) from error
        except Exception:
            self.close()
            raise

    def __exit__(self, *_: object) -> None:
        self.close()

    def validate(self) -> None:
        """Prove the exact config file and lock identities remain pinned."""

        try:
            directory_metadata = self._git_path.lstat()
            config_metadata = os.stat(
                "config",
                dir_fd=self._directory_fd,
                follow_symlinks=False,
            )
            lock_metadata = os.stat(
                "config.lock",
                dir_fd=self._directory_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError as error:
            raise ConnectorError("repository config identity changed") from error
        if (
            self._directory_identity is None
            or self._config_identity is None
            or self._lock_identity is None
            or _identity(directory_metadata) != self._directory_identity
            or _identity(config_metadata) != self._config_identity
            or _identity(lock_metadata) != self._lock_identity
            or self._config_fd < 0
            or _read_bounded(
                self._config_fd,
                os.fstat(self._config_fd),
                maximum_bytes=_MAX_CONFIG_BYTES,
                label="repository config",
            )
            != self._config_bytes
        ):
            raise ConnectorError("repository config identity changed")

    def close(self) -> None:
        """Release the pinned file descriptors and owned config lock."""

        if self._config_fd >= 0:
            os.close(self._config_fd)
            self._config_fd = -1
        if self._lock_fd >= 0:
            os.close(self._lock_fd)
            self._lock_fd = -1
        if self._directory_fd >= 0:
            if self._lock_identity is not None:
                try:
                    metadata = os.stat(
                        "config.lock",
                        dir_fd=self._directory_fd,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    metadata = None
                if metadata is not None and _identity(metadata) == self._lock_identity:
                    try:
                        os.unlink("config.lock", dir_fd=self._directory_fd)
                    except FileNotFoundError:
                        pass
            os.close(self._directory_fd)
            self._directory_fd = -1


def _identity(metadata: os.stat_result) -> tuple[int, int]:
    return (metadata.st_dev, metadata.st_ino)


def _read_bounded(
    file_descriptor: int,
    metadata: os.stat_result,
    *,
    maximum_bytes: int,
    label: str,
) -> bytes:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size < 0
        or metadata.st_size > maximum_bytes
    ):
        raise ConnectorError(f"{label} is invalid or too large")
    os.lseek(file_descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    remaining = metadata.st_size
    while remaining:
        chunk = os.read(file_descriptor, min(1024 * 1024, remaining))
        if not chunk:
            raise ConnectorError(f"{label} changed while being read")
        chunks.append(chunk)
        remaining -= len(chunk)
    payload = b"".join(chunks)
    if os.read(file_descriptor, 1):
        raise ConnectorError(f"{label} changed while being read")
    if len(payload) != metadata.st_size:
        raise ConnectorError(f"{label} changed while being read")
    return payload


def _read_path_bounded(
    path: Path,
    *,
    maximum_bytes: int,
    label: str,
    expected_identity: tuple[int, int] | None = None,
    expected_links: int | None = None,
) -> bytes:
    file_descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        metadata = os.fstat(file_descriptor)
        if (
            expected_identity is not None and _identity(metadata) != expected_identity
        ) or (expected_links is not None and metadata.st_nlink != expected_links):
            raise ConnectorError(f"{label} identity changed")
        return _read_bounded(
            file_descriptor,
            metadata,
            maximum_bytes=maximum_bytes,
            label=label,
        )
    finally:
        os.close(file_descriptor)


def _copy_exact(source_fd: int, destination_fd: int, size: int) -> None:
    remaining = size
    while remaining:
        chunk = os.read(source_fd, min(1024 * 1024, remaining))
        if not chunk:
            raise ConnectorError("repository index changed while being copied")
        view = memoryview(chunk)
        while view:
            written = os.write(destination_fd, view)
            if written <= 0:
                raise ConnectorError("private Git index write failed")
            view = view[written:]
        remaining -= len(chunk)
    if os.read(source_fd, 1):
        raise ConnectorError("repository index changed while being copied")


def _valid_reflog_records(
    payload: bytes,
    records: Sequence[tuple[str, str, str]],
) -> bool:
    lines = payload.splitlines(keepends=True)
    if len(lines) != len(records):
        return False
    for line, (old_oid, new_oid, reason) in zip(lines, records, strict=True):
        if (
            not line.startswith(f"{old_oid} {new_oid} ".encode("ascii"))
            or not line.endswith(f"\t{reason}\n".encode())
            or line.count(b"\n") != 1
        ):
            return False
    return True


@dataclass(frozen=True, slots=True)
class SandboxedGitResult:
    """Secret-free output from one fixed Git command."""

    stdout: str
    stdout_bytes: bytes
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
        bare_repository: bool = False,
        worktree: Path | None = None,
        working_directory: PinnedDirectory | None = None,
        check: bool = True,
    ) -> SandboxedGitResult:
        """Run an argv-only Git command with a minimal deterministic environment."""

        command = [
            self._git,
            *self._config_overrides(),
        ]
        if worktree is not None:
            command.extend(
                (
                    f"--git-dir={repository.resolve()}",
                    (
                        "--work-tree=."
                        if working_directory is not None
                        else f"--work-tree={worktree.resolve()}"
                    ),
                    "-c",
                    "core.bare=false",
                )
            )
        elif not bare_repository:
            command.extend(
                (
                    "-c",
                    (
                        "core.worktree=."
                        if working_directory is not None
                        else f"core.worktree={repository.resolve()}"
                    ),
                )
            )
        command.extend(arguments)
        inherited_descriptor: int | None = None
        try:
            launch_command = command
            launch_directory: Path = repository
            pass_descriptors: tuple[int, ...] = ()
            if working_directory is not None:
                selected = worktree if worktree is not None else repository
                if Path(os.path.abspath(os.fspath(selected))) != working_directory.path:
                    raise ConnectorError(
                        "pinned Git working directory does not match the command path"
                    )
                if os.name != "posix" or not hasattr(os, "fchdir"):
                    raise ConnectorError(
                        "descriptor-backed Git execution is unavailable"
                    )
                inherited_descriptor = working_directory.duplicate_fd()
                launch_command = [
                    sys.executable,
                    "-I",
                    "-c",
                    _PINNED_CWD_EXEC,
                    str(inherited_descriptor),
                    *command,
                ]
                launch_directory = Path(os.sep)
                pass_descriptors = (inherited_descriptor,)
            completed = subprocess.run(
                launch_command,
                cwd=launch_directory,
                input=input_bytes,
                capture_output=True,
                timeout=self._timeout_seconds,
                check=False,
                env=self._environment(index_file=index_file),
                close_fds=True,
                pass_fds=pass_descriptors,
            )
            if working_directory is not None:
                working_directory.validate()
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ConnectorError(
                f"fixed Git operation failed: {type(error).__name__}"
            ) from error
        finally:
            if inherited_descriptor is not None:
                os.close(inherited_descriptor)
        result = SandboxedGitResult(
            stdout=completed.stdout.decode("utf-8", errors="replace"),
            stdout_bytes=completed.stdout,
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

    @contextmanager
    def isolated_publication_repository(self, source: Path) -> Iterator[Path]:
        """Yield a config-isolated bare repository backed by source objects."""

        with tempfile.TemporaryDirectory(
            prefix="publication-",
            dir=self._root,
        ) as directory:
            repository = Path(directory) / "repository.git"
            try:
                completed = subprocess.run(
                    [
                        self._git,
                        *self._config_overrides(),
                        "init",
                        "--bare",
                        "--quiet",
                        str(repository),
                    ],
                    cwd=self._root,
                    capture_output=True,
                    timeout=self._timeout_seconds,
                    check=False,
                    env=self._environment(),
                )
            except (OSError, subprocess.TimeoutExpired) as error:
                raise ConnectorError(
                    f"isolated Git publication setup failed: {type(error).__name__}"
                ) from error
            if completed.returncode != 0:
                raise ConnectorError(
                    f"isolated Git publication setup returned {completed.returncode}"
                )
            objects = (source / ".git" / "objects").resolve()
            if not objects.is_dir():
                raise ConnectorError("repository object database is unavailable")
            if any(character in str(objects) for character in ("\n", "\r", "\0")):
                raise ConnectorError("repository object database path is invalid")
            alternates = repository / "objects" / "info" / "alternates"
            alternates.write_text(f"{objects}\n", encoding="utf-8")
            alternates.chmod(0o600)
            yield repository

    @contextmanager
    def isolated_worktree_snapshot(
        self,
        source: Path,
        *,
        head: str,
    ) -> Iterator[IsolatedWorktreeSnapshot]:
        """Yield config-isolated metadata for non-executable status/diff reads."""

        if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", head):
            raise ConnectorError("repository HEAD object ID is invalid")
        with self.isolated_publication_repository(source) as git_dir:
            (git_dir / "HEAD").write_text(f"{head}\n", encoding="ascii")
            index_file = git_dir.parent / "worktree-index"
            source_index = source / ".git" / "index"
            try:
                source_fd = os.open(
                    source_index,
                    os.O_RDONLY
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                )
            except FileNotFoundError:
                self.run(
                    git_dir,
                    ("read-tree", head),
                    index_file=index_file,
                    bare_repository=True,
                )
            else:
                destination_fd = -1
                try:
                    source_metadata = os.fstat(source_fd)
                    if (
                        not stat.S_ISREG(source_metadata.st_mode)
                        or source_metadata.st_size <= 0
                        or source_metadata.st_size > _MAX_INDEX_BYTES
                    ):
                        raise ConnectorError("repository index is invalid or too large")
                    destination_fd = os.open(
                        index_file,
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | getattr(os, "O_NOFOLLOW", 0)
                        | getattr(os, "O_CLOEXEC", 0),
                        0o600,
                    )
                    _copy_exact(source_fd, destination_fd, source_metadata.st_size)
                    copied_metadata = os.fstat(source_fd)
                    if (
                        _identity(copied_metadata) != _identity(source_metadata)
                        or copied_metadata.st_size != source_metadata.st_size
                        or copied_metadata.st_mtime_ns != source_metadata.st_mtime_ns
                        or copied_metadata.st_ctime_ns != source_metadata.st_ctime_ns
                    ):
                        raise ConnectorError(
                            "repository index changed while being copied"
                        )
                    os.fsync(destination_fd)
                finally:
                    os.close(source_fd)
                    if destination_fd >= 0:
                        os.close(destination_fd)
            yield IsolatedWorktreeSnapshot(
                git_dir=git_dir,
                index_file=index_file,
            )

    @contextmanager
    def isolated_ref_transaction_repository(
        self,
        source: Path,
        *,
        branch: str,
    ) -> Iterator[IsolatedRefTransaction]:
        """Yield trusted per-worktree metadata sharing only source refs/objects.

        The caller holds the source ``HEAD.lock``.  Git therefore updates the
        common branch ref and its reflog while locking a private symbolic HEAD.
        A hard link makes Git append the same transaction record to the pinned
        source HEAD reflog without releasing that lock.
        """

        common = (source / ".git").resolve()
        if any(character in str(common) for character in ("\n", "\r", "\0")):
            raise ConnectorError("repository Git metadata path is invalid")
        head_log = common / "logs" / "HEAD"
        branch_log = common / "logs" / "refs" / "heads" / Path(branch)
        if (
            head_log.parent.resolve() != head_log.parent
            or branch_log.parent.resolve() != branch_log.parent
        ):
            raise ConnectorError(
                "repository reflog directories cannot be symbolic links"
            )
        try:
            head_log_metadata = head_log.lstat()
            branch_log_metadata = branch_log.lstat()
        except FileNotFoundError as error:
            raise ConnectorError(
                "repository HEAD and branch reflogs are required for commit publication"
            ) from error
        current_uid = os.geteuid()
        if any(
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != current_uid
            or metadata.st_nlink != 1
            or metadata.st_size < 0
            or metadata.st_size > _MAX_REFLOG_BYTES
            for metadata in (head_log_metadata, branch_log_metadata)
        ):
            raise ConnectorError(
                "repository reflogs must be bounded, singly linked, current-user files"
            )
        head_log_before = _read_path_bounded(
            head_log,
            maximum_bytes=_MAX_REFLOG_BYTES,
            label="repository HEAD reflog",
            expected_identity=_identity(head_log_metadata),
            expected_links=1,
        )
        branch_log_before = _read_path_bounded(
            branch_log,
            maximum_bytes=_MAX_REFLOG_BYTES,
            label="repository branch reflog",
            expected_identity=_identity(branch_log_metadata),
            expected_links=1,
        )

        with tempfile.TemporaryDirectory(
            prefix="ref-transaction-",
            dir=self._root,
        ) as directory:
            git_dir = Path(directory) / "git-dir"
            logs = git_dir / "logs"
            logs.mkdir(parents=True, mode=0o700)
            (git_dir / "HEAD").write_text(
                f"ref: refs/heads/{branch}\n",
                encoding="ascii",
            )
            (git_dir / "commondir").write_text(f"{common}\n", encoding="utf-8")
            os.link(
                head_log,
                logs / "HEAD",
                follow_symlinks=False,
            )
            transaction = IsolatedRefTransaction(
                git_dir=git_dir,
                source_head_log=head_log,
                head_log_identity=_identity(head_log_metadata),
                head_log_before=head_log_before,
                source_branch_log=branch_log,
                branch_log_identity=_identity(branch_log_metadata),
                branch_log_before=branch_log_before,
            )
            transaction.validate_records()
            yield transaction

    @contextmanager
    def isolated_head_reflog_transaction(
        self,
        source: Path,
        *,
        branch: str,
    ) -> Iterator[IsolatedHeadReflogTransaction]:
        """Yield a private symbolic HEAD sharing only the pinned source HEAD log.

        The caller holds the source ``HEAD.lock`` and ``index.lock``. Symbolic
        HEAD can therefore move in trusted temporary metadata without touching
        the source worktree while Git appends an exact record to the real HEAD
        reflog through a verified hard link.
        """

        common = (source / ".git").resolve()
        if any(character in str(common) for character in ("\n", "\r", "\0")):
            raise ConnectorError("repository Git metadata path is invalid")
        head_log = common / "logs" / "HEAD"
        if head_log.parent.resolve() != head_log.parent:
            raise ConnectorError(
                "repository HEAD reflog directory cannot be a symbolic link"
            )
        try:
            head_log_metadata = head_log.lstat()
        except FileNotFoundError as error:
            raise ConnectorError(
                "repository HEAD reflog is required for branch publication"
            ) from error
        if (
            not stat.S_ISREG(head_log_metadata.st_mode)
            or head_log_metadata.st_uid != os.geteuid()
            or head_log_metadata.st_nlink != 1
            or head_log_metadata.st_size < 0
            or head_log_metadata.st_size > _MAX_REFLOG_BYTES
        ):
            raise ConnectorError(
                "repository HEAD reflog must be bounded, singly linked, and current-user owned"
            )
        head_log_before = _read_path_bounded(
            head_log,
            maximum_bytes=_MAX_REFLOG_BYTES,
            label="repository HEAD reflog",
            expected_identity=_identity(head_log_metadata),
            expected_links=1,
        )

        with tempfile.TemporaryDirectory(
            prefix="head-transaction-",
            dir=self._root,
        ) as directory:
            git_dir = Path(directory) / "git-dir"
            logs = git_dir / "logs"
            logs.mkdir(parents=True, mode=0o700)
            (git_dir / "HEAD").write_text(
                f"ref: refs/heads/{branch}\n",
                encoding="ascii",
            )
            (git_dir / "commondir").write_text(f"{common}\n", encoding="utf-8")
            os.link(
                head_log,
                logs / "HEAD",
                follow_symlinks=False,
            )
            transaction = IsolatedHeadReflogTransaction(
                git_dir=git_dir,
                source_head_log=head_log,
                head_log_identity=_identity(head_log_metadata),
                head_log_before=head_log_before,
            )
            transaction.validate_records()
            yield transaction

    def lock_repository_config(self, repository: Path) -> LockedGitConfig:
        """Return a context guard that pins local config and excludes writers."""

        return LockedGitConfig(repository)

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
        r"^diff\..+\.(command|textconv|cachetextconv)$",
        r"^difftool\..+\.cmd$",
        r"^merge\..+\.driver$",
        r"^mergetool\..+\.cmd$",
        r"^submodule\..+\.update$",
        r"^remote\..+\.(proxy|pushurl)$",
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

"""Small Git workspace operations for host-assisted development tasks."""

from __future__ import annotations

import os
import re
import signal
import subprocess
from pathlib import Path
from typing import Any

_OUTPUT_LIMIT = 12_000
_GIT_TIMEOUT = 60


class WorkspaceError(RuntimeError):
    """A workspace operation could not complete."""


def _redact(text: str) -> str:
    """Remove user information and common credential query parameters in URLs."""
    text = re.sub(
        r"([a-zA-Z][a-zA-Z0-9+.-]*://)[^/\s]+@",
        r"\1[redacted]@",
        text,
    )
    return re.sub(
        r"([?&](?:access_token|token|password|passwd|secret|api_key)=)[^&#\s]+",
        r"\1[redacted]",
        text,
        flags=re.IGNORECASE,
    )


def _output(text: str | bytes | None) -> str:
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="replace")
    clean = _redact(text or "")
    if len(clean) <= _OUTPUT_LIMIT:
        return clean
    return clean[:4_000] + "\n[output truncated]\n" + clean[-8_000:]


def _execute(
    command: list[str],
    *,
    cwd: Path,
    timeout: float,
    combine_output: bool = False,
) -> subprocess.CompletedProcess[str]:
    # A timed-out test runner may have children holding its output pipes open.
    # Give each operation a process group so timeout also stops those children.
    with subprocess.Popen(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT if combine_output else subprocess.PIPE,
        encoding="utf-8",
        errors="replace",
        start_new_session=os.name != "nt",
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
    ) as process:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            if os.name == "nt":
                try:
                    subprocess.run(
                        ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=10,
                        check=False,
                    )
                except (OSError, subprocess.TimeoutExpired):
                    pass
                if process.poll() is None:
                    process.kill()
            else:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            try:
                exc.output, exc.stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                # An independently detached descendant may still own a pipe.
                # Do not let that extend the caller's wait indefinitely.
                if process.stdout is not None:
                    process.stdout.close()
                if process.stderr is not None:
                    process.stderr.close()
            raise exc
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def _git(
    path: Path,
    *arguments: str,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    try:
        result = _execute(
            ["git", "-C", str(path), *arguments],
            cwd=path,
            timeout=_GIT_TIMEOUT,
        )
    except subprocess.TimeoutExpired as exc:
        detail = _output(exc.stderr or exc.stdout).strip()
        raise WorkspaceError(f"Git timed out after {_GIT_TIMEOUT}s. {detail}".strip()) from None
    except OSError as exc:
        raise WorkspaceError(f"Could not run Git: {_redact(str(exc))}") from None
    if check and result.returncode:
        detail = _output(result.stderr or result.stdout).strip()
        raise WorkspaceError(f"Git failed ({result.returncode}): {detail}")
    return result


def _root(path: Path) -> Path:
    resolved = Path(path).expanduser().resolve()
    if not resolved.is_dir():
        raise WorkspaceError(f"Workspace directory does not exist: {_redact(str(resolved))}")
    result = _git(resolved, "rev-parse", "--show-toplevel")
    return Path(result.stdout.strip()).resolve()


def _common_directory(path: Path) -> Path:
    result = _git(path, "rev-parse", "--git-common-dir")
    return (path / result.stdout.strip()).resolve()


def _branch(path: Path, branch: str) -> None:
    if (
        not isinstance(branch, str)
        or not branch
        or branch.startswith("-")
        or branch == "@"
        or "@{" in branch
        or "\x00" in branch
        or "\n" in branch
        or "\r" in branch
    ):
        raise WorkspaceError("Choose a valid, explicit Git branch name.")
    result = _git(path, "check-ref-format", "--branch", branch, check=False)
    if result.returncode:
        raise WorkspaceError("Choose a valid Git branch name.")


def prepare_worktree(
    repository: Path,
    destination: Path,
    branch: str,
    base: str | None = None,
) -> dict[str, Any]:
    """Create or resume an isolated Git worktree without changing the original.

    Parameters
    ----------
    repository : Path
        Existing non-bare repository or one of its worktrees.
    destination : Path
        New or empty directory, or the exact existing worktree to resume.
    branch : str
        Explicit local branch name. An existing branch is reused as-is.
    base : str, optional
        Commit reference for a new branch. Defaults to the repository's current
        HEAD, including local commits; no fetch or pull is performed.

    Returns
    -------
    dict[str, Any]
        Absolute ``path``, ``branch``, and resolved ``base`` commit. ``base`` is
        the requested/default starting reference; resuming an existing branch
        does not reset it or assert that this reference was its original base.

    Raises
    ------
    WorkspaceError
        If the branch/reference is invalid, a different checkout occupies the
        destination, or Git cannot create the worktree.
    """
    repository = _root(repository)
    destination = Path(destination).expanduser().resolve()
    _branch(repository, branch)
    if destination == repository:
        raise WorkspaceError("Choose a separate directory for the task worktree.")
    if base is not None and (
        not isinstance(base, str)
        or not base
        or base.startswith("-")
        or any(character in base for character in ("\x00", "\n", "\r"))
    ):
        raise WorkspaceError("Choose a valid Git base reference.")
    commit = _git(
        repository,
        "rev-parse",
        "--verify",
        "--end-of-options",
        f"{base if base is not None else 'HEAD'}^{{commit}}",
    ).stdout.strip()

    if destination.exists():
        if not destination.is_dir():
            raise WorkspaceError("The worktree destination is not a directory.")
        if any(destination.iterdir()):
            if _root(destination) != destination:
                raise WorkspaceError("The destination must be the exact worktree root.")
            if _common_directory(repository) != _common_directory(destination):
                raise WorkspaceError("The destination belongs to another repository.")
            if inspect_worktree(destination)["branch"] != branch:
                raise WorkspaceError("The destination is checked out on a different branch.")
            return {"path": str(destination), "branch": branch, "base": commit}

    exists = _git(
        repository, "show-ref", "--verify", "--quiet", f"refs/heads/{branch}", check=False
    )
    if exists.returncode == 0:
        _git(repository, "worktree", "add", "--", str(destination), branch)
    elif exists.returncode == 1:
        _git(
            repository,
            "worktree",
            "add",
            "--no-track",
            "-b",
            branch,
            "--",
            str(destination),
            commit,
        )
    else:
        raise WorkspaceError(f"Could not inspect the branch: {_output(exists.stderr).strip()}")
    return {"path": str(destination), "branch": branch, "base": commit}


def inspect_worktree(path: Path) -> dict[str, Any]:
    """Read the current branch, commit, and changed paths of a worktree.

    Parameters
    ----------
    path : Path
        Worktree directory or a directory inside it.

    Returns
    -------
    dict[str, Any]
        ``branch`` (None for detached HEAD), ``head``, ``dirty``, and
        ``changed_files`` relative to the worktree root. Includes staged,
        unstaged, and untracked files; ignored files are omitted.
    """
    path = _root(path)
    branch_result = _git(path, "symbolic-ref", "--quiet", "--short", "HEAD", check=False)
    if branch_result.returncode not in (0, 1):
        raise WorkspaceError(f"Could not inspect HEAD: {_output(branch_result.stderr).strip()}")
    branch = branch_result.stdout.strip() if branch_result.returncode == 0 else None
    head = _git(path, "rev-parse", "--verify", "HEAD").stdout.strip()
    status = _git(path, "status", "--porcelain=v1", "-z", "--untracked-files=all").stdout
    records = iter(status.split("\x00"))
    changed_files: list[str] = []
    for record in records:
        if not record:
            continue
        changed_files.append(record[3:])
        if "R" in record[:2] or "C" in record[:2]:
            next(records, None)  # Porcelain -z follows a rename with its old name.
    return {
        "branch": branch,
        "head": head,
        "dirty": bool(status),
        "changed_files": list(dict.fromkeys(changed_files)),
    }


def run_checks(
    path: Path,
    commands: list[list[str]],
    timeout: float = 300,
) -> list[dict[str, Any]]:
    """Run explicit argument-vector checks in a worktree without a shell.

    Parameters
    ----------
    path : Path
        Git worktree in which to run the checks.
    commands : list[list[str]]
        Nonempty commands such as ``[["python", "-m", "unittest"]]``. Strings
        containing a whole shell command are not accepted.
    timeout : float, default 300
        Maximum seconds for each command.

    Returns
    -------
    list[dict[str, Any]]
        ``command``, ``exit_code``, and combined ``output`` for each check.
        Nonzero exits are retained; timeouts return exit code 124. Credential
        URLs are redacted and long output is truncated.

    Raises
    ------
    WorkspaceError
        If arguments are malformed or a command could not be started.
    """
    if not isinstance(commands, list) or not commands:
        raise WorkspaceError("Provide at least one check as a list of arguments.")
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not 0 < timeout < float("inf")
    ):
        raise WorkspaceError("The check timeout must be a positive, finite number.")
    for command in commands:
        if (
            not isinstance(command, list)
            or not command
            or any(not isinstance(argument, str) or "\x00" in argument for argument in command)
            or not command[0]
        ):
            raise WorkspaceError("Each check must be a nonempty list of string arguments.")
    path = _root(path)
    results: list[dict[str, Any]] = []
    for command in commands:
        try:
            result = _execute(
                command,
                cwd=path,
                timeout=timeout,
                combine_output=True,
            )
            exit_code, output = result.returncode, _output(result.stdout)
        except subprocess.TimeoutExpired as exc:
            exit_code = 124
            output = _output(exc.stdout) + f"\nCheck timed out after {timeout:g}s."
        except OSError as exc:
            raise WorkspaceError(f"Could not start check: {_redact(str(exc))}") from None
        results.append(
            {
                "command": [_redact(argument) for argument in command],
                "exit_code": exit_code,
                "output": output,
            }
        )
    return results


def publish_branch(path: Path, remote: str = "origin") -> dict[str, Any]:
    """Push an existing clean worktree branch using a normal Git push.

    Parameters
    ----------
    path : Path
        Worktree containing already committed changes.
    remote : str, default 'origin'
        Name of a configured Git remote. Uses Git's normal credentials and
        hooks. Pushes only this branch, without force or accompanying tags.

    Returns
    -------
    dict[str, Any]
        Published ``branch``, ``commit``, and ``remote`` name.

    Raises
    ------
    WorkspaceError
        If the checkout is dirty/detached, the remote is unknown, or push fails.
    """
    path = _root(path)
    state = inspect_worktree(path)
    if state["dirty"]:
        raise WorkspaceError("Commit or remove the remaining worktree changes before publishing.")
    if state["branch"] is None:
        raise WorkspaceError("Check out a branch before publishing; HEAD is detached.")
    if (
        not isinstance(remote, str)
        or not remote
        or remote.startswith("-")
        or any(character in remote for character in ("\x00", "\n", "\r"))
        or remote not in _git(path, "remote").stdout.splitlines()
    ):
        raise WorkspaceError("Choose a configured Git remote name.")
    branch = state["branch"]
    _git(
        path,
        "push",
        "--set-upstream",
        "--no-follow-tags",
        "--",
        remote,
        f"refs/heads/{branch}:refs/heads/{branch}",
    )
    return {"branch": branch, "commit": state["head"], "remote": remote}

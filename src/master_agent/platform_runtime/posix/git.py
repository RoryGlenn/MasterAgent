"""POSIX trusted-Git backend identity."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PosixTrustedGitBackend:
    """Identify the existing POSIX descriptor-bound Git execution path."""

    backend_id: str = "posix-trusted-git"

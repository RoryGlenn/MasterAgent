"""POSIX atomic-publication backend identity."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PosixAtomicPublicationRecoveryBackend:
    """Identify the established descriptor-bound POSIX state transactions."""

    backend_id: str = "posix-atomic-publication"

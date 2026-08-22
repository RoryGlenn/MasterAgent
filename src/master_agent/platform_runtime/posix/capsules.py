"""Linux capability-capsule isolation identity."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class LinuxBubblewrapCapsuleIsolationBackend:
    """Identify the Linux bubblewrap namespace-isolation implementation."""

    backend_id: str = "linux-bubblewrap"

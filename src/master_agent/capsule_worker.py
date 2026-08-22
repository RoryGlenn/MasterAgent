"""Compatibility entrypoint for the POSIX capability-capsule worker.

Importing this platform-neutral module does not load ``resource``.  Capsule
execution selects and validates the POSIX worker explicitly through the
platform runtime before this compatibility entrypoint can run.
"""

from __future__ import annotations

import sys

from master_agent.platform_runtime import (
    PlatformCapabilityUnavailable,
    PlatformContract,
    require_platform_contract,
)


def main() -> int:
    """Delegate to the selected POSIX worker only when explicitly executed."""

    try:
        require_platform_contract(PlatformContract.PROCESS_SUPERVISION)
        require_platform_contract(PlatformContract.CAPSULE_ISOLATION)
        require_platform_contract(PlatformContract.SECURE_FILESYSTEM)
    except PlatformCapabilityUnavailable as error:
        print(f"error: PlatformCapabilityUnavailable: {error}", file=sys.stderr)
        return 2
    from master_agent.platform_runtime.posix.capsule_worker import main as posix_main

    return posix_main()


if __name__ == "__main__":
    raise SystemExit(main())

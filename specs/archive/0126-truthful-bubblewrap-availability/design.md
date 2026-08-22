# Design

## Approach

The POSIX capsule selector discovers or receives one candidate, rejects
relative paths, resolves the path strictly, and applies the same regular-file,
ownership, link-count, write-permission, private-group, and execute checks used
by the worker. The immutable backend carries the resolved executable path.

## Affected components

- `src/master_agent/platform_runtime/posix/capsules.py`
- `src/master_agent/platform_runtime/posix/runtime.py`
- `src/master_agent/platform_runtime/factory.py`
- `src/master_agent/capsule_runtime.py`
- `tests/test_platform_runtime.py`
- platform-runtime and release documentation

## Data flow

Linux runtime selection resolves and validates bubblewrap before setting
`capsule_isolation.available`. The selected backend path is cached as part of
the runtime identity and passed to `CapsuleWorker`, which revalidates it before
use. An explicit path never falls back to ambient discovery. macOS and Windows
fail before inspecting an explicit path.

## Compatibility

Trusted absolute Linux bubblewrap paths retain production isolation. Missing or
unsafe paths now fail earlier through the platform-unavailable contract.
`require_os_sandbox=False` without an explicit path remains test-only.

## Security

Unavailable status and errors contain no candidate path. The bounded cache
keys explicit selection separately, while relative paths are rejected before
they can bind one working directory's executable into another directory's
request. Execution revalidation handles post-selection artifact drift.

## Rejected alternatives

Readiness does not execute bubblewrap or probe namespaces. Kernel/AppArmor
launch failures remain bounded runtime failures rather than making inspection
effectful.

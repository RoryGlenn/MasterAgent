# Design

## Approach

Extend the capsule-isolation contract from an executable marker into a bounded
worker-launch boundary. Linux keeps its existing bubblewrap command and
namespace set. Windows adds a ctypes-backed AppContainer adapter that creates a
zero-capability profile, prepares an account-private runtime projection, grants
the AppContainer SID read/execute access only to that projection and full access
only to one per-call working directory, and launches the isolated interpreter
suspended with an explicit inherited-handle list and AppContainer security
capabilities. The existing Job Object limits are attached before resume.

The projection contains the base interpreter, required runtime DLLs and
standard library, and the restricted capsule worker. It excludes site packages,
tests, package-management tools, and reparse points. A deterministic tree digest
plus the interpreter, worker, native adapter, and process-boundary digests form
the worker identity. The projection is revalidated before each launch.

## Affected components

- capsule isolation and worker-execution platform contracts;
- native Windows AppContainer profile, DACL, runtime projection, pipe, and Job
  Object implementation;
- the portable restricted capsule worker and host-side capsule runtime;
- Windows runtime readiness and hosted standard-user tests;
- promotion evidence, release-content validation, semantic ownership, current
  requirements, and capsule/platform documentation.

## Data flow

1. Windows runtime construction probes required AppContainer, SID, ACL, process
   attribute, pipe, and Job Object symbols without launching capsule code.
2. `CapsuleWorker` requests the selected backend to prepare or revalidate an
   immutable runtime projection and returns its exact component identity.
3. The host validates and encodes one bounded worker envelope without ambient
   credentials.
4. The backend creates a fresh writable work directory, binds only stdin,
   stdout, and stderr handles, applies zero AppContainer capabilities, assigns
   Job Object quotas while suspended, and resumes the child.
5. The host writes the bounded request, drains combined bounded output, kills
   the complete job on timeout or overflow, and removes the work directory.
6. The host accepts only the existing typed worker response. Promotion and
   activation compare the combined component identity before use.

## Compatibility

Linux bubblewrap keeps the same namespace, mounts, environment, protocol,
resource limits, backend name, and worker identity inputs. macOS remains
unavailable. Direct tests may still opt into the non-production subprocess
worker, which never reports production isolation. Provider and side-effect
capsules remain blocked.

## Security

- the AppContainer has no capability SIDs and therefore no IPv4, IPv6, or
  localhost network capability; loopback probes target live host listeners so
  an AppContainer timeout/drop proves filtering rather than an absent service;
- the environment is allowlisted and contains no ambient credentials;
- the runtime projection is read/execute-only for the AppContainer, and only a
  fresh work directory is writable;
- the inherited handle list contains only protocol pipes;
- the Job Object limits process count, CPU, memory, wall time, and output and is
  kill-on-close;
- the worker retains the AST, builtins, audit-hook, input, output, and
  diagnostic bounds;
- all native failures map to bounded reason codes; and
- artifact, ACL, or digest drift fails before the request is executed.

## Rejected alternatives

- Granting broad filesystem capability would defeat the host-file boundary.
- Granting network capabilities and relying on Python checks would not enforce
  OS-level denial.
- Reusing the host temporary directory would give the AppContainer a wider
  writable surface.
- Passing inherited handles without an explicit attribute list would risk
  ambient handle access.
- Depending on an externally installed helper would make package readiness
  depend on an unbound binary; the narrow ctypes adapter is shipped, hashed,
  and promotion-bound with the Python runtime.

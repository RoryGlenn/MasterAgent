# Proposal

## Problem

The offline doctor command can write a secret-free readiness report, but its
output includes the selected local profile path and lacks the correlation,
version, and integrity metadata a helpdesk needs to receive and track one safe
diagnostic artifact. Issue #113 explicitly requires a redacted doctor bundle.

## Desired outcome

An employee can create one private, create-only JSON support bundle containing
only allowlisted doctor fields, bounded runtime version facts, a unique support
identifier, and integrity metadata. The bundle remains useful when setup or
later readiness levels are incomplete and is never uploaded automatically.

## Scope

- Add an offline `support-bundle` command with explicit output and optional
  profile selection.
- Reuse the doctor assessment while excluding local profile paths.
- Add section byte counts and SHA-256 digests.
- Document generation, safe contents, sharing, and escalation.

## Rationale

A single well-defined artifact is easier to review, transfer, correlate, and
verify than ad hoc console output. An allowlist is safer than attempting to
redact arbitrary logs after collecting them.

## Alternatives considered

- Reuse `doctor --output` unchanged. Rejected because it exposes a local path
  and has no helpdesk correlation or integrity metadata.
- Collect logs and environment variables into a ZIP archive. Rejected because
  those sources are high-risk, difficult to redact completely, and unnecessary
  for the acceptance criterion.
- Upload diagnostics automatically. Rejected because delivery destination,
  authorization, retention, and data policy are organization-owned concerns.

## Non-goals

- Network access, telemetry deployment, or automatic upload.
- Hostnames, usernames, command history, logs, environment values, provider
  content, or credential collection.
- Claiming enterprise readiness or satisfying external rollout gates.

## Risks

Future doctor fields could become unsafe if copied implicitly. The bundle uses
an explicit top-level allowlist, tests forbidden values, and never copies the
profile source path.

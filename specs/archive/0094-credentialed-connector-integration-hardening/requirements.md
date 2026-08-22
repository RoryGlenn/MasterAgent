# Requirement deltas

## ADDED

### MA-LIVE-INTEGRATION-001 — Protected credentialed integration evidence

MasterAgent MUST count a provider integration as verified only when reviewed
default-branch code executes a non-skipped live test with real protected
credentials and stable dedicated fixtures. The complete multi-provider matrix
MUST be manual-dispatch only, MUST NOT expose credentials to pull-request or
unreviewed branch code, and MUST keep read, effect, and administration secrets
in separately gated protected environments. Repository variables MUST remain
disabled until the corresponding environment, least-privilege credentials,
fixtures, restrictions, and reviewer rules are complete.

Delegated-only Microsoft coverage MUST use a restricted delegated token whose
provider scopes and remaining lifetime are validated before provider effects.
Application credentials MUST NOT be treated as equivalent evidence for
delegated OneNote or normal Teams operations. Compensatable live mutations MUST
write bounded private recovery state immediately after their provider result,
attempt and independently verify cleanup in-process, and run an independent
same-job cleanup step after ordinary failures. Recovery state MUST NOT be
uploaded or contain credential values. Non-reversible communication tests MUST
target explicitly dedicated nonproduction recipients.

The repository MUST statically test the workflow's triggers, branch binding,
environment names, privilege-specific credential mapping, opt-in gates,
private materialization, recovery step, action pins, and no-artifact boundary.
Missing credentials, fixtures, consent, or environment setup MUST be reported
as incomplete integration setup rather than silently replaced or counted as a
successful provider test.

Credentialed connectors that use a shared tenant gateway MUST bind the exact
product and tenant or cloud identifier in their API base path before credential
resolution. Relative, absolute, redirected, response, and pagination URLs MUST
NOT escape that path even when they remain on the same origin. A distinct
provider browser/UI root MAY be used only for sanitized user-facing references;
it MUST be independently allowlisted, approval-bound, and MUST never receive
connector credentials.

## MODIFIED

None.

## REMOVED

None.

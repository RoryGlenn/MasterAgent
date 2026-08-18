# Requirement deltas

## ADDED

### MA-ADVISORY-005 — Broker-owned live specialist adapter

A live advisory model adapter MUST execute only through the repository-owned broker, MUST preselect exactly one reviewed read-only specialist, MUST disable ambient host inference and extension discovery, MUST reject non-read tool use, MUST bind execution to the exact task/repository/profile state, and MUST fall back to direct-parent work when the adapter is unavailable or unsafe.

## MODIFIED

None.

## REMOVED

None.

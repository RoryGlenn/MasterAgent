# Proposal

## Problem

Company rollout issue #113 depends on protected live connector evidence. The
live-integration documentation requires an authenticated proxy username and
password for managed-network evidence, but the read workflow does not map
protected secrets to the fixed credential-broker environment names.
Provisioning the documented credentials would therefore still fail before the
first tunneled provider read.

## Desired outcome

The reviewed read job receives the dedicated test proxy credentials only while
the live connector harness runs, and static workflow evidence proves that the
effect and administration jobs cannot access those read credentials.

## Scope

Add privilege-specific read-environment proxy secret mappings, workflow
contract tests, and exact operator documentation.

## Rationale

The runtime already requires the fixed broker references
`MASTER_AGENT_PROXY_USERNAME` and `MASTER_AGENT_PROXY_PASSWORD`. Mapping
environment-scoped secrets at the protected workflow boundary completes the
existing design without adding another credential path.

## Alternatives considered

Embedding credentials in the integration TOML or proxy URL was rejected
because it would copy secrets into configuration and violate the network
profile requirement. Repository-wide secrets were rejected because they would
erase the existing privilege separation.

## Non-goals

This change does not create provider accounts, issue proxy credentials,
provision an inspection proxy, enable the live matrix, or claim successful
managed-network evidence. It advances but does not close #94 or #113.

## Risks

An overly broad mapping could expose read credentials to effect or
administration jobs. Static tests therefore pin the exact read-only mapping and
reject those secret names elsewhere in the workflow.

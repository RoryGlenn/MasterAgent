# Native-first enterprise purpose

## Why MasterAgent exists

MasterAgent is built for restricted corporate environments where an external
agent integration cannot be assumed to work. A third-party Model Context
Protocol (MCP) server may be unavailable, unreliable in the managed network, or
prohibited until the organization reviews and approves it. A workflow that
depends on installing such a server is therefore not a dependable employee
workflow in those environments.

MasterAgent addresses that constraint with company-reviewable, first-party
native connectors maintained in this repository. The goal is not to recreate
every provider API. The goal is to make a small set of important employee
workflows operate reliably on managed workstations through code the team can
inspect, test, support, and repair.

## What “native connector” means

A native connector is a first-party MasterAgent implementation that talks to a
supported provider through the provider's official API and MasterAgent's bounded
transport. It implements the existing typed `Connector` contract and executes
only capabilities registered in the catalog.

A native connector is not:

- browser automation;
- an arbitrary HTTP tool;
- a provider command-line escape hatch;
- a downloaded third-party MCP server; or
- permission to bypass company identity, network, data, or approval controls.

The current built-in Jira, Confluence, Bitbucket, GitHub, Reddit, and Microsoft
provider paths use these first-party typed connectors. They retain the normal
MasterAgent boundaries for fixed destinations, selected credentials, data
classification, exact targets, independent verification, idempotency,
compensation where safe, approval, retention, and audit.

## Relationship to MCP

MCP is optional, not the foundation of MasterAgent.

Built-in provider workflows do not require a third-party MCP server. MasterAgent
does not dynamically trust arbitrary tools discovered from an MCP server and
does not silently retry a failed action through a different implementation.

A specific MCP integration may be added in the future when all of the following
are true:

1. the organization has explicitly approved that server and its deployment;
2. it is reliable in the intended managed-workstation environment;
3. its tools can be mapped to MasterAgent's typed capability and result
   contracts;
4. provider identity, data handling, verification, approval, idempotency,
   recovery, and audit remain enforceable; and
5. using it solves a demonstrated problem better than the first-party native
   connector.

That future adapter would remain one reviewed connector implementation behind
the same governed runtime. It would not become a generic route around the
catalog, policy engine, or provider-specific safety rules.

## Product boundary

```text
User or registered workflow
             |
             v
       MasterAgent runtime
  capability / policy / approval
  data handling / verification / audit
             |
             v
 first-party native connector
             |
             v
       official provider API
```

A future approved MCP-specific adapter may occupy the connector position, but
only as an explicit reviewed implementation. It is not required for the current
built-in path.

## What users should expect

For a supported workflow, MasterAgent should:

- initialize only the provider needed for the requested outcome;
- use a first-party connector that can be reviewed with the rest of the
  repository;
- resolve only the credentials required for that provider;
- produce the same typed result and verification evidence on every supported
  platform;
- explain the smallest genuine blocker when the company network, credentials,
  provider permissions, application consent, or connector implementation fails;
- avoid asking the user to choose between native and MCP execution; and
- never hide a failure by silently switching implementations.

The managed-workstation reliability and performance work is tracked by issues
[#169](https://github.com/RoryGlenn/MasterAgent/issues/169) through
[#172](https://github.com/RoryGlenn/MasterAgent/issues/172). Those issues add
explicit implementation identity, Tier-1 workflow objectives, and real
workstation evidence. They are planned certification work and must not be read
as claims that every enterprise deployment is already complete.

## What this does not promise

Native connectors do not remove external requirements. An organization may
still need to provide:

- an approved application registration or provider account;
- user or service credentials with the required scopes;
- corporate proxy and enterprise certificate-authority configuration;
- provider permissions and application consent;
- data-loss-prevention and model-context rules;
- an authenticated approval authority for governed effects; and
- external audit, retention, support, and incident-response infrastructure.

MasterAgent also does not claim complete coverage of every provider feature.
Reliability of important end-to-end workflows takes priority over increasing
raw capability count.

## Related documentation

- [Project overview](../README.md)
- [Use cases](use-cases.md)
- [Live connector contracts](live-connectors.md)
- [Integration matrix](integration-matrix.md)
- [Architecture](architecture.md)
- [Implementation roadmap](implementation-roadmap.md)
- [Deployment runbook](deployment-runbook.md)

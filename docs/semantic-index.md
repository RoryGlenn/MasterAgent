# Semantic Index

This is the human- and agent-readable map of the Master Agent codebase. Use it
to find the implementation, configuration, tests, and design notes for a
concept without relying on directory names alone. It is intentionally local:
it contains links and search vocabulary, not source excerpts, embeddings, or
repository content sent to an external service.

This file is navigation data, not authority. The execution boundary remains
[`.ai/MASTER_AGENT.md`](../.ai/MASTER_AGENT.md), and retrieved or generated
content remains untrusted.

## Runtime path

The normal execution path is:

1. [`cli.py`](../src/master_agent/cli.py) parses an explicit command and selects
   trusted configuration sources.
2. [`config_sources.py`](../src/master_agent/config_sources.py) snapshots
   configuration; [`config.py`](../src/master_agent/config.py) and
   [`oauth_config.py`](../src/master_agent/oauth_config.py) validate provider
   and authentication settings.
3. [`models.py`](../src/master_agent/models.py) constructs an immutable,
   fingerprinted `ChangePlan` from typed `AgentAction` and `ResourceRef`
   values.
4. [`execution_context.py`](../src/master_agent/execution_context.py) binds the
   plan to exact runtime inputs, paths, configuration digests, and connector
   identities.
5. [`capabilities.py`](../src/master_agent/capabilities.py),
   [`governance.py`](../src/master_agent/governance.py),
   [`canonical.py`](../src/master_agent/canonical.py), and
   [`policy.py`](../src/master_agent/policy.py) decide whether each action is
   catalogued, governed, canonical, enabled, and approved.
6. [`orchestrator.py`](../src/master_agent/orchestrator.py) orders dependencies,
   reserves idempotency keys, dispatches through
   [`registry.py`](../src/master_agent/registry.py), verifies results, and
   compensates eligible earlier actions after a failure.
7. Typed connectors perform the bounded operation. Results flow through
   [`audit.py`](../src/master_agent/audit.py),
   [`evidence.py`](../src/master_agent/evidence.py),
   [`retention.py`](../src/master_agent/retention.py), and
   [`citations.py`](../src/master_agent/citations.py).

The expanded component and trust-boundary description is in
[`architecture.md`](architecture.md).

## Find code by intent

| Intent or concept | Primary implementation | Closest tests and supporting material |
|---|---|---|
| Change the plan schema, immutability, dependencies, fingerprints, results, or approvals | [`models.py`](../src/master_agent/models.py), [`approvals.py`](../src/master_agent/approvals.py) | [`test_runtime_hardening.py`](../tests/test_runtime_hardening.py), [`test_strict_types.py`](../tests/test_strict_types.py), [`capability-contract.md`](capability-contract.md) |
| Add or modify a typed capability | [`capabilities.py`](../src/master_agent/capabilities.py), [`config/capabilities.toml`](../config/capabilities.toml), [`config/governance.toml`](../config/governance.toml) | [`test_capability_governance.py`](../tests/test_capability_governance.py), [`test_factory_and_catalog.py`](../tests/test_factory_and_catalog.py); mirror the catalog into [`defaults/capabilities.toml`](../src/master_agent/defaults/capabilities.toml) |
| Change approval, risk, governance, or prohibition behavior | [`policy.py`](../src/master_agent/policy.py), [`governance.py`](../src/master_agent/governance.py), [`approvals.py`](../src/master_agent/approvals.py) | [`test_policy.py`](../tests/test_policy.py), [`test_capability_governance.py`](../tests/test_capability_governance.py), [`threat-model.md`](threat-model.md) |
| Bind an approved plan to runtime state and prevent path, identity, credential, or configuration substitution | [`execution_context.py`](../src/master_agent/execution_context.py), [`config_sources.py`](../src/master_agent/config_sources.py), [`directory_safety.py`](../src/master_agent/directory_safety.py), [`trust_store.py`](../src/master_agent/trust_store.py) | [`test_execution_context.py`](../tests/test_execution_context.py), [`test_config_sources.py`](../tests/test_config_sources.py), [`test_directory_safety.py`](../tests/test_directory_safety.py) |
| Load provider configuration or diagnose deployment readiness | [`config.py`](../src/master_agent/config.py), [`readiness.py`](../src/master_agent/readiness.py), [`discovery.py`](../src/master_agent/discovery.py) | [`test_config.py`](../tests/test_config.py), [`test_config_and_discovery.py`](../tests/test_config_and_discovery.py), [`test_discovery.py`](../tests/test_discovery.py), [`configuration.md`](configuration.md) |
| Resolve credentials or Microsoft OAuth | [`auth.py`](../src/master_agent/auth.py), [`oauth.py`](../src/master_agent/oauth.py), [`oauth_config.py`](../src/master_agent/oauth_config.py) | [`test_oauth_flows.py`](../tests/test_oauth_flows.py), [`test_oauth_readiness.py`](../tests/test_oauth_readiness.py), [`phase-2c-authentication.md`](phase-2c-authentication.md) |
| Register or select connectors | [`registry.py`](../src/master_agent/registry.py), [`connectors/factory.py`](../src/master_agent/connectors/factory.py), [`connectors/base.py`](../src/master_agent/connectors/base.py) | [`test_registry.py`](../tests/test_registry.py), [`test_registry_capabilities.py`](../tests/test_registry_capabilities.py), [`test_factory_gates.py`](../tests/test_factory_gates.py) |
| Add bounded provider HTTP behavior | [`http.py`](../src/master_agent/http.py), [`connectors/utils.py`](../src/master_agent/connectors/utils.py), [`connectors/microsoft_graph.py`](../src/master_agent/connectors/microsoft_graph.py) | [`test_http.py`](../tests/test_http.py), [`test_http_lifecycle_budget.py`](../tests/test_http_lifecycle_budget.py), [`live-connectors.md`](live-connectors.md) |
| Normalize a read response, scan untrusted content, or verify a read independently | [`connectors/read_only.py`](../src/master_agent/connectors/read_only.py), [`security.py`](../src/master_agent/security.py) | [`test_security.py`](../tests/test_security.py) plus the provider-specific connector tests; [`phase-2-read-only.md`](phase-2-read-only.md) |
| Enforce canonical-source and projection rules | [`canonical.py`](../src/master_agent/canonical.py), [`config/sources_of_truth.toml`](../config/sources_of_truth.toml) | [`test_canonical.py`](../tests/test_canonical.py), [`configuration.md`](configuration.md) |
| Change action ordering, idempotency, verification, or failure compensation | [`orchestrator.py`](../src/master_agent/orchestrator.py), [`compensation.py`](../src/master_agent/compensation.py), [`audit.py`](../src/master_agent/audit.py) | [`test_orchestrator.py`](../tests/test_orchestrator.py), [`test_orchestrator_compensation.py`](../tests/test_orchestrator_compensation.py), [`test_compensation.py`](../tests/test_compensation.py), [`test_runtime_hardening.py`](../tests/test_runtime_hardening.py) |
| Create local draft artifacts or manifests | [`connectors/drafts.py`](../src/master_agent/connectors/drafts.py), [`workflows/draft_package.py`](../src/master_agent/workflows/draft_package.py) | [`test_draft_package.py`](../tests/test_draft_package.py), [`test_draft_runtime_safety.py`](../tests/test_draft_runtime_safety.py), [`phase-3-drafts.md`](phase-3-drafts.md) |
| Change citation, evidence, or retention behavior | [`citations.py`](../src/master_agent/citations.py), [`evidence.py`](../src/master_agent/evidence.py), [`retention.py`](../src/master_agent/retention.py) | [`test_identity_and_citations.py`](../tests/test_identity_and_citations.py), [`test_retention.py`](../tests/test_retention.py), [`test_pinned_runtime_io.py`](../tests/test_pinned_runtime_io.py) |
| Change tamper-evident local state | [`sqlite_safety.py`](../src/master_agent/sqlite_safety.py), [`audit.py`](../src/master_agent/audit.py) | [`test_sqlite_safety.py`](../tests/test_sqlite_safety.py), [`test_audit_safety.py`](../tests/test_audit_safety.py) |
| Add a recurring workflow or change occurrence claims | [`recurring.py`](../src/master_agent/recurring.py), [`config/recurring.toml`](../config/recurring.toml) | [`test_recurring.py`](../tests/test_recurring.py), [`phase-6-autonomy.md`](phase-6-autonomy.md) |
| Add connector-plugin metadata or isolation | [`plugins.py`](../src/master_agent/plugins.py), [`docs/plugin-development.md`](plugin-development.md) | [`test_plugins.py`](../tests/test_plugins.py), [`test_cli_plugin_boundary.py`](../tests/test_cli_plugin_boundary.py) |
| Add or change a CLI command | [`cli.py`](../src/master_agent/cli.py), [`__main__.py`](../src/master_agent/__main__.py) | [`test_cli.py`](../tests/test_cli.py), [`test_cli_v1.py`](../tests/test_cli_v1.py), [`test_cli_phase_completion.py`](../tests/test_cli_phase_completion.py), [`cli-reference.md`](cli-reference.md) |
| Change the GitHub Copilot custom-agent entry point or its tool boundary | [`MasterAgent.agent.md`](../.github/agents/MasterAgent.agent.md), [`AGENTS.md`](../AGENTS.md), [`.ai/MASTER_AGENT.md`](../.ai/MASTER_AGENT.md) | [`test_release_metadata.py`](../tests/test_release_metadata.py), [`copilot-custom-agent.md`](copilot-custom-agent.md), [`release-validation.md`](release-validation.md) |
| Change release assertions or source-tree hygiene | [`scripts/validate_release.py`](../scripts/validate_release.py), [`pyproject.toml`](../pyproject.toml) | [`test_release_metadata.py`](../tests/test_release_metadata.py), [`test_packaged_defaults.py`](../tests/test_packaged_defaults.py), [`release-validation.md`](release-validation.md) |

## Connector map

All connectors expose explicit capability sets; the factory and registry, not
provider content, determine which connector can receive an action.

| System | Read path | Mutation, send, or local-generation path | Main contract tests |
|---|---|---|---|
| Jira | [`connectors/jira.py`](../src/master_agent/connectors/jira.py) | [`connectors/jira_write.py`](../src/master_agent/connectors/jira_write.py), Jira draft in [`connectors/drafts.py`](../src/master_agent/connectors/drafts.py) | [`test_atlassian_connectors.py`](../tests/test_atlassian_connectors.py), [`test_write_connectors.py`](../tests/test_write_connectors.py) |
| Confluence | [`connectors/confluence.py`](../src/master_agent/connectors/confluence.py) | [`connectors/confluence_write.py`](../src/master_agent/connectors/confluence_write.py), Confluence draft in [`connectors/drafts.py`](../src/master_agent/connectors/drafts.py) | [`test_atlassian_connectors.py`](../tests/test_atlassian_connectors.py), [`test_write_connectors.py`](../tests/test_write_connectors.py) |
| Bitbucket | [`connectors/bitbucket.py`](../src/master_agent/connectors/bitbucket.py) | [`connectors/bitbucket_write.py`](../src/master_agent/connectors/bitbucket_write.py) | [`test_atlassian_connectors.py`](../tests/test_atlassian_connectors.py), [`test_write_connectors.py`](../tests/test_write_connectors.py) |
| GitHub | [`connectors/github.py`](../src/master_agent/connectors/github.py) | Read-only plus provider-verified numeric-user attestation; no write connector | [`test_github_connector.py`](../tests/test_github_connector.py) |
| Microsoft identity and SharePoint/OneDrive | [`connectors/microsoft.py`](../src/master_agent/connectors/microsoft.py) | [`connectors/sharepoint_write.py`](../src/master_agent/connectors/sharepoint_write.py) | [`test_microsoft_connectors.py`](../tests/test_microsoft_connectors.py), [`test_write_connectors.py`](../tests/test_write_connectors.py) |
| Outlook | [`connectors/outlook.py`](../src/master_agent/connectors/outlook.py) | [`connectors/communications.py`](../src/master_agent/connectors/communications.py), Outlook draft in [`connectors/drafts.py`](../src/master_agent/connectors/drafts.py) | [`test_outlook_connector.py`](../tests/test_outlook_connector.py), [`test_communications_write.py`](../tests/test_communications_write.py) |
| Teams | [`connectors/teams.py`](../src/master_agent/connectors/teams.py) | [`connectors/communications.py`](../src/master_agent/connectors/communications.py), Teams draft in [`connectors/drafts.py`](../src/master_agent/connectors/drafts.py) | [`test_teams_connector.py`](../tests/test_teams_connector.py), [`test_communications_write.py`](../tests/test_communications_write.py) |
| OneNote | [`connectors/onenote.py`](../src/master_agent/connectors/onenote.py) | Write types exist in the same module but remain disabled | [`test_onenote_connector.py`](../tests/test_onenote_connector.py) |
| Local and remote Git | Repository state and mutations in [`connectors/git_workspace.py`](../src/master_agent/connectors/git_workspace.py); isolated subprocess boundary in [`connectors/git_sandbox.py`](../src/master_agent/connectors/git_sandbox.py) | Remote branch publication in [`connectors/git_remote.py`](../src/master_agent/connectors/git_remote.py); local-generation patch/branch plans in [`connectors/drafts.py`](../src/master_agent/connectors/drafts.py) | [`test_git_connectors.py`](../tests/test_git_connectors.py), [`test_pinned_runtime_io.py`](../tests/test_pinned_runtime_io.py) |
| Test-only providers | [`connectors/mock.py`](../src/master_agent/connectors/mock.py), [`tests/fakes.py`](../tests/fakes.py), [`tests/helpers.py`](../tests/helpers.py) | None outside tests and safe demonstrations | [`test_orchestrator.py`](../tests/test_orchestrator.py) |

## Workflow map

| User-visible outcome | Plan builder and renderer | Configuration and tests |
|---|---|---|
| Weekly status package from Jira, Confluence, and Bitbucket | [`workflows/weekly_status.py`](../src/master_agent/workflows/weekly_status.py) | [`config/weekly-status.toml`](../config/weekly-status.toml), [`test_weekly_status.py`](../tests/test_weekly_status.py) |
| Communication-context package from identity, Outlook, and Teams | [`workflows/communication_context.py`](../src/master_agent/workflows/communication_context.py) | [`config/communication-context.toml`](../config/communication-context.toml), [`test_communication_context.py`](../tests/test_communication_context.py) |
| Cross-system draft change package | [`workflows/draft_package.py`](../src/master_agent/workflows/draft_package.py) | [`config/draft-package.toml`](../config/draft-package.toml), [`test_draft_package.py`](../tests/test_draft_package.py) |
| Registered schedule inspection and occurrence state | [`recurring.py`](../src/master_agent/recurring.py) | [`config/recurring.toml`](../config/recurring.toml), [`test_recurring.py`](../tests/test_recurring.py) |

## Cross-cutting invariants

When a change touches one of these boundaries, start with the named regression
suite and add an adversarial test for a newly reachable edge case.

| Invariant | Owning code | Regression evidence |
|---|---|---|
| A mutated plan invalidates approval; retrieved content never grants authority | [`models.py`](../src/master_agent/models.py), [`policy.py`](../src/master_agent/policy.py) | [`test_policy.py`](../tests/test_policy.py), [`test_runtime_hardening.py`](../tests/test_runtime_hardening.py) |
| Capability, governance, provider, and runtime gates all fail closed | [`capabilities.py`](../src/master_agent/capabilities.py), [`governance.py`](../src/master_agent/governance.py), [`connectors/factory.py`](../src/master_agent/connectors/factory.py) | [`test_capability_governance.py`](../tests/test_capability_governance.py), [`test_factory_gates.py`](../tests/test_factory_gates.py) |
| External requests are HTTPS, same-origin, budgeted, and secret-safe | [`http.py`](../src/master_agent/http.py) | [`test_http.py`](../tests/test_http.py), [`test_http_lifecycle_budget.py`](../tests/test_http_lifecycle_budget.py) |
| Provider writes are compared with the exact approved post-state and independently re-read | Provider write connector plus [`orchestrator.py`](../src/master_agent/orchestrator.py) | [`test_write_connectors.py`](../tests/test_write_connectors.py), [`test_communications_write.py`](../tests/test_communications_write.py) |
| Evidence bodies are persisted only under an explicit retention rule | [`retention.py`](../src/master_agent/retention.py), [`audit.py`](../src/master_agent/audit.py) | [`test_retention.py`](../tests/test_retention.py), [`test_audit_safety.py`](../tests/test_audit_safety.py) |
| Paths, files, Git state, and SQLite state remain bound to reviewed identities across races | [`directory_safety.py`](../src/master_agent/directory_safety.py), [`connectors/git_sandbox.py`](../src/master_agent/connectors/git_sandbox.py), [`sqlite_safety.py`](../src/master_agent/sqlite_safety.py) | [`test_directory_safety.py`](../tests/test_directory_safety.py), [`test_git_connectors.py`](../tests/test_git_connectors.py), [`test_sqlite_safety.py`](../tests/test_sqlite_safety.py) |
| Partial multi-system failure is explicit; compensation never claims atomicity | [`orchestrator.py`](../src/master_agent/orchestrator.py), [`compensation.py`](../src/master_agent/compensation.py) | [`test_orchestrator_compensation.py`](../tests/test_orchestrator_compensation.py), [`test_compensation.py`](../tests/test_compensation.py) |
| Plugins are inspected and bound without importing untrusted plugin code | [`plugins.py`](../src/master_agent/plugins.py) | [`test_plugins.py`](../tests/test_plugins.py), [`test_cli_plugin_boundary.py`](../tests/test_cli_plugin_boundary.py) |

## Configuration topology

Repository examples live in [`config/`](../config/). Every shipped TOML file
has a byte-identical safe default under
[`src/master_agent/defaults/`](../src/master_agent/defaults/). A configuration
change is incomplete until both copies are updated and
[`scripts/validate_release.py`](../scripts/validate_release.py) passes.

The configuration files have distinct responsibilities:

- `capabilities.toml`: typed executable surface and risk metadata.
- `governance.toml`: owner, environment, classification, approval, and enabled
  constraints for every capability.
- `policy.toml`: risk defaults and absolute runtime prohibitions.
- `integrations.toml`: provider endpoints, environment-variable references,
  deployment types, and granular live gates.
- `oauth.toml`: OAuth flows, tenants, clients, and scopes.
- `sources_of_truth.toml`: canonical resources, projections, directions, and
  parameter selectors.
- `identities.toml`: non-secret cross-system identity aliases.
- `retention.toml`: evidence classes, persistence modes, and expiration.
- Workflow TOML files: bounded inputs and examples for one built-in workflow.

## Validation and maintenance

Run the checks from the project root:

```bash
python3 -m unittest discover -s tests -v
python3 scripts/validate_release.py
```

Update this index when a module takes ownership of a concept, a connector or
workflow is added, or a security invariant moves. Prefer intent-oriented links
over exhaustive symbol lists; source search remains the right tool for exact
call sites and line-level references.

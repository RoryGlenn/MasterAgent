"""Approval-bound live execution context tests."""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from pathlib import Path
from unittest.mock import MagicMock, patch

from master_agent.cli import main
from master_agent.config import IntegrationConfig
from master_agent.config_sources import ConfigSnapshot
from master_agent.connectors.factory import build_live_registry
from master_agent.errors import ConfigurationError
from master_agent.execution_context import (
    build_execution_context,
    build_runtime_execution_binding,
    enforce_execution_context,
)
from master_agent.models import (
    AgentAction,
    AuthoritySource,
    ChangePlan,
    DataClassification,
    ResourceRef,
    RiskLevel,
)
from master_agent.registry import ConnectorRegistry


class ExecutionContextTests(unittest.TestCase):
    """Verify approvals cover runtime destinations and trust roots."""

    def test_changed_resolved_origin_is_rejected_before_connector_construction(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            integrations_path = root / "integrations.toml"
            integrations_path.write_text(_JIRA_ENV_CONFIG, encoding="utf-8")
            source_plan = root / "plan.json"
            source_plan.write_text(
                json.dumps(_plan().to_dict()),
                encoding="utf-8",
            )
            bound_plan = root / "bound-plan.json"

            with (
                patch.dict(
                    os.environ,
                    {"MASTER_AGENT_JIRA_BASE_URL": "https://tenant-a.atlassian.net"},
                ),
                redirect_stdout(io.StringIO()),
            ):
                result = main(
                    [
                        "bind-context",
                        str(source_plan),
                        "--integrations",
                        str(integrations_path),
                        "--output",
                        str(bound_plan),
                    ]
                )
            self.assertEqual(result, 0)

            error_output = io.StringIO()
            with (
                patch.dict(
                    os.environ,
                    {"MASTER_AGENT_JIRA_BASE_URL": ("https://tenant-b.atlassian.net")},
                ),
                patch("master_agent.cli.build_live_registry") as build_registry,
                redirect_stderr(error_output),
            ):
                result = main(
                    [
                        "run",
                        str(bound_plan),
                        "--apply",
                        "--connector-mode",
                        "live",
                        "--integrations",
                        str(integrations_path),
                    ]
                )

            self.assertEqual(result, 1)
            self.assertIn("connector origin or CA identity", error_output.getvalue())
            build_registry.assert_not_called()

    def test_ca_bundle_content_and_path_are_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            integrations_path = root / "integrations.toml"
            integrations_path.write_text(_JIRA_CA_CONFIG, encoding="utf-8")
            first_ca = root / "first.pem"
            second_ca = root / "second.pem"
            first_ca.write_text("FIRST CA\n", encoding="utf-8")
            second_ca.write_text("SECOND CA\n", encoding="utf-8")
            integrations = IntegrationConfig.from_toml(integrations_path)

            first = build_execution_context(
                integrations,
                environ={"MASTER_AGENT_ENTERPRISE_CA_BUNDLE": str(first_ca)},
            )
            changed_content = first_ca.write_text("CHANGED CA\n", encoding="utf-8")
            self.assertGreater(changed_content, 0)
            second = build_execution_context(
                integrations,
                environ={"MASTER_AGENT_ENTERPRISE_CA_BUNDLE": str(first_ca)},
            )
            moved = build_execution_context(
                integrations,
                environ={"MASTER_AGENT_ENTERPRISE_CA_BUNDLE": str(second_ca)},
            )

            self.assertNotEqual(first.connectors, second.connectors)
            self.assertNotEqual(second.connectors, moved.connectors)

    def test_origin_change_after_construction_is_rejected_before_execution(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            integrations_path = root / "integrations.toml"
            integrations_path.write_text(_JIRA_ENV_CONFIG, encoding="utf-8")
            source_plan = root / "plan.json"
            source_plan.write_text(json.dumps(_plan().to_dict()), encoding="utf-8")
            bound_plan = root / "bound-plan.json"

            with patch.dict(
                os.environ,
                {"MASTER_AGENT_JIRA_BASE_URL": "https://tenant-a.atlassian.net"},
            ):
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(
                        main(
                            [
                                "bind-context",
                                str(source_plan),
                                "--integrations",
                                str(integrations_path),
                                "--draft-output-dir",
                                str(root / "drafts"),
                                "--output",
                                str(bound_plan),
                            ]
                        ),
                        0,
                    )

                def change_origin(
                    *_args: object, **_kwargs: object
                ) -> ConnectorRegistry:
                    os.environ["MASTER_AGENT_JIRA_BASE_URL"] = (
                        "https://tenant-b.atlassian.net"
                    )
                    return ConnectorRegistry()

                with (
                    patch(
                        "master_agent.cli.build_live_registry",
                        side_effect=change_origin,
                    ) as build_registry,
                    patch("master_agent.cli._orchestrator") as orchestrator,
                    redirect_stderr(io.StringIO()),
                ):
                    result = main(
                        [
                            "run",
                            str(bound_plan),
                            "--apply",
                            "--connector-mode",
                            "live",
                            "--integrations",
                            str(integrations_path),
                            "--draft-output-dir",
                            str(root / "drafts"),
                        ]
                    )

            self.assertEqual(result, 1)
            build_registry.assert_called_once()
            self.assertIsNotNone(
                build_registry.call_args.kwargs["approved_execution_context"]
            )
            orchestrator.assert_not_called()

    def test_factory_rejects_each_changed_approved_connector_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            integrations_path = root / "integrations.toml"
            integrations_path.write_text(_JIRA_CA_CONFIG, encoding="utf-8")
            ca_bundle = root / "approved.pem"
            ca_bundle.write_text("APPROVED CA\n", encoding="ascii")
            environ = {"MASTER_AGENT_ENTERPRISE_CA_BUNDLE": str(ca_bundle)}
            integrations = IntegrationConfig.from_toml(integrations_path)
            approved = build_execution_context(integrations, environ=environ)
            binding = approved.connectors[0]
            changed_bindings = (
                (
                    "config identity",
                    replace(binding, config_identity_sha256="0" * 64),
                ),
                (
                    "base URL",
                    replace(
                        binding,
                        resolved_base_url="https://other.atlassian.net",
                    ),
                ),
                (
                    "origin",
                    replace(binding, resolved_origin="https://other.atlassian.net"),
                ),
                (
                    "CA path",
                    replace(binding, ca_bundle_path=str(root / "other.pem")),
                ),
                (
                    "CA digest",
                    replace(binding, ca_bundle_sha256="0" * 64),
                ),
            )

            for expected_detail, changed in changed_bindings:
                with self.subTest(expected_detail=expected_detail):
                    changed_context = replace(approved, connectors=(changed,))
                    with self.assertRaisesRegex(ConfigurationError, expected_detail):
                        build_live_registry(
                            integrations,
                            environ=environ,
                            systems={"jira"},
                            approved_execution_context=changed_context,
                        )

            changed_integrations = replace(approved, integrations_sha256="0" * 64)
            with self.assertRaisesRegex(ConfigurationError, "integrations bundle"):
                build_live_registry(
                    integrations,
                    environ=environ,
                    systems={"jira"},
                    approved_execution_context=changed_integrations,
                )

    def test_tls_uses_approved_bytes_during_ca_path_swap_and_restore(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            integrations_path = root / "integrations.toml"
            integrations_path.write_text(_JIRA_CA_CONFIG, encoding="utf-8")
            ca_bundle = root / "active.pem"
            replacement = root / "replacement.pem"
            saved = root / "saved.pem"
            approved_bytes = b"APPROVED CA\n"
            attacker_bytes = b"ATTACKER CA\n"
            ca_bundle.write_bytes(approved_bytes)
            replacement.write_bytes(attacker_bytes)
            environ = {"MASTER_AGENT_ENTERPRISE_CA_BUNDLE": str(ca_bundle)}
            integrations = IntegrationConfig.from_toml(integrations_path)
            approved = build_execution_context(integrations, environ=environ)
            before_build = build_execution_context(integrations, environ=environ)
            during_swap = []

            def swap_path_then_restore(*args: object, **kwargs: object) -> MagicMock:
                self.assertEqual(args, ())
                ca_bundle.replace(saved)
                replacement.replace(ca_bundle)
                try:
                    during_swap.append(
                        build_execution_context(integrations, environ=environ)
                    )
                finally:
                    ca_bundle.replace(replacement)
                    saved.replace(ca_bundle)
                return MagicMock()

            with patch(
                "master_agent.http.ssl.create_default_context",
                side_effect=swap_path_then_restore,
            ) as create_context:
                registry = build_live_registry(
                    integrations,
                    environ=environ,
                    systems={"jira"},
                    approved_execution_context=approved,
                )

            after_build = build_execution_context(integrations, environ=environ)
            self.assertIn("jira", registry.systems())
            self.assertEqual(before_build, approved)
            self.assertEqual(after_build, approved)
            self.assertEqual(len(during_swap), 1)
            self.assertNotEqual(during_swap[0], approved)
            create_context.assert_called_once_with(
                cadata=approved_bytes.decode("ascii")
            )
            self.assertEqual(ca_bundle.read_bytes(), approved_bytes)

    def test_context_round_trip_is_part_of_plan_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            integrations_path = Path(directory) / "integrations.toml"
            integrations_path.write_text(_JIRA_ENV_CONFIG, encoding="utf-8")
            integrations = IntegrationConfig.from_toml(integrations_path)
            context = build_execution_context(
                integrations,
                environ={
                    "MASTER_AGENT_JIRA_BASE_URL": "https://tenant-a.atlassian.net"
                },
            )
            original = _plan()
            bound = ChangePlan.from_dict(
                {**original.to_dict(), "execution_context": context.to_dict()}
            )
            round_tripped = ChangePlan.from_dict(bound.to_dict())

        self.assertNotEqual(original.fingerprint, bound.fingerprint)
        self.assertEqual(round_tripped.execution_context, context)
        self.assertEqual(round_tripped.fingerprint, bound.fingerprint)
        with self.assertRaisesRegex(ConfigurationError, "bind-context"):
            enforce_execution_context(original, context)

    def test_runtime_paths_gates_and_configuration_digests_are_approval_bound(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            integrations_path = root / "integrations.toml"
            integrations_path.write_text(_JIRA_ENV_CONFIG, encoding="utf-8")
            integrations = IntegrationConfig.from_toml(integrations_path)
            sources = _runtime_sources(root, suffix="approved")
            approved_runtime = build_runtime_execution_binding(
                integrations,
                connector_mode="live",
                include_writes=True,
                include_communications=False,
                audit_database=root / "approved-audit.sqlite3",
                artifact_root=root / "approved-artifacts",
                workspace_root=root / "approved-workspaces",
                result_json=root / "approved-result.json",
                evidence_type="run-result/approved",
                configuration_sources=sources,
                environ={
                    "MASTER_AGENT_JIRA_BASE_URL": "https://tenant-a.atlassian.net"
                },
            )
            self.assertEqual(
                {item.name for item in approved_runtime.configurations},
                {
                    "approval_authorities",
                    "capabilities",
                    "governance",
                    "identities",
                    "policy",
                    "retention",
                    "sources_of_truth",
                },
            )
            approved = build_execution_context(
                integrations,
                environ={
                    "MASTER_AGENT_JIRA_BASE_URL": "https://tenant-a.atlassian.net"
                },
                runtime=approved_runtime,
            )
            bound_plan = replace(_plan(), execution_context=approved)

            variants = {
                "workspace root": replace(
                    approved_runtime, workspace_root=str(root / "other-workspaces")
                ),
                "artifact root": replace(
                    approved_runtime, artifact_root=str(root / "other-artifacts")
                ),
                "audit database": replace(
                    approved_runtime,
                    audit_database=str(root / "other-audit.sqlite3"),
                ),
                "result destination": replace(
                    approved_runtime, result_json=str(root / "other-result.json")
                ),
                "retention evidence type": replace(
                    approved_runtime, evidence_type="run-result/other"
                ),
                "write gate": replace(approved_runtime, include_writes=False),
                "policy configurations": build_runtime_execution_binding(
                    integrations,
                    connector_mode="live",
                    include_writes=True,
                    include_communications=False,
                    audit_database=root / "approved-audit.sqlite3",
                    artifact_root=root / "approved-artifacts",
                    workspace_root=root / "approved-workspaces",
                    result_json=root / "approved-result.json",
                    evidence_type="run-result/approved",
                    configuration_sources=_runtime_sources(root, suffix="changed"),
                    environ={
                        "MASTER_AGENT_JIRA_BASE_URL": ("https://tenant-a.atlassian.net")
                    },
                ),
            }
            for name, changed_runtime in variants.items():
                with self.subTest(name=name):
                    observed = replace(approved, runtime=changed_runtime)
                    with self.assertRaisesRegex(
                        ConfigurationError,
                        "runtime policy, principal, gate, or path binding",
                    ):
                        enforce_execution_context(bound_plan, observed)

    def test_basic_username_is_bound_without_binding_the_secret(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "integrations.toml"
            path.write_text(_JIRA_BASIC_CONFIG, encoding="utf-8")
            integrations = IntegrationConfig.from_toml(path)
            alice = build_execution_context(
                integrations,
                environ={"MASTER_AGENT_JIRA_USERNAME": "alice@example.test"},
            )
            bob = build_execution_context(
                integrations,
                environ={"MASTER_AGENT_JIRA_USERNAME": "bob@example.test"},
            )

        self.assertNotEqual(alice, bob)
        self.assertEqual(
            alice.connectors[0].credential_identity,
            "basic:alice@example.test",
        )
        self.assertNotIn("TOKEN", json.dumps(alice.to_dict()))

    def test_effective_bitbucket_publication_root_is_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "integrations.toml"
            path.write_text(_BITBUCKET_PUBLICATION_CONFIG, encoding="utf-8")
            integrations = IntegrationConfig.from_toml(path)
            sources = _runtime_sources(root, suffix="same")
            first = build_runtime_execution_binding(
                integrations,
                connector_mode="live",
                include_writes=True,
                include_communications=False,
                audit_database=root / "audit.sqlite3",
                artifact_root=root / "artifacts",
                workspace_root=root / "fallback",
                result_json=None,
                evidence_type="ignored-without-result",
                configuration_sources=sources,
                environ={"MASTER_AGENT_REPOSITORY_ROOT": str(root / "repo-a")},
            )
            second = build_runtime_execution_binding(
                integrations,
                connector_mode="live",
                include_writes=True,
                include_communications=False,
                audit_database=root / "audit.sqlite3",
                artifact_root=root / "artifacts",
                workspace_root=root / "fallback",
                result_json=None,
                evidence_type="ignored-without-result",
                configuration_sources=sources,
                environ={"MASTER_AGENT_REPOSITORY_ROOT": str(root / "repo-b")},
            )

        self.assertNotEqual(first, second)
        self.assertEqual(
            first.publication_roots[0].path,
            str((root / "repo-a").resolve()),
        )

    def test_opaque_token_requires_explicit_non_secret_credential_identity(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "integrations.toml"
            path.write_text(_MICROSOFT_BEARER_CONFIG, encoding="utf-8")
            integrations = IntegrationConfig.from_toml(path)
            with self.assertRaisesRegex(ConfigurationError, "credential_identity"):
                build_execution_context(integrations)

            path.write_text(
                _MICROSOFT_BEARER_CONFIG
                + '\ncredential_identity = "tenant-a:user-object-1"\n',
                encoding="utf-8",
            )
            declared = build_execution_context(IntegrationConfig.from_toml(path))

        self.assertEqual(
            declared.connectors[0].credential_identity,
            "tenant-a:user-object-1",
        )

    def test_entra_application_tenant_and_client_are_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "integrations.toml"
            path.write_text(_MICROSOFT_CLIENT_CREDENTIAL_CONFIG, encoding="utf-8")
            integrations = IntegrationConfig.from_toml(path)
            first = build_execution_context(
                integrations,
                environ={
                    "MASTER_AGENT_ENTRA_TENANT_ID": "tenant-a",
                    "MASTER_AGENT_ENTRA_APP_CLIENT_ID": "client-a",
                },
            )
            changed_tenant = build_execution_context(
                integrations,
                environ={
                    "MASTER_AGENT_ENTRA_TENANT_ID": "tenant-b",
                    "MASTER_AGENT_ENTRA_APP_CLIENT_ID": "client-a",
                },
            )
            changed_client = build_execution_context(
                integrations,
                environ={
                    "MASTER_AGENT_ENTRA_TENANT_ID": "tenant-a",
                    "MASTER_AGENT_ENTRA_APP_CLIENT_ID": "client-b",
                },
            )

        self.assertNotEqual(first, changed_tenant)
        self.assertNotEqual(first, changed_client)
        self.assertEqual(
            first.connectors[0].credential_identity,
            "entra-application:tenant=tenant-a;client=client-a",
        )

    def test_cli_rejects_changed_runtime_input_before_connector_construction(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan_path = root / "plan.json"
            plan_path.write_text(json.dumps(_plan().to_dict()), encoding="utf-8")
            bound_path = root / "bound.json"
            approved_workspace = root / "approved-workspace"
            database = root / "audit.sqlite3"
            drafts = root / "drafts"
            result_path = root / "result.json"
            retention = root / "retention.toml"
            changed_retention = root / "changed-retention.toml"
            retention_payload = (
                Path(__file__).resolve().parents[1] / "config/retention.toml"
            ).read_bytes()
            retention.write_bytes(retention_payload)
            changed_retention.write_bytes(retention_payload + b"\n")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    main(
                        [
                            "bind-context",
                            str(plan_path),
                            "--connector-mode",
                            "mock",
                            "--workspace-root",
                            str(approved_workspace),
                            "--database",
                            str(database),
                            "--draft-output-dir",
                            str(drafts),
                            "--result-json",
                            str(result_path),
                            "--evidence-type",
                            "run-result/full",
                            "--retention",
                            str(retention),
                            "--output",
                            str(bound_path),
                        ]
                    ),
                    0,
                )

            baseline = {
                "--connector-mode": "mock",
                "--workspace-root": str(approved_workspace),
                "--database": str(database),
                "--draft-output-dir": str(drafts),
                "--result-json": str(result_path),
                "--evidence-type": "run-result/full",
                "--retention": str(retention),
            }
            variants: dict[str, tuple[dict[str, str], tuple[str, ...]]] = {
                "workspace root": (
                    {"--workspace-root": str(root / "changed-workspace")},
                    (),
                ),
                "audit database": (
                    {"--database": str(root / "changed-audit.sqlite3")},
                    (),
                ),
                "artifact and draft root": (
                    {"--draft-output-dir": str(root / "changed-drafts")},
                    (),
                ),
                "result path": (
                    {"--result-json": str(root / "changed-result.json")},
                    (),
                ),
                "evidence type": (
                    {"--evidence-type": "run-result/changed"},
                    (),
                ),
                "retention configuration": (
                    {"--retention": str(changed_retention)},
                    (),
                ),
                "write gate": ({}, ("--enable-writes",)),
            }
            for name, (changes, flags) in variants.items():
                with self.subTest(name=name):
                    selected = {**baseline, **changes}
                    runtime_arguments = [
                        item
                        for option, value in selected.items()
                        for item in (option, value)
                    ]
                    stderr = io.StringIO()
                    with (
                        patch("master_agent.cli._mock_registry") as mock_registry,
                        redirect_stderr(stderr),
                    ):
                        result = main(
                            [
                                "run",
                                str(bound_path),
                                "--apply",
                                *runtime_arguments,
                                *flags,
                            ]
                        )

                    self.assertEqual(result, 1)
                    self.assertIn(
                        "runtime policy, principal, gate, or path",
                        stderr.getvalue(),
                    )
                    mock_registry.assert_not_called()
            self.assertFalse((root / "changed-audit.sqlite3").exists())
            self.assertFalse((root / "changed-result.json").exists())

    def test_cli_rejects_changed_capability_snapshot_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan_path = root / "plan.json"
            plan_path.write_text(json.dumps(_plan().to_dict()), encoding="utf-8")
            bound_path = root / "bound.json"
            capabilities = root / "capabilities.toml"
            capabilities.write_bytes(
                (
                    Path(__file__).resolve().parents[1] / "config/capabilities.toml"
                ).read_bytes()
            )
            database = root / "audit.sqlite3"
            drafts = root / "drafts"
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    main(
                        [
                            "bind-context",
                            str(plan_path),
                            "--connector-mode",
                            "mock",
                            "--capabilities",
                            str(capabilities),
                            "--database",
                            str(database),
                            "--draft-output-dir",
                            str(drafts),
                            "--output",
                            str(bound_path),
                        ]
                    ),
                    0,
                )
            capabilities.write_bytes(capabilities.read_bytes() + b"\n")

            stderr = io.StringIO()
            with (
                patch("master_agent.cli._mock_registry") as mock_registry,
                redirect_stderr(stderr),
            ):
                result = main(
                    [
                        "run",
                        str(bound_path),
                        "--apply",
                        "--connector-mode",
                        "mock",
                        "--capabilities",
                        str(capabilities),
                        "--database",
                        str(database),
                        "--draft-output-dir",
                        str(drafts),
                    ]
                )

        self.assertEqual(result, 1)
        self.assertIn("runtime policy, principal, gate, or path", stderr.getvalue())
        mock_registry.assert_not_called()


def _plan() -> ChangePlan:
    action = AgentAction(
        capability="jira.issue.read",
        target=ResourceRef(
            system="jira",
            resource_type="issue",
            resource_id="ENG-1",
        ),
        parameters={},
        risk=RiskLevel.READ_ONLY,
        data_classification=DataClassification.INTERNAL,
        authority_source=AuthoritySource.DIRECT_USER,
        requires_approval=False,
        idempotency_key="execution-context-test",
        justification="test live identity binding",
    )
    return ChangePlan(
        goal="test execution context", actions=(action,), created_by="test"
    )


_JIRA_ENV_CONFIG = """
[connectors.jira]
enabled = true
deployment = "cloud"
base_url_env = "MASTER_AGENT_JIRA_BASE_URL"
auth_mode = "none"
""".strip()


_JIRA_CA_CONFIG = """
[connectors.jira]
enabled = true
deployment = "cloud"
base_url = "https://tenant-a.atlassian.net"
auth_mode = "none"
ca_bundle_env = "MASTER_AGENT_ENTERPRISE_CA_BUNDLE"
""".strip()


_JIRA_BASIC_CONFIG = """
[connectors.jira]
enabled = true
deployment = "cloud"
base_url = "https://tenant-a.atlassian.net"
auth_mode = "basic"
username_env = "MASTER_AGENT_JIRA_USERNAME"
secret_env = "MASTER_AGENT_JIRA_TOKEN"
""".strip()


_MICROSOFT_BEARER_CONFIG = """
[connectors.microsoft]
enabled = true
deployment = "cloud"
base_url = "https://graph.microsoft.com/v1.0"
auth_mode = "bearer"
secret_env = "MASTER_AGENT_GRAPH_ACCESS_TOKEN"
""".strip()


_BITBUCKET_PUBLICATION_CONFIG = """
[connectors.bitbucket]
enabled = true
deployment = "cloud"
base_url = "https://api.bitbucket.org/2.0"
auth_mode = "none"
write_enabled = true
branch_push_enabled = true
repository_root_env = "MASTER_AGENT_REPOSITORY_ROOT"
""".strip()


_MICROSOFT_CLIENT_CREDENTIAL_CONFIG = """
[connectors.microsoft]
enabled = true
deployment = "cloud"
base_url = "https://graph.microsoft.com/v1.0"
auth_mode = "oauth_application"
oauth_flow = "client_credentials"
tenant_id_env = "MASTER_AGENT_ENTRA_TENANT_ID"
client_id_env = "MASTER_AGENT_ENTRA_APP_CLIENT_ID"
client_secret_env = "MASTER_AGENT_ENTRA_APP_CLIENT_SECRET"
scopes = ["https://graph.microsoft.com/.default"]
""".strip()


def _runtime_sources(root: Path, *, suffix: str) -> dict[str, ConfigSnapshot]:
    names = (
        "policy",
        "sources_of_truth",
        "capabilities",
        "governance",
        "identities",
        "retention",
        "approval_authorities",
    )
    return {
        name: ConfigSnapshot(
            display_path=root / f"{name}.toml",
            payload=f"{name}:{suffix}\n".encode(),
        )
        for name in names
    }


if __name__ == "__main__":
    unittest.main()

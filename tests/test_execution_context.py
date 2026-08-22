"""Approval-bound live execution context tests."""

from __future__ import annotations

import io
import json
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import master_agent.cli as cli_module
import master_agent.execution_context as execution_context_module
from master_agent.cli import main
from master_agent.config import IntegrationConfig
from master_agent.config_sources import (
    ConfigSnapshot,
    ConfigSource,
    resolve_config_source,
)
from master_agent.connectors.drafts import JiraDraftConnector
from master_agent.connectors.factory import build_live_connectors, build_live_registry
from master_agent.errors import ConfigurationError, ValidationError
from master_agent.execution_context import (
    build_execution_context,
    build_runtime_execution_binding,
    enforce_execution_context,
)
from master_agent.models import (
    AgentAction,
    Approval,
    AuthoritySource,
    ChangePlan,
    ConnectorExecutionBinding,
    DataClassification,
    ExecutionContext,
    ResourceRef,
    RiskLevel,
    RuntimePathExecutionBinding,
)
from master_agent.registry import ConnectorRegistry
from tests.fakes import ExpectedRequest, QueueTransport
from tests.helpers import private_temporary_directory


class ExecutionContextTests(unittest.TestCase):
    """Verify approvals cover runtime destinations and trust roots."""

    def test_windows_runtime_path_is_lexical_before_native_pin(self) -> None:
        selected = MagicMock(spec=Path)
        selected.expanduser.return_value = selected
        selected.is_absolute.return_value = True
        validated = MagicMock(canonical=r"C:\MasterAgent\state")
        windows_os = MagicMock()
        windows_os.name = "nt"

        with (
            patch.object(execution_context_module, "os", windows_os),
            patch(
                "master_agent.platform_runtime.windows.filesystem."
                "validate_windows_drive_path",
                return_value=validated,
            ) as validate_path,
        ):
            observed = execution_context_module._canonical_path(selected)

        self.assertEqual(observed, r"C:\MasterAgent\state")
        validate_path.assert_called_once_with(selected)
        selected.resolve.assert_not_called()

    def test_legacy_posix_runtime_path_round_trip_preserves_fingerprint_shape(
        self,
    ) -> None:
        payload = {
            "name": "audit.parent",
            "path": "/var/lib/master-agent",
            "anchor_path": "/var/lib/master-agent",
            "device": 7,
            "inode": 11,
            "owner": 501,
            "mode": 0o700,
        }

        binding = RuntimePathExecutionBinding.from_dict(payload)

        self.assertIsNone(binding.object_identity)
        self.assertEqual(binding.to_dict(), payload)
        self.assertEqual(binding.platform_identity.object_key, ("posix", "7", "11"))

    def test_runtime_path_rejects_non_object_native_identity(self) -> None:
        payload = {
            "name": "audit.parent",
            "path": "/var/lib/master-agent",
            "anchor_path": "/var/lib/master-agent",
            "device": 7,
            "inode": 11,
            "owner": 501,
            "mode": 0o700,
            "object_identity": "attacker-controlled-shape",
        }

        with self.assertRaisesRegex(ValidationError, "object identity is invalid"):
            RuntimePathExecutionBinding.from_dict(payload)

    def test_windows_operating_plan_and_approval_use_native_private_reads(
        self,
    ) -> None:
        plan = _plan()
        now = datetime.now(UTC)
        approval = Approval(
            plan_fingerprint=plan.fingerprint,
            approved_action_ids=(plan.actions[0].action_id,),
            approved_by="operator@example.test",
            issuer="master-agent-test",
            tenant="example.test",
            roles=("approver",),
            issued_at=now,
            expires_at=now + timedelta(minutes=5),
            key_id="test-key",
            signature="test-signature",
        )
        plan_payload = json.dumps(plan.to_dict()).encode("utf-8")
        approval_payload = json.dumps(approval.to_dict()).encode("utf-8")
        backend = MagicMock()
        backend.read_restricted_file.side_effect = (
            (Path("C:/approved/plan.json"), plan_payload, object()),
            (Path("C:/approved/approval.json"), approval_payload, object()),
        )

        with (
            patch.object(cli_module, "_uses_native_windows_paths", return_value=True),
            patch.object(
                cli_module,
                "get_secure_filesystem_backend",
                return_value=backend,
            ),
        ):
            observed_plan = cli_module._load_operating_plan(Path("/approved/plan.json"))
            observed_approval = cli_module._load_operating_approval(
                Path("/approved/approval.json")
            )

        self.assertEqual(observed_plan, plan)
        self.assertEqual(observed_approval, approval)
        self.assertEqual(backend.read_restricted_file.call_count, 2)
        for call in backend.read_restricted_file.call_args_list:
            self.assertEqual(call.args[1], cli_module.MAX_PLAN_BYTES + 1)
            self.assertTrue(call.kwargs["require_private"])

    def test_connector_url_override_is_normalized_and_approval_bound(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            integrations_path = root / "integrations.toml"
            integrations_path.write_text(_JIRA_ENV_CONFIG, encoding="utf-8")
            source_plan = root / "plan.json"
            source_plan.write_text(json.dumps(_plan().to_dict()), encoding="utf-8")
            bound_plan = root / "bound-plan.json"
            database = root / "audit.sqlite3"
            drafts = root / "drafts"
            _mkdir_private(drafts)
            runtime_arguments = [
                "--connector-mode",
                "live",
                "--integrations",
                str(integrations_path),
                "--database",
                str(database),
                "--draft-output-dir",
                str(drafts),
            ]

            with redirect_stdout(io.StringIO()):
                result = main(
                    [
                        "bind-context",
                        str(source_plan),
                        *runtime_arguments,
                        "--connector-url",
                        "jira=https://tenant-a.atlassian.net/jira/software/projects/ENG",
                        "--output",
                        str(bound_plan),
                    ]
                )
            self.assertEqual(result, 0)
            bound = ChangePlan.from_dict(json.loads(bound_plan.read_text()))
            self.assertIsNotNone(bound.execution_context)
            assert bound.execution_context is not None
            self.assertEqual(
                bound.execution_context.connectors[0].resolved_base_url,
                "https://tenant-a.atlassian.net",
            )

            stderr = io.StringIO()
            with (
                patch("master_agent.cli.build_live_registry") as build_registry,
                redirect_stderr(stderr),
            ):
                result = main(
                    [
                        "run",
                        str(bound_plan),
                        "--apply",
                        *runtime_arguments,
                        "--connector-url",
                        "jira=https://tenant-b.atlassian.net/jira/software/projects/ENG",
                    ]
                )

            self.assertEqual(result, 1)
            self.assertIn("connector origin or CA identity", stderr.getvalue())
            build_registry.assert_not_called()

    def test_changed_resolved_origin_is_rejected_before_connector_construction(
        self,
    ) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            integrations_path = root / "integrations.toml"
            integrations_path.write_text(_JIRA_ENV_CONFIG, encoding="utf-8")
            source_plan = root / "plan.json"
            source_plan.write_text(
                json.dumps(_plan().to_dict()),
                encoding="utf-8",
            )
            bound_plan = root / "bound-plan.json"
            database = root / "audit.sqlite3"
            drafts = root / "drafts"
            _mkdir_private(drafts)
            runtime_arguments = [
                "--database",
                str(database),
                "--draft-output-dir",
                str(drafts),
            ]

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
                        *runtime_arguments,
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
                        *runtime_arguments,
                    ]
                )

            self.assertEqual(result, 1)
            self.assertIn("connector origin or CA identity", error_output.getvalue())
            build_registry.assert_not_called()

    def test_ca_bundle_content_and_path_are_bound(self) -> None:
        with private_temporary_directory() as directory:
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
        with private_temporary_directory() as directory:
            root = Path(directory)
            integrations_path = root / "integrations.toml"
            integrations_path.write_text(_JIRA_ENV_CONFIG, encoding="utf-8")
            source_plan = root / "plan.json"
            source_plan.write_text(json.dumps(_plan().to_dict()), encoding="utf-8")
            bound_plan = root / "bound-plan.json"
            database = root / "audit.sqlite3"
            drafts = root / "drafts"
            _mkdir_private(drafts)

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
                                "--database",
                                str(database),
                                "--draft-output-dir",
                                str(drafts),
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
                            "--database",
                            str(database),
                            "--draft-output-dir",
                            str(drafts),
                        ]
                    )

            self.assertEqual(result, 1)
            build_registry.assert_called_once()
            self.assertIsNotNone(
                build_registry.call_args.kwargs["approved_execution_context"]
            )
            orchestrator.assert_not_called()

    def test_factory_rejects_each_changed_approved_connector_identity(self) -> None:
        with private_temporary_directory() as directory:
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
        with private_temporary_directory() as directory:
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
        with private_temporary_directory() as directory:
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
        with private_temporary_directory() as directory:
            root = Path(directory)
            integrations_path = root / "integrations.toml"
            integrations_path.write_text(_JIRA_ENV_CONFIG, encoding="utf-8")
            integrations = IntegrationConfig.from_toml(integrations_path)
            sources = _runtime_sources(root, suffix="approved")
            _mkdir_private(
                root / "approved-artifacts",
                root / "approved-results",
                root / "approved-state",
                root / "approved-workspaces",
            )
            approved_runtime = build_runtime_execution_binding(
                integrations,
                connector_mode="live",
                include_writes=True,
                include_communications=False,
                audit_database=root / "approved-state/audit.sqlite3",
                artifact_root=root / "approved-artifacts",
                workspace_root=root / "approved-workspaces",
                result_json=root / "approved-results/result.json",
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
            other_workspaces = (root / "other-workspaces").resolve(strict=False)
            other_artifacts = (root / "other-artifacts").resolve(strict=False)

            variants = {
                "workspace root": replace(
                    approved_runtime,
                    workspace_root=str(other_workspaces),
                    runtime_paths=_replace_runtime_path(
                        approved_runtime.runtime_paths,
                        "workspace.root",
                        other_workspaces,
                    ),
                ),
                "artifact root": replace(
                    approved_runtime,
                    artifact_root=str(other_artifacts),
                    runtime_paths=_replace_runtime_path(
                        approved_runtime.runtime_paths,
                        "artifact.root",
                        other_artifacts,
                    ),
                ),
                "audit database": replace(
                    approved_runtime,
                    audit_database=str(
                        (root / "approved-state/other-audit.sqlite3").resolve(
                            strict=False
                        )
                    ),
                ),
                "result destination": replace(
                    approved_runtime,
                    result_json=str(
                        (root / "approved-results/other-result.json").resolve(
                            strict=False
                        )
                    ),
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
                    audit_database=root / "approved-state/audit.sqlite3",
                    artifact_root=root / "approved-artifacts",
                    workspace_root=root / "approved-workspaces",
                    result_json=root / "approved-results/result.json",
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
        with private_temporary_directory() as directory:
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

    def test_github_principal_is_provider_verified_and_bound(self) -> None:
        with private_temporary_directory() as directory:
            path = Path(directory) / "integrations.toml"
            path.write_text(
                _GITHUB_BEARER_CONFIG
                + '\ncredential_identity = "claimed-admin-alias"\n',
                encoding="utf-8",
            )
            integrations = IntegrationConfig.from_toml(path)
            original = build_execution_context(
                integrations,
                environ={"MASTER_AGENT_GITHUB_TOKEN": "token-for-user-42"},
                principal_transport=_github_principal_transport(
                    login="OriginalLogin",
                    user_id=42,
                ),
            )
            rotated = build_execution_context(
                integrations,
                environ={"MASTER_AGENT_GITHUB_TOKEN": "rotated-token-for-user-42"},
                principal_transport=_github_principal_transport(
                    login="RenamedLogin",
                    user_id=42,
                ),
            )
            swapped = build_execution_context(
                integrations,
                environ={"MASTER_AGENT_GITHUB_TOKEN": "token-for-user-99"},
                principal_transport=_github_principal_transport(
                    login="DifferentUser",
                    user_id=99,
                ),
            )

        self.assertEqual(original, rotated)
        self.assertNotEqual(original, swapped)
        self.assertEqual(
            original.connectors[0].credential_identity,
            "github:user:42",
        )
        self.assertEqual(
            original.connectors[0].credential_scopes,
            ("repo", "workflow"),
        )
        rendered = json.dumps(original.to_dict())
        self.assertNotIn("token-for-user-42", rendered)
        self.assertNotIn("OriginalLogin", rendered)
        self.assertNotIn("claimed-admin-alias", rendered)

    def test_github_principal_swap_is_rejected_before_connector_actions(self) -> None:
        with private_temporary_directory() as directory:
            path = Path(directory) / "integrations.toml"
            path.write_text(_GITHUB_BEARER_CONFIG, encoding="utf-8")
            integrations = IntegrationConfig.from_toml(path)
            approved = build_execution_context(
                integrations,
                environ={"MASTER_AGENT_GITHUB_TOKEN": "approved-token"},
                principal_transport=_github_principal_transport(
                    login="ApprovedUser",
                    user_id=42,
                ),
            )
            swapped_transport = _github_principal_transport(
                login="DifferentUser",
                user_id=99,
            )

            with self.assertRaisesRegex(ConfigurationError, "credential identity"):
                build_live_connectors(
                    integrations,
                    environ={"MASTER_AGENT_GITHUB_TOKEN": "swapped-token-canary"},
                    systems={"github"},
                    transport=swapped_transport,
                    approved_execution_context=approved,
                )

        self.assertEqual(len(swapped_transport.requests), 1)

    def test_github_scope_drift_is_rejected_before_connector_actions(self) -> None:
        with private_temporary_directory() as directory:
            path = Path(directory) / "integrations.toml"
            path.write_text(_GITHUB_BEARER_CONFIG, encoding="utf-8")
            integrations = IntegrationConfig.from_toml(path)
            approved = build_execution_context(
                integrations,
                environ={"MASTER_AGENT_GITHUB_TOKEN": "approved-token"},
                principal_transport=_github_principal_transport(
                    login="ApprovedUser",
                    user_id=42,
                    scopes="repo",
                ),
            )
            drifted_transport = _github_principal_transport(
                login="ApprovedUser",
                user_id=42,
                scopes="admin:org",
            )

            with self.assertRaisesRegex(ConfigurationError, "credential scopes"):
                build_live_connectors(
                    integrations,
                    environ={"MASTER_AGENT_GITHUB_TOKEN": "same-user-new-scope"},
                    systems={"github"},
                    transport=drifted_transport,
                    approved_execution_context=approved,
                )

        self.assertEqual(len(drifted_transport.requests), 1)
        self.assertNotIn(
            "swapped-token-canary",
            json.dumps(approved.to_dict()),
        )

    def test_ca_drift_is_rejected_before_principal_attestation(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            path = root / "integrations.toml"
            path.write_text(
                _GITHUB_BEARER_CONFIG
                + '\nca_bundle_env = "MASTER_AGENT_ENTERPRISE_CA_BUNDLE"\n',
                encoding="utf-8",
            )
            ca_bundle = root / "enterprise-ca.pem"
            ca_bundle.write_text("APPROVED CA\n", encoding="ascii")
            integrations = IntegrationConfig.from_toml(path)
            environ = {
                "MASTER_AGENT_GITHUB_TOKEN": "approved-token",
                "MASTER_AGENT_ENTERPRISE_CA_BUNDLE": str(ca_bundle),
            }
            approved = build_execution_context(
                integrations,
                environ=environ,
                principal_transport=_github_principal_transport(
                    login="ApprovedUser",
                    user_id=42,
                ),
            )
            ca_bundle.write_text("UNAPPROVED CA\n", encoding="ascii")
            transport = _github_principal_transport(
                login="ApprovedUser",
                user_id=42,
            )

            with self.assertRaisesRegex(ConfigurationError, "CA digest"):
                build_live_connectors(
                    integrations,
                    environ=environ,
                    systems={"github"},
                    transport=transport,
                    approved_execution_context=approved,
                )

        self.assertEqual(transport.requests, [])

    def test_effective_bitbucket_publication_root_is_bound(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            path = root / "integrations.toml"
            path.write_text(_BITBUCKET_PUBLICATION_CONFIG, encoding="utf-8")
            integrations = IntegrationConfig.from_toml(path)
            sources = _runtime_sources(root, suffix="same")
            _mkdir_private(
                root / "artifacts",
                root / "fallback",
                root / "repo-a",
                root / "repo-b",
            )
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

    def test_declared_alias_cannot_hide_an_opaque_token_swap(self) -> None:
        with private_temporary_directory() as directory:
            path = Path(directory) / "integrations.toml"
            path.write_text(
                _MICROSOFT_BEARER_CONFIG
                + '\ncredential_identity = "tenant-a:user-object-1"\n',
                encoding="utf-8",
            )
            integrations = IntegrationConfig.from_toml(path)
            for token in ("opaque-token-for-user-a", "opaque-admin-token"):
                with (
                    self.subTest(token=token),
                    self.assertRaisesRegex(
                        ConfigurationError,
                        "no such adapter is implemented",
                    ),
                ):
                    build_execution_context(
                        integrations,
                        environ={"MASTER_AGENT_GRAPH_ACCESS_TOKEN": token},
                    )

    def test_live_bind_rejects_declared_opaque_principal_alias(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            integrations_path = root / "integrations.toml"
            integrations_path.write_text(
                _MICROSOFT_BEARER_CONFIG
                + '\ncredential_identity = "tenant-a:user-object-1"\n',
                encoding="utf-8",
            )
            source_plan = root / "plan.json"
            source_plan.write_text(json.dumps(_plan().to_dict()), encoding="utf-8")
            bound_plan = root / "bound.json"
            database = root / "audit.sqlite3"
            drafts = root / "drafts"
            _mkdir_private(drafts)
            stderr = io.StringIO()
            with (
                patch.dict(
                    os.environ,
                    {"MASTER_AGENT_GRAPH_ACCESS_TOKEN": "opaque-user-token"},
                ),
                redirect_stderr(stderr),
            ):
                result = main(
                    [
                        "bind-context",
                        str(source_plan),
                        "--connector-mode",
                        "live",
                        "--integrations",
                        str(integrations_path),
                        "--database",
                        str(database),
                        "--draft-output-dir",
                        str(drafts),
                        "--output",
                        str(bound_plan),
                    ]
                )
            bound_was_written = bound_plan.exists()

        self.assertEqual(result, 1)
        self.assertIn("provider-verified principal", stderr.getvalue())
        self.assertNotIn("opaque-user-token", stderr.getvalue())
        self.assertFalse(bound_was_written)

    def test_live_apply_rejects_legacy_alias_after_opaque_token_swap(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            integrations_path = root / "integrations.toml"
            integrations_path.write_text(
                _MICROSOFT_BEARER_CONFIG
                + '\ncredential_identity = "tenant-a:user-object-1"\n',
                encoding="utf-8",
            )
            integrations = IntegrationConfig.from_toml(integrations_path)
            integrations_sha256 = integrations.source_sha256
            self.assertIsNotNone(integrations_sha256)
            assert integrations_sha256 is not None
            database = root / "audit.sqlite3"
            drafts = root / "drafts"
            _mkdir_private(drafts)
            runtime = build_runtime_execution_binding(
                integrations,
                connector_mode="live",
                include_writes=False,
                include_communications=False,
                audit_database=database,
                artifact_root=drafts,
                workspace_root=None,
                result_json=None,
                evidence_type="run-result/full",
                configuration_sources=_default_runtime_sources(),
                environ={"MASTER_AGENT_GRAPH_ACCESS_TOKEN": "original-user-token"},
            )
            legacy_context = ExecutionContext(
                integrations_sha256=integrations_sha256,
                connectors=(
                    ConnectorExecutionBinding(
                        system="microsoft",
                        deployment="cloud",
                        config_identity_sha256=integrations.connector(
                            "microsoft"
                        ).identity,
                        resolved_base_url="https://graph.microsoft.com/v1.0",
                        resolved_origin="https://graph.microsoft.com",
                        credential_identity="tenant-a:user-object-1",
                    ),
                ),
                runtime=runtime,
            )
            plan_path = root / "legacy-bound-plan.json"
            plan_path.write_text(
                json.dumps(
                    replace(_plan(), execution_context=legacy_context).to_dict()
                ),
                encoding="utf-8",
            )
            stderr = io.StringIO()
            with (
                patch.dict(
                    os.environ,
                    {"MASTER_AGENT_GRAPH_ACCESS_TOKEN": "swapped-admin-token"},
                ),
                patch("master_agent.cli.build_live_registry") as build_registry,
                redirect_stderr(stderr),
            ):
                result = main(
                    [
                        "run",
                        str(plan_path),
                        "--apply",
                        "--connector-mode",
                        "live",
                        "--integrations",
                        str(integrations_path),
                        "--database",
                        str(database),
                        "--draft-output-dir",
                        str(drafts),
                    ]
                )

        self.assertEqual(result, 1)
        self.assertIn("trusted credential-broker attestation", stderr.getvalue())
        self.assertNotIn("swapped-admin-token", stderr.getvalue())
        build_registry.assert_not_called()

    def test_every_opaque_live_credential_flow_requires_attestation(self) -> None:
        configurations = {
            "bearer": """
auth_mode = "bearer"
secret_env = "MASTER_AGENT_GRAPH_ACCESS_TOKEN"
""",
            "application environment": """
auth_mode = "oauth_application"
oauth_flow = "environment"
secret_env = "MASTER_AGENT_GRAPH_ACCESS_TOKEN"
""",
        }
        with private_temporary_directory() as directory:
            path = Path(directory) / "integrations.toml"
            for name, authentication in configurations.items():
                with self.subTest(name=name):
                    path.write_text(
                        "[connectors.microsoft]\n"
                        "enabled = true\n"
                        'deployment = "cloud"\n'
                        'base_url = "https://graph.microsoft.com/v1.0"\n'
                        + authentication.strip()
                        + '\ncredential_identity = "claimed-principal"\n',
                        encoding="utf-8",
                    )
                    integrations = IntegrationConfig.from_toml(path)
                    with self.assertRaisesRegex(
                        ConfigurationError,
                        "provider-verified principal",
                    ):
                        build_execution_context(integrations, environ={})

    def test_microsoft_delegated_identity_and_scopes_are_provider_bound(self) -> None:
        with private_temporary_directory() as directory:
            path = Path(directory) / "integrations.toml"
            path.write_text(
                """
[connectors.microsoft]
enabled = true
deployment = "cloud"
base_url = "https://graph.microsoft.com/v1.0"
auth_mode = "oauth_delegated"
oauth_flow = "environment"
secret_env = "MASTER_AGENT_GRAPH_ACCESS_TOKEN"
identity_mode = "delegated"
scopes = ["Mail.Send", "User.Read"]
""".strip()
                + "\n",
                encoding="utf-8",
            )
            integrations = IntegrationConfig.from_toml(path)
            transport = QueueTransport(
                ExpectedRequest(
                    method="GET",
                    url_contains="/me?%24select=id",
                    payload={"id": "user-object-42"},
                )
            )

            context = build_execution_context(
                integrations,
                environ={"MASTER_AGENT_GRAPH_ACCESS_TOKEN": "opaque-token"},
                principal_transport=transport,
            )

        binding = context.connectors[0]
        self.assertEqual(binding.authentication_mode, "oauth_delegated")
        self.assertEqual(binding.credential_identity, "microsoft:user:user-object-42")
        self.assertEqual(binding.credential_scopes, ("Mail.Send", "User.Read"))
        self.assertNotIn("opaque-token", json.dumps(context.to_dict()))
        transport.assert_drained()

    def test_unselected_default_connectors_do_not_block_safe_context(
        self,
    ) -> None:
        root = Path(__file__).resolve().parents[1]
        integrations = IntegrationConfig.from_toml(root / "config/integrations.toml")

        context = build_execution_context(integrations, environ={}, systems=set())

        self.assertEqual(context.connectors, ())

    def test_entra_application_tenant_and_client_are_bound(self) -> None:
        with private_temporary_directory() as directory:
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

    def test_cli_rejects_principal_swaps_before_secrets_connectors_or_audit(
        self,
    ) -> None:
        scenarios = {
            "basic username": (
                _JIRA_BASIC_CONFIG,
                {"MASTER_AGENT_JIRA_USERNAME": "alice@example.test"},
                {
                    "MASTER_AGENT_JIRA_USERNAME": "bob@example.test",
                    "MASTER_AGENT_JIRA_TOKEN": "basic-secret-canary",
                },
                "basic-secret-canary",
            ),
            "Entra tenant": (
                _MICROSOFT_CLIENT_CREDENTIAL_CONFIG,
                {
                    "MASTER_AGENT_ENTRA_TENANT_ID": "tenant-a",
                    "MASTER_AGENT_ENTRA_APP_CLIENT_ID": "client-a",
                },
                {
                    "MASTER_AGENT_ENTRA_TENANT_ID": "tenant-b",
                    "MASTER_AGENT_ENTRA_APP_CLIENT_ID": "client-a",
                    "MASTER_AGENT_ENTRA_APP_CLIENT_SECRET": "entra-secret-canary",
                },
                "entra-secret-canary",
            ),
            "Entra client": (
                _MICROSOFT_CLIENT_CREDENTIAL_CONFIG,
                {
                    "MASTER_AGENT_ENTRA_TENANT_ID": "tenant-a",
                    "MASTER_AGENT_ENTRA_APP_CLIENT_ID": "client-a",
                },
                {
                    "MASTER_AGENT_ENTRA_TENANT_ID": "tenant-a",
                    "MASTER_AGENT_ENTRA_APP_CLIENT_ID": "client-b",
                    "MASTER_AGENT_ENTRA_APP_CLIENT_SECRET": "entra-secret-canary",
                },
                "entra-secret-canary",
            ),
        }
        for name, (configuration, approved, changed, canary) in scenarios.items():
            with (
                self.subTest(name=name),
                private_temporary_directory() as directory,
            ):
                root = Path(directory)
                integrations_path = root / "integrations.toml"
                integrations_path.write_text(configuration, encoding="utf-8")
                plan_path = root / "plan.json"
                plan_path.write_text(json.dumps(_plan().to_dict()), encoding="utf-8")
                bound_path = root / "bound.json"
                database = root / "audit.sqlite3"
                drafts = root / "drafts"
                _mkdir_private(drafts)
                arguments = [
                    "--connector-mode",
                    "live",
                    "--integrations",
                    str(integrations_path),
                    "--database",
                    str(database),
                    "--draft-output-dir",
                    str(drafts),
                ]
                with (
                    patch.dict(os.environ, approved, clear=True),
                    redirect_stdout(io.StringIO()),
                ):
                    self.assertEqual(
                        main(
                            [
                                "bind-context",
                                str(plan_path),
                                *arguments,
                                "--output",
                                str(bound_path),
                            ]
                        ),
                        0,
                    )

                stderr = io.StringIO()
                with (
                    patch.dict(os.environ, changed, clear=True),
                    patch("master_agent.cli.build_live_registry") as build_registry,
                    patch("master_agent.cli.AuditLog") as audit_log,
                    redirect_stderr(stderr),
                ):
                    result = main(["run", str(bound_path), "--apply", *arguments])

                self.assertEqual(result, 1)
                self.assertIn("connector origin or CA identity", stderr.getvalue())
                self.assertNotIn(canary, stderr.getvalue())
                build_registry.assert_not_called()
                audit_log.assert_not_called()
                self.assertFalse(database.exists())

    def test_cli_rejects_changed_runtime_input_before_connector_construction(
        self,
    ) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            plan_path = root / "plan.json"
            plan_path.write_text(json.dumps(_plan().to_dict()), encoding="utf-8")
            bound_path = root / "bound.json"
            approved_workspace = root / "approved-workspace"
            state = root / "state"
            results = root / "results"
            database = state / "audit.sqlite3"
            drafts = root / "drafts"
            result_path = results / "result.json"
            retention = root / "retention.toml"
            changed_retention = root / "changed-retention.toml"
            retention_payload = (
                Path(__file__).resolve().parents[1] / "config/retention.toml"
            ).read_bytes()
            retention.write_bytes(retention_payload)
            changed_retention.write_bytes(retention_payload + b"\n")
            _mkdir_private(approved_workspace, drafts, results, state)
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

    def test_cli_rejects_each_changed_policy_snapshot_before_effects(self) -> None:
        configurations = {
            "policy": "--policy",
            "sources_of_truth": "--sources-of-truth",
            "capabilities": "--capabilities",
            "governance": "--governance",
            "identities": "--identities",
            "retention": "--retention",
        }
        repository_root = Path(__file__).resolve().parents[1]
        for name, option in configurations.items():
            with (
                self.subTest(name=name),
                private_temporary_directory() as directory,
            ):
                root = Path(directory)
                plan_path = root / "plan.json"
                plan_path.write_text(json.dumps(_plan().to_dict()), encoding="utf-8")
                bound_path = root / "bound.json"
                selected = root / f"{name}.toml"
                selected.write_bytes(
                    (repository_root / f"config/{name}.toml").read_bytes()
                )
                database = root / "audit.sqlite3"
                drafts = root / "drafts"
                _mkdir_private(drafts)
                arguments = [
                    "--connector-mode",
                    "mock",
                    option,
                    str(selected),
                    "--database",
                    str(database),
                    "--draft-output-dir",
                    str(drafts),
                ]
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(
                        main(
                            [
                                "bind-context",
                                str(plan_path),
                                *arguments,
                                "--output",
                                str(bound_path),
                            ]
                        ),
                        0,
                    )
                selected.write_bytes(selected.read_bytes() + b"\n")

                stderr = io.StringIO()
                with (
                    patch("master_agent.cli._mock_registry") as mock_registry,
                    patch("master_agent.cli.AuditLog") as audit_log,
                    redirect_stderr(stderr),
                ):
                    result = main(["run", str(bound_path), "--apply", *arguments])

                self.assertEqual(result, 1)
                self.assertIn(
                    "runtime policy, principal, gate, or path", stderr.getvalue()
                )
                mock_registry.assert_not_called()
                audit_log.assert_not_called()
                self.assertFalse(database.exists())

    def test_apply_uses_canonical_paths_after_final_ancestor_alias_swap(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            approved = root / "approved"
            redirected = root / "redirected"
            for destination in (approved, redirected):
                for name in ("artifacts", "results", "state", "workspaces"):
                    (destination / name).mkdir(parents=True, mode=0o700)
            selected = root / "selected"
            selected.symlink_to(approved, target_is_directory=True)
            plan_path = root / "plan.json"
            plan_path.write_text(
                json.dumps(_draft_plan().to_dict()),
                encoding="utf-8",
            )
            bound_path = root / "bound.json"
            database = selected / "state" / "audit.sqlite3"
            artifacts = selected / "artifacts"
            workspaces = selected / "workspaces"
            result_path = selected / "results" / "report.json"
            arguments = [
                "--connector-mode",
                "mock",
                "--database",
                str(database),
                "--draft-output-dir",
                str(artifacts),
                "--workspace-root",
                str(workspaces),
                "--result-json",
                str(result_path),
            ]
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    main(
                        [
                            "bind-context",
                            str(plan_path),
                            *arguments,
                            "--output",
                            str(bound_path),
                        ]
                    ),
                    0,
                )
            real_orchestrator = cli_module._orchestrator

            def swap_alias_after_final_gate(
                *args: object,
                **kwargs: object,
            ) -> object:
                selected.unlink()
                selected.symlink_to(redirected, target_is_directory=True)
                return real_orchestrator(*args, **kwargs)

            with (
                patch.object(
                    cli_module,
                    "_orchestrator",
                    side_effect=swap_alias_after_final_gate,
                ),
                redirect_stdout(io.StringIO()),
            ):
                status = main(["run", str(bound_path), "--apply", *arguments])

            self.assertEqual(status, 0)
            self.assertTrue((approved / "state" / "audit.sqlite3").is_file())
            self.assertTrue((approved / "artifacts" / "jira-draft.json").is_file())
            self.assertTrue((approved / "results" / "report.json").is_file())
            self.assertEqual(tuple((redirected / "state").iterdir()), ())
            self.assertEqual(tuple((redirected / "artifacts").iterdir()), ())
            self.assertEqual(tuple((redirected / "results").iterdir()), ())

    def test_runtime_directories_must_preexist_before_binding(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            runtime_root = root / "runtime"
            plan_path = root / "plan.json"
            plan_path.write_text(
                json.dumps(_draft_plan().to_dict()),
                encoding="utf-8",
            )
            bound_path = root / "bound.json"
            arguments = [
                "--connector-mode",
                "mock",
                "--database",
                str(runtime_root / "state/audit.sqlite3"),
                "--draft-output-dir",
                str(runtime_root / "artifacts"),
                "--workspace-root",
                str(runtime_root / "workspaces"),
                "--result-json",
                str(runtime_root / "results/report.json"),
            ]
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                self.assertEqual(
                    main(
                        [
                            "bind-context",
                            str(plan_path),
                            *arguments,
                            "--output",
                            str(bound_path),
                        ]
                    ),
                    1,
                )
            self.assertFalse(runtime_root.exists())
            self.assertIn("must already exist and be private", stderr.getvalue())

            _mkdir_private(
                runtime_root / "state",
                runtime_root / "artifacts",
                runtime_root / "workspaces",
                runtime_root / "results",
            )
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    main(
                        [
                            "bind-context",
                            str(plan_path),
                            *arguments,
                            "--output",
                            str(bound_path),
                        ]
                    ),
                    0,
                )

            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    main(["run", str(bound_path), "--apply", *arguments]),
                    0,
                )

            self.assertTrue((runtime_root / "state/audit.sqlite3").is_file())
            self.assertTrue((runtime_root / "artifacts/jira-draft.json").is_file())
            self.assertTrue((runtime_root / "results/report.json").is_file())

    def test_apply_accepts_legacy_posix_runtime_identity_shape(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            runtime_root = root / "runtime"
            _mkdir_private(
                runtime_root / "state",
                runtime_root / "artifacts",
                runtime_root / "workspaces",
                runtime_root / "results",
            )
            plan_path = root / "plan.json"
            plan_path.write_text(
                json.dumps(_draft_plan().to_dict()),
                encoding="utf-8",
            )
            bound_path = root / "bound.json"
            arguments = [
                "--connector-mode",
                "mock",
                "--database",
                str(runtime_root / "state/audit.sqlite3"),
                "--draft-output-dir",
                str(runtime_root / "artifacts"),
                "--workspace-root",
                str(runtime_root / "workspaces"),
                "--result-json",
                str(runtime_root / "results/report.json"),
            ]
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    main(
                        [
                            "bind-context",
                            str(plan_path),
                            *arguments,
                            "--output",
                            str(bound_path),
                        ]
                    ),
                    0,
                )

            legacy_payload = json.loads(bound_path.read_text(encoding="utf-8"))
            runtime = legacy_payload["execution_context"]["runtime"]
            for collection in ("runtime_paths", "publication_roots"):
                for binding in runtime[collection]:
                    binding.pop("object_identity")
            bound_path.write_text(json.dumps(legacy_payload), encoding="utf-8")

            with redirect_stdout(io.StringIO()):
                status = main(["run", str(bound_path), "--apply", *arguments])

            self.assertEqual(status, 0)
            self.assertTrue((runtime_root / "state/audit.sqlite3").is_file())
            self.assertTrue((runtime_root / "artifacts/jira-draft.json").is_file())
            self.assertTrue((runtime_root / "results/report.json").is_file())

    def test_binding_rejects_aliased_writable_runtime_directories(self) -> None:
        scenarios = {
            "audit-artifact": ("shared/audit.sqlite3", "shared", "results/report.json"),
            "audit-result": ("shared/audit.sqlite3", "artifacts", "shared/report.json"),
            "artifact-result": ("state/audit.sqlite3", "shared", "shared/report.json"),
        }
        for name, (database_name, artifacts_name, result_name) in scenarios.items():
            with (
                self.subTest(name=name),
                private_temporary_directory() as directory,
            ):
                root = Path(directory)
                _mkdir_private(
                    root / "artifacts",
                    root / "results",
                    root / "shared",
                    root / "state",
                )
                plan_path = root / "plan.json"
                plan_path.write_text(
                    json.dumps(_draft_plan().to_dict()),
                    encoding="utf-8",
                )
                bound_path = root / "bound.json"
                stderr = io.StringIO()
                with redirect_stderr(stderr):
                    status = main(
                        [
                            "bind-context",
                            str(plan_path),
                            "--connector-mode",
                            "mock",
                            "--database",
                            str(root / database_name),
                            "--draft-output-dir",
                            str(root / artifacts_name),
                            "--result-json",
                            str(root / result_name),
                            "--output",
                            str(bound_path),
                        ]
                    )

                self.assertEqual(status, 1)
                self.assertIn("pairwise distinct", stderr.getvalue())
                self.assertFalse(bound_path.exists())

    def test_runtime_binding_rejects_distinct_spellings_of_same_inode(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            state = root / "state"
            artifacts = root / "artifacts"
            _mkdir_private(state, artifacts)
            runtime = build_runtime_execution_binding(
                IntegrationConfig.from_toml(
                    resolve_config_source(None, "integrations.toml")
                ),
                connector_mode="mock",
                include_writes=False,
                include_communications=False,
                audit_database=state / "audit.sqlite3",
                artifact_root=artifacts,
                workspace_root=None,
                result_json=None,
                evidence_type=None,
                configuration_sources=_runtime_sources(root, suffix="same-inode"),
            )
            audit_binding = next(
                item for item in runtime.runtime_paths if item.name == "audit.parent"
            )
            artifact_binding = next(
                item for item in runtime.runtime_paths if item.name == "artifact.root"
            )
            forged_artifact = replace(
                artifact_binding,
                path=str(root / "different-spelling"),
                anchor_path=str(root / "different-spelling"),
                device=audit_binding.device,
                inode=audit_binding.inode,
                object_identity=replace(
                    artifact_binding.object_identity,
                    device=audit_binding.device,
                    inode=audit_binding.inode,
                ),
            )
            with self.assertRaisesRegex(ValidationError, "identities.*distinct"):
                replace(
                    runtime,
                    artifact_root=forged_artifact.path,
                    runtime_paths=(audit_binding, forged_artifact),
                )

    def test_local_git_mutation_is_rejected_before_registry_or_audit(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            drafts = root / "drafts"
            _mkdir_private(drafts)
            plan_path = root / "plan.json"
            plan_path.write_text(
                json.dumps(_git_mutation_plan().to_dict()),
                encoding="utf-8",
            )
            bound_path = root / "bound.json"
            arguments = [
                "--connector-mode",
                "mock",
                "--database",
                str(root / "audit.sqlite3"),
                "--draft-output-dir",
                str(drafts),
            ]
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    main(
                        [
                            "bind-context",
                            str(plan_path),
                            *arguments,
                            "--output",
                            str(bound_path),
                        ]
                    ),
                    0,
                )

            stderr = io.StringIO()
            with (
                patch("master_agent.cli._mock_registry") as mock_registry,
                patch("master_agent.cli.AuditLog") as audit_log,
                redirect_stderr(stderr),
            ):
                status = main(["run", str(bound_path), "--apply", *arguments])

            self.assertEqual(status, 1)
            self.assertIn(
                "local Git mutation capabilities are disabled", stderr.getvalue()
            )
            mock_registry.assert_not_called()
            audit_log.assert_not_called()

    def test_apply_fails_closed_if_canonical_ancestor_is_replaced(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            approved = root / "approved"
            redirected = root / "redirected"
            saved = root / "approved.saved"
            for destination in (approved, redirected):
                for name in ("artifacts", "results", "state", "workspaces"):
                    (destination / name).mkdir(parents=True, mode=0o700)
            plan_path = root / "plan.json"
            plan_path.write_text(
                json.dumps(_draft_plan().to_dict()),
                encoding="utf-8",
            )
            bound_path = root / "bound.json"
            arguments = [
                "--connector-mode",
                "mock",
                "--database",
                str(approved / "state/audit.sqlite3"),
                "--draft-output-dir",
                str(approved / "artifacts"),
                "--workspace-root",
                str(approved / "workspaces"),
                "--result-json",
                str(approved / "results/report.json"),
            ]
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    main(
                        [
                            "bind-context",
                            str(plan_path),
                            *arguments,
                            "--output",
                            str(bound_path),
                        ]
                    ),
                    0,
                )
            real_orchestrator = cli_module._orchestrator

            def replace_approved_ancestor(
                *args: object,
                **kwargs: object,
            ) -> object:
                approved.rename(saved)
                approved.symlink_to(redirected, target_is_directory=True)
                return real_orchestrator(*args, **kwargs)

            stderr = io.StringIO()
            with (
                patch.object(
                    cli_module,
                    "_orchestrator",
                    side_effect=replace_approved_ancestor,
                ),
                redirect_stdout(io.StringIO()),
                redirect_stderr(stderr),
            ):
                status = main(["run", str(bound_path), "--apply", *arguments])

            self.assertEqual(status, 1)
            self.assertIn("runtime directory path was replaced", stderr.getvalue())
            self.assertTrue((saved / "state/audit.sqlite3").is_file())
            self.assertEqual(tuple((redirected / "state").iterdir()), ())
            self.assertEqual(tuple((redirected / "artifacts").iterdir()), ())
            self.assertEqual(tuple((redirected / "results").iterdir()), ())

    def test_apply_pins_approved_identity_before_first_context_gate(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            approved = root / "approved"
            saved = root / "approved.saved"
            for name in ("artifacts", "results", "state", "workspaces"):
                (approved / name).mkdir(parents=True, mode=0o700)
            plan_path = root / "plan.json"
            plan_path.write_text(
                json.dumps(_draft_plan().to_dict()),
                encoding="utf-8",
            )
            bound_path = root / "bound.json"
            arguments = [
                "--connector-mode",
                "mock",
                "--database",
                str(approved / "state/audit.sqlite3"),
                "--draft-output-dir",
                str(approved / "artifacts"),
                "--workspace-root",
                str(approved / "workspaces"),
                "--result-json",
                str(approved / "results/report.json"),
            ]
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    main(
                        [
                            "bind-context",
                            str(plan_path),
                            *arguments,
                            "--output",
                            str(bound_path),
                        ]
                    ),
                    0,
                )
            real_open = execution_context_module.PinnedDirectory.open
            swapped = False

            def replace_before_pin(*args: object, **kwargs: object) -> object:
                nonlocal swapped
                if not swapped:
                    approved.rename(saved)
                    for name in ("artifacts", "results", "state", "workspaces"):
                        (approved / name).mkdir(parents=True, mode=0o700)
                    swapped = True
                return real_open(*args, **kwargs)

            stderr = io.StringIO()
            with (
                patch.object(
                    execution_context_module.PinnedDirectory,
                    "open",
                    side_effect=replace_before_pin,
                ),
                patch("master_agent.cli._mock_registry") as mock_registry,
                patch("master_agent.cli.AuditLog") as audit_log,
                redirect_stderr(stderr),
            ):
                status = main(["run", str(bound_path), "--apply", *arguments])

            self.assertEqual(status, 1)
            self.assertIn("approved identity", stderr.getvalue())
            mock_registry.assert_not_called()
            audit_log.assert_not_called()
            self.assertEqual(tuple((approved / "state").iterdir()), ())
            self.assertEqual(tuple((approved / "artifacts").iterdir()), ())
            self.assertEqual(tuple((approved / "results").iterdir()), ())

    def test_draft_fails_closed_if_canonical_artifact_root_is_replaced(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            artifacts = root / "artifacts"
            redirected = root / "redirected"
            saved = root / "artifacts.saved"
            artifacts.mkdir(mode=0o700)
            redirected.mkdir(mode=0o700)
            plan_path = root / "plan.json"
            plan_path.write_text(
                json.dumps(_draft_plan().to_dict()),
                encoding="utf-8",
            )
            bound_path = root / "bound.json"
            arguments = [
                "--connector-mode",
                "mock",
                "--database",
                str(root / "audit.sqlite3"),
                "--draft-output-dir",
                str(artifacts),
            ]
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    main(
                        [
                            "bind-context",
                            str(plan_path),
                            *arguments,
                            "--output",
                            str(bound_path),
                        ]
                    ),
                    0,
                )
            real_execute = JiraDraftConnector.execute

            def replace_artifact_root(
                connector: JiraDraftConnector,
                action: AgentAction,
            ) -> object:
                artifacts.rename(saved)
                artifacts.symlink_to(redirected, target_is_directory=True)
                return real_execute(connector, action)

            with (
                patch.object(JiraDraftConnector, "execute", new=replace_artifact_root),
                redirect_stdout(io.StringIO()),
            ):
                status = main(["run", str(bound_path), "--apply", *arguments])

            self.assertEqual(status, 2)
            self.assertEqual(tuple(saved.iterdir()), ())
            self.assertEqual(tuple(redirected.iterdir()), ())

    def test_result_fails_closed_if_canonical_parent_is_replaced(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            results = root / "results"
            redirected = root / "redirected"
            saved = root / "results.saved"
            results.mkdir(mode=0o700)
            redirected.mkdir(mode=0o700)
            _mkdir_private(root / "artifacts")
            plan_path = root / "plan.json"
            plan_path.write_text(
                json.dumps(_draft_plan().to_dict()),
                encoding="utf-8",
            )
            bound_path = root / "bound.json"
            arguments = [
                "--connector-mode",
                "mock",
                "--database",
                str(root / "audit.sqlite3"),
                "--draft-output-dir",
                str(root / "artifacts"),
                "--result-json",
                str(results / "report.json"),
            ]
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    main(
                        [
                            "bind-context",
                            str(plan_path),
                            *arguments,
                            "--output",
                            str(bound_path),
                        ]
                    ),
                    0,
                )
            real_commit = cli_module.RetainedJSONReservation.commit

            def replace_result_parent(
                reservation: object,
                payload: object,
            ) -> object:
                results.rename(saved)
                results.symlink_to(redirected, target_is_directory=True)
                return real_commit(reservation, payload)  # type: ignore[arg-type]

            stderr = io.StringIO()
            with (
                patch.object(
                    cli_module.RetainedJSONReservation,
                    "commit",
                    new=replace_result_parent,
                ),
                redirect_stdout(io.StringIO()),
                redirect_stderr(stderr),
            ):
                status = main(["run", str(bound_path), "--apply", *arguments])

            self.assertEqual(status, 1)
            self.assertIn("runtime directory path was replaced", stderr.getvalue())
            self.assertFalse((saved / "report.json").exists())
            self.assertFalse((saved / "report.json.retention.json").exists())
            self.assertEqual(tuple(redirected.iterdir()), ())

    def test_stale_result_names_reject_before_registry_audit_or_effects(self) -> None:
        for stale_name in ("report.json", "report.json.retention.json"):
            with (
                self.subTest(stale_name=stale_name),
                private_temporary_directory() as directory,
            ):
                root = Path(directory)
                artifacts = root / "artifacts"
                results = root / "results"
                _mkdir_private(artifacts, results)
                plan_path = root / "plan.json"
                plan_path.write_text(
                    json.dumps(_draft_plan().to_dict()),
                    encoding="utf-8",
                )
                bound_path = root / "bound.json"
                database = root / "audit.sqlite3"
                result_path = results / "report.json"
                arguments = [
                    "--connector-mode",
                    "mock",
                    "--database",
                    str(database),
                    "--draft-output-dir",
                    str(artifacts),
                    "--result-json",
                    str(result_path),
                ]
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(
                        main(
                            [
                                "bind-context",
                                str(plan_path),
                                *arguments,
                                "--output",
                                str(bound_path),
                            ]
                        ),
                        0,
                    )
                stale = results / stale_name
                stale.write_bytes(b"peer-owned")
                stale.chmod(0o600)

                stderr = io.StringIO()
                with (
                    patch("master_agent.cli._mock_registry") as registry,
                    patch("master_agent.cli.AuditLog") as audit,
                    patch("master_agent.cli._orchestrator") as orchestrator,
                    redirect_stderr(stderr),
                ):
                    status = main(["run", str(bound_path), "--apply", *arguments])

                self.assertEqual(status, 1)
                self.assertIn("already exists", stderr.getvalue())
                registry.assert_not_called()
                audit.assert_not_called()
                orchestrator.assert_not_called()
                self.assertEqual(stale.read_bytes(), b"peer-owned")
                self.assertFalse(database.exists())
                self.assertEqual(tuple(artifacts.iterdir()), ())

    def test_result_is_committed_before_human_output(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            artifacts = root / "artifacts"
            results = root / "results"
            _mkdir_private(artifacts, results)
            plan_path = root / "plan.json"
            plan_path.write_text(
                json.dumps(_draft_plan().to_dict()),
                encoding="utf-8",
            )
            bound_path = root / "bound.json"
            result_path = results / "report.json"
            arguments = [
                "--connector-mode",
                "mock",
                "--database",
                str(root / "audit.sqlite3"),
                "--draft-output-dir",
                str(artifacts),
                "--result-json",
                str(result_path),
            ]
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    main(
                        [
                            "bind-context",
                            str(plan_path),
                            *arguments,
                            "--output",
                            str(bound_path),
                        ]
                    ),
                    0,
                )

            with (
                patch.object(
                    cli_module,
                    "_print_report",
                    side_effect=BrokenPipeError("closed output"),
                ),
                redirect_stderr(io.StringIO()),
            ):
                status = main(["run", str(bound_path), "--apply", *arguments])

            self.assertEqual(status, 1)
            self.assertTrue(result_path.is_file())
            self.assertTrue((results / "report.json.retention.json").is_file())

    def test_factory_rejects_bitbucket_local_git_publication(
        self,
    ) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            approved = root / "approved"
            redirected = root / "redirected"
            for destination in (approved, redirected):
                (destination / "repositories").mkdir(parents=True, mode=0o700)
            selected = root / "selected"
            selected.symlink_to(approved, target_is_directory=True)
            integrations_path = root / "integrations.toml"
            integrations_path.write_text(
                _BITBUCKET_PUBLICATION_CONFIG,
                encoding="utf-8",
            )
            integrations = IntegrationConfig.from_toml(integrations_path)
            environ = {"MASTER_AGENT_REPOSITORY_ROOT": str(selected / "repositories")}
            _mkdir_private(root / "artifacts", root / "workspaces")
            runtime = build_runtime_execution_binding(
                integrations,
                connector_mode="live",
                include_writes=True,
                include_communications=False,
                audit_database=root / "audit.sqlite3",
                artifact_root=root / "artifacts",
                workspace_root=root / "workspaces",
                result_json=None,
                evidence_type="unused",
                configuration_sources=_runtime_sources(root, suffix="same"),
                environ=environ,
            )
            approved_context = build_execution_context(
                integrations,
                environ=environ,
                runtime=runtime,
            )
            selected.unlink()
            selected.symlink_to(redirected, target_is_directory=True)

            with self.assertRaisesRegex(
                ConfigurationError,
                "branch publication is disabled",
            ):
                build_live_connectors(
                    integrations,
                    environ=environ,
                    systems={"bitbucket"},
                    include_writes=True,
                    workspace_root=root / "workspaces",
                    approved_execution_context=approved_context,
                )


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


def _draft_plan() -> ChangePlan:
    action = AgentAction(
        capability="jira.issue.update.draft",
        target=ResourceRef(
            system="jira",
            resource_type="issue",
            resource_id="ENG-1",
        ),
        parameters={
            "before": {"summary": "Before"},
            "fields": {"summary": "After"},
            "output_name": "jira-draft.json",
        },
        risk=RiskLevel.LOCAL_GENERATION,
        data_classification=DataClassification.INTERNAL,
        authority_source=AuthoritySource.DIRECT_USER,
        requires_approval=False,
        idempotency_key="execution-context-draft-test",
        justification="test canonical draft execution paths",
    )
    return ChangePlan(
        goal="test canonical execution paths",
        actions=(action,),
        created_by="test",
    )


def _git_mutation_plan() -> ChangePlan:
    action = AgentAction(
        capability="repository.patch.apply",
        target=ResourceRef(
            system="repository",
            resource_type="workspace",
            resource_id="example",
            expected_version="0" * 40,
        ),
        parameters={"patch": "diff --git a/a b/a\n"},
        risk=RiskLevel.REVERSIBLE_WRITE,
        data_classification=DataClassification.INTERNAL,
        authority_source=AuthoritySource.DIRECT_USER,
        requires_approval=True,
        idempotency_key="disabled-git-mutation",
        justification="prove local Git mutations are not routable",
    )
    return ChangePlan(
        goal="test disabled Git mutation",
        actions=(action,),
        created_by="test",
    )


def _replace_runtime_path(
    bindings: tuple[RuntimePathExecutionBinding, ...],
    name: str,
    path: Path,
) -> tuple[RuntimePathExecutionBinding, ...]:
    return tuple(
        replace(item, path=str(path), anchor_path=str(path))
        if item.name == name
        else item
        for item in bindings
    )


def _mkdir_private(*paths: Path) -> None:
    """Create explicit private runtime directories for binding tests."""

    for path in paths:
        path.mkdir(parents=True, mode=0o700, exist_ok=True)
        path.chmod(0o700)


def _github_principal_transport(
    *,
    login: str,
    user_id: int,
    scopes: str = "workflow, repo",
) -> QueueTransport:
    return QueueTransport(
        ExpectedRequest(
            method="GET",
            url_contains="/user",
            payload={"login": login, "id": user_id},
            headers={"X-OAuth-Scopes": scopes},
        )
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


_GITHUB_BEARER_CONFIG = """
[connectors.github]
enabled = true
deployment = "cloud"
base_url = "https://api.github.com"
auth_mode = "bearer"
secret_env = "MASTER_AGENT_GITHUB_TOKEN"
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


def _default_runtime_sources() -> dict[str, ConfigSource]:
    return {
        name: resolve_config_source(None, f"{name}.toml")
        for name in (
            "policy",
            "sources_of_truth",
            "capabilities",
            "governance",
            "identities",
            "retention",
        )
    }


if __name__ == "__main__":
    unittest.main()

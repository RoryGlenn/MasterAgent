"""End-to-end coverage for the progressive employee CLI workflow."""

from __future__ import annotations

import json
import os
import re
import stat
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import master_agent.cli as cli_module
from master_agent.approval_handoff import load_approval_request, write_restricted_json
from master_agent.capabilities import CapabilityCatalog
from master_agent.cli import main
from master_agent.config import IntegrationConfig
from master_agent.config_sources import ConfigSnapshot, resolve_config_source
from master_agent.connectors.factory import (
    build_live_registry as real_build_live_registry,
)
from master_agent.errors import AuthenticationError, AuthorizationError
from master_agent.models import (
    AgentAction,
    AuthoritySource,
    ChangePlan,
    DataClassification,
    ResourceRef,
    RiskLevel,
)
from master_agent.operating import install_organization_profile
from master_agent.platform_runtime import platform_runtime_status
from tests.fakes import ScriptedTransport
from tests.helpers import govern_test_plan

_APPROVAL_SECRET = "operating-approval-secret-" + "a" * 32


class OperatingModeCliTests(unittest.TestCase):
    """Exercise setup, doctor, and risk-routed execution."""

    def test_noninteractive_setup_is_private_local_and_idempotent(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            profile = root / "organization-profile.toml"
            with (
                patch("builtins.input") as prompt,
                patch("master_agent.cli.build_live_registry") as live_registry,
            ):
                first = _run_cli(
                    ["setup", "--profile", str(profile), "--non-interactive"]
                )
                second = _run_cli(
                    ["setup", "--profile", str(profile), "--non-interactive"]
                )

            self.assertEqual(first[0], 0, first[2])
            self.assertEqual(second[0], 0, second[2])
            self.assertIn("provider connections: none", first[1])
            self.assertEqual(stat.S_IMODE(profile.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE((root / "runs").stat().st_mode), 0o700)
            self.assertEqual(
                {item.name for item in root.iterdir()},
                {"organization-profile.toml", "runs"},
            )
            prompt.assert_not_called()
            live_registry.assert_not_called()

    def test_interactive_setup_can_cancel_before_local_mutation(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            profile = root / "organization-profile.toml"
            with patch("builtins.input", return_value="no") as prompt:
                status, stdout, stderr = _run_cli(
                    ["setup", "--profile", str(profile), "--interactive"]
                )

            self.assertEqual(status, 2, stderr)
            self.assertIn("setup cancelled", stdout)
            self.assertFalse(profile.exists())
            self.assertEqual(tuple(root.iterdir()), ())
            prompt.assert_called_once()

    def test_interactive_setup_treats_closed_stdin_as_safe_cancellation(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            profile = root / "organization-profile.toml"
            with patch("builtins.input", side_effect=EOFError) as prompt:
                status, stdout, stderr = _run_cli(
                    ["setup", "--profile", str(profile), "--interactive"]
                )

            self.assertEqual(status, 2, stderr)
            self.assertIn("setup cancelled", stdout)
            self.assertFalse(profile.exists())
            self.assertEqual(tuple(root.iterdir()), ())
            prompt.assert_called_once()

    def test_doctor_distinguishes_installation_from_missing_setup(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            profile = root / "organization-profile.toml"
            status, stdout, stderr = _run_cli(
                [
                    "doctor",
                    "--profile",
                    str(profile),
                    "--require-level",
                    "install",
                ]
            )

            self.assertEqual(status, 0, stderr)
            self.assertIn("install_ready: True", stdout)
            self.assertIn("read_ready: False", stdout)
            self.assertIn("draft_ready: False", stdout)
            self.assertIn("missing_organization_setup", stdout)
            self.assertEqual(tuple(root.iterdir()), ())

    def test_doctor_reports_profile_capabilities_without_network(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            profile = _setup_default(root)
            report = root / "doctor.json"
            with patch("master_agent.cli.build_live_registry") as live_registry:
                status, stdout, stderr = _run_cli(
                    [
                        "doctor",
                        "--profile",
                        str(profile),
                        "--require-level",
                        "draft",
                        "--output",
                        str(report),
                    ]
                )

            self.assertEqual(status, 0, stderr)
            self.assertIn("draft_ready: True", stdout)
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], "master-agent/operating-readiness@1")
            self.assertTrue(payload["levels"]["install_ready"])
            self.assertTrue(payload["levels"]["read_ready"])
            self.assertTrue(payload["levels"]["draft_ready"])
            self.assertFalse(payload["levels"]["enterprise_ready"])
            self.assertEqual(
                payload["platform_runtime"],
                platform_runtime_status().to_dict(),
            )
            live_registry.assert_not_called()

    def test_windows_doctor_reports_absent_profile_without_reading_bytes(
        self,
    ) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            profile = root / "missing-organization-profile.toml"
            with (
                patch(
                    "master_agent.platform_runtime.factory.sys.platform",
                    "win32",
                ),
                patch(
                    "master_agent.cli._load_active_organization_profile"
                ) as load_profile,
                patch(
                    "master_agent.cli.require_persistent_state_platform"
                ) as persistent_preflight,
                patch("master_agent.config_sources.os.open") as open_file,
            ):
                status, stdout, stderr = _run_cli(
                    [
                        "doctor",
                        "--profile",
                        str(profile),
                        "--require-level",
                        "draft",
                    ]
                )
            remaining = tuple(root.iterdir())

        self.assertEqual(status, 2, stderr)
        self.assertIn(
            "platform runtime: windows (windows-unavailable)",
            stdout,
        )
        self.assertIn(
            "secure_filesystem: unavailable (windows-unavailable)",
            stdout,
        )
        self.assertIn("install_ready: True", stdout)
        self.assertIn("read_ready: False", stdout)
        self.assertIn("draft_ready: False", stdout)
        self.assertIn("missing_organization_setup", stdout)
        load_profile.assert_not_called()
        persistent_preflight.assert_not_called()
        open_file.assert_not_called()
        self.assertEqual(remaining, ())

    def test_windows_doctor_rejects_existing_profile_before_reading_bytes(
        self,
    ) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            profile = _setup_default(root)
            with (
                patch(
                    "master_agent.platform_runtime.factory.sys.platform",
                    "win32",
                ),
                patch("master_agent.config_sources.os.open") as open_file,
            ):
                status, stdout, stderr = _run_cli(
                    [
                        "doctor",
                        "--profile",
                        str(profile),
                        "--require-level",
                        "install",
                    ]
                )

        self.assertEqual(status, 2)
        self.assertEqual(stdout, "")
        self.assertEqual(
            stderr,
            "error: runtime_defect: organization profile could not be loaded safely: "
            "native windows secure_filesystem backend is not implemented\n",
        )
        open_file.assert_not_called()

    def test_doctor_marks_ca_and_token_file_reads_as_filesystem_backed(self) -> None:
        cases = (
            (
                "github.public_repository.list",
                "MASTER_AGENT_ENTERPRISE_CA_BUNDLE",
                False,
            ),
            (
                "microsoft.identity.read",
                "MASTER_AGENT_GRAPH_TOKEN_FILE",
                True,
            ),
        )
        for capability, environment_name, expects_missing_auth in cases:
            with self.subTest(capability=capability), TemporaryDirectory() as raw:
                root = Path(raw).resolve()
                profile = _install_profile(root, capabilities=(capability,))
                selected_file = root / "selected-trust-file"
                selected_file.write_text(
                    "selected but never trusted\n", encoding="utf-8"
                )
                selected_file.chmod(0o600)
                output = root / "doctor.json"
                with (
                    patch.dict(
                        os.environ,
                        {environment_name: str(selected_file)},
                        clear=True,
                    ),
                    patch(
                        "master_agent.cli.platform_runtime_status",
                        return_value=platform_runtime_status("win32"),
                    ),
                    patch("master_agent.operating.capture_ca_bundle") as capture_bundle,
                    patch(
                        "master_agent.operating.create_ssl_context"
                    ) as create_context,
                    patch("master_agent.cli._write_json") as write_json,
                    redirect_stdout(StringIO()),
                ):
                    status = cli_module._doctor(
                        profile_path=profile,
                        require_level="read",
                        output=output,
                    )

                self.assertEqual(status, 2)
                payload = write_json.call_args.args[1]
                selected = next(
                    item
                    for item in payload["capabilities"]
                    if item["capability"] == capability
                )
                self.assertFalse(selected["read_ready"])
                issues = selected["issues"]
                self.assertTrue(
                    any(
                        issue["category"] == "runtime_defect"
                        and "secure_filesystem" in issue["message"]
                        for issue in issues
                    )
                )
                self.assertEqual(
                    any(
                        issue["category"] == "missing_user_authentication"
                        for issue in issues
                    ),
                    expects_missing_auth,
                )
                self.assertFalse(output.exists())
                capture_bundle.assert_not_called()
                create_context.assert_not_called()

    def test_doctor_detects_missing_private_state_without_recreating_it(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            profile = _setup_default(root)
            (root / "runs").rmdir()

            status, stdout, stderr = _run_cli(
                [
                    "doctor",
                    "--profile",
                    str(profile),
                    "--require-level",
                    "install",
                ]
            )

            self.assertEqual(status, 2, stderr)
            self.assertIn("install_ready: False", stdout)
            self.assertIn("missing_organization_setup", stdout)
            self.assertFalse((root / "runs").exists())

    def test_doctor_does_not_claim_effect_ready_without_approval_setup(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            profile, _authorities = _install_effect_profile(
                root,
                include_authorities=False,
            )

            status, stdout, stderr = _run_cli(
                [
                    "doctor",
                    "--profile",
                    str(profile),
                    "--require-level",
                    "effect",
                ]
            )

            self.assertEqual(status, 2, stderr)
            self.assertIn("effect_ready: False", stdout)
            self.assertIn("missing_organization_setup", stdout)
            self.assertIn("approval authorities", stdout)

    def test_doctor_uses_stable_categories_for_unsafe_or_missing_configuration(
        self,
    ) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            profile = _setup_default(root)
            alias = root / "profile-alias.toml"
            alias.symlink_to(profile)

            alias_status, _stdout, alias_stderr = _run_cli(
                ["doctor", "--profile", str(alias)]
            )
            profile.chmod(0o666)
            mode_status, _stdout, mode_stderr = _run_cli(
                ["doctor", "--profile", str(profile)]
            )

            self.assertEqual(alias_status, 2)
            self.assertIn("runtime_defect", alias_stderr)
            self.assertEqual(mode_status, 2)
            self.assertIn("runtime_defect", mode_stderr)

        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            missing = root / "missing-policy.toml"
            profile = _install_profile(
                root,
                capabilities=("github.public_repository.list",),
                configuration={"policy": missing},
            )
            report = root / "doctor.json"

            status, stdout, stderr = _run_cli(
                [
                    "doctor",
                    "--profile",
                    str(profile),
                    "--require-level",
                    "read",
                    "--output",
                    str(report),
                ]
            )

            self.assertEqual(status, 2, stderr)
            self.assertIn("missing_organization_setup", stdout)
            capability = json.loads(report.read_text(encoding="utf-8"))["capabilities"][
                0
            ]
            self.assertFalse(capability["read_ready"])
            self.assertEqual(
                capability["issues"][-1]["category"],
                "missing_organization_setup",
            )

    def test_doctor_scopes_missing_or_invalid_integrations_to_provider_capabilities(
        self,
    ) -> None:
        for condition, expected_category in (
            ("missing", "missing_organization_setup"),
            ("invalid", "runtime_defect"),
        ):
            with self.subTest(condition=condition), TemporaryDirectory() as raw:
                root = Path(raw).resolve()
                integrations = root / f"{condition}-integrations.toml"
                if condition == "invalid":
                    integrations.write_text("[connectors", encoding="utf-8")
                    integrations.chmod(0o600)
                profile = _install_profile(
                    root,
                    capabilities=(
                        "confluence.page.create.draft",
                        "github.public_repository.list",
                    ),
                    configuration={"integrations": integrations},
                )
                install_report = root / "install-doctor.json"
                draft_report = root / "draft-doctor.json"

                install_status, _stdout, install_stderr = _run_cli(
                    [
                        "doctor",
                        "--profile",
                        str(profile),
                        "--require-level",
                        "install",
                        "--output",
                        str(install_report),
                    ]
                )
                draft_status, _stdout, draft_stderr = _run_cli(
                    [
                        "doctor",
                        "--profile",
                        str(profile),
                        "--require-level",
                        "draft",
                        "--output",
                        str(draft_report),
                    ]
                )

                self.assertEqual(install_status, 0, install_stderr)
                self.assertEqual(draft_status, 0, draft_stderr)
                payload = json.loads(draft_report.read_text(encoding="utf-8"))
                self.assertTrue(payload["levels"]["install_ready"])
                self.assertTrue(payload["levels"]["draft_ready"])
                self.assertFalse(payload["levels"]["read_ready"])
                capabilities = {
                    item["capability"]: item for item in payload["capabilities"]
                }
                self.assertEqual(
                    capabilities["confluence.page.create.draft"]["issues"],
                    [],
                )
                provider_issues = capabilities["github.public_repository.list"][
                    "issues"
                ]
                self.assertEqual(
                    {item["category"] for item in provider_issues},
                    {expected_category},
                )
                self.assertEqual(tuple((root / "state" / "runs").iterdir()), ())
                plan = root / "local-draft.json"
                write_restricted_json(plan, _draft_plan().to_dict())
                execute_status, execute_stdout, execute_stderr = _run_cli(
                    ["execute", str(plan), "--profile", str(profile)]
                )
                self.assertEqual(execute_status, 0, execute_stderr)
                self.assertIn("successful: True", execute_stdout)
                self.assertEqual(
                    len(tuple((root / "state" / "runs").iterdir())),
                    1,
                )

    def test_doctor_keeps_the_capability_catalog_mandatory(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            profile = _install_profile(
                root,
                capabilities=("confluence.page.create.draft",),
                configuration={"capabilities": root / "missing-capabilities.toml"},
            )
            report = root / "doctor.json"

            status, _stdout, stderr = _run_cli(
                [
                    "doctor",
                    "--profile",
                    str(profile),
                    "--require-level",
                    "install",
                    "--output",
                    str(report),
                ]
            )

            self.assertEqual(status, 2)
            self.assertIn("missing_organization_setup", stderr)
            self.assertFalse(report.exists())

    def test_doctor_includes_audited_read_runtime_dependencies(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            governance = root / "governance.toml"
            governance.write_bytes(
                resolve_config_source(None, "governance.toml").payload.replace(
                    b"allow_ephemeral_direct_reads = true",
                    b"allow_ephemeral_direct_reads = false",
                    1,
                )
            )
            governance.chmod(0o600)
            profile = _install_profile(
                root,
                capabilities=("github.public_repository.list",),
                configuration={
                    "governance": governance,
                    "identities": root / "missing-identities.toml",
                    "retention": root / "missing-retention.toml",
                },
            )
            (root / "state" / "runs").rmdir()
            report = root / "doctor.json"

            with patch.dict(os.environ, {}, clear=True):
                status, _stdout, stderr = _run_cli(
                    [
                        "doctor",
                        "--profile",
                        str(profile),
                        "--require-level",
                        "read",
                        "--output",
                        str(report),
                    ]
                )

            self.assertEqual(status, 2, stderr)
            payload = json.loads(report.read_text(encoding="utf-8"))
            capability = payload["capabilities"][0]
            self.assertFalse(capability["read_ready"])
            messages = "\n".join(item["message"] for item in capability["issues"])
            self.assertIn("user authentication is missing", messages)
            self.assertIn("private operating state is not installed", messages)
            self.assertIn(
                "organization identities configuration is unavailable", messages
            )
            self.assertIn(
                "organization retention configuration is unavailable", messages
            )
            self.assertFalse((root / "state" / "runs").exists())

    def test_doctor_scopes_approval_required_reads_per_capability(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            governance = root / "governance.toml"
            governance.write_bytes(
                resolve_config_source(None, "governance.toml").payload
                + b"""

[[rules]]
pattern = "jira.issue.read"
owner = "jira-owner"
authentication = "provider_specific"
data_classifications = ["public", "internal", "confidential"]
approval_tier = "single"
environments = ["development", "non_production", "production"]
enabled = true
"""
            )
            governance.chmod(0o600)
            profile = _install_profile(
                root,
                capabilities=(
                    "github.public_repository.list",
                    "jira.issue.read",
                ),
                configuration={"governance": governance},
            )
            report = root / "doctor.json"

            with patch.dict(os.environ, {}, clear=True):
                status, _stdout, stderr = _run_cli(
                    [
                        "doctor",
                        "--profile",
                        str(profile),
                        "--require-level",
                        "read",
                        "--output",
                        str(report),
                    ]
                )

            self.assertEqual(status, 0, stderr)
            payload = json.loads(report.read_text(encoding="utf-8"))
            capabilities = {
                item["capability"]: item for item in payload["capabilities"]
            }
            github = capabilities["github.public_repository.list"]
            jira = capabilities["jira.issue.read"]
            self.assertTrue(github["read_ready"])
            self.assertEqual(github["issues"], [])
            self.assertFalse(jira["read_ready"])
            self.assertIn(
                "approval-required capability needs selected approval authorities",
                {item["message"] for item in jira["issues"]},
            )

    def test_execute_preflights_required_configs_before_run_allocation(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            profile = _install_profile(
                root,
                capabilities=("confluence.page.create.draft",),
                configuration={"retention": root / "missing-retention.toml"},
            )
            plan_path = root / "draft-plan.json"
            write_restricted_json(plan_path, _draft_plan().to_dict())

            status, _stdout, stderr = _run_cli(
                ["execute", str(plan_path), "--profile", str(profile)]
            )

            self.assertEqual(status, 2)
            self.assertIn("missing_organization_setup", stderr)
            self.assertEqual(tuple((root / "state" / "runs").iterdir()), ())

    def test_execute_ignores_unrelated_missing_approval_config_for_draft(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            profile = _install_profile(
                root,
                capabilities=("confluence.page.create.draft",),
                configuration={"approval_authorities": root / "missing-approval.toml"},
            )
            plan_path = root / "draft-plan.json"
            write_restricted_json(plan_path, _draft_plan().to_dict())

            status, stdout, stderr = _run_cli(
                ["execute", str(plan_path), "--profile", str(profile)]
            )

            self.assertEqual(status, 0, stderr)
            self.assertIn("successful: True", stdout)

    def test_unimplemented_catalog_capability_fails_before_state(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            catalog = root / "capabilities.toml"
            catalog.write_text(
                '[capabilities."github.unimplemented.read"]\n'
                "enabled = true\n"
                'authentication = "anonymous_or_configured_connector"\n'
                'risk = "read_only"\n',
                encoding="utf-8",
            )
            catalog.chmod(0o600)
            profile = _install_profile(
                root,
                capabilities=("github.unimplemented.read",),
                configuration={"capabilities": catalog},
            )
            plan_path = root / "unimplemented-plan.json"
            write_restricted_json(
                plan_path,
                _read_plan("github.unimplemented.read").to_dict(),
            )
            with patch("master_agent.cli.allocate_operating_run") as allocate:
                status, _stdout, stderr = _run_cli(
                    ["execute", str(plan_path), "--profile", str(profile)]
                )

            self.assertEqual(status, 2)
            self.assertIn("runtime_defect", stderr)
            allocate.assert_not_called()

    def test_disabled_provider_feature_is_blocked_before_state(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            authorities = _write_authorities(root)
            profile = _install_profile(
                root,
                capabilities=("confluence.page.create",),
                mode="developer",
                writes_enabled=True,
                configuration={"approval_authorities": authorities},
            )
            plan_path = root / "effect-plan.json"
            write_restricted_json(plan_path, _effect_plan().to_dict())
            with patch("master_agent.cli.allocate_operating_run") as allocate:
                status, _stdout, stderr = _run_cli(
                    ["execute", str(plan_path), "--profile", str(profile)]
                )

            self.assertEqual(status, 2)
            self.assertIn("blocked_policy", stderr)
            allocate.assert_not_called()

    def test_employee_missing_capability_fails_before_state_or_runtime(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            profile = _setup_default(root)
            plan = _read_plan("github.repository.read")
            path = root / "unsupported-plan.json"
            write_restricted_json(path, plan.to_dict())
            with (
                patch("master_agent.cli.allocate_operating_run") as allocate,
                patch("master_agent.cli._load_credential_store") as credentials,
                patch("master_agent.cli.build_live_registry") as live_registry,
            ):
                status, _stdout, stderr = _run_cli(
                    ["execute", str(path), "--profile", str(profile)]
                )

            self.assertEqual(status, 2)
            self.assertIn("unsupported_capability", stderr)
            allocate.assert_not_called()
            credentials.assert_not_called()
            live_registry.assert_not_called()

    def test_placeholder_provider_is_rejected_before_credentials_or_connector(
        self,
    ) -> None:
        token = "placeholder-endpoint-token-must-not-be-used"
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            profile = _install_profile(
                root,
                capabilities=("jira.issue.read",),
            )
            plan_path = root / "jira-plan.json"
            write_restricted_json(plan_path, _jira_read_plan().to_dict())

            with (
                patch.dict(
                    os.environ,
                    {
                        "MASTER_AGENT_JIRA_USERNAME": "employee",
                        "MASTER_AGENT_JIRA_TOKEN": token,
                    },
                    clear=True,
                ),
                patch("master_agent.cli.allocate_operating_run") as allocate,
                patch("master_agent.cli._load_credential_store") as credentials,
                patch("master_agent.cli.build_live_registry") as live_registry,
            ):
                status, stdout, stderr = _run_cli(
                    ["execute", str(plan_path), "--profile", str(profile)]
                )

            self.assertEqual(status, 2)
            self.assertIn("missing_organization_setup", stderr)
            self.assertIn("placeholder", stderr)
            self.assertNotIn(token, stdout + stderr)
            allocate.assert_not_called()
            credentials.assert_not_called()
            live_registry.assert_not_called()

    def test_allowed_direct_read_selects_stateless_existing_route(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            profile = _setup_default(root)
            plan = _read_plan("github.public_repository.list")
            path = root / "public-plan.json"
            write_restricted_json(path, plan.to_dict())
            with (
                patch("master_agent.cli._run", return_value=0) as run,
                patch("master_agent.cli.allocate_operating_run") as allocate,
            ):
                status, _stdout, stderr = _run_cli(
                    ["execute", str(path), "--profile", str(profile)]
                )

            self.assertEqual(status, 0, stderr)
            self.assertTrue(run.call_args.kwargs["direct_read"])
            self.assertFalse(run.call_args.kwargs["apply"])
            self.assertEqual(
                run.call_args.kwargs["organization_profile_path"],
                profile,
            )
            self.assertEqual(
                run.call_args.kwargs["loaded_plan"].fingerprint,
                plan.fingerprint,
            )
            self.assertEqual(
                run.call_args.kwargs["expected_plan_fingerprint"],
                plan.fingerprint,
            )
            allocate.assert_not_called()
            self.assertEqual(tuple((root / "runs").iterdir()), ())

    def test_governance_can_route_a_public_read_through_audited_execution(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            governance = root / "governance.toml"
            governance.write_bytes(
                resolve_config_source(None, "governance.toml").payload.replace(
                    b"allow_ephemeral_direct_reads = true",
                    b"allow_ephemeral_direct_reads = false",
                    1,
                )
            )
            governance.chmod(0o600)
            profile = _install_profile(
                root,
                capabilities=("github.public_repository.list",),
                configuration={"governance": governance},
            )
            plan_path = root / "public-plan.json"
            write_restricted_json(
                plan_path, _public_github_plan("public-user").to_dict()
            )

            with (
                patch("master_agent.cli._bind_context", return_value=2) as bind,
                patch("master_agent.cli._run", return_value=0) as run,
            ):
                status, _stdout, stderr = _run_cli(
                    ["execute", str(plan_path), "--profile", str(profile)]
                )

            self.assertEqual(status, 2, stderr)
            bind.assert_called_once()
            run.assert_not_called()
            self.assertEqual(len(tuple((root / "state" / "runs").iterdir())), 1)

    def test_approval_required_read_uses_governed_handoff_not_direct_session(
        self,
    ) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            policy = root / "policy.toml"
            policy.write_bytes(
                resolve_config_source(None, "policy.toml")
                .payload.replace(
                    b'auto_permit_risks = ["read_only", "local_generation"]',
                    b'auto_permit_risks = ["local_generation"]',
                    1,
                )
                .replace(
                    b'require_approval_risks = ["reversible_write",',
                    b'require_approval_risks = ["read_only", "reversible_write",',
                    1,
                )
            )
            policy.chmod(0o600)
            profile = _install_profile(
                root,
                capabilities=("github.public_repository.list",),
                configuration={"policy": policy},
            )
            plan_path = root / "public-plan.json"
            write_restricted_json(
                plan_path, _public_github_plan("public-user").to_dict()
            )
            report = root / "doctor.json"

            doctor_status, _stdout, doctor_stderr = _run_cli(
                [
                    "doctor",
                    "--profile",
                    str(profile),
                    "--require-level",
                    "read",
                    "--output",
                    str(report),
                ]
            )
            with (
                patch("master_agent.cli.allocate_operating_run") as allocate,
                patch("master_agent.cli._run") as run,
            ):
                status, _stdout, stderr = _run_cli(
                    ["execute", str(plan_path), "--profile", str(profile)]
                )

            self.assertEqual(doctor_status, 2, doctor_stderr)
            readiness = json.loads(report.read_text(encoding="utf-8"))
            self.assertFalse(readiness["capabilities"][0]["read_ready"])
            self.assertIn("approval authorities", json.dumps(readiness))
            self.assertEqual(status, 2)
            self.assertIn("missing_organization_setup", stderr)
            self.assertIn("approval authorities", stderr)
            allocate.assert_not_called()
            run.assert_not_called()

    def test_hardened_public_read_catalog_preserves_configured_authentication(
        self,
    ) -> None:
        source = resolve_config_source(None, "capabilities.toml")
        marker = b'[capabilities."github.public_repository.list"]'
        before, separator, selected = source.payload.partition(marker)
        self.assertTrue(separator)
        section, next_separator, after = selected.partition(b"\n[capabilities.")
        hardened = section.replace(
            b'authentication = "anonymous_or_configured_connector"',
            b'authentication = "configured_connector"',
            1,
        )
        self.assertNotEqual(hardened, section)
        payload = before + separator + hardened
        if next_separator:
            payload += next_separator + after
        catalog = CapabilityCatalog.from_toml(
            ConfigSnapshot(display_path=source.display_path, payload=payload)
        )
        integrations = IntegrationConfig.from_toml(
            resolve_config_source(None, "integrations.toml")
        )

        adapted, anonymous = cli_module._adapt_anonymous_direct_read_integrations(
            _public_github_plan("public-user"),
            provider="github",
            integrations=integrations,
            catalog=catalog,
        )

        self.assertFalse(anonymous)
        self.assertEqual(adapted, integrations)

    def test_high_level_public_github_read_is_anonymous_and_stateless(self) -> None:
        username = "public-user"
        ambient_token = "ambient-token-must-not-be-read-or-sent"
        repository = {
            "id": 7,
            "node_id": "R_7",
            "name": "project",
            "full_name": f"{username}/project",
            "owner": {"login": username},
            "private": False,
            "visibility": "public",
            "fork": False,
            "archived": False,
            "disabled": False,
            "default_branch": "main",
            "topics": [],
            "updated_at": "2026-08-20T10:00:00Z",
            "pushed_at": "2026-08-20T09:00:00Z",
            "html_url": f"https://github.com/{username}/project",
        }
        transport = ScriptedTransport()
        transport.add_json("GET", f"/users/{username}/repos", [repository])
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            profile = _setup_default(root)
            plan_path = root / "public-plan.json"
            write_restricted_json(
                plan_path,
                _public_github_plan(username).to_dict(),
            )

            def build_with_transport(*args: object, **kwargs: object) -> object:
                kwargs["transport"] = transport
                return real_build_live_registry(*args, **kwargs)  # type: ignore[arg-type]

            with (
                patch.dict(
                    os.environ,
                    {"MASTER_AGENT_GITHUB_TOKEN": ambient_token},
                    clear=True,
                ),
                patch("master_agent.cli._load_credential_store") as credentials,
                patch("master_agent.cli._credential_environment") as credential_env,
                patch(
                    "master_agent.cli.build_live_registry",
                    side_effect=build_with_transport,
                ),
            ):
                status, stdout, stderr = _run_cli(
                    ["execute", str(plan_path), "--profile", str(profile)]
                )

            self.assertEqual(status, 0, stderr)
            self.assertIn(f"{username}/project", stdout)
            credentials.assert_not_called()
            credential_env.assert_not_called()
            self.assertEqual(len(transport.requests), 2)
            self.assertTrue(
                all(
                    "Authorization" not in request.headers
                    for request in transport.requests
                )
            )
            self.assertNotIn(ambient_token, stdout + stderr)
            self.assertEqual(tuple((root / "runs").iterdir()), ())

    def test_high_level_public_bitbucket_read_is_anonymous_and_stateless(
        self,
    ) -> None:
        workspace = "public-workspace"
        ambient_token = "ambient-bitbucket-token-must-not-be-read-or-sent"
        repository = {
            "uuid": "{repo-1}",
            "name": "project",
            "slug": "project",
            "is_private": False,
            "links": {"html": {"href": f"https://bitbucket.org/{workspace}/project"}},
        }
        transport = ScriptedTransport()
        transport.add_json(
            "GET",
            f"/2.0/repositories/{workspace}",
            {"values": [repository], "next": None},
        )
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            profile = _setup_default(root)
            plan_path = root / "public-plan.json"
            write_restricted_json(
                plan_path,
                _public_bitbucket_plan(workspace).to_dict(),
            )

            def build_with_transport(*args: object, **kwargs: object) -> object:
                kwargs["transport"] = transport
                return real_build_live_registry(*args, **kwargs)  # type: ignore[arg-type]

            with (
                patch.dict(
                    os.environ,
                    {
                        "MASTER_AGENT_BITBUCKET_TOKEN": ambient_token,
                        "MASTER_AGENT_BITBUCKET_USERNAME": "ambient-user",
                    },
                    clear=True,
                ),
                patch("master_agent.cli._load_credential_store") as credentials,
                patch(
                    "master_agent.cli.build_live_registry",
                    side_effect=build_with_transport,
                ),
            ):
                status, stdout, stderr = _run_cli(
                    ["execute", str(plan_path), "--profile", str(profile)]
                )

            self.assertEqual(status, 0, stderr)
            self.assertIn(f"{workspace}/project", stdout)
            credentials.assert_not_called()
            self.assertEqual(len(transport.requests), 2)
            self.assertTrue(
                all(
                    "Authorization" not in request.headers
                    for request in transport.requests
                )
            )
            self.assertNotIn(ambient_token, stdout + stderr)
            self.assertEqual(tuple((root / "runs").iterdir()), ())

    def test_local_generation_allocates_one_private_governed_run(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            profile = _setup_default(root)
            plan = _draft_plan()
            path = root / "draft-plan.json"
            write_restricted_json(path, plan.to_dict())

            status, stdout, stderr = _run_cli(
                ["execute", str(path), "--profile", str(profile)]
            )

            self.assertEqual(status, 0, stderr)
            self.assertIn("successful: True", stdout)
            runs = tuple((root / "runs").iterdir())
            self.assertEqual(len(runs), 1)
            run = runs[0]
            for name in ("state", "artifacts", "results", "workspace"):
                self.assertEqual(stat.S_IMODE((run / name).stat().st_mode), 0o700)
            self.assertTrue((run / "plan.json").is_file())
            self.assertTrue((run / "bound-plan.json").is_file())
            self.assertTrue((run / "state" / "audit.sqlite3").is_file())
            self.assertTrue((run / "artifacts" / "draft.json").is_file())
            self.assertTrue((run / "results" / "result.json").is_file())

    def test_profile_state_root_drift_is_rejected_before_runtime(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            profile = _install_profile(
                root,
                capabilities=("confluence.page.create.draft",),
            )
            plan_path = root / "draft-plan.json"
            write_restricted_json(plan_path, _draft_plan().to_dict())
            real_bind = cli_module._bind_context

            def mutate_profile_then_bind(**kwargs: object) -> int:
                changed = profile.read_text(encoding="utf-8").replace(
                    'state_root = "state"',
                    'state_root = "other"',
                )
                profile.write_text(changed, encoding="utf-8")
                profile.chmod(0o600)
                return real_bind(**kwargs)  # type: ignore[arg-type]

            with (
                patch(
                    "master_agent.cli._bind_context",
                    side_effect=mutate_profile_then_bind,
                ),
                patch("master_agent.cli._mock_read_registry") as registry,
            ):
                status, _stdout, stderr = _run_cli(
                    ["execute", str(plan_path), "--profile", str(profile)]
                )

            self.assertEqual(status, 2)
            self.assertIn("profile fingerprint differs", stderr)
            registry.assert_not_called()

    def test_malformed_high_level_plan_has_stable_runtime_category(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            profile = _setup_default(root)
            plan = root / "malformed.json"
            plan.write_text("{", encoding="utf-8")
            plan.chmod(0o600)

            status, _stdout, stderr = _run_cli(
                ["execute", str(plan), "--profile", str(profile)]
            )

            self.assertEqual(status, 2)
            self.assertIn("runtime_defect", stderr)

    @unittest.skipUnless(
        os.name == "posix"
        and hasattr(os, "mkfifo")
        and hasattr(os, "O_NONBLOCK")
        and hasattr(os, "O_NOFOLLOW"),
        "nonblocking no-follow FIFO safety requires POSIX",
    )
    def test_high_level_plan_rejects_fifo_without_blocking(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            profile = _setup_default(root)
            plan = root / "plan.json"
            os.mkfifo(plan, mode=0o600)
            real_open = os.open
            real_path_open = Path.open

            def guarded_open(
                path: object,
                flags: int,
                *args: object,
                **kwargs: object,
            ) -> int:
                if path == plan.name and kwargs.get("dir_fd") is not None:
                    self.assertTrue(flags & os.O_NONBLOCK)
                    self.assertTrue(flags & os.O_NOFOLLOW)
                return real_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]

            def reject_legacy_open(
                selected: Path,
                *args: object,
                **kwargs: object,
            ) -> object:
                if selected == plan:
                    raise AssertionError("high-level execute used blocking Path.open")
                return real_path_open(selected, *args, **kwargs)  # type: ignore[call-overload]

            with (
                patch("master_agent.cli.os.open", side_effect=guarded_open),
                patch.object(Path, "open", new=reject_legacy_open),
                patch("master_agent.cli.allocate_operating_run") as allocate,
            ):
                status, _stdout, stderr = _run_cli(
                    ["execute", str(plan), "--profile", str(profile)]
                )

            self.assertEqual(status, 2)
            self.assertIn("runtime_defect", stderr)
            self.assertIn("private regular file", stderr)
            allocate.assert_not_called()

    @unittest.skipUnless(
        os.name == "posix"
        and hasattr(os, "mkfifo")
        and hasattr(os, "O_NONBLOCK")
        and hasattr(os, "O_NOFOLLOW"),
        "nonblocking no-follow FIFO safety requires POSIX",
    )
    def test_high_level_approval_rejects_fifo_without_blocking(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            profile, _authorities = _install_effect_profile(root)
            plan = root / "effect-plan.json"
            write_restricted_json(plan, _effect_plan().to_dict())
            initial_status, stdout, initial_stderr = _run_cli(
                ["execute", str(plan), "--profile", str(profile)]
            )
            self.assertEqual(initial_status, 2, initial_stderr)
            match = re.search(r"^approval request: (.+)$", stdout, re.MULTILINE)
            self.assertIsNotNone(match)
            assert match is not None
            approval = root / "approval.fifo"
            os.mkfifo(approval, mode=0o600)
            real_open = os.open

            def guarded_open(
                path: object,
                flags: int,
                *args: object,
                **kwargs: object,
            ) -> int:
                if path == approval.name and kwargs.get("dir_fd") is not None:
                    self.assertTrue(flags & os.O_NONBLOCK)
                    self.assertTrue(flags & os.O_NOFOLLOW)
                return real_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]

            with patch("master_agent.cli.os.open", side_effect=guarded_open):
                status, _stdout, stderr = _run_cli(
                    [
                        "execute",
                        "--resume",
                        match.group(1),
                        "--approval",
                        str(approval),
                    ]
                )

            self.assertEqual(status, 2)
            self.assertIn("runtime_defect", stderr)
            self.assertIn("approval artifact", stderr)
            self.assertIn("private regular file", stderr)

    def test_high_level_provider_failures_have_stable_auth_categories(self) -> None:
        cases = (
            (AuthenticationError("token expired"), "missing_user_authentication"),
            (AuthorizationError("resource denied"), "blocked_policy"),
        )
        for error, category in cases:
            with (
                self.subTest(category=category),
                patch("master_agent.cli._execute", side_effect=error),
            ):
                status, _stdout, stderr = _run_cli(["execute", "plan.json"])

            self.assertEqual(status, 2)
            self.assertIn(category, stderr)

    def test_source_of_truth_block_fails_before_run_allocation(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            profile = _setup_default(root)
            plan_path = root / "projection-only.json"
            write_restricted_json(plan_path, _projection_only_plan().to_dict())

            with patch("master_agent.cli.allocate_operating_run") as allocate:
                status, _stdout, stderr = _run_cli(
                    ["execute", str(plan_path), "--profile", str(profile)]
                )

            self.assertEqual(status, 2)
            self.assertIn("blocked_policy", stderr)
            self.assertIn("canonical source", stderr)
            allocate.assert_not_called()
            self.assertEqual(tuple((root / "runs").iterdir()), ())

    def test_resume_rejects_every_profile_override_before_request_access(self) -> None:
        with patch("master_agent.cli.load_approval_request") as load:
            status, _stdout, stderr = _run_cli(
                [
                    "execute",
                    "--resume",
                    "/private/request.json",
                    "--approval",
                    "/private/approval.json",
                    "--profile",
                    "/replacement/profile.toml",
                ]
            )

        self.assertEqual(status, 2)
        self.assertIn("restores the bound organization profile", stderr)
        load.assert_not_called()

    def test_effect_handoff_binds_profile_and_resumes_without_overrides(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            profile, authorities = _install_effect_profile(root)
            plan_path = root / "effect-plan.json"
            write_restricted_json(plan_path, _effect_plan().to_dict())

            status, stdout, stderr = _run_cli(
                ["execute", str(plan_path), "--profile", str(profile)]
            )

            self.assertEqual(status, 2, stderr)
            self.assertIn("execute --resume REQUEST --approval ARTIFACT", stdout)
            match = re.search(r"^approval request: (.+)$", stdout, re.MULTILINE)
            self.assertIsNotNone(match)
            assert match is not None
            request_path = Path(match.group(1))
            request = load_approval_request(request_path)
            self.assertEqual(request.run.organization_profile, str(profile.resolve()))
            runtime = request.execution_context.runtime
            self.assertIsNotNone(runtime)
            assert runtime is not None
            self.assertIn(
                "organization_profile",
                {item.name for item in runtime.configurations},
            )
            self.assertIn(
                "organization_profile_path",
                {item.name for item in runtime.configurations},
            )

            approval = root / "approval.json"
            with patch.dict(
                os.environ,
                {"TEST_OPERATING_APPROVAL_SECRET": _APPROVAL_SECRET},
                clear=False,
            ):
                approve_status, _approve_stdout, approve_stderr = _run_cli(
                    [
                        "approve-request",
                        str(request_path),
                        "--key-id",
                        "operator",
                        "--expected-fingerprint",
                        request.fingerprint,
                        "--output",
                        str(approval),
                    ]
                )
                resume_status, resume_stdout, resume_stderr = _run_cli(
                    [
                        "execute",
                        "--resume",
                        str(request_path),
                        "--approval",
                        str(approval),
                    ]
                )

            self.assertEqual(approve_status, 0, approve_stderr)
            self.assertEqual(resume_status, 0, resume_stderr)
            self.assertIn("successful: True", resume_stdout)
            self.assertTrue(Path(request.run.result_json or "").is_file())
            self.assertEqual(
                request.run.approval_authorities, str(authorities.resolve())
            )

    def test_changed_profile_fails_before_connector_construction_on_resume(
        self,
    ) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            profile, _authorities = _install_effect_profile(root)
            plan_path = root / "effect-plan.json"
            write_restricted_json(plan_path, _effect_plan().to_dict())
            status, stdout, stderr = _run_cli(
                ["execute", str(plan_path), "--profile", str(profile)]
            )
            self.assertEqual(status, 2, stderr)
            match = re.search(r"^approval request: (.+)$", stdout, re.MULTILINE)
            self.assertIsNotNone(match)
            assert match is not None
            request_path = Path(match.group(1))
            request = load_approval_request(request_path)
            approval = root / "approval.json"
            with patch.dict(
                os.environ,
                {"TEST_OPERATING_APPROVAL_SECRET": _APPROVAL_SECRET},
                clear=False,
            ):
                approve_status, _stdout, approve_stderr = _run_cli(
                    [
                        "approve-request",
                        str(request_path),
                        "--key-id",
                        "operator",
                        "--expected-fingerprint",
                        request.fingerprint,
                        "--output",
                        str(approval),
                    ]
                )
            self.assertEqual(approve_status, 0, approve_stderr)
            changed = profile.read_text(encoding="utf-8").replace(
                'organization = "effect-test"',
                'organization = "changed-test"',
            )
            profile.write_text(changed, encoding="utf-8")
            profile.chmod(0o600)

            with (
                patch.dict(
                    os.environ,
                    {"TEST_OPERATING_APPROVAL_SECRET": _APPROVAL_SECRET},
                    clear=False,
                ),
                patch("master_agent.cli._mock_read_registry") as connectors,
            ):
                resume_status, _stdout, resume_stderr = _run_cli(
                    [
                        "execute",
                        "--resume",
                        str(request_path),
                        "--approval",
                        str(approval),
                    ]
                )

            self.assertEqual(resume_status, 2)
            self.assertIn("profile fingerprint differs", resume_stderr)
            connectors.assert_not_called()

    def test_changed_execution_config_fails_before_credentials_on_resume(
        self,
    ) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            authorities = _write_authorities(root)
            integrations = root / "integrations.toml"
            integrations.write_bytes(
                resolve_config_source(None, "integrations.toml").payload
            )
            profile = _install_profile(
                root,
                capabilities=("confluence.page.create",),
                mode="developer",
                connector_mode="mock",
                writes_enabled=True,
                configuration={
                    "approval_authorities": authorities,
                    "integrations": integrations,
                },
            )
            plan_path = root / "effect-plan.json"
            write_restricted_json(plan_path, _effect_plan().to_dict())
            status, stdout, stderr = _run_cli(
                ["execute", str(plan_path), "--profile", str(profile)]
            )
            self.assertEqual(status, 2, stderr)
            match = re.search(r"^approval request: (.+)$", stdout, re.MULTILINE)
            self.assertIsNotNone(match)
            assert match is not None
            request_path = Path(match.group(1))
            request = load_approval_request(request_path)
            approval = root / "approval.json"
            with patch.dict(
                os.environ,
                {"TEST_OPERATING_APPROVAL_SECRET": _APPROVAL_SECRET},
                clear=False,
            ):
                approve_status, _stdout, approve_stderr = _run_cli(
                    [
                        "approve-request",
                        str(request_path),
                        "--key-id",
                        "operator",
                        "--expected-fingerprint",
                        request.fingerprint,
                        "--output",
                        str(approval),
                    ]
                )
            self.assertEqual(approve_status, 0, approve_stderr)
            integrations.write_bytes(integrations.read_bytes() + b"\n# drift\n")

            with (
                patch.dict(
                    os.environ,
                    {"TEST_OPERATING_APPROVAL_SECRET": _APPROVAL_SECRET},
                    clear=False,
                ),
                patch("master_agent.cli._load_credential_store") as credentials,
                patch("master_agent.cli._mock_read_registry") as connectors,
            ):
                resume_status, _stdout, resume_stderr = _run_cli(
                    [
                        "execute",
                        "--resume",
                        str(request_path),
                        "--approval",
                        str(approval),
                    ]
                )

            self.assertEqual(resume_status, 2)
            self.assertIn("integrations bundle", resume_stderr)
            credentials.assert_not_called()
            connectors.assert_not_called()

    def test_resume_rejects_same_bytes_at_a_substituted_profile_path(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            profile, _authorities = _install_effect_profile(root)
            plan_path = root / "effect-plan.json"
            write_restricted_json(plan_path, _effect_plan().to_dict())
            status, stdout, stderr = _run_cli(
                ["execute", str(plan_path), "--profile", str(profile)]
            )
            self.assertEqual(status, 2, stderr)
            match = re.search(r"^approval request: (.+)$", stdout, re.MULTILINE)
            self.assertIsNotNone(match)
            assert match is not None
            request = load_approval_request(Path(match.group(1)))
            alias = root / "same-profile.toml"
            alias.write_bytes(profile.read_bytes())
            alias.chmod(0o600)
            substituted = root / "substituted-request.json"
            write_restricted_json(
                substituted,
                replace(
                    request,
                    run=replace(
                        request.run,
                        organization_profile=str(alias),
                    ),
                ).to_dict(),
            )

            with patch("master_agent.cli._load_operating_approval") as approval:
                resume_status, _stdout, resume_stderr = _run_cli(
                    [
                        "execute",
                        "--resume",
                        str(substituted),
                        "--approval",
                        str(root / "unused-approval.json"),
                    ]
                )

            self.assertEqual(resume_status, 2)
            self.assertIn("profile path differs", resume_stderr)
            approval.assert_not_called()


def _setup_default(root: Path) -> Path:
    profile = root / "organization-profile.toml"
    status, _stdout, stderr = _run_cli(
        ["setup", "--profile", str(profile), "--non-interactive"]
    )
    if status:
        raise AssertionError(stderr)
    return profile


def _install_profile(
    root: Path,
    *,
    capabilities: tuple[str, ...],
    mode: str = "employee",
    connector_mode: str = "live",
    writes_enabled: bool = False,
    communications_enabled: bool = False,
    configuration: dict[str, Path] | None = None,
) -> Path:
    profile = root / "organization-profile.toml"
    lines = [
        'schema = "master-agent/organization-profile@1"',
        'organization = "operating-test"',
        f'mode = "{mode}"',
        'state_root = "state"',
        f'connector_mode = "{connector_mode}"',
        f"writes_enabled = {str(writes_enabled).lower()}",
        f"communications_enabled = {str(communications_enabled).lower()}",
        "capabilities = ["
        + ", ".join(json.dumps(capability) for capability in capabilities)
        + "]",
        "",
        "[configuration]",
    ]
    lines.extend(
        f"{name} = {json.dumps(str(path))}"
        for name, path in sorted((configuration or {}).items())
    )
    payload = ("\n".join(lines) + "\n").encode("utf-8")
    install_organization_profile(
        ConfigSnapshot(display_path=root / "profile-source.toml", payload=payload),
        destination=profile,
    )
    return profile


def _write_authorities(root: Path) -> Path:
    authorities = root / "approval-authorities.toml"
    authorities.write_text(
        "[authorities.operator]\n"
        'subject = "operator@example.test"\n'
        'issuer = "master-agent.test"\n'
        'tenant = "test-tenant"\n'
        'roles = ["change-approver"]\n'
        'secret_env = "TEST_OPERATING_APPROVAL_SECRET"\n',
        encoding="utf-8",
    )
    authorities.chmod(0o600)
    return authorities


def _install_effect_profile(
    root: Path,
    *,
    include_authorities: bool = True,
) -> tuple[Path, Path]:
    authorities = _write_authorities(root)
    profile = root / "organization-profile.toml"
    payload = (
        'schema = "master-agent/organization-profile@1"\n'
        'organization = "effect-test"\n'
        'mode = "developer"\n'
        'state_root = "state"\n'
        'connector_mode = "mock"\n'
        "writes_enabled = true\n"
        "communications_enabled = false\n"
        'capabilities = ["confluence.page.create"]\n\n'
        "[configuration]\n"
        + (f'approval_authorities = "{authorities}"\n' if include_authorities else "")
    ).encode()
    install_organization_profile(
        ConfigSnapshot(display_path=root / "profile-source.toml", payload=payload),
        destination=profile,
    )
    return profile, authorities


def _read_plan(capability: str) -> ChangePlan:
    action = AgentAction(
        capability=capability,
        target=ResourceRef(
            system="github",
            resource_type="repository",
            resource_id="octocat",
        ),
        parameters={},
        risk=RiskLevel.READ_ONLY,
        data_classification=DataClassification.PUBLIC,
        authority_source=AuthoritySource.DIRECT_USER,
        requires_approval=False,
        idempotency_key=f"operating-read:{capability}",
        justification="Read one explicitly requested public repository listing.",
    )
    return govern_test_plan(
        ChangePlan(
            goal="Read public repository metadata.",
            actions=(action,),
            created_by="test",
        )
    )


def _public_github_plan(username: str) -> ChangePlan:
    action = AgentAction(
        capability="github.public_repository.list",
        target=ResourceRef(
            system="github",
            resource_type="public_repository_collection",
            resource_id=username,
        ),
        parameters={"limit": 1, "username": username},
        risk=RiskLevel.READ_ONLY,
        data_classification=DataClassification.PUBLIC,
        authority_source=AuthoritySource.DIRECT_USER,
        requires_approval=False,
        idempotency_key=f"github:public:{username}",
        justification="Read explicitly requested public repositories.",
    )
    return govern_test_plan(
        ChangePlan(
            goal=f"Read public repositories for {username}.",
            actions=(action,),
            created_by="test",
        )
    )


def _jira_read_plan() -> ChangePlan:
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
        idempotency_key="jira:read:ENG-1",
        justification="Read one explicitly requested issue.",
    )
    return govern_test_plan(
        ChangePlan(
            goal="Read Jira issue ENG-1.",
            actions=(action,),
            created_by="test",
        )
    )


def _public_bitbucket_plan(workspace: str) -> ChangePlan:
    action = AgentAction(
        capability="bitbucket.public_repository.list",
        target=ResourceRef(
            system="bitbucket",
            resource_type="public_repository_collection",
            resource_id=workspace,
        ),
        parameters={"limit": 1, "workspace": workspace},
        risk=RiskLevel.READ_ONLY,
        data_classification=DataClassification.PUBLIC,
        authority_source=AuthoritySource.DIRECT_USER,
        requires_approval=False,
        idempotency_key=f"bitbucket:public:{workspace}",
        justification="Read explicitly requested public repositories.",
    )
    return govern_test_plan(
        ChangePlan(
            goal=f"Read public repositories for {workspace}.",
            actions=(action,),
            created_by="test",
        )
    )


def _projection_only_plan() -> ChangePlan:
    action = AgentAction(
        capability="teams.message.draft",
        target=ResourceRef(
            system="teams",
            resource_type="message",
            resource_id="weekly-status-draft",
        ),
        parameters={
            "recipient_type": "chat",
            "recipient_id": "weekly-status",
            "body": "Projection without its canonical source.",
            "output_name": "weekly-status.json",
        },
        risk=RiskLevel.LOCAL_GENERATION,
        data_classification=DataClassification.INTERNAL,
        authority_source=AuthoritySource.DIRECT_USER,
        requires_approval=False,
        idempotency_key="teams:projection-only",
        justification="Exercise deterministic source-of-truth admission.",
    )
    return govern_test_plan(
        ChangePlan(
            goal="Draft a governed projection.",
            actions=(action,),
            created_by="test",
        )
    )


def _draft_plan() -> ChangePlan:
    action = AgentAction(
        capability="confluence.page.create.draft",
        target=ResourceRef(
            system="confluence",
            resource_type="page",
            resource_id="new-draft",
        ),
        parameters={
            "title": "Local draft",
            "body": "Review before any provider effect.",
            "output_name": "draft.json",
        },
        risk=RiskLevel.LOCAL_GENERATION,
        authority_source=AuthoritySource.DIRECT_USER,
        requires_approval=False,
        idempotency_key="operating-draft:one",
        justification="Create a local review artifact only.",
    )
    return govern_test_plan(
        ChangePlan(
            goal="Create one local draft.",
            actions=(action,),
            created_by="test",
        )
    )


def _effect_plan() -> ChangePlan:
    action = AgentAction(
        capability="confluence.page.create",
        target=ResourceRef(
            system="confluence",
            resource_type="page",
            resource_id="new-page",
        ),
        parameters={
            "space_key": "SD",
            "title": "Approved page",
            "body": "<p>Reviewed content.</p>",
            "representation": "storage",
        },
        risk=RiskLevel.REVERSIBLE_WRITE,
        authority_source=AuthoritySource.DIRECT_USER,
        requires_approval=True,
        idempotency_key="operating-effect:one",
        justification="Verify the exact profile-bound approval handoff.",
    )
    return govern_test_plan(
        ChangePlan(
            goal="Create one approved test page.",
            actions=(action,),
            created_by="test",
        )
    )


def _run_cli(arguments: list[str]) -> tuple[int, str, str]:
    stdout = StringIO()
    stderr = StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        status = main(arguments)
    return status, stdout.getvalue(), stderr.getvalue()


if __name__ == "__main__":
    unittest.main()

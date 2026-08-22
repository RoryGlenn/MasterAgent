"""Deterministic platform-runtime selection and import-isolation tests."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import stat
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import cast
from unittest.mock import Mock, patch

from master_agent.platform_runtime import (
    FilesystemObjectKind,
    LockMode,
    PlatformCapabilityUnavailable,
    PlatformContract,
    PlatformObjectIdentity,
    get_platform_runtime,
    platform_runtime_status,
    require_persistent_state_platform,
    require_platform_contract,
)

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_NEUTRAL_IMPORTS = frozenset({"fcntl", "grp", "pwd", "resource"})
PRE_PLATFORM_RUNTIME_WORKER_SHA256 = (
    "2f66f6c47fc3ed57cd12111c7f2165bdae44bc35be2294e51f5ff8bcfd399bef"
)


class PlatformRuntimeTests(unittest.TestCase):
    """Keep native selection complete, inspectable, and fail closed."""

    def test_platform_object_identity_round_trips_without_native_coercion(self) -> None:
        posix = PlatformObjectIdentity.from_posix(
            kind=FilesystemObjectKind.DIRECTORY,
            device=7,
            inode=11,
            owner=501,
            mode=0o700,
        )
        windows = PlatformObjectIdentity.from_windows(
            kind=FilesystemObjectKind.FILE,
            volume_serial="a1b2c3d4",
            file_id="0123456789abcdef0123456789abcdef",
            owner_sid="S-1-5-21-123-456-789-1001",
            dacl_sha256="1" * 64,
            trust_policy_sha256="2" * 64,
        )

        self.assertEqual(PlatformObjectIdentity.from_dict(posix.to_dict()), posix)
        self.assertEqual(PlatformObjectIdentity.from_dict(windows.to_dict()), windows)
        self.assertEqual(posix.object_key, ("posix", "7", "11"))
        self.assertEqual(
            windows.object_key,
            ("windows", "a1b2c3d4", "0123456789abcdef0123456789abcdef"),
        )
        self.assertNotIn("device", windows.to_dict())
        self.assertNotIn("owner_sid", posix.to_dict())

    def test_platform_object_identity_rejects_mixed_or_malformed_payloads(self) -> None:
        with self.assertRaisesRegex(ValueError, "mixes native payloads"):
            PlatformObjectIdentity(
                platform="windows",
                kind=FilesystemObjectKind.DIRECTORY,
                device=1,
                volume_serial="1",
                file_id="0" * 32,
                owner_sid="S-1-5-18",
                dacl_sha256="1" * 64,
                trust_policy_sha256="2" * 64,
            )
        malformed = {
            "schema": "master-agent/platform-object-identity@1",
            "platform": "windows",
            "kind": "directory",
            "windows": {
                "volume_serial": "1",
                "file_id": "ABC",
                "owner_sid": "S-1-5-18",
                "dacl_sha256": "1" * 64,
                "trust_policy_sha256": "2" * 64,
            },
        }
        with self.assertRaisesRegex(ValueError, "file identity"):
            PlatformObjectIdentity.from_dict(malformed)
        valid_windows = PlatformObjectIdentity.from_windows(
            kind=FilesystemObjectKind.DIRECTORY,
            volume_serial="1",
            file_id="0" * 32,
            owner_sid="S-1-5-18",
            dacl_sha256="1" * 64,
            trust_policy_sha256="2" * 64,
        )
        mixed = {
            **valid_windows.to_dict(),
            "posix": {"device": 1, "inode": 2, "owner": 3, "mode": 0o700},
        }
        with self.assertRaisesRegex(ValueError, "shape"):
            PlatformObjectIdentity.from_dict(mixed)

    def test_advisory_and_capsule_state_preflight_before_creation(self) -> None:
        from master_agent.advisory_budget import AdvisoryBudgetStore
        from master_agent.capsules import CapsuleStore

        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            capsule_root = root / "capsules"
            advisory_root = root / "advisory"
            with patch("master_agent.platform_runtime.factory.sys.platform", "win32"):
                with self.assertRaisesRegex(
                    PlatformCapabilityUnavailable,
                    "^native windows secure_filesystem backend is not implemented$",
                ):
                    CapsuleStore(capsule_root)
                with self.assertRaisesRegex(
                    PlatformCapabilityUnavailable,
                    "^native windows secure_filesystem backend is not implemented$",
                ):
                    AdvisoryBudgetStore(advisory_root, ROOT)

            self.assertFalse(capsule_root.exists())
            self.assertFalse(advisory_root.exists())

    def test_advisory_and_capsule_state_require_atomic_publication(self) -> None:
        from master_agent.advisory_budget import AdvisoryBudgetStore
        from master_agent.capsules import CapsuleStore

        reason = "simulated atomic publication backend is unavailable"

        def unavailable_atomic(contract: PlatformContract) -> None:
            self.assertIs(contract, PlatformContract.ATOMIC_PUBLICATION_RECOVERY)
            raise PlatformCapabilityUnavailable(reason)

        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            capsule_root = root / "capsules"
            advisory_root = root / "advisory"
            with (
                patch(
                    "master_agent.capsules.require_platform_contract",
                    side_effect=unavailable_atomic,
                ),
                self.assertRaisesRegex(
                    PlatformCapabilityUnavailable,
                    f"^{reason}$",
                ),
            ):
                CapsuleStore(capsule_root)
            with (
                patch(
                    "master_agent.advisory_budget.require_platform_contract",
                    side_effect=unavailable_atomic,
                ),
                self.assertRaisesRegex(
                    PlatformCapabilityUnavailable,
                    f"^{reason}$",
                ),
            ):
                AdvisoryBudgetStore(advisory_root, ROOT)

            self.assertFalse(capsule_root.exists())
            self.assertFalse(advisory_root.exists())

    def test_capsule_install_checks_locking_before_subdirectory_creation(self) -> None:
        from master_agent.capsules import CapsuleStore

        with TemporaryDirectory() as raw:
            root = Path(raw).resolve() / "capsules"
            store = CapsuleStore(root)
            with (
                patch(
                    "master_agent.capsules.get_cross_process_locking_backend",
                    side_effect=PlatformCapabilityUnavailable(
                        "simulated locking backend is unavailable"
                    ),
                ),
                self.assertRaisesRegex(
                    PlatformCapabilityUnavailable,
                    "^simulated locking backend is unavailable$",
                ),
            ):
                store.install(object(), object(), trust=object())  # type: ignore[arg-type]

            self.assertEqual(tuple(root.iterdir()), ())

    def test_compatibility_worker_fails_typed_before_posix_import(self) -> None:
        from master_agent import capsule_worker
        from master_agent.platform_runtime.factory import _HOST_PLATFORM

        module_name = "master_agent.platform_runtime.posix.capsule_worker"
        imported_before = module_name in sys.modules
        prior_module = sys.modules.get(module_name)
        cases = (
            (
                "win32",
                (
                    "native windows capsule_isolation backend is not implemented"
                    if _HOST_PLATFORM == "win32"
                    else "native windows process_supervision backend is not implemented"
                ),
            ),
            (
                "secret-unsupported-platform",
                "unsupported platform process_supervision backend is unavailable",
            ),
        )
        for platform, reason in cases:
            stdout = StringIO()
            stderr = StringIO()
            with (
                self.subTest(platform=platform),
                patch("master_agent.platform_runtime.factory.sys.platform", platform),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                status = capsule_worker.main()
            self.assertEqual(status, 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(
                stderr.getvalue(),
                f"error: PlatformCapabilityUnavailable: {reason}\n",
            )
            self.assertLessEqual(len(stderr.getvalue()), 160)
            self.assertNotIn("secret-unsupported-platform", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())
            self.assertNotIn(os.fspath(ROOT), stderr.getvalue())
            self.assertEqual(module_name in sys.modules, imported_before)
            if imported_before:
                self.assertIs(sys.modules[module_name], prior_module)

    def test_git_callers_preflight_before_paths_discovery_or_temp_state(self) -> None:
        from master_agent.connectors.git_remote import GitBranchPushConnector
        from master_agent.connectors.git_sandbox import GitSandbox
        from master_agent.connectors.git_workspace import GitWorkspaceConnector

        expected = "native windows secure_filesystem backend is not implemented"
        with TemporaryDirectory() as raw:
            missing = Path(raw).resolve() / "missing"
            with (
                patch("master_agent.platform_runtime.factory.sys.platform", "win32"),
                patch("master_agent.connectors.git_sandbox.shutil.which") as discovery,
                patch(
                    "master_agent.connectors.git_sandbox.tempfile.TemporaryDirectory"
                ) as temporary_state,
            ):
                for operation in (
                    lambda: GitSandbox(timeout_seconds=1),
                    lambda: GitWorkspaceConnector(workspace_root=missing),
                    lambda: GitBranchPushConnector(repository_root=missing),
                ):
                    with self.assertRaisesRegex(
                        PlatformCapabilityUnavailable,
                        f"^{expected}$",
                    ):
                        operation()

            discovery.assert_not_called()
            temporary_state.assert_not_called()
            self.assertFalse(missing.exists())

    def test_git_preflights_exact_contracts_before_discovery_or_paths(self) -> None:
        from master_agent.connectors.git_remote import GitBranchPushConnector
        from master_agent.connectors.git_sandbox import GitSandbox
        from master_agent.connectors.git_workspace import GitWorkspaceConnector

        requested: list[PlatformContract] = []

        def unavailable_process(contract: PlatformContract) -> None:
            requested.append(contract)
            if contract is PlatformContract.PROCESS_SUPERVISION:
                raise PlatformCapabilityUnavailable(
                    "simulated process supervision backend is unavailable"
                )

        with (
            patch(
                "master_agent.connectors.git_sandbox.require_platform_contract",
                side_effect=unavailable_process,
            ),
            patch("master_agent.connectors.git_sandbox.shutil.which") as discovery,
            patch(
                "master_agent.connectors.git_sandbox.tempfile.TemporaryDirectory"
            ) as temporary_state,
            patch("master_agent.connectors.git_sandbox.subprocess.run") as run,
            self.assertRaisesRegex(
                PlatformCapabilityUnavailable,
                "^simulated process supervision backend is unavailable$",
            ),
        ):
            GitSandbox(timeout_seconds=1)

        self.assertEqual(
            requested,
            [
                PlatformContract.SECURE_FILESYSTEM,
                PlatformContract.CROSS_PROCESS_LOCKING,
                PlatformContract.PROCESS_SUPERVISION,
            ],
        )
        discovery.assert_not_called()
        temporary_state.assert_not_called()
        run.assert_not_called()

        connector_cases = (
            (
                "master_agent.connectors.git_workspace",
                lambda root: GitWorkspaceConnector(workspace_root=root),
            ),
            (
                "master_agent.connectors.git_remote",
                lambda root: GitBranchPushConnector(repository_root=root),
            ),
        )
        for module, construct in connector_cases:
            for unavailable_contract in (
                PlatformContract.ATOMIC_PUBLICATION_RECOVERY,
                PlatformContract.PROCESS_SUPERVISION,
            ):
                root = Mock(spec=Path)
                message = f"simulated {unavailable_contract} backend is unavailable"

                def fail_selected(
                    contract: PlatformContract,
                    *,
                    selected: PlatformContract = unavailable_contract,
                    reason: str = message,
                ) -> None:
                    if contract is selected:
                        raise PlatformCapabilityUnavailable(reason)

                persistent_effect = (
                    PlatformCapabilityUnavailable(message)
                    if unavailable_contract
                    is PlatformContract.ATOMIC_PUBLICATION_RECOVERY
                    else None
                )
                with (
                    self.subTest(
                        connector=module,
                        contract=unavailable_contract,
                    ),
                    patch(
                        f"{module}.require_persistent_state_platform",
                        side_effect=persistent_effect,
                    ),
                    patch(
                        f"{module}.require_platform_contract",
                        side_effect=fail_selected,
                    ),
                    patch(f"{module}.GitSandbox") as sandbox,
                    self.assertRaisesRegex(
                        PlatformCapabilityUnavailable,
                        f"^{message}$",
                    ),
                ):
                    construct(root)  # type: ignore[arg-type]

                root.expanduser.assert_not_called()
                sandbox.assert_not_called()

    def test_advisory_runner_preflights_files_git_and_processes(self) -> None:
        from master_agent.advisory import AdvisoryRole
        from master_agent.copilot_advisory import (
            AdvisoryPathScope,
            _run_git,
            repository_state_binding,
        )
        from scripts import advisory_subagent

        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            state = root / "advisory-state"
            with (
                patch("master_agent.platform_runtime.factory.sys.platform", "win32"),
                patch("master_agent.copilot_advisory.subprocess.Popen") as popen,
            ):
                with self.assertRaisesRegex(
                    PlatformCapabilityUnavailable,
                    "^native windows secure_filesystem backend is not implemented$",
                ):
                    repository_state_binding(root)
                with self.assertRaisesRegex(
                    PlatformCapabilityUnavailable,
                    "^native windows secure_filesystem backend is not implemented$",
                ):
                    AdvisoryPathScope.bind(root, ("scope",))
                with self.assertRaisesRegex(
                    PlatformCapabilityUnavailable,
                    "^native windows trusted_git backend is not implemented$",
                ):
                    _run_git(root, "status", max_bytes=1024)
                stdout = StringIO()
                with redirect_stdout(stdout):
                    status = advisory_subagent.run(
                        root,
                        AdvisoryRole.RESEARCH,
                        "bounded review",
                        ("scope",),
                        route="platform-runtime",
                        goal_id="platform-runtime-test",
                        state_directory=state,
                    )

            self.assertEqual(status, 2)
            self.assertEqual(
                json.loads(stdout.getvalue()),
                {
                    "fallback_to_parent": True,
                    "reason": "advisory runner prerequisites failed closed",
                    "status": "fallback",
                },
            )
            popen.assert_not_called()
            self.assertFalse(state.exists())

            requested: list[PlatformContract] = []

            def unavailable_process(
                contract: PlatformContract,
                *,
                calls: list[PlatformContract] = requested,
            ) -> None:
                calls.append(contract)
                if contract is PlatformContract.PROCESS_SUPERVISION:
                    raise PlatformCapabilityUnavailable(
                        "simulated process backend is unavailable"
                    )

            with (
                patch(
                    "scripts.advisory_subagent.require_persistent_state_platform"
                ) as persistent_preflight,
                patch(
                    "scripts.advisory_subagent.require_platform_contract",
                    side_effect=unavailable_process,
                ),
                patch(
                    "scripts.advisory_subagent._validated_semantic_route"
                ) as validate_route,
                redirect_stdout(StringIO()),
            ):
                status = advisory_subagent.run(
                    root,
                    AdvisoryRole.RESEARCH,
                    "bounded review",
                    ("scope",),
                    route="platform-runtime",
                    goal_id="platform-runtime-test",
                    state_directory=state,
                )

            self.assertEqual(status, 2)
            persistent_preflight.assert_called_once_with()
            self.assertEqual(
                requested,
                [
                    PlatformContract.PROCESS_SUPERVISION,
                ],
            )
            validate_route.assert_not_called()
            self.assertFalse(state.exists())

            for unavailable_contract in (
                PlatformContract.CROSS_PROCESS_LOCKING,
                PlatformContract.ATOMIC_PUBLICATION_RECOVERY,
            ):
                unavailable_reason = (
                    f"simulated {unavailable_contract} backend is unavailable"
                )
                untouched_root = Mock(spec=Path)
                stdout = StringIO()
                with (
                    self.subTest(contract=unavailable_contract),
                    patch(
                        "scripts.advisory_subagent.require_persistent_state_platform",
                        side_effect=PlatformCapabilityUnavailable(unavailable_reason),
                    ) as persistent_preflight,
                    patch(
                        "scripts.advisory_subagent.require_platform_contract"
                    ) as other_preflight,
                    patch(
                        "scripts.advisory_subagent._validated_semantic_route"
                    ) as validate_route,
                    patch(
                        "scripts.advisory_subagent.repository_state_binding"
                    ) as bind_repository,
                    patch.object(
                        advisory_subagent.AdvisoryPathScope,
                        "bind",
                    ) as bind_scope,
                    redirect_stdout(stdout),
                ):
                    status = advisory_subagent.run(
                        untouched_root,  # type: ignore[arg-type]
                        AdvisoryRole.RESEARCH,
                        "bounded review",
                        ("scope",),
                        route="platform-runtime",
                        goal_id="platform-runtime-test",
                        state_directory=state,
                    )

                self.assertEqual(status, 2)
                self.assertEqual(
                    json.loads(stdout.getvalue()),
                    {
                        "fallback_to_parent": True,
                        "reason": "advisory runner prerequisites failed closed",
                        "status": "fallback",
                    },
                )
                persistent_preflight.assert_called_once_with()
                other_preflight.assert_not_called()
                untouched_root.resolve.assert_not_called()
                validate_route.assert_not_called()
                bind_repository.assert_not_called()
                bind_scope.assert_not_called()
                self.assertFalse(state.exists())

    def test_advisory_public_git_boundaries_preflight_before_path_resolution(
        self,
    ) -> None:
        from master_agent.copilot_advisory import (
            load_agent_inventory_at_revision,
            repository_state_binding,
        )

        for operation in (
            lambda root: load_agent_inventory_at_revision(root, "a" * 40),
            repository_state_binding,
        ):
            root = Mock(spec=Path)
            requested: list[PlatformContract] = []

            def unavailable_process(
                contract: PlatformContract,
                *,
                calls: list[PlatformContract] = requested,
            ) -> None:
                calls.append(contract)
                if contract is PlatformContract.PROCESS_SUPERVISION:
                    raise PlatformCapabilityUnavailable(
                        "simulated process supervision backend is unavailable"
                    )

            with (
                self.subTest(operation=operation),
                patch(
                    "master_agent.copilot_advisory.require_platform_contract",
                    side_effect=unavailable_process,
                ),
                patch("master_agent.copilot_advisory.subprocess.Popen") as popen,
                self.assertRaisesRegex(
                    PlatformCapabilityUnavailable,
                    "^simulated process supervision backend is unavailable$",
                ),
            ):
                operation(root)  # type: ignore[arg-type]

            self.assertEqual(
                requested,
                [
                    PlatformContract.SECURE_FILESYSTEM,
                    PlatformContract.TRUSTED_GIT,
                    PlatformContract.PROCESS_SUPERVISION,
                ],
            )
            root.resolve.assert_not_called()
            popen.assert_not_called()

    def test_cli_stateful_routes_preflight_before_inputs_or_effects(self) -> None:
        import master_agent.cli as cli_module

        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            output = root / "output.json"
            missing = root / "missing.json"
            commands = (
                ["bind-context", str(missing), "--output", str(output)],
                [
                    "approve",
                    str(missing),
                    "--actions",
                    "00000000-0000-0000-0000-000000000000",
                    "--key-id",
                    "operator",
                    "--expected-fingerprint",
                    "0" * 64,
                    "--approval-authorities",
                    str(missing),
                    "--output",
                    str(output),
                ],
                [
                    "approve-request",
                    str(missing),
                    "--key-id",
                    "operator",
                    "--expected-fingerprint",
                    "0" * 64,
                    "--output",
                    str(output),
                ],
                ["run", str(missing)],
                [
                    "execute",
                    "--resume",
                    str(missing),
                    "--approval",
                    str(missing),
                ],
                ["oauth-device-code", "--token-file", str(output)],
                ["demo"],
                ["readiness", "--output", str(output)],
                ["discover", "--output", str(output)],
                ["connect", "--systems", "github", "--output", str(output)],
                ["sample-plan", "--output", str(output)],
                ["plugins", "--output", str(output)],
            )
            with (
                patch("master_agent.platform_runtime.factory.sys.platform", "win32"),
                patch("master_agent.cli.resolve_config_source") as resolve_config,
                patch("master_agent.cli._load_plan") as load_plan,
                patch("master_agent.cli.load_approval_request") as load_request,
                patch("master_agent.cli._load_credential_store") as load_credentials,
                patch("master_agent.cli.discover_integrations") as discover,
                patch(
                    "master_agent.cli.tempfile.TemporaryDirectory"
                ) as temporary_directory,
                patch("master_agent.cli.tempfile.mkdtemp") as make_temporary,
            ):
                for command in commands:
                    stderr = StringIO()
                    with self.subTest(command=command[0]), redirect_stderr(stderr):
                        status = cli_module.main(command)
                    self.assertIn(status, {1, 2})
                    self.assertIn(
                        "native windows secure_filesystem backend is not implemented",
                        stderr.getvalue(),
                    )

            resolve_config.assert_not_called()
            load_plan.assert_not_called()
            load_request.assert_not_called()
            load_credentials.assert_not_called()
            discover.assert_not_called()
            temporary_directory.assert_not_called()
            make_temporary.assert_not_called()
            self.assertEqual(tuple(root.iterdir()), ())

    def test_resume_approval_requires_complete_state_before_request_access(
        self,
    ) -> None:
        import master_agent.cli as cli_module

        requested: list[PlatformContract] = []
        runtime = Mock()

        def unavailable_atomic(contract: PlatformContract) -> None:
            requested.append(contract)
            if contract is PlatformContract.ATOMIC_PUBLICATION_RECOVERY:
                raise PlatformCapabilityUnavailable(
                    "simulated atomic publication backend is unavailable"
                )

        runtime.require_contract.side_effect = unavailable_atomic
        request_path = Mock(spec=Path)
        approval_path = Mock(spec=Path)
        with (
            patch(
                "master_agent.platform_runtime.factory.get_platform_runtime",
                return_value=runtime,
            ),
            patch("master_agent.cli.load_approval_request") as load_request,
            patch("master_agent.cli._load_plan") as load_plan,
            self.assertRaisesRegex(
                PlatformCapabilityUnavailable,
                "^simulated atomic publication backend is unavailable$",
            ),
        ):
            cli_module._resume_approval(
                request_path=request_path,  # type: ignore[arg-type]
                expected_fingerprint="0" * 64,
                approval_paths=(approval_path,),  # type: ignore[arg-type]
            )

        self.assertEqual(
            requested,
            [
                PlatformContract.SECURE_FILESYSTEM,
                PlatformContract.CROSS_PROCESS_LOCKING,
                PlatformContract.ATOMIC_PUBLICATION_RECOVERY,
            ],
        )
        request_path.expanduser.assert_not_called()
        approval_path.expanduser.assert_not_called()
        load_request.assert_not_called()
        load_plan.assert_not_called()

    def test_direct_and_output_free_routes_skip_persistent_state_preflight(
        self,
    ) -> None:
        import master_agent.cli as cli_module

        with (
            patch("master_agent.cli.require_persistent_state_platform") as preflight,
            patch("master_agent.cli._run_direct_read", return_value=0) as direct_read,
        ):
            status = cli_module.main(["run", "missing.json", "--direct-read"])

        self.assertEqual(status, 0)
        preflight.assert_not_called()
        direct_read.assert_called_once()

        with (
            patch("master_agent.cli.require_persistent_state_platform") as preflight,
            patch("master_agent.cli._readiness", return_value=0),
            patch("master_agent.cli._discover", return_value=0),
            patch("master_agent.cli._connect", return_value=0),
        ):
            self.assertEqual(cli_module.main(["readiness"]), 0)
            self.assertEqual(cli_module.main(["discover"]), 0)
            self.assertEqual(cli_module.main(["connect", "--systems", "github"]), 0)

        preflight.assert_not_called()

    def test_ca_selected_connector_preflights_filesystem_before_path_touch(
        self,
    ) -> None:
        import master_agent.cli as cli_module
        from master_agent.auth import AuthMode
        from master_agent.config import ConnectorConfig, DeploymentType
        from master_agent.discovery import DiscoveryRecord, DiscoveryStatus

        connector = ConnectorConfig(
            system="github",
            enabled=True,
            deployment=DeploymentType.CLOUD,
            base_url="https://api.github.com",
            base_url_env=None,
            auth_mode=AuthMode.NONE,
            username_env=None,
            secret_env=None,
            ca_bundle_env="MASTER_AGENT_ENTERPRISE_CA_BUNDLE",
        )
        selected_environment = {
            "MASTER_AGENT_ENTERPRISE_CA_BUNDLE": "never-inspected.pem"
        }
        with (
            patch("master_agent.platform_runtime.factory.sys.platform", "win32"),
            patch("master_agent.config.Path") as path_constructor,
            self.assertRaisesRegex(
                PlatformCapabilityUnavailable,
                "^native windows secure_filesystem backend is not implemented$",
            ),
        ):
            connector.resolve_execution_target(selected_environment)

        path_constructor.assert_not_called()

        with patch("master_agent.config.require_platform_contract") as preflight:
            base_url, ca_bundle = connector.resolve_execution_target({})

        self.assertEqual(base_url, "https://api.github.com")
        self.assertIsNone(ca_bundle)
        preflight.assert_not_called()

        stderr = StringIO()
        with (
            patch("master_agent.platform_runtime.factory.sys.platform", "win32"),
            patch.dict(os.environ, selected_environment, clear=True),
            patch("master_agent.config.Path") as path_constructor,
            patch("master_agent.cli.discover_integrations") as discover,
            redirect_stderr(stderr),
        ):
            status = cli_module.main(["connect", "--systems", "github"])

        self.assertEqual(status, 1)
        self.assertEqual(
            stderr.getvalue(),
            "error: PlatformCapabilityUnavailable: "
            "native windows secure_filesystem backend is not implemented\n",
        )
        path_constructor.assert_not_called()
        discover.assert_not_called()

        with (
            patch("master_agent.platform_runtime.factory.sys.platform", "win32"),
            patch.dict(
                os.environ,
                {"MASTER_AGENT_GITHUB_TOKEN": "opaque-test-token"},
                clear=True,
            ),
            patch("master_agent.config.require_platform_contract") as preflight,
            patch("master_agent.cli.preflight_probe_provider_egress"),
            patch(
                "master_agent.cli.discover_integrations",
                return_value=(
                    DiscoveryRecord(
                        configuration="github",
                        system="github",
                        status=DiscoveryStatus.REACHABLE,
                        enabled=True,
                        deployment="cloud",
                        auth_mode="bearer",
                        base_url="https://api.github.com",
                        required_environment=("MASTER_AGENT_GITHUB_TOKEN",),
                        missing_environment=(),
                    ),
                ),
            ),
            redirect_stdout(StringIO()),
        ):
            status = cli_module._connect(
                integrations_path=None,
                governance_path=None,
                credentials_file=None,
                systems={"github"},
                output=None,
            )

        self.assertEqual(status, 0)
        preflight.assert_not_called()

    def test_draft_factories_preflight_complete_state_before_output_touch(
        self,
    ) -> None:
        from master_agent.connectors.factory import register_draft_connectors
        from master_agent.registry import ConnectorRegistry
        from master_agent.workflows.draft_package import render_draft_package

        requested: list[PlatformContract] = []
        runtime = Mock()

        def unavailable_atomic(contract: PlatformContract) -> None:
            requested.append(contract)
            if contract is PlatformContract.ATOMIC_PUBLICATION_RECOVERY:
                raise PlatformCapabilityUnavailable(
                    "simulated atomic publication backend is unavailable"
                )

        runtime.require_contract.side_effect = unavailable_atomic
        output_root = Mock(spec=Path)
        registry = ConnectorRegistry()
        report = Mock()
        with (
            patch(
                "master_agent.platform_runtime.factory.get_platform_runtime",
                return_value=runtime,
            ),
            patch("master_agent.connectors.factory.pin_directory") as pin_factory,
            patch("master_agent.workflows.draft_package.pin_directory") as pin_renderer,
        ):
            for operation in (
                lambda: register_draft_connectors(
                    registry,
                    output_root,  # type: ignore[arg-type]
                ),
                lambda: render_draft_package(
                    report,
                    output_dir=output_root,  # type: ignore[arg-type]
                ),
            ):
                with self.assertRaisesRegex(
                    PlatformCapabilityUnavailable,
                    "^simulated atomic publication backend is unavailable$",
                ):
                    operation()

        self.assertEqual(
            requested,
            [
                PlatformContract.SECURE_FILESYSTEM,
                PlatformContract.CROSS_PROCESS_LOCKING,
                PlatformContract.ATOMIC_PUBLICATION_RECOVERY,
            ]
            * 2,
        )
        pin_factory.assert_not_called()
        pin_renderer.assert_not_called()
        self.assertEqual(registry.connectors(), ())
        self.assertEqual(output_root.mock_calls, [])
        self.assertEqual(report.mock_calls, [])

    def test_cli_output_helpers_preflight_atomic_state_before_any_input(self) -> None:
        import master_agent.cli as cli_module

        requested: list[PlatformContract] = []
        runtime = Mock()

        def unavailable_atomic(contract: PlatformContract) -> None:
            requested.append(contract)
            if contract is PlatformContract.ATOMIC_PUBLICATION_RECOVERY:
                raise PlatformCapabilityUnavailable(
                    "simulated atomic publication backend is unavailable"
                )

        runtime.require_contract.side_effect = unavailable_atomic
        workflow_path = Mock(spec=Path)
        draft_output = Mock(spec=Path)
        audit_database = Mock(spec=Path)
        profile_path = Mock(spec=Path)
        doctor_output = Mock(spec=Path)
        plan_path = Mock(spec=Path)
        report_path = Mock(spec=Path)
        compensation_output = Mock(spec=Path)
        evidence_input = Mock(spec=Path)
        evidence_output = Mock(spec=Path)
        retention_path = Mock(spec=Path)
        citations_input = Mock(spec=Path)
        citations_output = Mock(spec=Path)
        with (
            patch(
                "master_agent.platform_runtime.factory.get_platform_runtime",
                return_value=runtime,
            ),
            patch("master_agent.cli.PinnedDirectory.open") as pin_directory,
            patch("master_agent.cli.platform_runtime_status") as runtime_status,
            patch("master_agent.cli.os.path.lexists") as path_exists,
        ):
            for operation in (
                lambda: cli_module._draft_package(
                    workflow_path=workflow_path,  # type: ignore[arg-type]
                    output_dir=draft_output,  # type: ignore[arg-type]
                    database=audit_database,  # type: ignore[arg-type]
                ),
                lambda: cli_module._doctor(
                    profile_path=profile_path,  # type: ignore[arg-type]
                    require_level="install",
                    output=doctor_output,  # type: ignore[arg-type]
                ),
                lambda: cli_module._compensation_plan(
                    plan_path=plan_path,  # type: ignore[arg-type]
                    report_path=report_path,  # type: ignore[arg-type]
                    created_by="test",
                    output=compensation_output,  # type: ignore[arg-type]
                ),
                lambda: cli_module._retain_evidence(
                    input_path=evidence_input,  # type: ignore[arg-type]
                    output_path=evidence_output,  # type: ignore[arg-type]
                    evidence_type="run-result/full",
                    retention_path=retention_path,  # type: ignore[arg-type]
                    include_content=False,
                ),
                lambda: cli_module._citations(
                    citations_input,  # type: ignore[arg-type]
                    output=citations_output,  # type: ignore[arg-type]
                ),
            ):
                with self.assertRaisesRegex(
                    PlatformCapabilityUnavailable,
                    "^simulated atomic publication backend is unavailable$",
                ):
                    operation()

        self.assertEqual(
            requested,
            [
                PlatformContract.SECURE_FILESYSTEM,
                PlatformContract.CROSS_PROCESS_LOCKING,
                PlatformContract.ATOMIC_PUBLICATION_RECOVERY,
            ]
            * 5,
        )
        pin_directory.assert_not_called()
        runtime_status.assert_not_called()
        path_exists.assert_not_called()
        for path in (
            workflow_path,
            draft_output,
            audit_database,
            profile_path,
            doctor_output,
            plan_path,
            report_path,
            compensation_output,
            evidence_input,
            evidence_output,
            retention_path,
            citations_input,
            citations_output,
        ):
            self.assertEqual(path.mock_calls, [])

        diagnostic_input = Mock(spec=Path)
        diagnostic_input.read_text.return_value = "{}"
        with (
            patch("master_agent.cli.require_persistent_state_platform") as preflight,
            redirect_stdout(StringIO()),
        ):
            status = cli_module._citations(
                diagnostic_input,  # type: ignore[arg-type]
                output=None,
            )

        self.assertEqual(status, 0)
        preflight.assert_not_called()
        diagnostic_input.read_text.assert_called_once_with(encoding="utf-8")

    def test_retained_writers_require_atomic_state_before_transforming_input(
        self,
    ) -> None:
        from master_agent.retention import write_retained_json, write_retained_text

        reason = "simulated atomic publication backend is unavailable"

        def unavailable_atomic(contract: PlatformContract) -> None:
            self.assertIs(contract, PlatformContract.ATOMIC_PUBLICATION_RECOVERY)
            raise PlatformCapabilityUnavailable(reason)

        path = Mock(spec=Path)
        payload = Mock()
        config = Mock()
        with (
            patch("master_agent.retention.get_secure_filesystem_backend") as filesystem,
            patch(
                "master_agent.retention.get_cross_process_locking_backend"
            ) as locking,
            patch(
                "master_agent.retention.require_platform_contract",
                side_effect=unavailable_atomic,
            ) as atomic,
            patch("master_agent.retention._permitted_rule") as permitted_rule,
            patch("master_agent.retention._metadata_only") as metadata_only,
            patch("master_agent.retention._serialize_retained_json") as serialize_json,
            patch("master_agent.retention.content_digest") as digest,
            patch("master_agent.retention._atomic_write_files") as write_files,
        ):
            for operation in (
                lambda: write_retained_json(
                    path,  # type: ignore[arg-type]
                    payload,  # type: ignore[arg-type]
                    evidence_type="run-result/full",
                    config=config,  # type: ignore[arg-type]
                    include_content=False,
                ),
                lambda: write_retained_text(
                    path,  # type: ignore[arg-type]
                    "never-digested",
                    evidence_type="run-result/full",
                    config=config,  # type: ignore[arg-type]
                ),
            ):
                with self.assertRaisesRegex(
                    PlatformCapabilityUnavailable,
                    f"^{reason}$",
                ):
                    operation()

        self.assertEqual(filesystem.call_count, 2)
        self.assertEqual(locking.call_count, 2)
        self.assertEqual(
            tuple(item.args for item in atomic.call_args_list),
            ((PlatformContract.ATOMIC_PUBLICATION_RECOVERY,),) * 2,
        )
        permitted_rule.assert_not_called()
        metadata_only.assert_not_called()
        serialize_json.assert_not_called()
        digest.assert_not_called()
        write_files.assert_not_called()
        self.assertEqual(path.mock_calls, [])
        self.assertEqual(payload.mock_calls, [])
        self.assertEqual(config.mock_calls, [])

    def test_execute_requires_filesystem_first_but_keeps_stateless_read_route(
        self,
    ) -> None:
        import master_agent.cli as cli_module

        with (
            patch(
                "master_agent.cli.require_platform_contract",
                side_effect=PlatformCapabilityUnavailable(
                    "native windows secure_filesystem backend is not implemented"
                ),
            ) as filesystem_preflight,
            patch("master_agent.cli.os.path.lexists") as lexists,
            patch(
                "master_agent.cli._capture_active_organization_profile"
            ) as capture_profile,
            patch("master_agent.cli._load_operating_plan") as load_plan,
            self.assertRaisesRegex(
                PlatformCapabilityUnavailable,
                "^native windows secure_filesystem backend is not implemented$",
            ),
        ):
            cli_module._execute(
                plan_path=Path("never-read-plan.json"),
                profile_path=Path("never-read-profile.toml"),
                request_path=None,
                approval_paths=(),
            )

        filesystem_preflight.assert_called_once_with(PlatformContract.SECURE_FILESYSTEM)
        lexists.assert_not_called()
        capture_profile.assert_not_called()
        load_plan.assert_not_called()

        profile = Mock()
        profile.source_path = Path("organization-profile.toml")
        profile.fingerprint = "1" * 64
        profile.configuration_path = Mock(return_value=None)
        plan = Mock()
        plan.fingerprint = "2" * 64
        governance = Mock()
        governance.allows_direct_read_session.return_value = (True, None)
        captured_sources = {
            "capabilities": object(),
            "integrations": object(),
            "policy": object(),
            "governance": object(),
            "sources_of_truth": object(),
        }
        with (
            patch("master_agent.cli.require_platform_contract") as filesystem,
            patch(
                "master_agent.cli.require_persistent_state_platform",
                side_effect=PlatformCapabilityUnavailable(
                    "simulated atomic publication backend is unavailable"
                ),
            ) as persistent,
            patch(
                "master_agent.cli._capture_active_organization_profile",
                return_value=(profile, object()),
            ),
            patch("master_agent.cli._load_operating_plan", return_value=plan),
            patch(
                "master_agent.cli._eligible_direct_operating_read",
                return_value=True,
            ),
            patch(
                "master_agent.cli._capture_operating_execution_sources",
                return_value=captured_sources,
            ),
            patch("master_agent.cli.CapabilityCatalog.from_toml", return_value=Mock()),
            patch("master_agent.cli.IntegrationConfig.from_toml", return_value=Mock()),
            patch("master_agent.cli.PolicyConfig.from_toml", return_value=Mock()),
            patch(
                "master_agent.cli.GovernanceProfile.from_toml",
                return_value=governance,
            ),
            patch(
                "master_agent.cli.SourceOfTruthRegistry.from_toml",
                return_value=Mock(),
            ),
            patch(
                "master_agent.cli._plan_requires_authenticated_approval",
                return_value=False,
            ),
            patch("master_agent.cli._operating_runtime_capabilities", return_value=()),
            patch(
                "master_agent.cli._operating_policy_blocked_capabilities",
                return_value=(),
            ),
            patch("master_agent.cli.require_operating_plan"),
            patch("master_agent.cli._require_operating_policy_preflight"),
            patch("master_agent.cli._run", return_value=0) as run,
        ):
            status = cli_module._execute(
                plan_path=Path("captured-plan.json"),
                profile_path=Path("captured-profile.toml"),
                request_path=None,
                approval_paths=(),
            )

        self.assertEqual(status, 0)
        filesystem.assert_called_once_with(PlatformContract.SECURE_FILESYSTEM)
        persistent.assert_not_called()
        run.assert_called_once()

    def test_filesystem_trust_reads_fail_before_opening_protected_bytes(self) -> None:
        from master_agent.credentials import CredentialStoreSnapshot
        from master_agent.oauth import (
            RestrictedTokenFileProvider,
            write_token_file,
        )
        from master_agent.trust_store import capture_ca_bundle

        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            protected = root / "protected.pem"
            protected.write_bytes(b"protected trust bytes")
            token_output = root / "tokens" / "token.json"
            with (
                patch("master_agent.platform_runtime.factory.sys.platform", "win32"),
                patch(
                    "master_agent.credentials.canonical_credential_store_path"
                ) as canonical_credentials,
            ):
                with self.assertRaisesRegex(
                    PlatformCapabilityUnavailable,
                    "^native windows secure_filesystem backend is not implemented$",
                ):
                    RestrictedTokenFileProvider(protected)
                provider = RestrictedTokenFileProvider.__new__(
                    RestrictedTokenFileProvider
                )
                provider._path = protected
                with self.assertRaisesRegex(
                    PlatformCapabilityUnavailable,
                    "^native windows secure_filesystem backend is not implemented$",
                ):
                    provider.get_token()
                with self.assertRaisesRegex(
                    PlatformCapabilityUnavailable,
                    "^native windows secure_filesystem backend is not implemented$",
                ):
                    write_token_file(token_output, object())  # type: ignore[arg-type]
                with self.assertRaisesRegex(
                    PlatformCapabilityUnavailable,
                    "^native windows secure_filesystem backend is not implemented$",
                ):
                    capture_ca_bundle(protected)
                with self.assertRaisesRegex(
                    PlatformCapabilityUnavailable,
                    "^native windows secure_filesystem backend is not implemented$",
                ):
                    CredentialStoreSnapshot.load(protected, allowed_names=())

            canonical_credentials.assert_not_called()
            self.assertEqual(protected.read_bytes(), b"protected trust bytes")
            self.assertFalse(token_output.parent.exists())

    def test_oauth_readiness_reports_unavailable_filesystem_without_token_touch(
        self,
    ) -> None:
        from master_agent.capabilities import CapabilityCatalog
        from master_agent.config import IntegrationConfig
        from master_agent.governance import GovernanceProfile
        from master_agent.oauth_config import OAuthFlow, OAuthProfile, OAuthProfiles
        from master_agent.readiness import assess_readiness

        token_file = Mock(spec=Path)
        profile = OAuthProfile(
            name="restricted",
            provider="microsoft_graph",
            flow=OAuthFlow.RESTRICTED_FILE,
            scopes=("User.Read",),
            token_file=token_file,  # type: ignore[arg-type]
            enabled=True,
        )
        windows = platform_runtime_status("win32")

        errors = profile.readiness_errors({}, platform_status=windows)

        self.assertEqual(
            errors,
            (
                (
                    "token file cannot be inspected: native windows "
                    "secure_filesystem backend is not implemented"
                ),
            ),
        )
        token_file.expanduser.assert_not_called()

        with patch(
            "master_agent.readiness.platform_runtime_status",
            return_value=windows,
        ):
            report = assess_readiness(
                catalog=CapabilityCatalog.from_toml(
                    ROOT / "config" / "capabilities.toml"
                ),
                governance=GovernanceProfile.from_toml(
                    ROOT / "config" / "governance.toml"
                ),
                integrations=IntegrationConfig.from_toml(
                    ROOT / "config" / "integrations.toml"
                ),
                oauth_profiles=OAuthProfiles({"restricted": profile}),
                environ={},
            )

        oauth_check = next(
            item for item in report.checks if item["name"] == "oauth:restricted"
        )
        self.assertFalse(report.ready)
        self.assertFalse(oauth_check["passed"])
        self.assertIn("secure_filesystem", str(oauth_check["errors"]))
        token_file.expanduser.assert_not_called()

        with (
            patch("master_agent.platform_runtime.factory.sys.platform", "win32"),
            self.assertRaisesRegex(
                PlatformCapabilityUnavailable,
                "^native windows secure_filesystem backend is not implemented$",
            ),
        ):
            profile.build_provider(environ={})

        token_file.expanduser.assert_not_called()

        with TemporaryDirectory() as raw:
            missing = Path(raw) / "missing-token.json"
            posix_profile = OAuthProfile(
                name="restricted",
                provider="microsoft_graph",
                flow=OAuthFlow.RESTRICTED_FILE,
                scopes=("User.Read",),
                token_file=missing,
                enabled=True,
            )
            self.assertEqual(
                posix_profile.readiness_errors({}),
                (f"token file does not exist: {missing}",),
            )

    def test_explicit_config_requires_secure_filesystem_but_packaged_does_not(
        self,
    ) -> None:
        from master_agent.config_sources import resolve_config_source

        explicit = Mock(spec=Path)
        with (
            patch("master_agent.platform_runtime.factory.sys.platform", "win32"),
            patch("master_agent.config_sources.os.open") as open_file,
            self.assertRaisesRegex(
                PlatformCapabilityUnavailable,
                "^native windows secure_filesystem backend is not implemented$",
            ),
        ):
            resolve_config_source(explicit, "integrations.toml")  # type: ignore[arg-type]

        explicit.expanduser.assert_not_called()
        open_file.assert_not_called()

        with patch(
            "master_agent.config_sources.require_platform_contract",
            side_effect=AssertionError("packaged configuration selected a backend"),
        ) as preflight:
            packaged = resolve_config_source(None, "integrations.toml")

        self.assertTrue(packaged.payload)
        preflight.assert_not_called()

    def test_exported_path_boundaries_preflight_before_resolution_or_open(
        self,
    ) -> None:
        from master_agent.approval_handoff import (
            ApprovalRunInvocation,
            load_approval_request,
        )
        from master_agent.capsules import CapsuleBundle
        from master_agent.config import IntegrationConfig
        from master_agent.credentials import canonical_credential_store_path
        from master_agent.execution_context import (
            build_runtime_execution_binding,
            capture_runtime_execution_paths,
        )
        from master_agent.sqlite_safety import path_entry_exists

        invocation = ApprovalRunInvocation(
            plan_path="/plan.json",
            approval_paths=(),
            approval_authorities="/approval-authorities.toml",
            database="/audit.sqlite3",
            connector_mode="live",
            integrations=None,
            result_json=None,
            retention=None,
            evidence_type="run-result/full",
            identities=None,
            include_writes=False,
            include_communications=False,
            workspace_root=None,
            draft_output_dir="/drafts",
            capabilities=None,
            governance=None,
            policy=None,
            sources_of_truth=None,
            plugin_names=(),
            plugin_lock=None,
            credentials_file=None,
            credential_mappings=(),
            connector_urls=(),
        )
        request_path = Mock(spec=Path)
        credential_path = Mock(spec=Path)
        captured_approval_path = Mock(spec=Path)
        additional_approval_path = Mock(spec=Path)
        sqlite_path = Mock(spec=Path)
        capsule_path = Mock(spec=Path)
        audit_database = Mock(spec=Path)
        artifact_root = Mock(spec=Path)
        config_source = Mock()
        integrations = IntegrationConfig({})
        operations = (
            (request_path, lambda: load_approval_request(request_path)),
            (
                credential_path,
                lambda: canonical_credential_store_path(credential_path),
            ),
            (
                captured_approval_path,
                lambda: ApprovalRunInvocation.capture(
                    plan_path=captured_approval_path,
                    approval_paths=(),
                    approval_authorities=Path("/approval-authorities.toml"),
                    database=Path("/audit.sqlite3"),
                    connector_mode="live",
                    integrations=None,
                    result_json=None,
                    retention=None,
                    evidence_type="run-result/full",
                    identities=None,
                    include_writes=False,
                    include_communications=False,
                    workspace_root=None,
                    draft_output_dir=Path("/drafts"),
                    capabilities=None,
                    governance=None,
                    policy=None,
                    sources_of_truth=None,
                    plugin_names=(),
                    plugin_lock=None,
                    credentials_file=None,
                    credential_mappings=(),
                    connector_urls=(),
                ),
            ),
            (
                additional_approval_path,
                lambda: invocation.with_approvals((additional_approval_path,)),
            ),
            (sqlite_path, lambda: path_entry_exists(sqlite_path)),
            (capsule_path, lambda: CapsuleBundle.from_directory(capsule_path)),
            (
                audit_database,
                lambda: build_runtime_execution_binding(
                    integrations,
                    connector_mode="live",
                    include_writes=False,
                    include_communications=False,
                    audit_database=audit_database,
                    artifact_root=artifact_root,
                    workspace_root=None,
                    result_json=None,
                    evidence_type="run-result/full",
                    configuration_sources={"policy": config_source},
                    environ={},
                ),
            ),
            (
                artifact_root,
                lambda: capture_runtime_execution_paths(
                    integrations,
                    connector_mode="live",
                    include_writes=False,
                    audit_database=audit_database,
                    artifact_root=artifact_root,
                    workspace_root=None,
                    result_json=None,
                    environ={},
                ),
            ),
        )
        with (
            patch("master_agent.platform_runtime.factory.sys.platform", "win32"),
            patch("master_agent.approval_handoff.PinnedDirectory.open") as pin,
            patch("master_agent.approval_handoff.os.open") as open_file,
            patch("master_agent.capsules.os.open") as open_capsule,
            patch("master_agent.execution_context.PinnedDirectory.open") as pin_runtime,
        ):
            for path, operation in operations:
                with (
                    self.subTest(operation=operation),
                    self.assertRaisesRegex(
                        PlatformCapabilityUnavailable,
                        "^native windows secure_filesystem backend is not implemented$",
                    ),
                ):
                    operation()
                path.expanduser.assert_not_called()

        pin.assert_not_called()
        open_file.assert_not_called()
        open_capsule.assert_not_called()
        pin_runtime.assert_not_called()
        config_source.open.assert_not_called()
        sqlite_path.lstat.assert_not_called()

    def test_persistent_library_boundaries_fail_before_state_access(self) -> None:
        from master_agent.approval_handoff import (
            publish_approval_request,
            write_restricted_json,
        )
        from master_agent.connectors.drafts import (
            JiraDraftConnector,
            write_artifact_bundle,
        )
        from master_agent.recurring import RecurringStateStore
        from master_agent.sqlite_safety import readonly_snapshot_connection
        from master_agent.workflows.communication_context import (
            render_communication_context_package,
        )
        from master_agent.workflows.weekly_status import render_weekly_status_package

        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            state = root / "state.sqlite3"
            weekly = root / "weekly"
            communication = root / "communication"
            draft = root / "draft"

            def open_readonly() -> None:
                with readonly_snapshot_connection(state):
                    pass

            operations = (
                lambda: RecurringStateStore(state),
                open_readonly,
                lambda: write_restricted_json(root / "approval.json", {}),
                lambda: publish_approval_request(
                    root,
                    object(),  # type: ignore[arg-type]
                ),
                lambda: render_weekly_status_package(
                    object(),  # type: ignore[arg-type]
                    object(),  # type: ignore[arg-type]
                    output_dir=weekly,
                ),
                lambda: render_communication_context_package(
                    object(),  # type: ignore[arg-type]
                    object(),  # type: ignore[arg-type]
                    output_dir=communication,
                    retention=object(),  # type: ignore[arg-type]
                ),
                lambda: JiraDraftConnector(draft),
                lambda: write_artifact_bundle(draft, ()),
            )
            with (
                patch("master_agent.platform_runtime.factory.sys.platform", "win32"),
                patch("master_agent.recurring.path_entry_exists") as path_exists,
                patch("master_agent.sqlite_safety._open_trusted_parent") as open_parent,
            ):
                for operation in operations:
                    with self.assertRaisesRegex(
                        PlatformCapabilityUnavailable,
                        "^native windows secure_filesystem backend is not implemented$",
                    ):
                        operation()

            path_exists.assert_not_called()
            open_parent.assert_not_called()
            self.assertFalse(state.exists())
            self.assertFalse(weekly.exists())
            self.assertFalse(communication.exists())
            self.assertFalse(draft.exists())
            self.assertEqual(tuple(root.iterdir()), ())

    def test_plugin_loader_preflights_only_nonempty_execution_requests(self) -> None:
        from master_agent.plugins import load_connector_plugins
        from master_agent.registry import ConnectorRegistry

        registry = ConnectorRegistry()
        with (
            patch("master_agent.platform_runtime.factory.sys.platform", "win32"),
            patch("master_agent.plugins._installed_entries") as installed_entries,
            patch.object(registry, "register") as register,
        ):
            self.assertEqual(
                load_connector_plugins(registry, enabled_names=()),
                (),
            )
            with self.assertRaisesRegex(
                PlatformCapabilityUnavailable,
                "^native windows secure_filesystem backend is not implemented$",
            ):
                load_connector_plugins(registry, enabled_names=("example",))

        installed_entries.assert_not_called()
        register.assert_not_called()

    def test_operating_state_boundaries_preflight_before_mutation(self) -> None:
        from master_agent.config_sources import ConfigSnapshot
        from master_agent.operating import (
            OrganizationProfile,
            allocate_operating_run,
            install_organization_profile,
            provision_organization_state,
        )

        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            snapshot = ConfigSnapshot(
                display_path=root / "source.toml",
                payload=_organization_profile_payload(root / "state"),
            )
            profile = OrganizationProfile.from_toml(snapshot)
            destination = root / "profiles" / "organization-profile.toml"
            with patch("master_agent.platform_runtime.factory.sys.platform", "win32"):
                for operation in (
                    lambda: install_organization_profile(
                        snapshot,
                        destination=destination,
                    ),
                    lambda: provision_organization_state(profile),
                    lambda: allocate_operating_run(profile, run_id="0" * 32),
                ):
                    with self.assertRaisesRegex(
                        PlatformCapabilityUnavailable,
                        "^native windows secure_filesystem backend is not implemented$",
                    ):
                        operation()

            self.assertEqual(tuple(root.iterdir()), ())

    def test_setup_stays_blocked_when_only_atomic_publication_is_missing(self) -> None:
        from master_agent.config_sources import ConfigSnapshot
        from master_agent.operating import install_organization_profile

        requested: list[PlatformContract] = []
        runtime = Mock()

        def unavailable_atomic(contract: PlatformContract) -> None:
            requested.append(contract)
            if contract is PlatformContract.ATOMIC_PUBLICATION_RECOVERY:
                raise PlatformCapabilityUnavailable(
                    "native windows atomic_publication_recovery backend is not implemented"
                )

        runtime.require_contract.side_effect = unavailable_atomic
        with (
            patch(
                "master_agent.platform_runtime.factory.get_platform_runtime",
                return_value=runtime,
            ),
            self.assertRaisesRegex(
                PlatformCapabilityUnavailable,
                "^native windows atomic_publication_recovery backend is not implemented$",
            ),
        ):
            require_persistent_state_platform()

        self.assertEqual(
            requested,
            [
                PlatformContract.SECURE_FILESYSTEM,
                PlatformContract.CROSS_PROCESS_LOCKING,
                PlatformContract.ATOMIC_PUBLICATION_RECOVERY,
            ],
        )

        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            snapshot = ConfigSnapshot(
                display_path=root / "source.toml",
                payload=_organization_profile_payload(root / "state"),
            )
            with (
                patch(
                    "master_agent.operating.require_persistent_state_platform",
                    side_effect=PlatformCapabilityUnavailable(
                        "native windows atomic_publication_recovery backend "
                        "is not implemented"
                    ),
                ),
                self.assertRaisesRegex(
                    PlatformCapabilityUnavailable,
                    "^native windows atomic_publication_recovery backend is not implemented$",
                ),
            ):
                install_organization_profile(
                    snapshot,
                    destination=root / "profiles" / "organization-profile.toml",
                )

            self.assertEqual(tuple(root.iterdir()), ())

    def test_windows_cli_setup_reports_runtime_defect_without_mutation(self) -> None:
        import master_agent.cli as cli_module

        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            profile = root / "organization-profile.toml"
            stdout = StringIO()
            stderr = StringIO()
            with (
                patch("master_agent.platform_runtime.factory.sys.platform", "win32"),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                status = cli_module.main(
                    ["setup", "--profile", str(profile), "--non-interactive"]
                )

            self.assertEqual(status, 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(
                stderr.getvalue(),
                "error: runtime_defect: "
                "native windows secure_filesystem backend is not implemented\n",
            )
            self.assertEqual(tuple(root.iterdir()), ())

    def test_relocated_worker_preserves_promoted_source_identity(self) -> None:
        worker = ROOT / "src" / "master_agent" / "platform_runtime" / "posix"
        payload = (worker / "capsule_worker.py").read_bytes()

        self.assertEqual(
            hashlib.sha256(payload).hexdigest(),
            PRE_PLATFORM_RUNTIME_WORKER_SHA256,
        )

    def test_status_contains_all_six_contracts_in_canonical_order(self) -> None:
        status = platform_runtime_status("linux")

        self.assertEqual(status.platform, "linux")
        self.assertEqual(status.backend, "posix-linux")
        self.assertEqual(
            tuple(item.contract for item in status.capabilities),
            tuple(PlatformContract),
        )
        self.assertEqual(
            tuple(status.to_dict()),
            ("platform", "backend", "capabilities"),
        )
        capabilities = status.to_dict()["capabilities"]
        self.assertIsInstance(capabilities, dict)
        assert isinstance(capabilities, dict)
        self.assertEqual(
            tuple(capabilities), tuple(str(contract) for contract in PlatformContract)
        )

    def test_posix_runtime_exposes_truthful_linux_and_macos_identities(self) -> None:
        from master_agent.platform_runtime.factory import _runtime_for_identity
        from master_agent.platform_runtime.posix.capsules import (
            LinuxBubblewrapCapsuleIsolationBackend,
        )

        selected_bubblewrap = LinuxBubblewrapCapsuleIsolationBackend(
            executable=Path("/trusted/bwrap")
        )
        _runtime_for_identity.cache_clear()
        self.addCleanup(_runtime_for_identity.cache_clear)
        with patch(
            "master_agent.platform_runtime.posix.runtime."
            "select_linux_bubblewrap_backend",
            return_value=selected_bubblewrap,
        ):
            runtime = get_platform_runtime("linux")

        self.assertEqual(runtime.status.platform, "linux")
        self.assertEqual(runtime.status.backend, "posix-linux")
        self.assertFalse(runtime.supports(*tuple(PlatformContract)))
        self.assertTrue(
            runtime.supports(
                *(
                    contract
                    for contract in PlatformContract
                    if contract is not PlatformContract.CREDENTIAL_STORAGE
                )
            )
        )
        self.assertEqual(
            {str(item.contract): item.backend for item in runtime.status.capabilities},
            {
                "secure_filesystem": "posix-descriptor-filesystem",
                "cross_process_locking": "posix-flock",
                "atomic_publication_recovery": "posix-atomic-publication",
                "credential_storage": "posix-linux",
                "process_supervision": "posix-rlimit",
                "trusted_git": "posix-trusted-git",
                "capsule_isolation": "linux-bubblewrap",
            },
        )
        locking = runtime.require_cross_process_locking()
        with self.assertRaisesRegex(ValueError, "lock mode is invalid"):
            locking.acquire(-1, mode=cast(LockMode, "exclusive"))
        process = runtime.require_process_supervision()
        with self.assertRaisesRegex(ValueError, "positive integers"):
            process.apply_capsule_limits(
                cpu_seconds=0,
                memory_bytes=1,
                max_processes=1,
                max_output_bytes=1,
            )

        macos = get_platform_runtime("darwin")
        credential_status = macos.status.contract_status(
            PlatformContract.CREDENTIAL_STORAGE
        )
        capsule_status = macos.status.contract_status(
            PlatformContract.CAPSULE_ISOLATION
        )
        self.assertEqual(macos.status.platform, "macos")
        self.assertEqual(macos.status.backend, "posix-macos")
        self.assertTrue(
            macos.supports(
                PlatformContract.SECURE_FILESYSTEM,
                PlatformContract.CROSS_PROCESS_LOCKING,
                PlatformContract.ATOMIC_PUBLICATION_RECOVERY,
                PlatformContract.PROCESS_SUPERVISION,
                PlatformContract.TRUSTED_GIT,
            )
        )
        self.assertFalse(capsule_status.available)
        self.assertFalse(credential_status.available)
        self.assertEqual(
            credential_status.reason,
            "native macos credential_storage backend is not implemented",
        )
        self.assertEqual(capsule_status.backend, "posix-macos")
        self.assertEqual(
            capsule_status.reason,
            "native macos capsule_isolation backend is not implemented",
        )
        with self.assertRaisesRegex(
            PlatformCapabilityUnavailable,
            "^native macos capsule_isolation backend is not implemented$",
        ):
            macos.require_capsule_isolation()

    def test_linux_capsule_status_requires_a_trusted_bubblewrap_executable(
        self,
    ) -> None:
        from master_agent.platform_runtime import get_capsule_isolation_backend
        from master_agent.platform_runtime.factory import _runtime_for_identity

        reason = (
            "native linux capsule_isolation backend is unavailable: "
            "trusted bubblewrap executable is unavailable"
        )
        self.addCleanup(_runtime_for_identity.cache_clear)
        with patch(
            "master_agent.platform_runtime.posix.capsules.shutil.which",
            return_value=None,
        ):
            _runtime_for_identity.cache_clear()
            missing = get_platform_runtime("linux")

        missing_status = missing.status.contract_status(
            PlatformContract.CAPSULE_ISOLATION
        )
        self.assertFalse(missing_status.available)
        self.assertEqual(missing_status.backend, "posix-linux")
        self.assertEqual(missing_status.reason, reason)
        with self.assertRaisesRegex(PlatformCapabilityUnavailable, f"^{reason}$"):
            missing.require_capsule_isolation()

        with TemporaryDirectory() as raw:
            executable = Path(raw) / "bwrap"
            executable.write_bytes(b"trusted test executable")
            executable.chmod(0o700)
            with patch(
                "master_agent.platform_runtime.posix.capsules.shutil.which"
            ) as explicit_discovery:
                explicit = get_capsule_isolation_backend(
                    "linux",
                    executable=str(executable),
                )

            self.assertEqual(explicit.executable, executable.resolve())
            explicit_discovery.assert_not_called()
            with patch(
                "master_agent.platform_runtime.posix.capsules.shutil.which",
                return_value=str(executable),
            ):
                _runtime_for_identity.cache_clear()
                available = get_platform_runtime("linux")

            available_status = available.status.contract_status(
                PlatformContract.CAPSULE_ISOLATION
            )
            self.assertTrue(available_status.available)
            self.assertEqual(available_status.backend, "linux-bubblewrap")
            self.assertEqual(
                available.require_capsule_isolation().executable,
                executable.resolve(),
            )

            executable.chmod(0o702)
            with patch(
                "master_agent.platform_runtime.posix.capsules.shutil.which",
                return_value=str(executable),
            ):
                _runtime_for_identity.cache_clear()
                unsafe = get_platform_runtime("linux")

            unsafe_status = unsafe.status.contract_status(
                PlatformContract.CAPSULE_ISOLATION
            )
            self.assertFalse(unsafe_status.available)
            self.assertEqual(unsafe_status.reason, reason)

        for explicit_path in ("", "/missing/explicit/bwrap"):
            with (
                self.subTest(explicit_path=explicit_path),
                patch(
                    "master_agent.platform_runtime.posix.capsules.shutil.which"
                ) as invalid_discovery,
                self.assertRaisesRegex(
                    PlatformCapabilityUnavailable,
                    f"^{reason}$",
                ),
            ):
                get_capsule_isolation_backend(
                    "linux",
                    executable=explicit_path,
                )

            invalid_discovery.assert_not_called()

        with TemporaryDirectory() as raw:
            original_directory = Path.cwd()
            try:
                for name in ("first", "second"):
                    directory = Path(raw) / name
                    directory.mkdir()
                    relative_executable = directory / "bwrap"
                    relative_executable.write_bytes(b"trusted test executable")
                    relative_executable.chmod(0o700)
                    os.chdir(directory)
                    with (
                        self.subTest(directory=name),
                        patch(
                            "master_agent.platform_runtime.posix.capsules.shutil.which"
                        ) as relative_discovery,
                        self.assertRaisesRegex(
                            PlatformCapabilityUnavailable,
                            f"^{reason}$",
                        ),
                    ):
                        get_capsule_isolation_backend(
                            "linux",
                            executable="bwrap",
                        )

                    relative_discovery.assert_not_called()
            finally:
                os.chdir(original_directory)

        from master_agent.platform_runtime.posix.capsules import (
            select_linux_bubblewrap_backend,
        )

        filesystem = Mock()
        filesystem.effective_user_id.return_value = 501
        filesystem.group_is_private_to_owner.return_value = True
        metadata = Mock(
            st_mode=stat.S_IFREG | 0o720,
            st_uid=0,
            st_gid=0,
            st_nlink=1,
        )
        selected_path = Mock(spec=Path)
        selected_path.is_absolute.return_value = True
        selected_path.resolve.return_value = selected_path
        selected_path.lstat.return_value = metadata
        with (
            patch(
                "master_agent.platform_runtime.posix.capsules.Path",
                return_value=selected_path,
            ),
            patch(
                "master_agent.platform_runtime.posix.capsules.os.access",
                return_value=True,
            ),
        ):
            mismatched = select_linux_bubblewrap_backend(
                filesystem=filesystem,
                executable="/root-owned/group-writable/bwrap",
            )

        self.assertIsNone(mismatched)
        filesystem.group_is_private_to_owner.assert_not_called()

    def test_capsule_worker_selects_only_real_or_explicit_isolation(self) -> None:
        from master_agent.capsule_runtime import CapsuleWorker

        for arguments in (
            {},
            {"require_os_sandbox": False, "bubblewrap": "/trusted/bwrap"},
        ):
            with (
                self.subTest(platform="macos", arguments=arguments),
                patch("master_agent.platform_runtime.factory.sys.platform", "darwin"),
                patch(
                    "master_agent.platform_runtime.posix.capsules.shutil.which"
                ) as discovery,
                patch(
                    "master_agent.platform_runtime.posix.capsules.Path"
                ) as path_constructor,
                self.assertRaisesRegex(
                    PlatformCapabilityUnavailable,
                    "^native macos capsule_isolation backend is not implemented$",
                ),
            ):
                CapsuleWorker(**arguments)  # type: ignore[arg-type]

            discovery.assert_not_called()
            path_constructor.assert_not_called()

        with (
            patch("master_agent.platform_runtime.factory.sys.platform", "darwin"),
            patch(
                "master_agent.platform_runtime.posix.capsules.shutil.which"
            ) as discovery,
            patch("master_agent.capsule_runtime._validate_worker_artifact"),
        ):
            test_worker = CapsuleWorker(require_os_sandbox=False)

        self.assertEqual(test_worker.backend, "test-subprocess")
        self.assertFalse(test_worker.production_isolated)
        discovery.assert_not_called()

        with TemporaryDirectory() as raw:
            explicit_bubblewrap = Path(raw) / "bwrap"
            explicit_bubblewrap.write_bytes(b"trusted test executable")
            explicit_bubblewrap.chmod(0o700)
            with (
                patch("master_agent.platform_runtime.factory.sys.platform", "linux"),
                patch(
                    "master_agent.platform_runtime.posix.capsules.shutil.which"
                ) as discovery,
                patch("master_agent.capsule_runtime._validate_worker_artifact"),
            ):
                isolated_worker = CapsuleWorker(
                    require_os_sandbox=False,
                    bubblewrap=str(explicit_bubblewrap),
                )
                production_isolated = isolated_worker.production_isolated

        self.assertEqual(isolated_worker.backend, "linux-bubblewrap")
        self.assertTrue(production_isolated)
        discovery.assert_not_called()
        self.assertEqual(isolated_worker._bubblewrap, explicit_bubblewrap.resolve())

    def test_deployment_readiness_reports_macos_capsule_isolation_unavailable(
        self,
    ) -> None:
        from master_agent.capabilities import CapabilityCatalog
        from master_agent.config import IntegrationConfig
        from master_agent.governance import GovernanceProfile
        from master_agent.readiness import assess_readiness

        macos = platform_runtime_status("darwin")
        with patch(
            "master_agent.readiness.platform_runtime_status",
            return_value=macos,
        ):
            report = assess_readiness(
                catalog=CapabilityCatalog.from_toml(
                    ROOT / "config" / "capabilities.toml"
                ),
                governance=GovernanceProfile.from_toml(
                    ROOT / "config" / "governance.toml"
                ),
                integrations=IntegrationConfig.from_toml(
                    ROOT / "config" / "integrations.toml"
                ),
                environ={},
            )

        capsule_status = report.platform_runtime.contract_status(
            PlatformContract.CAPSULE_ISOLATION
        )
        self.assertFalse(capsule_status.available)
        self.assertEqual(
            capsule_status.reason,
            "native macos capsule_isolation backend is not implemented",
        )

    def test_deployment_readiness_reports_missing_linux_bubblewrap(self) -> None:
        from master_agent.capabilities import CapabilityCatalog
        from master_agent.config import IntegrationConfig
        from master_agent.governance import GovernanceProfile
        from master_agent.platform_runtime.factory import _runtime_for_identity
        from master_agent.readiness import assess_readiness

        self.addCleanup(_runtime_for_identity.cache_clear)
        with patch(
            "master_agent.platform_runtime.posix.capsules.shutil.which",
            return_value=None,
        ):
            _runtime_for_identity.cache_clear()
            linux = platform_runtime_status("linux")
        with patch(
            "master_agent.readiness.platform_runtime_status",
            return_value=linux,
        ):
            report = assess_readiness(
                catalog=CapabilityCatalog.from_toml(
                    ROOT / "config" / "capabilities.toml"
                ),
                governance=GovernanceProfile.from_toml(
                    ROOT / "config" / "governance.toml"
                ),
                integrations=IntegrationConfig.from_toml(
                    ROOT / "config" / "integrations.toml"
                ),
                environ={},
            )

        capsule_status = report.platform_runtime.contract_status(
            PlatformContract.CAPSULE_ISOLATION
        )
        self.assertFalse(capsule_status.available)
        self.assertEqual(
            capsule_status.reason,
            "native linux capsule_isolation backend is unavailable: "
            "trusted bubblewrap executable is unavailable",
        )

    def test_windows_contracts_are_inspectable_and_fail_closed(self) -> None:
        runtime = get_platform_runtime("win32")
        status = runtime.status

        self.assertEqual(status.platform, "windows")
        self.assertEqual(status.backend, "windows-unavailable")
        self.assertFalse(status.supports(*tuple(PlatformContract)))
        self.assertEqual(
            status.unavailable(tuple(PlatformContract)), status.capabilities
        )
        for contract in PlatformContract:
            with self.subTest(contract=contract):
                item = status.contract_status(contract)
                self.assertFalse(item.available)
                self.assertEqual(item.backend, "windows-unavailable")
                expected = f"native windows {contract} backend is not implemented"
                self.assertEqual(item.reason, expected)
                with self.assertRaisesRegex(
                    PlatformCapabilityUnavailable,
                    f"^{expected}$",
                ):
                    require_platform_contract(contract, "win32")

    def test_native_windows_host_selects_lazy_partial_runtime_builder(self) -> None:
        from master_agent.platform_runtime.factory import _runtime_for_identity

        expected = Mock()
        _runtime_for_identity.cache_clear()
        self.addCleanup(_runtime_for_identity.cache_clear)
        with (
            patch("master_agent.platform_runtime.factory.sys.platform", "win32"),
            patch("master_agent.platform_runtime.factory._HOST_PLATFORM", "win32"),
            patch(
                "master_agent.platform_runtime.windows.runtime.build_windows_runtime",
                return_value=expected,
            ) as build_windows,
        ):
            observed = get_platform_runtime()

        self.assertIs(observed, expected)
        build_windows.assert_called_once_with()

    def test_unknown_platform_never_falls_back_or_echoes_input(self) -> None:
        status = platform_runtime_status("secret-platform-value")

        self.assertEqual(status.platform, "unsupported")
        self.assertEqual(status.backend, "unsupported")
        self.assertNotIn("secret-platform-value", repr(status.to_dict()))
        self.assertTrue(all(not item.available for item in status.capabilities))
        self.assertEqual(
            platform_runtime_status("linux-attacker").platform, "unsupported"
        )
        self.assertEqual(platform_runtime_status("linux ").platform, "unsupported")

    def test_windows_cli_import_does_not_load_unix_only_modules(self) -> None:
        source_root = ROOT / "src"
        script = f"""
import sys

blocked = set({sorted(FORBIDDEN_NEUTRAL_IMPORTS)!r})
class DenyUnixModules:
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.', 1)[0] in blocked:
            raise ModuleNotFoundError('blocked Unix-only module: ' + fullname)
        return None

sys.meta_path.insert(0, DenyUnixModules())
sys.path.insert(0, {os.fspath(source_root)!r})
import master_agent
import master_agent.cli
from master_agent.platform_runtime import platform_runtime_status
for argument in ('--help', '--version'):
    try:
        master_agent.cli.main([argument])
    except SystemExit as error:
        assert error.code == 0
status = platform_runtime_status('win32')
assert status.platform == 'windows'
assert status.backend == 'windows-unavailable'
assert not blocked.intersection(sys.modules)
"""
        completed = subprocess.run(
            [sys.executable, "-I", "-S", "-c", script],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_platform_neutral_cli_import_does_not_load_windows_credentials(
        self,
    ) -> None:
        source_root = ROOT / "src"
        script = f"""
import sys
sys.path.insert(0, {os.fspath(source_root)!r})
import master_agent.cli
assert 'master_agent.platform_runtime.windows.credentials' not in sys.modules
"""
        completed = subprocess.run(
            [sys.executable, "-I", "-S", "-c", script],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_unix_only_imports_exist_only_in_posix_backend_modules(self) -> None:
        violations: list[str] = []
        source_root = ROOT / "src" / "master_agent"
        for path in sorted(source_root.rglob("*.py")):
            relative = path.relative_to(source_root)
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(relative))
            imported: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(alias.name.split(".", 1)[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module is not None:
                    imported.add(node.module.split(".", 1)[0])
            forbidden = sorted(imported & FORBIDDEN_NEUTRAL_IMPORTS)
            if forbidden and relative.parts[:2] != ("platform_runtime", "posix"):
                violations.append(f"{relative}: {','.join(forbidden)}")

        self.assertEqual(violations, [])


def _organization_profile_payload(state_root: Path) -> bytes:
    """Return one valid in-memory profile without creating local state."""

    return (
        'schema = "master-agent/organization-profile@1"\n'
        'organization = "Platform Runtime Test"\n'
        'mode = "employee"\n'
        f"state_root = {json.dumps(os.fspath(state_root))}\n"
        'connector_mode = "live"\n'
        "writes_enabled = false\n"
        "communications_enabled = false\n"
        "capabilities = []\n"
    ).encode()


if __name__ == "__main__":
    unittest.main()

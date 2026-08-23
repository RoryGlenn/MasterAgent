"""Progressive operating-mode profile, validation, and readiness tests."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import unittest
from collections.abc import Iterator, Mapping
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import master_agent.operating as operating_module
from master_agent.auth import AuthMode
from master_agent.capabilities import CapabilityCatalog, CapabilityDefinition
from master_agent.config import ConnectorConfig, DeploymentType, IntegrationConfig
from master_agent.config_sources import ConfigSnapshot
from master_agent.errors import ConfigurationError
from master_agent.models import (
    AgentAction,
    AuthoritySource,
    CapabilityCapsuleExecutionBinding,
    ChangePlan,
    ExecutionContext,
    PluginExecutionBinding,
    ResourceRef,
    RiskLevel,
)
from master_agent.operating import (
    ORGANIZATION_PROFILE_SCHEMA,
    ConnectorMode,
    OperatingFailureCategory,
    OperatingMode,
    OperatingValidationError,
    OrganizationProfile,
    allocate_operating_run,
    assess_operating_readiness,
    default_organization_profile_path,
    install_organization_profile,
    load_organization_profile,
    require_operating_plan,
    validate_operating_plan,
)
from master_agent.platform_runtime import PlatformContract, platform_runtime_status


class OrganizationProfileTests(unittest.TestCase):
    """Exercise the strict profile and private setup boundary."""

    def test_profile_is_strict_bounded_and_binds_relative_paths_to_source(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            source = root / "profiles" / "organization-profile.toml"
            payload = _profile_payload(
                state_root="../runtime",
                capabilities=("github.repository.read", "draft.package.generate"),
                configuration={
                    "capabilities": "../config/capabilities.toml",
                    "integrations": "../config/integrations.toml",
                },
            )

            profile = OrganizationProfile.from_toml(
                ConfigSnapshot(display_path=source, payload=payload)
            )

            self.assertEqual(profile.schema, ORGANIZATION_PROFILE_SCHEMA)
            self.assertEqual(profile.mode, OperatingMode.EMPLOYEE)
            self.assertEqual(profile.connector_mode, ConnectorMode.LIVE)
            self.assertEqual(profile.state_root, root / "runtime")
            self.assertEqual(
                profile.configuration_path("capabilities"),
                root / "config" / "capabilities.toml",
            )
            self.assertIsNone(profile.configuration_path("oauth"))
            self.assertEqual(profile.fingerprint, hashlib.sha256(payload).hexdigest())
            self.assertEqual(profile.source_path, source)
            with self.assertRaisesRegex(ConfigurationError, "unknown organization"):
                profile.configuration_path("secret_token")

    def test_profile_binds_managed_configuration_digest_and_writer_policy(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            source = root / "organization-profile.toml"
            trust_table = (
                "[configuration_trust.policy]\n"
                'class = "organization-managed"\n'
                f'sha256 = "{"a" * 64}"\n'
                "posix_uids = [0]\n"
                "posix_gids = [0]\n"
                'windows_sids = ["S-1-5-21-1-2-3-4100"]\n'
            ).encode()
            payload = (
                _profile_payload(
                    state_root="state",
                    configuration={"policy": "company/policy.toml"},
                )
                + trust_table
            )

            profile = OrganizationProfile.from_toml(
                ConfigSnapshot(display_path=source, payload=payload)
            )
            policy = profile.configuration_trust_policy("policy")
            self.assertIsNotNone(policy)
            assert policy is not None
            self.assertEqual(policy.sha256, "a" * 64)
            self.assertEqual(policy.posix_uids, (0,))
            self.assertEqual(policy.windows_sids, ("S-1-5-21-1-2-3-4100",))
            self.assertEqual(
                profile.configuration_trust_summary(),
                (("policy", "organization-managed"),),
            )
            self.assertEqual(
                profile.to_dict()["configuration_trust"],
                {
                    "policy": {
                        "class": "organization-managed",
                        "reason": "content-and-writer-bound",
                    }
                },
            )
            readiness = assess_operating_readiness(
                profile=profile,
                catalog=_catalog(),
            ).to_dict()
            self.assertEqual(
                readiness["configuration_trust"],
                {
                    "policy": {
                        "class": "organization-managed",
                        "reason": "content-and-writer-bound",
                    }
                },
            )

            missing_path = _profile_payload(state_root="state") + trust_table
            with self.assertRaisesRegex(ConfigurationError, "matching configuration"):
                OrganizationProfile.from_toml(
                    ConfigSnapshot(display_path=source, payload=missing_path)
                )

    def test_profile_rejects_unknown_fields_types_duplicates_and_secret_paths(
        self,
    ) -> None:
        with TemporaryDirectory() as raw:
            source = Path(raw).resolve() / "organization-profile.toml"
            valid = _profile_payload(state_root="state")
            cases = {
                "unknown keys": valid + b'credential = "secret"\n',
                "must be a boolean": valid.replace(
                    b"writes_enabled = false", b'writes_enabled = "false"'
                ),
                "must be unique": _profile_payload(
                    state_root="state",
                    capabilities=(
                        "github.repository.read",
                        "github.repository.read",
                    ),
                ),
                "unknown configuration paths": _profile_payload(
                    state_root="state",
                    configuration={"credential": "token.txt"},
                ),
            }
            for message, payload in cases.items():
                with (
                    self.subTest(message=message),
                    self.assertRaisesRegex(ConfigurationError, message),
                ):
                    OrganizationProfile.from_toml(
                        ConfigSnapshot(display_path=source, payload=payload)
                    )

    def test_profile_input_is_bounded_before_toml_parsing(self) -> None:
        oversized = b"#" * (256 * 1024 + 1)
        with self.assertRaisesRegex(ConfigurationError, "256 KiB"):
            OrganizationProfile.from_toml(
                ConfigSnapshot(
                    display_path=Path("/profile/organization-profile.toml"),
                    payload=oversized,
                )
            )

    def test_default_profile_path_is_home_scoped_not_cwd_scoped(self) -> None:
        with TemporaryDirectory() as raw:
            home = Path(raw).resolve()
            self.assertEqual(
                default_organization_profile_path(home=home),
                home / ".master-agent" / "MasterAgent" / "organization-profile.toml",
            )

    def test_missing_profile_uses_stable_setup_category(self) -> None:
        with TemporaryDirectory() as raw:
            missing = Path(raw).resolve() / "missing.toml"
            with self.assertRaises(OperatingValidationError) as raised:
                load_organization_profile(missing)
            self.assertEqual(
                raised.exception.category,
                OperatingFailureCategory.MISSING_ORGANIZATION_SETUP,
            )

    def test_setup_installs_exact_private_copy_without_runtime_files(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            destination = root / "home" / "organization-profile.toml"
            state_root = root / "runtime"
            payload = _profile_payload(state_root=os.fspath(state_root))
            snapshot = ConfigSnapshot(
                display_path=root / "template.toml",
                payload=payload,
            )

            first = install_organization_profile(snapshot, destination=destination)
            second = install_organization_profile(snapshot, destination=destination)

            self.assertTrue(first.profile_created)
            self.assertFalse(second.profile_created)
            self.assertEqual(destination.read_bytes(), payload)
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(state_root.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((state_root / "runs").stat().st_mode), 0o700)
            self.assertEqual(tuple(state_root.iterdir()), (state_root / "runs",))
            self.assertEqual(tuple((state_root / "runs").iterdir()), ())
            self.assertFalse((state_root / "audit.sqlite3").exists())
            self.assertFalse((state_root / "artifacts").exists())
            self.assertFalse((state_root / "result.json").exists())
            self.assertEqual(first.profile.source_path, destination)

    def test_setup_does_not_replace_a_different_installed_profile(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            destination = root / "profiles" / "organization-profile.toml"
            state_root = root / "state"
            first = ConfigSnapshot(
                display_path=root / "first.toml",
                payload=_profile_payload(state_root=os.fspath(state_root)),
            )
            second = ConfigSnapshot(
                display_path=root / "second.toml",
                payload=_profile_payload(
                    state_root=os.fspath(root / "replacement-state"),
                    mode="developer",
                ),
            )
            install_organization_profile(first, destination=destination)

            with self.assertRaisesRegex(ConfigurationError, "different bytes"):
                install_organization_profile(second, destination=destination)

            self.assertEqual(destination.read_bytes(), first.payload)
            self.assertFalse((root / "replacement-state").exists())

    def test_setup_rejects_state_root_at_or_below_profile_file(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            destination = root / "profile" / "organization-profile.toml"
            for state_root in (
                destination,
                destination / "state",
                destination.with_name(destination.name.upper()),
            ):
                with (
                    self.subTest(state_root=state_root),
                    self.assertRaisesRegex(ConfigurationError, "profile file path"),
                ):
                    install_organization_profile(
                        ConfigSnapshot(
                            display_path=root / "source.toml",
                            payload=_profile_payload(state_root=os.fspath(state_root)),
                        ),
                        destination=destination,
                    )
            self.assertFalse(destination.exists())

    def test_setup_rejects_unicode_normalization_alias_of_profile_path(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            destination = root / "caf\N{LATIN SMALL LETTER E WITH ACUTE}.toml"
            decomposed = root / "cafe\N{COMBINING ACUTE ACCENT}.toml"

            with self.assertRaisesRegex(ConfigurationError, "profile file path"):
                install_organization_profile(
                    ConfigSnapshot(
                        display_path=root / "source.toml",
                        payload=_profile_payload(state_root=os.fspath(decomposed)),
                    ),
                    destination=destination,
                )

            self.assertFalse(destination.exists())
            self.assertFalse(decomposed.exists())

    def test_setup_rejects_ancestor_and_final_symlink_aliases(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            real = root / "real"
            real.mkdir(mode=0o700)
            alias = root / "alias"
            alias.symlink_to(real, target_is_directory=True)
            payload = _profile_payload(state_root=os.fspath(root / "state"))
            source = ConfigSnapshot(display_path=root / "source.toml", payload=payload)

            with self.assertRaisesRegex(ConfigurationError, "no-follow"):
                install_organization_profile(
                    source,
                    destination=alias / "organization-profile.toml",
                )
            self.assertEqual(tuple(real.iterdir()), ())

            destination_root = root / "profiles"
            destination_root.mkdir(mode=0o700)
            outside = root / "outside.toml"
            outside.write_bytes(payload)
            outside.chmod(0o600)
            final_alias = destination_root / "organization-profile.toml"
            final_alias.symlink_to(outside)
            with self.assertRaisesRegex(ConfigurationError, "no-follow"):
                install_organization_profile(source, destination=final_alias)
            self.assertEqual(outside.read_bytes(), payload)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX named pipes")
    def test_setup_rejects_existing_fifo_without_creating_state(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            destination_root = root / "profiles"
            destination_root.mkdir(mode=0o700)
            destination = destination_root / "organization-profile.toml"
            os.mkfifo(destination, mode=0o600)
            state_root = root / "state"
            source = ConfigSnapshot(
                display_path=root / "source.toml",
                payload=_profile_payload(state_root=os.fspath(state_root)),
            )

            with self.assertRaisesRegex(ConfigurationError, "mode-0600 regular file"):
                install_organization_profile(source, destination=destination)

            self.assertTrue(stat.S_ISFIFO(destination.lstat().st_mode))
            self.assertFalse(state_root.exists())

    def test_setup_rejects_symlinked_state_root_without_following_it(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            outside = root / "outside"
            outside.mkdir(mode=0o700)
            alias = root / "state-alias"
            alias.symlink_to(outside, target_is_directory=True)
            source = ConfigSnapshot(
                display_path=root / "source.toml",
                payload=_profile_payload(state_root=os.fspath(alias)),
            )
            destination = root / "profiles" / "organization-profile.toml"

            with self.assertRaisesRegex(ConfigurationError, "no-follow"):
                install_organization_profile(source, destination=destination)

            self.assertEqual(tuple(outside.iterdir()), ())
            self.assertFalse(destination.exists())

    def test_setup_detects_profile_path_replacement_during_publication(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            destination = root / "profiles" / "organization-profile.toml"
            saved = root / "profiles" / "saved-profile.toml"
            attacker_payload = _profile_payload(
                state_root=os.fspath(root / "attacker-state"),
                mode="developer",
            )
            source = ConfigSnapshot(
                display_path=root / "source.toml",
                payload=_profile_payload(state_root=os.fspath(root / "state")),
            )

            def replace_during_write(descriptor: int, payload: bytes) -> None:
                destination.rename(saved)
                destination.write_bytes(attacker_payload)
                destination.chmod(0o600)
                os.write(descriptor, payload)

            with (
                patch.object(
                    operating_module,
                    "_write_all",
                    side_effect=replace_during_write,
                ),
                self.assertRaisesRegex(ConfigurationError, "identity change"),
            ):
                install_organization_profile(source, destination=destination)

            self.assertEqual(destination.read_bytes(), attacker_payload)
            self.assertEqual(saved.read_bytes(), source.payload)

    def test_setup_rollback_never_unlinks_a_replacement_profile(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            destination = root / "profiles" / "organization-profile.toml"
            saved = root / "profiles" / "saved-profile.toml"
            attacker_payload = _profile_payload(
                state_root=os.fspath(root / "attacker-state"),
                mode="developer",
            )
            source = ConfigSnapshot(
                display_path=root / "source.toml",
                payload=_profile_payload(state_root=os.fspath(root / "state")),
            )

            def replace_then_fail(descriptor: int, payload: bytes) -> None:
                del descriptor, payload
                destination.rename(saved)
                destination.write_bytes(attacker_payload)
                destination.chmod(0o600)
                raise OSError("simulated write failure")

            with (
                patch.object(
                    operating_module,
                    "_write_all",
                    side_effect=replace_then_fail,
                ),
                self.assertRaisesRegex(ConfigurationError, "identity change"),
            ):
                install_organization_profile(source, destination=destination)

            self.assertEqual(destination.read_bytes(), attacker_payload)
            self.assertEqual(saved.read_bytes(), b"")

    def test_setup_detects_equal_length_in_place_profile_overwrite(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            destination = root / "profiles" / "organization-profile.toml"
            intended = _profile_payload(state_root=os.fspath(root / "state-a"))
            substituted = _profile_payload(state_root=os.fspath(root / "state-b"))
            self.assertEqual(len(intended), len(substituted))
            source = ConfigSnapshot(
                display_path=root / "source.toml",
                payload=intended,
            )

            def overwrite_in_place(descriptor: int, payload: bytes) -> None:
                os.write(descriptor, payload)
                with destination.open("r+b", buffering=0) as handle:
                    handle.write(substituted)
                    handle.flush()
                    os.fsync(handle.fileno())

            with (
                patch.object(
                    operating_module,
                    "_write_all",
                    side_effect=overwrite_in_place,
                ),
                self.assertRaisesRegex(ConfigurationError, "bytes changed"),
            ):
                install_organization_profile(source, destination=destination)

            self.assertFalse(destination.exists())
            self.assertTrue((root / "state-a" / "runs").is_dir())
            self.assertFalse((root / "state-b").exists())

    def test_run_allocation_creates_only_private_directories_and_typed_paths(
        self,
    ) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            profile = _profile(root, mode="developer", connector_mode="mock")

            allocation = allocate_operating_run(
                profile,
                run_id="0123456789abcdef0123456789abcdef",
            )

            self.assertEqual(
                allocation.run_root,
                root / "state" / "runs" / allocation.run_id,
            )
            self.assertEqual(allocation.plan, allocation.run_root / "plan.json")
            self.assertEqual(
                allocation.bound_plan,
                allocation.run_root / "bound-plan.json",
            )
            self.assertEqual(
                allocation.audit_database,
                allocation.run_root / "state" / "audit.sqlite3",
            )
            self.assertEqual(
                allocation.result,
                allocation.run_root / "results" / "result.json",
            )
            self.assertEqual(
                {item.name for item in allocation.run_root.iterdir()},
                {"state", "artifacts", "results", "workspace"},
            )
            for directory in (
                allocation.run_root,
                allocation.audit_database.parent,
                allocation.artifacts,
                allocation.result.parent,
                allocation.workspace,
            ):
                self.assertTrue(directory.is_dir())
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
            for directory in (
                allocation.audit_database.parent,
                allocation.artifacts,
                allocation.result.parent,
                allocation.workspace,
            ):
                self.assertEqual(tuple(directory.iterdir()), ())
            for file_path in (
                allocation.plan,
                allocation.bound_plan,
                allocation.audit_database,
                allocation.result,
            ):
                self.assertFalse(file_path.exists())
            with self.assertRaisesRegex(ConfigurationError, "already exists"):
                allocate_operating_run(profile, run_id=allocation.run_id)


class OperatingPlanValidationTests(unittest.TestCase):
    """Exercise fail-closed plan validation before runtime construction."""

    def test_anonymous_allowlisted_read_is_valid_without_credentials(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            capability = "github.public_repository.list"
            profile = _profile(root, capabilities=(capability,))
            catalog = _catalog(_definition(capability, authentication="anonymous"))
            integrations = _integrations(auth_mode=AuthMode.BEARER)

            result = validate_operating_plan(
                _plan(_action(capability)),
                profile=profile,
                catalog=catalog,
                integrations=integrations,
                environ={},
            )

            self.assertTrue(result.allowed, result.issues)
            self.assertEqual(json.loads(result.to_json())["allowed"], True)

    def test_out_of_allowlist_is_unsupported_not_policy_blocked(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            capability = "github.public_repository.list"
            result = validate_operating_plan(
                _plan(_action(capability)),
                profile=_profile(root, capabilities=("draft.package.generate",)),
                catalog=_catalog(_definition(capability, authentication="anonymous")),
            )

            self.assertFalse(result.allowed)
            self.assertEqual(
                result.issues[0].category,
                OperatingFailureCategory.UNSUPPORTED_CAPABILITY,
            )

    def test_missing_disabled_and_runtime_missing_capabilities_are_rejected(
        self,
    ) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            capability = "github.public_repository.list"
            profile = _profile(root, capabilities=(capability,))
            plan = _plan(_action(capability))
            cases: tuple[
                tuple[
                    CapabilityCatalog,
                    frozenset[str] | None,
                    OperatingFailureCategory,
                ],
                ...,
            ] = (
                (
                    _catalog(),
                    None,
                    OperatingFailureCategory.UNSUPPORTED_CAPABILITY,
                ),
                (
                    _catalog(
                        _definition(
                            capability,
                            enabled=False,
                            authentication="anonymous",
                        )
                    ),
                    None,
                    OperatingFailureCategory.UNSUPPORTED_CAPABILITY,
                ),
                (
                    _catalog(_definition(capability, authentication="anonymous")),
                    frozenset(),
                    OperatingFailureCategory.RUNTIME_DEFECT,
                ),
            )
            for catalog, runtime, category in cases:
                with self.subTest(category=category):
                    result = validate_operating_plan(
                        plan,
                        profile=profile,
                        catalog=catalog,
                        runtime_capabilities=runtime,
                    )
                    self.assertIn(category, {item.category for item in result.issues})

    def test_live_authenticated_capability_requires_setup_then_user_auth(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            capability = "github.private_repository.read"
            profile = _profile(root, capabilities=(capability,))
            catalog = _catalog(_definition(capability, authentication="configured"))
            plan = _plan(_action(capability))

            missing_setup = validate_operating_plan(
                plan,
                profile=profile,
                catalog=catalog,
            )
            missing_auth = validate_operating_plan(
                plan,
                profile=profile,
                catalog=catalog,
                integrations=_integrations(auth_mode=AuthMode.BEARER),
                environ={},
            )
            whitespace_auth = validate_operating_plan(
                plan,
                profile=profile,
                catalog=catalog,
                integrations=_integrations(auth_mode=AuthMode.BEARER),
                environ={"MASTER_AGENT_GITHUB_TOKEN": " \t "},
            )
            authenticated = require_operating_plan(
                plan,
                profile=profile,
                catalog=catalog,
                integrations=_integrations(auth_mode=AuthMode.BEARER),
                environ={},
                authenticated_capabilities=frozenset({capability}),
            )

            self.assertIn(
                OperatingFailureCategory.MISSING_ORGANIZATION_SETUP,
                {item.category for item in missing_setup.issues},
            )
            self.assertIn(
                OperatingFailureCategory.MISSING_USER_AUTHENTICATION,
                {item.category for item in missing_auth.issues},
            )
            self.assertIn(
                OperatingFailureCategory.MISSING_USER_AUTHENTICATION,
                {item.category for item in whitespace_auth.issues},
            )
            self.assertTrue(authenticated.allowed)

    def test_profile_mode_and_effect_gates_fail_closed(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            cases = (
                (
                    "provider.item.write",
                    RiskLevel.REVERSIBLE_WRITE,
                    _profile(root, capabilities=("provider.item.write",)),
                ),
                (
                    "provider.message.send",
                    RiskLevel.EXTERNAL_COMMUNICATION,
                    _profile(root, capabilities=("provider.message.send",)),
                ),
                (
                    "provider.tenant.delete",
                    RiskLevel.DESTRUCTIVE,
                    _profile(
                        root,
                        capabilities=("provider.tenant.delete",),
                        writes_enabled=True,
                    ),
                ),
            )
            for capability, risk, profile in cases:
                definition = _definition(
                    capability,
                    risk=risk,
                    authentication="local",
                )
                result = validate_operating_plan(
                    _plan(_action(capability, risk=risk)),
                    profile=profile,
                    catalog=_catalog(definition),
                )
                with self.subTest(capability=capability):
                    self.assertIn(
                        OperatingFailureCategory.BLOCKED_POLICY,
                        {item.category for item in result.issues},
                    )

    def test_policy_and_action_contract_defects_are_distinguished(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            capability = "draft.package.generate"
            profile = _profile(
                root,
                mode="developer",
                connector_mode="mock",
                capabilities=(capability,),
            )
            definition = _definition(
                capability,
                risk=RiskLevel.LOCAL_GENERATION,
                authentication="local",
            )
            catalog = _catalog(definition)
            plan = _plan(_action(capability, risk=RiskLevel.LOCAL_GENERATION))
            blocked = validate_operating_plan(
                plan,
                profile=profile,
                catalog=catalog,
                policy_blocked_capabilities=frozenset({capability}),
            )
            malformed = validate_operating_plan(
                _plan(
                    replace(
                        plan.actions[0],
                        target=ResourceRef(
                            system="wrong",
                            resource_type="item",
                            resource_id="1",
                        ),
                    )
                ),
                profile=profile,
                catalog=catalog,
            )

            self.assertIn(
                OperatingFailureCategory.BLOCKED_POLICY,
                {item.category for item in blocked.issues},
            )
            self.assertIn(
                OperatingFailureCategory.RUNTIME_DEFECT,
                {item.category for item in malformed.issues},
            )
            with self.assertRaises(OperatingValidationError) as raised:
                malformed.require_valid()
            self.assertEqual(
                raised.exception.category,
                OperatingFailureCategory.RUNTIME_DEFECT,
            )

    def test_prebound_plugin_and_capsule_plans_are_rejected(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            capability = "draft.package.generate"
            profile = _profile(
                root,
                mode="developer",
                connector_mode="mock",
                capabilities=(capability,),
            )
            catalog = _catalog(
                _definition(
                    capability,
                    risk=RiskLevel.LOCAL_GENERATION,
                    authentication="local",
                )
            )
            context = ExecutionContext(
                integrations_sha256="0" * 64,
                plugins=(_plugin_binding(),),
                capsules=(_capsule_binding(capability),),
            )
            result = validate_operating_plan(
                replace(
                    _plan(_action(capability, risk=RiskLevel.LOCAL_GENERATION)),
                    execution_context=context,
                ),
                profile=profile,
                catalog=catalog,
            )

            self.assertFalse(result.allowed)
            self.assertEqual(
                [item.category for item in result.issues[:3]],
                [
                    OperatingFailureCategory.UNSUPPORTED_CAPABILITY,
                    OperatingFailureCategory.UNSUPPORTED_CAPABILITY,
                    OperatingFailureCategory.BLOCKED_POLICY,
                ],
            )


class OperatingReadinessTests(unittest.TestCase):
    """Exercise capability-scoped progressive readiness."""

    def test_optional_providers_do_not_break_install_readiness(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            read = "github.private_repository.read"
            draft = "draft.package.generate"
            effect = "provider.item.write"
            profile = _profile(
                root,
                capabilities=(read, draft, effect),
                writes_enabled=False,
            )
            report = assess_operating_readiness(
                profile=profile,
                catalog=_catalog(
                    _definition(read, authentication="configured"),
                    _definition(
                        draft,
                        risk=RiskLevel.LOCAL_GENERATION,
                        authentication="local",
                    ),
                    _definition(
                        effect,
                        risk=RiskLevel.REVERSIBLE_WRITE,
                        authentication="local",
                    ),
                ),
            )

            self.assertTrue(report.install_ready)
            self.assertFalse(report.read_ready)
            self.assertTrue(report.draft_ready)
            self.assertFalse(report.effect_ready)
            self.assertFalse(report.enterprise_ready)
            payload = json.loads(report.to_json())
            self.assertEqual(payload["levels"]["install_ready"], True)
            self.assertEqual(payload["levels"]["enterprise_ready"], False)
            self.assertIn("#113", payload["enterprise_blocker"])
            self.assertLess(len(report.to_json().encode("utf-8")), 1024 * 1024)

    def test_empty_readiness_levels_are_false_not_vacuously_true(self) -> None:
        with TemporaryDirectory() as raw:
            report = assess_operating_readiness(
                profile=_profile(Path(raw).resolve(), capabilities=()),
                catalog=_catalog(),
            )
            self.assertTrue(report.install_ready)
            self.assertFalse(report.read_ready)
            self.assertFalse(report.draft_ready)
            self.assertFalse(report.effect_ready)
            self.assertFalse(report.enterprise_ready)

    def test_unavailable_native_state_backends_fail_closed_per_capability(
        self,
    ) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            read = "github.private_repository.read"
            draft = "draft.package.generate"
            effect = "provider.item.write"
            report = assess_operating_readiness(
                profile=_profile(root, capabilities=(read, draft, effect)),
                catalog=_catalog(
                    _definition(read, authentication="configured"),
                    _definition(
                        draft,
                        risk=RiskLevel.LOCAL_GENERATION,
                        authentication="local",
                    ),
                    _definition(
                        effect,
                        risk=RiskLevel.REVERSIBLE_WRITE,
                        authentication="local",
                    ),
                ),
                state_backed_read_capabilities=frozenset({read}),
                platform_status=platform_runtime_status("win32"),
            )

        self.assertTrue(report.install_ready)
        self.assertFalse(report.read_ready)
        self.assertFalse(report.draft_ready)
        self.assertFalse(report.effect_ready)
        self.assertEqual(report.platform_runtime.platform, "windows")
        self.assertEqual(report.platform_runtime.backend, "windows-unavailable")
        for item in report.capabilities:
            platform_issues = tuple(
                issue
                for issue in item.issues
                if "native platform runtime contracts" in issue.message
            )
            self.assertEqual(len(platform_issues), 1, item.capability)
            self.assertEqual(
                platform_issues[0].category,
                OperatingFailureCategory.RUNTIME_DEFECT,
            )
            self.assertIn("secure_filesystem", platform_issues[0].message)
            self.assertIn("cross_process_locking", platform_issues[0].message)
            self.assertIn("atomic_publication_recovery", platform_issues[0].message)
        payload = report.to_dict()
        self.assertEqual(
            tuple(payload["platform_runtime"]["capabilities"]),
            (
                "secure_filesystem",
                "cross_process_locking",
                "atomic_publication_recovery",
                "credential_storage",
                "process_supervision",
                "trusted_git",
                "capsule_isolation",
            ),
        )

    def test_unavailable_native_state_backends_do_not_block_stateless_reads(
        self,
    ) -> None:
        with TemporaryDirectory() as raw:
            capability = "github.public_repository.list"
            report = assess_operating_readiness(
                profile=_profile(Path(raw).resolve(), capabilities=(capability,)),
                catalog=_catalog(_definition(capability, authentication="anonymous")),
                integrations=_integrations(auth_mode=AuthMode.BEARER),
                environ={},
                platform_status=platform_runtime_status("win32"),
            )

        self.assertTrue(report.install_ready)
        self.assertTrue(report.read_ready)
        self.assertEqual(report.capabilities[0].issues, ())

    def test_filesystem_backed_read_does_not_require_locking_or_atomic_state(
        self,
    ) -> None:
        unavailable = platform_runtime_status("win32")
        secure_filesystem_only = replace(
            unavailable,
            capabilities=tuple(
                replace(
                    item,
                    available=True,
                    backend="test-secure-filesystem",
                    reason=None,
                )
                if item.contract is PlatformContract.SECURE_FILESYSTEM
                else item
                for item in unavailable.capabilities
            ),
        )
        with TemporaryDirectory() as raw:
            capability = "github.public_repository.list"
            report = assess_operating_readiness(
                profile=_profile(Path(raw).resolve(), capabilities=(capability,)),
                catalog=_catalog(_definition(capability, authentication="anonymous")),
                integrations=_integrations(auth_mode=AuthMode.BEARER),
                environ={},
                filesystem_backed_read_capabilities=frozenset({capability}),
                platform_status=secure_filesystem_only,
            )

        self.assertTrue(report.install_ready)
        self.assertTrue(report.read_ready)
        self.assertEqual(report.capabilities[0].issues, ())

    def test_ca_backed_readiness_uses_platform_status_before_trust_path(self) -> None:
        configured = _integrations(auth_mode=AuthMode.BEARER)
        github = replace(
            configured.connector("github"),
            ca_bundle_env="MASTER_AGENT_ENTERPRISE_CA_BUNDLE",
        )
        integrations = IntegrationConfig({"github": github})
        with (
            TemporaryDirectory() as raw,
            patch("master_agent.config.Path") as path_constructor,
            patch("master_agent.operating.capture_ca_bundle") as capture_bundle,
            patch("master_agent.operating.create_ssl_context") as create_context,
        ):
            capability = "github.public_repository.list"
            report_profile = _profile(
                Path(raw).resolve(),
                capabilities=(capability,),
            )
            report = assess_operating_readiness(
                profile=report_profile,
                catalog=_catalog(_definition(capability, authentication="anonymous")),
                integrations=integrations,
                environ={"MASTER_AGENT_ENTERPRISE_CA_BUNDLE": "never-inspected.pem"},
                platform_status=platform_runtime_status("win32"),
            )

        self.assertFalse(report.read_ready)
        issues = report.capabilities[0].issues
        self.assertTrue(
            any(
                issue.category is OperatingFailureCategory.RUNTIME_DEFECT
                and "secure_filesystem" in issue.message
                for issue in issues
            )
        )
        self.assertFalse(
            any(
                "destination or trust configuration" in issue.message
                for issue in issues
            )
        )
        path_constructor.assert_not_called()
        capture_bundle.assert_not_called()
        create_context.assert_not_called()

        with (
            patch("master_agent.platform_runtime.factory.sys.platform", "win32"),
            patch("master_agent.config.Path") as validation_path,
            patch("master_agent.operating.capture_ca_bundle") as validation_capture,
        ):
            validation = validate_operating_plan(
                _plan(_action(capability)),
                profile=report_profile,
                catalog=_catalog(_definition(capability, authentication="anonymous")),
                integrations=integrations,
                environ={"MASTER_AGENT_ENTERPRISE_CA_BUNDLE": "never-inspected.pem"},
            )

        self.assertIsInstance(validation.issues, tuple)
        validation_path.assert_not_called()
        validation_capture.assert_not_called()

    def test_read_only_local_git_readiness_requires_all_git_contracts(self) -> None:
        from master_agent.operating import _readiness_platform_contracts

        available = platform_runtime_status("linux")
        git_contracts = (
            PlatformContract.SECURE_FILESYSTEM,
            PlatformContract.CROSS_PROCESS_LOCKING,
            PlatformContract.PROCESS_SUPERVISION,
            PlatformContract.TRUSTED_GIT,
        )
        git_runtime_unavailable = replace(
            available,
            capabilities=tuple(
                replace(
                    item,
                    available=False,
                    backend="test-git-runtime-unavailable",
                    reason=f"simulated {item.contract} backend is unavailable",
                )
                if item.contract in git_contracts
                else item
                for item in available.capabilities
            ),
        )
        with TemporaryDirectory() as raw:
            capability = "git.repository.read"
            definition = replace(
                _definition(
                    capability,
                    risk=RiskLevel.READ_ONLY,
                    authentication="local",
                ),
                authentication="local_git",
            )
            self.assertEqual(
                _readiness_platform_contracts(
                    definition,
                    state_backed_read=False,
                    filesystem_backed_read=False,
                ),
                git_contracts,
            )
            report = assess_operating_readiness(
                profile=_profile(
                    Path(raw).resolve(),
                    mode="developer",
                    capabilities=(capability,),
                ),
                catalog=_catalog(definition),
                platform_status=git_runtime_unavailable,
            )

        self.assertFalse(report.read_ready)
        platform_issues = tuple(
            issue
            for issue in report.capabilities[0].issues
            if "native platform runtime contracts" in issue.message
        )
        self.assertEqual(len(platform_issues), 1)
        for contract in git_contracts:
            self.assertIn(contract, platform_issues[0].message)
        self.assertNotIn(
            PlatformContract.ATOMIC_PUBLICATION_RECOVERY,
            platform_issues[0].message,
        )

    def test_anonymous_capability_is_read_ready_without_optional_credentials(
        self,
    ) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            capability = "github.public_repository.list"
            report = assess_operating_readiness(
                profile=_profile(root, capabilities=(capability,)),
                catalog=_catalog(_definition(capability, authentication="anonymous")),
                integrations=_integrations(auth_mode=AuthMode.BEARER),
                environ={},
            )
            self.assertTrue(report.install_ready)
            self.assertTrue(report.read_ready)
            self.assertNotIn(
                OperatingFailureCategory.MISSING_USER_AUTHENTICATION,
                {
                    issue.category
                    for capability_readiness in report.capabilities
                    for issue in capability_readiness.issues
                },
            )

    def test_anonymous_readiness_never_queries_credential_environment(self) -> None:
        class CredentialTrap(Mapping[str, str]):
            def __getitem__(self, key: str) -> str:
                if key == "MASTER_AGENT_GITHUB_TOKEN":
                    raise AssertionError("credential lookup")
                raise KeyError(key)

            def __iter__(self) -> Iterator[str]:
                return iter(())

            def __len__(self) -> int:
                return 0

        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            capability = "github.public_repository.list"
            report = assess_operating_readiness(
                profile=_profile(root, capabilities=(capability,)),
                catalog=_catalog(_definition(capability, authentication="anonymous")),
                integrations=_integrations(auth_mode=AuthMode.BEARER),
                environ=CredentialTrap(),
            )

            self.assertTrue(report.read_ready)

    def test_anonymous_read_requires_endpoint_setup_not_credentials(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            capability = "github.public_repository.list"
            base = _integrations(auth_mode=AuthMode.BEARER)
            connector = replace(
                base.connector("github"),
                base_url=None,
                base_url_env="MASTER_AGENT_GITHUB_BASE_URL",
            )
            report = assess_operating_readiness(
                profile=_profile(root, capabilities=(capability,)),
                catalog=_catalog(_definition(capability, authentication="anonymous")),
                integrations=IntegrationConfig({"github": connector}),
                environ={},
            )

            self.assertFalse(report.read_ready)
            self.assertIn(
                OperatingFailureCategory.MISSING_ORGANIZATION_SETUP,
                {issue.category for issue in report.capabilities[0].issues},
            )
            self.assertNotIn(
                OperatingFailureCategory.MISSING_USER_AUTHENTICATION,
                {issue.category for issue in report.capabilities[0].issues},
            )

    def test_catalog_cannot_relabel_nonpublic_runtime_read_as_anonymous(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            capability = "jira.issue.read"
            connector = replace(
                _integrations(auth_mode=AuthMode.BEARER).connector("github"),
                system="jira",
                base_url="https://company.atlassian.net",
                secret_env="MASTER_AGENT_JIRA_TOKEN",
            )

            report = assess_operating_readiness(
                profile=_profile(root, capabilities=(capability,)),
                catalog=_catalog(_definition(capability, authentication="anonymous")),
                integrations=IntegrationConfig({"jira": connector}),
                environ={},
            )

            self.assertFalse(report.read_ready)
            self.assertIn(
                OperatingFailureCategory.MISSING_USER_AUTHENTICATION,
                {issue.category for issue in report.capabilities[0].issues},
            )

    def test_missing_delegated_token_file_is_missing_user_authentication(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            capability = "microsoft.identity.read"
            connector = ConnectorConfig(
                system="microsoft",
                enabled=True,
                deployment=DeploymentType.CLOUD,
                base_url="https://graph.microsoft.com/v1.0",
                base_url_env=None,
                auth_mode=AuthMode.OAUTH_DELEGATED,
                username_env=None,
                secret_env="MASTER_AGENT_GRAPH_ACCESS_TOKEN",
                extra={
                    "oauth_flow": "token_file",
                    "token_file_env": "MASTER_AGENT_GRAPH_TOKEN_FILE",
                    "identity_mode": "delegated",
                },
            )
            report = assess_operating_readiness(
                profile=_profile(root, capabilities=(capability,)),
                catalog=_catalog(_definition(capability, authentication="configured")),
                integrations=IntegrationConfig({"microsoft": connector}),
                environ={
                    "MASTER_AGENT_GRAPH_TOKEN_FILE": str(root / "missing-token.json")
                },
            )

            self.assertFalse(report.read_ready)
            self.assertIn(
                OperatingFailureCategory.MISSING_USER_AUTHENTICATION,
                {issue.category for issue in report.capabilities[0].issues},
            )

    def test_token_file_contents_are_not_assumed_valid_by_offline_readiness(
        self,
    ) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            token_file = root / "token.json"
            token_file.write_text(
                json.dumps(
                    {
                        "access_token": "valid-token-not-read-by-doctor",
                        "expires_at": "2099-01-01T00:00:00+00:00",
                        "scopes": ["User.Read"],
                    }
                ),
                encoding="utf-8",
            )
            token_file.chmod(0o600)
            capability = "microsoft.identity.read"
            connector = ConnectorConfig(
                system="microsoft",
                enabled=True,
                deployment=DeploymentType.CLOUD,
                base_url="https://graph.microsoft.com/v1.0",
                base_url_env=None,
                auth_mode=AuthMode.OAUTH_DELEGATED,
                username_env=None,
                secret_env="MASTER_AGENT_GRAPH_ACCESS_TOKEN",
                extra={
                    "oauth_flow": "token_file",
                    "token_file_env": "MASTER_AGENT_GRAPH_TOKEN_FILE",
                    "identity_mode": "delegated",
                },
            )

            report = assess_operating_readiness(
                profile=_profile(root, capabilities=(capability,)),
                catalog=_catalog(_definition(capability, authentication="configured")),
                integrations=IntegrationConfig({"microsoft": connector}),
                environ={"MASTER_AGENT_GRAPH_TOKEN_FILE": str(token_file)},
            )
            validation = validate_operating_plan(
                _plan(_action(capability)),
                profile=_profile(root, capabilities=(capability,)),
                catalog=_catalog(_definition(capability, authentication="configured")),
                integrations=IntegrationConfig({"microsoft": connector}),
                environ={"MASTER_AGENT_GRAPH_TOKEN_FILE": str(token_file)},
            )

            self.assertFalse(report.read_ready)
            self.assertTrue(validation.allowed, validation.issues)
            self.assertIn(
                OperatingFailureCategory.MISSING_USER_AUTHENTICATION,
                {issue.category for issue in report.capabilities[0].issues},
            )

    def test_packaged_placeholder_endpoint_is_missing_setup(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            capability = "jira.issue.read"
            profile = _profile(root, capabilities=(capability,))
            catalog = _catalog(_definition(capability, authentication="configured"))
            for endpoint in (
                "https://example.atlassian.net",
                "https://EXAMPLE.ATLASSIAN.NET",
                "https://example.atlassian.net.",
                "https://example.atlassian.net:443",
            ):
                with self.subTest(endpoint=endpoint):
                    integrations = IntegrationConfig(
                        {
                            "jira": ConnectorConfig(
                                system="jira",
                                enabled=True,
                                deployment=DeploymentType.CLOUD,
                                base_url=endpoint,
                                base_url_env=None,
                                auth_mode=AuthMode.BASIC,
                                username_env="MASTER_AGENT_JIRA_USERNAME",
                                secret_env="MASTER_AGENT_JIRA_TOKEN",
                            )
                        }
                    )
                    environ = {
                        "MASTER_AGENT_JIRA_USERNAME": "employee",
                        "MASTER_AGENT_JIRA_TOKEN": "must-not-be-used",
                    }
                    report = assess_operating_readiness(
                        profile=profile,
                        catalog=catalog,
                        integrations=integrations,
                        environ=environ,
                    )
                    validation = validate_operating_plan(
                        _plan(_action(capability)),
                        profile=profile,
                        catalog=catalog,
                        integrations=integrations,
                        environ=environ,
                    )

                    self.assertFalse(report.read_ready)
                    self.assertFalse(validation.allowed)
                    self.assertEqual(
                        report.capabilities[0].issues[0].category,
                        OperatingFailureCategory.MISSING_ORGANIZATION_SETUP,
                    )
                    self.assertEqual(
                        validation.issues[0].category,
                        OperatingFailureCategory.MISSING_ORGANIZATION_SETUP,
                    )

    def test_invalid_ca_bundle_is_sanitized_before_provider_use(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            capability = "github.repository.read"
            base = _integrations(auth_mode=AuthMode.BEARER)
            connector = replace(
                base.connector("github"),
                ca_bundle_env="MASTER_AGENT_ENTERPRISE_CA_BUNDLE",
            )
            invalid = root / "SECRET-CANARY-invalid-ca.pem"
            invalid.write_bytes(b"not a certificate")
            oversized = root / "SECRET-CANARY-oversized-ca.pem"
            oversized.write_bytes(b"x" * (4 * 1024 * 1024 + 1))
            for selected in (
                root / "SECRET-CANARY-missing-ca.pem",
                invalid,
                oversized,
            ):
                with self.subTest(selected=selected):
                    report = assess_operating_readiness(
                        profile=_profile(root, capabilities=(capability,)),
                        catalog=_catalog(
                            _definition(capability, authentication="anonymous")
                        ),
                        integrations=IntegrationConfig({"github": connector}),
                        environ={"MASTER_AGENT_ENTERPRISE_CA_BUNDLE": str(selected)},
                    )

                    self.assertFalse(report.read_ready)
                    issue = report.capabilities[0].issues[0]
                    self.assertEqual(
                        issue.category,
                        OperatingFailureCategory.MISSING_ORGANIZATION_SETUP,
                    )
                    self.assertEqual(
                        issue.message,
                        "provider destination or trust configuration is missing or invalid",
                    )
                    self.assertNotIn("SECRET-CANARY", report.to_json())

    def test_cloud_only_reads_reject_data_center_as_unsupported(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            cases = (
                ("github.public_repository.list", "github"),
                ("bitbucket.public_repository.list", "bitbucket"),
                ("microsoft.identity.read", "microsoft"),
            )
            for capability, system in cases:
                with self.subTest(capability=capability):
                    integrations = IntegrationConfig(
                        {
                            system: ConnectorConfig(
                                system=system,
                                enabled=True,
                                deployment=DeploymentType.DATA_CENTER,
                                base_url=f"https://{system}.example.test",
                                base_url_env=None,
                                auth_mode=AuthMode.BEARER,
                                username_env=None,
                                secret_env=f"MASTER_AGENT_{system.upper()}_TOKEN",
                            )
                        }
                    )
                    profile = _profile(root, capabilities=(capability,))
                    catalog = _catalog(
                        _definition(
                            capability,
                            authentication=(
                                "configured" if system == "microsoft" else "anonymous"
                            ),
                        )
                    )
                    report = assess_operating_readiness(
                        profile=profile,
                        catalog=catalog,
                        integrations=integrations,
                        environ={},
                    )
                    validation = validate_operating_plan(
                        _plan(_action(capability)),
                        profile=profile,
                        catalog=catalog,
                        integrations=integrations,
                        environ={},
                    )

                    self.assertFalse(report.read_ready)
                    self.assertFalse(validation.allowed)
                    self.assertEqual(
                        report.capabilities[0].issues[0].category,
                        OperatingFailureCategory.UNSUPPORTED_CAPABILITY,
                    )
                    self.assertEqual(
                        validation.issues[0].category,
                        OperatingFailureCategory.UNSUPPORTED_CAPABILITY,
                    )

    def test_confluence_space_create_rejects_data_center_before_state(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            capability = "confluence.space.create"
            integrations = IntegrationConfig(
                {
                    "confluence": ConnectorConfig(
                        system="confluence",
                        enabled=True,
                        deployment=DeploymentType.DATA_CENTER,
                        base_url="https://confluence.example.test",
                        base_url_env=None,
                        auth_mode=AuthMode.BEARER,
                        username_env=None,
                        secret_env="MASTER_AGENT_CONFLUENCE_TOKEN",
                    )
                }
            )
            profile = _profile(
                root,
                mode="developer",
                capabilities=(capability,),
                writes_enabled=True,
            )
            catalog = _catalog(
                _definition(
                    capability,
                    risk=RiskLevel.REVERSIBLE_WRITE,
                    authentication="configured",
                )
            )
            plan = _plan(_action(capability, risk=RiskLevel.REVERSIBLE_WRITE))

            report = assess_operating_readiness(
                profile=profile,
                catalog=catalog,
                integrations=integrations,
                environ={"MASTER_AGENT_CONFLUENCE_TOKEN": "unused"},
            )
            validation = validate_operating_plan(
                plan,
                profile=profile,
                catalog=catalog,
                integrations=integrations,
                environ={"MASTER_AGENT_CONFLUENCE_TOKEN": "unused"},
            )

            self.assertFalse(report.effect_ready)
            self.assertFalse(validation.allowed)
            self.assertEqual(
                report.capabilities[0].issues[0].category,
                OperatingFailureCategory.UNSUPPORTED_CAPABILITY,
            )
            self.assertEqual(
                validation.issues[0].category,
                OperatingFailureCategory.UNSUPPORTED_CAPABILITY,
            )

    def test_one_ready_capability_makes_its_nonempty_level_ready(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            public = "github.public_repository.list"
            private = "github.private_repository.read"
            report = assess_operating_readiness(
                profile=_profile(root, capabilities=(public, private)),
                catalog=_catalog(
                    _definition(public, authentication="anonymous"),
                    _definition(private, authentication="configured"),
                ),
                integrations=_integrations(auth_mode=AuthMode.BEARER),
                environ={},
            )

            self.assertTrue(report.install_ready)
            self.assertTrue(report.read_ready)
            self.assertEqual(
                {item.capability: item.read_ready for item in report.capabilities},
                {private: False, public: True},
            )

    def test_known_disabled_capability_is_installed_but_not_operational(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            capability = "github.repository.read"
            report = assess_operating_readiness(
                profile=_profile(root, capabilities=(capability,)),
                catalog=_catalog(
                    _definition(
                        capability,
                        authentication="anonymous",
                        enabled=False,
                    )
                ),
                integrations=_integrations(auth_mode=AuthMode.NONE),
            )

            self.assertTrue(report.install_ready)
            self.assertFalse(report.read_ready)
            self.assertTrue(report.capabilities[0].install_ready)
            self.assertFalse(report.capabilities[0].read_ready)

    def test_unlisted_readiness_capability_is_unsupported(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            capability = "github.repository.read"
            report = assess_operating_readiness(
                profile=_profile(root, capabilities=()),
                catalog=_catalog(_definition(capability, authentication="anonymous")),
                capabilities=(capability,),
            )
            self.assertEqual(
                report.capabilities[0].issues[0].category,
                OperatingFailureCategory.UNSUPPORTED_CAPABILITY,
            )


def _profile_payload(
    *,
    state_root: str,
    mode: str = "employee",
    connector_mode: str = "live",
    capabilities: tuple[str, ...] = ("github.repository.read",),
    writes_enabled: bool = False,
    communications_enabled: bool = False,
    configuration: dict[str, str] | None = None,
) -> bytes:
    lines = [
        f'schema = "{ORGANIZATION_PROFILE_SCHEMA}"',
        'organization = "Example Organization"',
        f'mode = "{mode}"',
        f"state_root = {json.dumps(state_root)}",
        f'connector_mode = "{connector_mode}"',
        f"writes_enabled = {str(writes_enabled).lower()}",
        f"communications_enabled = {str(communications_enabled).lower()}",
        "capabilities = [" + ", ".join(json.dumps(item) for item in capabilities) + "]",
    ]
    if configuration is not None:
        lines.append("[configuration]")
        lines.extend(
            f"{name} = {json.dumps(value)}"
            for name, value in sorted(configuration.items())
        )
    return ("\n".join(lines) + "\n").encode("utf-8")


def _profile(
    root: Path,
    *,
    mode: str = "employee",
    connector_mode: str = "live",
    capabilities: tuple[str, ...] = ("github.repository.read",),
    writes_enabled: bool = False,
    communications_enabled: bool = False,
) -> OrganizationProfile:
    return OrganizationProfile.from_toml(
        ConfigSnapshot(
            display_path=root / "organization-profile.toml",
            payload=_profile_payload(
                state_root=os.fspath(root / "state"),
                mode=mode,
                connector_mode=connector_mode,
                capabilities=capabilities,
                writes_enabled=writes_enabled,
                communications_enabled=communications_enabled,
            ),
        )
    )


def _definition(
    capability: str,
    *,
    risk: RiskLevel = RiskLevel.READ_ONLY,
    authentication: str,
    enabled: bool = True,
) -> CapabilityDefinition:
    local_generation = risk is RiskLevel.LOCAL_GENERATION
    side_effect = risk is not RiskLevel.READ_ONLY
    return CapabilityDefinition(
        name=capability,
        enabled=enabled,
        authentication={
            "anonymous": "anonymous_or_configured_connector",
            "configured": "configured_connector",
            "local": "local",
        }[authentication],
        risk=risk,
        target_system=capability.split(".", 1)[0],
        target_resource_types=("item",) if side_effect else (),
        parameter_schema={"value": "string?"} if side_effect else {},
        max_input_bytes=4096 if local_generation else None,
        max_output_bytes=4096 if local_generation else None,
    )


def _catalog(*definitions: CapabilityDefinition) -> CapabilityCatalog:
    return CapabilityCatalog({item.name: item for item in definitions})


def _action(
    capability: str,
    *,
    risk: RiskLevel = RiskLevel.READ_ONLY,
) -> AgentAction:
    return AgentAction(
        capability=capability,
        target=ResourceRef(
            system=capability.split(".", 1)[0],
            resource_type="item",
            resource_id="1",
        ),
        parameters={} if risk is RiskLevel.READ_ONLY else {"value": "test"},
        risk=risk,
        authority_source=AuthoritySource.DIRECT_USER,
        requires_approval=risk not in {RiskLevel.READ_ONLY, RiskLevel.LOCAL_GENERATION},
        idempotency_key=f"test:{capability}",
        justification="Operating mode contract test.",
    )


def _plan(action: AgentAction) -> ChangePlan:
    return ChangePlan(
        goal="Validate the operating mode contract.",
        actions=(action,),
        created_by="test",
    )


def _integrations(*, auth_mode: AuthMode) -> IntegrationConfig:
    return IntegrationConfig(
        {
            "github": ConnectorConfig(
                system="github",
                enabled=True,
                deployment=DeploymentType.CLOUD,
                base_url="https://api.github.com",
                base_url_env=None,
                auth_mode=auth_mode,
                username_env=None,
                secret_env=(
                    "MASTER_AGENT_GITHUB_TOKEN"
                    if auth_mode is not AuthMode.NONE
                    else None
                ),
            )
        }
    )


def _plugin_binding() -> PluginExecutionBinding:
    return PluginExecutionBinding(
        name="example",
        group="master_agent.connectors",
        entry_point="example:connector",
        distribution="example-plugin",
        distribution_version="1.0.0",
        artifact_sha256="1" * 64,
        identity_sha256="2" * 64,
    )


def _capsule_binding(capability: str) -> CapabilityCapsuleExecutionBinding:
    digest = "3" * 64
    return CapabilityCapsuleExecutionBinding(
        capability_id=capability,
        version="1.0.0",
        risk=RiskLevel.LOCAL_GENERATION,
        manifest_sha256=digest,
        source_sha256=digest,
        artifact_sha256=digest,
        dependency_lock_sha256=digest,
        sbom_sha256=digest,
        test_suite_sha256=digest,
        validation_result_sha256=digest,
        sandbox_validation_sha256=digest,
        verification_contract_sha256=digest,
        compensation_contract_sha256=digest,
        policy_contract_sha256=digest,
        worker_sha256=digest,
        publisher="publisher",
        reviewer="reviewer",
        signer_key_id="signer",
    )


if __name__ == "__main__":
    unittest.main()

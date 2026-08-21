"""Command-line safety and exit-status tests."""

from __future__ import annotations

import base64
import json
import os
import stat
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from master_agent.cli import (
    _bitbucket_repositories,
    _connect,
    _github_repositories,
    _parse_credential_mappings,
    main,
)
from master_agent.connectors.read_only import ReadOnlyConnector, RetrievedPayload
from master_agent.errors import ConfigurationError
from master_agent.models import (
    AgentAction,
    AuthoritySource,
    ChangePlan,
    ConnectorExecutionBinding,
    DataClassification,
    ResourceRef,
    RiskLevel,
)
from master_agent.planners.static import build_weekly_status_plan
from master_agent.registry import ConnectorRegistry
from tests.fakes import ScriptedTransport
from tests.helpers import private_temporary_directory

ROOT = Path(__file__).resolve().parents[1]


class _DirectReadGitHubConnector(ReadOnlyConnector):
    """Small typed live-shaped connector for CLI direct-read coverage."""

    def __init__(self) -> None:
        super().__init__(
            system="github",
            capabilities=frozenset({"github.repository.list"}),
        )
        self._config = SimpleNamespace(
            auth=SimpleNamespace(mode="bearer"),
            config_identity="a" * 64,
            base_url="https://api.github.com",
            max_pages=4,
            max_response_bytes=4096,
            ca_bundle=None,
            ca_bundle_sha256=None,
        )

    def _fetch(self, action: AgentAction) -> RetrievedPayload:
        del action
        return RetrievedPayload(
            data={"repositories": [{"full_name": "example/project"}]},
            connector_reference="https://api.github.com/user/repos",
        )


class CliTests(unittest.TestCase):
    """Verify CLI boundaries that protect live credentials and operators."""

    def test_credential_mapping_argument_is_secret_free_and_unambiguous(self) -> None:
        self.assertEqual(
            _parse_credential_mappings(("friendlyJiraKey=MASTER_AGENT_JIRA_TOKEN",)),
            {"friendlyJiraKey": "MASTER_AGENT_JIRA_TOKEN"},
        )
        with self.assertRaisesRegex(ConfigurationError, "FILE_KEY=DECLARED_NAME"):
            _parse_credential_mappings(("missing-separator",))
        with self.assertRaisesRegex(ConfigurationError, "repeats"):
            _parse_credential_mappings(("key=ONE", "key=TWO"))

    def test_connect_rejects_credential_mapping_without_a_file(self) -> None:
        with self.assertRaisesRegex(ConfigurationError, "requires --credentials-file"):
            _connect(
                integrations_path=None,
                governance_path=None,
                credentials_file=None,
                credential_mappings=("key=MASTER_AGENT_GITHUB_TOKEN",),
                systems={"github"},
                output=None,
            )

    def test_bind_and_run_forward_connection_adapters(self) -> None:
        mappings = (
            "JIRA_EMAIL=MASTER_AGENT_CONFLUENCE_USERNAME",
            "MASTER_AGENT_JIRA_TOKEN=MASTER_AGENT_CONFLUENCE_TOKEN",
        )
        connector_urls = ("confluence=https://tenant.atlassian.net/wiki/spaces",)
        with patch("master_agent.cli._bind_context", return_value=0) as bind_context:
            status = main(
                [
                    "bind-context",
                    "plan.json",
                    "--output",
                    "bound.json",
                    *(
                        item
                        for mapping in mappings
                        for item in ("--credential-map", mapping)
                    ),
                    *(
                        item
                        for value in connector_urls
                        for item in ("--connector-url", value)
                    ),
                ]
            )
        self.assertEqual(status, 0)
        self.assertEqual(
            bind_context.call_args.kwargs["credential_mappings"], list(mappings)
        )
        self.assertEqual(
            bind_context.call_args.kwargs["connector_urls"], list(connector_urls)
        )

        with patch("master_agent.cli._run", return_value=0) as run:
            status = main(
                [
                    "run",
                    "bound.json",
                    "--apply",
                    *(
                        item
                        for mapping in mappings
                        for item in ("--credential-map", mapping)
                    ),
                    *(
                        item
                        for value in connector_urls
                        for item in ("--connector-url", value)
                    ),
                ]
            )
        self.assertEqual(status, 0)
        self.assertEqual(run.call_args.kwargs["credential_mappings"], list(mappings))
        self.assertEqual(run.call_args.kwargs["connector_urls"], list(connector_urls))

    def test_live_mode_dry_run_does_not_require_credentials(self) -> None:
        """A policy-only dry run must not construct live connectors."""

        with private_temporary_directory() as directory:
            root = Path(directory)
            plan_path = root / "plan.json"
            plan_path.write_text(
                __import__("json").dumps(
                    build_weekly_status_plan().to_dict(),
                    default=str,
                ),
                encoding="utf-8",
            )
            stdout = StringIO()
            stderr = StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                status = main(
                    [
                        "run",
                        str(plan_path),
                        "--connector-mode",
                        "live",
                        "--integrations",
                        str(ROOT / "config/integrations.toml"),
                        "--database",
                        str(root / "audit.sqlite3"),
                        "--draft-output-dir",
                        str(root / "persistent/drafts"),
                        "--workspace-root",
                        str(root / "persistent/workspaces"),
                    ]
                )
            self.assertEqual(status, 0, stderr.getvalue())
            self.assertIn("mode: dry-run", stdout.getvalue())
            self.assertFalse((root / "audit.sqlite3").exists())
            self.assertFalse((root / "persistent").exists())

    def test_dry_run_cannot_persist_an_unbound_result(self) -> None:
        """Review mode must not write audit or result files outside a manifest."""

        with private_temporary_directory() as directory:
            root = Path(directory)
            plan_path = root / "plan.json"
            plan_path.write_text(
                __import__("json").dumps(
                    build_weekly_status_plan().to_dict(),
                    default=str,
                ),
                encoding="utf-8",
            )
            stderr = StringIO()
            with redirect_stdout(StringIO()), redirect_stderr(stderr):
                status = main(
                    [
                        "run",
                        str(plan_path),
                        "--database",
                        str(root / "audit.sqlite3"),
                        "--result-json",
                        str(root / "result.json"),
                    ]
                )

            self.assertEqual(status, 1)
            self.assertIn("--result-json requires --apply", stderr.getvalue())
            self.assertFalse((root / "audit.sqlite3").exists())
            self.assertFalse((root / "result.json").exists())

    def test_direct_read_runs_one_typed_provider_without_persistent_state(
        self,
    ) -> None:
        """Direct reads use a verified in-memory connector, not apply runtime state."""

        action = AgentAction(
            capability="github.repository.list",
            target=ResourceRef("github", "repository_collection", "me"),
            parameters={"limit": 1, "visibility": "all"},
            risk=RiskLevel.READ_ONLY,
            authority_source=AuthoritySource.DIRECT_USER,
            requires_approval=False,
            idempotency_key="direct-read-cli",
            justification="List repositories visible to the requesting user.",
            data_classification=DataClassification.INTERNAL,
        )
        plan = ChangePlan(
            goal="List the repositories visible to me.",
            actions=(action,),
            created_by="direct-user",
        )
        binding = ConnectorExecutionBinding(
            system="github",
            deployment="cloud",
            config_identity_sha256="a" * 64,
            resolved_base_url="https://api.github.com",
            resolved_origin="https://api.github.com",
            authentication_mode="bearer",
            credential_identity="github:user:42",
        )
        registry = ConnectorRegistry()
        registry.register(_DirectReadGitHubConnector())

        with private_temporary_directory() as directory:
            root = Path(directory)
            plan_path = root / "plan.json"
            plan_path.write_text(
                json.dumps(plan.to_dict(), default=str),
                encoding="utf-8",
            )
            stdout = StringIO()
            stderr = StringIO()
            original = Path.cwd()
            try:
                os.chdir(root)
                with (
                    patch(
                        "master_agent.cli.capture_connector_executions",
                        return_value=(SimpleNamespace(binding=binding),),
                    ) as capture,
                    patch(
                        "master_agent.cli.build_live_registry",
                        return_value=registry,
                    ),
                    redirect_stdout(stdout),
                    redirect_stderr(stderr),
                ):
                    status = main(["run", str(plan_path), "--direct-read"])
            finally:
                os.chdir(original)

            self.assertEqual(status, 0, stderr.getvalue())
            self.assertIn("mode: direct-read", stdout.getvalue())
            self.assertIn("provider: github", stdout.getvalue())
            self.assertIn("example/project", stdout.getvalue())
            self.assertNotIn("audit.sqlite3", stdout.getvalue())
            self.assertFalse((root / ".master-agent").exists())
            capture.assert_called_once()

    def test_direct_read_rejects_effects_before_connector_capture(self) -> None:
        action = AgentAction(
            capability="github.issue.create",
            target=ResourceRef("github", "issue", "new"),
            parameters={
                "owner": "example",
                "repository": "project",
                "title": "should not run",
            },
            risk=RiskLevel.REVERSIBLE_WRITE,
            authority_source=AuthoritySource.DIRECT_USER,
            requires_approval=True,
            idempotency_key="direct-read-effect",
            justification="Test direct-read rejection.",
        )
        plan = ChangePlan(
            goal="Do not create an issue.",
            actions=(action,),
            created_by="direct-user",
        )

        with private_temporary_directory() as directory:
            plan_path = Path(directory) / "plan.json"
            plan_path.write_text(
                json.dumps(plan.to_dict(), default=str),
                encoding="utf-8",
            )
            stderr = StringIO()
            with (
                patch("master_agent.cli.capture_connector_executions") as capture,
                redirect_stdout(StringIO()),
                redirect_stderr(stderr),
            ):
                status = main(["run", str(plan_path), "--direct-read"])

        self.assertEqual(status, 1)
        self.assertIn("read-only", stderr.getvalue())
        capture.assert_not_called()

    def test_discovery_reports_missing_environment_without_failing_onboarding(
        self,
    ) -> None:
        """Normal discovery inventories setup gaps without a readiness failure."""

        with private_temporary_directory() as directory:
            root = Path(directory)
            config = root / "integrations.toml"
            config.write_text(
                """
[connectors.jira]
enabled = true
deployment = "cloud"
base_url = "https://example.atlassian.net"
auth_mode = "bearer"
secret_env = "MASTER_AGENT_JIRA_TOKEN"
""".strip()
                + "\n",
                encoding="utf-8",
            )
            stdout = StringIO()
            stderr = StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                status = main(
                    [
                        "discover",
                        "--integrations",
                        str(config),
                        "--systems",
                        "jira",
                    ]
                )
            self.assertEqual(status, 0, stderr.getvalue())
            self.assertIn("missing_environment", stdout.getvalue())
            self.assertNotIn("secret", stdout.getvalue().lower())

            stdout = StringIO()
            stderr = StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                status = main(
                    [
                        "discover",
                        "--integrations",
                        str(config),
                        "--systems",
                        "jira",
                        "--require-ready",
                    ]
                )
            self.assertEqual(status, 2, stderr.getvalue())
            self.assertIn("missing_environment", stdout.getvalue())

    def test_readiness_accepts_implemented_github_principal_adapter(self) -> None:
        with private_temporary_directory() as directory:
            config = Path(directory) / "integrations.toml"
            config.write_text(
                """
[connectors.github]
enabled = true
deployment = "cloud"
base_url = "https://api.github.com"
auth_mode = "bearer"
secret_env = "MASTER_AGENT_GITHUB_TOKEN"
""".strip()
                + "\n",
                encoding="utf-8",
            )
            stdout = StringIO()
            stderr = StringIO()
            with (
                patch.dict(
                    os.environ,
                    {"MASTER_AGENT_GITHUB_TOKEN": "opaque-token"},
                ),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                status = main(
                    [
                        "readiness",
                        "--integrations",
                        str(config),
                    ]
                )

        self.assertEqual(status, 0, stderr.getvalue())
        self.assertIn("ready: True", stdout.getvalue())
        self.assertIn(
            "live connectors: 1 available, 1 credential-ready", stdout.getvalue()
        )
        self.assertIn("PASS connector:github", stdout.getvalue())

    def test_packaged_defaults_allow_dry_run_outside_repository(self) -> None:
        """An installed package must not depend on the source-tree config path."""

        with private_temporary_directory() as directory:
            root = Path(directory)
            plan_path = root / "plan.json"
            plan_path.write_text(
                __import__("json").dumps(
                    build_weekly_status_plan().to_dict(),
                    default=str,
                ),
                encoding="utf-8",
            )
            stdout = StringIO()
            stderr = StringIO()
            original = Path.cwd()
            try:
                os.chdir(root)
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    status = main(
                        [
                            "run",
                            str(plan_path),
                            "--database",
                            str(root / "audit.sqlite3"),
                        ]
                    )
            finally:
                os.chdir(original)
            self.assertEqual(status, 0, stderr.getvalue())
            self.assertIn("mode: dry-run", stdout.getvalue())

    def test_packaged_integrations_support_default_discovery(self) -> None:
        """Default discovery should show available connectors needing credentials."""

        with private_temporary_directory() as directory:
            root = Path(directory)
            stdout = StringIO()
            stderr = StringIO()
            original = Path.cwd()
            try:
                os.chdir(root)
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    status = main(["discover"])
            finally:
                os.chdir(original)
            self.assertEqual(status, 0, stderr.getvalue())
            self.assertIn("missing_environment", stdout.getvalue())
            self.assertIn("jira", stdout.getvalue())

    def test_github_repositories_completes_read_only_onboarding_in_memory(
        self,
    ) -> None:
        token = "legacy-github-token-canary"
        repository = {
            "id": 1,
            "node_id": "R_1",
            "name": "MasterAgent",
            "full_name": "RoryGlenn/MasterAgent",
            "owner": {"login": "RoryGlenn"},
            "private": True,
            "visibility": "private",
            "default_branch": "main",
            "topics": ["agents"],
            "updated_at": "2026-08-15T10:00:00Z",
            "pushed_at": "2026-08-15T09:00:00Z",
            "html_url": "https://github.com/RoryGlenn/MasterAgent",
        }
        transport = ScriptedTransport()
        transport.add_json("GET", "/user", {"login": "RoryGlenn", "id": 42})
        transport.add_json("GET", "/user/repos", [repository])

        with private_temporary_directory() as directory:
            root = Path(directory)
            credentials = root / "github.json"
            original = json.dumps({"github": token})
            credentials.write_text(original, encoding="utf-8")
            credentials.chmod(0o600)
            output = root / "repositories.json"
            stdout = StringIO()
            with (
                patch.dict(
                    os.environ,
                    {"MASTER_AGENT_GITHUB_TOKEN": "ambient-token-is-ignored"},
                    clear=True,
                ),
                redirect_stdout(stdout),
            ):
                status = _github_repositories(
                    credentials_file=credentials,
                    limit=100,
                    visibility="all",
                    output=output,
                    transport=transport,
                )

            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(credentials.read_text(encoding="utf-8"), original)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

        self.assertEqual(status, 0)
        self.assertEqual(payload["authenticated_user"]["login"], "RoryGlenn")
        self.assertEqual(
            payload["repositories"][0]["full_name"],
            "RoryGlenn/MasterAgent",
        )
        self.assertTrue(payload["verified"])
        self.assertIn("GitHub account: RoryGlenn", stdout.getvalue())
        self.assertIn("RoryGlenn/MasterAgent", stdout.getvalue())
        self.assertEqual(len(transport.requests), 3)
        self.assertTrue(
            all(
                request.headers["Authorization"] == f"Bearer {token}"
                for request in transport.requests
            )
        )
        self.assertNotIn(token, stdout.getvalue())

    def test_github_repositories_lists_public_user_without_credentials(self) -> None:
        username = "rahul-aravind-opti"
        ambient_token = "ambient-token-must-not-be-sent"
        repository = {
            "id": 7,
            "node_id": "R_7",
            "name": "crossmint-challenge",
            "full_name": f"{username}/crossmint-challenge",
            "owner": {"login": username},
            "private": False,
            "visibility": "public",
            "fork": False,
            "archived": False,
            "disabled": False,
            "default_branch": "main",
            "topics": [],
            "updated_at": "2025-11-08T10:00:00Z",
            "pushed_at": "2025-11-08T09:00:00Z",
            "html_url": f"https://github.com/{username}/crossmint-challenge",
        }
        transport = ScriptedTransport()
        transport.add_json("GET", f"/users/{username}/repos", [repository])

        with private_temporary_directory() as directory:
            output = Path(directory) / "public-repositories.json"
            stdout = StringIO()
            with (
                patch.dict(
                    os.environ,
                    {"MASTER_AGENT_GITHUB_TOKEN": ambient_token},
                    clear=True,
                ),
                redirect_stdout(stdout),
            ):
                status = _github_repositories(
                    credentials_file=None,
                    limit=100,
                    visibility=None,
                    output=output,
                    username=username,
                    transport=transport,
                )

            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

        self.assertEqual(status, 0)
        self.assertEqual(payload["requested_user"]["login"], username)
        self.assertEqual(payload["requested_user"]["access"], "anonymous_public")
        self.assertEqual(
            payload["repositories"][0]["full_name"],
            f"{username}/crossmint-challenge",
        )
        self.assertTrue(payload["verified"])
        self.assertNotIn("authenticated_user", payload)
        self.assertIn(f"GitHub public user: {username}", stdout.getvalue())
        self.assertEqual(len(transport.requests), 2)
        self.assertTrue(
            all(
                "Authorization" not in request.headers for request in transport.requests
            )
        )
        self.assertNotIn(ambient_token, stdout.getvalue())

    def test_github_public_user_rejects_credentials_and_nonpublic_visibility(
        self,
    ) -> None:
        with self.assertRaisesRegex(
            ConfigurationError,
            "not accepted with --username",
        ):
            _github_repositories(
                credentials_file=Path("/unused/private-token.json"),
                limit=100,
                visibility=None,
                output=None,
                username="rahul-aravind-opti",
            )

        with self.assertRaisesRegex(ConfigurationError, "public repositories only"):
            _github_repositories(
                credentials_file=None,
                limit=100,
                visibility="private",
                output=None,
                username="rahul-aravind-opti",
            )

    def test_bitbucket_repositories_lists_public_workspace_anonymously(self) -> None:
        workspace = "public-workspace"
        ambient_token = "ambient-bitbucket-token-must-not-be-sent"
        repository = {
            "uuid": "{repo-1}",
            "name": "public-project",
            "slug": "public-project",
            "is_private": False,
            "links": {
                "html": {"href": f"https://bitbucket.org/{workspace}/public-project"}
            },
        }
        transport = ScriptedTransport()
        transport.add_json(
            "GET",
            f"/2.0/repositories/{workspace}",
            {"values": [repository], "next": None},
        )

        with private_temporary_directory() as directory:
            output = Path(directory) / "public-repositories.json"
            stdout = StringIO()
            with (
                patch.dict(
                    os.environ,
                    {
                        "MASTER_AGENT_BITBUCKET_TOKEN": ambient_token,
                        "MASTER_AGENT_BITBUCKET_USERNAME": "ambient-user",
                    },
                    clear=True,
                ),
                redirect_stdout(stdout),
            ):
                status = _bitbucket_repositories(
                    workspace=workspace,
                    limit=100,
                    output=output,
                    transport=transport,
                )

            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

        self.assertEqual(status, 0)
        self.assertEqual(payload["query"]["workspace"], workspace)
        self.assertEqual(payload["query"]["visibility"], "public")
        self.assertEqual(payload["repositories"][0]["slug"], "public-project")
        self.assertTrue(payload["verified"])
        self.assertIn(f"Bitbucket public workspace: {workspace}", stdout.getvalue())
        self.assertEqual(len(transport.requests), 2)
        self.assertTrue(
            all(
                "Authorization" not in request.headers for request in transport.requests
            )
        )
        self.assertNotIn(ambient_token, stdout.getvalue())

    def test_github_repositories_reports_missing_credential_without_network(
        self,
    ) -> None:
        stderr = StringIO()
        with (
            patch.dict(os.environ, {}, clear=True),
            redirect_stdout(StringIO()),
            redirect_stderr(stderr),
        ):
            status = main(["github-repositories"])

        self.assertEqual(status, 1)
        self.assertIn("MASTER_AGENT_GITHUB_TOKEN", stderr.getvalue())

    def test_connect_enables_github_only_in_memory_and_prefers_explicit_store(
        self,
    ) -> None:
        token = "provider-github-token-canary"
        transport = ScriptedTransport()
        transport.add_json("GET", "/user", {"login": "RoryGlenn", "id": 42})

        with private_temporary_directory() as directory:
            root = Path(directory)
            credentials = root / "providers.json"
            original = json.dumps({"github": token})
            credentials.write_text(original, encoding="utf-8")
            credentials.chmod(0o600)
            output = root / "connection.json"
            stdout = StringIO()
            with (
                patch.dict(
                    os.environ,
                    {"MASTER_AGENT_GITHUB_TOKEN": "ambient-token-is-ignored"},
                    clear=True,
                ),
                redirect_stdout(stdout),
            ):
                status = _connect(
                    integrations_path=None,
                    governance_path=None,
                    credentials_file=credentials,
                    systems={"github"},
                    output=output,
                    transport=transport,
                )

            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(credentials.read_text(encoding="utf-8"), original)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

        self.assertEqual(status, 0)
        self.assertFalse(payload["persistent_configuration_changed"])
        self.assertEqual(payload["records"][0]["status"], "reachable")
        self.assertEqual(payload["records"][0]["probe"]["user_id"], 42)
        self.assertIn("connected: github", stdout.getvalue())
        self.assertEqual(len(transport.requests), 1)
        self.assertEqual(
            transport.requests[0].headers["Authorization"],
            f"Bearer {token}",
        )
        self.assertNotIn(token, stdout.getvalue())

    def test_connect_infers_friendly_jira_credentials_without_persisting_config(
        self,
    ) -> None:
        username = "operator@example.test"
        token = "provider-jira-token-canary"
        transport = ScriptedTransport()
        transport.add_json(
            "GET",
            "/rest/api/3/serverInfo",
            {
                "baseUrl": "https://tenant.atlassian.net",
                "version": "1001.0.0",
                "deploymentType": "Cloud",
            },
        )

        with private_temporary_directory() as directory:
            root = Path(directory)
            integrations = root / "integrations.toml"
            original_config = (
                "[connectors.jira]\n"
                "enabled = false\n"
                'deployment = "cloud"\n'
                'base_url = "https://tenant.atlassian.net"\n'
                'auth_mode = "basic"\n'
                'username_env = "MASTER_AGENT_JIRA_USERNAME"\n'
                'secret_env = "MASTER_AGENT_JIRA_TOKEN"\n'
            )
            integrations.write_text(original_config, encoding="utf-8")
            credentials = root / "providers.json"
            original_credentials = json.dumps(
                {"jiraLoginEmail": username, "myJiraApiToken": token}
            )
            credentials.write_text(original_credentials, encoding="utf-8")
            credentials.chmod(0o600)
            stdout = StringIO()
            with redirect_stdout(stdout):
                status = _connect(
                    integrations_path=integrations,
                    governance_path=None,
                    credentials_file=credentials,
                    systems={"jira"},
                    output=None,
                    transport=transport,
                )

            self.assertEqual(integrations.read_text(encoding="utf-8"), original_config)
            self.assertEqual(
                credentials.read_text(encoding="utf-8"),
                original_credentials,
            )

        self.assertEqual(status, 0)
        self.assertIn("connected: jira", stdout.getvalue())
        self.assertEqual(len(transport.requests), 1)
        authorization = transport.requests[0].headers["Authorization"]
        self.assertTrue(authorization.startswith("Basic "))
        self.assertNotIn(username, authorization)
        self.assertNotIn(token, authorization)
        self.assertNotIn(token, stdout.getvalue())

    def test_connect_reuses_jira_atlassian_credentials_for_confluence_url(
        self,
    ) -> None:
        email = "operator@example.test"
        token = "shared-atlassian-token-canary"
        transport = ScriptedTransport()
        transport.add_json(
            "GET",
            "/wiki/rest/api/content/search",
            {"results": []},
            host="tenant.atlassian.net",
        )

        with private_temporary_directory() as directory:
            credentials = Path(directory) / "tokens.json"
            original = json.dumps(
                {
                    "schema": "master-agent/credential-store@1",
                    "credentials": {
                        "JIRA_EMAIL": email,
                        "MASTER_AGENT_JIRA_TOKEN": token,
                    },
                }
            )
            credentials.write_text(original, encoding="utf-8")
            credentials.chmod(0o600)
            stdout = StringIO()
            with redirect_stdout(stdout):
                status = _connect(
                    integrations_path=None,
                    governance_path=None,
                    credentials_file=credentials,
                    systems={"confluence"},
                    output=None,
                    transport=transport,
                    connector_urls=(
                        "confluence=https://tenant.atlassian.net/wiki/spaces",
                    ),
                )

            self.assertEqual(credentials.read_text(encoding="utf-8"), original)

        self.assertEqual(status, 0)
        self.assertIn("connected: confluence", stdout.getvalue())
        self.assertNotIn(token, stdout.getvalue())
        self.assertEqual(len(transport.requests), 1)
        request = transport.requests[0]
        self.assertTrue(
            request.url.startswith(
                "https://tenant.atlassian.net/wiki/rest/api/content/search"
            )
        )
        expected = base64.b64encode(f"{email}:{token}".encode()).decode()
        self.assertEqual(request.headers["Authorization"], f"Basic {expected}")

    def test_connect_prefers_explicit_confluence_credentials_over_jira_fallback(
        self,
    ) -> None:
        jira_token = "jira-labelled-token-canary"
        confluence_email = "confluence-operator@example.test"
        confluence_token = "explicit-confluence-token-canary"
        transport = ScriptedTransport()
        transport.add_json(
            "GET",
            "/wiki/rest/api/content/search",
            {"results": []},
            host="tenant.atlassian.net",
        )

        with private_temporary_directory() as directory:
            credentials = Path(directory) / "tokens.json"
            credentials.write_text(
                json.dumps(
                    {
                        "schema": "master-agent/credential-store@1",
                        "credentials": {
                            "JIRA_EMAIL": "jira-operator@example.test",
                            "MASTER_AGENT_JIRA_TOKEN": jira_token,
                            "MASTER_AGENT_CONFLUENCE_USERNAME": confluence_email,
                            "MASTER_AGENT_CONFLUENCE_TOKEN": confluence_token,
                        },
                    }
                ),
                encoding="utf-8",
            )
            credentials.chmod(0o600)
            with redirect_stdout(StringIO()):
                status = _connect(
                    integrations_path=None,
                    governance_path=None,
                    credentials_file=credentials,
                    systems={"confluence"},
                    output=None,
                    transport=transport,
                    connector_urls=(
                        "confluence=https://tenant.atlassian.net/wiki/spaces/ENG",
                    ),
                )

        self.assertEqual(status, 0)
        expected = base64.b64encode(
            f"{confluence_email}:{confluence_token}".encode()
        ).decode()
        self.assertEqual(
            transport.requests[0].headers["Authorization"], f"Basic {expected}"
        )

    def test_connect_reuses_confluence_atlassian_credentials_for_jira(self) -> None:
        email = "operator@example.test"
        token = "confluence-labelled-token-canary"
        transport = ScriptedTransport()
        transport.add_json(
            "GET",
            "/rest/api/3/serverInfo",
            {
                "baseUrl": "https://tenant.atlassian.net",
                "version": "1001.0.0",
                "deploymentType": "Cloud",
            },
            host="tenant.atlassian.net",
        )

        with private_temporary_directory() as directory:
            credentials = Path(directory) / "tokens.json"
            credentials.write_text(
                json.dumps(
                    {
                        "schema": "master-agent/credential-store@1",
                        "credentials": {
                            "MASTER_AGENT_CONFLUENCE_USERNAME": email,
                            "MASTER_AGENT_CONFLUENCE_TOKEN": token,
                        },
                    }
                ),
                encoding="utf-8",
            )
            credentials.chmod(0o600)
            with redirect_stdout(StringIO()):
                status = _connect(
                    integrations_path=None,
                    governance_path=None,
                    credentials_file=credentials,
                    systems={"jira"},
                    output=None,
                    transport=transport,
                    connector_urls=(
                        "jira=https://tenant.atlassian.net/jira/software/projects/ENG",
                    ),
                )

        self.assertEqual(status, 0)
        self.assertEqual(len(transport.requests), 1)
        expected = base64.b64encode(f"{email}:{token}".encode()).decode()
        self.assertEqual(
            transport.requests[0].headers["Authorization"], f"Basic {expected}"
        )

    def test_connect_does_not_reuse_atlassian_credentials_for_data_center(
        self,
    ) -> None:
        transport = ScriptedTransport()
        with private_temporary_directory() as directory:
            root = Path(directory)
            integrations = root / "integrations.toml"
            integrations.write_text(
                """
[connectors.jira]
enabled = true
deployment = "cloud"
base_url = "https://tenant.atlassian.net"
auth_mode = "basic"
username_env = "MASTER_AGENT_JIRA_USERNAME"
secret_env = "MASTER_AGENT_JIRA_TOKEN"

[connectors.confluence]
enabled = true
deployment = "data_center"
base_url = "https://confluence.example.test"
auth_mode = "basic"
username_env = "MASTER_AGENT_CONFLUENCE_USERNAME"
secret_env = "MASTER_AGENT_CONFLUENCE_TOKEN"
""".strip()
                + "\n",
                encoding="utf-8",
            )
            credentials = root / "tokens.json"
            credentials.write_text(
                json.dumps(
                    {
                        "schema": "master-agent/credential-store@1",
                        "credentials": {
                            "JIRA_EMAIL": "operator@example.test",
                            "MASTER_AGENT_JIRA_TOKEN": "jira-token-canary",
                        },
                    }
                ),
                encoding="utf-8",
            )
            credentials.chmod(0o600)

            with redirect_stdout(StringIO()):
                status = _connect(
                    integrations_path=integrations,
                    governance_path=None,
                    credentials_file=credentials,
                    systems={"confluence"},
                    output=None,
                    transport=transport,
                )

        self.assertEqual(status, 2)
        self.assertEqual(transport.requests, [])

    def test_connect_rejects_unsafe_or_unselected_connector_urls(self) -> None:
        scenarios = {
            "non-HTTPS": (
                "confluence=http://tenant.atlassian.net/wiki/spaces",
                "HTTPS",
            ),
            "credential-bearing": (
                "confluence=https://user:secret@tenant.atlassian.net/wiki/spaces",
                "must not contain credentials",
            ),
            "foreign origin": (
                "confluence=https://tenant.atlassian.net.example.test/wiki/spaces",
                "atlassian.net tenant",
            ),
            "unselected": (
                "jira=https://tenant.atlassian.net/jira/software",
                "unselected connector",
            ),
        }
        for name, (connector_url, message) in scenarios.items():
            with self.subTest(name=name):
                transport = ScriptedTransport()
                with self.assertRaisesRegex(ConfigurationError, message):
                    _connect(
                        integrations_path=None,
                        governance_path=None,
                        credentials_file=None,
                        systems={"confluence"},
                        output=None,
                        transport=transport,
                        connector_urls=(connector_url,),
                    )
                self.assertEqual(transport.requests, [])

        with self.assertRaisesRegex(ConfigurationError, "repeats connector"):
            _connect(
                integrations_path=None,
                governance_path=None,
                credentials_file=None,
                systems={"confluence"},
                output=None,
                connector_urls=(
                    "confluence=https://first.atlassian.net/wiki/spaces",
                    "confluence=https://second.atlassian.net/wiki/spaces",
                ),
            )

        with private_temporary_directory() as directory:
            integrations = Path(directory) / "integrations.toml"
            integrations.write_text(
                """
[connectors.confluence]
enabled = true
deployment = "data_center"
base_url = "https://confluence.example.test"
auth_mode = "none"
""".strip()
                + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ConfigurationError, "Data Center"):
                _connect(
                    integrations_path=integrations,
                    governance_path=None,
                    credentials_file=None,
                    systems={"confluence"},
                    output=None,
                    connector_urls=(
                        "confluence=https://tenant.atlassian.net/wiki/spaces",
                    ),
                )

    def test_connect_rejects_placeholder_provider_before_network(self) -> None:
        transport = ScriptedTransport()
        with self.assertRaisesRegex(ConfigurationError, "placeholder provider URL"):
            _connect(
                integrations_path=None,
                governance_path=None,
                credentials_file=None,
                systems={"jira"},
                output=None,
                transport=transport,
            )
        self.assertEqual(transport.requests, [])

    def test_connect_never_uses_a_credential_file_as_its_output(self) -> None:
        token = "provider-github-token-canary"
        transport = ScriptedTransport()
        with private_temporary_directory() as directory:
            credentials = Path(directory) / "providers.json"
            original = json.dumps({"github": token})
            credentials.write_text(original, encoding="utf-8")
            credentials.chmod(0o600)

            with self.assertRaisesRegex(ConfigurationError, "must not replace"):
                _connect(
                    integrations_path=None,
                    governance_path=None,
                    credentials_file=credentials,
                    systems={"github"},
                    output=credentials,
                    transport=transport,
                )

            self.assertEqual(credentials.read_text(encoding="utf-8"), original)
        self.assertEqual(transport.requests, [])

    def test_connect_selects_microsoft_environment_token_automatically(self) -> None:
        token = "provider-graph-token-canary"
        transport = ScriptedTransport()
        transport.add_json(
            "GET",
            "/v1.0/me",
            {
                "id": "user-42",
                "displayName": "Rory Glenn",
                "userPrincipalName": "rory@example.test",
            },
        )

        with private_temporary_directory() as directory:
            root = Path(directory)
            credentials = root / "providers.json"
            credentials.write_text(
                json.dumps({"microsoft": token}),
                encoding="utf-8",
            )
            credentials.chmod(0o600)
            stdout = StringIO()
            with redirect_stdout(stdout):
                status = _connect(
                    integrations_path=None,
                    governance_path=None,
                    credentials_file=credentials,
                    systems={"microsoft"},
                    output=None,
                    transport=transport,
                )

        self.assertEqual(status, 0)
        self.assertIn("connected: microsoft", stdout.getvalue())
        self.assertEqual(len(transport.requests), 1)
        self.assertEqual(
            transport.requests[0].headers["Authorization"],
            f"Bearer {token}",
        )
        self.assertNotIn(token, stdout.getvalue())

    def test_connect_enables_explicit_onenote_read_only_in_memory(self) -> None:
        token = "provider-onenote-token-canary"
        transport = ScriptedTransport()
        transport.add_json(
            "GET",
            "/v1.0/me/onenote/notebooks",
            {"value": []},
        )

        with private_temporary_directory() as directory:
            credentials = Path(directory) / "providers.json"
            credentials.write_text(
                json.dumps({"microsoft": {"token": token}}),
                encoding="utf-8",
            )
            credentials.chmod(0o600)
            stdout = StringIO()
            with redirect_stdout(stdout):
                status = _connect(
                    integrations_path=None,
                    governance_path=None,
                    credentials_file=credentials,
                    systems={"onenote"},
                    output=None,
                    transport=transport,
                )

        self.assertEqual(status, 0)
        self.assertIn("connected: onenote", stdout.getvalue())
        self.assertEqual(len(transport.requests), 1)
        self.assertEqual(
            transport.requests[0].headers["Authorization"],
            f"Bearer {token}",
        )

    def test_packaged_defaults_build_communication_plan_outside_repository(
        self,
    ) -> None:
        """Phase 2B planning must work from wheel-packaged safe defaults."""

        with private_temporary_directory() as directory:
            root = Path(directory)
            output = root / "communication-plan.json"
            stdout = StringIO()
            stderr = StringIO()
            original = Path.cwd()
            try:
                os.chdir(root)
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    status = main(
                        [
                            "communication-context-plan",
                            "--output",
                            str(output),
                        ]
                    )
            finally:
                os.chdir(original)
            self.assertEqual(status, 0, stderr.getvalue())
            payload = __import__("json").loads(output.read_text(encoding="utf-8"))
            self.assertEqual(len(payload["actions"]), 4)
            self.assertTrue(
                all(action["risk"] == "read_only" for action in payload["actions"])
            )
            self.assertIn("plan fingerprint", stdout.getvalue())

    def test_packaged_identity_resolves_delegated_microsoft_user(self) -> None:
        """The default identity registry should resolve Rory to Graph ``me``."""

        with private_temporary_directory() as directory:
            root = Path(directory)
            stdout = StringIO()
            stderr = StringIO()
            original = Path.cwd()
            try:
                os.chdir(root)
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    status = main(
                        [
                            "identity-resolve",
                            "Rory",
                            "--system",
                            "microsoft",
                        ]
                    )
            finally:
                os.chdir(original)
            self.assertEqual(status, 0, stderr.getvalue())
            self.assertIn("microsoft: me", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()

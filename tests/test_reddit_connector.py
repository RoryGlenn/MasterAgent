"""Contract tests for bounded Reddit reads and OAuth refresh."""

from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from master_agent.auth import AuthMode, ResolvedAuth
from master_agent.canonical import SourceOfTruthRegistry
from master_agent.capabilities import CapabilityCatalog
from master_agent.config import (
    DeploymentType,
    IntegrationConfig,
    ResolvedConnectorConfig,
)
from master_agent.connectors.reddit import RedditConnector
from master_agent.direct_read import DirectReadSession
from master_agent.errors import AuthenticationError
from master_agent.governance import GovernanceProfile
from master_agent.models import (
    AgentAction,
    AuthoritySource,
    ChangePlan,
    ConnectorExecutionBinding,
    DataClassification,
    ResourceRef,
    RiskLevel,
)
from master_agent.oauth import (
    AccessToken,
    RedditRefreshTokenProvider,
    StaticTokenProvider,
)
from master_agent.policy import PolicyConfig, PolicyEngine
from tests.fakes import ExpectedRequest, QueueTransport

ROOT = Path(__file__).resolve().parents[1]


class RedditConnectorTests(unittest.TestCase):
    def test_search_is_bounded_normalized_and_uses_reviewed_headers(self) -> None:
        transport = QueueTransport(
            ExpectedRequest(
                "GET",
                "/r/python/search?",
                _listing(_post()),
            )
        )
        connector = RedditConnector(_config(), transport=transport)

        result = connector.execute(
            _action(
                "reddit.search",
                "search",
                {"query": "typing", "subreddit": "python", "limit": 1},
            )
        )

        self.assertEqual(result.after["schema"], "master-agent/reddit-search@1")
        self.assertEqual(result.after["returned"], 1)
        self.assertEqual(result.after["items"][0]["fullname"], "t3_abc123")
        self.assertEqual(
            transport.requests[0]["headers"]["User-Agent"],
            "MasterAgent/1.0 test",
        )
        self.assertEqual(
            transport.requests[0]["headers"]["Authorization"], "Bearer access-marker"
        )
        self.assertNotIn("access-marker", str(result.after))
        transport.assert_drained()

    def test_principal_attestation_binds_immutable_id_and_scopes(self) -> None:
        transport = QueueTransport(
            ExpectedRequest("GET", "/api/v1/me", {"id": "stable123", "name": "rory"})
        )
        principal = RedditConnector(_config(), transport=transport).attest_principal()

        self.assertEqual(principal.identity, "reddit:user:stable123")
        self.assertEqual(principal.scopes, ("identity", "read"))
        self.assertNotIn("access-marker", repr(principal))
        transport.assert_drained()

    def test_inbox_accepts_reddit_message_fullnames(self) -> None:
        transport = QueueTransport(
            ExpectedRequest(
                "GET",
                "/message/inbox?",
                _listing(
                    {
                        "kind": "t4",
                        "data": {
                            "name": "t4_message1",
                            "id": "message1",
                            "author": "sender",
                            "body": "Inbox body",
                            "created_utc": 1770000000.0,
                        },
                    }
                ),
            )
        )
        result = RedditConnector(_config(), transport=transport).execute(
            _action("reddit.inbox.read", "inbox", {"limit": 1})
        )

        self.assertEqual(result.after["items"][0]["fullname"], "t4_message1")
        transport.assert_drained()

    def test_content_read_normalizes_a_canonical_reddit_url(self) -> None:
        transport = QueueTransport(
            ExpectedRequest("GET", "/api/info?", _listing(_post()))
        )
        result = RedditConnector(_config(), transport=transport).execute(
            _action(
                "reddit.content.read",
                "content",
                {
                    "reference": (
                        "https://www.reddit.com/r/python/comments/abc123/typing/"
                    ),
                    "kind": "post",
                },
            )
        )

        self.assertEqual(result.after["query"]["fullname"], "t3_abc123")
        self.assertEqual(result.after["items"][0]["title"], "Typing")
        transport.assert_drained()

    def test_subreddit_rules_are_bounded_and_normalized(self) -> None:
        transport = QueueTransport(
            ExpectedRequest(
                "GET",
                "/r/python/about/rules?",
                {
                    "rules": [
                        {
                            "kind": "all",
                            "short_name": "Be specific",
                            "description": "Include a reproducible example.",
                            "violation_reason": "Missing detail",
                        }
                    ]
                },
            )
        )
        result = RedditConnector(_config(), transport=transport).execute(
            _action(
                "reddit.subreddit.rules.read",
                "python-rules",
                {"subreddit": "python"},
            )
        )

        self.assertEqual(result.after["rules"][0]["short_name"], "Be specific")
        self.assertEqual(result.after["returned"], 1)
        transport.assert_drained()

    def test_authenticated_and_explicit_user_history_paths(self) -> None:
        cases = (
            (
                "reddit.user.submitted.read",
                {"username": "me", "limit": 1},
                (
                    ExpectedRequest(
                        "GET",
                        "/api/v1/me",
                        {"id": "stable123", "name": "rory"},
                    ),
                    ExpectedRequest("GET", "/user/rory/submitted?", _listing(_post())),
                ),
                "rory",
            ),
            (
                "reddit.user.comments.read",
                {"username": "alice", "limit": 1},
                (
                    ExpectedRequest(
                        "GET",
                        "/user/alice/comments?",
                        _listing(_comment()),
                    ),
                ),
                "alice",
            ),
        )
        for capability, parameters, expected, username in cases:
            with self.subTest(capability=capability):
                transport = QueueTransport(*expected)
                result = RedditConnector(_config(), transport=transport).execute(
                    _action(capability, username, parameters)
                )
                self.assertEqual(result.after["query"]["resolved_username"], username)
                self.assertEqual(result.after["returned"], 1)
                transport.assert_drained()

    def test_repository_config_resolves_refresh_credentials_and_attests_identity(
        self,
    ) -> None:
        transport = QueueTransport(
            ExpectedRequest(
                "POST",
                "https://www.reddit.com/api/v1/access_token",
                {
                    "access_token": "resolved-access-marker",
                    "token_type": "bearer",
                    "expires_in": 3600,
                    "scope": "identity read",
                },
            ),
            ExpectedRequest("GET", "/api/v1/me", {"id": "stable123", "name": "rory"}),
        )
        unresolved = IntegrationConfig.from_toml(
            ROOT / "config/integrations.toml"
        ).connector("reddit")
        environ = {
            "MASTER_AGENT_REDDIT_READ_CLIENT_ID": "client-id",
            "MASTER_AGENT_REDDIT_READ_CLIENT_SECRET": "client-secret-marker",
            "MASTER_AGENT_REDDIT_READ_REFRESH_TOKEN": "refresh-marker",
        }
        target = unresolved.capture_execution_target(environ)
        resolved = unresolved.resolve(
            environ,
            auth_transport=transport,
            execution_target=target,
        )

        principal = RedditConnector(resolved, transport=transport).attest_principal()

        self.assertEqual(principal.identity, "reddit:user:stable123")
        self.assertNotIn("refresh-marker", repr(resolved))
        self.assertNotIn("client-secret-marker", repr(resolved))
        transport.assert_drained()

    def test_search_executes_through_the_real_direct_read_boundary(self) -> None:
        transport = QueueTransport(
            ExpectedRequest("GET", "/r/python/search?", _listing(_post())),
            ExpectedRequest("GET", "/r/python/search?", _listing(_post())),
        )
        action = AgentAction(
            capability="reddit.search",
            target=ResourceRef("reddit", "search", "typing"),
            parameters={"query": "typing", "subreddit": "python", "limit": 1},
            risk=RiskLevel.READ_ONLY,
            data_classification=DataClassification.INTERNAL,
            authority_source=AuthoritySource.DIRECT_USER,
            requires_approval=False,
            idempotency_key="reddit:search:typing",
            justification="Read the directly requested Reddit search.",
        )
        session = DirectReadSession(
            catalog=CapabilityCatalog.from_toml(ROOT / "config/capabilities.toml"),
            governance=GovernanceProfile.from_toml(ROOT / "config/governance.toml"),
            policy=PolicyEngine(PolicyConfig.from_toml(ROOT / "config/policy.toml")),
            sources=SourceOfTruthRegistry.from_toml(
                ROOT / "config/sources_of_truth.toml"
            ),
            connector=RedditConnector(_config(), transport=transport),
            execution_binding=ConnectorExecutionBinding(
                system="reddit",
                deployment="cloud",
                config_identity_sha256="a" * 64,
                resolved_base_url="https://oauth.reddit.com",
                resolved_origin="https://oauth.reddit.com",
                authentication_mode="oauth_delegated",
                credential_identity="reddit:user:stable123",
                credential_scopes=("identity", "read"),
            ),
        )

        report = session.execute(
            ChangePlan(
                goal="Search Reddit.", actions=(action,), created_by="direct-user"
            )
        )

        self.assertTrue(report.successful)
        self.assertEqual(report.payloads[0].data["items"][0]["fullname"], "t3_abc123")
        transport.assert_drained()

    def test_refresh_exchange_uses_fixed_origin_basic_auth_and_no_secret_output(
        self,
    ) -> None:
        transport = QueueTransport(
            ExpectedRequest(
                "POST",
                "https://www.reddit.com/api/v1/access_token",
                {
                    "access_token": "new-access-marker",
                    "token_type": "bearer",
                    "expires_in": 3600,
                    "scope": "identity read",
                },
                body_contains="grant_type=refresh_token&refresh_token=refresh-marker",
            )
        )
        provider = RedditRefreshTokenProvider(
            client_id="client-id",
            client_secret="client-secret-marker",
            refresh_token="refresh-marker",
            scopes=("identity", "read"),
            user_agent="MasterAgent/1.0 test",
            transport=transport,
        )

        token = provider.get_token()

        self.assertEqual(token.value, "new-access-marker")
        self.assertEqual(token.scopes, ("identity", "read"))
        self.assertNotIn("client-secret-marker", repr(provider))
        self.assertNotIn("refresh-marker", repr(provider))
        headers = transport.requests[0]["headers"]
        self.assertTrue(headers["Authorization"].startswith("Basic "))
        self.assertNotIn("client-secret-marker", str(headers))
        transport.assert_drained()

    def test_refresh_requires_provider_reported_profile_bounded_scopes(self) -> None:
        cases = (
            (
                {"access_token": "token", "token_type": "bearer"},
                "did not report effective scopes",
            ),
            (
                {
                    "access_token": "token",
                    "token_type": "bearer",
                    "scope": "identity read submit",
                },
                "exceeded the configured credential profile",
            ),
        )
        for response, message in cases:
            with self.subTest(message=message):
                transport = QueueTransport(
                    ExpectedRequest(
                        "POST",
                        "https://www.reddit.com/api/v1/access_token",
                        response,
                    )
                )
                provider = RedditRefreshTokenProvider(
                    client_id="client-id",
                    client_secret="client-secret",
                    refresh_token="refresh-token",
                    scopes=("identity", "read"),
                    user_agent="MasterAgent/1.0 test",
                    transport=transport,
                )
                with self.assertRaisesRegex(AuthenticationError, message):
                    provider.get_token()
                transport.assert_drained()

    def test_reddit_credential_profiles_separate_reads_from_communications(
        self,
    ) -> None:
        read = IntegrationConfig.from_toml(ROOT / "config/integrations.toml").connector(
            "reddit"
        )
        read_environment = {
            "MASTER_AGENT_REDDIT_READ_CLIENT_ID": "read-client",
            "MASTER_AGENT_REDDIT_READ_CLIENT_SECRET": "read-secret",
            "MASTER_AGENT_REDDIT_READ_REFRESH_TOKEN": "read-refresh",
        }

        self.assertEqual(read.configuration_errors(read_environment), ())
        self.assertEqual(read.extra["credential_profile"], "read")
        self.assertNotIn("submit", read.extra["scopes"])
        self.assertNotIn("edit", read.extra["scopes"])

        communication_extra = dict(read.extra)
        communication_extra.update(
            {
                "credential_profile": "communication",
                "client_id_env": "MASTER_AGENT_REDDIT_COMMUNICATION_CLIENT_ID",
                "client_secret_env": (
                    "MASTER_AGENT_REDDIT_COMMUNICATION_CLIENT_SECRET"
                ),
                "refresh_token_env": (
                    "MASTER_AGENT_REDDIT_COMMUNICATION_REFRESH_TOKEN"
                ),
                "scopes": ["identity", "read", "submit"],
                "posts_enabled": True,
            }
        )
        communication = replace(read, extra=communication_extra)
        communication_environment = {
            "MASTER_AGENT_REDDIT_COMMUNICATION_CLIENT_ID": "effect-client",
            "MASTER_AGENT_REDDIT_COMMUNICATION_CLIENT_SECRET": "effect-secret",
            "MASTER_AGENT_REDDIT_COMMUNICATION_REFRESH_TOKEN": "effect-refresh",
        }

        self.assertEqual(
            communication.configuration_errors(communication_environment), ()
        )
        unsafe_read = replace(
            read,
            extra={**dict(read.extra), "posts_enabled": True},
        )
        self.assertIn(
            "Reddit read profile cannot enable provider mutations",
            unsafe_read.configuration_errors(read_environment),
        )


def _config() -> ResolvedConnectorConfig:
    token = AccessToken(
        value="access-marker",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        scopes=("read", "identity"),
    )
    return ResolvedConnectorConfig(
        system="reddit",
        deployment=DeploymentType.CLOUD,
        base_url="https://oauth.reddit.com",
        web_base_url="https://www.reddit.com",
        auth=ResolvedAuth(
            mode=AuthMode.OAUTH_DELEGATED,
            token_provider=StaticTokenProvider(token),
        ),
        max_items=100,
        max_pages=2,
        extra={"user_agent": "MasterAgent/1.0 test"},
        config_identity="a" * 64,
    )


def _action(
    capability: str, resource_id: str, parameters: dict[str, object]
) -> AgentAction:
    return AgentAction(
        capability=capability,
        target=ResourceRef(
            system="reddit", resource_type="reddit", resource_id=resource_id
        ),
        parameters=parameters,
        risk=RiskLevel.READ_ONLY,
        authority_source=AuthoritySource.DIRECT_USER,
        requires_approval=False,
        idempotency_key=f"test:{capability}",
        justification="test Reddit read",
    )


def _listing(*children: dict[str, object]) -> dict[str, object]:
    return {"kind": "Listing", "data": {"children": list(children), "after": None}}


def _post() -> dict[str, object]:
    return {
        "kind": "t3",
        "data": {
            "name": "t3_abc123",
            "id": "abc123",
            "author": "rory",
            "subreddit": "python",
            "title": "Typing",
            "selftext": "Bounded body",
            "permalink": "/r/python/comments/abc123/typing/",
            "url": "https://www.reddit.com/r/python/comments/abc123/typing/",
            "created_utc": 1770000000.0,
            "edited": False,
            "score": 1,
            "num_comments": 0,
        },
    }


def _comment() -> dict[str, object]:
    return {
        "kind": "t1",
        "data": {
            "name": "t1_comment1",
            "id": "comment1",
            "author": "alice",
            "subreddit": "python",
            "body": "A bounded comment.",
            "parent_id": "t3_abc123",
            "permalink": "/r/python/comments/abc123/typing/comment1/",
            "created_utc": 1770000000.0,
            "edited": False,
        },
    }

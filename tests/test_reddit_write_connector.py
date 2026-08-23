"""Contract tests for exact approval-bound Reddit mutations."""

from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta

from master_agent.auth import AuthMode, ResolvedAuth
from master_agent.config import DeploymentType, ResolvedConnectorConfig
from master_agent.connectors.reddit_write import RedditWriteConnector
from master_agent.errors import ConnectorError, RateLimitError
from master_agent.models import AgentAction, AuthoritySource, ResourceRef, RiskLevel
from master_agent.oauth import AccessToken, StaticTokenProvider
from tests.fakes import ExpectedRequest, QueueTransport


class RedditWriteConnectorTests(unittest.TestCase):
    def test_post_sends_exact_approved_fields_and_independently_verifies(self) -> None:
        item = _post()
        transport = QueueTransport(
            ExpectedRequest(
                "POST",
                "/api/submit",
                {"json": {"errors": [], "data": {"name": "t3_abc123"}}},
                body_contains="title=Approved+title",
            ),
            ExpectedRequest("GET", "/api/info?", _listing(item)),
            ExpectedRequest("GET", "/api/info?", _listing(item)),
        )
        connector = RedditWriteConnector(_config(), transport=transport)
        action = _action(
            "reddit.post.create",
            "new-post",
            {"subreddit": "python", "title": "Approved title", "body": "Exact body"},
            RiskLevel.EXTERNAL_COMMUNICATION,
        )

        result = connector.execute(action)
        verification = connector.verify(action, result)

        self.assertEqual(result.after["fullname"], "t3_abc123")
        self.assertTrue(verification.verified)
        self.assertEqual(
            result.connector_reference,
            "https://www.reddit.com/r/python/comments/abc123/approved/",
        )
        self.assertEqual(
            len([r for r in transport.requests if r["method"] == "POST"]), 1
        )
        transport.assert_drained()

    def test_every_mutation_requires_connector_level_approval(self) -> None:
        connector = RedditWriteConnector(_config(), transport=QueueTransport())
        action = _action(
            "reddit.post.create",
            "new-post",
            {"subreddit": "python", "title": "Title", "body": "Body"},
            RiskLevel.EXTERNAL_COMMUNICATION,
            requires_approval=False,
        )
        with self.assertRaisesRegex(ConnectorError, "requires exact approval"):
            connector.execute(action)

    def test_comment_and_reply_normalize_targets_and_return_urls(self) -> None:
        cases = (
            (
                "reddit.comment.create",
                "https://www.reddit.com/r/python/comments/post123/title/",
                "t3_post123",
                "t1_comment1",
            ),
            (
                "reddit.comment.reply",
                ("https://www.reddit.com/r/python/comments/post123/title/parent1/"),
                "t1_parent1",
                "t1_reply1",
            ),
        )
        for capability, reference, parent, created in cases:
            with self.subTest(capability=capability):
                item = _comment(
                    fullname=created,
                    parent_fullname=parent,
                    body="Approved comment",
                )
                transport = QueueTransport(
                    ExpectedRequest(
                        "POST",
                        "/api/comment",
                        {"json": {"errors": [], "data": {"name": created}}},
                        body_contains=f"thing_id={parent}",
                    ),
                    ExpectedRequest("GET", "/api/info?", _listing(item)),
                    ExpectedRequest("GET", "/api/info?", _listing(item)),
                )
                connector = RedditWriteConnector(_config(), transport=transport)
                action = _action(
                    capability,
                    "new-comment",
                    {"parent_fullname": reference, "body": "Approved comment"},
                    RiskLevel.EXTERNAL_COMMUNICATION,
                )

                result = connector.execute(action)
                verification = connector.verify(action, result)

                self.assertEqual(result.after["parent_fullname"], parent)
                self.assertTrue(verification.verified)
                self.assertTrue(result.connector_reference.startswith("https://"))
                transport.assert_drained()

    def test_comment_and_reply_reject_the_wrong_parent_kind_before_network(
        self,
    ) -> None:
        connector = RedditWriteConnector(_config(), transport=QueueTransport())
        cases = (
            ("reddit.comment.create", "t1_parent", "post"),
            ("reddit.comment.reply", "t3_parent", "comment"),
        )
        for capability, parent, expected in cases:
            with self.subTest(capability=capability):
                action = _action(
                    capability,
                    "new-comment",
                    {"parent_fullname": parent, "body": "Approved comment"},
                    RiskLevel.EXTERNAL_COMMUNICATION,
                )
                with self.assertRaisesRegex(
                    ConnectorError, f"must identify a {expected}"
                ):
                    connector.execute(action)

    def test_edit_requires_owned_version_and_independently_verifies(self) -> None:
        before = _comment()
        after = _comment(body="Approved replacement", edited=1770000100.0)
        transport = QueueTransport(
            ExpectedRequest("GET", "/api/info?", _listing(before)),
            ExpectedRequest("GET", "/api/v1/me", {"id": "stable123", "name": "rory"}),
            ExpectedRequest(
                "POST",
                "/api/editusertext",
                {"json": {"errors": [], "data": {}}},
                body_contains="text=Approved+replacement",
            ),
            ExpectedRequest("GET", "/api/info?", _listing(after)),
            ExpectedRequest("GET", "/api/info?", _listing(after)),
        )
        connector = RedditWriteConnector(_config(), transport=transport)
        action = _action(
            "reddit.content.edit",
            "https://www.reddit.com/r/python/comments/parent/post/comment/",
            {"body": "Approved replacement"},
            RiskLevel.EXTERNAL_COMMUNICATION,
            expected_version="1770000000.000000",
        )

        result = connector.execute(action)
        verification = connector.verify(action, result)

        self.assertEqual(result.after["body"], "Approved replacement")
        self.assertTrue(verification.verified)
        transport.assert_drained()

    def test_rate_limit_is_typed_and_write_is_not_retried(self) -> None:
        transport = QueueTransport(
            ExpectedRequest(
                "POST",
                "/api/comment",
                {"message": "slow down"},
                status=429,
                headers={"Retry-After": "12"},
            )
        )
        connector = RedditWriteConnector(_config(), transport=transport)
        action = _action(
            "reddit.comment.reply",
            "new-comment",
            {"parent_fullname": "t1_parent", "body": "Approved reply"},
            RiskLevel.EXTERNAL_COMMUNICATION,
        )

        with self.assertRaises(RateLimitError) as raised:
            connector.execute(action)

        self.assertEqual(raised.exception.retry_after_seconds, 12)
        self.assertEqual(len(transport.requests), 1)
        transport.assert_drained()

    def test_json_rate_limit_is_typed_and_write_is_not_retried(self) -> None:
        transport = QueueTransport(
            ExpectedRequest(
                "POST",
                "/api/comment",
                {
                    "json": {
                        "errors": [
                            [
                                "RATELIMIT",
                                "you are doing that too much; try again in 8 minutes.",
                                "ratelimit",
                            ]
                        ]
                    }
                },
            )
        )
        connector = RedditWriteConnector(_config(), transport=transport)
        action = _action(
            "reddit.comment.reply",
            "new-comment",
            {"parent_fullname": "t1_parent", "body": "Approved reply"},
            RiskLevel.EXTERNAL_COMMUNICATION,
        )

        with self.assertRaises(RateLimitError) as raised:
            connector.execute(action)

        self.assertEqual(str(raised.exception), "Reddit rate limit exceeded")
        self.assertEqual(raised.exception.retry_after_seconds, 480)
        self.assertEqual(len(transport.requests), 1)
        transport.assert_drained()

    def test_delete_requires_owned_versioned_content_and_verifies_absence(self) -> None:
        before = _comment()
        transport = QueueTransport(
            ExpectedRequest("GET", "/api/info?", _listing(before)),
            ExpectedRequest("GET", "/api/v1/me", {"id": "stable123", "name": "rory"}),
            ExpectedRequest("POST", "/api/del", {}),
            ExpectedRequest("GET", "/api/info?", _listing()),
            ExpectedRequest("GET", "/api/info?", _listing()),
        )
        connector = RedditWriteConnector(_config(), transport=transport)
        action = _action(
            "reddit.content.delete",
            "t1_comment",
            {},
            RiskLevel.HIGH_IMPACT,
            expected_version="1770000000.000000",
        )

        result = connector.execute(action)
        verification = connector.verify(action, result)

        self.assertTrue(result.after["deleted"])
        self.assertTrue(verification.verified)
        transport.assert_drained()


def _config() -> ResolvedConnectorConfig:
    token = AccessToken(
        value="access-marker",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        scopes=("identity", "read", "submit", "edit"),
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
        extra={
            "user_agent": "MasterAgent/1.0 test",
            "posts_enabled": True,
            "comments_enabled": True,
            "edits_enabled": True,
            "deletes_enabled": True,
        },
    )


def _action(
    capability: str,
    resource_id: str,
    parameters: dict[str, object],
    risk: RiskLevel,
    *,
    requires_approval: bool = True,
    expected_version: str | None = None,
) -> AgentAction:
    return AgentAction(
        capability=capability,
        target=ResourceRef(
            system="reddit",
            resource_type="reddit",
            resource_id=resource_id,
            expected_version=expected_version,
        ),
        parameters=parameters,
        risk=risk,
        authority_source=AuthoritySource.DIRECT_USER,
        requires_approval=requires_approval,
        idempotency_key=f"test:{capability}",
        justification="test Reddit mutation",
    )


def _listing(*children: dict[str, object]) -> dict[str, object]:
    return {"kind": "Listing", "data": {"children": list(children), "after": None}}


def _post() -> dict[str, object]:
    return {
        "kind": "t3",
        "data": {
            "name": "t3_abc123",
            "author": "rory",
            "subreddit": "python",
            "title": "Approved title",
            "selftext": "Exact body",
            "url": "https://www.reddit.com/r/python/comments/abc123/approved/",
            "permalink": "/r/python/comments/abc123/approved/",
            "created_utc": 1770000000.0,
            "edited": False,
        },
    }


def _comment(
    *,
    fullname: str = "t1_comment",
    parent_fullname: str = "t3_parent",
    body: str = "Prior body",
    edited: bool | float = False,
) -> dict[str, object]:
    return {
        "kind": "t1",
        "data": {
            "name": fullname,
            "author": "rory",
            "subreddit": "python",
            "body": body,
            "parent_id": parent_fullname,
            "permalink": "/r/python/comments/parent/post/comment/",
            "created_utc": 1770000000.0,
            "edited": edited,
        },
    }

"""Contract tests for bounded GitHub writes and administration."""

from __future__ import annotations

import unittest

from master_agent.auth import AuthMode, ResolvedAuth
from master_agent.config import DeploymentType, ResolvedConnectorConfig
from master_agent.connectors.github_write import (
    GitHubAdminConnector,
    GitHubWriteConnector,
)
from master_agent.errors import ConnectorError
from master_agent.models import (
    AgentAction,
    AuthoritySource,
    ResourceRef,
    RiskLevel,
)
from tests.fakes import ExpectedRequest, QueueTransport


class GitHubWriteConnectorTests(unittest.TestCase):
    def test_issue_create_is_path_bound_and_independently_verified(self) -> None:
        created = _issue(17)
        closed = {**created, "state": "closed", "updated_at": "2026-08-15T10:02:00Z"}
        transport = QueueTransport(
            ExpectedRequest(
                "POST",
                "/repos/RoryGlenn/MasterAgent/issues",
                created,
                body_contains='"title":"Bounded issue"',
            ),
            ExpectedRequest("GET", "/issues/17", created),
            ExpectedRequest("GET", "/issues/17", created),
            ExpectedRequest("GET", "/issues/17", created),
            ExpectedRequest(
                "PATCH", "/issues/17", closed, body_contains='"state":"closed"'
            ),
            ExpectedRequest("GET", "/issues/17", closed),
            ExpectedRequest("GET", "/issues/17", closed),
        )
        connector = GitHubWriteConnector(_config(), transport=transport)
        action = _action(
            "github.issue.create",
            RiskLevel.REVERSIBLE_WRITE,
            parameters={
                "owner": "RoryGlenn",
                "repository": "MasterAgent",
                "title": "Bounded issue",
                "body": "Exact body",
            },
        )

        result = connector.execute(action)
        verification = connector.verify(action, result)
        compensation = connector.compensate(action, result)
        compensation_verification = connector.verify_compensation(
            action, result, compensation
        )

        self.assertEqual(result.after["number"], 17)
        self.assertEqual(result.compensation["kind"], "close_issue")
        self.assertTrue(verification.verified)
        self.assertTrue(compensation_verification.verified)
        transport.assert_drained()

    def test_pull_request_create_rejects_unsafe_branch_before_http(self) -> None:
        connector = GitHubWriteConnector(_config(), transport=QueueTransport())
        with self.assertRaisesRegex(ConnectorError, "unsafe branch"):
            connector.execute(
                _action(
                    "github.pull_request.create",
                    RiskLevel.REVERSIBLE_WRITE,
                    parameters={
                        "owner": "RoryGlenn",
                        "repository": "MasterAgent",
                        "title": "Unsafe",
                        "head": "../main",
                        "base": "main",
                    },
                )
            )


class GitHubAdminConnectorTests(unittest.TestCase):
    def test_repository_settings_are_version_checked_and_verified(self) -> None:
        before = _repository_settings(has_issues=True, allow_auto_merge=False)
        after = _repository_settings(has_issues=False, allow_auto_merge=True)
        transport = QueueTransport(
            ExpectedRequest("GET", "/repos/RoryGlenn/MasterAgent", before),
            ExpectedRequest(
                "PATCH",
                "/repos/RoryGlenn/MasterAgent",
                after,
                body_contains='"has_issues":false',
            ),
            ExpectedRequest("GET", "/repos/RoryGlenn/MasterAgent", after),
            ExpectedRequest("GET", "/repos/RoryGlenn/MasterAgent", after),
            ExpectedRequest("GET", "/repos/RoryGlenn/MasterAgent", after),
            ExpectedRequest(
                "PATCH",
                "/repos/RoryGlenn/MasterAgent",
                before,
                body_contains='"has_issues":true',
            ),
            ExpectedRequest("GET", "/repos/RoryGlenn/MasterAgent", before),
            ExpectedRequest("GET", "/repos/RoryGlenn/MasterAgent", before),
        )
        connector = GitHubAdminConnector(_config(), transport=transport)
        action = _action(
            "github.repository.settings.update",
            RiskLevel.REVERSIBLE_WRITE,
            expected_version="2026-08-15T10:00:00Z",
            parameters={
                "owner": "RoryGlenn",
                "repository": "MasterAgent",
                "settings": {"has_issues": False, "allow_auto_merge": True},
            },
        )

        result = connector.execute(action)
        verification = connector.verify(action, result)
        compensation = connector.compensate(action, result)
        compensation_verification = connector.verify_compensation(
            action, result, compensation
        )

        self.assertEqual(
            result.before["settings"],
            {"has_issues": True, "allow_auto_merge": False},
        )
        self.assertEqual(result.compensation["kind"], "restore_repository_settings")
        self.assertTrue(verification.verified)
        self.assertTrue(compensation_verification.verified)
        transport.assert_drained()

    def test_collaborator_admin_updates_only_an_existing_builtin_role(self) -> None:
        transport = QueueTransport(
            ExpectedRequest("GET", "/collaborators/alice/permission", _role("pull")),
            ExpectedRequest(
                "PUT",
                "/collaborators/alice",
                b"",
                status=204,
                body_contains='"permission":"push"',
            ),
            ExpectedRequest("GET", "/collaborators/alice/permission", _role("push")),
        )
        connector = GitHubAdminConnector(_config(), transport=transport)
        result = connector.execute(
            _action(
                "github.collaborator.access.update",
                RiskLevel.HIGH_IMPACT,
                parameters={
                    "owner": "RoryGlenn",
                    "repository": "MasterAgent",
                    "username": "alice",
                    "role": "push",
                },
            )
        )

        self.assertEqual(result.after["role_name"], "push")
        self.assertEqual(result.compensation["mode"], "manual")
        transport.assert_drained()

    def test_collaborator_admin_rejects_invitation_and_custom_role(self) -> None:
        connector = GitHubAdminConnector(_config(), transport=QueueTransport())
        with self.assertRaisesRegex(ConnectorError, "must be pull"):
            connector.execute(
                _action(
                    "github.collaborator.access.update",
                    RiskLevel.HIGH_IMPACT,
                    parameters={
                        "owner": "RoryGlenn",
                        "repository": "MasterAgent",
                        "username": "alice",
                        "role": "custom-role",
                    },
                )
            )

        transport = QueueTransport(
            ExpectedRequest("GET", "/collaborators/alice/permission", _role("none"))
        )
        connector = GitHubAdminConnector(_config(), transport=transport)
        with self.assertRaisesRegex(ConnectorError, "existing collaborator"):
            connector.execute(
                _action(
                    "github.collaborator.access.update",
                    RiskLevel.HIGH_IMPACT,
                    parameters={
                        "owner": "RoryGlenn",
                        "repository": "MasterAgent",
                        "username": "alice",
                        "role": "push",
                    },
                )
            )
        transport.assert_drained()

    def test_collaborator_race_cancels_provider_invitation_and_fails(self) -> None:
        transport = QueueTransport(
            ExpectedRequest("GET", "/collaborators/alice/permission", _role("pull")),
            ExpectedRequest(
                "PUT",
                "/collaborators/alice",
                {"id": 91},
                status=201,
            ),
            ExpectedRequest("DELETE", "/invitations/91", b"", status=204),
        )
        connector = GitHubAdminConnector(_config(), transport=transport)
        with self.assertRaisesRegex(ConnectorError, "invitation was cancelled"):
            connector.execute(
                _action(
                    "github.collaborator.access.update",
                    RiskLevel.HIGH_IMPACT,
                    parameters={
                        "owner": "RoryGlenn",
                        "repository": "MasterAgent",
                        "username": "alice",
                        "role": "push",
                    },
                )
            )
        transport.assert_drained()


def _config() -> ResolvedConnectorConfig:
    return ResolvedConnectorConfig(
        system="github",
        deployment=DeploymentType.CLOUD,
        base_url="https://api.github.com",
        auth=ResolvedAuth(mode=AuthMode.BEARER, secret="github-token"),
        max_pages=10,
        max_items=100,
    )


def _action(
    capability: str,
    risk: RiskLevel,
    *,
    parameters: dict[str, object],
    expected_version: str | None = None,
) -> AgentAction:
    return AgentAction(
        capability=capability,
        target=ResourceRef("github", "test", "RoryGlenn/MasterAgent", expected_version),
        parameters=parameters,
        risk=risk,
        authority_source=AuthoritySource.DIRECT_USER,
        requires_approval=True,
        idempotency_key=f"test:{capability}",
        justification="GitHub mutation contract test.",
    )


def _issue(number: int) -> dict[str, object]:
    return {
        "number": number,
        "title": "Bounded issue",
        "body": "Exact body",
        "state": "open",
        "updated_at": "2026-08-15T10:01:00Z",
        "html_url": f"https://github.com/RoryGlenn/MasterAgent/issues/{number}",
    }


def _repository_settings(
    *, has_issues: bool, allow_auto_merge: bool
) -> dict[str, object]:
    return {
        "full_name": "RoryGlenn/MasterAgent",
        "updated_at": "2026-08-15T10:00:00Z",
        "has_issues": has_issues,
        "allow_auto_merge": allow_auto_merge,
    }


def _role(role: str) -> dict[str, object]:
    return {
        "permission": "write" if role == "push" else role,
        "role_name": role,
        "user": {"login": "alice"},
    }


if __name__ == "__main__":
    unittest.main()

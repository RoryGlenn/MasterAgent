"""Contract tests for Jira, Confluence, and Bitbucket connectors."""

import unittest
from dataclasses import replace
from urllib.parse import urlparse

from master_agent.config import DeploymentType
from master_agent.connectors.bitbucket import BitbucketConnector
from master_agent.connectors.confluence import ConfluenceConnector
from master_agent.connectors.jira import JiraConnector
from master_agent.errors import ConnectorError, ConnectorHttpError
from tests.fakes import ScriptedTransport
from tests.helpers import read_action, resolved_config


class JiraConnectorTests(unittest.TestCase):
    """Verify deployment-specific Jira search behavior."""

    def test_cloud_uses_enhanced_jql_search_and_normalizes_blocker(self) -> None:
        transport = ScriptedTransport()
        transport.add_json(
            "POST",
            "/rest/api/3/search/jql",
            {
                "issues": [_jira_issue()],
                "total": 1,
                "isLast": True,
            },
        )
        connector = JiraConnector(
            resolved_config("jira", base_url="https://acme.atlassian.net"),
            transport=transport,
        )
        action = read_action(
            "jira.issue.search",
            system="jira",
            resource_type="issue_collection",
            resource_id="weekly",
            parameters={"jql": "project = RISE", "limit": 25},
        )

        result = connector.execute(action)
        verification = connector.verify(action, result)

        self.assertTrue(verification.verified)
        self.assertEqual(result.after["returned"], 1)
        self.assertTrue(result.after["issues"][0]["blocked"])
        self.assertEqual(result.after["issues"][0]["assignee"], "Rory Glenn")
        self.assertEqual(len(transport.requests), 2)
        self.assertEqual(
            urlparse(transport.requests[0].url).path,
            "/rest/api/3/search/jql",
        )
        self.assertEqual(transport.requests[0].json_body()["jql"], "project = RISE")

    def test_data_center_uses_v2_search(self) -> None:
        transport = ScriptedTransport()
        transport.add_json(
            "POST",
            "/rest/api/2/search",
            {"issues": [_jira_issue()], "total": 1},
        )
        connector = JiraConnector(
            resolved_config(
                "jira",
                deployment=DeploymentType.DATA_CENTER,
                base_url="https://jira.internal.test",
            ),
            transport=transport,
        )
        action = read_action(
            "jira.issue.search",
            system="jira",
            resource_type="issue_collection",
            resource_id="dc-weekly",
            parameters={"jql": "project = CORE", "limit": 10},
        )

        result = connector.execute(action)

        self.assertEqual(result.after["deployment"], DeploymentType.DATA_CENTER)
        self.assertEqual(
            urlparse(transport.requests[0].url).path,
            "/rest/api/2/search",
        )
        self.assertEqual(transport.requests[0].json_body()["startAt"], 0)


class ConfluenceConnectorTests(unittest.TestCase):
    """Verify page normalization for Cloud and Data Center."""

    def test_cloud_page_read_converts_storage_html_to_text(self) -> None:
        transport = ScriptedTransport()
        transport.add_json(
            "GET",
            "/wiki/api/v2/pages/123",
            {
                "id": "123",
                "title": "Project Status",
                "status": "current",
                "spaceId": "space-1",
                "version": {"number": 12, "createdAt": "2026-08-13T10:00:00Z"},
                "body": {
                    "storage": {
                        "value": "<h1>Release</h1><p>On track with two blockers.</p>"
                    }
                },
                "_links": {"webui": "/spaces/RISE/pages/123"},
            },
        )
        connector = ConfluenceConnector(
            resolved_config("confluence", base_url="https://acme.atlassian.net"),
            transport=transport,
        )
        action = read_action(
            "confluence.page.read",
            system="confluence",
            resource_type="page",
            resource_id="123",
            expected_version="12",
        )

        result = connector.execute(action)
        verification = connector.verify(action, result)

        self.assertTrue(verification.verified)
        page = result.after["page"]
        self.assertEqual(page["version"], 12)
        self.assertIn("On track with two blockers", page["body_text"])
        self.assertEqual(
            page["web_url"],
            "https://acme.atlassian.net/spaces/RISE/pages/123",
        )

    def test_data_center_search_uses_rest_content_endpoint(self) -> None:
        transport = ScriptedTransport()
        transport.add_json(
            "GET",
            "/rest/api/content/search",
            {
                "results": [
                    {
                        "id": "8",
                        "title": "Status",
                        "status": "current",
                        "version": {"number": 3},
                        "space": {"id": 2, "key": "CORE"},
                        "history": {"lastUpdated": {"when": "2026-08-13"}},
                        "_links": {"webui": "/display/CORE/Status"},
                    }
                ],
                "_links": {},
            },
        )
        connector = ConfluenceConnector(
            resolved_config(
                "confluence",
                deployment=DeploymentType.DATA_CENTER,
                base_url="https://confluence.internal.test",
            ),
            transport=transport,
        )
        action = read_action(
            "confluence.page.search",
            system="confluence",
            resource_type="page_collection",
            resource_id="status-search",
            parameters={"cql": "space = CORE", "limit": 5},
        )

        result = connector.execute(action)

        self.assertEqual(result.after["returned"], 1)
        self.assertEqual(result.after["pages"][0]["space_key"], "CORE")
        self.assertEqual(
            urlparse(transport.requests[0].url).path,
            "/rest/api/content/search",
        )


class BitbucketConnectorTests(unittest.TestCase):
    """Verify PR and CI enrichment across deployment families."""

    def test_public_workspace_repository_list_is_anonymous_and_verified(self) -> None:
        transport = ScriptedTransport()
        transport.add_json(
            "GET",
            "/2.0/repositories/blahdeblahblahblah",
            {
                "values": [
                    {
                        "uuid": "{repo-1}",
                        "name": "public-project",
                        "slug": "public-project",
                        "is_private": False,
                        "links": {
                            "html": {
                                "href": (
                                    "https://bitbucket.org/"
                                    "blahdeblahblahblah/public-project"
                                )
                            }
                        },
                    }
                ],
                "next": None,
            },
        )
        connector = BitbucketConnector(
            resolved_config(
                "bitbucket",
                base_url="https://api.bitbucket.org/2.0",
            ),
            transport=transport,
        )
        action = read_action(
            "bitbucket.public_repository.list",
            system="bitbucket",
            resource_type="public_repository_collection",
            resource_id="blahdeblahblahblah",
            parameters={"workspace": "blahdeblahblahblah", "limit": 10},
        )

        result = connector.execute(action)
        verification = connector.verify(action, result)

        self.assertTrue(verification.verified)
        self.assertEqual(result.after["returned"], 1)
        self.assertEqual(
            result.after["repositories"][0]["slug"],
            "public-project",
        )
        self.assertNotIn("Authorization", transport.requests[0].headers)
        self.assertEqual(len(transport.requests), 2)

    def test_public_workspace_repository_list_rejects_private_response(self) -> None:
        transport = ScriptedTransport()
        transport.add_json(
            "GET",
            "/2.0/repositories/blahdeblahblahblah",
            {
                "values": [{"name": "private-project", "is_private": True}],
                "next": None,
            },
        )
        connector = BitbucketConnector(
            resolved_config(
                "bitbucket",
                base_url="https://api.bitbucket.org/2.0",
            ),
            transport=transport,
        )

        with self.assertRaisesRegex(ConnectorError, "was not public"):
            connector.execute(
                read_action(
                    "bitbucket.public_repository.list",
                    system="bitbucket",
                    resource_type="public_repository_collection",
                    resource_id="blahdeblahblahblah",
                    parameters={
                        "workspace": "blahdeblahblahblah",
                        "limit": 10,
                    },
                )
            )

    def test_public_workspace_repository_list_rejects_off_path_pagination(
        self,
    ) -> None:
        transport = ScriptedTransport()
        transport.add_json(
            "GET",
            "/2.0/repositories/blahdeblahblahblah",
            {
                "values": [
                    {
                        "name": "public-project",
                        "slug": "public-project",
                        "is_private": False,
                    }
                ],
                "next": "https://api.bitbucket.org/2.0/user",
            },
        )
        connector = BitbucketConnector(
            resolved_config(
                "bitbucket",
                base_url="https://api.bitbucket.org/2.0",
            ),
            transport=transport,
        )

        with self.assertRaisesRegex(ConnectorError, "left the fixed workspace"):
            connector.execute(
                read_action(
                    "bitbucket.public_repository.list",
                    system="bitbucket",
                    resource_type="public_repository_collection",
                    resource_id="blahdeblahblahblah",
                    parameters={
                        "workspace": "blahdeblahblahblah",
                        "limit": 10,
                    },
                )
            )

        self.assertEqual(len(transport.requests), 1)

    def test_cloud_pull_requests_include_ci_summary(self) -> None:
        transport = ScriptedTransport()
        transport.add_json(
            "GET",
            "/2.0/repositories/acme/widget/pullrequests",
            {"values": [_cloud_pull_request()], "next": None},
        )
        transport.add_json(
            "GET",
            "/2.0/repositories/acme/widget/pullrequests/7/statuses",
            {
                "values": [
                    {"key": "tests", "name": "Tests", "state": "FAILED"},
                    {"key": "lint", "name": "Lint", "state": "SUCCESSFUL"},
                ],
                "next": None,
            },
        )
        connector = BitbucketConnector(
            resolved_config(
                "bitbucket",
                base_url="https://api.bitbucket.org/2.0",
            ),
            transport=transport,
        )
        action = read_action(
            "bitbucket.pull_request.search",
            system="bitbucket",
            resource_type="pull_request_collection",
            resource_id="open-prs",
            parameters={
                "workspace": "acme",
                "repository": "widget",
                "state": "OPEN",
                "include_statuses": True,
                "limit": 20,
            },
        )

        result = connector.execute(action)
        verification = connector.verify(action, result)

        self.assertTrue(verification.verified)
        pull_request = result.after["pull_requests"][0]
        self.assertEqual(pull_request["ci_summary"]["failed"], 1)
        self.assertEqual(pull_request["ci_summary"]["successful"], 1)
        self.assertEqual(pull_request["source_branch"], "feature/status")
        self.assertEqual(len(transport.requests), 4)

    def test_data_center_pull_requests_use_build_status_commit_endpoint(self) -> None:
        transport = ScriptedTransport()
        transport.add_json(
            "GET",
            "/rest/api/latest/projects/CORE/repos/widget/pull-requests",
            {"values": [_dc_pull_request()], "isLastPage": True},
        )
        transport.add_json(
            "GET",
            "/rest/build-status/latest/commits/abc123",
            {
                "values": [{"key": "build", "name": "Build", "state": "SUCCESSFUL"}],
                "isLastPage": True,
            },
        )
        connector = BitbucketConnector(
            resolved_config(
                "bitbucket",
                deployment=DeploymentType.DATA_CENTER,
                base_url="https://bitbucket.internal.test",
            ),
            transport=transport,
        )
        action = read_action(
            "bitbucket.pull_request.search",
            system="bitbucket",
            resource_type="pull_request_collection",
            resource_id="dc-prs",
            parameters={
                "project": "CORE",
                "repository": "widget",
                "include_statuses": True,
                "limit": 10,
            },
        )

        result = connector.execute(action)

        pull_request = result.after["pull_requests"][0]
        self.assertEqual(pull_request["ci_summary"]["successful"], 1)
        paths = [urlparse(item.url).path for item in transport.requests]
        self.assertIn("/rest/build-status/latest/commits/abc123", paths)

    def test_nested_enrichment_shares_one_global_request_budget(self) -> None:
        transport = ScriptedTransport()
        transport.add_json(
            "GET",
            "/2.0/repositories/acme/widget/pullrequests",
            {"values": [_cloud_pull_request()]},
        )
        transport.add_json(
            "GET",
            "/2.0/repositories/acme/widget/pullrequests/7/statuses",
            {"values": []},
        )
        transport.add_json(
            "GET",
            "/2.0/repositories/acme/widget/pullrequests/7/diffstat",
            {"values": []},
        )
        config = replace(
            resolved_config(
                "bitbucket",
                base_url="https://api.bitbucket.org/2.0",
            ),
            max_pages=2,
        )
        connector = BitbucketConnector(config, transport=transport)
        action = read_action(
            "bitbucket.pull_request.search",
            system="bitbucket",
            resource_type="pull_request_collection",
            resource_id="open-prs-budget",
            parameters={
                "workspace": "acme",
                "repository": "widget",
                "include_statuses": True,
                "include_diffstat": True,
                "enrichment_limit": 1,
                "limit": 1,
            },
        )

        with self.assertRaisesRegex(ConnectorHttpError, "request/page budget"):
            connector.execute(action)

        self.assertEqual(len(transport.requests), 2)


def _jira_issue() -> dict[str, object]:
    return {
        "id": "10001",
        "key": "RISE-142",
        "fields": {
            "summary": "Resolve release blocker",
            "status": {
                "name": "Blocked",
                "statusCategory": {"name": "In Progress"},
            },
            "assignee": {"displayName": "Rory Glenn"},
            "priority": {"name": "High"},
            "issuetype": {"name": "Bug"},
            "project": {"key": "RISE"},
            "labels": ["release-blocker"],
            "updated": "2026-08-13T12:00:00.000+0000",
            "resolutiondate": None,
        },
    }


def _cloud_pull_request() -> dict[str, object]:
    return {
        "id": 7,
        "title": "Add weekly status",
        "description": "Read-only workflow",
        "state": "OPEN",
        "author": {"display_name": "Rory"},
        "source": {
            "branch": {"name": "feature/status"},
            "commit": {"hash": "abc123"},
        },
        "destination": {"branch": {"name": "main"}},
        "participants": [],
        "reviewers": [{"display_name": "Don"}],
        "links": {
            "html": {"href": "https://bitbucket.org/acme/widget/pull-requests/7"}
        },
        "created_on": "2026-08-12T10:00:00Z",
        "updated_on": "2026-08-13T10:00:00Z",
    }


def _dc_pull_request() -> dict[str, object]:
    return {
        "id": 9,
        "version": 2,
        "title": "Data Center status",
        "description": "Read-only workflow",
        "state": "OPEN",
        "author": {"user": {"displayName": "Rory"}},
        "fromRef": {
            "displayId": "feature/status",
            "latestCommit": "abc123",
        },
        "toRef": {"displayId": "main"},
        "reviewers": [],
        "createdDate": 1,
        "updatedDate": 2,
    }


if __name__ == "__main__":
    unittest.main()

"""Contract tests for Jira, Confluence, and Bitbucket connectors."""

import unittest
from dataclasses import replace
from urllib.parse import parse_qs, urlparse

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

    def test_gateway_api_root_keeps_browser_links_on_tenant(self) -> None:
        cloud_id = "12345678-1234-1234-1234-123456789abc"
        transport = ScriptedTransport()
        transport.add_json(
            "POST",
            f"/ex/jira/{cloud_id}/rest/api/3/search/jql",
            {
                "issues": [_jira_issue()],
                "total": 1,
                "isLast": True,
            },
        )
        connector = JiraConnector(
            replace(
                resolved_config(
                    "jira",
                    base_url=f"https://api.atlassian.com/ex/jira/{cloud_id}",
                ),
                web_base_url="https://acme.atlassian.net/",
            ),
            transport=transport,
        )
        action = read_action(
            "jira.issue.search",
            system="jira",
            resource_type="issue_collection",
            resource_id="gateway-search",
            parameters={"jql": "project = RISE", "limit": 1},
        )

        result = connector.execute(action)

        self.assertEqual(
            urlparse(transport.requests[0].url).path,
            f"/ex/jira/{cloud_id}/rest/api/3/search/jql",
        )
        self.assertEqual(
            result.after["issues"][0]["web_url"],
            "https://acme.atlassian.net/browse/RISE-142",
        )

    def test_review_context_reads_exact_fields_and_normalizes_relations(self) -> None:
        issue = _jira_issue()
        fields = issue["fields"]
        assert isinstance(fields, dict)
        fields.update(
            {
                "description": {
                    "type": "doc",
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [{"type": "text", "text": "Exact scope."}],
                        }
                    ],
                },
                "customfield_10001": {
                    "type": "doc",
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [
                                {"type": "text", "text": "Ship cited evidence."}
                            ],
                        }
                    ],
                },
                "customfield_10002": (
                    "https://api.bitbucket.org/2.0/repositories/"
                    "acme/widget/pullrequests/8"
                ),
            }
        )
        transport = ScriptedTransport()
        transport.add_json("GET", "/rest/api/3/issue/RISE-142", issue)
        transport.add_json(
            "GET",
            "/rest/api/3/issue/RISE-142/remotelink",
            [
                {
                    "id": "remote-pr",
                    "object": {
                        "url": "https://bitbucket.org/acme/widget/pull-requests/7"
                    },
                },
                {
                    "id": "remote-page",
                    "object": {
                        "url": (
                            "https://acme.atlassian.net/wiki/spaces/ENG/"
                            "pages/11/Requirement"
                        )
                    },
                },
                {
                    "id": "ignored-off-origin",
                    "object": {"url": "https://attacker.example/pr/7"},
                },
            ],
        )
        connector = JiraConnector(
            resolved_config(
                "jira",
                base_url="https://acme.atlassian.net",
                extra={
                    "review_acceptance_field_ids": ["customfield_10001"],
                    "review_relation_field_kinds": {
                        "customfield_10002": "bitbucket_pull_request_url"
                    },
                },
            ),
            transport=transport,
        )
        action = read_action(
            "jira.issue.review_context.read",
            system="jira",
            resource_type="issue",
            resource_id="RISE-142",
            parameters={
                "fields": [
                    "id",
                    "key",
                    "summary",
                    "description",
                    "acceptance_criteria",
                    "external_relations",
                ],
                "bitbucket_origin": "https://api.bitbucket.org",
                "bitbucket_owner": "acme",
                "bitbucket_repository": "widget",
                "bitbucket_pull_request_id": "7",
                "confluence_origin": "https://acme.atlassian.net",
                "confluence_space_id": "space-1",
                "confluence_space_key": "ENG",
                "confluence_page_ids": ["11"],
            },
        )

        result = connector.execute(action)
        verification = connector.verify(action, result)

        self.assertTrue(verification.verified)
        normalized = result.after["issue"]
        self.assertEqual(normalized["key"], "RISE-142")
        self.assertEqual(normalized["description"], "Exact scope.")
        self.assertEqual(
            normalized["acceptance_criteria"],
            [{"field_id": "customfield_10001", "text": "Ship cited evidence."}],
        )
        self.assertCountEqual(
            [
                (item["provider"], item.get("pull_request_id") or item.get("page_id"))
                for item in normalized["external_relations"]
            ],
            [("bitbucket", "8"), ("bitbucket", "7"), ("confluence", "11")],
        )
        self.assertNotIn("attacker.example", str(result.after))
        self.assertEqual(len(transport.requests), 4)
        requested_fields = parse_qs(urlparse(transport.requests[0].url).query)[
            "fields"
        ][0].split(",")
        self.assertEqual(
            requested_fields,
            ["customfield_10001", "customfield_10002", "description", "summary"],
        )

    def test_review_context_rejects_a_different_issue_identity(self) -> None:
        issue = _jira_issue()
        issue["key"] = "RISE-143"
        transport = ScriptedTransport()
        transport.add_json("GET", "/rest/api/3/issue/RISE-142", issue)
        connector = JiraConnector(
            resolved_config("jira", base_url="https://acme.atlassian.net"),
            transport=transport,
        )

        with self.assertRaisesRegex(ConnectorError, "identity"):
            connector.execute(
                read_action(
                    "jira.issue.review_context.read",
                    system="jira",
                    resource_type="issue",
                    resource_id="RISE-142",
                    parameters={"fields": ["id", "key", "summary"]},
                )
            )


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
            parameters={"space_id": "space-1", "space_key": "RISE"},
            expected_version="12",
        )

        result = connector.execute(action)
        verification = connector.verify(action, result)

        self.assertTrue(verification.verified)
        page = result.after["page"]
        self.assertEqual(page["version"], 12)
        self.assertEqual(page["space_id"], "space-1")
        self.assertEqual(page["space_key"], "RISE")
        self.assertIn("On track with two blockers", page["body_text"])
        self.assertEqual(
            page["web_url"],
            "https://acme.atlassian.net/spaces/RISE/pages/123",
        )

    def test_cloud_page_read_rejects_a_different_exact_space(self) -> None:
        transport = ScriptedTransport()
        transport.add_json(
            "GET",
            "/wiki/api/v2/pages/123",
            {
                "id": "123",
                "title": "Project Status",
                "spaceId": "space-1",
                "version": {"number": 12},
                "body": {"storage": {"value": "<p>On track.</p>"}},
                "_links": {"webui": "/spaces/OTHER/pages/123"},
            },
        )
        connector = ConfluenceConnector(
            resolved_config("confluence", base_url="https://acme.atlassian.net"),
            transport=transport,
        )

        with self.assertRaisesRegex(ConnectorError, "configured space"):
            connector.execute(
                read_action(
                    "confluence.page.read",
                    system="confluence",
                    resource_type="page",
                    resource_id="123",
                    parameters={"space_id": "space-1", "space_key": "RISE"},
                )
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

    def test_gateway_api_root_keeps_page_links_on_tenant(self) -> None:
        cloud_id = "12345678-1234-1234-1234-123456789abc"
        transport = ScriptedTransport()
        transport.add_json(
            "GET",
            f"/ex/confluence/{cloud_id}/wiki/api/v2/pages/123",
            {
                "id": "123",
                "title": "Project Status",
                "status": "current",
                "spaceId": "space-1",
                "version": {"number": 12, "createdAt": "2026-08-13T10:00:00Z"},
                "body": {"storage": {"value": "<p>On track.</p>"}},
                "_links": {"webui": "/spaces/RISE/pages/123"},
            },
        )
        connector = ConfluenceConnector(
            replace(
                resolved_config(
                    "confluence",
                    base_url=(f"https://api.atlassian.com/ex/confluence/{cloud_id}"),
                ),
                web_base_url="https://acme.atlassian.net/",
            ),
            transport=transport,
        )
        action = read_action(
            "confluence.page.read",
            system="confluence",
            resource_type="page",
            resource_id="123",
        )

        result = connector.execute(action)

        self.assertEqual(
            urlparse(transport.requests[0].url).path,
            f"/ex/confluence/{cloud_id}/wiki/api/v2/pages/123",
        )
        self.assertEqual(
            result.after["page"]["web_url"],
            "https://acme.atlassian.net/spaces/RISE/pages/123",
        )

    def test_gateway_pagination_cannot_cross_to_sibling_product(self) -> None:
        cloud_id = "12345678-1234-1234-1234-123456789abc"
        transport = ScriptedTransport()
        transport.add_json(
            "GET",
            f"/ex/confluence/{cloud_id}/wiki/rest/api/content/search",
            {
                "results": [{"id": "123", "title": "Project Status"}],
                "_links": {
                    "next": (
                        "https://api.atlassian.com/ex/jira/"
                        f"{cloud_id}/rest/api/3/issue/MA-1"
                    )
                },
            },
        )
        connector = ConfluenceConnector(
            replace(
                resolved_config(
                    "confluence",
                    base_url=(f"https://api.atlassian.com/ex/confluence/{cloud_id}"),
                ),
                web_base_url="https://acme.atlassian.net",
            ),
            transport=transport,
        )

        with self.assertRaisesRegex(ConnectorHttpError, "outside"):
            connector.execute(
                read_action(
                    "confluence.page.search",
                    system="confluence",
                    resource_type="page_collection",
                    resource_id="gateway-search",
                    parameters={"cql": "type = page", "limit": 2},
                )
            )

        self.assertEqual(len(transport.requests), 1)

    def test_provider_web_link_cannot_escape_approved_tenant(self) -> None:
        transport = ScriptedTransport()
        transport.add_json(
            "GET",
            "/wiki/api/v2/pages/123",
            {
                "id": "123",
                "title": "Project Status",
                "version": {"number": 1},
                "body": {"storage": {"value": "<p>On track.</p>"}},
                "_links": {"webui": "https://attacker.example/phishing"},
            },
        )
        connector = ConfluenceConnector(
            resolved_config(
                "confluence",
                base_url="https://acme.atlassian.net",
            ),
            transport=transport,
        )

        result = connector.execute(
            read_action(
                "confluence.page.read",
                system="confluence",
                resource_type="page",
                resource_id="123",
            )
        )

        self.assertIsNone(result.after["page"]["web_url"])
        self.assertNotIn(
            "https://attacker.example/phishing",
            result.after["source_urls"],
        )


class BitbucketConnectorTests(unittest.TestCase):
    """Verify PR and CI enrichment across deployment families."""

    def test_exact_cloud_repository_rejects_missing_or_foreign_identity(self) -> None:
        action = read_action(
            "bitbucket.repository.read",
            system="bitbucket",
            resource_type="repository",
            resource_id="widget",
            parameters={"workspace": "acme", "repository": "widget"},
        )
        payloads = (
            {"uuid": "{missing}", "name": "Widget"},
            {
                "uuid": "{foreign}",
                "name": "Foreign",
                "slug": "widget",
                "full_name": "other/widget",
            },
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                transport = ScriptedTransport()
                transport.add_json(
                    "GET",
                    "/2.0/repositories/acme/widget",
                    payload,
                )
                connector = BitbucketConnector(
                    resolved_config(
                        "bitbucket",
                        base_url="https://api.bitbucket.org/2.0",
                    ),
                    transport=transport,
                )

                with self.assertRaisesRegex(ConnectorError, "exact target"):
                    connector.execute(action)

    def test_exact_data_center_repository_rejects_foreign_project(self) -> None:
        transport = ScriptedTransport()
        transport.add_json(
            "GET",
            "/rest/api/latest/projects/CORE/repos/widget",
            {
                "id": 12,
                "name": "Widget",
                "slug": "widget",
                "project": {"key": "OTHER", "name": "Other"},
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

        with self.assertRaisesRegex(ConnectorError, "exact target"):
            connector.execute(
                read_action(
                    "bitbucket.repository.read",
                    system="bitbucket",
                    resource_type="repository",
                    resource_id="widget",
                    parameters={"project": "CORE", "repository": "widget"},
                )
            )

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

    def test_cloud_build_status_reads_the_exact_pull_request_head(self) -> None:
        transport = ScriptedTransport()
        transport.add_json(
            "GET",
            "/2.0/repositories/acme/widget/pullrequests/7",
            _cloud_pull_request(),
        )
        transport.add_json(
            "GET",
            "/2.0/repositories/acme/widget/commit/abc123/statuses",
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
            "bitbucket.build_status.read",
            system="bitbucket",
            resource_type="pull_request",
            resource_id="7",
            parameters={
                "workspace": "acme",
                "repository": "widget",
                "pull_request_id": "7",
                "limit": 10,
            },
        )

        result = connector.execute(action)
        verification = connector.verify(action, result)

        self.assertTrue(verification.verified)
        self.assertEqual(result.after["commit"], "abc123")
        self.assertEqual(result.after["pull_request_id"], "7")
        self.assertEqual(result.after["returned"], 2)
        self.assertEqual(result.after["summary"]["failed"], 1)
        self.assertEqual(
            [item["key"] for item in result.after["statuses"]],
            ["lint", "tests"],
        )
        self.assertEqual(
            [urlparse(item.url).path for item in transport.requests],
            [
                "/2.0/repositories/acme/widget/pullrequests/7",
                "/2.0/repositories/acme/widget/commit/abc123/statuses",
                "/2.0/repositories/acme/widget/pullrequests/7",
                "/2.0/repositories/acme/widget/commit/abc123/statuses",
            ],
        )

    def test_data_center_build_status_reads_the_exact_pull_request_head(self) -> None:
        transport = ScriptedTransport()
        transport.add_json(
            "GET",
            "/rest/api/latest/projects/CORE/repos/widget/pull-requests/9",
            _dc_pull_request(),
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
            "bitbucket.build_status.read",
            system="bitbucket",
            resource_type="pull_request",
            resource_id="9",
            parameters={
                "project": "CORE",
                "repository": "widget",
                "pull_request_id": "9",
                "limit": 10,
            },
        )

        result = connector.execute(action)
        verification = connector.verify(action, result)

        self.assertTrue(verification.verified)
        self.assertEqual(result.after["commit"], "abc123")
        self.assertEqual(result.after["pull_request_id"], "9")
        self.assertEqual(result.after["summary"]["successful"], 1)
        self.assertEqual(
            [urlparse(item.url).path for item in transport.requests],
            [
                "/rest/api/latest/projects/CORE/repos/widget/pull-requests/9",
                "/rest/build-status/latest/commits/abc123",
                "/rest/api/latest/projects/CORE/repos/widget/pull-requests/9",
                "/rest/build-status/latest/commits/abc123",
            ],
        )

    def test_legacy_commit_build_status_keeps_bounded_truncation(self) -> None:
        path = "/2.0/repositories/acme/widget/commit/abc123/statuses"
        first = {
            "values": [{"key": "first", "state": "SUCCESSFUL"}],
            "next": "https://api.bitbucket.org/2.0/repositories/acme/widget/commit/abc123/statuses?page=2",
        }
        second = {
            "values": [{"key": "second", "state": "FAILED"}],
            "next": None,
        }
        transport = ScriptedTransport()
        for payload in (first, second, first, second):
            transport.add_json("GET", path, payload)
        connector = BitbucketConnector(
            resolved_config(
                "bitbucket",
                base_url="https://api.bitbucket.org/2.0",
                max_items=1,
            ),
            transport=transport,
        )
        action = read_action(
            "bitbucket.build_status.read",
            system="bitbucket",
            resource_type="commit",
            resource_id="abc123",
            parameters={"workspace": "acme", "repository": "widget"},
        )

        result = connector.execute(action)
        verification = connector.verify(action, result)

        self.assertTrue(verification.verified)
        self.assertNotIn("pull_request_id", result.after)
        self.assertEqual(result.after["returned"], 1)
        self.assertEqual(result.after["statuses"][0]["key"], "first")
        self.assertEqual(len(transport.requests), 4)
        self.assertEqual(
            parse_qs(urlparse(transport.requests[0].url).query)["pagelen"],
            ["50"],
        )

    def test_pull_request_build_status_fails_closed_on_limit_overflow(self) -> None:
        transport = ScriptedTransport()
        transport.add_json(
            "GET",
            "/2.0/repositories/acme/widget/pullrequests/7",
            _cloud_pull_request(),
        )
        transport.add_json(
            "GET",
            "/2.0/repositories/acme/widget/commit/abc123/statuses",
            {
                "values": [{"key": "tests", "state": "SUCCESSFUL"}],
                "next": (
                    "https://api.bitbucket.org/2.0/repositories/acme/widget/"
                    "commit/abc123/statuses?page=2"
                ),
            },
        )
        connector = BitbucketConnector(
            resolved_config(
                "bitbucket",
                base_url="https://api.bitbucket.org/2.0",
            ),
            transport=transport,
        )

        with self.assertRaisesRegex(ConnectorError, "exact requested limit"):
            connector.execute(
                read_action(
                    "bitbucket.build_status.read",
                    system="bitbucket",
                    resource_type="pull_request",
                    resource_id="7",
                    parameters={
                        "workspace": "acme",
                        "repository": "widget",
                        "pull_request_id": "7",
                        "limit": 1,
                    },
                )
            )

    def test_pull_request_build_status_rejects_empty_nonterminal_page(self) -> None:
        transport = ScriptedTransport()
        transport.add_json(
            "GET",
            "/2.0/repositories/acme/widget/pullrequests/7",
            _cloud_pull_request(),
        )
        transport.add_json(
            "GET",
            "/2.0/repositories/acme/widget/commit/abc123/statuses",
            {
                "values": [],
                "next": (
                    "https://api.bitbucket.org/2.0/repositories/acme/widget/"
                    "commit/abc123/statuses?page=2"
                ),
            },
        )
        connector = BitbucketConnector(
            resolved_config(
                "bitbucket",
                base_url="https://api.bitbucket.org/2.0",
            ),
            transport=transport,
        )

        with self.assertRaisesRegex(ConnectorError, "empty nonterminal page"):
            connector.execute(
                read_action(
                    "bitbucket.build_status.read",
                    system="bitbucket",
                    resource_type="pull_request",
                    resource_id="7",
                    parameters={
                        "workspace": "acme",
                        "repository": "widget",
                        "pull_request_id": "7",
                        "limit": 10,
                    },
                )
            )

        self.assertEqual(len(transport.requests), 2)

    def test_pull_request_build_status_rejects_oversized_terminal_page(self) -> None:
        transport = ScriptedTransport()
        transport.add_json(
            "GET",
            "/2.0/repositories/acme/widget/pullrequests/7",
            _cloud_pull_request(),
        )
        transport.add_json(
            "GET",
            "/2.0/repositories/acme/widget/commit/abc123/statuses",
            {
                "values": [
                    {"key": "tests", "state": "SUCCESSFUL"},
                    {"key": "lint", "state": "SUCCESSFUL"},
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

        with self.assertRaisesRegex(ConnectorError, "exact requested limit"):
            connector.execute(
                read_action(
                    "bitbucket.build_status.read",
                    system="bitbucket",
                    resource_type="pull_request",
                    resource_id="7",
                    parameters={
                        "workspace": "acme",
                        "repository": "widget",
                        "pull_request_id": "7",
                        "limit": 1,
                    },
                )
            )

    def test_pull_request_build_status_rejects_malformed_status_item(self) -> None:
        transport = ScriptedTransport()
        transport.add_json(
            "GET",
            "/2.0/repositories/acme/widget/pullrequests/7",
            _cloud_pull_request(),
        )
        transport.add_json(
            "GET",
            "/2.0/repositories/acme/widget/commit/abc123/statuses",
            {"values": ["not-a-status-object"], "next": None},
        )
        connector = BitbucketConnector(
            resolved_config(
                "bitbucket",
                base_url="https://api.bitbucket.org/2.0",
            ),
            transport=transport,
        )

        with self.assertRaisesRegex(ConnectorError, "invalid status schema"):
            connector.execute(
                read_action(
                    "bitbucket.build_status.read",
                    system="bitbucket",
                    resource_type="pull_request",
                    resource_id="7",
                    parameters={
                        "workspace": "acme",
                        "repository": "widget",
                        "pull_request_id": "7",
                        "limit": 10,
                    },
                )
            )

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

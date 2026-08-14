"""Contract tests for approved reversible provider writes."""

from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest

from master_agent.config import DeploymentType
from master_agent.connectors.bitbucket_write import BitbucketWriteConnector
from master_agent.connectors.confluence_write import ConfluenceWriteConnector
from master_agent.connectors.jira_write import JiraWriteConnector
from master_agent.connectors.sharepoint_write import SharePointWriteConnector
from master_agent.errors import ConnectorError, VersionConflictError
from master_agent.models import RiskLevel
from tests.fakes import ScriptedTransport
from tests.helpers import action_for, resolved_config


class JiraWriteConnectorTests(unittest.TestCase):
    """Validate version checks, writes, verification, and compensation."""

    def test_cloud_update_and_compensation_restore_prior_fields(self) -> None:
        transport = ScriptedTransport()
        path = "/rest/api/3/issue/RISE-1"
        old = _jira_issue("Old summary", "2026-08-13T10:00:00.000+0000")
        new = _jira_issue("New summary", "2026-08-13T10:01:00.000+0000")
        restored = _jira_issue("Old summary", "2026-08-13T10:02:00.000+0000")
        for payload in (old, new, new, new, new, restored):
            transport.add_json("GET", path, payload)
        transport.add_bytes("PUT", path, b"", status=204)
        transport.add_bytes("PUT", path, b"", status=204)
        connector = JiraWriteConnector(
            resolved_config(
                "jira",
                deployment=DeploymentType.CLOUD,
                base_url="https://example.atlassian.net",
            ),
            transport=transport,
        )
        action = action_for(
            "jira.issue.update",
            system="jira",
            resource_type="issue",
            resource_id="RISE-1",
            risk=RiskLevel.REVERSIBLE_WRITE,
            expected_version="2026-08-13T10:00:00.000+0000",
            parameters={"fields": {"summary": "New summary"}},
        )

        result = connector.execute(action)
        verification = connector.verify(action, result)
        compensation = connector.compensate(action, result)
        compensation_verification = connector.verify_compensation(
            action,
            result,
            compensation,
        )

        self.assertTrue(verification.verified)
        self.assertTrue(compensation_verification.verified)
        self.assertEqual(compensation.after["fields"]["summary"], "Old summary")
        put_requests = [item for item in transport.requests if item.method == "PUT"]
        self.assertEqual(len(put_requests), 2)
        self.assertEqual(put_requests[0].json_body()["fields"]["summary"], "New summary")
        self.assertEqual(put_requests[1].json_body()["fields"]["summary"], "Old summary")

    def test_version_mismatch_blocks_update_before_put(self) -> None:
        transport = ScriptedTransport()
        path = "/rest/api/3/issue/RISE-2"
        transport.add_json(
            "GET",
            path,
            _jira_issue("Current", "2026-08-13T11:00:00.000+0000"),
        )
        connector = JiraWriteConnector(
            resolved_config(
                "jira",
                deployment=DeploymentType.CLOUD,
                base_url="https://example.atlassian.net",
            ),
            transport=transport,
        )
        action = action_for(
            "jira.issue.update",
            system="jira",
            resource_type="issue",
            resource_id="RISE-2",
            risk=RiskLevel.REVERSIBLE_WRITE,
            expected_version="stale",
            parameters={"fields": {"summary": "Attempted"}},
        )

        with self.assertRaises(VersionConflictError):
            connector.execute(action)
        self.assertEqual([item.method for item in transport.requests], ["GET"])


class ConfluenceWriteConnectorTests(unittest.TestCase):
    """Validate cloud page update and exact-content rollback."""

    def test_cloud_update_and_compensation(self) -> None:
        transport = ScriptedTransport()
        path = "/wiki/api/v2/pages/42"
        old = _confluence_page("Status", "<p>Old</p>", 4)
        new = _confluence_page("Status", "<p>New</p>", 5)
        restored = _confluence_page("Status", "<p>Old</p>", 6)
        for payload in (old, new, new, new, new, restored):
            transport.add_json("GET", path, payload)
        transport.add_json("PUT", path, {})
        transport.add_json("PUT", path, {})
        connector = ConfluenceWriteConnector(
            resolved_config(
                "confluence",
                deployment=DeploymentType.CLOUD,
                base_url="https://example.atlassian.net",
            ),
            transport=transport,
        )
        action = action_for(
            "confluence.page.update",
            system="confluence",
            resource_type="page",
            resource_id="42",
            risk=RiskLevel.REVERSIBLE_WRITE,
            expected_version="4",
            parameters={
                "title": "Status",
                "body": "<p>New</p>",
                "representation": "storage",
                "status": "current",
            },
        )

        result = connector.execute(action)
        self.assertTrue(connector.verify(action, result).verified)
        compensation = connector.compensate(action, result)
        self.assertTrue(
            connector.verify_compensation(action, result, compensation).verified
        )
        self.assertEqual(compensation.after["body"], "<p>Old</p>")
        writes = [item.json_body() for item in transport.requests if item.method == "PUT"]
        self.assertEqual(writes[0]["version"]["number"], 5)
        self.assertEqual(writes[1]["version"]["number"], 6)


class BitbucketWriteConnectorTests(unittest.TestCase):
    """Validate pull-request creation and decline compensation."""

    def test_cloud_pull_request_create_verify_and_decline(self) -> None:
        transport = ScriptedTransport()
        collection = "/2.0/repositories/acme/service/pullrequests"
        item = "/2.0/repositories/acme/service/pullrequests/9"
        decline = item + "/decline"
        transport.add_json("POST", collection, {"id": 9}, status=201)
        transport.add_json("GET", item, _cloud_pr("OPEN"))
        transport.add_json("GET", item, _cloud_pr("OPEN"))
        transport.add_json("GET", item, _cloud_pr("OPEN"))
        transport.add_bytes("POST", decline, b"", status=200)
        transport.add_json("GET", item, _cloud_pr("DECLINED"))
        connector = BitbucketWriteConnector(
            resolved_config(
                "bitbucket",
                deployment=DeploymentType.CLOUD,
                base_url="https://api.bitbucket.org/2.0",
            ),
            transport=transport,
        )
        action = action_for(
            "bitbucket.pull_request.create",
            system="bitbucket",
            resource_type="pull_request",
            resource_id="new",
            risk=RiskLevel.REVERSIBLE_WRITE,
            parameters={
                "workspace": "acme",
                "repository": "service",
                "title": "Agent change",
                "source_branch": "agent/change",
                "destination_branch": "main",
                "description": "Reviewed proposal",
            },
        )

        result = connector.execute(action)
        self.assertTrue(connector.verify(action, result).verified)
        compensation = connector.compensate(action, result)
        self.assertTrue(
            connector.verify_compensation(action, result, compensation).verified
        )
        self.assertEqual(compensation.after["state"], "DECLINED")

    def test_close_source_branch_requires_boolean(self) -> None:
        transport = ScriptedTransport()
        connector = BitbucketWriteConnector(
            resolved_config(
                "bitbucket",
                base_url="https://api.bitbucket.org/2.0",
                deployment=DeploymentType.CLOUD,
            ),
            transport=transport,
        )
        action = action_for(
            "bitbucket.pull_request.create",
            system="bitbucket",
            resource_type="pull_request",
            resource_id="new",
            risk=RiskLevel.REVERSIBLE_WRITE,
            parameters={
                "workspace": "workspace",
                "repository": "repository",
                "title": "Test",
                "source_branch": "agent/test",
                "destination_branch": "main",
                "close_source_branch": "false",
            },
        )
        with self.assertRaises(ConnectorError):
            connector.execute(action)
        self.assertEqual(transport.requests, [])

    def test_unsafe_branch_is_rejected_before_network(self) -> None:
        transport = ScriptedTransport()
        connector = BitbucketWriteConnector(
            resolved_config(
                "bitbucket",
                deployment=DeploymentType.CLOUD,
                base_url="https://api.bitbucket.org/2.0",
            ),
            transport=transport,
        )
        action = action_for(
            "bitbucket.pull_request.create",
            system="bitbucket",
            resource_type="pull_request",
            resource_id="new",
            risk=RiskLevel.REVERSIBLE_WRITE,
            parameters={
                "workspace": "acme",
                "repository": "service",
                "title": "Bad",
                "source_branch": "../main",
                "destination_branch": "main",
            },
        )
        with self.assertRaises(ConnectorError):
            connector.execute(action)
        self.assertEqual(transport.requests, [])


class SharePointWriteConnectorTests(unittest.TestCase):
    """Validate bounded overwrite and provider-version compensation."""

    def test_existing_file_is_overwritten_and_restored(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            local = root / "status.txt"
            local.write_bytes(b"new content")
            transport = ScriptedTransport()
            item = "/v1.0/drives/drive/items/item"
            content = item + "/content"
            versions = item + "/versions"
            restore = versions + "/3/restoreVersion"
            before = _drive_item("status.txt", len(b"old"), '"etag-1"')
            after = _drive_item("status.txt", len(b"new content"), '"etag-2"')
            restored = _drive_item("status.txt", len(b"old"), '"etag-3"')
            transport.add_json("GET", item, before)
            transport.add_json("GET", versions, {"value": [{"id": "3"}]})
            transport.add_bytes("PUT", content, b"", status=200)
            transport.add_json("GET", item, after)
            transport.add_json("GET", item, after)
            transport.add_json("GET", item, after)
            transport.add_bytes("POST", restore, b"", status=204)
            transport.add_json("GET", item, restored)
            transport.add_json("GET", item, restored)
            connector = SharePointWriteConnector(
                resolved_config(
                    "microsoft",
                    base_url="https://graph.microsoft.com/v1.0",
                    extra={
                        "identity_mode": "delegated",
                        "max_upload_bytes": 1000,
                    },
                ),
                artifact_root=root,
                transport=transport,
            )
            action = action_for(
                "sharepoint.file.upload",
                system="sharepoint",
                resource_type="file",
                resource_id="item",
                risk=RiskLevel.REVERSIBLE_WRITE,
                expected_version='"etag-1"',
                parameters={
                    "drive_id": "drive",
                    "local_path": str(local),
                    "local_sha256": hashlib.sha256(
                        local.read_bytes()
                    ).hexdigest(),
                    "content_type": "text/plain",
                },
            )

            result = connector.execute(action)
            self.assertTrue(connector.verify(action, result).verified)
            compensation = connector.compensate(action, result)
            self.assertTrue(
                connector.verify_compensation(action, result, compensation).verified
            )
            methods = [request.method for request in transport.requests]
            self.assertIn("PUT", methods)
            self.assertIn("POST", methods)

    def test_file_outside_artifact_root_is_rejected_before_network(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            approved = root / "approved"
            approved.mkdir()
            local = root / "outside.txt"
            local.write_text("new", encoding="utf-8")
            transport = ScriptedTransport()
            connector = SharePointWriteConnector(
                resolved_config(
                    "microsoft",
                    base_url="https://graph.microsoft.com/v1.0",
                    extra={"identity_mode": "delegated"},
                ),
                artifact_root=approved,
                transport=transport,
            )
            action = action_for(
                "sharepoint.file.upload",
                system="sharepoint",
                resource_type="file",
                resource_id="item",
                risk=RiskLevel.REVERSIBLE_WRITE,
                parameters={"drive_id": "drive", "local_path": str(local)},
            )
            with self.assertRaises(ConnectorError):
                connector.execute(action)
            self.assertEqual(transport.requests, [])


def _jira_issue(summary: str, updated: str) -> dict[str, object]:
    return {
        "id": "10001",
        "key": "RISE-1",
        "fields": {
            "summary": summary,
            "updated": updated,
            "status": {"name": "In Progress"},
        },
    }


def _confluence_page(title: str, body: str, version: int) -> dict[str, object]:
    return {
        "id": "42",
        "title": title,
        "status": "current",
        "spaceId": "SPACE",
        "version": {"number": version},
        "body": {"storage": {"representation": "storage", "value": body}},
    }


def _cloud_pr(state: str) -> dict[str, object]:
    return {
        "id": 9,
        "title": "Agent change",
        "state": state,
        "updated_on": "2026-08-13T20:00:00Z",
        "links": {"html": {"href": "https://bitbucket.example/pr/9"}},
    }


def _drive_item(name: str, size: int, etag: str) -> dict[str, object]:
    return {
        "id": "item",
        "name": name,
        "size": size,
        "eTag": etag,
        "cTag": "ctag",
        "lastModifiedDateTime": "2026-08-13T20:00:00Z",
        "webUrl": "https://tenant.sharepoint.com/item",
    }


if __name__ == "__main__":
    unittest.main()

"""Phase 4 approved-write and compensation contract tests."""

from __future__ import annotations

import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path

from master_agent.connectors.bitbucket_write import BitbucketWriteConnector
from master_agent.connectors.git_remote import GitBranchPushConnector
from master_agent.connectors.jira_write import JiraWriteConnector
from master_agent.connectors.onenote import OneNoteWriteConnector
from master_agent.connectors.sharepoint_write import SharePointWriteConnector
from master_agent.models import (
    AgentAction,
    AuthoritySource,
    ResourceRef,
    RiskLevel,
)
from tests.fakes import ScriptedTransport
from tests.helpers import resolved_config


def write_action(
    capability: str,
    *,
    system: str,
    resource_type: str,
    resource_id: str,
    parameters: dict[str, object],
    expected_version: str | None = None,
) -> AgentAction:
    """Build an approval-required reversible action for connector tests."""

    return AgentAction(
        capability=capability,
        target=ResourceRef(
            system=system,
            resource_type=resource_type,
            resource_id=resource_id,
            expected_version=expected_version,
        ),
        parameters=parameters,
        risk=RiskLevel.REVERSIBLE_WRITE,
        authority_source=AuthoritySource.DIRECT_USER,
        requires_approval=True,
        idempotency_key=f"test:{capability}:{resource_id}",
        justification="Phase 4 connector contract test.",
    )


class Phase4ConnectorTests(unittest.TestCase):
    """Verify provider writes remain bounded, versioned, and recoverable."""

    def test_jira_update_restores_prior_fields(self) -> None:
        transport = ScriptedTransport()
        issue_path = "/rest/api/3/issue/PROJ-1"
        before = {
            "id": "1",
            "key": "PROJ-1",
            "fields": {
                "updated": "v1",
                "summary": "Old",
                "status": {"name": "Open"},
            },
        }
        changed = {
            "id": "1",
            "key": "PROJ-1",
            "fields": {
                "updated": "v2",
                "summary": "New",
                "status": {"name": "Open"},
            },
        }
        restored = {
            "id": "1",
            "key": "PROJ-1",
            "fields": {
                "updated": "v3",
                "summary": "Old",
                "status": {"name": "Open"},
            },
        }
        transport.add_json("GET", issue_path, before)
        transport.add_bytes("PUT", issue_path, b"", status=204)
        transport.add_json("GET", issue_path, changed)
        transport.add_json("GET", issue_path, changed)
        transport.add_json("GET", issue_path, changed)
        transport.add_json("GET", issue_path, changed)
        transport.add_bytes("PUT", issue_path, b"", status=204)
        transport.add_json("GET", issue_path, restored)

        connector = JiraWriteConnector(
            resolved_config("jira"),
            transport=transport,
        )
        action = write_action(
            "jira.issue.update",
            system="jira",
            resource_type="issue",
            resource_id="PROJ-1",
            expected_version="v1",
            parameters={"fields": {"summary": "New"}},
        )
        result = connector.execute(action)
        self.assertTrue(connector.verify(action, result).verified)
        compensation = connector.compensate(action, result)
        self.assertTrue(
            connector.verify_compensation(action, result, compensation).verified
        )
        self.assertEqual(compensation.after["fields"]["summary"], "Old")

    def test_sharepoint_upload_restores_previous_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "status.pptx"
            artifact.write_bytes(b"new-content")
            transport = ScriptedTransport()
            item = "/v1.0/drives/drive-1/items/item-1"
            transport.add_json(
                "GET",
                item,
                {"id": "item-1", "name": "status.pptx", "size": 3, "eTag": "e1"},
            )
            transport.add_json(
                "GET",
                item + "/versions",
                {"value": [{"id": "v1"}]},
            )
            transport.add_json(
                "PUT",
                item + "/content",
                {"id": "item-1"},
                status=200,
            )
            changed = {
                "id": "item-1",
                "name": "status.pptx",
                "size": len(b"new-content"),
                "eTag": "e2",
            }
            restored = {
                "id": "item-1",
                "name": "status.pptx",
                "size": 3,
                "eTag": "e3",
            }
            transport.add_json("GET", item, changed)
            transport.add_json("GET", item, changed)
            transport.add_json("GET", item, changed)
            transport.add_bytes(
                "POST",
                item + "/versions/v1/restoreVersion",
                b"",
                status=204,
            )
            transport.add_json("GET", item, restored)

            connector = SharePointWriteConnector(
                resolved_config(
                    "microsoft", base_url="https://graph.microsoft.com/v1.0"
                ),
                artifact_root=root,
                transport=transport,
            )
            action = write_action(
                "sharepoint.file.upload",
                system="sharepoint",
                resource_type="drive_item",
                resource_id="item-1",
                expected_version="e1",
                parameters={
                    "drive_id": "drive-1",
                    "local_path": str(artifact),
                    "local_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                },
            )
            result = connector.execute(action)
            self.assertTrue(connector.verify(action, result).verified)
            compensation = connector.compensate(action, result)
            self.assertTrue(
                connector.verify_compensation(action, result, compensation).verified
            )

    def test_bitbucket_pull_request_can_be_declined_on_rollback(self) -> None:
        transport = ScriptedTransport()
        collection = "/2.0/repositories/work/repo/pullrequests"
        item = collection + "/12"
        created = {
            "id": 12,
            "title": "Agent change",
            "state": "OPEN",
            "updated_on": "v1",
            "source": {"branch": {"name": "agent/change"}},
            "destination": {"branch": {"name": "main"}},
        }
        declined = {**created, "state": "DECLINED", "updated_on": "v2"}
        transport.add_json("POST", collection, {"id": 12}, status=201)
        transport.add_json("GET", item, created)
        transport.add_json("GET", item, created)
        transport.add_json("GET", item, created)
        transport.add_json("POST", item + "/decline", declined, status=200)
        transport.add_json("GET", item, declined)
        connector = BitbucketWriteConnector(
            resolved_config("bitbucket", base_url="https://api.bitbucket.org/2.0"),
            transport=transport,
        )
        action = write_action(
            "bitbucket.pull_request.create",
            system="bitbucket",
            resource_type="pull_request_collection",
            resource_id="new",
            parameters={
                "workspace": "work",
                "repository": "repo",
                "title": "Agent change",
                "source_branch": "agent/change",
                "destination_branch": "main",
            },
        )
        result = connector.execute(action)
        self.assertTrue(connector.verify(action, result).verified)
        compensation = connector.compensate(action, result)
        self.assertTrue(
            connector.verify_compensation(action, result, compensation).verified
        )

    def test_onenote_create_can_be_deleted_on_rollback(self) -> None:
        transport = ScriptedTransport()
        transport.add_json(
            "POST",
            "/v1.0/me/onenote/sections/section-1/pages",
            {"id": "page-1"},
            status=201,
        )
        metadata = {
            "id": "page-1",
            "title": "Status",
            "lastModifiedDateTime": "v1",
        }
        content = b"<html><body><h1>Status</h1><div>Ready</div></body></html>"
        for _ in range(2):
            transport.add_json("GET", "/v1.0/me/onenote/pages/page-1", metadata)
            transport.add_bytes("GET", "/v1.0/me/onenote/pages/page-1/content", content)
        transport.add_json("GET", "/v1.0/me/onenote/pages/page-1", metadata)
        transport.add_bytes("DELETE", "/v1.0/me/onenote/pages/page-1", b"", status=204)
        transport.add_json(
            "GET", "/v1.0/me/onenote/pages/page-1", {"error": "not found"}, status=404
        )
        connector = OneNoteWriteConnector(
            resolved_config(
                "microsoft",
                base_url="https://graph.microsoft.com/v1.0",
                extra={"identity_mode": "delegated"},
            ),
            transport=transport,
        )
        action = write_action(
            "onenote.page.create",
            system="onenote",
            resource_type="section",
            resource_id="section-1",
            parameters={
                "section_id": "section-1",
                "html": "<html><head><title>Status</title></head><body><div>Ready</div></body></html>",
            },
        )
        result = connector.execute(action)
        self.assertTrue(connector.verify(action, result).verified)
        compensation = connector.compensate(action, result)
        self.assertTrue(
            connector.verify_compensation(action, result, compensation).verified
        )

    def test_git_connector_pushes_and_rolls_back_only_new_agent_branch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            remote = root / "remote.git"
            repository = root / "repo"
            subprocess.run(
                ["git", "init", "--bare", str(remote)], check=True, capture_output=True
            )
            subprocess.run(
                ["git", "init", str(repository)], check=True, capture_output=True
            )
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repository),
                    "config",
                    "user.email",
                    "test@example.test",
                ],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(repository), "config", "user.name", "Test"],
                check=True,
            )
            (repository / "README.md").write_text("hello\n", encoding="utf-8")
            subprocess.run(
                ["git", "-C", str(repository), "add", "README.md"], check=True
            )
            subprocess.run(
                ["git", "-C", str(repository), "commit", "-m", "initial"],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "-C", str(repository), "checkout", "-b", "agent/test"],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "-C", str(repository), "remote", "add", "origin", str(remote)],
                check=True,
            )
            head = subprocess.run(
                ["git", "-C", str(repository), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()

            connector = GitBranchPushConnector(
                repository_root=root,
                allow_file_remotes=True,
            )
            action = write_action(
                "bitbucket.branch.push",
                system="bitbucket",
                resource_type="branch",
                resource_id="agent/test",
                parameters={
                    "repository_path": str(repository),
                    "branch": "agent/test",
                    "remote": "origin",
                    "remote_url": str(remote),
                },
                expected_version=head,
            )
            result = connector.execute(action)
            self.assertTrue(connector.verify(action, result).verified)
            compensation = connector.compensate(action, result)
            self.assertTrue(
                connector.verify_compensation(action, result, compensation).verified
            )


if __name__ == "__main__":
    unittest.main()

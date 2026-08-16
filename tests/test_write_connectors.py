"""Contract tests for approved reversible provider writes."""

from __future__ import annotations

import hashlib
import unittest
from pathlib import Path

from master_agent.config import DeploymentType
from master_agent.connectors.bitbucket_write import BitbucketWriteConnector
from master_agent.connectors.confluence_write import ConfluenceWriteConnector
from master_agent.connectors.jira_write import JiraWriteConnector
from master_agent.connectors.sharepoint_write import SharePointWriteConnector
from master_agent.errors import ConnectorError, VersionConflictError
from master_agent.models import AgentAction, RiskLevel
from tests.fakes import ScriptedTransport
from tests.helpers import action_for, private_temporary_directory, resolved_config


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
        self.assertEqual(
            put_requests[0].json_body()["fields"]["summary"], "New summary"
        )
        self.assertEqual(
            put_requests[1].json_body()["fields"]["summary"], "Old summary"
        )

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

    def test_provider_altered_first_update_poststate_is_rejected(self) -> None:
        transport = ScriptedTransport()
        path = "/rest/api/3/issue/RISE-1"
        transport.add_json("GET", path, _jira_issue("Old", "v1"))
        transport.add_bytes("PUT", path, b"", status=204)
        transport.add_json("GET", path, _jira_issue("PROVIDER ALTERED", "v2"))
        connector = JiraWriteConnector(
            resolved_config(
                "jira",
                deployment=DeploymentType.CLOUD,
                base_url="https://example.atlassian.net",
            ),
            transport=transport,
        )
        action = _jira_update_action()

        with self.assertRaisesRegex(ConnectorError, "poststate"):
            connector.execute(action)

    def test_fresh_update_verification_rejects_later_substitution(self) -> None:
        transport = ScriptedTransport()
        path = "/rest/api/3/issue/RISE-1"
        transport.add_json("GET", path, _jira_issue("Old", "v1"))
        transport.add_bytes("PUT", path, b"", status=204)
        transport.add_json("GET", path, _jira_issue("New summary", "v2"))
        transport.add_json("GET", path, _jira_issue("PROVIDER ALTERED", "v2"))
        connector = JiraWriteConnector(
            resolved_config(
                "jira",
                deployment=DeploymentType.CLOUD,
                base_url="https://example.atlassian.net",
            ),
            transport=transport,
        )
        action = _jira_update_action()

        result = connector.execute(action)

        self.assertFalse(connector.verify(action, result).verified)

    def test_unsupported_update_operator_is_rejected_before_network(self) -> None:
        transport = ScriptedTransport()
        connector = JiraWriteConnector(
            resolved_config(
                "jira",
                deployment=DeploymentType.CLOUD,
                base_url="https://example.atlassian.net",
            ),
            transport=transport,
        )
        action = _jira_update_action(
            parameters={
                "fields": {"summary": "New summary"},
                "update": {"labels": [{"add": "approved-label"}]},
            }
        )

        with self.assertRaisesRegex(ConnectorError, "operators are disabled"):
            connector.execute(action)
        self.assertEqual(transport.requests, [])

    def test_transition_requires_verifiable_reversible_shape(self) -> None:
        invalid_parameters = (
            {"transition_id": "31", "reverse_transition_id": "21"},
            {"transition_id": "31", "target_status": "Done"},
            {
                "transition_id": "31",
                "target_status": "Done",
                "reverse_transition_id": "21",
                "fields": {"resolution": {"name": "Fixed"}},
            },
        )
        for parameters in invalid_parameters:
            with self.subTest(parameters=parameters):
                transport = ScriptedTransport()
                connector = JiraWriteConnector(
                    resolved_config(
                        "jira",
                        deployment=DeploymentType.CLOUD,
                        base_url="https://example.atlassian.net",
                    ),
                    transport=transport,
                )
                action = _jira_transition_action(parameters)
                with self.assertRaises(ConnectorError):
                    connector.execute(action)
                self.assertEqual(transport.requests, [])

    def test_ignored_transition_is_rejected_at_first_poststate(self) -> None:
        transport = ScriptedTransport()
        path = "/rest/api/3/issue/RISE-1"
        transport.add_json("GET", path, _jira_issue("Old", "v1", status="Open"))
        transport.add_bytes("POST", path + "/transitions", b"", status=204)
        transport.add_json("GET", path, _jira_issue("Old", "v2", status="Open"))
        connector = JiraWriteConnector(
            resolved_config(
                "jira",
                deployment=DeploymentType.CLOUD,
                base_url="https://example.atlassian.net",
            ),
            transport=transport,
        )
        action = _jira_transition_action(
            {
                "transition_id": "31",
                "target_status": "Done",
                "reverse_transition_id": "21",
            }
        )

        with self.assertRaisesRegex(ConnectorError, "poststate"):
            connector.execute(action)

    def test_fresh_transition_verification_uses_approved_status(self) -> None:
        transport = ScriptedTransport()
        path = "/rest/api/3/issue/RISE-1"
        transport.add_json("GET", path, _jira_issue("Old", "v1", status="Open"))
        transport.add_bytes("POST", path + "/transitions", b"", status=204)
        transport.add_json("GET", path, _jira_issue("Old", "v2", status="Done"))
        transport.add_json("GET", path, _jira_issue("Old", "v2", status="Open"))
        connector = JiraWriteConnector(
            resolved_config(
                "jira",
                deployment=DeploymentType.CLOUD,
                base_url="https://example.atlassian.net",
            ),
            transport=transport,
        )
        action = _jira_transition_action(
            {
                "transition_id": "31",
                "target_status": "Done",
                "reverse_transition_id": "21",
            }
        )

        result = connector.execute(action)

        self.assertFalse(connector.verify(action, result).verified)

    def test_comment_verification_rejects_provider_added_adf_semantics(self) -> None:
        transport = ScriptedTransport()
        issue_path = "/rest/api/3/issue/RISE-1"
        collection = issue_path + "/comment"
        item = collection + "/7"
        altered = _jira_comment("7", "approved")
        altered["body"]["content"][0]["content"][0]["marks"] = [
            {
                "type": "link",
                "attrs": {"href": "https://evil.example"},
            }
        ]
        transport.add_json("GET", issue_path, _jira_issue("Old", "v1"))
        transport.add_json("POST", collection, {"id": "7"}, status=201)
        transport.add_json("GET", item, altered)
        connector = _jira_connector(transport)
        action = _jira_comment_action("approved")

        result = connector.execute(action)

        self.assertFalse(connector.verify(action, result).verified)

    def test_update_verification_rejects_json_type_substitution(self) -> None:
        transport = ScriptedTransport()
        path = "/rest/api/3/issue/RISE-1"
        before = _jira_issue("Old", "v1")
        before["fields"]["customfield_10000"] = 0
        altered = _jira_issue("Old", "v2")
        altered["fields"]["customfield_10000"] = True
        transport.add_json("GET", path, before)
        transport.add_bytes("PUT", path, b"", status=204)
        transport.add_json("GET", path, altered)
        connector = _jira_connector(transport)
        action = _jira_update_action(parameters={"fields": {"customfield_10000": 1}})

        with self.assertRaisesRegex(ConnectorError, "poststate"):
            connector.execute(action)

    def test_update_verification_accepts_exact_nested_json(self) -> None:
        transport = ScriptedTransport()
        path = "/rest/api/3/issue/RISE-1"
        before = _jira_issue("Old", "v1")
        changed = _jira_issue("Old", "v2")
        exact = {
            "priority": {"name": "High"},
            "components": [{"id": "10001"}],
        }
        changed["fields"].update(exact)
        transport.add_json("GET", path, before)
        transport.add_bytes("PUT", path, b"", status=204)
        transport.add_json("GET", path, changed)
        transport.add_json("GET", path, changed)
        connector = _jira_connector(transport)
        action = _jira_update_action(parameters={"fields": exact})

        result = connector.execute(action)

        self.assertTrue(connector.verify(action, result).verified)

    def test_comment_compensation_requires_provider_not_found(self) -> None:
        transport = ScriptedTransport()
        issue_path = "/rest/api/3/issue/RISE-1"
        collection = issue_path + "/comment"
        item = collection + "/7"
        transport.add_json("GET", issue_path, _jira_issue("Old", "v1"))
        transport.add_json("GET", issue_path, _jira_issue("Old", "v2"))
        transport.add_json("POST", collection, {"id": "7"}, status=201)
        transport.add_json("GET", item, _jira_comment("7", "approved"))
        transport.add_json("GET", item, _jira_comment("7", "approved"))
        transport.add_bytes("GET", item, b"{}", status=404)
        transport.add_bytes("DELETE", item, b"", status=204)
        connector = _jira_connector(transport)
        action = _jira_comment_action("approved")

        result = connector.execute(action)
        self.assertTrue(connector.verify(action, result).verified)
        compensation = connector.compensate(action, result)
        request_count = len(transport.requests)
        verification = connector.verify_compensation(action, result, compensation)

        self.assertTrue(verification.verified)
        self.assertEqual(verification.observed, {"comment_id": "7", "exists": False})
        self.assertEqual(len(transport.requests), request_count + 1)
        self.assertEqual(transport.requests[-1].method, "GET")

    def test_comment_compensation_rejects_still_present_comment(self) -> None:
        transport = ScriptedTransport()
        issue_path = "/rest/api/3/issue/RISE-1"
        collection = issue_path + "/comment"
        item = collection + "/7"
        transport.add_json("GET", issue_path, _jira_issue("Old", "v1"))
        transport.add_json("GET", issue_path, _jira_issue("Old", "v2"))
        transport.add_json("POST", collection, {"id": "7"}, status=201)
        transport.add_json("GET", item, _jira_comment("7", "approved"))
        transport.add_json("GET", item, _jira_comment("7", "approved"))
        transport.add_json("GET", item, _jira_comment("7", "approved"))
        transport.add_bytes("DELETE", item, b"", status=204)
        connector = _jira_connector(transport)
        action = _jira_comment_action("approved")

        result = connector.execute(action)
        self.assertTrue(connector.verify(action, result).verified)
        compensation = connector.compensate(action, result)
        verification = connector.verify_compensation(action, result, compensation)

        self.assertFalse(verification.verified)
        observed = verification.observed
        self.assertIsNotNone(observed)
        assert observed is not None
        self.assertEqual(observed["comment_id"], "7")

    def test_comment_compensation_does_not_treat_other_errors_as_absence(self) -> None:
        transport = ScriptedTransport()
        issue_path = "/rest/api/3/issue/RISE-1"
        collection = issue_path + "/comment"
        item = collection + "/7"
        transport.add_json("GET", issue_path, _jira_issue("Old", "v1"))
        transport.add_json("GET", issue_path, _jira_issue("Old", "v2"))
        transport.add_json("POST", collection, {"id": "7"}, status=201)
        transport.add_json("GET", item, _jira_comment("7", "approved"))
        transport.add_json("GET", item, _jira_comment("7", "approved"))
        transport.add_bytes("GET", item, b"{}", status=400)
        transport.add_bytes("DELETE", item, b"", status=204)
        connector = _jira_connector(transport)
        action = _jira_comment_action("approved")

        result = connector.execute(action)
        self.assertTrue(connector.verify(action, result).verified)
        compensation = connector.compensate(action, result)

        with self.assertRaises(ConnectorError):
            connector.verify_compensation(action, result, compensation)

    def test_update_compensation_verification_rejects_later_substitution(
        self,
    ) -> None:
        transport = ScriptedTransport()
        path = "/rest/api/3/issue/RISE-1"
        old = _jira_issue("Old summary", "v1")
        changed = _jira_issue("New summary", "v2")
        restored = _jira_issue("Old summary", "v3")
        substituted = _jira_issue("PROVIDER ALTERED", "v3")
        for payload in (
            old,
            changed,
            changed,
            changed,
            changed,
            restored,
            substituted,
        ):
            transport.add_json("GET", path, payload)
        transport.add_bytes("PUT", path, b"", status=204)
        transport.add_bytes("PUT", path, b"", status=204)
        connector = _jira_connector(transport)
        action = _jira_update_action()

        result = connector.execute(action)
        self.assertTrue(connector.verify(action, result).verified)
        compensation = connector.compensate(action, result)

        self.assertFalse(
            connector.verify_compensation(action, result, compensation).verified
        )

    def test_transition_compensation_verification_rejects_later_substitution(
        self,
    ) -> None:
        transport = ScriptedTransport()
        path = "/rest/api/3/issue/RISE-1"
        transition_path = path + "/transitions"
        old = _jira_issue("Old", "v1", status="Open")
        changed = _jira_issue("Old", "v2", status="Done")
        restored = _jira_issue("Old", "v3", status="Open")
        substituted = _jira_issue("Old", "v3", status="Done")
        for payload in (old, changed, changed, changed, restored, substituted):
            transport.add_json("GET", path, payload)
        transport.add_bytes("POST", transition_path, b"", status=204)
        transport.add_bytes("POST", transition_path, b"", status=204)
        connector = _jira_connector(transport)
        action = _jira_transition_action(
            {
                "transition_id": "31",
                "target_status": "Done",
                "reverse_transition_id": "21",
            }
        )

        result = connector.execute(action)
        self.assertTrue(connector.verify(action, result).verified)
        compensation = connector.compensate(action, result)

        self.assertFalse(
            connector.verify_compensation(action, result, compensation).verified
        )


class ConfluenceWriteConnectorTests(unittest.TestCase):
    """Validate cloud page update and exact-content rollback."""

    def test_cloud_space_create_verify_and_compensate(self) -> None:
        transport = ScriptedTransport()
        collection = "/wiki/api/v2/spaces"
        item = "/wiki/api/v2/spaces/9001"
        deletion = "/wiki/rest/api/space/BMS"
        space = _confluence_space()
        transport.add_json("POST", collection, {"id": "9001"}, status=201)
        for _ in range(3):
            transport.add_json("GET", item, space)
        transport.add_json(
            "GET",
            item + "/pages",
            {"results": [{"id": "HOME"}]},
        )
        transport.add_bytes("DELETE", deletion, b"", status=202)
        transport.add_bytes("GET", item, b"{}", status=404)
        connector = _confluence_connector(transport)
        action = _confluence_space_action()

        result = connector.execute(action)
        self.assertTrue(connector.verify(action, result).verified)
        compensation = connector.compensate(action, result)
        self.assertTrue(
            connector.verify_compensation(action, result, compensation).verified
        )
        self.assertEqual(result.after["key"], "BMS")
        self.assertTrue(compensation.after["deleted"])

    def test_space_compensation_refuses_concurrently_added_page(self) -> None:
        transport = ScriptedTransport()
        collection = "/wiki/api/v2/spaces"
        item = "/wiki/api/v2/spaces/9001"
        transport.add_json("POST", collection, {"id": "9001"}, status=201)
        transport.add_json("GET", item, _confluence_space())
        transport.add_json("GET", item, _confluence_space())
        transport.add_json(
            "GET",
            item + "/pages",
            {"results": [{"id": "HOME"}, {"id": "OTHER"}]},
        )
        connector = _confluence_connector(transport)
        action = _confluence_space_action()
        result = connector.execute(action)

        with self.assertRaisesRegex(VersionConflictError, "another page"):
            connector.compensate(action, result)

        self.assertNotIn("DELETE", [request.method for request in transport.requests])

    def test_cloud_page_create_resolves_approved_space_key(self) -> None:
        transport = ScriptedTransport()
        transport.add_json(
            "GET",
            "/wiki/api/v2/spaces",
            {"results": [_confluence_space()]},
        )
        transport.add_json(
            "POST",
            "/wiki/api/v2/pages",
            {"id": "42"},
            status=200,
        )
        transport.add_json(
            "GET",
            "/wiki/api/v2/pages/42",
            _confluence_page("Status", "<p>Approved</p>", 1, space_id="9001"),
        )
        connector = _confluence_connector(transport)
        action = action_for(
            "confluence.page.create",
            system="confluence",
            resource_type="page",
            resource_id="new",
            risk=RiskLevel.REVERSIBLE_WRITE,
            parameters={
                "space_key": "bms",
                "title": "Status",
                "body": "<p>Approved</p>",
                "representation": "storage",
                "status": "current",
            },
        )

        result = connector.execute(action)

        self.assertEqual(result.after["space_id"], "9001")
        self.assertIn("keys=BMS", transport.requests[0].url)

    def test_space_create_rejects_provider_identity_change(self) -> None:
        transport = ScriptedTransport()
        transport.add_json(
            "POST",
            "/wiki/api/v2/spaces",
            {"id": "9001"},
            status=201,
        )
        transport.add_json(
            "GET",
            "/wiki/api/v2/spaces/9001",
            _confluence_space(name="Provider altered"),
        )
        connector = _confluence_connector(transport)

        with self.assertRaisesRegex(ConnectorError, "poststate"):
            connector.execute(_confluence_space_action())

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
        writes = [
            item.json_body() for item in transport.requests if item.method == "PUT"
        ]
        self.assertEqual(writes[0]["version"]["number"], 5)
        self.assertEqual(writes[1]["version"]["number"], 6)

    def test_update_rejects_provider_altered_first_poststate(self) -> None:
        transport = ScriptedTransport()
        path = "/wiki/api/v2/pages/42"
        transport.add_json("GET", path, _confluence_page("Status", "<p>Old</p>", 4))
        transport.add_json(
            "GET",
            path,
            _confluence_page("Status", "<p>PROVIDER ALTERED</p>", 5),
        )
        transport.add_json("PUT", path, {})
        connector = _confluence_connector(transport)
        action = _confluence_update_action("<p>Approved</p>")

        with self.assertRaisesRegex(ConnectorError, "poststate"):
            connector.execute(action)

        self.assertEqual(
            [request.method for request in transport.requests],
            ["GET", "PUT", "GET"],
        )

    def test_update_verification_compares_provider_to_approved_action(self) -> None:
        transport = ScriptedTransport()
        path = "/wiki/api/v2/pages/42"
        transport.add_json("GET", path, _confluence_page("Status", "<p>Old</p>", 4))
        transport.add_json(
            "GET",
            path,
            _confluence_page("Status", "<p>Approved</p>", 5),
        )
        transport.add_json(
            "GET",
            path,
            _confluence_page("Status", "<p>PROVIDER ALTERED</p>", 5),
        )
        transport.add_json("PUT", path, {})
        connector = _confluence_connector(transport)
        action = _confluence_update_action("<p>Approved</p>")

        result = connector.execute(action)
        verification = connector.verify(action, result)

        self.assertFalse(verification.verified)
        self.assertEqual(
            verification.observed["body"],
            "<p>PROVIDER ALTERED</p>",
        )

    def test_update_rejects_provider_representation_change(self) -> None:
        transport = ScriptedTransport()
        path = "/wiki/api/v2/pages/42"
        body = '{"type":"doc","version":1}'
        transport.add_json("GET", path, _confluence_page("Status", "<p>Old</p>", 4))
        transport.add_json(
            "GET",
            path,
            _confluence_page("Status", body, 5, representation="storage"),
        )
        transport.add_json("PUT", path, {})
        connector = _confluence_connector(transport)
        action = _confluence_update_action(
            body,
            representation="atlas_doc_format",
        )

        with self.assertRaisesRegex(ConnectorError, "poststate"):
            connector.execute(action)

    def test_update_rejects_wrong_resulting_identity_or_version(self) -> None:
        cases = (
            _confluence_page("Status", "<p>Approved</p>", 6),
            _confluence_page(
                "Status",
                "<p>Approved</p>",
                5,
                page_id="99",
            ),
        )
        for altered in cases:
            with self.subTest(altered=altered):
                transport = ScriptedTransport()
                path = "/wiki/api/v2/pages/42"
                transport.add_json(
                    "GET",
                    path,
                    _confluence_page("Status", "<p>Old</p>", 4),
                )
                transport.add_json("GET", path, altered)
                transport.add_json("PUT", path, {})
                connector = _confluence_connector(transport)

                with self.assertRaisesRegex(ConnectorError, "poststate"):
                    connector.execute(_confluence_update_action("<p>Approved</p>"))

    def test_update_verifies_approved_atlas_representation(self) -> None:
        transport = ScriptedTransport()
        path = "/wiki/api/v2/pages/42"
        body = '{"type":"doc","version":1}'
        transport.add_json("GET", path, _confluence_page("Status", "<p>Old</p>", 4))
        for _ in range(2):
            transport.add_json(
                "GET",
                path,
                _confluence_page(
                    "Status",
                    body,
                    5,
                    representation="atlas_doc_format",
                ),
            )
        transport.add_json("PUT", path, {})
        connector = _confluence_connector(transport)
        action = _confluence_update_action(
            body,
            representation="atlas_doc_format",
        )

        result = connector.execute(action)
        verification = connector.verify(action, result)

        self.assertTrue(verification.verified)
        self.assertIn("body-format=atlas_doc_format", transport.requests[-1].url)

    def test_create_rejects_provider_altered_first_poststate(self) -> None:
        transport = ScriptedTransport()
        collection = "/wiki/api/v2/pages"
        item = "/wiki/api/v2/pages/42"
        transport.add_json("POST", collection, {"id": "42"}, status=201)
        transport.add_json(
            "GET",
            item,
            _confluence_page("Status", "<p>PROVIDER ALTERED</p>", 1),
        )
        connector = _confluence_connector(transport)
        action = _confluence_create_action("<p>Approved</p>")

        with self.assertRaisesRegex(ConnectorError, "poststate"):
            connector.execute(action)

    def test_create_rejects_wrong_resulting_identity_or_version(self) -> None:
        cases = (
            _confluence_page("Status", "<p>Approved</p>", 2),
            _confluence_page(
                "Status",
                "<p>Approved</p>",
                1,
                page_id="99",
            ),
        )
        for altered in cases:
            with self.subTest(altered=altered):
                transport = ScriptedTransport()
                collection = "/wiki/api/v2/pages"
                item = "/wiki/api/v2/pages/42"
                transport.add_json(
                    "POST",
                    collection,
                    {"id": "42"},
                    status=201,
                )
                transport.add_json("GET", item, altered)
                connector = _confluence_connector(transport)

                with self.assertRaisesRegex(ConnectorError, "poststate"):
                    connector.execute(_confluence_create_action("<p>Approved</p>"))

    def test_create_verification_compares_provider_to_approved_action(self) -> None:
        transport = ScriptedTransport()
        collection = "/wiki/api/v2/pages"
        item = "/wiki/api/v2/pages/42"
        transport.add_json("POST", collection, {"id": "42"}, status=201)
        transport.add_json(
            "GET",
            item,
            _confluence_page("Status", "<p>Approved</p>", 1),
        )
        transport.add_json(
            "GET",
            item,
            _confluence_page("Status", "<p>PROVIDER ALTERED</p>", 1),
        )
        connector = _confluence_connector(transport)
        action = _confluence_create_action("<p>Approved</p>")

        result = connector.execute(action)
        verification = connector.verify(action, result)

        self.assertFalse(verification.verified)
        self.assertEqual(result.after["id"], "42")
        self.assertEqual(result.after["version"], 1)


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

    def test_altered_first_provider_poststate_is_rejected(self) -> None:
        approved = _cloud_pr("OPEN")
        alterations = {
            "id": None,
            "title": "PROVIDER ALTERED",
            "description": "PROVIDER ALTERED",
            "source": {"branch": {"name": "attacker/source"}},
            "destination": {"branch": {"name": "production"}},
            "close_source_branch": True,
        }
        for field, value in alterations.items():
            with self.subTest(field=field):
                transport = ScriptedTransport()
                collection = "/2.0/repositories/acme/service/pullrequests"
                item = collection + "/9"
                transport.add_json("POST", collection, {"id": 9}, status=201)
                transport.add_json("GET", item, {**approved, field: value})
                connector = _bitbucket_cloud_connector(transport)

                with self.assertRaisesRegex(ConnectorError, "poststate"):
                    connector.execute(_bitbucket_action())

    def test_fresh_verification_uses_approved_action_not_first_read(self) -> None:
        transport = ScriptedTransport()
        collection = "/2.0/repositories/acme/service/pullrequests"
        item = collection + "/9"
        transport.add_json("POST", collection, {"id": 9}, status=201)
        transport.add_json("GET", item, _cloud_pr("OPEN"))
        transport.add_json(
            "GET",
            item,
            {**_cloud_pr("OPEN"), "title": "PROVIDER ALTERED"},
        )
        connector = _bitbucket_cloud_connector(transport)
        action = _bitbucket_action()

        result = connector.execute(action)

        self.assertFalse(connector.verify(action, result).verified)

    def test_data_center_fields_are_normalized_and_verified(self) -> None:
        transport = ScriptedTransport()
        collection = "/rest/api/1.0/projects/PROJ/repos/service/pull-requests"
        item = collection + "/7"
        exact = _server_pr("OPEN")
        transport.add_json("POST", collection, {"id": 7}, status=201)
        transport.add_json("GET", item, exact)
        transport.add_json("GET", item, exact)
        connector = BitbucketWriteConnector(
            resolved_config(
                "bitbucket",
                deployment=DeploymentType.DATA_CENTER,
                base_url="https://bitbucket.example",
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
                "project_key": "PROJ",
                "repository_slug": "service",
                "title": "Agent change",
                "description": "Reviewed proposal",
                "source_branch": "agent/change",
                "destination_branch": "main",
            },
        )

        result = connector.execute(action)

        self.assertTrue(connector.verify(action, result).verified)

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

    def test_exact_lifecycle_requires_sufficient_request_budget(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory) / "artifacts"
            with self.assertRaisesRegex(ConnectorError, "at least 12"):
                SharePointWriteConnector(
                    resolved_config(
                        "microsoft",
                        base_url="https://graph.microsoft.com/v1.0",
                        max_pages=11,
                    ),
                    artifact_root=root,
                    transport=ScriptedTransport(),
                )
            self.assertFalse(root.exists())

    def test_existing_file_is_overwritten_and_restored(self) -> None:
        with private_temporary_directory() as directory:
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
            transport.add_bytes("GET", content, b"old")
            transport.add_json("GET", versions, {"value": [{"id": "3"}]})
            transport.add_bytes("PUT", content, b"", status=200)
            transport.add_json("GET", item, after)
            transport.add_bytes("GET", content, b"new content")
            transport.add_bytes("GET", content, b"new content")
            transport.add_json("GET", item, after)
            transport.add_bytes("POST", restore, b"", status=204)
            transport.add_json("GET", item, restored)
            transport.add_bytes("GET", content, b"old")
            transport.add_bytes("GET", content, b"old")
            connector = SharePointWriteConnector(
                resolved_config(
                    "microsoft",
                    base_url="https://graph.microsoft.com/v1.0",
                    extra={
                        "identity_mode": "delegated",
                        "max_upload_bytes": 1000,
                    },
                    max_pages=12,
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
                    "local_sha256": hashlib.sha256(local.read_bytes()).hexdigest(),
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

    def test_same_size_provider_substitution_is_rejected(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            local = root / "status.txt"
            local.write_bytes(b"GOOD")
            transport = ScriptedTransport()
            item = "/v1.0/drives/drive/items/item"
            content = item + "/content"
            transport.add_json("GET", item, _drive_item("status.txt", 4, "e1"))
            transport.add_bytes("GET", content, b"OLD!")
            transport.add_json("GET", item + "/versions", {"value": [{"id": "1"}]})
            transport.add_bytes("PUT", content, b"", status=200)
            transport.add_json("GET", item, _drive_item("status.txt", 4, "e2"))
            transport.add_bytes("GET", content, b"EVIL")
            connector = _sharepoint_connector(root, transport)
            action = _sharepoint_action(local, expected_version="e1")

            with self.assertRaisesRegex(ConnectorError, "approved bytes"):
                connector.execute(action)

    def test_fresh_content_verification_rejects_later_substitution(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            local = root / "status.txt"
            local.write_bytes(b"GOOD")
            transport = ScriptedTransport()
            item = "/v1.0/drives/drive/items/item"
            content = item + "/content"
            transport.add_json("GET", item, _drive_item("status.txt", 4, "e1"))
            transport.add_bytes("GET", content, b"OLD!")
            transport.add_json("GET", item + "/versions", {"value": [{"id": "1"}]})
            transport.add_bytes("PUT", content, b"", status=200)
            transport.add_json("GET", item, _drive_item("status.txt", 4, "e2"))
            transport.add_bytes("GET", content, b"GOOD")
            transport.add_bytes("GET", content, b"EVIL")
            connector = _sharepoint_connector(root, transport)
            action = _sharepoint_action(local, expected_version="e1")

            result = connector.execute(action)

            self.assertFalse(connector.verify(action, result).verified)

    def test_restore_rejects_same_size_wrong_prior_bytes(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            local = root / "status.txt"
            local.write_bytes(b"GOOD")
            transport = ScriptedTransport()
            item = "/v1.0/drives/drive/items/item"
            content = item + "/content"
            versions = item + "/versions"
            transport.add_json("GET", item, _drive_item("status.txt", 4, "e1"))
            transport.add_bytes("GET", content, b"OLD!")
            transport.add_json("GET", versions, {"value": [{"id": "1"}]})
            transport.add_bytes("PUT", content, b"", status=200)
            transport.add_json("GET", item, _drive_item("status.txt", 4, "e2"))
            transport.add_bytes("GET", content, b"GOOD")
            transport.add_json("GET", item, _drive_item("status.txt", 4, "e2"))
            transport.add_bytes("POST", versions + "/1/restoreVersion", b"", status=204)
            transport.add_json("GET", item, _drive_item("status.txt", 4, "e3"))
            transport.add_bytes("GET", content, b"EVIL")
            connector = _sharepoint_connector(root, transport)
            action = _sharepoint_action(local, expected_version="e1")
            result = connector.execute(action)

            with self.assertRaisesRegex(ConnectorError, "prior bytes"):
                connector.compensate(action, result)

    def test_file_outside_artifact_root_is_rejected_before_network(self) -> None:
        with private_temporary_directory() as directory:
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
                    max_pages=12,
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


def _jira_issue(
    summary: str,
    updated: str,
    *,
    status: str = "In Progress",
) -> dict[str, object]:
    return {
        "id": "10001",
        "key": "RISE-1",
        "fields": {
            "summary": summary,
            "updated": updated,
            "status": {"name": status},
        },
    }


def _jira_update_action(
    *,
    parameters: dict[str, object] | None = None,
) -> AgentAction:
    return action_for(
        "jira.issue.update",
        system="jira",
        resource_type="issue",
        resource_id="RISE-1",
        risk=RiskLevel.REVERSIBLE_WRITE,
        expected_version="v1",
        parameters=parameters or {"fields": {"summary": "New summary"}},
    )


def _jira_comment_action(body: str) -> AgentAction:
    return action_for(
        "jira.issue.comment.create",
        system="jira",
        resource_type="issue",
        resource_id="RISE-1",
        risk=RiskLevel.REVERSIBLE_WRITE,
        expected_version="v1",
        parameters={"body": body},
    )


def _jira_transition_action(parameters: dict[str, object]) -> AgentAction:
    return action_for(
        "jira.issue.transition",
        system="jira",
        resource_type="issue",
        resource_id="RISE-1",
        risk=RiskLevel.REVERSIBLE_WRITE,
        expected_version="v1",
        parameters=parameters,
    )


def _jira_connector(transport: ScriptedTransport) -> JiraWriteConnector:
    return JiraWriteConnector(
        resolved_config(
            "jira",
            deployment=DeploymentType.CLOUD,
            base_url="https://example.atlassian.net",
        ),
        transport=transport,
    )


def _jira_comment(comment_id: str, body: str) -> dict[str, object]:
    return {
        "id": comment_id,
        "body": {
            "type": "doc",
            "version": 1,
            "content": [
                {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": body}],
                }
            ],
        },
    }


def _confluence_connector(
    transport: ScriptedTransport,
) -> ConfluenceWriteConnector:
    return ConfluenceWriteConnector(
        resolved_config(
            "confluence",
            deployment=DeploymentType.CLOUD,
            base_url="https://example.atlassian.net",
        ),
        transport=transport,
    )


def _confluence_update_action(
    body: str,
    *,
    representation: str = "storage",
) -> AgentAction:
    return action_for(
        "confluence.page.update",
        system="confluence",
        resource_type="page",
        resource_id="42",
        risk=RiskLevel.REVERSIBLE_WRITE,
        expected_version="4",
        parameters={
            "title": "Status",
            "body": body,
            "representation": representation,
            "status": "current",
        },
    )


def _confluence_create_action(body: str) -> AgentAction:
    return action_for(
        "confluence.page.create",
        system="confluence",
        resource_type="page",
        resource_id="new",
        risk=RiskLevel.REVERSIBLE_WRITE,
        parameters={
            "space_id": "SPACE",
            "title": "Status",
            "body": body,
            "representation": "storage",
            "status": "current",
        },
    )


def _confluence_page(
    title: str,
    body: str,
    version: int,
    *,
    representation: str = "storage",
    page_id: str = "42",
    space_id: str = "SPACE",
) -> dict[str, object]:
    return {
        "id": page_id,
        "title": title,
        "status": "current",
        "spaceId": space_id,
        "version": {"number": version},
        "body": {
            representation: {
                "representation": representation,
                "value": body,
            }
        },
    }


def _confluence_space_action() -> AgentAction:
    return action_for(
        "confluence.space.create",
        system="confluence",
        resource_type="space",
        resource_id="BMS",
        risk=RiskLevel.REVERSIBLE_WRITE,
        parameters={
            "key": "BMS",
            "name": "Blow Me Sideways",
            "description": "A private educational space.",
        },
    )


def _confluence_space(
    *,
    name: str = "Blow Me Sideways",
) -> dict[str, object]:
    return {
        "id": "9001",
        "key": "BMS",
        "name": name,
        "type": "global",
        "status": "current",
        "homepageId": "HOME",
    }


def _cloud_pr(state: str) -> dict[str, object]:
    return {
        "id": 9,
        "title": "Agent change",
        "description": "Reviewed proposal",
        "source": {"branch": {"name": "agent/change"}},
        "destination": {"branch": {"name": "main"}},
        "close_source_branch": False,
        "state": state,
        "updated_on": "2026-08-13T20:00:00Z",
        "links": {"html": {"href": "https://bitbucket.example/pr/9"}},
    }


def _server_pr(state: str) -> dict[str, object]:
    return {
        "id": 7,
        "title": "Agent change",
        "description": "Reviewed proposal",
        "fromRef": {"id": "refs/heads/agent/change"},
        "toRef": {"id": "refs/heads/main"},
        "state": state,
        "version": 1,
    }


def _bitbucket_cloud_connector(
    transport: ScriptedTransport,
) -> BitbucketWriteConnector:
    return BitbucketWriteConnector(
        resolved_config(
            "bitbucket",
            deployment=DeploymentType.CLOUD,
            base_url="https://api.bitbucket.org/2.0",
        ),
        transport=transport,
    )


def _bitbucket_action() -> AgentAction:
    return action_for(
        "bitbucket.pull_request.create",
        system="bitbucket",
        resource_type="pull_request",
        resource_id="new",
        risk=RiskLevel.REVERSIBLE_WRITE,
        parameters={
            "workspace": "acme",
            "repository": "service",
            "title": "Agent change",
            "description": "Reviewed proposal",
            "source_branch": "agent/change",
            "destination_branch": "main",
        },
    )


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


def _sharepoint_connector(
    root: Path,
    transport: ScriptedTransport,
) -> SharePointWriteConnector:
    return SharePointWriteConnector(
        resolved_config(
            "microsoft",
            base_url="https://graph.microsoft.com/v1.0",
            extra={"identity_mode": "delegated", "max_upload_bytes": 1000},
            max_pages=12,
        ),
        artifact_root=root,
        transport=transport,
    )


def _sharepoint_action(local: Path, *, expected_version: str) -> AgentAction:
    return action_for(
        "sharepoint.file.upload",
        system="sharepoint",
        resource_type="file",
        resource_id="item",
        risk=RiskLevel.REVERSIBLE_WRITE,
        expected_version=expected_version,
        parameters={
            "drive_id": "drive",
            "local_path": str(local),
            "local_sha256": hashlib.sha256(local.read_bytes()).hexdigest(),
            "content_type": "text/plain",
        },
    )


if __name__ == "__main__":
    unittest.main()

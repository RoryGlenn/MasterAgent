"""Contract tests for delegated OneNote read and write capabilities."""

from __future__ import annotations

import unittest

from master_agent.connectors.onenote import OneNoteReadConnector, OneNoteWriteConnector
from master_agent.errors import ConnectorError
from master_agent.models import RiskLevel
from tests.fakes import ScriptedTransport
from tests.helpers import action_for, read_action, resolved_config


class OneNoteReadConnectorTests(unittest.TestCase):
    """Validate bounded page discovery and content reads."""

    def test_page_read_returns_untrusted_html_with_digest(self) -> None:
        transport = ScriptedTransport()
        metadata_path = "/v1.0/me/onenote/pages/page-1"
        content_path = metadata_path + "/content"
        metadata = _page_metadata("page-1", "Status", "2026-08-13T20:00:00Z")
        html = b'<html><body id="body"><p>Status is green.</p></body></html>'
        # ReadOnlyConnector performs one execution retrieval and one verification retrieval.
        transport.add_json("GET", metadata_path, metadata)
        transport.add_bytes("GET", content_path, html)
        connector = OneNoteReadConnector(
            resolved_config(
                "microsoft",
                base_url="https://graph.microsoft.com/v1.0",
                extra={"identity_mode": "delegated"},
            ),
            transport=transport,
        )
        action = read_action(
            "onenote.page.read",
            system="onenote",
            resource_type="page",
            resource_id="page-1",
            expected_version="2026-08-13T20:00:00Z",
        )

        result = connector.execute(action)
        verification = connector.verify(action, result)

        self.assertTrue(verification.verified)
        self.assertEqual(result.after["page"]["title"], "Status")
        self.assertIn("Status is green", result.after["page"]["content_html"])
        self.assertTrue(result.after["security"]["content_is_untrusted"])

    def test_application_identity_is_rejected(self) -> None:
        with self.assertRaises(ConnectorError):
            OneNoteReadConnector(
                resolved_config(
                    "microsoft",
                    base_url="https://graph.microsoft.com/v1.0",
                    extra={"identity_mode": "application"},
                )
            )


class OneNoteWriteConnectorTests(unittest.TestCase):
    """Validate delegated update and compensation."""

    def test_update_and_restore_previous_html(self) -> None:
        transport = ScriptedTransport()
        metadata_path = "/v1.0/me/onenote/pages/page-1"
        content_path = metadata_path + "/content"
        old_metadata = _page_metadata("page-1", "Status", "2026-08-13T20:00:00Z")
        new_metadata = _page_metadata("page-1", "Status", "2026-08-13T20:01:00Z")
        restored_metadata = _page_metadata("page-1", "Status", "2026-08-13T20:02:00Z")
        old_html = b'<html><body id="body"><p>Old</p></body></html>'
        new_html = b'<html><body id="body"><p>New</p></body></html>'
        # Execute: old metadata/content, PATCH, new metadata/content.
        # Verify: new metadata/content.
        # Compensate: current metadata, PATCH, restored metadata/content.
        for payload in (
            old_metadata,
            new_metadata,
            new_metadata,
            new_metadata,
            restored_metadata,
        ):
            transport.add_json("GET", metadata_path, payload)
        for payload in (old_html, new_html, new_html, old_html):
            transport.add_bytes("GET", content_path, payload)
        transport.add_bytes("PATCH", content_path, b"", status=204)
        transport.add_bytes("PATCH", content_path, b"", status=204)
        connector = OneNoteWriteConnector(
            resolved_config(
                "microsoft",
                base_url="https://graph.microsoft.com/v1.0",
                extra={"identity_mode": "delegated"},
            ),
            transport=transport,
        )
        action = action_for(
            "onenote.page.update",
            system="onenote",
            resource_type="page",
            resource_id="page-1",
            risk=RiskLevel.REVERSIBLE_WRITE,
            expected_version="2026-08-13T20:00:00Z",
            parameters={
                "identity": "me",
                "commands": [
                    {"target": "body", "action": "replace", "content": "<p>New</p>"}
                ],
            },
        )

        result = connector.execute(action)
        self.assertTrue(connector.verify(action, result).verified)
        compensation = connector.compensate(action, result)
        self.assertTrue(
            connector.verify_compensation(action, result, compensation).verified
        )
        patch_bodies = [
            request.json_body()
            for request in transport.requests
            if request.method == "PATCH"
        ]
        self.assertEqual(patch_bodies[0][0]["content"], "<p>New</p>")
        self.assertIn("<p>Old</p>", patch_bodies[1][0]["content"])

    def test_application_identity_is_rejected(self) -> None:
        with self.assertRaises(ConnectorError):
            OneNoteWriteConnector(
                resolved_config(
                    "microsoft",
                    base_url="https://graph.microsoft.com/v1.0",
                    extra={"identity_mode": "application"},
                )
            )


def _page_metadata(page_id: str, title: str, modified: str) -> dict[str, object]:
    return {
        "id": page_id,
        "title": title,
        "createdDateTime": "2026-08-13T19:00:00Z",
        "lastModifiedDateTime": modified,
        "parentSection": {"id": "section-1"},
        "links": {"oneNoteWebUrl": {"href": f"https://onenote.example/{page_id}"}},
    }


if __name__ == "__main__":
    unittest.main()

"""Contract tests for delegated OneNote read and disabled write capabilities."""

from __future__ import annotations

import unittest

from master_agent.connectors.onenote import OneNoteReadConnector, OneNoteWriteConnector
from master_agent.errors import ConnectorError
from tests.fakes import ScriptedTransport
from tests.helpers import read_action, resolved_config


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
    """Validate the fail-closed compatibility surface."""

    def test_write_capabilities_are_disabled_before_network(self) -> None:
        transport = ScriptedTransport()
        self.assertEqual(OneNoteWriteConnector._CAPABILITIES, frozenset())
        with self.assertRaisesRegex(ConnectorError, "OneNote writes are disabled"):
            OneNoteWriteConnector(
                resolved_config(
                    "microsoft",
                    base_url="https://graph.microsoft.com/v1.0",
                    extra={"identity_mode": "delegated"},
                ),
                transport=transport,
            )
        self.assertEqual(transport.requests, [])

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

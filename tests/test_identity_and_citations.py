"""Cross-system identity and enterprise citation tests."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from master_agent.citations import (
    enrich_resource_citations,
    find_citations,
    make_resource_citation,
)
from master_agent.connectors.identity import IdentityMapConnector
from master_agent.errors import ConfigurationError
from master_agent.identity import IdentityRegistry
from tests.helpers import read_action


class IdentityRegistryTests(unittest.TestCase):
    """Verify exact, unambiguous cross-system person resolution."""

    def test_alias_and_system_identifier_resolution(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "identities.toml"
            path.write_text(
                """
[people.rory]
display_name = "Rory Glenn"
aliases = ["Rory", "R. Glenn"]

[people.rory.identifiers]
microsoft = "user-123"
email = "rory@example.com"
jira = "jira-account-1"
""".strip(),
                encoding="utf-8",
            )
            registry = IdentityRegistry.from_toml(path)

        person = registry.resolve("r. glenn")

        self.assertEqual(person.key, "rory")
        self.assertEqual(registry.resolve_identifier("Rory", "microsoft"), "user-123")
        self.assertEqual(
            registry.correlate_microsoft_user(
                {
                    "id": "user-123",
                    "display_name": "Rory Glenn",
                    "mail": "rory@example.com",
                }
            ),
            person,
        )

    def test_ambiguous_alias_fails_closed(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "identities.toml"
            path.write_text(
                """
[people.one]
display_name = "Alex One"
aliases = ["Alex"]

[people.two]
display_name = "Alex Two"
aliases = ["Alex"]
""".strip(),
                encoding="utf-8",
            )
            registry = IdentityRegistry.from_toml(path)

        with self.assertRaisesRegex(ConfigurationError, "ambiguous"):
            registry.resolve("Alex")

    def test_identity_connector_returns_cited_read_only_evidence(self) -> None:
        registry = IdentityRegistry.from_toml(
            Path(__file__).resolve().parents[1] / "config" / "identities.toml"
        )
        connector = IdentityMapConnector(registry)
        action = read_action(
            "identity.person.resolve",
            system="identity",
            resource_type="person",
            resource_id="Rory",
            parameters={"query": "Rory"},
        )

        result = connector.execute(action)
        verification = connector.verify(action, result)

        self.assertTrue(verification.verified)
        self.assertEqual(result.after["person"]["key"], "rory")
        self.assertTrue(result.after["person"]["citation_id"].startswith("CIT-"))
        self.assertEqual(result.after["retention"]["evidence_type"], "identity.mapping.metadata")


class CitationTests(unittest.TestCase):
    """Verify stable, secret-safe citation generation."""

    def test_citation_is_stable_and_strips_query_and_fragment(self) -> None:
        first = make_resource_citation(
            system="outlook",
            resource_type="message",
            resource_id="message-1",
            title="Release status",
            url="https://outlook.office.com/mail/message-1?token=secret#section",
        )
        second = make_resource_citation(
            system="outlook",
            resource_type="message",
            resource_id="message-1",
            title="Different display title",
            url="https://outlook.office.com/mail/message-1?other=value",
        )

        self.assertEqual(first["citation_id"], second["citation_id"])
        self.assertEqual(first["url"], "https://outlook.office.com/mail/message-1")
        self.assertNotIn("secret", str(first))

    def test_non_scalar_optional_fields_are_discarded(self) -> None:
        citation = make_resource_citation(
            system="teams",
            resource_type="message",
            resource_id="message-1",
            version={"etag": "unsafe-shape"},
            parent_resource_id=["chat-1"],
        )

        self.assertIsNone(citation["version"])
        self.assertIsNone(citation["parent_resource_id"])

    def test_url_with_embedded_credentials_is_discarded(self) -> None:
        citation = make_resource_citation(
            system="sharepoint",
            resource_type="file",
            resource_id="file-1",
            url="https://user:password@example.com/file",
        )

        self.assertIsNone(citation["url"])

    def test_enrichment_marks_each_record_and_recursive_find_deduplicates(self) -> None:
        action = read_action(
            "outlook.message.search",
            system="outlook",
            resource_type="mail_search",
            resource_id="search-1",
        )
        payload = {
            "system": "outlook",
            "messages": [
                {
                    "id": "message-1",
                    "subject": "Release status",
                    "web_url": "https://outlook.office.com/message-1?token=temp",
                },
                {
                    "id": "message-2",
                    "subject": "Coverage update",
                },
            ],
        }

        citations = enrich_resource_citations(
            payload,
            action=action,
            connector_reference="https://graph.microsoft.com/v1.0/me/messages?$search=secret",
        )
        nested = {"one": payload, "two": {"citations": list(citations)}}
        found = find_citations(nested)

        self.assertEqual(len(citations), 2)
        self.assertEqual(len(found), 2)
        self.assertTrue(all("citation_id" in item for item in payload["messages"]))
        self.assertTrue(all("?" not in str(item.get("url")) for item in citations))


if __name__ == "__main__":
    unittest.main()

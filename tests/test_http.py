"""Restricted HTTP client tests."""

import unittest

from master_agent.errors import AuthenticationError, ConnectorHttpError
from master_agent.http import SafeHttpClient
from tests.fakes import ScriptedTransport


class SafeHttpClientTests(unittest.TestCase):
    """Verify origin restrictions and secret-safe errors."""

    def test_same_origin_relative_url_is_allowed(self) -> None:
        transport = ScriptedTransport()
        transport.add_json("GET", "/api/items", {"value": 1})
        client = SafeHttpClient(
            base_url="https://example.test/api/",
            transport=transport,
        )
        value, _ = client.request_json("GET", "items", query={"limit": 10})
        self.assertEqual(value, {"value": 1})
        self.assertIn("limit=10", transport.requests[0].url)

    def test_cross_origin_absolute_url_is_rejected_before_transport(self) -> None:
        transport = ScriptedTransport()
        client = SafeHttpClient(
            base_url="https://example.test/api",
            transport=transport,
        )
        with self.assertRaisesRegex(ConnectorHttpError, "outside"):
            client.request_json("GET", "https://attacker.test/data")
        self.assertEqual(transport.requests, [])

    def test_authentication_error_does_not_expose_token_or_query(self) -> None:
        transport = ScriptedTransport()
        transport.add_json(
            "GET",
            "/api/items",
            {"error": "bad token"},
            status=401,
        )
        secret = "super-secret-token"
        client = SafeHttpClient(
            base_url="https://example.test/api",
            default_headers={"Authorization": f"Bearer {secret}"},
            transport=transport,
        )
        with self.assertRaises(AuthenticationError) as context:
            client.request_json("GET", "items", query={"token": "also-secret"})
        rendered = str(context.exception)
        self.assertNotIn(secret, rendered)
        self.assertNotIn("also-secret", rendered)
        self.assertNotIn("bad token", rendered)

    def test_request_specific_response_limit_is_forwarded_to_transport(self) -> None:
        transport = ScriptedTransport()
        transport.add_json("GET", "/api/items", {"value": 1})
        client = SafeHttpClient(
            base_url="https://example.test/api",
            transport=transport,
            max_response_bytes=10_000,
        )

        client.request_bytes("GET", "items", max_response_bytes=321)

        self.assertEqual(transport.requests[0].max_response_bytes, 321)

    def test_post_is_blocked_unless_explicitly_allowed(self) -> None:
        client = SafeHttpClient(
            base_url="https://example.test/api",
            transport=ScriptedTransport(),
        )
        with self.assertRaisesRegex(ConnectorHttpError, "not permitted"):
            client.request_json("POST", "items", json_body={"read": True})


if __name__ == "__main__":
    unittest.main()

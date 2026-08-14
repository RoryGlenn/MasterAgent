"""Restricted HTTP client tests."""

import socket
import unittest
from unittest.mock import MagicMock, patch
from urllib.request import ProxyHandler

from master_agent.errors import AuthenticationError, ConnectorHttpError
from master_agent.http import (
    HttpResponse,
    SafeHttpClient,
    UrllibTransport,
    _PinnedHTTPSConnection,
    http_action_budget,
)
from tests.fakes import ExpectedRequest, QueueTransport, ScriptedTransport


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

    def test_parse_errors_and_response_references_drop_query_strings(self) -> None:
        response = HttpResponse(
            status=200,
            headers={},
            body=b"not-json",
            url="https://example.test/items?$search=confidential-project",
        )
        with self.assertRaises(ConnectorHttpError) as context:
            response.json()
        self.assertNotIn("confidential-project", str(context.exception))

        transport = ScriptedTransport()
        transport.add_json("GET", "/api/items", {"value": 1})
        client = SafeHttpClient(
            base_url="https://example.test/api", transport=transport
        )
        _, returned = client.request_json(
            "GET",
            "items",
            query={"token": "confidential-query-token"},
        )
        self.assertNotIn("confidential-query-token", returned.url)
        self.assertNotIn("?", returned.url)

    def test_request_id_is_dropped_when_it_contains_provider_diagnostics(self) -> None:
        transport = ScriptedTransport()
        transport.add_json(
            "GET",
            "/api/items",
            {"error": "no"},
            status=500,
            headers={"x-request-id": "secret query=value"},
        )
        client = SafeHttpClient(
            base_url="https://example.test/api", transport=transport
        )
        with self.assertRaises(ConnectorHttpError) as context:
            client.request_json("GET", "items")
        self.assertNotIn("secret", str(context.exception))
        self.assertIsNone(context.exception.request_id)

    def test_global_action_budget_counts_nested_requests(self) -> None:
        transport = ScriptedTransport()
        transport.add_json("GET", "/api/one", {"value": 1})
        transport.add_json("GET", "/api/two", {"value": 2})
        client = SafeHttpClient(
            base_url="https://example.test/api", transport=transport
        )
        with http_action_budget(max_requests=1, max_response_bytes=1024):
            client.request_json("GET", "one")
            with self.assertRaisesRegex(ConnectorHttpError, "request/page budget"):
                client.request_json("GET", "two")
        self.assertEqual(len(transport.requests), 1)

    def test_global_action_budget_counts_aggregate_response_bytes(self) -> None:
        transport = QueueTransport(
            ExpectedRequest("GET", "/api/one", b"12345678"),
            ExpectedRequest("GET", "/api/two", b"abcdefgh"),
        )
        client = SafeHttpClient(
            base_url="https://example.test/api", transport=transport
        )
        with http_action_budget(max_requests=2, max_response_bytes=12):
            client.request_bytes("GET", "one")
            with self.assertRaisesRegex(ConnectorHttpError, "response-byte budget"):
                client.request_bytes("GET", "two")

    def test_default_transport_ignores_ambient_proxy_configuration(self) -> None:
        with patch.dict(
            "os.environ",
            {"HTTPS_PROXY": "http://user:secret@attacker.test:8080"},
        ):
            transport = UrllibTransport()

        proxy_handlers = [
            handler
            for handler in transport._opener.handlers
            if isinstance(handler, ProxyHandler)
        ]
        # ``build_opener`` omits an explicitly empty ProxyHandler from the
        # finalized chain; its absence proves the environment-derived default
        # handler was suppressed.
        self.assertEqual(proxy_handlers, [])

    def test_https_connection_uses_vetted_address_and_original_tls_hostname(
        self,
    ) -> None:
        public_address = "93.184.216.34"
        records = [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                (public_address, 443),
            )
        ]
        connected_socket = MagicMock()
        connected_socket.getpeername.return_value = (public_address, 443)
        context = MagicMock()
        context.wrap_socket.return_value = connected_socket
        connection = _PinnedHTTPSConnection(
            "api.example.test",
            timeout=3.0,
            context=context,
        )

        with (
            patch("master_agent.http.socket.getaddrinfo", return_value=records),
            patch("master_agent.http.socket.socket", return_value=connected_socket),
        ):
            connection.connect()

        connected_socket.connect.assert_called_once_with((public_address, 443))
        context.wrap_socket.assert_called_once_with(
            connected_socket,
            server_hostname="api.example.test",
        )

    def test_https_connection_rejects_private_rebinding_result_before_connect(
        self,
    ) -> None:
        records = [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("127.0.0.1", 443),
            )
        ]
        connection = _PinnedHTTPSConnection(
            "api.example.test",
            timeout=3.0,
            context=MagicMock(),
        )

        with (
            patch("master_agent.http.socket.getaddrinfo", return_value=records),
            patch("master_agent.http.socket.socket") as socket_factory,
            self.assertRaisesRegex(ConnectorHttpError, "private or reserved"),
        ):
            connection.connect()

        socket_factory.assert_not_called()


if __name__ == "__main__":
    unittest.main()

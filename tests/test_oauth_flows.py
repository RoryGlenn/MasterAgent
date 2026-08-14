"""Deterministic OAuth acquisition and token-file lifecycle tests."""

from __future__ import annotations

import os
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from master_agent.errors import AuthenticationError
from master_agent.oauth import (
    AccessToken,
    EntraClientCredentialsProvider,
    EntraDeviceCodeProvider,
    RestrictedTokenFileProvider,
    write_token_file,
)
from tests.fakes import ScriptedTransport


class OAuthFlowTests(unittest.TestCase):
    """Validate bounded OAuth flows without external network access."""

    def test_client_credentials_uses_form_body_and_returns_scopes(self) -> None:
        transport = ScriptedTransport()
        transport.add_json(
            "POST",
            "/tenant/oauth2/v2.0/token",
            {
                "access_token": "application-access-token",
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": "https://graph.microsoft.com/.default",
            },
        )
        provider = EntraClientCredentialsProvider(
            tenant_id="tenant",
            client_id="client",
            client_secret="client-secret",
            scopes=("https://graph.microsoft.com/.default",),
            transport=transport,
        )

        token = provider.get_token()

        self.assertEqual(token.scopes, ("https://graph.microsoft.com/.default",))
        self.assertNotIn("application-access-token", repr(token))
        request = transport.requests[0]
        self.assertEqual(
            request.headers["Content-Type"],
            "application/x-www-form-urlencoded",
        )
        body = request.body.decode("utf-8") if request.body else ""
        self.assertIn("grant_type=client_credentials", body)
        self.assertIn("client_secret=client-secret", body)

    def test_device_code_pending_then_success(self) -> None:
        transport = ScriptedTransport()
        transport.add_json(
            "POST",
            "/tenant/oauth2/v2.0/devicecode",
            {
                "device_code": "device-secret",
                "user_code": "ABCD-EFGH",
                "verification_uri": "https://microsoft.com/devicelogin",
                "message": "Authenticate",
                "expires_in": 900,
                "interval": 1,
            },
        )
        transport.add_json(
            "POST",
            "/tenant/oauth2/v2.0/token",
            {"error": "authorization_pending"},
            status=400,
        )
        transport.add_json(
            "POST",
            "/tenant/oauth2/v2.0/token",
            {
                "access_token": "delegated-access-token",
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": "User.Read Mail.Read",
            },
        )
        sleeps: list[float] = []
        challenges: list[str] = []
        provider = EntraDeviceCodeProvider(
            tenant_id="tenant",
            client_id="client",
            scopes=("User.Read", "Mail.Read"),
            transport=transport,
            sleep=sleeps.append,
        )
        provider.set_challenge_callback(
            lambda challenge: challenges.append(challenge.user_code)
        )

        token = provider.get_token()

        self.assertEqual(challenges, ["ABCD-EFGH"])
        self.assertEqual(sleeps, [1])
        self.assertEqual(token.scopes, ("User.Read", "Mail.Read"))
        self.assertEqual(
            [item.method for item in transport.requests], ["POST", "POST", "POST"]
        )

    def test_restricted_token_file_round_trip_and_permission_enforcement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "graph-token.json"
            token = AccessToken(
                value="delegated-token",
                expires_at=datetime.now(UTC) + timedelta(hours=1),
                scopes=("User.Read",),
                source="test",
            )
            write_token_file(path, token)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            loaded = RestrictedTokenFileProvider(path).get_token()
            self.assertEqual(loaded.scopes, token.scopes)
            self.assertNotIn("delegated-token", repr(loaded))
            if os.name == "posix":
                path.chmod(0o644)
                with self.assertRaises(AuthenticationError):
                    RestrictedTokenFileProvider(path).get_token()

    @unittest.skipUnless(os.name == "posix", "symlink safety requires POSIX")
    def test_token_write_does_not_follow_predictable_or_target_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            victim = root / "victim.txt"
            victim.write_text("do-not-overwrite\n", encoding="utf-8")
            path = root / "graph-token.json"
            old_predictable_temp = path.with_suffix(path.suffix + ".tmp")
            old_predictable_temp.symlink_to(victim)
            token = AccessToken(
                value="delegated-token",
                expires_at=datetime.now(UTC) + timedelta(hours=1),
                scopes=("User.Read",),
                source="test",
            )

            write_token_file(path, token)
            self.assertEqual(victim.read_text(encoding="utf-8"), "do-not-overwrite\n")
            path.unlink()
            path.symlink_to(victim)
            with self.assertRaisesRegex(AuthenticationError, "symlink"):
                write_token_file(path, token)
            with self.assertRaises(AuthenticationError):
                RestrictedTokenFileProvider(path).get_token()
            self.assertEqual(victim.read_text(encoding="utf-8"), "do-not-overwrite\n")


if __name__ == "__main__":
    unittest.main()

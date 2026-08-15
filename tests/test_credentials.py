"""Restricted JSON credential-store security tests."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from master_agent.credentials import CredentialStoreSnapshot
from master_agent.errors import ConfigurationError
from tests.helpers import private_temporary_directory

_NAME = "MASTER_AGENT_GITHUB_TOKEN"
_SECRET = "credential-store-secret-canary"


class CredentialStoreTests(unittest.TestCase):
    def test_valid_store_is_redacted_and_overlays_environment(self) -> None:
        with private_temporary_directory() as directory:
            path = _write_store(Path(directory), {_NAME: _SECRET})
            snapshot = CredentialStoreSnapshot.load(path, allowed_names=(_NAME,))
            environ = snapshot.overlay({"PATH": "/bin"})
        self.assertEqual(snapshot.names, (_NAME,))
        self.assertEqual(environ[_NAME], _SECRET)
        self.assertNotIn(_SECRET, repr(snapshot))

    def test_ambient_collision_does_not_render_values(self) -> None:
        with private_temporary_directory() as directory:
            snapshot = CredentialStoreSnapshot.load(
                _write_store(Path(directory), {_NAME: _SECRET}),
                allowed_names=(_NAME,),
            )
            with self.assertRaises(ConfigurationError) as raised:
                snapshot.overlay({_NAME: "ambient-secret-canary"})
        self.assertNotIn(_SECRET, str(raised.exception))
        self.assertNotIn("ambient-secret-canary", str(raised.exception))

    def test_github_compatibility_shape_is_adapted_only_in_memory(self) -> None:
        with private_temporary_directory() as directory:
            path = Path(directory) / "github.json"
            original = json.dumps({"github": _SECRET})
            path.write_text(original, encoding="utf-8")
            path.chmod(0o600)

            snapshot = CredentialStoreSnapshot.load_github_compatible(path)
            environ = snapshot.overlay({})

            self.assertEqual(snapshot.names, (_NAME,))
            self.assertEqual(environ[_NAME], _SECRET)
            self.assertEqual(path.read_text(encoding="utf-8"), original)
            self.assertNotIn(_SECRET, repr(snapshot))

    def test_github_compatibility_accepts_named_token_object(self) -> None:
        with private_temporary_directory() as directory:
            path = Path(directory) / "github.json"
            original = json.dumps({"github": {"token": _SECRET}})
            path.write_text(original, encoding="utf-8")
            path.chmod(0o600)

            snapshot = CredentialStoreSnapshot.load_github_compatible(path)

            self.assertEqual(snapshot.overlay({})[_NAME], _SECRET)
            self.assertEqual(path.read_text(encoding="utf-8"), original)

    def test_github_compatibility_rejects_ambiguous_shapes(self) -> None:
        documents = (
            {"github": _SECRET, "other": "value"},
            {"github": {"password": _SECRET}},
            {"github": ""},
        )
        with private_temporary_directory() as directory:
            for index, document in enumerate(documents):
                path = Path(directory) / f"github-invalid-{index}.json"
                path.write_text(json.dumps(document), encoding="utf-8")
                path.chmod(0o600)
                with self.subTest(index=index), self.assertRaises(ConfigurationError):
                    CredentialStoreSnapshot.load_github_compatible(path)

    def test_provider_compatibility_adapts_selected_named_fields_in_memory(
        self,
    ) -> None:
        jira_token = "jira-token-canary"
        jira_username = "operator@example.test"
        with private_temporary_directory() as directory:
            path = Path(directory) / "providers.json"
            original = json.dumps(
                {
                    "jira": {
                        "username": jira_username,
                        "token": jira_token,
                    }
                }
            )
            path.write_text(original, encoding="utf-8")
            path.chmod(0o600)

            snapshot = CredentialStoreSnapshot.load_provider_compatible(
                path,
                allowed_names=("JIRA_USERNAME", "JIRA_TOKEN"),
                aliases={
                    "jira": {
                        "username": "JIRA_USERNAME",
                        "token": "JIRA_TOKEN",
                    }
                },
            )
            environ = snapshot.overlay({})

            self.assertEqual(environ["JIRA_USERNAME"], jira_username)
            self.assertEqual(environ["JIRA_TOKEN"], jira_token)
            self.assertEqual(path.read_text(encoding="utf-8"), original)
            self.assertNotIn(jira_token, repr(snapshot))

    def test_provider_compatibility_rejects_unknown_and_duplicate_aliases(
        self,
    ) -> None:
        cases = (
            (
                {"unknown": _SECRET},
                {"github": {"token": _NAME}},
            ),
            (
                {"github": {"password": _SECRET}},
                {"github": {"token": _NAME}},
            ),
            (
                {"github": {}},
                {"github": {"token": _NAME}},
            ),
            (
                {"github": _SECRET, "git": _SECRET},
                {
                    "github": {"token": _NAME},
                    "git": {"token": _NAME},
                },
            ),
        )
        with private_temporary_directory() as directory:
            for index, (document, aliases) in enumerate(cases):
                path = Path(directory) / f"providers-invalid-{index}.json"
                path.write_text(json.dumps(document), encoding="utf-8")
                path.chmod(0o600)
                with self.subTest(index=index), self.assertRaises(ConfigurationError):
                    CredentialStoreSnapshot.load_provider_compatible(
                        path,
                        allowed_names=(_NAME,),
                        aliases=aliases,
                    )

    def test_permissions_symlinks_and_owner_fail_closed(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            target = _write_store(root, {_NAME: _SECRET})
            link = root / "link.json"
            link.symlink_to(target)
            with self.assertRaises(ConfigurationError):
                CredentialStoreSnapshot.load(link, allowed_names=(_NAME,))
            target.chmod(0o640)
            with self.assertRaisesRegex(ConfigurationError, "0600"):
                CredentialStoreSnapshot.load(target, allowed_names=(_NAME,))
            target.chmod(0o600)
            with (
                patch("master_agent.credentials.os.geteuid", return_value=99_999),
                self.assertRaisesRegex(ConfigurationError, "owned"),
            ):
                CredentialStoreSnapshot.load(target, allowed_names=(_NAME,))

    def test_parent_must_be_private(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            shared = root / "shared"
            shared.mkdir(mode=0o700)
            shared.chmod(0o750)
            path = _write_store(shared, {_NAME: _SECRET})
            with self.assertRaises(ConfigurationError):
                CredentialStoreSnapshot.load(path, allowed_names=(_NAME,))

    def test_malformed_duplicate_unknown_and_invalid_values_fail(self) -> None:
        documents = (
            "{",
            '{"schema":"master-agent/credential-store@1","schema":"x","credentials":{}}',
            json.dumps({"schema": "wrong", "credentials": {_NAME: _SECRET}}),
            json.dumps(
                {
                    "schema": "master-agent/credential-store@1",
                    "credentials": {"UNDECLARED_TOKEN": _SECRET},
                }
            ),
            json.dumps(
                {
                    "schema": "master-agent/credential-store@1",
                    "credentials": {_NAME: ""},
                }
            ),
        )
        with private_temporary_directory() as directory:
            for index, document in enumerate(documents):
                path = Path(directory) / f"invalid-{index}.json"
                path.write_text(document, encoding="utf-8")
                path.chmod(0o600)
                with self.subTest(index=index), self.assertRaises(ConfigurationError):
                    CredentialStoreSnapshot.load(path, allowed_names=(_NAME,))

    def test_relative_oversized_and_non_utf8_files_fail(self) -> None:
        with self.assertRaisesRegex(ConfigurationError, "absolute"):
            CredentialStoreSnapshot.load(
                Path("credentials.json"), allowed_names=(_NAME,)
            )
        with private_temporary_directory() as directory:
            for name, payload in (
                ("oversized", b"x" * (1024 * 1024 + 1)),
                ("non-utf8", b"\xff"),
            ):
                path = Path(directory) / f"{name}.json"
                path.write_bytes(payload)
                path.chmod(0o600)
                with self.subTest(name=name), self.assertRaises(ConfigurationError):
                    CredentialStoreSnapshot.load(path, allowed_names=(_NAME,))


def _write_store(root: Path, credentials: dict[str, object]) -> Path:
    path = root / "credentials.json"
    path.write_text(
        json.dumps(
            {"schema": "master-agent/credential-store@1", "credentials": credentials}
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)
    return path


if __name__ == "__main__":
    unittest.main()

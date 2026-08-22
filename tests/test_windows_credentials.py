"""Windows Credential Manager and current-user DPAPI storage tests."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import shutil
import sys
import unittest
from pathlib import Path
from typing import Self

from master_agent.errors import ConfigurationError
from master_agent.platform_runtime.windows import (
    MAX_WINDOWS_CREDENTIAL_MANAGER_VALUE_BYTES,
    WINDOWS_CREDENTIAL_MANAGER_PROVIDER,
    WINDOWS_CREDENTIAL_STORAGE_BACKEND_ID,
    WINDOWS_DPAPI_PROVIDER,
    WindowsCredentialStorageBackend,
    build_windows_runtime,
    probe_windows_credential_storage_backend,
)

_SECRET = "windows-credential-secret-canary"
_TARGET = "MasterAgent/tests/issue-101"
_DPAPI_PATH = r"C:\MasterAgent\issue-101-credentials.bin"


class _FakeCredentialApi:
    def __init__(self, *, user: str = "current-user") -> None:
        self.user = user
        self.credentials: dict[str, bytes] = {}
        self.reads: list[str] = []
        self.fail_write_target: str | None = None
        self.fail_delete_target: str | None = None
        self.probes = 0

    def probe(self) -> None:
        self.probes += 1

    def credential_read(self, target: str) -> bytes | None:
        self.reads.append(target)
        return self.credentials.get(target)

    def credential_write(self, target: str, payload: bytes) -> None:
        if target == self.fail_write_target:
            raise OSError("write failed with " + _SECRET)
        self.credentials[target] = bytes(payload)

    def credential_delete(self, target: str) -> None:
        if target == self.fail_delete_target:
            raise OSError("delete failed with " + _SECRET)
        self.credentials.pop(target, None)

    def protect_data(self, payload: bytes, entropy: bytes) -> bytes:
        key = hashlib.sha256(self.user.encode("utf-8") + entropy).digest()
        ciphertext = bytes(
            value ^ key[index % len(key)] for index, value in enumerate(payload)
        )
        tag = hmac.new(key, ciphertext, hashlib.sha256).digest()
        return b"fake-dpapi-v1\0" + tag + ciphertext

    def unprotect_data(self, payload: bytes, entropy: bytes) -> bytes:
        prefix = b"fake-dpapi-v1\0"
        if not payload.startswith(prefix) or len(payload) < len(prefix) + 32:
            raise OSError("invalid protected payload")
        key = hashlib.sha256(self.user.encode("utf-8") + entropy).digest()
        tag = payload[len(prefix) : len(prefix) + 32]
        ciphertext = payload[len(prefix) + 32 :]
        if not hmac.compare_digest(
            tag, hmac.new(key, ciphertext, hashlib.sha256).digest()
        ):
            raise OSError("another user cannot decrypt " + _SECRET)
        return bytes(
            value ^ key[index % len(key)] for index, value in enumerate(ciphertext)
        )


class _FakeAtomicTransaction:
    def __init__(
        self,
        backend: _FakeAtomicBackend,
        path: Path,
        *,
        max_bytes: int,
        create: bool,
    ) -> None:
        self._backend = backend
        self.path = path
        self._max_bytes = max_bytes
        self._create = create
        self.identity: object | None = None

    def __enter__(self) -> Self:
        key = str(self.path)
        if not self._create and key not in self._backend.payloads:
            raise FileNotFoundError(key)
        self.identity = self._backend.identities.get(key)
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read_bytes(self) -> bytes | None:
        return self._backend.payloads.get(str(self.path))

    def publish_bytes(self, payload: bytes, *, expected: object | None) -> object:
        if len(payload) > self._max_bytes:
            raise ConfigurationError("fake atomic payload exceeds limit")
        if expected is not self.identity:
            raise ConfigurationError("fake atomic identity changed")
        key = str(self.path)
        identity = object()
        self._backend.payloads[key] = bytes(payload)
        self._backend.identities[key] = identity
        self.identity = identity
        return identity

    def remove(self, *, expected: object) -> bool:
        if expected is not self.identity:
            raise ConfigurationError("fake atomic identity changed")
        key = str(self.path)
        existed = key in self._backend.payloads
        self._backend.payloads.pop(key, None)
        self._backend.identities.pop(key, None)
        self.identity = None
        return existed


class _FakeAtomicBackend:
    backend_id = "fake-atomic"

    def __init__(self) -> None:
        self.payloads: dict[str, bytes] = {}
        self.identities: dict[str, object] = {}
        self.opens: list[tuple[str, int, bool]] = []

    def open_transaction(
        self,
        path: Path,
        *,
        max_bytes: int,
        create: bool,
    ) -> _FakeAtomicTransaction:
        self.opens.append((str(path), max_bytes, create))
        return _FakeAtomicTransaction(
            self,
            path,
            max_bytes=max_bytes,
            create=create,
        )


class WindowsCredentialStorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.atomic = _FakeAtomicBackend()
        self.api = _FakeCredentialApi()
        self.backend = WindowsCredentialStorageBackend(
            atomic=self.atomic,
            api=self.api,
        )

    def test_credential_manager_uses_exact_namespaced_entries(self) -> None:
        self.backend.store_credentials(
            provider=WINDOWS_CREDENTIAL_MANAGER_PROVIDER,
            target=_TARGET,
            credentials={"MASTER_AGENT_GITHUB_TOKEN": _SECRET},
        )
        self.api.reads.clear()

        observed = self.backend.load_credentials(
            provider=WINDOWS_CREDENTIAL_MANAGER_PROVIDER,
            target=_TARGET,
            allowed_names=("MASTER_AGENT_GITHUB_TOKEN",),
        )

        entry = _TARGET + "/MASTER_AGENT_GITHUB_TOKEN"
        self.assertEqual(dict(observed), {"MASTER_AGENT_GITHUB_TOKEN": _SECRET})
        self.assertEqual(self.api.reads, [entry])
        self.assertEqual(self.api.credentials[entry], _SECRET.encode())
        self.backend.remove_credentials(
            provider=WINDOWS_CREDENTIAL_MANAGER_PROVIDER,
            target=_TARGET,
            credential_names=("MASTER_AGENT_GITHUB_TOKEN",),
        )
        self.assertNotIn(entry, self.api.credentials)

    def test_credential_manager_rolls_back_without_rendering_values(self) -> None:
        original = {
            "MASTER_AGENT_JIRA_USERNAME": "operator@example.test",
            "MASTER_AGENT_JIRA_TOKEN": "old-token",
        }
        self.backend.store_credentials(
            provider=WINDOWS_CREDENTIAL_MANAGER_PROVIDER,
            target=_TARGET,
            credentials=original,
        )
        self.api.fail_write_target = _TARGET + "/MASTER_AGENT_JIRA_TOKEN"

        with self.assertRaisesRegex(ConfigurationError, "update failed") as raised:
            self.backend.store_credentials(
                provider=WINDOWS_CREDENTIAL_MANAGER_PROVIDER,
                target=_TARGET,
                credentials={
                    "MASTER_AGENT_JIRA_USERNAME": "changed@example.test",
                    "MASTER_AGENT_JIRA_TOKEN": _SECRET,
                },
            )

        self.assertNotIn(_SECRET, str(raised.exception))
        self.assertEqual(
            self.api.credentials[_TARGET + "/MASTER_AGENT_JIRA_USERNAME"],
            original["MASTER_AGENT_JIRA_USERNAME"].encode(),
        )
        self.assertEqual(
            self.api.credentials[_TARGET + "/MASTER_AGENT_JIRA_TOKEN"],
            original["MASTER_AGENT_JIRA_TOKEN"].encode(),
        )

    def test_dpapi_persists_ciphertext_and_enforces_current_user(self) -> None:
        credentials = {
            "MASTER_AGENT_ENTRA_APP_CLIENT_ID": "client-id",
            "MASTER_AGENT_ENTRA_APP_CLIENT_SECRET": _SECRET,
        }
        self.backend.store_credentials(
            provider=WINDOWS_DPAPI_PROVIDER,
            target=_DPAPI_PATH,
            credentials=credentials,
        )

        envelope = self.atomic.payloads[_DPAPI_PATH]
        self.assertNotIn(_SECRET.encode(), envelope)
        self.assertNotIn(b"client-id", envelope)
        self.assertIn(b'"scope":"current-user"', envelope)
        self.assertEqual(
            dict(
                self.backend.load_credentials(
                    provider=WINDOWS_DPAPI_PROVIDER,
                    target=_DPAPI_PATH,
                    allowed_names=tuple(credentials),
                )
            ),
            credentials,
        )

        other_user = WindowsCredentialStorageBackend(
            atomic=self.atomic,
            api=_FakeCredentialApi(user="another-user"),
        )
        with self.assertRaisesRegex(
            ConfigurationError,
            "could not be decrypted by this user",
        ) as raised:
            other_user.load_credentials(
                provider=WINDOWS_DPAPI_PROVIDER,
                target=_DPAPI_PATH,
                allowed_names=tuple(credentials),
            )
        self.assertNotIn(_SECRET, str(raised.exception))

    def test_dpapi_removal_republishes_then_removes_exact_document(self) -> None:
        self.backend.store_credentials(
            provider=WINDOWS_DPAPI_PROVIDER,
            target=_DPAPI_PATH,
            credentials={
                "MASTER_AGENT_JIRA_USERNAME": "operator@example.test",
                "MASTER_AGENT_JIRA_TOKEN": _SECRET,
            },
        )
        self.backend.remove_credentials(
            provider=WINDOWS_DPAPI_PROVIDER,
            target=_DPAPI_PATH,
            credential_names=("MASTER_AGENT_JIRA_TOKEN",),
        )
        self.assertEqual(
            dict(
                self.backend.load_credentials(
                    provider=WINDOWS_DPAPI_PROVIDER,
                    target=_DPAPI_PATH,
                    allowed_names=("MASTER_AGENT_JIRA_USERNAME",),
                )
            ),
            {"MASTER_AGENT_JIRA_USERNAME": "operator@example.test"},
        )
        self.backend.remove_credentials(
            provider=WINDOWS_DPAPI_PROVIDER,
            target=_DPAPI_PATH,
            credential_names=("MASTER_AGENT_JIRA_USERNAME",),
        )
        self.assertNotIn(_DPAPI_PATH, self.atomic.payloads)

    def test_dpapi_envelope_is_bound_to_its_canonical_path(self) -> None:
        other_path = r"C:\MasterAgent\copied-credentials.bin"
        self.backend.store_credentials(
            provider=WINDOWS_DPAPI_PROVIDER,
            target=_DPAPI_PATH,
            credentials={"MASTER_AGENT_GITHUB_TOKEN": _SECRET},
        )
        self.atomic.payloads[other_path] = self.atomic.payloads[_DPAPI_PATH]
        self.atomic.identities[other_path] = object()

        with self.assertRaisesRegex(ConfigurationError, "identity is invalid"):
            self.backend.load_credentials(
                provider=WINDOWS_DPAPI_PROVIDER,
                target=other_path,
                allowed_names=("MASTER_AGENT_GITHUB_TOKEN",),
            )

    def test_invalid_targets_names_and_provider_fail_closed(self) -> None:
        cases = (
            (WINDOWS_CREDENTIAL_MANAGER_PROVIDER, "other/application"),
            (WINDOWS_DPAPI_PROVIDER, r"\\server\share\credentials.bin"),
            (WINDOWS_DPAPI_PROVIDER, r"C:\MasterAgent\..\credentials.bin"),
        )
        for provider, target in cases:
            with (
                self.subTest(provider=provider, target=target),
                self.assertRaises(ConfigurationError),
            ):
                self.backend.load_credentials(
                    provider=provider,
                    target=target,
                    allowed_names=("MASTER_AGENT_GITHUB_TOKEN",),
                )
        with self.assertRaises(ConfigurationError):
            self.backend.load_credentials(
                provider="ambient",
                target=_TARGET,
                allowed_names=("MASTER_AGENT_GITHUB_TOKEN",),
            )
        with self.assertRaises(ConfigurationError):
            self.backend.load_credentials(
                provider=WINDOWS_CREDENTIAL_MANAGER_PROVIDER,
                target=_TARGET,
                allowed_names=("github_token",),
            )

        oversized = "s" * (MAX_WINDOWS_CREDENTIAL_MANAGER_VALUE_BYTES + 1)
        with self.assertRaisesRegex(ConfigurationError, "2.5 KiB") as raised:
            self.backend.store_credentials(
                provider=WINDOWS_CREDENTIAL_MANAGER_PROVIDER,
                target=_TARGET,
                credentials={"MASTER_AGENT_GITHUB_TOKEN": oversized},
            )
        self.assertNotIn(oversized, str(raised.exception))

    def test_probe_is_secret_free_and_does_not_touch_state(self) -> None:
        observed = probe_windows_credential_storage_backend(
            atomic=self.atomic,
            api=self.api,
        )
        self.assertIs(observed, self.api)
        self.assertEqual(self.api.probes, 1)
        self.assertEqual(self.api.credentials, {})
        self.assertEqual(self.atomic.payloads, {})
        self.assertEqual(self.backend.backend_id, WINDOWS_CREDENTIAL_STORAGE_BACKEND_ID)


@unittest.skipUnless(sys.platform == "win32", "requires native Windows APIs")
class WindowsCredentialNativeIntegrationTests(unittest.TestCase):
    def test_current_user_credential_manager_and_dpapi_round_trip(self) -> None:
        backend = build_windows_runtime().require_credential_storage()
        suffix = secrets.token_hex(12)
        namespace = "MasterAgent/tests/" + suffix
        state_root = Path(os.environ["TEMP"]) / ("credential-state-" + suffix)
        atomic = build_windows_runtime().require_atomic_publication_recovery()
        atomic.ensure_private_directory(state_root)
        dpapi_path = state_root / "credentials.dpapi"
        name = "MASTER_AGENT_GITHUB_TOKEN"
        try:
            backend.store_credentials(
                provider=WINDOWS_CREDENTIAL_MANAGER_PROVIDER,
                target=namespace,
                credentials={name: _SECRET},
            )
            self.assertEqual(
                backend.load_credentials(
                    provider=WINDOWS_CREDENTIAL_MANAGER_PROVIDER,
                    target=namespace,
                    allowed_names=(name,),
                )[name],
                _SECRET,
            )
            backend.store_credentials(
                provider=WINDOWS_DPAPI_PROVIDER,
                target=str(dpapi_path),
                credentials={name: _SECRET},
            )
            self.assertNotIn(_SECRET.encode(), dpapi_path.read_bytes())
            self.assertEqual(
                backend.load_credentials(
                    provider=WINDOWS_DPAPI_PROVIDER,
                    target=str(dpapi_path),
                    allowed_names=(name,),
                )[name],
                _SECRET,
            )
        finally:
            backend.remove_credentials(
                provider=WINDOWS_CREDENTIAL_MANAGER_PROVIDER,
                target=namespace,
                credential_names=(name,),
            )
            backend.remove_credentials(
                provider=WINDOWS_DPAPI_PROVIDER,
                target=str(dpapi_path),
                credential_names=(name,),
            )
            shutil.rmtree(state_root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

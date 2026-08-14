"""OAuth token acquisition and in-memory lifecycle management.

The runtime never writes access or refresh tokens unless a caller explicitly
uses :func:`write_token_file`. Persistent refresh-token storage is intentionally
left to an organization-approved secret manager or operating-system keychain.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import stat
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from master_agent.errors import AuthenticationError, ConfigurationError
from master_agent.http import HttpTransport, SafeHttpClient


@dataclass(frozen=True, slots=True)
class AccessToken:
    """An OAuth access token held only in process memory by default.

    Parameters
    ----------
    value
        Bearer token value.
    expires_at
        UTC expiry time.
    scopes
        Granted delegated scopes or application roles reported by the provider.
    token_type
        OAuth token type, normally ``Bearer``.
    source
        Non-secret description of the acquisition source.
    """

    value: str = field(repr=False)
    expires_at: datetime
    scopes: tuple[str, ...] = ()
    token_type: str = "Bearer"
    source: str = "unknown"

    def __post_init__(self) -> None:
        if not self.value:
            raise ConfigurationError("access token must not be empty")
        if self.expires_at.tzinfo is None:
            raise ConfigurationError("access-token expiry must be timezone-aware")
        if self.token_type.lower() != "bearer":
            raise ConfigurationError("only Bearer access tokens are supported")

    def is_valid(self, *, skew_seconds: int = 120) -> bool:
        """Return whether the token remains valid beyond a refresh skew."""

        return datetime.now(UTC) + timedelta(seconds=skew_seconds) < self.expires_at

    def authorization_headers(self) -> dict[str, str]:
        """Return an HTTP Authorization header."""

        return {"Authorization": f"Bearer {self.value}"}


class TokenProvider(Protocol):
    """Provider capable of returning a usable access token."""

    def get_token(self) -> AccessToken:
        """Return a current token, acquiring or refreshing as necessary."""


@dataclass(frozen=True, slots=True)
class DeviceCodeChallenge:
    """User-visible Microsoft identity device-code challenge."""

    user_code: str
    verification_uri: str
    message: str
    expires_at: datetime
    interval_seconds: int
    device_code: str = field(repr=False)


class StaticTokenProvider:
    """Return one caller-supplied token without persistence."""

    def __init__(self, token: AccessToken) -> None:
        self._token = token

    def get_token(self) -> AccessToken:
        """Return the configured token and reject an expired value."""

        if not self._token.is_valid(skew_seconds=0):
            raise AuthenticationError("configured access token has expired")
        return self._token


class EnvironmentTokenProvider:
    """Read a bearer token and optional expiry from environment variables."""

    def __init__(
        self,
        *,
        token_env: str,
        expires_at_env: str | None = None,
        scopes: tuple[str, ...] = (),
        environ: Mapping[str, str] | None = None,
    ) -> None:
        self._token_env = token_env
        self._expires_at_env = expires_at_env
        self._scopes = scopes
        self._environ = environ if environ is not None else os.environ

    def get_token(self) -> AccessToken:
        """Resolve the token at request time so rotation does not require restart."""

        value = self._environ.get(self._token_env, "").strip()
        if not value:
            raise AuthenticationError(
                f"access-token environment variable is missing: {self._token_env}"
            )
        expiry = datetime.now(UTC) + timedelta(hours=1)
        if self._expires_at_env:
            raw_expiry = self._environ.get(self._expires_at_env, "").strip()
            if raw_expiry:
                try:
                    expiry = datetime.fromisoformat(raw_expiry)
                except ValueError as error:
                    raise AuthenticationError(
                        "access-token expiry environment value is invalid"
                    ) from error
        return AccessToken(
            value=value,
            expires_at=expiry,
            scopes=self._scopes,
            source=f"environment:{self._token_env}",
        )


class RestrictedTokenFileProvider:
    """Read an explicitly created, permission-restricted token JSON file."""

    def __init__(self, path: Path) -> None:
        selected = path.expanduser()
        absolute = selected if selected.is_absolute() else Path.cwd() / selected
        self._path = absolute.parent.resolve(strict=True) / absolute.name

    def get_token(self) -> AccessToken:
        """Read the token file after enforcing restrictive POSIX permissions."""

        try:
            raw = json.loads(_read_restricted_token_file(self._path))
        except (OSError, json.JSONDecodeError) as error:
            raise AuthenticationError("token file could not be read") from error
        if not isinstance(raw, Mapping):
            raise AuthenticationError("token file must contain a JSON object")
        try:
            expires_at = datetime.fromisoformat(str(raw["expires_at"]))
            scopes_raw = raw.get("scopes", [])
            scopes = tuple(str(item) for item in scopes_raw)
            token = AccessToken(
                value=str(raw["access_token"]),
                expires_at=expires_at,
                scopes=scopes,
                token_type=str(raw.get("token_type", "Bearer")),
                source=f"restricted-file:{self._path.name}",
            )
        except (KeyError, TypeError, ValueError) as error:
            raise AuthenticationError("token file schema is invalid") from error
        if not token.is_valid(skew_seconds=0):
            raise AuthenticationError("token file contains an expired token")
        return token


class InMemoryTokenCache:
    """Thread-safe access-token cache around another provider."""

    def __init__(
        self,
        provider: TokenProvider,
        *,
        refresh_skew_seconds: int = 120,
    ) -> None:
        if refresh_skew_seconds < 0:
            raise ConfigurationError("refresh skew must not be negative")
        self._provider = provider
        self._refresh_skew_seconds = refresh_skew_seconds
        self._token: AccessToken | None = None
        self._lock = threading.Lock()

    def get_token(self) -> AccessToken:
        """Return a cached token or acquire a replacement atomically."""

        token = self._token
        if token is not None and token.is_valid(
            skew_seconds=self._refresh_skew_seconds
        ):
            return token
        with self._lock:
            token = self._token
            if token is None or not token.is_valid(
                skew_seconds=self._refresh_skew_seconds
            ):
                token = self._provider.get_token()
                self._token = token
            return token


class EntraClientCredentialsProvider:
    """Acquire Microsoft Entra application tokens with client credentials."""

    def __init__(
        self,
        *,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        scopes: tuple[str, ...],
        transport: HttpTransport | None = None,
        timeout_seconds: float = 20.0,
    ) -> None:
        for name, value in (
            ("tenant_id", tenant_id),
            ("client_id", client_id),
            ("client_secret", client_secret),
        ):
            if not value.strip():
                raise ConfigurationError(f"{name} must not be empty")
        if not scopes:
            raise ConfigurationError("at least one OAuth scope is required")
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._scopes = scopes
        self._client = SafeHttpClient(
            base_url=(f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/"),
            transport=transport,
            timeout_seconds=timeout_seconds,
            max_response_bytes=1024 * 1024,
            retry_attempts=1,
            allowed_methods=frozenset({"POST"}),
        )

    def get_token(self) -> AccessToken:
        """Acquire an application token without persisting credential material."""

        data, _ = self._client.request_form(
            "POST",
            "token",
            form={
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "scope": " ".join(self._scopes),
                "grant_type": "client_credentials",
            },
        )
        return _token_from_response(
            data,
            fallback_scopes=self._scopes,
            source="entra-client-credentials",
        )


class EntraDeviceCodeProvider:
    """Acquire delegated Microsoft Entra tokens through device authorization."""

    def __init__(
        self,
        *,
        tenant_id: str,
        client_id: str,
        scopes: tuple[str, ...],
        transport: HttpTransport | None = None,
        timeout_seconds: float = 20.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not tenant_id.strip() or not client_id.strip():
            raise ConfigurationError("tenant_id and client_id are required")
        if not scopes:
            raise ConfigurationError("at least one delegated scope is required")
        self._client_id = client_id
        self._scopes = scopes
        self._sleep = sleep
        self._client = SafeHttpClient(
            base_url=(f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/"),
            transport=transport,
            timeout_seconds=timeout_seconds,
            max_response_bytes=1024 * 1024,
            retry_attempts=1,
            allowed_methods=frozenset({"POST"}),
        )
        self._challenge: DeviceCodeChallenge | None = None
        self._challenge_callback: Callable[[DeviceCodeChallenge], None] | None = None

    def set_challenge_callback(
        self,
        callback: Callable[[DeviceCodeChallenge], None],
    ) -> None:
        """Set the callback invoked before interactive polling begins."""

        self._challenge_callback = callback

    def start(self) -> DeviceCodeChallenge:
        """Request a new device-code challenge."""

        data, _ = self._client.request_form(
            "POST",
            "devicecode",
            form={
                "client_id": self._client_id,
                "scope": " ".join(self._scopes),
            },
        )
        if not isinstance(data, Mapping):
            raise AuthenticationError("device-code response must be an object")
        try:
            expires_in = int(data["expires_in"])
            challenge = DeviceCodeChallenge(
                user_code=str(data["user_code"]),
                verification_uri=str(
                    data.get("verification_uri") or data.get("verification_url")
                ),
                message=str(data.get("message", "")),
                expires_at=datetime.now(UTC) + timedelta(seconds=expires_in),
                interval_seconds=max(1, int(data.get("interval", 5))),
                device_code=str(data["device_code"]),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise AuthenticationError(
                "device-code response schema is invalid"
            ) from error
        self._challenge = challenge
        return challenge

    def poll(self, challenge: DeviceCodeChallenge) -> AccessToken:
        """Poll until the user authenticates, the challenge expires, or access fails."""

        interval = challenge.interval_seconds
        while datetime.now(UTC) < challenge.expires_at:
            data, response = self._client.request_form(
                "POST",
                "token",
                form={
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "client_id": self._client_id,
                    "device_code": challenge.device_code,
                },
                accepted_statuses=frozenset({400}),
            )
            if response.status == 200:
                return _token_from_response(
                    data,
                    fallback_scopes=self._scopes,
                    source="entra-device-code",
                )
            if not isinstance(data, Mapping):
                raise AuthenticationError("device-code polling response is invalid")
            error_code = _safe_oauth_error_code(data.get("error"))
            if error_code == "authorization_pending":
                self._sleep(interval)
                continue
            if error_code == "slow_down":
                interval += 5
                self._sleep(interval)
                continue
            if error_code in {"authorization_declined", "expired_token"}:
                raise AuthenticationError(
                    f"device-code authentication ended: {error_code}"
                )
            raise AuthenticationError(
                f"device-code authentication failed: {error_code}"
            )
        raise AuthenticationError("device-code challenge expired")

    def get_token(self) -> AccessToken:
        """Run an interactive device-code flow using the configured callback."""

        challenge = self._challenge or self.start()
        if self._challenge_callback is None:
            raise AuthenticationError(
                "device-code authentication requires a challenge callback"
            )
        self._challenge_callback(challenge)
        token = self.poll(challenge)
        self._challenge = None
        return token


def write_token_file(path: Path, token: AccessToken) -> Path:
    """Explicitly persist an access token to a mode-0600 JSON file.

    The function does not store refresh tokens. Production deployments should
    prefer an organization-approved secret manager instead.
    """

    selected = path.expanduser()
    resolved = selected if selected.is_absolute() else Path.cwd() / selected
    resolved.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent = resolved.parent.resolve(strict=True)
    resolved = parent / resolved.name
    parent_before = parent.lstat()
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        directory_fd = os.open(parent, directory_flags)
    except OSError as error:
        raise AuthenticationError(
            "token directory could not be opened safely"
        ) from error

    parent_open = os.fstat(directory_fd)
    try:
        _validate_token_directory(parent_open, expected=parent_before)
        try:
            existing = os.stat(
                resolved.name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            existing = None
        if existing is not None and stat.S_ISLNK(existing.st_mode):
            raise AuthenticationError("token file target must not be a symlink")
        if existing is not None and not stat.S_ISREG(existing.st_mode):
            raise AuthenticationError("token file target must be a regular file")

        return _write_token_at(
            directory_fd=directory_fd,
            parent=parent,
            parent_metadata=parent_open,
            resolved=resolved,
            token=token,
        )
    finally:
        os.close(directory_fd)


def _write_token_at(
    *,
    directory_fd: int,
    parent: Path,
    parent_metadata: os.stat_result,
    resolved: Path,
    token: AccessToken,
) -> Path:
    """Write one token using only operations relative to a pinned directory."""

    payload = {
        "access_token": token.value,
        "expires_at": token.expires_at.isoformat(),
        "scopes": list(token.scopes),
        "token_type": token.token_type,
        "source": token.source,
    }
    encoded = (json.dumps(payload, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    temporary = f".{resolved.name}.{secrets.token_hex(16)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    installed = False
    try:
        descriptor = os.open(temporary, flags, 0o600, dir_fd=directory_fd)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = None
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        if not _directory_path_matches(parent, parent_metadata):
            raise AuthenticationError("token directory changed during write")
        os.replace(
            temporary,
            resolved.name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        installed = True
        target_fd = os.open(
            resolved.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
        try:
            target = os.fstat(target_fd)
            if not stat.S_ISREG(target.st_mode):
                raise AuthenticationError("token file target must be a regular file")
            if stat.S_IMODE(target.st_mode) != 0o600:
                raise AuthenticationError("token file permissions are not restricted")
        finally:
            os.close(target_fd)
        os.fsync(directory_fd)
        if not _directory_path_matches(parent, parent_metadata):
            raise AuthenticationError("token directory changed during write")
    except OSError as error:
        raise AuthenticationError("token file could not be written safely") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        if installed and not _directory_path_matches(parent, parent_metadata):
            try:
                os.unlink(resolved.name, dir_fd=directory_fd)
                os.fsync(directory_fd)
            except FileNotFoundError:
                pass
    return resolved


def _validate_token_directory(
    observed: os.stat_result,
    *,
    expected: os.stat_result,
) -> None:
    """Require a stable, current-user-owned, non-writable token directory."""

    if (observed.st_dev, observed.st_ino) != (expected.st_dev, expected.st_ino):
        raise AuthenticationError("token directory changed while opening")
    if not stat.S_ISDIR(observed.st_mode):
        raise AuthenticationError("token directory must be a regular directory")
    if os.name == "posix":
        if observed.st_uid != os.geteuid():
            raise AuthenticationError("token directory must be owned by current user")
        if stat.S_IMODE(observed.st_mode) & (stat.S_IWGRP | stat.S_IWOTH):
            raise AuthenticationError(
                "token directory must not be group- or other-writable"
            )


def _directory_path_matches(path: Path, expected: os.stat_result) -> bool:
    """Return whether a directory path still names the pinned directory."""

    try:
        observed = path.lstat()
    except FileNotFoundError:
        return False
    return stat.S_ISDIR(observed.st_mode) and (
        observed.st_dev,
        observed.st_ino,
    ) == (expected.st_dev, expected.st_ino)


def inspect_jwt_claims(value: str) -> dict[str, Any]:
    """Decode non-secret JWT claim metadata without validating the signature.

    This is only a readiness aid. Connectors must rely on the provider to
    validate and authorize tokens.
    """

    parts = value.split(".")
    if len(parts) != 3:
        return {}
    try:
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return {}
    if not isinstance(data, Mapping):
        return {}
    allowed = {
        "aud",
        "exp",
        "iat",
        "iss",
        "roles",
        "scp",
        "tid",
        "upn",
        "preferred_username",
    }
    return {str(key): data[key] for key in allowed if key in data}


def _token_from_response(
    data: Any,
    *,
    fallback_scopes: tuple[str, ...],
    source: str,
) -> AccessToken:
    if not isinstance(data, Mapping):
        raise AuthenticationError("OAuth token response must be an object")
    if data.get("error"):
        raise AuthenticationError(
            f"OAuth token request failed: {_safe_oauth_error_code(data.get('error'))}"
        )
    try:
        value = str(data["access_token"])
        expires_in = max(1, int(data.get("expires_in", 3600)))
    except (KeyError, TypeError, ValueError) as error:
        raise AuthenticationError("OAuth token response schema is invalid") from error
    raw_scope = str(data.get("scope", "")).strip()
    scopes = tuple(raw_scope.split()) if raw_scope else fallback_scopes
    return AccessToken(
        value=value,
        expires_at=datetime.now(UTC) + timedelta(seconds=expires_in),
        scopes=scopes,
        token_type=str(data.get("token_type", "Bearer")),
        source=source,
    )


def _read_restricted_token_file(path: Path) -> str:
    """Read a bounded regular token file without following symbolic links."""

    selected = path.expanduser()
    resolved = selected if selected.is_absolute() else Path.cwd() / selected
    try:
        parent = resolved.parent.resolve(strict=True)
        parent_before = parent.lstat()
    except FileNotFoundError as error:
        raise AuthenticationError("token file does not exist") from error
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        directory_fd = os.open(parent, directory_flags)
    except OSError as error:
        raise AuthenticationError(
            "token directory could not be opened safely"
        ) from error
    parent_open = os.fstat(directory_fd)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        _validate_token_directory(parent_open, expected=parent_before)
        descriptor = os.open(resolved.name, flags, dir_fd=directory_fd)
    except FileNotFoundError as error:
        os.close(directory_fd)
        raise AuthenticationError("token file does not exist") from error
    except OSError as error:
        os.close(directory_fd)
        raise AuthenticationError("token file could not be opened safely") from error
    except AuthenticationError:
        os.close(directory_fd)
        raise
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise AuthenticationError("token file must be a regular file")
        if os.name == "posix":
            if metadata.st_uid != os.geteuid():
                raise AuthenticationError(
                    "token file must be owned by the current user"
                )
            mode = stat.S_IMODE(metadata.st_mode)
            if mode & (stat.S_IRWXG | stat.S_IRWXO):
                raise AuthenticationError(
                    "token file permissions must not grant group or other access"
                )
        payload = os.read(descriptor, 1024 * 1024 + 1)
        if len(payload) > 1024 * 1024:
            raise AuthenticationError("token file exceeds the 1 MiB limit")
        try:
            rendered = payload.decode("utf-8")
        except UnicodeDecodeError as error:
            raise AuthenticationError("token file is not valid UTF-8") from error
        if not _directory_path_matches(parent, parent_open):
            raise AuthenticationError("token directory changed during read")
        return rendered
    finally:
        os.close(descriptor)
        os.close(directory_fd)


def _fsync_directory(directory: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(directory, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _safe_oauth_error_code(value: object) -> str:
    """Return a provider error code without copying arbitrary diagnostics."""

    rendered = str(value or "unknown_error").strip()
    if not rendered or len(rendered) > 80:
        return "unknown_error"
    if not all(
        character.isalnum() or character in {"_", "-", "."} for character in rendered
    ):
        return "unknown_error"
    return rendered

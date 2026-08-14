"""OAuth token acquisition and in-memory lifecycle management.

The runtime never writes access or refresh tokens unless a caller explicitly
uses :func:`write_token_file`. Persistent refresh-token storage is intentionally
left to an organization-approved secret manager or operating-system keychain.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
import base64
import json
import os
from pathlib import Path
import stat
import threading
import time
from typing import Any, Callable, Mapping, Protocol

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
                    expiry = datetime.fromisoformat(raw_expiry.replace("Z", "+00:00"))
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
        self._path = path.expanduser().resolve()

    def get_token(self) -> AccessToken:
        """Read the token file after enforcing restrictive POSIX permissions."""

        _require_restricted_file(self._path)
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise AuthenticationError("token file could not be read") from error
        if not isinstance(raw, Mapping):
            raise AuthenticationError("token file must contain a JSON object")
        try:
            expires_at = datetime.fromisoformat(
                str(raw["expires_at"]).replace("Z", "+00:00")
            )
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
            base_url=(
                "https://login.microsoftonline.com/"
                f"{tenant_id}/oauth2/v2.0/"
            ),
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
            base_url=(
                "https://login.microsoftonline.com/"
                f"{tenant_id}/oauth2/v2.0/"
            ),
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
                    data.get("verification_uri")
                    or data.get("verification_url")
                ),
                message=str(data.get("message", "")),
                expires_at=datetime.now(UTC) + timedelta(seconds=expires_in),
                interval_seconds=max(1, int(data.get("interval", 5))),
                device_code=str(data["device_code"]),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise AuthenticationError("device-code response schema is invalid") from error
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
            error_code = str(data.get("error", "unknown_error"))
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

    resolved = path.expanduser().resolve()
    resolved.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "access_token": token.value,
        "expires_at": token.expires_at.isoformat(),
        "scopes": list(token.scopes),
        "token_type": token.token_type,
        "source": token.source,
    }
    temporary = resolved.with_suffix(resolved.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    os.chmod(temporary, stat.S_IRUSR | stat.S_IWUSR)
    temporary.replace(resolved)
    os.chmod(resolved, stat.S_IRUSR | stat.S_IWUSR)
    return resolved


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
            f"OAuth token request failed: {data.get('error')}"
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


def _require_restricted_file(path: Path) -> None:
    if not path.is_file():
        raise AuthenticationError("token file does not exist")
    if os.name == "posix":
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise AuthenticationError(
                "token file permissions must not grant group or other access"
            )

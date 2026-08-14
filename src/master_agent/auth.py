"""Authentication header construction without secret persistence."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import base64

from master_agent.errors import ConfigurationError
from master_agent.oauth import TokenProvider


class AuthMode(StrEnum):
    """Supported connector authentication modes."""

    NONE = "none"
    BEARER = "bearer"
    BASIC = "basic"
    OAUTH_DELEGATED = "oauth_delegated"
    OAUTH_APPLICATION = "oauth_application"


@dataclass(frozen=True, slots=True)
class ResolvedAuth:
    """Resolved authentication material held only in process memory.

    Parameters
    ----------
    mode
        Authentication scheme.
    username
        Username for Basic authentication.
    secret
        Token, password, or app password. The value is excluded from ``repr``.
    """

    mode: AuthMode
    username: str | None = None
    secret: str | None = field(default=None, repr=False)
    token_provider: TokenProvider | None = field(default=None, repr=False, compare=False)

    def headers(self) -> dict[str, str]:
        """Build HTTP authentication headers.

        Returns
        -------
        dict[str, str]
            Headers suitable for a connector HTTP client.

        Raises
        ------
        ConfigurationError
            If required authentication material is absent.
        """

        if self.mode is AuthMode.NONE:
            return {}
        if self.mode in {
            AuthMode.BEARER,
            AuthMode.OAUTH_DELEGATED,
            AuthMode.OAUTH_APPLICATION,
        }:
            if self.token_provider is not None:
                return self.token_provider.get_token().authorization_headers()
            if not self.secret:
                raise ConfigurationError(
                    f"authentication secret is missing for mode {self.mode}"
                )
            return {"Authorization": f"Bearer {self.secret}"}
        if not self.secret:
            raise ConfigurationError(
                f"authentication secret is missing for mode {self.mode}"
            )
        if self.mode is AuthMode.BASIC:
            if not self.username:
                raise ConfigurationError(
                    "username is required for Basic authentication"
                )
            material = f"{self.username}:{self.secret}".encode("utf-8")
            encoded = base64.b64encode(material).decode("ascii")
            return {"Authorization": f"Basic {encoded}"}
        raise ConfigurationError(f"unsupported authentication mode: {self.mode}")

"""Small JSON HTTP client with bounded reads and no ambiguous write replay."""

from __future__ import annotations

import json
import ssl
import time
from collections.abc import Callable
from http.client import HTTPException
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


class ProviderError(RuntimeError):
    """Report an actionable provider failure without remote bodies or credentials.

    Parameters
    ----------
    message : str
        Safe, local explanation of the failure.
    uncertain : bool, optional
        Whether a write may have completed despite the missing result.
    """

    def __init__(self, message: str, *, uncertain: bool = False) -> None:
        super().__init__(message)
        self.uncertain = uncertain


def validate_url(url: str, base_url: str) -> str:
    """Validate an HTTPS destination against its configured origin and context.

    Parameters
    ----------
    url : str
        Absolute target URL.
    base_url : str
        Configured origin and optional application context path.

    Returns
    -------
    str
        The validated, unchanged target URL.
    """
    try:
        target, base = urlsplit(url), urlsplit(base_url)
        if (
            target.scheme != "https"
            or base.scheme != "https"
            or not target.hostname
            or not base.hostname
            or target.username is not None
            or target.password is not None
            or base.username is not None
            or base.password is not None
            or (target.scheme, target.hostname, target.port or 443)
            != (base.scheme, base.hostname, base.port or 443)
            or target.fragment
            or base.query
            or base.fragment
            or any(ord(char) < 33 or char == "\\" for char in url + base_url)
        ):
            raise ValueError
        # Reject encoded path traversal before a proxy/server can normalize it.
        for path in (target.path, base.path):
            decoded = path
            for _ in range(4):
                updated = unquote(decoded)
                if updated == decoded:
                    break
                decoded = updated
            if (
                any(part in {".", ".."} for part in decoded.split("/"))
                or "\\" in decoded
                or any(ord(char) < 32 for char in decoded)
                or decoded.count("/") != path.count("/")
            ):
                raise ValueError
        context = base.path.rstrip("/")
        if (
            context
            and target.path != context
            and not target.path.startswith(context + "/")
        ):
            raise ValueError
    except (TypeError, ValueError):
        raise ProviderError(
            "URL must use the configured HTTPS provider and context path."
        ) from None
    return url


class _ScopedRedirect(HTTPRedirectHandler):
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url

    def redirect_request(
        self, req: Request, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> Request | None:
        try:
            validate_url(newurl, self.base_url)
        except ProviderError:
            raise ProviderError(
                "Provider redirect left its configured origin or context.",
                uncertain=req.get_method() not in {"GET", "HEAD"},
            ) from None
        if req.get_method() not in {"GET", "HEAD"}:
            raise ProviderError(
                "Write redirect was not followed; check the provider result.",
                uncertain=True,
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class HttpTransport:
    """Reuse an authenticated opener for one configured provider API.

    Parameters
    ----------
    base_url : str
        HTTPS API base including any application context path.
    authorization : str
        In-memory Authorization header value.
    timeout : float, optional
        Timeout in seconds for each request.
    ca_bundle : str, optional
        Additional trusted CA bundle supported by the local organization.
    opener : object, optional
        Test opener exposing ``open(request, timeout=...)``.
    sleep : callable, optional
        Injectable delay function for retry tests.
    """

    def __init__(
        self,
        base_url: str,
        authorization: str,
        *,
        timeout: float = 30,
        ca_bundle: str | None = None,
        opener: Any = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.base_url = validate_url(base_url.rstrip("/"), base_url.rstrip("/"))
        self.timeout = max(1, min(float(timeout), 120))
        self._authorization = authorization
        self._sleep = sleep
        try:
            context = ssl.create_default_context()
            if ca_bundle:
                context.load_verify_locations(cafile=ca_bundle)
            self._opener = opener or build_opener(
                HTTPSHandler(context=context), _ScopedRedirect(self.base_url)
            )
        except (OSError, ssl.SSLError):
            raise ProviderError(
                "Could not load the configured provider CA bundle."
            ) from None

    def request(self, method: str, path: str, data: Any = None) -> Any:
        """Send JSON and return decoded JSON, retrying only safe reads.

        Parameters
        ----------
        method : str
            HTTP verb.
        path : str
            Relative API path, or validated absolute pagination URL.
        data : object, optional
            JSON request body.

        Returns
        -------
        object
            Decoded JSON, or an empty dictionary for an empty response.
        """
        method = method.upper()
        read = method in {"GET", "HEAD"}
        url = path if urlsplit(path).scheme else urljoin(self.base_url + "/", path)
        validate_url(url, self.base_url)
        body = None if data is None else json.dumps(data).encode("utf-8")
        headers = {"Accept": "application/json", "Authorization": self._authorization}
        if body is not None:
            headers["Content-Type"] = "application/json"
        for attempt in range(3 if read else 1):
            try:
                request = Request(url, data=body, headers=headers, method=method)
                with self._opener.open(request, timeout=self.timeout) as response:
                    raw = response.read(8 * 1024 * 1024 + 1)
                    if len(raw) > 8 * 1024 * 1024:
                        raise ProviderError(
                            "Provider response exceeded 8 MiB.", uncertain=not read
                        )
                    return json.loads(raw) if raw else {}
            except HTTPError as error:
                code = error.code
                retry_after = (
                    error.headers.get("Retry-After", "") if error.headers else ""
                )
                error.close()
                if read and attempt < 2 and code in {429, 502, 503, 504}:
                    try:
                        delay = min(5, max(0, float(retry_after)))
                    except ValueError:
                        delay = float(2**attempt)
                    self._sleep(delay)
                    continue
                uncertain = not read and (
                    code >= 500 or code == 408 or 300 <= code < 400
                )
                if code in {401, 403}:
                    message = f"Provider returned HTTP {code}; check credentials and account permissions."
                elif code == 429:
                    message = "Provider rate limit reached; try again later."
                else:
                    message = f"Provider returned HTTP {code}."
                raise ProviderError(message, uncertain=uncertain) from None
            except (URLError, OSError, HTTPException):
                if read and attempt < 2:
                    self._sleep(float(2**attempt))
                    continue
                raise ProviderError(
                    "Provider connection failed; check the network and configured URL.",
                    uncertain=not read,
                ) from None
            except (ValueError, UnicodeError):
                raise ProviderError(
                    "Provider returned invalid JSON.", uncertain=not read
                ) from None
        raise ProviderError("Provider request did not complete.")

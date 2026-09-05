"""Practical Jira, Confluence and Bitbucket tools for a personal assistant."""

from __future__ import annotations

import base64
import json
import os
import re
from collections.abc import Callable, Iterator
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qs, unquote, urlencode, urlsplit, urlunsplit

from .transport import HttpTransport, ProviderError, validate_url

MAX_PAGES = 10


def _text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "".join(_text(item) for item in value)
    if isinstance(value, dict):
        result = str(value.get("text", "")) + _text(value.get("content", []))
        return result + ("\n" if value.get("type") in {"paragraph", "heading", "listItem", "hardBreak"} else "")
    return ""


def _links(value: Any) -> set[str]:
    if isinstance(value, str):
        return {link.rstrip(".,;)]}") for link in re.findall(r"https?://[^\s<>\"']+", value)}
    if isinstance(value, list):
        return set().union(*(_links(item) for item in value)) if value else set()
    if isinstance(value, dict):
        return _links(list(value.values()))
    return set()


class _PageText(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag in {"p", "div", "li", "tr", "h1", "h2", "h3", "pre"}:
            self.parts.append("\n")

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "br":
            self.parts.append("\n")


class Providers:
    """Lazily connect to only the providers needed by the current task.

    Parameters
    ----------
    config : dict
        Sections ``jira``, ``confluence`` and ``bitbucket`` with ``url``,
        ``deployment`` (cloud/server), and credential environment variable names.
    transport : object, optional
        Injectable transport, per-provider transport mapping, or a factory with
        the same constructor arguments as ``HttpTransport``.
    """

    def __init__(self, config: dict[str, Any], transport: Any = None) -> None:
        self.config = config
        self._transport = transport
        self._clients: dict[str, Any] = {}

    def _settings(self, name: str) -> dict[str, Any]:
        section = self.config.get(name)
        if not isinstance(section, dict) or not section.get("url"):
            raise ProviderError(f"Configure {name}.url before using this tool.")
        if section.get("deployment", "cloud") not in {"cloud", "server"}:
            raise ProviderError(f"Set {name}.deployment to cloud or server.")
        return section

    def _cloud(self, name: str) -> bool:
        return self._settings(name).get("deployment", "cloud") == "cloud"

    def _base(self, name: str) -> str:
        base = str(self._settings(name)["url"]).rstrip("/")
        validate_url(base, base)
        if name == "bitbucket" and self._cloud(name):
            if base != "https://bitbucket.org":
                raise ProviderError("Set Bitbucket Cloud URL to https://bitbucket.org.")
        if name == "confluence" and self._cloud(name) and not urlsplit(base).path:
            base += "/wiki"
        return base

    def _client(self, name: str) -> Any:
        if name in self._clients:
            return self._clients[name]
        settings = self._settings(name)
        base = self._base(name)
        if name == "bitbucket" and self._cloud(name):
            base = "https://api.bitbucket.org/2.0"
        if isinstance(self._transport, dict):
            client = self._transport[name]
        elif self._transport is not None and hasattr(self._transport, "request"):
            client = self._transport
        else:
            token_env = settings.get("token_env", f"{name.upper()}_TOKEN")
            token = os.environ.get(token_env, "")
            if not token:
                raise ProviderError(f"Set the environment variable configured by {name}.token_env.")
            username_env = settings.get("username_env")
            username = os.environ.get(username_env, "") if username_env else ""
            if username_env and not username:
                raise ProviderError(f"Set the environment variable configured by {name}.username_env.")
            if self._cloud(name) and name in {"jira", "confluence"} and not username:
                raise ProviderError(f"Configure {name}.username_env with your Atlassian account email.")
            if username:
                encoded = base64.b64encode(f"{username}:{token}".encode()).decode("ascii")
                authorization = f"Basic {encoded}"
            else:
                authorization = f"Bearer {token}"
            factory: Callable[..., Any] = self._transport or HttpTransport
            client = factory(base, authorization, timeout=settings.get("timeout", 30), ca_bundle=settings.get("ca_bundle"))
        self._clients[name] = client
        return client

    def _request(self, name: str, method: str, path: str, data: Any = None) -> Any:
        return self._client(name).request(method, path, data)

    def _pages(self, name: str, path: str, field: str = "values") -> Iterator[dict[str, Any]]:
        """Traverse bounded pagination; incomplete discovery must block writes."""
        current = path
        seen: set[str] = set()
        for _ in range(MAX_PAGES):
            if current in seen:
                raise ProviderError("Provider pagination repeated a page; discovery is incomplete.")
            seen.add(current)
            data = self._request(name, "GET", current)
            if not isinstance(data, dict) or not isinstance(data.get(field), list):
                raise ProviderError("Provider returned an unexpected paginated response.")
            values = data[field]
            for value in values:
                if not isinstance(value, dict):
                    raise ProviderError("Provider returned an unexpected item.")
                yield value
            if data.get("next"):
                next_url = str(data["next"])
                base = "https://api.bitbucket.org/2.0" if name == "bitbucket" and self._cloud(name) else self._base(name)
                validate_url(next_url, base)
                expected_path = urlsplit(base + "/" + path).path
                if urlsplit(next_url).path != expected_path:
                    raise ProviderError("Provider pagination changed its API endpoint.")
                current = next_url
            elif data.get("isLastPage") is False:
                next_start = data.get("nextPageStart")
                if not isinstance(next_start, int) or next_start < 0:
                    raise ProviderError("Provider pagination omitted its next offset.")
                parsed = urlsplit(path)
                query = parse_qs(parsed.query)
                query["start"] = [str(next_start)]
                current = urlunsplit(("", "", parsed.path, urlencode(query, doseq=True), ""))
            elif field == "comments" and int(data.get("startAt", 0)) + len(values) < int(data.get("total", 0)):
                if not values:
                    raise ProviderError("Provider returned an empty page before discovery completed.")
                parsed = urlsplit(path)
                query = parse_qs(parsed.query)
                query["startAt"] = [str(int(data.get("startAt", 0)) + len(values))]
                current = urlunsplit(("", "", parsed.path, urlencode(query, doseq=True), ""))
            else:
                return
        raise ProviderError(f"Discovery exceeded {MAX_PAGES} pages; narrow the target before retrying.")

    def _issue_path(self, key: str) -> str:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*-\d+", key):
            raise ProviderError("Use a Jira issue key such as PROJ-123.")
        version = "3" if self._cloud("jira") else "2"
        return f"rest/api/{version}/issue/{key}"

    def issue(self, key: str) -> dict[str, Any]:
        """Read an issue and its linked work.

        Parameters
        ----------
        key : str
            Jira issue key.

        Returns
        -------
        dict
            Key, title, plain description, status, URL and discovered links.
        """
        path = self._issue_path(key)
        data = self._request("jira", "GET", path + "?fields=summary,description,status,issuelinks")
        fields = data.get("fields", {})
        remote = self._request("jira", "GET", path + "/remotelink")
        return {
            "key": data.get("key", key), "title": fields.get("summary", ""),
            "description": _text(fields.get("description")).strip(),
            "status": (fields.get("status") or {}).get("name", "Unknown"),
            "url": self._base("jira") + "/browse/" + key,
            "links": sorted(_links(fields.get("description")) | _links(remote) | _links(fields.get("issuelinks"))),
        }

    def _repository(self, repository: str) -> tuple[str, str]:
        parts = repository.split("/")
        if len(parts) != 2 or any(not re.fullmatch(r"[A-Za-z0-9_~.-]+", part) or part in {".", ".."} for part in parts):
            raise ProviderError("Use workspace/repository or PROJECT/repository.")
        return parts[0], parts[1]

    def _pr_path(self, repository: str) -> str:
        owner, repo = self._repository(repository)
        if self._cloud("bitbucket"):
            return f"repositories/{owner}/{repo}/pullrequests"
        return f"rest/api/1.0/projects/{owner}/repos/{repo}/pull-requests"

    def _same_repository(self, actual: str, requested: str) -> bool:
        if self._cloud("bitbucket"):
            return actual == requested
        actual_owner, actual_repo = self._repository(actual)
        requested_owner, requested_repo = self._repository(requested)
        return actual_owner.upper() == requested_owner.upper() and actual_repo == requested_repo

    def _normalize_pr(self, data: dict[str, Any], repository: str) -> dict[str, Any]:
        owner, repo = self._repository(repository)
        number = data.get("id")
        if not str(number).isdigit():
            raise ProviderError("Provider returned a pull request without a numeric ID.")
        if self._cloud("bitbucket"):
            source, target = data.get("source", {}), data.get("destination", {})
            source_branch, target_branch = source.get("branch", {}).get("name", ""), target.get("branch", {}).get("name", "")
            commit = source.get("commit", {}).get("hash", "")
            source_repository = source.get("repository", {}).get("full_name", repository)
            url = f"{self._base('bitbucket')}/{owner}/{repo}/pull-requests/{number}"
        else:
            source, target = data.get("fromRef", {}), data.get("toRef", {})
            source_branch = source.get("id", "").removeprefix("refs/heads/")
            target_branch = target.get("id", "").removeprefix("refs/heads/")
            commit = source.get("latestCommit", "")
            source_repo = source.get("repository", {})
            source_repository = f"{source_repo.get('project', {}).get('key', owner)}/{source_repo.get('slug', repo)}"
            url = f"{self._base('bitbucket')}/projects/{owner}/repos/{repo}/pull-requests/{number}"
        return {
            "id": number, "url": url, "title": data.get("title", ""), "state": data.get("state", "UNKNOWN"),
            "source_branch": source_branch, "target_branch": target_branch,
            "commit": commit, "repository": repository, "source_repository": source_repository,
            "draft": data.get("draft") if isinstance(data.get("draft"), bool) else None,
        }

    def pull_request(self, url: str) -> dict[str, Any]:
        """Read a pull request belonging to the configured Bitbucket server.

        Parameters
        ----------
        url : str
            Bitbucket pull request UI URL.

        Returns
        -------
        dict
            Normalized pull request and source commit metadata.
        """
        base = self._base("bitbucket")
        parsed = urlsplit(url)
        clean_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
        validate_url(clean_url, base)
        relative = parsed.path[len(urlsplit(base).path):].strip("/")
        pattern = r"([^/]+)/([^/]+)/pull-requests/(\d+)(?:/.*)?" if self._cloud("bitbucket") else r"projects/([^/]+)/repos/([^/]+)/pull-requests/(\d+)(?:/.*)?"
        match = re.fullmatch(pattern, relative)
        if not match:
            raise ProviderError("Use a Bitbucket pull request URL.")
        repository = f"{match[1]}/{match[2]}"
        data = self._request("bitbucket", "GET", self._pr_path(repository) + "/" + match[3])
        return self._normalize_pr(data, repository)

    def builds(self, pr: dict[str, Any]) -> list[dict[str, Any]]:
        """Read CI build statuses for the pull request's source commit.

        Parameters
        ----------
        pr : dict
            Normalized pull request returned by ``pull_request``.

        Returns
        -------
        list of dict
            Build names, states and links.
        """
        commit = str(pr.get("commit", ""))
        if not re.fullmatch(r"[0-9a-fA-F]{7,64}", commit):
            raise ProviderError("Pull request did not contain a usable source commit.")
        owner, repo = self._repository(pr.get("source_repository", pr["repository"]))
        if self._cloud("bitbucket"):
            path = f"repositories/{owner}/{repo}/commit/{commit}/statuses?pagelen=100"
        else:
            path = f"rest/api/1.0/projects/{owner}/repos/{repo}/commits/{commit}/builds?limit=100"
        return [{"name": item.get("name") or item.get("key", "Build"), "state": item.get("state", "UNKNOWN"), "url": item.get("url", "")} for item in self._pages("bitbucket", path)]

    def page(self, url: str) -> dict[str, Any]:
        """Read a Confluence page by ID URL or legacy space/title URL.

        Parameters
        ----------
        url : str
            Confluence page UI URL.

        Returns
        -------
        dict
            Page ID, title, plain text body and URL.
        """
        base = self._base("confluence")
        parsed = urlsplit(url)
        clean_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))
        validate_url(clean_url, base)
        relative = parsed.path[len(urlsplit(base).path):].strip("/")
        ids = parse_qs(parsed.query).get("pageId", [])
        match = re.search(r"(?:^|/)pages/(\d+)(?:/|$)", relative)
        page_id = ids[0] if len(ids) == 1 else (match[1] if match else "")
        if page_id:
            if not page_id.isdigit():
                raise ProviderError("Confluence page ID must be numeric.")
            data = self._request("confluence", "GET", f"rest/api/content/{page_id}?expand=body.storage")
        else:
            display = re.fullmatch(r"display/([^/]+)/(.+)", relative)
            if not display:
                raise ProviderError("Use a Confluence page URL containing a page ID or /display/SPACE/Title.")
            query = urlencode({"spaceKey": unquote(display[1]), "title": unquote(display[2].replace("+", " ")), "expand": "body.storage", "limit": 2})
            result = self._request("confluence", "GET", "rest/api/content?" + query)
            if len(result.get("results", [])) != 1:
                raise ProviderError("Confluence page lookup was empty or ambiguous; use a page ID URL.")
            data = result["results"][0]
        parser = _PageText()
        parser.feed(data.get("body", {}).get("storage", {}).get("value", ""))
        page_id = str(data.get("id", page_id))
        return {"id": page_id, "title": data.get("title", ""), "body": "".join(parser.parts).strip(), "url": f"{base}/pages/viewpage.action?pageId={page_id}"}

    def create_pull_request(self, repository: str, source: str, target: str, title: str, description: str) -> dict[str, Any]:
        """Request a draft pull request, or reuse the existing branch pair.

        Parameters
        ----------
        repository : str
            Workspace/repository or project/repository.
        source : str
            Source branch name.
        target : str
            Destination branch name.
        title : str
            Pull request title.
        description : str
            Pull request description.

        Returns
        -------
        dict
            Normalized newly created or already open pull request. ``draft``
            reflects the provider's boolean, or None when it does not report
            draft state. Older Data Center servers may ignore draft requests.
        """
        owner, repo = self._repository(repository)
        if not source or not target or source == target or not title.strip():
            raise ProviderError("Provide a title and distinct source and target branches.")
        path = self._pr_path(repository)
        cloud = self._cloud("bitbucket")
        query = urlencode({
            "state": "OPEN", "pagelen": 100,
            "q": f"source.branch.name = {json.dumps(source)} AND destination.branch.name = {json.dumps(target)}",
        }) if cloud else urlencode({"state": "OPEN", "limit": 100, "at": "refs/heads/" + source, "direction": "OUTGOING"})
        for existing in self._pages("bitbucket", path + "?" + query):
            normalized = self._normalize_pr(existing, repository)
            if normalized["source_branch"] == source and normalized["target_branch"] == target and self._same_repository(normalized["source_repository"], repository):
                return normalized
        if cloud:
            payload = {"title": title, "description": description, "source": {"branch": {"name": source}}, "destination": {"branch": {"name": target}}, "close_source_branch": False, "draft": True}
        else:
            repository_data = {"slug": repo, "project": {"key": owner}}
            payload = {"title": title, "description": description, "fromRef": {"id": "refs/heads/" + source, "repository": repository_data}, "toRef": {"id": "refs/heads/" + target, "repository": repository_data}, "draft": True}
        data = self._request("bitbucket", "POST", path, payload)
        try:
            normalized = self._normalize_pr(data, repository)
            if normalized["source_branch"] != source or normalized["target_branch"] != target or not self._same_repository(normalized["source_repository"], repository):
                raise ProviderError("Created pull request did not match the requested branch pair.")
            normalized["draft_requested"] = True
            return normalized
        except (ProviderError, AttributeError, TypeError):
            raise ProviderError("Pull request creation returned an incomplete result; inspect Bitbucket before retrying.", uncertain=True) from None

    def comment_issue(self, key: str, body: str, marker: str) -> dict[str, Any]:
        """Post a marked Jira comment once, checking history before sending.

        Parameters
        ----------
        key : str
            Jira issue key.
        body : str
            User-authorized comment text.
        marker : str
            Stable task-specific identifier used to find earlier delivery.

        Returns
        -------
        dict
            Comment ID and a link to the issue comment.
        """
        if not marker or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,120}", marker):
            raise ProviderError("Use a nonempty task marker with letters, digits, dots, dashes, colons or underscores.")
        if not body.strip():
            raise ProviderError("Comment body must not be empty.")
        path = self._issue_path(key) + "/comment"
        stamp = f"[masteragent:{marker}]"
        for comment in self._pages("jira", path + "?maxResults=100", "comments"):
            if stamp in _text(comment.get("body")):
                return self._comment_result(key, comment)
        content = body.rstrip() + "\n\n" + stamp
        payload: dict[str, Any] = {"body": content}
        if self._cloud("jira"):
            payload["body"] = {"type": "doc", "version": 1, "content": [{"type": "paragraph", "content": [{"type": "text", "text": line}]} if line else {"type": "paragraph", "content": []} for line in content.split("\n")]}
        result = self._request("jira", "POST", path, payload)
        try:
            return self._comment_result(key, result)
        except (ProviderError, AttributeError, TypeError):
            raise ProviderError("Comment delivery returned an incomplete result; inspect Jira before retrying.", uncertain=True) from None

    def _comment_result(self, key: str, data: dict[str, Any]) -> dict[str, Any]:
        number = str(data.get("id", ""))
        if not number.isdigit():
            raise ProviderError("Provider returned a comment without a numeric ID.")
        return {"id": number, "url": self._base("jira") + f"/browse/{key}?focusedCommentId={number}#comment-{number}"}

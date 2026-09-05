"""Provider routes and recovery exercised without opening network connections."""

from __future__ import annotations

import io
import json
import os
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request

from masteragent.providers import MAX_PAGES, Providers
from masteragent.transport import (
    HttpTransport,
    ProviderError,
    _ScopedRedirect,
    validate_url,
)


class FakeTransport:
    def __init__(self, responses: list[object]) -> None:
        self.responses = iter(responses)
        self.calls: list[tuple[str, str, object]] = []

    def request(self, method: str, path: str, data: object = None) -> object:
        self.calls.append((method, path, data))
        result = next(self.responses)
        if isinstance(result, Exception):
            raise result
        return result


class FakeResponse(io.BytesIO):
    pass


class FakeOpener:
    def __init__(self, responses: list[object]) -> None:
        self.responses = iter(responses)
        self.calls: list[Request] = []

    def open(self, request: Request, timeout: float) -> FakeResponse:
        self.calls.append(request)
        response = next(self.responses)
        if isinstance(response, Exception):
            raise response
        return FakeResponse(json.dumps(response).encode())


def config(cloud: bool = True) -> dict:
    deployment = "cloud" if cloud else "server"
    return {
        "jira": {"url": "https://team.atlassian.net" if cloud else "https://work.example/jira", "deployment": deployment},
        "confluence": {"url": "https://team.atlassian.net/wiki" if cloud else "https://work.example/confluence", "deployment": deployment},
        "bitbucket": {"url": "https://bitbucket.org" if cloud else "https://work.example/bitbucket", "deployment": deployment},
    }


def cloud_pr(source: str = "feature", target: str = "main", number: int = 7) -> dict:
    return {"id": number, "title": "Caching", "state": "OPEN", "source": {"branch": {"name": source}, "commit": {"hash": "abcdef1234"}, "repository": {"full_name": "team/repo"}}, "destination": {"branch": {"name": target}}}


def server_pr(source: str = "feature", target: str = "main") -> dict:
    return {"id": 8, "title": "Caching", "state": "OPEN", "fromRef": {"id": "refs/heads/" + source, "latestCommit": "abcdef1234", "repository": {"slug": "repo", "project": {"key": "TEAM"}}}, "toRef": {"id": "refs/heads/" + target}}


class ProviderTests(unittest.TestCase):
    def test_cloud_issue_extracts_adf_and_remote_links(self) -> None:
        fake = FakeTransport([
            {"key": "APP-12", "fields": {"summary": "Caching", "status": {"name": "In progress"}, "description": {"type": "doc", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Read the PR", "marks": [{"type": "link", "attrs": {"href": "https://bitbucket.org/team/repo/pull-requests/7"}}]}]}]}}},
            [{"object": {"url": "https://team.atlassian.net/wiki/spaces/DEV/pages/9/Cache"}}],
        ])
        issue = Providers(config(), fake).issue("APP-12")
        self.assertEqual(issue["description"], "Read the PR")
        self.assertEqual(len(issue["links"]), 2)
        self.assertEqual(fake.calls[0][1], "rest/api/3/issue/APP-12?fields=summary,description,status,issuelinks")
        self.assertEqual(fake.calls[1][1], "rest/api/3/issue/APP-12/remotelink")

    def test_server_issue_keeps_context_and_plain_text(self) -> None:
        fake = FakeTransport([{"fields": {"summary": "Cache", "description": "See https://work.example/bitbucket/projects/TEAM/repos/repo/pull-requests/8."}}, []])
        result = Providers(config(False), fake).issue("APP-12")
        self.assertEqual(result["url"], "https://work.example/jira/browse/APP-12")
        self.assertTrue(fake.calls[0][1].startswith("rest/api/2/"))
        self.assertEqual(result["links"], ["https://work.example/bitbucket/projects/TEAM/repos/repo/pull-requests/8"])

    def test_cloud_pr_and_paginated_builds(self) -> None:
        next_url = "https://api.bitbucket.org/2.0/repositories/team/repo/commit/abcdef1234/statuses?page=2"
        fake = FakeTransport([cloud_pr(), {"values": [{"name": "Unit", "state": "SUCCESSFUL", "url": "https://ci.example/1"}], "next": next_url}, {"values": [{"name": "Lint", "state": "FAILED"}]}])
        providers = Providers(config(), fake)
        pr = providers.pull_request("https://bitbucket.org/team/repo/pull-requests/7/diff#part")
        self.assertEqual(pr["source_branch"], "feature")
        self.assertEqual(len(providers.builds(pr)), 2)
        self.assertEqual(fake.calls[0][1], "repositories/team/repo/pullrequests/7")
        self.assertEqual(fake.calls[2][1], next_url)

    def test_server_pr_and_builds_use_context_api(self) -> None:
        fake = FakeTransport([server_pr(), {"values": [{"key": "build", "state": "SUCCESSFUL"}], "isLastPage": True}])
        providers = Providers(config(False), fake)
        pr = providers.pull_request("https://work.example/bitbucket/projects/TEAM/repos/repo/pull-requests/8/overview")
        self.assertEqual(pr["target_branch"], "main")
        self.assertEqual(providers.builds(pr)[0]["name"], "build")
        self.assertEqual(fake.calls[0][1], "rest/api/1.0/projects/TEAM/repos/repo/pull-requests/8")
        self.assertEqual(fake.calls[1][1], "rest/api/1.0/projects/TEAM/repos/repo/commits/abcdef1234/builds?limit=100")

    def test_pages_read_numeric_cloud_and_server_display_urls(self) -> None:
        page = {"id": "9", "title": "Cache plan", "body": {"storage": {"value": "<h1>Plan</h1><p>Use &amp; reuse.</p>"}}}
        for cloud, url, response in [(True, "https://team.atlassian.net/wiki/spaces/DEV/pages/9/Cache", page), (False, "https://work.example/confluence/display/DEV/Cache+plan", {"results": [page]})]:
            with self.subTest(cloud=cloud):
                fake = FakeTransport([response])
                result = Providers(config(cloud), fake).page(url)
                self.assertEqual(result["body"], "Plan\nUse & reuse.")
                if cloud:
                    self.assertEqual(fake.calls[0][1], "rest/api/content/9?expand=body.storage")
                else:
                    query = parse_qs(urlsplit(fake.calls[0][1]).query)
                    self.assertEqual(query["spaceKey"], ["DEV"])
                    self.assertEqual(query["title"], ["Cache plan"])

    def test_external_and_context_escape_urls_never_reach_transport(self) -> None:
        fake = FakeTransport([])
        providers = Providers(config(False), fake)
        for url in ["https://evil.example/bitbucket/projects/TEAM/repos/repo/pull-requests/8", "https://work.example/other/projects/TEAM/repos/repo/pull-requests/8", "https://work.example/bitbucket/../projects/TEAM/repos/repo/pull-requests/8", "https://work.example/bitbucket/%252e%252e/projects/TEAM/repos/repo/pull-requests/8"]:
            with self.subTest(url=url), self.assertRaises(ProviderError):
                providers.pull_request(url)
        self.assertEqual(fake.calls, [])

    def test_pr_creation_reuses_exact_branch_pair_on_second_cloud_page(self) -> None:
        fake = FakeTransport([{"values": [cloud_pr("other")], "next": "https://api.bitbucket.org/2.0/repositories/team/repo/pullrequests?page=2"}, {"values": [cloud_pr()]}])
        result = Providers(config(), fake).create_pull_request("team/repo", "feature", "main", "Cache", "Details")
        self.assertEqual(result["id"], 7)
        self.assertTrue(all(call[0] == "GET" for call in fake.calls))

    def test_pr_creation_sends_cloud_draft_and_server_refs(self) -> None:
        for cloud in (True, False):
            with self.subTest(cloud=cloud):
                fake = FakeTransport([{"values": [], "isLastPage": True}, cloud_pr() if cloud else server_pr()])
                Providers(config(cloud), fake).create_pull_request("team/repo" if cloud else "TEAM/repo", "feature", "main", "Cache", "Details")
                self.assertEqual(fake.calls[1][0], "POST")
                payload = fake.calls[1][2]
                self.assertTrue(payload["draft"])
                if cloud:
                    self.assertEqual(payload["source"]["branch"]["name"], "feature")
                else:
                    self.assertEqual(payload["fromRef"]["id"], "refs/heads/feature")
                    self.assertEqual(payload["toRef"]["repository"]["project"]["key"], "TEAM")

    def test_draft_result_reports_only_provider_state(self) -> None:
        for cloud in (True, False):
            for draft in (True, False, None):
                with self.subTest(cloud=cloud, draft=draft):
                    returned = cloud_pr() if cloud else server_pr()
                    if draft is not None:
                        returned["draft"] = draft
                    fake = FakeTransport([{"values": [], "isLastPage": True}, returned])
                    result = Providers(config(cloud), fake).create_pull_request("team/repo" if cloud else "TEAM/repo", "feature", "main", "Cache", "Details")
                    self.assertIs(result["draft"], draft)
                    self.assertTrue(result["draft_requested"])
                    self.assertEqual(result["commit"], "abcdef1234")

    def test_create_mismatched_source_or_target_is_uncertain(self) -> None:
        for source, target in (("wrong-source", "main"), ("feature", "wrong-target")):
            with self.subTest(source=source, target=target):
                fake = FakeTransport([{"values": []}, cloud_pr(source, target)])
                with self.assertRaises(ProviderError) as failure:
                    Providers(config(), fake).create_pull_request("team/repo", "feature", "main", "Cache", "Details")
                self.assertTrue(failure.exception.uncertain)
                self.assertEqual(len(fake.calls), 2)

    def test_server_pr_pagination_uses_next_page_start(self) -> None:
        fake = FakeTransport([{"values": [server_pr("other")], "isLastPage": False, "nextPageStart": 47}, {"values": [server_pr()], "isLastPage": True}])
        Providers(config(False), fake).create_pull_request("TEAM/repo", "feature", "main", "Cache", "Details")
        self.assertEqual(parse_qs(urlsplit(fake.calls[1][1]).query)["start"], ["47"])
        self.assertEqual(len(fake.calls), 2)

    def test_server_project_case_does_not_create_a_duplicate_pr(self) -> None:
        fake = FakeTransport([{"values": [server_pr()], "isLastPage": True}])
        result = Providers(config(False), fake).create_pull_request("team/repo", "feature", "main", "Cache", "Details")
        self.assertEqual(result["id"], 8)
        self.assertEqual(len(fake.calls), 1)

    def test_comment_search_paginates_before_sending(self) -> None:
        fake = FakeTransport([{"comments": [{"id": "1", "body": "Old"}], "startAt": 0, "total": 2}, {"comments": [{"id": "2", "body": "Already delivered\n[masteragent:task-1]"}], "startAt": 1, "total": 2}])
        result = Providers(config(False), fake).comment_issue("APP-12", "Update", "task-1")
        self.assertEqual(result["id"], "2")
        self.assertEqual(len(fake.calls), 2)
        self.assertEqual(parse_qs(urlsplit(fake.calls[1][1]).query)["startAt"], ["1"])

    def test_cloud_comment_uses_adf_and_reuses_marker(self) -> None:
        fake = FakeTransport([{"comments": [], "total": 0}, {"id": "23"}])
        result = Providers(config(), fake).comment_issue("APP-12", "Done\nTests pass.", "task-1")
        body = fake.calls[1][2]["body"]
        self.assertEqual(body["type"], "doc")
        self.assertEqual(body["content"][-1]["content"][0]["text"], "[masteragent:task-1]")
        self.assertEqual(result["id"], "23")

    def test_bound_prevents_post_after_incomplete_discovery(self) -> None:
        pages = [{"values": [], "isLastPage": False, "nextPageStart": index + 1} for index in range(MAX_PAGES)]
        fake = FakeTransport(pages)
        with self.assertRaisesRegex(ProviderError, "exceeded"):
            Providers(config(False), fake).create_pull_request("TEAM/repo", "feature", "main", "Cache", "Details")
        self.assertEqual(len(fake.calls), MAX_PAGES)
        self.assertTrue(all(call[0] == "GET" for call in fake.calls))

    def test_cross_origin_pagination_rejected_before_next_request(self) -> None:
        fake = FakeTransport([{"values": [], "next": "https://evil.example/pullrequests"}])
        with self.assertRaises(ProviderError):
            Providers(config(), fake).create_pull_request("team/repo", "feature", "main", "Cache", "Details")
        self.assertEqual(len(fake.calls), 1)

    def test_credentials_resolve_once_for_only_used_provider(self) -> None:
        settings = config()
        settings["jira"].update(token_env="TEST_JIRA_TOKEN", username_env="TEST_JIRA_EMAIL")
        clients: list[tuple] = []
        fake = FakeTransport([{"fields": {}}, [], {"fields": {}}, []])

        def factory(*args: object, **kwargs: object) -> FakeTransport:
            clients.append((args, kwargs))
            return fake

        providers = Providers(settings, factory)
        with patch.dict(os.environ, {"TEST_JIRA_TOKEN": "private-token", "TEST_JIRA_EMAIL": "rory@example.com"}, clear=True):
            providers.issue("APP-12")
        with patch.dict(os.environ, {}, clear=True):
            providers.issue("APP-12")
        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[0][0][0], "https://team.atlassian.net")
        self.assertTrue(clients[0][0][1].startswith("Basic "))
        self.assertEqual(set(providers._clients), {"jira"})

    def test_uncertain_write_failure_is_not_replayed(self) -> None:
        fake = FakeTransport([{"comments": [], "total": 0}, ProviderError("Lost response", uncertain=True)])
        with self.assertRaises(ProviderError) as failure:
            Providers(config(), fake).comment_issue("APP-12", "Done", "task-1")
        self.assertTrue(failure.exception.uncertain)
        self.assertEqual([call[0] for call in fake.calls], ["GET", "POST"])


class TransportTests(unittest.TestCase):
    def test_context_prefix_and_headers_are_preserved(self) -> None:
        opener = FakeOpener([{"ok": True}])
        client = HttpTransport("https://work.example/jira", "Bearer private-token", opener=opener)
        self.assertTrue(client.request("GET", "rest/api/2/issue/APP-12")["ok"])
        self.assertEqual(opener.calls[0].full_url, "https://work.example/jira/rest/api/2/issue/APP-12")
        self.assertEqual(opener.calls[0].get_header("Authorization"), "Bearer private-token")

    def test_read_retry_is_bounded_and_retry_after_capped(self) -> None:
        delays: list[float] = []
        errors = [HTTPError("https://work.example/jira", 429, "token should not appear", {"Retry-After": "999"}, io.BytesIO(b"private content")) for _ in range(3)]
        opener = FakeOpener(errors)
        client = HttpTransport("https://work.example/jira", "Bearer private-token", opener=opener, sleep=delays.append)
        with self.assertRaises(ProviderError) as failure:
            client.request("GET", "rest/api/2/issue/APP-12")
        self.assertEqual(len(opener.calls), 3)
        self.assertEqual(delays, [5, 5])
        self.assertNotIn("private", str(failure.exception))
        self.assertFalse(failure.exception.uncertain)

    def test_network_write_failure_is_uncertain_and_never_retried(self) -> None:
        opener = FakeOpener([URLError("private-token")])
        client = HttpTransport("https://work.example/jira", "Bearer private-token", opener=opener)
        with self.assertRaises(ProviderError) as failure:
            client.request("POST", "rest/api/2/issue/APP-12/comment", {"body": "Done"})
        self.assertEqual(len(opener.calls), 1)
        self.assertTrue(failure.exception.uncertain)
        self.assertNotIn("private-token", str(failure.exception))

    def test_http_503_write_is_uncertain_and_not_retried(self) -> None:
        opener = FakeOpener([HTTPError("https://work.example/jira", 503, "failure", {}, io.BytesIO(b"private"))])
        client = HttpTransport("https://work.example/jira", "Bearer token", opener=opener)
        with self.assertRaises(ProviderError) as failure:
            client.request("POST", "rest/api/2/issue/APP-12/comment", {"body": "Done"})
        self.assertTrue(failure.exception.uncertain)
        self.assertEqual(len(opener.calls), 1)

    def test_redirect_blocks_cross_origin_and_context_before_auth_can_leave(self) -> None:
        redirect = _ScopedRedirect("https://work.example/jira")
        request = Request("https://work.example/jira/rest/api/2/issue/APP-12", headers={"Authorization": "Bearer secret"})
        for target in ["https://evil.example/jira", "https://work.example/login", "http://work.example/jira"]:
            with self.subTest(target=target), self.assertRaises(ProviderError):
                redirect.redirect_request(request, None, 302, "Found", {}, target)
        allowed = redirect.redirect_request(request, None, 302, "Found", {}, "https://work.example/jira/rest/api/2/issue/APP-13")
        self.assertEqual(allowed.get_header("Authorization"), "Bearer secret")

    def test_write_redirect_is_not_followed(self) -> None:
        redirect = _ScopedRedirect("https://work.example/jira")
        request = Request("https://work.example/jira/comment", method="POST", data=b"{}")
        with self.assertRaises(ProviderError) as failure:
            redirect.redirect_request(request, None, 302, "Found", {}, "https://work.example/jira/other")
        self.assertTrue(failure.exception.uncertain)

    def test_url_credentials_and_encoded_traversal_rejected(self) -> None:
        for url in ["https://user:secret@work.example/jira/rest/api", "https://work.example/jira/%2e%2e/other", "https://work.example/jira/%252e%252e/other", "https://work.example/jira%2fother", "https://work.example/jira/../other", "https://work.example/jira\\other", "https://work.example/jira-other"]:
            with self.subTest(url=url), self.assertRaises(ProviderError):
                validate_url(url, "https://work.example/jira")


if __name__ == "__main__":
    unittest.main()

"""Connector implementations for governed external capabilities."""

from master_agent.connectors.bitbucket import BitbucketConnector
from master_agent.connectors.confluence import ConfluenceConnector
from master_agent.connectors.github import GitHubConnector
from master_agent.connectors.github_write import (
    GitHubAdminConnector,
    GitHubWriteConnector,
)
from master_agent.connectors.jira import JiraConnector
from master_agent.connectors.microsoft import (
    MicrosoftIdentityConnector,
    SharePointConnector,
)
from master_agent.connectors.mock import MockConnector
from master_agent.connectors.reddit import RedditConnector
from master_agent.connectors.reddit_write import RedditWriteConnector

__all__ = [
    "BitbucketConnector",
    "ConfluenceConnector",
    "GitHubAdminConnector",
    "GitHubConnector",
    "GitHubWriteConnector",
    "JiraConnector",
    "MicrosoftIdentityConnector",
    "MockConnector",
    "RedditConnector",
    "RedditWriteConnector",
    "SharePointConnector",
]

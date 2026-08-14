"""Connector implementations for governed external capabilities."""

from master_agent.connectors.bitbucket import BitbucketConnector
from master_agent.connectors.confluence import ConfluenceConnector
from master_agent.connectors.jira import JiraConnector
from master_agent.connectors.microsoft import (
    MicrosoftIdentityConnector,
    SharePointConnector,
)
from master_agent.connectors.mock import MockConnector

__all__ = [
    "BitbucketConnector",
    "ConfluenceConnector",
    "JiraConnector",
    "MicrosoftIdentityConnector",
    "MockConnector",
    "SharePointConnector",
]

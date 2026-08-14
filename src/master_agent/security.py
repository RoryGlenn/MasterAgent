"""Untrusted-content controls and prompt-injection detection."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SecurityFinding:
    """Potentially dangerous instruction found in retrieved content."""

    category: str
    excerpt: str
    severity: str


class PromptInjectionGuard:
    """Detect common instruction-like attacks in retrieved content.

    This scanner is only a signal. The hard boundary is enforced by the
    ``AuthoritySource`` policy: retrieved content cannot authorize writes.
    """

    _PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
        (
            "instruction_override",
            "high",
            re.compile(
                r"\b(ignore|disregard|override)\b.{0,80}\b"
                r"(instructions?|policy|rules?|system|developer)\b",
                re.IGNORECASE | re.DOTALL,
            ),
        ),
        (
            "credential_request",
            "high",
            re.compile(
                r"\b(password|api[_ -]?key|access token|secret|credentials?)\b",
                re.IGNORECASE,
            ),
        ),
        (
            "external_action_request",
            "medium",
            re.compile(
                r"\b(send|email|message|upload|publish|delete|merge|transfer)\b"
                r".{0,80}\b(file|document|secret|credential|repository|issue)\b",
                re.IGNORECASE | re.DOTALL,
            ),
        ),
        (
            "authority_claim",
            "medium",
            re.compile(
                r"\b(you are authorized|approval is not required|act as admin|"
                r"bypass approval)\b",
                re.IGNORECASE,
            ),
        ),
    )

    def scan(self, text: str) -> tuple[SecurityFinding, ...]:
        """Scan retrieved text for instruction-like content.

        Parameters
        ----------
        text
            Untrusted text retrieved from a system.

        Returns
        -------
        tuple[SecurityFinding, ...]
            Findings for review and audit.
        """

        findings: list[SecurityFinding] = []
        for category, severity, pattern in self._PATTERNS:
            match = pattern.search(text)
            if match is None:
                continue
            start = max(match.start() - 40, 0)
            end = min(match.end() + 40, len(text))
            findings.append(
                SecurityFinding(
                    category=category,
                    severity=severity,
                    excerpt=text[start:end].replace("\n", " ").strip(),
                )
            )
        return tuple(findings)


@dataclass(frozen=True, slots=True)
class LocatedSecurityFinding:
    """Security finding annotated with a JSON-like content path."""

    path: str
    category: str
    excerpt: str
    severity: str


def scan_untrusted_value(
    value: object,
    *,
    guard: PromptInjectionGuard | None = None,
    max_characters: int = 200_000,
) -> tuple[LocatedSecurityFinding, ...]:
    """Scan strings inside a nested retrieved value.

    Parameters
    ----------
    value
        Nested mapping/list/scalar value retrieved from a connector.
    guard
        Optional scanner instance.
    max_characters
        Maximum total string content to inspect.

    Returns
    -------
    tuple[LocatedSecurityFinding, ...]
        Findings with the location of the suspicious string.
    """

    scanner = guard or PromptInjectionGuard()
    findings: list[LocatedSecurityFinding] = []
    remaining = max_characters

    def visit(current: object, path: str) -> None:
        nonlocal remaining
        if remaining <= 0:
            return
        if isinstance(current, str):
            candidate = current[:remaining]
            remaining -= len(candidate)
            for finding in scanner.scan(candidate):
                findings.append(
                    LocatedSecurityFinding(
                        path=path,
                        category=finding.category,
                        excerpt=finding.excerpt,
                        severity=finding.severity,
                    )
                )
            return
        if isinstance(current, dict):
            for key, item in current.items():
                visit(item, f"{path}.{key}")
            return
        if isinstance(current, (tuple, list, set)):
            for index, item in enumerate(current):
                visit(item, f"{path}[{index}]")

    visit(value, "$")
    return tuple(findings)

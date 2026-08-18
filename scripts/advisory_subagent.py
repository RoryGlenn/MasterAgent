"""Run one optional broker-owned Copilot advisory specialist."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from master_agent.advisory import (
    AdvisoryBroker,
    AdvisoryRole,
    DelegationStatus,
    RepositoryFixture,
    load_agent_inventory,
)
from master_agent.copilot_advisory import CopilotSdkAdvisoryWorker

_MAX_CITED_FILE_BYTES = 64 * 1024


def _safe_citation_text(root: Path, relative: str) -> str:
    candidate = (root / relative).resolve(strict=True)
    try:
        candidate.relative_to(root)
    except ValueError as error:
        raise ValueError(f"citation escapes repository root: {relative}") from error
    if not candidate.is_file() or candidate.is_symlink():
        raise ValueError(f"citation is not a regular repository file: {relative}")
    payload = candidate.read_bytes()
    if len(payload) > _MAX_CITED_FILE_BYTES:
        raise ValueError(f"citation exceeds the advisory evidence limit: {relative}")
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"citation is not UTF-8 text: {relative}") from error


def _role(value: str) -> AdvisoryRole:
    if value == "research":
        return AdvisoryRole.RESEARCH
    if value == "plan-review":
        return AdvisoryRole.PLAN_REVIEW
    raise ValueError(f"unsupported advisory role: {value}")


def run(root: Path, role: AdvisoryRole, task: str, paths: tuple[str, ...]) -> int:
    """Execute one live specialist call through the repository-owned broker."""

    root = root.resolve()
    inventory = load_agent_inventory(root)
    broker = AdvisoryBroker(inventory, RepositoryFixture({}))
    session = broker.start_session("MasterAgent", f"cli-{role.value}")
    payload: dict[str, object] = {"task": task}
    if paths:
        payload["paths"] = list(paths)
    outcome = session.delegate(
        role,
        payload,
        worker=CopilotSdkAdvisoryWorker(root),
    )

    if outcome.status is not DelegationStatus.COMPLETED or outcome.report is None:
        print(
            json.dumps(
                {
                    "status": outcome.status.value,
                    "fallback_to_parent": outcome.fallback_to_parent,
                    "reason": outcome.reason,
                },
                sort_keys=True,
            )
        )
        return 2 if outcome.fallback_to_parent else 3

    try:
        cited = {
            path: _safe_citation_text(root, path)
            for path in sorted(set(outcome.report.citations))
        }
        verification_broker = AdvisoryBroker(inventory, RepositoryFixture(cited))
        verified = verification_broker.recheck_report(outcome.report)
    except (OSError, ValueError) as error:
        print(
            json.dumps(
                {
                    "status": "fallback",
                    "fallback_to_parent": True,
                    "reason": f"parent citation revalidation failed: {error}",
                },
                sort_keys=True,
            )
        )
        return 2

    print(
        json.dumps(
            {
                "status": "completed",
                "fallback_to_parent": False,
                "summary": verified.summary,
                "findings": list(verified.findings),
                "citations": list(verified.citations),
            },
            sort_keys=True,
        )
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run one governed read-only MasterAgent Copilot specialist."
    )
    parser.add_argument("role", choices=("research", "plan-review"))
    parser.add_argument("--task", required=True)
    parser.add_argument("--path", action="append", default=[])
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    return run(root, _role(arguments.role), arguments.task, tuple(arguments.path))


if __name__ == "__main__":
    raise SystemExit(main())

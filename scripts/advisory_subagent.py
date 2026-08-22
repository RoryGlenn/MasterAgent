"""Run one optional broker-owned Copilot advisory specialist."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from master_agent.advisory import (
    AdvisoryBroker,
    AdvisoryRole,
    AgentInventory,
    DelegationStatus,
    RepositoryFixture,
    SemanticRouteSlice,
)
from master_agent.advisory_budget import (
    AdvisoryBudgetStateError,
    AdvisoryBudgetStore,
)
from master_agent.copilot_advisory import (
    AdvisoryPathScope,
    AdvisoryRepositoryState,
    CopilotRepositoryChanged,
    CopilotRepositoryScanRejected,
    CopilotScopeRejected,
    CopilotSdkAdvisoryWorker,
    load_agent_inventory_at_revision,
    read_scoped_text,
    repository_state_binding,
)
from master_agent.platform_runtime import (
    PlatformCapabilityUnavailable,
    PlatformContract,
    require_persistent_state_platform,
    require_platform_contract,
)

if __package__:
    from scripts import semantic_router as _semantic_router
else:
    import semantic_router as _semantic_router  # type: ignore[import-not-found,no-redef]

_MAX_CITED_FILE_BYTES = 64 * 1024


@dataclass(frozen=True, slots=True)
class _BoundSemanticRoute:
    """One validated route tied to the repository state that authorized it."""

    route: SemanticRouteSlice
    repository_state: AdvisoryRepositoryState
    inventory: AgentInventory


def _safe_citation_text(scope: AdvisoryPathScope, relative: str) -> str:
    return read_scoped_text(scope, relative, max_bytes=_MAX_CITED_FILE_BYTES)


def _role(value: str) -> AdvisoryRole:
    if value == "research":
        return AdvisoryRole.RESEARCH
    if value == "plan-review":
        return AdvisoryRole.PLAN_REVIEW
    raise ValueError(f"unsupported advisory role: {value}")


def run(
    root: Path,
    role: AdvisoryRole,
    task: str,
    paths: tuple[str, ...],
    *,
    route: str | None,
    goal_id: str,
    state_directory: Path | None = None,
) -> int:
    """Execute one live specialist call through the repository-owned broker."""

    try:
        require_persistent_state_platform()
        require_platform_contract(PlatformContract.PROCESS_SUPERVISION)
        require_platform_contract(PlatformContract.TRUSTED_GIT)
        root = root.resolve()
        selected_state = state_directory or root / ".master-agent/advisory"
        bound_route = _validated_semantic_route(root, route, paths)
        semantic_route = bound_route.route
        scope = AdvisoryPathScope.bind(root, paths)
        inventory = bound_route.inventory
        task_id = _task_id(
            goal_id,
            role,
            task,
            scope,
            semantic_route,
            bound_route.repository_state.digest,
        )
        with AdvisoryBudgetStore(selected_state, root) as budget:
            broker = AdvisoryBroker(
                inventory,
                RepositoryFixture({}),
                budget=budget,
            )
            session = broker.start_session(
                "MasterAgent",
                task_id,
                goal_id=goal_id,
                semantic_route=semantic_route,
            )
            outcome = session.delegate(
                role,
                {"task": task, "paths": list(scope.relative_paths)},
                worker=CopilotSdkAdvisoryWorker(
                    root,
                    scope=scope,
                    expected_repository_digest=bound_route.repository_state.digest,
                    profile_inventory=inventory,
                ),
            )
    except (
        AdvisoryBudgetStateError,
        CopilotRepositoryChanged,
        CopilotRepositoryScanRejected,
        CopilotScopeRejected,
        PlatformCapabilityUnavailable,
        OSError,
        ValueError,
    ):
        return _print_fallback("advisory runner prerequisites failed closed")

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
            path: _safe_citation_text(scope, path)
            for path in sorted(set(outcome.report.citations))
        }
        verification_broker = AdvisoryBroker(inventory, RepositoryFixture(cited))
        verified = verification_broker.recheck_report(outcome.report)
    except (CopilotScopeRejected, OSError, ValueError):
        return _print_fallback("parent citation revalidation failed closed")

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


def _task_id(
    goal_id: str,
    role: AdvisoryRole,
    task: str,
    scope: AdvisoryPathScope,
    semantic_route: SemanticRouteSlice,
    repository_digest: str,
) -> str:
    material = json.dumps(
        {
            "goal_id": goal_id,
            "role": role.value,
            "repository_digest": repository_digest,
            "semantic_route": semantic_route.to_payload(),
            "scope_digest": scope.digest,
            "task": task,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return f"cli-{hashlib.sha256(material).hexdigest()}"


def _validated_semantic_route(
    root: Path,
    route_id: str | None,
    requested_paths: Sequence[str],
) -> _BoundSemanticRoute:
    """Load one exact route from one stable repository-state snapshot."""

    if not isinstance(route_id, str) or not route_id or route_id != route_id.strip():
        raise _semantic_router.ManifestError(
            "one exact parent-selected semantic route identifier is required"
        )
    repository_state = repository_state_binding(root)
    manifest = _semantic_router.load_manifest_at_revision(
        root,
        repository_state.head_revision,
    )
    inventory = load_agent_inventory_at_revision(
        root,
        repository_state.head_revision,
    )
    errors = _semantic_router.validate_repository(root, manifest)
    if errors:
        raise _semantic_router.ManifestError("semantic router validation failed")
    selected = manifest.routes_by_id.get(route_id)
    if selected is None:
        raise _semantic_router.ManifestError(
            "parent-selected semantic route is unknown"
        )
    _validate_requested_route_paths(manifest, selected.id, requested_paths)
    semantic_route = SemanticRouteSlice(
        route=selected.id,
        title=selected.title,
        lifecycle=selected.lifecycle,
        summary=selected.summary,
        authority=selected.authority,
        implementation=selected.implementation,
        configuration=selected.configuration,
        tests=selected.tests,
        release_gates=selected.release_gates,
        dependencies=selected.dependencies,
    )
    if repository_state_binding(root) != repository_state:
        raise CopilotRepositoryChanged(
            "repository changed while semantic route authorization was being bound"
        )
    return _BoundSemanticRoute(semantic_route, repository_state, inventory)


def _validate_requested_route_paths(
    manifest: _semantic_router.SemanticManifest,
    selected_route_id: str,
    requested_paths: Sequence[str],
) -> None:
    """Require exact files owned or linked by a route dependency closure."""

    route_ids: set[str] = set()
    pending = [selected_route_id]
    routes = manifest.routes_by_id
    while pending:
        route_id = pending.pop()
        if route_id in route_ids:
            continue
        route = routes.get(route_id)
        if route is None:
            raise _semantic_router.ManifestError("semantic route dependency is unknown")
        route_ids.add(route_id)
        pending.extend(route.dependencies)

    allowed_paths = {
        path
        for route_id in route_ids
        for field in _semantic_router.ROUTE_PATH_FIELDS
        for path in getattr(routes[route_id], field)
    }
    for category in _semantic_router.PATH_OWNERSHIP_CATEGORIES:
        allowed_paths.update(
            path
            for path, owner in manifest.ownership[category].items()
            if owner in route_ids
        )

    if not requested_paths or any(
        not isinstance(path, str) or path not in allowed_paths
        for path in requested_paths
    ):
        raise CopilotScopeRejected(
            "advisory path is outside the selected semantic route"
        )


def _print_fallback(reason: str) -> int:
    print(
        json.dumps(
            {
                "status": "fallback",
                "fallback_to_parent": True,
                "reason": reason,
            },
            sort_keys=True,
        )
    )
    return 2


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run one governed read-only MasterAgent Copilot specialist."
    )
    parser.add_argument("role", choices=("research", "plan-review"))
    parser.add_argument("--task", required=True)
    parser.add_argument(
        "--route",
        action="append",
        required=True,
        help="Exact stable route ID selected by the parent semantic-router hop.",
    )
    parser.add_argument(
        "--goal-id",
        required=True,
        help="Opaque stable identifier reused for one operator goal.",
    )
    parser.add_argument(
        "--path",
        action="append",
        required=True,
        help="Exact repository-relative file in the selected semantic route.",
    )
    parser.add_argument(
        "--state-dir",
        type=Path,
        help="Private mode-0700 budget directory (default: .master-agent/advisory).",
    )
    arguments = parser.parse_args()
    if len(arguments.route) != 1:
        return _print_fallback(
            "advisory runner requires exactly one parent-selected semantic route"
        )
    root = Path(__file__).resolve().parents[1]
    return run(
        root,
        _role(arguments.role),
        arguments.task,
        tuple(arguments.path),
        route=arguments.route[0],
        goal_id=arguments.goal_id,
        state_directory=arguments.state_dir,
    )


if __name__ == "__main__":
    raise SystemExit(main())

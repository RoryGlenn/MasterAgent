"""A small command surface for Copilot and direct terminal use."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .settings import (
    PROVIDERS,
    configure_project,
    configure_provider,
    home_path,
    initialize,
    load_config,
    readiness,
    save_config,
)
from .state import TaskStore
from .workflows import Workflows


def parser() -> argparse.ArgumentParser:
    """Build the CLI with discoverable workflow and recovery commands."""
    root = argparse.ArgumentParser(prog="masteragent", description="Native work tools and remembered tasks for your assistant.")
    root.add_argument("--version", action="version", version=__version__)
    root.add_argument("--home", help="Local state directory (default MASTERAGENT_HOME or ~/.masteragent)")
    root.add_argument("--json", action="store_true", help="Return structured results for a host assistant")
    commands = root.add_subparsers(dest="command", required=True)
    setup = commands.add_parser("setup", help="Remember connection details and project defaults")
    setup.add_argument("--provider", choices=PROVIDERS)
    setup.add_argument("--url", help="Provider HTTPS base URL, including any server context path")
    setup.add_argument("--deployment", choices=("cloud", "server"))
    setup.add_argument("--token-env", help="Environment variable name containing the token")
    setup.add_argument("--username-env", help="Environment variable name containing the Cloud account email/username")
    setup.add_argument("--ca-bundle", help="Corporate CA bundle file for this provider")
    setup.add_argument("--project", help="Jira project key")
    setup.add_argument("--repository", help="Local Git repository")
    setup.add_argument("--bitbucket-repository", help="workspace/repo or PROJECT/repo")
    setup.add_argument("--page", action="append", help="Default Confluence page, repeat for multiple pages")
    setup.add_argument("--check-json", action="append", help='Check command argv as JSON, e.g. ["python","-m","unittest","discover"]')
    commands.add_parser("doctor", help="Show local setup and missing environment names; no network calls")
    commands.add_parser("context", help="Show the editable preferences file")
    review = commands.add_parser("review", help="Collect issue, linked PR/builds, and documentation")
    review.add_argument("issue")
    review.add_argument("--pr", action="append", default=[])
    review.add_argument("--page", action="append", default=[])
    develop = commands.add_parser("develop", help="Prepare an isolated worktree and handoff for host coding")
    develop.add_argument("issue")
    develop.add_argument("--base", help="Local Git base ref (default current repository HEAD)")
    for name, help_text in (("checks", "Run configured checks on a development worktree"), ("show", "Show a saved task"), ("resume", "Continue unfinished steps"), ("cancel", "Cancel a task before its next tool step")):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("task")
    publish = commands.add_parser("publish", help="Push tested commits, open a Bitbucket PR, and comment on Jira")
    publish.add_argument("task")
    publish.add_argument("--title", required=True)
    publish.add_argument("--description-file", required=True, type=Path)
    publish.add_argument("--target", default="main")
    publish.add_argument("--remote", default="origin")
    status = commands.add_parser("status", help="Create a local status draft from saved task history")
    status.add_argument("--task", action="append")
    commands.add_parser("tasks", help="List saved tasks")
    note = commands.add_parser("note", help="Replace the task's editable handoff note")
    note.add_argument("task")
    note.add_argument("text")
    resolve = commands.add_parser("resolve", help="Record an observed result for an uncertain external write")
    resolve.add_argument("task")
    resolve.add_argument("step")
    resolution = resolve.add_mutually_exclusive_group(required=True)
    resolution.add_argument("--result-file", type=Path, help="JSON result observed in the provider")
    resolution.add_argument("--not-applied", action="store_true", help="I checked the provider and confirmed this write did not happen; allow retry")
    commands.add_parser("demo", help="Run fictional review and status workflows without credentials")
    return root


def _setup(args: argparse.Namespace, home: Path, config: dict[str, Any]) -> dict[str, Any]:
    if args.provider:
        if not args.url:
            raise ValueError("Provide --url with --provider.")
        configure_provider(config, args.provider, args.url, deployment=args.deployment, token_env=args.token_env, username_env=args.username_env, ca_bundle=args.ca_bundle)
    elif any((args.url, args.deployment, args.token_env, args.username_env, args.ca_bundle)):
        raise ValueError("Connection settings require --provider.")
    if args.project:
        checks = None
        if args.check_json:
            checks = [json.loads(item) for item in args.check_json]
            if any(not isinstance(command, list) for command in checks):
                raise ValueError("Each --check-json value must be a JSON array of arguments.")
        configure_project(config, args.project, repository=args.repository, bitbucket_repository=args.bitbucket_repository, pages=args.page, checks=checks)
    elif any((args.repository, args.bitbucket_repository, args.page, args.check_json)):
        raise ValueError("Project settings require --project KEY.")
    save_config(home, config)
    return {"home": str(home), "config": str(home / "config.json"), "context": str(home / "context.md"), "readiness": readiness(config), "next_action": "Select MasterAgent Simple in Copilot, or configure a provider with setup --provider NAME --url URL."}


def execute(args: argparse.Namespace) -> Any:
    """Dispatch a command without importing an LLM SDK or legacy runtime."""
    if args.command == "demo":
        from .demo import run_demo
        return run_demo()
    home = home_path(args.home)
    config = load_config(home)
    if args.command == "setup":
        return _setup(args, home, config)
    if args.command == "doctor":
        return {"home": str(home), **readiness(config)}
    initialize(home)
    if args.command == "context":
        return {"path": str(home / "context.md"), "content": (home / "context.md").read_text(encoding="utf-8")}
    with TaskStore(home / "tasks.sqlite3") as store:
        if args.command == "tasks":
            return store.list_tasks()
        if args.command == "show":
            return store.get(args.task)
        if args.command == "cancel":
            store.cancel(args.task)
            return store.get(args.task)
        if args.command == "note":
            store.note(args.task, args.text)
            return store.get(args.task)
        if args.command == "resolve":
            if args.not_applied:
                store.retry_step(args.task, args.step)
            else:
                result = json.loads(args.result_file.read_text(encoding="utf-8"))
                required = {"git.push": ("branch", "commit", "remote"), "bitbucket.create_pr": ("url",), "jira.comment": ("id", "url")}.get(args.step)
                if required is None or not isinstance(result, dict) or any(not result.get(field) for field in required):
                    raise ValueError(f"Provide an observed result object containing {', '.join(required or ())} for a known publication step.")
                store.resolve_step(args.task, args.step, result)
            return store.get(args.task)
        from .providers import Providers
        runner = Workflows(home, config, store, Providers(config), progress=lambda message: print(message, file=sys.stderr))
        if args.command == "review":
            return runner.review(args.issue, prs=args.pr, pages=args.page)
        if args.command == "develop":
            return runner.develop(args.issue, base=args.base)
        if args.command == "checks":
            return runner.checks(args.task)
        if args.command == "publish":
            return runner.publish(args.task, title=args.title, description=args.description_file.read_text(encoding="utf-8"), target=args.target, remote=args.remote)
        if args.command == "status":
            return runner.status(args.task)
        if args.command == "resume":
            return runner.resume(args.task)
    raise ValueError(f"Unknown command {args.command}")


def _display(result: Any) -> None:
    if isinstance(result, list):
        if not result:
            print("No tasks yet. Start with review ISSUE or develop ISSUE.")
        for task in result:
            print(f"{task['id']}  {task['status']:10}  {task['workflow']}  {task['inputs'].get('issue', '')}")
    elif isinstance(result, dict) and result.get("demo"):
        print("Offline demo — fictional data; no accounts contacted.\n")
        print(result["review"])
        print(result["status_draft"])
    elif isinstance(result, dict) and "workflow" in result:
        print(f"Task {result['id']}: {result['status']}")
        data = result.get("result") or {}
        if data.get("artifact"):
            print(f"Output: {data['artifact']}")
        if data.get("workspace"):
            print(f"Worktree: {data['workspace']['path']}")
        if data.get("pull_request"):
            print(f"PR: {data['pull_request']['url']}")
            draft = data["pull_request"].get("draft")
            print(f"Draft: {'yes' if draft is True else 'no' if draft is False else 'not reported by provider'}")
        if data.get("next_action"):
            print(data["next_action"])
        if result.get("error"):
            print(result["error"])
    elif isinstance(result, dict) and "content" in result:
        print(f"{result['path']}\n\n{result['content']}")
    else:
        print(json.dumps(result, indent=2, ensure_ascii=False))


def main(argv: list[str] | None = None) -> int:
    """Run a command and return an exit status suitable for host tools."""
    args = parser().parse_args(argv)
    try:
        result = execute(args)
    except (RuntimeError, ValueError, OSError, KeyError) as exc:
        if args.json:
            print(json.dumps({"error": str(exc), "command": args.command}))
        else:
            print(str(exc), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrupted. Completed steps are saved; use tasks and resume to continue.", file=sys.stderr)
        return 130
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        _display(result)
    if isinstance(result, dict):
        if result.get("status") == "failed":
            return 1
        if "evidence" in result and not result["evidence"]["passed"]:
            return 1
    return 0

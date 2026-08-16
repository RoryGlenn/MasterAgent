"""End-to-end and adversarial coverage for resumable approval handoffs."""

from __future__ import annotations

import json
import os
import re
import stat
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from master_agent.approval_handoff import load_approval_request
from master_agent.cli import main
from master_agent.errors import ConfigurationError, ValidationError
from master_agent.models import (
    AgentAction,
    AuthoritySource,
    ChangePlan,
    DataClassification,
    ResourceRef,
    RiskLevel,
)
from tests.helpers import private_temporary_directory

ROOT = Path(__file__).resolve().parents[1]
_ALICE_SECRET = "alice-approval-secret-" + "a" * 32
_BOB_SECRET = "bob-approval-secret-" + "b" * 32


class ApprovalHandoffTests(unittest.TestCase):
    """Exercise the complete missing-approval, sign, and resume user flow."""

    def test_bind_rejects_unresumable_approval_required_plan(self) -> None:
        with private_temporary_directory() as directory:
            paths = _workspace(Path(directory))
            stderr = StringIO()
            with redirect_stdout(StringIO()), redirect_stderr(stderr):
                status = main(
                    [
                        "bind-context",
                        str(paths.plan),
                        *_runtime_arguments(paths, include_authorities=False),
                        "--output",
                        str(paths.bound),
                    ]
                )

            self.assertEqual(status, 1)
            self.assertIn("must bind --approval-authorities", stderr.getvalue())
            self.assertFalse(paths.bound.exists())

    def test_missing_approval_creates_private_request_and_resumes(self) -> None:
        with private_temporary_directory() as directory:
            paths = _workspace(Path(directory))
            _bind(paths, include_result=True)

            status, stdout, stderr = _run_bound(paths, include_result=True)
            self.assertEqual(status, 2, stderr)
            request_path = _request_path(stdout)
            request = load_approval_request(request_path)
            first_inode = request_path.stat().st_ino

            self.assertEqual(stat.S_IMODE(request_path.stat().st_mode), 0o600)
            self.assertEqual(
                request.plan_fingerprint, _load_plan(paths.bound).fingerprint
            )
            self.assertEqual(len(request.required_approvals), 1)
            self.assertEqual(request.run.approval_paths, ())
            self.assertIn("confluence.page.create", request_path.read_text())
            self.assertNotIn(_ALICE_SECRET, request_path.read_text())
            self.assertFalse(paths.result.exists())
            self.assertIn("remains reserved", stdout)

            inspect_stdout = StringIO()
            with redirect_stdout(inspect_stdout):
                self.assertEqual(
                    main(["inspect-approval-request", str(request_path)]),
                    0,
                )
            self.assertIn(request.fingerprint, inspect_stdout.getvalue())
            self.assertIn("Test approval handoff", inspect_stdout.getvalue())
            self.assertIn("captured non-secret run", inspect_stdout.getvalue())

            # The same retry reuses exact bytes rather than overwriting the request.
            retry_status, retry_stdout, retry_stderr = _run_bound(
                paths,
                include_result=True,
            )
            self.assertEqual(retry_status, 2, retry_stderr)
            self.assertEqual(_request_path(retry_stdout), request_path)
            self.assertEqual(request_path.stat().st_ino, first_inode)

            approval = paths.approvals / "alice.json"
            with patch.dict(
                os.environ,
                {"TEST_APPROVAL_SECRET_ALICE": _ALICE_SECRET},
                clear=False,
            ):
                approve_stderr = StringIO()
                with redirect_stdout(StringIO()), redirect_stderr(approve_stderr):
                    approve_status = main(
                        [
                            "approve-request",
                            str(request_path),
                            "--key-id",
                            "alice",
                            "--expected-fingerprint",
                            request.fingerprint,
                            "--output",
                            str(approval),
                        ]
                    )
            self.assertEqual(approve_status, 0, approve_stderr.getvalue())
            self.assertEqual(stat.S_IMODE(approval.stat().st_mode), 0o600)

            with patch.dict(
                os.environ,
                {"TEST_APPROVAL_SECRET_ALICE": _ALICE_SECRET},
                clear=False,
            ):
                resume_stdout = StringIO()
                resume_stderr = StringIO()
                with redirect_stdout(resume_stdout), redirect_stderr(resume_stderr):
                    resume_status = main(
                        [
                            "resume-approval",
                            str(request_path),
                            "--expected-fingerprint",
                            request.fingerprint,
                            "--approval",
                            str(approval),
                        ]
                    )

            self.assertEqual(resume_status, 0, resume_stderr.getvalue())
            self.assertIn("verified", resume_stdout.getvalue())
            self.assertIn("successful: True", resume_stdout.getvalue())
            self.assertTrue(paths.result.exists())
            result = json.loads(paths.result.read_text(encoding="utf-8"))
            self.assertTrue(result["successful"])

    def test_partial_dual_approval_is_carried_into_the_next_request(self) -> None:
        with private_temporary_directory() as directory:
            paths = _workspace(Path(directory), dual=True)
            _bind(paths)
            status, stdout, stderr = _run_bound(paths)
            self.assertEqual(status, 2, stderr)
            first_path = _request_path(stdout)
            first = load_approval_request(first_path)

            alice = paths.approvals / "alice.json"
            with (
                patch.dict(
                    os.environ,
                    {"TEST_APPROVAL_SECRET_ALICE": _ALICE_SECRET},
                    clear=False,
                ),
                redirect_stdout(StringIO()),
            ):
                self.assertEqual(
                    main(
                        [
                            "approve-request",
                            str(first_path),
                            "--key-id",
                            "alice",
                            "--expected-fingerprint",
                            first.fingerprint,
                            "--output",
                            str(alice),
                        ]
                    ),
                    0,
                )
            with patch.dict(
                os.environ,
                {
                    "TEST_APPROVAL_SECRET_ALICE": _ALICE_SECRET,
                    "TEST_APPROVAL_SECRET_BOB": _BOB_SECRET,
                },
                clear=False,
            ):
                partial_stdout = StringIO()
                partial_stderr = StringIO()
                with redirect_stdout(partial_stdout), redirect_stderr(partial_stderr):
                    partial_status = main(
                        [
                            "resume-approval",
                            str(first_path),
                            "--expected-fingerprint",
                            first.fingerprint,
                            "--approval",
                            str(alice),
                        ]
                    )

            self.assertEqual(partial_status, 2, partial_stderr.getvalue())
            second_path = _request_path(partial_stdout.getvalue())
            self.assertNotEqual(second_path, first_path)
            second = load_approval_request(second_path)
            self.assertEqual(second.run.approval_paths, (str(alice.resolve()),))
            self.assertIn("2 distinct approval", second.required_approvals[0].reason)

            bob = paths.approvals / "bob.json"
            with (
                patch.dict(
                    os.environ,
                    {"TEST_APPROVAL_SECRET_BOB": _BOB_SECRET},
                    clear=False,
                ),
                redirect_stdout(StringIO()),
            ):
                self.assertEqual(
                    main(
                        [
                            "approve-request",
                            str(second_path),
                            "--key-id",
                            "bob",
                            "--expected-fingerprint",
                            second.fingerprint,
                            "--output",
                            str(bob),
                        ]
                    ),
                    0,
                )
            with patch.dict(
                os.environ,
                {
                    "TEST_APPROVAL_SECRET_ALICE": _ALICE_SECRET,
                    "TEST_APPROVAL_SECRET_BOB": _BOB_SECRET,
                },
                clear=False,
            ):
                final_stdout = StringIO()
                final_stderr = StringIO()
                with redirect_stdout(final_stdout), redirect_stderr(final_stderr):
                    final_status = main(
                        [
                            "resume-approval",
                            str(second_path),
                            "--expected-fingerprint",
                            second.fingerprint,
                            "--approval",
                            str(bob),
                        ]
                    )

            self.assertEqual(final_status, 0, final_stderr.getvalue())
            self.assertIn("successful: True", final_stdout.getvalue())

    def test_tampered_or_symlinked_request_fails_before_resume(self) -> None:
        with private_temporary_directory() as directory:
            paths = _workspace(Path(directory))
            _bind(paths)
            status, stdout, stderr = _run_bound(paths)
            self.assertEqual(status, 2, stderr)
            request_path = _request_path(stdout)
            original = json.loads(request_path.read_text(encoding="utf-8"))
            original["goal"] = "tampered goal"
            request_path.write_text(json.dumps(original), encoding="utf-8")
            request_path.chmod(0o600)

            with self.assertRaisesRegex(ValidationError, "fingerprint changed"):
                load_approval_request(request_path)

            link = paths.artifacts / "request-link.json"
            link.symlink_to(request_path)
            with self.assertRaisesRegex(
                ConfigurationError,
                "could not be opened safely",
            ):
                load_approval_request(link)

    def test_changed_bound_authority_is_rejected_before_signing(self) -> None:
        with private_temporary_directory() as directory:
            paths = _workspace(Path(directory))
            _bind(paths)
            status, stdout, stderr = _run_bound(paths)
            self.assertEqual(status, 2, stderr)
            request_path = _request_path(stdout)
            request = load_approval_request(request_path)
            paths.authorities.write_text(
                paths.authorities.read_text(encoding="utf-8") + "\n",
                encoding="utf-8",
            )
            approval = paths.approvals / "stale-authority.json"

            approve_stderr = StringIO()
            with (
                patch.dict(
                    os.environ,
                    {"TEST_APPROVAL_SECRET_ALICE": _ALICE_SECRET},
                    clear=False,
                ),
                redirect_stdout(StringIO()),
                redirect_stderr(approve_stderr),
            ):
                approve_status = main(
                    [
                        "approve-request",
                        str(request_path),
                        "--key-id",
                        "alice",
                        "--expected-fingerprint",
                        request.fingerprint,
                        "--output",
                        str(approval),
                    ]
                )

            self.assertEqual(approve_status, 1)
            self.assertIn("differs from the bound plan", approve_stderr.getvalue())
            self.assertFalse(approval.exists())


class _Paths:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.plan = root / "plan.json"
        self.bound = root / "bound.json"
        self.authorities = root / "approval-authorities.toml"
        self.governance = root / "governance.toml"
        self.state = root / "state"
        self.artifacts = root / "artifacts"
        self.approvals = root / "approvals"
        self.results = root / "results"
        self.result = self.results / "report.json"


def _workspace(root: Path, *, dual: bool = False) -> _Paths:
    paths = _Paths(root)
    for directory in (paths.state, paths.artifacts, paths.approvals, paths.results):
        directory.mkdir(mode=0o700)
    paths.plan.write_text(json.dumps(_plan().to_dict()), encoding="utf-8")
    authority_payload = (
        "[authorities.alice]\n"
        'subject = "alice@example.test"\n'
        'secret_env = "TEST_APPROVAL_SECRET_ALICE"\n'
    )
    if dual:
        authority_payload += (
            "\n[authorities.bob]\n"
            'subject = "bob@example.test"\n'
            'secret_env = "TEST_APPROVAL_SECRET_BOB"\n'
        )
    paths.authorities.write_text(
        authority_payload,
        encoding="utf-8",
    )
    if dual:
        governance = (ROOT / "config/governance.toml").read_text(encoding="utf-8")
        paths.governance.write_text(
            governance
            + "\n[[rules]]\n"
            + 'pattern = "confluence.page.create"\n'
            + 'owner = "confluence-owner"\n'
            + 'authentication = "configured_connector"\n'
            + 'data_classifications = ["internal", "confidential"]\n'
            + 'approval_tier = "dual"\n'
            + 'environments = ["development", "non_production", "production"]\n'
            + "enabled = true\n",
            encoding="utf-8",
        )
    return paths


def _plan() -> ChangePlan:
    action = AgentAction(
        capability="confluence.page.create",
        target=ResourceRef(
            system="confluence",
            resource_type="page",
            resource_id="new",
        ),
        parameters={
            "space_key": "SD",
            "title": "Test approval handoff",
            "body": "<p>Private test content.</p>",
            "representation": "storage",
            "status": "current",
        },
        risk=RiskLevel.REVERSIBLE_WRITE,
        data_classification=DataClassification.INTERNAL,
        authority_source=AuthoritySource.DIRECT_USER,
        requires_approval=True,
        idempotency_key="test-resumable-approval",
        justification="Exercise the authenticated approval handoff.",
    )
    return ChangePlan(
        goal="Test approval handoff",
        actions=(action,),
        created_by="test",
    )


def _runtime_arguments(
    paths: _Paths,
    *,
    include_authorities: bool = True,
    include_result: bool = False,
) -> list[str]:
    arguments = [
        "--connector-mode",
        "mock",
        "--database",
        str(paths.state / "audit.sqlite3"),
        "--draft-output-dir",
        str(paths.artifacts),
        "--enable-writes",
    ]
    if include_authorities:
        arguments.extend(["--approval-authorities", str(paths.authorities)])
    if include_result:
        arguments.extend(["--result-json", str(paths.result)])
    if paths.governance.exists():
        arguments.extend(["--governance", str(paths.governance)])
    return arguments


def _bind(paths: _Paths, *, include_result: bool = False) -> None:
    stdout = StringIO()
    stderr = StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        status = main(
            [
                "bind-context",
                str(paths.plan),
                *_runtime_arguments(paths, include_result=include_result),
                "--output",
                str(paths.bound),
            ]
        )
    if status != 0:
        raise AssertionError(stderr.getvalue())


def _run_bound(
    paths: _Paths,
    *,
    include_result: bool = False,
) -> tuple[int, str, str]:
    stdout = StringIO()
    stderr = StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        status = main(
            [
                "run",
                str(paths.bound),
                "--apply",
                *_runtime_arguments(paths, include_result=include_result),
            ]
        )
    return status, stdout.getvalue(), stderr.getvalue()


def _request_path(stdout: str) -> Path:
    match = re.search(r"^approval request: (.+)$", stdout, flags=re.MULTILINE)
    if match is None:
        raise AssertionError(f"approval request path missing from output: {stdout}")
    return Path(match.group(1))


def _load_plan(path: Path) -> ChangePlan:
    return ChangePlan.from_dict(json.loads(path.read_text(encoding="utf-8")))


if __name__ == "__main__":
    unittest.main()

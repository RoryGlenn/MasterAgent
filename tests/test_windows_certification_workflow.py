from __future__ import annotations

import unittest
from pathlib import Path


class WindowsCertificationWorkflowTests(unittest.TestCase):
    """Validate the protected Windows certification trust boundary."""

    def test_protected_certification_is_default_branch_bound(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github/workflows/windows-certification.yml").read_text(
            encoding="utf-8"
        )

        for required in (
            'workflows: ["CI"]',
            "types: [completed]",
            "workflow_dispatch:",
            "MASTER_AGENT_WINDOWS_CERTIFICATION_ENABLED == 'true'",
            "github.event.workflow_run.event == 'push'",
            "github.event.workflow_run.conclusion == 'success'",
            "github.event.workflow_run.head_branch == github.event.repository.default_branch",
            "github.event.workflow_run.head_repository.full_name == github.repository",
            "repos/$REPOSITORY/branches/$DEFAULT_BRANCH",
            "jq -r '.protected'",
            'test "$SELECTED_SHA" = "$branch_sha"',
            "runs-on: [self-hosted, Windows, X64, masteragent-windows-11-x64]",
            "environment: windows-11-certification",
            "certification runner must use a non-administrator account",
            "certification requires a Windows workstation, not Windows Server",
            "certification requires native x64 Windows",
            "production credential environment names are forbidden",
            "ref: ${{ needs.authorize-commit.outputs.sha }}",
            "persist-credentials: false",
            "clean: true",
            "& $buildPython -m build --outdir $artifactRoot",
            "wheel installation failed",
            "source distribution installation failed",
            "tests.test_windows_atomic_state",
            "tests.test_windows_capsules",
            "tests.test_windows_certification_workflow",
            "tests.test_windows_credential_cli",
            "tests.test_windows_credentials",
            "tests.test_windows_git",
            "tests.test_windows_platform_runtime",
            "tests.test_windows_process",
            "scripts\\run_windows_adversarial.py --group hosted",
            "scripts\\run_windows_adversarial.py --group certification",
            "certification-only Windows adversarial tests failed",
            "scripts\\specs.py validate",
            "scripts\\validate_release.py",
            "if: always()",
        ):
            with self.subTest(required=required):
                self.assertIn(required, workflow)
        self.assertEqual(workflow.count("actions/checkout@"), 1)
        self.assertLess(
            workflow.index("Verify the clean standard-user Windows 11 host"),
            workflow.index("actions/checkout@"),
        )
        self.assertNotIn("pull_request_target", workflow)
        self.assertNotIn("${{ secrets.", workflow)


if __name__ == "__main__":
    unittest.main()

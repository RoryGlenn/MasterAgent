from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path

from scripts.run_windows_adversarial import (
    DEFAULT_MATRIX,
    MATRIX_SCHEMA,
    REQUIRED_INVARIANTS,
    AdversarialCase,
    MatrixError,
    load_matrix,
    run_group,
)


class PassingEvidenceFixture(unittest.TestCase):
    def required_case(self) -> None:
        self.assertTrue(True)


class SkippedEvidenceFixture(unittest.TestCase):
    @unittest.skip("required native evidence unavailable")
    def required_case(self) -> None:
        self.fail("a skipped fixture must not execute")


class WindowsAdversarialRunnerTests(unittest.TestCase):
    def test_default_matrix_is_complete_resolvable_and_grouped(self) -> None:
        cases = load_matrix()

        self.assertEqual({item.invariant for item in cases}, REQUIRED_INVARIANTS)
        hosted = {item.invariant for item in cases if item.group == "hosted"}
        certification = {
            item.invariant for item in cases if item.group == "certification"
        }
        self.assertTrue(hosted)
        self.assertTrue(certification)
        self.assertFalse(hosted & certification)
        self.assertEqual(hosted | certification, REQUIRED_INVARIANTS)
        self.assertEqual(
            {item.blocking_issue for item in cases if item.blocking_issue is not None},
            {111, 112},
        )

    def test_missing_duplicate_unknown_and_unresolvable_cases_fail_closed(self) -> None:
        valid_case = {
            "invariant": "fixture.required",
            "area": "fixture",
            "group": "hosted",
            "test_id": (
                "tests.test_windows_adversarial_runner."
                "PassingEvidenceFixture.required_case"
            ),
            "expected_reason": "fixture_passed",
        }
        documents = (
            ({"schema": MATRIX_SCHEMA, "cases": []}, "invariant_set_mismatch"),
            (
                {"schema": MATRIX_SCHEMA, "cases": [valid_case, valid_case]},
                "duplicate_invariant",
            ),
            (
                {
                    "schema": MATRIX_SCHEMA,
                    "cases": [valid_case | {"invariant": "fixture.unknown"}],
                },
                "invariant_set_mismatch",
            ),
            (
                {
                    "schema": MATRIX_SCHEMA,
                    "cases": [valid_case | {"test_id": "tests.missing.Case.test"}],
                },
                "test_unresolvable",
            ),
        )
        for document, reason in documents:
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as raw:
                path = Path(raw) / "matrix.json"
                path.write_text(json.dumps(document), encoding="utf-8")
                with self.assertRaisesRegex(MatrixError, reason):
                    load_matrix(
                        path,
                        expected_invariants=frozenset({"fixture.required"}),
                    )

    def test_required_skip_and_dependency_block_return_failure(self) -> None:
        skipped = AdversarialCase(
            invariant="fixture.skipped",
            area="fixture",
            group="hosted",
            test_id=(
                "tests.test_windows_adversarial_runner."
                "SkippedEvidenceFixture.required_case"
            ),
            expected_reason="skip_forbidden",
        )
        blocked = AdversarialCase(
            invariant="fixture.blocked",
            area="fixture",
            group="hosted",
            test_id=(
                "tests.test_windows_adversarial_runner."
                "PassingEvidenceFixture.required_case"
            ),
            expected_reason="dependency_incomplete",
            blocking_issue=112,
        )

        skip_output = io.StringIO()
        self.assertEqual(run_group((skipped,), "hosted", stream=skip_output), 1)
        self.assertIn("SKIPPED required tests", skip_output.getvalue())
        blocked_output = io.StringIO()
        self.assertEqual(run_group((blocked,), "hosted", stream=blocked_output), 1)
        self.assertIn("requires GitHub issue #112", blocked_output.getvalue())

    def test_active_exact_case_returns_success(self) -> None:
        case = AdversarialCase(
            invariant="fixture.active",
            area="fixture",
            group="hosted",
            test_id=(
                "tests.test_windows_adversarial_runner."
                "PassingEvidenceFixture.required_case"
            ),
            expected_reason="fixture_passed",
        )
        self.assertEqual(run_group((case,), "hosted", stream=io.StringIO()), 0)

    def test_default_matrix_stays_bounded_and_repository_owned(self) -> None:
        self.assertEqual(DEFAULT_MATRIX.parent, Path(__file__).resolve().parent)
        self.assertLess(DEFAULT_MATRIX.stat().st_size, 256 * 1024)


if __name__ == "__main__":
    unittest.main()

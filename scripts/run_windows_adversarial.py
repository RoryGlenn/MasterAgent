"""Run the exact Windows adversarial evidence for one certification group."""

from __future__ import annotations

import argparse
import json
import re
import sys
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
DEFAULT_MATRIX = ROOT / "tests" / "windows_adversarial_matrix.json"
MATRIX_SCHEMA = "master-agent/windows-adversarial-matrix@1"
GROUPS = frozenset({"hosted", "certification"})
MAX_MATRIX_BYTES = 256 * 1024

REQUIRED_INVARIANTS = frozenset(
    {
        "capsule.environment_secret",
        "capsule.handle_access",
        "capsule.host_filesystem",
        "capsule.named_pipe",
        "capsule.network_ipv4",
        "capsule.network_ipv6",
        "capsule.network_localhost",
        "capsule.output_exhaustion",
        "capsule.runtime_identity_tamper",
        "capsule.subprocess_tree",
        "credentials.cross_user_dpapi",
        "credentials.secret_redaction",
        "filesystem.alternate_data_stream",
        "filesystem.ancestor_replacement",
        "filesystem.case_collision",
        "filesystem.cloud_placeholder",
        "filesystem.destination_contention",
        "filesystem.hardlink_substitution",
        "filesystem.interrupted_recovery",
        "filesystem.owner_dacl_broadening",
        "filesystem.remote_namespace",
        "filesystem.reparse_substitution",
        "filesystem.reserved_device_name",
        "filesystem.trailing_dot_space",
        "filesystem.unicode_long_path",
        "filesystem.unsupported_filesystem",
        "git.case_collision",
        "git.credential_helper",
        "git.crlf_stability",
        "git.global_system_config",
        "git.hooks_executable_config",
        "git.index_contention",
        "git.repository_junction",
        "git.unicode_long_repository",
        "managed.antivirus_contention",
        "managed.applocker_wdac",
        "managed.authenticated_proxy",
        "managed.defender_cfa",
        "managed.enterprise_ca",
        "managed.onedrive_reparse",
        "managed.organization_acl_inheritance",
        "managed.standard_user",
        "managed.support_edr_principals",
        "process.application_control",
        "process.descendant_escape",
        "process.encoding_console",
        "process.environment_secret",
        "process.inherited_handle",
        "process.memory_limit",
        "process.output_flood",
        "process.process_limit",
        "process.timeout_tree_termination",
    }
)

_INVARIANT_PATTERN = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$")
_TEST_ID_PATTERN = re.compile(r"^tests(?:\.[A-Za-z_][A-Za-z0-9_]*){3,}$")
_REASON_PATTERN = re.compile(r"^[a-z][a-z0-9_]{1,79}$")


class MatrixError(ValueError):
    """The adversarial matrix is incomplete or malformed."""


@dataclass(frozen=True, slots=True)
class AdversarialCase:
    """One exact invariant-to-test binding."""

    invariant: str
    area: str
    group: str
    test_id: str
    expected_reason: str
    posix_equivalent: tuple[str, ...] = ()
    blocking_issue: int | None = None


def load_matrix(
    path: Path = DEFAULT_MATRIX,
    *,
    expected_invariants: frozenset[str] = REQUIRED_INVARIANTS,
) -> tuple[AdversarialCase, ...]:
    """Load and validate one bounded adversarial matrix.

    Parameters
    ----------
    path:
        JSON matrix to validate.
    expected_invariants:
        Exact invariant set required by the caller.

    Returns
    -------
    tuple[AdversarialCase, ...]
        Validated cases in deterministic invariant order.
    """

    try:
        payload = path.read_bytes()
    except OSError as error:
        raise MatrixError("adversarial_matrix_unreadable") from error
    if len(payload) > MAX_MATRIX_BYTES:
        raise MatrixError("adversarial_matrix_too_large")
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MatrixError("adversarial_matrix_invalid_json") from error
    if not isinstance(document, dict) or set(document) != {"schema", "cases"}:
        raise MatrixError("adversarial_matrix_invalid_document")
    if document["schema"] != MATRIX_SCHEMA or not isinstance(document["cases"], list):
        raise MatrixError("adversarial_matrix_invalid_schema")

    parsed = tuple(_parse_case(value) for value in document["cases"])
    identifiers = tuple(item.invariant for item in parsed)
    if len(set(identifiers)) != len(identifiers):
        raise MatrixError("adversarial_matrix_duplicate_invariant")
    actual = frozenset(identifiers)
    if actual != expected_invariants:
        missing = sorted(expected_invariants - actual)
        unknown = sorted(actual - expected_invariants)
        detail = ",".join((*missing, *unknown))[:512]
        raise MatrixError(f"adversarial_matrix_invariant_set_mismatch:{detail}")
    for test_id in sorted(
        {
            reference
            for item in parsed
            for reference in (item.test_id, *item.posix_equivalent)
        }
    ):
        _resolve_exact_test(test_id)
    return tuple(sorted(parsed, key=lambda item: item.invariant))


def run_group(
    cases: tuple[AdversarialCase, ...],
    group: str,
    *,
    stream: TextIO = sys.stderr,
) -> int:
    """Run one exact group and reject skips, omissions, or blocked evidence."""

    if group not in GROUPS:
        raise MatrixError("adversarial_group_unknown")
    selected = tuple(item for item in cases if item.group == group)
    if not selected:
        raise MatrixError("adversarial_group_empty")
    blocked = tuple(item for item in selected if item.blocking_issue is not None)
    active_ids = tuple(
        dict.fromkeys(item.test_id for item in selected if item.blocking_issue is None)
    )
    suite = unittest.TestSuite(_resolve_exact_test(test_id) for test_id in active_ids)
    runner = unittest.TextTestRunner(
        stream=stream,
        verbosity=2,
        resultclass=_RecordingResult,
    )
    result = runner.run(suite)
    if not isinstance(result, _RecordingResult):
        raise MatrixError("adversarial_result_contract_failed")

    expected = set(active_ids)
    missing = sorted(expected - result.started_ids)
    skipped = sorted(test.id() for test, _reason in result.skipped)
    stream.writelines(
        f"BLOCKED {item.invariant}: requires GitHub issue #{item.blocking_issue}\n"
        for item in blocked
    )
    if missing:
        stream.write(f"MISSING required tests: {', '.join(missing)}\n")
    if skipped:
        stream.write(f"SKIPPED required tests: {', '.join(skipped)}\n")
    if blocked or missing or skipped or not result.wasSuccessful():
        return 1
    return 0


def _parse_case(value: object) -> AdversarialCase:
    if not isinstance(value, dict):
        raise MatrixError("adversarial_matrix_case_not_object")
    allowed = {
        "invariant",
        "area",
        "group",
        "test_id",
        "expected_reason",
        "posix_equivalent",
        "blocking_issue",
    }
    required = {"invariant", "area", "group", "test_id", "expected_reason"}
    if not required <= set(value) or not set(value) <= allowed:
        raise MatrixError("adversarial_matrix_case_fields_invalid")
    invariant = value["invariant"]
    area = value["area"]
    group = value["group"]
    test_id = value["test_id"]
    reason = value["expected_reason"]
    if not isinstance(invariant, str) or not _INVARIANT_PATTERN.fullmatch(invariant):
        raise MatrixError("adversarial_matrix_invariant_invalid")
    if not isinstance(area, str) or invariant.split(".", 1)[0] != area:
        raise MatrixError("adversarial_matrix_area_invalid")
    if group not in GROUPS:
        raise MatrixError("adversarial_matrix_group_invalid")
    if not isinstance(test_id, str) or not _TEST_ID_PATTERN.fullmatch(test_id):
        raise MatrixError("adversarial_matrix_test_id_invalid")
    if not isinstance(reason, str) or not _REASON_PATTERN.fullmatch(reason):
        raise MatrixError("adversarial_matrix_reason_invalid")

    posix = value.get("posix_equivalent", [])
    if not isinstance(posix, list) or any(
        not isinstance(item, str) or not _TEST_ID_PATTERN.fullmatch(item)
        for item in posix
    ):
        raise MatrixError("adversarial_matrix_posix_reference_invalid")
    if len(set(posix)) != len(posix):
        raise MatrixError("adversarial_matrix_posix_reference_duplicate")
    blocking_issue = value.get("blocking_issue")
    if blocking_issue is not None and (
        isinstance(blocking_issue, bool)
        or not isinstance(blocking_issue, int)
        or blocking_issue <= 0
    ):
        raise MatrixError("adversarial_matrix_blocking_issue_invalid")
    return AdversarialCase(
        invariant=invariant,
        area=area,
        group=group,
        test_id=test_id,
        expected_reason=reason,
        posix_equivalent=tuple(posix),
        blocking_issue=blocking_issue,
    )


def _resolve_exact_test(test_id: str) -> unittest.TestCase:
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromName(test_id)
    if loader.errors or suite.countTestCases() != 1:
        raise MatrixError(f"adversarial_matrix_test_unresolvable:{test_id}")
    tests = tuple(_flatten_suite(suite))
    if len(tests) != 1 or tests[0].id() != test_id:
        raise MatrixError(f"adversarial_matrix_test_inexact:{test_id}")
    return tests[0]


def _flatten_suite(suite: unittest.TestSuite) -> tuple[unittest.TestCase, ...]:
    values: list[unittest.TestCase] = []
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            values.extend(_flatten_suite(item))
        elif isinstance(item, unittest.TestCase):
            values.append(item)
        else:
            raise MatrixError("adversarial_matrix_test_type_invalid")
    return tuple(values)


class _RecordingResult(unittest.TextTestResult):
    """Record exact started IDs so a loader omission cannot look successful."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.started_ids: set[str] = set()

    def startTest(self, test: unittest.TestCase) -> None:
        self.started_ids.add(test.id())
        super().startTest(test)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run exact, skip-intolerant Windows adversarial evidence."
    )
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    parser.add_argument("--group", choices=sorted(GROUPS))
    parser.add_argument("--validate-only", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if arguments.validate_only == (arguments.group is not None):
        _parser().error("select exactly one of --group or --validate-only")
    try:
        cases = load_matrix(arguments.matrix)
        if arguments.validate_only:
            print(f"validated {len(cases)} Windows adversarial invariants")
            return 0
        assert arguments.group is not None
        return run_group(cases, arguments.group)
    except MatrixError as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

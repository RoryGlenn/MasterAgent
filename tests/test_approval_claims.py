"""Adversarial approval-claim and revocation regressions."""

from __future__ import annotations

import json
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

from master_agent.approvals import ApprovalAuthority, HmacApprovalAuthenticator
from master_agent.cli import main
from master_agent.errors import ConfigurationError, ValidationError
from master_agent.models import (
    AgentAction,
    Approval,
    AuthoritySource,
    ChangePlan,
    ResourceRef,
    RiskLevel,
)
from master_agent.policy import PolicyConfig, PolicyEngine

ROOT = Path(__file__).resolve().parents[1]
SECRET = b"approval-claim-regression-secret-32-bytes"


class ApprovalClaimTests(unittest.TestCase):
    """Prove approval identity claims are authenticated and revocable."""

    def setUp(self) -> None:
        self.authority = ApprovalAuthority(
            key_id="alice-key",
            subject="Alice@example.test",
            issuer="master-agent.test",
            tenant="example-tenant",
            roles=("change-approver", "security-reviewer"),
            secret=SECRET,
        )
        self.authenticator = HmacApprovalAuthenticator(
            {self.authority.key_id: self.authority}
        )
        self.plan = _plan()
        self.now = datetime(2026, 8, 16, 12, tzinfo=UTC)

    def test_signed_claims_are_required_and_tampering_fails(self) -> None:
        approval = self._issue()

        self.assertEqual(approval.issuer, self.authority.issuer)
        self.assertEqual(approval.tenant, self.authority.tenant)
        self.assertEqual(approval.roles, self.authority.roles)
        self.assertEqual(
            self.authenticator.authenticated_subject(approval),
            "master-agent.test|example-tenant|alice@example.test",
        )

        for tampered in (
            replace(approval, approved_by="Mallory@example.test"),
            replace(approval, issuer="other-issuer.test"),
            replace(approval, tenant="other-tenant"),
            replace(approval, roles=("change-approver",)),
            replace(approval, signature="0" * 64),
        ):
            with self.subTest(tampered=tampered.to_dict()):
                self.assertIsNone(self.authenticator.authenticated_subject(tampered))

    def test_specific_and_time_based_revocation_fail_closed(self) -> None:
        approval_id = uuid4()
        approval = self._issue(approval_id=approval_id)

        specifically_revoked = HmacApprovalAuthenticator(
            {
                self.authority.key_id: replace(
                    self.authority,
                    revoked_approval_ids=frozenset({approval_id}),
                )
            }
        )
        time_revoked = HmacApprovalAuthenticator(
            {
                self.authority.key_id: replace(
                    self.authority,
                    revoked_before=self.now,
                )
            }
        )

        self.assertIsNone(specifically_revoked.authenticated_subject(approval))
        self.assertIsNone(time_revoked.authenticated_subject(approval))

    def test_unicode_and_case_aliases_do_not_satisfy_dual_approval(self) -> None:
        authorities = {
            "alice-ascii": replace(
                self.authority,
                key_id="alice-ascii",
                subject="Alice@example.test",
            ),
            "alice-fullwidth": replace(
                self.authority,
                key_id="alice-fullwidth",
                subject="Ａlice@example.test",
                secret=b"second-approval-claim-secret-32-bytes!!",
            ),
        }
        authenticator = HmacApprovalAuthenticator(authorities)
        approvals = tuple(
            authenticator.issue(
                plan=self.plan,
                approved_action_ids=(self.plan.actions[0].action_id,),
                key_id=key_id,
                issued_at=self.now,
                expires_at=self.now + timedelta(minutes=5),
            )
            for key_id in authorities
        )
        engine = PolicyEngine(
            PolicyConfig.from_toml(ROOT / "config/policy.toml"),
            approval_authenticator=authenticator,
        )

        decision = engine.evaluate(
            self.plan,
            self.plan.actions[0],
            approvals,
            now=self.now + timedelta(seconds=1),
            minimum_distinct_approvers=2,
        )

        self.assertFalse(decision.permitted)
        self.assertTrue(decision.approval_required)

    def test_whitespace_identity_aliases_are_rejected(self) -> None:
        with self.assertRaisesRegex(ConfigurationError, "normalized"):
            replace(self.authority, subject=" Alice@example.test")

        payload = self._issue().to_dict()
        payload["approved_by"] = "Alice@example.test "
        with self.assertRaisesRegex(ValidationError, "normalized"):
            Approval.from_dict(payload)

    def test_toml_requires_explicit_issuer_tenant_and_roles(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "authorities.toml"
            path.write_text(
                "[authorities.alice]\n"
                'subject = "alice@example.test"\n'
                'secret_env = "APPROVAL_TEST_SECRET"\n',
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ConfigurationError, "requires string field"):
                HmacApprovalAuthenticator.from_toml(
                    path,
                    environ={"APPROVAL_TEST_SECRET": "x" * 32},
                )

    def test_toml_revocation_controls_invalidate_matching_artifact(self) -> None:
        approval_id = uuid4()
        with TemporaryDirectory() as directory:
            path = Path(directory) / "authorities.toml"
            path.write_text(
                "[authorities.alice-key]\n"
                'subject = "Alice@example.test"\n'
                'issuer = "master-agent.test"\n'
                'tenant = "example-tenant"\n'
                'roles = ["change-approver", "security-reviewer"]\n'
                'secret_env = "APPROVAL_TEST_SECRET"\n'
                f'revoked_approval_ids = ["{approval_id}"]\n',
                encoding="utf-8",
            )
            authenticator = HmacApprovalAuthenticator.from_toml(
                path,
                environ={"APPROVAL_TEST_SECRET": SECRET.decode("ascii")},
            )
            approval = authenticator.issue(
                plan=self.plan,
                approved_action_ids=(self.plan.actions[0].action_id,),
                key_id="alice-key",
                issued_at=self.now,
                expires_at=self.now + timedelta(minutes=5),
                approval_id=approval_id,
            )

        self.assertIsNone(authenticator.authenticated_subject(approval))

    def test_artifact_without_authenticated_claims_is_rejected(self) -> None:
        payload = self._issue().to_dict()
        payload.pop("tenant")

        with self.assertRaisesRegex(ValidationError, "approval tenant"):
            Approval.from_dict(payload)

    def test_inspect_manifest_renders_every_effect_bearing_field(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            path.write_text(json.dumps(self.plan.to_dict()), encoding="utf-8")
            output = StringIO()
            with redirect_stdout(output):
                status = main(["inspect", str(path)])

        rendered = output.getvalue()
        self.assertEqual(status, 0)
        for expected in (
            self.plan.fingerprint,
            "outlook.email.send",
            "mailbox@example.test",
            '"expected_version": "draft-v7"',
            '"recipients"',
            "recipient@example.test",
            '"body": "Exact approved body"',
            '"authority_source": "direct_user"',
            "Send the exact reviewed message.",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, rendered)

    def _issue(self, *, approval_id=None):
        return self.authenticator.issue(
            plan=self.plan,
            approved_action_ids=(self.plan.actions[0].action_id,),
            key_id=self.authority.key_id,
            issued_at=self.now,
            expires_at=self.now + timedelta(minutes=5),
            approval_id=approval_id,
        )


def _plan() -> ChangePlan:
    action = AgentAction(
        capability="outlook.email.send",
        target=ResourceRef(
            system="outlook",
            resource_type="message",
            resource_id="mailbox@example.test",
            expected_version="draft-v7",
        ),
        parameters={
            "recipients": ["recipient@example.test"],
            "subject": "Exact approved subject",
            "body": "Exact approved body",
        },
        risk=RiskLevel.EXTERNAL_COMMUNICATION,
        authority_source=AuthoritySource.DIRECT_USER,
        requires_approval=True,
        idempotency_key="approval-claim-manifest",
        justification="Send the exact reviewed message.",
    )
    return ChangePlan(
        goal="Prove the complete approval manifest",
        actions=(action,),
        created_by="approval-claim-test",
    )


if __name__ == "__main__":
    unittest.main()

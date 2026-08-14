"""Approved SharePoint and OneDrive versioned file replacement."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from copy import deepcopy
from pathlib import Path
from typing import Any

from master_agent.config import ResolvedConnectorConfig
from master_agent.connectors.microsoft_graph import graph_client
from master_agent.connectors.utils import (
    enforce_expected_version,
    quote_segment,
    string_parameter,
)
from master_agent.errors import ConnectorError, VersionConflictError
from master_agent.http import HttpTransport
from master_agent.models import (
    ActionState,
    AgentAction,
    CompensationDescriptor,
    CompensationMode,
    ExecutionResult,
    ResourceRef,
    RiskLevel,
    VerificationResult,
)


class SharePointWriteConnector:
    """Replace an existing DriveItem and restore its prior version on rollback.

    Only files beneath ``artifact_root`` may be uploaded. The target must be an
    existing DriveItem with at least one provider version available before the
    write. The connector never creates arbitrary paths or uploads from outside
    the generated-artifact boundary.

    Parameters
    ----------
    config
        Resolved Microsoft Graph connector configuration.
    artifact_root
        Root containing files generated and approved for publication.
    transport
        Optional injectable HTTP transport.
    """

    _CAPABILITIES = frozenset({"sharepoint.file.upload"})

    def __init__(
        self,
        config: ResolvedConnectorConfig,
        *,
        artifact_root: Path,
        transport: HttpTransport | None = None,
    ) -> None:
        if config.max_pages < 12:
            raise ConnectorError(
                "SharePoint exact upload and rollback verification requires a "
                "request budget of at least 12"
            )
        try:
            configured_max_upload = int(config.extra.get("max_upload_bytes", 1_000_000))
        except (TypeError, ValueError) as error:
            raise ConnectorError(
                "SharePoint max_upload_bytes must be an integer"
            ) from error
        lifecycle_byte_limit = config.max_response_bytes // 6
        if configured_max_upload <= 0 or lifecycle_byte_limit <= 0:
            raise ConnectorError(
                "SharePoint upload and response limits must be positive"
            )
        root = artifact_root.expanduser().resolve()
        root.mkdir(parents=True, exist_ok=True)
        self._artifact_root = root
        self._config = config
        self._client = graph_client(
            config,
            transport=transport,
            allowed_methods=frozenset({"GET", "PUT", "POST"}),
        )
        self._last: dict[str, dict[str, Any]] = {}
        self._max_upload_bytes = min(configured_max_upload, lifecycle_byte_limit)

    @property
    def system(self) -> str:
        """Return connector system."""

        return "sharepoint"

    @property
    def capabilities(self) -> frozenset[str]:
        """Return supported capabilities."""

        return self._CAPABILITIES

    def execute(self, action: AgentAction) -> ExecutionResult:
        """Replace one existing file after an exact eTag precondition check."""

        self._validate(action)
        drive_id = string_parameter(action.parameters, "drive_id", required=True)
        item_id = action.target.resource_id
        local_path = self._local_path(action.parameters)
        content = local_path.read_bytes()
        approved_digest = str(action.parameters.get("local_sha256", "")).strip().lower()
        observed_digest = hashlib.sha256(content).hexdigest()
        if len(approved_digest) != 64 or approved_digest != observed_digest:
            raise ConnectorError(
                "SharePoint local artifact does not match approved local_sha256"
            )
        if len(content) > self._max_upload_bytes:
            raise ConnectorError(
                "SharePoint upload exceeds configured maximum of "
                f"{self._max_upload_bytes} bytes"
            )

        item_path = self._item_path(drive_id, item_id)
        before = self._read_metadata(item_path)
        enforce_expected_version(action, before.get("etag"))
        before_size = _integer_size(before.get("size"))
        before_content = self._read_content_evidence(item_path, before_size)
        if before_content.get("size") != before_size or not before_content.get(
            "sha256"
        ):
            raise ConnectorError(
                "SharePoint prior provider bytes could not be verified exactly"
            )
        retained_before = {
            **before,
            "content_size": before_size,
            "content_sha256": before_content["sha256"],
        }
        versions = self._read_versions(item_path)
        if not versions:
            raise ConnectorError(
                "SharePoint target has no restorable provider version; write rejected"
            )
        prior_version_id = str(versions[0].get("id", "")).strip()
        if not prior_version_id:
            raise ConnectorError("SharePoint version response omitted a version ID")

        response = self._client.request_bytes(
            "PUT",
            f"{item_path}/content",
            body=content,
            content_type=str(
                action.parameters.get("content_type", "application/octet-stream")
            ),
            safe_to_retry=False,
        )
        after = self._read_metadata(item_path)
        provider_content = self._read_content_evidence(item_path, len(content))
        if not _uploaded_item_matches(
            after,
            item_id=item_id,
            expected_size=len(content),
            expected_sha256=observed_digest,
            content_evidence=provider_content,
            prior_etag=before.get("etag"),
        ):
            raise ConnectorError(
                "SharePoint provider poststate did not match the approved bytes"
            )
        normalized = {
            **after,
            "drive_id": drive_id,
            "item_id": item_id,
            "uploaded_size": len(content),
            "uploaded_sha256": observed_digest,
            "provider_sha256": provider_content["sha256"],
            "source_name": local_path.name,
            "prior_version_id": prior_version_id,
        }
        self._last[item_id] = deepcopy(normalized)
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=retained_before,
            after=normalized,
            connector_reference=str(after.get("web_url") or response.url),
            message="SharePoint DriveItem replaced with an approved artifact",
            compensation=CompensationDescriptor(
                kind="restore_drive_item_version",
                mode=CompensationMode.IN_PROCESS,
                target_resource_id=item_id,
                reason=(
                    "provider-version restore is available only through the "
                    "originating connector run"
                ),
            ).to_dict(),
        )

    def read(self, resource: ResourceRef) -> dict[str, object] | None:
        """Return the most recent normalized state for a DriveItem."""

        value = self._last.get(resource.resource_id)
        return deepcopy(value) if value is not None else None

    def verify(
        self,
        action: AgentAction,
        result: ExecutionResult,
    ) -> VerificationResult:
        """Independently download and hash the approval-bound provider bytes."""

        drive_id = string_parameter(action.parameters, "drive_id", required=True)
        item_id = action.target.resource_id
        expected_sha256 = str(action.parameters.get("local_sha256", "")).lower()
        expected_size = _integer_size((result.after or {}).get("uploaded_size"))
        observed = self._read_content_evidence(
            self._item_path(drive_id, item_id),
            expected_size,
        )
        verified = bool(
            len(expected_sha256) == 64
            and expected_size >= 0
            and observed.get("size") == expected_size
            and observed.get("sha256") == expected_sha256
        )
        return VerificationResult(
            action_id=action.action_id,
            verified=verified,
            observed=observed,
            message=(
                "verified SharePoint replacement by independent exact-byte digest"
                if verified
                else "SharePoint provider bytes did not match the approved replacement"
            ),
        )

    def compensate(
        self,
        action: AgentAction,
        result: ExecutionResult,
    ) -> ExecutionResult:
        """Restore the provider version that existed before the upload."""

        after = result.after or {}
        drive_id = str(after.get("drive_id", "")).strip()
        item_id = str(after.get("item_id", action.target.resource_id)).strip()
        version_id = str(after.get("prior_version_id", "")).strip()
        if not drive_id or not item_id or not version_id:
            raise ConnectorError("SharePoint rollback metadata is incomplete")
        item_path = self._item_path(drive_id, item_id)
        current = self._read_metadata(item_path)
        if current.get("etag") != after.get("etag"):
            raise VersionConflictError(
                "SharePoint item changed after upload; version restore is refused"
            )
        response = self._client.request_bytes(
            "POST",
            f"{item_path}/versions/{quote_segment(version_id)}/restoreVersion",
            safe_to_retry=False,
            accepted_statuses=frozenset({200, 202, 204}),
        )
        restored = self._read_metadata(item_path)
        original_before = result.before or {}
        prior_size = _integer_size(original_before.get("content_size"))
        prior_sha256 = str(original_before.get("content_sha256", ""))
        restored_content = self._read_content_evidence(item_path, prior_size)
        if not _restored_item_matches(
            restored,
            item_id=item_id,
            expected_size=prior_size,
            expected_sha256=prior_sha256,
            content_evidence=restored_content,
            uploaded_etag=after.get("etag"),
        ):
            raise ConnectorError(
                "SharePoint restored provider version did not match prior bytes"
            )
        compensation = ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=current,
            after={
                **restored,
                "drive_id": drive_id,
                "item_id": item_id,
                "restored_version_id": version_id,
                "restored_size": prior_size,
                "restored_sha256": restored_content["sha256"],
            },
            connector_reference=str(restored.get("web_url") or response.url),
            message="restored the prior SharePoint DriveItem version",
        )
        self._last[item_id] = deepcopy(dict(compensation.after or {}))
        return compensation

    def verify_compensation(
        self,
        action: AgentAction,
        original: ExecutionResult,
        compensation: ExecutionResult,
    ) -> VerificationResult:
        """Independently download and hash the retained pre-write bytes."""

        drive_id = string_parameter(action.parameters, "drive_id", required=True)
        item_id = action.target.resource_id
        before = original.before or {}
        expected_size = _integer_size(before.get("content_size"))
        expected_sha256 = str(before.get("content_sha256", ""))
        observed = self._read_content_evidence(
            self._item_path(drive_id, item_id),
            expected_size,
        )
        verified = bool(
            len(expected_sha256) == 64
            and observed.get("size") == expected_size
            and observed.get("sha256") == expected_sha256
        )
        return VerificationResult(
            action_id=action.action_id,
            verified=verified,
            observed=observed,
            message=(
                "verified restored SharePoint bytes by independent digest"
                if verified
                else "restored SharePoint bytes did not match the prior version"
            ),
        )

    def _local_path(self, parameters: Mapping[str, Any]) -> Path:
        value = string_parameter(parameters, "local_path", required=True)
        path = Path(value).expanduser().resolve()
        try:
            path.relative_to(self._artifact_root)
        except ValueError as error:
            raise ConnectorError(
                "local_path is outside the approved artifact root"
            ) from error
        if not path.is_file():
            raise ConnectorError("SharePoint local_path is not a file")
        return path

    def _read_metadata(self, item_path: str) -> dict[str, Any]:
        data, response = self._client.request_json("GET", item_path)
        if not isinstance(data, Mapping):
            raise ConnectorError("SharePoint DriveItem metadata must be an object")
        return {
            "id": str(data.get("id", "")),
            "name": str(data.get("name", "")),
            "size": data.get("size"),
            "etag": data.get("eTag") or data.get("@odata.etag"),
            "ctag": data.get("cTag"),
            "last_modified": data.get("lastModifiedDateTime"),
            "web_url": data.get("webUrl"),
            "reference": response.url,
        }

    def _read_versions(self, item_path: str) -> list[Mapping[str, Any]]:
        data, _ = self._client.request_json("GET", f"{item_path}/versions")
        if not isinstance(data, Mapping) or not isinstance(data.get("value"), list):
            raise ConnectorError(
                "SharePoint versions response must contain a value list"
            )
        return [item for item in data["value"] if isinstance(item, Mapping)]

    def _read_content_evidence(
        self,
        item_path: str,
        expected_size: int,
    ) -> dict[str, object]:
        """Download bounded provider bytes and return non-content evidence."""

        if expected_size < 0 or expected_size > self._max_upload_bytes:
            raise ConnectorError("SharePoint expected content size is outside limits")
        response = self._client.request_bytes(
            "GET",
            f"{item_path}/content",
            max_response_bytes=max(expected_size, 1),
        )
        return {
            "size": len(response.body),
            "sha256": hashlib.sha256(response.body).hexdigest(),
            "reference": response.url,
        }

    def _validate(self, action: AgentAction) -> None:
        if action.target.system != self.system:
            raise ConnectorError("SharePoint write connector received another system")
        if action.capability not in self.capabilities:
            raise ConnectorError(
                f"unsupported SharePoint write capability: {action.capability}"
            )
        if action.risk is not RiskLevel.REVERSIBLE_WRITE:
            raise ConnectorError(
                "SharePoint replacement must use reversible_write risk"
            )
        if not action.requires_approval:
            raise ConnectorError("SharePoint replacement requires explicit approval")

    @staticmethod
    def _item_path(drive_id: str, item_id: str) -> str:
        return f"drives/{quote_segment(drive_id)}/items/{quote_segment(item_id)}"


def _uploaded_item_matches(
    metadata: Mapping[str, Any],
    *,
    item_id: str,
    expected_size: int,
    expected_sha256: str,
    content_evidence: Mapping[str, object],
    prior_etag: object,
) -> bool:
    """Match provider identity, version metadata, and exact remote bytes."""

    return bool(
        metadata.get("id") == item_id
        and _integer_size(metadata.get("size")) == expected_size
        and metadata.get("etag")
        and metadata.get("etag") != prior_etag
        and content_evidence.get("size") == expected_size
        and content_evidence.get("sha256") == expected_sha256
    )


def _restored_item_matches(
    metadata: Mapping[str, Any],
    *,
    item_id: str,
    expected_size: int,
    expected_sha256: str,
    content_evidence: Mapping[str, object],
    uploaded_etag: object,
) -> bool:
    """Require the restored item to equal the retained pre-write bytes."""

    return bool(
        len(expected_sha256) == 64
        and metadata.get("id") == item_id
        and _integer_size(metadata.get("size")) == expected_size
        and metadata.get("etag")
        and metadata.get("etag") != uploaded_etag
        and content_evidence.get("size") == expected_size
        and content_evidence.get("sha256") == expected_sha256
    )


def _integer_size(value: object) -> int:
    """Return an exact non-boolean integer size or a fail-closed sentinel."""

    return value if isinstance(value, int) and not isinstance(value, bool) else -1

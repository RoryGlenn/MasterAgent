"""Approved SharePoint and OneDrive versioned file replacement."""

from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
from typing import Any, Mapping

from master_agent.config import ResolvedConnectorConfig
from master_agent.connectors.microsoft_graph import graph_client
from master_agent.connectors.utils import enforce_expected_version, quote_segment, string_parameter
from master_agent.errors import ConnectorError
from master_agent.http import HttpTransport
from master_agent.models import (
    ActionState,
    AgentAction,
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
        self._max_upload_bytes = int(
            config.extra.get("max_upload_bytes", 10 * 1024 * 1024)
        )

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
        if len(content) > self._max_upload_bytes:
            raise ConnectorError(
                "SharePoint upload exceeds configured maximum of "
                f"{self._max_upload_bytes} bytes"
            )

        item_path = self._item_path(drive_id, item_id)
        before = self._read_metadata(item_path)
        enforce_expected_version(action, before.get("etag"))
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
        if int(after.get("size") or -1) != len(content):
            raise ConnectorError("SharePoint provider did not report the uploaded size")
        normalized = {
            **after,
            "drive_id": drive_id,
            "item_id": item_id,
            "uploaded_size": len(content),
            "uploaded_sha256": hashlib.sha256(content).hexdigest(),
            "source_name": local_path.name,
            "prior_version_id": prior_version_id,
        }
        self._last[item_id] = deepcopy(normalized)
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=before,
            after=normalized,
            connector_reference=str(after.get("web_url") or response.url),
            message="SharePoint DriveItem replaced with an approved artifact",
            compensation={
                "kind": "restore_drive_item_version",
                "drive_id": drive_id,
                "item_id": item_id,
                "version_id": prior_version_id,
            },
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
        """Independently verify item identity, size, and changed eTag."""

        after = result.after or {}
        drive_id = str(after.get("drive_id", ""))
        item_id = str(after.get("item_id", action.target.resource_id))
        observed = self._read_metadata(self._item_path(drive_id, item_id))
        before = result.before or {}
        expected_size = int(after.get("uploaded_size") or -1)
        verified = bool(
            observed.get("id") == item_id
            and int(observed.get("size") or -2) == expected_size
            and observed.get("etag")
            and observed.get("etag") != before.get("etag")
        )
        return VerificationResult(
            action_id=action.action_id,
            verified=verified,
            observed=observed,
            message=(
                "verified SharePoint replacement by independent metadata re-read"
                if verified
                else "SharePoint metadata did not match the approved replacement"
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
        response = self._client.request_bytes(
            "POST",
            f"{item_path}/versions/{quote_segment(version_id)}/restoreVersion",
            safe_to_retry=False,
            accepted_statuses=frozenset({200, 202, 204}),
        )
        restored = self._read_metadata(item_path)
        compensation = ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=current,
            after={
                **restored,
                "drive_id": drive_id,
                "item_id": item_id,
                "restored_version_id": version_id,
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
        """Verify the restored item differs from the uploaded version."""

        after = compensation.after or {}
        drive_id = str(after.get("drive_id", ""))
        item_id = str(after.get("item_id", action.target.resource_id))
        observed = self._read_metadata(self._item_path(drive_id, item_id))
        uploaded = original.after or {}
        before = original.before or {}
        verified = bool(
            observed.get("id") == item_id
            and observed.get("etag")
            and observed.get("etag") != uploaded.get("etag")
            and (
                before.get("size") is None
                or int(observed.get("size") or -1) == int(before.get("size") or -2)
            )
        )
        return VerificationResult(
            action_id=action.action_id,
            verified=verified,
            observed=observed,
            message=(
                "verified restored SharePoint provider version"
                if verified
                else "restored SharePoint state did not match the prior version"
            ),
        )

    def _local_path(self, parameters: Mapping[str, Any]) -> Path:
        value = string_parameter(parameters, "local_path", required=True)
        path = Path(value).expanduser().resolve()
        try:
            path.relative_to(self._artifact_root)
        except ValueError as error:
            raise ConnectorError("local_path is outside the approved artifact root") from error
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
            raise ConnectorError("SharePoint versions response must contain a value list")
        return [item for item in data["value"] if isinstance(item, Mapping)]

    def _validate(self, action: AgentAction) -> None:
        if action.target.system != self.system:
            raise ConnectorError("SharePoint write connector received another system")
        if action.capability not in self.capabilities:
            raise ConnectorError(
                f"unsupported SharePoint write capability: {action.capability}"
            )
        if action.risk is not RiskLevel.REVERSIBLE_WRITE:
            raise ConnectorError("SharePoint replacement must use reversible_write risk")
        if not action.requires_approval:
            raise ConnectorError("SharePoint replacement requires explicit approval")

    @staticmethod
    def _item_path(drive_id: str, item_id: str) -> str:
        return (
            f"drives/{quote_segment(drive_id)}/items/{quote_segment(item_id)}"
        )

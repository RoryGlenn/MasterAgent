"""Read-only Microsoft Graph identity and SharePoint connectors."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any, Mapping

from master_agent.config import ResolvedConnectorConfig
from master_agent.connectors.microsoft_graph import graph_client, graph_paged_values
from master_agent.connectors.read_only import ReadOnlyConnector, RetrievedPayload
from master_agent.connectors.utils import (
    enforce_expected_version,
    integer_parameter,
    quote_segment,
    safe_graph_resource_id,
    string_list_parameter,
    string_parameter,
)
from master_agent.errors import ConnectorError
from master_agent.http import (
    HttpTransport,
    SafeHttpClient,
    download_public_https,
)
from master_agent.models import AgentAction
from master_agent.text import excerpt


class MicrosoftIdentityConnector(ReadOnlyConnector):
    """Resolve signed-in or explicitly addressed Microsoft Entra identities."""

    _CAPABILITIES = frozenset({"microsoft.identity.read", "microsoft.identity.search"})

    def __init__(
        self,
        config: ResolvedConnectorConfig,
        *,
        transport: HttpTransport | None = None,
    ) -> None:
        super().__init__(system="microsoft", capabilities=self._CAPABILITIES)
        self._config = config
        self._client = graph_client(config, transport=transport)

    def probe(self) -> Mapping[str, Any]:
        """Verify Graph identity access."""

        identity = str(self._config.extra.get("default_identity", "me"))
        user, reference = self._read_identity(identity, ())
        return {
            "reachable": True,
            "identity_id": user.get("id"),
            "display_name": user.get("display_name"),
            "reference": reference,
        }

    def _fetch(self, action: AgentAction) -> RetrievedPayload:
        if action.capability == "microsoft.identity.search":
            return self._search_identities(action)
        identity = action.target.resource_id or str(
            self._config.extra.get("default_identity", "me")
        )
        fields = string_list_parameter(
            action.parameters,
            "fields",
            default=(
                "id",
                "displayName",
                "givenName",
                "surname",
                "mail",
                "userPrincipalName",
                "jobTitle",
                "department",
                "companyName",
                "officeLocation",
                "employeeId",
                "accountEnabled",
                "userType",
            ),
        )
        user, reference = self._read_identity(identity, fields)
        return RetrievedPayload(
            data={
                "schema": "master-agent/microsoft-identity@1",
                "system": "microsoft",
                "identity": user,
                "retention": {
                    "evidence_type": "microsoft.identity.metadata",
                    "content_kind": "directory_metadata",
                },
                "source_urls": [reference],
            },
            connector_reference=reference,
        )

    def _search_identities(self, action: AgentAction) -> RetrievedPayload:
        query_text = string_parameter(action.parameters, "query", required=True)
        query_text = " ".join(query_text.split())
        if len(query_text) > 200:
            raise ConnectorError("Microsoft identity query exceeds 200 characters")
        escaped = query_text.replace("\\", "\\\\").replace('"', '\\"')
        graph_search = f'"displayName:{escaped}"'
        limit = integer_parameter(
            action.parameters,
            "limit",
            default=25,
            maximum=min(self._config.max_items, 100),
        )
        fields = string_list_parameter(
            action.parameters,
            "fields",
            default=(
                "id",
                "displayName",
                "givenName",
                "surname",
                "mail",
                "userPrincipalName",
                "jobTitle",
                "department",
                "companyName",
                "officeLocation",
                "employeeId",
                "accountEnabled",
                "userType",
            ),
        )
        users, reference = graph_paged_values(
            self._client,
            config=self._config,
            path="users",
            query={
                "$search": graph_search,
                "$orderby": "displayName",
                "$count": "true",
                "$select": ",".join(fields),
                "$top": min(limit, 100),
            },
            limit=limit,
            normalizer=_normalize_user,
            headers={"ConsistencyLevel": "eventual"},
        )
        return RetrievedPayload(
            data={
                "schema": "master-agent/microsoft-identities@1",
                "system": "microsoft",
                "query": {
                    "free_text": query_text,
                    "graph_search": graph_search,
                },
                "returned": len(users),
                "users": users,
                "retention": {
                    "evidence_type": "microsoft.identity.metadata",
                    "content_kind": "directory_metadata",
                },
                "source_urls": [reference],
            },
            connector_reference=reference,
        )

    def _read_identity(
        self,
        identity: str,
        fields: tuple[str, ...],
    ) -> tuple[dict[str, Any], str]:
        identity_mode = str(
            self._config.extra.get("identity_mode", "delegated")
        ).lower()
        if identity == "me":
            if identity_mode != "delegated":
                raise ConnectorError(
                    "Microsoft Graph /me requires delegated identity mode; "
                    "configure an explicit user ID for app-only access"
                )
            path = "me"
        else:
            path = f"users/{quote_segment(identity)}"
        query = {"$select": ",".join(fields)} if fields else None
        data, response = self._client.request_json("GET", path, query=query)
        if not isinstance(data, Mapping):
            raise ConnectorError("Microsoft Graph user response must be an object")
        return _normalize_user(data), response.url


class SharePointConnector(ReadOnlyConnector):
    """Search SharePoint sites and inspect document libraries through Graph."""

    _CAPABILITIES = frozenset(
        {
            "sharepoint.site.search",
            "sharepoint.site.read",
            "sharepoint.drive.list",
            "sharepoint.drive.children",
            "sharepoint.file.metadata.read",
            "sharepoint.file.text.read",
        }
    )

    def __init__(
        self,
        config: ResolvedConnectorConfig,
        *,
        transport: HttpTransport | None = None,
    ) -> None:
        super().__init__(system="sharepoint", capabilities=self._CAPABILITIES)
        self._config = config
        self._transport = transport
        self._client = graph_client(config, transport=transport)

    def probe(self) -> Mapping[str, Any]:
        """Verify SharePoint site access using the tenant root site."""

        data, response = self._client.request_json("GET", "sites/root")
        if not isinstance(data, Mapping):
            raise ConnectorError("Microsoft Graph site response must be an object")
        return {
            "reachable": True,
            "site_id": data.get("id"),
            "display_name": data.get("displayName"),
            "web_url": data.get("webUrl"),
            "reference": response.url,
        }

    def _fetch(self, action: AgentAction) -> RetrievedPayload:
        capability = action.capability
        if capability == "sharepoint.site.search":
            return self._search_sites(action)
        if capability == "sharepoint.site.read":
            return self._read_site(action)
        if capability == "sharepoint.drive.list":
            return self._list_drives(action)
        if capability == "sharepoint.drive.children":
            return self._list_children(action)
        if capability == "sharepoint.file.metadata.read":
            return self._read_file_metadata(action)
        if capability == "sharepoint.file.text.read":
            return self._read_text_file(action)
        raise ConnectorError(f"unsupported SharePoint capability: {capability}")

    def _search_sites(self, action: AgentAction) -> RetrievedPayload:
        query_text = string_parameter(action.parameters, "query", required=True)
        limit = integer_parameter(
            action.parameters,
            "limit",
            default=25,
            maximum=self._config.max_items,
        )
        sites, reference = self._paged_values(
            "sites",
            query={
                "search": query_text,
                "$select": "id,name,displayName,description,webUrl,createdDateTime,lastModifiedDateTime",
                "$top": min(limit, 100),
            },
            limit=limit,
            normalizer=_normalize_site,
        )
        return RetrievedPayload(
            data={
                "schema": "master-agent/sharepoint-sites@1",
                "system": "sharepoint",
                "query": {"search": query_text},
                "returned": len(sites),
                "sites": sites,
                "source_urls": [
                    reference,
                    *[
                        str(site["web_url"])
                        for site in sites
                        if site.get("web_url")
                    ],
                ],
            },
            connector_reference=reference,
        )

    def _read_site(self, action: AgentAction) -> RetrievedPayload:
        site_id = safe_graph_resource_id(action.target.resource_id)
        data, response = self._client.request_json("GET", f"sites/{site_id}")
        if not isinstance(data, Mapping):
            raise ConnectorError("Microsoft Graph site response must be an object")
        site = _normalize_site(data)
        enforce_expected_version(action, site.get("updated_at"))
        return RetrievedPayload(
            data={
                "schema": "master-agent/sharepoint-site@1",
                "system": "sharepoint",
                "site": site,
                "source_urls": [response.url, site.get("web_url")],
            },
            connector_reference=response.url,
        )

    def _list_drives(self, action: AgentAction) -> RetrievedPayload:
        site_id = safe_graph_resource_id(
            string_parameter(
                action.parameters,
                "site_id",
                default=action.target.resource_id,
                required=True,
            )
        )
        limit = integer_parameter(
            action.parameters,
            "limit",
            default=100,
            maximum=self._config.max_items,
        )
        drives, reference = self._paged_values(
            f"sites/{site_id}/drives",
            query={
                "$select": "id,name,description,driveType,webUrl,createdDateTime,lastModifiedDateTime,quota",
                "$top": min(limit, 100),
            },
            limit=limit,
            normalizer=_normalize_drive,
        )
        return RetrievedPayload(
            data={
                "schema": "master-agent/sharepoint-drives@1",
                "system": "sharepoint",
                "site_id": site_id,
                "returned": len(drives),
                "drives": drives,
                "source_urls": [
                    reference,
                    *[
                        str(drive["web_url"])
                        for drive in drives
                        if drive.get("web_url")
                    ],
                ],
            },
            connector_reference=reference,
        )

    def _list_children(self, action: AgentAction) -> RetrievedPayload:
        drive_id = quote_segment(
            string_parameter(action.parameters, "drive_id", required=True)
        )
        item_id = string_parameter(
            action.parameters,
            "item_id",
            default=action.target.resource_id,
        )
        limit = integer_parameter(
            action.parameters,
            "limit",
            default=100,
            maximum=self._config.max_items,
        )
        if not item_id or item_id == "root":
            path = f"drives/{drive_id}/root/children"
        else:
            path = (
                f"drives/{drive_id}/items/{quote_segment(item_id)}/children"
            )
        items, reference = self._paged_values(
            path,
            query={"$top": min(limit, 200)},
            limit=limit,
            normalizer=_normalize_drive_item,
        )
        return RetrievedPayload(
            data={
                "schema": "master-agent/sharepoint-drive-items@1",
                "system": "sharepoint",
                "drive_id": drive_id,
                "parent_item_id": item_id or "root",
                "returned": len(items),
                "items": items,
                "source_urls": [
                    reference,
                    *[
                        str(item["web_url"])
                        for item in items
                        if item.get("web_url")
                    ],
                ],
            },
            connector_reference=reference,
        )

    def _read_file_metadata(self, action: AgentAction) -> RetrievedPayload:
        metadata, reference = self._file_metadata(action)
        enforce_expected_version(
            action,
            metadata.get("etag") or metadata.get("updated_at"),
        )
        return RetrievedPayload(
            data={
                "schema": "master-agent/sharepoint-file-metadata@1",
                "system": "sharepoint",
                "file": metadata,
                "source_urls": [reference, metadata.get("web_url")],
            },
            connector_reference=reference,
        )

    def _read_text_file(self, action: AgentAction) -> RetrievedPayload:
        metadata, reference = self._file_metadata(action, include_download_url=True)
        name = str(metadata.get("name", ""))
        extension = PurePosixPath(name).suffix.lower()
        allowed_extensions = tuple(
            str(item).lower()
            for item in self._config.extra.get(
                "allowed_text_extensions",
                [".txt", ".md", ".json", ".csv", ".yaml", ".yml", ".log"],
            )
        )
        if extension not in allowed_extensions:
            raise ConnectorError(
                f"SharePoint text read rejected unsupported extension: {extension}"
            )
        max_bytes = integer_parameter(
            action.parameters,
            "max_bytes",
            default=int(self._config.extra.get("max_text_file_bytes", 1_000_000)),
            maximum=min(self._config.max_response_bytes, 5_000_000),
        )
        size = metadata.get("size")
        if isinstance(size, int) and size > max_bytes:
            raise ConnectorError(
                f"SharePoint file size {size} exceeds text-read limit {max_bytes}"
            )
        download_url = metadata.pop("download_url", None)
        if not isinstance(download_url, str) or not download_url:
            raise ConnectorError(
                "Microsoft Graph did not return a temporary file download URL"
            )
        suffixes = tuple(
            str(item)
            for item in self._config.extra.get(
                "download_host_suffixes",
                [".sharepoint.com", ".1drv.com"],
            )
        )
        response = download_public_https(
            download_url,
            allowed_host_suffixes=suffixes,
            transport=self._transport,
            timeout_seconds=self._config.timeout_seconds,
            max_response_bytes=max_bytes,
        )
        try:
            content = response.body.decode("utf-8-sig")
        except UnicodeDecodeError as error:
            raise ConnectorError(
                "SharePoint text file is not valid UTF-8"
            ) from error
        return RetrievedPayload(
            data={
                "schema": "master-agent/sharepoint-text-file@1",
                "system": "sharepoint",
                "file": metadata,
                "content": content,
                "content_excerpt": excerpt(content, limit=1000),
                "source_urls": [reference, metadata.get("web_url")],
            },
            connector_reference=reference,
        )

    def _file_metadata(
        self,
        action: AgentAction,
        *,
        include_download_url: bool = False,
    ) -> tuple[dict[str, Any], str]:
        drive_id = quote_segment(
            string_parameter(action.parameters, "drive_id", required=True)
        )
        item_id = quote_segment(action.target.resource_id)
        data, response = self._client.request_json(
            "GET",
            f"drives/{drive_id}/items/{item_id}",
        )
        if not isinstance(data, Mapping):
            raise ConnectorError("Microsoft Graph drive item response must be an object")
        metadata = _normalize_drive_item(data)
        if include_download_url:
            metadata["download_url"] = data.get("@microsoft.graph.downloadUrl")
        return metadata, response.url

    def _paged_values(
        self,
        path: str,
        *,
        query: Mapping[str, Any] | None,
        limit: int,
        normalizer: Any,
    ) -> tuple[list[dict[str, Any]], str]:
        values: list[dict[str, Any]] = []
        next_url: str | None = None
        reference = ""
        for _ in range(self._config.max_pages):
            if len(values) >= limit:
                break
            if next_url:
                data, response = self._client.request_json("GET", next_url)
            else:
                data, response = self._client.request_json(
                    "GET",
                    path,
                    query=query,
                )
            reference = response.url
            if not isinstance(data, Mapping):
                raise ConnectorError("Microsoft Graph collection must be an object")
            page = data.get("value", [])
            if not isinstance(page, list):
                raise ConnectorError("Microsoft Graph value must be a list")
            mapped = [item for item in page if isinstance(item, Mapping)]
            values.extend(normalizer(item) for item in mapped)
            next_value = data.get("@odata.nextLink")
            next_url = str(next_value) if next_value else None
            if not mapped or not next_url:
                break
        return values[:limit], reference



def _normalize_user(user: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": user.get("id"),
        "display_name": user.get("displayName"),
        "given_name": user.get("givenName"),
        "surname": user.get("surname"),
        "mail": user.get("mail"),
        "user_principal_name": user.get("userPrincipalName"),
        "job_title": user.get("jobTitle"),
        "department": user.get("department"),
        "company_name": user.get("companyName"),
        "office_location": user.get("officeLocation"),
        "employee_id": user.get("employeeId"),
        "account_enabled": user.get("accountEnabled"),
        "user_type": user.get("userType"),
    }


def _normalize_site(site: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": site.get("id"),
        "name": site.get("name"),
        "display_name": site.get("displayName"),
        "description": site.get("description"),
        "web_url": site.get("webUrl"),
        "created_at": site.get("createdDateTime"),
        "updated_at": site.get("lastModifiedDateTime"),
    }


def _normalize_drive(drive: Mapping[str, Any]) -> dict[str, Any]:
    quota = drive.get("quota")
    quota = quota if isinstance(quota, Mapping) else {}
    return {
        "id": drive.get("id"),
        "name": drive.get("name"),
        "description": drive.get("description"),
        "drive_type": drive.get("driveType"),
        "web_url": drive.get("webUrl"),
        "created_at": drive.get("createdDateTime"),
        "updated_at": drive.get("lastModifiedDateTime"),
        "quota": {
            "total": quota.get("total"),
            "used": quota.get("used"),
            "remaining": quota.get("remaining"),
        },
    }


def _normalize_drive_item(item: Mapping[str, Any]) -> dict[str, Any]:
    file_facet = item.get("file")
    file_facet = file_facet if isinstance(file_facet, Mapping) else {}
    folder_facet = item.get("folder")
    folder_facet = folder_facet if isinstance(folder_facet, Mapping) else {}
    hashes = file_facet.get("hashes")
    hashes = hashes if isinstance(hashes, Mapping) else {}
    return {
        "id": item.get("id"),
        "name": item.get("name"),
        "size": item.get("size"),
        "web_url": item.get("webUrl"),
        "created_at": item.get("createdDateTime"),
        "updated_at": item.get("lastModifiedDateTime"),
        "etag": item.get("eTag"),
        "ctag": item.get("cTag"),
        "is_file": bool(file_facet),
        "is_folder": bool(folder_facet),
        "mime_type": file_facet.get("mimeType"),
        "sha1_hash": hashes.get("sha1Hash"),
        "quick_xor_hash": hashes.get("quickXorHash"),
        "child_count": folder_facet.get("childCount"),
    }

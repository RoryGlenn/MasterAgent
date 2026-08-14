"""Read-only connector for cross-system employee identity mappings."""

from __future__ import annotations

from typing import Any, Mapping

from master_agent.connectors.read_only import ReadOnlyConnector, RetrievedPayload
from master_agent.connectors.utils import integer_parameter, string_parameter
from master_agent.errors import ConnectorError
from master_agent.identity import IdentityRegistry, PersonIdentity
from master_agent.models import AgentAction


class IdentityMapConnector(ReadOnlyConnector):
    """Resolve configured people into system-specific identifiers."""

    _CAPABILITIES = frozenset(
        {
            "identity.person.list",
            "identity.person.resolve",
            "identity.identifier.resolve",
        }
    )

    def __init__(self, registry: IdentityRegistry) -> None:
        super().__init__(system="identity", capabilities=self._CAPABILITIES)
        self._registry = registry

    def probe(self) -> Mapping[str, Any]:
        """Return an audit-safe local registry summary."""

        return {
            "reachable": True,
            "people": len(self._registry.people),
            "configured_systems": sorted(
                {
                    system
                    for person in self._registry.people.values()
                    for system in person.identifiers
                }
            ),
        }

    def _fetch(self, action: AgentAction) -> RetrievedPayload:
        if action.capability == "identity.person.list":
            return self._list_people(action)
        if action.capability == "identity.person.resolve":
            return self._resolve_person(action)
        if action.capability == "identity.identifier.resolve":
            return self._resolve_identifier(action)
        raise ConnectorError(f"unsupported identity capability: {action.capability}")

    def _list_people(self, action: AgentAction) -> RetrievedPayload:
        limit = integer_parameter(
            action.parameters,
            "limit",
            default=100,
            maximum=1000,
        )
        people = [
            _normalize_person(person)
            for _, person in sorted(self._registry.people.items())
        ][:limit]
        return RetrievedPayload(
            data={
                "schema": "master-agent/identity-people@1",
                "system": "identity",
                "returned": len(people),
                "people": people,
                "retention": {
                    "evidence_type": "identity.mapping.metadata",
                    "content_kind": "directory_metadata",
                },
                "source_urls": [],
            },
            connector_reference="identity://registry",
        )

    def _resolve_person(self, action: AgentAction) -> RetrievedPayload:
        query = string_parameter(
            action.parameters,
            "query",
            default=action.target.resource_id,
            required=True,
        )
        person = self._registry.resolve(query)
        return RetrievedPayload(
            data={
                "schema": "master-agent/identity-person@1",
                "system": "identity",
                "query": query,
                "person": _normalize_person(person),
                "retention": {
                    "evidence_type": "identity.mapping.metadata",
                    "content_kind": "directory_metadata",
                },
                "source_urls": [],
            },
            connector_reference=f"identity://person/{person.key}",
        )

    def _resolve_identifier(self, action: AgentAction) -> RetrievedPayload:
        query = string_parameter(
            action.parameters,
            "query",
            default=action.target.resource_id,
            required=True,
        )
        target_system = string_parameter(
            action.parameters,
            "target_system",
            required=True,
        )
        person = self._registry.resolve(query)
        identifier = person.identifier(target_system)
        if identifier is None:
            raise ConnectorError(
                f"identity {person.key} has no configured {target_system} identifier"
            )
        return RetrievedPayload(
            data={
                "schema": "master-agent/identity-identifier@1",
                "system": "identity",
                "query": query,
                "target_system": target_system,
                "identifier": identifier,
                "person": _normalize_person(person),
                "retention": {
                    "evidence_type": "identity.mapping.metadata",
                    "content_kind": "directory_metadata",
                },
                "source_urls": [],
            },
            connector_reference=f"identity://person/{person.key}/{target_system}",
        )


def _normalize_person(person: PersonIdentity) -> dict[str, Any]:
    return {
        "id": person.key,
        "key": person.key,
        "display_name": person.display_name,
        "aliases": list(person.aliases),
        "identifiers": dict(person.identifiers),
    }

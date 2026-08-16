"""Policy-first intent routing and exact active capability sessions."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any

from master_agent.capsules import CapsuleManifest, CapsuleState
from master_agent.errors import ConfigurationError, ValidationError
from master_agent.models import DataClassification, RiskLevel
from master_agent.resource_limits import measure_json_resources

_TOKEN = re.compile(r"[a-z0-9]+")
_NEGATION_UNIT = re.compile(r"[a-z0-9]+|[,.;:!?]+")
_CAPABILITY_ID = re.compile(r"[a-z][a-z0-9]*(?:[._-][a-z0-9][a-z0-9_-]*)+")
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?")
_NEGATORS = frozenset({"avoid", "dont", "never", "no", "not", "without"})
_NEGATION_BREAKERS = frozenset(
    {"although", "but", "except", "however", "instead", "then", "though", "yet"}
)
_NEGATION_MODIFIERS = frozenset(
    {
        "accidentally",
        "actually",
        "any",
        "at",
        "automatically",
        "directly",
        "ever",
        "even",
        "immediately",
        "intentionally",
        "just",
        "only",
        "permanently",
        "please",
        "possibly",
        "really",
        "simply",
        "still",
        "to",
        "under",
    }
)
_MAX_NEGATION_SCOPE_TOKENS = 12
_READ_TERMS = frozenset({"find", "get", "inspect", "list", "read", "search", "show"})
_WRITE_TERMS = frozenset(
    {
        "add",
        "admin",
        "archive",
        "create",
        "delete",
        "edit",
        "merge",
        "move",
        "publish",
        "remove",
        "send",
        "update",
        "write",
    }
)


@dataclass(frozen=True, slots=True)
class CapabilityCard:
    """Compact immutable routing facts for one promoted capability."""

    capability_id: str
    version: str
    manifest_sha256: str
    risk: RiskLevel
    intents: tuple[str, ...]
    negative_intents: tuple[str, ...]
    data_classification: DataClassification

    @classmethod
    def from_manifest(cls, manifest: CapsuleManifest) -> CapabilityCard:
        if manifest.state is not CapsuleState.ENABLED:
            raise ConfigurationError("routing cards require enabled capsules")
        return cls(
            capability_id=manifest.spec.capability_id,
            version=manifest.spec.version,
            manifest_sha256=manifest.manifest_sha256,
            risk=manifest.spec.risk,
            intents=manifest.spec.intents,
            negative_intents=manifest.spec.negative_intents,
            data_classification=manifest.spec.data_classification,
        )

    def __post_init__(self) -> None:
        if (
            not isinstance(self.risk, RiskLevel)
            or not isinstance(self.data_classification, DataClassification)
            or _CAPABILITY_ID.fullmatch(self.capability_id) is None
            or _VERSION.fullmatch(self.version) is None
            or len(self.manifest_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in self.manifest_sha256
            )
            or not self.intents
            or any(not intent.strip() for intent in self.intents)
        ):
            raise ValidationError("capability routing card is incomplete")

    def to_dict(self) -> dict[str, object]:
        return {
            "capability_id": self.capability_id,
            "version": self.version,
            "manifest_sha256": self.manifest_sha256,
            "risk": str(self.risk),
            "intents": list(self.intents),
            "negative_intents": list(self.negative_intents),
            "data_classification": str(self.data_classification),
        }


@dataclass(frozen=True, slots=True)
class RoutingDecision:
    """Small exact candidate set suitable for plan binding."""

    cards: tuple[CapabilityCard, ...]
    normalized_intent_sha256: str

    @property
    def binding_sha256(self) -> str:
        payload = [card.to_dict() for card in self.cards]
        return hashlib.sha256(_canonical_json(payload)).hexdigest()


class CapabilityRouter:
    """Filter by policy first, then apply advisory lexical intent matching."""

    def resolve(
        self,
        prompt: str,
        cards: Sequence[CapabilityCard],
        *,
        policy_allows: Callable[[CapabilityCard], bool],
        maximum_candidates: int = 3,
    ) -> RoutingDecision:
        if not 1 <= maximum_candidates <= 8:
            raise ConfigurationError("routing candidate limit must be 1..8")
        surface = _normalize_surface(prompt)
        normalized = " ".join(_TOKEN.findall(surface))
        tokens = tuple(_TOKEN.findall(normalized))
        if not tokens:
            raise ValidationError("routing intent contains no usable terms")
        policy_filtered = tuple(card for card in cards if policy_allows(card))
        _reject_confusable_cards(policy_filtered)
        negated = _negated_terms(surface)
        explicit_read = bool(set(tokens) & _READ_TERMS)
        explicit_write = bool((set(tokens) & _WRITE_TERMS) - negated)
        scored: list[tuple[int, str, CapabilityCard]] = []
        for card in policy_filtered:
            if card.risk not in {RiskLevel.READ_ONLY, RiskLevel.LOCAL_GENERATION}:
                if explicit_read and not explicit_write:
                    continue
            elif explicit_write and not explicit_read:
                continue
            intent_tokens = {
                token
                for phrase in card.intents
                for token in _TOKEN.findall(_normalize_intent(phrase))
            }
            negative_phrases = tuple(
                _normalize_intent(phrase) for phrase in card.negative_intents
            )
            if any(phrase and phrase in normalized for phrase in negative_phrases):
                continue
            if intent_tokens & negated:
                continue
            overlap = len(intent_tokens & set(tokens))
            phrase_bonus = sum(
                4 for phrase in card.intents if _normalize_intent(phrase) in normalized
            )
            score = overlap + phrase_bonus
            if score:
                scored.append((score, card.capability_id, card))
        scored.sort(key=lambda item: (-item[0], item[1], item[2].version))
        selected = tuple(item[2] for item in scored[:maximum_candidates])
        if not selected:
            raise ValidationError("no policy-permitted capability matches the intent")
        return RoutingDecision(
            cards=selected,
            normalized_intent_sha256=hashlib.sha256(normalized.encode()).hexdigest(),
        )


@dataclass(slots=True)
class CapabilitySession:
    """Bounded call authority for only the exact selected capsule versions."""

    plan_fingerprint: str
    cards: tuple[CapabilityCard, ...]
    expires_at: datetime
    maximum_calls: int
    maximum_total_bytes: int
    _calls: int = 0
    _bytes: int = 0

    def __post_init__(self) -> None:
        if len(self.plan_fingerprint) != 64 or self.expires_at.tzinfo is None:
            raise ConfigurationError("capability session identity is malformed")
        if not self.cards or not 1 <= self.maximum_calls <= 256:
            raise ConfigurationError("capability session call budget is invalid")
        if not 1 <= self.maximum_total_bytes <= 16 * 1024 * 1024:
            raise ConfigurationError("capability session byte budget is invalid")
        identities = {
            (card.capability_id, card.version, card.manifest_sha256)
            for card in self.cards
        }
        if len(identities) != len(self.cards):
            raise ConfigurationError("capability session cards must be unique")

    def authorize(
        self,
        *,
        plan_fingerprint: str,
        capability_id: str,
        version: str,
        manifest_sha256: str,
        payload: Mapping[str, Any],
        now: datetime | None = None,
    ) -> None:
        """Consume budget only after every exact identity check succeeds."""

        current = (now or datetime.now(UTC)).astimezone(UTC)
        if current >= self.expires_at.astimezone(UTC):
            raise ConfigurationError("capability session expired")
        if plan_fingerprint != self.plan_fingerprint:
            raise ConfigurationError("capability session belongs to another plan")
        requested = (capability_id, version, manifest_sha256)
        if requested not in {
            (card.capability_id, card.version, card.manifest_sha256)
            for card in self.cards
        }:
            raise ConfigurationError("capability call is outside the active session")
        usage = measure_json_resources(
            payload,
            context="capability session payload",
            max_bytes=self.maximum_total_bytes,
        )
        if self._calls + 1 > self.maximum_calls:
            raise ConfigurationError("capability session call budget exhausted")
        if self._bytes + usage.scalar_bytes > self.maximum_total_bytes:
            raise ConfigurationError("capability session byte budget exhausted")
        self._calls += 1
        self._bytes += usage.scalar_bytes

    def to_dict(self) -> Mapping[str, object]:
        """Return content-free session status; no executable routing data."""

        return MappingProxyType(
            {
                "plan_fingerprint": self.plan_fingerprint,
                "capability_bindings_sha256": hashlib.sha256(
                    _canonical_json([card.to_dict() for card in self.cards])
                ).hexdigest(),
                "expires_at": self.expires_at.astimezone(UTC).isoformat(),
                "maximum_calls": self.maximum_calls,
                "calls_used": self._calls,
                "maximum_total_bytes": self.maximum_total_bytes,
                "bytes_used": self._bytes,
            }
        )


def _normalize_intent(value: str) -> str:
    return " ".join(_TOKEN.findall(_normalize_surface(value)))


def _normalize_surface(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    if any(unicodedata.category(character) in {"Cc", "Cf"} for character in normalized):
        raise ValidationError(
            "routing intent contains control or formatting characters"
        )
    # Tokenization drops apostrophes. Normalize the common contraction first so
    # "don't delete" keeps the same negation semantics as "do not delete".
    return normalized.replace("don't", "dont").replace("don’t", "dont")


def _negated_terms(surface: str) -> set[str]:
    """Return operation terms covered by a bounded lexical negation scope."""

    units = tuple(_NEGATION_UNIT.findall(surface))
    operation_terms = _READ_TERMS | _WRITE_TERMS
    negated: set[str] = set()
    for index, token in enumerate(units[:-1]):
        if token not in _NEGATORS:
            continue
        fallback: str | None = None
        operation_found = False
        words_seen = 0
        for candidate in units[index + 1 :]:
            if not candidate[0].isalnum():
                if candidate != "," or operation_found:
                    break
                continue
            if candidate in _NEGATION_BREAKERS:
                break
            words_seen += 1
            if words_seen > _MAX_NEGATION_SCOPE_TOKENS:
                break
            if fallback is None and candidate not in _NEGATION_MODIFIERS:
                fallback = candidate
            if candidate in operation_terms:
                negated.add(candidate)
                operation_found = True
        if not operation_found and fallback is not None:
            # Custom capability verbs are not all in the built-in read/write
            # vocabulary. Preserve the old immediate-term behavior for those.
            negated.add(fallback)
    return negated


def _reject_confusable_cards(cards: Sequence[CapabilityCard]) -> None:
    by_skeleton: dict[str, str] = {}
    for card in cards:
        skeleton = "".join(
            character
            for character in unicodedata.normalize(
                "NFKC", card.capability_id
            ).casefold()
            if character.isalnum()
        )
        previous = by_skeleton.get(skeleton)
        if previous is not None and previous != card.capability_id:
            raise ConfigurationError("policy-permitted capability names are confusable")
        by_skeleton[skeleton] = card.capability_id


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")

# Design

## Approach

The first version accepts one owner-controlled, regular JSON file containing
agent provenance and bounded declarative ability records. A capability record
may embed one complete capsule bundle. Inspection parses and statically checks
the bundle as data, validates dependency/SBOM agreement, compares its proposed
capability ID with the current catalog, and returns one of: already supported,
safely importable, conflicting, unsupported, or unsafe.

The selection API accepts exactly one ability name plus the expected source
digest. It captures and reinspects the source, derives a new capsule whose
`source_provenance` contains that digest, and installs only the signed
quarantined state. The existing promotion service then performs independent
test, sandbox, review, publish, and enable transitions.

## Affected components

- `src/master_agent/capability_import.py`
- `src/master_agent/capsule_promotion.py`
- `src/master_agent/cli.py`
- `src/master_agent/config_sources.py`
- capability-capsule documentation, semantic routing, and tests

## Data flow

```text
foreign JSON bytes -> immutable safe snapshot -> strict parse/static preview
       -> explicit ability + expected digest -> signed quarantine
       -> independent capsule lifecycle -> enabled typed catalog/routing card
       -> deprecate or revoke -> no longer resolvable/routable
```

Inspection never constructs the capsule worker, imports foreign modules,
resolves credentials, opens a provider connection, or invokes a hook. The
preview is descriptive data and grants no authority.

## Compatibility

Existing capsule creation and promotion APIs remain supported. Promotion gains
an additional path for an already installed quarantined bundle. Updates use a
new semantic version and source digest; immutable prior versions remain as
audit evidence. Removal is logical revocation, not destructive artifact
deletion.

## Security

The manifest parser rejects duplicate JSON keys, unknown fields, unbounded
data, malformed identifiers, duplicate names/mappings, hidden executable
fields, and non-finite numbers. Static source screening is preview defense in
depth; the capsule validator and isolated worker remain the authoritative
execution boundary. Dependency declarations must match the embedded lock,
SBOM, notices, and license policy. Authority-bearing requirements classify as
unsafe and cannot be selected.

## Rejected alternatives

A directory package was rejected because it expands traversal, symlink, and
multi-file race handling without adding first-version value. Whole-agent and
prompt import were rejected because instructions are not typed capabilities.
Automatic batch selection was rejected because one-at-a-time admission gives
clear conflict handling and avoids partial multi-import state.

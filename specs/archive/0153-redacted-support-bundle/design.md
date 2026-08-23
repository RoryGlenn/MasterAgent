# Design

## Approach

Extract the existing doctor assessment into one reusable CLI helper. The
doctor renderer and the support-bundle command consume that same assessment so
their readiness facts cannot drift. A pure builder in `operating.py` selects a
fixed set of doctor fields, projects each issue onto its category, valid
capability, and fixed helpdesk guidance, redacts any remaining path-bearing
string as a whole, adds bounded support/runtime metadata, computes canonical
JSON section digests, and returns the bundle mapping. The CLI writes that
mapping through the existing restricted JSON publisher.

## Affected components

- `src/master_agent/operating.py`: bounded bundle schema and builder.
- `src/master_agent/cli.py`: shared doctor assessment and new command.
- `tests/test_operating.py` and `tests/test_operating_modes.py`: schema,
  redaction, offline, integrity, and publication evidence.
- `.ai/semantic-router.toml`: route the new command to operating modes.
- `docs/cli-reference.md` and `docs/operations.md`: user and helpdesk workflow.

## Data flow

1. Resolve the explicit or default organization profile path.
2. Run the existing offline doctor assessment without connectors or credential
   reads.
3. Select allowlisted readiness fields, omit `profile_source`, replace parser
   messages with fixed categorical guidance, and redact any path-bearing string
   as a whole.
4. Add a random support ID, UTC creation time, MasterAgent version, and Python
   version.
5. Hash canonical doctor and runtime sections and record their byte counts.
6. Create the explicit output exactly once through restricted publication.

## Compatibility

The doctor command and report schema remain unchanged. The new command is
additive and has no effect on setup, readiness, provider execution, or
enterprise readiness.

## Security

The bundle never reads arbitrary logs, environment values, token files,
provider bodies, hostnames, usernames, or command history. It accepts only
known doctor fields from the internal assessment, never exports raw parser
messages, and replaces a whole string when any local-path marker is present.
Output is bounded, private, create-only, no-follow, and not uploaded. SHA-256
digests detect later section changes but do not authenticate the bundle or
grant authority.

## Rejected alternatives

Archive formats were unnecessary for the bounded structured data and add
parser, metadata, and extraction risk. A single JSON document preserves exact
schemas and is easier for both people and support automation to inspect.

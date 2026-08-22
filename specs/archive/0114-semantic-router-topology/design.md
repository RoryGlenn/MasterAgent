# Design

## Approach

Store the canonical navigation data in `.ai/semantic-router.toml`. Exact
ownership tables enumerate repository assets rather than granting ownership by
broad glob. Route records provide lifecycle, authority links, implementation,
configuration, tests, release gates, exact cross-owned dependencies, aliases,
and one owning topology node. Implementation, test, and requirement links must
agree directly with their semantic owner.
Topology records describe the selected MasterAgent parent, the read researcher,
the plan reviewer, the documentation contract applied directly by the parent,
and the deterministic governed runtime.

`scripts/semantic_router.py` performs bounded TOML and UTF-8 reads, validates
safe repository-relative regular-file references, derives live inventories,
compares every owned category exactly, checks lifecycle and topology rules,
evaluates deterministic query fixtures, and renders `docs/semantic-index.md`.
The release validator calls the same implementation. The generated document is
a compact route table and topology view; exact per-asset ownership remains in
the manifest and is emitted only for a selected route.

The optional advisory runner requires the parent to capture one complete
repository-state binding, parse the manifest from the exact immutable HEAD
revision carried inside it, and reject staged or unstaged manifest drift. That
digest is carried separately from the child-visible route slice and must match
the worker's first state binding before SDK client creation. Only the route
slice enters the sanitized task envelope. The exact profile inventory is also
loaded from that immutable revision and passed unchanged to both broker and
worker. State capture uses a verified commit ID, raw stage-zero index entries,
and descriptor-safe hashes of tracked and non-ignored untracked worktree bytes;
Git filters, replacement objects, worktree redirects, protocols, and lazy fetch
are disabled. Every commit, tree, and prompt-bearing blob read from Git is
rehashed against its requested object ID before parsing. The specialist's technical scope
rejects the global policy, manifest, generated index, and every parent or
sibling profile mechanically.

Object-address verification follows the repository object format. SHA-256
repositories receive SHA-256 binding. Legacy SHA-1 repositories receive the
standard SHA-1 content-address check; this implementation does not claim Git's
separate SHA1DC collision-detection property.

## Affected components

- `.ai/semantic-router.toml`
- `scripts/semantic_router.py`
- `tests/test_semantic_router.py`
- `scripts/advisory_subagent.py` and `src/master_agent/copilot_advisory.py`
- advisory integration, runner, and scope tests
- `scripts/validate_release.py`
- `AGENTS.md`, `.ai/MASTER_AGENT.md`, and checked-in parent profile guidance
- `docs/semantic-index.md`, architecture, advisory, and release documentation
- behavioral specification and changelog

## Data flow

An agent reads minimum global authority policy, consults the generated compact
router, resolves the task to one deterministic route, and loads that route's
linked authority/specification and evidence. CI independently derives the
repository inventories, validates exact ownership and topology, renders the
document in memory, and rejects any byte difference.

## Compatibility

This is development-plane navigation only. It does not change provider access,
capability selection, approvals, credentials, or governed runtime behavior.
Existing source documents remain authoritative. Existing agent roles and tool
allowlists remain unchanged.

## Security

Manifest reads are size-bounded and reject symlinks, traversal, absolute paths,
non-regular files, malformed types, duplicate identifiers, unknown lifecycle
states, or unmapped assets. A planned route cannot claim released
implementation. Agent topology must exactly match the checked-in profile
inventory, children have depth zero and bounded tools, and sibling awareness is
false. Route authorization is parsed from the immutable commit captured by the
repository binding, worktree manifest drift is rejected, and the worker's first
state binding must share the same repository digest. The specialist inventory
is parsed from that same verified commit rather than mutable worktree bytes.
This closes transient ABA manifest or profile swaps, physical Git-object
substitution, and the validation-to-worker race. Generated content is
deterministic and never treated as authority.

## Rejected alternatives

Runtime provider routing, embedding source excerpts, broad filesystem globs,
and peer-to-peer specialist awareness were rejected because they either widen
authority, hide ownership drift, expand context, or couple unrelated roles.

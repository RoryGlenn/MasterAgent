# Requirement deltas

## ADDED

### MA-DOCS-001 — Documentation review is a completion gate

Require MasterAgent to apply the authoritative Docs Agent contract after
implementation and tests for every non-trivial repository change. Accept
`updated` or justified `no_change`; route `needs_review` back to planning or
implementation. While direct host delegation is disabled, complete the same
documentation review directly in the selected parent.

### MA-DOCS-002 — Documentation matches the intended audience

Require audience classification, plain-language-first explanations for mixed
audiences, progressive technical detail, and conditional analogies followed by
the literal technical explanation without replacing exact reference material.

### MA-DOCS-003 — Documentation changes preserve evidence and lifecycle boundaries

Require comparison of authoritative evidence, conflict reporting instead of
documenting apparent defects as intent, current/historical/planned/generated
lifecycle handling, one source of truth, a valid `no_change` result, narrow
default edit scope, validation evidence, and structured completion output.

## MODIFIED

None.

## REMOVED

None.
